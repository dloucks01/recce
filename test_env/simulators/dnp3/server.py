"""Minimal DNP3 outstation — hand-rolled Data-Link + App layer just enough
for recce's `dnp3` probe to fingerprint the endpoint.

No mature MIT/BSD-licensed DNP3 outstation library exists on PyPI:
* `pydnp3` / `dnp3-python` wrap opendnp3 (Apache-2.0) but the wheels are
  build-from-source with cmake + boost, which bloats the sim image.
* Hand-rolling gives a ~90-line responder that covers the two probe steps
  that matter for detection: REQUEST_LINK_STATUS (FC9) and FC1 Read of
  Class 0 (g60v1).

Wire format from IEEE 1815-2012 §8 (Data Link) and §4-5 (App layer).
CRC-16-DNP (poly 0xA6BC reflected) is applied per-block (16 bytes user data).
"""
from __future__ import annotations

import os
import socket
import socketserver
import struct


PORT = int(os.environ.get("DNP3_PORT", "20000"))
OUTSTATION_ADDR = int(os.environ.get("DNP3_OUTSTATION_ADDR", "1024"))

DL_FC_REQ_LINK_STATUS = 0x09
DL_FC_STATUS_OF_LINK = 0x0B
DL_FC_UNCONFIRMED_UD = 0x04

APP_FC_READ = 0x01
APP_FC_RESPONSE = 0x81
APP_FIR = 0x80
APP_FIN = 0x40


def crc_dnp(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (crc ^ 0xFFFF) & 0xFFFF


def with_block_crcs(user: bytes) -> bytes:
    out = b""
    for i in range(0, len(user), 16):
        block = user[i:i + 16]
        out += block + struct.pack("<H", crc_dnp(block))
    return out


def build_dl(fc: int, dst: int, src: int, user: bytes = b"",
             dir_master: bool = False, prm_primary: bool = True) -> bytes:
    ctrl = (0x80 if dir_master else 0) | (0x40 if prm_primary else 0) | (fc & 0x0F)
    length = 5 + len(user)
    header = struct.pack("<BBBBHH", 0x05, 0x64, length, ctrl, dst, src)
    return header + struct.pack("<H", crc_dnp(header)) + with_block_crcs(user)


def parse_dl(data: bytes) -> dict | None:
    if len(data) < 10 or data[0] != 0x05 or data[1] != 0x64:
        return None
    if struct.unpack("<H", data[8:10])[0] != crc_dnp(data[:8]):
        return None
    ctrl = data[3]
    return {"length": data[2], "fc": ctrl & 0x0F,
            "dst": struct.unpack("<H", data[4:6])[0],
            "src": struct.unpack("<H", data[6:8])[0]}


def build_status_of_link(master: int) -> bytes:
    # Reply from secondary → primary: DIR=0 PRM=0 FC=11.
    return build_dl(DL_FC_STATUS_OF_LINK, master, OUTSTATION_ADDR,
                    dir_master=False, prm_primary=False)


def build_class0_response(master: int, app_seq: int, tp_seq: int) -> bytes:
    # g1v2 single-bit input + quality: qualifier 0x00 (1-oct start/stop),
    # start=0, stop=0, one payload byte (0x81 = online + state=1).
    objects = bytes([0x01, 0x02, 0x00, 0x00, 0x00, 0x81])
    app = bytes([APP_FIR | APP_FIN | (app_seq & 0x0F),
                 APP_FC_RESPONSE, 0x00, 0x00]) + objects  # IIN1=0 IIN2=0
    tp = bytes([0xC0 | (tp_seq & 0x3F)])  # TP FIR + FIN
    # Outstation-originated user data: DIR=0 PRM=1 FC=4.
    return build_dl(DL_FC_UNCONFIRMED_UD, master, OUTSTATION_ADDR, tp + app,
                    dir_master=False, prm_primary=True)


class DNP3Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(30.0)
        buf = b""
        while True:
            try:
                chunk = self.request.recv(4096)
            except (socket.timeout, OSError):
                return
            if not chunk:
                return
            buf += chunk
            while len(buf) >= 10:
                dl = parse_dl(buf)
                if not dl:
                    buf = buf[1:]
                    continue
                # Advance past the full frame (header + user with CRCs).
                ud_len = dl["length"] - 5
                block_bytes = 0
                remaining = ud_len
                while remaining > 0:
                    take = min(16, remaining)
                    block_bytes += take + 2
                    remaining -= take
                frame_len = 10 + block_bytes
                if len(buf) < frame_len:
                    break
                frame = buf[:frame_len]
                buf = buf[frame_len:]
                self._dispatch(dl, frame)

    def _dispatch(self, dl: dict, frame: bytes) -> None:
        master = dl["src"]
        if dl["fc"] == DL_FC_REQ_LINK_STATUS:
            self.request.sendall(build_status_of_link(master))
            return
        if dl["fc"] == DL_FC_UNCONFIRMED_UD:
            # Peek app FC — if it's Read, reply with a Class 0 response.
            user_start = 10
            # First user byte is TP; second is APP_CTRL; third is APP_FC.
            if len(frame) >= user_start + 3:
                tp = frame[user_start]
                app_ctrl = frame[user_start + 1]
                app_fc = frame[user_start + 2]
                if app_fc == APP_FC_READ:
                    self.request.sendall(
                        build_class0_response(master, app_ctrl & 0x0F,
                                              tp & 0x3F))


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> None:
    with _ReusableTCPServer(("0.0.0.0", PORT), DNP3Handler) as srv:
        print(f"dnp3-sim: outstation addr {OUTSTATION_ADDR} listening on "
              f"0.0.0.0:{PORT}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
