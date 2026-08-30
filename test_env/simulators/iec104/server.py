"""Minimal IEC 60870-5-104 responder — APCI framing + U-format
TESTFR/STARTDT/STOPDT ack + tiny S-frame ack for any I-frame received
(enough for recce's `iec104` probe to enter data-transfer state).

lib60870-python and c104 both exist but pull in build-from-source C
libraries; a ~70-line stdlib server covers detection without that.

Wire format: IEC 60870-5-104 §5. APCI is a fixed 6-byte prefix
(0x68, length, ctl1..4). I-format frames carry an ASDU after the APCI.
"""
from __future__ import annotations

import os
import socket
import socketserver
import struct


PORT = int(os.environ.get("IEC104_PORT", "2404"))
CAA = int(os.environ.get("IEC104_CAA", "1"))          # common ASDU address

START = 0x68

U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT = 0x13
U_STOPDT_CON = 0x23
U_TESTFR_ACT = 0x43
U_TESTFR_CON = 0x83

TI_C_IC_NA_1 = 100     # General Interrogation
COT_ACT_CON = 7
COT_ACT_TERM = 10


def u_frame(func: int) -> bytes:
    return bytes([START, 0x04, func, 0x00, 0x00, 0x00])


def s_frame(nr: int) -> bytes:
    ctl3 = (nr & 0x7F) << 1
    ctl4 = (nr >> 7) & 0xFF
    return bytes([START, 0x04, 0x01, 0x00, ctl3, ctl4])


def i_frame(ns: int, nr: int, asdu: bytes) -> bytes:
    ns_bytes = struct.pack("<H", (ns & 0x7FFF) << 1)
    nr_bytes = struct.pack("<H", (nr & 0x7FFF) << 1)
    return bytes([START, 4 + len(asdu)]) + ns_bytes + nr_bytes + asdu


def gi_actcon(ns: int, nr: int, cot: int) -> bytes:
    # Reply to General Interrogation: same TI 100, VSQ 1, COT, orig=0,
    # CAA, then IOA=0 + QOI=20.
    asdu = (bytes([TI_C_IC_NA_1, 0x01, cot & 0x3F, 0x00])
            + struct.pack("<H", CAA & 0xFFFF)
            + bytes([0, 0, 0, 20]))
    return i_frame(ns, nr, asdu)


class IECHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(60.0)
        buf = b""
        ns = 0
        nr = 0
        started = False
        while True:
            try:
                chunk = self.request.recv(4096)
            except (socket.timeout, OSError):
                return
            if not chunk:
                return
            buf += chunk
            while len(buf) >= 6:
                if buf[0] != START:
                    buf = buf[1:]
                    continue
                length = buf[1]
                if length < 4 or length > 253:
                    buf = buf[1:]
                    continue
                total = 2 + length
                if len(buf) < total:
                    break
                frame = buf[:total]
                buf = buf[total:]
                ns, nr, started = self._dispatch(frame, ns, nr, started)

    def _dispatch(self, frame: bytes, ns: int, nr: int, started: bool):
        ctl1, ctl2, ctl3, ctl4 = frame[2], frame[3], frame[4], frame[5]
        if ctl1 & 0x03 == 0x03:                            # U-format
            if ctl1 == U_STARTDT_ACT:
                self.request.sendall(u_frame(U_STARTDT_CON))
                started = True
            elif ctl1 == U_STOPDT_ACT:
                self.request.sendall(u_frame(U_STOPDT_CON))
                started = False
            elif ctl1 == U_TESTFR_ACT:
                self.request.sendall(u_frame(U_TESTFR_CON))
        elif ctl1 & 0x01 == 0x01:                          # S-format ack
            pass
        else:                                              # I-format
            peer_ns = ((ctl2 << 8) | ctl1) >> 1
            nr = (peer_ns + 1) & 0x7FFF
            asdu = frame[6:]
            if asdu and asdu[0] == TI_C_IC_NA_1 and started:
                # ActCon then ActTerm — cheap two-frame reply so the probe
                # sees ≥1 interrogation record land.
                self.request.sendall(gi_actcon(ns, nr, COT_ACT_CON))
                ns = (ns + 1) & 0x7FFF
                self.request.sendall(gi_actcon(ns, nr, COT_ACT_TERM))
                ns = (ns + 1) & 0x7FFF
            else:
                # Plain S-frame ack.
                self.request.sendall(s_frame(nr))
        return ns, nr, started


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> None:
    with _ReusableTCPServer(("0.0.0.0", PORT), IECHandler) as srv:
        print(f"iec104-sim: CAA {CAA} listening on 0.0.0.0:{PORT}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
