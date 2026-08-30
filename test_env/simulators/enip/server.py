"""Minimal EtherNet/IP encapsulation responder — enough for recce's `enip`
probe to fingerprint the endpoint via List Identity + List Services +
RegisterSession.

cpppo (`python -m cpppo.server.enip`) is the obvious pick but is licensed
GPLv3 which would attach to a distributed simulator image; a ~90-line
stdlib server that answers the four command codes the recce probe sends
avoids the licence concern entirely.

Wire format from ODVA Vol 2 §2 (Encapsulation) and Vol 1 §5 (CIP).
All fields LITTLE-ENDIAN.
"""
from __future__ import annotations

import os
import socket
import socketserver
import struct


PORT = int(os.environ.get("ENIP_PORT", "44818"))
VENDOR_ID = int(os.environ.get("ENIP_VENDOR_ID", "999"))
SERIAL = int(os.environ.get("ENIP_SERIAL", "0xDEADBEEF"), 0)
PRODUCT_NAME = os.environ.get("ENIP_PRODUCT_NAME", "RecceSim-ENIP-1")

CMD_LIST_SERVICES = 0x0004
CMD_LIST_IDENTITY = 0x0063
CMD_LIST_INTERFACES = 0x0064
CMD_REGISTER_SESSION = 0x0065
CMD_UNREGISTER_SESSION = 0x0066

CPF_IDENTITY_ITEM = 0x000C
CPF_LIST_SERVICES_ITEM = 0x0100


def encap(cmd: int, session: int, body: bytes, status: int = 0,
          context: bytes = b"\x00" * 8) -> bytes:
    return (struct.pack("<HHII", cmd, len(body), session, status)
            + context + b"\x00\x00\x00\x00" + body)


def identity_item() -> bytes:
    name = PRODUCT_NAME.encode("latin-1")[:32]
    return (struct.pack("<H", 1)                     # protocol version
            + b"\x00" * 16                           # sockaddr_in (unused)
            + struct.pack("<HHH", VENDOR_ID, 0x000C, 1)   # vendor / dev-type / product-code
            + bytes([1, 0])                          # revision major.minor
            + struct.pack("<HI", 0x0000, SERIAL)     # status / serial
            + bytes([len(name)]) + name
            + bytes([3]))                            # device state = operational


def services_item() -> bytes:
    name = b"Communications".ljust(16, b"\x00")
    # version 1, flags bit 5 set (supports CIP encapsulation via TCP).
    return struct.pack("<HH", 1, 0x0120) + name


def list_reply(cmd: int, item_type: int, item_body: bytes,
               ctx: bytes) -> bytes:
    cpf = struct.pack("<H", 1) + struct.pack("<HH", item_type, len(item_body)) + item_body
    return encap(cmd, 0, cpf, context=ctx)


def register_reply(session: int, ctx: bytes) -> bytes:
    return encap(CMD_REGISTER_SESSION, session, struct.pack("<HH", 1, 0),
                 context=ctx)


class ENIPHandler(socketserver.BaseRequestHandler):
    session_counter = 0x1000

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
            while len(buf) >= 24:
                cmd, length, session, status = struct.unpack("<HHII", buf[:12])
                ctx = buf[12:20]
                if len(buf) < 24 + length:
                    break
                body = buf[24:24 + length]
                buf = buf[24 + length:]
                self._dispatch(cmd, session, ctx, body)

    def _dispatch(self, cmd: int, session: int, ctx: bytes,
                  body: bytes) -> None:
        if cmd == CMD_LIST_IDENTITY:
            self.request.sendall(
                list_reply(cmd, CPF_IDENTITY_ITEM, identity_item(), ctx))
        elif cmd == CMD_LIST_SERVICES:
            self.request.sendall(
                list_reply(cmd, CPF_LIST_SERVICES_ITEM, services_item(), ctx))
        elif cmd == CMD_LIST_INTERFACES:
            # No interface items — reply with an empty CPF list.
            self.request.sendall(encap(cmd, 0, struct.pack("<H", 0), context=ctx))
        elif cmd == CMD_REGISTER_SESSION:
            ENIPHandler.session_counter += 1
            self.request.sendall(register_reply(ENIPHandler.session_counter, ctx))
        elif cmd == CMD_UNREGISTER_SESSION:
            return
        else:
            # invalid command → status = 1
            self.request.sendall(encap(cmd, session, b"", status=1, context=ctx))


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> None:
    with _ReusableTCPServer(("0.0.0.0", PORT), ENIPHandler) as srv:
        print(f"enip-sim: vendor {VENDOR_ID} product {PRODUCT_NAME!r} "
              f"listening on 0.0.0.0:{PORT}", flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
