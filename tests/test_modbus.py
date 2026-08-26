"""Tests for recce.services.modbus — Modbus/TCP probe.

Serve canned Modbus responses over TCP; verify probe() parses register
values and device identification, and degrades cleanly on non-Modbus
services.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import modbus


def _build_registers_response(tid: int, unit_id: int, regs: list[int]) -> bytes:
    """Assemble a Read-Holding-Registers response ADU for `regs`."""
    pdu = struct.pack(">BB", 0x03, len(regs) * 2)
    for r in regs:
        pdu += struct.pack(">H", r)
    length = len(pdu) + 1
    return struct.pack(">HHHB", tid, 0, length, unit_id) + pdu


def _build_device_id_response(tid: int, unit_id: int,
                              vendor: str, product: str) -> bytes:
    """Assemble a Read-Device-Identification response ADU carrying vendor +
    product strings as objects 0 and 1."""
    v = vendor.encode(); p = product.encode()
    # PDU: fn(2B) mei(0E) rdid_code(01) conformity(01) more(00) next_obj(00) n_objs(02)
    body = struct.pack(">BBBBBBB", 0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x02)
    body += struct.pack(">BB", 0x00, len(v)) + v
    body += struct.pack(">BB", 0x01, len(p)) + p
    length = len(body) + 1
    return struct.pack(">HHHB", tid, 0, length, unit_id) + body


class _ModbusServer:
    def __init__(self, responder):
        """responder(request_bytes) -> response_bytes."""
        self._respond = responder
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                # Multiple exchanges per connection — probe sends registers first
                # and may follow with device ID request.
                for _ in range(4):
                    data = conn.recv(1024)
                    if not data: break
                    resp = self._respond(data)
                    if resp:
                        conn.sendall(resp)
            except OSError:
                pass
            finally:
                try: conn.close()
                except OSError: pass

    def close(self):
        self._stop = True
        try: self._srv.close()
        except OSError: pass


class ProbeTest(unittest.TestCase):
    def test_registers_and_device_id_parsed(self):
        def responder(req):
            if len(req) < 8: return b""
            tid = struct.unpack(">H", req[0:2])[0]
            unit_id = req[6]
            fn = req[7]
            if fn == 0x03:
                return _build_registers_response(tid, unit_id, [0x1234])
            if fn == 0x2B:
                return _build_device_id_response(tid, unit_id,
                                                 vendor="ACME PLC Corp",
                                                 product="ModelX-2000")
            return b""
        srv = _ModbusServer(responder)
        try:
            p = modbus.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["registers"], [0x1234])
        self.assertEqual(p["vendor"], "ACME PLC Corp")
        self.assertEqual(p["product"], "ModelX-2000")

    def test_non_modbus_service_not_flagged(self):
        # Server sends back garbage — probe must not raise or false-flag.
        srv = _ModbusServer(lambda req: b"HTTP/1.1 400 Bad Request\r\n\r\n")
        try:
            p = modbus.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertFalse(p["reachable"])

    def test_dead_port(self):
        p = modbus.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


if __name__ == "__main__":
    unittest.main()
