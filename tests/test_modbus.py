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


def _build_report_slave_id_response(tid: int, unit_id: int,
                                    server_id: bytes, run_on: bool) -> bytes:
    """Assemble a Function 0x11 Report Server ID response ADU.
    PDU: fn(0x11) byte_count server_id... run_indicator."""
    body = server_id + (b"\xff" if run_on else b"\x00")
    pdu = struct.pack(">BB", 0x11, len(body)) + body
    length = len(pdu) + 1
    return struct.pack(">HHHB", tid, 0, length, unit_id) + pdu


def _build_exception_response(tid: int, unit_id: int, fn: int,
                              excode: int) -> bytes:
    """Assemble a Modbus exception response (function | 0x80)."""
    pdu = struct.pack(">BB", fn | 0x80, excode)
    length = len(pdu) + 1
    return struct.pack(">HHHB", tid, 0, length, unit_id) + pdu


class ReportSlaveIdTest(unittest.TestCase):
    def test_report_slave_id_captured_after_device_id(self):
        server_id = b"Schneider M340 v3.10"

        def responder(req):
            tid = struct.unpack(">H", req[0:2])[0]
            unit_id = req[6]
            fn = req[7]
            if fn == 0x03:
                return _build_registers_response(tid, unit_id, [0xBEEF])
            if fn == 0x2B:
                return _build_device_id_response(tid, unit_id,
                                                 vendor="Schneider",
                                                 product="M340")
            if fn == 0x11:
                return _build_report_slave_id_response(tid, unit_id,
                                                      server_id, run_on=True)
            return b""

        srv = _ModbusServer(responder)
        try:
            p = modbus.probe(srv.host, srv.port, timeout=2, sweep_units=False)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["run_indicator"], "ON")
        self.assertEqual(p["slave_id_hex"], server_id.hex())

    def test_report_slave_id_exception_is_silent(self):
        """A device that refuses 0x11 (exception 0x91) must not corrupt probe output."""
        def responder(req):
            tid = struct.unpack(">H", req[0:2])[0]
            unit_id = req[6]
            fn = req[7]
            if fn == 0x03:
                return _build_registers_response(tid, unit_id, [1])
            if fn == 0x2B:
                return _build_device_id_response(tid, unit_id, "V", "P")
            if fn == 0x11:
                return _build_exception_response(tid, unit_id, 0x11, 0x01)
            return b""

        srv = _ModbusServer(responder)
        try:
            p = modbus.probe(srv.host, srv.port, timeout=2, sweep_units=False)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["slave_id_hex"], "")
        self.assertEqual(p["run_indicator"], "")

    def test_parse_report_slave_id_direct(self):
        wire = _build_report_slave_id_response(1, 1, b"AB\x01\x02", run_on=False)
        parsed = modbus._parse_report_slave_id(wire)
        self.assertEqual(parsed["slave_id_hex"], b"AB\x01\x02".hex())
        self.assertEqual(parsed["run_indicator"], "OFF")


class UnitSweepTest(unittest.TestCase):
    def test_sweep_discovers_multiple_units_behind_gateway(self):
        # Gateway model: unit IDs 5 and 7 exist behind the TCP endpoint;
        # any other unit returns exception 0x0B (gateway-target-failed).
        # Unit 1 also answers so the primary probe reaches the endpoint.
        present = {1, 5, 7}

        def responder(req):
            tid = struct.unpack(">H", req[0:2])[0]
            unit_id = req[6]
            fn = req[7]
            if fn == 0x03:
                if unit_id in present:
                    return _build_registers_response(tid, unit_id, [unit_id])
                return _build_exception_response(tid, unit_id, 0x03, 0x0B)
            if fn == 0x2B:
                return _build_device_id_response(tid, unit_id, "V", "P")
            if fn == 0x11:
                return b""
            return b""

        srv = _ModbusServer(responder)
        try:
            p = modbus.probe(srv.host, srv.port, timeout=2, sweep_units=True)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        # Winning unit 1 plus swept units 5, 7 should all appear.
        self.assertIn(1, p["units"])
        self.assertIn(5, p["units"])
        self.assertIn(7, p["units"])
        # Gateway-target-failed (0x0B) responses must NOT be treated as presence.
        self.assertNotIn(2, p["units"])
        self.assertNotIn(3, p["units"])

    def test_gateway_finding_emitted_on_multiple_units(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.9", ports=[Port(portid=502)])
        probes = {("10.0.0.9", 502): {
            "reachable": True, "registers": [0], "vendor": "", "product": "",
            "revision": "", "slave_id_hex": "", "run_indicator": "",
            "units": [1, 5, 7],
        }}
        fs = modbus.findings([h], probes)
        kinds = [f["kind"] for f in fs]
        self.assertIn("modbus_gateway_units", kinds)
        gw = next(f for f in fs if f["kind"] == "modbus_gateway_units")
        self.assertEqual(gw["severity"], "high")
        self.assertIn("1", gw["detail"])
        self.assertIn("5", gw["detail"])
        self.assertIn("7", gw["detail"])

    def test_single_unit_does_not_emit_gateway_finding(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.10", ports=[Port(portid=502)])
        probes = {("10.0.0.10", 502): {
            "reachable": True, "registers": [0], "vendor": "", "product": "",
            "revision": "", "slave_id_hex": "", "run_indicator": "",
            "units": [1],
        }}
        fs = modbus.findings([h], probes)
        kinds = [f["kind"] for f in fs]
        self.assertNotIn("modbus_gateway_units", kinds)


if __name__ == "__main__":
    unittest.main()
