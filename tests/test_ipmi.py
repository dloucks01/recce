"""Tests for recce.services.ipmi — the IPMI 623/udp probe.

Stand up a loopback UDP responder that replays canned Get Channel Auth
Capabilities responses; verify probe() correctly decodes:
  * auth-type bitmap (none, MD2, MD5, password, OEM)
  * null-user + anonymous-login flags
  * IPMI 2.0 support flag
  * cipher-zero heuristic (none + IPMI 2.0)
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import ipmi


def _build_gcac_response(auth_types: int, auth_status: int,
                        ext_caps: int) -> bytes:
    """Assemble an RMCP/IPMI Get Channel Auth Capabilities response with
    the given three bytes of interest. Returns the full UDP payload."""
    # RMCP header
    hdr = bytes([0x06, 0x00, 0xff, 0x07])
    # Session header (auth type 0, seq 0, id 0), then msg-length
    sess = bytes([0x00]) + b"\x00" * 4 + b"\x00" * 4
    # Message layout expected by probe():
    #   rqAddr(1) netFn|lun(1) csum(1) rsAddr(1) rsSeq|lun(1) cmd(1)
    #   compCode(1) channel(1) authTypes(1) authStatus(1) extCaps(1) oem(3)
    msg = bytes([
        0x81,       # rqAddr
        0x1c,       # netFn 7 (APP resp) << 2
        0x63,       # csum1 (not verified by probe)
        0x20,       # rsAddr
        0x00,       # rsSeq
        0x38,       # cmd
        0x00,       # completion code
        0x01,       # channel
        auth_types & 0xff,
        auth_status & 0xff,
        ext_caps & 0xff,
        0x00, 0x00, 0x00,   # OEM
    ])
    return hdr + sess + bytes([len(msg)]) + msg


class _UDPServer:
    def __init__(self, response: bytes):
        self._resp = response
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.host, self.port = self._sock.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                data, addr = self._sock.recvfrom(4096)
                self._sock.sendto(self._resp, addr)
            except (socket.timeout, OSError):
                continue

    def close(self):
        self._stop = True
        try: self._sock.close()
        except OSError: pass


class ProbeTest(unittest.TestCase):
    def test_cipher_zero_flagged_when_none_plus_ipmi20(self):
        # auth_types: bit 0 (none) + bit 4 (password) = 0x11
        # auth_status: no anon/null
        # ext_caps: bit 0 (IPMI 2.0) set
        srv = _UDPServer(_build_gcac_response(
            auth_types=0x11, auth_status=0x00, ext_caps=0x01))
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["ipmi_version"], "2.0")
        self.assertIn("none", p["auth_types"])
        self.assertIn("password", p["auth_types"])
        self.assertTrue(p["cipher_zero"], "'none' + IPMI 2.0 should mark cipher_zero")

    def test_null_user_and_anonymous_detected(self):
        srv = _UDPServer(_build_gcac_response(
            auth_types=0x14,        # MD5 + password
            auth_status=0x03,       # anonymous (bit 0) + null user (bit 1)
            ext_caps=0x01))
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["anonymous_login"])
        self.assertTrue(p["null_user"])
        self.assertIn("MD5", p["auth_types"])

    def test_hardened_bmc_produces_no_severity(self):
        # Only password auth (bit 4 = 0x10), no anon/null, IPMI 1.5 only
        srv = _UDPServer(_build_gcac_response(
            auth_types=0x10, auth_status=0x00, ext_caps=0x00))
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["cipher_zero"])
        self.assertFalse(p["anonymous_login"])
        self.assertFalse(p["null_user"])
        self.assertEqual(p["auth_types"], ["password"])

    def test_dead_port_returns_unreachable(self):
        # Bound to a port with nothing listening
        p = ipmi.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


if __name__ == "__main__":
    unittest.main()
