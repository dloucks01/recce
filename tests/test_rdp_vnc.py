"""Tests for recce.services.rdp and recce.services.vnc.

Loopback TCP servers replay canned RDP/VNC handshakes; verify probes
correctly identify NLA-off (RDP), no-auth (VNC type 1), and DES-only
(VNC type 2).
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import rdp as rdp_svc
from recce.services import vnc as vnc_svc


class _TCPResponder:
    """Accept one connection, read the request, send a fixed response, close."""
    def __init__(self, responder):
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
                self._respond(conn)
            except OSError:
                pass
            finally:
                try: conn.close()
                except OSError: pass

    def close(self):
        self._stop = True
        try: self._srv.close()
        except OSError: pass


def _rdp_negotiation_response(protocol: int) -> bytes:
    """Build a full TPKT + X.224 CC + RDP Negotiation Response."""
    # RDP Neg Response: type 2, flags 0, length 8, selectedProtocol (4 LE)
    neg = struct.pack("<BBH I", 0x02, 0x00, 8, protocol)
    # X.224 CC: length_indicator(1) + type(1)=0xd0 + dst-ref(2) + src-ref(2)
    # + class(1). Then the neg payload.
    x224 = bytes([6 + len(neg), 0xd0, 0, 0, 0, 0, 0]) + neg
    # TPKT: version(1)=3, reserved(1)=0, length(2 BE) = 4 + len(x224)
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
    return tpkt


class RDPTest(unittest.TestCase):
    def test_no_nla_flagged(self):
        # protocol 0 = Standard RDP (no SSL/CredSSP)
        srv = _TCPResponder(lambda c: (c.recv(4096), c.sendall(_rdp_negotiation_response(0))))
        try:
            p = rdp_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["standard_rdp_accepted"])
        self.assertFalse(p["nla_required"])
        self.assertEqual(p["protocol"], "STANDARD_RDP")

    def test_hybrid_nla_marked_required(self):
        # protocol 3 = CredSSP+SSL (bit 0x02 = CredSSP)
        srv = _TCPResponder(lambda c: (c.recv(4096), c.sendall(_rdp_negotiation_response(3))))
        try:
            p = rdp_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["standard_rdp_accepted"])
        self.assertTrue(p["nla_required"])

    def test_dead_port(self):
        p = rdp_svc.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


def _vnc_server_handler(sec_types: list[int]):
    """Return a connection handler that speaks VNC 3.8 with the given
    security-type list."""
    def _handle(conn):
        conn.sendall(b"RFB 003.008\n")
        # Read client's version (12 bytes)
        conn.recv(12)
        # Send security-type list (n + n bytes)
        conn.sendall(bytes([len(sec_types)]) + bytes(sec_types))
    return _handle


class VNCTest(unittest.TestCase):
    def test_no_auth_flagged(self):
        srv = _TCPResponder(_vnc_server_handler([1]))     # type 1 = None
        try:
            p = vnc_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["no_auth"])
        self.assertIn("None", p["security_types"])

    def test_des_only_flagged(self):
        srv = _TCPResponder(_vnc_server_handler([2]))     # type 2 = DES VNC auth
        try:
            p = vnc_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["no_auth"])
        self.assertTrue(p["des_only"])

    def test_strong_auth_offered_no_severity(self):
        srv = _TCPResponder(_vnc_server_handler([19, 2]))  # VeNCrypt + fallback
        try:
            p = vnc_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["no_auth"])
        self.assertFalse(p["des_only"])

    def test_dead_port(self):
        p = vnc_svc.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


if __name__ == "__main__":
    unittest.main()
