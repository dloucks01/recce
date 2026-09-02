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


# --- CredSSP TSRequest + NTLM CHALLENGE parsing (wire-shape fixtures) ----------

def _av(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


def _build_ntlm_type2(av_pairs: bytes, flags: int = 0x02028215,
                      version: bytes = b"\x0a\x00\x69\x4a\x00\x00\x00\x0f") -> bytes:
    """A wire-shape NTLMSSP CHALLENGE_MESSAGE (Type 2) with a Version field
    (default 10.0.19049) and the caller's AV_PAIR TargetInfo block."""
    ti_off = 56                                             # 48-byte header + 8-byte Version
    return (b"NTLMSSP\x00" + struct.pack("<I", 2)
            + struct.pack("<HHI", 0, 0, 0)                  # TargetName (empty)
            + struct.pack("<I", flags)
            + b"\x01" * 8                                   # ServerChallenge
            + b"\x00" * 8                                   # Reserved
            + struct.pack("<HHI", len(av_pairs), len(av_pairs), ti_off)
            + version
            + av_pairs)


class RDPCredSSPTest(unittest.TestCase):
    def test_tsrequest_roundtrip_preserves_version_and_negotoken(self):
        """build -> parse yields the same negoToken and version."""
        token = b"NTLMSSP\x00\x02\x00\x00\x00" + b"\xaa" * 32
        built = rdp_svc.build_credssp_tsrequest(token, version=6)
        # Outer must be a DER SEQUENCE.
        self.assertEqual(built[0], 0x30)
        ts = rdp_svc.parse_credssp_tsrequest(built)
        self.assertIsNotNone(ts)
        self.assertEqual(ts["version"], 6)
        self.assertEqual(ts["negoToken"], token)

    def test_tsrequest_parse_rejects_garbage(self):
        self.assertIsNone(rdp_svc.parse_credssp_tsrequest(b""))
        self.assertIsNone(rdp_svc.parse_credssp_tsrequest(b"not-asn1"))
        # A SEQUENCE with a bad inner length must not crash.
        self.assertIsNone(rdp_svc.parse_credssp_tsrequest(b"\x30\x82\xff\xff"))

    def test_tsrequest_version_encodes_high_bit_safely(self):
        """A one-byte INTEGER whose high bit is set must not be misread as negative;
        we ship the extra leading 0x00 byte, and the parser reads it back verbatim."""
        for v in (0, 2, 6, 128, 200):
            built = rdp_svc.build_credssp_tsrequest(b"tok", version=v)
            ts = rdp_svc.parse_credssp_tsrequest(built)
            self.assertIsNotNone(ts, f"parse failed for version {v}")
            self.assertEqual(ts["version"], v)

    def test_parse_ntlm_challenge_extracts_avpairs_and_os_build(self):
        ti = (_av(0x0002, _utf16("CORP"))                   # MsvAvNbDomainName
              + _av(0x0001, _utf16("RDPHOST"))              # MsvAvNbComputerName
              + _av(0x0004, _utf16("corp.local"))           # MsvAvDnsDomainName
              + _av(0x0003, _utf16("rdphost.corp.local"))   # MsvAvDnsComputerName
              + _av(0x0005, _utf16("corp.local"))           # MsvAvDnsTreeName
              + _av(0x0007, struct.pack("<Q", 133518912000000000))  # MsvAvTimestamp
              + _av(0x0000, b""))                           # MsvAvEOL
        version = b"\x0a\x00\xfb\x43\x00\x00\x00\x0f"       # 10.0.17403
        info = rdp_svc.parse_ntlm_challenge_info(_build_ntlm_type2(ti, version=version))
        self.assertIsNotNone(info)
        self.assertEqual(info["netbios_computer"], "RDPHOST")
        self.assertEqual(info["netbios_domain"], "CORP")
        self.assertEqual(info["dns_computer"], "rdphost.corp.local")
        self.assertEqual(info["dns_domain"], "corp.local")
        self.assertEqual(info["dns_tree"], "corp.local")
        self.assertEqual(info["os_version"], "10.0.17403")
        self.assertEqual(info["ntlm_revision"], 0x0F)
        self.assertGreater(info["server_time_epoch"], 0)

    def test_parse_ntlm_challenge_rejects_non_ntlm(self):
        self.assertIsNone(rdp_svc.parse_ntlm_challenge_info(b""))
        self.assertIsNone(rdp_svc.parse_ntlm_challenge_info(b"no-ntlmssp-here"))

    def test_findings_emit_rdp_ntlm_info_and_credssp_unpatched(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.5", ports=[Port(portid=3389, service="ms-wbt-server",
                                            state="open")])
        pr = {"reachable": True, "standard_rdp_accepted": False,
              "nla_required": True, "protocol_code": 0x03,
              "protocol": "CredSSP+SSL", "failure_reason": "",
              "ntlm_info": {"netbios_computer": "RDPHOST",
                            "netbios_domain": "CORP",
                            "dns_domain": "corp.local",
                            "os_version": "10.0.17403",
                            "credssp_version": 2}}
        fs = rdp_svc.findings([h], {("10.0.0.5", 3389): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("rdp_ntlm_info", kinds)
        self.assertIn("rdp_credssp_unpatched", kinds)
        info_f = next(f for f in fs if f["kind"] == "rdp_ntlm_info")
        # Detail carries the extracted intel.
        self.assertIn("RDPHOST", info_f["detail"])
        self.assertIn("corp.local", info_f["detail"])
        self.assertIn("10.0.17403", info_f["detail"])
        # CVE-2018-0886 finding is medium.
        credssp_f = next(f for f in fs if f["kind"] == "rdp_credssp_unpatched")
        self.assertEqual(credssp_f["severity"], "medium")

    def test_findings_no_credssp_unpatched_when_version_ge_3(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.5", ports=[Port(portid=3389, service="ms-wbt-server",
                                            state="open")])
        pr = {"reachable": True, "standard_rdp_accepted": False,
              "protocol_code": 0x03,
              "ntlm_info": {"netbios_computer": "PATCHED",
                            "credssp_version": 6}}
        fs = rdp_svc.findings([h], {("10.0.0.5", 3389): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("rdp_ntlm_info", kinds)
        self.assertNotIn("rdp_credssp_unpatched", kinds)

    def test_findings_no_ntlm_finding_when_probe_lacks_ntlm_info(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.5", ports=[Port(portid=3389, service="ms-wbt-server",
                                            state="open")])
        pr = {"reachable": True, "standard_rdp_accepted": False,
              "protocol_code": 0x03, "protocol": "CredSSP+SSL"}
        fs = rdp_svc.findings([h], {("10.0.0.5", 3389): pr})
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("rdp_ntlm_info", kinds)
        self.assertNotIn("rdp_credssp_unpatched", kinds)


# --- T2 promotion: rdp_no_nla confirmed via Standard-only NegReq ---------------

def _rdp_negotiation_failure(code: int) -> bytes:
    """Build TPKT + X.224 CC + RDP Negotiation Failure PDU (type 3)."""
    # NegFailure: type 3, flags 0, length 8, failureCode (4 LE)
    neg = struct.pack("<BBH I", 0x03, 0x00, 8, code)
    x224 = bytes([6 + len(neg), 0xd0, 0, 0, 0, 0, 0]) + neg
    tpkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
    return tpkt


class RDPNlaConfirmProbeTest(unittest.TestCase):
    """probe_standard_only sends Standard-only NegReq and reads server verdict."""

    def test_standard_only_accepted_confirms_nla_bypass(self):
        captured: list[bytes] = []
        def _handle(c):
            captured.append(c.recv(4096))
            c.sendall(_rdp_negotiation_response(0))
        srv = _TCPResponder(_handle)
        try:
            r = rdp_svc.probe_standard_only(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertIsNotNone(r)
        self.assertIs(r["confirmed"], True)
        self.assertEqual(r["selected_protocol"], 0)
        self.assertEqual(r["phase"], "neg_response")
        self.assertIn("STANDARD_RDP only", r["evidence"])
        # Wire-shape: the CR we sent must have all-zero requestedProtocols
        # trailer, byte-for-byte matching the constant probe_standard_only ships.
        self.assertEqual(captured[0], rdp_svc._X224_CR_STANDARD_ONLY)
        self.assertTrue(all(b == 0 for b in captured[0][15:]))

    def test_ssl_required_failure_refutes_nla_bypass(self):
        srv = _TCPResponder(
            lambda c: (c.recv(4096), c.sendall(_rdp_negotiation_failure(0x01))))
        try:
            r = rdp_svc.probe_standard_only(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertIsNotNone(r)
        self.assertIs(r["confirmed"], False)
        self.assertEqual(r["failure_code"], 0x01)
        self.assertEqual(r["failure_reason"], "SSL_REQUIRED_BY_SERVER")
        self.assertEqual(r["phase"], "neg_failure")
        self.assertIn("NLA enforcement is real", r["evidence"])

    def test_hybrid_required_failure_refutes_nla_bypass(self):
        srv = _TCPResponder(
            lambda c: (c.recv(4096), c.sendall(_rdp_negotiation_failure(0x05))))
        try:
            r = rdp_svc.probe_standard_only(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertIsNotNone(r)
        self.assertIs(r["confirmed"], False)
        self.assertEqual(r["failure_reason"], "HYBRID_REQUIRED_BY_SERVER")

    def test_dead_port_returns_none(self):
        r = rdp_svc.probe_standard_only("127.0.0.1", 1, timeout=1)
        self.assertIsNone(r)

    def test_server_closes_without_replying_reports_inconclusive(self):
        # Server accepts, reads the CR, then closes (no reply). The recv()
        # returns b"" — the phase-1 shape check surfaces this as inconclusive
        # rather than crashing or claiming a decisive verdict.
        srv = _TCPResponder(lambda c: c.recv(4096))
        try:
            r = rdp_svc.probe_standard_only(srv.host, srv.port, timeout=1)
        finally:
            srv.close()
        self.assertIsNotNone(r)
        self.assertIsNone(r["confirmed"])
        self.assertEqual(r["phase"], "tpkt")

    def test_short_reply_reports_inconclusive(self):
        # Non-TPKT byte first -> inconclusive.
        srv = _TCPResponder(
            lambda c: (c.recv(4096), c.sendall(b"\x00" * 19)))
        try:
            r = rdp_svc.probe_standard_only(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertIsNotNone(r)
        self.assertIsNone(r["confirmed"])
        self.assertEqual(r["phase"], "tpkt")

    def test_server_upgrades_us_reports_inconclusive(self):
        # Server responds with selectedProtocol=0x02 despite requestedProtocols=0.
        srv = _TCPResponder(
            lambda c: (c.recv(4096), c.sendall(_rdp_negotiation_response(2))))
        try:
            r = rdp_svc.probe_standard_only(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertIsNotNone(r)
        self.assertIsNone(r["confirmed"])
        self.assertEqual(r["selected_protocol"], 2)


class RDPNoNlaT2FindingTest(unittest.TestCase):
    """The rdp_no_nla finding upgrades to depth_tier='t2' iff nla_confirm is
    positive; otherwise it stays at t1 with the T1 evidence unchanged."""

    def _host(self):
        from recce.core.models import Host, Port
        return Host(ip="10.0.0.5",
                    ports=[Port(portid=3389, service="ms-wbt-server",
                                state="open")])

    def test_confirmed_promotes_to_t2_with_evidence_in_detail(self):
        pr = {"reachable": True, "standard_rdp_accepted": True,
              "nla_required": False, "protocol_code": 0x00,
              "protocol": "STANDARD_RDP", "failure_reason": "",
              "nla_confirm": {"confirmed": True, "selected_protocol": 0,
                              "phase": "neg_response",
                              "evidence": "canary-t2-evidence-line"}}
        fs = rdp_svc.findings([self._host()], {("10.0.0.5", 3389): pr})
        f = next(f for f in fs if f["kind"] == "rdp_no_nla")
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("T2 confirming evidence", f["detail"])
        self.assertIn("canary-t2-evidence-line", f["detail"])

    def test_refuted_confirm_leaves_finding_at_t1(self):
        pr = {"reachable": True, "standard_rdp_accepted": True,
              "nla_required": False, "protocol_code": 0x00,
              "protocol": "STANDARD_RDP", "failure_reason": "",
              "nla_confirm": {"confirmed": False, "failure_code": 0x05,
                              "failure_reason": "HYBRID_REQUIRED_BY_SERVER",
                              "phase": "neg_failure",
                              "evidence": "hybrid-only-canary"}}
        fs = rdp_svc.findings([self._host()], {("10.0.0.5", 3389): pr})
        f = next(f for f in fs if f["kind"] == "rdp_no_nla")
        self.assertEqual(f["depth_tier"], "t1")
        # Inconclusive-refutation evidence is surfaced so the operator sees
        # the second-observation disagreement instead of silently dropping it.
        self.assertIn("did not decide", f["detail"])
        self.assertIn("hybrid-only-canary", f["detail"])

    def test_missing_confirm_stays_t1(self):
        pr = {"reachable": True, "standard_rdp_accepted": True,
              "nla_required": False, "protocol_code": 0x00,
              "protocol": "STANDARD_RDP", "failure_reason": ""}
        fs = rdp_svc.findings([self._host()], {("10.0.0.5", 3389): pr})
        f = next(f for f in fs if f["kind"] == "rdp_no_nla")
        self.assertEqual(f["depth_tier"], "t1")
        self.assertNotIn("T2 confirming evidence", f["detail"])
        self.assertNotIn("did not decide", f["detail"])


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
