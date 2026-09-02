"""Coverage-boosting tests for recce.services.rdp — the paths not already
exercised by tests/test_rdp_vnc.py.

Covers:
  * probe() NegFailure branch (X.224 type=0x03) and its NLA-required
    inference from HYBRID_REQUIRED_BY_SERVER (0x05).
  * probe() malformed-response branches (short body, non-TPKT reply,
    unrecognised NegPDU type).
  * The X.224 CR fixture — recce's connect bytes are exactly 19 (they
    used to be 18 and got rejected by strict-conformant xrdp).
  * _read_tsrequest bounded-read behaviour.
  * analyze() — full aggregator including runbook fold-out.
  * The rdp_targets() classifier.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import rdp as rdp_svc


# --- wire-shape helpers -----------------------------------------------------

def _rdp_neg_failure(failure_code: int) -> bytes:
    """TPKT + X.224 CC + RDP Negotiation FAILURE (type=0x03, len=8, code)."""
    neg = struct.pack("<BBHI", 0x03, 0x00, 8, failure_code)
    x224 = bytes([6 + len(neg), 0xd0, 0, 0, 0, 0, 0]) + neg
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


def _rdp_unknown_neg(ptype: int) -> bytes:
    """TPKT + X.224 CC + unknown NegPDU type (neither 0x02 nor 0x03)."""
    neg = struct.pack("<BBHI", ptype, 0x00, 8, 0)
    x224 = bytes([6 + len(neg), 0xd0, 0, 0, 0, 0, 0]) + neg
    return struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224


class _TCPResponder:
    """Loopback: accept one connection, read whatever's sent, reply once."""
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


# --- probe() NegFailure branch ----------------------------------------------

class NegFailureProbeTest(unittest.TestCase):
    def test_hybrid_required_marks_nla(self):
        """HYBRID_REQUIRED_BY_SERVER (0x05) → nla_required=True even though
        we got a NegFailure. This is the *secure* hardened-Windows path."""
        srv = _TCPResponder(
            lambda c: (c.recv(4096), c.sendall(_rdp_neg_failure(0x05))))
        try:
            pr = rdp_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["nla_required"])
        self.assertEqual(pr["failure_reason"], "HYBRID_REQUIRED_BY_SERVER")
        # No selected-protocol because this was a failure, not a response.
        self.assertIsNone(pr["protocol_code"])

    def test_ssl_required_by_server_captures_reason_without_nla_flag(self):
        """SSL_REQUIRED_BY_SERVER (0x01) — captured as a reason but the
        no-CredSSP-flag path leaves nla_required at its default False."""
        srv = _TCPResponder(
            lambda c: (c.recv(4096), c.sendall(_rdp_neg_failure(0x01))))
        try:
            pr = rdp_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["failure_reason"], "SSL_REQUIRED_BY_SERVER")
        self.assertFalse(pr["nla_required"])

    def test_unknown_failure_code_stringified(self):
        """A failure code recce doesn't recognise still surfaces as a hex
        string via the _FAILURE_CODES default branch."""
        srv = _TCPResponder(
            lambda c: (c.recv(4096), c.sendall(_rdp_neg_failure(0xAB))))
        try:
            pr = rdp_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertIn("unknown(0xab)", pr["failure_reason"])


# --- probe() malformed / edge responses -------------------------------------

class MalformedResponseTest(unittest.TestCase):
    def test_non_tpkt_reply_leaves_probe_at_defaults(self):
        # Server closes after writing garbage.
        srv = _TCPResponder(lambda c: (c.recv(4096), c.sendall(b"HELLO\n")))
        try:
            pr = rdp_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        # < 11 bytes OR first byte != 0x03 → probe returns un-flipped
        # reachable=False (the recv came back but wasn't TPKT).
        self.assertFalse(pr["reachable"])

    def test_short_tpkt_returns_reachable_but_no_negotiation(self):
        """A TPKT header with fewer than 19 bytes trips the len(data)<19
        guard after we've already flipped reachable=True."""
        # 12-byte reply: TPKT(4) + partial X.224 CC(8), truncated before
        # the negotiation payload.
        tpkt_only = struct.pack(">BBH", 3, 0, 12) + b"\x08\xd0\x00\x00\x00\x00\x00\x00"
        srv = _TCPResponder(lambda c: (c.recv(4096), c.sendall(tpkt_only)))
        try:
            pr = rdp_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertIsNone(pr["protocol_code"])

    def test_unknown_negpdu_type_leaves_no_finding_fields(self):
        # ptype 0x77 is neither NegResponse (0x02) nor NegFailure (0x03).
        srv = _TCPResponder(
            lambda c: (c.recv(4096), c.sendall(_rdp_unknown_neg(0x77))))
        try:
            pr = rdp_svc.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["nla_required"])
        self.assertEqual(pr["failure_reason"], "")


# --- X.224 CR fixture regression --------------------------------------------

class X224CRLengthTest(unittest.TestCase):
    def test_cr_is_exactly_the_tpkt_declared_length(self):
        """Regression guard for the "18 bytes but TPKT says 19" bug that
        strict-conformant xrdp rejected. TPKT header (bytes 2-3, big-endian)
        must always match len(_X224_CR)."""
        wire = rdp_svc._X224_CR
        tpkt_len = struct.unpack(">H", wire[2:4])[0]
        self.assertEqual(tpkt_len, len(wire),
                         f"TPKT length header says {tpkt_len} but packet is "
                         f"{len(wire)} bytes; strict RFC parsers reject.")
        # X.224 LI + all following bytes must match the LI value.
        self.assertEqual(wire[4] + 5, len(wire))


# --- _read_tsrequest bounded read -------------------------------------------

class ReadTSRequestBoundedTest(unittest.TestCase):
    def test_returns_full_sequence_when_length_matches(self):
        """A well-formed DER SEQUENCE — the reader stops as soon as the
        outer length is satisfied."""
        # SEQUENCE with a 5-byte body: 30 05 <body>
        payload = bytes([0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x06])
        srv = _TCPResponder(lambda c: (c.sendall(payload), c.recv(4096)))
        try:
            with socket.create_connection((srv.host, srv.port)) as s:
                out = rdp_svc._read_tsrequest(s, timeout=2)
        finally:
            srv.close()
        self.assertEqual(out, payload)

    def test_returns_empty_on_immediately_closed_socket(self):
        """A server that closes without sending anything — reader returns
        b"" without raising."""
        srv = _TCPResponder(lambda c: c.close())
        try:
            with socket.create_connection((srv.host, srv.port)) as s:
                out = rdp_svc._read_tsrequest(s, timeout=1)
        finally:
            srv.close()
        self.assertEqual(out, b"")


# --- rdp_targets classifier -------------------------------------------------

class TargetsTest(unittest.TestCase):
    def test_picks_3389_regardless_of_service_label(self):
        h = Host(ip="10.0.0.9",
                 ports=[Port(portid=3389, service="ms-wbt-server"),
                        Port(portid=22, service="ssh")])
        t = rdp_svc.rdp_targets([h])
        self.assertEqual(len(t), 1)
        self.assertEqual(t[0]["port"], 3389)

    def test_picks_by_service_label_when_port_is_atypical(self):
        h = Host(ip="10.0.0.9", ports=[Port(portid=13389, service="rdp")])
        t = rdp_svc.rdp_targets([h])
        self.assertEqual(t[0]["port"], 13389)

    def test_ms_term_serv_label_also_matches(self):
        h = Host(ip="10.0.0.9", ports=[Port(portid=3389, service="ms-term-serv")])
        self.assertEqual(len(rdp_svc.rdp_targets([h])), 1)


# --- analyze() aggregator ---------------------------------------------------

class AnalyzeTest(unittest.TestCase):
    def test_active_probe_folds_state_into_targets(self):
        """analyze() feeds targets through probe() and stamps the flat
        state fields (reachable / standard_rdp_accepted / nla_required)
        onto each target dict for the caller."""
        h = Host(ip="10.0.0.9",
                 ports=[Port(portid=3389, service="ms-wbt-server")])
        canned = {"reachable": True, "protocol": "STANDARD_RDP",
                  "protocol_code": 0, "failure_reason": "",
                  "nla_required": False, "standard_rdp_accepted": True}
        # Bypass network by stubbing probe(); avoid the CredSSP roundtrip
        # by never setting the CredSSP flag on protocol_code.
        orig_probe = rdp_svc.probe
        rdp_svc.probe = lambda ip, port: canned
        try:
            out = rdp_svc.analyze([h], active=True)
        finally:
            rdp_svc.probe = orig_probe
        self.assertEqual(out["stats"]["targets"], 1)
        self.assertGreaterEqual(out["stats"]["findings"], 1)
        t = out["targets"][0]
        self.assertTrue(t["reachable"])
        self.assertTrue(t["standard_rdp_accepted"])
        self.assertFalse(t["nla_required"])
        # analyze() also builds runbooks for every target.
        self.assertEqual(len(out["runbooks"]), 1)

    def test_active_probe_with_credssp_triggers_ntlm_extra_probe(self):
        """When the base probe reports a CredSSP-capable protocol_code,
        analyze() takes the extra probe_ntlm_info roundtrip and folds any
        result into the probe dict as ntlm_info."""
        h = Host(ip="10.0.0.9", ports=[Port(portid=3389, service="rdp")])
        canned_probe = {"reachable": True, "protocol": "CredSSP+SSL",
                        "protocol_code": 0x03, "failure_reason": "",
                        "nla_required": True, "standard_rdp_accepted": False}
        ntlm_out = {"os_version": "10.0.19041", "ntlm_revision": 15}
        orig_probe = rdp_svc.probe
        orig_ntlm = rdp_svc.probe_ntlm_info
        rdp_svc.probe = lambda ip, port: canned_probe
        rdp_svc.probe_ntlm_info = lambda ip, port: ntlm_out
        try:
            out = rdp_svc.analyze([h], active=True)
        finally:
            rdp_svc.probe = orig_probe
            rdp_svc.probe_ntlm_info = orig_ntlm
        # analyze() stamps the ntlm_info on the target for downstream
        # consumers (webui, findings).
        self.assertEqual(out["targets"][0].get("ntlm_info"), ntlm_out)

    def test_active_probe_with_std_rdp_triggers_confirm_roundtrip(self):
        """When the base probe reports Standard RDP accepted, analyze()
        takes the extra probe_standard_only confirm roundtrip and stashes
        the verdict under nla_confirm."""
        h = Host(ip="10.0.0.9", ports=[Port(portid=3389, service="rdp")])
        canned_probe = {"reachable": True, "protocol": "STANDARD_RDP",
                        "protocol_code": 0, "failure_reason": "",
                        "nla_required": False, "standard_rdp_accepted": True}
        confirm = {"confirmed": True, "selected_protocol": 0,
                   "phase": "neg_response", "evidence": "std reachable"}
        orig_probe = rdp_svc.probe
        orig_confirm = rdp_svc.probe_standard_only
        rdp_svc.probe = lambda ip, port: canned_probe
        rdp_svc.probe_standard_only = lambda ip, port: confirm
        try:
            out = rdp_svc.analyze([h], active=True)
        finally:
            rdp_svc.probe = orig_probe
            rdp_svc.probe_standard_only = orig_confirm
        pr = list(out["probes"].values())[0]
        self.assertEqual(pr["nla_confirm"], confirm)

    def test_inactive_analyze_yields_empty_probes(self):
        h = Host(ip="10.0.0.9", ports=[Port(portid=3389, service="rdp")])
        out = rdp_svc.analyze([h], active=False)
        self.assertEqual(out["probes"], {})
        self.assertEqual(out["stats"]["findings"], 0)


if __name__ == "__main__":
    unittest.main()
