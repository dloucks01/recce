"""T2 SAFE-proof tests for CVE-2013-4786 (cipher suite 0).

Covers `ipmi.cipher_zero_session_proof()` and its integration into `probe()`
and `findings()` at depth_tier="t2":

  * vulnerable BMC — Open Session Response status=0x00, echoed auth_alg=0
    → session_accepted=True, evidence populated, finding tier="t2"
  * patched BMC   — Open Session Response status!=0 (or accepted auth alg
    != 0) → session_accepted=False, existing t1 finding still emitted
  * timeout       — no responder → session_accepted=False, probe stays
    on the t1 confirmed finding via the App/0x54 cipher-suites answer

All fixtures assembled from IPMI 2.0 §13.19 Table 13-17. No live network:
each test binds a loopback UDP socket that replies to specific IPMI cmds.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import ipmi


# --- Shared fake BMC: dispatch by IPMI 1.5 cmd byte OR RMCP+ payload type ---
class _MultiBMC:
    """Loopback UDP responder that dispatches on (cmd, payload_type).

    Session-less IPMI 1.5 requests have cmd at fixed offset (byte 19 —
    RMCP(4) + session_hdr(9) + msg_len(1) + rqAddr(1) + netFn(1) + csum(1)
    + rqSeq(1) + rqAddr(1) = 19). RMCP+ requests (auth_type=6 at byte 4)
    are dispatched by payload type at byte 5 (masked to 0x3f).
    """

    def __init__(self, ipmi15_replies: dict[int, bytes],
                 rmcpplus_replies: dict[int, bytes] | None = None):
        self._replies = dict(ipmi15_replies)
        self._plus = dict(rmcpplus_replies or {})
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.host, self.port = self._sock.getsockname()
        self._stop = False
        # Record every received IPMI 1.5 cmd for assertions.
        self.seen_cmds: list[int] = []
        self.seen_plus: list[int] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                data, addr = self._sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            if len(data) < 6:
                continue
            # RMCP+ (auth_type=0x06 at session header byte 0 == pkt[4])
            if data[4] == 0x06:
                payload_type = data[5] & 0x3f
                self.seen_plus.append(payload_type)
                reply = self._plus.get(payload_type)
            else:
                cmd = data[19] if len(data) >= 20 else None
                if cmd is not None:
                    self.seen_cmds.append(cmd)
                reply = self._replies.get(cmd) if cmd is not None else None
            if reply:
                self._sock.sendto(reply, addr)

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


# --- Fixture builders -------------------------------------------------------
def _open_session_response(status: int, accepted_auth: int,
                           accepted_integrity: int = 0,
                           accepted_conf: int = 0,
                           truncate_alg_payloads: bool = False) -> bytes:
    """Build an RMCP+ Open Session Response per IPMI 2.0 §13.19.

    Layout of payload (36 bytes with all three algorithm payloads):
      0  message tag
      1  RMCP+ status
      2  max priv (echoed)
      3  reserved
      4-7 remote console session ID (echo — we return the fixed sentinel
          0xa0a0a0a0 for tests; the parser doesn't validate this since our
          proof only checks status + accepted auth alg).
      8-11 managed system session ID
      12-19 auth payload: [type=0, rsvd, rsvd, len=8, alg, rsvd*3]
      20-27 integrity payload
      28-35 confidentiality payload
    """
    tag = 0x00
    max_priv = 0x04
    remote_sid = 0xa0a0a0a0
    managed_sid = 0x11223344
    header = (
        bytes([tag, status & 0xff, max_priv, 0x00])
        + struct.pack("<I", remote_sid)
        + struct.pack("<I", managed_sid)
    )
    if truncate_alg_payloads:
        # Keep the payload at the 16-byte minimum the base parser accepts
        # (12-byte header + 4 padding bytes) but omit the algorithm
        # payloads a real BMC would append. Simulates a refusal response
        # that stops after the session IDs.
        payload = header + b"\x00\x00\x00\x00"
    else:
        auth_pl = bytes([0x00, 0x00, 0x00, 0x08,
                         accepted_auth & 0xff, 0x00, 0x00, 0x00])
        int_pl = bytes([0x01, 0x00, 0x00, 0x08,
                        accepted_integrity & 0xff, 0x00, 0x00, 0x00])
        conf_pl = bytes([0x02, 0x00, 0x00, 0x08,
                         accepted_conf & 0xff, 0x00, 0x00, 0x00])
        payload = header + auth_pl + int_pl + conf_pl
    # RMCP header + RMCP+ session header (auth=6, payload_type=0x11 open
    # session response, session_id=0, seq=0, length=<payload>).
    rmcp = b"\x06\x00\xff\x07"
    session = (b"\x06" + bytes([0x11])
               + struct.pack("<I", 0) + struct.pack("<I", 0)
               + struct.pack("<H", len(payload)))
    return rmcp + session + payload


# --- Direct unit tests ------------------------------------------------------
class CipherZeroSessionProofTest(unittest.TestCase):
    def test_vulnerable_bmc_returns_session_accepted(self):
        # Status = 0x00, accepted auth = 0 → session-negotiation engine
        # accepts cipher-0.
        srv = _MultiBMC(
            {},
            rmcpplus_replies={
                ipmi._PAYLOAD_OPEN_SESSION_REQ:
                    _open_session_response(status=0, accepted_auth=0),
            },
        )
        try:
            r = ipmi.cipher_zero_session_proof(srv.host, srv.port,
                                               timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertTrue(r["session_accepted"])
        self.assertEqual(r["accepted_auth_alg"], 0)
        self.assertEqual(r["status"], 0)
        self.assertIn("cipher suite 0", r["evidence"].lower())

    def test_patched_bmc_refuses_with_nonzero_status(self):
        # Status = 0x11 "no matching cipher suite" — the negotiation engine
        # rejects cipher-0. session_accepted must be False, evidence must
        # explain the refusal.
        srv = _MultiBMC(
            {},
            rmcpplus_replies={
                ipmi._PAYLOAD_OPEN_SESSION_REQ:
                    _open_session_response(status=0x11, accepted_auth=1),
            },
        )
        try:
            r = ipmi.cipher_zero_session_proof(srv.host, srv.port,
                                               timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertFalse(r["session_accepted"])
        self.assertEqual(r["status"], 0x11)
        self.assertIn("refused", r["error"].lower())

    def test_bmc_downgrades_to_nonzero_alg_is_not_a_proof(self):
        # Some BMCs accept the session (status=0) but SELECT a different
        # auth alg from the one requested. That MUST NOT count as cipher-0
        # proof — cipher-0 was offered by us and not chosen by the BMC.
        srv = _MultiBMC(
            {},
            rmcpplus_replies={
                ipmi._PAYLOAD_OPEN_SESSION_REQ:
                    _open_session_response(status=0, accepted_auth=1),
            },
        )
        try:
            r = ipmi.cipher_zero_session_proof(srv.host, srv.port,
                                               timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertFalse(r["session_accepted"])
        self.assertEqual(r["accepted_auth_alg"], 1)
        self.assertIn("advertised but not selectable", r["evidence"].lower())

    def test_timeout_when_no_responder(self):
        # Closed port → recvfrom raises socket.timeout. session_accepted
        # False, error mentions timeout.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = ipmi.cipher_zero_session_proof("127.0.0.1", port, timeout=0.4)
        self.assertFalse(r["reachable"])
        self.assertFalse(r["session_accepted"])
        self.assertIn("timeout", r["error"].lower())

    def test_truncated_open_session_response_still_parses_status(self):
        # Some BMCs truncate the alg payloads on refusal. Parser must not
        # raise and must surface status != 0 with accepted_auth_alg=None.
        srv = _MultiBMC(
            {},
            rmcpplus_replies={
                ipmi._PAYLOAD_OPEN_SESSION_REQ:
                    _open_session_response(status=0x02, accepted_auth=0,
                                           truncate_alg_payloads=True),
            },
        )
        try:
            r = ipmi.cipher_zero_session_proof(srv.host, srv.port,
                                               timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertFalse(r["session_accepted"])
        self.assertEqual(r["status"], 0x02)
        self.assertIsNone(r["accepted_auth_alg"])


# --- End-to-end integration: probe() + findings() =========================
def _ipmi15_reply(cmd: int, data: bytes) -> bytes:
    """Copy of the helper in test_ipmi_extra.py — inlined here so this test
    module does not import from a peer test file."""
    rq_addr = 0x81
    netfn_resp = (0x07 << 2)
    csum1 = (-(rq_addr + netfn_resp)) & 0xff
    rs_addr = 0x20
    rs_seq = 0x00
    body = bytes([rs_addr, rs_seq, cmd, 0x00]) + data
    csum2 = (-sum(body)) & 0xff
    msg = bytes([rq_addr, netfn_resp, csum1]) + body + bytes([csum2])
    rmcp = b"\x06\x00\xff\x07"
    sess = b"\x00" + b"\x00" * 4 + b"\x00" * 4
    return rmcp + sess + bytes([len(msg)]) + msg


def _build_gcac_response(auth_types: int, auth_status: int,
                        ext_caps: int) -> bytes:
    hdr = bytes([0x06, 0x00, 0xff, 0x07])
    sess = bytes([0x00]) + b"\x00" * 4 + b"\x00" * 4
    msg = bytes([
        0x81, 0x1c, 0x63, 0x20, 0x00, 0x38,
        0x00, 0x01,
        auth_types & 0xff, auth_status & 0xff, ext_caps & 0xff,
        0x00, 0x00, 0x00,
    ])
    return hdr + sess + bytes([len(msg)]) + msg


class ProbeAndFindingsT2Test(unittest.TestCase):
    def test_probe_flags_session_accepted_when_negotiation_agrees(self):
        # GCAC: none+password, IPMI 2.0. Cipher suites: cipher-0 confirmed.
        # Open Session Response: status=0, auth=0 → t2 promotion fires.
        srv = _MultiBMC(
            {
                0x38: _build_gcac_response(auth_types=0x11,
                                           auth_status=0x00,
                                           ext_caps=0x01),
                0x54: _ipmi15_reply(0x54, bytes([0x0e])
                                    + bytes.fromhex("c000004080")),
            },
            rmcpplus_replies={
                ipmi._PAYLOAD_OPEN_SESSION_REQ:
                    _open_session_response(status=0, accepted_auth=0),
            },
        )
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["cipher_zero"])
        self.assertTrue(p["cipher_zero_confirmed"])
        self.assertTrue(p["cipher_zero_session_accepted"])
        self.assertIn("cipher suite 0",
                      p["cipher_zero_session_evidence"].lower())

        host = Host(ip="10.0.0.9",
                    ports=[Port(portid=623, protocol="udp",
                                state="open", service="ipmi")])
        fs = ipmi.findings([host], {("10.0.0.9", 623): p})
        cz = [f for f in fs if f["kind"] == "ipmi_cipher_zero_confirmed"]
        self.assertEqual(len(cz), 1)
        self.assertEqual(cz[0]["depth_tier"], "t2")
        self.assertIn("PROVEN usable", cz[0]["detail"])

    def test_probe_stays_at_t1_when_negotiation_refuses(self):
        # GCAC + Cipher Suites both confirm cipher-0 in the catalog, but the
        # BMC REFUSES an actual cipher-0 session negotiation (status=0x11).
        # The finding must remain at depth_tier="t1", not silently downgrade
        # and not incorrectly claim t2.
        srv = _MultiBMC(
            {
                0x38: _build_gcac_response(auth_types=0x11,
                                           auth_status=0x00,
                                           ext_caps=0x01),
                0x54: _ipmi15_reply(0x54, bytes([0x0e])
                                    + bytes.fromhex("c000004080")),
            },
            rmcpplus_replies={
                ipmi._PAYLOAD_OPEN_SESSION_REQ:
                    _open_session_response(status=0x11, accepted_auth=1),
            },
        )
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(p["cipher_zero_confirmed"])
        self.assertFalse(p["cipher_zero_session_accepted"])

        host = Host(ip="10.0.0.9",
                    ports=[Port(portid=623, protocol="udp",
                                state="open", service="ipmi")])
        fs = ipmi.findings([host], {("10.0.0.9", 623): p})
        cz = [f for f in fs if f["kind"] == "ipmi_cipher_zero_confirmed"]
        self.assertEqual(len(cz), 1)
        self.assertEqual(cz[0]["depth_tier"], "t1")

    def test_probe_stays_at_t1_when_open_session_response_times_out(self):
        # GCAC + Cipher Suites confirm cipher-0 in the catalog, but the BMC
        # does not answer the Open Session Request at all. Existing t1
        # ipmi_cipher_zero_confirmed finding must still fire — additive
        # T2 promotion must NEVER break the T1 signal on timeout.
        srv = _MultiBMC(
            {
                0x38: _build_gcac_response(auth_types=0x11,
                                           auth_status=0x00,
                                           ext_caps=0x01),
                0x54: _ipmi15_reply(0x54, bytes([0x0e])
                                    + bytes.fromhex("c000004080")),
            },
            rmcpplus_replies={},                # no reply → timeout
        )
        try:
            # Short but > _CIPHER0_PROOF_MIN clamp — proxy.scaled applies
            # inside the function, so real wall-clock cap is 2s * 2.5 when
            # a proxy is set, unbounded otherwise. Tests run direct → ~2s.
            p = ipmi.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(p["cipher_zero_confirmed"])
        self.assertFalse(p["cipher_zero_session_accepted"])

        host = Host(ip="10.0.0.9",
                    ports=[Port(portid=623, protocol="udp",
                                state="open", service="ipmi")])
        fs = ipmi.findings([host], {("10.0.0.9", 623): p})
        cz = [f for f in fs if f["kind"] == "ipmi_cipher_zero_confirmed"]
        self.assertEqual(len(cz), 1)
        self.assertEqual(cz[0]["depth_tier"], "t1")


if __name__ == "__main__":
    unittest.main()
