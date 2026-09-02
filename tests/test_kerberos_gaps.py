"""Pre-auth password spray and passive KDC probe (skew + FAST + crealm).

Fixtures are DER built by hand, deliberately NOT via recce's encoders, so a
decoder change cannot be masked by a symmetric fixture bug. All network I/O is
monkey-patched at the module boundary (`K._send_recv`)."""
import time
import unittest

from recce.ad import kerberos as K


# --- hand-rolled DER helpers (do NOT use recce encoders) ---------------------

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content


def _der_int(n):
    if n == 0:
        body = b"\x00"
    else:
        body = b""
        v = n
        while v:
            body = bytes([v & 0xFF]) + body
            v >>= 8
        if body[0] & 0x80:
            body = b"\x00" + body
    return _tlv(0x02, body)


def _der_seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _der_ctx(n, inner):
    return _tlv(0xA0 | n, inner)


def _der_octet(b):
    return _tlv(0x04, b)


def _der_gstr(s):
    return _tlv(0x1B, s.encode("utf-8"))


def _der_gtime(s):
    return _tlv(0x18, s.encode("ascii"))


def _krb_error(code, stime="", crealm="", padata_types=(), padata_values=None):
    """Build a KRB-ERROR ([APPLICATION 30]) with optional stime[4], crealm[9],
    and PA-DATA entries. `padata_types` is the SEQUENCE of type numbers; by
    default each carries an empty value. Pass `padata_values` (a dict of
    type_number -> bytes) to attach non-empty octet-string values to specific
    entries — used by the FAST T2-evidence tests where the presence of a real
    PA-FX-FAST-REPLY value must round-trip through kdc_probe."""
    parts = [_der_ctx(0, _der_int(5)),                 # pvno
             _der_ctx(1, _der_int(30))]                # msg-type
    if stime:
        parts.append(_der_ctx(4, _der_gtime(stime)))
    parts.append(_der_ctx(6, _der_int(code)))
    if crealm:
        parts.append(_der_ctx(9, _der_gstr(crealm)))
    if padata_types:
        vals = dict(padata_values or {})
        method_data = _der_seq(*[
            _der_seq(_der_ctx(1, _der_int(t)),
                     _der_ctx(2, _der_octet(vals.get(t, b""))))
            for t in padata_types
        ])
        parts.append(_der_ctx(12, _der_octet(method_data)))
    body = _der_seq(*parts)
    return _tlv(0x7E, body)


def _fake_asrep():
    """A minimal [APPLICATION 11] AS-REP envelope. Spray only classifies on the
    outer tag (0x6B), so an empty inner SEQUENCE is enough."""
    return _tlv(0x6B, _der_seq())


def _patch_wire(testcase, payload):
    orig = K._send_recv
    K._send_recv = lambda *a, **kw: payload
    testcase.addCleanup(lambda: setattr(K, "_send_recv", orig))


# --- pre-auth password spray -------------------------------------------------

class KerberosSprayTest(unittest.TestCase):
    def test_wrong_password_is_bad_password(self):
        _patch_wire(self, _krb_error(K.KDC_ERR_PREAUTH_FAILED))
        r = K.spray_user("127.0.0.1", "CORP.LOCAL", "alice", password="wrong")
        self.assertEqual(r["state"], "bad_password")
        self.assertEqual(r["code"], K.KDC_ERR_PREAUTH_FAILED)

    def test_correct_password_reads_as_success(self):
        _patch_wire(self, _fake_asrep())
        r = K.spray_user("127.0.0.1", "CORP.LOCAL", "alice", password="right")
        self.assertEqual(r["state"], "success")

    def test_locked_account_reads_as_locked(self):
        _patch_wire(self, _krb_error(K.KDC_ERR_CLIENT_REVOKED))
        r = K.spray_user("127.0.0.1", "CORP.LOCAL", "alice", password="pw")
        self.assertEqual(r["state"], "locked")

    def test_unknown_user_is_distinguished_from_bad_password(self):
        _patch_wire(self, _krb_error(K.KDC_ERR_PRINCIPAL_UNKNOWN))
        r = K.spray_user("127.0.0.1", "CORP.LOCAL", "ghost", password="pw")
        self.assertEqual(r["state"], "unknown_user")

    def test_unreachable_kdc_is_no_reply(self):
        _patch_wire(self, None)
        r = K.spray_user("127.0.0.1", "CORP.LOCAL", "alice", password="pw")
        self.assertEqual(r["state"], "no_reply")

    def test_nthash_is_accepted_alongside_password(self):
        _patch_wire(self, _fake_asrep())
        r = K.spray_user("127.0.0.1", "CORP.LOCAL", "alice",
                         nthash="8846f7eaee8fb117ad06bdd830b7586c")
        self.assertEqual(r["state"], "success")

    def test_spray_stops_on_lockout_by_default(self):
        # Every reply is 'locked' - spray should stop after the first user.
        _patch_wire(self, _krb_error(K.KDC_ERR_CLIENT_REVOKED))
        users = ["alice", "bob", "carol"]
        out = K.spray("127.0.0.1", "CORP.LOCAL", users, password="pw")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["state"], "locked")

    def test_spray_continues_past_lockout_when_disabled(self):
        _patch_wire(self, _krb_error(K.KDC_ERR_CLIENT_REVOKED))
        out = K.spray("127.0.0.1", "CORP.LOCAL", ["a", "b"], password="pw",
                      stop_on_lockout=False)
        self.assertEqual(len(out), 2)

    def test_findings_flag_privileged_success_as_critical(self):
        rs = [{"user": "admin", "state": "success"},
              {"user": "bob", "state": "success"},
              {"user": "eve", "state": "bad_password"}]
        fs = K.spray_findings("10.0.0.1", "CORP.LOCAL", rs,
                              privileged={"admin"})
        # one per success (2), none for bad_password
        self.assertEqual(len(fs), 2)
        sevs = {f["severity"] for f in fs}
        self.assertEqual(sevs, {"critical", "high"})
        for f in fs:
            self.assertEqual(f["kind"], "kerberos_spray_success")
            self.assertTrue(f["narrative"])                # narrative wired


# --- passive KDC probe (stime + crealm + FAST) -------------------------------

class KerberosKdcProbeTest(unittest.TestCase):
    def test_reads_stime_crealm_and_computes_skew(self):
        # A stime 60s behind local wall clock.
        stime = time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() - 60))
        _patch_wire(self, _krb_error(K.KDC_ERR_PREAUTH_REQUIRED,
                                     stime=stime, crealm="CORP.LOCAL"))
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL", user="krbtgt")
        self.assertTrue(r["reachable"])
        self.assertEqual(r["code"], K.KDC_ERR_PREAUTH_REQUIRED)
        self.assertEqual(r["stime"], stime)
        self.assertEqual(r["crealm"], "CORP.LOCAL")
        # skew is ~60s within a small margin for test execution jitter
        self.assertGreaterEqual(r["skew_seconds"], 55)
        self.assertLessEqual(r["skew_seconds"], 70)
        self.assertFalse(r["has_fast"])

    def test_fast_advertised_flag_is_set(self):
        _patch_wire(self, _krb_error(K.KDC_ERR_PREAUTH_REQUIRED,
                                     padata_types=(K._PADATA_FX_FAST, 19)))
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL")
        self.assertTrue(r["has_fast"])
        self.assertIn(K._PADATA_FX_FAST, r["padata_types"])

    def test_no_fast_when_only_other_padata(self):
        _patch_wire(self, _krb_error(K.KDC_ERR_PREAUTH_REQUIRED,
                                     padata_types=(19,)))
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL")
        self.assertFalse(r["has_fast"])

    def test_unreachable_kdc_returns_reachable_false(self):
        _patch_wire(self, None)
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL")
        self.assertFalse(r["reachable"])
        self.assertEqual(r["padata_types"], [])

    def test_as_rep_reply_leaves_defaults(self):
        # If the KDC issues an AS-REP (no pre-auth account), there is no
        # KRB-ERROR body to mine - probe returns reachable but nothing else.
        _patch_wire(self, _fake_asrep())
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL")
        self.assertTrue(r["reachable"])
        self.assertEqual(r["code"], None)
        self.assertEqual(r["crealm"], "")

    def test_probe_findings_flag_fast(self):
        probe = {"reachable": True, "has_fast": True, "skew_seconds": 0,
                 "stime": "20260101000000Z"}
        fs = K.kdc_probe_findings("10.0.0.1", probe)
        kinds = {f["kind"] for f in fs}
        self.assertIn("kerberos_fast_enforced", kinds)

    # --- T2 promotion: real PA-FX-FAST value bytes on the wire ------------

    def test_probe_captures_fast_value_bytes(self):
        """A KRB-ERROR whose PA-FX-FAST padata carries a real octet-string
        value round-trips into probe['fast_value_hex']. This is the T2 wire
        evidence — the KDC actually returned a PA-FX-FAST-REPLY structure,
        not just an empty type=136 stub."""
        # Deliberately non-trivial bytes so a hex round-trip is visible.
        fast_value = bytes.fromhex("30820102a003020101")
        payload = _krb_error(K.KDC_ERR_PREAUTH_REQUIRED,
                             padata_types=(K._PADATA_FX_FAST, 19),
                             padata_values={K._PADATA_FX_FAST: fast_value})
        _patch_wire(self, payload)
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL")
        self.assertTrue(r["has_fast"])
        self.assertEqual(r["fast_value_hex"], fast_value.hex())

    def test_probe_fast_value_empty_when_no_value(self):
        """An advertised-but-empty PA-FX-FAST entry (has_fast True) leaves
        fast_value_hex empty — the T1 path."""
        _patch_wire(self, _krb_error(K.KDC_ERR_PREAUTH_REQUIRED,
                                     padata_types=(K._PADATA_FX_FAST,)))
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL")
        self.assertTrue(r["has_fast"])
        self.assertEqual(r["fast_value_hex"], "")

    def test_probe_fast_value_absent_when_no_fast(self):
        """Without PA-FX-FAST at all, fast_value_hex is empty and defaults
        do not leak from an unrelated padata type."""
        _patch_wire(self, _krb_error(K.KDC_ERR_PREAUTH_REQUIRED,
                                     padata_types=(19,),
                                     padata_values={19: b"\x01\x02\x03"}))
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL")
        self.assertFalse(r["has_fast"])
        self.assertEqual(r["fast_value_hex"], "")

    def test_probe_fast_value_empty_on_timeout(self):
        """A timeout / unreachable KDC leaves has_fast False and
        fast_value_hex empty — no fabricated evidence."""
        _patch_wire(self, None)
        r = K.kdc_probe("127.0.0.1", "CORP.LOCAL")
        self.assertFalse(r["has_fast"])
        self.assertEqual(r["fast_value_hex"], "")

    def test_fast_finding_promoted_to_t2_with_value_bytes(self):
        """When probe['fast_value_hex'] is non-empty, the FAST finding is
        emitted at depth_tier=t2 and the detail carries the hex evidence."""
        fast_hex = "30820102a003020101"
        probe = {"reachable": True, "has_fast": True, "skew_seconds": 0,
                 "stime": "20260101000000Z", "fast_value_hex": fast_hex}
        fs = K.kdc_probe_findings("10.0.0.1", probe)
        fast = [f for f in fs if f["kind"] == "kerberos_fast_enforced"]
        self.assertEqual(len(fast), 1)
        self.assertEqual(fast[0]["depth_tier"], "t2")
        self.assertIn(fast_hex, fast[0]["detail"])
        # Also carries the byte-count preamble so the evidence is legible.
        self.assertIn(f"{len(fast_hex) // 2} bytes", fast[0]["detail"])

    def test_fast_finding_stays_t1_without_value_bytes(self):
        """Absent wire evidence, the FAST finding stays at t1 — the audit's
        'defensive posture, deterministic but nothing more to prove' state."""
        probe = {"reachable": True, "has_fast": True, "skew_seconds": 0,
                 "stime": "20260101000000Z", "fast_value_hex": ""}
        fs = K.kdc_probe_findings("10.0.0.1", probe)
        fast = [f for f in fs if f["kind"] == "kerberos_fast_enforced"]
        self.assertEqual(len(fast), 1)
        self.assertEqual(fast[0]["depth_tier"], "t1")

    def test_fast_finding_stays_t1_when_key_missing(self):
        """Legacy probe dicts (before fast_value_hex existed) must not crash
        or spuriously promote — a missing key is treated as 'no evidence'."""
        probe = {"reachable": True, "has_fast": True, "skew_seconds": 0,
                 "stime": "20260101000000Z"}
        fs = K.kdc_probe_findings("10.0.0.1", probe)
        fast = [f for f in fs if f["kind"] == "kerberos_fast_enforced"]
        self.assertEqual(len(fast), 1)
        self.assertEqual(fast[0]["depth_tier"], "t1")

    def test_fast_finding_t2_evidence_slice_bounded(self):
        """A large FAST-REPLY value is trimmed in the finding detail so it
        cannot dominate the write-up; the full hex remains available on the
        probe dict for downstream tooling."""
        big = ("ab" * 200)                                 # 400-char hex
        probe = {"reachable": True, "has_fast": True, "skew_seconds": 0,
                 "stime": "20260101000000Z", "fast_value_hex": big}
        fs = K.kdc_probe_findings("10.0.0.1", probe)
        fast = [f for f in fs if f["kind"] == "kerberos_fast_enforced"]
        self.assertEqual(fast[0]["depth_tier"], "t2")
        self.assertIn("...", fast[0]["detail"])
        # The 128-char preview leads with the value's real prefix.
        self.assertIn(big[:128], fast[0]["detail"])

    def test_probe_findings_flag_skew_over_threshold(self):
        probe = {"reachable": True, "has_fast": False, "skew_seconds": 3600,
                 "stime": "20260101000000Z"}
        fs = K.kdc_probe_findings("10.0.0.1", probe)
        kinds = {f["kind"] for f in fs}
        self.assertEqual(kinds, {"kdc_time_skew"})

    def test_probe_findings_ignore_small_skew(self):
        probe = {"reachable": True, "has_fast": False, "skew_seconds": 30,
                 "stime": "20260101000000Z"}
        self.assertEqual(K.kdc_probe_findings("10.0.0.1", probe), [])

    def test_probe_findings_empty_when_unreachable(self):
        self.assertEqual(K.kdc_probe_findings("10.0.0.1",
                                              {"reachable": False}), [])


# --- kpasswd exposure probe (TCP/464, RFC 3244) ------------------------------

class KerberosKpasswdProbeTest(unittest.TestCase):
    """Bare TCP connect to 464. `_kpasswd_reachable` is the isolated seam so
    tests never open a real socket."""

    def _patch_reach(self, value):
        orig = K._kpasswd_reachable
        K._kpasswd_reachable = lambda *a, **kw: value
        self.addCleanup(lambda: setattr(K, "_kpasswd_reachable", orig))

    def test_reachable_port_reports_reachable_true(self):
        self._patch_reach(True)
        r = K.kpasswd_probe("127.0.0.1")
        self.assertTrue(r["reachable"])

    def test_filtered_port_reports_reachable_false(self):
        self._patch_reach(False)
        r = K.kpasswd_probe("127.0.0.1")
        self.assertFalse(r["reachable"])

    def test_finding_emitted_when_reachable(self):
        fs = K.kpasswd_findings("10.0.0.1", {"reachable": True})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["kind"], "kpasswd_exposed")
        self.assertEqual(fs[0]["severity"], "medium")
        self.assertEqual(fs[0]["depth_tier"], "t1")
        self.assertEqual(fs[0]["target"], "10.0.0.1:464")
        self.assertTrue(fs[0]["exploit_note"])
        self.assertTrue(fs[0]["narrative"])                # narrative wired
        self.assertIn("CWE-306", fs[0]["cwes"])

    def test_no_finding_when_port_filtered(self):
        self.assertEqual(K.kpasswd_findings("10.0.0.1",
                                            {"reachable": False}), [])

    def test_no_finding_on_empty_probe(self):
        self.assertEqual(K.kpasswd_findings("10.0.0.1", {}), [])


# --- UDP transport probe (RFC 4120 sec 7.2.1) ------------------------------------

class KerberosUdpTransportTest(unittest.TestCase):
    """AS-REQ over UDP/88. `_send_recv_udp` is monkeypatched at the module
    boundary so the tests never touch a real UDP socket."""

    def _patch_udp(self, payload):
        orig = K._send_recv_udp
        K._send_recv_udp = lambda *a, **kw: payload
        self.addCleanup(lambda: setattr(K, "_send_recv_udp", orig))

    def test_krb_error_over_udp_reports_reachable(self):
        # A pre-auth-required reply for krbtgt is what an AD DC returns to a
        # pre-auth-less AS-REQ — reachable, not too-big.
        self._patch_udp(_krb_error(K.KDC_ERR_PREAUTH_REQUIRED,
                                   crealm="CORP.LOCAL"))
        r = K.udp_transport_probe("127.0.0.1", "CORP.LOCAL")
        self.assertTrue(r["reachable"])
        self.assertEqual(r["code"], K.KDC_ERR_PREAUTH_REQUIRED)
        self.assertFalse(r["too_big"])

    def test_response_too_big_flag_from_kdc(self):
        # KRB_ERR_RESPONSE_TOO_BIG (52) is the AD-vs-MIT fingerprint on UDP.
        self._patch_udp(_krb_error(K.KRB_ERR_RESPONSE_TOO_BIG))
        r = K.udp_transport_probe("127.0.0.1", "CORP.LOCAL")
        self.assertTrue(r["reachable"])
        self.assertTrue(r["too_big"])
        self.assertEqual(r["code"], K.KRB_ERR_RESPONSE_TOO_BIG)

    def test_no_reply_reports_unreachable(self):
        # Patched / dropped UDP: no datagram back.
        self._patch_udp(None)
        r = K.udp_transport_probe("127.0.0.1", "CORP.LOCAL")
        self.assertFalse(r["reachable"])
        self.assertFalse(r["too_big"])
        self.assertIsNone(r["code"])

    def test_finding_emitted_when_udp_reachable(self):
        fs = K.udp_transport_findings("10.0.0.1",
                                      {"reachable": True, "too_big": False,
                                       "code": K.KDC_ERR_PREAUTH_REQUIRED})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["kind"], "kerberos_udp_fallback")
        self.assertEqual(fs[0]["severity"], "medium")
        self.assertEqual(fs[0]["depth_tier"], "t1")
        self.assertEqual(fs[0]["target"], "10.0.0.1:88")
        self.assertTrue(fs[0]["narrative"])
        self.assertTrue(fs[0]["exploit_note"])
        # No too-big flag -> detail should NOT carry the fingerprint sentence.
        self.assertNotIn("RESPONSE_TOO_BIG", fs[0]["detail"])

    def test_finding_notes_too_big_fingerprint(self):
        fs = K.udp_transport_findings("10.0.0.1",
                                      {"reachable": True, "too_big": True,
                                       "code": K.KRB_ERR_RESPONSE_TOO_BIG})
        self.assertEqual(len(fs), 1)
        self.assertIn("RESPONSE_TOO_BIG", fs[0]["detail"])
        self.assertIn("AD-vs-MIT", fs[0]["detail"])

    def test_no_finding_when_udp_unreachable(self):
        self.assertEqual(K.udp_transport_findings("10.0.0.1",
                                                  {"reachable": False}), [])


if __name__ == "__main__":
    unittest.main()
