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


def _krb_error(code, stime="", crealm="", padata_types=()):
    """Build a KRB-ERROR ([APPLICATION 30]) with optional stime[4], crealm[9],
    and PA-DATA entries (only padata-type[1] populated - value is empty)."""
    parts = [_der_ctx(0, _der_int(5)),                 # pvno
             _der_ctx(1, _der_int(30))]                # msg-type
    if stime:
        parts.append(_der_ctx(4, _der_gtime(stime)))
    parts.append(_der_ctx(6, _der_int(code)))
    if crealm:
        parts.append(_der_ctx(9, _der_gstr(crealm)))
    if padata_types:
        method_data = _der_seq(*[_der_seq(_der_ctx(1, _der_int(t)),
                                          _der_ctx(2, _der_octet(b"")))
                                 for t in padata_types])
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


if __name__ == "__main__":
    unittest.main()
