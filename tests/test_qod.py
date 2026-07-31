"""Stage 1 — Quality-of-Detection scoring is the single confidence authority.

Pins the tier table (docs/ARCHITECTURE.md §3.1): confidence is derived ONCE from the
detection method, orthogonal to severity. These tests are the contract the rest of the
pipeline reads instead of re-deriving "is this real?" from strings.
"""

import unittest

from recce import qod
from recce.models import Host, Port, Vuln


def _v(**kw):
    kw.setdefault("ip", "10.0.0.1")
    kw.setdefault("port", 443)
    kw.setdefault("protocol", "tcp")
    kw.setdefault("script_id", "x")
    return Vuln(**kw)


class QodScoreTest(unittest.TestCase):
    def test_version_db_likely_is_a_visible_lead_not_verified(self):
        v = _v(source="version-db", confidence="likely")
        score, kind = qod.score(v)
        self.assertEqual((score, kind), (80, "remote_banner"))
        self.assertTrue(qod.is_visible(v))       # shown in the default view
        self.assertFalse(qod.is_verified(v))     # but NOT a confirmed/exploitable finding

    def test_version_db_potential_is_hidden_by_default(self):
        # advisory / distro-backport / unreliable -> below the 70 default filter.
        v = _v(source="version-db", confidence="potential")
        self.assertEqual(qod.score(v), (30, "banner_unreliable"))
        self.assertFalse(qod.is_visible(v))
        self.assertFalse(qod.is_verified(v))

    def test_nse_vulnerable_is_verified(self):
        v = _v(source="nse", state="VULNERABLE")
        self.assertEqual(qod.score(v), (99, "active_vuln"))
        self.assertTrue(qod.is_verified(v))

    def test_nse_weak_config_is_visible_not_verified(self):
        v = _v(source="config", state="finding", title="Anonymous FTP login allowed")
        self.assertEqual(qod.score(v), (90, "config_observed"))
        self.assertTrue(qod.is_visible(v))
        self.assertFalse(qod.is_verified(v))

    def test_live_probe_is_verified(self):
        self.assertTrue(qod.is_verified(_v(source="probe")))

    def test_credentialed_and_ontarget_are_verified(self):
        self.assertTrue(qod.is_verified(_v(source="cred")))
        self.assertTrue(qod.is_verified(_v(source="ingest")))

    def test_inferred_port_is_low_and_hidden(self):
        v = _v(source="version-db", confidence="likely")
        p = Port(portid=443, detect_source="inferred")
        self.assertEqual(qod.score(v, p), (50, "inferred_port"))
        self.assertFalse(qod.is_visible(v, port=p))

    def test_min_qod_dial(self):
        v = _v(source="version-db", confidence="potential")   # 30
        self.assertFalse(qod.is_visible(v))                   # hidden at default 70
        self.assertTrue(qod.is_visible(v, min_qod=20))        # revealed when dialed down

    def test_qod_is_orthogonal_to_severity(self):
        # a critical-severity banner guess is still a low-QoD lead, not verified.
        v = _v(source="version-db", confidence="likely", severity="critical")
        self.assertEqual(v.severity, "critical")
        self.assertFalse(qod.is_verified(v))

    def test_annotate_stamps_every_finding_once(self):
        h = Host(ip="10.0.0.9", ports=[Port(portid=22, protocol="tcp", detect_source="nmap")])
        h.vulns = [_v(ip="10.0.0.9", port=22, source="version-db", confidence="likely"),
                   _v(ip="10.0.0.9", port=22, source="nse", state="VULNERABLE")]
        qod.annotate(h)
        self.assertEqual([v.qod for v in h.vulns], [80, 99])
        self.assertEqual([v.qod_type for v in h.vulns], ["remote_banner", "active_vuln"])

    def test_qod_survives_json_roundtrip(self):
        v = _v(source="nse", state="VULNERABLE")
        qod.annotate(Host(ip="10.0.0.1", ports=[Port(portid=443, protocol="tcp")],
                          vulns=[v]))
        h2 = Host.from_json(Host(ip="10.0.0.1", vulns=[v]).to_json())
        self.assertEqual(h2.vulns[0].qod, 99)


class QodReportColumnTest(unittest.TestCase):
    def test_vulns_sheet_shows_qod_tier(self):
        from recce.report_excel import _spec_vulns
        h = Host(ip="10.0.0.5", ports=[Port(portid=22, protocol="tcp", service="ssh")])
        h.vulns = [_v(ip="10.0.0.5", port=22, source="version-db", confidence="likely",
                      title="OpenSSH < 7.7 user enum"),
                   _v(ip="10.0.0.5", port=22, source="nse", state="VULNERABLE",
                      title="ms17-010")]
        spec = _spec_vulns([h])
        self.assertIn("QoD", [c[0] for c in spec.cols])
        self.assertNotIn("Conf.", [c[0] for c in spec.cols])
        qcells = {r["data"]["Finding"]: r["data"]["QoD"] for r in spec.rows}
        self.assertEqual(qcells["OpenSSH < 7.7 user enum"], "80 remote_banner")
        self.assertEqual(qcells["ms17-010"], "99 active_vuln ✓")   # verified marker


if __name__ == "__main__":
    unittest.main()
