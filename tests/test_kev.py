"""Stage 5: CISA KEV prioritization — flag + fix-first sort for exploited-in-the-wild CVEs."""

import unittest

from recce import kev, qod
from recce.models import Host, Port, Vuln
from recce.report_excel import _spec_vulns


class KevTest(unittest.TestCase):
    def test_catalogue_lookup(self):
        self.assertTrue(kev.is_kev("CVE-2021-44228"))       # log4shell
        self.assertTrue(kev.is_kev("cve-2017-0143"))        # case-insensitive
        self.assertFalse(kev.is_kev("CVE-2099-0000"))
        self.assertTrue(kev.any_kev(["CVE-2099-0000", "CVE-2020-1472"]))

    def test_annotate_flags_kev_findings(self):
        h = Host(ip="10.0.0.1", up_reason="syn-ack",
                 vulns=[Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="x",
                             ids=["CVE-2021-44228"]),
                        Vuln(ip="10.0.0.1", port=80, protocol="tcp", script_id="y",
                             ids=["CVE-2099-0000"])])
        kev.annotate(h)
        self.assertTrue(h.vulns[0].kev)
        self.assertFalse(h.vulns[1].kev)


class KevPresentationTest(unittest.TestCase):
    def _host(self):
        h = Host(ip="10.0.0.1", up_reason="syn-ack",
                 ports=[Port(portid=445, protocol="tcp", state="open")])
        h.vulns = [
            Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="a",
                 title="a critical non-KEV", severity="critical", source="version-db",
                 ids=["CVE-2099-0000"]),
            Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="b",
                 title="a high KEV", severity="high", source="version-db",
                 ids=["CVE-2020-1472"]),   # zerologon - in KEV
        ]
        qod.annotate(h)
        kev.annotate(h)
        return h

    def test_fix_first_column_and_marker(self):
        spec = _spec_vulns([self._host()])
        self.assertIn("Fix first", [c[0] for c in spec.cols])
        marks = {r["data"]["Finding"]: r["data"]["Fix first"] for r in spec.rows}
        self.assertEqual(marks["a high KEV"], "🔥 KEV")
        self.assertEqual(marks["a critical non-KEV"], "")

    def test_kev_sorts_above_higher_severity_non_kev(self):
        # the high-severity KEV finding sorts ABOVE the critical non-KEV (fix-first wins)
        rows = _spec_vulns([self._host()]).rows
        findings = [r["data"]["Finding"] for r in rows]
        self.assertLess(findings.index("a high KEV"), findings.index("a critical non-KEV"))


if __name__ == "__main__":
    unittest.main()
