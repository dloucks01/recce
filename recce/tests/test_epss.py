"""Stage 5b: EPSS prioritization — score annotation, fix-first cell, exploitation-weighted sort."""

import unittest

from recce import epss, kev, qod
from recce.models import Host, Port, Vuln
from recce.report_excel import _priority_cell, _spec_vulns


class EpssTest(unittest.TestCase):
    def test_score_lookup(self):
        self.assertGreater(epss.score_for("CVE-2021-44228"), 0.9)
        self.assertEqual(epss.score_for("CVE-2099-0000"), 0.0)      # unknown -> 0, never a guess
        self.assertGreater(epss.best(["CVE-2099-0000", "CVE-2021-44228"]), 0.9)

    def test_annotate_sets_epss(self):
        h = Host(ip="10.0.0.1", vulns=[Vuln(ip="10.0.0.1", port=80, protocol="tcp",
                                            script_id="x", ids=["CVE-2017-5638"])])
        epss.annotate(h)
        self.assertGreater(h.vulns[0].epss, 0.9)

    def test_priority_cell(self):
        kv = Vuln(ip="1", port=1, protocol="tcp", script_id="x", kev=True, epss=0.9)
        self.assertEqual(_priority_cell(kv), "🔥 KEV")               # KEV wins
        hi = Vuln(ip="1", port=1, protocol="tcp", script_id="x", epss=0.97)
        self.assertEqual(_priority_cell(hi), "EPSS 97%")
        lo = Vuln(ip="1", port=1, protocol="tcp", script_id="x", epss=0.02)
        self.assertEqual(_priority_cell(lo), "")


class EpssSortTest(unittest.TestCase):
    def test_high_epss_sorts_above_low_epss_same_severity(self):
        h = Host(ip="10.0.0.1", up_reason="syn-ack",
                 ports=[Port(portid=80, protocol="tcp", state="open")])
        h.vulns = [
            Vuln(ip="10.0.0.1", port=80, protocol="tcp", script_id="a", title="low-epss",
                 severity="high", source="version-db", ids=["CVE-2018-15473"]),   # ~0.62
            Vuln(ip="10.0.0.1", port=80, protocol="tcp", script_id="b", title="high-epss",
                 severity="high", source="version-db", ids=["CVE-2017-5638"]),    # ~0.975
        ]
        qod.annotate(h); kev.annotate(h); epss.annotate(h)
        findings = [r["data"]["Finding"] for r in _spec_vulns([h]).rows]
        self.assertLess(findings.index("high-epss"), findings.index("low-epss"))


if __name__ == "__main__":
    unittest.main()
