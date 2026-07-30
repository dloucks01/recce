"""Stage 4a: honest tiered presentation — Tier + To-confirm columns on the vulns sheet."""

import unittest

from recce import qod
from recce.models import Host, Port, Vuln
from recce.report_excel import _spec_vulns


def _host():
    p = Port(portid=445, protocol="tcp", state="open", service="microsoft-ds")
    h = Host(ip="10.0.0.1", up_reason="syn-ack", ports=[p])
    h.vulns = [
        Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="smb-vuln-ms17-010",
             title="ms17-010", source="nse", state="VULNERABLE", severity="critical",
             ids=["CVE-2017-0143"]),                                   # confirmed
        Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="version-db",
             title="SMBv1 legacy lead", source="version-db", severity="medium",
             ids=["CVE-2017-0143"]),                                   # a lead
    ]
    qod.annotate(h)
    return h


class TieredPresentationTest(unittest.TestCase):
    def setUp(self):
        self.spec = _spec_vulns([_host()])
        self.byfinding = {r["data"]["Finding"]: r["data"] for r in self.spec.rows}

    def test_columns_present(self):
        cols = [c[0] for c in self.spec.cols]
        self.assertIn("Tier", cols)
        self.assertIn("To confirm", cols)

    def test_confirmed_finding_tiered_and_no_confirm_command(self):
        row = self.byfinding["ms17-010"]
        self.assertEqual(row["Tier"], "confirmed")
        self.assertEqual(row["To confirm"], "")               # already verified

    def test_lead_tiered_and_has_confirm_command(self):
        row = self.byfinding["SMBv1 legacy lead"]
        self.assertIn(row["Tier"], ("likely", "lead"))
        self.assertIn("recce verify", row["To confirm"])       # actionable next step
        self.assertIn("smb-vuln-ms17-010", row["To confirm"])  # the safe re-check


if __name__ == "__main__":
    unittest.main()
