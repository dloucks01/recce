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


class ExploitCandidateLabelTest(unittest.TestCase):
    """Stage 4b: an exploitation action off a version lead reads 'candidate — verify',
    not confirmed (the two-definitions-of-CONFIRMED fix)."""

    def _host(self):
        h = Host(ip="10.0.0.2", up_reason="syn-ack", os_family="Windows",
                 ports=[Port(portid=445, protocol="tcp", state="open", service="microsoft-ds"),
                        Port(portid=21, protocol="tcp", state="open", service="ftp")])
        h.vulns = [
            Vuln(ip="10.0.0.2", port=445, protocol="tcp", script_id="smb-vuln-ms17-010",
                 title="ms17-010", source="nse", state="VULNERABLE", severity="critical",
                 ids=["CVE-2017-0143"]),                                   # verified
            Vuln(ip="10.0.0.2", port=21, protocol="tcp", script_id="version-db",
                 title="vsftpd 2.3.4 backdoor (smiley-face) - remote root",
                 source="version-db", severity="critical", ids=["CVE-2011-2523"]),  # lead
        ]
        qod.annotate(h)
        return h

    def test_actions_carry_verified_flag(self):
        from recce import exploitplan
        acts = exploitplan.actions_for_host(self._host())
        vmap = {a["finding"]: a.get("verified") for a in acts}
        self.assertTrue(vmap.get("ms17-010"))                              # confirmed
        self.assertIn(False, [v for k, v in vmap.items() if "vsftpd" in k])  # candidate

    def test_exploitation_sheet_confidence_column(self):
        from recce.report_excel import _spec_exploitation
        spec = _spec_exploitation([self._host()])
        self.assertIn("Confidence", [c[0] for c in spec.cols])
        confs = {r["data"]["Finding"]: r["data"]["Confidence"] for r in spec.rows}
        self.assertEqual(confs.get("ms17-010"), "confirmed")
        vsftpd = next(c for f, c in confs.items() if "vsftpd" in f)
        self.assertEqual(vsftpd, "candidate — verify")


if __name__ == "__main__":
    unittest.main()
