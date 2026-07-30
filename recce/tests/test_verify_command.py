"""Stage 3c: `recce verify` — dry-run by default; --run folds a safe re-check and lets the
normal pipeline confirm/refute the lead. Scanner + report are mocked (no nmap, no workbook)."""

import argparse
import shutil
import tempfile
import unittest

from recce import cli
from recce import parser as np
from recce import scanner
from recce.models import Host, Port, Script, Vuln
from recce.store import Store


def _lead_host():
    return Host(ip="10.0.0.1", up_reason="syn-ack",
                ports=[Port(portid=445, protocol="tcp", state="open",
                            service="microsoft-ds", vuln_scanned=True)],
                vulns=[Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="version-db",
                            title="ms17-010 (version lead)", source="version-db",
                            ids=["CVE-2017-0143"], qod=80, qod_type="remote_banner")])


class VerifyCommandTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="recce-verify-")
        self.paths = cli._open_paths(self.dir)
        s = Store(self.paths["db"])
        s.upsert_host(_lead_host())
        s.close()
        self._orig = (scanner.nse_scan, np.parse_nmap_xml, cli._final_report, cli._print_next)

    def tearDown(self):
        scanner.nse_scan, np.parse_nmap_xml, cli._final_report, cli._print_next = self._orig
        shutil.rmtree(self.dir, ignore_errors=True)

    def _args(self, run):
        return argparse.Namespace(output_dir=self.dir, run=run, title="t")

    def test_dry_run_sends_no_traffic(self):
        sent = []
        scanner.nse_scan = lambda *a, **k: sent.append(1) or ("x", None)
        rc = cli.cmd_verify(self._args(run=False))
        self.assertEqual(rc, 0)
        self.assertEqual(sent, [])                       # dry run: nothing sent

    def test_run_folds_a_confirmation_into_the_store(self):
        # the safe re-check comes back VULNERABLE -> folds an NSE finding onto the host,
        # which the report pipeline then merges/promotes.
        scanner.nse_scan = lambda ip, ports, xml, profile, scripts, creds=None: (xml, None)
        np.parse_nmap_xml = lambda path: [Host(
            ip="10.0.0.1", up_reason="syn-ack",
            ports=[Port(portid=445, protocol="tcp", state="open",
                        scripts=[Script(id="smb-vuln-ms17-010",
                                        output="State: VULNERABLE\nIDs: CVE:CVE-2017-0143")])],
            vulns=[Vuln(ip="10.0.0.1", port=445, protocol="tcp",
                        script_id="smb-vuln-ms17-010", title="ms17-010", source="nse",
                        state="VULNERABLE", ids=["CVE-2017-0143"])])]
        cli._final_report = lambda *a, **k: None
        cli._print_next = lambda *a, **k: None
        rc = cli.cmd_verify(self._args(run=True))
        self.assertEqual(rc, 0)
        s = Store(self.paths["db"])
        h = s.get_host("10.0.0.1")
        s.close()
        sids = {v.script_id for v in h.vulns}
        self.assertIn("smb-vuln-ms17-010", sids)         # confirmation folded in
        self.assertIn("version-db", sids)                # original lead kept
        # the NSE result is present on the port (drives refute/promote at report time)
        p = next(p for p in h.ports if p.portid == 445)
        self.assertIn("smb-vuln-ms17-010", {sc.id for sc in p.scripts})


if __name__ == "__main__":
    unittest.main()
