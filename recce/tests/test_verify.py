"""Stage 3a: refute version-inference leads an NSE check already disproved (verify-don't-infer).

Zero new traffic — it harvests NSE `NOT VULNERABLE` results recce already collected and
refutes the matching version-db leads. Refuted findings are hidden by default but never
deleted.
"""

import unittest

from recce import verify
from recce.models import Evidence, Host, Port, Script, Vuln


def _lead(cve, port=445, source="version-db"):
    return Vuln(ip="10.0.0.1", port=port, protocol="tcp", script_id="version-db",
                title=f"lead {cve}", source=source, ids=[cve], qod=80, qod_type="remote_banner")


def _host_with_script(script_id, output, *vulns, host_level=False):
    p = Port(portid=445, protocol="tcp", state="open",
             scripts=[] if host_level else [Script(id=script_id, output=output)])
    h = Host(ip="10.0.0.1", ports=[p], vulns=list(vulns))
    if host_level:
        h.host_scripts = [Script(id=script_id, output=output)]
    return h


class RefutationTest(unittest.TestCase):
    def test_not_vulnerable_refutes_matching_lead(self):
        h = _host_with_script("smb-vuln-ms17-010",
                              "State: NOT VULNERABLE\nIDs: CVE:CVE-2017-0143",
                              _lead("CVE-2017-0143"))
        n = verify.apply_refutations(h)
        self.assertEqual(n, 1)
        v = h.vulns[0]
        self.assertTrue(verify.is_refuted(v))
        self.assertEqual(v.qod, 1)
        self.assertTrue(any(e.kind == "nse" and not e.positive for e in v.evidence))

    def test_refutes_via_curated_script_map_without_embedded_cve(self):
        # output has no CVE text, but the script->CVE map covers ms17-010.
        h = _host_with_script("smb-vuln-ms17-010", "State: NOT VULNERABLE",
                              _lead("CVE-2017-0144"))
        self.assertEqual(verify.apply_refutations(h), 1)
        self.assertTrue(verify.is_refuted(h.vulns[0]))

    def test_vulnerable_result_does_not_refute(self):
        h = _host_with_script("smb-vuln-ms17-010",
                              "State: VULNERABLE\nCVE-2017-0143", _lead("CVE-2017-0143"))
        self.assertEqual(verify.apply_refutations(h), 0)
        self.assertFalse(verify.is_refuted(h.vulns[0]))

    def test_never_refutes_a_live_confirmed_finding(self):
        # a version-db lead AND a positive NSE finding for the same CVE: the positive wins,
        # the lead is not refuted (contradiction guard).
        h = _host_with_script("smb-vuln-ms17-010", "State: NOT VULNERABLE\nCVE-2017-0143",
                              _lead("CVE-2017-0143"))
        h.vulns.append(Vuln(ip="10.0.0.1", port=445, protocol="tcp",
                            script_id="smb-vuln-ms17-010", title="ms17-010", source="nse",
                            state="VULNERABLE", ids=["CVE-2017-0143"]))
        self.assertEqual(verify.apply_refutations(h), 0)

    def test_only_refutes_version_db_leads_not_probe_findings(self):
        h = _host_with_script("ssl-heartbleed", "State: NOT VULNERABLE",
                              _lead("CVE-2014-0160", source="probe"))
        self.assertEqual(verify.apply_refutations(h), 0)

    def test_unrelated_cve_untouched(self):
        h = _host_with_script("smb-vuln-ms17-010", "State: NOT VULNERABLE\nCVE-2017-0143",
                              _lead("CVE-2099-9999"))
        self.assertEqual(verify.apply_refutations(h), 0)
        self.assertFalse(verify.is_refuted(h.vulns[0]))

    def test_host_level_script_also_refutes(self):
        h = _host_with_script("ssl-heartbleed", "State: NOT VULNERABLE",
                              _lead("CVE-2014-0160"), host_level=True)
        self.assertEqual(verify.apply_refutations(h), 1)


if __name__ == "__main__":
    unittest.main()
