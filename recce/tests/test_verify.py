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


class ConfirmPlanTest(unittest.TestCase):
    def test_registry_lookup(self):
        from recce import verify_rules
        r = verify_rules.rule_for_cve("CVE-2017-0143")
        self.assertEqual(r["nse"], "smb-vuln-ms17-010")
        self.assertIn("B", r["tier"])
        self.assertIsNone(verify_rules.rule_for_cve("CVE-2099-0000"))

    def test_plan_for_unconfirmed_lead(self):
        h = Host(ip="10.0.0.7", ports=[Port(portid=445, protocol="tcp", state="open")],
                 vulns=[_lead("CVE-2017-0143")])
        plan = verify.confirm_plan(h)
        self.assertEqual(len(plan), 1)
        p = plan[0]
        self.assertEqual(p["check"], "smb-vuln-ms17-010")
        self.assertFalse(p["ran"])                 # detector hasn't run here
        self.assertIn("10.0.0.7", p["command"])    # <ip> filled in
        self.assertIn("smb-vuln-ms17-010", p["command"])

    def test_plan_marks_check_that_already_ran(self):
        h = _host_with_script("smb-vuln-ms17-010", "State: NOT VULNERABLE",
                              _lead("CVE-2017-0143"))
        # refute it first, then the plan should skip a refuted lead
        verify.apply_refutations(h)
        self.assertEqual(verify.confirm_plan(h), [])

    def test_plan_skips_leads_without_a_rule(self):
        h = Host(ip="10.0.0.7", vulns=[_lead("CVE-2099-9999")])
        self.assertEqual(verify.confirm_plan(h), [])


if __name__ == "__main__":
    unittest.main()
