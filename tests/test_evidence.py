"""Stage 1b-ii foundation: findings carry structured Evidence.

Evidence(kind, positive) is what lets the verifier promote/refute a finding without
re-parsing free text. These tests pin that producers attach the right evidence and that
it survives the datastore round-trip. (The proofs rewrite that consumes it lands next.)
"""

import unittest

from recce import parser, vulndb
from recce.models import Evidence, Host, Port, Script, Vuln


class EvidenceProducersTest(unittest.TestCase):
    def test_nse_positive_vuln_carries_positive_nse_evidence(self):
        s = Script(id="smb-vuln-ms17-010",
                   output="State: VULNERABLE\naffected by CVE-2017-0143")
        v = parser._classify_vuln("10.0.0.1", Port(portid=445), s)
        self.assertTrue(any(e.kind == "nse" and e.positive for e in v.evidence))

    def test_nse_not_affected_but_cve_mentioned_is_dropped(self):
        # (also covered by the FP sweep) - a non-positive CVE mention isn't a finding.
        s = Script(id="http-vuln-x", output="Not affected. See CVE-2021-44228.")
        self.assertIsNone(parser._classify_vuln("10.0.0.1", Port(portid=80), s))

    def test_weak_config_carries_config_observed_evidence(self):
        s = Script(id="ftp-anon", output="Anonymous FTP login allowed (FTP code 230)")
        v = parser._classify_vuln("10.0.0.1", Port(portid=21), s) or \
            parser._weak_config("10.0.0.1", Port(portid=21), s)
        self.assertTrue(any(e.kind == "config-observed" and e.positive for e in v.evidence))

    def test_versiondb_carries_version_range_evidence(self):
        h = Host(ip="10.0.0.2", ports=[Port(portid=22, state="open", service="ssh",
                                            product="OpenSSH", version="7.2")])
        vulns = vulndb.assess_host(h)
        self.assertTrue(vulns)
        for v in vulns:
            kinds = {e.kind for e in v.evidence}
            self.assertIn("version-range", kinds)
            # a version inference is never tagged as a live corroboration
            self.assertNotIn("live-probe", kinds)

    def test_evidence_survives_json_roundtrip(self):
        v = Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="x",
                 evidence=[Evidence(kind="nse", detail="State: VULNERABLE", positive=True),
                           Evidence(kind="version-range", detail="OpenSSH 7.2", positive=False)])
        h2 = Host.from_json(Host(ip="10.0.0.1", vulns=[v]).to_json())
        ev = h2.vulns[0].evidence
        self.assertEqual([(e.kind, e.positive) for e in ev],
                         [("nse", True), ("version-range", False)])
        self.assertIsInstance(ev[0], Evidence)   # rebuilt as objects, not dicts


if __name__ == "__main__":
    unittest.main()
