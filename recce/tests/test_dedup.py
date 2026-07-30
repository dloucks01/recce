"""Stage 2: finding dedup/correlation — collapse duplicates, never drop a distinct finding."""

import unittest

from recce import dedup
from recce.models import Vuln


def _v(cve=None, port=443, title="t", sid="s", source="version-db", sev="medium",
       qod=0, conf=""):
    return Vuln(ip="10.0.0.1", port=port, protocol="tcp", script_id=sid, title=title,
                severity=sev, source=source, ids=([cve] if cve else []), qod=qod,
                confidence=conf)


class DedupTest(unittest.TestCase):
    def test_same_cve_same_port_merges(self):
        a = _v(cve="CVE-2018-15473", source="version-db", qod=80, sid="version-db",
               title="OpenSSH < 7.7 user enum")
        b = _v(cve="CVE-2018-15473", source="nse", qod=99, sid="ssh-enum",
               title="OpenSSH user enum (NSE)")
        out = dedup.dedupe([a, b])
        self.assertEqual(len(out), 1)
        # corroboration keeps the higher QoD and unions the sources
        self.assertEqual(out[0].qod, 99)
        self.assertIn("Corroborated by 2", out[0].output)

    def test_distinct_cves_stay_separate(self):
        a = _v(cve="CVE-2018-15473", port=22)
        b = _v(cve="CVE-2024-6387", port=22)   # same port, different issue
        self.assertEqual(len(dedup.dedupe([a, b])), 2)

    def test_no_cve_only_exact_duplicate_merges(self):
        a = _v(cve=None, sid="ftp-anon", title="Anonymous FTP login allowed")
        b = _v(cve=None, sid="ftp-anon", title="Anonymous FTP login allowed")
        c = _v(cve=None, sid="ssl-cert", title="Self-signed TLS certificate")  # distinct
        out = dedup.dedupe([a, b, c])
        self.assertEqual(len(out), 2)   # a+b merge, c stays

    def test_different_ports_never_merge(self):
        a = _v(cve="CVE-2021-1", port=80)
        b = _v(cve="CVE-2021-1", port=8080)
        self.assertEqual(len(dedup.dedupe([a, b])), 2)

    def test_merge_keeps_worst_severity_and_unions_refs(self):
        a = _v(cve="CVE-1", sev="low", qod=80)
        a.cwes = ["CWE-200"]
        b = _v(cve="CVE-1", sev="high", qod=70)
        b.ids = ["CVE-1", "CVE-2"]
        b.cwes = ["CWE-79"]
        out = dedup.dedupe([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "high")            # worst severity kept
        self.assertEqual(out[0].ids, ["CVE-1", "CVE-2"])     # refs unioned
        self.assertEqual(out[0].cwes, sorted(["CWE-200", "CWE-79"]))

    def test_order_preserved_and_singletons_untouched(self):
        a = _v(cve="CVE-A", title="a")
        b = _v(cve="CVE-B", title="b")
        out = dedup.dedupe([a, b])
        self.assertEqual([v.ids[0] for v in out], ["CVE-A", "CVE-B"])

    def test_empty(self):
        self.assertEqual(dedup.dedupe([]), [])


if __name__ == "__main__":
    unittest.main()
