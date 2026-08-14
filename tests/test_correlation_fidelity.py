"""Dedup / correlation fidelity.

The same issue is often seen by several detectors at once - an nmap NSE VULNERABLE
result, an offline version->CVE match, and recce's own live probe. Presenting three
"findings" for one flaw is noise; collapsing them wrongly loses a distinct finding.
recce correlates by (ip, port, proto, CVE) and folds a group into ONE finding that
keeps the BEST of every axis. This suite guards that fold, and its interaction with
the QoD/honesty model: corroboration must UPGRADE confidence (a version guess seen
live becomes verified), never the reverse, and a distinct finding is never dropped.

test_dedup.py covers the core merge unit cases; this adds the cross-source ×
confidence interaction and the protocol boundary.
"""
import unittest

from recce import dedup, qod
from recce.models import Host, Port, Vuln


def _v(port, cves, source, confidence="", severity="high", proto="tcp", state="",
       title="finding", script_id=None):
    v = Vuln(ip="10.0.0.1", port=port, protocol=proto, title=title,
             script_id=script_id or source, source=source, severity=severity,
             confidence=confidence, state=state, ids=list(cves))
    v.qod, v.qod_type = qod.score(v)
    return v


class CorrelationFidelityTest(unittest.TestCase):

    def test_multi_source_corroboration_collapses_and_upgrades(self):
        # Same CVE on the same port from three detectors: a version-db banner guess,
        # an NSE VULNERABLE result, and a live probe. They must fold into ONE finding
        # that keeps the strongest evidence.
        group = [
            _v(445, ["CVE-2017-0143"], "version-db", confidence="likely",
               title="EternalBlue (version-inferred)"),
            _v(445, ["CVE-2017-0143"], "nse", state="VULNERABLE", severity="critical",
               title="smb-vuln-ms17-010"),
            _v(445, ["CVE-2017-0143", "CVE-2017-0144"], "probe", confidence="confirmed",
               title="EternalBlue (probe)"),
        ]
        out = dedup.dedupe(group)
        self.assertEqual(len(out), 1)
        m = out[0]
        # Corroboration UPGRADES: the merged finding is verified, not a lead.
        self.assertEqual(m.confidence, "confirmed")
        self.assertEqual(m.qod, 99)                       # highest QoD across the group
        self.assertTrue(qod.is_verified(m))
        self.assertEqual(m.severity, "critical")          # worst severity kept
        self.assertEqual(m.ids, ["CVE-2017-0143", "CVE-2017-0144"])   # CVEs unioned
        self.assertIn("Corroborated by", m.output or "")  # provenance recorded

    def test_version_only_duplicates_stay_a_guess(self):
        # Two version-db matches for the same CVE corroborate each other but neither is
        # a live check - the fold must NOT be promoted to verified.
        group = [_v(22, ["CVE-2024-6387"], "version-db", confidence="likely"),
                 _v(22, ["CVE-2024-6387"], "version-db", confidence="likely")]
        m = dedup.dedupe(group)[0]
        self.assertEqual(len(dedup.dedupe(group)), 1)
        self.assertFalse(qod.is_verified(m))
        self.assertEqual(m.confidence, "likely")

    def test_udp_and_tcp_same_port_cve_do_not_merge(self):
        # Correlation includes the protocol: a TCP and a UDP finding on the same port
        # number citing the same CVE are distinct exposures and stay separate.
        group = [_v(161, ["CVE-9999-0001"], "nse", proto="tcp"),
                 _v(161, ["CVE-9999-0001"], "nse", proto="udp")]
        self.assertEqual(len(dedup.dedupe(group)), 2)

    def test_distinct_cves_on_one_port_from_different_sources_stay_separate(self):
        # A version-db match for CVE-A and an NSE result for CVE-B on the same port are
        # two different issues - never collapsed by the shared (ip, port).
        group = [_v(80, ["CVE-2021-41773"], "version-db", confidence="likely",
                    title="Apache path traversal"),
                 _v(80, ["CVE-2021-44228"], "nse", state="VULNERABLE",
                    title="log4shell")]
        out = dedup.dedupe(group)
        self.assertEqual(len(out), 2)
        self.assertEqual({c for v in out for c in v.ids},
                         {"CVE-2021-41773", "CVE-2021-44228"})

    def test_dedupe_host_never_drops_a_distinct_finding(self):
        # A realistic host: two corroborating detections of one flaw, plus three
        # genuinely distinct findings -> exactly 4 survivors, none lost.
        h = Host(ip="10.0.0.1", ports=[
            Port(portid=445, protocol="tcp", state="open", service="microsoft-ds"),
            Port(portid=80, protocol="tcp", state="open", service="http"),
            Port(portid=161, protocol="udp", state="open", service="snmp")])
        h.vulns = [
            _v(445, ["CVE-2017-0143"], "nse", state="VULNERABLE", severity="critical",
               title="smb-vuln-ms17-010"),
            _v(445, ["CVE-2017-0143"], "version-db", confidence="likely",
               title="EternalBlue (version-inferred)"),   # merges with the NSE one
            _v(80, ["CVE-2021-44228"], "nse", state="VULNERABLE", title="log4shell"),
            _v(161, [], "config", title="SNMP readable with a guessable community",
               proto="udp"),
            _v(445, [], "config", title="SMB signing not required"),   # no-CVE, distinct
        ]
        qod.annotate(h)
        dedup.dedupe_host(h)
        titles = sorted(v.title for v in h.vulns)
        self.assertEqual(len(h.vulns), 4)                 # 5 raw -> one pair merged
        self.assertIn("log4shell", titles)
        self.assertIn("SMB signing not required", titles)
        self.assertIn("SNMP readable with a guessable community", titles)
        # The merged EternalBlue survivor is the verified (NSE) one, not the guess.
        eb = next(v for v in h.vulns if "CVE-2017-0143" in v.ids)
        self.assertTrue(qod.is_verified(eb))


if __name__ == "__main__":
    unittest.main()
