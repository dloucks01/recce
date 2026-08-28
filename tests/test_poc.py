"""`recce poc` — assemble a per-CVE PoC dossier + harness skeleton from OFFLINE intel.

Pins that the generator gathers the right data (vulndb signature, KEV/EPSS, msf ref,
affected hosts), writes a dossier + a *valid, non-weaponized* Python harness that pins
the engagement's target, and that CVE collection from findings works. Exploit-DB
assertions are gated on searchsploit being present.
"""
from __future__ import annotations

import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recce.vuln import exploits                        # noqa: E402
from recce.act import pocgen                           # noqa: E402
from recce.core.models import Host, Port, Vuln         # noqa: E402


def _host_with_cve(ip="10.0.20.6", cve="CVE-2011-2523"):
    h = Host(ip=ip, state="up")
    h.ports.append(Port(portid=21, protocol="tcp", state="open"))
    h.vulns.append(Vuln(ip=ip, port=21, protocol="tcp", script_id="v",
                        state="VULNERABLE", title="vsftpd 2.3.4 backdoor",
                        severity="critical", ids=[cve], confidence="likely"))
    return h


class Gather(unittest.TestCase):
    def test_valid_cve(self):
        self.assertTrue(pocgen.valid_cve("CVE-2021-44228"))
        self.assertFalse(pocgen.valid_cve("log4shell"))
        self.assertFalse(pocgen.valid_cve("CVE-21-1"))

    def test_gather_assembles_offline_intel(self):
        d = pocgen.gather("CVE-2011-2523", [_host_with_cve()])
        self.assertIsNotNone(d["sig"])                      # in the curated vulndb
        self.assertEqual(d["severity"], "critical")
        self.assertGreater(d["epss"], 0.5)                  # vsftpd backdoor is high-EPSS
        self.assertTrue(d["msf"])                           # mapped to a metasploit module
        self.assertEqual(len(d["affected"]), 1)
        self.assertEqual(d["affected"][0]["ip"], "10.0.20.6")
        if exploits.available():
            self.assertTrue(d["edb"], "expected Exploit-DB entries for a known CVE")

    def test_kev_cve_is_flagged(self):
        d = pocgen.gather("CVE-2017-0143", [])              # EternalBlue -> CISA KEV
        self.assertTrue(d["kev"])


class Generate(unittest.TestCase):
    def test_writes_dossier_and_valid_harness(self):
        out = tempfile.mkdtemp()
        res = pocgen.generate(["CVE-2011-2523"], [_host_with_cve()], out)
        self.assertEqual(len(res), 1)
        cdir = os.path.join(out, "poc", "CVE-2011-2523")
        md = Path(cdir, "CVE-2011-2523.md").read_text()
        self.assertIn("Affected in this engagement", md)
        self.assertIn("10.0.20.6:21", md)
        self.assertIn("does not", md.lower())               # the non-weaponize notice
        harness = Path(cdir, "poc.py").read_text()
        ast.parse(harness)                                  # the scaffold is valid Python
        self.assertIn('("10.0.20.6", 21)', harness)         # target pinned from the engagement
        self.assertIn("NotImplementedError", harness)       # check()/exploit() are stubs

    def test_dossier_and_harness_are_written_as_utf8_not_platform_default(self):
        # Regression: both files were opened bare open(...,"w") - no encoding= - so
        # a non-ASCII finding title/KEV flag (recce's own dossier renders a real 🔥
        # emoji for a CISA-KEV CVE) would raise UnicodeEncodeError on a platform
        # whose default text encoding isn't UTF-8 (e.g. cp1252 on Windows, which
        # recce explicitly ships an airgap build for). Prove the failure mode is
        # real, then prove recce's own writer is immune to it.
        d = pocgen.gather("CVE-2017-0143", [])       # EternalBlue -> CISA KEV -> 🔥 in the dossier
        dossier = pocgen.render_dossier(d)
        self.assertTrue(any(ord(c) > 127 for c in dossier), "expected non-ASCII (KEV flag) in the dossier")
        with tempfile.TemporaryDirectory() as scratch:
            with self.assertRaises(UnicodeEncodeError):
                with open(os.path.join(scratch, "x.md"), "w", encoding="cp1252") as fh:
                    fh.write(dossier)
        out = tempfile.mkdtemp()
        pocgen.generate(["CVE-2017-0143"], [], out)
        cdir = os.path.join(out, "poc", "CVE-2017-0143")
        with open(os.path.join(cdir, "CVE-2017-0143.md"), encoding="utf-8") as fh:
            self.assertIn("\U0001f525", fh.read())    # round-trips correctly as UTF-8

    def test_harness_survives_hostile_title(self):
        # a scan-derived finding title carries free text; one containing `"""`, a backslash
        # or a newline must not break the generated harness (it lands in the docstring).
        h = Host(ip="10.0.0.5", state="up")
        h.ports.append(Port(portid=8080, protocol="tcp", state="open"))
        h.vulns.append(Vuln(ip="10.0.0.5", port=8080, protocol="tcp", script_id="x",
                            state="VULNERABLE", title='evil"""\nimport os  # \\ break out',
                            severity="high", ids=["CVE-2099-0001"], confidence="likely"))
        out = tempfile.mkdtemp()
        pocgen.generate(["CVE-2099-0001"], [h], out)          # no vulndb sig -> title falls back
        harness = Path(out, "poc", "CVE-2099-0001", "poc.py").read_text()
        ast.parse(harness)                                    # must still be valid Python

    def test_cves_from_findings(self):
        from recce.cli import _cves_from_findings
        hosts = [_host_with_cve(cve="CVE-2011-2523"), _host_with_cve(ip="10.0.0.9", cve="CVE-2017-0143")]
        got = _cves_from_findings(hosts)
        self.assertEqual(got, ["CVE-2011-2523", "CVE-2017-0143"])
        self.assertEqual(_cves_from_findings(hosts, confirmed_only=True), [])   # both are "likely"


if __name__ == "__main__":
    unittest.main()
