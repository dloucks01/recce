"""Stage 7: coverage-safe scan efficiency — the vuln pass skips the deep enum scripts only
when they've already run on the host (their output is present), so no finding is ever lost."""

import unittest

from recce import scanner
from recce.models import Host, Port, Script


class EnumPresentTest(unittest.TestCase):
    def test_present_when_an_enum_script_ran(self):
        h = Host(ip="10.0.0.1", ports=[Port(portid=443, protocol="tcp", state="open",
                                            scripts=[Script(id="ssl-cert", output="...")])])
        self.assertTrue(scanner.enum_scripts_present(h))   # ssl-cert is a deep enum script

    def test_absent_when_no_enum_script_ran(self):
        h = Host(ip="10.0.0.1", ports=[Port(portid=445, protocol="tcp", state="open",
                                            scripts=[Script(id="banner", output="x")])])
        self.assertFalse(scanner.enum_scripts_present(h))
        self.assertFalse(scanner.enum_scripts_present(Host(ip="10.0.0.1")))


class VulnScriptSelectionTest(unittest.TestCase):
    def setUp(self):
        self._run = scanner._run
        self.cmd = {}
        scanner._run = lambda cmd, timeout=None: (self.cmd.update(c=cmd)
                                                  or scanner.RunOutcome(returncode=0))

    def tearDown(self):
        scanner._run = self._run

    def _script_arg(self):
        c = self.cmd["c"]
        return c[c.index("--script") + 1]

    def test_skip_drops_enum_scripts_keeps_detectors(self):
        scanner.vuln_scan("10.0.0.1", [443], "/tmp/x.xml", scanner.ScanProfile(),
                          skip_enum_scripts=True)
        arg = self._script_arg()
        self.assertNotIn("http-title", arg)        # a deep-enum script is dropped
        self.assertNotIn("ssl-cert", arg)
        self.assertIn("smb-vuln-ms17-010", arg)    # the vuln detectors stay
        self.assertIn("(vuln and safe)", arg)

    def test_default_includes_enum_scripts(self):
        scanner.vuln_scan("10.0.0.1", [443], "/tmp/x.xml", scanner.ScanProfile(),
                          skip_enum_scripts=False)
        arg = self._script_arg()
        self.assertIn("http-title", arg)           # coverage preserved when enum didn't run
        self.assertIn("smb-vuln-ms17-010", arg)


if __name__ == "__main__":
    unittest.main()
