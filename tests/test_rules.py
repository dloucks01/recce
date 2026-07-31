"""Stage 6: data-driven detection — extra rules from JSON + negative (absent) matchers."""

import json
import tempfile
import unittest

from recce import vulndb
from recce.models import Host, Port


def _host(product="AcmeApp", version="1.0.0", extrainfo=""):
    return Host(ip="10.0.0.1", up_reason="syn-ack",
                ports=[Port(portid=8080, protocol="tcp", state="open", service="http",
                            product=product, version=version, extrainfo=extrainfo)])


class LoadRulesTest(unittest.TestCase):
    def setUp(self):
        self._n = len(vulndb.SIGNATURES)

    def tearDown(self):
        del vulndb.SIGNATURES[self._n:]              # remove rules this test added

    def _write(self, rules):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"rules": rules}, f)
        f.close()
        return f.name

    def test_loads_rule_and_detects(self):
        path = self._write([{"product": ["acmeapp"], "lt": "2.0", "severity": "high",
                             "title": "AcmeApp < 2.0 RCE", "cves": ["CVE-2099-1111"]}])
        self.assertEqual(vulndb.load_rules(path), 1)
        titles = {v.title for v in vulndb.assess_host(_host(version="1.0.0"))}
        self.assertIn("AcmeApp < 2.0 RCE", titles)
        # patched build is out of range -> not flagged
        self.assertNotIn("AcmeApp < 2.0 RCE",
                         {v.title for v in vulndb.assess_host(_host(version="2.5.0"))})

    def test_negative_matcher_excludes(self):
        # a rule that must NOT be a distro build
        path = self._write([{"product": ["acmeapp"], "lt": "2.0", "severity": "high",
                             "title": "AcmeApp upstream RCE", "absent": ["ubuntu", "debian"]}])
        vulndb.load_rules(path)
        # a distro-tagged banner is excluded by the negative matcher...
        self.assertNotIn("AcmeApp upstream RCE",
                         {v.title for v in vulndb.assess_host(
                             _host(version="1.0.0", extrainfo="Ubuntu 4ubuntu0.1"))})
        # ...but a genuine upstream build matches
        self.assertIn("AcmeApp upstream RCE",
                      {v.title for v in vulndb.assess_host(_host(version="1.0.0"))})

    def test_bad_rule_file_is_safe(self):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        f.write("{ not valid json ")
        f.close()
        self.assertEqual(vulndb.load_rules(f.name), 0)   # never raises
        self.assertEqual(vulndb.load_rules("/no/such/file.json"), 0)


if __name__ == "__main__":
    unittest.main()
