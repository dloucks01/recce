"""Unit tests for the third-party scanner parsers (recce.importers).

Each parser maps a tool's export into recce Vulns, drops info-level noise, and
fails soft (a malformed doc -> []). Samples match the tools' documented schemas.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recce import importers as I   # noqa: E402

NESSUS = '''<?xml version="1.0"?><NessusClientData_v2><Report name="s">
<ReportHost name="10.0.0.5"><HostProperties><tag name="host-ip">10.0.0.5</tag></HostProperties>
<ReportItem port="445" protocol="tcp" severity="4" pluginID="97833" pluginName="MS17-010">
<cve>CVE-2017-0143</cve><synopsis>EternalBlue</synopsis><solution>Patch</solution></ReportItem>
<ReportItem port="0" protocol="tcp" severity="0" pluginID="19506" pluginName="Scan Info">
<description>noise</description></ReportItem></ReportHost></Report></NessusClientData_v2>'''

OPENVAS = '''<?xml version="1.0"?><report><results>
<result><host>10.0.0.9</host><port>443/tcp</port><threat>High</threat>
<nvt oid="1.2"><name>Heartbleed</name><cve>CVE-2014-0160</cve></nvt><description>bleed</description></result>
<result><host>10.0.0.9</host><port>general/tcp</port><threat>Log</threat>
<nvt oid="1.3"><name>noise</name></nvt></result></results></report>'''

NUCLEI = ('{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical",'
          '"classification":{"cve-id":["CVE-2021-44228"]}},"ip":"10.0.0.15",'
          '"matched-at":"http://10.0.0.15:8080/"}')

TESTSSL = ('[{"id":"heartbleed","ip":"web/10.0.0.9","port":"443","severity":"HIGH",'
           '"finding":"vulnerable","cve":"CVE-2014-0160"},'
           '{"id":"cert","ip":"web/10.0.0.9","port":"443","severity":"OK","finding":"ok"}]')


class Detection(unittest.TestCase):
    def test_each_format_is_detected(self):
        self.assertEqual(I.detect_scanner(NESSUS), "nessus")
        self.assertEqual(I.detect_scanner(OPENVAS), "openvas")
        self.assertEqual(I.detect_scanner(NUCLEI), "nuclei")
        self.assertEqual(I.detect_scanner(TESTSSL), "testssl")
        self.assertEqual(I.detect_scanner("just some text"), "")

    def test_malformed_input_never_raises(self):
        for fn in I.SCANNER_PARSERS.values():
            self.assertEqual(fn("<not valid"), [])
            self.assertEqual(fn(""), [])


class Nessus(unittest.TestCase):
    def test_folds_findings_and_drops_info(self):
        vs = I.parse_nessus(NESSUS)
        self.assertEqual(len(vs), 1)               # severity-0 info item dropped
        v = vs[0]
        self.assertEqual((v.ip, v.port, v.severity), ("10.0.0.5", 445, "critical"))
        self.assertIn("CVE-2017-0143", v.ids)
        self.assertEqual(v.source, "nessus")


class OpenVAS(unittest.TestCase):
    def test_threat_maps_to_severity_and_log_dropped(self):
        vs = I.parse_openvas(OPENVAS)
        self.assertEqual(len(vs), 1)
        self.assertEqual((vs[0].ip, vs[0].port, vs[0].severity), ("10.0.0.9", 443, "high"))
        self.assertIn("CVE-2014-0160", vs[0].ids)


class Nuclei(unittest.TestCase):
    def test_jsonl_line_maps_to_vuln(self):
        vs = I.parse_nuclei(NUCLEI)
        self.assertEqual(len(vs), 1)
        self.assertEqual((vs[0].ip, vs[0].port, vs[0].severity), ("10.0.0.15", 8080, "critical"))
        self.assertIn("CVE-2021-44228", vs[0].ids)


class TestSSL(unittest.TestCase):
    def test_severity_findings_kept_ok_dropped(self):
        vs = I.parse_testssl(TESTSSL)
        self.assertEqual(len(vs), 1)               # the OK row is not a finding
        self.assertEqual((vs[0].ip, vs[0].port, vs[0].severity), ("10.0.0.9", 443, "high"))


if __name__ == "__main__":
    unittest.main()
