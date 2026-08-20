"""Report-content fidelity: a whole engagement renders COMPLETELY across every format.

Per-feature report tests check one widget at a time. This drives a realistic multi-host
engagement (a DC, a web server, a database host - with findings at every severity, an
account, AD roles, a domain) through all four report builders at once and asserts the
completeness contract of each:

  * NO host is ever dropped from any format.
  * The COMPLETE formats (HTML detail, the xlsx Vulnerabilities sheet, and the combined
    .docx write-up) carry EVERY finding, at every severity.
  * The summary format (markdown) surfaces the high/critical findings.
  * Engagement data (accounts, AD roles) reaches the workbook.
  * Nothing crashes; every format is non-empty and lists the same set of hosts.

Guards against the "a finding renders in HTML but silently vanishes from the workbook"
class of bug.
"""
import os
import tempfile
import unittest

import openpyxl

from recce import qod, report_docx, report_excel, report_html, report_markdown
from recce.models import Account, Host, Port, Vuln


def _engagement():
    dc = Host(ip="10.0.0.1", hostnames=["DC01"], os_family="Windows",
              roles=["Domain Controller", "Global Catalog"], enumerated=True,
              ports=[Port(portid=445, service="microsoft-ds", state="open"),
                     Port(portid=389, service="ldap", state="open")],
              accounts=[Account(ip="10.0.0.1", source="ldap", kind="user",
                                name="svc_backup", domain="corp.local")])
    dc.vulns = [
        Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="smb",
             title="SMB signing not required", severity="medium", source="config",
             confidence="confirmed", cwes=["CWE-322"]),
        Vuln(ip="10.0.0.1", port=389, protocol="tcp", script_id="ldap",
             title="Anonymous LDAP directory read", severity="high", source="probe",
             confidence="confirmed", cwes=["CWE-306"]),
    ]
    web = Host(ip="10.0.0.10", hostnames=["web01"], os_family="Linux", enumerated=True,
               ports=[Port(portid=80, service="http", product="nginx",
                           version="1.18.0", state="open")])
    web.vulns = [Vuln(ip="10.0.0.10", port=80, protocol="tcp", script_id="version-db",
                      title="nginx DNS resolver off-by-one", severity="high",
                      source="version-db", confidence="likely", ids=["CVE-2021-23017"])]
    db = Host(ip="10.0.0.20", hostnames=["db01"], os_family="Linux", enumerated=True,
              ports=[Port(portid=27017, service="mongodb", state="open")])
    db.vulns = [Vuln(ip="10.0.0.20", port=27017, protocol="tcp", script_id="mongodb",
                     title="MongoDB exposed without authentication", severity="critical",
                     source="probe", confidence="confirmed", cwes=["CWE-306"])]
    hosts = [dc, web, db]
    for h in hosts:
        qod.annotate(h)
    return hosts


def _xlsx_text(path):
    wb = openpyxl.load_workbook(path)
    parts = []
    for ws in wb.worksheets:
        for row in ws.iter_rows(values_only=True):
            parts.append(" ".join(str(c) for c in row if c is not None))
    return " ".join(parts).lower()


def _docx_text(path):
    """All visible text from a .docx (every part first asserted well-formed)."""
    import xml.etree.ElementTree as ET
    import zipfile
    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if n.endswith((".xml", ".rels")):
                ET.fromstring(z.read(n))          # malformed part -> raises here
        root = ET.fromstring(z.read("word/document.xml"))
    return " ".join(t.text or "" for t in root.iter(f"{W}t")).lower()


class ReportContentFidelityTest(unittest.TestCase):

    HOSTS_IPS = ("10.0.0.1", "10.0.0.10", "10.0.0.20")

    @classmethod
    def setUpClass(cls):
        cls.hosts = _engagement()
        cls.all_findings = [v.title.lower() for h in cls.hosts for v in h.vulns]
        cls.notable = [v.title.lower() for h in cls.hosts for v in h.vulns
                       if v.severity in ("critical", "high")]
        cls.dir = tempfile.mkdtemp(prefix="recce-report-fidelity-")
        cls.md_path = os.path.join(cls.dir, "report.md")
        cls.html_path = os.path.join(cls.dir, "report.html")
        cls.xlsx_path = os.path.join(cls.dir, "report.xlsx")
        cls.docx_path = os.path.join(cls.dir, "findings_report.docx")
        report_markdown.build_markdown(cls.hosts, cls.md_path, title="Engagement")
        report_html.build_html(cls.hosts, cls.html_path, title="Engagement")
        report_excel.build_workbook(cls.hosts, cls.xlsx_path)
        report_docx.build_combined(cls.hosts, cls.docx_path, title="Engagement")
        cls.md = open(cls.md_path).read().lower()
        cls.html = open(cls.html_path).read().lower()
        cls.xlsx = _xlsx_text(cls.xlsx_path)
        cls.docx = _docx_text(cls.docx_path)

    def test_every_format_is_non_empty(self):
        for path in (self.md_path, self.html_path, self.xlsx_path, self.docx_path):
            self.assertGreater(os.path.getsize(path), 0, path)

    def test_no_host_is_dropped_from_any_format(self):
        for ip in self.HOSTS_IPS:
            self.assertIn(ip, self.md, f"{ip} missing from markdown")
            self.assertIn(ip, self.html, f"{ip} missing from HTML")
            self.assertIn(ip, self.xlsx, f"{ip} missing from the workbook")
            self.assertIn(ip, self.docx, f"{ip} missing from the combined write-up")

    def test_complete_formats_carry_every_finding(self):
        # HTML detail, the xlsx Vulnerabilities sheet, and the combined .docx must show
        # EVERY finding, at every severity (including the medium one summary formats may
        # omit). The engagement's findings are all real (confirmed/likely) and >= low,
        # so the combined write-up's real-only, low+ filter keeps all of them.
        for title in self.all_findings:
            self.assertIn(title, self.html, f"finding missing from HTML: {title!r}")
            self.assertIn(title, self.xlsx, f"finding missing from the workbook: {title!r}")
            self.assertIn(title, self.docx,
                          f"finding missing from the combined write-up: {title!r}")

    def test_markdown_surfaces_high_and_critical_findings(self):
        for title in self.notable:
            self.assertIn(title, self.md, f"notable finding missing from markdown: {title!r}")

    def test_engagement_data_reaches_the_workbook(self):
        # Accounts and AD roles are engagement data that lands in the workbook.
        self.assertIn("svc_backup", self.xlsx, "account missing from the workbook")
        self.assertIn("domain controller", self.xlsx, "DC role missing from the workbook")

    def test_all_formats_list_the_same_hosts(self):
        # Cross-format consistency: the set of engagement host IPs is identical.
        for blob, name in ((self.md, "markdown"), (self.html, "HTML"),
                           (self.xlsx, "xlsx"), (self.docx, "docx")):
            present = {ip for ip in self.HOSTS_IPS if ip in blob}
            self.assertEqual(present, set(self.HOSTS_IPS),
                             f"{name} host set mismatch: {present}")


if __name__ == "__main__":
    unittest.main()


def test_report_surfaces_kev_known_exploited():
    """group_findings must propagate KEV/EPSS, and the HTML report must surface it
    (exec-summary tile + per-finding badge) - the fix-first signal, previously dropped."""
    import os
    import tempfile

    from recce.models import Host, Port, Vuln
    from recce.report_docx import group_findings
    from recce.report_html import build_html

    h = Host(ip="10.0.0.5", up_reason="syn-ack",
             ports=[Port(portid=445, service="microsoft-ds", state="open")],
             vulns=[Vuln(ip="10.0.0.5", port=445, protocol="tcp", script_id="ms17",
                         title="EternalBlue", severity="critical", ids=["CVE-2017-0144"],
                         kev=True, epss=0.97, source="nse", state="VULNERABLE")])
    f = group_findings([h])[0]
    assert f.kev is True and abs(f.epss - 0.97) < 1e-6

    out = os.path.join(tempfile.mkdtemp(), "report.html")
    build_html([h], out, title="t")
    html = open(out).read()
    assert "Known-exploited" in html       # exec-summary tile
    assert "🔥 KEV" in html                 # per-finding fix-first badge
