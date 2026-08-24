"""High-fidelity integration tests: the whole workflow end-to-end, with a hard
focus on correctness of the spreadsheet - that the RIGHT fields land on the RIGHT
IP row, that per-IP tracking never bleeds across hosts, and that re-scans/updates
preserve everything.

These drive the real parser -> store -> workbook writer -> read-back -> report
paths (no nmap needed) against the bundled sample scan, whose four hosts each
have a distinct fingerprint:

    10.0.10.10  dc01.corp.local  Windows Server 2019  88,389,445,3389  ms17-010
    10.0.10.25  ws01.corp.local  Windows 10 21H2      135,445,3389     (no vulns)
    10.0.20.5   web01            Linux 5.4            22,80,443        4 vulns
    10.0.20.6   web02            Linux 5.4            22,80,21,3306    ftp-anon
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce import ad, parser, xlsx
from recce import tracking as tr
from recce.models import Host, Port, Vuln
from recce.report_excel import (build_workbook, read_key_order,
                                 read_workbook_edits, read_workbook_tracking,
                                 update_workbook, STATUS_WIP, STATUS_TODO)
from recce.store import Store
from recce.targets import _subnet_of

SAMPLE = os.path.join(os.path.dirname(parser.__file__), "sample_scan.xml")

# Ground-truth facts, keyed by IP, for cross-checking the spreadsheet.
FACTS = {
    "10.0.10.10": {"host": "dc01.corp.local", "os": "Windows Server 2019",
                   "ports": [88, 389, 445, 3389], "nvulns": 1},
    "10.0.10.25": {"host": "ws01.corp.local", "os": "Windows 10",
                   "ports": [135, 445, 3389], "nvulns": 0},
    "10.0.20.5": {"host": "web01", "os": "Linux",
                  "ports": [22, 80, 443], "nvulns": 4},
    "10.0.20.6": {"host": "web02", "os": "Linux",
                  "ports": [21, 22, 80, 3306], "nvulns": 1},
}


def sample_hosts():
    hosts = parser.parse_nmap_xml(SAMPLE)
    for h in hosts:
        h.subnet = _subnet_of(h.ip)
        h.enumerated = True
    ad.analyze_hosts(hosts)
    return hosts


def header_index(rows, *must_have):
    """Row index of the real column-header row (the first row that holds every
    token in must_have). A legend/note line can precede the header, so we locate
    it instead of assuming row 0."""
    for i, r in enumerate(rows):
        if all(tok in r for tok in must_have):
            return i
    return 0


def rows_by_ip(sheets, title):
    """Return (header, {ip: [row-as-dict, ...]}) for a sheet with an IP column.

    Skips collapsible group-header band rows (they carry a label in the IP column
    but no Key), so callers only see real data rows keyed by a bare IP."""
    rows = sheets[title]
    hidx = header_index(rows, "IP")
    hdr = rows[hidx]
    ipc = hdr.index("IP")
    kidx = hdr.index("Key") if "Key" in hdr else None
    out: dict = {}
    for r in rows[hidx + 1:]:
        if kidx is not None and (len(r) <= kidx or not r[kidx]):
            continue                       # group-header band row - not data
        if len(r) > ipc and r[ipc]:
            out.setdefault(str(r[ipc]), []).append(dict(zip(hdr, r)))
    return hdr, out




# Re-export helpers so a caller could `from _workflow_helpers import ...` too.
from _workflow_helpers import SAMPLE, FACTS, sample_hosts, header_index, rows_by_ip  # noqa: F401





class ChecklistPerIpFidelityTest(unittest.TestCase):
    """Every host's Checklist row carries ITS OWN facts - no cross-IP bleed."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = os.path.join(self.d, "wb.xlsx")
        build_workbook(sample_hosts(), self.out)
        self.sheets = xlsx.read_sheets(self.out)

    def test_each_ip_row_has_its_own_identity(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Checklist")
        self.assertEqual(set(by_ip), set(FACTS))
        for ip, facts in FACTS.items():
            self.assertEqual(len(by_ip[ip]), 1, f"{ip} should be exactly one row")
            row = by_ip[ip][0]
            self.assertEqual(row["Hostname"], facts["host"])
            self.assertIn(facts["os"].split()[0], row["OS"])
            self.assertEqual(str(row["# Vulns"]), str(facts["nvulns"]))
            # Open-ports cell lists exactly this host's ports, in order.
            self.assertEqual(row["Open ports"],
                             ", ".join(str(p) for p in facts["ports"]))

    def test_dc_role_only_on_the_dc_row(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Checklist")
        self.assertIn("Domain Controller", by_ip["10.0.10.10"][0]["Roles"])
        for ip in ("10.0.20.5", "10.0.20.6"):
            self.assertNotIn("Domain Controller", by_ip[ip][0]["Roles"] or "")

    def test_surface_steps_match_host_type(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Checklist")
        # DC: AD applies (☐, manual), Web/DB do not (—).
        dc = by_ip["10.0.10.10"][0]
        self.assertEqual(dc["AD"], xlsx.CHECK_OFF)
        self.assertEqual(dc["Web"], tr.STEP_NA)
        self.assertEqual(dc["DB"], tr.STEP_NA)
        # web01: Web applies, AD does not, DB does not.
        web = by_ip["10.0.20.5"][0]
        self.assertEqual(web["Web"], xlsx.CHECK_OFF)
        self.assertEqual(web["AD"], tr.STEP_NA)
        self.assertEqual(web["DB"], tr.STEP_NA)
        # web02: has MySQL -> DB applies.
        self.assertEqual(by_ip["10.0.20.6"][0]["DB"], xlsx.CHECK_OFF)




class ServicesPerIpFidelityTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = os.path.join(self.d, "wb.xlsx")
        build_workbook(sample_hosts(), self.out)
        self.sheets = xlsx.read_sheets(self.out)

    def test_every_service_row_maps_port_to_correct_ip(self):
        hdr, by_ip = rows_by_ip(self.sheets, "Services")
        for ip, facts in FACTS.items():
            got = sorted(int(r["Port"]) for r in by_ip.get(ip, []))
            self.assertEqual(got, sorted(facts["ports"]),
                             f"{ip} services should be exactly its own ports")
        # The FTP service (21) exists on web02 ONLY.
        ftp_rows = [r for rs in by_ip.values() for r in rs if str(r["Port"]) == "21"]
        self.assertEqual(len(ftp_rows), 1)
        self.assertEqual(ftp_rows[0]["IP"], "10.0.20.6")
        self.assertIn("ftp", ftp_rows[0]["Service"].lower())

    def test_hostname_rides_in_the_collapsible_ip_band(self):
        # Hostname is no longer a per-row column; it appears once in each host's
        # collapsible band (IP · hostname · N ports), not repeated on every port row.
        rows = self.sheets["Services"]
        self.assertNotIn("Hostname", rows[0])
        ipc = rows[0].index("IP")
        bands = " ".join(str(r[ipc]) for r in rows[1:] if "·" in str(r[ipc]))
        for ip, facts in FACTS.items():
            if facts["host"]:
                self.assertIn(facts["host"], bands)




class VulnerabilitiesPerIpFidelityTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.out = os.path.join(self.d, "wb.xlsx")
        build_workbook(sample_hosts(), self.out)
        self.sheets = xlsx.read_sheets(self.out)

    def test_findings_attributed_to_correct_ip(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Vulnerabilities")
        # ms17-010 is on the DC only.
        dc_finds = " ".join(r["Finding"] for r in by_ip.get("10.0.10.10", []))
        self.assertIn("ms17-010", dc_finds)
        # ...and NOT attributed to any other host.
        for ip in ("10.0.20.5", "10.0.20.6", "10.0.10.25"):
            self.assertNotIn("ms17-010",
                             " ".join(r["Finding"] for r in by_ip.get(ip, [])))
        # ftp-anon is web02 only.
        self.assertIn("FTP", " ".join(r["Finding"] for r in by_ip.get("10.0.20.6", [])))

    def test_grouped_by_host_no_hostname_col_and_full_details(self):
        from recce.report_excel import build_workbook
        from recce.models import Host, Port, Vuln
        rows = self.sheets["Vulnerabilities"]
        hdr = rows[0]
        self.assertNotIn("Hostname", hdr)                 # Hostname moved to the band
        ipc = hdr.index("IP")
        # A collapsible per-host band exists (IP · hostname · N findings · worst ...).
        bands = [str(r[ipc]) for r in rows[1:] if "finding" in str(r[ipc])]
        self.assertTrue(bands)
        self.assertTrue(any("worst:" in b for b in bands))
        # Details is shown IN FULL (wrapped), never truncated with an ellipsis.
        big = "A" * 1200
        h = Host(ip="10.9.9.9", subnet="10.9.9.0/24", state="up", enumerated=True,
                 ports=[Port(portid=445, service="smb")],
                 vulns=[Vuln(ip="10.9.9.9", port=445, protocol="tcp", script_id="x",
                             title="f", severity="high", source="nse", state="finding",
                             output=big)])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook([h], out)
            vr = xlsx.read_sheets(out)["Vulnerabilities"]
        dc = vr[0].index("Details")
        detail = next(str(r[dc]) for r in vr[1:] if len(r) > dc and "A" in str(r[dc]))
        self.assertEqual(detail, big)                     # full, untruncated
        self.assertNotIn("…", detail)

    def test_exploit_column_proven_vs_candidate(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Vulnerabilities")
        self.assertIn("Exploit", _hdr)
        self.assertNotIn("Proven exploit", _hdr)
        # The DC's ms17-010 finding carries the proven EternalBlue exploit (curated).
        dc = by_ip["10.0.10.10"]
        ms17 = next(r for r in dc if "ms17-010" in r["Finding"])
        self.assertIn("eternalblue", ms17["Exploit"].lower())
        # A potential/advisory finding (now shown by its low QoD tier) never claims
        # an exploit.
        for r in dc:
            if "banner_unreliable" in r["QoD"]:
                self.assertEqual(r["Exploit"], "")
        # A config/hardening finding (weak TLS cipher/protocol, missing header)
        # never gets a PROVEN exploit, even if a CVE leaked into its output.
        for rs in by_ip.values():
            for r in rs:
                f = r["Finding"].lower()
                if any(k in f for k in ("weak", "cipher", "tlsv1", "missing", "header")):
                    self.assertFalse(r["Exploit"].startswith(("Metasploit", "impacket")),
                                     f"hardening finding wrongly proven: {r['Finding']}")
        # searchsploit hits are shown as CANDIDATES to verify, never as proof.
        for rs in by_ip.values():
            for r in rs:
                if r["Exploit"].startswith("candidate"):
                    self.assertIn("verify", r["Exploit"].lower())
        # Overview 'curated exploit' tile counts only the curated (non-candidate) ones.
        n_proven = sum(1 for rs in by_ip.values() for r in rs
                       if r["Exploit"] and not r["Exploit"].startswith("candidate"))
        ov = ["|".join(str(c) for c in r) for r in self.sheets["Overview"]]
        self.assertTrue(any(f"Findings with a curated exploit|{n_proven}" in t for t in ov))
        self.assertEqual(by_ip.get("10.0.10.25", []), [])

    def test_vuln_row_counts_match_per_host(self):
        _hdr, by_ip = rows_by_ip(self.sheets, "Vulnerabilities")
        for ip, facts in FACTS.items():
            self.assertEqual(len(by_ip.get(ip, [])), facts["nvulns"], ip)




class TrackingIsolationTest(unittest.TestCase):
    """Ticking a box for one IP must never touch another IP's tracking."""

    def test_reviewing_one_host_isolates_to_that_key(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "s.sqlite"))
            for h in sample_hosts():
                store.upsert_host(h)
            store.set_reviewed(tr.host_key("10.0.20.5"), True, notes="looked at web01")
            got = store.get_tracking()
            self.assertTrue(got[tr.host_key("10.0.20.5")][0])
            for ip in ("10.0.10.10", "10.0.10.25", "10.0.20.6"):
                self.assertNotIn(tr.host_key(ip), got)
            store.close()

    def test_step_and_status_keys_are_per_ip(self):
        # Distinct hosts, same open port -> distinct svc/step keys, no collision.
        a = tr.svc_key("10.0.20.5", "tcp", 80)
        b = tr.svc_key("10.0.20.6", "tcp", 80)
        self.assertNotEqual(a, b)
        self.assertNotEqual(tr.step_key("vuln", "10.0.20.5"),
                            tr.step_key("vuln", "10.0.20.6"))
        self.assertNotEqual(tr.vuln_key("10.0.20.5", 80, "http-x"),
                            tr.vuln_key("10.0.20.6", 80, "http-x"))

    def test_workbook_reviewed_readback_targets_the_edited_ip(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            hosts = sample_hosts()
            # Operator ticks Reviewed for web02 (10.0.20.6) only.
            build_workbook(hosts, out,
                           tracking={tr.host_key("10.0.20.6"): (True, "done")})
            back = read_workbook_tracking(out)
            self.assertTrue(back[tr.host_key("10.0.20.6")][0])
            for ip in ("10.0.10.10", "10.0.10.25", "10.0.20.5"):
                self.assertFalse(back.get(tr.host_key(ip), (False, ""))[0])

    def test_per_port_status_isolates_to_one_service_row(self):
        # Every service row carries a Status (default "Not started"); only the one
        # we set should read back as In-progress - no other row is elevated.
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            k = tr.svc_key("10.0.20.6", "tcp", 21)
            build_workbook(sample_hosts(), out, statuses={k: STATUS_WIP})
            _edits, statuses = read_workbook_edits(out)
            self.assertEqual(statuses.get(k), STATUS_WIP)
            others = {kk: v for kk, v in statuses.items() if kk != k}
            self.assertTrue(others, "other service rows should still be present")
            self.assertTrue(all(v == STATUS_TODO for v in others.values()),
                            "no other port should be marked in-progress/done")




class MergeRescanFidelityTest(unittest.TestCase):
    """Re-scanning a host merges into the right IP and leaves others untouched."""

    def test_rescan_merges_ports_flags_vulns_without_touching_other_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "s.sqlite"))
            a1 = Host(ip="10.0.0.5", subnet="10.0.0.0/24", enumerated=True,
                      hostnames=["a"], ports=[Port(portid=80, service="http")])
            b = Host(ip="10.0.0.9", subnet="10.0.0.0/24", enumerated=True,
                     hostnames=["b"], ports=[Port(portid=22, service="ssh")])
            store.upsert_host(a1)
            store.upsert_host(b)
            # Re-scan A: new port + a vuln + db flag; same vuln twice to test dedup.
            v = Vuln(ip="10.0.0.5", port=443, protocol="tcp", script_id="ssl-x",
                     title="weak tls", severity="medium")
            a2 = Host(ip="10.0.0.5", subnet="10.0.0.0/24", db_scanned=True,
                      ports=[Port(portid=443, service="https")], vulns=[v, v])
            store.upsert_host(a2)

            A = store.get_host("10.0.0.5")
            self.assertEqual(sorted(p.portid for p in A.ports), [80, 443])
            self.assertTrue(A.enumerated)          # preserved from first scan
            self.assertTrue(A.db_scanned)           # merged from rescan
            self.assertEqual(len(A.vulns), 1)       # deduped
            # B is completely untouched.
            B = store.get_host("10.0.0.9")
            self.assertEqual([p.portid for p in B.ports], [22])
            self.assertEqual(B.vulns, [])
            store.close()

    def test_regenerate_preserves_row_order_and_appends_new_host(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            hosts = sample_hosts()
            build_workbook(hosts, out)
            order_before = read_key_order(out)["Checklist"]
            # A new host is discovered on a later scan.
            newh = Host(ip="10.0.20.99", subnet="10.0.20.0/24", enumerated=True,
                        hostnames=["new"], ports=[Port(portid=8080, service="http")])
            update_workbook(out, hosts + [newh])
            order_after = read_key_order(out)["Checklist"]
            # Existing rows keep their exact positions; the new one is appended.
            self.assertEqual(order_after[:len(order_before)], order_before)
            self.assertEqual(order_after[-1], tr.host_key("10.0.20.99"))




class CoverageMathFidelityTest(unittest.TestCase):
    def test_marking_one_host_counts_once_in_the_right_subnet(self):
        hosts = sample_hosts()
        tracking = {tr.host_key("10.0.10.10"): (True, "")}
        cov = tr.compute_coverage(hosts, tracking)
        self.assertEqual(cov["hosts"]["total"], 4)
        self.assertEqual(cov["hosts"]["done"], 1)
        sc = tr.subnet_coverage(hosts, tracking)
        self.assertEqual(sc["10.0.10.0/24"]["done"], 1)   # the DC's subnet
        self.assertEqual(sc["10.0.10.0/24"]["total"], 2)
        self.assertEqual(sc["10.0.20.0/24"]["done"], 0)   # other subnet unaffected

    def test_service_coverage_counts_all_open_ports(self):
        hosts = sample_hosts()
        keys = tr.item_keys(hosts)
        total_ports = sum(len(h.open_ports) for h in hosts)
        self.assertEqual(len(keys["services"]), total_ports)
        # Mark exactly one service done -> coverage done == 1.
        k = tr.svc_key("10.0.20.6", "tcp", 21)
        cov = tr.compute_coverage(hosts, {k: (True, "")})
        self.assertEqual(cov["services"]["done"], 1)

    def test_overview_phase_table_honors_operator_override(self):
        """Regression: the Overview per-subnet phase table must reflect an
        operator un-tick the same way the Checklist does, or the two diverge."""
        try:
            import openpyxl
        except ImportError:
            self.skipTest("openpyxl not installed (test-only dependency)")
        from recce.report_excel import build_workbook

        def enum_cell(path):
            ov = openpyxl.load_workbook(path)["Overview"]
            for row in ov.iter_rows(values_only=True):
                if row and row[0] == "10.0.0.0/24":
                    return row[3]   # "Enumerated" column
        hosts = [Host(ip="10.0.0.5", subnet="10.0.0.0/24", enumerated=True, state="up",
                      ports=[Port(portid=80, service="http", state="open")]),
                 Host(ip="10.0.0.6", subnet="10.0.0.0/24", enumerated=True, state="up",
                      ports=[Port(portid=80, service="http", state="open")])]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "wb.xlsx")
            build_workbook(hosts, p, tracking={})
            self.assertEqual(enum_cell(p), "2/2")
            build_workbook(hosts, p,
                           tracking={tr.step_key("enum", "10.0.0.6"): (False, "redo")})
            self.assertEqual(enum_cell(p), "1/2")

    def test_accounts_differing_only_by_rid_dont_collide(self):
        """Regression: the store keeps accounts distinct by rid, so acct_key must
        include rid or two such accounts collapse to one row + undercount."""
        from recce.models import Account
        a = Account(ip="10.0.0.5", source="ldap", kind="user", name="svc", domain="corp", rid="1103")
        b = Account(ip="10.0.0.5", source="ldap", kind="user", name="svc", domain="corp", rid="1104")
        ka = tr.acct_key(a.source, a.kind, a.domain, a.name, a.rid)
        kb = tr.acct_key(b.source, b.kind, b.domain, b.name, b.rid)
        self.assertNotEqual(ka, kb)
        # A rid-less account keeps its historical (colon-free) key.
        self.assertEqual(tr.acct_key("ldap", "share", "corp", "SYSVOL"),
                         "acct:ldap:share:corp:SYSVOL")
        h = Host(ip="10.0.0.5", accounts=[a, b])
        self.assertEqual(len(tr.item_keys([h])["accounts"]), 2)




class WriteupPerIpFidelityTest(unittest.TestCase):
    def test_grouped_finding_lists_only_the_affected_ip(self):
        from recce.report_docx import group_findings
        findings = group_findings(sample_hosts())
        ms17 = next(f for f in findings if "ms17-010" in f.title.lower())
        self.assertEqual(sorted({a[0] for a in ms17.affected}), ["10.0.10.10"])
        ftp = next(f for f in findings if "ftp" in f.title.lower())
        self.assertEqual(sorted({a[0] for a in ftp.affected}), ["10.0.20.6"])

    def test_shared_finding_across_hosts_lists_all_affected(self):
        # Two hosts with the same finding title -> one write-up, both IPs.
        from recce.report_docx import group_findings
        hosts = [
            Host(ip="10.0.0.1", ports=[Port(portid=443, service="https")],
                 vulns=[Vuln(ip="10.0.0.1", port=443, protocol="tcp",
                             script_id="ssl", title="Weak TLS", severity="medium")]),
            Host(ip="10.0.0.2", ports=[Port(portid=443, service="https")],
                 vulns=[Vuln(ip="10.0.0.2", port=443, protocol="tcp",
                             script_id="ssl", title="Weak TLS", severity="medium")]),
        ]
        f = group_findings(hosts)[0]
        self.assertEqual(sorted({a[0] for a in f.affected}),
                         ["10.0.0.1", "10.0.0.2"])

    def test_generated_docx_contains_correct_ip_only(self):
        from recce.report_docx import build_writeups
        import zipfile
        import xml.etree.ElementTree as ET
        W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "w")
            build_writeups(sample_hosts(), out)
            fn = next(p for p in os.listdir(out) if "ms17" in p)
            root = ET.fromstring(zipfile.ZipFile(os.path.join(out, fn))
                                 .read("word/document.xml"))
            text = "\n".join("".join(t.text or "" for t in p.iter(f"{W}t"))
                             for p in root.iter(f"{W}p"))
            self.assertIn("10.0.10.10", text)          # the affected host
            self.assertNotIn("10.0.20.5", text)         # not an unrelated host




class MarkdownCsvFidelityTest(unittest.TestCase):
    def test_markdown_attributes_findings_to_correct_host(self):
        from recce.report_markdown import build_markdown
        with tempfile.TemporaryDirectory() as d:
            md = os.path.join(d, "r.md")
            build_markdown(sample_hosts(), md, title="Eng", domains=[])
            with open(md) as fh:
                text = fh.read()
        self.assertIn("Eng", text)
        self.assertIn("10.0.10.10", text)
        # The DC's finding is present and tied to the DC's IP line.
        dc_line = next(ln for ln in text.splitlines()
                       if "ms17-010" in ln)
        self.assertIn("10.0.10.10", dc_line)

    def test_csv_one_row_per_open_port_with_correct_ip(self):
        import csv as csvmod
        from recce.report_markdown import build_csv
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "s.csv")
            build_csv(sample_hosts(), p)
            with open(p) as fh:
                rows = list(csvmod.reader(fh))
        hdr, data = rows[0], rows[1:]
        self.assertEqual(len(data), sum(len(FACTS[ip]["ports"]) for ip in FACTS))
        ipc, portc = hdr.index("ip"), hdr.index("port")
        # The FTP port row (21) belongs to web02.
        ftp = [r for r in data if r[portc] == "21"]
        self.assertEqual(len(ftp), 1)
        self.assertEqual(ftp[0][ipc], "10.0.20.6")
        # Every row's port genuinely belongs to that row's IP.
        for r in data:
            self.assertIn(int(r[portc]), FACTS[r[ipc]]["ports"])
