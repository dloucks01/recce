"""Offline tests for the enumeration pipeline (no network / nmap needed)."""

import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce import ad
from recce.core import parser, scanner
from recce.vuln import exploits
from recce.core import tracking as tr
from recce.report.formats import xlsx
from recce.core.models import Account, Host, Port, Script, Vuln
from recce.report.excel import (build_workbook, read_workbook_tracking,
                                       update_workbook)
from recce.core.store import Store
from recce.core.targets import apply_exclusions, load_targets

SAMPLE = os.path.join(os.path.dirname(parser.__file__), "sample_scan.xml")


def header_index(rows, *must_have):
    """Row index of the real column-header row (first row holding every token in
    must_have). The Checklist puts a legend line above its header, so callers must
    locate it rather than assume row 0."""
    for i, r in enumerate(rows):
        if all(tok in r for tok in must_have):
            return i
    return 0


class TargetsTest(unittest.TestCase):
    def test_cidr_and_range(self):
        hosts, sm, _ = load_targets(["10.0.0.0/30", "192.168.1.5-8"])
        self.assertEqual(hosts, ["10.0.0.1", "10.0.0.2", "192.168.1.5",
                                 "192.168.1.6", "192.168.1.7", "192.168.1.8"])
        # A CIDR token becomes the subnet label for its hosts.
        self.assertEqual(sm["10.0.0.1"], "10.0.0.0/30")
        # A bare range falls back to a /24 label.
        self.assertEqual(sm["192.168.1.5"], "192.168.1.0/24")

    def test_exclusions(self):
        hosts, _, _ = load_targets(["192.168.1.0/29"])
        kept = apply_exclusions(hosts, ["192.168.1.1", "192.168.1.2-3"])
        self.assertNotIn("192.168.1.1", kept)
        self.assertNotIn("192.168.1.3", kept)
        self.assertIn("192.168.1.4", kept)

    def test_dedup(self):
        hosts, _, _ = load_targets(["10.0.0.1", "10.0.0.1", "10.0.0.0/30"])
        self.assertEqual(hosts.count("10.0.0.1"), 1)

    def test_range_drops_network_and_broadcast(self):
        # A full-octet range means "the subnet", not "scan .0 and .255".
        hosts, _, _ = load_targets(["10.200.37.0-255"])
        self.assertNotIn("10.200.37.0", hosts)
        self.assertNotIn("10.200.37.255", hosts)
        self.assertIn("10.200.37.1", hosts)
        self.assertIn("10.200.37.254", hosts)

    def test_explicit_single_dot_zero_is_respected(self):
        # An explicitly-typed single address is kept (the user asked for it).
        hosts, _, _ = load_targets(["10.200.37.0"])
        self.assertEqual(hosts, ["10.200.37.0"])

    def test_exclude_accepts_ips_cidrs_and_file(self):
        from recce.core.targets import apply_exclusions, expand_excludes
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "ex.txt")
            with open(f, "w") as fh:
                fh.write("10.0.0.9 badbox\n10.0.0.16/30\n# note\n")
            ex = expand_excludes(["10.0.0.5", "@" + f, "192.168.1.1"])
        self.assertIn("10.0.0.5", ex)
        self.assertIn("10.0.0.9", ex)          # IP from an 'IP hostname' file line
        self.assertIn("10.0.0.17", ex)         # from the CIDR in the file
        self.assertIn("192.168.1.1", ex)
        kept = apply_exclusions(["10.0.0.5", "10.0.0.6", "192.168.1.1"],
                                ["10.0.0.5", "192.168.1.1"])
        self.assertEqual(kept, ["10.0.0.6"])

    def test_file_parses_ip_hostname_pairs(self):
        # An authoritative @file may carry IP+hostname (space / comma / tab / hosts-
        # file style); the name is captured and the IP is still the scan target.
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "scope.txt")
            with open(f, "w") as fh:
                fh.write("10.0.0.5 dc01.corp.local\n"
                         "10.0.0.6,web01\n"
                         "10.0.0.7\tmail01 alias.corp\n"
                         "10.0.0.0/30\n"          # a CIDR: no bogus name attached
                         "# a comment line\n"
                         "\n"
                         "203.0.113.9\n")         # bare IP, no name
            hosts, _, names = load_targets(["@" + f])
        self.assertIn("10.0.0.5", hosts)
        self.assertIn("10.0.0.1", hosts)          # CIDR expanded
        self.assertEqual(names["10.0.0.5"], "dc01.corp.local")
        self.assertEqual(names["10.0.0.6"], "web01")
        self.assertEqual(names["10.0.0.7"], "mail01")   # first non-IP token wins
        self.assertNotIn("10.0.0.1", names)       # a CIDR line gets no hostname
        self.assertNotIn("203.0.113.9", names)


class ParserTest(unittest.TestCase):
    def setUp(self):
        self.hosts = parser.parse_nmap_xml(SAMPLE)

    def test_host_count(self):
        self.assertEqual(len(self.hosts), 4)

    def test_hostnames_and_os(self):
        dc = next(h for h in self.hosts if h.ip == "10.0.10.10")
        self.assertEqual(dc.hostname, "dc01.corp.local")
        self.assertEqual(dc.os_family, "Windows")
        self.assertEqual(len(dc.open_ports), 4)

    def test_vuln_severity(self):
        # ms17-010 (CVSSv2 9.3) -> critical
        dc = next(h for h in self.hosts if h.ip == "10.0.10.10")
        sev = {v.script_id: v.severity for v in dc.vulns}
        self.assertEqual(sev["smb-vuln-ms17-010"], "critical")

    def test_vulners_score_parsed(self):
        # vulners line "CVE-2021-42013 9.8" -> critical
        web = next(h for h in self.hosts if h.ip == "10.0.20.5")
        self.assertTrue(any(v.severity == "critical" for v in web.vulns))

    def test_cvss_vector_not_misread_as_score(self):
        """Regression: a CVSS vector string ('CVSS:3.1/AV:N/...') must not be
        read as base score 3.1 (which downgraded criticals to 'low'); the
        'Base Score' phrasing must be recognized."""
        from recce.core.parser import _classify_vuln
        from recce.core.models import Script, Port
        p = Port(portid=443, protocol="tcp", service="https")
        # Vector + explicit base score 9.8 -> must classify critical, not low.
        out = ("VULNERABLE\nCVE-2021-44228\n"
               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
               "CVSS Base Score: 9.8\n")
        v = _classify_vuln("10.0.0.5", p, Script(id="vuln-log4shell", output=out))
        self.assertEqual(v.severity, "critical")
        # Vector ONLY (no numeric score) must not become 'low' via the 3.1.
        v2 = _classify_vuln("10.0.0.5", p, Script(
            id="vuln-x", output="VULNERABLE\nCVE-2021-1\nCVSS:3.1/AV:N/AC:L\n"))
        self.assertNotEqual(v2.severity, "low")

    def test_not_vulnerable_is_not_a_finding(self):
        """Regression (audit): a patched host whose NSE script prints
        'State: NOT VULNERABLE' must NOT produce a Vuln — the substring
        'VULNERABLE' inside 'NOT VULNERABLE' previously created a false high."""
        from recce.core.parser import _classify_vuln
        from recce.core.models import Script, Port
        p = Port(portid=445, protocol="tcp", service="microsoft-ds")
        self.assertIsNone(_classify_vuln(
            "10.0.0.9", p, Script(id="smb-vuln-ms17-010",
                                  output="\n  State: NOT VULNERABLE\n")))
        # A genuinely VULNERABLE result with no embedded CVSS is still a finding,
        # and a known-RCE family rates critical (not the generic 'high').
        v = _classify_vuln("10.0.0.9", p, Script(
            id="smb-vuln-ms17-010", output="\n  State: VULNERABLE\n"))
        self.assertIsNotNone(v)
        self.assertEqual(v.severity, "critical")

    def test_ad_users_extracted(self):
        dc = next(h for h in self.hosts if h.ip == "10.0.10.10")
        users = [a.name for a in dc.accounts if a.kind == "user"]
        self.assertIn("Administrator", users)
        self.assertIn("svc_sql", users)


class VulnDbRangeTest(unittest.TestCase):
    """Regression (audit): version-range accuracy for false-finding-prone sigs."""

    def _ssh(self, ver):
        from recce.vuln import vulndb
        from recce.core.models import Host, Port
        h = Host(ip="1.1.1.1", ports=[Port(portid=22, protocol="tcp", service="ssh",
                                           product="OpenSSH", version=ver)])
        vulndb.assess_host_inplace(h)
        return [v.title for v in h.vulns]

    def test_regresshion_range_not_eq_patched(self):
        # 9.8p1 is the FIX — must not be flagged; 9.6p1 is vulnerable — must be.
        self.assertFalse(any("regreSSHion" in t for t in self._ssh("9.8p1")))
        self.assertTrue(any("regreSSHion" in t for t in self._ssh("9.6p1")))

    def test_os_version_maps_windows_product_names(self):
        # BlueKeep os_lt gate needs an NT version from nmap's product-name OS string.
        from recce.vuln import vulndb
        from recce.core.models import Host
        self.assertEqual(vulndb._os_version(Host(ip="x", os_name="Microsoft Windows 7")), "6.1")
        self.assertEqual(vulndb._os_version(
            Host(ip="x", os_name="Microsoft Windows Server 2008 R2")), "6.1")
        self.assertEqual(vulndb._os_version(
            Host(ip="x", os_name="Microsoft Windows Server 2012")), "6.2")


class ProductGroupingTest(unittest.TestCase):
    def test_same_version_groups(self):
        hosts = parser.parse_nmap_xml(SAMPLE)
        keys = {}
        for h in hosts:
            for p in h.open_ports:
                keys.setdefault(p.product_version_key, []).append(h.ip)
        apache = next(k for k in keys if k.startswith("Apache httpd|2.4.41"))
        self.assertEqual(len(keys[apache]), 3)


class StoreMergeTest(unittest.TestCase):
    def test_merge_upsert(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "t.sqlite")
            store = Store(db)
            h1 = Host(ip="1.2.3.4", ports=[Port(portid=80, service="http")])
            store.upsert_host(h1)
            # Second scan adds a port and enriches OS.
            h2 = Host(ip="1.2.3.4", os_name="Linux", os_accuracy=95,
                      ports=[Port(portid=443, service="https")],
                      accounts=[Account(ip="1.2.3.4", source="smb", name="bob")])
            store.upsert_host(h2)
            merged = store.get_host("1.2.3.4")
            self.assertEqual({p.portid for p in merged.ports}, {80, 443})
            self.assertEqual(merged.os_name, "Linux")
            self.assertEqual(len(merged.accounts), 1)
            store.close()
class TrackingRoundTripTest(unittest.TestCase):
    def test_prefill_and_readback(self):
        hosts = parser.parse_nmap_xml(SAMPLE)
        ad.analyze_hosts(hosts)
        tracking = {
            tr.host_key("10.0.10.10"): (True, "DC reviewed"),
            tr.svc_key("10.0.20.5", "tcp", 80): (True, ""),
        }
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook(hosts, out, tracking=tracking)
            back = read_workbook_tracking(out)
        self.assertTrue(back[tr.host_key("10.0.10.10")][0])
        self.assertEqual(back[tr.host_key("10.0.10.10")][1], "DC reviewed")
        self.assertTrue(back[tr.svc_key("10.0.20.5", "tcp", 80)][0])
        self.assertFalse(back[tr.host_key("10.0.20.6")][0])
class InPlaceUpdateTest(unittest.TestCase):
    def _hosts(self, ips):
        out = []
        for ip in ips:
            h = Host(ip=ip, subnet="10.0.0.0/24", ports=[Port(portid=80, service="http")])
            out.append(h)
        return out

    def test_new_ip_appended_order_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            # First generation, mark the first host reviewed.
            build_workbook(self._hosts(["10.0.0.10", "10.0.0.20"]), out,
                           tracking={tr.host_key("10.0.0.10"): (True, "done")})
            # A new IP that would sort to the TOP if re-sorted.
            update_workbook(out, self._hosts(["10.0.0.10", "10.0.0.20", "10.0.0.1"]),
                            tracking={tr.host_key("10.0.0.10"): (True, "done")})
            rows = xlsx.read_sheets(out)["Checklist"]
            hidx = header_index(rows, "IP")
            hdr = rows[hidx]
            ipc = hdr.index("IP")
            # Skip the collapsible subnet band rows (empty Reviewed checkbox cell).
            data_rows = [r for r in rows[hidx + 1:]
                         if r[0] in (xlsx.CHECK_ON, xlsx.CHECK_OFF)]
            ips = [r[ipc] for r in data_rows]
        # Existing order kept; new IP appended last (not sorted in).
        self.assertEqual(ips, ["10.0.0.10", "10.0.0.20", "10.0.0.1"])
        self.assertEqual(data_rows[0][0], xlsx.CHECK_ON)  # first host still reviewed


class XlsxEngineTest(unittest.TestCase):
    def test_write_read_roundtrip(self):
        wb = xlsx.Workbook()
        sh = wb.add_sheet("S")
        sh.write([("H1", "header"), ("Key", "header")])
        sh.write([("val,with&special<chars>", None), "k1"])
        sh.write([(42, None), "k2"])
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.xlsx")
            wb.save(p)
            rows = xlsx.read_sheets(p)["S"]
        self.assertEqual(rows[1][0], "val,with&special<chars>")
        self.assertEqual(rows[2][0], "42")

    def test_col_letter(self):
        self.assertEqual(xlsx.col_letter(1), "A")
        self.assertEqual(xlsx.col_letter(27), "AA")
def _docx_text(path):
    import zipfile
    import xml.etree.ElementTree as ET
    W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():          # every xml part must be well-formed
            if n.endswith((".xml", ".rels")):
                ET.fromstring(z.read(n))
        root = ET.fromstring(z.read("word/document.xml"))
        parts = z.namelist()
    return "\n".join("".join(t.text or "" for t in p.iter(f"{W}t"))
                     for p in root.iter(f"{W}p")), parts
class CredEnumTest(unittest.TestCase):
    NXC = (
        r"SMB  10.0.0.10  445  DC01  [*] Windows Server 2019 Build 17763 "
        r"(name:DC01) (domain:corp.local) (signing:True)" "\n"
        r"SMB  10.0.0.10  445  DC01  [+] corp.local\admin:Pw (Pwn3d!)" "\n"
        r"SMB  10.0.0.10  445  DC01  [*] Enumerated shares" "\n"
        r"SMB  10.0.0.10  445  DC01  Share    Permissions   Remark" "\n"
        r"SMB  10.0.0.10  445  DC01  -----    -----------   ------" "\n"
        r"SMB  10.0.0.10  445  DC01  ADMIN$   READ,WRITE    Remote Admin" "\n"
        r"SMB  10.0.0.10  445  DC01  [*] Enumerated domain user(s)" "\n"
        r"SMB  10.0.0.10  445  DC01  corp.local\Administrator  badpwdcount: 0" "\n"
        r"SMB  10.0.0.10  445  DC01  [+] Dumping password info for domain: CORP" "\n"
        r"SMB  10.0.0.10  445  DC01  Account lockout threshold: None"
    )

    def test_parse_nxc_smb(self):
        from recce.creds import credenum as c
        d = c.parse_nxc_smb(self.NXC)
        self.assertTrue(d["admin"])
        self.assertIn("ADMIN$", [s["name"] for s in d["shares"]])
        self.assertIn("Administrator", [u["name"] for u in d["users"]])
        self.assertEqual(d["passpol"]["account lockout threshold"], "none")

    def test_parse_roasting(self):
        from recce.creds import credenum as c
        spns = c.parse_getuserspns(
            "MSSQL/dc.corp.local  sqlsvc  Domain Users  2020\n"
            "$krb5tgs$23$*sqlsvc$CORP.LOCAL$MSSQL*$deadbeef")
        self.assertEqual(spns[0]["name"], "sqlsvc")
        self.assertTrue(spns[0]["hash"].startswith("$krb5tgs$"))
        asrep = c.parse_getnpusers("$krb5asrep$23$svc-web@CORP.LOCAL:abcd")
        self.assertEqual(asrep[0]["name"], "svc-web")

    def test_parse_secretsdump_and_ssh(self):
        from recce.creds import credenum as c
        sd = c.parse_secretsdump(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
            "31d6cfe0d16ae931b73c59d7e0c089c0:::")
        self.assertEqual(sd[0]["name"], "Administrator")
        self.assertEqual(sd[0]["nt"], "31d6cfe0d16ae931b73c59d7e0c089c0")
        ssh = c.parse_ssh_enum(
            "===ID===\nuid=0(root)\n===SUDO===\n(ALL) NOPASSWD: ALL\n"
            "===SUID===\n/usr/bin/find\n/usr/bin/sudo")
        self.assertIn("uid=0(root)", ssh["id"])
        self.assertTrue(ssh["sudo"])
        self.assertIn("/usr/bin/find", ssh["suid"])

    def test_fold_into_host_and_quickwins(self):
        from recce.creds import credenum as c
        d = c.parse_nxc_smb(self.NXC)
        h = Host(ip="10.0.0.10", os_family="Windows", roles=["Domain Controller"],
                 ports=[Port(portid=445, state="open"),
                        Port(portid=389, state="open")])
        c._fold_nxc(h, d)
        c._fold_roast(h, [{"name": "sqlsvc", "spn": "MSSQL/dc", "hash": "$krb5tgs$x"}],
                      [{"name": "svc-web", "hash": "$krb5asrep$x"}], "corp.local")
        srcs = {a.source for a in h.accounts}
        self.assertEqual(srcs, {"netexec", "impacket"})
        titles = [v.title for v in h.vulns]
        self.assertTrue(any("Local admin" in t for t in titles))
        # Roasted accounts flow into the AD quick-wins.
        self.assertIn("sqlsvc", [a.name for a in ad.kerberoastable([h])])
        self.assertIn("svc-web", [a.name for a in ad.asrep_roastable([h])])

    def test_dual_account_user_enumerates_admin_dumps(self):
        """Low-priv account enumerates; privileged account does the admin-only
        power moves (confirm admin reach + secretsdump), labelled per account."""
        from recce.creds import credenum as c
        used = []

        def fake_nxc(ip, creds):
            # Only the privileged account is local admin here.
            return ({"admin": creds["username"] == "da", "host_info": "corp",
                     "shares": [{"name": "C$", "perms": "READ"}],
                     "users": [{"name": "bob", "domain": "corp"}],
                     "loggedon": [], "passpol": {}}, None)

        def fake_dump(ip, creds):
            used.append(("secretsdump", creds["username"]))
            return ([{"name": "krbtgt", "rid": "502", "nt": "abc"}], None)

        onx, osd, odc = c.run_nxc_smb, c.run_secretsdump, c._is_dc
        c.run_nxc_smb, c.run_secretsdump, c._is_dc = fake_nxc, fake_dump, lambda h: False
        try:
            h = Host(ip="10.0.0.5", os_family="Windows",
                     ports=[Port(portid=445, state="open")])
            c.enrich_host(h, {"username": "bob", "password": "x", "domain": "corp"},
                          None, aggressive=False,
                          admin_creds={"username": "da", "password": "y", "domain": "corp"})
        finally:
            c.run_nxc_smb, c.run_secretsdump, c._is_dc = onx, osd, odc
        # secretsdump ran with the PRIVILEGED account, never the user account.
        self.assertEqual(used, [("secretsdump", "da")])
        titles = " ".join(v.title for v in h.vulns)
        self.assertIn("Local admin confirmed - privileged account", titles)
        self.assertIn("Credential hashes dumped", titles)
        # User enumeration still folded shares/users (once, not duplicated).
        self.assertEqual(sum(1 for a in h.accounts if a.kind == "share"), 1)

    def test_missing_tool_is_not_reported_as_auth_fail(self):
        """A missing netexec (run_nxc_smb -> (None, None)) must NOT record a FAIL
        cell nor attempt secretsdump - it's a tooling gap, not a bad credential."""
        from recce.creds import credenum as c
        dumped = []
        onx, osd = c.run_nxc_smb, c.run_secretsdump
        c.run_nxc_smb = lambda ip, creds: (None, None)          # tool absent
        c.run_secretsdump = lambda ip, creds: (dumped.append(ip) or ([], None))
        try:
            h = Host(ip="10.0.0.5", os_family="Windows",
                     ports=[Port(portid=445, state="open")])
            issues, auth = c.enrich_host(
                h, {"username": "u", "password": "p", "domain": "d"}, None,
                admin_creds={"username": "a", "password": "p", "domain": "d"})
        finally:
            c.run_nxc_smb, c.run_secretsdump = onx, osd
        self.assertEqual(auth, {})           # nothing recorded -> cells show "-"
        self.assertEqual(dumped, [])         # no doomed secretsdump

    def test_secretsdump_skipped_when_admin_auth_rejected(self):
        """secretsdump must not run where the admin bind was rejected."""
        from recce.creds import credenum as c
        dumped = []
        onx, osd, odc = c.run_nxc_smb, c.run_secretsdump, c._is_dc
        # Both accounts authenticate but neither is admin (auth True, admin False).
        c.run_nxc_smb = lambda ip, creds: (
            {"auth": True, "admin": False, "host_info": "", "shares": [],
             "users": [], "loggedon": [], "passpol": {}}, None)
        c.run_secretsdump = lambda ip, creds: (dumped.append(ip) or ([], None))
        c._is_dc = lambda h: False
        try:
            h = Host(ip="10.0.0.9", os_family="Windows",
                     ports=[Port(portid=445, state="open")])
            # Rejected admin: auth False for the admin account.
            c.run_nxc_smb = lambda ip, creds: (
                {"auth": creds["username"] == "u", "admin": False, "host_info": "",
                 "shares": [], "users": [], "loggedon": [], "passpol": {}}, None)
            issues, auth = c.enrich_host(
                h, {"username": "u", "password": "p", "domain": "d"}, None,
                admin_creds={"username": "adm", "password": "bad", "domain": "d"})
        finally:
            c.run_nxc_smb, c.run_secretsdump, c._is_dc = onx, osd, odc
        self.assertFalse(auth["admin"]["auth"])   # admin bind rejected
        self.assertEqual(dumped, [])              # so no secretsdump

    def test_smb_error_records_err_not_fail(self):
        """A tool/connection error (None, err) is ERR, distinct from a FAIL."""
        from recce.creds import credenum as c
        onx = c.run_nxc_smb
        c.run_nxc_smb = lambda ip, creds: (None, "connection refused")
        try:
            h = Host(ip="10.0.0.7", os_family="Windows",
                     ports=[Port(portid=445, state="open")])
            _, auth = c.enrich_host(h, {"username": "u", "password": "p"}, None)
        finally:
            c.run_nxc_smb = onx
        self.assertTrue(auth["user"]["error"])
        self.assertFalse(auth["user"]["auth"])

    def test_ssh_finding_and_facts_recorded(self):
        from recce.creds import credenum as c
        h = Host(ip="10.0.0.5", ports=[Port(portid=22, state="open")])
        c._fold_ssh(h, {"id": "uid=0(root)", "kernel": "Linux 5.4", "os": "Ubuntu",
                        "sudo": ["(ALL) NOPASSWD: ALL"], "suid": ["/opt/weird"]})
        self.assertTrue(any(s.id == "ssh-local-enum" for s in h.host_scripts))
        titles = [v.title for v in h.vulns]
        self.assertTrue(any("Sudo" in t for t in titles))
        self.assertTrue(any("SUID" in t for t in titles))

    def test_tool_gating_no_crash_when_absent(self):
        # With no external tools present, runners return (None/[], None) - no raise.
        from recce.creds import credenum as c
        h = Host(ip="10.0.0.9", os_family="Windows",
                 ports=[Port(portid=445, state="open")])
        issues, auth = c.enrich_host(h, {"username": "u", "password": "p"}, None)
        self.assertTrue(h.cred_enumerated)
        self.assertIsInstance(issues, list)
        self.assertIsInstance(auth, dict)


class RobustnessTest(unittest.TestCase):
    """Field-crash guards: bad tool output / unexpected errors must not crash."""

    def test_run_survives_non_utf8_tool_output(self):
        # A service banner with raw non-UTF-8 bytes must not raise
        # UnicodeDecodeError mid-scan (errors='replace' on the runner).
        outcome = scanner._run(
            ["python3", "-c",
             "import sys; sys.stdout.buffer.write(b'open \\xff\\xfe port\\n')"])
        self.assertEqual(outcome.returncode, 0)
        self.assertIn("open", outcome.stdout)          # decoded, not crashed
        self.assertFalse(outcome.missing)

    def test_run_missing_tool_is_marked_not_raised(self):
        outcome = scanner._run(["definitely-not-a-real-binary-xyz", "--x"])
        self.assertTrue(outcome.missing)
        self.assertEqual(outcome.returncode, 127)

    def test_credenum_run_survives_non_utf8(self):
        from recce.creds import credenum
        out, err = credenum._run(
            ["python3", "-c",
             "import sys; sys.stdout.buffer.write(b'\\xff\\xfe done')"])
        self.assertIsNone(err)
        self.assertIn("done", out)

    def test_parse_nmap_xml_never_raises_on_bad_files(self):
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "nope.xml")
            self.assertEqual(parser.parse_nmap_xml(missing), [])   # absent file
            for name, content in [
                ("empty.xml", ""),
                ("garbage.xml", "\x00\x01 not xml at all \xff"),
                ("trunc.xml", '<?xml version="1.0"?><nmaprun start="1"><host>'),
                ("partial.xml",
                 '<?xml version="1.0"?><nmaprun><host><status state="up"/>'
                 '<address addr="10.0.0.1" addrtype="ipv4"/></host>'),  # no close
            ]:
                p = os.path.join(d, name)
                with open(p, "w") as fh:
                    fh.write(content)
                out = parser.parse_nmap_xml(p)      # must not raise
                self.assertIsInstance(out, list)

    def test_xlsx_survives_control_chars_in_cells(self):
        # NSE/banner output with XML-illegal control bytes must not corrupt the
        # workbook - it must strip them and still read back.
        wb = xlsx.Workbook()
        sh = wb.add_sheet("S")
        sh.write([("banner \x00\x01\x08 with \x1f control bytes", "default")])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "w.xlsx")
            wb.save(out)
            sheets = xlsx.read_sheets(out)          # must NOT raise ParseError
            flat = " ".join(str(c) for row in sheets["S"] for c in row)
            self.assertIn("banner", flat)
            self.assertNotIn("\x00", flat)          # control bytes stripped

    def test_docx_survives_control_chars(self):
        import xml.etree.ElementTree as ET
        import zipfile
        from recce.report.formats.docx import Document
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.docx")
            doc = Document()
            doc.title("title \x00\x08")
            doc.mono_block("evidence \x00\x01\x1f bytes")
            doc.save(p)
            self.assertIsNone(zipfile.ZipFile(p).testzip())
            with zipfile.ZipFile(p) as z:            # Word-openable = well-formed XML
                ET.fromstring(z.read("word/document.xml"))

    def test_store_raises_clean_error_on_corrupt_db(self):
        from recce.core.store import Store, StoreError
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "results.sqlite")
            with open(bad, "wb") as fh:
                fh.write(b"this is not a sqlite database at all\x00\x01")
            with self.assertRaises(StoreError):
                Store(bad)

    def test_invalid_targets_exit_clean(self):
        # A bad CIDR/range must yield a clean "Invalid targets" message + a None
        # result (caller exits 1), not a traceback. Exercised via _discover so the
        # test doesn't depend on nmap being installed.
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            paths = cli._open_paths(d)
            store = Store(paths["db"])
            args = SimpleNamespace(targets=["10.0.0.0/99"], exclude=[], fast=False)
            profile = scanner.PROFILES["standard"]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                result = cli._discover(args, profile, store, paths)
            store.close()
            # 5-tuple (…, disc_reasons, hostname_map) matching what cmd_enum/cmd_scan
            # unpack; the error path must not return a short tuple (that crashed the
            # caller).
            self.assertEqual(result, (None, [], None, None, {}))
            self.assertIn("Invalid targets", buf.getvalue())

    def test_main_top_level_guard_returns_clean_on_crash(self):
        # An unexpected error inside a command must become a clean exit 1, not a
        # traceback dumped at the tester.
        import argparse
        from recce import cli

        def boom(args):
            raise RuntimeError("simulated deep crash")

        class _P:
            def parse_args(self, _a):
                ns = argparse.Namespace()
                ns.command = "boom"      # non-None so main() dispatches to func
                ns.func = boom
                return ns

        orig = cli.build_arg_parser
        cli.build_arg_parser = lambda: _P()
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main([])
        finally:
            cli.build_arg_parser = orig
        self.assertEqual(rc, 1)
        out = buf.getvalue()
        self.assertIn("unexpected error", out)
        self.assertNotIn("Traceback", out)             # no raw traceback by default


class ScanHardeningTest(unittest.TestCase):
    def test_timeout_and_version_args(self):
        p = scanner.PROFILES["standard"]
        args, kill = scanner._timeout_args(p)
        self.assertEqual(args, ["--host-timeout", f"{p.host_timeout}m"])
        self.assertEqual(kill, p.host_timeout * 60 + 120)
        # 0 disables both.
        self.assertEqual(scanner._timeout_args(p, 0), ([], None))
        # Service detection: explicit intensity vs --version-all.
        self.assertIn("--version-intensity", scanner._version_args(p))
        self.assertIn("--version-all", scanner._version_args(scanner.PROFILES["thorough"]))

    def test_issue_classification(self):
        s = scanner
        self.assertEqual(
            s._issue_from(s.RunOutcome(timed_out=True), "/no", "enum", 20).level,
            "error")
        self.assertEqual(
            s._issue_from(s.RunOutcome(missing=True), "/no", "enum", 20).level,
            "error")
        ht = s.RunOutcome(returncode=0, stdout="Skipping host X due to host timeout")
        self.assertEqual(s._issue_from(ht, "/no", "port-sweep", 20).level, "warning")
        # A clean run against a real (existing, non-empty) file -> no issue.
        self.assertIsNone(s._issue_from(s.RunOutcome(returncode=0), SAMPLE, "enum", 20))

    def test_store_issue_log(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "s.sqlite"))
            store.add_issue("10.0.0.5", "port-sweep", "warning", "host timed out")
            store.add_issue("10.0.0.9", "enum", "error", "nmap unresponsive")
            self.assertEqual(store.count_issues(),
                             {"warning": 1, "error": 1, "total": 2})
            issues = store.get_issues()
            self.assertEqual(len(issues), 2)
            self.assertEqual(issues[0]["ip"], "10.0.0.9")   # newest first
            store.close()

    def test_overview_surfaces_issues(self):
        issues = [{"ts": "t", "ip": "10.0.0.9", "phase": "enum", "level": "error",
                   "message": "hard-timed-out"}]
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook([Host(ip="10.0.0.5", subnet="10.0.0.0/24")], out,
                           issues=issues)
            flat = [str(c) for r in xlsx.read_sheets(out)["Overview"] for c in r]
            self.assertTrue(any("SCAN ISSUES" in c for c in flat))
            self.assertTrue(any("hard-timed-out" in c for c in flat))

    def test_migration_adds_issues_table(self):
        # A datastore created before the issues table still gains it.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.sqlite")
            import sqlite3
            con = sqlite3.connect(path)
            con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
            con.commit(); con.close()
            store = Store(path)
            store.add_issue("1.2.3.4", "enum", "error", "boom")
            self.assertEqual(store.count_issues()["total"], 1)
            store.close()


class ProbesTest(unittest.TestCase):
    def test_port_classification(self):
        from recce.services import probes
        self.assertTrue(probes._is_tls(Port(portid=443, service="https")))
        self.assertTrue(probes._is_tls(Port(portid=8443, service="http", tunnel="ssl")))
        self.assertFalse(probes._is_tls(Port(portid=80, service="http")))
        self.assertTrue(probes._is_http(Port(portid=8080, service="http-proxy")))
        self.assertTrue(probes._is_http(Port(portid=443, service="https")))
        self.assertFalse(probes._is_http(Port(portid=22, service="ssh")))

    def test_http_header_findings_flag_missing_headers(self):
        from recce.services import probes
        port = Port(portid=80, service="http")
        # Server present with a version, but security headers absent.
        headers = {"server": "Apache/2.4.41", "content-type": "text/html"}
        orig = probes._fetch_headers
        probes._fetch_headers = lambda ip, p, tls: (200, headers)
        try:
            findings = probes.http_findings("10.0.0.9", port)
        finally:
            probes._fetch_headers = orig
        titles = {f.title for f in findings}
        self.assertIn("Missing X-Frame-Options / frame-ancestors (clickjacking)", titles)
        self.assertIn("Missing X-Content-Type-Options header (MIME sniffing)", titles)
        self.assertTrue(any("banner discloses" in t for t in titles))
        # No HSTS finding over plain HTTP.
        self.assertNotIn("Missing HSTS header", titles)
        for f in findings:
            self.assertEqual(f.source, "probe")
            if "banner" not in f.title:
                self.assertTrue(f.cwes)

    def test_http_findings_none_when_unreachable(self):
        from recce.services import probes
        orig = probes._fetch_headers
        probes._fetch_headers = lambda ip, p, tls: None
        try:
            self.assertEqual(probes.http_findings("10.0.0.9", Port(portid=80)), [])
        finally:
            probes._fetch_headers = orig

    def test_parse_cert_time(self):
        from recce.services import probes
        epoch = probes._parse_cert_time("Jun  1 12:00:00 2030 GMT")
        self.assertIsNotNone(epoch)
        self.assertIsNone(probes._parse_cert_time("not a date"))

    def test_probe_host_dedups(self):
        from recce.services import probes
        h = Host(ip="10.0.0.9", ports=[Port(portid=80, service="http")])
        headers = {"server": "nginx"}
        orig = probes._fetch_headers
        probes._fetch_headers = lambda ip, p, tls: (200, headers)
        try:
            first = probes.probe_host(h)
            second = probes.probe_host(h)   # idempotent re-run
        finally:
            probes._fetch_headers = orig
        self.assertGreater(first, 0)
        self.assertEqual(second, 0)


class ExploitsTest(unittest.TestCase):
    SS_JSON = ('{"RESULTS_EXPLOIT": ['
               '{"Title": "vsftpd 2.3.4 - Backdoor Command Execution",'
               ' "EDB-ID": "17491", "Type": "remote", "Path": "unix/remote/17491.rb",'
               ' "Codes": "CVE-2011-2523"}]}')

    def test_parse_json(self):
        recs = exploits.parse_searchsploit_json(self.SS_JSON)
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["EDB-ID"], "17491")

    def test_record_to_exploit_extracts_cve(self):
        rec = exploits.parse_searchsploit_json(self.SS_JSON)[0]
        e = exploits._record_to_exploit(rec, "10.0.0.9", 21, "vsftpd", "2.3.4")
        self.assertEqual(e.edb_id, "17491")
        self.assertIn("CVE-2011-2523", e.cves)
        self.assertEqual(e.type, "remote")

    def test_clean_version(self):
        self.assertEqual(exploits._clean_version("8.2p1 Ubuntu 4ubuntu0.5"), "8.2p1")
        self.assertEqual(exploits._clean_version("2.4.41"), "2.4.41")

    def test_query_terms_trims_vendor(self):
        self.assertEqual(exploits._query_terms("Apache httpd", "2.4.41"), "httpd 2.4.41")

    def test_exploit_tracking_key_and_coverage(self):
        h = Host(ip="10.0.0.9", subnet="10.0.0.0/24")
        from recce.core.models import Exploit
        h.exploits = [Exploit(ip="10.0.0.9", port=21, edb_id="17491")]
        keys = tr.item_keys([h])
        self.assertIn(tr.exploit_key("10.0.0.9", 21, "17491"), keys["exploits"])
        self.assertIn("exploits", tr.COVERAGE_CATEGORIES)


class SubnetCoverageTest(unittest.TestCase):
    def test_overview_includes_empty_scope_subnet(self):
        from recce.report.excel import build_workbook
        from recce.report.formats import xlsx
        hosts = [Host(ip="10.0.10.5", subnet="10.0.10.0/24", enumerated=True)]
        scope = {"10.0.10.0/24": 254, "10.0.99.0/24": 254}  # 2nd has no live hosts
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook(hosts, out, scope=scope)
            rows = xlsx.read_sheets(out)["Overview"]
        subnets = [r[0] for r in rows if r and r[0].startswith("10.0.")]
        self.assertIn("10.0.99.0/24", subnets)   # empty subnet still accounted for
        self.assertIn("10.0.10.0/24", subnets)

    def test_checklist_grouped_by_subnet(self):
        from recce.report.excel import _spec_checklist
        # up_reason set: a real discovery reply keeps a 0-port host on the list (the
        # Checklist shows only confirmed-up hosts).
        hosts = [Host(ip="10.0.20.9", subnet="10.0.20.0/24", up_reason="syn-ack"),
                 Host(ip="10.0.10.5", subnet="10.0.10.0/24", up_reason="echo-reply")]
        spec = _spec_checklist(hosts)
        rows = spec.rows
        # Sorted by subnet then IP -> 10.0.10.x before 10.0.20.x.
        self.assertEqual([r["data"]["IP"] for r in rows], ["10.0.10.5", "10.0.20.9"])
        # Subnet now lives in the collapsible group band, not a per-row column.
        self.assertEqual(spec.group_by, "Subnet")
        self.assertEqual(rows[0]["group"], "10.0.10.0/24")
        self.assertNotIn("Subnet", rows[0]["data"])

    def test_checklist_collapsible_band_rollup_and_risk_sort(self):
        from recce.report.excel import build_workbook
        from recce.core.models import Vuln
        from recce.core import tracking as _tr
        from recce.report.formats import xlsx as _x
        crit = Host(ip="10.0.10.9", subnet="10.0.10.0/24", state="up", enumerated=True,
                    ports=[Port(portid=445, service="smb")],
                    vulns=[Vuln(ip="10.0.10.9", port=445, protocol="tcp", script_id="x",
                                title="f", severity="critical", source="nse",
                                state="finding")])
        clean = Host(ip="10.0.10.1", subnet="10.0.10.0/24", state="up", enumerated=True,
                     ports=[Port(portid=22, service="ssh")])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook([clean, crit], out,
                           tracking={_tr.host_key("10.0.10.1"): (True, "")})
            rows = xlsx.read_sheets(out)["Checklist"]
        hidx = header_index(rows, "IP")
        ipc = rows[hidx].index("IP")
        band = next(r for r in rows[hidx + 1:] if str(r[ipc]).startswith("10.0.10.0/24"))
        self.assertIn("2 hosts", str(band[ipc]))
        self.assertIn("1/2 reviewed", str(band[ipc]))
        self.assertIn("high/crit", str(band[ipc]))                # the critical host
        # Risk-first: the critical host sorts above the clean host within the subnet.
        host_ips = [r[ipc] for r in rows[hidx + 1:]
                    if r[0] in (_x.CHECK_ON, _x.CHECK_OFF)]
        self.assertEqual(host_ips, ["10.0.10.9", "10.0.10.1"])

    def test_store_scope_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "s.sqlite"))
            store.set_scope("10.0.0.0/24", 254)
            store.set_scope("10.0.0.0/24", 100)  # keeps the larger
            self.assertEqual(store.get_scope()["10.0.0.0/24"], 254)
            store.close()


class AuditRegressionTest(unittest.TestCase):
    """Regression coverage for bugs found in the full-codebase audit."""

    def test_store_merge_preserves_port_enrichment_fields(self):
        # binary/detect_source/banner (set by ingest/deploy on an existing port) must
        # survive a later merge, not be dropped.
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "s.sqlite"))
            st.upsert_host(Host(ip="10.0.0.5",
                                ports=[Port(portid=22, service="ssh", state="open")]))
            st.upsert_host(Host(ip="10.0.0.5", ports=[Port(
                portid=22, service="ssh", state="open", binary="/usr/sbin/sshd",
                detect_source="local", banner="SSH-2.0-OpenSSH")]))
            p = st.get_host("10.0.0.5").ports[0]
            self.assertEqual(p.binary, "/usr/sbin/sshd")
            self.assertEqual(p.detect_source, "local")
            self.assertEqual(p.banner, "SSH-2.0-OpenSSH")
            st.close()

    def test_store_merge_folds_account_attrs(self):
        from recce.core.store import Store
        from recce.core.models import Account
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "s.sqlite"))
            st.upsert_host(Host(ip="10.0.0.5", accounts=[Account(
                ip="10.0.0.5", source="ldap", kind="user", name="svc")]))
            st.upsert_host(Host(ip="10.0.0.5", accounts=[Account(
                ip="10.0.0.5", source="ldap", kind="user", name="svc",
                attrs={"spn": "MSSQLSvc/db", "admincount": "1"})]))
            a = st.get_host("10.0.0.5").accounts[0]
            self.assertEqual(a.attrs.get("spn"), "MSSQLSvc/db")
            self.assertEqual(a.attrs.get("admincount"), "1")
            st.close()

    def test_smb2_negotiate_rejects_error_response(self):
        import struct
        from recce.services import smb
        # A valid NEGOTIATE OK (command 0, status 0, StructureSize 65) parses...
        hdr = b"\xfeSMB" + b"\x40\x00" + b"\x00\x00" + b"\x00\x00\x00\x00" + \
              b"\x00\x00" + b"\x01\x00" + b"\x00" * (64 - 16)
        body_ok = struct.pack("<H", 65) + struct.pack("<H", 0x0003) + \
            struct.pack("<H", 0x0300) + b"\x00" * 40
        ok = smb.parse_smb2_negotiate(b"\x00\x00\x00\x00" + hdr + body_ok)
        self.assertIsNotNone(ok)
        # ...but an ERROR response (STATUS_INVALID_PARAMETER) is rejected, not read as
        # a dialect-0 / signing-not-required host.
        err_hdr = b"\xfeSMB" + b"\x40\x00" + b"\x00\x00" + b"\x0d\x00\x00\xc0" + \
                  b"\x00\x00" + b"\x01\x00" + b"\x00" * (64 - 16)
        self.assertIsNone(smb.parse_smb2_negotiate(
            b"\x00\x00\x00\x00" + err_hdr + b"\x09\x00" + b"\x00" * 6))

    def test_ftp_write_proof_flags_failed_cleanup(self):
        from recce.services import ftp
        ok = ftp.write_proof_finding("1.2.3.4", 21,
                                     {"writable": True, "cleanup_ok": True,
                                      "evidence": "x", "marker": "m.txt"}, None)
        self.assertIn("fully reversible", ok["detail"])
        bad = ftp.write_proof_finding("1.2.3.4", 21,
                                      {"writable": True, "cleanup_ok": False,
                                       "evidence": "x", "marker": "m.txt"}, None)
        self.assertIn("CLEANUP FAILED", bad["detail"])
        self.assertNotIn("fully reversible", bad["detail"])

    def test_nullsession_verdict_needs_anonymous_marker(self):
        from recce.vuln import proofs
        from recce.core.models import Vuln, Host
        h = Host(ip="1.1.1.1")
        # A credentialed share listing (no anon marker) -> LIKELY, not a false CONFIRMED.
        cred = Vuln(ip="1.1.1.1", port=445, protocol="tcp", script_id="smb-enum-shares",
                    title="shares", output="Shares\n  account_used: corp\\alice",
                    source="nse", state="finding")
        self.assertEqual(proofs._v_nullsession(h, None, cred)[0], proofs.LIKELY)
        # An anonymous session marker -> CONFIRMED.
        anon = Vuln(ip="1.1.1.1", port=445, protocol="tcp", script_id="smb-enum-shares",
                    title="shares", output="Shares\n  account_used: <blank>",
                    source="nse", state="finding")
        self.assertEqual(proofs._v_nullsession(h, None, anon)[0], proofs.CONFIRMED)

    def test_checklist_sqref_is_range_compressed(self):
        from recce.report.excel import _col_sqref, build_workbook
        # Unit: contiguous rows collapse to one range token; gaps split runs.
        self.assertEqual(_col_sqref("A", [4, 5, 6, 8, 9]), "A4:A6 A8:A9")
        self.assertEqual(_col_sqref("J", [4]), "J4")
        self.assertEqual(_col_sqref("J", []), "")
        # End-to-end: a subnet of contiguous hosts must emit a RANGE, not a per-cell
        # list, in the Checklist step-column validations (keeps the XML tiny at scale).
        import zipfile
        import re as _re
        hosts = [Host(ip=f"10.0.0.{i}", subnet="10.0.0.0/24", state="up",
                      enumerated=True,
                      ports=[Port(portid=445, service="smb", state="open",
                                  vuln_scanned=True)]) for i in range(1, 6)]
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook(hosts, out)
            with zipfile.ZipFile(out) as z:
                blobs = [z.read(n).decode() for n in z.namelist()
                         if "worksheets/sheet" in n]
        # Some sheet's validation sqref is a contiguous range spanning >1 row.
        sqrefs = [s for x in blobs
                  for s in _re.findall(r'<dataValidation[^>]*sqref="([^"]+)"', x)]
        self.assertTrue(any(_re.fullmatch(r"[A-Z]+\d+:[A-Z]+\d+", s) for s in sqrefs),
                        f"expected a compressed range sqref, got {sqrefs}")

    def test_fold_service_findings_refreshes_only_its_own_source(self):
        # The shared deep-service fold helper must replace THIS source's prior vulns
        # (a re-run doesn't duplicate) while leaving other sources untouched.
        from recce import cli
        from recce.core.store import Store
        from recce.core.models import Vuln

        def mk(src, title):
            return Vuln(ip="10.0.0.5", port=445, protocol="tcp", script_id="x",
                        title=title, severity="high", source=src, state="finding")
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "s.sqlite"))
            h = Host(ip="10.0.0.5", ports=[Port(portid=445, state="open")],
                     vulns=[mk("nse", "keep-me"), mk("smb", "stale-smb")])
            st.upsert_host(h)
            analysis = {"findings": [{"title": "New SMB issue", "target": "10.0.0.5:445",
                                      "severity": "critical", "detail": "d"}],
                        "stats": {}}
            import io as _io
            import contextlib as _c
            with _c.redirect_stdout(_io.StringIO()):
                cli._fold_service_findings(st, [st.get_host("10.0.0.5")], analysis,
                                           "smb", __import__("recce.services.smb", fromlist=["x"]).findings_to_vulns,
                                           "SMB")
            got = st.get_host("10.0.0.5")
            titles = {v.title for v in got.vulns}
            self.assertIn("keep-me", titles)            # other source preserved
            self.assertNotIn("stale-smb", titles)       # prior smb vuln refreshed away
            self.assertIn("New SMB issue", titles)      # new smb finding folded in
            self.assertEqual(st.get_meta("smb") is not None, True)
            st.close()

    def test_shared_findings_to_vulns_keeps_source_prefix_port(self):
        # The 5 service modules now delegate to svccommon; the source label, the
        # script_id prefix (k8s differs from its 'kubernetes' source) and the default
        # port must survive.
        from recce.services import smb, kubernetes, docker
        f = {"target": "1.2.3.4", "title": "X", "severity": "high",
             "detail": "d", "cwes": ["CWE-306"]}
        vs = smb.findings_to_vulns([dict(f)])["1.2.3.4"][0]
        self.assertEqual((vs.source, vs.port), ("smb", 445))
        self.assertTrue(vs.script_id.startswith("smb:"))
        kv = kubernetes.findings_to_vulns([dict(f)])["1.2.3.4"][0]
        self.assertEqual(kv.source, "kubernetes")
        self.assertTrue(kv.script_id.startswith("k8s:"))    # prefix != source
        dv = docker.findings_to_vulns([{**f, "target": "1.2.3.4:2375"}])["1.2.3.4"][0]
        self.assertEqual((dv.source, dv.port), ("docker", 2375))

    def test_eol_recipe_does_not_swallow_rce_findings(self):
        from recce.vuln import proofs
        from recce.core.models import Vuln

        def mk(t):
            return Vuln(ip="1.1.1.1", port=445, protocol="tcp", script_id="x",
                        title=t, output=t, source="version-db", state="finding")
        # Pure EOL -> eol-service; legacy-but-RCE -> routed to a real version-CVE verdict.
        self.assertEqual(proofs.recipe_for(mk("Legacy MongoDB (<3.6) no-auth"))["id"],
                         "eol-service")
        self.assertEqual(
            proofs.recipe_for(mk("Legacy Samba 3.x - multiple RCE (cve-2007-2447)"))["id"],
            "version-cve-generic")
        # SambaCry now gets a Verification row at all (previously None).
        self.assertIsNotNone(proofs.recipe_for(
            mk("Samba CVE-2017-7494 SambaCry remote code execution")))


class AuditMediumLowRegressionTest(unittest.TestCase):
    """Regressions for the medium/low findings fixed after the full-codebase audit."""

    def test_vuln_key_distinguishes_udp_from_tcp(self):
        # A udp finding must not collapse onto a distinct tcp finding on the same
        # port/script/title; the tcp key stays byte-for-byte stable (backward compat).
        from recce.core.models import Vuln
        common = dict(ip="10.0.0.1", port=161, script_id="svc", title="Unencrypted service")
        tcp = Vuln(protocol="tcp", **common)
        udp = Vuln(protocol="udp", **common)
        self.assertNotEqual(tcp.key, udp.key)
        self.assertEqual(tcp.key, "10.0.0.1:161:svc:Unencrypted service")   # unchanged
        self.assertTrue(udp.key.endswith(":udp"))

    def test_from_json_tolerates_explicit_null_lists(self):
        # A hand-edited/corrupt results.sqlite with explicit JSON null for the list
        # fields must load (the whole point of from_json's tolerance), not TypeError.
        from recce.core.models import Host
        h = Host.from_json({"ip": "10.0.0.2", "ports": None, "vulns": None,
                            "accounts": None, "exploits": None, "host_scripts": None})
        self.assertEqual(h.ip, "10.0.0.2")
        self.assertEqual(h.ports, [])
        # a null nested list (scripts/evidence) is tolerated too
        h2 = Host.from_json({"ip": "10.0.0.3",
                             "ports": [{"portid": 80, "protocol": "tcp", "scripts": None}],
                             "vulns": [{"ip": "10.0.0.3", "port": 80, "protocol": "tcp",
                                        "script_id": "x", "title": "t", "evidence": None}]})
        self.assertEqual(h2.ports[0].scripts, [])
        self.assertEqual(h2.vulns[0].evidence, [])

    def test_gnmap_preserves_version_containing_slash(self):
        from recce.core import parser
        line = ("Host: 10.0.0.4 ()\tPorts: 443/open/tcp//http//Apache httpd 2.2.14 "
                "((Ubuntu) mod_ssl/2.2.14 OpenSSL/0.9.8k)/\n")
        with tempfile.NamedTemporaryFile("w", suffix=".gnmap", delete=False) as f:
            f.write(line); path = f.name
        try:
            hosts = parser.parse_gnmap(path)
        finally:
            os.unlink(path)
        p = hosts[0].ports[0]
        self.assertEqual(p.product, "Apache httpd")
        self.assertEqual(p.version, "2.2.14")           # was silently truncated/lost

    def test_parse_normal_reads_ipv6_target(self):
        from recce.core import parser
        txt = "Nmap scan report for 2001:db8::1\n22/tcp open ssh OpenSSH 8.2p1\n"
        with tempfile.NamedTemporaryFile("w", suffix=".nmap", delete=False) as f:
            f.write(txt); path = f.name
        try:
            hosts = parser.parse_normal(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(hosts), 1)                 # was zero (IPv4-only regex)
        self.assertEqual(hosts[0].ip, "2001:db8::1")
        self.assertEqual(len(hosts[0].ports), 1)

    def test_xml_import_refuses_entity_declaration(self):
        from recce.core import parser
        bomb = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "x">]>'
                '<nmaprun><host><status state="up"/>'
                '<address addr="10.0.0.5" addrtype="ipv4"/></host></nmaprun>')
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(bomb); path = f.name
        try:
            self.assertEqual(parser.parse_nmap_xml(path), [])   # refused, not expanded
        finally:
            os.unlink(path)

    def test_script_args_quote_credentials(self):
        from recce.core import scanner
        self.assertEqual(scanner._script_arg_val("a,b{c}"), '"a,b{c}"')
        args = scanner._creds_args({"username": "u", "password": "p,w{d}"})
        joined = args[1]                                 # the --script-args value
        self.assertIn('smbpassword="p,w{d}"', joined)    # comma stays inside quotes
        self.assertNotIn("smbpassword=p,w", joined)      # not split into bogus pairs

    def test_ftp_cleartext_finding_reachable_without_anonymous(self):
        # The "no AUTH TLS" cleartext finding must fire for an auth-REQUIRED server
        # (the common case), not only when anonymous login is open.
        from recce.services import ftp
        h = Host(ip="10.0.0.6", ports=[Port(portid=21, service="ftp", state="open")])
        pr = {("10.0.0.6", 21): {"anonymous": False, "auth_tls": False,
                                 "banner": "vsftpd 3.0.3"}}
        titles = [f["title"].lower() for f in ftp.findings([h], pr)]
        self.assertTrue(any("cleartext" in t for t in titles))

    def test_redis_single_component_version_not_flagged_eol(self):
        from recce.services.db import redis
        self.assertFalse(redis._old_version("6"))        # was True ([6] < [6,0])
        self.assertFalse(redis._old_version("6.2"))
        self.assertTrue(redis._old_version("5.9"))

    def test_docx_labels_jpeg_by_magic_bytes(self):
        from recce.report.formats import docx
        self.assertEqual(docx._img_format(b"\xff\xd8\xff\xe0" + b"\x00" * 20), "jpg")
        self.assertEqual(docx._img_format(b"\x89PNG\r\n\x1a\n"), "png")
        d = docx.Document()
        # A JPEG (SOF0 says 40x30) is stored as image1.jpg, not mislabeled png.
        jpeg = (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 4
                + b"\xff\xc0\x00\x11\x08\x00\x1e\x00\x28" + b"\x00" * 8 + b"\xff\xd9")
        d.image(jpeg)
        self.assertTrue(any(name.endswith(".jpg") for name, _ in d._media))

    def test_mask_short_secret_hides_chars_and_length(self):
        from recce.report import html as rh
        masked = rh._mask_secret("P@ss", "password")     # 4 chars
        self.assertNotIn("P", masked)                    # no boundary char
        self.assertNotIn("chars", masked)                # no exact length
        # a longer secret still shows the recognisability hint
        self.assertIn("[9 chars]", rh._mask_secret("longsec99", "password"))

    def test_poc_url_strips_shell_metacharacters(self):
        from recce.act import poc

        class V:
            output = "reachable at http://evil$(reboot)/path"
            ip, port = "10.0.0.7", 80
        self.assertEqual(poc._url_from_vuln(V()), "http://evil")   # truncated at '$'

    def test_cmd_run_bails_when_scan_fails(self):
        # A failed cmd_scan (e.g. store setup returned 1) must stop the run, not go
        # on to the authenticated sweep / next-steps against a half-set-up engagement.
        from unittest import mock
        from types import SimpleNamespace
        from recce import cli
        args = SimpleNamespace(output_dir="/tmp/recce-nonexistent", username="u")
        with mock.patch.object(cli, "cmd_scan", return_value=1), \
                mock.patch.object(cli, "_run_sweep") as sweep, \
                mock.patch.object(cli, "_open_paths") as open_paths, \
                mock.patch.object(cli, "_print_next") as print_next:
            rc = cli.cmd_run(args)
        self.assertEqual(rc, 1)
        sweep.assert_not_called()
        open_paths.assert_not_called()
        print_next.assert_not_called()


class ArgvCredentialDisclosureTest(unittest.TestCase):
    """Credentials must not sit on a tool's (world-readable) process argv - they go
    via env (sshpass), a 0600 file (ldapsearch -y), or stdin (impacket getpass)."""

    def test_run_tool_env_extra_delivered_and_off_argv(self):
        from recce.core import util
        script = ("import os,sys;"
                  "print('ARGV='+repr(sys.argv[1:]));"
                  "print('ENVPW='+repr(os.environ.get('SSHPASS','')))")
        out, err = util.run_tool([sys.executable, "-c", script, "ssh", "user@host"],
                                 env_extra={"SSHPASS": "s3cr3t!"})
        self.assertIsNone(err)
        self.assertIn("ENVPW='s3cr3t!'", out)            # tool got it from env
        self.assertNotIn("s3cr3t!", out.split("ENVPW=")[0])   # not on argv

    def test_run_tool_stdin_answers_getpass_off_argv(self):
        # The mechanism impacket relies on: password answered to getpass() over stdin,
        # new_session detaches the tty so getpass falls back to stdin.
        from recce.core import util
        script = ("import sys,getpass;"
                  "print('ARGV='+repr(sys.argv[1:]));"
                  "pw=getpass.getpass('Password:');"
                  "print('PW='+repr(pw));"
                  "print('REST='+repr(sys.stdin.read().strip()))")
        out, err = util.run_tool([sys.executable, "-c", script, "dom/user@ip"],
                                 stdin_data="p@ss\nSELECT 1\n", new_session=True)
        self.assertIsNone(err)
        self.assertIn("PW='p@ss'", out)                  # read from stdin
        self.assertIn("REST='SELECT 1'", out)            # script followed the password
        self.assertNotIn("p@ss", out.split("PW=")[0])    # never on argv

    def test_impacket_targets_carry_no_password(self):
        from recce.creds import credenum
        captured = {}

        def fake_run(cmd, timeout=120, **kw):
            captured["cmd"], captured["kw"] = cmd, kw
            return "", None
        creds = {"domain": "CORP.LOCAL", "username": "alice",
                 "password": "S3cret!", "dc_ip": "10.0.0.1"}
        with mock.patch.object(credenum, "impacket_tool", return_value="impacket-secretsdump"), \
                mock.patch.object(credenum, "_run", side_effect=fake_run):
            credenum.run_secretsdump("10.0.0.5", creds)
        self.assertNotIn("S3cret!", " ".join(captured["cmd"]))          # not on argv
        self.assertEqual(captured["kw"].get("stdin_data"), "S3cret!\n")  # via stdin
        self.assertTrue(captured["kw"].get("new_session"))

    def test_mssqlclient_target_has_no_password(self):
        from recce.services.db import mssql
        with mock.patch.object(mssql, "mssqlclient_tool", return_value="impacket-mssqlclient"):
            cmd = mssql._mssqlclient_cmd("10.0.0.5",
                                         {"user": "sa", "secret": "S3cret!", "domain": ""},
                                         mssql._DEFAULT_PORT, windows_auth=False)
        self.assertNotIn("S3cret!", " ".join(cmd))
        self.assertIn("sa@10.0.0.5", " ".join(cmd))

    def test_ldapsearch_password_via_file_not_argv(self):
        from recce import ad
        seen = {}

        def fake_subrun(cmd, **kw):
            seen["cmd"] = cmd
            # the -y file must exist, be 0600, and contain the password (no newline)
            i = cmd.index("-y")
            path = cmd[i + 1]
            seen["mode"] = oct(os.stat(path).st_mode & 0o777)
            seen["filecontent"] = open(path).read()
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch("recce.ad.subprocess.run", side_effect=fake_subrun):
            ad._run_ldapsearch("10.0.0.1", "dc=x", "(objectClass=*)", [], "sub",
                               "alice", "S3cret!", "CORP.LOCAL", False)
        self.assertNotIn("-w", seen["cmd"])                 # not -w <pw>
        self.assertNotIn("S3cret!", " ".join(seen["cmd"]))  # not on argv
        self.assertEqual(seen["mode"], "0o600")             # owner-only file
        self.assertEqual(seen["filecontent"], "S3cret!")    # whole file, no newline

    def test_deploy_sshpass_password_via_env_not_argv(self):
        from recce.creds import deploy
        seen = {}

        def fake_run(argv, timeout, stdin=None, env=None, new_session=False):
            seen["argv"], seen["env"] = argv, env
            return 0, "recce-enum host=x\n", ""
        with mock.patch("recce.creds.deploy.shutil.which", return_value="/usr/bin/sshpass"), \
                mock.patch.object(deploy, "_run", side_effect=fake_run):
            deploy.run_ssh("1.2.3.4", {"username": "u", "password": "S3cret!"}, "SCRIPT", 60)
        self.assertIn("sshpass", seen["argv"])
        self.assertIn("-e", seen["argv"])                   # env mode, not -p
        self.assertNotIn("S3cret!", " ".join(seen["argv"]))  # not on argv
        self.assertEqual(seen["env"], {"SSHPASS": "S3cret!"})

    def test_bloodhound_impacket_target_password_via_stdin(self):
        from recce.ad import bloodhound as bh
        creds = {"domain": "CORP.LOCAL", "user": "alice", "secret": "S3cret!",
                 "is_hash": False, "dc_ip": "10.0.0.1"}
        base, flags, stdin_pw = bh._impacket_target(creds)
        self.assertNotIn("S3cret!", base)                   # not in the target/argv
        self.assertNotIn("S3cret!", " ".join(flags))
        self.assertEqual(stdin_pw, "S3cret!\n")             # answered over stdin
        # An NT hash has no off-argv option, so it stays in -hashes (stdin None).
        h = {"domain": "CORP.LOCAL", "user": "alice", "secret": "aabbcc", "is_hash": True}
        _b, hflags, hstdin = bh._impacket_target(h)
        self.assertIn("-hashes", hflags)
        self.assertIsNone(hstdin)

    def test_deploy_wmiexec_password_via_stdin_not_argv(self):
        from recce.creds import deploy
        seen = {}

        def fake_run(argv, timeout, stdin=None, env=None, new_session=False):
            seen["argv"], seen["stdin"], seen["ns"] = argv, stdin, new_session
            return 0, "", ""
        with mock.patch.object(deploy, "_run", side_effect=fake_run):
            deploy._wmiexec("impacket-wmiexec",
                            {"username": "a", "password": "S3cret!", "domain": "d"},
                            "1.2.3.4", "whoami", 60)
        self.assertNotIn("S3cret!", " ".join(seen["argv"]))  # not on argv
        self.assertEqual(seen["stdin"], "S3cret!\n")         # via stdin
        self.assertTrue(seen["ns"])


class HostUpCertaintyTest(unittest.TestCase):
    """The Checklist shows only hosts we can PROVE are up - but is never allowed to
    write a live host off as down. is_up is the single source of that judgement."""

    def test_is_up_only_on_positive_evidence(self):
        from recce.core.models import Vuln
        # An open port is unambiguous proof.
        self.assertTrue(Host(ip="1.1.1.1",
                             ports=[Port(portid=22, state="open")]).is_up)
        # A finding means a service actually responded.
        self.assertTrue(Host(ip="1.1.1.1",
                             vulns=[Vuln(ip="1.1.1.1", port=0, protocol="tcp",
                                         script_id="x", title="t", severity="low",
                                         source="nse", state="finding")]).is_up)
        # `enumerated` alone is NOT proof: the pipeline sets it on every host it tries,
        # including a dead -Pn IP that answered nothing.
        self.assertFalse(Host(ip="1.1.1.1", enumerated=True).is_up)
        # A real nmap discovery reply (not the -Pn assume-up).
        self.assertTrue(Host(ip="1.1.1.1", up_reason="echo-reply").is_up)
        self.assertTrue(Host(ip="1.1.1.1", up_reason="arp-response").is_up)
        # DNS / ARP / OS evidence => it answered something.
        self.assertTrue(Host(ip="1.1.1.1", mac="00:11:22:33:44:55").is_up)
        self.assertTrue(Host(ip="1.1.1.1", hostnames=["dc01"]).is_up)
        # A closed/filtered-only port is NOT an open port.
        self.assertFalse(Host(ip="1.1.1.1",
                              ports=[Port(portid=22, state="filtered")]).is_up)
        # The -Pn blanket assume-up ("user-set") is NOT proof, and a bare host isn't.
        self.assertFalse(Host(ip="1.1.1.1", state="up", up_reason="user-set").is_up)
        self.assertFalse(Host(ip="1.1.1.1").is_up)

    def test_checklist_hides_unconfirmed_keeps_confirmed(self):
        from recce.report.excel import build_workbook
        confirmed = Host(ip="10.0.0.5", subnet="10.0.0.0/24", state="up",
                         up_reason="syn-ack", ports=[Port(portid=445, state="open")])
        phantom = Host(ip="10.0.0.6", subnet="10.0.0.0/24", state="up",
                       up_reason="user-set")     # -Pn assume-up, no proof of life
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook([confirmed, phantom], out)
            rows = xlsx.read_sheets(out)["Checklist"]
        hidx = header_index(rows, "IP")
        ipc = rows[hidx].index("IP")
        ips = {str(r[ipc]) for r in rows[hidx + 1:]}
        self.assertIn("10.0.0.5", ips)            # confirmed-up host shown
        self.assertNotIn("10.0.0.6", ips)         # unconfirmed phantom hidden

    def test_checklist_carries_legend_above_header_and_round_trips(self):
        from recce.report.excel import (build_workbook, read_workbook_tracking,
                                         CHECKLIST_TITLE)
        h = Host(ip="10.0.0.5", subnet="10.0.0.0/24", state="up", enumerated=True,
                 ports=[Port(portid=445, service="smb", state="open", vuln_scanned=True)])
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook([h], out)
            rows = xlsx.read_sheets(out)["Checklist"]
            # A legend line precedes the header row (row 0 is not the header).
            hidx = header_index(rows, "IP")
            self.assertGreater(hidx, 0)
            self.assertIn("Legend", str(rows[0][0]))
            self.assertIn("confirmed UP", str(rows[0][0]))
            # Tracking still round-trips despite the shifted header: an auto-ticked
            # vuln step reads back True.
            back = read_workbook_tracking(out)
            self.assertTrue(back[tr.step_key("vuln", "10.0.0.5")][0])

    def test_overview_tallies_unconfirmed_hosts(self):
        from recce.report.excel import build_workbook
        confirmed = Host(ip="10.0.0.5", subnet="10.0.0.0/24",
                         ports=[Port(portid=445, state="open")])
        phantom = Host(ip="10.0.0.6", subnet="10.0.0.0/24", up_reason="user-set")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "wb.xlsx")
            build_workbook([confirmed, phantom], out)
            rows = xlsx.read_sheets(out)["Overview"]
        blob = "\n".join(" ".join(str(c) for c in r) for r in rows)
        self.assertIn("Scanned, not confirmed up", blob)
        self.assertIn("Hosts confirmed up", blob)

    def test_udp_fallback_flips_silent_pn_host_to_up(self):
        # A -Pn host silent on TCP gets a UDP liveness ping; a reply confirms it up.
        from recce import cli
        from recce.core import scanner
        saved = (cli._ports_for_host, cli._fold_host, scanner.full_port_scan,
                 scanner.verify_port_scan, scanner.udp_liveness_probe,
                 scanner.enum_scan, cli.np.parse_nmap_xml)
        udp_calls = {"n": 0}

        def fake_parse(path):
            # Only the UDP-liveness XML reports a live host; TCP/enum XMLs are empty.
            if "udpalive" in path:
                return [Host(ip="10.0.0.9", up_reason="udp-response")]
            return []

        def fake_udp(ip, out, profile):
            udp_calls["n"] += 1
            return out, None
        cli._ports_for_host = lambda path, ip: []          # silent on TCP
        cli._fold_host = lambda ip, parsed, sm: Host(ip=ip, subnet="10.0.0.0/24")
        scanner.full_port_scan = lambda ip, out, profile: (out, None)
        scanner.verify_port_scan = lambda ip, out, profile: (out, None)
        scanner.udp_liveness_probe = fake_udp
        scanner.enum_scan = lambda ip, ports, out, profile, creds=None: (out, None)
        cli.np.parse_nmap_xml = fake_parse
        try:
            with tempfile.TemporaryDirectory() as d:
                prof = scanner.ScanProfile(ping_discovery=False, assume_up=True,
                                           udp_basic=False)
                host, _ = cli._enum_worker("10.0.0.9", prof, {"raw": d}, None, None,
                                           {"10.0.0.9": "10.0.0.0/24"})
            self.assertEqual(udp_calls["n"], 1)            # UDP fallback fired
            self.assertEqual(host.up_reason, "udp-response")
            self.assertTrue(host.is_up)                    # up despite 0 open TCP ports
        finally:
            (cli._ports_for_host, cli._fold_host, scanner.full_port_scan,
             scanner.verify_port_scan, scanner.udp_liveness_probe,
             scanner.enum_scan, cli.np.parse_nmap_xml) = saved

    def test_discovery_reply_reason_propagates_and_skips_udp(self):
        # A host discovered live carries its real reply reason into the stored host,
        # and the UDP fallback is NOT wasted on a host we already proved is up.
        from recce import cli
        from recce.core import scanner
        saved = (cli._ports_for_host, cli._fold_host, scanner.full_port_scan,
                 scanner.verify_port_scan, scanner.udp_liveness_probe,
                 scanner.enum_scan, cli.np.parse_nmap_xml)
        udp_calls = {"n": 0}
        cli._ports_for_host = lambda path, ip: []          # silent on TCP
        cli._fold_host = lambda ip, parsed, sm: Host(ip=ip, subnet="10.0.0.0/24")
        scanner.full_port_scan = lambda ip, out, profile: (out, None)
        scanner.verify_port_scan = lambda ip, out, profile: (out, None)
        scanner.udp_liveness_probe = lambda ip, out, profile: (
            udp_calls.__setitem__("n", udp_calls["n"] + 1), (out, None))[1]
        scanner.enum_scan = lambda ip, ports, out, profile, creds=None: (out, None)
        cli.np.parse_nmap_xml = lambda path: []
        try:
            with tempfile.TemporaryDirectory() as d:
                prof = scanner.ScanProfile(ping_discovery=True, udp_basic=False)
                host, _ = cli._enum_worker("10.0.0.9", prof, {"raw": d}, None, None,
                                           {"10.0.0.9": "10.0.0.0/24"},
                                           disc_reason="echo-reply")
            self.assertEqual(host.up_reason, "echo-reply")
            self.assertTrue(host.is_up)
            self.assertEqual(udp_calls["n"], 0)            # already proven up -> no UDP
        finally:
            (cli._ports_for_host, cli._fold_host, scanner.full_port_scan,
             scanner.verify_port_scan, scanner.udp_liveness_probe,
             scanner.enum_scan, cli.np.parse_nmap_xml) = saved

    def test_merge_never_downgrades_proof_of_life(self):
        # A real reply must survive a later -Pn re-scan that only knows "user-set".
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "s.sqlite"))
            store.upsert_host(Host(ip="10.0.0.5", up_reason="echo-reply"))
            store.upsert_host(Host(ip="10.0.0.5", up_reason="user-set"))
            got = store.get_host("10.0.0.5")
            self.assertEqual(got.up_reason, "echo-reply")
            self.assertTrue(got.is_up)
            store.close()


class VulnDbTest(unittest.TestCase):
    def test_version_comparator(self):
        from recce.vuln import vulndb
        self.assertLess(vulndb._cmp("2.4.41", "2.4.53"), 0)
        self.assertGreater(vulndb._cmp("2.4.50", "2.4.49"), 0)
        self.assertLess(vulndb._cmp("8.2p1", "8.5"), 0)
        self.assertGreater(vulndb._cmp("1.0.2k", "1.0.2"), 0)
        self.assertEqual(vulndb._cmp("2.3.4", "2.3.4"), 0)

    def test_mariadb_handshake_prefix_not_read_as_eol_mysql(self):
        """Regression: MariaDB 10.x announces '5.5.5-10.x.y-MariaDB'. The
        leading 5.5.5 must not be read as the version, or a patched MariaDB gets
        a bogus EOL medium + high CVE-2012-2122."""
        from recce.vuln import vulndb
        self.assertEqual(vulndb._clean_version("5.5.5-10.11.6-MariaDB-0+deb12u1"),
                         "10.11.6-MariaDB-0+deb12u1")
        h = Host(ip="10.0.0.5", ports=[Port(portid=3306, service="mysql",
                 product="MySQL", version="5.5.5-10.11.6-MariaDB-0+deb12u1")])
        vulndb.assess_host_inplace(h)
        titles = {v.title for v in h.vulns}
        self.assertFalse(any("MySQL" in t for t in titles), titles)
        # A genuine old MySQL 5.5.40 (no handshake prefix) is still flagged.
        h2 = Host(ip="10.0.0.6", ports=[Port(portid=3306, service="mysql",
                  product="MySQL", version="5.5.40")])
        vulndb.assess_host_inplace(h2)
        self.assertTrue(any("End-of-life MySQL" in v.title for v in h2.vulns))

    def test_product_advisory_reported_on_every_matching_port(self):
        """Regression: a product-only advisory exposed on two ports must yield a
        finding per port (was deduped by title, dropping all but the first)."""
        from recce.vuln import vulndb
        from recce.report.docx import group_findings
        h = Host(ip="10.0.0.5", ports=[
            Port(portid=8090, service="http", product="Atlassian Confluence", version=""),
            Port(portid=8091, service="http", product="Atlassian Confluence", version="")])
        vulndb.assess_host_inplace(h)
        conf = [v for v in h.vulns if "Confluence" in v.title]
        self.assertEqual(sorted(v.port for v in conf), [8090, 8091])
        # The grouped write-up lists both affected ports.
        f = next(f for f in group_findings([h]) if "Confluence" in f.title)
        self.assertEqual(sorted({a[1] for a in f.affected}), [8090, 8091])

    def test_exact_and_range_matches(self):
        from recce.vuln import vulndb
        h = Host(ip="10.0.0.9", os_name="Linux", ports=[
            Port(portid=21, service="ftp", product="vsftpd", version="2.3.4"),
            Port(portid=80, service="http", product="Apache httpd", version="2.4.41"),
            Port(portid=3306, service="mysql", product="MySQL", version="5.7.38"),
        ])
        vulndb.assess_host_inplace(h)
        titles = {v.title for v in h.vulns}
        self.assertTrue(any("vsftpd 2.3.4 backdoor" in t for t in titles))   # exact
        self.assertTrue(any("Apache" in t for t in titles))                  # range
        # MySQL 5.7.38 is >= 5.7 -> not flagged as EOL (< 5.7).
        self.assertFalse(any("End-of-life MySQL" in t for t in titles))

    def test_findings_carry_remediation_and_source(self):
        from recce.vuln import vulndb
        h = Host(ip="10.0.0.9", ports=[Port(portid=21, service="ftp",
                 product="vsftpd", version="2.3.4")])
        vulndb.assess_host_inplace(h)
        v = h.vulns[0]
        self.assertEqual(v.source, "version-db")
        self.assertEqual(v.severity, "critical")
        self.assertIn("CVE-2011-2523", v.ids)
        self.assertTrue(v.remediation)

    def test_multiple_findings_per_port_have_distinct_keys(self):
        from recce.core.models import Vuln
        a = Vuln(ip="1.1.1.1", port=80, protocol="tcp", script_id="version-db",
                 title="Finding A")
        b = Vuln(ip="1.1.1.1", port=80, protocol="tcp", script_id="version-db",
                 title="Finding B")
        self.assertNotEqual(a.key, b.key)

    def test_no_version_no_false_positive(self):
        from recce.vuln import vulndb
        # product matches but no version -> a version-gated sig must not fire.
        h = Host(ip="10.0.0.9", ports=[Port(portid=80, service="http",
                 product="Apache httpd", version="")])
        n = vulndb.assess_host_inplace(h)
        self.assertEqual(n, 0)

    def test_signature_database_is_large(self):
        from recce.vuln import vulndb
        self.assertGreaterEqual(vulndb.signature_count(), 80)

    def test_new_signature_categories_match(self):
        from recce.vuln import vulndb
        cases = {
            "ActiveMQ OpenWire transport": "ActiveMQ",
            "Oracle WebLogic admin httpd": "WebLogic",
            "Docker": "Docker Engine API",
            "Apache Solr": "Solr",
            "Zabbix": "Zabbix",
            "JetBrains TeamCity": "TeamCity",
            "VMware ESXi": "ESXi",
            "Apache CouchDB": "CouchDB",
            "Ivanti Connect Secure": "Ivanti",
            "F5 BIG-IP": "BIG-IP",
            "MikroTik RouterOS": "MikroTik",
            "Cisco ASA": "Cisco ASA",
        }
        for product, expect in cases.items():
            h = Host(ip="1.1.1.1", ports=[Port(portid=8080, service="http",
                     product=product, state="open")])
            vulndb.assess_host_inplace(h)
            self.assertTrue(any(expect in v.title for v in h.vulns),
                            f"{product} -> expected a '{expect}' finding")

    def test_windows_advisories_are_os_gated(self):
        from recce.vuln import vulndb
        # A non-DC Windows host gets the Windows SMB advisories, but NOT ZeroLogon
        # (which attacks a domain controller's Netlogon only).
        win = Host(ip="1.1.1.1", os_family="Windows", os_name="Windows Server 2019",
                   ports=[Port(portid=445, service="microsoft-ds",
                               product="Microsoft Windows Server 2019", state="open")])
        vulndb.assess_host_inplace(win)
        titles = " ".join(v.title for v in win.vulns)
        for expect in ("SMBGhost", "PrintNightmare"):
            self.assertIn(expect, titles)
        self.assertNotIn("ZeroLogon", titles)          # DC-only -> not on a member
        # A Linux/Samba SMB host must NOT get the Windows-only advisories.
        lin = Host(ip="1.1.1.2", os_family="Linux", os_name="Linux",
                   ports=[Port(portid=445, service="microsoft-ds",
                               product="Samba smbd", version="4.13.0", state="open")])
        vulndb.assess_host_inplace(lin)
        self.assertFalse(any(w in " ".join(v.title for v in lin.vulns)
                             for w in ("SMBGhost", "PrintNightmare", "ZeroLogon")))

    def test_iis_mssql_seimpersonate_potato_advisories(self):
        from recce.vuln import vulndb
        h = Host(ip="10.0.10.50", os_family="Windows", os_name="Windows 11",
                 ports=[Port(portid=80, service="http",
                             product="Microsoft IIS httpd", version="10.0"),
                        Port(portid=1433, service="ms-sql-s",
                             product="Microsoft SQL Server", version="15.0")])
        vulndb.assess_host_inplace(h)
        titles = " ".join(v.title for v in h.vulns)
        self.assertIn("IIS AppPool - SeImpersonate", titles)
        self.assertIn("MSSQL service account - SeImpersonate", titles)
        potato = [v for v in h.vulns if "SeImpersonate" in v.title]
        for v in potato:
            self.assertEqual(v.confidence, "potential")       # advisory
            self.assertIn("CWE-269", v.cwes)
            self.assertIn("GodPotato", v.output + v.remediation or "")

    def test_zerologon_is_dc_only(self):
        from recce.vuln import vulndb
        # A real DC (Kerberos 88 + LDAP 389 + SMB 445) DOES get ZeroLogon.
        dc = Host(ip="10.0.10.10", os_family="Windows", os_name="Windows Server 2019",
                  ports=[Port(portid=88, service="kerberos-sec", state="open"),
                         Port(portid=389, service="ldap", state="open"),
                         Port(portid=445, service="microsoft-ds",
                              product="Windows Server 2019", state="open")])
        vulndb.assess_host_inplace(dc)
        self.assertIn("ZeroLogon", " ".join(v.title for v in dc.vulns))
        # Role-tagged DC with only SMB visible still matches via the role.
        dc2 = Host(ip="10.0.10.11", os_family="Windows", roles=["Domain Controller"],
                   ports=[Port(portid=445, service="microsoft-ds",
                               product="Windows Server", state="open")])
        vulndb.assess_host_inplace(dc2)
        self.assertIn("ZeroLogon", " ".join(v.title for v in dc2.vulns))

    def test_jetty_version_gate(self):
        from recce.vuln import vulndb
        for ver, should in [("9.4.30.v20200611", True), ("9.4.50", False)]:
            h = Host(ip="1.1.1.1", ports=[Port(portid=8080, service="http",
                     product="Jetty", version=ver, state="open")])
            vulndb.assess_host_inplace(h)
            hit = any("Jetty" in v.title for v in h.vulns)
            self.assertEqual(hit, should, f"Jetty {ver}")

    def test_findings_carry_cwes(self):
        from recce.vuln import vulndb
        h = Host(ip="10.0.0.9", ports=[Port(portid=21, service="ftp",
                 product="vsftpd", version="2.3.4")])
        vulndb.assess_host_inplace(h)
        v = h.vulns[0]
        self.assertTrue(v.cwes)
        self.assertTrue(all(c.startswith("CWE-") for c in v.cwes))

    def test_advisory_signature_is_product_only_and_potential(self):
        from recce.vuln import vulndb
        # A product-only advisory (no version) should still fire, tagged potential.
        h = Host(ip="10.0.0.9", ports=[Port(portid=8080, service="http",
                 product="Apache Tomcat", version="")])
        vulndb.assess_host_inplace(h)
        adv = [v for v in h.vulns if "default credentials" in v.title]
        self.assertTrue(adv)
        self.assertEqual(adv[0].confidence, "potential")
        self.assertTrue(adv[0].cwes)

    def test_every_signature_has_cwe_field(self):
        from recce.vuln import vulndb
        for sig in vulndb.SIGNATURES:
            self.assertIn("cwe", sig, f"{sig['title']} missing cwe")
            self.assertTrue(sig["cwe"], f"{sig['title']} empty cwe")


class PhaseModelTest(unittest.TestCase):
    def _host(self, ip="10.0.0.5", scanned=None):
        h = Host(ip=ip, subnet="10.0.0.0/24", ports=[
            Port(portid=80, service="http"), Port(portid=445, service="microsoft-ds")])
        if scanned:
            for p in h.ports:
                if p.portid in scanned:
                    p.vuln_scanned = True
        return h

    def test_status_transitions(self):
        h = self._host()
        self.assertEqual(h.status, "discovered")
        h.enumerated = True
        self.assertEqual(h.status, "enumerated")
        h.ports[0].vuln_scanned = True
        self.assertEqual(h.status, "vuln-scanned 1/2")
        h.ports[1].vuln_scanned = True
        self.assertEqual(h.status, "vuln-scanned")

    def test_vuln_targets_only_and_unscanned(self):
        from recce import cli
        h = self._host(scanned={80})
        h.enumerated = True
        # --only http -> just port 80
        ns = SimpleNamespace(only=["http"], subnet=None, host=None, unscanned=False)
        tgt = cli._vuln_targets([h], ns)
        self.assertEqual(tgt, [(h, [80])])
        # --unscanned -> only port 445 (80 already scanned)
        ns = SimpleNamespace(only=None, subnet=None, host=None, unscanned=True)
        self.assertEqual(cli._vuln_targets([h], ns), [(h, [445])])
        # --only by port number
        ns = SimpleNamespace(only=["445"], subnet=None, host=None, unscanned=False)
        self.assertEqual(cli._vuln_targets([h], ns), [(h, [445])])

    def test_vuln_targets_subnet_and_host_filter(self):
        from recce import cli
        a = self._host("10.0.0.5"); b = self._host("10.0.1.9")
        b.subnet = "10.0.1.0/24"
        ns = SimpleNamespace(only=None, subnet=["10.0.0.0/24"], host=None, unscanned=False)
        got = cli._vuln_targets([a, b], ns)
        self.assertEqual([h.ip for h, _ in got], ["10.0.0.5"])

    def test_merge_vuln_results(self):
        from recce import cli
        from recce.core.models import Vuln
        h = self._host()
        parsed = Host(ip="10.0.0.5", ports=[Port(portid=80, service="http",
                      scripts=[Script(id="http-git", output="x")])],
                      vulns=[Vuln(ip="10.0.0.5", port=80, protocol="tcp",
                                  script_id="http-git", severity="medium")])
        cli._merge_vuln_results(h, [parsed])
        self.assertEqual(len(h.vulns), 1)
        self.assertTrue(any(s.id == "http-git" for s in h.ports[0].scripts))


class TargetingTest(unittest.TestCase):
    def test_ip_matcher(self):
        from recce.core.targets import ip_matcher
        m = ip_matcher(["10.0.0.5", "10.0.1.0/24", "192.168.1.10-12"])
        self.assertTrue(m("10.0.0.5"))       # exact ip
        self.assertTrue(m("10.0.1.99"))      # in cidr
        self.assertTrue(m("192.168.1.11"))   # in range
        self.assertFalse(m("10.0.0.6"))
        self.assertFalse(m("172.16.0.1"))

    def test_empty_matches_all(self):
        from recce.core.targets import ip_matcher
        m = ip_matcher([])
        self.assertTrue(m("1.2.3.4"))

    def test_selected_hosts(self):
        from recce import cli
        a = Host(ip="10.0.0.5", subnet="10.0.0.0/24")
        b = Host(ip="10.0.9.9", subnet="10.0.9.0/24")
        ns = SimpleNamespace(targets=["10.0.0.0/24"], host=None, subnet=None)
        self.assertEqual([h.ip for h in cli._selected_hosts([a, b], ns)], ["10.0.0.5"])
class PrivescModuleTest(unittest.TestCase):
    def test_windows_playbook(self):
        # The generic OS checklist now lives on the separate reference sheet
        # (playbook_rows), scoped to the OSes present in the engagement.
        from recce.act import privesc
        h = Host(ip="10.0.0.5", os_family="Windows",
                 ports=[Port(portid=445, service="microsoft-ds")])
        oses = {r["os"] for r in privesc.playbook_rows([h])}
        self.assertEqual(oses, {"windows"})

    def test_linux_playbook(self):
        from recce.act import privesc
        h = Host(ip="10.0.0.6", os_family="Linux",
                 ports=[Port(portid=22, service="ssh")])
        oses = {r["os"] for r in privesc.playbook_rows([h])}
        self.assertEqual(oses, {"linux"})

    def test_playbook_shows_both_oses_for_mixed_or_unknown_scope(self):
        from recce.act import privesc
        mixed = [Host(ip="10.0.0.5", os_family="Windows"),
                 Host(ip="10.0.0.6", os_family="Linux")]
        self.assertEqual({r["os"] for r in privesc.playbook_rows(mixed)},
                         {"windows", "linux"})
        unknown = [Host(ip="10.0.0.9")]
        self.assertEqual({r["os"] for r in privesc.playbook_rows(unknown)},
                         {"windows", "linux"})

    def test_remote_finding_from_vuln(self):
        from recce.act import privesc
        from recce.core.models import Vuln
        h = Host(ip="10.0.0.5", os_family="Windows")
        h.vulns = [Vuln(ip="10.0.0.5", port=445, protocol="tcp",
                        script_id="smb-vuln-ms17-010", title="ms17-010",
                        severity="critical")]
        findings = [r for r in privesc.plan(h) if r["category"] == "finding"]
        self.assertTrue(any("MS17-010" in r["vector"] for r in findings))

    def test_current_potato_playbook_and_service_hints(self):
        from recce.act import privesc
        h = Host(ip="10.0.10.50", os_family="Windows", os_name="Windows 11",
                 ports=[Port(portid=80, service="http",
                             product="Microsoft IIS httpd", version="10.0"),
                        Port(portid=1433, service="ms-sql-s",
                             product="Microsoft SQL Server")])
        # The Potato playbook is reference material (playbook sheet)...
        pb_blob = " ".join(f"{r['vector']} {r['howto']} {r['note']}"
                           for r in privesc.playbook_rows([h]))
        for tool in ("GodPotato", "PrintSpoofer", "EfsPotato", "JuicyPotatoNG",
                     "RoguePotato", "LocalPotato"):
            self.assertIn(tool, pb_blob)
        self.assertIn("CVE-2023-21746", pb_blob)              # LocalPotato CVE
        self.assertIn("SeImpersonate", pb_blob)               # precondition named
        # ...but recce flags the opportunity remotely from the IIS + MSSQL services
        # as real findings on the Priv-Esc tab.
        findings = [r for r in privesc.plan(h) if r["category"] == "finding"]
        self.assertTrue(any("IIS" in r["vector"] for r in findings))
        self.assertTrue(any("MSSQL" in r["vector"] for r in findings))
class CliSmokeTest(unittest.TestCase):
    def test_arg_parser_has_all_commands(self):
        from recce import cli
        p = cli.build_arg_parser()
        # Parse a representative invocation of each command without executing.
        for argv in (["enum", "10.0.0.1"], ["vulns", "10.0.0.0/24", "--fast"],
                     ["db", "-o", "x"], ["privesc", "--scan"], ["scan", "10.0.0.1"],
                     ["credenum", "-u", "a", "-p", "b", "-d", "corp.local"],
                     ["writeups", "--min-severity", "high", "--no-screenshots"],
                     ["writeups", "--include-potential"],
                     ["writeup", "F-007", "-o", "eng"],
                     ["services", "-o", "eng", "-a"],
                     ["exploitplan", "-o", "eng", "--lhost", "10.0.0.1", "--run"],
                     ["attackpath", "-o", "eng"],
                     ["creds", "--add", "CORP\\alice:Pw!", "--plan", "-o", "eng"],
                     ["ingest", "loot.txt", "--host", "1.2.3.4"],
                     ["import", "scan.xml", "-o", "eng"],
                     ["report"], ["status"], ["review", "--host", "1.2.3.4"],
                     ["demo"], ["doctor", "--no-self-scan"]):
            ns = p.parse_args(argv)
            self.assertTrue(callable(ns.func))

    def test_cli_works_with_every_optional_dependency_absent(self):
        # The core promise: recce is stdlib-only, and ONLY `recce serve` needs
        # fastapi/uvicorn (the bundle extra). Verify it for real, in a fresh
        # subprocess with fastapi/uvicorn/openpyxl/ldap3/impacket blocked at
        # __import__ time - not just by reading cli.py's own top-level imports,
        # which only proves ONE file, not the whole transitive import graph
        # reachable from `recce.cli` / `from .webui.app import create_app`.
        # Regression target: a future module that cli.py imports at module level
        # (not lazily, like cmd_serve's own try/except) picking up a stray
        # `import openpyxl`/etc. would silently break every OTHER command too,
        # not just serve - this catches that even though no single file's diff
        # would look wrong on its own.
        import subprocess
        import textwrap
        script = textwrap.dedent("""
            import sys, builtins, tempfile
            _BLOCKED = {"fastapi", "uvicorn", "openpyxl", "ldap3", "impacket"}
            _orig_import = builtins.__import__
            def _blocking_import(name, *a, **kw):
                if name.split(".")[0] in _BLOCKED:
                    raise ImportError(f"No module named {name!r} (simulated absent)")
                return _orig_import(name, *a, **kw)
            builtins.__import__ = _blocking_import

            from recce import cli
            p = cli.build_arg_parser()
            assert len(p._subparsers._group_actions[0].choices) > 40

            ns = p.parse_args(["doctor", "--no-self-scan"])
            assert ns.func(ns) in (0, 1)               # never raises

            d = tempfile.mkdtemp()
            ns2 = p.parse_args(["serve", "-o", d])
            assert ns2.func(ns2) == 1                   # fails CLEANLY, not a crash
            print("ALL_OK")
        """)
        r = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ALL_OK", r.stdout)

    def test_no_dest_collisions_except_the_intentional_toggle_pair(self):
        # Two add_argument() calls sharing a dest= is legal argparse but usually a
        # copy-paste mistake - one flag silently shadows the other. The single
        # legitimate case is an explicit enable/disable pair sharing one dest
        # (--show-refuted/--no-show-refuted); anything else should fail loudly.
        import argparse
        from collections import defaultdict
        from recce import cli
        p = cli.build_arg_parser()
        sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
        allowed = {("report", "show_refuted")}
        for name, subp in sub.choices.items():
            by_dest = defaultdict(list)
            for act in subp._actions:
                if isinstance(act, argparse._HelpAction):
                    continue
                by_dest[act.dest].append(act.option_strings)
            for dest, groups in by_dest.items():
                if len(groups) > 1 and (name, dest) not in allowed:
                    self.fail(f"[{name}] dest={dest!r} shared by {groups} - "
                             f"unintentional dest collision?")

    def test_short_flags_mean_the_same_thing_in_every_subcommand(self):
        # -u/-p/-d etc. should resolve to the same long flag everywhere an operator
        # might reasonably expect consistency (muscle memory across subcommands).
        # Regression: `creds` used -u/--user and -p/--pass while every other
        # credentialed subcommand used --username/--password.
        import argparse
        from collections import defaultdict
        from recce import cli
        p = cli.build_arg_parser()
        sub = next(a for a in p._actions if isinstance(a, argparse._SubParsersAction))
        by_short: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for name, subp in sub.choices.items():
            for act in subp._actions:
                shorts = [o for o in act.option_strings
                         if len(o) == 2 and o[0] == "-" and o[1] != "-"]
                longs = [o for o in act.option_strings if o.startswith("--")]
                if shorts and longs:
                    by_short[shorts[0]][longs[0]].append(name)
        for short, longs in by_short.items():
            self.assertEqual(len(longs), 1,
                             f"{short} means different things across subcommands: "
                             f"{dict((k, v) for k, v in longs.items())}")

    def test_doctor_runs_without_crashing(self):
        from recce import cli
        rc = cli.cmd_doctor(SimpleNamespace(no_self_scan=True))
        self.assertIn(rc, (0, 1))  # 0 if nmap present, 1 if not - never raises

    def test_doctor_ldap_uses_capability_gate_not_just_binary(self):
        """Regression: doctor reports LDAP via ad.ldap_available() (ldapsearch OR
        the ldap3 package), not a raw which('ldapsearch') - else a box with only
        the ldap3 package is falsely told LDAP is missing, and the detail line
        and the summary disagree."""
        import io
        import contextlib
        import shutil
        from recce import cli, ad
        orig_avail, orig_which = ad.ldap_available, shutil.which

        def run():
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                cli.cmd_doctor(SimpleNamespace(no_self_scan=True))
            return buf.getvalue()
        try:
            # ldap3 present, ldapsearch binary absent -> capability IS available
            ad.ldap_available = lambda: True
            shutil.which = lambda n: None if n == "ldapsearch" else orig_which(n)
            out = run()
            self.assertTrue(any(l.strip().startswith("ldap") and "OK" in l
                                for l in out.splitlines()), out)
            missing = next((l for l in out.splitlines()
                            if "Optional tools missing" in l), "")
            self.assertNotIn("ldap", missing)
            # neither backend present -> reported missing (detail + summary agree)
            ad.ldap_available = lambda: False
            out = run()
            self.assertTrue(any(l.strip().startswith("ldap") and "-   (optional)" in l
                                for l in out.splitlines()), out)
        finally:
            ad.ldap_available, shutil.which = orig_avail, orig_which


class ExploitPlanTest(unittest.TestCase):
    @staticmethod
    def _read(*parts):
        with open(os.path.join(*parts)) as fh:
            return fh.read()

    def _hosts(self):
        from recce.core.models import Vuln, Account
        dc = Host(ip="10.0.10.5", hostnames=["dc01"], os_family="Windows",
                  roles=["Domain Controller"], smb_signing="not required",
                  accounts=[Account(ip="10.0.10.5", source="nse", kind="domain",
                                    domain="CORP")],
                  ports=[Port(portid=445, service="microsoft-ds")],
                  vulns=[Vuln(ip="10.0.10.5", port=445, protocol="tcp",
                              script_id="smb-vuln-ms17-010", title="smb-vuln-ms17-010",
                              severity="high", source="nse", ids=["CVE-2017-0143"],
                              output="VULNERABLE")])
        ftp = Host(ip="10.0.10.30", os_family="Linux",
                   ports=[Port(portid=21, service="ftp")],
                   vulns=[Vuln(ip="10.0.10.30", port=21, protocol="tcp",
                               script_id="version-db", title="vsftpd 2.3.4 backdoor",
                               severity="critical", source="version-db",
                               confidence="likely", ids=["CVE-2011-2523"]),
                          # a 'potential' guess must NOT get a plan
                          Vuln(ip="10.0.10.30", port=23, protocol="tcp",
                               script_id="version-db", title="Telnet cleartext",
                               severity="medium", source="version-db",
                               confidence="potential")])
        return [dc, ftp]

    def test_msf_mapping(self):
        from recce.act import exploitplan as ep
        self.assertEqual(ep._msf_for("smb-vuln-ms17-010 CVE-2017-0143")["module"],
                         "exploit/windows/smb/ms17_010_eternalblue")
        self.assertEqual(ep._msf_for("vsftpd 2.3.4 backdoor")["module"],
                         "exploit/unix/ftp/vsftpd_234_backdoor")
        self.assertIsNone(ep._msf_for("telnet cleartext credentials"))

    def test_msf_mapping_covers_headline_cves_exploitref_already_names(self):
        # Regression: exploitref.PROVEN_EXPLOIT ("the single source of truth shared
        # by the Word write-ups") named a real msf module for Zerologon/Log4Shell/
        # the Apache path-traversal RCE/Struts2, but _MSF here had no entry for any
        # of them - a confirmed finding of one of these (the demo engagement's own
        # flagship critical findings) silently got NO .rc from `recce exploitplan`,
        # despite the write-up step correctly naming a module that exists.
        from recce.act import exploitplan as ep
        self.assertEqual(ep._msf_for("Zerologon CVE-2020-1472")["module"],
                         "auxiliary/admin/dcerpc/cve_2020_1472_zerologon")
        self.assertEqual(ep._msf_for("Log4Shell CVE-2021-44228")["module"],
                         "exploit/multi/http/log4shell_header_injection")
        self.assertEqual(ep._msf_for("Apache path traversal CVE-2021-41773")["module"],
                         "exploit/multi/http/apache_normalize_path_rce")
        self.assertEqual(ep._msf_for("Struts2 OGNL CVE-2017-5638")["module"],
                         "exploit/multi/http/struts2_content_type_ognl")
        # PrintNightmare / MS10-061 are deliberately excluded: their msf modules
        # require SMBUser/SMBPass/SMBDomain, which the generic RHOSTS/RPORT/PAYLOAD
        # template has no field for - a generated .rc would look ready but fail.
        self.assertIsNone(ep._msf_for("PrintNightmare CVE-2021-34527"))
        self.assertIsNone(ep._msf_for("MS10-061 spoolss CVE-2010-2729"))

    def test_plan_files_are_written_as_utf8_not_platform_default(self):
        # Regression: the per-host .sh and README.txt were opened bare open(...,
        # "w") - they embed real finding titles (e.g. "Zerologon — Netlogon
        # privilege escalation", a real em-dash) - which would raise
        # UnicodeEncodeError on a platform whose default text encoding isn't UTF-8
        # (e.g. cp1252 on Windows, which recce explicitly ships an airgap build for).
        from recce.act import exploitplan as ep
        from recce.core.models import Vuln
        h = Host(ip="10.0.10.5", os_family="Windows",
                 ports=[Port(portid=445, service="microsoft-ds")],
                 vulns=[Vuln(ip="10.0.10.5", port=445, protocol="tcp",
                             script_id="smb-vuln-zerologon",
                             title="Zerologon — Netlogon privilege escalation",
                             severity="critical", source="nse",
                             ids=["CVE-2020-1472"], confidence="confirmed")])
        with tempfile.TemporaryDirectory() as d:
            s = ep.build_plan([h], d, lhost="10.9.9.9")
            with open(os.path.join(s["dir"], "10.0.10.5.sh"), encoding="utf-8") as fh:
                self.assertIn("Zerologon — Netlogon", fh.read())
            with open(os.path.join(s["dir"], "README.txt"), encoding="utf-8") as fh:
                self.assertIn("10.0.10.5.sh", fh.read())

    def test_build_plan_safe_default(self):
        from recce.act import exploitplan as ep
        with tempfile.TemporaryDirectory() as d:
            s = ep.build_plan(self._hosts(), d, lhost="10.9.9.9")
            self.assertEqual(sorted(s["plans"]), ["10.0.10.30", "10.0.10.5"])
            self.assertEqual(s["rc_files"], 2)          # ms17-010 + vsftpd
            pd = s["dir"]
            eb = next(f for f in os.listdir(pd) if "eternalblue" in f)
            rc = self._read(pd, eb)
            self.assertIn("set RHOSTS 10.0.10.5", rc)
            self.assertIn("set LHOST 10.9.9.9", rc)
            self.assertIn("check", rc)
            self.assertIn("# exploit -j", rc)           # launch commented (safe)
            # DC gets AS-REP + Kerberoast + relay actions with the domain filled in.
            dc_sh = self._read(pd, "10.0.10.5.sh")
            self.assertIn("impacket-GetNPUsers CORP/", dc_sh)
            self.assertIn("impacket-GetUserSPNs CORP/", dc_sh)
            self.assertIn("ntlmrelayx", dc_sh)

    def test_run_arms_launch(self):
        from recce.act import exploitplan as ep
        with tempfile.TemporaryDirectory() as d:
            s = ep.build_plan(self._hosts(), d, lhost="10.9.9.9", run=True)
            eb = next(f for f in os.listdir(s["dir"]) if "eternalblue" in f)
            rc = self._read(s["dir"], eb)
            self.assertRegex(rc, r"(?m)^exploit -j$")   # active, not commented

    def test_potential_findings_get_no_plan(self):
        from recce.act import exploitplan as ep
        from recce.core.models import Vuln
        h = Host(ip="10.0.0.9", os_family="Linux",
                 ports=[Port(portid=23, service="telnet")],
                 vulns=[Vuln(ip="10.0.0.9", port=23, protocol="tcp",
                             script_id="version-db", title="Telnet cleartext",
                             severity="medium", source="version-db",
                             confidence="potential")])
        with tempfile.TemporaryDirectory() as d:
            s = ep.build_plan([h], d)
            self.assertEqual(s["plans"], [])            # nothing confirmed -> no plan

    def test_actions_for_host_structured(self):
        from recce.act import exploitplan as ep
        dc = self._hosts()[0]                            # DC with ms17-010 + signing off
        acts = ep.actions_for_host(dc, lhost="10.9.9.9")
        kinds = {a["kind"] for a in acts}
        self.assertIn("remote-msf", kinds)
        self.assertIn("remote-tool", kinds)             # AS-REP/Kerberoast/relay
        msf = next(a for a in acts if a["kind"] == "remote-msf")
        self.assertIn("ms17_010_eternalblue", msf["cmd"])
        self.assertIn("10.9.9.9", msf["cmd"])           # LHOST filled in

    def test_exploitation_sheet_unifies_actions(self):
        from recce.report.excel import _spec_exploitation
        spec = _spec_exploitation(self._hosts())
        types = {r["data"]["Type"] for r in spec.rows}
        self.assertIn("remote (msf)", types)

    def test_services_sheet_has_enum_command(self):
        from recce.report.excel import _spec_services
        spec = _spec_services(self._hosts())
        self.assertIn("Enum command", [c[0] for c in spec.cols])
        cmds = [r["data"].get("Enum command", "") for r in spec.rows]
        self.assertTrue(any("recce-service.sh smb" in c for c in cmds))


class IngestServiceTest(unittest.TestCase):
    OUT = ("\n==== SMB  ->  10.0.0.5:445 ====\n"
           "[+] 445/tcp is open\n"
           "[!] SMB signing NOT required -> NTLM relay target\n"
           "[!] Null session lists shares -> anonymous SMB access\n"
           "[!] Test BlueKeep CVE-2019-0708 on legacy Windows\n"
           "==== SNMP  ->  10.0.0.9:161 ====\n"
           "[!] SNMP community string works: 'public' (v2c)\n")

    def test_parse_service_output(self):
        from recce.intake import ingest
        p = ingest.parse_service_output(self.OUT)
        self.assertTrue(p["is_service"])
        self.assertEqual(len(p["findings"]), 4)
        self.assertEqual({f["ip"] for f in p["findings"]}, {"10.0.0.5", "10.0.0.9"})
        smb = [f for f in p["findings"] if f["ip"] == "10.0.0.5"]
        self.assertTrue(all(f["port"] == 445 for f in smb))

    def test_service_vulns_confidence_and_source(self):
        from recce.intake import ingest
        vulns = ingest.service_findings_to_vulns(ingest.parse_service_output(self.OUT))
        adv = next(v for v in vulns if v.title.startswith("Test BlueKeep"))
        self.assertEqual(adv.confidence, "potential")   # advisory -> off writeups
        sign = next(v for v in vulns if "signing" in v.title)
        self.assertEqual(sign.confidence, "")           # observed -> real
        self.assertEqual(sign.source, "service-enum")
        self.assertEqual(sign.port, 445)
        self.assertEqual(sign.severity, "high")

    def test_rce_and_nfs_export_severity_from_real_scripts(self):
        # Literal find_ strings copied verbatim from the real per-service scripts
        # (not hand-approximated), so this catches severity drift against what
        # recce-service.sh actually prints, not just an idealized fixture.
        from recce.intake import ingest
        cases = [
            # elasticsearch.sh: RCE named mid-sentence, not right after "->" - the
            # old "-> rce" pattern missed it and fell through to medium.
            ("Elasticsearch 1.4 (old) -> Groovy/MVEL sandbox RCE "
             "(CVE-2014-3120 / CVE-2015-1427)", "critical"),
            # smtp.sh / ftp.sh: "(RCE)" in parens, same gap.
            ("Exim 4.87 -> check CVE-2019-10149 (RCE) and the 4.87-4.91 "
             "local-root chain", "critical"),
            ("ProFTPD 1.3.4 -> check mod_copy RCE CVE-2015-3306 (SITE CPFR/CPTO)",
             "critical"),
            # rpc-nfs.sh: a wildcard NFS export is the same finding class recce's
            # own NFS probe already rates high (vulndb's nfs-world-export); the
            # service-script path disagreed until this severity list caught up.
            ("NFS export shared to * (everyone) -> mountable by any host", "high"),
            # Words that CONTAIN "rce" as a substring (enfoRCEd, coeRCE) must not
            # false-positive into critical - \brce\b is word-boundaried.
            ("NLA does not appear enforced -> pre-auth attack surface", "medium"),
            ("SMB coerce potential (xp_dirtree) -> often SYSTEM", "medium"),
        ]
        for text, want in cases:
            self.assertEqual(ingest._svc_sev(text), want, text)

    def test_real_lib_sh_output_round_trips(self):
        # Strongest check: source the REAL recce/scripts/lib.sh, call its actual
        # svc_header/find_/ok/info/note functions (what every service script under
        # recce/scripts/services/ uses), and parse genuinely bash-produced stdout -
        # not a hand-typed fixture approximating the format. Guards against lib.sh's
        # printf formats drifting out of sync with _SVC_HDR/_FIND without anyone
        # updating the Python side (or a fixture) to match.
        import shutil
        import subprocess
        from recce.intake import ingest
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        libsh = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "recce", "scripts", "lib.sh")
        script = (
            f'. "{libsh}"\n'
            'svc_header "SMB" "10.0.10.5" "445"\n'
            'ok "445/tcp is open"\n'
            'find_ "SMB signing not required - relay possible"\n'
            'info "just an informational line, not a finding"\n'
            'note "next: netexec smb 10.0.10.5 --shares"\n'
        )
        r = subprocess.run([bash, "-c", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        parsed = ingest.parse_service_output(r.stdout)
        self.assertTrue(parsed["is_service"])
        self.assertEqual(len(parsed["findings"]), 1)
        f = parsed["findings"][0]
        self.assertEqual((f["ip"], f["port"], f["service"]),
                         ("10.0.10.5", 445, "smb"))
        self.assertIn("signing not required", f["text"])
        # info/ok/note lines must never be picked up as findings.
        vulns = ingest.service_findings_to_vulns(parsed)
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].severity, "high")

    def test_ingest_service_output_into_store(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "results.sqlite")
            st = Store(db)
            st.upsert_host(Host(ip="10.0.0.5", subnet="10.0.0.0/24",
                                ports=[Port(portid=445, service="microsoft-ds")]))
            st.close()
            loot = os.path.join(d, "svc.txt")
            with open(loot, "w") as fh:
                fh.write(self.OUT)
            rc = cli.cmd_ingest(SimpleNamespace(
                output_dir=d, loot=loot, host=None, title="t"))
            self.assertEqual(rc, 0)
            st = Store(db)
            hosts = {h.ip: h for h in st.all_hosts()}
            st.close()
            self.assertIn("10.0.0.9", hosts)            # new host created from output
            titles = [v.title for v in hosts["10.0.0.5"].vulns]
            self.assertTrue(any("signing" in t for t in titles))
class VersionTupleTest(unittest.TestCase):
    def test_openssh_patch_level_preserved(self):
        """Regression: greedy [a-z]* used to swallow the 'p', collapsing 9.3p1 and
        9.3p2 to the same tuple and losing the OpenSSH < 9.3p2 finding."""
        from recce.vuln.vulndb import _ver_tuple, _cmp
        self.assertEqual(_ver_tuple("8.2p1"), (8, 2, 1))      # docstring example
        self.assertEqual(_ver_tuple("9.3p1"), (9, 3, 1))
        self.assertEqual(_ver_tuple("9.3p2"), (9, 3, 2))
        self.assertEqual(_cmp("9.3p1", "9.3p2"), -1)          # p1 sorts below p2
        self.assertEqual(_ver_tuple("1.0.2k"), (1, 0, 2, 11))  # letter suffix intact
        self.assertEqual(_cmp("2.3.4", "2.3.4a"), -1)          # ...still < a-suffix

    def test_openssh_9_3p1_flags_double_free(self):
        from recce.vuln import vulndb
        h = Host(ip="10.0.0.9", os_family="Linux",
                 ports=[Port(portid=22, service="ssh", product="OpenSSH",
                             version="9.3p1")])
        vulndb.assess_host_inplace(h)
        self.assertTrue(any("double-free" in v.title for v in h.vulns))
        # 9.3p2 (patched) must NOT flag it
        h2 = Host(ip="10.0.0.10", os_family="Linux",
                  ports=[Port(portid=22, service="ssh", product="OpenSSH",
                              version="9.3p2")])
        vulndb.assess_host_inplace(h2)
        self.assertFalse(any("double-free" in v.title for v in h2.vulns))
class PrivEscVerdictTest(unittest.TestCase):
    def test_verdict_orders_and_classifies(self):
        from recce.act import privesc as pe
        h = Host(ip="10.0.0.5", os_family="Linux", local_findings=[
            {"category": "sudo",
             "vector": "NOPASSWD sudo: /usr/bin/find -> GTFOBins 'find'",
             "section": "Sudo", "source": "recce-enum"},
            {"category": "local",
             "vector": "recently modified config /opt/app/settings.conf",
             "section": "Files", "source": "recce-enum"}])
        rows = pe.plan(h)
        # escalation sorts first; the unmappable observation is a finding. The
        # generic checklist is NOT here anymore (it's the Playbook sheet), and a
        # swept host gets no 'run recce deploy' to-do.
        self.assertEqual(rows[0]["type"], "escalation")
        self.assertIn("GTFOBins", rows[0]["howto"])       # verdict shows the tool
        types = [r["type"] for r in rows]
        self.assertIn("finding", types)                   # the unmappable observation
        self.assertNotIn("checklist", types)
        self.assertNotIn("action", types)                 # already swept -> no to-do
        order = {"escalation": 0, "finding": 1, "action": 2}
        idx = [order[t] for t in types]
        self.assertEqual(idx, sorted(idx))

    def test_unswept_host_with_ports_gets_a_deploy_todo_not_a_checklist(self):
        from recce.act import privesc as pe
        rows = pe.plan(Host(ip="10.0.0.6", os_family="Windows",
                            ports=[Port(portid=445, service="microsoft-ds")]))
        self.assertEqual([r["type"] for r in rows], ["action"])
        self.assertIn("recce deploy", rows[0]["howto"])

    def test_dead_ip_produces_no_privesc_rows(self):
        # A host with no open ports and nothing observed (e.g. a network/broadcast
        # address that slipped into scope) must not fabricate privesc entries.
        from recce.act import privesc as pe
        self.assertEqual(pe.plan(Host(ip="10.200.37.0")), [])
        self.assertEqual(pe.all_rows([Host(ip="10.200.37.0")]), [])


class LocalEnumEnrichmentTest(unittest.TestCase):
    """The lateral-movement / shell-escape / persistence additions to the on-target
    scripts must flow through parsing, categorization, promotion and the playbook."""

    def test_new_sections_categorize(self):
        from recce.intake import ingest
        loot = (
            "recce-enum  host=WEB01  user=svc  now\n"
            "==== Lateral movement & pivoting ====\n"
            "[!] ssh-agent socket live (/tmp/ssh-x/agent.1) -> hijack to SSH onward\n"
            "[!] Kerberoastable accounts (SPN set): svc_sql, svc_web\n"
            "==== Restricted shell & shell escape ====\n"
            "[!] Restricted shell (/bin/rbash) -> escape via an allowed interpreter\n"
            "==== Persistence footholds (writable login/boot hooks) ====\n"
            "[!] Writable login-time file: /etc/profile.d/init.sh\n")
        parsed = ingest.parse_loot(loot)
        cats = {f["text"][:12]: f["category"] for f in parsed["findings"]}
        self.assertEqual(cats["ssh-agent so"], "lateral")
        self.assertEqual(cats["Kerberoastab"], "lateral")
        self.assertEqual(cats["Restricted s"], "escape")
        self.assertEqual(cats["Writable log"], "persistence")

    def test_high_value_lateral_findings_promote(self):
        from recce.intake import ingest
        findings = [
            {"vector": "Unconstrained-delegation hosts: SRV01 -> coerce auth + capture a TGT"},
            {"vector": "Kerberoastable accounts (SPN set): svc_sql"},
            {"vector": "Kubernetes service-account token readable (/var/run/secrets...)"},
        ]
        titles = {v.title for v in ingest.promote_to_vulns("10.0.0.9", findings)}
        self.assertTrue(any("Unconstrained delegation" in t for t in titles))
        self.assertTrue(any("Kerberoastable" in t for t in titles))
        self.assertTrue(any("Kubernetes" in t for t in titles))

    def test_playbook_maps_new_vectors(self):
        from recce.act import playbook as pb
        self.assertEqual(pb.for_text("Kerberoastable accounts (SPN set): svc",
                                     "windows")["id"], "win-kerberoast")
        self.assertEqual(pb.for_text("Unconstrained-delegation hosts: SRV01",
                                     "windows")["id"], "win-delegation")
        p = pb.for_text("ssh-agent socket live (/tmp/ssh-x/agent.1) -> hijack", "linux")
        self.assertEqual(p["id"], "lin-ssh-agent")
        self.assertIn("/tmp/ssh-x/agent.1", p["cmd"])          # {X} filled in
        self.assertEqual(pb.for_text("Restricted shell (/bin/rbash) -> escape",
                                     "linux")["id"], "lin-restricted-shell")

    def test_shipped_linux_script_parses(self):
        import shutil
        import subprocess
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "recce", "local", "recce-enum.sh")
        r = subprocess.run([bash, "-n", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_gtfobins_lite_returns_exact_technique(self):
        # The script's embedded GTFOBins-lite must resolve a specific binary to a
        # precise command (this is the "dive deeper into the exact exploit" logic).
        import shutil
        import subprocess
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash not available")
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "recce", "local", "recce-enum.sh")
        harness = (
            f"source <(sed -n '/^gtfo_suid()/,/^}}/p;/^gtfo_sudo()/,/^}}/p' {script})\n"
            "echo SUID_FIND:$(gtfo_suid /usr/bin/find)\n"
            "echo SUID_PY:$(gtfo_suid /usr/bin/python3)\n"
            "echo SUDO_VIM:$(gtfo_sudo /usr/bin/vim)\n"
            "echo UNKNOWN:[$(gtfo_suid /usr/bin/nope)]\n")
        r = subprocess.run([bash, "-c", harness], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SUID_FIND:/usr/bin/find . -exec /bin/sh -p", r.stdout)
        self.assertIn("os.setuid(0)", r.stdout)                 # python technique
        self.assertIn("SUDO_VIM:sudo /usr/bin/vim -c ':!/bin/sh'", r.stdout)
        self.assertIn("UNKNOWN:[]", r.stdout)                   # no false technique

    def test_suid_static_analysis_and_secret_phrasings_map(self):
        from recce.act import playbook as pb
        from recce.intake import ingest
        # The static-analysis SUID findings promote and map to a play.
        promoted = ingest.promote_to_vulns("10.0.0.5", [
            {"vector": "SUID PATH-hijack candidate: /usr/bin/foo invokes bare "
                       "command(s) [backup] -> plant a malicious binary earlier in PATH"}])
        self.assertTrue(any("Custom SUID" in v.title for v in promoted))
        play = pb.for_text("SUID PATH-hijack candidate: /usr/bin/foo invokes bare "
                           "command(s) [backup] -> plant", "linux")
        self.assertEqual(play["id"], "lin-suid-pathhijack")
        self.assertIn("backup", play["cmd"])                    # {X} filled in
        # Encrypted vs ready-to-use private keys are both surfaced as SSH_KEY-ish
        # credential findings and categorized under creds.
        parsed = ingest.parse_loot(
            "recce-enum  host=h  user=u  now\n"
            "==== Credential & secret hunting ====\n"
            "[!] Private key (UNENCRYPTED, ready): /home/u/.ssh/id_rsa\n")
        self.assertEqual(parsed["findings"][0]["category"], "creds")

    def test_windows_exact_exploit_findings_map_and_promote(self):
        from recce.act import playbook as pb
        from recce.intake import ingest
        unq = ("Unquoted service path EXPLOITABLE: service 'Foo' runs as LocalSystem "
               "-> plant your payload at  C:\\Program Files\\Sub.exe  (dir 'C:\\Program "
               "Files' is writable), then: sc stop Foo & sc start Foo")
        p = pb.for_text(unq, "windows")
        self.assertEqual(p["id"], "win-unquoted")
        self.assertIn("C:\\Program Files\\Sub.exe", p["cmd"])       # exact intercept
        dll = ("Writable app dir (DLL hijack): C:\\Program Files\\App -> exe(s): app.exe. "
               "The app dir is searched FIRST, so drop a DLL...")
        self.assertEqual(pb.for_text(dll, "windows")["id"], "win-dll-hijack")
        titles = {v.title for v in ingest.promote_to_vulns("10.0.0.5", [
            {"vector": unq}, {"vector": dll},
            {"vector": "Writable service binary EXPLOITABLE: C:\\svc\\a.exe (service X)"}])}
        self.assertTrue(any("Unquoted service path" in t for t in titles))
        self.assertTrue(any("DLL hijack" in t for t in titles))
        self.assertTrue(any("Writable service binary/registry" in t for t in titles))
class PocRecipeTest(unittest.TestCase):
    def test_finding_text_selects_the_right_recipe(self):
        from recce.act import poc
        cases = {
            "SUID env-injection candidate: /usr/bin/foo reads LD_PRELOAD": "ld_preload",
            "/etc/passwd is WRITABLE -> add a UID 0 user": "linux_passwd",
            "SUID PATH-hijack candidate: /usr/bin/foo invokes bare command(s) [backup]": "linux_root_job",
            "Unquoted service path EXPLOITABLE: service 'Foo' runs as LocalSystem": "win_service_exe",
            "Writable app dir (DLL hijack): C:\\Program Files\\App": "win_dll",
            "AlwaysInstallElevated = 1 (HKLM+HKCU)": "win_msi",
        }
        for text, key in cases.items():
            self.assertEqual(poc.recipe_key_for(text), key, text)

    def test_select_for_host_covers_confirmed_findings(self):
        from recce.act import poc
        h = Host(ip="10.0.0.5", local_findings=[
            {"category": "suid", "vector": "SUID env-injection candidate: /x reads LD_PRELOAD"},
            {"category": "writable", "vector": "/etc/passwd is WRITABLE -> add a UID 0 user"}])
        keys = set(poc.select_for_host(h))
        self.assertEqual(keys, {"ld_preload", "linux_passwd"})

    def test_write_files_and_plan_lines(self):
        from recce.act import poc
        with tempfile.TemporaryDirectory() as d:
            recipes = {k: poc.RECIPES[k] for k in ("ld_preload", "win_dll")}
            written = poc.write_files(d, recipes)
            self.assertTrue(any(p.endswith("recce_poc_preload.c") for p in written))
            self.assertTrue(any(p.endswith("recce_poc_dll.c") for p in written))
            block = "\n".join(poc.plan_lines(recipes))
            self.assertIn("PoC BUILD RECIPES", block)
            self.assertIn("gcc -fPIC -shared", block)
            self.assertIn("msfvenom", block)

    def test_web_pocs_per_finding(self):
        from recce.act import poc
        from recce.core.models import Host, Vuln

        def v(sid, out):
            return Vuln(ip="10.0.0.5", port=443, protocol="tcp", script_id=sid,
                        title=sid, output=out, source="web")
        h = Host(ip="10.0.0.5", vulns=[
            v("web-git", "GET https://10.0.0.5/.git/HEAD -> HTTP 200"),
            v("web-cors", "Origin: … -> ACAO https://10.0.0.5"),
            v("web-jwt", "alg=none token"),
            v("web-ssti", "GET https://10.0.0.5/?rc=… -> 49"),
            v("web-graphql", "POST https://10.0.0.5/graphql"),
            v("web-actuator-heapdump", "GET https://10.0.0.5/actuator/heapdump"),
        ])
        pocs = {f: (c, n) for f, c, n in poc.web_pocs_for_host(h)}
        # one artifact per finding, URL filled in, right extension.
        self.assertTrue(any(f.startswith("poc_web-git_") and f.endswith(".sh") for f in pocs))
        self.assertTrue(any(f.startswith("poc_web-cors_") and f.endswith(".html") for f in pocs))
        jwt_f = next(f for f in pocs if f.startswith("poc_web-jwt_"))
        self.assertTrue(jwt_f.endswith(".py"))
        # the generated Python + shell must be valid.
        compile(pocs[jwt_f][0], jwt_f, "exec")             # JWT forge PoC parses
        cors = next(pocs[f][0] for f in pocs if "cors" in f)
        self.assertIn("credentials:'include'", cors)
        self.assertIn("https://10.0.0.5", cors)             # target URL embedded
        # Every PoC states an unambiguous PROVEN verdict + the ROE hand-off marker.
        for fname, (content, _note) in pocs.items():
            self.assertIn("ROE:", content, fname)
            self.assertIn("PROVEN", content, fname)
        # The JWT PoC actually replays the forged token (accepted-vs-denied).
        jwt_src = pocs[jwt_f][0]
        self.assertIn("forged  status", jwt_src)
        self.assertIn("urllib.request", jwt_src)
        import shutil
        import subprocess
        if shutil.which("sh"):
            for f, (content, _) in pocs.items():
                if f.endswith(".sh"):
                    r = subprocess.run(["sh", "-n", "/dev/stdin"], input=content,
                                       capture_output=True, text=True)
                    self.assertEqual(r.returncode, 0, f"{f}: {r.stderr}")

    def test_exploitplan_writes_web_pocs(self):
        from recce.act import exploitplan
        from recce.core.models import Host, Vuln
        h = Host(ip="10.0.0.5", os_family="Linux", vulns=[
            Vuln(ip="10.0.0.5", port=80, protocol="tcp", script_id="web-git",
                 title="Exposed Git repository (.git)", output="GET http://10.0.0.5/.git/HEAD",
                 source="web", confidence="confirmed")])
        with tempfile.TemporaryDirectory() as d:
            summary = exploitplan.build_plan([h], d)
            poc_dir = os.path.join(summary["dir"], "poc")
            files = os.listdir(poc_dir) if os.path.isdir(poc_dir) else []
            self.assertTrue(any(f.startswith("poc_web-git_") for f in files))

    def test_ld_preload_poc_source_actually_compiles(self):
        # The emitted .so source must be valid C that builds - proves it's real,
        # not pseudo-code. (Skipped where gcc is unavailable.)
        import shutil
        import subprocess
        gcc = shutil.which("gcc")
        if not gcc:
            self.skipTest("gcc not available")
        from recce.act import poc
        with tempfile.TemporaryDirectory() as d:
            poc.write_files(d, {"ld_preload": poc.RECIPES["ld_preload"]})
            src = os.path.join(d, "recce_poc_preload.c")
            so = os.path.join(d, "recce_poc.so")
            r = subprocess.run([gcc, "-fPIC", "-shared", "-nostartfiles", "-o", so, src],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(so))

    def test_exploitplan_writes_poc_files(self):
        from recce.act import exploitplan
        from recce.core.models import Vuln
        h = Host(ip="10.0.0.5", os_family="Linux",
                 local_findings=[{"category": "writable",
                                  "vector": "/etc/passwd is WRITABLE -> add a UID 0 user"}])
        h.vulns = [Vuln(ip="10.0.0.5", port=None, protocol="tcp", script_id="local-enum",
                        title="Writable /etc/passwd (add a UID 0 user)", source="local",
                        confidence="confirmed")]
        with tempfile.TemporaryDirectory() as d:
            summary = exploitplan.build_plan([h], d)
            self.assertGreaterEqual(summary.get("poc_files", 0), 0)
            script = os.path.join(summary["dir"], "10.0.0.5.sh")
            self.assertTrue(os.path.exists(script))
            with open(script) as fh:
                self.assertIn("PoC BUILD RECIPES", fh.read())


class ProofEngineTest(unittest.TestCase):
    def _vuln(self, **kw):
        base = dict(ip="10.0.0.5", port=None, protocol="tcp", script_id="s",
                    title="", output="", source="nse")
        base.update(kw)
        return Vuln(**base)

    def test_activemq_patched_is_false_positive(self):
        from recce.vuln import proofs
        h = Host(ip="10.0.0.5", ports=[Port(portid=61616, service="activemq",
                                            product="Apache ActiveMQ", version="5.18.3",
                                            state="open")])
        h.vulns = [self._vuln(port=61616, title="Apache ActiveMQ 5.18.3",
                              ids=["CVE-2023-46604"])]
        r = proofs.verify_host(h)[0]
        self.assertEqual(r["verdict"], proofs.FALSE_POSITIVE)

    def test_activemq_old_with_openwire_is_likely(self):
        from recce.vuln import proofs
        h = Host(ip="10.0.0.5", ports=[Port(portid=61616, service="activemq",
                                            product="Apache ActiveMQ", version="5.17.1",
                                            state="open")])
        h.vulns = [self._vuln(port=61616, title="Apache ActiveMQ 5.17.1",
                              ids=["CVE-2023-46604"])]
        r = proofs.verify_host(h)[0]
        self.assertEqual(r["verdict"], proofs.LIKELY)
        self.assertTrue(any("61616 is OPEN" in e for e in r["evidence"]))

    def _ver_host(self, portid, prod, ver, title, ids=None):
        h = Host(ip="10.0.0.5", ports=[Port(portid=portid, service="x", product=prod,
                                            version=ver, state="open")])
        h.vulns = [self._vuln(port=portid, title=title, source="version-db",
                              ids=ids or [])]
        return h

    def test_version_cve_findings_now_get_a_verdict(self):
        # Gap-1: version->CVE matches that previously had NO prove path.
        from recce.vuln import proofs
        # regreSSHion: patched build -> FALSE POSITIVE (catches the over-flag).
        h = self._ver_host(22, "OpenSSH", "9.8p1", "OpenSSH regreSSHion pre-auth RCE",
                           ["CVE-2024-6387"])
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.FALSE_POSITIVE)
        # regreSSHion: affected window -> LIKELY.
        h = self._ver_host(22, "OpenSSH", "9.2p1", "OpenSSH regreSSHion", ["CVE-2024-6387"])
        r = proofs.verify_host(h)[0]
        self.assertEqual(r["verdict"], proofs.LIKELY)
        self.assertTrue(any("backport" in e.lower() or "glibc" in e.lower()
                            for e in r["evidence"]))
        # Apache smuggling: version match -> LIKELY with the backport caveat.
        h = self._ver_host(80, "Apache httpd", "2.4.52",
                           "Apache httpd < 2.4.59 mod_proxy SSRF / smuggling")
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.LIKELY)
        # EOL software: the version fact IS the proof -> CONFIRMED.
        for prod, ver, title in [("MySQL", "5.6.0", "End-of-life MySQL (< 5.7) exposed"),
                                 ("MongoDB", "3.4", "Legacy MongoDB (< 3.6) exposure"),
                                 ("Microsoft IIS", "6.0", "Legacy Microsoft IIS - unsupported")]:
            h = self._ver_host(3306, prod, ver, title)
            self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.CONFIRMED, title)

    def test_smb_signing_confirmed_vs_false_positive(self):
        from recce.vuln import proofs
        h = Host(ip="10.0.0.5", smb_signing="not required",
                 ports=[Port(portid=445, service="microsoft-ds", state="open")])
        h.vulns = [self._vuln(port=445, title="SMB signing not required",
                              script_id="smb2-security-mode")]
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.CONFIRMED)
        h.smb_signing = "required"
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.FALSE_POSITIVE)

    def test_ms17_010_nse_state_drives_verdict(self):
        from recce.vuln import proofs
        h = Host(ip="10.0.0.5", ports=[Port(portid=445, service="microsoft-ds", state="open")])
        h.vulns = [self._vuln(port=445, script_id="smb-vuln-ms17-010",
                              title="ms17-010", state="VULNERABLE", source="nse")]
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.CONFIRMED)
        h.vulns[0].state = "NOT VULNERABLE"
        h.vulns[0].output = "NOT VULNERABLE (patched)"
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.FALSE_POSITIVE)

    def test_seimpersonate_enabled_confirms_but_remote_only_inconclusive(self):
        from recce.vuln import proofs
        # On-target enum says Enabled -> CONFIRMED.
        h = Host(ip="10.0.0.5", os_family="Windows",
                 local_findings=[{"category": "token",
                                  "vector": "SeImpersonate / SeAssignPrimaryToken held (Enabled) -> Potato"}])
        h.vulns = [self._vuln(port=None, title="SeImpersonate -> Potato -> SYSTEM")]
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.CONFIRMED)
        # Remote inference only (no on-target confirmation) -> INCONCLUSIVE.
        h2 = Host(ip="10.0.0.6", os_family="Windows",
                  ports=[Port(portid=1433, service="ms-sql-s", state="open")])
        h2.vulns = [self._vuln(ip="10.0.0.6", port=1433,
                               title="MSSQL service - likely holds SeImpersonate")]
        self.assertEqual(proofs.verify_host(h2)[0]["verdict"], proofs.INCONCLUSIVE)

    def test_confirmed_sorts_before_false_positive(self):
        from recce.vuln import proofs
        h = Host(ip="10.0.0.5", smb_signing="not required",
                 ports=[Port(portid=445, state="open"),
                        Port(portid=61616, product="Apache ActiveMQ", version="5.18.5",
                             state="open")])
        h.vulns = [self._vuln(port=61616, title="ActiveMQ 5.18.5", ids=["CVE-2023-46604"]),
                   self._vuln(port=445, title="SMB signing not required",
                              script_id="smb2-security-mode")]
        verdicts = [r["verdict"] for r in proofs.verify_host(h)]
        self.assertEqual(verdicts[0], proofs.CONFIRMED)
        self.assertEqual(verdicts[-1], proofs.FALSE_POSITIVE)

    def test_printnightmare_verdicts(self):
        from recce.vuln import proofs
        # On-target LPE precondition present -> LIKELY.
        h = Host(ip="10.0.0.5", os_family="Windows", local_findings=[{"category": "hardening",
                 "vector": "PrintNightmare surface: Spooler running + PointAndPrint "
                           "NoWarningNoElevationOnInstall=1 (CVE-2021-34527)"}])
        h.vulns = [self._vuln(title="PrintNightmare surface", script_id="local")]
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.LIKELY)
        # Non-Windows host flagged -> FALSE POSITIVE.
        h2 = Host(ip="10.0.0.6", os_family="Linux")
        h2.vulns = [self._vuln(ip="10.0.0.6", title="printnightmare (CVE-2021-34527)")]
        self.assertEqual(proofs.verify_host(h2)[0]["verdict"], proofs.FALSE_POSITIVE)

    def test_bluekeep_os_gating(self):
        from recce.vuln import proofs
        old = Host(ip="10.0.0.5", os_name="Windows 7 Professional",
                   ports=[Port(portid=3389, service="ms-wbt-server", state="open")])
        old.vulns = [self._vuln(port=3389, title="BlueKeep", ids=["CVE-2019-0708"])]
        self.assertEqual(proofs.verify_host(old)[0]["verdict"], proofs.LIKELY)
        new = Host(ip="10.0.0.6", os_name="Windows Server 2019",
                   ports=[Port(portid=3389, service="ms-wbt-server", state="open")])
        new.vulns = [self._vuln(ip="10.0.0.6", port=3389, title="BlueKeep",
                                ids=["CVE-2019-0708"])]
        self.assertEqual(proofs.verify_host(new)[0]["verdict"], proofs.FALSE_POSITIVE)

    def test_zerologon_only_on_dcs(self):
        from recce.vuln import proofs
        dc = Host(ip="10.0.0.5", os_family="Windows",
                  ports=[Port(portid=88, service="kerberos", state="open"),
                         Port(portid=389, service="ldap", state="open")])
        dc.vulns = [self._vuln(port=None, title="ZeroLogon", ids=["CVE-2020-1472"])]
        self.assertEqual(proofs.verify_host(dc)[0]["verdict"], proofs.LIKELY)
        member = Host(ip="10.0.0.6", os_family="Windows",
                      ports=[Port(portid=445, service="microsoft-ds", state="open")])
        member.vulns = [self._vuln(ip="10.0.0.6", title="ZeroLogon", ids=["CVE-2020-1472"])]
        self.assertEqual(proofs.verify_host(member)[0]["verdict"], proofs.FALSE_POSITIVE)

    def test_heartbleed_and_kerberoast(self):
        from recce.vuln import proofs
        h = Host(ip="10.0.0.5", ports=[Port(portid=443, service="https", state="open")])
        h.vulns = [self._vuln(port=443, script_id="ssl-heartbleed", title="heartbleed",
                              state="VULNERABLE", source="nse")]
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.CONFIRMED)
        k = Host(ip="10.0.0.7", os_family="Windows",
                 local_findings=[{"category": "lateral",
                                  "vector": "Kerberoastable accounts (SPN set): svc_sql"}])
        k.vulns = [self._vuln(ip="10.0.0.7", title="Kerberoastable accounts (SPN set): svc_sql")]
        self.assertEqual(proofs.verify_host(k)[0]["verdict"], proofs.CONFIRMED)

    def test_verification_sheet_builds(self):
        from recce.report.excel import _spec_verification
        h = Host(ip="10.0.0.5", smb_signing="not required",
                 ports=[Port(portid=445, state="open")])
        h.vulns = [self._vuln(port=445, title="SMB signing not required",
                              script_id="smb2-security-mode")]
        spec = _spec_verification([h])
        self.assertEqual(spec.title, "Verification")
        self.assertTrue(spec.rows)
        self.assertIn("Verdict", [c[0] for c in spec.cols])


class CredentialsTest(unittest.TestCase):
    def _hosts(self):
        return [Host(ip="10.0.10.5", subnet="10.0.10.0/24", os_family="Windows",
                     ports=[Port(portid=445, service="microsoft-ds"),
                            Port(portid=5985, service="http"),
                            Port(portid=389, service="ldap")]),
                Host(ip="10.0.20.9", subnet="10.0.20.0/24", os_family="Linux",
                     ports=[Port(portid=22, service="ssh")])]

    def test_parse_and_stack_dedupe(self):
        from recce import cli
        from recce.creds import credentials as cr
        a = cli._parse_cred_spec("CORP\\alice:Passw0rd!")
        self.assertEqual((a.domain, a.username, a.kind), ("CORP", "alice", "password"))
        b = cli._parse_cred_spec("administrator:aad3b435b51404eeaad3b435b51404ee")
        self.assertEqual(b.kind, "nthash")             # 32-hex -> hash
        c = cli._parse_cred_spec("bob")
        self.assertEqual(c.kind, "blank")
        stacked = cr.stack([], [a, b, a])              # duplicate a collapses
        self.assertEqual(len(stacked), 2)

    def test_spray_plan_files_and_commands(self):
        from recce.creds import credentials as cr
        from recce.core.models import Credential
        creds = [Credential(username="alice", secret="Pw!", kind="password", domain="CORP"),
                 Credential(username="administrator",
                            secret="aad3b435b51404eeaad3b435b51404ee", kind="nthash")]
        with tempfile.TemporaryDirectory() as d:
            s = cr.build_spray(creds, self._hosts(), d)
            self.assertIn("users.txt", s["files"])
            self.assertIn("passwords.txt", s["files"])
            self.assertIn("nthashes.txt", s["files"])
            cmds = "\n".join(s["commands"])
            self.assertIn("netexec smb 10.0.10.5", cmds)   # the discovered IP, not the /24
            self.assertNotIn("/24", cmds)                  # never widen the spray to a subnet
            self.assertIn("-H nthashes.txt", cmds)         # pass-the-hash line
            self.assertIn("netexec ssh 10.0.20.9", cmds)
            self.assertNotIn("netexec ssh 10.0.20.9 -u users.txt -H", cmds)  # no PtH over ssh

    def test_spray_plan_files_are_written_as_utf8_not_platform_default(self):
        # Regression: users.txt/passwords.txt were opened bare open(...,"w") - a
        # captured non-ASCII username/password (real in an AD environment with
        # international display names) would raise UnicodeEncodeError on a
        # platform whose default text encoding isn't UTF-8 (e.g. cp1252 on
        # Windows, which recce explicitly ships an airgap build for).
        from recce.creds import credentials as cr
        from recce.core.models import Credential
        creds = [Credential(username="josé", secret="contraseña—uno!",
                            kind="password", domain="CORP")]
        with tempfile.TemporaryDirectory() as d:
            s = cr.build_spray(creds, self._hosts(), d)
            with open(s["files"]["users.txt"], encoding="utf-8") as fh:
                self.assertIn("josé", fh.read())
            with open(s["files"]["passwords.txt"], encoding="utf-8") as fh:
                self.assertIn("contraseña—uno!", fh.read())

    def test_harvest_from_accounts(self):
        from recce.creds import credentials as cr
        from recce.core.models import Account
        h = Host(ip="10.0.0.5", accounts=[
            Account(ip="10.0.0.5", source="secretsdump", kind="user", name="svc",
                    domain="CORP", attrs={"password": "S3cret"})])
        got = cr.harvest([h])
        self.assertEqual(len(got), 1)
        self.assertEqual((got[0].username, got[0].secret), ("svc", "S3cret"))

    def test_creds_add_list_plan_via_cli(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "results.sqlite")
            st = Store(db)
            st.upsert_host(Host(ip="10.0.10.5", subnet="10.0.10.0/24",
                                ports=[Port(portid=445, service="microsoft-ds")]))
            st.close()
            def ns(**kw):
                base = dict(output_dir=d, targets=[], host=[], subnet=[], add=None,
                            user=None, password=None, hash=None, domain=None,
                            plan=False, title="t")
                base.update(kw)
                return SimpleNamespace(**base)
            self.assertEqual(cli.cmd_creds(ns(add=["CORP\\alice:Pw!"])), 0)
            st = Store(db)
            self.assertEqual(len(st.all_credentials()), 1)
            st.close()
            self.assertEqual(cli.cmd_creds(ns(plan=True)), 0)
            self.assertTrue(os.path.exists(os.path.join(d, "creds", "users.txt")))
class KubernetesTest(unittest.TestCase):
    def _host(self):
        return Host(ip="10.0.0.90", os_family="Linux",
                    ports=[Port(portid=10250, state="open"),
                           Port(portid=2379, state="open"),
                           Port(portid=6443, state="open")])

    def test_findings_all_surfaces(self):
        from recce.services import kubernetes as k8s
        from recce.report.docx import _vuln_type
        pr = {("10.0.0.90", 10250): {"role": "kubelet", "anon_pods": True, "pod_count": 7},
              ("10.0.0.90", 2379): {"role": "etcd", "v2_readable": True,
                                    "etcd_version": "3.5.9"},
              ("10.0.0.90", 6443): {"role": "apiserver", "version": "v1.28",
                                    "anon_list": True, "anon_secrets": True,
                                    "anon_status": 200}}
        fs = k8s.findings([self._host()], pr)
        titles = " | ".join(f["title"] for f in fs)
        self.assertIn("Kubelet allows anonymous", titles)
        self.assertIn("etcd exposed", titles)
        self.assertIn("anonymous resource listing", titles)
        by = k8s.findings_to_vulns(fs)
        for v in by["10.0.0.90"]:
            vt, _ = _vuln_type(v.cwes)
            self.assertTrue(vt, v.cwes)

    def test_prove_engine_confirms_and_downgrades(self):
        from recce.services import kubernetes as k8s
        from recce.vuln import proofs
        pr = {("10.0.0.90", 10250): {"role": "kubelet", "anon_pods": True, "pod_count": 3},
              ("10.0.0.90", 6443): {"role": "apiserver", "version": "v1.28",
                                    "anon_list": False, "anon_status": 403}}
        h = Host(ip="10.0.0.90", ports=[Port(portid=10250, state="open"),
                                        Port(portid=6443, state="open")])
        h.vulns = k8s.findings_to_vulns(k8s.findings([h], pr))["10.0.0.90"]
        verdicts = [r["verdict"] for r in proofs.verify_host(h)]
        self.assertIn(proofs.CONFIRMED, verdicts)                  # kubelet read
        self.assertIn(proofs.LIKELY, verdicts)                     # anonymous-auth 403

    def test_v3_etcd_is_flagged(self):
        # Modern etcd disables the v2 keys API; a readable v3 gateway must still fire.
        from recce.services import kubernetes as k8s
        pr = {("10.0.0.90", 2379): {"role": "etcd", "v2_readable": False,
                                    "v3_readable": True, "etcd_version": "3.5.9"}}
        h = Host(ip="10.0.0.90", ports=[Port(portid=2379, state="open")])
        fs = k8s.findings([h], pr)
        self.assertTrue(any("etcd exposed" in f["title"] for f in fs))
        self.assertIn("v3", " ".join(f["detail"] for f in fs))

    def test_8080_is_not_auto_selected_as_apiserver(self):
        from recce.services import kubernetes as k8s
        self.assertEqual(k8s.role(8080), "unknown")
        self.assertFalse(k8s.is_k8s(Port(portid=8080, state="open", service="http")))
        # but a service explicitly named kube-apiserver is still caught
        self.assertTrue(k8s.is_k8s(Port(portid=8080, state="open",
                                        service="kube-apiserver")))

    def test_probe_parsers(self):
        from recce.services import kubernetes as k8s
        self.assertTrue(k8s._is_podlist({"kind": "PodList", "items": [1, 2]}))
        self.assertEqual(k8s._pod_count({"items": [1, 2, 3]}), 3)
        self.assertTrue(k8s._is_list({"kind": "NamespaceList", "items": []}))
        self.assertEqual(k8s._etcd_version({"etcdserver": "3.5.9"}), "3.5.9")
        self.assertEqual(k8s.role(10250), "kubelet")
        self.assertEqual(k8s.role(2379), "etcd")

    def test_cmd_kubernetes_end_to_end(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services import kubernetes as k8s
        from recce.core.store import Store
        import http.server
        import threading
        import json as _json

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/pods":
                    b = _json.dumps({"kind": "PodList",
                                     "items": [{"m": 1}, {"m": 2}]}).encode()
                    self.send_response(200)
                else:
                    b = b"{}"
                    self.send_response(404)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        orig_role, orig_is = k8s.role, k8s.is_k8s
        k8s.role = lambda p: "kubelet-ro" if p == port else orig_role(p)
        k8s.is_k8s = lambda p: (p.state == "open" and (p.portid == port or orig_is(p)))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=port, state="open",
                                                service="kubelet")]))
                st.close()
                rc = cli.main(["k8s", "-o", out])
                self.assertEqual(rc, 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("Kubernetes", sheets)
                vtxt = "\n".join(" ".join(map(str, r))
                                 for r in sheets["Vulnerabilities"])
                self.assertIn("Kubelet", vtxt)
                st = Store(os.path.join(out, "results.sqlite"))
                h = st.get_host("127.0.0.1")
                st.close()
                self.assertTrue([v for v in h.vulns if v.source == "kubernetes"])
        finally:
            httpd.shutdown()
            k8s.role, k8s.is_k8s = orig_role, orig_is

    def test_no_endpoints_is_graceful(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.7", ports=[Port(portid=80, service="http")]))
            st.close()
            self.assertEqual(cli.main(["kubernetes", "-o", out, "--no-probe"]), 0)


class CapabilityAutoCheckTest(unittest.TestCase):
    """Running a deep-service capability auto-marks the Checklist boxes for the
    ports it assessed (no manual ticking)."""

    def test_mark_capability_scanned_flags_ports_and_db(self):
        from recce import cli
        from recce.core import tracking as tr
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "s.sqlite"))
            st.upsert_host(Host(ip="10.0.0.5", subnet="10.0.0.0/24", enumerated=True,
                                ports=[Port(portid=445, state="open", service="smb"),
                                       Port(portid=1433, state="open",
                                            service="ms-sql-s")]))
            # An SMB run assessed only 445 -> that port is scanned, 1433 is not, and a
            # host with an un-scanned port is NOT yet 'vuln-scanned' overall.
            cli._mark_capability_scanned(st, [{"ip": "10.0.0.5", "port": 445}])
            h = st.get_host("10.0.0.5")
            self.assertTrue(next(p for p in h.ports if p.portid == 445).vuln_scanned)
            self.assertFalse(next(p for p in h.ports if p.portid == 1433).vuln_scanned)
            self.assertFalse(tr.step_auto(h, "vuln"))
            self.assertFalse(h.db_scanned)
            # An MSSQL run assesses 1433 AND flags the host db-scanned -> now every port
            # is covered, so Vuln-scan and DB both auto-tick.
            cli._mark_capability_scanned(st, [{"ip": "10.0.0.5", "port": 1433}], db=True)
            h = st.get_host("10.0.0.5")
            self.assertTrue(tr.step_auto(h, "vuln"))
            self.assertTrue(tr.step_auto(h, "db"))
            st.close()


class DockerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import http.server
        import threading
        import json as _json

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                m = {"/version": {"Version": "24.0.5", "ApiVersion": "1.43",
                                  "Os": "linux", "KernelVersion": "6.1"},
                     "/info": {"Name": "node1", "Containers": 2, "ContainersRunning": 1,
                               "Images": 5, "ServerVersion": "24.0.5"},
                     "/containers/json": [{"Image": "nginx", "Names": ["/web"],
                                           "Command": "nginx", "State": "running"}],
                     "/images/json": [{"RepoTags": ["nginx:latest", "app:1.2"]}]}
                b = _json.dumps(m.get(self.path, {})).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_probe_and_findings(self):
        from recce.services import docker
        from recce.report.docx import _vuln_type
        pr = docker.probe("127.0.0.1", self.port)
        self.assertTrue(pr and pr["exposed"])
        self.assertEqual(pr["server_version"], "24.0.5")
        # findings() needs is_docker(port) True; the test server is on a random port,
        # so exercise the finding path on a canonical 2375 host with the same probe.
        h2 = Host(ip="127.0.0.1", ports=[Port(portid=2375, state="open")])
        fs = docker.findings([h2], {("127.0.0.1", 2375): pr})
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("exposed without authentication", titles)
        by = docker.findings_to_vulns(fs)
        for v in by["127.0.0.1"]:
            vt, _ = _vuln_type(v.cwes)
            self.assertTrue(vt, v.cwes)

    def test_prove_engine_confirms_exposure(self):
        from recce.services import docker
        from recce.vuln import proofs
        pr = docker.probe("127.0.0.1", self.port)
        h = Host(ip="127.0.0.1", ports=[Port(portid=2375, state="open")])
        h.vulns = docker.findings_to_vulns(
            docker.findings([h], {("127.0.0.1", 2375): pr}))["127.0.0.1"]
        verdicts = [r["verdict"] for r in proofs.verify_host(h)]
        self.assertIn(proofs.CONFIRMED, verdicts)

    def test_probed_but_not_exposed_marks_false(self):
        # A Docker port that answers TCP but whose API read fails (TLS-locked/auth) must
        # come back exposed=False + probed=True, not an unset 'not probed'.
        from recce.services import docker
        h = Host(ip="127.0.0.1", ports=[Port(portid=2375, state="open")])
        an = docker.analyze([h], active=True)   # nothing is listening on 2375 here
        t = an["targets"][0]
        self.assertFalse(t.get("exposed"))
        self.assertTrue(t.get("probed"))

    def test_cmd_docker_end_to_end(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services import docker
        from recce.core.store import Store
        orig = docker.is_docker
        docker.is_docker = lambda p: (p.state == "open"
                                      and (p.portid == self.port or orig(p)))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=self.port, state="open",
                                                service="docker")]))
                st.close()
                rc = cli.main(["docker", "-o", out])
                self.assertEqual(rc, 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("Docker", sheets)
                vtxt = "\n".join(" ".join(map(str, r))
                                 for r in sheets["Vulnerabilities"])
                self.assertIn("Docker Engine API", vtxt)
                st = Store(os.path.join(out, "results.sqlite"))
                h = st.get_host("127.0.0.1")
                st.close()
                self.assertTrue([v for v in h.vulns if v.source == "docker"])
        finally:
            docker.is_docker = orig

    def test_no_endpoints_is_graceful(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.7", ports=[Port(portid=22, service="ssh")]))
            st.close()
            self.assertEqual(cli.main(["docker", "-o", out, "--no-probe"]), 0)
class ListenerBackfillTest(unittest.TestCase):
    LOOT = (
        "recce-enum  host=web01  user=root  now\n"
        "==== Network ====\n"
        "    listening-service inventory (proto/port/process/binary):\n"
        "    LISTEN proto=tcp addr=0.0.0.0 port=80 pid=1337 proc=nginx bin=/usr/sbin/nginx\n"
        "    LISTEN proto=tcp addr=127.0.0.1 port=6379 pid=990 proc=redis-server bin=/usr/bin/redis-server\n"
        "    LISTEN proto=tcp addr=0.0.0.0 port=5985 pid=1200 proc=svchost svc=WinRM bin=C:\\Windows\\svchost.exe\n"
        "    LISTEN proto=udp addr=[::] port=53 pid=800 proc=named bin=/usr/sbin/named\n")

    def test_parse_listeners_linux_and_windows_lines(self):
        from recce.intake import ingest
        ls = {(x["proto"], x["port"]): x for x in ingest.parse_listeners(self.LOOT)}
        self.assertEqual(ls[("tcp", 80)]["bin"], "/usr/sbin/nginx")
        self.assertFalse(ls[("tcp", 80)]["loopback"])
        self.assertTrue(ls[("tcp", 6379)]["loopback"])          # 127.0.0.1
        self.assertEqual(ls[("tcp", 5985)]["svc"], "WinRM")     # windows svc= field
        self.assertEqual(ls[("udp", 53)]["port"], 53)
        # No listener lines -> empty (older loot degrades gracefully).
        self.assertEqual(ingest.parse_listeners("recce-enum host=x\n[!] a finding"), [])

    def test_backfill_enriches_and_adds_ports(self):
        from recce.intake import ingest
        h = Host(ip="10.0.0.9", ports=[
            Port(portid=80, protocol="tcp", service="http", product="nginx",
                 detect_source="nmap", state="open")])
        added, enriched = ingest.backfill_ports(h, ingest.parse_listeners(self.LOOT))
        self.assertEqual((added, enriched), (3, 1))
        idx = {(p.protocol, p.portid): p for p in h.ports}
        # Existing nmap port keeps its service; only gains the backing binary.
        self.assertEqual(idx[("tcp", 80)].service, "http")
        self.assertEqual(idx[("tcp", 80)].detect_source, "nmap")
        self.assertEqual(idx[("tcp", 80)].binary, "/usr/sbin/nginx")
        # Loopback-only service the network scan never saw is now on the host.
        self.assertIn(("tcp", 6379), idx)
        self.assertEqual(idx[("tcp", 6379)].detect_source, "local")
        self.assertIn("loopback", idx[("tcp", 6379)].extrainfo)
        # Windows svc name becomes the service label + noted in extra info.
        self.assertEqual(idx[("tcp", 5985)].service, "WinRM")
        self.assertEqual(idx[("udp", 53)].service, "named")

    def test_fold_loot_backfills_ports_end_to_end(self):
        from recce import cli
        h = Host(ip="10.0.0.9", os_family="Linux",
                 ports=[Port(portid=80, protocol="tcp", service="http",
                             detect_source="nmap", state="open")])
        cli._fold_loot(h, self.LOOT, "loot.txt")
        idx = {(p.protocol, p.portid): p for p in h.ports}
        self.assertEqual(idx[("tcp", 80)].binary, "/usr/sbin/nginx")
        self.assertIn(("tcp", 6379), idx)               # loopback service added

    def test_backfill_survives_store_round_trip(self):
        from recce.intake import ingest
        from recce.core.store import Store
        h = Host(ip="10.0.0.9", subnet="10.0.0.0/24", ports=[])
        ingest.backfill_ports(h, ingest.parse_listeners(self.LOOT))
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "r.sqlite"))
            st.upsert_host(h)
            back = st.get_host("10.0.0.9")
            st.close()
        binp = {(p.protocol, p.portid): p.binary for p in back.ports}
        self.assertEqual(binp[("tcp", 80)], "/usr/sbin/nginx")


class EngagementPermsTest(unittest.TestCase):
    def test_relax_perms_owner_only_never_world_readable(self):
        # The engagement tree holds captured creds/NTLM hashes, so relax must give
        # the operator access (dirs 0700, files 0600) WITHOUT any group/world bits.
        from recce import cli
        with tempfile.TemporaryDirectory() as d:
            sub = os.path.join(d, "raw")
            os.makedirs(sub)
            f1 = os.path.join(d, "report.html")
            f2 = os.path.join(sub, "10.0.0.5.xml")
            for f in (f1, f2):
                with open(f, "w") as fh:
                    fh.write("x")
                os.chmod(f, 0o644)          # simulate a world-readable created file
            cli._relax_perms(d)
            for p in (d, sub):
                self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o700, p)
            for p in (f1, f2):
                self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600, p)
            # No group/world access anywhere in the tree.
            for p in (d, sub, f1, f2):
                self.assertEqual(stat.S_IMODE(os.stat(p).st_mode) & 0o077, 0, p)

    def test_relax_perms_is_best_effort_on_missing_dir(self):
        from recce import cli
        cli._relax_perms("/nonexistent/path/xyz")      # must not raise

    def test_open_paths_owner_only_output_dir(self):
        from recce import cli
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "engagement")
            cli._open_paths(out)
            self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(out, "raw")).st_mode),
                             0o700)

    def test_main_finally_relaxes_perms_even_on_early_return(self):
        from recce import cli
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            # attackpath with no datastore returns 1 early - the finally must still
            # relax the folder that _open_paths created.
            rc = cli.main(["attackpath", "-o", out])
            self.assertEqual(rc, 1)
            self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(out).st_mode) & 0o077, 0)


class AVAwarenessTest(unittest.TestCase):
    LOOT = ("recce-enum  host=DC01  user=admin  now\n"
            "==== AV / EDR detection ====\n"
            "    AV product: Windows Defender\n"
            "[!] EDR/AV process: CSFalcon\n"
            "    EDR/AV service: CSAgent\n"
            "==== OS hardening & defences ====\n"
            "    Defender: RealTime=True Tamper=True\n"
            "    LSA protection (RunAsPPL)=1\n"
            "    Sysmon service present (activity is being logged)\n"
            "    AppLocker policy present (review allowed paths)\n")

    def test_extract_defenses(self):
        from recce.intake import ingest
        j = " | ".join(ingest.extract_defenses(self.LOOT))
        for expect in ("AV: Windows Defender", "CSFalcon (process)",
                       "CSAgent (service)", "Defender RTP=True",
                       "LSASS protected (RunAsPPL)", "Sysmon present (logging)",
                       "AppLocker enforced"):
            self.assertIn(expect, j)

    def test_ingest_populates_defenses(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as dd:
            db = os.path.join(dd, "results.sqlite")
            st = Store(db)
            st.upsert_host(Host(ip="10.0.0.5", subnet="10.0.0.0/24",
                                os_family="Windows",
                                ports=[Port(portid=445, service="microsoft-ds")]))
            st.close()
            loot = os.path.join(dd, "l.txt")
            with open(loot, "w") as fh:
                fh.write(self.LOOT)
            cli.cmd_ingest(SimpleNamespace(output_dir=dd, loot=loot,
                                           host="10.0.0.5", title="t"))
            st = Store(db)
            h = {x.ip: x for x in st.all_hosts()}["10.0.0.5"]
            st.close()
            self.assertTrue(any("CSFalcon" in x for x in h.defenses))

    def test_checklist_and_exploitation_columns(self):
        from recce.report.excel import _spec_checklist, _spec_exploitation
        from recce.core.models import Vuln
        h = Host(ip="10.0.0.5", os_family="Windows",
                 defenses=["EDR/AV: CSFalcon (process)"],
                 ports=[Port(portid=445, service="microsoft-ds")],
                 vulns=[Vuln(ip="10.0.0.5", port=445, protocol="tcp",
                             script_id="local-enum",
                             title="SeImpersonate -> Potato -> SYSTEM", severity="high",
                             source="local", confidence="confirmed",
                             output="SeImpersonate held")])
        cl = _spec_checklist([h])
        self.assertIn("AV / EDR", [c[0] for c in cl.cols])
        self.assertEqual(cl.rows[0]["data"]["AV / EDR"], "EDR/AV: CSFalcon (process)")
        ex = _spec_exploitation([h])
        self.assertIn("Defenses (host)", [c[0] for c in ex.cols])
        self.assertTrue(any("CSFalcon" in r["data"].get("Defenses (host)", "")
                            for r in ex.rows))

    def test_exploitplan_defenses_banner(self):
        from recce.act import exploitplan as ep
        from recce.core.models import Vuln
        h = Host(ip="10.0.0.5", os_family="Windows",
                 defenses=["EDR/AV: CSFalcon (process)"],
                 ports=[Port(portid=445, service="microsoft-ds")],
                 vulns=[Vuln(ip="10.0.0.5", port=445, protocol="tcp",
                             script_id="smb-vuln-ms17-010", title="smb-vuln-ms17-010",
                             severity="high", source="nse", ids=["CVE-2017-0143"],
                             output="VULNERABLE")])
        with tempfile.TemporaryDirectory() as dd:
            s = ep.build_plan([h], dd)
            with open(os.path.join(s["dir"], "10.0.0.5.sh")) as fh:
                sh = fh.read()
        self.assertIn("DEFENSES on 10.0.0.5", sh)
        self.assertIn("CSFalcon", sh)
        self.assertIn("does not evade AV", sh)   # coordination, not evasion


class ServiceEnumTest(unittest.TestCase):
    def test_script_mapping(self):
        from recce.services import serviceenum as se
        self.assertEqual(se.script_for("microsoft-ds", 445), "smb")
        self.assertEqual(se.script_for("netbios-ssn", 139), "smb")
        self.assertEqual(se.script_for("ssl/http", 8443), "http")
        self.assertEqual(se.script_for("", 6379), "redis")       # port fallback
        self.assertEqual(se.script_for("http", 5985), "winrm")   # WinRM port wins
        self.assertEqual(se.script_for("ms-wbt-server", 3389), "rdp")
        self.assertEqual(se.script_for("unknown-thing", 12345), "")

    def test_commands_and_unmapped(self):
        from recce.services import serviceenum as se
        h = Host(ip="10.0.0.5", hostnames=["dc"],
                 ports=[Port(portid=445, service="microsoft-ds"),
                        Port(portid=6379, service="redis"),
                        Port(portid=9999, service="weird", state="open")])
        cmds = se.commands_for_host(h)
        scripts = {c[2] for c in cmds}
        self.assertEqual(scripts, {"smb", "redis"})
        self.assertTrue(all(c[3].startswith("./scripts/recce-service.sh") for c in cmds))
        self.assertIn((9999, "weird"), se.unmapped_ports(h))

    def test_cmd_services_smoke(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "results.sqlite")
            st = Store(db)
            st.upsert_host(Host(ip="10.0.0.5", subnet="10.0.0.0/24",
                                ports=[Port(portid=445, service="microsoft-ds"),
                                       Port(portid=80, service="http")]))
            st.close()
            rc = cli.cmd_services(SimpleNamespace(output_dir=d, targets=[],
                                                  host=[], subnet=[], aggressive=False))
            self.assertEqual(rc, 0)


class SvcDetectTest(unittest.TestCase):
    def test_servicefp_mining_names_unknown_port(self):
        from recce.services import svcdetect as sd
        p = Port(portid=5900, service="unknown", servicefp="RFB 003.008\n")
        self.assertTrue(sd.enrich_port("1.1.1.1", p, active=False))
        self.assertEqual(p.service, "vnc")
        self.assertEqual(p.detect_source, "inferred")

    def test_curated_port_map_labels_windows_services(self):
        from recce.services import svcdetect as sd
        p = Port(portid=5040, service="unknown")
        sd.enrich_port("1.1.1.1", p, active=False)
        self.assertEqual(p.service, "cdpsvc")
        self.assertIn("CDPSvc", p.extrainfo)
        self.assertEqual(p.detect_source, "inferred")
        # Dynamic MSRPC ephemeral range.
        p2 = Port(portid=49664, service="")
        sd.enrich_port("1.1.1.1", p2, active=False)
        self.assertEqual(p2.service, "msrpc")

    def test_nmap_named_port_is_never_overwritten(self):
        from recce.services import svcdetect as sd
        p = Port(portid=80, service="http", detect_source="nmap")
        self.assertFalse(sd.enrich_port("1.1.1.1", p, active=False))
        self.assertEqual(p.service, "http")

    def test_banner_signature_matching(self):
        from recce.services import svcdetect as sd
        self.assertEqual(sd._match_signature("SSH-2.0-OpenSSH_8.9")[0], "ssh")
        self.assertEqual(sd._match_signature("HTTP/1.1 200 OK")[0], "http")
        self.assertEqual(sd._match_signature("+PONG\r\n")[0], "redis")
        self.assertEqual(sd._match_signature("\x03\x00\x00\x13")[0], "ms-wbt-server")
        self.assertIsNone(sd._match_signature("random noise"))

    def test_silent_http_on_nonstandard_port_is_identified(self):
        """A web server on an odd port stays mute on connect and has no nudge of
        its own; the generic HTTP fallback must still coax an HTTP/ banner so the
        port gets a real service label (and thus web/api enum). Regression for the
        lab shakeout where 8099 came back 'unknown' and all API surface was missed."""
        import socket as _socket
        import threading
        from recce.services import svcdetect as sd

        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))                 # silent HTTP-ish server on an odd port
        port_no = srv.getsockname()[1]
        srv.listen(1)

        def serve_once():
            try:
                conn, _ = srv.accept()
                conn.recv(256)                     # wait to be spoken to, THEN answer
                conn.sendall(b"HTTP/1.0 200 OK\r\nServer: LabAPI/1.0\r\n\r\n")
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=serve_once, daemon=True)
        t.start()
        try:
            port = Port(portid=port_no, protocol="tcp", state="open", service="unknown")
            host = Host(ip="127.0.0.1", ports=[port])
            sd.enrich_host(host, active=True)
            self.assertEqual(port.service, "http")
            self.assertEqual(port.detect_source, "banner")
        finally:
            srv.close()
            t.join(timeout=2)

    def test_silent_https_on_nonstandard_port_is_identified(self):
        """The TLS twin of the plaintext fix: a silent HTTPS app on an odd port
        answers a plaintext HEAD with a TLS alert (not HTTP/), so grab_banner can't
        name it. enrich_port must then try a TLS handshake + HEAD and label it
        'https' - which makes both _is_tls and _is_web fire. Uses a monkeypatched
        probe so the test needs no cert; the live handshake path is covered by the
        real-socket negative test below."""
        from recce.services import svcdetect as sd, probes
        from recce.services import web

        orig = sd.tls_http_probe
        sd.tls_http_probe = lambda ip, port, timeout=4.0: (
            "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n")
        try:
            port = Port(portid=9999, protocol="tcp", state="open", service="unknown")
            host = Host(ip="127.0.0.1", ports=[port])
            sd.enrich_host(host, active=True)
        finally:
            sd.tls_http_probe = orig
        self.assertEqual(port.service, "https")
        self.assertEqual(port.detect_source, "banner")
        self.assertEqual((port.product, port.version), ("nginx", "1.25.3"))
        self.assertTrue(web.is_web(port))
        self.assertTrue(probes._is_tls(port))          # scheme -> https
        self.assertEqual(web.scheme_for(port), "https")

    def test_tls_probe_does_not_misfire_on_plaintext(self):
        """tls_http_probe against a plaintext (non-TLS) service must return "" - the
        handshake fails, so we never mislabel a cleartext port as https."""
        import socket as _socket
        import threading
        from recce.services import svcdetect as sd

        srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port_no = srv.getsockname()[1]
        srv.listen(1)

        def serve_once():
            try:
                conn, _ = srv.accept()
                conn.recv(256)
                conn.sendall(b"HTTP/1.0 200 OK\r\n\r\n")   # cleartext, not TLS
                conn.close()
            except OSError:
                pass

        t = threading.Thread(target=serve_once, daemon=True)
        t.start()
        try:
            port = Port(portid=port_no, protocol="tcp", state="open", service="unknown")
            self.assertEqual(sd.tls_http_probe("127.0.0.1", port), "")
        finally:
            srv.close()
            t.join(timeout=2)

    def test_suggest_command_only_for_still_unknown(self):
        from recce.services import svcdetect as sd
        unknown = Port(portid=1234, service="unknown")
        self.assertIn("nmap -sV --version-all",
                      sd.suggest_id_command("1.1.1.1", unknown))
        named = Port(portid=1234, service="cdpsvc", detect_source="inferred")
        self.assertEqual(sd.suggest_id_command("1.1.1.1", named), "")

    def test_reprobe_upgrades_still_unknown_ports(self):
        from recce.services import svcdetect as sd
        host = Host(ip="10.0.0.7", ports=[
            Port(portid=8888, service="unknown", state="open"),
            Port(portid=5040, service="cdpsvc", detect_source="inferred", state="open"),
        ])
        self.assertEqual(sd.still_unknown_ports(host), [8888])
        # nmap's second-opinion parse now names 8888 concretely.
        parsed = [Host(ip="10.0.0.7", ports=[
            Port(portid=8888, service="http", product="nginx", version="1.25",
                 state="open")])]
        n = sd.apply_reprobe(host, parsed)
        self.assertEqual(n, 1)
        p = next(p for p in host.ports if p.portid == 8888)
        self.assertEqual((p.service, p.product, p.detect_source),
                         ("http", "nginx", "nmap"))
        # The inferred port nmap still can't name is left untouched.
        self.assertEqual(sd.still_unknown_ports(host), [])

    def test_reprobe_scanner_command_targets_only_leftover_ports(self):
        from recce.core import scanner
        seen = {}
        orig = scanner._run

        def fake_run(cmd, timeout=None):
            seen["cmd"] = cmd
            return scanner.RunOutcome(returncode=0)
        scanner._run = fake_run
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "rp.xml")
                scanner.reprobe_services("10.0.0.7", [8888, 3389], out,
                                         scanner.PROFILES["standard"])
        finally:
            scanner._run = orig
        cmd = seen["cmd"]
        self.assertIn("--version-all", cmd)
        self.assertIn("3389,8888", cmd)          # ports are sorted
        # Empty leftover list -> no scan (returns an empty XML, never shells out).
        seen.clear()
        with tempfile.TemporaryDirectory() as d:
            scanner.reprobe_services("10.0.0.7", [], os.path.join(d, "e.xml"),
                                     scanner.PROFILES["standard"])
        self.assertNotIn("cmd", seen)

    def test_parse_product_version_from_banners(self):
        from recce.services import svcdetect as sd
        cases = {
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3": ("OpenSSH", "8.9p1"),
            "220 (vsFTPd 3.0.3)": ("vsFTPd", "3.0.3"),
            "220 mail ESMTP Exim 4.94 Debian": ("Exim", "4.94"),
            "5.5.5-10.3.34-MariaDB-log": ("MariaDB", "10.3.34"),
            "Server: Apache/2.4.41 (Ubuntu)": ("Apache", "2.4.41"),
            "+OK Dovecot ready.": ("Dovecot", ""),
        }
        for banner, (prod, ver) in cases.items():
            got = sd.parse_product_version(banner)
            self.assertIsNotNone(got, banner)
            self.assertEqual(got[0], prod, banner)
            if ver:
                self.assertEqual(got[1], ver, banner)
        self.assertIsNone(sd.parse_product_version("just some noise"))

    def test_enrich_versions_fills_product_for_cve_mapping(self):
        from recce.services import svcdetect as sd
        # nmap named the service but left product blank; we hold its banner.
        host = Host(ip="10.0.0.8", ports=[
            Port(portid=22, service="ssh", detect_source="nmap", state="open",
                 banner="SSH-2.0-OpenSSH_7.4"),
            Port(portid=25, service="smtp", detect_source="nmap", state="open",
                 servicefp="220 relay ESMTP Postfix 3.4.14"),
        ])
        n = sd.enrich_versions(host)
        self.assertEqual(n, 2)
        p22 = next(p for p in host.ports if p.portid == 22)
        self.assertEqual((p22.product, p22.version), ("OpenSSH", "7.4"))
        p25 = next(p for p in host.ports if p.portid == 25)
        self.assertEqual(p25.product, "Postfix")

    def test_enrich_versions_never_overwrites_nmap_product(self):
        from recce.services import svcdetect as sd
        host = Host(ip="10.0.0.8", ports=[
            Port(portid=22, service="ssh", product="OpenSSH", version="9.6",
                 detect_source="nmap", state="open",
                 banner="SSH-2.0-OpenSSH_7.4")])   # stale banner must NOT win
        self.assertEqual(sd.enrich_versions(host), 0)
        self.assertEqual(host.ports[0].version, "9.6")

    def test_new_port_fields_round_trip_through_store(self):
        # servicefp / detect_source / banner must survive a datastore round-trip.
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "r.sqlite"))
            st.upsert_host(Host(ip="10.0.0.9", subnet="10.0.0.0/24",
                                ports=[Port(portid=5040, service="cdpsvc",
                                            detect_source="inferred",
                                            servicefp="fp", banner="b")]))
            back = st.get_host("10.0.0.9")
            st.close()
            p = back.ports[0]
            self.assertEqual((p.service, p.detect_source), ("cdpsvc", "inferred"))
            self.assertEqual((p.servicefp, p.banner), ("fp", "b"))
class MasscanParseTest(unittest.TestCase):
    def test_parse_sweep(self):
        xml = (
            '<?xml version="1.0"?><nmaprun>'
            '<host><address addr="10.0.0.5" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open"/></port>'
            '<port protocol="tcp" portid="443"><state state="open"/></port></ports></host>'
            '<host><address addr="10.0.0.6" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="3389"><state state="open"/></port></ports>'
            '</host></nmaprun>'
        )
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "m.xml")
            with open(p, "w") as fh:
                fh.write(xml)
            got = scanner.parse_masscan_sweep_xml(p)
        self.assertEqual(got["10.0.0.5"], [22, 443])
        self.assertEqual(got["10.0.0.6"], [3389])


class StoreTrackingTest(unittest.TestCase):
    def test_set_and_get(self):
        with tempfile.TemporaryDirectory() as d:
            store = Store(os.path.join(d, "t.sqlite"))
            store.set_reviewed("host:1.2.3.4", True, notes="checked")
            store.bulk_set_tracking({"svc:1.2.3.4:tcp:80": (True, "")})
            t = store.get_tracking()
            self.assertTrue(t["host:1.2.3.4"][0])
            self.assertEqual(t["host:1.2.3.4"][1], "checked")
            self.assertTrue(t["svc:1.2.3.4:tcp:80"][0])
            # Un-review preserves prior note when notes not passed.
            store.set_reviewed("host:1.2.3.4", False)
            self.assertEqual(store.get_tracking()["host:1.2.3.4"], (False, "checked"))
            store.close()


class PlaybookTest(unittest.TestCase):
    def test_host_level_finding_walkthrough_has_no_bogus_port(self):
        # A port-less (host-level) priv-esc finding must not render "nmap -p None".
        from recce.report.docx import group_findings, _walkthrough_steps
        h = Host(ip="10.0.20.5", os_family="Linux", vulns=[
            Vuln(ip="10.0.20.5", port=None, protocol="tcp", script_id="local-enum",
                 title="SUID GTFOBins escalation candidate", severity="high",
                 source="local", confidence="confirmed",
                 output="On-target enum: SUID /usr/bin/find - GTFOBins")])
        steps = " ".join(_walkthrough_steps(group_findings([h])[0]))
        self.assertNotIn("None", steps)
        self.assertNotIn("-p ,", steps)

    def test_port_less_finding_writeup_has_no_none(self):
        # The whole rendered write-up (Affected systems / Evidence / walkthrough)
        # must never show "ip:None" for a host-level finding.
        import zipfile
        from recce.report.docx import build_writeups
        h = Host(ip="10.0.20.5", os_family="Linux", vulns=[
            Vuln(ip="10.0.20.5", port=None, protocol="tcp", script_id="local-enum",
                 title="Sudo misconfiguration -> root", severity="high",
                 source="local", confidence="confirmed",
                 output="On-target enum: NOPASSWD sudo entries present")])
        with tempfile.TemporaryDirectory() as d:
            build_writeups([h], d, min_severity="low")
            import glob
            docs = glob.glob(os.path.join(d, "*.docx"))
            self.assertTrue(docs)
            for f in docs:
                t = zipfile.ZipFile(f).read("word/document.xml").decode("utf-8", "replace")
                self.assertNotIn(":None", t)
                self.assertNotIn("-p None", t)

    def test_windows_seimpersonate_maps_to_potato(self):
        from recce.act import playbook
        e = playbook.for_text("Token holds SeImpersonate -> SYSTEM", "Windows")
        self.assertIsNotNone(e)
        self.assertIn("GodPotato", e["tool"])
        self.assertIn("whoami", e["cmd"].lower())
        self.assertIn("SYSTEM", e["validate"])

    def test_finding_values_are_substituted_into_command(self):
        from recce.act import playbook
        # the SUID binary path from the finding is filled into the command
        e = playbook.for_text("SUID /usr/bin/find - GTFOBins escalation candidate",
                              "Linux")
        self.assertIn("/usr/bin/find", e["cmd"])
        # unquoted service path is extracted too
        e2 = playbook.for_text(
            r"Unquoted service path with a writable parent: C:\Program Files\X\s.exe",
            "Windows")
        self.assertIn(r"C:\Program Files\X\s.exe", e2["cmd"])

    def test_no_match_returns_none(self):
        from recce.act import playbook
        self.assertIsNone(playbook.for_text("some benign http banner", "Linux"))
        self.assertIsNone(playbook.for_text("", ""))

    def test_confirmed_only_advisories_excluded(self):
        # A 'potential' advisory vuln must NOT get an exploitation entry, even if
        # its text would otherwise match.
        from recce.act import playbook
        h = Host(ip="10.0.0.5", os_family="Windows", vulns=[
            Vuln(ip="10.0.0.5", port=445, protocol="tcp", script_id="adv",
                 title="SeImpersonate advisory", severity="high",
                 source="version-db", confidence="potential")])
        self.assertEqual(playbook.host_entries(h), [])
        h.vulns[0].confidence = "confirmed"
        self.assertEqual(len(playbook.host_entries(h)), 1)

    def test_linux_writable_service_unit_does_not_get_windows_command(self):
        # OS-distinct matching: a Linux systemd 'writable service unit' finding
        # must not resolve to the Windows sc-config play.
        from recce.act import playbook
        e = playbook.for_text("Writable service unit: /etc/systemd/system/x.service",
                              "Linux")
        if e is not None:
            self.assertNotIn("sc config", e["cmd"].lower())


class ExploitRefTest(unittest.TestCase):
    def test_cve_exact_match(self):
        from recce.vuln.exploitref import proven_exploit_ref
        ref = proven_exploit_ref(["CVE-2017-0144"])
        self.assertIsNotNone(ref)
        self.assertIn("eternalblue", ref.lower())

    def test_no_match_returns_none(self):
        from recce.vuln.exploitref import proven_exploit_ref
        self.assertIsNone(proven_exploit_ref(["CVE-1999-0001"]))
        self.assertIsNone(proven_exploit_ref(None))
        self.assertIsNone(proven_exploit_ref([], ""))

    def test_cve_embedded_in_nse_id_text(self):
        # A raw NSE finding carrying the CVE only in its id must resolve the same.
        from recce.vuln.exploitref import proven_exploit_ref
        ref = proven_exploit_ref([], "http-vuln-cve2021-41773")
        self.assertIsNotNone(ref)
        self.assertIn("apache", ref.lower())

    def test_keyword_fallback_when_no_cve(self):
        from recce.vuln.exploitref import proven_exploit_ref
        self.assertIn("ms17_010",
                      (proven_exploit_ref([], "SMB ms17-010 vulnerable") or "").lower())
        self.assertIn("vsftpd",
                      (proven_exploit_ref([], "vsftpd 2.3.4 backdoor") or "").lower())

    def test_explicit_cve_beats_text(self):
        from recce.vuln.exploitref import proven_exploit_ref
        # A known CVE in the list wins even if the text mentions nothing.
        self.assertEqual(proven_exploit_ref(["CVE-2014-0160"]),
                         proven_exploit_ref([], "heartbleed"))

    def test_windows_references_resolve(self):
        from recce.vuln.exploitref import proven_exploit_ref
        cases = [
            (["CVE-2008-4250"], "ms08_067"),      # MS08-067
            (["CVE-2017-0147"], "eternalblue"),   # EternalBlue variant CVE
            (["CVE-2020-1472"], "zerologon"),     # ZeroLogon (module + PoC)
            (["CVE-2020-0796"], "smbghost"),      # SMBGhost
            (["CVE-2014-6324"], "ms14-068"),      # Kerberos PAC
        ]
        for cves, needle in cases:
            self.assertIn(needle, (proven_exploit_ref(cves) or "").lower(), cves)

    def test_token_privilege_maps_to_potato_tools(self):
        # A confirmed SeImpersonate finding (no CVE) points at the existing Potato
        # tools - a reference, not generated code.
        from recce.vuln.exploitref import proven_exploit_ref
        ref = proven_exploit_ref([], "Token holds SeImpersonate -> Potato -> SYSTEM")
        self.assertIsNotNone(ref)
        self.assertIn("godpotato", ref.lower())
        self.assertIn("printspoofer", ref.lower())

    def test_keyword_table_values_are_real_exploit_entries(self):
        # Integrity: every keyword ref must be a real curated reference - either a
        # concrete CVE entry, or the (CVE-less) token-privilege Potato reference.
        # Catches a typo'd/dangling keyword value.
        from recce.vuln.exploitref import PROVEN_EXPLOIT, PROVEN_KW, _POTATO
        allowed = set(PROVEN_EXPLOIT.values()) | {_POTATO}
        self.assertTrue(set(PROVEN_KW.values()) <= allowed)
        self.assertTrue(all(v.strip() for v in PROVEN_KW.values()))


class DeployTest(unittest.TestCase):
    def _host(self, ip, os_, ports):
        return Host(ip=ip, os_family=os_,
                    ports=[Port(portid=p, state="open") for p in ports])

    def test_transport_selection(self):
        from recce.creds import deploy
        ssh = {"username": "u", "password": "p"}
        win = {"username": "a", "password": "b"}
        self.assertEqual(deploy.transport_for(self._host("1", "Linux", [22, 80]), ssh, win), "ssh")
        self.assertEqual(deploy.transport_for(self._host("2", "Windows", [445, 5985]), ssh, win), "winrm")
        self.assertEqual(deploy.transport_for(self._host("3", "Windows", [445]), ssh, win), "smb")
        # Windows box but we only have SSH creds and it runs sshd -> ssh
        self.assertEqual(deploy.transport_for(self._host("4", "Windows", [22, 445]), ssh, None), "ssh")
        self.assertIsNone(deploy.transport_for(self._host("5", "Linux", [80]), ssh, win))   # no exec port
        self.assertIsNone(deploy.transport_for(self._host("6", "Linux", [22]), None, None))  # no creds

    def test_skip_reason_explains_why_a_host_is_unable(self):
        from recce.creds import deploy
        ssh = {"username": "u", "password": "p"}
        win = {"username": "a", "password": "b"}
        # No remote-exec port at all.
        self.assertIn("no remote-exec port",
                      deploy.skip_reason(self._host("1", "Linux", [80]), ssh, win))
        # SSH port open but no SSH creds held.
        self.assertIn("SSH creds",
                      deploy.skip_reason(self._host("2", "Linux", [22]), None, win))
        # SMB/WinRM open but no Windows creds held.
        self.assertIn("Windows creds",
                      deploy.skip_reason(self._host("3", "Windows", [445]), ssh, None))
        # nxc precheck said none of the protocols authenticated on this host.
        amap = {"4": {"smb": False, "winrm": False, "ssh": False}}
        self.assertIn("did not authenticate",
                      deploy.skip_reason(self._host("4", "Windows", [445, 5985]),
                                         ssh, win, amap))

    def test_domain_qualified_username_is_split(self):
        from recce import cli

        class A:
            def __init__(self, u, d=None, p="Pw"):
                self.username, self.domain, self.password = u, d, p
        # NetBIOS backslash form.
        c = cli._creds_of(A("CORP\\administrator"))
        self.assertEqual((c["username"], c["domain"]), ("administrator", "CORP"))
        # UPN @ form.
        c = cli._creds_of(A("administrator@corp.local"))
        self.assertEqual((c["username"], c["domain"]), ("administrator", "corp.local"))
        # domain/user form.
        c = cli._creds_of(A("corp.local/svc"))
        self.assertEqual((c["username"], c["domain"]), ("svc", "corp.local"))
        # Explicit -d wins over an embedded NetBIOS domain.
        c = cli._creds_of(A("CORP\\administrator", d="corp.local"))
        self.assertEqual((c["username"], c["domain"]), ("administrator", "corp.local"))
        # Plain username, explicit domain - unchanged.
        c = cli._creds_of(A("administrator", d="corp.local"))
        self.assertEqual((c["username"], c["domain"]), ("administrator", "corp.local"))
        # Plain username, no domain.
        c = cli._creds_of(A("administrator"))
        self.assertEqual((c["username"], c["domain"]), ("administrator", ""))

    def test_ps_payload_is_utf16le_base64(self):
        import base64
        from recce.creds import deploy
        b = deploy._b64_ps("Write-Host hi")
        self.assertEqual(base64.b64decode(b).decode("utf-16-le"), "Write-Host hi")

    def test_ssh_key_auth_pipes_script_no_disk_artifact(self):
        from recce.creds import deploy
        calls = {}

        def fake_run(argv, timeout, stdin=None, env=None, new_session=False):
            calls["argv"], calls["stdin"] = argv, stdin
            return 0, "recce-enum host=x\n[!] finding", ""
        orig = deploy._run
        deploy._run = fake_run
        try:
            out, err = deploy.run_ssh("1.2.3.4", {"username": "u", "key": "/k"}, "SCRIPT", 60)
        finally:
            deploy._run = orig
        self.assertIsNone(err)
        self.assertEqual(calls["stdin"], "SCRIPT")            # script piped over stdin
        self.assertIn("bash -s -- -q", calls["argv"])         # not written to disk
        self.assertNotEqual(calls["argv"][0], "sshpass")      # key auth, no sshpass
        self.assertIn("/k", calls["argv"])

    def test_winrm_and_smb_run_encoded_powershell(self):
        from recce.creds import deploy
        seen = {}

        def fake_run(argv, timeout, stdin=None, env=None, new_session=False):
            seen.setdefault("argvs", []).append(argv)
            return 0, "recce-enum host=x\n[!] x", ""
        o_run, o_tool = deploy._run, deploy.smb_tool
        deploy._run, deploy.smb_tool = fake_run, (lambda: "nxc")
        try:
            _, e1 = deploy.run_winrm("1.2.3.4", {"username": "a", "password": "b"}, "S", 60)
            _, e2 = deploy.run_smb("1.2.3.4", {"username": "a", "password": "b"}, "/tmp/x.ps1", 60)
        finally:
            deploy._run, deploy.smb_tool = o_run, o_tool
        self.assertIsNone(e1)
        winrm = seen["argvs"][0]
        self.assertIn("winrm", winrm)
        self.assertIn("EncodedCommand", " ".join(winrm))
        self.assertIn("--put-file", " ".join(seen["argvs"][1]))   # smb pushes the script

    def test_deploy_dry_run_executes_nothing(self):
        from recce import cli
        from recce.creds import deploy
        called = {"n": 0}
        orig = deploy.deploy_one
        deploy.deploy_one = lambda *a, **k: (called.__setitem__("n", called["n"] + 1)
                                             or ("ssh", "x", None))
        try:
            with tempfile.TemporaryDirectory() as d:
                paths = cli._open_paths(d)
                st = cli._open_store(paths["db"])
                st.upsert_host(self._host("10.0.0.5", "Linux", [22]))
                st.close()
                args = SimpleNamespace(output_dir=d, workers=2, title="t", dry_run=True,
                                       ssh_user="u", ssh_pass=None, ssh_key="/k",
                                       username=None, password=None, domain=None,
                                       hash=None, targets=[], host=None)
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = cli.cmd_deploy(args)
                self.assertEqual(rc, 0)
                self.assertEqual(called["n"], 0)   # dry-run ran nothing on the target
        finally:
            deploy.deploy_one = orig

    def test_stager_serves_script_under_token_only(self):
        import urllib.request
        import urllib.error
        from recce.creds.stager import Stager
        data = b"# recce-enum.ps1"
        with Stager("127.0.0.1", {"recce-enum.ps1": data}) as st:
            got = urllib.request.urlopen(st.url("recce-enum.ps1"), timeout=5).read()
            self.assertEqual(got, data)
            self.assertEqual(st.hits, 1)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{st.port}/wrong/recce-enum.ps1", timeout=5)
            self.assertEqual(cm.exception.code, 404)

    def test_nxc_auth_parse_and_authmap_selection(self):
        from recce.creds import deploy
        rows = deploy._parse_nxc_auth(
            "SMB   10.0.0.1  445  DC  [+] d\\a:p (Pwn3d!)\n"
            "SMB   10.0.0.2  445  WS  [-] d\\a:p STATUS_LOGON_FAILURE")
        self.assertEqual(rows, [("10.0.0.1", True, True), ("10.0.0.2", False, False)])
        ssh = {"username": "u", "password": "p"}
        win = {"username": "a", "password": "b"}
        amap = {"1": {"winrm": True}, "2": {"winrm": False, "smb": True},
                "3": {"ssh": True}, "4": {"winrm": False, "smb": False}}
        self.assertEqual(deploy.transport_for(self._host("1", "Windows", [445, 5985]), ssh, win, amap), "winrm")
        self.assertEqual(deploy.transport_for(self._host("2", "Windows", [445, 5985]), ssh, win, amap), "smb")
        self.assertEqual(deploy.transport_for(self._host("3", "Linux", [22]), ssh, win, amap), "ssh")
        self.assertIsNone(deploy.transport_for(self._host("4", "Windows", [445]), ssh, win, amap))

    def test_rejected_winrm_login_not_folded_as_success(self):
        """A rejected nxc WinRM login is a bare '[-]' banner with no STATUS keyword
        and no script output - it must be reported as a failure, never folded as a
        successful run with garbage loot."""
        from recce.creds import deploy
        o_run, o_smb = deploy._run, deploy.smb_tool
        deploy.smb_tool = lambda: "nxc"
        deploy._run = lambda argv, timeout, stdin=None: (
            0, "WINRM 10.0.0.5 5985 HOST [-] corp\\u:BadPw", "")
        try:
            out, err = deploy.run_winrm("10.0.0.5", {"username": "u", "password": "x"},
                                        "SCRIPT", 60)
        finally:
            deploy._run, deploy.smb_tool = o_run, o_smb
        self.assertIsNone(out)                          # not a success
        self.assertIn("auth", err.lower())

    def test_exploit_cell_needs_cve_match_not_just_port(self):
        from recce.report.excel import _exploit_cell, _curated_exploit
        from recce.core.models import Exploit
        host = Host(ip="1.1.1.1", exploits=[
            Exploit(ip="1.1.1.1", port=80, edb_id="99999", cves=["CVE-2099-9999"])])
        # unrelated port-80 finding, no shared CVE -> NO exploit attached (was the bug)
        risky = Vuln(ip="1.1.1.1", port=80, protocol="tcp", script_id="http-methods",
                     title="Risky HTTP methods enabled", severity="low", confidence="likely")
        self.assertEqual(_exploit_cell(host, risky), "")
        # a finding sharing the EDB's CVE -> a clearly-labelled CANDIDATE, not proof
        match = Vuln(ip="1.1.1.1", port=80, protocol="tcp", script_id="x", title="Some RCE",
                     severity="high", confidence="likely", ids=["CVE-2099-9999"])
        cell = _exploit_cell(host, match)
        self.assertIn("EDB-99999", cell)
        self.assertIn("candidate", cell.lower())
        # a weak-TLS finding never claims a proven exploit, even with heartbleed's CVE
        tls = Vuln(ip="1.1.1.1", port=443, protocol="tcp", script_id="ssl-enum-ciphers",
                   title="Weak SSL/TLS ciphers or protocols", severity="medium",
                   confidence="likely", ids=["CVE-2014-0160"])
        self.assertEqual(_curated_exploit(tls), "")

    def test_impacket_engine_runs_stager_cradle_when_no_nxc(self):
        """With netexec absent but impacket present, the Windows path uses
        impacket wmiexec (which pairs cleanly with --stager: runs the cradle, no
        file push)."""
        from recce.creds import deploy
        seen = []

        def fake_run(argv, timeout, stdin=None, env=None, new_session=False):
            seen.append(argv[0])
            return 0, "recce-enum host=x\n[!] finding", ""

        class FS:
            def url(self, n):
                return f"http://1.2.3.4:8000/t/{n}"
        o_run, o_smb, o_imp = deploy._run, deploy.smb_tool, deploy.impacket_tool
        deploy._run = fake_run
        deploy.smb_tool = lambda: None                                  # no nxc
        deploy.impacket_tool = lambda n: "impacket-wmiexec" if n == "wmiexec" else None
        try:
            self.assertEqual(deploy.win_engine(), ("impacket", "impacket-wmiexec"))
            out, err, status = deploy.run_win_stager(
                "10.0.0.9", {"username": "a", "password": "b", "domain": "d"},
                "smb", FS(), 60)
            self.assertEqual(status, "ok")
            self.assertEqual(seen[0], "impacket-wmiexec")
            self.assertEqual(deploy._impacket_target({"username": "a", "hash": "NT"}, "1.2.3.4"),
                             "a@1.2.3.4")
        finally:
            deploy._run, deploy.smb_tool, deploy.impacket_tool = o_run, o_smb, o_imp

    def test_stager_unreachable_falls_back_to_push(self):
        from recce.creds import deploy
        win = {"username": "a", "password": "b"}
        seen = []

        def fake_run(argv, timeout, stdin=None, env=None, new_session=False):
            joined = " ".join(argv)
            if "EncodedCommand" in joined:            # the stager cradle
                seen.append("stager")
                return 0, "PowerShell WebException: unable to connect", ""
            if "--put-file" in joined:                # the push fallback
                seen.append("put")
                return 0, "", ""
            return 0, "recce-enum host=x\n[!] finding", ""   # push exec

        class FakeStager:
            def url(self, n):
                return f"http://1.2.3.4:8000/tok/{n}"
        o_run, o_tool = deploy._run, deploy.smb_tool
        deploy._run, deploy.smb_tool = fake_run, (lambda: "nxc")
        try:
            t, out, err = deploy.deploy_one(
                self._host("10.0.0.9", "Windows", [445]), None, win,
                stager=FakeStager(), authmap={"10.0.0.9": {"smb": True}})
        finally:
            deploy._run, deploy.smb_tool = o_run, o_tool
        self.assertIn("stager", seen)                 # tried the stager first
        self.assertIn("put", seen)                    # then fell back to push
        self.assertTrue(out and "recce-enum" in out)  # and got output

    def test_deploy_worker_folds_recce_enum_output(self):
        from recce import cli
        from recce.creds import deploy
        sample = ("recce-enum host=web01 os=linux\n"
                  "[!] sudo: NOPASSWD entry - run a root command via sudo\n")
        orig = deploy.deploy_one
        deploy.deploy_one = lambda host, s, w, timeout, stager=None, authmap=None: (
            "ssh", sample, None)
        try:
            with tempfile.TemporaryDirectory() as d:
                host, transport, added, promoted, err = cli._deploy_worker(
                    self._host("10.0.0.5", "Linux", [22]), {"username": "u"}, None, 60, d)
                self.assertIsNone(err)
                self.assertEqual(transport, "ssh")
                self.assertGreaterEqual(added, 1)              # finding folded in
                self.assertTrue(host.local_findings)
                self.assertTrue(host.privesc_checked)
                self.assertTrue(os.path.exists(os.path.join(d, "10.0.0.5.txt")))  # loot saved
        finally:
            deploy.deploy_one = orig


class SnmpTest(unittest.TestCase):
    """Deep SNMP module: BER/OID round-trip, a mock UDP agent (community brute +
    GETNEXT walk), findings, account harvesting, prove verdicts, `recce snmp`."""

    @classmethod
    def setUpClass(cls):
        import socket
        import threading
        from recce.services import snmp as S

        # MIB: exact-match GETs + a couple of walkable subtrees. Values are the
        # already-BER-encoded value bytes (what sits after the OID in a varbind).
        cls.mib = {
            "1.3.6.1.2.1.1.1.0": S._octet("Windows Server 2019 x64"),   # sysDescr
            "1.3.6.1.2.1.1.5.0": S._octet("DC01"),                       # sysName
            "1.3.6.1.4.1.77.1.2.25.1": S._octet("Administrator"),        # LanMgr users
            "1.3.6.1.4.1.77.1.2.25.2": S._octet("Guest"),
            "1.3.6.1.4.1.77.1.2.25.3": S._octet("svc_backup"),
            "1.3.6.1.2.1.25.4.2.1.2.1": S._octet("services.exe"),        # a process
        }
        cls._sorted = sorted(cls.mib, key=lambda o: [int(x) for x in o.split(".")])

        def _tuple(o):
            return [int(x) for x in o.split(".")]

        def _get_response(community, rid, oid, value_bytes):
            varbind = S._tlv(0x30, S.encode_oid(oid) + value_bytes)
            pdu = S._tlv(0xA2, S._int(rid) + S._int(0) + S._int(0)
                         + S._tlv(0x30, varbind))
            return S._tlv(0x30, S._int(1) + S._octet(community) + pdu)

        def _parse_request(data):
            _, msg, _ = S._parse_tlv(data, 0)
            _, _ver, i = S._parse_tlv(msg, 0)
            _, comm, i = S._parse_tlv(msg, i)
            pdu_tag, pdu, _ = S._parse_tlv(msg, i)
            _, rid_b, j = S._parse_tlv(pdu, 0)
            rid = int.from_bytes(rid_b, "big")
            _, _err, j = S._parse_tlv(pdu, j)
            _, _eidx, j = S._parse_tlv(pdu, j)
            _, vbs, _ = S._parse_tlv(pdu, j)
            _, vb, _ = S._parse_tlv(vbs, 0)
            _, oid_b, _ = S._parse_tlv(vb, 0)
            return comm.decode(), rid, pdu_tag, S.decode_oid(oid_b)

        END_OF_MIB = b"\x82\x00"                   # endOfMibView -> walk stops

        def _answer(community, rid, pdu_tag, oid):
            if community != "public":               # only this community answers
                return None
            if pdu_tag == 0xA0:                      # GetRequest (exact)
                val = cls.mib.get(oid)
                return _get_response(community, rid, oid,
                                     val if val is not None else END_OF_MIB)
            # GetNextRequest: the numerically-next OID in the MIB.
            want = _tuple(oid)
            for cand in cls._sorted:
                if _tuple(cand) > want:
                    return _get_response(community, rid, cand, cls.mib[cand])
            return _get_response(community, rid, oid, END_OF_MIB)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        cls.port = sock.getsockname()[1]
        cls.sock = sock
        cls._stop = False

        def serve():
            while not cls._stop:
                try:
                    sock.settimeout(0.3)
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    comm, rid, tag, oid = _parse_request(data)
                    resp = _answer(comm, rid, tag, oid)
                    if resp is not None:
                        sock.sendto(resp, addr)
                except (IndexError, ValueError):
                    pass

        cls._thread = threading.Thread(target=serve, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls):
        cls._stop = True
        cls._thread.join(timeout=2)
        cls.sock.close()

    def test_ber_and_oid_roundtrip(self):
        from recce.services import snmp as S
        for oid in ("1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.77.1.2.25.3",
                    "1.3.6.1.2.1.25.4.2.1.2.1"):
            _tag, body, _ = S._parse_tlv(S.encode_oid(oid), 0)
            self.assertEqual(S.decode_oid(body), oid)
        # A well-formed GetResponse parses back to (error_status, [(oid, value)]).
        err, vbs = S.parse_response(_self_response())
        self.assertEqual(err, 0)
        self.assertEqual(vbs, [("1.3.6.1.2.1.1.1.0", "x")])

    def test_probe_brutes_community_and_walks(self):
        from recce.services import snmp as S
        pr = S.probe("127.0.0.1", self.port, timeout=1.0, known_open=True)
        self.assertIsNotNone(pr)
        self.assertEqual(pr["community"], "public")
        self.assertEqual(pr["sys_descr"], "Windows Server 2019 x64")
        self.assertEqual(pr["sys_name"], "DC01")
        self.assertEqual(pr["users"], ["Administrator", "Guest", "svc_backup"])
        self.assertEqual(pr["processes"], ["services.exe"])

    def test_findings_accounts_and_prove(self):
        from recce.services import snmp as S
        from recce.vuln import proofs
        pr = S.probe("127.0.0.1", self.port, timeout=1.0, known_open=True)
        h = Host(ip="127.0.0.1", ports=[Port(portid=161, service="snmp", state="open")])
        fs = S.findings([h], {("127.0.0.1", 161): pr})
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("guessable community string", titles)
        self.assertIn("local user accounts", titles)
        self.assertIn("process / software inventory", titles)
        # Enumerated users become Account rows.
        accts = S.accounts_from_probe("127.0.0.1", pr)
        names = {a.name for a in accts}
        self.assertEqual(names, {"Administrator", "Guest", "svc_backup"})
        self.assertTrue(all(a.source == "snmp" for a in accts))
        # Prove engine CONFIRMs the community exposure (directly observed).
        h.vulns = S.findings_to_vulns(fs)["127.0.0.1"]
        verdicts = [r["verdict"] for r in proofs.verify_host(h)]
        self.assertIn(proofs.CONFIRMED, verdicts)

    def test_cmd_snmp_end_to_end(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services import snmp as S
        from recce.core.store import Store
        orig_targets, orig_is = S.snmp_targets, S.is_snmp
        # Point the single target at the mock agent's ephemeral port, and teach is_snmp
        # to recognise that port so findings() matches the probe.
        S.snmp_targets = lambda hosts: [{"ip": "127.0.0.1", "hostname": "",
                                         "port": self.port, "known_open": True}]
        S.is_snmp = lambda p: p.portid == self.port or orig_is(p)
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=self.port, state="open",
                                                service="snmp")]))
                st.close()
                rc = cli.main(["snmp", "-o", out])
                self.assertEqual(rc, 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("SNMP", sheets)
                st = Store(os.path.join(out, "results.sqlite"))
                h = st.get_host("127.0.0.1")
                st.close()
                self.assertTrue([v for v in h.vulns if v.source == "snmp"])
                # Enumerated accounts persisted onto the host.
                self.assertTrue([a for a in h.accounts if a.source == "snmp"])
        finally:
            S.snmp_targets, S.is_snmp = orig_targets, orig_is

    def test_no_answer_is_graceful(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.8", ports=[Port(portid=22, service="ssh")]))
            st.close()
            self.assertEqual(cli.main(["snmp", "-o", out, "--no-probe"]), 0)


def _self_response():
    """Tiny well-formed GetResponse so a bare parse_response smoke-check has input."""
    from recce.services import snmp as S
    varbind = S._tlv(0x30, S.encode_oid("1.3.6.1.2.1.1.1.0") + S._octet("x"))
    pdu = S._tlv(0xA2, S._int(1) + S._int(0) + S._int(0) + S._tlv(0x30, varbind))
    return S._tlv(0x30, S._int(1) + S._octet("public") + pdu)
class RsyncTest(unittest.TestCase):
    """Deep rsync module: a mock rsync daemon (@RSYNCD greeting, #list, per-module
    OK/AUTHREQD), anonymous-access detection, findings, prove, `recce rsync`."""

    @classmethod
    def setUpClass(cls):
        import socketserver
        import threading

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.settimeout(3.0)
                sock.sendall(b"@RSYNCD: 31.0\n")
                # Read the client's version echo + the request line.
                buf = b""
                while buf.count(b"\n") < 2:
                    try:
                        c = sock.recv(256)
                    except OSError:
                        return
                    if not c:
                        return
                    buf += c
                lines = buf.decode().split("\n")
                req = lines[1] if len(lines) > 1 else ""
                if req == "#list":
                    sock.sendall(b"backups\tnightly server backups\n")
                    sock.sendall(b"public\tanonymous share\n")
                    sock.sendall(b"secret\trestricted\n")
                    sock.sendall(b"@RSYNCD: EXIT\n")
                elif req == "secret":
                    sock.sendall(b"@RSYNCD: AUTHREQD abcdef\n")
                else:                                   # backups / public: anonymous OK
                    sock.sendall(b"@RSYNCD: OK\n")

        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_list_and_access(self):
        from recce.services import rsync as R
        pr = R.list_modules("127.0.0.1", self.port, timeout=3.0)
        self.assertTrue(pr["reachable"])
        self.assertEqual([m["name"] for m in pr["modules"]],
                         ["backups", "public", "secret"])
        self.assertEqual(R.probe_module("127.0.0.1", self.port, "backups", 3.0), "open")
        self.assertEqual(R.probe_module("127.0.0.1", self.port, "secret", 3.0), "auth")

    def test_findings_and_prove(self):
        from recce.services import rsync as R
        from recce.vuln import proofs
        analysis = R.analyze([Host(ip="127.0.0.1",
                                   ports=[Port(portid=self.port, state="open",
                                               service="rsync")])], active=True)
        # is_rsync gates on port 873; drive findings directly off the probe instead.
        pr = {("10.0.8.8", 873): R.list_modules("127.0.0.1", self.port, 3.0)}
        for m in pr[("10.0.8.8", 873)]["modules"]:
            m["access"] = R.probe_module("127.0.0.1", self.port, m["name"], 3.0)
        h = Host(ip="10.0.8.8", ports=[Port(portid=873, service="rsync", state="open")])
        fs = R.findings([h], pr)
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("rsync module readable without authentication", titles)
        self.assertIn("rsync modules enumerable", titles)
        h.vulns = R.findings_to_vulns(fs)["10.0.8.8"]
        self.assertIn(proofs.CONFIRMED, [r["verdict"] for r in proofs.verify_host(h)])

    def test_cmd_rsync_end_to_end(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services import rsync as R
        from recce.core.store import Store
        orig = R.is_rsync
        R.is_rsync = lambda p: p.state == "open" and (p.portid == self.port or orig(p))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=self.port, state="open",
                                                service="rsync")]))
                st.close()
                self.assertEqual(cli.main(["rsync", "-o", out]), 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("rsync", sheets)
                vtxt = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
                self.assertIn("rsync", vtxt)
        finally:
            R.is_rsync = orig


class NfsTest(unittest.TestCase):
    """Deep NFS module: a mock ONC RPC server (portmapper DUMP + mountd EXPORT over
    record marking), world-export detection, findings, prove, `recce nfs`."""

    @classmethod
    def setUpClass(cls):
        import socketserver
        import struct
        import threading
        from recce.services import nfs as N

        def xstr(s):
            b = s.encode()
            return struct.pack(">I", len(b)) + b + b"\x00" * ((4 - len(b) % 4) % 4)

        def reply(xid, results):
            body = (struct.pack(">III", xid, 1, 0)      # xid, REPLY, MSG_ACCEPTED
                    + struct.pack(">II", 0, 0)          # verf AUTH_NULL
                    + struct.pack(">I", 0)              # accept_stat SUCCESS
                    + results)
            return struct.pack(">I", 0x80000000 | len(body)) + body

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.settimeout(3.0)
                rec = N._recv_record(sock, 3.0)
                if rec is None:
                    return
                xid, mtype, rpcvers, prog, vers, proc = struct.unpack_from(">IIIIII", rec, 0)
                myport = self.server.server_address[1]
                if prog == N._PMAP_PROG and proc == 4:          # portmap DUMP
                    res = b""
                    for pr, ve, po in ((N._MOUNT_PROG, 3, myport),
                                       (N._NFS_PROG, 3, 2049)):
                        res += struct.pack(">IIIII", 1, pr, ve, N._IPPROTO_TCP, po)
                    res += struct.pack(">I", 0)
                    sock.sendall(reply(xid, res))
                elif prog == N._MOUNT_PROG and proc == 5:       # mountd EXPORT
                    res = b""
                    res += struct.pack(">I", 1) + xstr("/srv/backups") \
                        + struct.pack(">I", 1) + xstr("*") + struct.pack(">I", 0)
                    res += struct.pack(">I", 1) + xstr("/home") \
                        + struct.pack(">I", 1) + xstr("10.0.0.0/24") + struct.pack(">I", 0)
                    res += struct.pack(">I", 0)
                    sock.sendall(reply(xid, res))
                else:
                    sock.sendall(reply(xid, b""))

        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_probe_lists_exports(self):
        from recce.services import nfs as N
        pr = N.probe("127.0.0.1", timeout=3.0, pmport=self.port)
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["nfs"])
        dirs = [e["dir"] for e in pr["exports"]]
        self.assertEqual(dirs, ["/srv/backups", "/home"])
        self.assertTrue(N._is_world(pr["exports"][0]["groups"]))     # '*'
        self.assertFalse(N._is_world(pr["exports"][1]["groups"]))    # subnet

    def test_is_world_scoped_wildcard_not_world(self):
        # Regression (audit): a scoped wildcard is a domain restriction, NOT everyone.
        from recce.services import nfs as N
        self.assertTrue(N._is_world([]))                             # no restriction
        self.assertTrue(N._is_world(["*"]))                          # bare wildcard
        self.assertTrue(N._is_world(["(everyone)"]))
        self.assertFalse(N._is_world(["*.corp.example.com"]))        # domain-scoped
        self.assertFalse(N._is_world(["10.0.0.0/8"]))

    def test_recv_record_bounds_hostile_fragments(self):
        # Regression (audit): a never-last fragment stream must terminate, not hang.
        from recce.services import nfs as N
        import io
        class _FakeSock:
            def __init__(self):
                self.n = 0
            def settimeout(self, t):
                pass
            def recv(self, n):
                # Always a non-last 4-byte fragment header + 4 bytes of body.
                self.n += 1
                return b"\x00\x00\x00\x04" if self.n % 2 else b"AAAA"
        self.assertIsNone(N._recv_record(_FakeSock(), 1.0))          # bounded -> None

    def test_findings_and_prove(self):
        from recce.services import nfs as N
        from recce.vuln import proofs
        pr = {"10.0.8.9": N.probe("127.0.0.1", timeout=3.0, pmport=self.port)}
        h = Host(ip="10.0.8.9", ports=[Port(portid=2049, service="nfs", state="open"),
                                       Port(portid=111, service="rpcbind", state="open")])
        fs = N.findings([h], pr)
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("NFS export shared to any host", titles)
        self.assertIn("NFS exports enumerable", titles)
        h.vulns = N.findings_to_vulns(fs)["10.0.8.9"]
        self.assertIn(proofs.CONFIRMED, [r["verdict"] for r in proofs.verify_host(h)])

    def test_rpc_reply_framing(self):
        from recce.services import nfs as N
        import struct
        body = struct.pack(">III", 0x1003, 1, 0) + struct.pack(">II", 0, 0) \
            + struct.pack(">I", 0) + b"payload!!"
        self.assertEqual(N._parse_reply(body, 0x1003), b"payload!!")
        self.assertIsNone(N._parse_reply(body, 0x9999))          # wrong xid
class SvcProbeTest(unittest.TestCase):
    """The shared sequential-probe driver: wall-clock budget, per-target progress,
    and clean partial results on Ctrl-C."""

    def test_budget_stops_early_with_partial(self):
        import time
        from recce.services import svcprobe as S
        targets = [{"ip": f"10.0.0.{i}"} for i in range(20)]
        st = {}
        got = [r for _, r in S.iter_probe(
            targets, lambda t: (time.sleep(0.03) or t["ip"]),
            budget=0.1, state=st)]
        self.assertEqual(st["stopped"], "budget")
        self.assertLess(len(got), 20)                    # stopped early
        self.assertEqual(st["done"], len(got))           # bookkeeping matches

    def test_keyboardinterrupt_yields_partial(self):
        from recce.services import svcprobe as S
        targets = [{"ip": f"10.0.0.{i}"} for i in range(10)]

        def probe(t):
            if t["ip"] == "10.0.0.4":
                raise KeyboardInterrupt
            return t["ip"]
        st = {}
        got = [r for _, r in S.iter_probe(targets, probe, state=st)]
        self.assertEqual(st["stopped"], "interrupt")
        self.assertEqual(got, [f"10.0.0.{i}" for i in range(4)])   # 4 completed

    def test_progress_fires_and_completes(self):
        from recce.services import svcprobe as S
        targets = [{"ip": f"10.0.0.{i}"} for i in range(5)]
        seen = []
        st = {}
        out = [r for _, r in S.iter_probe(
            targets, lambda t: t["ip"],
            progress=lambda i, n, t: seen.append((i, n)), state=st)]
        self.assertEqual(out, [f"10.0.0.{i}" for i in range(5)])
        self.assertEqual(seen, [(i, 5) for i in range(1, 6)])
        self.assertIsNone(st["stopped"])                 # ran to completion

    def test_progress_exception_never_breaks_the_loop(self):
        from recce.services import svcprobe as S
        def boom(i, n, t):
            raise ValueError("progress must never break a scan")
        out = [r for _, r in S.iter_probe(
            [{"ip": "1.1.1.1"}], lambda t: "ok", progress=boom)]
        self.assertEqual(out, ["ok"])


class DiscoveryReconfirmTest(unittest.TestCase):
    """False-negative hardening: the discovery probe set, and the reconfirm re-probe
    that recovers firewalled hosts which block ping but answer a port scan."""

    def test_discovery_command_probes_ad_ports_and_retries(self):
        from recce.core import scanner
        seen = {}
        orig = scanner._run
        scanner._run = lambda cmd, timeout=None: (seen.__setitem__("cmd", cmd),
                                                  scanner.RunOutcome(returncode=0))[1]
        try:
            with tempfile.TemporaryDirectory() as d:
                tf = os.path.join(d, "t.txt")
                with open(tf, "w") as _f:
                    _f.write("10.0.0.1\n10.0.0.2\n")
                scanner.discover_hosts(tf, os.path.join(d, "disc.xml"))
        finally:
            scanner._run = orig
        cmd = " ".join(seen["cmd"])
        self.assertIn("-sn", seen["cmd"])
        for p in ("88", "389", "5985"):                 # AD/Windows ports firewalls allow
            self.assertIn(p, cmd)
        # A single dropped probe shouldn't lose a host -> at least 2 retries.
        self.assertIn("--max-retries", seen["cmd"])
        self.assertEqual(seen["cmd"][seen["cmd"].index("--max-retries") + 1], "2")

    def test_udp_basic_scan_command(self):
        from recce.core import scanner
        seen = {}
        orig_run, orig_root = scanner._run, scanner._is_root
        scanner._is_root = lambda: True          # pretend root so it builds the command
        scanner._run = lambda cmd, timeout=None: (seen.__setitem__("cmd", cmd),
                                                 scanner.RunOutcome(returncode=0))[1]
        try:
            with tempfile.TemporaryDirectory() as d:
                scanner.udp_basic_scan("10.0.0.5", os.path.join(d, "u.xml"),
                                       scanner.PROFILES["standard"])
        finally:
            scanner._run, scanner._is_root = orig_run, orig_root
        cmd = " ".join(seen["cmd"])
        self.assertIn("-sU", seen["cmd"])                     # UDP scan
        for p in ("53", "161", "123", "500"):                 # DNS/SNMP/NTP/IKE covered
            self.assertIn(p, scanner._UDP_BASIC_PORTS.split(","))
        self.assertIn("161", cmd)
        # Default profile enables the basic UDP sweep.
        self.assertTrue(scanner.PROFILES["standard"].udp_basic)

    def test_reconfirm_command_is_bounded_pn_topports(self):
        from recce.core import scanner
        seen = {}
        orig = scanner._run
        scanner._run = lambda cmd, timeout=None: (seen.__setitem__("cmd", cmd),
                                                  scanner.RunOutcome(returncode=0))[1]
        try:
            with tempfile.TemporaryDirectory() as d:
                tf = os.path.join(d, "m.txt")
                with open(tf, "w") as _f:
                    _f.write("10.0.0.5\n")
                scanner.reconfirm_hosts(tf, os.path.join(d, "rc.xml"),
                                        scanner.PROFILES["standard"])
        finally:
            scanner._run = orig
        cmd = seen["cmd"]
        self.assertIn("-Pn", cmd)                       # scan even if ping said down
        self.assertIn("--open", cmd)                    # only report hosts with open ports
        self.assertIn("--top-ports", cmd)
        self.assertEqual(cmd[cmd.index("--top-ports") + 1], "100")

    def test_reconfirm_promotes_firewalled_host(self):
        from recce import cli
        from recce.core import scanner
        orig_rc, orig_parse = scanner.reconfirm_hosts, cli.np.parse_nmap_xml
        # 10.0.0.50 blocked ping but answers on 445; 10.0.0.51 is genuinely dead.
        cli.np.parse_nmap_xml = lambda path: [
            Host(ip="10.0.0.50", ports=[Port(portid=445, state="open")],
                 up_reason="syn-ack")]
        scanner.reconfirm_hosts = lambda tf, out, profile: (out, None)
        try:
            with tempfile.TemporaryDirectory() as d:
                prof = scanner.ScanProfile()
                recovered, _ = cli._reconfirm_missed(["10.0.0.50", "10.0.0.51"],
                                                     prof, {"raw": d})
        finally:
            scanner.reconfirm_hosts, cli.np.parse_nmap_xml = orig_rc, orig_parse
        self.assertIn("10.0.0.50", recovered)           # recovered (open port = up)
        self.assertNotIn("10.0.0.51", recovered)        # stays down (no open port)

    def test_reconfirm_respects_cap_and_optout(self):
        from recce import cli
        from recce.core import scanner
        calls = {"n": 0}
        orig = scanner.reconfirm_hosts
        scanner.reconfirm_hosts = lambda tf, out, profile: (
            calls.__setitem__("n", calls["n"] + 1), (out, None))[1]
        try:
            with tempfile.TemporaryDirectory() as d:
                # Over the cap -> skipped, nmap never invoked.
                prof = scanner.ScanProfile(reconfirm_cap=1)
                rec, _ = cli._reconfirm_missed(["a", "b", "c"], prof, {"raw": d})
                self.assertEqual((rec, calls["n"]), ({}, 0))
                # Opted out -> skipped.
                prof2 = scanner.ScanProfile(reconfirm=False)
                rec2, _ = cli._reconfirm_missed(["a"], prof2, {"raw": d})
                self.assertEqual((rec2, calls["n"]), ({}, 0))
        finally:
            scanner.reconfirm_hosts = orig

    def test_seed_targets_preseeds_named_up_hosts(self):
        # An authoritative list pre-registers every target BEFORE scanning, so a
        # timeout/failure can't drop it. Each is present, named, and shown up.
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "r.sqlite"))
            n = cli._seed_targets(st, ["10.0.0.5", "10.0.0.6"],
                                  {"10.0.0.5": "10.0.0.0/24", "10.0.0.6": "10.0.0.0/24"},
                                  {"10.0.0.5": "dc01.corp.local"})
            self.assertEqual(n, 2)
            h5 = st.get_host("10.0.0.5")
            h6 = st.get_host("10.0.0.6")
            st.close()
        self.assertIsNotNone(h5)                         # present before any scan
        self.assertEqual(h5.hostnames, ["dc01.corp.local"])
        self.assertEqual(h5.up_reason, "target-list")
        self.assertTrue(h5.is_up)                         # provided list vouches -> up
        self.assertIsNotNone(h6)                          # a nameless target is seeded too

    def test_seed_targets_never_clobbers_a_scanned_host(self):
        # Re-seeding merges - it must not wipe ports/findings already collected.
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "r.sqlite"))
            st.upsert_host(Host(ip="10.0.0.5", subnet="10.0.0.0/24",
                                ports=[Port(portid=445, state="open")],
                                up_reason="syn-ack", enumerated=True))
            cli._seed_targets(st, ["10.0.0.5"], {"10.0.0.5": "10.0.0.0/24"},
                              {"10.0.0.5": "dc01"})
            h = st.get_host("10.0.0.5")
            st.close()
        self.assertTrue(h.open_ports)                    # scan result preserved
        self.assertEqual(h.up_reason, "syn-ack")         # real reply reason kept

    def test_port_scope_label_and_all_ports_override(self):
        from recce import cli
        from recce.core import scanner
        # standard + thorough = full sweep; quick = partial (top-N).
        self.assertEqual(scanner.port_scope_label(scanner.PROFILES["standard"]),
                         ("all 65535 TCP ports", True))
        self.assertEqual(scanner.port_scope_label(scanner.PROFILES["thorough"]),
                         ("all 65535 TCP ports", True))
        label, is_full = scanner.port_scope_label(scanner.PROFILES["quick"])
        self.assertFalse(is_full)
        self.assertIn("top 200", label)
        # --all-ports forces a full sweep even on the quick profile.
        prof = scanner.ScanProfile(all_ports=False, top_ports=200)
        cli._apply_profile_overrides(prof, SimpleNamespace(all_ports=True))
        self.assertTrue(prof.all_ports)
        # A stray --top-ports followed by --all-ports still ends up full (order wins).
        prof2 = scanner.ScanProfile()
        cli._apply_profile_overrides(prof2, SimpleNamespace(top_ports=100, all_ports=True))
        self.assertTrue(prof2.all_ports)

    def test_targets_up_implies_pn(self):
        # --targets-up forces -Pn semantics so discovery can never drop a provided host.
        from recce import cli
        from recce.core import scanner
        prof = scanner.ScanProfile()
        args = SimpleNamespace(targets_up=True, no_discovery=False)
        cli._apply_profile_overrides(prof, args)
        self.assertFalse(prof.ping_discovery)            # discovery skipped
        self.assertTrue(prof.assume_up)                  # every target scanned as up
        # Without the flag (and without -Pn) discovery still runs normally.
        prof2 = scanner.ScanProfile()
        cli._apply_profile_overrides(prof2, SimpleNamespace(targets_up=False,
                                                            no_discovery=False))
        self.assertTrue(prof2.ping_discovery)


class AuditRegressionE2ETest(unittest.TestCase):
    """Regressions for bugs found in the full code audit + end-to-end run.

    Distinct from AuditRegressionTest above: sharing the class name silently
    shadowed one block so ~9 tests never ran."""

    def test_plain_http_product_not_flipped_to_tls(self):
        # BUG: _is_tls substring-matched the PRODUCT, so "SimpleHTTPServer" (contains
        # "https") got scanned as HTTPS and every web finding was missed on 8080.
        from recce.services import probes
        from recce.core.models import Port
        self.assertFalse(probes._is_tls(
            Port(portid=8080, service="http", product="SimpleHTTPServer")))
        self.assertFalse(probes._is_tls(Port(portid=80, service="http", product="nginx")))
        # Real TLS still detected via service/tunnel (not the port-only heuristic).
        self.assertTrue(probes._is_tls(Port(portid=8443, service="http", tunnel="ssl")))
        self.assertTrue(probes._is_tls(Port(portid=9999, service="ssl/http")))

    def test_targets_dashed_hostname_and_huge_cidr(self):
        from recce.core.targets import _expand_token
        # A hyphenated FQDN / typo must not crash the scope (was ValueError).
        self.assertEqual(_expand_token("mail-1.corp.example"), ["mail-1.corp.example"])
        self.assertEqual(_expand_token("10.0.0.10-"), ["10.0.0.10-"])
        # A genuine range still expands.
        self.assertEqual(_expand_token("10.0.0.10-12"),
                         ["10.0.0.10", "10.0.0.11", "10.0.0.12"])
        # A too-large network is refused, not materialised (OOM guard).
        with self.assertRaises(ValueError):
            _expand_token("10.0.0.0/8")

    def test_parser_tolerates_bad_numeric_attr(self):
        from recce.core import parser
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "x.xml")
            with open(f, "w") as fh:
                fh.write('<?xml version="1.0"?><nmaprun><host><status state="up" '
                         'reason="syn-ack"/><address addr="1.2.3.4" addrtype="ipv4"/>'
                         '<ports><port protocol="tcp" portid=""><state state="open"/>'
                         '</port></ports></host></nmaprun>')
            hosts = parser.parse_nmap_xml(f)          # must not raise
        self.assertEqual(len(hosts), 1)

    def test_bson_parse_negative_length_terminates(self):
        from recce.services.db import mongodb
        import struct
        body = b"\x02\x00" + struct.pack("<i", -6)    # string, empty name, negative len
        doc = struct.pack("<i", len(body) + 5) + body + b"\x00"
        out, idx = mongodb.bson_parse(doc, 0)          # must return, not hang
        self.assertEqual(out, {})

    def test_from_json_ignores_unknown_keys(self):
        from recce.core.models import Host
        data = {"ip": "1.2.3.4", "subnet": "1.2.3.0/24",
                "some_removed_field": "legacy",       # schema drift on a carried DB
                "ports": [{"portid": 80, "state": "open", "gone_field": 1}]}
        h = Host.from_json(data)                        # must not raise TypeError
        self.assertEqual(h.ip, "1.2.3.4")
        self.assertEqual([p.portid for p in h.ports], [80])

    def test_coverage_excludes_unconfirmed_phantom_hosts(self):
        from recce.core import tracking as tr
        confirmed = Host(ip="10.0.0.5", subnet="10.0.0.0/24",
                         ports=[Port(portid=445, state="open")])
        phantom = Host(ip="10.0.0.250", subnet="10.0.0.0/24", up_reason="user-set")
        keys = tr.item_keys([confirmed, phantom])
        self.assertIn(tr.host_key("10.0.0.5"), keys["hosts"])
        self.assertNotIn(tr.host_key("10.0.0.250"), keys["hosts"])  # not on any sheet
        # A fully-reviewed confirmed host => 100%, not stuck below by a phantom.
        cov = tr.compute_coverage([confirmed, phantom],
                                  {tr.host_key("10.0.0.5"): (True, "")})
        self.assertEqual(cov["hosts"], {"total": 1, "done": 1, "pct": 100})

    def test_incomplete_scan_survives_merge_over_seed(self):
        # A --targets-up seed (never enumerated) must not mark a truncated enum complete.
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "r.sqlite"))
            st.upsert_host(Host(ip="10.0.0.9", subnet="10.0.0.0/24",
                                up_reason="target-list"))          # seed, enumerated=False
            st.upsert_host(Host(ip="10.0.0.9", subnet="10.0.0.0/24", enumerated=True,
                                incomplete_scan=True,
                                ports=[Port(portid=80, state="open")]))  # truncated enum
            h = st.get_host("10.0.0.9")
            st.close()
        self.assertTrue(h.incomplete_scan)             # truncation preserved


if __name__ == "__main__":
    unittest.main(verbosity=2)
