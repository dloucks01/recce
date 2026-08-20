"""End-to-end import matrix — a realistic sample of EVERY supported format, fed through
the real /api/import endpoint, verifying both the response and the data that lands in the
store. Import is a primary way testers share information, so this exercises the whole path
(decode -> detect -> parse -> fold) the way a dropped file actually would.
"""
from __future__ import annotations

import base64
import os
import tempfile
import time
import unittest

from fastapi.testclient import TestClient

from recce.store import Store
from recce.webui.app import create_app


def _client():
    d = tempfile.mkdtemp()
    Store(os.path.join(d, "results.sqlite")).close()
    return TestClient(create_app(d)), d


def _post(c, raw, kind="auto", filename="x"):
    payload = {"content": base64.b64encode(raw if isinstance(raw, bytes) else raw.encode()).decode(),
               "encoding": "base64", "kind": kind, "filename": filename}
    return c.post("/api/import", json=payload)


def _wait_hosts(d, want, timeout=8.0):
    """Job-mode imports fold asynchronously; poll the store until `want` hosts appear."""
    db = os.path.join(d, "results.sqlite")
    end = time.time() + timeout
    while time.time() < end:
        st = Store(db)
        try:
            hs = st.all_hosts()
        finally:
            st.close()
        if len(hs) >= want:
            return hs
        time.sleep(0.1)
    return hs


NMAP_XML = """<?xml version="1.0"?><nmaprun><host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.2"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.4.0"/></port></ports></host></nmaprun>"""

NMAP_GNMAP = "Host: 10.0.0.5 ()\tStatus: Up\nHost: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///\tIgnored State: closed (0)\n"

NMAP_NORMAL = "Nmap scan report for 10.0.0.5\nHost is up.\nPORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n"

NESSUS = """<NessusClientData_v2><Report name="r"><ReportHost name="10.0.0.5">
<HostProperties><tag name="host-ip">10.0.0.5</tag></HostProperties>
<ReportItem port="445" protocol="tcp" severity="4" pluginID="97833" pluginName="MS17-010">
<synopsis>Remote code execution</synopsis><solution>Patch</solution><cve>CVE-2017-0143</cve></ReportItem>
</ReportHost></Report></NessusClientData_v2>"""

OPENVAS = """<report><results><result><host>10.0.0.9</host><port>443/tcp</port>
<threat>High</threat><nvt oid="1.2"><name>TLS issue</name>
<refs><ref type="cve" id="CVE-2014-0160"/></refs></nvt>
<description>heartbleed</description></result></results></report>"""

NUCLEI_JSONL = ('{"template-id":"apache-detect","info":{"name":"Apache","severity":"info"},"host":"http://10.0.0.5"}\n'
                '{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical","classification":{"cve-id":"CVE-2021-44228"}},"host":"https://10.0.0.5:8443/app","matched-at":"10.0.0.5:8443"}\n')

TESTSSL_PRETTY = ('{"scanResult":[{"ip":"web/10.0.0.5","port":"443","vulnerabilities":['
                  '{"id":"heartbleed","severity":"CRITICAL","finding":"VULNERABLE","cve":"CVE-2014-0160"}]}]}')

NXC_SMB = ("SMB 10.0.0.10 445 DC01 [*] Windows Server 2019 Build 17763 x64\n"
           "SMB 10.0.0.10 445 DC01 [+] corp.local\\admin:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 (Pwn3d!)\n")

KERBEROAST = "ServicePrincipalName  Name  MemberOf\nMSSQLSvc/sql01  svc_sql  \n$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01*$abcdef0123456789abcdef\n"

ASREP_IMPACKET = "$krb5asrep$23$roastme@CORP.LOCAL:aabbccddeeff00112233445566778899\n"
ASREP_JTR = "$krb5asrep$roastme2@CORP.LOCAL:00112233445566778899aabbccddeeff\n"

SECRETSDUMP = ("[*] Dumping Domain Credentials\n"
               "corp.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
               "corp.local\\svc_web:1104:aad3b435b51404eeaad3b435b51404ee:1122334455667788990011223344556677:::\n"
               "DC01$:1000:aad3b435b51404eeaad3b435b51404ee:ffffffffffffffffffffffffffffffff:::\n")

LOOT = "===ID===\nuid=0(root) gid=0(root)\n===SUID===\n/usr/bin/pkexec\n[!] recce-enum.sh v1\n"


class ScannerFormats(unittest.TestCase):
    def _findings(self, d):
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            return [v for h in st.all_hosts() for v in h.vulns]
        finally:
            st.close()

    def test_nessus(self):
        c, d = _client()
        self.assertEqual(_post(c, NESSUS).json()["added"], 1)
        f = self._findings(d)
        self.assertTrue(any("CVE-2017-0143" in v.ids for v in f))

    def test_openvas_modern_ref(self):
        c, d = _client()
        self.assertGreaterEqual(_post(c, OPENVAS).json()["added"], 1)
        self.assertTrue(any("CVE-2014-0160" in v.ids for v in self._findings(d)))

    def test_nuclei_jsonl_info_gated(self):
        c, d = _client()
        r = _post(c, NUCLEI_JSONL).json()
        self.assertEqual(r["kind"], "nuclei")
        f = self._findings(d)
        self.assertEqual(len(f), 1)                       # info template gated out
        self.assertEqual(f[0].ip, "10.0.0.5")             # not the URL
        self.assertEqual(f[0].port, 8443)

    def test_testssl_pretty(self):
        c, d = _client()
        self.assertEqual(_post(c, TESTSSL_PRETTY).json()["kind"], "testssl")
        f = self._findings(d)
        self.assertTrue(f and f[0].ip == "10.0.0.5" and "CVE-2014-0160" in f[0].ids)


class CredentialFormats(unittest.TestCase):
    def _creds(self, d):
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            return st.all_credentials()
        finally:
            st.close()

    def test_nxc_smb_lmnt(self):
        c, d = _client()
        r = _post(c, NXC_SMB).json()
        self.assertEqual(r["kind"], "nxc")
        cr = next(x for x in self._creds(d) if x.username == "admin")
        self.assertEqual(cr.kind, "nthash")
        self.assertEqual(cr.secret, "31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_kerberoast_full_hash(self):
        c, d = _client()
        r = _post(c, KERBEROAST).json()
        self.assertEqual(r["kind"], "kerberoast")
        cr = next(x for x in self._creds(d) if x.username == "svc_sql")
        self.assertEqual(cr.kind, "hash")
        self.assertTrue(cr.secret.startswith("$krb5tgs$"))

    def test_asrep_impacket_and_jtr(self):
        for sample, who in ((ASREP_IMPACKET, "roastme"), (ASREP_JTR, "roastme2")):
            c, d = _client()
            r = _post(c, sample).json()
            self.assertEqual(r["kind"], "asrep", sample)
            cr = next(x for x in self._creds(d) if x.username == who)
            self.assertTrue(cr.secret.startswith("$krb5asrep$"))

    def test_secretsdump_labels_and_history(self):
        c, d = _client()
        r = _post(c, SECRETSDUMP).json()
        self.assertEqual(r["kind"], "secretsdump")
        creds = {x.username: x for x in self._creds(d)}
        self.assertEqual(creds["corp.local\\Administrator"].kind, "nthash")
        self.assertIn("DC01$", creds)                     # machine account kept


class ScanFormats(unittest.TestCase):
    """Job-mode imports (nmap/masscan) fold asynchronously — poll the store."""

    def test_nmap_xml(self):
        c, d = _client()
        self.assertEqual(_post(c, NMAP_XML, filename="s.xml").json()["mode"], "job")
        hs = _wait_hosts(d, 1)
        self.assertEqual(hs[0].ip, "10.0.0.5")
        self.assertEqual({p.portid for p in hs[0].open_ports}, {22, 80})

    def test_nmap_gnmap(self):
        c, d = _client()
        _post(c, NMAP_GNMAP, filename="s.gnmap")
        hs = _wait_hosts(d, 1)
        self.assertEqual({p.portid for p in hs[0].open_ports}, {22, 80})

    def test_nmap_normal_oN(self):
        c, d = _client()
        _post(c, NMAP_NORMAL, filename="s.txt")           # a bare -oN with a neutral name
        hs = _wait_hosts(d, 1)
        self.assertEqual(hs[0].ip, "10.0.0.5")

    def test_masscan_list(self):
        c, d = _client()
        _post(c, "open tcp 22 10.0.0.5 1\nopen tcp 80 10.0.0.5 1\n", filename="m.list")
        hs = _wait_hosts(d, 1)
        self.assertEqual({p.portid for p in hs[0].open_ports}, {22, 80})


class EncodingAndDetection(unittest.TestCase):
    def test_utf16_and_ansi_nxc(self):
        c, d = _client()
        ansi = "SMB 10.0.0.10 445 DC01 \x1b[32m[+]\x1b[0m corp\\u:31d6cfe0d16ae931b73c59d7e0c089c0 (Pwn3d!)\n"
        r = _post(c, ansi.encode("utf-16"), kind="nxc").json()   # UTF-16 + ANSI together
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            self.assertTrue(any(x.username == "u" for x in st.all_credentials()))
        finally:
            st.close()

    def test_auto_detect_every_format(self):
        c, _ = _client()
        cases = {
            "nmap": NMAP_XML, "nessus": NESSUS, "openvas": OPENVAS, "nuclei": NUCLEI_JSONL,
            "testssl": TESTSSL_PRETTY, "nxc": NXC_SMB, "kerberoast": KERBEROAST,
            "asrep": ASREP_IMPACKET, "secretsdump": SECRETSDUMP, "loot": LOOT,
        }
        from recce.webui.app import _detect_import_kind
        for want, sample in cases.items():
            self.assertEqual(_detect_import_kind(sample), want, f"auto-detect for {want}")


class Deduplication(unittest.TestCase):
    """Re-importing the same output (a common accident when several testers share) must
    never double-count, and overlapping/cross-format imports must merge onto one host."""

    def _counts(self, d):
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            hs = st.all_hosts()
            return {"hosts": len(hs),
                    "vulns": sum(len(h.vulns) for h in hs),
                    "ports": sum(len(h.ports) for h in hs),
                    "creds": len(st.all_credentials())}
        finally:
            st.close()

    def test_direct_parse_formats_dedup_on_reimport(self):
        for name, sample, kind in [
            ("nessus", NESSUS, "auto"), ("openvas", OPENVAS, "auto"),
            ("nuclei", NUCLEI_JSONL, "auto"), ("testssl", TESTSSL_PRETTY, "auto"),
            ("nxc", NXC_SMB, "auto"), ("kerberoast", KERBEROAST, "auto"),
            ("asrep", ASREP_IMPACKET, "auto"), ("secretsdump", SECRETSDUMP, "auto"),
            ("creds", "corp\\alice:Passw0rd!\nbob:hunter2\n", "creds"),
        ]:
            c, d = _client()
            _post(c, sample, kind)
            after1 = self._counts(d)
            _post(c, sample, kind)                        # exact same input again
            after2 = self._counts(d)
            self.assertEqual(after1, after2, f"{name}: re-import changed counts {after1} -> {after2}")

    def test_job_formats_dedup_on_reimport(self):
        for sample, fname in [(NMAP_XML, "s.xml"), ("open tcp 22 10.0.0.5 1\n", "m.list")]:
            c, d = _client()
            _post(c, sample, filename=fname)
            _wait_hosts(d, 1)
            a = self._counts(d)
            _post(c, sample, filename=fname)
            _wait_hosts(d, 1)
            # give the 2nd async fold a moment, then confirm no growth
            time.sleep(0.5)
            b = self._counts(d)
            self.assertEqual(a["hosts"], b["hosts"], f"{fname}: host count grew")
            self.assertEqual(a["ports"], b["ports"], f"{fname}: port count grew")

    def test_cross_format_merges_onto_one_host(self):
        # an nmap scan and a Nessus finding for the SAME ip -> ONE host, not two
        c, d = _client()
        _post(c, NMAP_XML, filename="s.xml")
        _wait_hosts(d, 1)
        _post(c, NESSUS)                                  # nessus finding on 10.0.0.5 too
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            hs = st.all_hosts()
        finally:
            st.close()
        self.assertEqual([h.ip for h in hs], ["10.0.0.5"])          # merged, not forked
        h = hs[0]
        self.assertEqual({p.portid for p in h.open_ports}, {22, 80})
        self.assertTrue(any("CVE-2017-0143" in v.ids for v in h.vulns))

    def test_credential_dedup_across_sources(self):
        c, d = _client()
        _post(c, "corp\\alice:S3cret!\n", kind="creds")
        _post(c, "corp\\alice:S3cret!\n", kind="creds")             # same cred again
        self.assertEqual(self._counts(d)["creds"], 1)

    def test_overlapping_nmap_scans_union_ports(self):
        c, d = _client()
        _post(c, NMAP_XML, filename="a.xml")                        # 22, 80 on 10.0.0.5
        _wait_hosts(d, 1)
        second = NMAP_XML.replace('portid="80"', 'portid="443"')    # 22, 443 (80 -> 443)
        _post(c, second, filename="b.xml")
        _wait_hosts(d, 1)
        time.sleep(0.5)
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            hs = st.all_hosts()
        finally:
            st.close()
        self.assertEqual(len(hs), 1)                                # one host
        self.assertEqual({p.portid for p in hs[0].open_ports}, {22, 80, 443})   # union, no dup


class EdgeCases(unittest.TestCase):
    def test_reimport_is_idempotent(self):
        c, d = _client()
        _post(c, NESSUS)
        _post(c, NESSUS)                                  # same file twice
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            vulns = [v for h in st.all_hosts() for v in h.vulns]
        finally:
            st.close()
        self.assertEqual(len(vulns), 1)                   # union-merge dedups, no double count

    def test_nxc_hostname_target_captures_cred_no_bogus_host(self):
        c, d = _client()
        # nxc run against a NAME, not an IP: the cred is valuable, the host key is not.
        _post(c, "SMB DC01.corp.local 445 DC01 [+] corp\\admin:Passw0rd! (Pwn3d!)\n", kind="nxc")
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            self.assertTrue(any(x.username == "admin" for x in st.all_credentials()))
            self.assertFalse(any(h.ip == "DC01.corp.local" for h in st.all_hosts()))
        finally:
            st.close()

    def test_empty_rejected(self):
        c, _ = _client()
        self.assertEqual(_post(c, "   ").status_code, 400)

    def test_unknown_format_rejected(self):
        c, _ = _client()
        r = _post(c, "just some random prose that isn't any tool output at all")
        self.assertEqual(r.status_code, 422)
        self.assertIn("could not detect", r.json()["detail"])

    def test_bloodhound_zip_routes_to_job(self):
        c, _ = _client()
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("20240101_users.json",
                       '{"meta":{"type":"users","count":0},"data":[]}')
        r = _post(c, buf.getvalue(), kind="bloodhound", filename="bh.zip").json()
        self.assertEqual(r["mode"], "job")                # decoded zip -> ad engine, no error

    def test_wrong_kind_scanner_still_safe(self):
        # user picks "nessus" but pastes nuclei — parses 0, flagged, doesn't crash/pollute
        c, d = _client()
        r = _post(c, NUCLEI_JSONL, kind="nessus").json()
        self.assertEqual(r["added"], 0)
        self.assertIn("0 rows", r["summary"])
        st = Store(os.path.join(d, "results.sqlite"))
        try:
            self.assertEqual(st.all_hosts(), [])
        finally:
            st.close()


if __name__ == "__main__":
    unittest.main()
