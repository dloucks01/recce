"""Import hardening — encoding, hash-type labeling, and host-key safety.

These pin the Phase-1 fixes: a UTF-16 upload (the default of a Windows PowerShell
redirect) and an ANSI-coloured log must import; an LM:NT / cleartext / history secret
must be labeled correctly (a wrong label breaks the credential spray); and a hostname/URL
must never be stored as a host IP.
"""
from __future__ import annotations

import base64
import os
import tempfile
import unittest

from recce import importers as im


class Helpers(unittest.TestCase):
    def test_decode_bytes_encodings(self):
        self.assertEqual(im.decode_bytes("héllo".encode("utf-16")), "héllo")       # UTF-16 + BOM
        self.assertEqual(im.decode_bytes("SMB dc".encode("utf-16-le")), "SMB dc")  # BOM-less UTF-16
        self.assertEqual(im.decode_bytes(b"\xef\xbb\xbfhi"), "hi")                  # UTF-8 BOM
        self.assertEqual(im.decode_bytes("plain".encode()), "plain")
        self.assertEqual(im.decode_bytes(b""), "")

    def test_strip_ansi(self):
        self.assertEqual(im.strip_ansi("\x1b[34mSMB\x1b[0m 1.2.3.4"), "SMB 1.2.3.4")

    def test_is_ip(self):
        self.assertTrue(im.is_ip("10.0.0.5"))
        self.assertTrue(im.is_ip("dead::1"))
        self.assertFalse(im.is_ip("dc01.corp.local"))
        self.assertFalse(im.is_ip("https://shop.example.com/login"))

    def test_classify_secret(self):
        nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
        self.assertEqual(im.classify_secret(f"aad3b435b51404eeaad3b435b51404ee:{nt}"), ("nthash", nt))
        self.assertEqual(im.classify_secret(nt), ("nthash", nt))
        self.assertEqual(im.classify_secret("Summer2023!"), ("password", "Summer2023!"))
        self.assertEqual(im.classify_secret("$krb5tgs$23$x")[0], "hash")


class Secretsdump(unittest.TestCase):
    def test_cleartext_history_and_hash(self):
        from recce.credenum import parse_secretsdump
        rows = {r["name"]: r for r in parse_secretsdump(
            "CORP\\svc:CLEARTEXT:PlainPw1\n"
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "Administrator_history0:500:aad3b435b51404eeaad3b435b51404ee:0000000000000000000000000000ffff:::\n")}
        self.assertEqual(rows["CORP\\svc"]["kind"], "password")
        self.assertEqual(rows["CORP\\svc"]["secret"], "PlainPw1")
        self.assertEqual(rows["Administrator"]["kind"], "nthash")
        self.assertFalse(rows["Administrator"]["history"])
        self.assertTrue(rows["Administrator_history0"]["history"])

    def test_asrep_jtr_form_kept(self):
        from recce.credenum import parse_getnpusers
        got = parse_getnpusers("$krb5asrep$roastme@CORP.LOCAL:a1b2c3d4deadbeef")
        self.assertEqual(got[0]["name"], "roastme")
        self.assertTrue(got[0]["hash"].endswith("deadbeef"))          # full hash, not truncated


class ImportEndpoint(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient
        from recce.store import Store
        from recce.webui.app import create_app
        d = tempfile.mkdtemp()
        Store(os.path.join(d, "results.sqlite")).close()
        return TestClient(create_app(d)), d

    def _imp(self, c, raw: bytes, kind: str):
        return c.post("/api/import", json={"content": base64.b64encode(raw).decode(),
                                           "encoding": "base64", "kind": kind}).json()

    def test_utf16_nxc_lmnt_login(self):
        c, d = self._client()
        from recce.store import Store
        nxc = ("SMB 10.0.0.5 445 DC01 [+] corp\\admin:"
               "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 (Pwn3d!)\n")
        r = self._imp(c, nxc.encode("utf-16"), "nxc")      # UTF-16, LM:NT
        self.assertGreaterEqual(r["added"], 1)
        creds = Store(os.path.join(d, "results.sqlite")).all_credentials()
        cr = next(x for x in creds if x.username == "admin")
        self.assertEqual(cr.kind, "nthash")                # LM:NT -> nthash, not password
        self.assertEqual(cr.secret, "31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_creds_list_keeps_pth_and_hashcat(self):
        c, d = self._client()
        from recce.store import Store
        body = ("corp\\bob:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
                "31d6cfe0d16ae931b73c59d7e0c089c0:CrackedPw\n"
                "alice:Summer2024!\n")
        r = self._imp(c, body.encode(), "creds")
        self.assertEqual(r["added"], 3)                    # old count(":")!=1 dropped the PtH line
        kinds = {x.username: x.kind for x in Store(os.path.join(d, "results.sqlite")).all_credentials()}
        self.assertEqual(kinds["bob"], "nthash")


class Feedback(unittest.TestCase):
    def _client(self):
        from fastapi.testclient import TestClient
        from recce.store import Store
        from recce.webui.app import create_app
        d = tempfile.mkdtemp()
        Store(os.path.join(d, "results.sqlite")).close()
        return TestClient(create_app(d))

    def _b64(self, raw):
        return base64.b64encode(raw if isinstance(raw, bytes) else raw.encode()).decode()

    def test_preview_does_not_commit(self):
        c = self._client()
        arr = ('[{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical"},'
               '"host":"https://1.2.3.4:8443/x"}]')
        r = c.post("/api/import", json={"content": self._b64(arr), "encoding": "base64",
                                        "kind": "auto", "preview": True}).json()
        self.assertEqual(r["mode"], "preview")
        self.assertEqual(r["kind"], "nuclei")
        self.assertEqual(r["count"], 1)
        self.assertFalse(r["warning"])                  # a real finding -> no warning
        # nothing committed
        self.assertEqual(c.get("/api/findings").json(), [])

    def test_preview_warns_on_zero_rows(self):
        c = self._client()
        r = c.post("/api/import", json={"content": self._b64("not xml"), "encoding": "base64",
                                        "kind": "nessus", "preview": True}).json()
        self.assertEqual(r["count"], 0)
        self.assertIn("0 rows", r["warning"])

    def test_commit_zero_rows_is_flagged_not_success(self):
        c = self._client()
        r = c.post("/api/import", json={"content": self._b64("garbage"), "encoding": "base64",
                                        "kind": "nessus"}).json()
        self.assertEqual(r["added"], 0)
        self.assertIn("0 rows", r["summary"])

    def test_concatenated_paste_rejected(self):
        c = self._client()
        cat = ("Nmap scan report for 10.0.0.5\n80/tcp open http\n"
               "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n")
        r = c.post("/api/import", json={"content": self._b64(cat), "encoding": "base64", "kind": "auto"})
        self.assertEqual(r.status_code, 422)
        self.assertIn("more than one", r.json()["detail"])


class ParserVariants(unittest.TestCase):
    def test_nuclei_array_url_host_info_gate(self):
        arr = ('[{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell","severity":"critical",'
               '"classification":{"cve-id":"CVE-2021-44228"}},"host":"https://shop.ex.com:8443/x"},'
               '{"template-id":"tech","info":{"name":"nginx","severity":"info"},"host":"https://shop.ex.com"}]')
        v = im.parse_nuclei(arr)
        self.assertEqual(len(v), 1)                       # info template dropped
        self.assertEqual(v[0].ip, "shop.ex.com")          # hostname, not the URL
        self.assertEqual(v[0].port, 8443)
        self.assertEqual(v[0].ids, ["CVE-2021-44228"])

    def test_testssl_pretty_nested(self):
        pretty = ('{"scanResult":[{"ip":"web/93.184.216.34","port":"443",'
                  '"vulnerabilities":[{"id":"heartbleed","severity":"CRITICAL","cve":"CVE-2014-0160"}]}]}')
        v = im.parse_testssl(pretty)
        self.assertEqual(len(v), 1)
        self.assertEqual((v[0].ip, v[0].port, v[0].ids), ("93.184.216.34", 443, ["CVE-2014-0160"]))

    def test_openvas_modern_ref_cve(self):
        ov = ('<report><results><result><host>10.0.0.9</host><port>443/tcp</port><threat>High</threat>'
              '<nvt><name>X</name><refs><ref type="cve" id="CVE-2019-1234"/></refs></nvt></result></results></report>')
        self.assertEqual(im.parse_openvas(ov)[0].ids, ["CVE-2019-1234"])

    def test_nessus_compliance_failed(self):
        ns = ('<NessusClientData_v2><Report><ReportHost name="1.2.3.4"><HostProperties>'
              '<tag name="host-ip">1.2.3.4</tag></HostProperties>'
              '<ReportItem severity="0" pluginID="9" pluginName="CIS" port="0">'
              '<compliance-result>FAILED</compliance-result></ReportItem></ReportHost></Report></NessusClientData_v2>')
        v = im.parse_nessus(ns)
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0].severity, "medium")

    def test_masscan_list_and_json(self):
        from recce import parser
        import tempfile
        d = tempfile.mkdtemp()
        lp = os.path.join(d, "m.list")
        open(lp, "w").write("open tcp 80 10.0.0.5 1\nopen udp 53 10.0.0.9 1\n")
        self.assertEqual(sorted(h.ip for h in parser.parse_masscan_list(lp)), ["10.0.0.5", "10.0.0.9"])
        jp = os.path.join(d, "m.json")
        open(jp, "w").write('[{"ip":"10.0.0.5","ports":[{"port":22,"proto":"tcp","status":"open"}]}]')
        hs = parser.parse_masscan_json(jp)
        self.assertEqual(hs[0].open_ports[0].portid, 22)

    def test_detection(self):
        from recce.webui.app import _detect_import_kind
        self.assertEqual(_detect_import_kind("open tcp 80 10.0.0.5 1\n"), "nmap")           # masscan -oL
        self.assertEqual(_detect_import_kind("LDAP 10.0.0.10 389 DC01 [+] c\\u:p"), "nxc")  # non-SMB nxc
        cat = ("Nmap scan report for 10.0.0.5\n80/tcp open http\n"
               "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n")
        self.assertEqual(_detect_import_kind(cat), "multiple")                              # concatenated


if __name__ == "__main__":
    unittest.main()
