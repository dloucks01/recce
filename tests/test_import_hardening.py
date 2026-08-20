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


if __name__ == "__main__":
    unittest.main()
