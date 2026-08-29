"""Offline tests split out of tests/test_pipeline.py.

Every test class here is what the original monolith called it. Shared
helpers (header_index, _docx_text, _self_response) live in _pipeline_helpers."""
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


from _pipeline_helpers import header_index, _docx_text, _self_response, SAMPLE  # noqa: F401





class ADAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.hosts = parser.parse_nmap_xml(SAMPLE)
        ad.analyze_hosts(self.hosts)

    def test_dc_identified(self):
        dcs = ad.domain_controllers(self.hosts)
        self.assertEqual([h.ip for h in dcs], ["10.0.10.10"])

    def test_dc_signing_from_hostscript(self):
        dc = next(h for h in self.hosts if h.ip == "10.0.10.10")
        self.assertEqual(dc.smb_signing, "required")

    def test_relay_target_from_portscript(self):
        relay = ad.relay_targets(self.hosts)
        self.assertEqual([h.ip for h in relay], ["10.0.10.25"])

    def test_password_policy_parsed(self):
        doms = ad.derive_domains(self.hosts)
        corp = next(d for d in doms if d.name == "corp.local")
        self.assertEqual(corp.password_policy.get("min_length"), 7)
        self.assertEqual(corp.password_policy.get("lockout_threshold"), 0)
        self.assertIn("10.0.10.10", corp.dc_ips)

    def test_ntlm_domain_facts(self):
        ws = next(h for h in self.hosts if h.ip == "10.0.10.25")
        self.assertEqual(ws.ntlm.get("netbios_domain"), "CORP")
        self.assertEqual(ws.ntlm.get("dns_domain"), "corp.local")




class ADTargetListTest(unittest.TestCase):
    """LDAP-derived findings via synthetic accounts (no live DC needed)."""

    def _dc_with(self, *accounts):
        h = Host(ip="10.0.10.10", roles=["Domain Controller"])
        h.accounts.extend(accounts)
        return [h]

    def test_kerberoastable(self):
        hosts = self._dc_with(
            Account(ip="10.0.10.10", source="ldap", kind="user", name="svc_sql",
                    domain="corp.local", attrs={"spn": "MSSQLSvc/db01"}),
            Account(ip="10.0.10.10", source="ldap", kind="user", name="krbtgt",
                    domain="corp.local", attrs={"spn": "kadmin/changepw"}),
        )
        kerb = ad.kerberoastable(hosts)
        self.assertEqual([a.name for a in kerb], ["svc_sql"])  # krbtgt excluded

    def test_asrep_and_delegation(self):
        hosts = self._dc_with(
            Account(ip="10.0.10.10", source="ldap", kind="user", name="alice",
                    attrs={"asrep_roastable": "yes"}),
            Account(ip="10.0.10.10", source="ldap", kind="computer", name="SRV$",
                    attrs={"delegation": "unconstrained"}),
        )
        self.assertEqual([a.name for a in ad.asrep_roastable(hosts)], ["alice"])
        self.assertEqual([a.name for a in ad.delegation_accounts(hosts)], ["SRV$"])

    def test_privileged(self):
        hosts = self._dc_with(
            Account(ip="10.0.10.10", source="ldap", kind="user", name="admin",
                    attrs={"memberof": "Domain Admins; IT"}),
            Account(ip="10.0.10.10", source="ldap", kind="user", name="bob"),
        )
        self.assertEqual([a.name for a in ad.privileged_accounts(hosts)], ["admin"])

    def test_uac_flag_decoding(self):
        # DONT_REQ_PREAUTH (0x400000) + ACCOUNTDISABLE (0x2)
        flags = ad._uac_flags(0x400002)
        self.assertIn("DONT_REQ_PREAUTH", flags)
        self.assertIn("ACCOUNTDISABLE", flags)

    def test_ldap_available_is_bool(self):
        self.assertIsInstance(ad.ldap_available(), bool)




class AdLiveKerberosLootTest(unittest.TestCase):
    def test_loot_files_are_written_as_utf8_not_platform_default(self):
        # Regression: kerberoast.hash/asrep.hash/secretsdump.txt were opened bare
        # open(...,"w") - no encoding= - and a $krb5tgs$/$krb5asrep$ hash embeds the
        # account name, and secretsdump's own output embeds account names too, both
        # of which can be non-ASCII in a real AD environment. Would raise
        # UnicodeEncodeError on a platform whose default text encoding isn't UTF-8
        # (e.g. cp1252 on Windows, which recce explicitly ships an airgap build for).
        from types import SimpleNamespace
        from recce import cli

        class _FakeBH:
            @staticmethod
            def live_kerberos(creds, graph, do_roast, do_asrep, do_dcsync):
                return {
                    "runs": {
                        "kerberoast": {"hashes": [
                            {"hash": "$krb5tgs$23$*josé$CORP.LOCAL$MSSQLSvc/db*$aa$bb"}]},
                        "dcsync": {"output": "corp.local\\josé:1104:aad3...:31d6...:::\n"},
                    },
                    "findings": [],
                }
        with tempfile.TemporaryDirectory() as d:
            args = SimpleNamespace(output_dir=d, roast=True, asrep=False, dcsync=True)
            creds = {"secret": "x", "dc_ip": "10.0.0.1"}
            cli._ad_live_kerberos(args, _FakeBH(), creds, [], {})
            with open(os.path.join(d, "loot", "kerberoast.hash"), encoding="utf-8") as fh:
                self.assertIn("josé", fh.read())
            with open(os.path.join(d, "loot", "secretsdump.txt"), encoding="utf-8") as fh:
                self.assertIn("josé", fh.read())




class NtlmTest(unittest.TestCase):
    """NTLMSSP / NTLMv2 crypto, validated against the MS-NLMP 4.2.4 worked example."""

    def test_md4_and_nt_hash_vectors(self):
        from recce.ad import ntlm as N
        self.assertEqual(N.md4(b"").hex(), "31d6cfe0d16ae931b73c59d7e0c089c0")
        # NT hash of "password" (MD4 of the UTF-16LE password).
        self.assertEqual(N.nt_hash("password").hex(),
                         "8846f7eaee8fb117ad06bdd830b7586c")

    def test_ntlmv2_matches_ms_nlmp_vector(self):
        from recce.ad import ntlm as N
        nthash = N.nt_hash("Password")               # MS-NLMP example password
        # ResponseKeyNT = HMAC-MD5(NT hash, UPPER(user)+domain).
        self.assertEqual(N._ntv2_key("User", "Domain", nthash).hex(),
                         "0c868a403bfd7a93a3001ef22ef02e3f")
        target_info = bytes.fromhex(
            "02000c0044006f006d00610069006e0001000c00530065007200760065007200"
            "00000000")
        resp = N.ntlmv2_response("User", "Domain", nthash,
                                 bytes.fromhex("0123456789abcdef"), target_info,
                                 timestamp=0,
                                 client_challenge=bytes.fromhex("aaaaaaaaaaaaaaaa"))
        # NTProofStr is the first 16 bytes of the NtChallengeResponse.
        self.assertEqual(resp[:16].hex(), "68cd0ab851e51c96aabc927bebef6a1c")

    def test_rc4_known_answer_vectors(self):
        from recce.ad import ntlm as N
        self.assertEqual(N.rc4k(b"Key", b"Plaintext").hex(), "bbf316e8d940af0ad3")
        self.assertEqual(N.rc4k(b"Wiki", b"pedia").hex(), "1021bf0420")
        self.assertEqual(N.rc4k(b"Secret", b"Attack at dawn").hex(),
                         "45a01f645fc35b383552544b9bf5")

    def test_seal_wrap_signature_format_and_roundtrip(self):
        import hmac
        import hashlib
        import struct
        from recce.ad import ntlm as N
        exported = bytes(range(16))
        ctx = N.SecurityContext(exported)
        token = ctx.wrap(b"hello ldap")
        # NTLMSSP_MESSAGE_SIGNATURE: version 0x00000001 + sealed checksum(8) + seq(4).
        self.assertEqual(token[:4], b"\x01\x00\x00\x00")
        self.assertEqual(token[12:16], b"\x00\x00\x00\x00")     # first message: seq 0
        # A peer with the same key decrypts (message first, then its checksum).
        seal = N.RC4(N._derive_key(exported, N._C2S_SEAL))
        msg = seal.update(token[16:])
        chk = seal.update(token[4:12])
        want = hmac.new(N._derive_key(exported, N._C2S_SIGN),
                        struct.pack("<I", 0) + msg, hashlib.md5).digest()[:8]
        self.assertEqual(msg, b"hello ldap")
        self.assertEqual(chk, want)
        # unwrap reverses a server-sealed token and verifies the signature.
        s_seal = N.RC4(N._derive_key(exported, N._S2C_SEAL))
        pt = b"server reply"
        sealed = s_seal.update(pt)
        schk = s_seal.update(hmac.new(N._derive_key(exported, N._S2C_SIGN),
                                      struct.pack("<I", 0) + pt, hashlib.md5).digest()[:8])
        stoken = b"\x01\x00\x00\x00" + schk + struct.pack("<I", 0) + sealed
        self.assertEqual(ctx.unwrap(stoken), pt)
        # A tampered signature is rejected.
        with self.assertRaises(ValueError):
            ctx2 = N.SecurityContext(exported)
            ctx2.unwrap(b"\x01\x00\x00\x00" + b"\x00" * 8 + struct.pack("<I", 0) + sealed)

    def test_message_structure_and_hash_normalize(self):
        from recce.ad import ntlm as N
        self.assertEqual(N.type1()[:8], N._SIG)
        ch = {"challenge": b"\x01" * 8, "target_info": b"", "flags": N._TYPE1_FLAGS}
        t3 = N.type3("u", "d", b"\x00" * 16, ch)
        self.assertEqual(t3[:8], N._SIG)
        self.assertEqual(t3[8:12], b"\x03\x00\x00\x00")   # MessageType 3
        # LM:NT and a bare NT hash both normalize to the 16-byte NT hash.
        nt = "8846f7eaee8fb117ad06bdd830b7586c"
        self.assertEqual(N.normalize_nt_hash(nt), bytes.fromhex(nt))
        self.assertEqual(N.normalize_nt_hash("aad3b435b51404eeaad3b435b51404ee:" + nt),
                         bytes.fromhex(nt))




class LdapTest(unittest.TestCase):
    """Deep LDAP module: the stdlib BER client, the probe against a mock DC, findings,
    prove verdicts, and the full `recce ldap` command."""

    @classmethod
    def setUpClass(cls):
        import socketserver
        import threading
        from recce.services import ldap as L

        def tlv(tag, val):
            return bytes([tag]) + L._ber_len(len(val)) + val

        def attr(n, vals):
            return tlv(0x30, L._octet(n)
                       + tlv(0x31, b"".join(L._octet(v) for v in vals)))

        def msg(mid, op):
            return tlv(0x30, L._int(mid) + op)

        bind_ok = msg(1, tlv(0x61, L._enum(0) + L._octet("") + L._octet("")))
        rootdse = msg(2, tlv(0x64, L._octet("") + tlv(0x30,
            attr("defaultNamingContext", ["DC=corp,DC=local"])
            + attr("dnsHostName", ["dc01.corp.local"])
            + attr("domainControllerFunctionality", ["7"])
            + attr("forestFunctionality", ["7"])
            + attr("domainFunctionality", ["7"])
            + attr("isGlobalCatalogReady", ["TRUE"])
            + attr("supportedSASLMechanisms", ["GSSAPI", "GSS-SPNEGO"]))))
        done2 = msg(2, tlv(0x65, L._enum(0) + L._octet("") + L._octet("")))
        ncobj = msg(3, tlv(0x64, L._octet("DC=corp,DC=local") + tlv(0x30,
            attr("objectClass", ["top", "domain"])
            + attr("ms-DS-MachineAccountQuota", ["10"]))))
        done3 = msg(3, tlv(0x65, L._enum(0) + L._octet("") + L._octet("")))
        # Per-connection reply script: one response per request the client sends.
        cls._script = [bind_ok, rootdse + done2, ncobj + done3]

        script = cls._script

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                for resp in script:
                    req = L._read_message(self.request, 5.0)
                    if req is None:
                        return
                    self.request.sendall(resp)

        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_ber_encode_decode_roundtrip(self):
        from recce.services import ldap as L
        self.assertEqual(L.build_bind_request(1, "", "")[0], 0x30)
        self.assertEqual(L.build_search_request(2, "", 0, ["dnsHostName"])[0], 0x30)
        # A synthetic searchResEntry parses into {attr: [values]}.

        def tlv(t, v):
            return bytes([t]) + L._ber_len(len(v)) + v
        entry = tlv(0x30, L._int(2) + tlv(0x64, L._octet("") + tlv(0x30,
            tlv(0x30, L._octet("dnsHostName") + tlv(0x31, L._octet("dc01.corp.local"))))))
        _obj, attrs = L.parse_search_entry(entry)
        self.assertEqual(attrs["dnsHostName"], ["dc01.corp.local"])
        self.assertEqual(L._dn_to_domain("DC=corp,DC=local"), "corp.local")

    def test_probe_reads_rootdse_and_detects_anon(self):
        from recce.services import ldap as L
        pr = L.probe("127.0.0.1", self.port)
        self.assertIsNotNone(pr)
        self.assertTrue(pr["anon_bind"])
        self.assertTrue(pr["anon_read"])
        self.assertEqual(pr["domain"], "corp.local")
        self.assertEqual(pr["dc_dns"], "dc01.corp.local")
        self.assertEqual(pr["dc_level"], "2016")       # functional level 7 -> Server 2016
        self.assertTrue(pr["is_gc"])

    def test_findings_and_prove_confirm(self):
        from recce.services import ldap as L
        from recce.vuln import proofs
        pr = L.probe("127.0.0.1", self.port)
        h = Host(ip="10.0.10.10", ports=[Port(portid=389, service="ldap", state="open")])
        fs = L.findings([h], {("10.0.10.10", 389): pr})
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("Anonymous LDAP directory read", titles)
        self.assertIn("Anonymous LDAP bind allowed", titles)
        self.assertIn("cleartext", titles.lower())
        h.vulns = L.findings_to_vulns(fs)["10.0.10.10"]
        verdicts = [r["verdict"] for r in proofs.verify_host(h)]
        self.assertIn(proofs.CONFIRMED, verdicts)

    @staticmethod
    def _serve_scripts(scripts):
        """A TCP server that replays scripts[i] (a list of response byte-strings) on the
        i-th connection - so a probe connection and an enum connection get different
        replies. Returns (server, port); caller shuts it down."""
        import socketserver
        import threading
        from recce.services import ldap as L
        state = {"n": 0}
        lock = threading.Lock()

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with lock:
                    idx = state["n"]
                    state["n"] += 1
                script = scripts[idx] if idx < len(scripts) else []
                for r in script:
                    if L._read_message(self.request, 5.0) is None:
                        return
                    self.request.sendall(r)

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1]

    def test_authenticated_enum_pages_and_derives_accounts(self):
        from recce.services import ldap as L
        from recce.core.models import Host

        def tlv(t, v):
            return bytes([t]) + L._ber_len(len(v)) + v

        def attr(n, vals):
            return tlv(0x30, L._octet(n) + tlv(0x31, b"".join(L._octet(v) for v in vals)))

        def entry(mid, dn, pairs):
            return tlv(0x30, L._int(mid) + tlv(0x64, L._octet(dn)
                       + tlv(0x30, b"".join(attr(n, v) for n, v in pairs))))

        def done(mid, cookie=b""):
            if cookie is None:
                ctl = b""
            else:
                pv = tlv(0x30, L._int(0) + L._octet(cookie))
                ctl = tlv(0xA0, tlv(0x30, L._octet(L._PAGED_OID) + L._octet(pv)))
            return tlv(0x30, L._int(mid) + tlv(0x65, L._enum(0) + L._octet("")
                       + L._octet("")) + ctl)

        def bind_ok(mid=1):
            return tlv(0x30, L._int(mid) + tlv(0x61, L._enum(0) + L._octet("")
                       + L._octet("")))
        # bind, users page1 (cookie 'c1'), users page2 (empty), computers, domain
        enum_script = [
            bind_ok(1),
            entry(10, "CN=alice", [("sAMAccountName", ["alice"]),
                                   ("servicePrincipalName", ["HTTP/web"]),
                                   ("userAccountControl", ["512"])]) + done(10, b"c1"),
            entry(11, "CN=bob", [("sAMAccountName", ["bob"]),
                                 ("userAccountControl", ["4194816"]),
                                 ("description", ["svc pw=Summer2025"])]) + done(11, b""),
            done(1000, b""),
            entry(9000, "DC=corp,DC=local", [("ms-DS-MachineAccountQuota", ["10"]),
                                             ("lockoutThreshold", ["0"])]) + done(9000, None),
        ]
        srv, port = self._serve_scripts([enum_script])
        try:
            en = L.enum_authenticated("127.0.0.1", port, "DC=corp,DC=local",
                                      {"user": "alice", "secret": "x", "domain": "corp.local"},
                                      prefer_ldap3=False)   # this test drives the native BER parser
            self.assertIsNone(en["error"])
            self.assertEqual(len(en["users"]), 2)          # paging walked both pages
            h = Host(ip="127.0.0.1")
            summary, fs = L.apply_enum(h, "corp.local", "127.0.0.1", 389, en)
            self.assertEqual(summary["kerberoastable"], 1)
            self.assertEqual(summary["asrep"], 1)
            # Accounts carry the exact attrs ad.quick_wins consumes.
            alice = next(a for a in h.accounts if a.name == "alice")
            self.assertEqual(alice.attrs["spn"], "HTTP/web")
            bob = next(a for a in h.accounts if a.name == "bob")
            self.assertEqual(bob.attrs["asrep_roastable"], "yes")
            titles = " ".join(f["title"] for f in fs)
            self.assertIn("Machine account quota", titles)
            self.assertIn("lockout", titles.lower())
            self.assertIn("Passwords in LDAP description", titles)
        finally:
            srv.shutdown()

    @staticmethod
    def _serve_sealed_dc(user, domain, nthash, responses):
        """A mock DC that runs the sealed NTLM bind, derives the session key from the
        client's Type 3, then unseals the client's LDAP requests and seals its own
        responses - so the whole sign+seal channel is exercised end to end. `responses`
        is one plaintext LDAP response blob per client search request (in order)."""
        import socketserver
        import struct as _s
        import threading
        import hmac as _h
        import hashlib as _hl
        from recce.ad import ntlm as N
        from recce.services import ldap as L

        def tlv(t, v):
            return bytes([t]) + L._ber_len(len(v)) + v

        def type2():
            ti = b""
            return (N._SIG + _s.pack("<I", 2) + _s.pack("<HHI", 0, 0, 48)
                    + _s.pack("<I", N._SEAL_FLAGS) + bytes.fromhex("0123456789abcdef")
                    + b"\x00" * 8 + _s.pack("<HHI", len(ti), len(ti), 48) + ti)

        def bind_resp(mid, rc, creds=b""):
            op = L._enum(rc) + L._octet("") + L._octet("")
            if creds:
                op += tlv(0x87, creds)
            return tlv(0x30, L._int(mid) + tlv(0x61, op))

        def field(msg, i):
            ln = _s.unpack("<H", msg[12 + i * 8:14 + i * 8])[0]
            off = _s.unpack("<I", msg[16 + i * 8:20 + i * 8])[0]
            return msg[off:off + ln]

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                L._read_message(sock, 5.0)                         # bind1 (Type 1)
                sock.sendall(bind_resp(1, 14, type2()))           # saslBindInProgress
                bind2 = L._read_message(sock, 5.0)                # bind2 (Type 3)
                t3 = bind2[bind2.find(N._SIG):]
                nt_proof = field(t3, 1)[:16]
                enc_sk = field(t3, 5)
                kek = N._session_base_key(user, domain, nthash, nt_proof)
                exported = N.rc4k(kek, enc_sk)                    # recover ExportedSessionKey
                sock.sendall(bind_resp(2, 0))                     # bind success
                c_seal = N.RC4(N._derive_key(exported, N._C2S_SEAL))
                s_seal = N.RC4(N._derive_key(exported, N._S2C_SEAL))
                s_sign = N._derive_key(exported, N._S2C_SIGN)
                seq = 0
                for plain in responses:
                    hdr = L._recvn(sock, 4)
                    if len(hdr) < 4:
                        return
                    frame = L._recvn(sock, _s.unpack(">I", hdr)[0])
                    sig, sealed = frame[:16], frame[16:]
                    c_seal.update(sealed)                         # unseal request (stream sync)
                    c_seal.update(sig[4:12])                      # + its checksum
                    ct = s_seal.update(plain)                     # seal the response
                    chk = _h.new(s_sign, _s.pack("<I", seq) + plain, _hl.md5).digest()[:8]
                    sct = s_seal.update(chk)
                    token = b"\x01\x00\x00\x00" + sct + _s.pack("<I", seq) + ct
                    seq += 1
                    sock.sendall(_s.pack(">I", len(token)) + token)

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1]

    def test_ntlm_sealed_pth_end_to_end(self):
        from recce.ad import ntlm as N
        from recce.services import ldap as L
        from recce.core.models import Host

        def tlv(t, v):
            return bytes([t]) + L._ber_len(len(v)) + v

        def attr(n, vals):
            return tlv(0x30, L._octet(n) + tlv(0x31, b"".join(L._octet(v) for v in vals)))

        def entry(mid, dn, pairs):
            return tlv(0x30, L._int(mid) + tlv(0x64, L._octet(dn)
                       + tlv(0x30, b"".join(attr(n, v) for n, v in pairs))))

        def sdone(mid):
            return tlv(0x30, L._int(mid) + tlv(0x65, L._enum(0) + L._octet("")
                       + L._octet("")))
        # One sealed response blob per client search request: users, computers, domain.
        responses = [
            entry(10, "CN=svc", [("sAMAccountName", ["svc_web"]),
                                 ("servicePrincipalName", ["HTTP/web"]),
                                 ("userAccountControl", ["512"])]) + sdone(10),
            sdone(1000),
            entry(9000, "DC=corp,DC=local", [("lockoutThreshold", ["5"])]) + sdone(9000),
        ]
        nthash = N.nt_hash("Password")
        srv, port = self._serve_sealed_dc("alice", "corp.local", nthash, responses)
        try:
            en = L.enum_authenticated("127.0.0.1", port, "DC=corp,DC=local",
                                      {"user": "alice", "domain": "corp.local",
                                       "secret": "", "hash": nthash.hex()},
                                      prefer_ldap3=False)   # this test drives the native BER parser
            self.assertIsNone(en["error"])
            # Plaintext 389 + a hash -> the bind is sign+sealed, and the sealed search
            # traffic round-trips (the DC could read our requests, we read its replies).
            self.assertEqual(en["bind_method"], "NTLM sealed (pass-the-hash)")
            self.assertEqual([u.get("sAMAccountName") for u in en["users"]], [["svc_web"]])
            h = Host(ip="10.0.10.10")
            L.apply_enum(h, "corp.local", "10.0.10.10", 389, en)
            self.assertIn("svc_web", [a.name for a in h.accounts])
        finally:
            srv.shutdown()

    def test_rbcd_victim_surfaces_as_a_quick_win_row(self):
        """Any object with a populated msDS-AllowedToActOnBehalf... blob is a
        S4U2Proxy target - full compromise if the attacker controls (or can add)
        the trusted-from principal. It must land in quick_wins with the trusted
        SID(s) named where recce can extract them."""
        from recce import ad
        from recce.core.models import Host, Domain
        dc = Host(ip="10.0.0.10", roles=["Domain Controller"])
        dom = Domain(name="CORP.LOCAL")
        dom.rbcd_victims = [
            {"name": "FILESRV01", "kind": "computer",
             "trusted_from": ["S-1-5-21-1111-2222-3333-1104"], "attr_len": 116},
            {"name": "svc_delegated", "kind": "user",
             "trusted_from": [], "attr_len": 48},
        ]
        dc.domains = [dom]
        rbcd_rows = [r for r in ad.quick_wins([dc])
                     if r["category"].startswith("RBCD")]
        assert len(rbcd_rows) == 2
        computer_row = next(r for r in rbcd_rows if "FILESRV01" in r["target"])
        assert "computer" in computer_row["target"]
        assert "1104" in computer_row["detail"]
        # An entry with no extracted SID falls back to the blob-length hint,
        # so a malformed SD still produces a usable row.
        user_row = next(r for r in rbcd_rows if "svc_delegated" in r["target"])
        assert "48B" in user_row["detail"]

    def test_sids_in_sd_scan_finds_domain_sids_and_ignores_noise(self):
        """The scanner walks bytes rather than parsing an SD; verify it picks a
        real S-1-5-21-... SID out of a blob and does not confuse random bytes."""
        from recce.ad import _sids_in_sd
        import struct
        # SID: revision(1)=1, subauth_count(1)=5, authority(6)=NT_AUTHORITY(5),
        # 5 x uint32 LE subauths = S-1-5-21-100-200-300-1104
        sid_blob = (b"\x01\x05" + (5).to_bytes(6, "big")
                    + struct.pack("<I", 21)
                    + struct.pack("<I", 100)
                    + struct.pack("<I", 200)
                    + struct.pack("<I", 300)
                    + struct.pack("<I", 1104))
        found = _sids_in_sd(b"\x00" * 8 + sid_blob + b"\xff" * 8)
        assert "S-1-5-21-100-200-300-1104" in found
        assert _sids_in_sd(b"") == [] and _sids_in_sd(b"\x00" * 20) == []

    def test_synthesis_finding_coerce_to_esc8_chain(self):
        """When any host in the engagement exposes MSRPC coercion AND any host
        carries an ADCS ESC8 vuln, the standard "coerce DC$ -> relay to Web
        Enrollment -> DC cert issued" chain is reachable. That belongs in the
        engagement-level quick-wins even though it crosses two subsystems."""
        from recce import ad
        from recce.core.models import Host, Domain, Vuln
        coerce_h = Host(ip="10.0.10.5")
        coerce_h.vulns = [Vuln(ip="10.0.10.5", port=135, protocol="tcp",
            script_id="msrpc:MSRPC exposes authentication-coerc",
            title="MSRPC exposes authentication-coercion interfaces",
            severity="high", state="finding")]
        ca_h = Host(ip="10.0.10.20", roles=["Domain Controller"])
        ca_h.vulns = [Vuln(ip="10.0.10.20", port=80, protocol="tcp",
            script_id="adcs-esc8",
            title="ADCS ESC8: Web/NDES enrolment enabled",
            severity="critical", state="finding")]
        ca_h.domains = [Domain(name="CORP.LOCAL")]
        rows = ad.quick_wins([coerce_h, ca_h])
        chain = next((r for r in rows
                      if "Coerce -> ADCS ESC8" in r["category"]), None)
        assert chain is not None, "chain not synthesised"
        assert "10.0.10.5" in chain["target"] and "10.0.10.20" in chain["target"]
        assert "ntlmrelayx" in chain["why"] or "certipy relay" in chain["why"].lower()

    def test_synthesis_stays_silent_when_only_one_leg_is_present(self):
        """A coercion-capable host on its own must NOT emit the chain row, and
        neither should an ESC8 CA on its own — the finding value is the pair."""
        from recce import ad
        from recce.core.models import Host, Domain, Vuln
        # coerce alone (with a domain-carrying DC that has NO ESC8)
        coerce_h = Host(ip="10.0.10.5")
        coerce_h.vulns = [Vuln(ip="10.0.10.5", port=135, protocol="tcp",
            script_id="msrpc:coerce", title="MSRPC coercion", severity="high",
            state="finding")]
        dc_only = Host(ip="10.0.10.20", roles=["Domain Controller"])
        dc_only.domains = [Domain(name="CORP.LOCAL")]
        rows = ad.quick_wins([coerce_h, dc_only])
        assert not any("Coerce -> ADCS ESC8" in r["category"] for r in rows)

    def test_synthesis_finding_rbcd_to_s4u_chain(self):
        """RBCD victim + attacker-controllable principal (either MAQ>0 or an
        already-known kerberoastable account) = full compromise of the victim
        via S4U2Self -> S4U2Proxy."""
        from recce import ad
        from recce.core.models import Host, Domain
        dc = Host(ip="10.0.10.20", roles=["Domain Controller"])
        dom = Domain(name="CORP.LOCAL")
        dom.rbcd_victims = [{"name": "FILESRV01", "kind": "computer",
                             "trusted_from": ["S-1-5-21-1-2-3-1104"], "attr_len": 116}]
        dom.machine_account_quota = 10
        dc.domains = [dom]
        chain = next((r for r in ad.quick_wins([dc])
                      if "RBCD -> S4U2Proxy" in r["category"]), None)
        assert chain is not None
        assert "FILESRV01" in chain["target"]
        assert "machine-account quota" in chain["detail"]

        # MAQ=0 AND no roastable accounts => the chain does NOT stand on its own
        dom.machine_account_quota = 0
        dc.domains = [dom]
        assert not any("RBCD -> S4U2Proxy" in r["category"]
                       for r in ad.quick_wins([dc]))

    def test_adcs_esc_map_includes_esc16(self):
        """ESC16 is the CA-global variant of the security-extension bypass -
        reachable through ANY enrollable template, not just the ESC9 one."""
        from recce.ad.adcs import _ESC
        assert "ESC16" in _ESC
        sev, title, cmd, remediation = _ESC["ESC16"]
        assert sev == "critical"
        assert "SID" in title or "security extension" in title.lower()
        assert "certipy" in cmd.lower()

    def test_authenticated_accounts_feed_ad_quick_wins(self):
        from recce import ad
        from recce.services import ldap as L
        from recce.core.models import Host
        h = Host(ip="10.0.10.10", hostnames=["dc01"])
        en = {"users": [
            {"sAMAccountName": ["svc_sql"], "servicePrincipalName": ["MSSQL/db"],
             "userAccountControl": ["512"]},
            {"sAMAccountName": ["noPreAuth"], "userAccountControl": ["4194816"]}],
            "computers": [], "domain": {}, "error": None, "bind_dn": "a@b"}
        L.apply_enum(h, "corp.local", "10.0.10.10", 389, en)
        # ad.py's existing derived lists must light up from the LDAP-produced accounts.
        self.assertIn("svc_sql", [a.name for a in ad.kerberoastable([h])])
        self.assertIn("noPreAuth", [a.name for a in ad.asrep_roastable([h])])

    def test_cmd_ldap_authenticated_e2e_persists_accounts(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services import ldap as L
        from recce.core.store import Store

        # This test drives the native BER client end-to-end via a scripted fake server;
        # force the native path (the ldap3-preferred path would connect to the fake
        # server itself and disturb the script).
        _orig_ok = L._ldap3_ok
        L._ldap3_ok = lambda: False
        self.addCleanup(lambda: setattr(L, "_ldap3_ok", _orig_ok))

        def tlv(t, v):
            return bytes([t]) + L._ber_len(len(v)) + v

        def attr(n, vals):
            return tlv(0x30, L._octet(n) + tlv(0x31, b"".join(L._octet(v) for v in vals)))

        def entry(mid, dn, pairs):
            return tlv(0x30, L._int(mid) + tlv(0x64, L._octet(dn)
                       + tlv(0x30, b"".join(attr(n, v) for n, v in pairs))))

        def sdone(mid, cookie=None):
            ctl = b""
            if cookie is not None:
                pv = tlv(0x30, L._int(0) + L._octet(cookie))
                ctl = tlv(0xA0, tlv(0x30, L._octet(L._PAGED_OID) + L._octet(pv)))
            return tlv(0x30, L._int(mid) + tlv(0x65, L._enum(0) + L._octet("")
                       + L._octet("")) + ctl)

        def bind_ok(mid=1):
            return tlv(0x30, L._int(mid) + tlv(0x61, L._enum(0) + L._octet("")
                       + L._octet("")))
        # Connection 1 = the anonymous probe; connection 2 = the authenticated enum.
        probe_script = [
            bind_ok(1),
            entry(2, "", [("defaultNamingContext", ["DC=corp,DC=local"]),
                          ("dnsHostName", ["dc01.corp.local"]),
                          ("domainControllerFunctionality", ["7"])]) + sdone(2),
            entry(3, "DC=corp,DC=local", [("objectClass", ["domain"])]) + sdone(3),
        ]
        enum_script = [
            bind_ok(1),
            entry(10, "CN=svc", [("sAMAccountName", ["svc_web"]),
                                 ("servicePrincipalName", ["HTTP/web"]),
                                 ("userAccountControl", ["512"])]) + sdone(10, b""),
            sdone(1000, b""),
            entry(9000, "DC=corp,DC=local", [("lockoutThreshold", ["5"])]) + sdone(9000),
        ]
        srv, port = self._serve_scripts([probe_script, enum_script])
        orig = L.is_ldap
        L.is_ldap = lambda p: p.state == "open" and (p.portid == port or orig(p))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=port, state="open",
                                                service="ldap")]))
                st.close()
                rc = cli.main(["ldap", "-u", "alice", "-p", "x", "-d", "corp.local",
                               "-o", out])
                self.assertEqual(rc, 0)
                st = Store(os.path.join(out, "results.sqlite"))
                h = st.get_host("127.0.0.1")
                st.close()
                # The authenticated account persisted with its kerberoast SPN.
                ldap_accts = [a for a in h.accounts if a.source == "ldap"]
                self.assertIn("svc_web", [a.name for a in ldap_accts])
                self.assertEqual(next(a for a in ldap_accts
                                      if a.name == "svc_web").attrs["spn"], "HTTP/web")
                # ...and it reached the AD Quick Wins sheet as a Kerberoastable row.
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                qw = "\n".join(" ".join(map(str, r)) for r in sheets["AD Quick Wins"])
                self.assertIn("svc_web", qw)
        finally:
            L.is_ldap = orig
            srv.shutdown()

    def test_cmd_ldap_end_to_end(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services import ldap as L
        from recce.core.store import Store
        orig = L.is_ldap
        L.is_ldap = lambda p: p.state == "open" and (p.portid == self.port or orig(p))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=self.port, state="open",
                                                service="ldap")]))
                st.close()
                self.assertEqual(cli.main(["ldap", "-o", out]), 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("LDAP", sheets)
                vtxt = "\n".join(" ".join(map(str, r))
                                 for r in sheets["Vulnerabilities"])
                self.assertIn("Anonymous LDAP", vtxt)
                st = Store(os.path.join(out, "results.sqlite"))
                h = st.get_host("127.0.0.1")
                st.close()
                self.assertTrue([v for v in h.vulns if v.source == "ldap"])
                # The port recce assessed is auto-ticked vuln-scanned on the Checklist.
                self.assertTrue(h.ports[0].vuln_scanned)
        finally:
            L.is_ldap = orig

    def test_no_endpoints_is_graceful(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.7", ports=[Port(portid=22, service="ssh")]))
            st.close()
            self.assertEqual(cli.main(["ldap", "-o", out, "--no-probe"]), 0)




class FtpTest(unittest.TestCase):
    def _host(self):
        return Host(ip="10.0.0.80", subnet="10.0.0.0/24", hostnames=["FTP01"],
                    os_family="Linux", enumerated=True,
                    ports=[Port(portid=21, service="ftp", product="vsftpd",
                                version="2.3.4", state="open")])

    def test_findings_from_probe(self):
        from recce.services import ftp
        pr = {("10.0.0.80", 21): {"banner": "(vsFTPd 2.3.4)", "anonymous": True,
                                  "auth_tls": False}}
        fs = ftp.findings([self._host()], pr)
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("backdoor", titles.lower())                  # vsftpd 2.3.4
        self.assertIn("Anonymous FTP login", titles)
        self.assertIn("cleartext", titles.lower())
        self.assertTrue(all(f.get("narrative") for f in fs))

    def test_findings_to_vulns_have_classified_cwes(self):
        from recce.services import ftp
        from recce.report.docx import _vuln_type
        pr = {("10.0.0.80", 21): {"banner": "(vsFTPd 2.3.4)", "anonymous": True,
                                  "auth_tls": False}}
        by_ip = ftp.findings_to_vulns(ftp.findings([self._host()], pr))
        self.assertIn("10.0.0.80", by_ip)
        for v in by_ip["10.0.0.80"]:
            vt, _ = _vuln_type(v.cwes)
            self.assertTrue(vt, v.cwes)

    def test_prove_engine_adjudicates_ftp(self):
        from recce.services import ftp
        from recce.vuln import proofs
        pr = {("10.0.0.80", 21): {"banner": "(vsFTPd 2.3.4)", "anonymous": True,
                                  "auth_tls": False}}
        h = self._host()
        h.vulns = ftp.findings_to_vulns(ftp.findings([h], pr))["10.0.0.80"]
        verdicts = {r["vuln"]: r["verdict"] for r in proofs.verify_host(h)}
        anon = next(v for k, v in verdicts.items() if "Anonymous FTP" in k)
        back = next(v for k, v in verdicts.items() if "Backdoor" in k or "RCE FTP" in k)
        self.assertEqual(anon, proofs.CONFIRMED)                   # 230 observed
        self.assertEqual(back, proofs.LIKELY)                      # banner-based

    def test_write_proof_finding(self):
        from recce.services import ftp
        f = ftp.write_proof_finding("10.0.0.80", 21,
                                    {"writable": True, "evidence": "STOR ok\nDELE ok"},
                                    None)
        self.assertIsNotNone(f)
        self.assertIn("proven", f["title"].lower())
        self.assertIn("CWE-732", f["cwes"])
        self.assertIsNone(ftp.write_proof_finding("10.0.0.80", 21,
                                                  {"writable": False}, None))

    def test_multiline_220_banner_reaches_backdoor_match(self):
        # A ProFTPD version on the SECOND 220 line must still be captured + matched.
        import socket
        import threading
        from recce.services import ftp
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def serve():
            try:
                c, _ = srv.accept()
                c.sendall(b"220-Welcome to ACME FTP\r\n220 ProFTPD 1.3.5 Server ready\r\n")
                while True:
                    data = c.recv(1024)
                    if not data:
                        break
                    cmd = data.decode("latin-1", "replace").upper()
                    if cmd.startswith("FEAT"):
                        c.sendall(b"211-Features:\r\n AUTH TLS\r\n211 End\r\n")
                    elif cmd.startswith("USER"):
                        c.sendall(b"331 password please\r\n")
                    elif cmd.startswith("PASS"):
                        c.sendall(b"530 login incorrect\r\n")
                    elif cmd.startswith("SYST"):
                        c.sendall(b"215 UNIX Type: L8\r\n")
                    elif cmd.startswith("QUIT"):
                        c.sendall(b"221 bye\r\n")
                        break
                c.close()
            except OSError:
                pass
        threading.Thread(target=serve, daemon=True).start()
        try:
            pr = ftp.probe("127.0.0.1", port, timeout=3.0)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertIn("ProFTPD 1.3.5", pr["banner"])              # 2nd line captured
        h = Host(ip="127.0.0.1", ports=[Port(portid=21, state="open", service="ftp")])
        fs = ftp.findings([h], {("127.0.0.1", 21): pr})
        self.assertTrue(any("mod_copy" in f["title"].lower() for f in fs))

    def test_cmd_ftp_end_to_end(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(self._host())
            st.close()
            rc = cli.main(["ftp", "-o", out, "--no-run", "--no-probe"])
            self.assertEqual(rc, 0)
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            self.assertIn("FTP", sheets)
            mtxt = "\n".join(" ".join(map(str, r)) for r in sheets["FTP"])
            self.assertIn("10.0.0.80:21", mtxt)
            vtxt = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
            self.assertIn("backdoor", vtxt.lower())                # folded into totals
            st = Store(os.path.join(out, "results.sqlite"))
            h = st.get_host("10.0.0.80")
            st.close()
            self.assertTrue([v for v in h.vulns if v.source == "ftp"])

    def test_no_endpoints_is_graceful(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.7", ports=[Port(portid=22, service="ssh")]))
            st.close()
            self.assertEqual(cli.main(["ftp", "-o", out, "--no-probe", "--no-run"]), 0)




class SmbTest(unittest.TestCase):
    def _host(self):
        return Host(ip="10.0.0.60", subnet="10.0.0.0/24", hostnames=["FS01"],
                    os_family="Windows", enumerated=True,
                    ports=[Port(portid=445, service="microsoft-ds",
                                product="Windows Server 2019", state="open"),
                           Port(portid=80, service="http", state="open")])

    def test_smb2_negotiate_roundtrips(self):
        import struct
        from recce.services import smb
        req = smb._build_smb2_negotiate()
        self.assertEqual(req[4:8], b"\xfeSMB")
        self.assertEqual(struct.unpack(">I", req[:4])[0], len(req) - 4)
        # Synthetic SMB2 negotiate response: 3.1.1, signing NOT required.
        hdr = smb._smb2_header(0x0000, flags=0x00000001)
        body = (struct.pack("<H", 65) + struct.pack("<H", 0x01)   # signing enabled only
                + struct.pack("<H", 0x0311) + struct.pack("<H", 0) + b"\x11" * 16
                + struct.pack("<I", 7) + struct.pack("<I", 0x800000) * 3)
        resp = struct.pack(">I", len(hdr + body)) + hdr + body
        p = smb.parse_smb2_negotiate(resp)
        self.assertEqual(p["dialect_name"], "SMB 3.1.1")
        self.assertFalse(p["signing_required"])
        self.assertTrue(p["signing_enabled"])

    def test_smb1_negotiate_detection(self):
        import struct
        from recce.services import smb
        req = smb._build_smb1_negotiate()
        self.assertEqual(req[4:8], b"\xffSMB")
        # SMBv1 answer with a selected dialect index -> enabled.
        hdr = (b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x98" + b"\x01\x28"
               + b"\x00\x00" + b"\x00" * 8 + b"\x00\x00" + b"\x00\x00" + b"\x2f\x4b"
               + b"\x00\x08" + b"\xc5\x5e")
        body = struct.pack("<B", 17) + struct.pack("<H", 5) + b"\x00" * 30
        resp = struct.pack(">I", len(hdr + body)) + hdr + body
        self.assertTrue(smb.parse_smb1_negotiate(resp)["smbv1"])
        # A server answering SMB2 to the SMB1 negotiate -> SMBv1 off.
        self.assertFalse(smb.parse_smb1_negotiate(
            struct.pack(">I", 8) + b"\xfeSMB" + b"\x00" * 4)["smbv1"])

    def test_findings_from_probe(self):
        from recce.services import smb
        pr = {("10.0.0.60", 445): {"smbv1": True, "signing_required": False,
                                   "signing_enabled": True,
                                   "dialect_name": "SMB 3.1.1"}}
        fs = smb.findings([self._host()], pr)
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("SMBv1", titles)
        self.assertIn("signing not required", titles.lower())
        self.assertTrue(all(f.get("narrative") for f in fs))       # narratives attached

    def test_signing_finding_distinguishes_enabled_but_not_required(self):
        """nxc reports "signing enabled" as a boolean and calls it clean, but a
        host that ADVERTISES signing without REQUIRING it is still a relay
        target. Recce must state which of the two SecurityMode bits (0x01
        SIGN_ENABLED / 0x02 SIGN_REQUIRED) it observed, or a report reader
        can't tell if the finding is real."""
        from recce.services import smb
        # Case 1: enabled=True, required=False — the common misreporting case.
        fs = smb.findings([self._host()], {("10.0.0.60", 445): {
            "signing_enabled": True, "signing_required": False,
            "dialect_name": "SMB 3.1.1"}})
        f = next(f for f in fs if f["kind"] == "smb_signing_not_required")
        assert "SIGN_ENABLED=True" in f["detail"]
        assert "SIGN_REQUIRED=False" in f["detail"]
        assert "available" in f["detail"]           # names the sub-state
        # Case 2: enabled=False, required=False — the legacy fully-off case.
        fs2 = smb.findings([self._host()], {("10.0.0.60", 445): {
            "signing_enabled": False, "signing_required": False,
            "dialect_name": "SMB 2.0.2"}})
        f2 = next(f for f in fs2 if f["kind"] == "smb_signing_not_required")
        assert "SIGN_ENABLED=False" in f2["detail"]
        assert "not offer signing at all" in f2["detail"]
        # Case 3: required=True — no finding at all (the actual clean state).
        fs3 = smb.findings([self._host()], {("10.0.0.60", 445): {
            "signing_enabled": True, "signing_required": True,
            "dialect_name": "SMB 3.1.1"}})
        assert not any(f["kind"] == "smb_signing_not_required" for f in fs3)

    def test_findings_to_vulns_have_classified_cwes(self):
        from recce.services import smb
        from recce.report.docx import _vuln_type
        pr = {("10.0.0.60", 445): {"smbv1": True, "signing_required": False,
                                   "dialect_name": "SMB 3.1.1"}}
        by_ip = smb.findings_to_vulns(smb.findings([self._host()], pr))
        self.assertIn("10.0.0.60", by_ip)
        for v in by_ip["10.0.0.60"]:
            vt, _ = _vuln_type(v.cwes)
            self.assertTrue(vt, v.cwes)                             # every CWE classifies

    def test_prove_engine_adjudicates_smb(self):
        from recce.services import smb
        from recce.vuln import proofs
        pr = {("10.0.0.60", 445): {"smbv1": True, "signing_required": False,
                                   "dialect_name": "SMB 3.1.1"}}
        h = self._host()
        h.vulns = smb.findings_to_vulns(smb.findings([h], pr))["10.0.0.60"]
        h.smb_signing = "not required"
        verdicts = {r["vuln"]: r["verdict"] for r in proofs.verify_host(h)}
        smbv1 = next(v for k, v in verdicts.items() if "SMBv1" in k)
        signing = next(v for k, v in verdicts.items() if "signing" in k.lower())
        self.assertEqual(smbv1, proofs.CONFIRMED)
        self.assertEqual(signing, proofs.CONFIRMED)

    def test_writable_shares_do_not_collapse(self):
        # Two writable shares on one host must survive as two distinct findings/Vulns.
        from recce.services import smb
        f1 = smb.write_proof_finding("10.0.0.60", 445, "data",
                                     {"writable": True, "evidence": "e"}, None)
        f2 = smb.write_proof_finding("10.0.0.60", 445, "backups",
                                     {"writable": True, "evidence": "e"}, None)
        self.assertNotEqual(f1["title"], f2["title"])
        vulns = smb.findings_to_vulns([f1, f2])["10.0.0.60"]
        self.assertEqual(len({v.key for v in vulns}), 2)          # both survive dedup

    def test_writable_share_confirmed_by_prove_engine(self):
        from recce.services import smb
        from recce.vuln import proofs
        f = smb.write_proof_finding("10.0.0.60", 445, "data",
                                    {"writable": True, "evidence": "e"}, None)
        h = Host(ip="10.0.0.60", ports=[Port(portid=445, state="open")],
                 vulns=smb.findings_to_vulns([f])["10.0.0.60"])
        verdicts = [r["verdict"] for r in proofs.verify_host(h)]
        self.assertIn(proofs.CONFIRMED, verdicts)                 # dedicated recipe

    def test_prove_writable_judges_the_put_and_cleans_up(self):
        from recce.services import smb
        orig_tool, orig_run = smb.smbclient_tool, smb._run
        smb.smbclient_tool = lambda: "/usr/bin/smbclient"
        try:
            # Success: put lands, delete is silent -> writable + cleaned up.
            smb._run = lambda cmd, timeout=60: (
                "putting file /tmp/x as \\recce_smb_probe.txt (10.0 kb/s)\n"
                "  recce_smb_probe.txt\n", None)
            r = smb.prove_writable("1.2.3.4", "data", None)
            self.assertTrue(r["writable"])
            self.assertTrue(r["cleanup_ok"])
            # Write lands but the in-script delete is DENIED -> still writable, and a
            # second explicit delete is attempted (cleanup retried).
            calls = []

            def run_deldenied(cmd, timeout=60):
                calls.append(cmd)
                if len(calls) == 1:
                    return ("putting file /tmp/x as \\recce_smb_probe.txt (9 kb/s)\n"
                            "NT_STATUS_ACCESS_DENIED deleting remote file "
                            "\\recce_smb_probe.txt\n", None)
                return ("", None)                                 # explicit retry del
            smb._run = run_deldenied
            r = smb.prove_writable("1.2.3.4", "data", None)
            self.assertTrue(r["writable"])
            self.assertEqual(len(calls), 2)                       # cleanup retried
            # Put refused -> not writable (no false positive from a trailing marker).
            smb._run = lambda cmd, timeout=60: (
                "NT_STATUS_ACCESS_DENIED opening remote file "
                "\\recce_smb_probe.txt\n", None)
            self.assertFalse(smb.prove_writable("1.2.3.4", "data", None)["writable"])
        finally:
            smb.smbclient_tool, smb._run = orig_tool, orig_run

    def test_null_session_findings(self):
        from recce.services import smb
        session = {"ran": True, "error": None,
                   "shares": [{"name": "backups", "perms": "READ"},
                              {"name": "IPC$", "perms": "READ"}],
                   "users": [{"domain": "CORP", "name": "alice"}]}
        fs = smb.null_session_findings("10.0.0.60", 445, session)
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("null / anonymous session", titles)
        self.assertIn("readable without credentials", titles)       # backups (not IPC$)

    def test_cmd_smb_end_to_end(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            h = self._host()
            h.ports[0].scripts = [Script(id="smb-vuln-ms17-010",
                                         output="VULNERABLE: MS17-010")]
            st.upsert_host(h)
            st.close()
            # --no-probe (no live socket in CI); feed a synthetic probe via meta? No -
            # instead assert the sheet renders and the runbook is creds-filled.
            rc = cli.main(["smb", "-o", out, "--no-run", "--no-probe",
                           "-u", "alice", "-p", "P@ss", "-d", "corp.local"])
            self.assertEqual(rc, 0)
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            self.assertIn("SMB", sheets)
            mtxt = "\n".join(" ".join(map(str, r)) for r in sheets["SMB"])
            self.assertIn("10.0.0.60:445", mtxt)
            self.assertIn("corp.local", mtxt)                       # runbook creds-filled

    def test_no_endpoints_is_graceful(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.7", ports=[Port(portid=25, service="smtp")]))
            st.close()
            self.assertEqual(cli.main(["smb", "-o", out, "--no-probe", "--no-run"]), 0)




class MssqlTest(unittest.TestCase):
    def _host(self):
        from recce.core.models import Vuln
        return Host(ip="10.0.0.50", subnet="10.0.0.0/24", hostnames=["SQL01"],
                    os_family="Windows", enumerated=True,
                    ports=[Port(portid=1433, service="ms-sql-s",
                                product="Microsoft SQL Server", version="12.0.2000",
                                state="open",
                                scripts=[Script(id="ms-sql-ntlm-info",
                                                output="NetBIOS_Domain_Name: CORP")])],
                    vulns=[Vuln(ip="10.0.0.50", port=1433, protocol="tcp",
                                script_id="ms-sql-empty-password",
                                title="MSSQL sa empty password", severity="critical",
                                source="nse")])

    def test_sql_browser_parse(self):
        from recce.services.db import mssql
        insts = mssql._parse_browser(
            "ServerName;WINSQL;InstanceName;SQLEXPRESS;IsClustered;No;"
            "Version;15.0.2000.5;tcp;1433;;")
        self.assertEqual(insts[0]["instance"], "SQLEXPRESS")
        self.assertEqual(insts[0]["tcp"], "1433")
        self.assertEqual(insts[0]["version"], "15.0.2000.5")

    def test_prelogin_request_is_wellformed_and_response_parses(self):
        import struct
        from recce.services.db import mssql
        req = mssql._build_prelogin()
        self.assertEqual(req[0], 0x12)                              # PRELOGIN type
        self.assertEqual(struct.unpack(">H", req[2:4])[0], len(req))  # length field
        # Synthetic response: SQL 2019, encryption required.
        table = struct.pack(">BHH", 0x00, 11, 6) + struct.pack(">BHH", 0x01, 17, 1) + b"\xff"
        data = bytes([15, 0]) + struct.pack(">H", 2000) + b"\x00\x00" + bytes([3])
        payload = table + data
        resp = struct.pack(">BBHHBB", 0x04, 0x01, 8 + len(payload), 0, 0, 0) + payload
        p = mssql._parse_prelogin(resp)
        self.assertEqual(p["version"], "15.0.2000")
        self.assertEqual(p["encryption"], "required")
        self.assertIn("SQL Server 2019", mssql.version_name(p["version"]))

    def test_findings_from_nse_and_version(self):
        from recce.services.db import mssql
        fs = mssql.findings([self._host()])
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("blank password", titles)                    # ms-sql-empty-password
        self.assertIn("End-of-life", titles)                       # 12.x = 2014
        self.assertIn("NetBIOS", titles)                           # ms-sql-ntlm-info
        blank = next(f for f in fs if "blank password" in f["title"])
        self.assertEqual(blank["severity"], "critical")
        self.assertIn("impacket-mssqlclient", blank["command"])

    def test_runbook_commands_prefilled_with_creds(self):
        from recce.services.db import mssql
        an = mssql.analyze([self._host()], creds={"user": "alice", "secret": "P@ss",
                           "domain": "corp.local", "dc_ip": "10.0.0.9"}, active=False)
        cmds = " ".join(s["cmd"] for s in an["runbooks"][0]["credentialed"])
        self.assertIn("nxc mssql 10.0.0.50 -u alice -p P@ss", cmds)
        self.assertIn("corp.local/alice:P@ss@10.0.0.50", cmds)     # mssqlclient target
        self.assertIn("OPENQUERY", cmds)                           # linked-server chain
        self.assertIn("EXECUTE AS LOGIN", cmds)                    # impersonation chain

    def test_parse_nxc_mssql(self):
        from recce.services.db import mssql
        r = mssql.parse_nxc_mssql("MSSQL 10.0.0.50 1433 SQL01 [+] CORP\\alice:P@ss (Pwn3d!)")
        self.assertTrue(r["access"] and r["admin"])
        r2 = mssql.parse_nxc_mssql("MSSQL 10.0.0.50 1433 SQL01 [-] CORP\\bob:x")
        self.assertFalse(r2["access"])

    def test_findings_to_vulns_have_classified_cwes(self):
        from recce.services.db import mssql
        from recce.report.docx import _vuln_type
        fs = mssql.findings([self._host()])
        by_ip = mssql.findings_to_vulns(fs)
        self.assertIn("10.0.0.50", by_ip)
        for v in by_ip["10.0.0.50"]:
            vt, _ = _vuln_type(v.cwes)
            self.assertTrue(vt, v.cwes)                            # every CWE classifies

    def test_cmd_mssql_end_to_end(self):
        from recce import cli
        from recce.report.formats import xlsx
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(self._host())
            st.close()
            rc = cli.main(["mssql", "-o", out, "--no-run", "--no-probe",
                           "-u", "alice", "-p", "P@ss", "-d", "corp.local",
                           "--lhost", "10.0.0.9"])
            self.assertEqual(rc, 0)
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            self.assertIn("MSSQL", sheets)
            mtxt = "\n".join(" ".join(map(str, r)) for r in sheets["MSSQL"])
            self.assertIn("10.0.0.50:1433", mtxt)
            self.assertIn("corp.local/alice:P@ss", mtxt)           # runbook creds-filled
            vtxt = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
            self.assertIn("blank password", vtxt)                  # folded into main totals
            st = Store(os.path.join(out, "results.sqlite"))
            h = st.get_host("10.0.0.50")
            st.close()
            self.assertTrue([v for v in h.vulns if v.source == "mssql"])

    def test_no_endpoints_is_graceful(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.7", ports=[Port(portid=80, service="http")]))
            st.close()
            self.assertEqual(cli.main(["mssql", "-o", out, "--no-probe"]), 0)

    _LIVE = ("SQL (CORP\\alice guest@master)>\n"
             "@@B:server\nSQL01|CORP\\alice|0|1|15.0.2000.5\n@@E:server\n"
             "@@B:logins\nsa|1\nCORP\\alice|0\n@@E:logins\n"
             "@@B:databases\nmaster|0|sa\npayroll|1|sa\nappdb|0|CORP\\svc\n@@E:databases\n"
             "@@B:links\nDW01|SQL Server|dw01.corp.local\n@@E:links\n"
             "@@B:impersonate\nsa|1\n@@E:impersonate\n"
             "@@B:config\nxp_cmdshell|1\n@@E:config\n"
             "@@B:hashes\nsa|0x0200ABCD\n@@E:hashes\n")

    def test_parse_enum_extracts_sections(self):
        from recce.services.db import mssql
        e = mssql.parse_enum(self._LIVE)
        self.assertEqual(e["server"][0][0], "SQL01")
        self.assertEqual([r for r in e["logins"] if r[1] == "1"][0][0], "sa")
        self.assertEqual([r[0] for r in e["databases"] if r[1] == "1"], ["payroll"])
        self.assertEqual(e["links"][0][0], "DW01")

    def test_build_enum_script_wraps_sentinels(self):
        from recce.services.db import mssql
        script = mssql.build_enum_script()
        self.assertIn("@@B:databases", script)
        self.assertIn("@@E:impersonate", script)
        self.assertTrue(script.strip().endswith("exit"))

    def test_chains_from_enum_detects_concrete_chain(self):
        from recce.services.db import mssql
        e = mssql.parse_enum(self._LIVE)
        t = {"ip": "10.0.0.50", "port": 1433}
        fs, chain, summary = mssql.chains_from_enum(
            t, e, {"user": "alice", "secret": "P@ss", "domain": "corp.local"})
        joined = " -> ".join(chain)
        self.assertIn("impersonate sysadmin login 'sa'", joined)
        self.assertIn("TRUSTWORTHY db 'payroll'", joined)
        self.assertIn("hop linked server(s) DW01", joined)
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("Impersonatable sysadmin login", titles)
        self.assertIn("TRUSTWORTHY database owned by a sysadmin", titles)
        self.assertIn("linked server(s) reachable", titles)
        self.assertIn("SQL login password hash", titles)
        # A concrete command with the real db name filled in.
        tw = next(f for f in fs if "TRUSTWORTHY database" in f["title"])
        self.assertIn("USE [payroll]", tw["command"])

    def test_chains_direct_sysadmin(self):
        from recce.services.db import mssql
        e = mssql.parse_enum(
            "@@B:server\nSQL01|sa|1|0|15.0.2000.5\n@@E:server\n"
            "@@B:logins\nsa|1\n@@E:logins\n")
        t = {"ip": "10.0.0.50", "port": 1433}
        fs, chain, summary = mssql.chains_from_enum(t, e, {"user": "sa", "secret": "x"})
        self.assertTrue(summary["is_sysadmin"])
        self.assertTrue(t["admin"])
        self.assertIn("already sysadmin", chain[0])
        self.assertTrue(any("sysadmin on this MSSQL" in f["title"] for f in fs))

    def test_nested_exec_at_quote_doubling(self):
        from recce.services.db import mssql
        self.assertEqual(mssql._nested_at(["DW01"], "SELECT 1"),
                         "EXEC ('SELECT 1') AT [DW01]")
        d2 = mssql._nested_at(["DW01", "DW02"], "SELECT x+'|'+y")
        # inner quotes double once per hop (quadruple at depth 2).
        self.assertEqual(d2, "EXEC ('EXEC (''SELECT x+''''|''''+y'') AT [DW02]') AT [DW01]")
        self.assertEqual(mssql._nested_at([], "SELECT 1"), "SELECT 1")

    def test_walk_links_bfs_with_cycle(self):
        from recce.services.db import mssql
        calls = {"n": 0}

        def fake(script):
            calls["n"] += 1
            if calls["n"] == 1:                                 # entry -> DW01 (not sa)
                return "@@L:0\nDW01SRV|CORP\\svc|0|DW02\n@@LE:0\n"
            if calls["n"] == 2:                                 # DW01 -> DW02 (sa), loops back
                return "@@L:0\nDW02SRV|sa|1|DW01\n@@LE:0\n"
            return ""
        nodes = mssql.walk_links(["DW01"], fake, max_depth=5)
        self.assertEqual(len(nodes), 2)
        self.assertEqual(nodes[0]["server"], "DW01SRV")
        self.assertTrue(nodes[1]["sysadmin"])
        self.assertEqual(nodes[1]["path"], ["DW01", "DW02"])
        self.assertEqual(calls["n"], 2)                         # cycle stopped the walk

    def test_walk_links_respects_depth_bound(self):
        from recce.services.db import mssql
        calls = {"n": 0}

        def fake(script):                                       # each hop leads to a NEW server
            calls["n"] += 1
            n = calls["n"]
            return f"@@L:0\nSRV{n}|u|0|L{n + 1}\n@@LE:0\n"
        nodes = mssql.walk_links(["L1"], fake, max_depth=3)
        self.assertEqual(max(n["depth"] for n in nodes), 3)     # walked exactly to the bound
        self.assertEqual(calls["n"], 3)                         # and stopped there

    def test_link_findings_flag_sysadmin_node_with_rce(self):
        from recce.services.db import mssql
        nodes = [{"path": ["DW01"], "depth": 1, "server": "DW01SRV",
                  "login": "CORP\\svc", "sysadmin": False, "links": ["DW02"]},
                 {"path": ["DW01", "DW02"], "depth": 2, "server": "DW02SRV",
                  "login": "sa", "sysadmin": True, "links": []}]
        t = {"ip": "10.0.0.50", "port": 1433, "live_login": "CORP\\alice"}
        fs, chain = mssql.link_findings(t, nodes, {"user": "alice"})
        crit = next(f for f in fs if "SYSADMIN on DW02SRV" in f["title"])
        self.assertEqual(crit["severity"], "critical")
        self.assertIn("xp_cmdshell", crit["command"])           # nested RCE command
        self.assertIn("AT [DW01]", crit["command"])             # walks through the chain
        self.assertIn("DW01 -> DW02", " ".join(chain))

    def test_linked_server_walk_flows_into_sheet_and_totals(self):
        from unittest import mock
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services.db import mssql
        from recce.core.store import Store
        enum = mssql.parse_enum(
            "@@B:server\nSQL01|CORP\\alice|0|1|15.0.2000.5\n@@E:server\n"
            "@@B:logins\nsa|1\n@@E:logins\n@@B:databases\nmaster|0|sa\n@@E:databases\n"
            "@@B:links\nDW01|SQL Server|dw01\n@@E:links\n"
            "@@B:impersonate\n@@E:impersonate\n@@B:config\nxp_cmdshell|0\n@@E:config\n"
            "@@B:hashes\n@@E:hashes\n")
        lvl = {"n": 0}

        def runner_factory(*a, **k):
            def run(script):
                lvl["n"] += 1
                if lvl["n"] == 1:
                    return "@@L:0\nDW01SRV|CORP\\svc|0|DW02\n@@LE:0\n"
                if lvl["n"] == 2:
                    return "@@L:0\nDW02SRV|sa|1|DW01\n@@LE:0\n"
                return ""
            return run
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(self._host())
            st.close()
            with mock.patch.object(mssql, "mssqlclient_tool", return_value="x"), \
                    mock.patch.object(mssql, "nxc_tool", return_value=None), \
                    mock.patch.object(mssql, "run_mssqlclient", return_value=(enum, None)), \
                    mock.patch.object(mssql, "link_runner", side_effect=runner_factory):
                rc = cli.main(["mssql", "-o", out, "--no-probe",
                               "-u", "alice", "-p", "P@ss", "-d", "corp.local"])
            self.assertEqual(rc, 0)
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            m = "\n".join(" ".join(map(str, r)) for r in sheets["MSSQL"])
            self.assertIn("Linked-server chain:", m)
            self.assertIn("Linked-server graph", m)
            self.assertIn("DW02SRV", m)
            v = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
            self.assertIn("chain to SYSADMIN on DW02SRV", v)     # in the main totals

    def test_verify_dbowner_confirms_and_guards_context(self):
        from recce.services.db import mssql
        # db_owner=1 and DB_NAME() matches -> confirmed.
        ok = mssql.parse_dbowner("@@DBO:0\n1|payroll\n@@DBOE:0\n", ["payroll"])
        self.assertTrue(ok["payroll"])
        # db_owner=1 but a failed USE left us in another db -> NOT confirmed.
        bad = mssql.parse_dbowner("@@DBO:0\n1|master\n@@DBOE:0\n", ["payroll"])
        self.assertFalse(bad["payroll"])
        # db_owner=0 -> not confirmed.
        no = mssql.parse_dbowner("@@DBO:0\n0|payroll\n@@DBOE:0\n", ["payroll"])
        self.assertFalse(no["payroll"])

    def test_trustworthy_chain_confirmed_vs_candidate(self):
        from recce.services.db import mssql
        enum = mssql.parse_enum(
            "@@B:server\nSQL01|CORP\\alice|0|1|15.0.2000.5\n@@E:server\n"
            "@@B:logins\nsa|1\n@@E:logins\n"
            "@@B:databases\npayroll|1|sa\n@@E:databases\n"
            "@@B:links\n@@E:links\n@@B:impersonate\n@@E:impersonate\n"
            "@@B:config\n@@E:config\n@@B:hashes\n@@E:hashes\n")
        t = {"ip": "10.0.0.50", "port": 1433}
        # Candidate (no verification): high.
        fs, _c, _s = mssql.chains_from_enum(t, enum, {"user": "alice"})
        tw = next(f for f in fs if "TRUSTWORTHY" in f["title"])
        self.assertEqual(tw["severity"], "high")
        # Verified db_owner: critical + CONFIRMED wording.
        fs2, _c2, s2 = mssql.chains_from_enum(t, enum, {"user": "alice"},
                                              dbo_map={"payroll": True})
        tw2 = next(f for f in fs2 if "CONFIRMED privesc" in f["title"])
        self.assertEqual(tw2["severity"], "critical")
        self.assertEqual(s2["dbowner_confirmed"], ["payroll"])
        # Verified NOT db_owner: no trustworthy finding at all.
        fs3, _c3, _s3 = mssql.chains_from_enum(t, enum, {"user": "alice"},
                                               dbo_map={"payroll": False})
        self.assertFalse([f for f in fs3 if "TRUSTWORTHY" in f["title"]
                          or "CONFIRMED" in f["title"]])

    def test_server_level_deep_checks(self):
        from recce.services.db import mssql
        enum = mssql.parse_enum(
            "@@B:server\nSQL01|CORP\\alice|0|0|15.0.2000.5\n@@E:server\n"
            "@@B:logins\nsa|1\n@@E:logins\n@@B:databases\nmaster|0|sa\n@@E:databases\n"
            "@@B:links\n@@E:links\n@@B:impersonate\n@@E:impersonate\n@@B:config\n@@E:config\n"
            "@@B:hashes\n@@E:hashes\n@@B:credentials\n@@E:credentials\n@@B:proxies\n@@E:proxies\n"
            "@@B:linkedlogins\n@@E:linkedlogins\n"
            "@@B:serverperms\nCONNECT SQL|GRANT\nIMPERSONATE ANY LOGIN|GRANT\n@@E:serverperms\n"
            "@@B:publicserver\nALTER ANY LOGIN|GRANT\n@@E:publicserver\n"
            "@@B:startup\nsp_backdoor|startup\n@@E:startup\n")
        fs, chain, summary = mssql.chains_from_enum(
            {"ip": "10.0.0.50", "port": 1433}, enum, {"user": "alice"})
        kinds = {f["kind"] for f in fs}
        self.assertIn("mixed_mode", kinds)                       # IsIntegratedSecurityOnly=0
        self.assertIn("server_perms", kinds)                     # IMPERSONATE ANY LOGIN
        self.assertIn("public_role", kinds)                      # ALTER ANY LOGIN to public
        self.assertIn("startup_proc", kinds)                     # sp_backdoor
        sp = next(f for f in fs if f["kind"] == "server_perms")
        self.assertEqual(sp["severity"], "high")
        self.assertIn("IMPERSONATE ANY LOGIN", sp["detail"])
        self.assertIn("abuse server permission(s) IMPERSONATE ANY LOGIN", " -> ".join(chain))
        # public ALTER ANY LOGIN is a dangerous perm -> high.
        self.assertEqual(next(f for f in fs if f["kind"] == "public_role")["severity"], "high")
        self.assertTrue(summary["mixed_mode"])
        self.assertEqual(summary["public_server"], ["ALTER ANY LOGIN"])

    def test_permission_mining_guest_and_public_grants(self):
        from recce.services.db import mssql
        dbs = ["master", "payroll", "hr"]
        script = mssql.build_permmine_script(dbs)
        self.assertIn("USE [payroll]", script)
        self.assertIn("guest", script.lower())
        out = ("@@GST:1\npayroll|guest_enabled\n@@GSTE:1\n"
               "@@PBP:1\npayroll|public|SELECT|dbo.Salaries\npayroll|guest|EXECUTE|dbo.sp_Pay\n@@PBPE:1\n"
               "@@GST:2\n@@GSTE:2\n@@PBP:2\nhr|public|SELECT|dbo.Employees\n@@PBPE:2\n")
        perms = mssql.parse_permmine(out, dbs)
        self.assertTrue(perms["payroll"]["guest"])
        self.assertFalse(perms["hr"]["guest"])
        self.assertIn(("guest", "EXECUTE", "dbo.sp_Pay"), perms["payroll"]["grants"])
        fs = mssql.permmine_findings({"ip": "10.0.0.50", "port": 1433}, perms, {"user": "a"})
        kinds = {f["kind"] for f in fs}
        self.assertIn("guest_enabled", kinds)
        obj = next(f for f in fs if f["kind"] == "object_perms")
        self.assertEqual(obj["severity"], "high")                # EXECUTE = write/execute
        self.assertIn("dbo.sp_Pay", obj["detail"])

    def test_permmine_context_guard(self):
        from recce.services.db import mssql
        # Rows tagged with the wrong DB_NAME (failed USE) are rejected.
        out = "@@GST:0\nmaster|guest_enabled\n@@GSTE:0\n@@PBP:0\n@@PBPE:0\n"
        perms = mssql.parse_permmine(out, ["payroll"])
        self.assertFalse(perms["payroll"]["guest"])

    def test_proof_screenshot_html_and_gating(self):
        from recce import cli
        from recce.services.db import mssql
        from types import SimpleNamespace
        html = mssql.proof_html(["EXEC xp_cmdshell 'whoami'"], "nt service\\mssql <b>x</b>",
                                banner="impacket-mssqlclient alice@10.0.0.50")
        # A faithful terminal render: the real command at a SQL> prompt, verbatim
        # output, and NO recce branding/badge.
        self.assertIn("SQL&gt;", html)
        self.assertIn("EXEC xp_cmdshell", html)
        self.assertIn("impacket-mssqlclient alice@10.0.0.50", html)  # console banner
        self.assertIn("&lt;b&gt;", html)                         # output is HTML-escaped
        self.assertNotIn("PROOF", html)                          # no manufactured badge
        self.assertNotIn(">recce<", html)                        # unbranded
        # Multiple command lines each get a prompt.
        multi = mssql.proof_html(["CREATE TABLE ##x (...)", "DROP TABLE ##x"], "")
        self.assertEqual(multi.count("SQL&gt;"), 3)              # 2 commands + trailing prompt
        # _mssql_shot is a no-op unless --screenshots is set.
        self.assertIsNone(cli._mssql_shot(
            SimpleNamespace(screenshots=False), "10.0.0.50", "n", "b", "c", "o"))

    def test_datamine_finds_tables_and_sensitive_columns(self):
        from recce.services.db import mssql
        dbs = ["master", "payroll", "appdb"]
        script = mssql.build_datamine_script(dbs)
        self.assertIn("USE [payroll]", script)
        self.assertIn("c.name LIKE '%ssn%'", script)             # interesting-column filter
        out = ("@@TBL:1\npayroll|dbo.Employees|1240\npayroll|dbo.Salaries|1240\n@@TBLE:1\n"
               "@@COL:1\npayroll|dbo.Employees.ssn\npayroll|dbo.Employees.email\n@@COLE:1\n"
               "@@TBL:2\nappdb|dbo.Users|55\n@@TBLE:2\n"
               "@@COL:2\nappdb|dbo.Users.password_hash\n@@COLE:2\n")
        mined = mssql.parse_datamine(out, dbs)
        self.assertEqual(mined["payroll"]["tables"],
                         [("dbo.Employees", "1240"), ("dbo.Salaries", "1240")])
        self.assertIn("dbo.Employees.ssn", mined["payroll"]["interesting"])
        fs = mssql.datamine_findings({"ip": "10.0.0.50", "port": 1433}, mined,
                                     {"user": "alice"})
        f = fs[0]
        self.assertEqual(f["severity"], "high")                  # sensitive data present
        self.assertEqual(f["kind"], "data_at_rest")
        self.assertIn("ssn", f["detail"])
        self.assertIn("Users", f["detail"])                      # interesting table name
        self.assertGreater(len(f["narrative"]), 120)

    def test_datamine_context_guard_rejects_wrong_db(self):
        from recce.services.db import mssql
        # A failed USE leaves rows tagged with the wrong DB_NAME -> not attributed.
        out = "@@TBL:0\nmaster|dbo.x|1\n@@TBLE:0\n@@COL:0\n@@COLE:0\n"
        mined = mssql.parse_datamine(out, ["payroll"])
        self.assertEqual(mined["payroll"]["tables"], [])         # 'master' != 'payroll'

    def test_write_proof_is_reversible_and_evidenced(self):
        from recce.services.db import mssql
        s = mssql.build_write_proof_script("ab12cd")
        # Proves create/insert/update AND reverts everything.
        self.assertIn("CREATE TABLE ##recce_ab12cd", s)
        self.assertIn("UPDATE ##recce_ab12cd SET note='MODIFIED_ab12cd'", s)
        self.assertIn("DROP TABLE ##recce_ab12cd", s)            # reverted
        self.assertIn("ALTER SERVER ROLE dbcreator ADD MEMBER recce_ab12cd", s)
        self.assertIn("DROP LOGIN recce_ab12cd", s)              # reverted
        ev = mssql.parse_write_proof(
            "@@W:begin\nINSERT|before\nUPDATE|MODIFIED_ab12cd\nPERM|1\n@@W:end\n")
        self.assertEqual(ev["update"], "MODIFIED_ab12cd")
        self.assertEqual(ev["perm"], "1")
        f = mssql.write_proof_finding({"ip": "10.0.0.50", "port": 1433}, ev, {"user": "a"})
        self.assertEqual(f["severity"], "critical")
        self.assertIn("reverted", f["detail"])
        self.assertIn("role", f["detail"])

    def test_write_proof_requires_actual_modification(self):
        from recce.services.db import mssql
        from unittest import mock
        # If UPDATE didn't round-trip, prove_write reports failure (no false claim).
        with mock.patch.object(mssql, "_mssqlclient_cmd", return_value=["x"]), \
                mock.patch.object(mssql, "_run_stdin", return_value=("@@W:begin\n@@W:end\n", None)):
            ev, err = mssql.prove_write("10.0.0.50", {"user": "a", "secret": "b"}, "tok")
        self.assertIsNone(ev)
        self.assertIn("not proven", err)

    def test_data_and_prove_write_flow_into_totals(self):
        from unittest import mock
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services.db import mssql
        from recce.core.store import Store
        enum = mssql.parse_enum(
            "@@B:server\nSQL01|sa|1|0|15.0.2000.5\n@@E:server\n@@B:logins\nsa|1\n@@E:logins\n"
            "@@B:databases\nmaster|0|sa\npayroll|0|sa\n@@E:databases\n@@B:links\n@@E:links\n"
            "@@B:impersonate\n@@E:impersonate\n@@B:config\n@@E:config\n@@B:hashes\n@@E:hashes\n"
            "@@B:credentials\n@@E:credentials\n@@B:proxies\n@@E:proxies\n"
            "@@B:linkedlogins\n@@E:linkedlogins\n")

        def runner_factory(*a, **k):
            def run(script):
                if "@@TBL:" in script:                          # dbs order: [master, payroll]
                    return ("@@TBL:0\nmaster|dbo.spt_values|1\n@@TBLE:0\n@@COL:0\n@@COLE:0\n"
                            "@@TBL:1\npayroll|dbo.Employees|1240\n@@TBLE:1\n"
                            "@@COL:1\npayroll|dbo.Employees.ssn\n@@COLE:1\n")
                return ""
            return run
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(self._host())
            st.close()
            with mock.patch.object(mssql, "mssqlclient_tool", return_value="x"), \
                    mock.patch.object(mssql, "nxc_tool", return_value=None), \
                    mock.patch.object(mssql, "run_mssqlclient", return_value=(enum, None)), \
                    mock.patch.object(mssql, "link_runner", side_effect=runner_factory), \
                    mock.patch.object(mssql, "prove_write",
                                      return_value=({"insert": "before", "update": "MODIFIED_x",
                                                     "perm": "1"}, None)):
                rc = cli.main(["mssql", "-o", out, "--no-probe", "--no-links",
                               "--data", "--prove-write",
                               "-u", "alice", "-p", "P@ss", "-d", "corp.local"])
            self.assertEqual(rc, 0)
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            v = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
            self.assertIn("Sensitive data accessible", v)
            self.assertIn("Proved write + permission-modify", v)
            m = "\n".join(" ".join(map(str, r)) for r in sheets["MSSQL"])
            self.assertIn("SENSITIVE COLUMNS", m)

    def test_findings_carry_detailed_narratives(self):
        from recce.services.db import mssql
        # A rich enum that exercises many finding kinds.
        enum = mssql.parse_enum(
            "@@B:server\nSQL01|CORP\\alice|0|1|12.0.2000.5\n@@E:server\n"
            "@@B:logins\nsa|1\n@@E:logins\n@@B:databases\npayroll|1|sa\n@@E:databases\n"
            "@@B:links\nDW01|SQL Server|dw01\n@@E:links\n@@B:impersonate\nsa|1\n@@E:impersonate\n"
            "@@B:config\nxp_cmdshell|1\n@@E:config\n@@B:hashes\nsa|0x0200AB\n@@E:hashes\n"
            "@@B:credentials\nAppCred|CORP\\svc\n@@E:credentials\n@@B:proxies\n@@E:proxies\n"
            "@@B:linkedlogins\nDW01|sa|0\n@@E:linkedlogins\n")
        fs, _c, _s = mssql.chains_from_enum(
            t := {"ip": "10.0.0.50", "port": 1433}, enum,
            {"user": "alice", "secret": "P@ss", "domain": "corp.local"})
        _ = t
        # Every finding must carry a substantial narrative and a kind.
        for f in fs:
            self.assertTrue(f.get("kind"), f["title"])
            self.assertGreater(len(f.get("narrative", "")), 120, f["title"])
        # The xp_cmdshell narrative explains its real capability in detail.
        xp = next(f for f in fs if f["kind"] == "xp_cmdshell")
        for phrase in ("service account", "SeImpersonate", "SYSTEM", "LSASS"):
            self.assertIn(phrase, xp["narrative"])

    def test_narrative_folds_into_vuln_evidence(self):
        from recce.services.db import mssql
        fs = mssql.findings([self._host()])
        by_ip = mssql.findings_to_vulns(fs)
        blob = "\n".join(v.output for v in by_ip["10.0.0.50"])
        self.assertIn("What this enables", blob)                # narrative in evidence

    def test_testing_methodology_narrative(self):
        from recce.services.db import mssql
        phases = [p for p, _t in mssql.TESTING_NARRATIVE]
        self.assertTrue(any("Discovery" in p for p in phases))
        self.assertTrue(any("Escalation" in p for p in phases))
        self.assertEqual(len(mssql.TESTING_NARRATIVE), 6)
        # Each phase has a real explanation.
        for _p, text in mssql.TESTING_NARRATIVE:
            self.assertGreater(len(text), 100)

    def test_credential_and_linked_login_secret_extraction(self):
        from recce.services.db import mssql
        from recce.report.docx import _vuln_type
        enum = mssql.parse_enum(
            "@@B:server\nSQL01|CORP\\alice|0|1|15.0.2000.5\n@@E:server\n"
            "@@B:logins\nsa|1\n@@E:logins\n@@B:databases\nmaster|0|sa\n@@E:databases\n"
            "@@B:links\nDW01|SQL Server|dw01\n@@E:links\n@@B:impersonate\n@@E:impersonate\n"
            "@@B:config\n@@E:config\n@@B:hashes\n@@E:hashes\n"
            "@@B:credentials\nAppCred|CORP\\svc_backup\n@@E:credentials\n"
            "@@B:proxies\nDeployProxy|CORP\\svc_deploy\n@@E:proxies\n"
            "@@B:linkedlogins\nDW01|sa|0\nRPT01|reader|1\n@@E:linkedlogins\n")
        t = {"ip": "10.0.0.50", "port": 1433}
        fs, chain, summary = mssql.chains_from_enum(
            t, enum, {"user": "alice", "secret": "P@ss", "domain": "corp.local"})
        cred = next(f for f in fs if "stored SQL credential" in f["title"])
        self.assertIn("CORP\\svc_backup", cred["detail"])              # the stored account
        self.assertIn("DeployProxy", cred["detail"])                   # agent proxy shown
        self.assertIn("Get-SQLCredential", cred["command"])            # extraction command
        # Fixed linked login mapping to sa -> critical + decrypt command.
        link = next(f for f in fs if "stored fixed login" in f["title"])
        self.assertEqual(link["severity"], "critical")                # maps to sa
        self.assertIn("Get-SQLServerLinkedServerLogin", link["command"])
        self.assertIn("DW01->sa", " ".join(chain))
        # Self-mapping (uses_self_credential=1) is NOT flagged as a stored secret.
        self.assertEqual(summary["linkedlogins"], ["DW01->sa [fixed]", "RPT01->reader"])
        # CWEs classify (keeps the coverage test green + gives writeups a type).
        for f in (cred, link):
            vt, _ = _vuln_type(f["cwes"])
            self.assertTrue(vt, f["cwes"])

    def test_exec_script_builders_per_method(self):
        from recce.services.db import mssql
        xp = mssql.build_exec_script("whoami", "xp")
        self.assertIn("EXEC xp_cmdshell 'whoami'", xp)
        self.assertIn("sp_configure 'xp_cmdshell',1", xp)
        ole = mssql.build_exec_script("whoami", "ole")
        self.assertIn("sp_OACreate 'WScript.Shell'", ole)
        self.assertIn("OPENROWSET(BULK", ole)              # reads output back
        agent = mssql.build_exec_script("whoami", "agent")
        self.assertIn("sp_add_job", agent)
        self.assertIn("@subsystem='CmdExec'", agent)
        self.assertIn("sp_delete_job", agent)              # cleans up after itself
        self.assertIsNone(mssql.build_exec_script("x", "clr"))
        # A single quote in the command is doubled for the T-SQL literal.
        self.assertIn("echo ''hi''", mssql.build_exec_script("echo 'hi'", "ole"))

    def test_parse_exec_strips_chrome(self):
        from recce.services.db import mssql
        out = mssql.parse_exec("SQL>\n@@X:out\n--------\noutput\ncorp\\alice\nNULL\n@@XE:out\n")
        self.assertEqual(out, "corp\\alice")

    def test_exec_command_clr_is_a_handoff_not_executed(self):
        from recce.services.db import mssql
        o, e, ref = mssql.exec_command("10.0.0.50",
                                       {"user": "alice", "secret": "P@ss", "domain": "corp.local"},
                                       "whoami", method="clr")
        self.assertIsNone(o)
        self.assertIsNone(e)
        self.assertIn("mssqlpwner", ref)                   # delegates, never loads a DLL
        self.assertIn("custom-asm", ref)

    def test_exec_rce_flows_into_totals(self):
        from unittest import mock
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services.db import mssql
        from recce.core.store import Store
        enum = mssql.parse_enum(
            "@@B:server\nSQL01|sa|1|0|15.0.2000.5\n@@E:server\n@@B:logins\nsa|1\n@@E:logins\n"
            "@@B:databases\nmaster|0|sa\n@@E:databases\n@@B:links\n@@E:links\n"
            "@@B:impersonate\n@@E:impersonate\n@@B:config\nxp_cmdshell|1\n@@E:config\n"
            "@@B:hashes\n@@E:hashes\n")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(self._host())
            st.close()
            with mock.patch.object(mssql, "mssqlclient_tool", return_value="x"), \
                    mock.patch.object(mssql, "nxc_tool", return_value=None), \
                    mock.patch.object(mssql, "run_mssqlclient", return_value=(enum, None)), \
                    mock.patch.object(mssql, "link_runner",
                                      side_effect=lambda *a, **k: (lambda s: "")), \
                    mock.patch.object(mssql, "exec_command",
                                      return_value=("nt service\\mssqlserver", None, None)):
                rc = cli.main(["mssql", "-o", out, "--no-probe", "--no-links",
                               "-u", "alice", "-p", "P@ss", "-d", "corp.local",
                               "--exec", "whoami", "--method", "agent"])
            self.assertEqual(rc, 0)
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            v = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
            self.assertIn("Confirmed OS command execution via agent", v)
            self.assertIn("nt service\\mssqlserver", v)    # captured output

    def test_relay_targets_and_finding(self):
        from recce.services.db import mssql
        hosts = [
            Host(ip="10.0.0.50", ports=[Port(portid=1433, service="ms-sql-s")]),
            Host(ip="10.0.0.9", roles=["Domain Controller"],
                 ports=[Port(portid=389, service="ldap")]),
            Host(ip="10.0.0.20", smb_signing="not required",
                 ports=[Port(portid=445, service="microsoft-ds")]),
            Host(ip="10.0.0.60", ports=[Port(portid=1433, service="ms-sql-s")]),
        ]
        rt = mssql.relay_targets(hosts, "10.0.0.50")
        kinds = {r["kind"] for r in rt}
        self.assertEqual(kinds, {"ldap", "mssql", "smb"})
        self.assertTrue(any(r["target"] == "10.0.0.9" for r in rt))       # DC ldap
        self.assertTrue(any(r["target"] == "10.0.0.60:1433" for r in rt))  # other mssql
        self.assertFalse(any("10.0.0.50" in r["target"] for r in rt))      # not itself
        f = mssql.relay_finding({"ip": "10.0.0.50", "port": 1433}, rt, "10.10.14.5",
                                {"user": "alice"})
        self.assertIn("ntlmrelayx", f["command"])
        self.assertIn("xp_dirtree", f["command"])
        self.assertIn("10.10.14.5", f["command"])                          # lhost filled

    def test_live_enum_flows_into_sheet_and_totals(self):
        from unittest import mock
        from recce import cli
        from recce.report.formats import xlsx
        from recce.services.db import mssql
        from recce.core.store import Store
        enum = mssql.parse_enum(self._LIVE)
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(self._host())
            st.close()
            with mock.patch.object(mssql, "mssqlclient_tool", return_value="impacket-mssqlclient"), \
                    mock.patch.object(mssql, "nxc_tool", return_value=None), \
                    mock.patch.object(mssql, "run_mssqlclient",
                                      return_value=(enum, None)):
                rc = cli.main(["mssql", "-o", out, "--no-probe", "--no-links",
                               "-u", "alice", "-p", "P@ss", "-d", "corp.local"])
            self.assertEqual(rc, 0)
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            m = "\n".join(" ".join(map(str, r)) for r in sheets["MSSQL"])
            self.assertIn("Live chain:", m)
            self.assertIn("payroll", m)                        # TRUSTWORTHY db named
            self.assertIn("DW01", m)                           # linked server named
            self.assertIn("Live enumeration (impacket", m)
            v = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
            self.assertIn("Impersonatable sysadmin", v)        # chain finding in totals
            self.assertIn("TRUSTWORTHY database", v)




class BloodHoundTest(unittest.TestCase):
    BASE = "S-1-5-21-1-2-3"

    def _collection(self, d):
        """Write a synthetic SharpHound collection into dir `d`. Encodes:
        BOB(user, Domain Users) --GenericAll--> HELPDESK --MemberOf--> Domain Admins,
        BOB has DCSync on the domain, is kerberoastable, and has a pwd in its
        description; ALICE is AS-REP roastable; SVC has unconstrained delegation."""
        B = self.BASE
        users = {"meta": {"type": "users", "count": 3}, "data": [
            {"ObjectIdentifier": f"{B}-1001",
             "Properties": {"name": "BOB@CORP.LOCAL", "domain": "CORP.LOCAL",
                            "enabled": True, "hasspn": True,
                            "serviceprincipalnames": ["MSSQL/db.corp.local"],
                            "description": "svc account pwd=Summer2024!"},
             "Aces": []},
            {"ObjectIdentifier": f"{B}-1002",
             "Properties": {"name": "ALICE@CORP.LOCAL", "enabled": True,
                            "dontreqpreauth": True}, "Aces": []},
            {"ObjectIdentifier": f"{B}-1003",
             "Properties": {"name": "SVC@CORP.LOCAL", "enabled": True,
                            "unconstraineddelegation": True}, "Aces": []},
        ]}
        groups = {"meta": {"type": "groups", "count": 3}, "data": [
            {"ObjectIdentifier": f"{B}-512",
             "Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "highvalue": True},
             "Members": [{"ObjectIdentifier": f"{B}-1105", "ObjectType": "Group"}],
             "Aces": []},
            {"ObjectIdentifier": f"{B}-513",
             "Properties": {"name": "DOMAIN USERS@CORP.LOCAL"},
             "Members": [{"ObjectIdentifier": f"{B}-1001", "ObjectType": "User"}],
             "Aces": []},
            {"ObjectIdentifier": f"{B}-1105",
             "Properties": {"name": "HELPDESK@CORP.LOCAL"}, "Members": [],
             "Aces": [{"PrincipalSID": f"{B}-1001", "PrincipalType": "User",
                       "RightName": "GenericAll"}]},
        ]}
        domains = {"meta": {"type": "domains", "count": 1}, "data": [
            {"ObjectIdentifier": B,
             "Properties": {"name": "CORP.LOCAL", "functionallevel": "2016",
                            "machineaccountquota": 10},
             "Trusts": [],
             "Aces": [{"PrincipalSID": f"{B}-1001", "RightName": "GetChanges"},
                      {"PrincipalSID": f"{B}-1001", "RightName": "GetChangesAll"}]},
        ]}
        import json as _json
        for name, blob in (("users", users), ("groups", groups), ("domains", domains)):
            with open(os.path.join(d, f"2026_{name}.json"), "w") as fh:
                fh.write(_json.dumps(blob))

    def test_load_graph_builds_nodes_and_edges(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            g = bh.load_graph(d)
        self.assertEqual(g["nodes"][f"{self.BASE}-1001"]["type"], "User")
        # GenericAll ACE -> edge; group Members -> MemberOf; GetChanges*2 -> DCSync.
        labels = {(s.split("-")[-1], lbl, dd.split("-")[-1]) for s, lbl, dd in g["edges"]}
        self.assertIn(("1001", "GenericAll", "1105"), labels)
        self.assertIn(("1105", "MemberOf", "512"), labels)
        self.assertTrue(any(lbl == "DCSync" for _s, lbl, _d in g["edges"]))

    def test_is_sharphound_detects_collection(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            self.assertTrue(bh.is_sharphound(d))
        with tempfile.TemporaryDirectory() as d2:
            with open(os.path.join(d2, "x.json"), "w") as fh:
                fh.write('{"nope": 1}')
            self.assertFalse(bh.is_sharphound(d2))

    def test_findings_cover_the_classics(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            fs = bh.findings(bh.load_graph(d))
        cats = {f["category"] for f in fs}
        for expect in ("kerberoast", "asrep", "delegation", "dcsync", "hygiene", "creds"):
            self.assertIn(expect, cats)
        dcsync = next(f for f in fs if f["category"] == "dcsync")
        self.assertEqual(dcsync["severity"], "critical")
        self.assertIn("secretsdump", dcsync["command"])

    def test_attack_path_owned_user_to_domain_admin(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            g = bh.load_graph(d)
        paths = bh.attack_paths(g, owned={"BOB@CORP.LOCAL"})
        da = next((p for p in paths if "DOMAIN ADMINS" in p["target"].upper()), None)
        self.assertIsNotNone(da)
        self.assertEqual(da["length"], 2)                       # BOB->HELPDESK->DA
        self.assertEqual([s["label"] for s in da["steps"]], ["GenericAll", "MemberOf"])
        self.assertIn("GenericAll", da["chain"])
        # The domain object is reachable in one DCSync hop.
        self.assertTrue(any(p["length"] == 1 and s["label"] == "DCSync"
                            for p in paths for s in p["steps"]))

    def test_architecture_is_curated_tier0(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            arch = bh.architecture(bh.load_graph(d))
        by_rid = {s.split("-")[-1]: v for s, v in arch["nodes"].items()}
        # Domain object on top (tier 0); Domain Admins is a high-value group (tier 1).
        self.assertEqual(by_rid[self.BASE.split("-")[-1]]["tier"], 0)
        self.assertEqual(by_rid["512"]["tier"], 1)
        self.assertTrue(by_rid["512"]["hv"])
        # BOB is pulled in: it can DCSync the domain and controls HELPDESK (tier 2).
        self.assertIn("1001", by_rid)
        self.assertEqual(by_rid["1001"]["tier"], 2)
        # Only tier-0-relevant objects are kept — SVC/ALICE (no tier-0 edge) are out.
        self.assertNotIn("1002", by_rid)               # ALICE
        self.assertNotIn("1003", by_rid)               # SVC
        # The membership + control + DCSync edges are present.
        rid_edges = {(s.split("-")[-1], l, dd.split("-")[-1]) for s, l, dd in arch["edges"]}
        self.assertIn(("1105", "MemberOf", "512"), rid_edges)
        self.assertIn(("1001", "GenericAll", "1105"), rid_edges)
        self.assertTrue(any(l == "DCSync" for _s, l, _d in arch["edges"]))
        self.assertFalse(arch["truncated"])

    def test_architecture_truncates_large_graph(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            g = bh.load_graph(d)
            arch = bh.architecture(g, max_nodes=2)
        self.assertTrue(arch["truncated"])
        self.assertLessEqual(len(arch["nodes"]), 2)

    def test_architecture_persisted_in_analysis(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            analysis = bh.analyze(d)
        self.assertIn("architecture", analysis)
        self.assertTrue(analysis["architecture"]["nodes"])
        # Must round-trip through JSON (it lives in the ad_bloodhound meta blob).
        import json as _json
        _json.loads(_json.dumps(analysis))

    def test_architecture_embedded_in_assets_page(self):
        from recce.ad import bloodhound as bh
        from recce.report import html as report_html
        from recce.core.models import Host
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            analysis = bh.analyze(d)
            host = Host(ip="10.0.0.10", subnet="10.0.0.0/24", state="up",
                        up_reason="syn-ack", roles=["Domain Controller"])
            p = os.path.join(d, "assets.html")
            report_html.build_assets_html([host], p, title="AD",
                                          ad_bloodhound=analysis)
            with open(p, encoding="utf-8") as fh:
                html = fh.read()
        self.assertIn("AD architecture", html)
        self.assertIn("from BloodHound", html)
        self.assertIn("<svg", html)
        self.assertIn("DOMAIN ADMINS", html)
        self.assertNotIn("xmlns", html)                # inline SVG stays self-contained
        for bad in ("src=", "<link", "<script"):
            self.assertNotIn(bad, html)

    def test_kerberos_actions_with_hash(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            g = bh.load_graph(d)
        acts = bh.kerberos_actions(g, {"domain": "CORP.LOCAL", "user": "bob",
                                       "secret": "aad3b...:31d6c...", "is_hash": True,
                                       "dc_ip": "10.0.0.1"})
        titles = " ".join(a["title"] for a in acts)
        self.assertIn("Kerberoast", titles)
        self.assertIn("AS-REP", titles)
        self.assertTrue(any("-hashes :" in a["command"] for a in acts))

    def test_live_kerberos_parsers(self):
        from recce.ad import bloodhound as bh
        tgs = ("[*] Getting TGS for svc_sql\n"
               "$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db.corp.local:1433*$"
               "a1b2c3d4e5f6a7b8c9d0e1f2$deadbeef" * 1 + "\n"
               "$krb5tgs$23$*svc_web$CORP.LOCAL$HTTP/web.corp.local*$00112233$cafebabe\n")
        rows = bh.parse_tgs(tgs)
        self.assertEqual([r["user"] for r in rows], ["svc_sql", "svc_web"])
        self.assertEqual(rows[0]["spn"], "MSSQLSvc/db.corp.local:1433")
        asrep = ("[*] AS-REP for jdoe\n"
                 "$krb5asrep$23$jdoe@CORP.LOCAL:aabbcc$ddeeff001122\n")
        ar = bh.parse_asrep(asrep)
        self.assertEqual(ar[0]["user"], "jdoe")
        dump = ("Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
                "31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
                "CORP.LOCAL\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:"
                "1a2b3c4d5e6f70819293a4b5c6d7e8f9:::\n")
        sd = bh.parse_secretsdump(dump)
        self.assertEqual(len(sd), 2)
        krb = [h for h in sd if h["krbtgt"]]
        self.assertEqual(len(krb), 1)
        self.assertEqual(krb[0]["nt"], "1a2b3c4d5e6f70819293a4b5c6d7e8f9")

    def test_live_kerberos_toolmissing_is_clean(self):
        # When impacket is absent each runner reports the missing tool, never raises,
        # and produces no findings. Force the tool lookup to "missing" so this holds
        # deterministically even on a Kali box that has impacket installed (recce's
        # own target platform), instead of assuming an impacket-free CI runner.
        from unittest import mock
        from recce.ad import bloodhound as bh
        from recce.creds import credenum
        creds = {"domain": "CORP.LOCAL", "user": "bob", "secret": "Pw",
                 "is_hash": False, "dc_ip": "10.0.0.1"}
        # _kerb_tool=None disables bloodhound's impacket fallbacks, but live_kerberoast
        # tries a NATIVE path first (credenum.run_kerberoast), which itself reaches for
        # impacket-GetUserSPNs against the DC - a real subprocess to the non-routable
        # 10.0.0.1 that blocks up to the 180s tool timeout. Stub the native roast to
        # empty so the runner cleanly falls through to the "not installed" fallback.
        with mock.patch.object(bh, "_kerb_tool", return_value=None), \
             mock.patch.object(credenum, "run_kerberoast", return_value=([], None)):
            res = bh.live_kerberos(creds, None, do_roast=True, do_asrep=True,
                                   do_dcsync=True)
        self.assertEqual(res["findings"], [])
        self.assertEqual(len(res["errors"]), 3)
        self.assertTrue(all("not installed" in e for e in res["errors"]))

    def test_live_capture_findings_fold_into_vulns(self):
        # A captured TGS -> a proven 'roasted' finding -> a confirmed Vuln that reaches
        # the main totals with the real hash as evidence and the right CWE.
        from recce.ad import bloodhound as bh
        out = bh.parse_tgs("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db*$aa$bb\n")
        # Simulate a successful capture by exercising the finding-builder path.
        creds = {"user": "bob", "domain": "CORP.LOCAL"}
        fs = []
        for h in out:
            fs.append(bh._finding(
                "roasted", "high", "Kerberoast hash captured (proven)", h["user"], "",
                f"Captured a live TGS-REP for SPN '{h['spn']}'.\n\n{h['hash']}",
                "hashcat", "hashcat -m 13100 kerberoast.hash rockyou.txt", "rotate"))
        an = {"findings": fs}
        vulns = bh.findings_to_vulns(an, "10.0.0.9", "CORP.LOCAL")
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v.confidence, "confirmed")
        self.assertIn("CWE-262", v.cwes)
        self.assertIn("$krb5tgs$", v.output)
        _ = creds

    def test_analyze_is_json_serialisable(self):
        from recce.ad import bloodhound as bh
        import json as _json
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            an = bh.analyze(d, owned={"BOB@CORP.LOCAL"})
        _json.dumps(an)                                          # must round-trip
        self.assertEqual(an["stats"]["nodes"], 7)
        self.assertTrue(an["stats"]["findings"] >= 6)
        self.assertTrue(an["paths"])

    def test_report_sheets_render(self):
        from recce.ad import bloodhound as bh
        from recce.report import excel as report_excel
        from recce.report.formats import xlsx
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            an = bh.analyze(d, owned={"BOB@CORP.LOCAL"},
                            creds={"domain": "CORP.LOCAL", "user": "bob",
                                   "secret": "x", "is_hash": False, "dc_ip": "1.2.3.4"})
            p = os.path.join(d, "wb.xlsx")
            report_excel.build_workbook([], p, meta={"subtitle": "T", "ad_bloodhound": an})
            sheets = xlsx.read_sheets(p)
        self.assertIn("AD Findings", sheets)
        self.assertIn("AD Attack Paths", sheets)
        findings_txt = "\n".join(" ".join(map(str, r)) for r in sheets["AD Findings"])
        self.assertIn("DCSync", findings_txt)
        self.assertIn("secretsdump", findings_txt)               # the prove command
        paths_txt = "\n".join(" ".join(map(str, r)) for r in sheets["AD Attack Paths"])
        self.assertIn("DOMAIN ADMINS", paths_txt)
        self.assertIn("MemberOf", paths_txt)                     # the edge chain
        self.assertIn("GetUserSPNs", paths_txt)                  # kerberos action

    def test_cmd_bloodhound_end_to_end(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            out = os.path.join(d, "eng")
            rc = cli.cmd_bloodhound(SimpleNamespace(
                paths=[d], username=None, password=None, domain=None,
                owned=["BOB@CORP.LOCAL"], creds=None, dc_ip=None,
                output_dir=out, title="T"))
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(os.path.join(out, "enumeration.xlsx")))
            st = Store(os.path.join(out, "results.sqlite"))
            blob = st.get_meta("ad_bloodhound")
            doms = {dm.name: dm for dm in st.all_domains()}
            st.close()
            self.assertTrue(blob)                                # analysis persisted
            self.assertIn("corp.local", doms)                    # domain merged in
            self.assertIn("bloodhound", doms["corp.local"].sources)

    def test_findings_to_vulns_feed_main_findings_and_writeups(self):
        from recce.ad import bloodhound as bh
        from recce.report.docx import group_findings, list_findings, _vuln_type
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            an = bh.analyze(d, owned={"BOB@CORP.LOCAL"})
        vulns = bh.findings_to_vulns(an, "10.0.0.9", "CORP.LOCAL")
        self.assertTrue(vulns)
        h = Host(ip="10.0.0.9", os_family="Windows", roles=["Domain Controller"],
                 vulns=vulns)
        # group_findings powers the severity rollup, Vulnerabilities sheet + writeups.
        groups = group_findings([h])
        titles = {f.title for f in groups}
        self.assertIn("DCSync rights held off tier-0", titles)
        dcsync = next(f for f in groups if f.title == "DCSync rights held off tier-0")
        self.assertEqual(dcsync.severity, "critical")
        self.assertTrue(dcsync.remediation)                      # remediation carried
        self.assertIn("secretsdump", " ".join(o for _i, _p, o in dcsync.evidence))
        # Every AD CWE must classify (keeps the CWE-coverage test green) + have a type.
        for f in groups:
            vt, _cia = _vuln_type(f.cwes)
            self.assertTrue(vt, f.cwes)
        # list_findings (the appendix/HTML feed) includes them with severity.
        lf = list_findings([h], min_severity="info")
        self.assertTrue(any("DCSync" in x["title"] for x in lf))

    def test_ad_findings_reach_vulnerabilities_sheet_e2e(self):
        from recce import cli
        from recce.report.formats import xlsx
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            out = os.path.join(d, "eng")
            cli.cmd_bloodhound(SimpleNamespace(
                paths=[d], username="alice", password="Passw0rd!", domain="corp.local",
                owned=None, creds=None, dc_ip="10.0.0.9", output_dir=out, title="T"))
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
        vtxt = "\n".join(" ".join(map(str, r)) for r in sheets.get("Vulnerabilities", []))
        self.assertIn("DCSync", vtxt)                            # in the MAIN vuln sheet
        self.assertIn("Kerberoastable", vtxt)

    def _collection_small(self, d):
        """A reduced collection - only ALICE (AS-REP roastable) - simulating a
        follow-up import after the other findings were remediated."""
        B = self.BASE
        import json as _json
        users = {"meta": {"type": "users"}, "data": [
            {"ObjectIdentifier": f"{B}-1002",
             "Properties": {"name": "ALICE@CORP.LOCAL", "enabled": True,
                            "dontreqpreauth": True}, "Aces": []}]}
        domains = {"meta": {"type": "domains"}, "data": [
            {"ObjectIdentifier": B, "Properties": {"name": "CORP.LOCAL"},
             "Trusts": [], "Aces": []}]}
        for n, b in (("users", users), ("domains", domains)):
            with open(os.path.join(d, f"2026_{n}.json"), "w") as fh:
                fh.write(_json.dumps(b))

    def test_replace_ad_clears_remediated_findings_but_keeps_scan_vulns(self):
        from recce import cli
        from recce.core.models import Host, Vuln
        from recce.core.store import Store

        def db(out):
            st = Store(os.path.join(out, "results.sqlite"))
            h = st.get_host("10.0.0.9")
            st.close()
            return {v.title for v in h.vulns}
        with tempfile.TemporaryDirectory() as d:
            full = os.path.join(d, "full")
            small = os.path.join(d, "small")
            out = os.path.join(d, "eng")
            os.makedirs(full)
            os.makedirs(small)
            os.makedirs(out)
            self._collection(full)
            self._collection_small(small)
            # Pre-seed the DC host with a scan-sourced vuln that must SURVIVE replace.
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.9",
                                ports=[Port(portid=445, service="microsoft-ds")],
                                vulns=[Vuln(ip="10.0.0.9", port=445, protocol="tcp",
                                            script_id="smb-vuln-ms17-010", title="MS17-010",
                                            severity="critical", source="nse")]))
            st.close()
            base = dict(username="alice", password="p", domain="corp.local", owned=None,
                        creds=None, dc_ip="10.0.0.9", output_dir=out, title="T")
            cli.cmd_bloodhound(SimpleNamespace(paths=[full], replace_ad=False, **base))
            t1 = db(out)
            self.assertIn("Kerberoastable account", t1)
            self.assertIn("MS17-010", t1)
            # Re-import the remediated (smaller) collection WITH --replace-ad.
            cli.cmd_bloodhound(SimpleNamespace(paths=[small], replace_ad=True, **base))
            t2 = db(out)
            self.assertNotIn("Kerberoastable account", t2)       # remediated -> gone
            self.assertNotIn("DCSync rights held off tier-0", t2)
            self.assertIn("AS-REP roastable account (no Kerberos pre-auth)", t2)  # kept
            self.assertIn("MS17-010", t2)                        # scan vuln survived

    def test_distinct_findings_are_not_deduped_in_main_totals(self):
        # Two kerberoastable users share the generic title but must produce TWO
        # Vulns (distinct keys) so the main severity totals aren't undercounted.
        from recce.ad import bloodhound as bh
        B = self.BASE
        analysis = {"findings": [
            {"category": "kerberoast", "severity": "medium",
             "title": "Kerberoastable account", "principal": "SVC1@C", "target": "",
             "detail": "", "command": "x", "remediation": "y"},
            {"category": "kerberoast", "severity": "medium",
             "title": "Kerberoastable account", "principal": "SVC2@C", "target": "",
             "detail": "", "command": "x", "remediation": "y"}]}
        vulns = bh.findings_to_vulns(analysis, "10.0.0.9", "C")
        self.assertEqual(len({v.key for v in vulns}), 2)         # distinct, not collapsed
        _ = B  # silence

    def test_domain_controller_not_flagged_for_unconstrained_delegation(self):
        from recce.ad import bloodhound as bh
        B = self.BASE
        with tempfile.TemporaryDirectory() as d:
            # DC01 has unconstrained delegation AND is a member of Domain Controllers
            # (RID 516). It must NOT be reported (that's normal for a DC).
            comps = {"meta": {"type": "computers"}, "data": [
                {"ObjectIdentifier": f"{B}-1000",
                 "Properties": {"name": "DC01.CORP.LOCAL", "enabled": True,
                                "unconstraineddelegation": True}, "Aces": []}]}
            groups = {"meta": {"type": "groups"}, "data": [
                {"ObjectIdentifier": f"{B}-516",
                 "Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL"},
                 "Members": [{"ObjectIdentifier": f"{B}-1000", "ObjectType": "Computer"}],
                 "Aces": []}]}
            import json as _json
            for n, b in (("computers", comps), ("groups", groups)):
                with open(os.path.join(d, f"{n}.json"), "w") as fh:
                    fh.write(_json.dumps(b))
            fs = bh.findings(bh.load_graph(d))
        self.assertFalse([f for f in fs if f["category"] == "delegation"])
        # A non-DC computer with unconstrained delegation IS flagged.
        with tempfile.TemporaryDirectory() as d:
            comps = {"meta": {"type": "computers"}, "data": [
                {"ObjectIdentifier": f"{B}-1001",
                 "Properties": {"name": "APP01.CORP.LOCAL", "enabled": True,
                                "unconstraineddelegation": True}, "Aces": []}]}
            import json as _json
            with open(os.path.join(d, "computers.json"), "w") as fh:
                fh.write(_json.dumps(comps))
            fs = bh.findings(bh.load_graph(d))
        self.assertTrue([f for f in fs if f["category"] == "delegation"])

    def test_enabled_null_is_treated_as_enabled(self):
        from recce.ad import bloodhound as bh
        B = self.BASE
        with tempfile.TemporaryDirectory() as d:
            users = {"meta": {"type": "users"}, "data": [
                {"ObjectIdentifier": f"{B}-1001",
                 "Properties": {"name": "SVC@C", "enabled": None, "hasspn": True,
                                "serviceprincipalnames": ["x/y"]}, "Aces": []}]}
            import json as _json
            with open(os.path.join(d, "users.json"), "w") as fh:
                fh.write(_json.dumps(users))
            fs = bh.findings(bh.load_graph(d))
        self.assertTrue([f for f in fs if f["category"] == "kerberoast"])

    def test_bare_string_members_do_not_crash(self):
        from recce.ad import bloodhound as bh
        B = self.BASE
        with tempfile.TemporaryDirectory() as d:
            # Members / LocalAdmins as bare SID strings (older SharpHound).
            groups = {"meta": {"type": "groups"}, "data": [
                {"ObjectIdentifier": f"{B}-512", "Properties": {"name": "DA@C"},
                 "Members": [f"{B}-1001"], "Aces": []}]}
            comps = {"meta": {"type": "computers"}, "data": [
                {"ObjectIdentifier": f"{B}-1000", "Properties": {"name": "WS@C"},
                 "LocalAdmins": [f"{B}-1001"], "Aces": []}]}
            import json as _json
            for n, b in (("groups", groups), ("computers", comps)):
                with open(os.path.join(d, f"{n}.json"), "w") as fh:
                    fh.write(_json.dumps(b))
            g = bh.load_graph(d)                                 # must not raise
        labels = {(s.split("-")[-1], lbl, dd.split("-")[-1]) for s, lbl, dd in g["edges"]}
        self.assertIn(("1001", "MemberOf", "512"), labels)
        self.assertIn(("1001", "AdminTo", "1000"), labels)

    def test_fill_creds_password_containing_a_token_is_safe(self):
        from recce.ad import bloodhound as bh
        an = {"findings": [{"command": "run <DOMAIN>/<user>:<pass> against <dc>"}],
              "kerberos": [], "paths": []}
        # Password literally contains "<dc>" - must NOT be re-substituted.
        bh.fill_creds(an, {"domain": "corp.local", "user": "alice",
                           "secret": "p<dc>w", "is_hash": False, "dc_ip": "10.0.0.1"})
        cmd = an["findings"][0]["command"]
        self.assertIn("corp.local/alice:p<dc>w", cmd)            # password intact
        self.assertTrue(cmd.endswith("against 10.0.0.1"))        # real <dc> filled

    def test_fill_creds_makes_commands_copy_paste_ready(self):
        from recce.ad import bloodhound as bh
        with tempfile.TemporaryDirectory() as d:
            self._collection(d)
            an = bh.analyze(d, owned={"BOB@CORP.LOCAL"})
        bh.fill_creds(an, {"domain": "corp.local", "user": "alice",
                           "secret": "Passw0rd!", "is_hash": False, "dc_ip": "10.0.0.1"})
        cmds = " ".join(f["command"] for f in an["findings"])
        self.assertIn("corp.local/alice:Passw0rd!", cmds)        # DOMAIN/user:pass filled
        self.assertIn("10.0.0.1", cmds)                          # dc-ip filled
        self.assertNotIn("<dc>", cmds)
        self.assertNotIn("<DOMAIN>", cmds)

    def test_simple_credentialed_run_defaults_owned_to_you(self):
        # -u alice with no --owned: paths must start from ALICE (the simple UX).
        from recce import cli
        with tempfile.TemporaryDirectory() as d:
            # ALICE has GenericAll on HELPDESK instead of BOB.
            self._collection(d)
            import json as _json
            groups_path = os.path.join(d, "2026_groups.json")
            g = _json.loads(open(groups_path).read())
            for obj in g["data"]:
                if obj["ObjectIdentifier"].endswith("-1105"):
                    obj["Aces"] = [{"PrincipalSID": f"{self.BASE}-1002",
                                    "RightName": "GenericAll"}]
            open(groups_path, "w").write(_json.dumps(g))
            out = os.path.join(d, "eng")
            rc = cli.cmd_bloodhound(SimpleNamespace(
                paths=[d], username="alice", password="Passw0rd!", domain="CORP.LOCAL",
                owned=None, creds=None, dc_ip="10.0.0.1", output_dir=out, title="T"))
            self.assertEqual(rc, 0)
            from recce.report.formats import xlsx
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            paths_txt = "\n".join(" ".join(map(str, r))
                                  for r in sheets.get("AD Attack Paths", []))
            self.assertIn("ALICE", paths_txt.upper())            # path starts from ALICE
            # Kerberos command carries the real creds, not placeholders.
            self.assertIn("CORP.LOCAL/alice", paths_txt)




class AdcsCertipyTest(unittest.TestCase):
    def _certipy(self, path):
        data = {
            "Certificate Authorities": {
                "0": {"CA Name": "CORP-CA", "DNS Name": "ca.corp.local",
                      "Web Enrollment": "Enabled",
                      "[!] Vulnerabilities": {
                          "ESC8": "Web Enrollment is enabled and Request Disposition is Issue"}}},
            "Certificate Templates": {
                "0": {"Template Name": "VulnUser", "Enabled": True,
                      "Client Authentication": True, "Enrollee Supplies Subject": True,
                      "Certificate Authorities": ["CORP-CA"],
                      "Permissions": {"Enrollment Permissions": {
                          "Enrollment Rights": ["CORP.LOCAL\\Domain Users"]}},
                      "[!] Vulnerabilities": {
                          "ESC1": "'CORP.LOCAL\\Domain Users' can enroll and supply a SAN"}},
                "1": {"Template Name": "Boring", "Enabled": True,
                      "[!] Vulnerabilities": {}}}}
        import json as _json
        with open(path, "w") as fh:
            fh.write(_json.dumps(data))

    def test_is_certipy_detects_file(self):
        from recce.ad import adcs
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "20260101_Certipy.json")
            self._certipy(p)
            self.assertTrue(adcs.is_certipy(p))
            other = os.path.join(d, "sh.json")
            with open(other, "w") as fh:
                fh.write('{"meta": {"type": "users"}, "data": []}')
            self.assertFalse(adcs.is_certipy(other))

    def test_findings_map_esc_to_exact_commands(self):
        from recce.ad import adcs
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            self._certipy(p)
            fs = adcs.findings(p)
        cats = {f["category"] for f in fs}
        self.assertIn("adcs-esc1", cats)
        self.assertIn("adcs-esc8", cats)
        esc1 = next(f for f in fs if f["category"] == "adcs-esc1")
        self.assertEqual(esc1["severity"], "critical")
        self.assertIn("certipy req", esc1["command"])
        self.assertIn("VulnUser", esc1["command"])               # real template name
        self.assertIn("Domain Users", esc1["principal"])         # who can enroll

    def test_enrollment_rights_as_dict_does_not_crash(self):
        from recce.ad import adcs
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            data = {"Certificate Templates": {"0": {
                "Template Name": "VulnUser",
                "Permissions": {"Enrollment Permissions": {
                    "Enrollment Rights": {"CORP\\Domain Users": "Enroll"}}},  # dict form
                "[!] Vulnerabilities": {"ESC1": "x"}}}}
            import json as _json
            with open(p, "w") as fh:
                fh.write(_json.dumps(data))
            fs = adcs.findings(p)                                # must not raise
        self.assertTrue(fs)
        self.assertIn("Domain Users", fs[0]["principal"])

    def test_certipy_flows_into_workbook_with_creds(self):
        from recce import cli
        from recce.report.formats import xlsx
        with tempfile.TemporaryDirectory() as d:
            cp = os.path.join(d, "certipy.json")
            self._certipy(cp)
            out = os.path.join(d, "eng")
            rc = cli.cmd_bloodhound(SimpleNamespace(
                paths=[cp], username="alice", password="Passw0rd!",
                domain="corp.local", owned=None, creds=None, dc_ip="10.0.0.1",
                output_dir=out, title="T"))
            self.assertEqual(rc, 0)
            sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
            txt = "\n".join(" ".join(map(str, r)) for r in sheets["AD Findings"])
            self.assertIn("ESC1", txt)
            self.assertIn("VulnUser", txt)
            self.assertIn("alice@corp.local", txt)               # creds pre-filled
            self.assertIn("10.0.0.1", txt)




class AttackPathTest(unittest.TestCase):
    def _hosts(self):
        from recce.core.models import Vuln, Account
        dc = Host(ip="10.0.10.5", hostnames=["dc01"], os_family="Windows",
                  roles=["Domain Controller"], smb_signing="not required",
                  accounts=[Account(ip="10.0.10.5", source="nse", kind="domain",
                                    domain="CORP")],
                  ports=[Port(portid=445, service="microsoft-ds"),
                         Port(portid=5985, service="http")],
                  vulns=[Vuln(ip="10.0.10.5", port=445, protocol="tcp",
                              script_id="smb-vuln-ms17-010", title="smb-vuln-ms17-010",
                              severity="high", source="nse", ids=["CVE-2017-0143"],
                              output="VULNERABLE"),
                         Vuln(ip="10.0.10.5", port=0, protocol="tcp",
                              script_id="local-enum", title="SeImpersonate -> Potato",
                              severity="high", source="local", confidence="confirmed",
                              output="SeImpersonate held")])
        return [dc]

    def test_stages_and_ordering(self):
        from recce.act import attackpath as ap
        steps = ap.build(self._hosts())
        stages = [s["stage"] for s in steps]
        # ordered by STAGE_ORDER
        idx = [ap.STAGE_ORDER.index(s) for s in stages]
        self.assertEqual(idx, sorted(idx))
        self.assertIn("Initial Access", stages)          # ms17-010
        self.assertIn("Privilege Escalation", stages)    # SeImpersonate/Potato
        self.assertIn("Domain Dominance", stages)        # AS-REP/Kerberoast/relay on DC
        self.assertIn("Lateral Movement", stages)        # SMB/WinRM present

    def test_narrative_grounded(self):
        from recce.act import attackpath as ap
        hosts = self._hosts()
        text = " ".join(ap.narrative(hosts))
        self.assertIn("Likely path", text)
        self.assertIn("10.0.10.5", text)                 # names the real host

    def test_attackpath_sheet(self):
        from recce.report.excel import _spec_attackpath
        spec = _spec_attackpath(self._hosts())
        self.assertEqual(spec.title, "Attack Path")
        self.assertIn("Stage", [c[0] for c in spec.cols])
        self.assertTrue(spec.rows)

    def test_empty_when_no_confirmed(self):
        from recce.act import attackpath as ap
        h = Host(ip="10.0.0.1", os_family="Linux",
                 ports=[Port(portid=23, service="telnet")])
        self.assertEqual(ap.build([h]), [])              # no confirmed findings

    def test_svg_graph(self):
        import xml.dom.minidom as md
        from recce.act import attackpath as ap
        hosts = self._hosts()
        s = ap.svg(hosts)
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)                                # well-formed XML (renders anywhere)
        self.assertNotIn("xmlns", s)                     # inline, self-contained
        self.assertIn("Initial Access", s)               # a stage header
        self.assertIn("10.0.10.5", s)                    # real host on a card
        self.assertIn("marker-end", s)                   # stage / same-host arrows

    def test_svg_empty_is_valid(self):
        import xml.dom.minidom as md
        from recce.act import attackpath as ap
        h = Host(ip="10.0.0.1", os_family="Linux",
                 ports=[Port(portid=23, service="telnet")])
        s = ap.svg([h])
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)
        self.assertIn("No confirmed attack path", s)

    def test_cmd_writes_svg_diagram(self):
        from recce import cli
        from recce.core.store import Store
        with tempfile.TemporaryDirectory() as dd:
            db = os.path.join(dd, "results.sqlite")
            st = Store(db)
            for h in self._hosts():
                st.upsert_host(h)
            st.close()
            rc = cli.cmd_attackpath(SimpleNamespace(output_dir=dd, targets=[]))
            self.assertEqual(rc, 0)
            svg_path = os.path.join(dd, "attack-path.svg")
            self.assertTrue(os.path.exists(svg_path))
            self.assertFalse(os.path.exists(os.path.join(dd, "attack_path.mmd")))
            self.assertFalse(os.path.exists(os.path.join(dd, "attack_path.dot")))
            with open(svg_path) as fh:
                self.assertIn("xmlns", fh.read())        # standalone-renderable




class KerberosTest(unittest.TestCase):
    """Credential-less AD roasting: DER round-trip, a mock KDC (AS-REP for a
    pre-auth-disabled user, KRB-ERROR otherwise), roast/enum classification,
    findings, prove, `recce kerberos`."""

    @classmethod
    def setUpClass(cls):
        import socketserver
        import struct
        import threading
        from recce.ad import kerberos as K

        def asrep():
            cipher = bytes(range(40))                   # 16 checksum + 24 edata
            enc = K._seq(K._ctx(0, K._int(23)), K._ctx(2, K._tlv(0x04, cipher)))
            return K._tlv(0x6B, K._seq(
                K._ctx(3, K._gstr("CORP.LOCAL")),
                K._ctx(4, K._principal(1, ["svc_roast"])),
                K._ctx(6, enc)))

        def krberr(code):
            return K._tlv(0x7E, K._seq(K._ctx(6, K._int(code))))

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.settimeout(3.0)
                hdr = K._recvn(sock, 4, 3.0)
                if hdr is None:
                    return
                n = struct.unpack(">I", hdr)[0]
                req = K._recvn(sock, n, 3.0) or b""
                if b"svc_roast" in req:
                    resp = asrep()
                elif b"jdoe" in req:
                    resp = krberr(K.KDC_ERR_PREAUTH_REQUIRED)     # 25 = valid
                else:
                    resp = krberr(K.KDC_ERR_PRINCIPAL_UNKNOWN)    # 6 = unknown
                sock.sendall(struct.pack(">I", len(resp)) + resp)

        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls._orig_port = K._PORT
        K._PORT = cls.port                              # roast connects here, not 88

    @classmethod
    def tearDownClass(cls):
        from recce.ad import kerberos as K
        K._PORT = cls._orig_port
        cls.srv.shutdown()

    def test_der_roundtrip(self):
        from recce.ad import kerberos as K
        err = K._tlv(0x7E, K._seq(K._ctx(6, K._int(25))))
        self.assertEqual(K.parse_response(err), {"type": "error", "code": 25})
        cipher = bytes(range(40))
        enc = K._seq(K._ctx(0, K._int(23)), K._ctx(2, K._tlv(0x04, cipher)))
        rep = K._tlv(0x6B, K._seq(K._ctx(3, K._gstr("CORP.LOCAL")),
                                  K._ctx(4, K._principal(1, ["jdoe"])),
                                  K._ctx(6, enc)))
        r = K.parse_response(rep)
        self.assertEqual((r["type"], r["user"], r["etype"]), ("asrep", "jdoe", 23))
        self.assertTrue(K.asrep_hash("jdoe", "CORP.LOCAL", 23, cipher)
                        .startswith("$krb5asrep$23$jdoe@CORP.LOCAL:"))

    def test_roast_classification(self):
        from recce.ad import kerberos as K
        self.assertEqual(K.roast_user("127.0.0.1", "CORP.LOCAL", "svc_roast")["state"],
                         "roastable")
        self.assertEqual(K.roast_user("127.0.0.1", "CORP.LOCAL", "jdoe")["state"],
                         "valid")
        self.assertEqual(K.roast_user("127.0.0.1", "CORP.LOCAL", "ghost")["state"],
                         "unknown_user")

    def test_findings_and_prove(self):
        from recce.ad import kerberos as K
        from recce.vuln import proofs
        analysis = K.analyze(
            [Host(ip="127.0.0.1", state="up", up_reason="syn-ack",
                  ports=[Port(portid=self.port, state="open", service="kerberos")])],
            users=["svc_roast", "jdoe", "ghost"], realm="CORP.LOCAL",
            dc_ip="127.0.0.1", privileged={"svc_roast"})
        titles = " ".join(f["title"] for f in analysis["findings"])
        self.assertIn("AS-REP roastable account", titles)
        self.assertIn("Kerberos username enumeration", titles)
        h = Host(ip="127.0.0.1",
                 ports=[Port(portid=88, service="kerberos", state="open")])
        h.vulns = K.findings_to_vulns(analysis["findings"])["127.0.0.1"]
        self.assertIn(proofs.CONFIRMED, [r["verdict"] for r in proofs.verify_host(h)])

    def test_cmd_kerberos_end_to_end(self):
        from recce import cli
        from recce.ad import kerberos as K
        from recce.report.formats import xlsx
        from recce.core.models import Account
        from recce.core.store import Store
        orig = K.is_kerberos
        K.is_kerberos = lambda p: p.state == "open" and (p.portid == self.port or orig(p))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(
                    ip="127.0.0.1", state="up", up_reason="syn-ack",
                    ports=[Port(portid=self.port, state="open", service="kerberos")],
                    accounts=[Account(ip="127.0.0.1", source="ldap", kind="user",
                                      name="svc_roast"),
                              Account(ip="127.0.0.1", source="ldap", kind="user",
                                      name="jdoe")]))
                st.close()
                rc = cli.main(["kerberos", "-d", "CORP.LOCAL", "-o", out])
                self.assertEqual(rc, 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("Kerberos", sheets)
                vtxt = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
                self.assertIn("roastable", vtxt.lower())
        finally:
            K.is_kerberos = orig
