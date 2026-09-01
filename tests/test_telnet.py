"""Tests for recce.services.telnet.

Fixtures are RFC/wire-derived: every IAC byte sequence in this file is copied
by hand from RFC 854 (IAC command structure), RFC 855 (option negotiation),
RFC 1572 (NEW-ENVIRON), RFC 2941 (AUTHENTICATION), MS-NLMP §2.2.2.1 (AV_PAIR).
Nothing here calls the module's own encoders to build a fixture.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import telnet


# --- IAC parser: canonical byte-level fixtures ---------------------------------

# RFC 854: "IAC" = 255 (0xFF). Three-byte negotiations: IAC WILL/WONT/DO/DONT opt
# WILL = 251 (0xFB), WONT = 252 (0xFC), DO = 253 (0xFD), DONT = 254 (0xFE)
IAC_DO_ECHO = bytes.fromhex("fffd01")            # RFC 857 (option 1)
IAC_WILL_ECHO = bytes.fromhex("fffb01")
IAC_DO_SUPPRESS_GA = bytes.fromhex("fffd03")     # RFC 858 (option 3)
IAC_WILL_SUPPRESS_GA = bytes.fromhex("fffb03")
IAC_DO_NAWS = bytes.fromhex("fffd1f")            # RFC 1073 (option 31)
IAC_DO_TTYPE = bytes.fromhex("fffd18")           # RFC 1091 (option 24)
IAC_DO_NEW_ENVIRON = bytes.fromhex("fffd27")     # RFC 1572 (option 39)
IAC_WILL_NEW_ENVIRON = bytes.fromhex("fffb27")
IAC_WILL_ENCRYPT = bytes.fromhex("fffb26")       # RFC 2946 (option 38)
IAC_WILL_AUTH = bytes.fromhex("fffb25")          # RFC 2941 (option 37)

# RFC 1572: IAC SB NEW-ENVIRON IS VAR "USER" VALUE "root" IAC SE
# SB = 250 (0xFA), SE = 240 (0xF0), IS = 0, VAR = 0, VALUE = 1
IAC_SB_NEWENV_IS_USER_ROOT = bytes.fromhex(
    "fffa27"        # IAC SB NEW-ENVIRON
    "00"            # IS
    "00" + b"USER".hex() +      # VAR "USER"
    "01" + b"root".hex() +      # VALUE "root"
    "fff0"          # IAC SE
)

# Same but VAR "DISPLAY" VALUE ":0.0"
IAC_SB_NEWENV_IS_DISPLAY = bytes.fromhex(
    "fffa27"
    "00"
    "00" + b"DISPLAY".hex() +
    "01" + b":0.0".hex() +
    "fff0"
)

# Cisco IOS canonical banner (from any operator's screen; ASCII, no IAC).
CISCO_BANNER = b"\r\n\r\nUser Access Verification\r\n\r\nUsername: "

# BusyBox login prompt (from an OpenWrt image over telnet).
BUSYBOX_PROMPT = b"\r\n\r\n(none) login: "

# Solaris 10 pre-login banner.
SOLARIS_BANNER = b"\r\n\r\nSunOS 5.10\r\n\r\nlogin: "


class IacParserTest(unittest.TestCase):
    def test_will_do_extracted(self):
        stream = IAC_WILL_ECHO + IAC_DO_SUPPRESS_GA + b"hello"
        p = telnet._iac_parse(stream)
        self.assertIn(telnet.OPT_ECHO, p["will"])
        self.assertIn(telnet.OPT_SUPPRESS_GA, p["do"])
        self.assertEqual(p["text"], b"hello")

    def test_iac_iac_is_literal_ff(self):
        # RFC 854: IAC IAC is the sole way to send a literal 0xFF in the stream.
        stream = b"AB" + bytes.fromhex("ffff") + b"CD"
        p = telnet._iac_parse(stream)
        self.assertEqual(p["text"], b"AB\xffCD")

    def test_sb_body_captured(self):
        stream = IAC_SB_NEWENV_IS_USER_ROOT
        p = telnet._iac_parse(stream)
        self.assertIn(telnet.OPT_NEW_ENVIRON, p["sb"])
        body = p["sb"][telnet.OPT_NEW_ENVIRON][0]
        self.assertEqual(body[0], telnet.NEW_IS)
        self.assertIn(b"USER", body)
        self.assertIn(b"root", body)

    def test_banner_stripped_of_iac(self):
        stream = IAC_DO_ECHO + CISCO_BANNER + IAC_WILL_SUPPRESS_GA
        p = telnet._iac_parse(stream)
        self.assertEqual(p["text"], CISCO_BANNER)


class EnvironParseTest(unittest.TestCase):
    def test_new_environ_is_user(self):
        # The 3 body bytes past IAC SB NEW-ENVIRON are: IS VAR USER VALUE root
        body = bytes.fromhex("00" + "00" + b"USER".hex() + "01" + b"root".hex())
        out = telnet._environ_parse(body)
        self.assertEqual(out.get("USER"), "root")

    def test_multiple_vars(self):
        body = bytes.fromhex(
            "00"
            "00" + b"USER".hex() + "01" + b"admin".hex() +
            "00" + b"DISPLAY".hex() + "01" + b":0.0".hex()
        )
        out = telnet._environ_parse(body)
        self.assertEqual(out.get("USER"), "admin")
        self.assertEqual(out.get("DISPLAY"), ":0.0")


class VendorFingerprintTest(unittest.TestCase):
    def test_cisco_from_banner(self):
        slug, desc = telnet._vendor_from("User Access Verification\nUsername:")
        self.assertEqual(slug, "cisco-ios")
        self.assertIn("Cisco", desc)

    def test_busybox_from_prompt(self):
        slug, _ = telnet._vendor_from("\n(none) login: ")
        self.assertEqual(slug, "busybox")

    def test_solaris_from_banner(self):
        slug, _ = telnet._vendor_from("SunOS 5.10\nlogin:")
        self.assertEqual(slug, "solaris")

    def test_unknown_returns_unknown(self):
        slug, _ = telnet._vendor_from("gibberish nothing here")
        self.assertEqual(slug, "unknown")


# --- fake in-process telnet server ---------------------------------------------

class _FakeTelnetServer:
    """Serves ONE canned response to the first connection then optionally
    echoes anything the client subsequently sends back into a follow-up buffer.
    Threaded so probe() can talk to it over a real socket."""
    def __init__(self, initial: bytes, followup: bytes = b""):
        self._initial = initial
        self._followup = followup
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.host, self.port = self._sock.getsockname()
        self.recv_log = bytearray()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            self._sock.settimeout(2.0)
            c, _ = self._sock.accept()
        except (socket.timeout, OSError):
            return
        try:
            c.settimeout(0.5)
            c.sendall(self._initial)
            try:
                data = c.recv(4096)
                if data:
                    self.recv_log.extend(data)
            except (socket.timeout, OSError):
                pass
            if self._followup:
                try:
                    c.sendall(self._followup)
                except OSError:
                    pass
            # Keep the socket open briefly so the client's second recv gets it.
            try:
                data = c.recv(4096)
                if data:
                    self.recv_log.extend(data)
            except (socket.timeout, OSError):
                pass
        finally:
            try: c.close()
            except OSError: pass

    def close(self):
        self._stop = True
        try: self._sock.close()
        except OSError: pass


class ProbeTest(unittest.TestCase):
    def test_probe_captures_options_and_banner(self):
        # Server opens with a common Cisco-style IAC negotiation + banner.
        initial = (IAC_WILL_ECHO + IAC_WILL_SUPPRESS_GA
                   + IAC_DO_TTYPE + IAC_DO_NAWS
                   + CISCO_BANNER)
        srv = _FakeTelnetServer(initial)
        try:
            pr = telnet.probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertIn(telnet.OPT_ECHO, pr["options_will"])
        self.assertIn(telnet.OPT_SUPPRESS_GA, pr["options_will"])
        self.assertIn(telnet.OPT_TTYPE, pr["options_do"])
        self.assertIn(telnet.OPT_NAWS, pr["options_do"])
        self.assertEqual(pr["vendor"], "cisco-ios")
        self.assertIn("User Access Verification", pr["banner"])
        # ENCRYPT + AUTH not offered -> flags are False.
        self.assertFalse(pr["encrypt_offered"])
        self.assertFalse(pr["auth_offered"])
        self.assertFalse(pr["environ_offered"])

    def test_probe_solaris_banner_flags_vendor(self):
        initial = IAC_WILL_ECHO + SOLARIS_BANNER
        srv = _FakeTelnetServer(initial)
        try:
            pr = telnet.probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertEqual(pr["vendor"], "solaris")

    def test_probe_environ_leak_captured(self):
        # First: server offers NEW-ENVIRON. Then (after our SEND) it sends IS.
        initial = IAC_DO_NEW_ENVIRON + b"\r\nlogin: "
        followup = IAC_SB_NEWENV_IS_USER_ROOT + IAC_SB_NEWENV_IS_DISPLAY
        srv = _FakeTelnetServer(initial, followup=followup)
        try:
            pr = telnet.probe(srv.host, srv.port, timeout=4)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertTrue(pr["environ_offered"])
        self.assertEqual(pr["environ_leak"].get("USER"), "root")
        self.assertEqual(pr["environ_leak"].get("DISPLAY"), ":0.0")

    def test_probe_encrypt_and_auth_offered(self):
        initial = (IAC_WILL_ENCRYPT + IAC_WILL_AUTH + IAC_WILL_ECHO
                   + b"\r\nlogin: ")
        srv = _FakeTelnetServer(initial)
        try:
            pr = telnet.probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertTrue(pr["encrypt_offered"])
        self.assertTrue(pr["auth_offered"])

    def test_probe_dead_port_returns_none(self):
        # Port 1 on loopback should refuse — probe returns None.
        pr = telnet.probe("127.0.0.1", 1, timeout=1)
        self.assertIsNone(pr)


# --- T2 controlled read: RFC 2946 ENCRYPT probe --------------------------------

# RFC 2946: ENCRYPT is option 38 (0x26). IAC WONT = 0xFC, IAC WILL = 0xFB.
IAC_WONT_ENCRYPT = bytes.fromhex("fffc26")
IAC_DONT_ENCRYPT = bytes.fromhex("fffe26")


class EncryptProbeTest(unittest.TestCase):
    """The T2 promotion: single-shot DO ENCRYPT + capture the server's reply.

    Each subtest asserts the parser recognised a concrete server-side response
    (WONT / WILL / DONT ENCRYPT) or the definitive silence case."""

    def test_encrypt_probe_captures_wont_refusal(self):
        # Server settles the opening negotiation, then answers our DO ENCRYPT
        # with the definitive IAC WONT ENCRYPT refusal.
        initial = IAC_WILL_ECHO + b"\r\nlogin: "
        followup = IAC_WONT_ENCRYPT
        srv = _FakeTelnetServer(initial, followup=followup)
        try:
            ep = telnet.encrypt_probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        self.assertIsNotNone(ep)
        self.assertTrue(ep["asked"])
        self.assertTrue(ep["server_wont_encrypt"])
        self.assertFalse(ep["server_will_encrypt"])
        self.assertFalse(ep["silent"])
        self.assertIn("WONT ENCRYPT", ep["evidence"])
        self.assertIn("fffc26", ep["response_hex"])

    def test_encrypt_probe_captures_will_acceptance(self):
        # An accepting server: initial silent-ish, replies WILL ENCRYPT.
        initial = IAC_WILL_ECHO + b"\r\nlogin: "
        followup = IAC_WILL_ENCRYPT
        srv = _FakeTelnetServer(initial, followup=followup)
        try:
            ep = telnet.encrypt_probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        self.assertIsNotNone(ep)
        self.assertTrue(ep["server_will_encrypt"])
        self.assertFalse(ep["server_wont_encrypt"])
        self.assertIn("WILL ENCRYPT", ep["evidence"])

    def test_encrypt_probe_captures_dont_refusal(self):
        initial = b"\r\nlogin: "
        followup = IAC_DONT_ENCRYPT
        srv = _FakeTelnetServer(initial, followup=followup)
        try:
            ep = telnet.encrypt_probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        self.assertIsNotNone(ep)
        self.assertTrue(ep["server_dont_encrypt"])

    def test_encrypt_probe_silent_server(self):
        # Server sends only an initial banner and never answers the DO ENCRYPT.
        initial = IAC_WILL_ECHO + b"\r\nlogin: "
        srv = _FakeTelnetServer(initial, followup=b"")
        try:
            ep = telnet.encrypt_probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertIsNotNone(ep)
        self.assertTrue(ep["silent"])
        self.assertFalse(ep["server_wont_encrypt"])
        self.assertFalse(ep["server_will_encrypt"])

    def test_encrypt_probe_dead_port_returns_none(self):
        # Loopback port 1 refuses -> probe returns None (no exception).
        self.assertIsNone(telnet.encrypt_probe("127.0.0.1", 1, timeout=1))

    def test_encrypt_probe_timeout_bounded(self):
        # A silent server must not stall the probe beyond the timeout window.
        srv = _FakeTelnetServer(b"", followup=b"")
        try:
            import time as _t
            t0 = _t.monotonic()
            ep = telnet.encrypt_probe(srv.host, srv.port, timeout=2)
            elapsed = _t.monotonic() - t0
        finally:
            srv.close()
        self.assertIsNotNone(ep)
        self.assertLess(elapsed, 6.0)


class EncryptProbeFindingUpgradeTest(unittest.TestCase):
    """T2 promotion: when encrypt_probe captured a definitive server reply,
    the telnet_no_encrypt finding upgrades to depth_tier='t2' with the raw
    wire bytes surfaced as evidence."""

    def test_definitive_wont_upgrades_to_t2(self):
        h, pr = _host_with_telnet(b"login: ", encrypt=False)
        pr["encrypt_probe"] = {
            "asked": True, "response_hex": "fffc26",
            "server_wont_encrypt": True, "server_will_encrypt": False,
            "server_dont_encrypt": False, "silent": False,
            "initial_offered": False,
            "evidence": "Server replied IAC WONT ENCRYPT (0xFF 0xFC 0x26) — "
                        "a definitive RFC 2946 refusal.",
            "elapsed": 0.1,
        }
        fs = telnet.findings([h], {(h.ip, 23): pr})
        f = next(x for x in fs if x["kind"] == "telnet_no_encrypt")
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("T2 controlled read", f["detail"])
        self.assertIn("fffc26", f["detail"])
        self.assertIn("IAC WONT ENCRYPT", f["detail"])

    def test_silent_probe_stays_t0(self):
        # No definitive server reply -> tier remains t0 (existing behaviour).
        h, pr = _host_with_telnet(b"login: ", encrypt=False)
        pr["encrypt_probe"] = {
            "asked": True, "response_hex": "",
            "server_wont_encrypt": False, "server_will_encrypt": False,
            "server_dont_encrypt": False, "silent": True,
            "initial_offered": False,
            "evidence": "Server ignored the DO ENCRYPT request entirely.",
            "elapsed": 0.5,
        }
        fs = telnet.findings([h], {(h.ip, 23): pr})
        f = next(x for x in fs if x["kind"] == "telnet_no_encrypt")
        self.assertEqual(f["depth_tier"], "t0")
        self.assertNotIn("T2 controlled read", f["detail"])

    def test_missing_encrypt_probe_stays_t0(self):
        # T1 path unchanged: no probe -> t0 finding still fires with no crash.
        h, pr = _host_with_telnet(b"login: ", encrypt=False)
        self.assertNotIn("encrypt_probe", pr)
        fs = telnet.findings([h], {(h.ip, 23): pr})
        f = next(x for x in fs if x["kind"] == "telnet_no_encrypt")
        self.assertEqual(f["depth_tier"], "t0")


# --- known-bad map + findings --------------------------------------------------

def _host_with_telnet(banner_bytes: bytes,
                     vendor: str = "unknown",
                     port: int = 23,
                     environ_leak: dict | None = None,
                     ntlm: dict | None = None,
                     encrypt: bool = False,
                     ayt: bool = False,
                     default_creds: list | None = None,
                     solaris_dashf: dict | None = None,
                     timing_enum: list | None = None) -> tuple[Host, dict]:
    h = Host(ip="10.0.0.5", ports=[Port(portid=port, service="telnet")])
    pr = {
        "ip": h.ip, "port": port,
        "banner": telnet._clean_banner(banner_bytes),
        "options_will": [telnet.OPT_ECHO],
        "options_do": [telnet.OPT_TTYPE],
        "options_wont": [], "options_dont": [],
        "encrypt_offered": encrypt, "auth_offered": False,
        "environ_offered": bool(environ_leak),
        "environ_leak": environ_leak or {},
        "vendor": vendor, "vendor_desc": "",
        "ntlm": ntlm or {}, "ayt_ok": ayt, "tls": port == telnet._TLS_PORT,
        "looks_like_telnet": True,
    }
    if default_creds is not None:
        pr["default_creds"] = default_creds
    if solaris_dashf is not None:
        pr["solaris_dashf"] = solaris_dashf
    if timing_enum is not None:
        pr["timing_enum"] = timing_enum
    return h, pr


class FindingsTest(unittest.TestCase):
    def test_presence_finding_always_fires(self):
        h, pr = _host_with_telnet(b"nothing here", vendor="unknown")
        fs = telnet.findings([h], {(h.ip, 23): pr})
        titles = [f["title"] for f in fs]
        self.assertTrue(any("cleartext by design" in t for t in titles))

    def test_solaris_known_bad_fires_from_banner(self):
        h, pr = _host_with_telnet(SOLARIS_BANNER, vendor="solaris")
        fs = telnet.findings([h], {(h.ip, 23): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("telnet_known_backdoor", kinds)
        backdoor = next(f for f in fs if f["kind"] == "telnet_known_backdoor")
        self.assertEqual(backdoor["severity"], "critical")
        self.assertIn("CVE-2007-0882", backdoor["title"])

    def test_busybox_known_bad(self):
        h, pr = _host_with_telnet(BUSYBOX_PROMPT, vendor="busybox")
        fs = telnet.findings([h], {(h.ip, 23): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("telnet_known_backdoor", kinds)

    def test_environ_leak_finding(self):
        h, pr = _host_with_telnet(b"login: ",
                                  environ_leak={"USER": "admin"})
        fs = telnet.findings([h], {(h.ip, 23): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("telnet_environ_leak", kinds)

    def test_encrypt_absent_finding(self):
        h, pr = _host_with_telnet(b"login: ", encrypt=False)
        fs = telnet.findings([h], {(h.ip, 23): pr})
        self.assertTrue(any(f["kind"] == "telnet_no_encrypt" for f in fs))

    def test_encrypt_present_suppresses_finding(self):
        h, pr = _host_with_telnet(b"login: ", encrypt=True)
        fs = telnet.findings([h], {(h.ip, 23): pr})
        self.assertFalse(any(f["kind"] == "telnet_no_encrypt" for f in fs))

    def test_vendor_fingerprint_finding(self):
        h, pr = _host_with_telnet(CISCO_BANNER, vendor="cisco-ios")
        fs = telnet.findings([h], {(h.ip, 23): pr})
        self.assertTrue(any(f["kind"] == "telnet_vendor_fingerprint" for f in fs))

    def test_ntlm_av_pair_finding(self):
        h, pr = _host_with_telnet(b"Welcome to Microsoft Telnet",
                                  vendor="windows",
                                  ntlm={"nb_computer_name": "WEB01",
                                        "dns_domain_name": "corp.local"})
        fs = telnet.findings([h], {(h.ip, 23): pr})
        self.assertTrue(any(f["kind"] == "telnet_ntlm_info_leak" for f in fs))

    def test_ayt_liveness_info(self):
        h, pr = _host_with_telnet(b"login: ", ayt=True)
        fs = telnet.findings([h], {(h.ip, 23): pr})
        self.assertTrue(any(f["kind"] == "telnet_ayt_liveness" for f in fs))

    def test_default_creds_finding_critical(self):
        h, pr = _host_with_telnet(BUSYBOX_PROMPT, vendor="busybox",
                                  default_creds=[{"user": "root",
                                                  "password": "xc3511",
                                                  "evidence": "# ",
                                                  "elapsed": 0.5}])
        fs = telnet.findings([h], {(h.ip, 23): pr})
        creds_f = [f for f in fs if f["kind"] == "telnet_default_creds"]
        self.assertEqual(len(creds_f), 1)
        self.assertEqual(creds_f[0]["severity"], "critical")

    def test_solaris_dashf_success_finding(self):
        h, pr = _host_with_telnet(SOLARIS_BANNER, vendor="solaris",
                                  solaris_dashf={"success": True,
                                                 "evidence": "# uname -a"})
        fs = telnet.findings([h], {(h.ip, 23): pr})
        self.assertTrue(any(f["kind"] == "telnet_solaris_dashf_rce" for f in fs))

    def test_timing_enum_valid_users(self):
        h, pr = _host_with_telnet(b"login: ",
                                  timing_enum=[{"user": "alice",
                                                "elapsed": 3.0,
                                                "baseline_avg": 1.0,
                                                "valid": True}])
        fs = telnet.findings([h], {(h.ip, 23): pr})
        self.assertTrue(any(f["kind"] == "telnet_user_enum_timing" for f in fs))

    def test_sniff_runbook_always_fires(self):
        h, pr = _host_with_telnet(b"login: ")
        fs = telnet.findings([h], {(h.ip, 23): pr})
        self.assertTrue(any(f["kind"] == "telnet_sniff_runbook" for f in fs))


# --- NTLM AV_PAIR parse --------------------------------------------------------

def _build_ntlm_type2(av_pairs: list[tuple[int, bytes]]) -> bytes:
    """Assemble a minimal NTLMSSP CHALLENGE_MESSAGE (message type 2) with the
    given AV_PAIRs in TargetInfo. Follows MS-NLMP §2.2.1.2 header layout."""
    ti = bytearray()
    for av_id, val in av_pairs:
        ti += struct.pack("<HH", av_id, len(val)) + val
    ti += struct.pack("<HH", 0, 0)  # MsvAvEOL
    # Header: 8 sig + 4 msgtype + 8 target-name buf + 4 flags + 8 challenge
    # + 8 reserved + 8 target-info buf + 8 version = 56 bytes minimum.
    header_len = 56
    header = bytearray()
    header += b"NTLMSSP\x00"
    header += struct.pack("<I", 2)                    # MessageType
    header += struct.pack("<HHI", 0, 0, header_len)   # TargetName SecBuf (empty)
    header += struct.pack("<I", 0)                    # NegotiateFlags
    header += b"\x00" * 8                             # ServerChallenge
    header += b"\x00" * 8                             # Reserved
    header += struct.pack("<HHI", len(ti), len(ti), header_len)  # TargetInfo
    header += b"\x00" * 8                             # Version
    assert len(header) == header_len
    return bytes(header + ti)


class NtlmParseTest(unittest.TestCase):
    def test_avpair_names_decoded(self):
        # MS-NLMP §2.2.2.1: AvId=1 MsvAvNbComputerName, 4 MsvAvDnsDomainName.
        av = [
            (1, "WEB01".encode("utf-16-le")),
            (4, "corp.local".encode("utf-16-le")),
        ]
        blob = _build_ntlm_type2(av)
        out = telnet._parse_ntlm_type2(blob)
        self.assertEqual(out.get("nb_computer_name"), "WEB01")
        self.assertEqual(out.get("dns_domain_name"), "corp.local")

    def test_not_ntlm_returns_empty(self):
        self.assertEqual(telnet._parse_ntlm_type2(b"nothing here at all"), {})


# --- targets, findings_to_vulns wiring -----------------------------------------

class TargetsAndVulnsTest(unittest.TestCase):
    def test_telnet_targets_picks_23(self):
        h = Host(ip="10.0.0.1", ports=[Port(portid=23, service="telnet"),
                                        Port(portid=80, service="http")])
        t = telnet.telnet_targets([h])
        self.assertEqual(len(t), 1)
        self.assertEqual(t[0]["port"], 23)

    def test_telnet_targets_picks_iot_alt_ports(self):
        h = Host(ip="10.0.0.1", ports=[Port(portid=2323),
                                        Port(portid=5555)])
        t = telnet.telnet_targets([h])
        self.assertEqual(sorted(x["port"] for x in t), [2323, 5555])

    def test_findings_to_vulns_produces_source_telnet(self):
        h, pr = _host_with_telnet(SOLARIS_BANNER, vendor="solaris")
        fs = telnet.findings([h], {(h.ip, 23): pr})
        by_ip = telnet.findings_to_vulns(fs)
        vulns = by_ip.get("10.0.0.5") or []
        self.assertTrue(vulns)
        self.assertTrue(all(v.source == "telnet" for v in vulns))
        self.assertTrue(any(v.severity == "critical" for v in vulns))


# --- gated attacks: refuse to run without opt-in -------------------------------

class GateTest(unittest.TestCase):
    def test_default_cred_sweep_refuses_without_gate(self, ):
        # No env, no active_attacks=True -> returns [] without touching net.
        import os
        prev = os.environ.pop("RECCE_ACTIVE_ATTACKS", None)
        try:
            hits = telnet.default_cred_sweep("127.0.0.1", 1, "busybox",
                                             timeout=1)
        finally:
            if prev is not None:
                os.environ["RECCE_ACTIVE_ATTACKS"] = prev
        self.assertEqual(hits, [])

    def test_solaris_dashf_gated(self):
        import os
        prev = os.environ.pop("RECCE_ACTIVE_ATTACKS", None)
        try:
            r = telnet.solaris_dashf_bypass("127.0.0.1", 1, timeout=1)
        finally:
            if prev is not None:
                os.environ["RECCE_ACTIVE_ATTACKS"] = prev
        self.assertFalse(r["success"])
        self.assertTrue(r.get("gated"))


if __name__ == "__main__":
    unittest.main()
