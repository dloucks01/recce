"""Tests for recce.services.nrpe.

Wire-level packet fixtures (raw bytes, matching the NRPE v2 protocol as
documented in nrpe.h — packet_version=2, packet_type QUERY=1/RESPONSE=2,
1036-byte fixed frame with CRC32 over the whole zeroed packet), plus a
threaded loopback server that responds with those bytes for the probe/
findings paths. No network traffic leaves loopback.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest
import zlib

from recce.core.models import Host, Port
from recce.services import nrpe


# --- raw wire helpers -------------------------------------------------------

_V2_PACKET_LEN = 1036
_V2_BUFFER_LEN = 1024


def _make_v2_packet(ptype: int, result_code: int, body: str,
                    version: int = 2, corrupt_crc: bool = False) -> bytes:
    """Build a wire-format NRPE v2 packet (1036 bytes) with a valid CRC32."""
    payload = body.encode("utf-8")[:_V2_BUFFER_LEN - 1] + b"\x00"
    payload = payload + b"\xff" * (_V2_BUFFER_LEN - len(payload))
    header = struct.pack(">HHIH", version, ptype, 0, result_code)
    pad = b"\x00\x00"
    pkt = header + payload + pad
    crc = zlib.crc32(pkt) & 0xffffffff
    if corrupt_crc:
        crc ^= 0xdeadbeef
    return pkt[:4] + struct.pack(">I", crc) + pkt[8:]


# --- Encoder / decoder --------------------------------------------------------

class WireFormatTest(unittest.TestCase):
    def test_v2_query_is_fixed_length_and_wellformed(self):
        pkt = nrpe._build_v2_query("_NRPE_CHECK")
        self.assertEqual(len(pkt), _V2_PACKET_LEN)
        version, ptype, crc, rc = struct.unpack(">HHIH", pkt[:10])
        self.assertEqual(version, 2)
        self.assertEqual(ptype, 1)          # query
        self.assertEqual(rc, 0)
        # CRC must validate on the zeroed packet.
        zeroed = pkt[:4] + b"\x00\x00\x00\x00" + pkt[8:]
        self.assertEqual(zlib.crc32(zeroed) & 0xffffffff, crc)
        # Command sits at offset 10 followed by NUL, then 0xff padding.
        self.assertTrue(pkt[10:21].startswith(b"_NRPE_CHECK"))
        self.assertEqual(pkt[21], 0x00)
        self.assertEqual(pkt[22], 0xff)
        # Trailing two-byte pad is 0x00 0x00.
        self.assertEqual(pkt[-2:], b"\x00\x00")

    def test_parse_v2_response_extracts_output_and_verifies_crc(self):
        pkt = _make_v2_packet(ptype=2, result_code=0, body="NRPE v2.15")
        r = nrpe._parse_v2_response(pkt)
        self.assertIsNotNone(r)
        self.assertEqual(r["version"], 2)
        self.assertEqual(r["type"], 2)
        self.assertEqual(r["result_code"], 0)
        self.assertEqual(r["output"], "NRPE v2.15")
        self.assertTrue(r["crc_valid"])

    def test_parse_v2_response_rejects_non_response_type(self):
        # A query packet (type=1) is not a valid response.
        pkt = _make_v2_packet(ptype=1, result_code=0, body="anything")
        self.assertIsNone(nrpe._parse_v2_response(pkt))

    def test_parse_v2_response_detects_bad_crc(self):
        pkt = _make_v2_packet(ptype=2, result_code=0, body="NRPE v2.15",
                              corrupt_crc=True)
        r = nrpe._parse_v2_response(pkt)
        self.assertIsNotNone(r)
        self.assertFalse(r["crc_valid"])

    def test_version_regex(self):
        self.assertEqual(nrpe._parse_version("NRPE v2.15"), "2.15")
        self.assertEqual(nrpe._parse_version("NRPE v3.2.1"), "3.2.1")
        self.assertEqual(nrpe._parse_version("NRPE v4.0.0"), "4.0.0")
        self.assertEqual(nrpe._parse_version("hi there"), "")

    def test_command_not_defined_detector(self):
        self.assertTrue(nrpe._command_not_defined(
            "NRPE: Command 'check_foo' not defined"))
        self.assertFalse(nrpe._command_not_defined("USERS OK - 3 users"))

    def test_classify_os_from_plugin_path(self):
        self.assertEqual(
            nrpe._classify_os("NRPE: /usr/lib64/nagios/plugins/check_x: "
                              "No such file"), "RHEL/CentOS/Fedora")
        self.assertEqual(
            nrpe._classify_os("NRPE: /usr/lib/nagios/plugins/check_x not found"),
            "Debian/Ubuntu")
        self.assertEqual(nrpe._classify_os("nothing here"), "")

    def test_extract_users_from_verbose_check_users(self):
        text = "USERS OK - 3 users currently logged in (users: alice, bob, carol)"
        got = nrpe._extract_users(text)
        self.assertEqual(sorted(got), ["alice", "bob", "carol"])

    def test_extract_hostname_from_check_output(self):
        self.assertEqual(nrpe._extract_hostname("hostname: web-01.corp.example"),
                         "web-01.corp.example")
        self.assertEqual(nrpe._extract_hostname("mail.example.com\n"),
                         "mail.example.com")

    def test_is_nrpe_predicate(self):
        self.assertTrue(nrpe.is_nrpe(Port(portid=5666)))
        self.assertTrue(nrpe.is_nrpe(Port(portid=9999, service="nrpe")))
        self.assertTrue(nrpe.is_nrpe(Port(portid=9999, product="Nagios NRPE")))
        self.assertFalse(nrpe.is_nrpe(Port(portid=22, service="ssh")))


# --- Loopback NRPE server ---------------------------------------------------

class _NrpeServer:
    """Minimal loopback NRPE responder.

    responder(command_str) -> response_bytes. Returning b"" closes the
    connection with nothing.
    """

    def __init__(self, responder, use_tls: bool = False,
                 anon_dh: bool = False):
        self._respond = responder
        self._use_tls = use_tls
        self._anon_dh = anon_dh
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.3)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                self._handle(conn)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def _handle(self, conn):
        conn.settimeout(2.0)
        data = b""
        while len(data) < _V2_PACKET_LEN:
            try:
                chunk = conn.recv(_V2_PACKET_LEN - len(data))
            except (socket.timeout, OSError):
                return
            if not chunk:
                return
            data += chunk
        if len(data) < 24:
            return
        buf = data[10:10 + _V2_BUFFER_LEN]
        cmd = buf.split(b"\x00", 1)[0].decode("utf-8", "replace")
        resp = self._respond(cmd)
        if resp:
            try:
                conn.sendall(resp)
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def _default_responder(cmd: str) -> bytes:
    """Handle _NRPE_CHECK, check_users, check_hostname, check_procs, and
    absent commands with paths that fingerprint Debian."""
    if cmd == "_NRPE_CHECK":
        return _make_v2_packet(2, 0, "NRPE v2.15")
    if cmd == "check_users":
        return _make_v2_packet(2, 0,
                               "USERS OK - 2 users currently logged in "
                               "(users: alice, bob)")
    if cmd == "check_procs":
        return _make_v2_packet(2, 0,
                               "PROCS OK: 42 processes\n"
                               "root 1 /sbin/init\n"
                               "alice 202 -bash")
    if cmd == "check_hostname":
        return _make_v2_packet(2, 0, "web-01.corp.example")
    if cmd == "check_load":
        return _make_v2_packet(2, 0, "OK - load average: 0.10, 0.20, 0.30")
    if cmd == "check_mysql":
        return _make_v2_packet(2, 0, "MYSQL OK - Uptime: 12345")
    if cmd == "check_http":
        return _make_v2_packet(2, 0, "HTTP OK: HTTP/1.1 200 OK")
    # Unknown commands → not-defined with Debian plugin path.
    return _make_v2_packet(2, 3,
                           f"NRPE: Command '{cmd}' not defined "
                           "(/usr/lib/nagios/plugins/{cmd} missing)")


class ProbeTest(unittest.TestCase):
    def test_probe_plaintext_extracts_version_users_hostname(self):
        srv = _NrpeServer(_default_responder)
        try:
            pr = nrpe.probe(srv.host, srv.port, timeout=2,
                            commands=("check_users", "check_hostname",
                                      "check_load", "check_mysql",
                                      "check_http", "check_procs",
                                      "check_bogus"))
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["plaintext"])
        self.assertFalse(pr["tls"])
        self.assertEqual(pr["version"], "2.15")
        self.assertTrue(pr["crc32_only_integrity"])
        self.assertIn("check_users", pr["commands_present"])
        self.assertIn("check_load", pr["commands_present"])
        self.assertIn("check_mysql", pr["commands_present"])
        self.assertIn("check_bogus", pr["commands_absent"])
        self.assertIn("alice", pr["users"])
        self.assertIn("bob", pr["users"])
        self.assertEqual(pr["hostname"], "web-01.corp.example")
        self.assertEqual(pr["os_hint"], "Debian/Ubuntu")

    def test_probe_cve_2020_6581_flags_pre_321_version(self):
        srv = _NrpeServer(lambda cmd: _make_v2_packet(2, 0, "NRPE v3.1.0")
                          if cmd == "_NRPE_CHECK"
                          else _make_v2_packet(2, 3, "NRPE: not defined"))
        try:
            pr = nrpe.probe(srv.host, srv.port, timeout=2, commands=())
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version"], "3.1.0")
        self.assertTrue(pr["cve_2020_6581_applies"])

    def test_probe_cve_2020_6581_clears_on_modern_version(self):
        srv = _NrpeServer(lambda cmd: _make_v2_packet(2, 0, "NRPE v4.0.3")
                          if cmd == "_NRPE_CHECK"
                          else _make_v2_packet(2, 3, "NRPE: not defined"))
        try:
            pr = nrpe.probe(srv.host, srv.port, timeout=2, commands=())
        finally:
            srv.close()
        self.assertEqual(pr["version"], "4.0.3")
        self.assertFalse(pr["cve_2020_6581_applies"])

    def test_probe_arg_injection_marker_confirms_rce(self):
        # Only echo the marker back for the arg-injection payload; the
        # baseline exchange must complete first with a real _NRPE_CHECK.
        def responder(cmd):
            if cmd == "_NRPE_CHECK":
                return _make_v2_packet(2, 0, "NRPE v2.14")
            if cmd == "check_users":
                return _make_v2_packet(2, 0, "USERS OK - 1 user")
            # The arg-injection payload starts with the target command
            # name followed by "!"; simulate a vulnerable daemon by
            # echoing the marker back verbatim.
            if nrpe._ARG_INJECTION_MARKER + "_LF" in cmd:
                return _make_v2_packet(
                    2, 0, f"OK - {nrpe._ARG_INJECTION_MARKER}_LF echoed")
            if nrpe._ARG_INJECTION_MARKER in cmd:
                return _make_v2_packet(
                    2, 0, f"OK - {nrpe._ARG_INJECTION_MARKER} echoed uid=0")
            return _make_v2_packet(2, 3, "NRPE: not defined")

        srv = _NrpeServer(responder)
        try:
            pr = nrpe.probe(srv.host, srv.port, timeout=2,
                            commands=("check_users",), active_rce=True)
        finally:
            srv.close()
        self.assertTrue(pr["arg_injection_rce"])
        self.assertIn(nrpe._ARG_INJECTION_MARKER, pr["arg_injection_evidence"])
        self.assertTrue(pr["metachar_bypass_rce"])
        self.assertIn(nrpe._ARG_INJECTION_MARKER + "_LF",
                      pr["metachar_bypass_evidence"])

    def test_probe_dead_port_returns_unreachable(self):
        pr = nrpe.probe("127.0.0.1", 1, timeout=1, commands=())
        self.assertFalse(pr["reachable"])
        self.assertFalse(pr["plaintext"])
        self.assertFalse(pr["tls"])

    def test_probe_non_nrpe_server_not_flagged(self):
        # Server sends back garbage that is not a valid NRPE response.
        def responder(cmd):
            return b"HTTP/1.1 400 Bad Request\r\n\r\n" + b"\x00" * 1000
        srv = _NrpeServer(responder)
        try:
            pr = nrpe.probe(srv.host, srv.port, timeout=2, commands=())
        finally:
            srv.close()
        self.assertFalse(pr["reachable"])


# --- TLS anon-DH detection (monkeypatch avoids real TLS + cert plumbing) ----

class TlsAnonDhDetectionTest(unittest.TestCase):
    def test_anon_dh_cipher_flagged(self, monkeypatch=None):
        # We monkeypatch _try_tls to simulate a successful anon-DH handshake
        # rather than stand up a full self-signed TLS server. The purpose
        # of the test is the finding path, not OpenSSL cipher negotiation.
        fake_parsed = {"version": 4, "type": 2, "crc": 0, "crc_valid": True,
                       "result_code": 0, "output": "NRPE v4.0.3"}
        fake_info = {"handshake_ok": True, "anon_dh": True,
                     "cipher": "ADH-AES256-SHA", "cert_der": b"",
                     "cert_cn": "", "cert_sans": [], "error": ""}
        original_plain = nrpe._try_plain
        original_tls = nrpe._try_tls
        try:
            nrpe._try_plain = lambda *a, **k: None
            nrpe._try_tls = lambda *a, **k: (fake_parsed, fake_info)
            pr = nrpe.probe("127.0.0.1", 5666, timeout=1, commands=())
        finally:
            nrpe._try_plain = original_plain
            nrpe._try_tls = original_tls
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["tls"])
        self.assertTrue(pr["anon_dh_tls"])
        self.assertEqual(pr["tls_cipher"], "ADH-AES256-SHA")
        self.assertEqual(pr["version"], "4.0.3")


# --- Findings emission ------------------------------------------------------

def _fake_host(ip: str = "10.0.0.5", port: int = 5666,
               extra_ports=()) -> Host:
    ports = [Port(portid=port, service="nrpe")]
    for pid, svc in extra_ports:
        ports.append(Port(portid=pid, service=svc))
    return Host(ip=ip, ports=ports)


class FindingsTest(unittest.TestCase):
    def _by_kind(self, fs):
        return {f["kind"]: f for f in fs}

    def test_reachable_plaintext_emits_expected_findings(self):
        h = _fake_host()
        pr = {
            "reachable": True, "plaintext": True, "tls": False,
            "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
            "tls_cert_sans": [],
            "version": "2.15", "version_line": "NRPE v2.15",
            "commands_present": ["check_load", "check_users", "check_mysql"],
            "commands_absent": ["check_bogus"],
            "command_outputs": {}, "users": ["alice", "bob"],
            "hostname": "web-01.corp.example",
            "os_hint": "Debian/Ubuntu",
            "arg_injection_rce": False, "arg_injection_evidence": "",
            "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
            "cve_2020_6581_applies": False,
            "crc32_only_integrity": True,
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        kinds = {f["kind"] for f in fs}
        # Expected core findings.
        self.assertIn("nrpe_reachable", kinds)
        self.assertIn("nrpe_version_disclosed", kinds)
        self.assertIn("nrpe_plaintext_traffic", kinds)
        self.assertIn("nrpe_no_message_auth", kinds)
        self.assertIn("nrpe_allowed_hosts_permissive", kinds)
        self.assertIn("nrpe_command_surface", kinds)
        self.assertIn("nrpe_implied_local_services", kinds)
        self.assertIn("nrpe_userlist_extracted", kinds)
        self.assertIn("nrpe_hostname_extracted", kinds)
        self.assertIn("nrpe_os_fingerprint", kinds)
        # Not applicable in this fixture.
        self.assertNotIn("nrpe_anon_dh_tls", kinds)
        self.assertNotIn("nrpe_tls_cert_extracted", kinds)
        self.assertNotIn("nrpe_arg_injection_rce", kinds)
        self.assertNotIn("nrpe_metachar_bypass_rce", kinds)
        self.assertNotIn("nrpe_cve_2020_6581_version", kinds)

        by = self._by_kind(fs)
        self.assertEqual(by["nrpe_reachable"]["severity"], "medium")
        self.assertEqual(by["nrpe_plaintext_traffic"]["severity"], "high")
        self.assertEqual(by["nrpe_allowed_hosts_permissive"]["severity"], "high")
        self.assertIn("CWE-284",
                      by["nrpe_allowed_hosts_permissive"]["cwes"])

    def test_implied_local_services_flags_pivot_only(self):
        # MySQL check is registered on the agent but 3306 is NOT open on
        # the host — that is the localhost-only pivot signal.
        h = _fake_host(extra_ports=[(80, "http")])
        pr = {
            "reachable": True, "plaintext": True, "tls": False,
            "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
            "tls_cert_sans": [], "version": "3.2.1",
            "version_line": "NRPE v3.2.1",
            "commands_present": ["check_mysql", "check_http"],
            "commands_absent": [], "command_outputs": {},
            "users": [], "hostname": "", "os_hint": "",
            "arg_injection_rce": False, "arg_injection_evidence": "",
            "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
            "cve_2020_6581_applies": False,
            "crc32_only_integrity": True,
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        implied = [f for f in fs if f["kind"] == "nrpe_implied_local_services"]
        self.assertEqual(len(implied), 1)
        detail = implied[0]["detail"]
        self.assertIn("mysql", detail)
        self.assertIn("localhost-only", detail)   # 3306 not open on host
        # http is open on 80, so it should not be tagged localhost-only.
        http_seg = detail.split("http", 1)[1][:40]
        self.assertNotIn("localhost-only", http_seg)

    def test_arg_injection_finding_cites_cve_2013_1362(self):
        h = _fake_host()
        pr = {
            "reachable": True, "plaintext": True, "tls": False,
            "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
            "tls_cert_sans": [], "version": "2.14",
            "version_line": "NRPE v2.14",
            "commands_present": ["check_users"], "commands_absent": [],
            "command_outputs": {}, "users": [], "hostname": "", "os_hint": "",
            "arg_injection_rce": True,
            "arg_injection_evidence": f"OK - {nrpe._ARG_INJECTION_MARKER} echoed uid=0",
            "metachar_bypass_rce": True,
            "metachar_bypass_evidence": f"OK - {nrpe._ARG_INJECTION_MARKER}_LF echoed",
            "cve_2020_6581_applies": False,
            "crc32_only_integrity": True,
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        by = self._by_kind(fs)
        self.assertIn("nrpe_arg_injection_rce", by)
        self.assertEqual(by["nrpe_arg_injection_rce"]["severity"], "critical")
        self.assertIn("CVE-2013-1362", by["nrpe_arg_injection_rce"]["cves"])
        self.assertIn("CWE-78", by["nrpe_arg_injection_rce"]["cwes"])
        self.assertIn("nrpe_metachar_bypass_rce", by)
        self.assertEqual(by["nrpe_metachar_bypass_rce"]["severity"], "critical")
        self.assertIn("CVE-2014-2913",
                      by["nrpe_metachar_bypass_rce"]["cves"])

    def test_anon_dh_tls_finding_emitted(self):
        h = _fake_host()
        pr = {
            "reachable": True, "plaintext": False, "tls": True,
            "anon_dh_tls": True, "tls_cipher": "ADH-AES256-SHA",
            "tls_cert_cn": "", "tls_cert_sans": [],
            "version": "4.0.3", "version_line": "NRPE v4.0.3",
            "commands_present": [], "commands_absent": [],
            "command_outputs": {}, "users": [], "hostname": "", "os_hint": "",
            "arg_injection_rce": False, "arg_injection_evidence": "",
            "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
            "cve_2020_6581_applies": False,
            "crc32_only_integrity": False,
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        by = self._by_kind(fs)
        self.assertIn("nrpe_anon_dh_tls", by)
        self.assertEqual(by["nrpe_anon_dh_tls"]["severity"], "high")
        self.assertIn("CWE-295", by["nrpe_anon_dh_tls"]["cwes"])
        # No plaintext / no CRC-only finding when TLS is in use.
        self.assertNotIn("nrpe_plaintext_traffic", by)
        self.assertNotIn("nrpe_no_message_auth", by)

    def test_tls_cert_findings_emitted_when_cert_present(self):
        h = _fake_host()
        pr = {
            "reachable": True, "plaintext": False, "tls": True,
            "anon_dh_tls": False, "tls_cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "tls_cert_cn": "monitor.corp.example",
            "tls_cert_sans": ["monitor.corp.example", "nrpe.corp.example"],
            "version": "4.0.3", "version_line": "NRPE v4.0.3",
            "commands_present": [], "commands_absent": [],
            "command_outputs": {}, "users": [], "hostname": "", "os_hint": "",
            "arg_injection_rce": False, "arg_injection_evidence": "",
            "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
            "cve_2020_6581_applies": False,
            "crc32_only_integrity": False,
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        by = self._by_kind(fs)
        self.assertIn("nrpe_tls_cert_extracted", by)
        self.assertIn("monitor.corp.example",
                      by["nrpe_tls_cert_extracted"]["detail"])
        self.assertNotIn("nrpe_anon_dh_tls", by)

    def test_cve_2020_6581_version_finding_present(self):
        h = _fake_host()
        pr = {
            "reachable": True, "plaintext": True, "tls": False,
            "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
            "tls_cert_sans": [], "version": "3.1.0",
            "version_line": "NRPE v3.1.0",
            "commands_present": [], "commands_absent": [],
            "command_outputs": {}, "users": [], "hostname": "", "os_hint": "",
            "arg_injection_rce": False, "arg_injection_evidence": "",
            "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
            "cve_2020_6581_applies": True,
            "crc32_only_integrity": True,
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        by = self._by_kind(fs)
        self.assertIn("nrpe_cve_2020_6581_version", by)
        self.assertIn("CVE-2020-6581",
                      by["nrpe_cve_2020_6581_version"]["cves"])
        self.assertEqual(by["nrpe_cve_2020_6581_version"]["severity"], "low")

    def test_unreachable_probe_emits_no_findings(self):
        h = _fake_host()
        pr = {"reachable": False}
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        self.assertEqual(fs, [])

    def test_findings_to_vulns_maps_to_vuln_objects(self):
        h = _fake_host()
        pr = {
            "reachable": True, "plaintext": True, "tls": False,
            "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
            "tls_cert_sans": [], "version": "2.15",
            "version_line": "NRPE v2.15",
            "commands_present": ["check_load"], "commands_absent": [],
            "command_outputs": {}, "users": [], "hostname": "", "os_hint": "",
            "arg_injection_rce": False, "arg_injection_evidence": "",
            "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
            "cve_2020_6581_applies": False,
            "crc32_only_integrity": True,
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        by_ip = nrpe.findings_to_vulns(fs)
        self.assertIn(h.ip, by_ip)
        self.assertTrue(all(v.port == 5666 for v in by_ip[h.ip]))
        self.assertTrue(all(v.source == "nrpe" for v in by_ip[h.ip]))

    def test_runbook_shape(self):
        rb = nrpe.runbook("10.0.0.5", 5666)
        self.assertTrue(rb)
        for step in rb:
            self.assertIn("step", step)
            self.assertIn("cmd", step)
            self.assertIn("10.0.0.5", step["cmd"])


# --- T2 uplift: plaintext_traffic captures real server-side evidence -------

class PlaintextT2EvidenceTest(unittest.TestCase):
    """T2 promotion for nrpe_plaintext_traffic.

    T1 was 'plaintext v2 handshake succeeded' — inference from a
    round-trip. T2 = the same plaintext channel actually carried real
    server-side host state (a check_ output line), captured as evidence.
    A single controlled read reused from the enumeration reads already
    performed by probe(); no MITM, no extra network round-trip.
    """

    def test_vulnerable_plaintext_probe_populates_evidence(self):
        # Vulnerable = daemon answers check_load with real host state
        # over cleartext; the enumeration captures it and probe() lifts
        # the first non-error output into plaintext_evidence.
        def responder(cmd):
            if cmd == "_NRPE_CHECK":
                return _make_v2_packet(2, 0, "NRPE v2.15")
            if cmd == "check_load":
                return _make_v2_packet(
                    2, 0, "OK - load average: 0.42, 0.31, 0.19")
            return _make_v2_packet(2, 3, "NRPE: Command not defined")

        srv = _NrpeServer(responder)
        try:
            pr = nrpe.probe(srv.host, srv.port, timeout=2,
                            commands=("check_load",))
        finally:
            srv.close()
        self.assertTrue(pr["plaintext"])
        self.assertIn("load average", pr["plaintext_evidence"])
        self.assertEqual(pr["plaintext_evidence_command"], "check_load")

    def test_patched_tls_probe_leaves_evidence_empty(self):
        # Patched = TLS with a real cert; no plaintext path so no evidence.
        fake_parsed = {"version": 4, "type": 2, "crc": 0, "crc_valid": True,
                       "result_code": 0, "output": "NRPE v4.0.3"}
        fake_info = {"handshake_ok": True, "anon_dh": False,
                     "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
                     "cert_der": b"", "cert_cn": "nrpe.example",
                     "cert_sans": [], "error": ""}
        original_plain = nrpe._try_plain
        original_tls = nrpe._try_tls
        try:
            nrpe._try_plain = lambda *a, **k: None
            nrpe._try_tls = lambda *a, **k: (fake_parsed, fake_info)
            pr = nrpe.probe("127.0.0.1", 5666, timeout=1, commands=())
        finally:
            nrpe._try_plain = original_plain
            nrpe._try_tls = original_tls
        self.assertFalse(pr["plaintext"])
        self.assertEqual(pr["plaintext_evidence"], "")

    def test_timeout_probe_leaves_evidence_empty(self):
        # Timeout = dead port; probe returns unreachable, no evidence.
        pr = nrpe.probe("127.0.0.1", 1, timeout=1, commands=())
        self.assertFalse(pr["reachable"])
        self.assertEqual(pr["plaintext_evidence"], "")

    def test_findings_upgrade_plaintext_traffic_to_t2_with_output(self):
        # With plaintext_evidence populated, the emitted finding carries
        # depth_tier='t2' and an output field with the captured line.
        h = _fake_host()
        pr = {
            "reachable": True, "plaintext": True, "tls": False,
            "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
            "tls_cert_sans": [],
            "version": "2.15", "version_line": "NRPE v2.15",
            "commands_present": ["check_load"], "commands_absent": [],
            "command_outputs": {"check_load": "OK - load average: 0.42, 0.31, 0.19"},
            "users": [], "hostname": "", "os_hint": "",
            "arg_injection_rce": False, "arg_injection_evidence": "",
            "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
            "cve_2020_6581_applies": False,
            "crc32_only_integrity": True,
            "plaintext_evidence": "OK - load average: 0.42, 0.31, 0.19",
            "plaintext_evidence_command": "check_load",
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        pt = [f for f in fs if f["kind"] == "nrpe_plaintext_traffic"][0]
        self.assertEqual(pt["depth_tier"], "t2")
        self.assertIn("output", pt)
        self.assertIn("load average", pt["output"])
        self.assertIn("check_load", pt["detail"])
        self.assertIn("T2 evidence", pt["detail"])

    def test_findings_keep_plaintext_traffic_at_t1_without_evidence(self):
        # T1 path unchanged: empty plaintext_evidence -> depth_tier stays t1
        # and no output field is added.
        h = _fake_host()
        pr = {
            "reachable": True, "plaintext": True, "tls": False,
            "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
            "tls_cert_sans": [],
            "version": "2.15", "version_line": "NRPE v2.15",
            "commands_present": [], "commands_absent": [],
            "command_outputs": {}, "users": [], "hostname": "", "os_hint": "",
            "arg_injection_rce": False, "arg_injection_evidence": "",
            "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
            "cve_2020_6581_applies": False,
            "crc32_only_integrity": True,
            "plaintext_evidence": "",
            "plaintext_evidence_command": "",
        }
        fs = nrpe.findings([h], {(h.ip, 5666): pr})
        pt = [f for f in fs if f["kind"] == "nrpe_plaintext_traffic"][0]
        self.assertEqual(pt["depth_tier"], "t1")
        self.assertNotIn("output", pt)

    def test_findings_skip_not_defined_error_as_evidence(self):
        # A 'not defined' error line must not be lifted as T2 evidence —
        # probe() skips it, so the finding stays at t1.
        srv = _NrpeServer(lambda cmd:
                          _make_v2_packet(2, 0, "NRPE v2.15")
                          if cmd == "_NRPE_CHECK"
                          else _make_v2_packet(
                              2, 3,
                              f"NRPE: Command '{cmd}' not defined"))
        try:
            pr = nrpe.probe(srv.host, srv.port, timeout=2,
                            commands=("check_bogus", "check_alsobogus"))
        finally:
            srv.close()
        self.assertTrue(pr["plaintext"])
        self.assertEqual(pr["plaintext_evidence"], "")
        self.assertEqual(pr["plaintext_evidence_command"], "")


class AnalyzeTest(unittest.TestCase):
    def test_analyze_end_to_end_with_loopback_server(self):
        srv = _NrpeServer(_default_responder)
        try:
            h = Host(ip=srv.host, ports=[Port(portid=srv.port, service="nrpe")])
            res = nrpe.analyze([h], active=True)
        finally:
            srv.close()
        self.assertEqual(res["stats"]["targets"], 1)
        self.assertGreater(res["stats"]["findings"], 0)
        # Reachable target on plaintext.
        pr = res["probes"][f"{srv.host}:{srv.port}"]
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["plaintext"])
        self.assertEqual(pr["version"], "2.15")


if __name__ == "__main__":
    unittest.main()
