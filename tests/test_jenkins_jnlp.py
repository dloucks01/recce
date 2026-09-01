"""Tests for recce.services.jenkins_jnlp.

Fixtures are wire-derived: raw bytes from a real Jenkins TcpSlaveAgentListener
error response, real HTTP-header sets from /tcpSlaveAgentListener/, and a real
DRDA DSS reply (0xD0 magic) captured off Db2 — NOT round-trips through our
own encoder. Sockets are stubbed via monkeypatch and threaded loopback servers;
no network traffic leaves the box.
"""
from __future__ import annotations

import base64
import hashlib
import socket
import struct
import threading
import unittest

from recce.services import jenkins_jnlp as jj
from recce.core.models import Host, Port


# --- wire-derived fixtures --------------------------------------------------

# A real Jenkins 2.319 controller replies to an unknown protocol name with a
# text line naming the offender AND a "supported protocols" listing. Captured
# form (Jenkins source: JnlpAgentReceiveHandler + DefaultJnlpConnectionState):
_JNLP_ERROR_LISTING = (
    b"Unknown protocol: PROTOCOL_INVALID\n"
    b"Supported protocols: PROTOCOL_JNLP4-connect, PROTOCOL_JNLP3-connect, "
    b"PROTOCOL_JNLP2-connect, PROTOCOL_JNLP-connect, PROTOCOL_CLI2-connect, "
    b"PROTOCOL_CLI-connect, PROTOCOL_Ping\n"
)

# A hardened modern controller — only JNLP4 and Ping.
_JNLP_ERROR_HARDENED = (
    b"Protocol:PROTOCOL_INVALID not understood by this server\n"
    b"Supported: PROTOCOL_JNLP4-connect, PROTOCOL_Ping\n"
)

# Db2/DRDA EXCSATRD reply: DSS header [len:2][magic 0xD0][fmt 0x01][corr 0x0001]
# followed by an EXCSATRD body. We only care that byte 2 is 0xD0 so recce
# routes this port to Db2, not to JNLP. Bytes below are the first 32 bytes
# of an EXCSATRD frame captured from a real Db2 LUW 11.5.
_DRDA_REPLY = bytes.fromhex(
    "00 8C D0 01 00 01 00 86 14 43"      # DSS header + start of EXCSATRD
    "00 08 14 04 00 08 14 03 00 07"
    "00 08 14 44 00 07 00 08 24 0F"
    "00 07".replace(" ", ""))


# --- loopback fake servers --------------------------------------------------

class _CannedTCPServer:
    """Accept one connection, discard the first ≤128 bytes, send a fixed
    response, close. Mimics an unauthenticated single-shot agent listener."""

    def __init__(self, response: bytes):
        self._resp = response
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                # Drain what the client wrote (bounded).
                conn.settimeout(0.5)
                try:
                    conn.recv(256)
                except (socket.timeout, OSError):
                    pass
                if self._resp:
                    try:
                        conn.sendall(self._resp)
                    except OSError:
                        pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


# --- version comparison ----------------------------------------------------

class VersionCmpTest(unittest.TestCase):
    def test_2024_43044_weekly(self):
        # Weekly line: fixed at 2.471.
        self.assertTrue(jj.cve_2024_43044_vulnerable("2.319"))
        self.assertTrue(jj.cve_2024_43044_vulnerable("2.470"))
        self.assertFalse(jj.cve_2024_43044_vulnerable("2.471"))
        self.assertFalse(jj.cve_2024_43044_vulnerable("2.472"))

    def test_2024_43044_lts(self):
        # LTS line: fixed at 2.452.3.
        self.assertTrue(jj.cve_2024_43044_vulnerable("2.440.1"))
        self.assertTrue(jj.cve_2024_43044_vulnerable("2.452.2"))
        self.assertFalse(jj.cve_2024_43044_vulnerable("2.452.3"))
        self.assertFalse(jj.cve_2024_43044_vulnerable("2.462.1"))

    def test_2017_1000353_weekly(self):
        self.assertTrue(jj.cve_2017_1000353_vulnerable("2.32"))
        self.assertTrue(jj.cve_2017_1000353_vulnerable("2.56"))
        self.assertFalse(jj.cve_2017_1000353_vulnerable("2.57"))
        self.assertFalse(jj.cve_2017_1000353_vulnerable("2.60"))

    def test_2017_1000353_lts(self):
        self.assertTrue(jj.cve_2017_1000353_vulnerable("2.32.2"))
        self.assertTrue(jj.cve_2017_1000353_vulnerable("2.46.1"))
        self.assertFalse(jj.cve_2017_1000353_vulnerable("2.46.2"))
        self.assertFalse(jj.cve_2017_1000353_vulnerable("2.60.3"))

    def test_garbage_versions(self):
        self.assertFalse(jj.cve_2024_43044_vulnerable(""))
        self.assertFalse(jj.cve_2024_43044_vulnerable("unknown"))
        self.assertFalse(jj.cve_2017_1000353_vulnerable(""))


# --- classifier / signature -------------------------------------------------

class ClassifierTest(unittest.TestCase):
    def test_port_50000_alone(self):
        p = Port(portid=50000)
        self.assertTrue(jj.is_jenkins_jnlp(p))

    def test_port_50000_but_db2_service_wins(self):
        p = Port(portid=50000, service="drda", product="IBM Db2")
        self.assertFalse(jj.is_jenkins_jnlp(p))

    def test_jenkins_svc_tag(self):
        p = Port(portid=61234, service="jnlp-agent",
                 extrainfo="Jenkins JNLP agent listener")
        self.assertTrue(jj.is_jenkins_jnlp(p))

    def test_random_port_no_signal(self):
        p = Port(portid=61234, service="unknown")
        self.assertFalse(jj.is_jenkins_jnlp(p))

    def test_servicefp_matches_signature(self):
        p = Port(portid=61234, servicefp="Jenkins-Agent-Protocols: JNLP4-connect")
        self.assertTrue(jj.is_jenkins_jnlp(p))


# --- protocol-listing parser ------------------------------------------------

class ParseProtocolsTest(unittest.TestCase):
    def test_error_listing_all_protocols(self):
        text = _JNLP_ERROR_LISTING.decode("latin-1")
        protos = jj._parse_protocols(text)
        for expected in ("JNLP-connect", "JNLP2-connect", "JNLP3-connect",
                         "JNLP4-connect", "CLI-connect", "CLI2-connect", "Ping"):
            self.assertIn(expected, protos,
                          f"{expected} missing from parse: {protos}")

    def test_hardened_listing(self):
        text = _JNLP_ERROR_HARDENED.decode("latin-1")
        protos = jj._parse_protocols(text)
        self.assertEqual(protos, ["JNLP4-connect", "Ping"])

    def test_comma_separated_header(self):
        # Real X-Jenkins-Agent-Protocols header form.
        text = "JNLP4-connect, Ping"
        self.assertEqual(jj._parse_protocols(text), ["JNLP4-connect", "Ping"])


# --- disambiguator (JNLP vs Db2) --------------------------------------------

class DisambiguatorTest(unittest.TestCase):
    def test_jnlp_endpoint(self):
        srv = _CannedTCPServer(_JNLP_ERROR_LISTING)
        try:
            r = jj.disambiguate(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertEqual(r["service"], "jnlp")

    def test_db2_endpoint(self):
        srv = _CannedTCPServer(_DRDA_REPLY)
        try:
            r = jj.disambiguate(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertEqual(r["service"], "db2")

    def test_unknown_endpoint(self):
        srv = _CannedTCPServer(b"random garbage no signal here\n")
        try:
            r = jj.disambiguate(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertEqual(r["service"], "unknown")

    def test_unreachable(self):
        # Deliberately closed port.
        r = jj.disambiguate("127.0.0.1", 1, timeout=1)
        self.assertFalse(r["reachable"])
        self.assertEqual(r["service"], "unknown")


# --- negotiate_protocols against a fake JNLP listener -----------------------

class NegotiateTest(unittest.TestCase):
    def test_full_protocol_matrix(self):
        srv = _CannedTCPServer(_JNLP_ERROR_LISTING)
        try:
            r = jj.negotiate_protocols(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertIn("JNLP4-connect", r["protocols"])
        self.assertIn("CLI2-connect", r["protocols"])
        self.assertIn("JNLP-connect", r["protocols"])

    def test_hardened_only_jnlp4(self):
        srv = _CannedTCPServer(_JNLP_ERROR_HARDENED)
        try:
            r = jj.negotiate_protocols(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertEqual(r["protocols"], ["JNLP4-connect", "Ping"])

    def test_unreachable(self):
        r = jj.negotiate_protocols("127.0.0.1", 1, timeout=1)
        self.assertFalse(r["reachable"])
        self.assertEqual(r["protocols"], [])


# --- HTTP sibling fetch (monkeypatched _http_get) ---------------------------

class _FakeIdentity:
    """A believable X-Instance-Identity value + its expected SHA-256."""

    def __init__(self):
        # 32 arbitrary bytes stand in for the DER SPKI. This is what recce
        # SHA-256s — the semantic point is that base64(same-bytes) → same fp.
        self.der = bytes(range(32))
        self.b64 = base64.b64encode(self.der).decode("ascii")
        self.fp = hashlib.sha256(self.der).hexdigest()


class HttpSiblingTest(unittest.TestCase):
    def test_full_metadata_disclosure(self):
        idt = _FakeIdentity()
        headers = {
            "content-type": "text/plain;charset=utf-8",
            "x-jenkins": "2.319.1",
            "x-jenkins-agent-protocols":
                "JNLP4-connect, JNLP2-connect, CLI2-connect, Ping",
            "x-instance-identity": idt.b64,
            "x-hudson-jnlp-port": "50123",
            "x-hudson-cli-port": "50123",
        }
        calls: list[tuple] = []

        def fake_http_get(ip, port, path, tls, timeout):
            calls.append((ip, port, path, tls))
            if port == 8080 and path == "/tcpSlaveAgentListener/":
                return 200, headers, b""
            return None

        h = Host(ip="10.1.2.3", ports=[
            Port(portid=50000),
            Port(portid=8080, service="http", product="Jetty"),
        ])
        original = jj._http_get
        jj._http_get = fake_http_get
        try:
            r = jj.http_sibling(h, timeout=1)
        finally:
            jj._http_get = original

        self.assertTrue(r["found"])
        self.assertEqual(r["http_port"], 8080)
        self.assertEqual(r["jenkins_version"], "2.319.1")
        self.assertEqual(r["agent_port"], 50123)
        self.assertIn("JNLP4-connect", r["protocols"])
        self.assertIn("CLI2-connect", r["protocols"])
        self.assertEqual(r["instance_identity_b64"], idt.b64)
        self.assertEqual(r["instance_identity_fp"], idt.fp)
        # Made only the HTTP-port GET, nothing else.
        self.assertEqual([(c[1], c[2]) for c in calls if c[0] == "10.1.2.3"],
                         [(8080, "/tcpSlaveAgentListener/")])

    def test_no_jenkins_headers_treated_as_not_found(self):
        headers = {"content-type": "text/html", "server": "nginx"}

        def fake_http_get(ip, port, path, tls, timeout):
            return 200, headers, b"<html>nope</html>"

        h = Host(ip="10.1.2.4", ports=[Port(portid=8080, service="http")])
        original = jj._http_get
        jj._http_get = fake_http_get
        try:
            r = jj.http_sibling(h, timeout=1)
        finally:
            jj._http_get = original
        self.assertFalse(r["found"])
        self.assertEqual(r["jenkins_version"], "")

    def test_http_port_candidates_include_web_ports_and_hints(self):
        h = Host(ip="10.1.2.5", ports=[
            Port(portid=50000),
            Port(portid=8443, service="https", tunnel="ssl"),
            Port(portid=9999, service="unknown"),
            Port(portid=443, service="https"),
        ])
        cands = jj._http_ports(h)
        # 8443 (https/tls) and 443 (tls) both marked tls; 9999 skipped
        # entirely (not a web port and not on the hint list).
        pairs = set(cands)
        self.assertIn((8443, True), pairs)
        self.assertIn((443, True), pairs)
        self.assertNotIn((9999, False), pairs)
        self.assertNotIn((9999, True), pairs)


# --- full probe() end-to-end ------------------------------------------------

class ProbeTest(unittest.TestCase):
    def test_probe_against_fake_listener_finds_legacy_protocols(self):
        srv = _CannedTCPServer(_JNLP_ERROR_LISTING)
        try:
            pr = jj.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["is_jnlp"])
        self.assertIn("JNLP-connect", pr["legacy_jnlp"])
        self.assertIn("JNLP2-connect", pr["plaintext_jnlp"])
        self.assertIn("CLI2-connect", pr["cli_legacy"])

    def test_probe_against_db2_endpoint_stops_early(self):
        srv = _CannedTCPServer(_DRDA_REPLY)
        try:
            pr = jj.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["is_jnlp"])
        self.assertIn("Db2", pr["error"])

    def test_probe_unreachable(self):
        pr = jj.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(pr["reachable"])


# --- findings ---------------------------------------------------------------

class FindingsTest(unittest.TestCase):
    def _host_with_open_jnlp(self, port_id=50000, service="jnlp-agent",
                             extrainfo="Jenkins JNLP agent listener"):
        h = Host(ip="10.0.0.1", ports=[
            Port(portid=port_id, service=service, extrainfo=extrainfo),
        ])
        return h

    def test_full_matrix_yields_all_expected_kinds(self):
        idt = _FakeIdentity()
        h = self._host_with_open_jnlp()
        probes = {("10.0.0.1", 50000): {
            "reachable": True, "is_jnlp": True,
            "protocols": ["JNLP4-connect", "JNLP2-connect", "JNLP-connect",
                          "CLI2-connect", "Ping"],
            "legacy_jnlp": ["JNLP2-connect", "JNLP-connect"],
            "plaintext_jnlp": ["JNLP2-connect", "JNLP-connect"],
            "cli_legacy": ["CLI2-connect"],
            "http_sibling": {"found": True, "http_port": 8080, "tls": False,
                             "jenkins_version": "2.319.1", "agent_port": 50000,
                             "protocols": ["JNLP4-connect", "CLI2-connect"],
                             "instance_identity_b64": idt.b64,
                             "instance_identity_fp": idt.fp,
                             "url": "http://10.0.0.1:8080/tcpSlaveAgentListener/"},
            "version": "2.319.1", "instance_identity_fp": idt.fp, "error": "",
            "banner": "",
        }}
        fs = jj.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        # Every headline capability should have surfaced a finding.
        for expect in ("jnlp_legacy_protocols",
                       "jnlp_plaintext_agent_channel",
                       "jnlp_cli2_deser_rce",
                       "jenkins_agent_listener_discovered",
                       "jenkins_controller_identity",
                       "jnlp_version_propagation",
                       "jnlp_cve_2024_43044",
                       "jnlp_reachable"):
            self.assertIn(expect, kinds, f"missing finding: {expect}")
        # Structured CVE ids attached where relevant.
        by_kind = {f["kind"]: f for f in fs}
        self.assertIn("CVE-2017-1000353",
                      by_kind["jnlp_cli2_deser_rce"].get("cves") or [])
        self.assertIn("CVE-2024-43044",
                      by_kind["jnlp_cve_2024_43044"].get("cves") or [])

    def test_hardened_yields_only_baseline_reachable(self):
        h = self._host_with_open_jnlp()
        probes = {("10.0.0.1", 50000): {
            "reachable": True, "is_jnlp": True,
            "protocols": ["JNLP4-connect", "Ping"],
            "legacy_jnlp": [], "plaintext_jnlp": [], "cli_legacy": [],
            "http_sibling": {},
            "version": "", "instance_identity_fp": "", "error": "",
            "banner": "",
        }}
        fs = jj.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("jnlp_reachable", kinds)
        self.assertNotIn("jnlp_legacy_protocols", kinds)
        self.assertNotIn("jnlp_plaintext_agent_channel", kinds)
        self.assertNotIn("jnlp_cli2_deser_rce", kinds)
        self.assertNotIn("jnlp_cve_2024_43044", kinds)

    def test_db2_confirmed_probe_yields_no_findings(self):
        h = self._host_with_open_jnlp()
        # probe() marked is_jnlp False after DRDA magic seen.
        probes = {("10.0.0.1", 50000): {
            "reachable": True, "is_jnlp": False, "protocols": [],
            "legacy_jnlp": [], "plaintext_jnlp": [], "cli_legacy": [],
            "http_sibling": {}, "version": "", "instance_identity_fp": "",
            "error": "endpoint identified as Db2/DRDA, not Jenkins JNLP",
            "banner": "",
        }}
        fs = jj.findings([h], probes)
        self.assertEqual(fs, [])


# --- SPKI fingerprint -------------------------------------------------------

class SpkiFpTest(unittest.TestCase):
    def test_fingerprint_matches_sha256_of_decoded_bytes(self):
        raw = b"\x30\x82\x01\x22" + b"A" * 274  # arbitrary DER-ish bytes
        b64 = base64.b64encode(raw).decode("ascii")
        self.assertEqual(jj._spki_fingerprint(b64), hashlib.sha256(raw).hexdigest())

    def test_empty_and_garbage(self):
        self.assertEqual(jj._spki_fingerprint(""), "")
        # Not valid b64 → falls through; base64.b64decode(validate=False)
        # returns b"" on characters it cannot map, so fingerprint is "".
        self.assertEqual(jj._spki_fingerprint("!!!"), "")


# --- targets and analyze glue ----------------------------------------------

class AnalyzeTest(unittest.TestCase):
    def test_targets_include_only_jnlp_candidates(self):
        h = Host(ip="10.0.0.9", ports=[
            Port(portid=50000, service="jnlp-agent",
                 extrainfo="Jenkins JNLP agent listener"),
            Port(portid=22, service="ssh"),
        ])
        tgts = jj.jnlp_targets([h])
        self.assertEqual(len(tgts), 1)
        self.assertEqual(tgts[0]["port"], 50000)

    def test_analyze_wires_probe_findings_runbooks(self):
        srv = _CannedTCPServer(_JNLP_ERROR_HARDENED)
        try:
            h = Host(ip="127.0.0.1", ports=[
                Port(portid=srv.port, service="jnlp-agent",
                     extrainfo="Jenkins JNLP agent listener"),
            ])
            result = jj.analyze([h], active=True)
        finally:
            srv.close()
        self.assertEqual(result["stats"]["targets"], 1)
        self.assertGreaterEqual(result["stats"]["findings"], 1)
        # Runbook returned per target and matches ip.
        self.assertEqual(result["runbooks"][0]["ip"], "127.0.0.1")


# --- disambiguator uses the real DRDA-magic byte ---------------------------

class DrdaMagicTest(unittest.TestCase):
    def test_reply_has_dss_magic_at_offset_two(self):
        # The wire-derived fixture MUST have 0xD0 at byte 2, or the
        # disambiguator's logic no longer matches reality.
        self.assertEqual(_DRDA_REPLY[2], 0xD0)
        # And the DSS length prefix is a plausible 16-bit BE length.
        (length,) = struct.unpack(">H", _DRDA_REPLY[:2])
        self.assertGreaterEqual(length, 6)
        self.assertLessEqual(length, 65535)


# --- T2 unauth-evidence probe (/whoAmI/api/json on the twin) ---------------

# Wire-derived: Jenkins WhoAmI descriptor as a real anonymous caller sees it
# on an ACL-permissive controller (name='anonymous', authenticated=false).
_WHOAMI_ANON_JSON = (
    b'{"_class":"hudson.security.WhoAmI",'
    b'"anonymous":true,"authenticated":false,'
    b'"authorities":["anonymous"],'
    b'"details":"RemoteIpAddress: 10.0.0.5; SessionId: null",'
    b'"name":"anonymous",'
    b'"toString":"..."}'
)


class UnauthEvidenceProbeTest(unittest.TestCase):
    def test_anonymous_whoami_200_captures_identity(self):
        def fake_http_get(ip, port, path, tls, timeout):
            self.assertEqual(path, "/whoAmI/api/json")
            self.assertFalse(tls)
            return 200, {"content-type": "application/json"}, _WHOAMI_ANON_JSON
        original = jj._http_get
        jj._http_get = fake_http_get
        try:
            ev = jj._probe_unauth_evidence("10.0.0.7", 8080, False, timeout=1)
        finally:
            jj._http_get = original
        self.assertIsNotNone(ev)
        self.assertTrue(ev["probed"])
        self.assertEqual(ev["status"], 200)
        self.assertEqual(ev["endpoint"], "/whoAmI/api/json")
        self.assertEqual(ev["name"], "anonymous")
        self.assertIs(ev["authenticated"], False)
        self.assertIs(ev["anonymous"], True)
        self.assertIn("anonymous", ev["authorities"])

    def test_patched_returns_403_no_identity_capture(self):
        def fake_http_get(ip, port, path, tls, timeout):
            return 403, {}, b"Forbidden"
        original = jj._http_get
        jj._http_get = fake_http_get
        try:
            ev = jj._probe_unauth_evidence("10.0.0.7", 8080, False, timeout=1)
        finally:
            jj._http_get = original
        # Probed but 403 — name field empty, so caller does NOT upgrade.
        self.assertIsNotNone(ev)
        self.assertTrue(ev["probed"])
        self.assertEqual(ev["status"], 403)
        self.assertEqual(ev["name"], "")
        self.assertIsNone(ev["authenticated"])

    def test_timeout_returns_none_no_upgrade(self):
        def fake_http_get(ip, port, path, tls, timeout):
            return None  # simulate timeout / connection error
        original = jj._http_get
        jj._http_get = fake_http_get
        try:
            ev = jj._probe_unauth_evidence("10.0.0.7", 8080, False, timeout=1)
        finally:
            jj._http_get = original
        # None result signals "no evidence — caller keeps T1".
        self.assertIsNone(ev)

    def test_malformed_json_body_leaves_fields_empty(self):
        def fake_http_get(ip, port, path, tls, timeout):
            return 200, {}, b"<html>not-json</html>"
        original = jj._http_get
        jj._http_get = fake_http_get
        try:
            ev = jj._probe_unauth_evidence("10.0.0.7", 8080, False, timeout=1)
        finally:
            jj._http_get = original
        self.assertIsNotNone(ev)
        self.assertEqual(ev["status"], 200)
        self.assertEqual(ev["name"], "")

    def test_authorities_capped_to_six(self):
        big = ('{"name":"anonymous","authenticated":false,"anonymous":true,'
               '"authorities":["a","b","c","d","e","f","g","h","i","j"]}')
        def fake_http_get(ip, port, path, tls, timeout):
            return 200, {}, big.encode("utf-8")
        original = jj._http_get
        jj._http_get = fake_http_get
        try:
            ev = jj._probe_unauth_evidence("10.0.0.7", 8080, False, timeout=1)
        finally:
            jj._http_get = original
        self.assertEqual(len(ev["authorities"]), 6)


class T2PromotionFindingsTest(unittest.TestCase):
    """The jenkins_agent_listener_discovered finding should carry depth_tier=
    't2' with captured evidence when _probe_unauth_evidence produced a real
    identity readback, and stay at 't1' otherwise."""

    def _base_probe(self, http_evidence: dict):
        idt = _FakeIdentity()
        return {("10.0.0.1", 50000): {
            "reachable": True, "is_jnlp": True,
            "protocols": ["JNLP4-connect", "Ping"],
            "legacy_jnlp": [], "plaintext_jnlp": [], "cli_legacy": [],
            "http_sibling": {"found": True, "http_port": 8080, "tls": False,
                             "jenkins_version": "2.319.1",
                             "agent_port": 50000,
                             "protocols": ["JNLP4-connect"],
                             "instance_identity_b64": idt.b64,
                             "instance_identity_fp": idt.fp,
                             "url": "http://10.0.0.1:8080/tcpSlaveAgentListener/"},
            "version": "2.319.1", "instance_identity_fp": idt.fp, "error": "",
            "banner": "",
            "unauth_evidence": http_evidence,
        }}

    def _host(self):
        return Host(ip="10.0.0.1", ports=[
            Port(portid=50000, service="jnlp-agent",
                 extrainfo="Jenkins JNLP agent listener"),
        ])

    def test_upgrade_to_t2_when_whoami_identity_captured(self):
        ev = {"probed": True, "status": 200, "endpoint": "/whoAmI/api/json",
              "name": "anonymous", "authenticated": False, "anonymous": True,
              "authorities": ["anonymous"]}
        probes = self._base_probe(ev)
        fs = jj.findings([self._host()], probes)
        listener = next(f for f in fs
                        if f["kind"] == "jenkins_agent_listener_discovered")
        self.assertEqual(listener["depth_tier"], "t2")
        self.assertIn("evidence", listener)
        self.assertEqual(listener["evidence"]["name"], "anonymous")
        self.assertEqual(listener["evidence"]["http_status"], 200)
        self.assertIs(listener["evidence"]["authenticated"], False)
        # Detail line reflects the captured proof.
        self.assertIn("T2 proof", listener["detail"])
        self.assertIn("/whoAmI/api/json", listener["detail"])
        self.assertIn("anonymous", listener["detail"])

    def test_stays_t1_when_whoami_returns_403(self):
        ev = {"probed": True, "status": 403, "endpoint": "/whoAmI/api/json",
              "name": "", "authenticated": None, "anonymous": None,
              "authorities": []}
        probes = self._base_probe(ev)
        fs = jj.findings([self._host()], probes)
        listener = next(f for f in fs
                        if f["kind"] == "jenkins_agent_listener_discovered")
        self.assertEqual(listener["depth_tier"], "t1")
        self.assertNotIn("evidence", listener)
        self.assertNotIn("T2 proof", listener["detail"])

    def test_stays_t1_when_probe_absent(self):
        # Simulates a timeout / no-response path — probe() left unauth_evidence
        # as the default empty dict.
        probes = self._base_probe({})
        fs = jj.findings([self._host()], probes)
        listener = next(f for f in fs
                        if f["kind"] == "jenkins_agent_listener_discovered")
        self.assertEqual(listener["depth_tier"], "t1")
        self.assertNotIn("evidence", listener)


class ProbeInvokesUnauthEvidenceTest(unittest.TestCase):
    """When probe() fetches the HTTP sibling successfully, it should also invoke
    the T2 evidence probe on the twin — a single extra GET, no more."""

    def test_probe_calls_whoami_after_sibling_hit(self):
        idt = _FakeIdentity()
        headers = {
            "x-jenkins": "2.319.1",
            "x-jenkins-agent-protocols": "JNLP4-connect, Ping",
            "x-instance-identity": idt.b64,
        }
        seen: list[str] = []

        def fake_http_get(ip, port, path, tls, timeout):
            seen.append(path)
            if path == "/tcpSlaveAgentListener/":
                return 200, headers, b""
            if path == "/whoAmI/api/json":
                return 200, {}, _WHOAMI_ANON_JSON
            return None

        srv = _CannedTCPServer(_JNLP_ERROR_HARDENED)
        try:
            h = Host(ip="127.0.0.1", ports=[
                Port(portid=srv.port, service="jnlp-agent"),
                Port(portid=8080, service="http"),
            ])
            original = jj._http_get
            jj._http_get = fake_http_get
            try:
                pr = jj.probe("127.0.0.1", srv.port, timeout=2, host=h)
            finally:
                jj._http_get = original
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["unauth_evidence"].get("name"), "anonymous")
        # Exactly the two twin paths were fetched (single extra read for T2).
        self.assertIn("/tcpSlaveAgentListener/", seen)
        self.assertIn("/whoAmI/api/json", seen)
        self.assertEqual(seen.count("/whoAmI/api/json"), 1)


if __name__ == "__main__":
    unittest.main()
