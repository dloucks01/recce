"""WinRM (5985/5986): WSMan Identify + auth mechanism disclosure.

Tests drive a fake HTTP responder that speaks the WSMan Identify SOAP reply
verbatim from the DMTF wsmanidentity.xsd schema (not from recce's own body),
so a decoder change in recce cannot be masked by a symmetric fixture bug.
"""
from __future__ import annotations

import base64
import socket
import struct
import threading

from http.server import BaseHTTPRequestHandler, HTTPServer

from recce.core.models import Host, Port
from recce.services import winrm


_IDENTIFY_XML = ('<?xml version="1.0" encoding="UTF-8"?>'
                 '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
                 ' xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/'
                 'wsmanidentity.xsd">'
                 '<s:Header/><s:Body><wsmid:IdentifyResponse>'
                 '<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>'
                 '<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>'
                 '<wsmid:ProductVersion>OS: 10.0.19041 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>'
                 '</wsmid:IdentifyResponse></s:Body></s:Envelope>')


def _fake_server(auth: str = "", body: str = _IDENTIFY_XML) -> HTTPServer:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
            code = 200 if body else 401
            self.send_response(code)
            self.send_header("Content-Type", "application/soap+xml;charset=UTF-8")
            if auth:
                for scheme in auth.split(","):
                    self.send_header("WWW-Authenticate", scheme.strip())
            self.end_headers()
            if body:
                self.wfile.write(body.encode("utf-8"))
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _stop(srv):
    srv.shutdown()
    srv.server_close()


# --- decoding ----------------------------------------------------------------

def test_predicate_matches_both_ports_and_service_names():
    for svc, port in (("wsman", 5985), ("wsmans", 5986), ("winrm", 5985)):
        assert winrm.is_winrm(Port(portid=port, state="open", service=svc))
    assert not winrm.is_winrm(Port(portid=80, state="open", service="http"))


def test_identify_parses_vendor_version_and_advertised_auth():
    """A real ntpq-style single-shot exchange should extract exactly what the
    WWW-Authenticate header lists AND the ProductVendor/Version XML."""
    srv = _fake_server(auth="Negotiate, Kerberos, Basic")
    try:
        pr = winrm.probe("127.0.0.1", srv.server_address[1], timeout=2.0)
    finally:
        _stop(srv)
    assert pr["reachable"] is True
    assert pr["vendor"] == "Microsoft Corporation"
    assert "10.0.19041" in pr["version"]
    assert set(pr["auth"]) >= {"Negotiate", "Kerberos", "Basic"}


def test_probe_returns_unreachable_on_a_closed_port():
    """Find a free port and probe it — nothing is listening, so reachable=False."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    pr = winrm.probe("127.0.0.1", port, timeout=1.0)
    assert pr["reachable"] is False


# --- findings ----------------------------------------------------------------

def _host(port=5985):
    return Host(ip="10.0.0.10", ports=[Port(portid=port, state="open", service="wsman")])


def test_basic_over_plain_http_is_high_severity():
    """The specific combination is what matters — Basic anywhere is worth
    naming, Basic over HTTP puts the plaintext password on the segment."""
    fs = winrm.findings([_host(5985)], {("10.0.0.10", 5985): {
        "reachable": True, "port": 5985, "tls": False,
        "auth": ["Negotiate", "Basic"]}})
    f = next(f for f in fs if f["kind"] == "winrm_basic_plaintext")
    assert f["severity"] == "high"


def test_basic_over_tls_is_low_not_ignored():
    """Basic over TLS keeps the password off the wire but still sends it to the
    server in cleartext — the server-side lands it in memory. Worth reporting
    as low, not skipping."""
    fs = winrm.findings([_host(5986)], {("10.0.0.10", 5986): {
        "reachable": True, "port": 5986, "tls": True, "auth": ["Basic"]}})
    kinds = {f["kind"] for f in fs}
    assert "winrm_basic" in kinds
    assert "winrm_basic_plaintext" not in kinds


def test_credssp_produces_its_own_finding():
    """CredSSP forwards plaintext credentials to the server by design — a
    separate concern from Basic and worth flagging on its own."""
    fs = winrm.findings([_host()], {("10.0.0.10", 5985): {
        "reachable": True, "port": 5985, "tls": False,
        "auth": ["Negotiate", "CredSSP"]}})
    assert any(f["kind"] == "winrm_credssp" for f in fs)


def test_reachable_only_still_produces_the_landing_finding():
    fs = winrm.findings([_host()], {("10.0.0.10", 5985): {
        "reachable": True, "port": 5985, "tls": False, "auth": []}})
    f = next(f for f in fs if f["kind"] == "winrm_reachable")
    assert "evil-winrm" in f["command"].lower() or "nxc" in f["command"].lower()


def test_findings_map_to_vulns_on_port_5985():
    fs = winrm.findings([_host()], {("10.0.0.10", 5985): {
        "reachable": True, "port": 5985, "tls": False,
        "auth": ["Basic"]}})
    v = winrm.findings_to_vulns([f for f in fs if f["kind"] == "winrm_basic_plaintext"])
    vuln = v["10.0.0.10"][0]
    assert vuln.source == "winrm" and vuln.port == 5985


def test_analyze_shape_matches_the_service_convention():
    res = winrm.analyze([_host()], active=False)
    assert set(res) >= {"targets", "findings", "runbooks", "probes", "stats"}


# --- NTLM Type-2 CHALLENGE harvest -------------------------------------------

def _av_pair(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def _build_type2_challenge(*, nb_computer: str = "WIN10",
                           nb_domain: str = "CORP",
                           dns_computer: str = "win10.corp.local",
                           dns_domain: str = "corp.local",
                           dns_tree: str = "corp.local",
                           filetime: int = 133_777_777_777_777_777,
                           os_ver: tuple[int, int, int] = (10, 0, 19041)
                           ) -> bytes:
    """Assemble a wire-legal NTLMSSP CHALLENGE_MESSAGE from RFC/MS-NLMP fixed
    offsets (§2.2.1.2 header, §2.2.2.1 AV_PAIRs). The fixture is built here
    from the spec, not by round-tripping recce's own decoder, so a decoder
    change cannot be masked by a symmetric fixture bug."""
    tgt_name = nb_domain.encode("utf-16-le")
    tinfo = (_av_pair(0x0002, nb_domain.encode("utf-16-le"))
             + _av_pair(0x0001, nb_computer.encode("utf-16-le"))
             + _av_pair(0x0004, dns_domain.encode("utf-16-le"))
             + _av_pair(0x0003, dns_computer.encode("utf-16-le"))
             + _av_pair(0x0005, dns_tree.encode("utf-16-le"))
             + _av_pair(0x0007, struct.pack("<Q", filetime))
             + _av_pair(0x0000, b""))

    # Fixed header = 56 bytes: sig(8)+type(4)+tgtname_fields(8)+flags(4)+
    # challenge(8)+reserved(8)+tinfo_fields(8)+version(8) = 56
    flags = (0x00000001 | 0x00000004 | 0x00000200 | 0x00080000
             | 0x02000000)  # +NEGOTIATE_VERSION so the OS bytes populate
    payload_off = 56
    tgt_off = payload_off
    tinfo_off = payload_off + len(tgt_name)
    version = struct.pack("<BBHBBBB", os_ver[0], os_ver[1], os_ver[2],
                          0, 0, 0, 15)
    header = (b"NTLMSSP\x00"
              + struct.pack("<I", 2)
              + struct.pack("<HHI", len(tgt_name), len(tgt_name), tgt_off)
              + struct.pack("<I", flags)
              + b"\x11\x22\x33\x44\x55\x66\x77\x88"        # ServerChallenge
              + b"\x00" * 8                                # Reserved
              + struct.pack("<HHI", len(tinfo), len(tinfo), tinfo_off)
              + version)
    return header + tgt_name + tinfo


def _ntlm_server(*, offer_auth: str = "Negotiate",
                 challenge_blob: bytes | None = None) -> HTTPServer:
    """POST /wsman without Authorization -> 401 advertising `offer_auth`.
    POST /wsman with Authorization: Negotiate <b64> -> 401 carrying
    `challenge_blob` (or a canonical Type-2 if unset) in the same header slot.
    The server also returns a valid Identify body so probe() treats it as reachable."""
    blob = challenge_blob if challenge_blob is not None else _build_type2_challenge()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
            authz = self.headers.get("Authorization", "")
            if authz.lower().startswith("negotiate "):
                # Second round-trip: return the Type-2 challenge.
                b64 = base64.b64encode(blob).decode("ascii")
                self.send_response(401)
                self.send_header("WWW-Authenticate", f"Negotiate {b64}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # First round-trip: Identify + auth advertisement.
            body = _IDENTIFY_XML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/soap+xml;charset=UTF-8")
            for scheme in offer_auth.split(","):
                self.send_header("WWW-Authenticate", scheme.strip())
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_parse_av_pairs_extracts_every_documented_field():
    """MS-NLMP §2.2.2.1 AV_PAIR list decode is wire-driven — build the bytes
    from the spec, feed them through recce's parser, expect every field."""
    ti = (_av_pair(0x0001, "WIN10".encode("utf-16-le"))
          + _av_pair(0x0002, "CORP".encode("utf-16-le"))
          + _av_pair(0x0003, "win10.corp.local".encode("utf-16-le"))
          + _av_pair(0x0004, "corp.local".encode("utf-16-le"))
          + _av_pair(0x0005, "corp.local".encode("utf-16-le"))
          + _av_pair(0x0007, struct.pack("<Q", 132_000_000_000_000_000))
          + _av_pair(0x0000, b""))
    got = winrm._parse_av_pairs(ti)
    assert got["netbios_computer"] == "WIN10"
    assert got["netbios_domain"] == "CORP"
    assert got["dns_computer"] == "win10.corp.local"
    assert got["dns_domain"] == "corp.local"
    assert got["dns_tree"] == "corp.local"
    assert "server_time_epoch" in got


def test_parse_ntlm_challenge_gets_names_and_os_version_from_type2():
    """A canonical Type-2 blob with NEGOTIATE_VERSION set carries the OS bytes
    at offset 48; the parser should surface them as 'os_version' plus every
    AV_PAIR name pulled from the target-info payload."""
    blob = _build_type2_challenge(os_ver=(10, 0, 19041))
    info = winrm._parse_ntlm_challenge(blob)
    assert info is not None
    assert info["netbios_computer"] == "WIN10"
    assert info["dns_computer"] == "win10.corp.local"
    assert info["dns_domain"] == "corp.local"
    assert info["os_version"] == "10.0.19041"


def test_probe_harvests_ntlm_info_when_server_offers_negotiate():
    srv = _ntlm_server(offer_auth="Negotiate")
    try:
        pr = winrm.probe("127.0.0.1", srv.server_address[1], timeout=2.0)
    finally:
        _stop(srv)
    assert pr["reachable"] is True
    assert "Negotiate" in pr["auth"]
    info = pr.get("ntlm_info")
    assert info and info["netbios_computer"] == "WIN10"
    assert info["dns_domain"] == "corp.local"
    assert info["os_version"] == "10.0.19041"


def test_probe_skips_ntlm_round_trip_when_negotiate_not_advertised():
    """If the server advertises only Basic/Kerberos there's no NTLMSSP path —
    the second POST would just get a 401 without a Type-2, so probe() shouldn't
    fire it and shouldn't set ntlm_info."""
    srv = _ntlm_server(offer_auth="Basic, Kerberos")
    try:
        pr = winrm.probe("127.0.0.1", srv.server_address[1], timeout=2.0)
    finally:
        _stop(srv)
    assert pr["reachable"] is True
    assert "ntlm_info" not in pr


def test_probe_parses_structured_productversion():
    """'OS: 10.0.19041 SP: 0.0 Stack: 3.0' should split into version_parsed."""
    srv = _fake_server(auth="Negotiate")
    try:
        pr = winrm.probe("127.0.0.1", srv.server_address[1], timeout=2.0)
    finally:
        _stop(srv)
    vp = pr.get("version_parsed") or {}
    assert vp.get("os_build") == "10.0.19041"
    assert vp.get("stack") == "3.0"


def test_ntlm_info_finding_emits_names_and_kerberos_skew_evidence():
    """The winrm_ntlm_info finding should carry the harvested identity in its
    detail — that's the whole point (feeds the operator's report and any
    downstream reader that grep-matches the detail string)."""
    fs = winrm.findings([_host()], {("10.0.0.10", 5985): {
        "reachable": True, "port": 5985, "tls": False,
        "auth": ["Negotiate"],
        "ntlm_info": {"netbios_computer": "WIN10", "netbios_domain": "CORP",
                      "dns_computer": "win10.corp.local",
                      "dns_domain": "corp.local", "dns_tree": "corp.local",
                      "os_version": "10.0.19041",
                      "server_time_epoch": 1_700_000_000}}})
    f = next(f for f in fs if f["kind"] == "winrm_ntlm_info")
    assert f["severity"] == "low"
    assert "CWE-200" in f["cwes"]
    for token in ("WIN10", "CORP", "win10.corp.local", "corp.local",
                  "10.0.19041", "server clock="):
        assert token in f["detail"]


def test_relay_target_finding_only_over_plain_http():
    """Negotiate on 5985/tcp = canonical impacket ntlmrelayx victim; the same
    posture on 5986 (TLS) is not a relay target here because EPA/CBT would
    be tested separately, so the finding must NOT fire on TLS."""
    fs_http = winrm.findings([_host(5985)], {("10.0.0.10", 5985): {
        "reachable": True, "port": 5985, "tls": False,
        "auth": ["Negotiate", "Kerberos"]}})
    kinds_http = {f["kind"] for f in fs_http}
    assert "winrm_relay_target" in kinds_http
    f = next(f for f in fs_http if f["kind"] == "winrm_relay_target")
    assert "CWE-294" in f["cwes"]
    assert "ntlmrelayx" in f["command"].lower()

    fs_tls = winrm.findings([_host(5986)], {("10.0.0.10", 5986): {
        "reachable": True, "port": 5986, "tls": True,
        "auth": ["Negotiate", "Kerberos"]}})
    assert "winrm_relay_target" not in {f["kind"] for f in fs_tls}


def test_analyze_folds_ntlm_info_into_host_ntlm_store():
    """Cross-service feed: the AV_PAIR intel WinRM harvests must land in
    host.ntlm so known_hostnames / known_domains / kerberos consumers see it."""
    srv = _ntlm_server(offer_auth="Negotiate")
    try:
        port = srv.server_address[1]
        h = Host(ip="127.0.0.1", ports=[Port(portid=port, state="open",
                                             service="wsman")])
        # Make is_winrm() recognise the ephemeral port via service string.
        res = winrm.analyze([h], active=True)
    finally:
        _stop(srv)
    assert h.ntlm.get("netbios_computer") == "WIN10"
    assert h.ntlm.get("dns_computer") == "win10.corp.local"
    assert h.ntlm.get("dns_domain") == "corp.local"
    assert h.ntlm.get("fqdn") == "win10.corp.local"
    assert h.ntlm.get("os_version") == "10.0.19041"
    kinds = {f["kind"] for f in res["findings"]}
    assert "winrm_ntlm_info" in kinds


# --- CredSSP T2 SAFE probe ---------------------------------------------------

def _parse_der_len(buf: bytes, off: int) -> tuple[int, int]:
    """Return (length, new_offset) - the minimum needed for verifier tests."""
    b = buf[off]
    off += 1
    if b < 0x80:
        return b, off
    n = b & 0x7F
    return int.from_bytes(buf[off:off + n], "big"), off + n


def test_build_credssp_tsrequest_is_wire_legal_der():
    """The TSRequest we send on the wire must be a DER SEQUENCE with the
    right context-specific tags — verify structurally with a hand parser
    (not the same encoder that built it) so an encoder change can't hide."""
    ts = winrm._build_credssp_tsrequest(b"\xDE\xAD\xBE\xEF", version=6)
    assert ts[0] == 0x30                          # outer SEQUENCE
    _outer_len, off = _parse_der_len(ts, 1)
    assert ts[off] == 0xA0                        # [0] version
    ver_len, off2 = _parse_der_len(ts, off + 1)
    off = off2
    assert ts[off] == 0x02                        # INTEGER
    ilen, off = _parse_der_len(ts, off + 1)
    assert int.from_bytes(ts[off:off + ilen], "big") == 6
    off += ilen
    assert ts[off] == 0xA1                        # [1] negoTokens
    _nlen, off = _parse_der_len(ts, off + 1)
    # NegoData SEQUENCE OF NegoDataItem SEQUENCE { [0] OCTET STRING }
    assert ts[off] == 0x30 and ts[off + 2] == 0x30
    # The negoToken bytes we passed in must appear verbatim inside.
    assert b"\xDE\xAD\xBE\xEF" in ts


def _credssp_ts_response_with_type2(nb_computer: str = "WIN10") -> bytes:
    """Build a wire-legal TSRequest carrying an NTLM Type-2 as negoToken,
    from the DER + MS-NLMP specs (not by round-tripping our own encoder)."""
    type2 = _build_type2_challenge(nb_computer=nb_computer)
    # Use the module helper only for the outer DER frame; the inner Type-2
    # is built independently by the fixture above.
    return winrm._build_credssp_tsrequest(type2, version=6)


def _credssp_server(*, offer_auth: str = "Negotiate, CredSSP",
                    credssp_response: bytes | None = None) -> HTTPServer:
    """POST /wsman without Authorization -> 200 Identify + offer_auth.
    POST /wsman with Authorization: CredSSP -> 401 with WWW-Authenticate:
    CredSSP <b64 credssp_response> when credssp_response is bytes (a live
    handler); an empty bytes value re-advertises without a token body
    (handler not wired); None means the CredSSP path returns a raw 500."""
    body = _IDENTIFY_XML.encode("utf-8")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a, **k):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
            authz = self.headers.get("Authorization", "")
            if authz.lower().startswith("credssp "):
                if credssp_response is None:
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if credssp_response == b"":
                    # Patched/not-wired: re-advertises option list with no
                    # CredSSP token body.
                    self.send_response(401)
                    for scheme in offer_auth.split(","):
                        self.send_header("WWW-Authenticate", scheme.strip())
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                b64 = base64.b64encode(credssp_response).decode("ascii")
                self.send_response(401)
                self.send_header("WWW-Authenticate", f"CredSSP {b64}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            # Identify + auth advertisement.
            self.send_response(200)
            self.send_header("Content-Type", "application/soap+xml;charset=UTF-8")
            for scheme in offer_auth.split(","):
                self.send_header("WWW-Authenticate", scheme.strip())
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_credssp_probe_detects_live_handler_and_surfaces_evidence():
    """Vulnerable-path: a CredSSP handler that echoes a real TSRequest
    continuation token is proof the SSP is wired — probe returns evidence."""
    resp = _credssp_ts_response_with_type2(nb_computer="WIN10")
    srv = _credssp_server(credssp_response=resp)
    try:
        pr = winrm.probe("127.0.0.1", srv.server_address[1], timeout=2.0)
    finally:
        _stop(srv)
    live = pr.get("credssp_live") or {}
    assert live, "credssp_live evidence should be present against a live handler"
    assert live.get("response_len", 0) > 0
    ntlm_info = live.get("ntlm_info") or {}
    assert ntlm_info.get("netbios_computer") == "WIN10"


def test_credssp_probe_quiet_when_handler_not_wired():
    """Patched-path: CredSSP advertised in Options but the handler answers a
    CredSSP request by re-advertising (no token body). Must NOT set
    credssp_live so winrm_credssp stays T1."""
    srv = _credssp_server(credssp_response=b"")
    try:
        pr = winrm.probe("127.0.0.1", srv.server_address[1], timeout=2.0)
    finally:
        _stop(srv)
    assert "credssp_live" not in pr


def test_credssp_probe_quiet_on_timeout(monkeypatch):
    """Timeout-path: if _credssp_probe raises socket.timeout internally, the
    probe swallows the error and the T1 posture is preserved."""
    import http.client as _hc

    def _raise_timeout(*a, **k):
        raise socket.timeout("credssp probe hung")

    monkeypatch.setattr(_hc.HTTPConnection, "request", _raise_timeout)
    got = winrm._credssp_probe("127.0.0.1", 5985, tls=False, timeout=1.0)
    assert got is None


def test_credssp_probe_skipped_when_credssp_not_advertised():
    """If CredSSP is not in the WWW-Authenticate list, probe() must NOT fire
    the extra round-trip — the credssp_live key stays absent."""
    srv = _credssp_server(offer_auth="Negotiate, Kerberos",
                          credssp_response=b"unreachable")
    try:
        pr = winrm.probe("127.0.0.1", srv.server_address[1], timeout=2.0)
    finally:
        _stop(srv)
    assert "credssp_live" not in pr


def test_findings_promote_credssp_to_t2_with_evidence():
    """When credssp_live evidence is present, winrm_credssp is emitted with
    depth_tier='t2' and the detail carries the CredSSP handler evidence."""
    fs = winrm.findings([_host()], {("10.0.0.10", 5985): {
        "reachable": True, "port": 5985, "tls": False,
        "auth": ["Negotiate", "CredSSP"],
        "credssp_live": {"response_len": 187,
                         "ntlm_info": {"netbios_computer": "DC01",
                                       "dns_computer": "dc01.corp.local",
                                       "dns_domain": "corp.local",
                                       "os_version": "10.0.20348"}}}})
    f = next(f for f in fs if f["kind"] == "winrm_credssp")
    assert f["depth_tier"] == "t2"
    for token in ("continuation token", "DC01", "corp.local", "10.0.20348",
                  "187B"):
        assert token in f["detail"]


def test_findings_keep_credssp_at_t1_without_evidence():
    """T1 path unchanged: without credssp_live evidence the finding stays
    at depth_tier='t1' and the detail carries no evidence sentence."""
    fs = winrm.findings([_host()], {("10.0.0.10", 5985): {
        "reachable": True, "port": 5985, "tls": False,
        "auth": ["Negotiate", "CredSSP"]}})
    f = next(f for f in fs if f["kind"] == "winrm_credssp")
    assert f["depth_tier"] == "t1"
    assert "continuation token" not in f["detail"]


def test_credssp_probe_ignores_bare_credssp_option_reply():
    """Distinguish a live-handler response 'CredSSP <b64token>' from a bare
    'CredSSP' option re-advertisement (no token body). Only the former is
    evidence of a live SSP."""
    srv = _credssp_server(offer_auth="CredSSP", credssp_response=b"")
    try:
        pr = winrm.probe("127.0.0.1", srv.server_address[1], timeout=2.0)
    finally:
        _stop(srv)
    # CredSSP was in the initial advertisement so the probe DID fire, but
    # the handler answered without a token body -> no credssp_live.
    assert "credssp_live" not in pr


def test_analyze_does_not_clobber_a_preexisting_dns_domain():
    """LDAP writes host.ntlm['dns_domain'] first in practice — WinRM must
    only fill blanks, never overwrite a value another module established."""
    srv = _ntlm_server(offer_auth="Negotiate")
    try:
        port = srv.server_address[1]
        h = Host(ip="127.0.0.1", ports=[Port(portid=port, state="open",
                                             service="wsman")])
        h.ntlm = {"dns_domain": "other.example"}
        winrm.analyze([h], active=True)
    finally:
        _stop(srv)
    assert h.ntlm["dns_domain"] == "other.example"
    # But other blanks got filled.
    assert h.ntlm.get("netbios_computer") == "WIN10"
