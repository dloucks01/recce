"""WinRM (5985/5986): WSMan Identify + auth mechanism disclosure.

Tests drive a fake HTTP responder that speaks the WSMan Identify SOAP reply
verbatim from the DMTF wsmanidentity.xsd schema (not from recce's own body),
so a decoder change in recce cannot be masked by a symmetric fixture bug.
"""
from __future__ import annotations

import socket
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
