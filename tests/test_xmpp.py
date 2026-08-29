"""XMPP deep-module tests. All fixtures are hand-authored to match the wire
shapes RFC 6120 / XEP-0030 / XEP-0077 / XEP-0092 mandate — never round-trips
through recce's own encoder. Fake servers replace real network I/O."""
from __future__ import annotations

import socket
import socketserver
import threading
import time

from recce.core.models import Host, Port
from recce.services import xmpp


# --- fixtures (captured/derived wire) ---------------------------------------

# stream:features Prosody typically sends AFTER STARTTLS+SASL, showing modern
# SCRAM-* mechanisms and bind. Used for _parse_features.
_FEATURES_MODERN = (
    b"<?xml version='1.0'?>"
    b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'"
    b" from='chat.example.org' id='ab12' version='1.0'>"
    b"<stream:features>"
    b"<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
    b"<mechanism>SCRAM-SHA-256</mechanism>"
    b"<mechanism>SCRAM-SHA-1</mechanism>"
    b"</mechanisms>"
    b"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
    b"<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>"
    b"</stream:features>"
)

# Weak PLAIN advertised BEFORE STARTTLS (pre-TLS). Also includes STARTTLS with
# <required/>, and IBR.
_FEATURES_WEAK_PRE_TLS = (
    b"<?xml version='1.0'?>"
    b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'"
    b" from='xmpp.example.org' id='pre1' version='1.0'>"
    b"<stream:features>"
    b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"
    b"<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
    b"<mechanism>PLAIN</mechanism>"
    b"<mechanism>LOGIN</mechanism>"
    b"<mechanism>DIGEST-MD5</mechanism>"
    b"<mechanism>ANONYMOUS</mechanism>"
    b"</mechanisms>"
    b"<register xmlns='http://jabber.org/features/iq-register'/>"
    b"</stream:features>"
)

# stream:features on 5269 with dialback and no STARTTLS-required.
_FEATURES_S2S_DIALBACK = (
    b"<?xml version='1.0'?>"
    b"<stream:stream xmlns='jabber:server' xmlns:stream='http://etherx.jabber.org/streams'"
    b" xmlns:db='jabber:server:dialback' from='fed.example.org' id='s1' version='1.0'>"
    b"<stream:features>"
    b"<dialback xmlns='urn:xmpp:features:dialback'/>"
    b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
    b"</stream:features>"
)

# stream:error with Prosody-flavored host-unknown text.
_STREAM_ERROR_PROSODY = (
    b"<?xml version='1.0'?>"
    b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'"
    b" from='real.example.org' id='e1' version='1.0'>"
    b"<stream:error>"
    b"<host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
    b"<text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>"
    b"This server does not serve recce-bogus.invalid (Prosody 0.11.13)"
    b"</text>"
    b"</stream:error>"
    b"</stream:stream>"
)


# --- parse_features unit ----------------------------------------------------

def test_parse_features_modern_extracts_scram_and_bind():
    f = xmpp._parse_features(_FEATURES_MODERN)
    assert f["sasl_mechs"] == ["SCRAM-SHA-1", "SCRAM-SHA-256"]
    assert f["starttls_offered"] is False
    assert f["bind_offered"] is True
    assert f["session_offered"] is True
    assert f["from_domain"] == "chat.example.org"
    assert f["stream_version"] == "1.0"


def test_parse_features_pre_tls_flags_weak_and_required_starttls():
    f = xmpp._parse_features(_FEATURES_WEAK_PRE_TLS)
    assert set(f["sasl_mechs"]) == {"PLAIN", "LOGIN", "DIGEST-MD5", "ANONYMOUS"}
    assert f["starttls_offered"] is True
    assert f["starttls_required"] is True
    assert f["register_offered"] is True
    assert f["from_domain"] == "xmpp.example.org"


def test_parse_features_s2s_shows_dialback_and_optional_starttls():
    f = xmpp._parse_features(_FEATURES_S2S_DIALBACK)
    assert f["dialback_offered"] is True
    assert f["starttls_offered"] is True
    assert f["starttls_required"] is False


def test_fingerprint_prosody_from_stream_error():
    assert xmpp._fingerprint(_STREAM_ERROR_PROSODY) == "Prosody"


def test_fingerprint_ejabberd_and_openfire():
    assert xmpp._fingerprint(b"<stream:error>ejabberd rejected</stream:error>") \
        == "ejabberd"
    assert xmpp._fingerprint(b"Openfire XMPP Server") == "Openfire"
    assert xmpp._fingerprint(b"<not-a-hint/>") == ""


# --- is_xmpp ----------------------------------------------------------------

def test_is_xmpp_by_port_and_service():
    assert xmpp.is_xmpp(Port(portid=5222, service="", state="open"))
    assert xmpp.is_xmpp(Port(portid=5223, service="ssl/jabber", state="open"))
    assert xmpp.is_xmpp(Port(portid=5269, service="xmpp-server", state="open"))
    assert xmpp.is_xmpp(Port(portid=8888, service="jabber-client", state="open"))
    assert not xmpp.is_xmpp(Port(portid=5222, service="xmpp", state="closed"))
    assert not xmpp.is_xmpp(Port(portid=443, service="https", state="open"))


# --- fake-server helpers ----------------------------------------------------

def _run_server(handler_fn) -> tuple[int, socketserver.ThreadingTCPServer]:
    """Spin a threading TCP server; handler_fn(sock) runs on connect."""

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            try:
                handler_fn(self.request)
            except (OSError, socket.timeout):
                pass

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], srv


import re as _re


class _SockReader:
    """Byte-oriented reader with a small pushback buffer, so `_read_element`
    can peek forward without losing data for the next call."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def read_byte(self) -> bytes:
        if self.buf:
            b, self.buf = self.buf[:1], self.buf[1:]
            return b
        try:
            chunk = self.sock.recv(4096)
        except (OSError, socket.timeout):
            return b""
        if not chunk:
            return b""
        b, self.buf = chunk[:1], chunk[1:]
        return b


def _read_element(reader: "_SockReader") -> bytes:
    """Read one complete XML element from `reader`: either a self-closed
    '<x .../>' or a paired '<x ...>...</x>'. Discards any leading '<?xml ...?>'
    prolog(s). Lines the scripted fake XMPP server up 1-to-1 with client
    requests (stream open, <auth/>, <iq>...</iq>, </stream:stream>)."""
    buf = b""
    # Loop until we have enough of a start-tag to classify as prolog / element.
    while True:
        while len(buf.lstrip()) < 2:
            ch = reader.read_byte()
            if not ch:
                return buf
            buf += ch
        s = buf.lstrip()
        if not s.startswith(b"<?"):
            break
        # Prolog: read until '?>' then discard and restart classification.
        while not buf.endswith(b"?>"):
            ch = reader.read_byte()
            if not ch:
                return buf
            buf += ch
        buf = b""
    # `buf` now has "<X" and possibly more; read the start-tag through '>'.
    while b">" not in buf:
        ch = reader.read_byte()
        if not ch:
            return buf
        buf += ch
    if buf.rstrip().endswith(b"/>"):
        return buf
    if _re.match(rb"\s*</", buf):
        return buf
    m = _re.match(rb"\s*<([A-Za-z][A-Za-z0-9:_-]*)", buf)
    if not m:
        return buf
    tag = m.group(1)
    if tag == b"stream:stream":
        return buf
    end = b"</" + tag + b">"
    while end not in buf:
        ch = reader.read_byte()
        if not ch:
            return buf
        buf += ch
    return buf


def _c2s_handler(sequence):
    """Return a handler function that plays back a scripted list of replies.
    Each entry may be:
        ("send", bytes)  -> write bytes verbatim
        ("recv", None)   -> read one client element
    """
    def handler(sock):
        reader = _SockReader(sock)
        for kind, payload in sequence:
            if kind == "send":
                sock.sendall(payload)
            elif kind == "recv":
                _read_element(reader)
        # linger briefly so the client can close cleanly
        time.sleep(0.05)
    return handler


# --- probe end-to-end with a fake ANONYMOUS server --------------------------

def _anon_server_script(domain="fake.example.org"):
    features = (
        b"<?xml version='1.0'?>"
        b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'"
        b" from='" + domain.encode() + b"' id='s1' version='1.0'>"
        b"<stream:features>"
        b"<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
        b"<mechanism>ANONYMOUS</mechanism>"
        b"<mechanism>PLAIN</mechanism>"
        b"</mechanisms>"
        b"<register xmlns='http://jabber.org/features/iq-register'/>"
        b"</stream:features>"
    )
    features_after_sasl = (
        b"<?xml version='1.0'?>"
        b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'"
        b" from='" + domain.encode() + b"' id='s2' version='1.0'>"
        b"<stream:features>"
        b"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>"
        b"</stream:features>"
    )
    sasl_success = b"<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>"
    bind_result = (
        b"<iq type='result' id='bind1'>"
        b"<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>"
        b"<jid>anon-abc123@" + domain.encode() + b"/recce</jid>"
        b"</bind></iq>"
    )
    ibr_result = (
        b"<iq type='result' id='reg1'>"
        b"<query xmlns='jabber:iq:register'>"
        b"<instructions>Register</instructions>"
        b"<username/><password/><email/>"
        b"</query></iq>"
    )
    version_result = (
        b"<iq type='result' id='ver1'>"
        b"<query xmlns='jabber:iq:version'>"
        b"<name>Prosody</name><version>0.11.13</version><os>Debian</os>"
        b"</query></iq>"
    )
    disco_items = (
        b"<iq type='result' id='di1'>"
        b"<query xmlns='http://jabber.org/protocol/disco#items'>"
        b"<item jid='conference." + domain.encode() + b"' name='Chatrooms'/>"
        b"<item jid='upload." + domain.encode() + b"' name='Uploads'/>"
        b"</query></iq>"
    )
    disco_info_muc = (
        b"<iq type='result' id='df1'>"
        b"<query xmlns='http://jabber.org/protocol/disco#info'>"
        b"<identity category='conference' type='text' name='Chatrooms'/>"
        b"<feature var='http://jabber.org/protocol/muc'/>"
        b"</query></iq>"
    )
    disco_info_upload = (
        b"<iq type='result' id='df1'>"
        b"<query xmlns='http://jabber.org/protocol/disco#info'>"
        b"<identity category='store' type='file' name='HTTP File Upload'/>"
        b"<feature var='urn:xmpp:http:upload:0'/>"
        b"</query></iq>"
    )
    return [
        ("recv", None),                    # stream:stream open
        ("send", features),
        ("recv", None),                    # <auth ANONYMOUS/>
        ("send", sasl_success),
        ("recv", None),                    # restart stream
        ("send", features_after_sasl),
        ("recv", None),                    # bind IQ
        ("send", bind_result),
        ("recv", None),                    # register IQ
        ("send", ibr_result),
        ("recv", None),                    # version IQ
        ("send", version_result),
        ("recv", None),                    # disco items
        ("send", disco_items),
        ("recv", None),                    # disco info -> conference
        ("send", disco_info_muc),
        ("recv", None),                    # disco info -> upload
        ("send", disco_info_upload),
        ("recv", None),                    # </stream:stream>
    ]


def test_probe_walks_full_anonymous_session_and_captures_facts():
    port, srv = _run_server(_c2s_handler(_anon_server_script()))
    try:
        pr = xmpp.probe("127.0.0.1", port, timeout=3, domain="fake.example.org")
    finally:
        srv.shutdown()

    assert pr["reachable"] is True
    assert pr["server_from"] == "fake.example.org"
    assert "ANONYMOUS" in pr["features"]["sasl_mechs"]
    assert pr["anonymous"] is True
    assert pr["anon_jid"].startswith("anon-abc123@")
    assert pr["ibr_offered"] is True
    assert pr["sw_version"]["name"] == "Prosody"
    assert pr["sw_version"]["version"] == "0.11.13"
    kinds = {c["kind"] for c in pr["components"]}
    assert {"muc", "http_upload"} <= kinds
    # product fingerprinted from the version response (not stream-error here).
    assert pr["product"] == ""     # stream open carried no product hint text


# --- findings coverage ------------------------------------------------------

def _mkhost(port_id: int = 5222) -> Host:
    return Host(ip="10.0.0.9", ports=[
        Port(portid=port_id, service="xmpp-client", state="open")])


def test_findings_starttls_missing_when_no_starttls_offered():
    h = _mkhost()
    probes = {("10.0.0.9", 5222): {
        "reachable": True, "features": {
            "sasl_mechs": ["SCRAM-SHA-1"], "starttls_offered": False,
            "starttls_required": False, "register_offered": False,
        }, "is_s2s": False, "legacy_tls": False, "server_from": "x"}}
    titles = [f["title"] for f in xmpp.findings([h], probes)]
    assert any("STARTTLS not offered" in t for t in titles)


def test_findings_starttls_offered_but_not_required_is_medium():
    h = _mkhost()
    probes = {("10.0.0.9", 5222): {
        "reachable": True, "features": {
            "sasl_mechs": [], "starttls_offered": True,
            "starttls_required": False,
        }, "is_s2s": False, "legacy_tls": False}}
    hits = [f for f in xmpp.findings([h], probes)
            if f["kind"] == "xmpp_starttls_missing"]
    assert hits and hits[0]["severity"] == "medium"


def test_findings_ibr_and_anon_and_weak_sasl():
    h = _mkhost()
    probes = {("10.0.0.9", 5222): {
        "reachable": True, "features": {
            "sasl_mechs": ["PLAIN", "LOGIN", "ANONYMOUS", "DIGEST-MD5"],
            "starttls_offered": True, "starttls_required": True,
            "register_offered": True,
        }, "is_s2s": False, "legacy_tls": False, "tls_negotiated": False,
        "ibr_offered": True, "anonymous": True,
        "anon_jid": "anon-xxx@fake/recce"}}
    fs = xmpp.findings([h], probes)
    kinds = {f["kind"] for f in fs}
    assert "xmpp_ibr_open" in kinds
    assert "xmpp_anon_bind" in kinds
    assert "xmpp_weak_sasl" in kinds
    weak = next(f for f in fs if f["kind"] == "xmpp_weak_sasl")
    assert "PLAIN" in weak["title"] or "DIGEST-MD5" in weak["title"]


def test_findings_digest_md5_flagged_even_after_tls():
    h = _mkhost()
    probes = {("10.0.0.9", 5222): {
        "reachable": True, "features": {
            "sasl_mechs": ["SCRAM-SHA-1", "DIGEST-MD5"],
            "starttls_offered": True, "starttls_required": True,
        }, "is_s2s": False, "legacy_tls": False,
        "tls_negotiated": True}}
    kinds = {f["kind"] for f in xmpp.findings([h], probes)}
    assert "xmpp_weak_sasl" in kinds


def test_findings_plain_not_flagged_when_only_post_tls():
    """PLAIN on the post-TLS features view (tls_negotiated=True) is standard."""
    h = _mkhost()
    probes = {("10.0.0.9", 5222): {
        "reachable": True, "features": {
            "sasl_mechs": ["PLAIN", "SCRAM-SHA-1"],
            "starttls_offered": True, "starttls_required": True,
        }, "is_s2s": False, "legacy_tls": False, "tls_negotiated": True}}
    kinds = {f["kind"] for f in xmpp.findings([h], probes)}
    assert "xmpp_weak_sasl" not in kinds


def test_findings_s2s_dialback_without_tls_required():
    h = Host(ip="10.0.0.9", ports=[
        Port(portid=5269, service="xmpp-server", state="open")])
    probes = {("10.0.0.9", 5269): {
        "reachable": True, "features": {
            "sasl_mechs": [], "starttls_offered": True,
            "starttls_required": False, "dialback_offered": True,
        }, "is_s2s": True, "legacy_tls": False}}
    kinds = {f["kind"] for f in xmpp.findings([h], probes)}
    assert "xmpp_s2s_dialback_weak" in kinds


def test_findings_sw_version_and_components_and_fingerprint():
    h = _mkhost()
    probes = {("10.0.0.9", 5222): {
        "reachable": True, "features": {
            "sasl_mechs": ["SCRAM-SHA-1"], "starttls_offered": True,
            "starttls_required": True,
        }, "is_s2s": False, "legacy_tls": False,
        "sw_version": {"name": "ejabberd", "version": "21.12", "os": "Linux"},
        "product": "ejabberd", "stream_error": "",
        "components": [
            {"jid": "conference.x", "kind": "muc",
             "name": "Chat", "identities": [], "features": []},
            {"jid": "upload.x", "kind": "http_upload",
             "name": "Up", "identities": [], "features": []},
        ]}}
    fs = xmpp.findings([h], probes)
    kinds = {f["kind"] for f in fs}
    assert "xmpp_sw_version" in kinds
    # xmpp_fingerprint should NOT fire when sw_version supplied one already
    assert "xmpp_fingerprint" not in kinds
    assert "xmpp_disco_components" in kinds


def test_findings_fingerprint_falls_back_when_no_sw_version():
    h = _mkhost()
    probes = {("10.0.0.9", 5222): {
        "reachable": True, "features": {
            "sasl_mechs": ["SCRAM-SHA-1"], "starttls_offered": True,
            "starttls_required": True,
        }, "is_s2s": False, "legacy_tls": False,
        "sw_version": {}, "product": "Prosody",
        "stream_error": "host-unknown (Prosody 0.11)"}}
    kinds = {f["kind"] for f in xmpp.findings([h], probes)}
    assert "xmpp_fingerprint" in kinds


def test_findings_legacy_tls_5223_and_cert_mismatch():
    h = Host(ip="10.0.0.9", ports=[
        Port(portid=5223, service="xmpps", state="open")])
    probes = {("10.0.0.9", 5223): {
        "reachable": True, "features": {
            "sasl_mechs": ["SCRAM-SHA-1"], "starttls_offered": False,
            "starttls_required": False,
        }, "is_s2s": False, "legacy_tls": True,
        "server_from": "chat.example.org",
        "legacy_tls_cert": {"sans": ["other.example.org"],
                            "subject_cn": "other.example.org",
                            "issuer_cn": "Test CA",
                            "not_after": "Jan  1 00:00:00 2099 GMT"}}}
    fs = xmpp.findings([h], probes)
    kinds = {f["kind"] for f in fs}
    assert "xmpp_legacy_tls_5223" in kinds
    assert "xmpp_cert_mismatch" in kinds
    # And starttls_missing is NOT raised on the encrypted legacy port.
    assert "xmpp_starttls_missing" not in kinds


def test_san_covers_exact_and_wildcard():
    assert xmpp._san_covers("chat.example.org", "chat.example.org")
    assert xmpp._san_covers("*.example.org", "chat.example.org")
    assert not xmpp._san_covers("*.example.org", "example.org")
    assert not xmpp._san_covers("*.example.org", "a.b.example.org")
    assert not xmpp._san_covers("", "chat.example.org")


# --- findings_to_vulns wiring ----------------------------------------------

def test_findings_to_vulns_sets_source_label_and_default_port():
    fs = [{
        "category": "xmpp", "severity": "high",
        "title": "XMPP anonymous SASL bind accepted",
        "target": "10.0.0.9:5222", "detail": "d", "tool": "python",
        "command": "c", "remediation": "r", "cwes": ["CWE-287"],
        "kind": "xmpp_anon_bind", "narrative": "n",
    }]
    by_ip = xmpp.findings_to_vulns(fs)
    v = by_ip["10.0.0.9"][0]
    assert v.source == "xmpp"
    assert v.port == 5222
    assert v.severity == "high"


# --- xmpp_targets / runbook / analyze --------------------------------------

def test_xmpp_targets_picks_all_open_xmpp_ports():
    hosts = [Host(ip="10.0.0.1", ports=[
        Port(portid=5222, service="xmpp-client", state="open"),
        Port(portid=5223, service="", state="open"),
        Port(portid=22, service="ssh", state="open"),
    ])]
    ts = xmpp.xmpp_targets(hosts)
    ports = sorted(t["port"] for t in ts)
    assert ports == [5222, 5223]


def test_runbook_mentions_openssl_starttls_and_disco():
    steps = xmpp.credfree_runbook("10.0.0.9", 5222)
    joined = " ".join(s["command"] for s in steps)
    assert "openssl s_client -starttls xmpp" in joined
    assert "disco#items" in joined


def test_cred_runbook_substitutes_user():
    steps = xmpp.cred_runbook("10.0.0.9", 5222, {"user": "alice"})
    joined = " ".join(s["command"] for s in steps)
    assert "alice" in joined


def test_analyze_no_targets_returns_empty_stats():
    r = xmpp.analyze([Host(ip="10.0.0.9", ports=[])], active=False)
    assert r["targets"] == []
    assert r["findings"] == []
    assert r["stats"]["targets"] == 0


def test_analyze_active_walks_probe_and_emits_findings(monkeypatch):
    hosts = [Host(ip="10.0.0.9", ports=[
        Port(portid=5222, service="xmpp-client", state="open")])]

    fake_probe = {
        "reachable": True, "features": {
            "sasl_mechs": ["ANONYMOUS", "PLAIN"], "starttls_offered": False,
            "starttls_required": False, "register_offered": True,
        }, "is_s2s": False, "legacy_tls": False, "tls_negotiated": False,
        "server_from": "x", "product": "", "stream_error": "",
        "ibr_offered": True, "anonymous": True, "anon_jid": "anon@x/recce",
        "sw_version": {}, "components": []}

    monkeypatch.setattr(xmpp, "probe",
                        lambda ip, port, active=True: fake_probe)
    r = xmpp.analyze(hosts, active=True)
    kinds = {f["kind"] for f in r["findings"]}
    assert "xmpp_anon_bind" in kinds
    assert "xmpp_ibr_open" in kinds
    assert "xmpp_starttls_missing" in kinds
    assert r["stats"]["targets"] == 1


# --- MUC enumeration --------------------------------------------------------

def test_enum_muc_rooms_lists_public_rooms():
    features = (
        b"<?xml version='1.0'?>"
        b"<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'"
        b" from='chat.x' id='m1' version='1.0'>"
        b"<stream:features></stream:features>"
    )
    items = (
        b"<iq type='result' id='di1'>"
        b"<query xmlns='http://jabber.org/protocol/disco#items'>"
        b"<item jid='engineering@conference.x' name='Engineering'/>"
        b"<item jid='secret@conference.x' name='Secret'/>"
        b"</query></iq>"
    )
    info_public = (
        b"<iq type='result' id='df1'>"
        b"<query xmlns='http://jabber.org/protocol/disco#info'>"
        b"<identity category='conference' type='text' name='Engineering'/>"
        b"<feature var='http://jabber.org/protocol/muc'/>"
        b"</query></iq>"
    )
    info_hidden = (
        b"<iq type='result' id='df1'>"
        b"<query xmlns='http://jabber.org/protocol/disco#info'>"
        b"<identity category='conference' type='text' name='Secret'/>"
        b"<feature var='muc_hidden'/>"
        b"<feature var='muc_passwordprotected'/>"
        b"</query></iq>"
    )
    script = [
        ("recv", None),                    # stream open
        ("send", features),
        ("recv", None),                    # disco items
        ("send", items),
        ("recv", None),                    # disco info room 1
        ("send", info_public),
        ("recv", None),                    # disco info room 2
        ("send", info_hidden),
    ]
    port, srv = _run_server(_c2s_handler(script))
    try:
        rooms = xmpp.enum_muc_rooms("127.0.0.1", port, "conference.x",
                                    timeout=3, domain="chat.x")
    finally:
        srv.shutdown()
    jids = {r["jid"] for r in rooms}
    assert "engineering@conference.x" in jids
    secret = next(r for r in rooms if r["jid"] == "secret@conference.x")
    assert secret["hidden"] is True
    assert secret["password_protected"] is True


# --- stream error fingerprint round-trip through the probe -----------------

def test_probe_captures_stream_error_and_fingerprint():
    def script():
        return [
            ("recv", None),
            ("send", _STREAM_ERROR_PROSODY),
        ]
    port, srv = _run_server(_c2s_handler(script()))
    try:
        pr = xmpp.probe("127.0.0.1", port, timeout=3,
                        domain="real.example.org", active=False)
    finally:
        srv.shutdown()
    assert pr["reachable"] is True
    assert pr["product"] == "Prosody"
    assert "recce-bogus.invalid" in pr["stream_error"]


def test_probe_unreachable_returns_false():
    # Nothing bound: connect refused.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    pr = xmpp.probe("127.0.0.1", port, timeout=1)
    assert pr["reachable"] is False
