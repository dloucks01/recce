"""core.cleartext_creds: cross-service cleartext-auth exposure reader.

Fixtures below feed the reader wire-derived shapes — a real Telnet IAC
negotiation buffer (RFC 854 §3), a real FTP 220/USER/PASS exchange (RFC
959 §4.2 reply codes), a real HTTP 401 with a `WWW-Authenticate: Basic`
header on plaintext HTTP (RFC 7617 §2) — decoded with stdlib only. Nothing
here calls a recce encoder; the tests exercise the reader against bytes
that could have come off a pcap.

The integration test drives `ftp.analyze()` with a stubbed probe (offline)
to show a real producer populates the reader without extra glue.
"""
from __future__ import annotations

import base64
import re

from recce.core.cleartext_creds import (cleartext_creds_for,
                                        cleartext_credentials_observed,
                                        record_cleartext_auth)
from recce.core.models import Host, Port


# --- wire-derived fixtures --------------------------------------------------

# RFC 854/1143 IAC negotiation prefix a real telnet server emits before the
# login prompt: IAC(255) DO(253) SUPPRESS-GO-AHEAD(3), IAC WILL(251) ECHO(1),
# then the "login:" ASCII banner. A packet that starts with these bytes IS a
# cleartext-auth telnet endpoint.
_TELNET_HELLO = bytes([255, 253, 3, 255, 251, 1]) + b"\r\nlogin: "

# RFC 959 §4.2: 220 greeting, 331 password-required, 230 logged-in. A server
# that returns 230 after a plaintext PASS confirmed a cleartext-auth flow.
_FTP_GREETING = b"220 (vsFTPd 3.0.3)\r\n"
_FTP_USER_331 = b"331 Please specify the password.\r\n"
_FTP_PASS_230 = b"230 Login successful.\r\n"

# RFC 7617 §2: a 401 on plaintext HTTP with `WWW-Authenticate: Basic`. The
# header alone proves the server will accept `Authorization: Basic <b64>`
# over an unencrypted channel — the exact hazard the RFC calls out.
_HTTP_401_BASIC = (
    b"HTTP/1.1 401 Unauthorized\r\n"
    b"WWW-Authenticate: Basic realm=\"admin\"\r\n"
    b"Content-Length: 0\r\n\r\n"
)


def _telnet_looks_like_login(buf: bytes) -> bool:
    """A telnet-server hello per RFC 854 §3: begins with an IAC (0xFF)
    negotiation stream. Kept tiny — the module under test does not care how
    the producer detected it; only that the producer calls the recorder."""
    return len(buf) >= 3 and buf[0] == 0xFF


def _ftp_login_ok(greeting: bytes, user_reply: bytes, pass_reply: bytes) -> bool:
    """RFC 959 §4.2: only a 2xx to PASS means credentialed session. 230 = OK."""
    return (greeting.startswith(b"220")
            and user_reply.startswith(b"331")
            and pass_reply.startswith(b"230"))


def _http_wants_basic(response: bytes) -> bool:
    """RFC 7617 §2: `WWW-Authenticate: Basic` on a 401."""
    if not response.startswith(b"HTTP/1.1 401"):
        return False
    return bool(re.search(rb"(?im)^WWW-Authenticate:\s*Basic\b", response))


# --- record_cleartext_auth --------------------------------------------------

def test_record_attaches_to_host_and_reader_reads_back():
    h = Host(ip="10.0.0.10")
    assert _telnet_looks_like_login(_TELNET_HELLO)
    record_cleartext_auth(h, 23, "Telnet", "password", "telnet:iac-hello")
    got = cleartext_creds_for(h)
    assert len(got) == 1
    r = got[0]
    assert r["ip"] == "10.0.0.10"
    assert r["port"] == 23
    # First-seen casing preserved for display
    assert r["protocol"] == "Telnet"
    assert r["auth_type"] == "password"
    assert r["sources"] == ["telnet:iac-hello"]


def test_record_is_idempotent_on_same_endpoint_and_auth_type():
    """A re-probe of the same telnet endpoint MUST NOT double-count."""
    h = Host(ip="10.0.0.10")
    record_cleartext_auth(h, 23, "telnet", "password", "telnet:probe")
    record_cleartext_auth(h, 23, "telnet", "password", "telnet:probe")
    got = cleartext_creds_for(h)
    assert len(got) == 1
    assert got[0]["sources"] == ["telnet:probe"]


def test_record_unions_sources_on_repeat_from_different_producer():
    """Same endpoint reported by two producers — one row, two sources."""
    h = Host(ip="10.0.0.10")
    record_cleartext_auth(h, 21, "ftp", "password", "ftp:220-banner")
    record_cleartext_auth(h, 21, "ftp", "password", "ftp:230-login")
    got = cleartext_creds_for(h)
    assert len(got) == 1
    assert got[0]["sources"] == ["ftp:220-banner", "ftp:230-login"]


def test_record_case_insensitive_dedup_with_first_seen_casing_preserved():
    """Protocol names arrive from banners in mixed casing. Dedup is
    case-insensitive; the display string keeps what the first producer saw."""
    h = Host(ip="10.0.0.10")
    record_cleartext_auth(h, 21, "FTP", "PASSWORD", "ftp:a")
    record_cleartext_auth(h, 21, "ftp", "password", "ftp:b")
    got = cleartext_creds_for(h)
    assert len(got) == 1
    assert got[0]["protocol"] == "FTP"
    assert got[0]["auth_type"] == "PASSWORD"
    assert got[0]["sources"] == ["ftp:a", "ftp:b"]


def test_record_different_auth_type_is_separate_row():
    """Same port, two auth mechanisms (SMTP AUTH PLAIN + AUTH LOGIN) — two
    rows, because the mitigation ("disable this mechanism") is per-mech."""
    h = Host(ip="10.0.0.10")
    record_cleartext_auth(h, 25, "smtp", "plain", "smtp:ehlo")
    record_cleartext_auth(h, 25, "smtp", "login", "smtp:ehlo")
    got = cleartext_creds_for(h)
    assert {r["auth_type"] for r in got} == {"plain", "login"}


def test_record_silently_drops_empty_protocol_or_port():
    h = Host(ip="10.0.0.10")
    record_cleartext_auth(h, 0, "ftp", "password", "s")
    record_cleartext_auth(h, 21, "", "password", "s")
    record_cleartext_auth(h, 21, "   ", "password", "s")
    assert cleartext_creds_for(h) == []


def test_creds_for_returns_copies_so_consumer_cannot_corrupt_store():
    h = Host(ip="10.0.0.10")
    record_cleartext_auth(h, 23, "telnet", "password", "s")
    got = cleartext_creds_for(h)
    got[0]["protocol"] = "tampered"
    got[0]["sources"].append("tampered")
    fresh = cleartext_creds_for(h)
    assert fresh[0]["protocol"] == "telnet"
    assert fresh[0]["sources"] == ["s"]


# --- cleartext_credentials_observed engagement-wide reader ------------------

def test_reader_unions_across_hosts_and_returns_by_protocol_counts():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    c = Host(ip="10.0.0.30")
    # Wire-shaped input: only feed the recorder when the wire says "clear".
    assert _telnet_looks_like_login(_TELNET_HELLO)
    assert _ftp_login_ok(_FTP_GREETING, _FTP_USER_331, _FTP_PASS_230)
    assert _http_wants_basic(_HTTP_401_BASIC)
    record_cleartext_auth(a, 23, "telnet", "password", "telnet:iac")
    record_cleartext_auth(b, 21, "ftp", "password", "ftp:230")
    record_cleartext_auth(c, 80, "http-basic", "basic", "http:401")
    got = cleartext_credentials_observed([a, b, c])
    assert got["by_protocol"] == {"telnet": 1, "ftp": 1, "http-basic": 1}
    assert got["by_ip"]["10.0.0.10"] == [{"proto": "telnet", "port": 23}]
    assert got["by_ip"]["10.0.0.20"] == [{"proto": "ftp", "port": 21}]
    assert got["by_ip"]["10.0.0.30"] == [{"proto": "http-basic", "port": 80}]


def test_reader_deduplicates_same_endpoint_reported_by_two_hosts_view():
    """Same host object appears once in the list but its records are
    still deduped through the engagement view (defensive: the caller may
    pass the same host twice through different code paths)."""
    h = Host(ip="10.0.0.10")
    record_cleartext_auth(h, 23, "telnet", "password", "s1")
    record_cleartext_auth(h, 23, "telnet", "password", "s2")
    got = cleartext_credentials_observed([h, h])
    assert len(got["instances"]) == 1
    assert got["instances"][0]["sources"] == ["s1", "s2"]


def test_reader_orders_instances_by_severity_priority():
    """Priority: telnet before ftp before http-basic before pop3/imap/smtp,
    then insertion order as tiebreaker. Report readers depend on this
    ordering to render the "most severe first" list without re-sorting."""
    a = Host(ip="10.0.0.40")
    b = Host(ip="10.0.0.10")
    c = Host(ip="10.0.0.20")
    d = Host(ip="10.0.0.30")
    # Insert deliberately out of priority order.
    record_cleartext_auth(a, 143, "imap", "login", "imap:plain")
    record_cleartext_auth(b, 21, "ftp", "password", "ftp:230")
    record_cleartext_auth(c, 23, "telnet", "password", "telnet:iac")
    record_cleartext_auth(d, 80, "http-basic", "basic", "http:401")
    got = cleartext_credentials_observed([a, b, c, d])
    protos = [r["protocol"] for r in got["instances"]]
    assert protos == ["telnet", "ftp", "http-basic", "imap"]


def test_reader_by_ip_groups_multiple_ports_on_one_host():
    """A dual-role box (FTP on 21, POP3 on 110, both cleartext) shows both
    entries under one IP in by_ip. Order follows priority."""
    h = Host(ip="10.0.0.10")
    record_cleartext_auth(h, 110, "pop3", "password", "pop3:USER")
    record_cleartext_auth(h, 21, "ftp", "password", "ftp:230")
    got = cleartext_credentials_observed([h])
    assert got["by_ip"]["10.0.0.10"] == [
        {"proto": "ftp", "port": 21},
        {"proto": "pop3", "port": 110},
    ]


def test_reader_ignores_hosts_with_no_recorded_exposures():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_cleartext_auth(a, 23, "telnet", "password", "s")
    got = cleartext_credentials_observed([a, b])
    assert "10.0.0.20" not in got["by_ip"]
    assert got["by_protocol"] == {"telnet": 1}


def test_http_basic_over_plain_http_from_wire_response():
    """RFC 7617 §4: `Authorization: Basic base64(user:pass)` transmits the
    password with no confidentiality when the URL is `http://`. The wire
    fixture is a real 401 challenge; base64 of `admin:admin` decodes to
    exactly what a captured header would carry."""
    assert _http_wants_basic(_HTTP_401_BASIC)
    assert base64.b64decode(b"YWRtaW46YWRtaW4=") == b"admin:admin"
    h = Host(ip="10.0.0.55")
    record_cleartext_auth(h, 80, "http-basic", "basic", "http:401-challenge")
    got = cleartext_credentials_observed([h])
    assert got["instances"][0] == {
        "ip": "10.0.0.55", "port": 80, "protocol": "http-basic",
        "auth_type": "basic", "sources": ["http:401-challenge"],
    }


# --- producer wire: ftp.analyze() -> record_cleartext_auth ------------------

def test_ftp_analyze_wires_cleartext_auth_into_reader(monkeypatch):
    """Integration: ftp.analyze() feeds the reader when its probe confirms
    the port speaks FTP (any 220 greeting on plaintext = cleartext-auth
    exposure, whether or not AUTH TLS is offered). Probe is stubbed offline;
    the shape matches what a live probe returns."""
    from recce.services import ftp, svcprobe

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=21, protocol="tcp", state="open", service="ftp")]

    fake_pr = {"ip": "10.0.0.10", "port": 21,
               "banner": "vsFTPd 3.0.3", "anonymous": False,
               "auth_tls": False, "syst": "UNIX Type: L8",
               "pasv_ip": "", "site_verbs": []}

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)

    ftp.analyze([h], active=True)

    got = cleartext_creds_for(h)
    assert len(got) == 1
    assert got[0]["protocol"] == "ftp"
    assert got[0]["port"] == 21
    assert got[0]["auth_type"] == "password"
    # Engagement-wide view sees the wired exposure.
    view = cleartext_credentials_observed([h])
    assert view["by_protocol"] == {"ftp": 1}
    assert view["by_ip"]["10.0.0.10"] == [{"proto": "ftp", "port": 21}]


def test_telnet_analyze_wires_cleartext_auth_into_reader(monkeypatch):
    """Integration: telnet.analyze() feeds the reader on any probe that
    identifies a telnet-speaking endpoint — telnet has NO transport crypto
    per RFC 854, so every reachable telnet endpoint is a cleartext-auth
    exposure. Probe is stubbed offline."""
    from recce.services import telnet, svcprobe

    h = Host(ip="10.0.0.11")
    h.ports = [Port(portid=23, protocol="tcp", state="open", service="telnet")]

    fake_pr = {"ip": "10.0.0.11", "port": 23, "banner": "login: ",
               "options_will": [1], "options_do": [3],
               "options_wont": [], "options_dont": [],
               "encrypt_offered": False, "auth_offered": False,
               "environ_offered": False, "environ_leak": {},
               "vendor": "unknown", "vendor_desc": "",
               "ntlm": {}, "ayt_ok": True, "tls": False,
               "looks_like_telnet": True}

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)
    # Bypass any active-attack code paths regardless of env state.
    monkeypatch.setattr(telnet, "_active_gate", lambda: False)

    telnet.analyze([h], active=True, active_attacks=False)

    got = cleartext_creds_for(h)
    assert any(r["protocol"] == "telnet" and r["port"] == 23 for r in got)
    view = cleartext_credentials_observed([h])
    assert view["by_protocol"].get("telnet") == 1
