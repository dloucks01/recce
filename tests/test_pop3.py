"""Tests for recce.services.pop3.

Fixtures are RFC-derived: every server reply is a raw byte string copied from
RFC 1939 (POP3) / RFC 2449 (CAPA) / RFC 2595 (STLS) / RFC 5034 (SASL) / RFC
2971 examples or from a real Dovecot/Cyrus transcript that matches the RFC
shape, not constructed by calling the module's own encoder.
"""
from __future__ import annotations

import base64
import socketserver
import struct
import threading

from recce.services import pop3
from recce.core.models import Host, Port


# --- RFC-derived wire fixtures ---------------------------------------------
# RFC 1939 §4 example greeting.
GREETING_PLAIN = b"+OK POP3 server ready\r\n"

# RFC 1939 §7 (APOP) example greeting: <processid.time@hostname>.
GREETING_APOP = (
    b"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>\r\n"
)

# Dovecot with product/version in the banner (banner-grab -> known-CVE table).
GREETING_DOVECOT_VULN = b"+OK Dovecot 2.3.16 ready.\r\n"

# RFC 2449 §5 CAPA reply. Multi-line, terminated by '.' on its own line.
CAPA_FULL = (
    b"+OK Capability list follows\r\n"
    b"TOP\r\n"
    b"USER\r\n"
    b"SASL PLAIN LOGIN CRAM-MD5 NTLM\r\n"
    b"UIDL\r\n"
    b"LOGIN-DELAY 30\r\n"
    b"IMPLEMENTATION Dovecot\r\n"
    b"STLS\r\n"
    b"PIPELINING\r\n"
    b"RESP-CODES\r\n"
    b".\r\n"
)

CAPA_NO_STLS = (
    b"+OK Capability list follows\r\n"
    b"TOP\r\n"
    b"USER\r\n"
    b"SASL PLAIN LOGIN\r\n"
    b"UIDL\r\n"
    b"IMPLEMENTATION Dovecot\r\n"
    b".\r\n"
)

# Post-STLS CAPA: server still advertises PLAIN/LOGIN inside TLS (downgrade).
CAPA_POST_STLS_SAME = (
    b"+OK Capability list follows\r\n"
    b"USER\r\n"
    b"SASL PLAIN LOGIN\r\n"
    b"UIDL\r\n"
    b"TOP\r\n"
    b".\r\n"
)

# Cyrus 2.4 unmaintained banner.
GREETING_CYRUS_VULN = b"+OK Cyrus 2.4.17 POP3 server ready\r\n"

# RFC 1939 §5 USER responses. Distinct wording for existing vs missing.
USER_OK_EXISTS = b"+OK send PASS\r\n"
USER_ERR_MISSING = b"-ERR Never heard of mailbox name\r\n"

# RFC 5034 SASL: server continuation is '+ <b64>'; abort is '*'.
# RFC 2195 §2 CRAM-MD5 example challenge encoded as base64.
CRAM_CONT = b"+ PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+\r\n"
SASL_ABORTED = b"-ERR authentication aborted\r\n"

# STLS success (RFC 2595 §4): "+OK Begin TLS negotiation now".
STLS_OK = b"+OK Begin TLS negotiation now\r\n"

# LOGIN responses.
PASS_ERR = b"-ERR authentication failed\r\n"
PASS_OK = b"+OK Logged in.\r\n"


# --- fake POP3 server harness ---------------------------------------------

class _Server:
    """Threaded loopback TCP server that speaks POP3.

    `script` maps upper-case command tokens ("USER", "PASS", "CAPA", "AUTH",
    "STLS", "QUIT", "STAT", "LIST", "UIDL", "TOP", "*") to a bytes reply, or a
    callable(cmd_text) -> bytes. `_SASL_CONT` handles the SASL follow-up line
    (defaults to `-ERR aborted` when the client sends '*').
    """

    def __init__(self, greeting: bytes, script: dict):
        self.greeting = greeting
        self.script = script
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(outer.greeting)
                self.wfile.flush()
                pending_sasl = False
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    text = line.decode("latin-1", "replace").rstrip("\r\n")
                    if pending_sasl:
                        pending_sasl = False
                        sasl = outer.script.get("_SASL_CONT")
                        if callable(sasl):
                            reply = sasl(text)
                        elif sasl is not None:
                            reply = sasl
                        else:
                            reply = SASL_ABORTED
                        self.wfile.write(reply)
                        self.wfile.flush()
                        continue
                    parts = text.split(None, 1)
                    if not parts:
                        continue
                    cmd = parts[0].upper()
                    reply = outer.script.get(cmd)
                    if callable(reply):
                        reply = reply(text)
                    if reply is None:
                        reply = b"-ERR unknown command\r\n"
                    self.wfile.write(reply)
                    self.wfile.flush()
                    if reply.startswith(b"+ ") or reply == b"+\r\n":
                        pending_sasl = True
                    if cmd == "QUIT":
                        return

        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


# --- parser unit tests -----------------------------------------------------

def test_parse_apop_timestamp_from_rfc_greeting():
    assert pop3._parse_apop_timestamp(GREETING_APOP) == (
        "<1896.697170952@dbc.mtview.ca.us>")
    assert pop3._parse_apop_timestamp(GREETING_PLAIN) == ""


def test_parse_capa_extracts_all_known_tokens():
    caps = pop3._parse_capa(CAPA_FULL)
    assert "STLS" in caps
    assert caps["SASL"].split() == ["PLAIN", "LOGIN", "CRAM-MD5", "NTLM"]
    assert caps["LOGIN-DELAY"].startswith("30")
    assert caps["IMPLEMENTATION"].startswith("Dovecot")
    assert pop3._sasl_mechs(caps) == ["PLAIN", "LOGIN", "CRAM-MD5", "NTLM"]
    assert pop3._login_delay(caps) == 30


def test_parse_av_pairs_decodes_utf16_names():
    # Real MS-NLMP AV_PAIR layout: (type<H> len<H> value)*, terminated 0x0000.
    def av(t, s):
        v = s.encode("utf-16-le")
        return struct.pack("<HH", t, len(v)) + v
    ti = (av(0x0001, "SRV01") + av(0x0002, "CORP")
          + av(0x0003, "srv01.corp.local") + av(0x0004, "corp.local")
          + av(0x0005, "corp.local") + b"\x00\x00\x00\x00")
    out = pop3._parse_av_pairs(ti)
    assert out["nb_computer"] == "SRV01"
    assert out["nb_domain"] == "CORP"
    assert out["dns_computer"] == "srv01.corp.local"
    assert out["dns_domain"] == "corp.local"


def test_is_pop3_respects_open_state_and_port():
    assert pop3.is_pop3(Port(portid=110, service="pop3", state="open"))
    assert pop3.is_pop3(Port(portid=995, service="pop3s", state="open"))
    assert not pop3.is_pop3(Port(portid=110, service="pop3", state="closed"))
    assert not pop3.is_pop3(Port(portid=8080, service="http", state="open"))


# --- probe: banner + CAPA + STLS-missing -----------------------------------

def test_probe_captures_apop_timestamp_capa_and_cleartext_auth():
    srv = _Server(GREETING_APOP, {
        "CAPA": CAPA_FULL,
        # STLS says +OK but a real TLS handshake will fail on the raw socket -
        # that is fine; we only need the reply to show STLS is advertised in
        # CAPA, and this exchange runs BEFORE the STLS attempt.
        "USER": b"+OK\r\n",
        "PASS": b"-ERR [AUTH] Authentication failed.\r\n",
        "AUTH": b"+ PDE4OTYu\r\n",     # continuation for CRAM/DIGEST/NTLM
        "*": SASL_ABORTED,
        "STLS": b"-ERR STLS not available\r\n",
        "QUIT": b"+OK Bye.\r\n",
    })
    try:
        pr = pop3.probe("127.0.0.1", srv.port, timeout=3)
    finally:
        srv.close()
    assert pr["reachable"]
    assert pr["apop_timestamp"] == "<1896.697170952@dbc.mtview.ca.us>"
    assert pr["stls"] is True
    assert "PLAIN" in pr["sasl"]
    assert pr["login_delay"] == 30
    assert pr["implementation"].startswith("Dovecot")
    assert pr["plaintext_auth"] == "accepted"


def test_probe_flags_no_stls_and_no_apop():
    srv = _Server(GREETING_PLAIN, {
        "CAPA": CAPA_NO_STLS,
        "USER": b"+OK\r\n",
        "PASS": b"-ERR authentication failed\r\n",
        "QUIT": b"+OK Bye.\r\n",
    })
    try:
        pr = pop3.probe("127.0.0.1", srv.port, timeout=3)
    finally:
        srv.close()
    assert pr["reachable"]
    assert pr["stls"] is False
    assert pr["apop_timestamp"] == ""
    assert pr["plaintext_auth"] == "accepted"


def test_probe_captures_ntlm_type2_av_pairs():
    # Build a real NTLMSSP Type-2 message with an AV-pair target-info block.
    def av(t, s):
        v = s.encode("utf-16-le")
        return struct.pack("<HH", t, len(v)) + v
    ti = (av(0x0001, "MAIL01") + av(0x0002, "CORP")
          + av(0x0003, "mail01.corp.local") + av(0x0004, "corp.local")
          + b"\x00\x00\x00\x00")
    # NTLMSSP header (RFC-adjacent MS-NLMP 2.2.1.2): sig, type=2, target-name
    # fields (zeroed), flags, challenge, reserved, target-info fields.
    ti_off = 48
    header = (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)                         # message type = 2
        + struct.pack("<HHI", 0, 0, ti_off)            # TargetName fields (empty)
        + struct.pack("<I", 0)                         # NegotiateFlags
        + b"\x11\x22\x33\x44\x55\x66\x77\x88"          # server challenge
        + b"\x00" * 8                                  # reserved
        + struct.pack("<HHI", len(ti), len(ti), ti_off)  # TargetInfo fields
    )
    # Pad to ti_off then append the AV-pair blob.
    pad = b"\x00" * (ti_off - len(header)) if len(header) < ti_off else b""
    type2 = header + pad + ti
    t2_b64 = base64.b64encode(type2)

    srv = _Server(GREETING_PLAIN, {
        "CAPA": CAPA_FULL,
        # AUTH NTLM first replies "+ " continuation; second call (after client
        # sends the Type-1) replies with the base64 Type-2 challenge.
        "AUTH": (lambda text: b"+ \r\n"
                 if "NTLM" in text.upper() else b"+ PDE4OTYu\r\n"),
        "_SASL_CONT": (lambda body: b"+ " + t2_b64 + b"\r\n"
                       if len(body) > 20 and body.strip("*")
                       else SASL_ABORTED),
        "STLS": b"-ERR STLS not available\r\n",
        "USER": b"+OK\r\n",
        "PASS": PASS_ERR,
        "*": SASL_ABORTED,
        "QUIT": b"+OK Bye.\r\n",
    })
    try:
        pr = pop3.probe("127.0.0.1", srv.port, timeout=3)
    finally:
        srv.close()
    assert pr["reachable"]
    ntlm = pr.get("ntlm_info") or {}
    assert ntlm.get("nb_computer") == "MAIL01"
    assert ntlm.get("dns_domain") == "corp.local"


# --- findings mapping ------------------------------------------------------

def _host_at(port: int) -> Host:
    return Host(ip="10.0.0.9",
                ports=[Port(portid=port, service="pop3", state="open")])


def test_findings_emits_all_key_kinds_for_worst_case_probe():
    h = _host_at(110)
    pr = {
        "reachable": True, "port": 110,
        "banner": "+OK Dovecot 2.3.16 ready <99.11@host.corp.local>",
        "apop_timestamp": "<99.11@host.corp.local>",
        "capa": {"USER": "", "SASL": "PLAIN LOGIN CRAM-MD5 NTLM",
                 "IMPLEMENTATION": "Dovecot",
                 "LOGIN-DELAY": "30", "TOP": "", "UIDL": ""},
        "capa_pre_tls": {"SASL": "PLAIN LOGIN"},
        "capa_supported": True,
        "sasl": ["PLAIN", "LOGIN", "CRAM-MD5", "NTLM"],
        "stls": False, "implementation": "Dovecot",
        "login_delay": 30, "product": "Dovecot", "version": "2.3.16",
        "plaintext_auth": "accepted",
        "sasl_challenges": {"cram_md5": "PDE4OTYu"},
        "ntlm_info": {"nb_computer": "MAIL01", "dns_domain": "corp.local"},
        "cert": {}, "stls_negotiated": False,
        "starttls_downgrade": False, "sasl_post_tls": [],
        "enum": {"distinguishes": True, "existing": ["root", "postmaster"],
                 "responses": {}, "timings": {}},
        "credentialed": {"login": True, "user": "mail", "default_creds": True,
                         "mailbox": {"stat": "+OK 3 1234",
                                     "addresses": ["a@corp.local"],
                                     "received_from": ["relay.corp.local"],
                                     "headers": ["From: a@corp.local"]}},
    }
    fs = pop3.findings([h], {("10.0.0.9", 110): pr})
    kinds = {f["kind"] for f in fs}
    for expected in (
        "pop3_no_stls",
        "pop3_cleartext_auth",
        "pop3_sasl_mechs",
        "pop3_apop_timestamp",
        "pop3_apop_crackable",
        "pop3_ntlm_info",
        "pop3_implementation",
        "pop3_known_cve",
        "pop3_user_enum",
        "pop3_mailbox_read",
        "pop3_weak_password",
    ):
        assert expected in kinds, f"missing {expected}: got {kinds}"


def test_findings_starttls_downgrade_fires_when_mechs_unchanged():
    h = _host_at(110)
    pr = {"reachable": True, "port": 110, "banner": "+OK ready",
          "apop_timestamp": "", "capa": {"STLS": "", "SASL": "PLAIN LOGIN"},
          "capa_pre_tls": {"SASL": "PLAIN LOGIN"},
          "capa_supported": True,
          "sasl": ["PLAIN", "LOGIN"], "stls": True,
          "implementation": "", "login_delay": 0,
          "product": "", "version": "", "plaintext_auth": "",
          "sasl_challenges": {}, "ntlm_info": {}, "cert": {},
          "stls_negotiated": True, "starttls_downgrade": True,
          "sasl_post_tls": ["PLAIN", "LOGIN"]}
    fs = pop3.findings([h], {("10.0.0.9", 110): pr})
    assert any(f["kind"] == "pop3_stls_broken" for f in fs)


def test_findings_on_995_downgrades_plain_severity_to_low():
    h = _host_at(995)
    pr = {"reachable": True, "port": 995, "banner": "+OK ready",
          "apop_timestamp": "", "capa": {"SASL": "PLAIN"},
          "capa_pre_tls": {}, "capa_supported": True,
          "sasl": ["PLAIN"], "stls": False, "implementation": "",
          "login_delay": 0, "product": "", "version": "",
          "plaintext_auth": "", "sasl_challenges": {}, "ntlm_info": {},
          "cert": {"names": ["mail.corp.local"], "expired": False,
                   "self_signed": True, "error": "self signed certificate"},
          "stls_negotiated": False, "starttls_downgrade": False,
          "sasl_post_tls": []}
    fs = pop3.findings([h], {("10.0.0.9", 995): pr})
    plain = [f for f in fs if f["kind"] == "pop3_sasl_mechs"]
    assert plain and plain[0]["severity"] == "low"
    # No "no STLS on 110" finding: implicit TLS 995 is fine.
    assert not any(f["kind"] == "pop3_no_stls" for f in fs)
    # Self-signed cert becomes a low finding.
    assert any(f["kind"] == "pop3s_cert" for f in fs)


def test_findings_known_cve_matches_dovecot_vulnerable_banner():
    h = _host_at(110)
    pr = {"reachable": True, "port": 110,
          "banner": "+OK Dovecot 2.3.16 ready",
          "apop_timestamp": "", "capa": {}, "capa_pre_tls": {},
          "capa_supported": True, "sasl": [], "stls": True,
          "implementation": "", "login_delay": 0,
          "product": "Dovecot", "version": "2.3.16",
          "plaintext_auth": "", "sasl_challenges": {}, "ntlm_info": {},
          "cert": {}, "stls_negotiated": False, "starttls_downgrade": False,
          "sasl_post_tls": []}
    fs = pop3.findings([h], {("10.0.0.9", 110): pr})
    known = [f for f in fs if f["kind"] == "pop3_known_cve"]
    assert known
    assert "Dovecot" in known[0]["title"]


def test_findings_to_vulns_source_and_shape():
    h = _host_at(110)
    pr = {"reachable": True, "port": 110, "banner": "+OK ready",
          "apop_timestamp": "", "capa": {}, "capa_pre_tls": {},
          "capa_supported": True, "sasl": [], "stls": False,
          "implementation": "", "login_delay": 0,
          "product": "", "version": "", "plaintext_auth": "accepted",
          "sasl_challenges": {}, "ntlm_info": {}, "cert": {},
          "stls_negotiated": False, "starttls_downgrade": False,
          "sasl_post_tls": []}
    fs = pop3.findings([h], {("10.0.0.9", 110): pr})
    by_ip = pop3.findings_to_vulns(fs)
    assert "10.0.0.9" in by_ip
    assert all(v.source == "pop3" for v in by_ip["10.0.0.9"])


# --- user enumeration via monkeypatched socket -----------------------------

def test_enum_users_detects_response_differential(monkeypatch):
    valid = {"root"}

    class _FakeSock:
        def __init__(self, user_line: bytes):
            self._buf = b"+OK POP3 server ready\r\n"
            self._reply_user = user_line

        def settimeout(self, _t): pass

        def sendall(self, data: bytes):
            up = data.upper()
            if up.startswith(b"USER "):
                self._buf += self._reply_user
            elif up.startswith(b"QUIT"):
                self._buf += b"+OK Bye.\r\n"

        def recv(self, n: int) -> bytes:
            out, self._buf = self._buf[:n], self._buf[n:]
            return out or b""

        def close(self): pass

    class _Rotator:
        def __init__(self, users): self.users = list(users); self.i = 0
        def next(self):
            u = self.users[self.i % len(self.users)]
            self.i += 1
            return u

    users = ["root", "alice", "bob", "carol"]
    rot = _Rotator(users)

    def fake_open(ip, port, timeout):
        u = rot.next()
        line = USER_OK_EXISTS if u in valid else USER_ERR_MISSING
        return _FakeSock(line)

    monkeypatch.setattr(pop3, "_open_socket", fake_open)
    result = pop3.enum_users("127.0.0.1", 110, users=users, timeout=1)
    assert result["distinguishes"] is True
    assert set(result["existing"]) == valid


# --- login-delay aware spray ----------------------------------------------

def test_spray_honours_login_delay_between_same_user_attempts(monkeypatch):
    times: list[float] = []
    now = {"t": 0.0}

    def fake_monotonic():
        return now["t"]

    def fake_sleep(sec):
        now["t"] += sec
        times.append(sec)

    monkeypatch.setattr(pop3.time if hasattr(pop3, "time") else __import__("time"),
                        "monotonic", fake_monotonic)
    # `spray` imports time inside the function; patch the module-level import.
    import time as _t
    monkeypatch.setattr(_t, "monotonic", fake_monotonic)
    monkeypatch.setattr(_t, "sleep", fake_sleep)

    calls: list[tuple[str, str]] = []

    def fake_try_login(ip, port, user, secret, timeout=6.0):
        calls.append((user, secret))
        return False

    monkeypatch.setattr(pop3, "try_login", fake_try_login)

    out = pop3.spray("127.0.0.1", 110, users=["a"], secrets=["p1", "p2", "p3"],
                     login_delay=5, cap=10, timeout=1)
    assert out["tried"] == 3
    # Two sleeps for the second and third attempt against the same user.
    assert sum(1 for s in times if s > 0) == 2


# --- credentialed_probe via monkeypatched socket ---------------------------

def test_credentialed_probe_pulls_stat_list_uidl_and_top_headers(monkeypatch):
    """Simulate a +OK PASS + TOP flow and confirm header addresses / Received
    hosts are harvested. STAT reply follows RFC 1939 §5 ('+OK <count> <size>')."""
    script = [
        b"+OK Dovecot ready\r\n",                             # greeting
        b"+OK Capability list follows\r\nUSER\r\n.\r\n",     # CAPA (no STLS)
        b"+OK\r\n",                                           # USER
        b"+OK Logged in.\r\n",                                # PASS
        b"+OK 1 512\r\n",                                     # STAT
        b"+OK scan listing follows\r\n1 512\r\n.\r\n",       # LIST
        b"+OK unique-id listing follows\r\n1 abc\r\n.\r\n",  # UIDL
        b"+OK top of message follows\r\n"
        b"Received: from relay.corp.local by mail.corp.local\r\n"
        b"From: alice@corp.local\r\n"
        b"To: bob@corp.local\r\n"
        b"Subject: hi\r\n\r\n"
        b".\r\n",                                             # TOP 1 25
        b"+OK Bye.\r\n",                                      # QUIT
    ]

    class _FakeSock:
        def __init__(self):
            self._buf = script[0]
            self._i = 1

        def settimeout(self, _t): pass

        def sendall(self, data: bytes):
            if self._i < len(script):
                self._buf += script[self._i]
                self._i += 1

        def recv(self, n: int) -> bytes:
            out, self._buf = self._buf[:n], self._buf[n:]
            return out or b""

        def close(self): pass

    monkeypatch.setattr(pop3, "_open_socket",
                        lambda ip, port, timeout: _FakeSock())
    r = pop3.credentialed_probe("127.0.0.1", 110, "mail", "mailpw", timeout=1)
    assert r["login"] is True
    mb = r["mailbox"]
    assert "512" in mb["stat"]
    assert any("alice@corp.local" in a for a in mb["addresses"])
    assert "relay.corp.local" in mb["received_from"]


# --- analyze wiring --------------------------------------------------------

def test_analyze_returns_targets_and_probes():
    h = _host_at(110)
    # Active=False so the fake host is not actually dialed.
    out = pop3.analyze([h], active=False)
    assert out["targets"][0]["ip"] == "10.0.0.9"
    assert out["stats"]["targets"] == 1
    assert out["findings"] == []
