"""SMTP deep module, validated against a fake SMTP server that speaks enough of the
protocol to exercise the real smtplib-based probe (open relay / VRFY / STARTTLS)."""
from __future__ import annotations

import socketserver
import threading

from recce.services import smtp
from recce.core.models import Host, Port


def _serve(responder):
    class H(socketserver.StreamRequestHandler):
        def handle(self):
            self.wfile.write(b"220 fake ESMTP\r\n")
            while True:
                line = self.rfile.readline()
                if not line:
                    return
                cmd = line.decode("latin-1").strip()
                reply = responder(cmd)
                self.wfile.write(reply.encode() + b"\r\n")
                if cmd.upper().startswith("QUIT"):
                    return

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], srv


def _open_relay_server(cmd: str) -> str:
    up = cmd.upper()
    if up.startswith("EHLO"):
        return "250-fake\r\n250-STARTTLS\r\n250 VRFY"
    if up.startswith("VRFY"):
        return "250 root <root@fake>"
    if up.startswith(("MAIL", "RCPT", "RSET")):
        return "250 OK"                              # accepts external RCPT -> open relay
    if up.startswith("QUIT"):
        return "221 bye"
    return "250 OK"


def _locked_server(cmd: str) -> str:
    up = cmd.upper()
    if up.startswith("EHLO"):
        return "250-fake\r\n250 SIZE 1024"           # no STARTTLS, no VRFY
    if up.startswith("VRFY"):
        return "502 VRFY disabled"
    if up.startswith("RCPT"):
        return "554 relay access denied"             # not an open relay
    if up.startswith("QUIT"):
        return "221 bye"
    return "250 OK"


def test_probe_detects_open_relay_and_vrfy():
    port, srv = _serve(_open_relay_server)
    try:
        pr = smtp.probe("127.0.0.1", port, timeout=4)
    finally:
        srv.shutdown()
    assert pr["reachable"] and pr["esmtp"]
    assert pr["open_relay"] is True
    assert pr["vrfy"] is True
    assert pr["starttls"] is True


def test_probe_clean_server_flags_nothing_bad():
    port, srv = _serve(_locked_server)
    try:
        pr = smtp.probe("127.0.0.1", port, timeout=4)
    finally:
        srv.shutdown()
    assert pr["reachable"]
    assert pr["open_relay"] is False
    assert pr["vrfy"] is False
    assert pr["starttls"] is False       # -> a cleartext (low) finding, not relay


def test_findings_from_probe():
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    probes = {("10.0.0.5", 25): {"open_relay": True, "vrfy": True, "starttls": False}}
    titles = {f["title"] for f in smtp.findings([h], probes)}
    assert "SMTP open relay" in titles
    assert "SMTP VRFY user enumeration" in titles
    assert "SMTP without STARTTLS (cleartext)" in titles
    relay = next(f for f in smtp.findings([h], probes) if f["title"] == "SMTP open relay")
    assert relay["severity"] == "high"
    assert smtp.findings_to_vulns(smtp.findings([h], probes))["10.0.0.5"][0].source == "smtp"


def test_is_smtp_respects_open_state():
    assert smtp.is_smtp(Port(portid=25, service="smtp", state="open"))
    assert smtp.is_smtp(Port(portid=587, service="submission", state="open"))
    assert not smtp.is_smtp(Port(portid=25, service="smtp", state="closed"))


# --- capability gap: banner fingerprint + version-gated CVE mapping ---------

def test_fingerprint_exim_below_492_flags_cve_2019_10149():
    fp = smtp._fingerprint(
        "220 mx01.example.org ESMTP Exim 4.89 Wed, 12 Feb 2020 10:12:00 +0000"
    )
    assert fp["product"] == "Exim"
    assert fp["version"] == "4.89"
    ids = {c["id"] for c in fp["cves"]}
    assert "CVE-2019-10149" in ids
    assert "CVE-2020-28017" in ids   # 21Nails also gates open at <4.94.2


def test_fingerprint_exim_current_release_emits_no_cve():
    fp = smtp._fingerprint("220 mx.example.net ESMTP Exim 4.98 Wed, 01 Aug 2025 10:00:00")
    assert fp["product"] == "Exim"
    assert fp["version"] == "4.98"
    assert fp["cves"] == []


def test_fingerprint_exchange_and_postfix_product_only():
    fp = smtp._fingerprint("220 EXCH01.corp.local Microsoft ESMTP MAIL Service, "
                           "Version: 15.2.858.5 ready at Wed, 12 Feb 2020 10:12:00")
    assert fp["product"] == "Microsoft Exchange"
    assert fp["version"] == "15.2.858.5"
    assert fp["cves"] == []       # no version-gate we're willing to ship
    fp2 = smtp._fingerprint("220 mail.example.com ESMTP Postfix")
    assert fp2["product"] == "Postfix"
    assert fp2["cves"] == []


def test_fingerprint_unknown_banner_yields_nothing():
    fp = smtp._fingerprint("220 unknown MTA ready")
    assert fp == {"product": "", "version": "", "cves": []}


# --- capability gap: AUTH-mech deep-parse ------------------------------------

def test_split_auth_mechs_handles_rfc_and_comma_and_equals_forms():
    assert smtp._split_auth_mechs("PLAIN LOGIN") == ["PLAIN", "LOGIN"]
    assert smtp._split_auth_mechs("=PLAIN LOGIN CRAM-MD5") == ["PLAIN", "LOGIN", "CRAM-MD5"]
    assert smtp._split_auth_mechs("plain,login,ntlm") == ["PLAIN", "LOGIN", "NTLM"]
    assert smtp._split_auth_mechs("") == []


def test_findings_flag_auth_before_starttls_on_25():
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    probes = {("10.0.0.5", 25): {"open_relay": False, "vrfy": False,
                                 "starttls": False, "auth": "PLAIN LOGIN"}}
    kinds = {f["kind"] for f in smtp.findings([h], probes)}
    assert "smtp_auth_before_tls" in kinds
    row = next(f for f in smtp.findings([h], probes)
               if f["kind"] == "smtp_auth_before_tls")
    assert row["severity"] == "medium"        # 25 = medium, 587 = high


def test_findings_flag_auth_before_starttls_on_587_high():
    h = Host(ip="10.0.0.5", ports=[Port(portid=587, service="submission", state="open")])
    probes = {("10.0.0.5", 587): {"starttls": False, "auth": "PLAIN"}}
    row = next(f for f in smtp.findings([h], probes)
               if f["kind"] == "smtp_auth_before_tls")
    assert row["severity"] == "high"           # RFC 6409 submission-port


def test_findings_flag_weak_auth_mechs_only_when_present():
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    # STARTTLS advertised so the tls-violation finding is silent — isolate weak-mech.
    probes = {("10.0.0.5", 25): {"starttls": True,
                                 "auth": "PLAIN LOGIN CRAM-MD5 DIGEST-MD5"}}
    kinds = {f["kind"] for f in smtp.findings([h], probes)}
    assert "smtp_auth_weak_mech" in kinds
    assert "smtp_auth_before_tls" not in kinds
    probes_clean = {("10.0.0.5", 25): {"starttls": True, "auth": "PLAIN LOGIN"}}
    kinds_clean = {f["kind"] for f in smtp.findings([h], probes_clean)}
    assert "smtp_auth_weak_mech" not in kinds_clean


def test_findings_flag_ntlm_auth_leak():
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    probes = {("10.0.0.5", 25): {"starttls": True, "auth": "PLAIN NTLM"}}
    row = next(f for f in smtp.findings([h], probes)
               if f["kind"] == "smtp_auth_ntlm_leak")
    assert "NTLM" in row["detail"]
    assert row["severity"] == "medium"


def test_findings_emit_cve_from_fingerprint():
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    fp = smtp._fingerprint("220 x ESMTP Exim 4.89 ready")
    probes = {("10.0.0.5", 25): {"starttls": True, "fingerprint": fp}}
    fs = [f for f in smtp.findings([h], probes) if f["kind"] == "smtp_cve"]
    ids = {c for f in fs for c in f["cwes"] if c.startswith("CVE-")}
    assert "CVE-2019-10149" in ids


# --- capability gap: EXPN well-known alias sweep -----------------------------

def _expn_server(cmd: str) -> str:
    up = cmd.upper()
    if up.startswith("EHLO"):
        return "250-fake\r\n250 EXPN"
    if up.startswith("EXPN ALL"):
        # Multi-line 250 body listing three members.
        return ("250-Alice <alice@fake>\r\n"
                "250-Bob <bob@fake>\r\n"
                "250 Carol <carol@fake>")
    if up.startswith("EXPN STAFF"):
        return "250 Eve <eve@fake>"
    if up.startswith("EXPN "):
        return "550 access denied"
    if up.startswith("QUIT"):
        return "221 bye"
    return "250 OK"


def test_expn_aliases_parses_multiline_and_single_member():
    port, srv = _serve(_expn_server)
    try:
        out = smtp.expn_aliases("127.0.0.1", port, timeout=4)
    finally:
        srv.shutdown()
    # `all` should have three members, `staff` one, others silent (550).
    assert set(out) == {"all", "staff"}
    assert {a.lower() for a in out["all"]} == {"alice@fake", "bob@fake", "carol@fake"}
    assert out["staff"] == ["eve@fake"]


def test_parse_expn_members_handles_angle_addr_and_bare_local():
    members = smtp._parse_expn_members(
        "Alice <alice@fake>\nBob\nRoot Admin <root@corp>\nalice@fake\n"
    )
    lo = {m.lower() for m in members}
    assert "alice@fake" in lo
    assert "root@corp" in lo
    assert "bob" in lo           # bare local name still counted
    # dedupe: alice@fake appeared twice
    assert sum(1 for m in members if m.lower() == "alice@fake") == 1


def test_findings_emit_expn_alias_leak():
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    probes = {("10.0.0.5", 25): {"starttls": True,
                                 "expn_aliases": {"all": ["a@x", "b@x", "c@x"],
                                                  "staff": ["eve@x"]}}}
    row = next(f for f in smtp.findings([h], probes)
               if f["kind"] == "smtp_expn_alias_leak")
    assert row["severity"] == "medium"
    assert "4 member" in row["detail"]         # 3 + 1
    assert "EXPN all" in row["detail"]
