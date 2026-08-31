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


# --- T2 promotion: VRFY reply-body evidence capture --------------------------
#
# Fixtures are wire-derived: reply bodies mirror what an RFC-compliant MTA
# actually writes on a VRFY 250 line — either angle-addr form or bare
# `local@domain`. We do NOT build the wire via any recce encoder.

def _vrfy_evidence_server(cmd: str) -> str:
    up = cmd.upper()
    if up.startswith("EHLO"):
        return "250-mx.corp.local\r\n250 VRFY"
    if up.startswith("VRFY POSTMASTER"):
        return "250 Post Master <postmaster@mx.corp.local>"
    if up.startswith("VRFY ROOT"):
        return "250 root@mx.corp.local"
    if up.startswith("VRFY ADMIN"):
        return "252 Cannot VRFY user, but will accept"   # no resolved addr
    if up.startswith("VRFY MAILER-DAEMON"):
        return "550 no such user"
    if up.startswith("QUIT"):
        return "221 bye"
    return "250 OK"


def _vrfy_bare_ok_server(cmd: str) -> str:
    # Server always answers 250 OK but never names a real mailbox. This is
    # the false-positive class the T2 gate must reject.
    up = cmd.upper()
    if up.startswith("EHLO"):
        return "250-mx.locked\r\n250 VRFY"
    if up.startswith("VRFY"):
        return "250 OK"
    if up.startswith("QUIT"):
        return "221 bye"
    return "250 OK"


def test_parse_vrfy_reply_extracts_angle_and_bare_forms():
    assert smtp._parse_vrfy_reply("Post Master <postmaster@x.corp>") == "postmaster@x.corp"
    assert smtp._parse_vrfy_reply("root@x.corp") == "root@x.corp"
    # Bare status only — must NOT hallucinate a mailbox.
    assert smtp._parse_vrfy_reply("OK") == ""
    assert smtp._parse_vrfy_reply("Cannot VRFY user") == ""


def test_probe_vrfy_evidence_captures_resolved_mailboxes():
    port, srv = _serve(_vrfy_evidence_server)
    try:
        ev = smtp.probe_vrfy_evidence("127.0.0.1", port, timeout=4)
    finally:
        srv.shutdown()
    by_user = {e["user"]: e for e in ev}
    assert by_user["postmaster"]["code"] == 250
    assert by_user["postmaster"]["resolved"] == "postmaster@mx.corp.local"
    assert by_user["root"]["resolved"] == "root@mx.corp.local"
    # 252 = "will accept" but no resolved mailbox -> not T2 evidence.
    assert by_user["admin"]["code"] == 252
    assert by_user["admin"]["resolved"] == ""
    # 550 refusal
    assert by_user["mailer-daemon"]["code"] == 550


def test_probe_vrfy_evidence_bare_ok_yields_no_evidence():
    port, srv = _serve(_vrfy_bare_ok_server)
    try:
        ev = smtp.probe_vrfy_evidence("127.0.0.1", port, timeout=4)
    finally:
        srv.shutdown()
    # All four users reply 250 OK but NONE resolved a mailbox -> stays T1.
    assert ev, "should still return code entries"
    assert all(e["resolved"] == "" for e in ev)


def test_probe_vrfy_evidence_unreachable_returns_empty():
    # 127.0.0.1:1 is refused everywhere; probe must fail cleanly.
    ev = smtp.probe_vrfy_evidence("127.0.0.1", 1, timeout=2)
    assert ev == []


def test_findings_smtp_vrfy_promotes_to_t2_with_evidence():
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    probes = {("10.0.0.5", 25): {
        "vrfy": True, "starttls": True,
        "vrfy_evidence": [
            {"user": "postmaster", "code": 250, "resolved": "postmaster@mx.corp.local"},
            {"user": "root", "code": 250, "resolved": "root@mx.corp.local"},
            {"user": "admin", "code": 252, "resolved": ""},
        ]}}
    row = next(f for f in smtp.findings([h], probes) if f["kind"] == "smtp_vrfy")
    assert row["depth_tier"] == "t2"
    assert row.get("output"), "T2 promotion must attach evidence to output"
    assert "postmaster@mx.corp.local" in row["output"]
    assert "root@mx.corp.local" in row["output"]
    # The admin 252 line has no resolved mailbox -> excluded from evidence.
    assert "VRFY admin" not in row["output"]
    # Detail should reflect the chain.
    assert "CHAINED" in row["detail"]


def test_findings_smtp_vrfy_stays_t1_without_evidence():
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    probes = {("10.0.0.5", 25): {"vrfy": True, "starttls": True}}
    row = next(f for f in smtp.findings([h], probes) if f["kind"] == "smtp_vrfy")
    assert row["depth_tier"] == "t1"
    assert "output" not in row
    assert "CHAINED" not in row["detail"]


def test_findings_smtp_vrfy_stays_t1_when_evidence_has_no_resolved():
    # Probe fired but every response was a bare 250 OK (no mailbox).
    h = Host(ip="10.0.0.5", ports=[Port(portid=25, service="smtp", state="open")])
    probes = {("10.0.0.5", 25): {
        "vrfy": True, "starttls": True,
        "vrfy_evidence": [
            {"user": "postmaster", "code": 250, "resolved": ""},
            {"user": "root", "code": 250, "resolved": ""},
        ]}}
    row = next(f for f in smtp.findings([h], probes) if f["kind"] == "smtp_vrfy")
    assert row["depth_tier"] == "t1"
    assert "output" not in row
