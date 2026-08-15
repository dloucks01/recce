"""SMTP deep module, validated against a fake SMTP server that speaks enough of the
protocol to exercise the real smtplib-based probe (open relay / VRFY / STARTTLS)."""
from __future__ import annotations

import socketserver
import threading

from recce import smtp
from recce.models import Host, Port


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
