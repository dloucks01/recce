"""Deep SMTP enumeration (stdlib smtplib, read-only-ish).

Tests the classic unauthenticated SMTP exposures without ever sending a message:
  * OPEN RELAY - the server accepts an envelope (MAIL FROM + RCPT TO) for a non-local
    recipient with no auth (we stop before DATA, so nothing is ever delivered).
  * VRFY / EXPN user enumeration.
  * cleartext posture - no STARTTLS offered on 25/587.

Findings fold into the severity totals / Vulnerabilities sheet (source="smtp").
"""
from __future__ import annotations

import smtplib
import socket

from .models import Host, Port

_PORTS = (25, 465, 587, 2525)
_DEFAULT_PORT = 25
_TIMEOUT = 6.0
_EXTERNAL = "relay-test@example.net"      # a non-local recipient -> relaying if accepted


def is_smtp(port: Port) -> bool:
    if not port.is_open:
        return False
    svc = (port.service or "").lower()
    return port.portid in _PORTS or "smtp" in svc or svc == "submission"


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    res = {"reachable": False, "banner": "", "esmtp": False, "starttls": False,
           "vrfy": False, "open_relay": False, "auth": "", "error": ""}
    try:
        cls = smtplib.SMTP_SSL if port == 465 else smtplib.SMTP
        srv = cls(timeout=timeout)
        srv.connect(ip, port)
    except (OSError, smtplib.SMTPException) as e:
        res["error"] = str(e)
        return res
    try:
        res["reachable"] = True
        code, msg = srv.ehlo("recce-scan.local")
        text = (msg or b"").decode("utf-8", "replace") if isinstance(msg, bytes) else str(msg)
        res["banner"] = text.splitlines()[0][:200] if text else ""
        res["esmtp"] = code == 250
        feats = getattr(srv, "esmtp_features", {}) or {}
        res["starttls"] = "starttls" in feats
        res["auth"] = (feats.get("auth") or "").strip()
        # VRFY user enumeration (250 confirmed / 252 will-attempt)
        try:
            vcode, _ = srv.docmd("VRFY", "root")
            res["vrfy"] = vcode in (250, 252)
        except smtplib.SMTPException:
            pass
        # Open-relay test: envelope only, NEVER DATA. A 250/251 on an external RCPT
        # from an unauthenticated session is relaying.
        try:
            srv.docmd("RSET")
            srv.docmd("MAIL", "FROM:<recce-probe@example.com>")
            rcode, _ = srv.docmd("RCPT", f"TO:<{_EXTERNAL}>")
            res["open_relay"] = rcode in (250, 251)
            srv.docmd("RSET")
        except smtplib.SMTPException:
            pass
        try:
            srv.quit()
        except smtplib.SMTPException:
            srv.close()
        return res
    except (OSError, smtplib.SMTPException, socket.error) as e:
        res["error"] = str(e)
        try:
            srv.close()
        except Exception:
            pass
        return res


def smtp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_smtp(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "smtp", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_smtp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            if pr.get("open_relay"):
                out.append(_finding(
                    "high", "SMTP open relay", tgt,
                    "The server accepted an envelope (MAIL FROM + RCPT TO) for an "
                    f"external recipient ({_EXTERNAL}) with no authentication - it will "
                    "relay mail for anyone (spam / phishing / spoofing).",
                    f"swaks --server {h.ip}:{p.portid} --from x@example.com "
                    f"--to {_EXTERNAL}",
                    "Restrict relaying to authenticated senders / trusted networks "
                    "(smtpd_relay_restrictions / mynetworks).",
                    ["CWE-269", "CWE-16"], kind="smtp_open_relay"))
            if pr.get("vrfy"):
                out.append(_finding(
                    "low", "SMTP VRFY user enumeration", tgt,
                    "VRFY returned a positive response, so valid local usernames can be "
                    "enumerated over SMTP (feeds password spraying).",
                    f"for u in root admin postmaster; do echo VRFY $u | nc {h.ip} {p.portid}; done",
                    "Disable VRFY/EXPN (disable_vrfy_command = yes).",
                    ["CWE-200"], kind="smtp_vrfy"))
            if not pr.get("starttls") and p.portid in (25, 587):
                out.append(_finding(
                    "low", "SMTP without STARTTLS (cleartext)", tgt,
                    "The server does not offer STARTTLS on this port, so mail and any "
                    "AUTH credentials cross the wire in cleartext.",
                    f"openssl s_client -starttls smtp -connect {h.ip}:{p.portid}",
                    "Offer/require STARTTLS; require TLS before AUTH.",
                    ["CWE-319"], kind="smtp_cleartext"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [{"step": "Test open relay (envelope only, no DATA)",
             "cmd": f"swaks --server {ip}:{port} --from x@example.com --to {_EXTERNAL} --quit-after RCPT"},
            {"step": "User enumeration",
             "cmd": f"smtp-user-enum -M VRFY -U users.txt -t {ip} -p {port}"}]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "smtp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = smtp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["open_relay"] = pr.get("open_relay", False)
                t["vrfy"] = pr.get("vrfy", False)
                t["version"] = pr.get("banner", "") or t.get("version", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
