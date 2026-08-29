"""WinRM (5985/tcp HTTP, 5986/tcp HTTPS): WSMan Identify + auth posture.

WinRM is the primary AD lateral-movement path — Evil-WinRM landings are one of
the highest-yield outcomes on an internal — so recce should identify:

  * **Reachability** — a WSMan Identify (SOAP over HTTP) that returns
    ProductVendor / ProductVersion / ProtocolVersion. That is a live WinRM
    speaker, unauthenticated, on either port.
  * **HTTP on 5985** — Kerberos/Negotiate on plain HTTP is common in AD, but
    Basic on plain HTTP puts the operator's password in cleartext on the wire
    once used. recce flags the combination, not the auth mechanism alone.
  * **Auth mechanisms** — the WWW-Authenticate header on an unauthenticated
    POST advertises them: Basic, Negotiate, Kerberos, CredSSP. Basic anywhere
    is worth calling out; CredSSP forwards credentials by design.
  * **TLS posture on 5986** — self-signed / expired / weak-suite (via the
    existing probes module).

All reads are single POSTs, stdlib only. Read-only: recce never sends creds.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl

from ..core.models import Host, Port


_HTTP_PORT = 5985
_HTTPS_PORT = 5986
_TIMEOUT = 4.0

# The one-shot SOAP body wsman Identify accepts on an unauthenticated request.
_IDENTIFY = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
             ' xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/'
             'wsmanidentity.xsd">'
             '<s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>')

_VENDOR_RE = re.compile(r"<wsmid:ProductVendor>([^<]+)</wsmid:ProductVendor>", re.I)
_VERSION_RE = re.compile(r"<wsmid:ProductVersion>([^<]+)</wsmid:ProductVersion>", re.I)
_PROTO_RE = re.compile(r"<wsmid:ProtocolVersion>([^<]+)</wsmid:ProtocolVersion>", re.I)


def is_winrm(port: Port) -> bool:
    svc = (port.service or "").lower()
    return (port.portid in (_HTTP_PORT, _HTTPS_PORT)
            or "wsman" in svc or "winrm" in svc)


def _identify(ip: str, port: int, tls: bool, timeout: float) -> dict | None:
    """WSMan Identify: reachable + product info if the server responds."""
    conn = None
    try:
        if tls:
            ctx = ssl._create_unverified_context()      # noqa: S323 - self-signed is the norm
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("POST", "/wsman", body=_IDENTIFY,
                     headers={"Content-Type": "application/soap+xml;charset=UTF-8",
                              "User-Agent": "recce-winrm/1.0"})
        r = conn.getresponse()
        body = r.read(16384).decode("utf-8", "replace")
    except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
    if r.status not in (200, 401, 403):
        return None
    out: dict = {"status": r.status, "auth": _auth_from_headers(r)}
    for name, rx in (("vendor", _VENDOR_RE), ("version", _VERSION_RE),
                     ("protocol", _PROTO_RE)):
        m = rx.search(body)
        if m:
            out[name] = m.group(1).strip()
    return out


def _auth_from_headers(resp) -> list[str]:
    """WWW-Authenticate lists every mechanism the server accepts, one per line
    or comma-separated in a single header. Basic / Negotiate / Kerberos /
    CredSSP is the set worth naming; anything else is passed through."""
    seen: list[str] = []
    for _k, v in resp.getheaders():
        if _k.lower() != "www-authenticate":
            continue
        for scheme in v.split(","):
            name = scheme.strip().split(" ", 1)[0]
            if name and name not in seen:
                seen.append(name)
    return seen


def probe(ip: str, port: int = _HTTP_PORT, timeout: float = _TIMEOUT) -> dict:
    """Probe whatever port we were handed; auto-select TLS for 5986/443."""
    tls = port in (_HTTPS_PORT, 443)
    out: dict = {"reachable": False, "port": port, "tls": tls}
    r = _identify(ip, port, tls, timeout)
    if r is None:
        return out
    out.update(r)
    out["reachable"] = True
    return out


def winrm_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_winrm(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_winrm(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            vendor = pr.get("vendor") or ""
            version = pr.get("version") or ""
            auth = pr.get("auth") or []
            tls = pr.get("tls", False)

            out.append(_finding(
                "medium" if not tls else "low",
                "WinRM reachable — Evil-WinRM / nxc winrm landing surface", tgt,
                f"WSMan Identify answered on {tgt}"
                + (f" ({vendor} {version})." if vendor or version else ".")
                + " With valid credentials or an NT hash this is a shell."
                + (" Plain HTTP on 5985 — credentials sent in cleartext once "
                   "Basic is used." if not tls else ""),
                "netexec / evil-winrm",
                f"nxc winrm {h.ip} -u USER -p 'PASS'   # or: "
                f"evil-winrm -i {h.ip} -u USER -p 'PASS'",
                "Restrict WinRM to management networks; disable Basic; require "
                "HTTPS on 5986 with a valid certificate.",
                ["CWE-284"], kind="winrm_reachable"))

            if "Basic" in auth and not tls:
                out.append(_finding(
                    "high",
                    "WinRM accepts Basic authentication over plain HTTP", tgt,
                    f"5985/tcp advertises Basic in WWW-Authenticate. Any valid "
                    f"authentication attempt puts the password on the wire in "
                    f"base64 — a passive listener on the segment recovers it "
                    f"immediately. Every auth mechanism the server offers: "
                    f"{', '.join(auth)}.",
                    "wireshark / responder",
                    f"# demonstrate: run a Basic auth against http://{h.ip}:5985/"
                    "wsman with a marker password and capture the request",
                    "Turn Basic off (Set-Item WSMan:\\localhost\\Service\\Auth\\"
                    "Basic $false); require HTTPS listener on 5986 only.",
                    ["CWE-319", "CWE-522"], kind="winrm_basic_plaintext"))
            elif "Basic" in auth:
                out.append(_finding(
                    "low",
                    "WinRM Basic auth enabled (even over TLS this is worth checking)",
                    tgt, f"WinRM at {tgt} advertises Basic. Over TLS the password "
                    f"is protected in transit, but Basic sends the CLEARTEXT "
                    f"password to the server on every request — kept in memory "
                    f"and reused. Auth mechanisms advertised: {', '.join(auth)}.",
                    "review", "curl -kv https://{ip}:5986/wsman -H 'Authorization: Basic ...'",
                    "Prefer Negotiate/Kerberos so the password never leaves the "
                    "client.", ["CWE-522"], kind="winrm_basic"))

            if "CredSSP" in auth:
                out.append(_finding(
                    "medium",
                    "WinRM offers CredSSP (delegates credentials to this host)", tgt,
                    "CredSSP forwards the caller's plaintext credentials to this "
                    "server so they can be re-used against a third system. On a "
                    "compromised server that is a credential-theft primitive; "
                    "MS-recommended only for controlled scenarios.",
                    "review", "Get-WSManCredSSP",
                    "Disable CredSSP unless a specific workflow requires it "
                    "(Disable-WSManCredSSP Server); if kept, restrict which "
                    "clients may delegate.",
                    ["CWE-522"], kind="winrm_credssp"))
    return out


def runbook(ip: str, port: int = _HTTP_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "nxc",
         "command": f"nxc winrm {ip} -u USER -p PASS   # or -H NTHASH",
         "why": "validates credentials and reports if the account can execute"},
        {"phase": "exploit", "tool": "evil-winrm",
         "command": f"evil-winrm -i {ip} -u USER -p PASS   # -H for pass-the-hash",
         "why": "interactive PowerShell shell when the account is authorised"},
        {"phase": "enumerate", "tool": "curl",
         "command": f"curl -kv -X POST https://{ip}:5986/wsman -H "
                    f"'Content-Type: application/soap+xml' -d '<Identify/>'",
         "why": "the WSMan Identify recce ran, by hand — useful with -kv to "
                "see WWW-Authenticate and the TLS chain"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "winrm", _HTTP_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = winrm_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["auth"] = pr.get("auth") or []
                t["vendor"] = pr.get("vendor", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
