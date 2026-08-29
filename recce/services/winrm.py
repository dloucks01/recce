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

import base64
import http.client
import re
import socket
import ssl
import struct

from ..core.models import Host, Port


_HTTP_PORT = 5985
_HTTPS_PORT = 5986
_TIMEOUT = 4.0

# NTLMSSP Type-2 AV_PAIR ids (MS-NLMP §2.2.2.1). Same map used by smb/pop3/telnet
# harvesters so the cross-service host.ntlm store stays consistent.
_NTLM_AV = {0x0001: "netbios_computer", 0x0002: "netbios_domain",
            0x0003: "dns_computer",     0x0004: "dns_domain",
            0x0005: "dns_tree"}

# "OS: 10.0.19041 SP: 0.0 Stack: 3.0" -> {os_build, sp, stack}. WinRM's
# ProductVersion follows DMTF wsmanidentity.xsd on Windows.
_PV_OS_RE = re.compile(r"OS:\s*([0-9]+(?:\.[0-9]+){1,3})", re.I)
_PV_SP_RE = re.compile(r"SP:\s*([0-9]+(?:\.[0-9]+)?)", re.I)
_PV_STK_RE = re.compile(r"Stack:\s*([0-9]+(?:\.[0-9]+)?)", re.I)

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


def _parse_version(raw: str) -> dict:
    """Split ProductVersion free-text into structured os_build/sp/stack fields.
    Empty dict if none of the well-known keys are present."""
    out: dict = {}
    for name, rx in (("os_build", _PV_OS_RE), ("sp", _PV_SP_RE),
                     ("stack", _PV_STK_RE)):
        m = rx.search(raw or "")
        if m:
            out[name] = m.group(1)
    return out


def _parse_av_pairs(target_info: bytes) -> dict:
    """MS-NLMP §2.2.2.1 AV_PAIR list -> {netbios_computer, ..., server_time_epoch}.
    Same shape as smb/telnet/pop3 so cross-service consumers key off the same names."""
    out: dict = {}
    i, n = 0, len(target_info)
    while i + 4 <= n:
        av_id, av_len = struct.unpack_from("<HH", target_info, i)
        i += 4
        if av_id == 0x0000:
            break
        if i + av_len > n:
            break
        v = target_info[i:i + av_len]
        if av_id in _NTLM_AV:
            out[_NTLM_AV[av_id]] = v.decode("utf-16-le", "replace")
        elif av_id == 0x0007 and av_len == 8:
            # MsvAvTimestamp: FILETIME (100ns intervals since 1601-01-01 UTC).
            filetime = struct.unpack("<Q", v)[0]
            out["server_time_epoch"] = (filetime // 10_000_000) - 11_644_473_600
        i += av_len
    return out


def _parse_ntlm_challenge(sec_buffer: bytes) -> dict | None:
    """Extract the info-disclosure fields from an NTLMSSP CHALLENGE_MESSAGE.
    Same primitive smb.parse_ntlm_challenge_info uses (bare Type-2, no SPNEGO
    wrapper - WinRM's HTTP-transport carries raw NTLMSSP in Authorization/WWW-
    Authenticate). Returns None on any parse failure so the caller stays silent."""
    from ..ad import ntlm
    base = ntlm.parse_type2(sec_buffer)
    if not base:
        return None
    out: dict = _parse_av_pairs(base.get("target_info") or b"")
    out["ntlm_flags"] = base["flags"]
    # OS version at bytes 48..56 of the NTLMSSP header, iff NEGOTIATE_VERSION
    # (0x02000000) is set. Locate NTLMSSP signature to skip any SPNEGO wrapper.
    idx = sec_buffer.find(b"NTLMSSP\x00")
    if idx >= 0 and idx + 56 <= len(sec_buffer) and (base["flags"] & 0x02000000):
        ver = sec_buffer[idx + 48:idx + 56]
        major, minor = ver[0], ver[1]
        build = struct.unpack("<H", ver[2:4])[0]
        if major or minor or build:
            out["os_version"] = f"{major}.{minor}.{build}"
    return out


def _ntlm_challenge(ip: str, port: int, tls: bool, timeout: float) -> dict | None:
    """One extra POST /wsman round-trip carrying a bare NTLMSSP NEGOTIATE
    (Type-1) in Authorization: Negotiate. WinRM (via HTTP.sys/IIS) answers 401
    with WWW-Authenticate: Negotiate <base64 Type-2> - the CHALLENGE_MESSAGE
    whose AV_PAIRs disclose NetBIOS/DNS names, AD domain, forest, server clock,
    and OS build (MS-NLMP §2.2.1.2 / §2.2.2.1). All read-only, no creds."""
    from ..ad import ntlm
    conn = None
    try:
        if tls:
            ctx = ssl._create_unverified_context()      # noqa: S323 - self-signed is the norm
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        t1 = base64.b64encode(ntlm.type1()).decode("ascii")
        conn.request("POST", "/wsman", body=_IDENTIFY,
                     headers={"Content-Type": "application/soap+xml;charset=UTF-8",
                              "Authorization": f"Negotiate {t1}",
                              "User-Agent": "recce-winrm/1.0"})
        r = conn.getresponse()
        r.read(4096)                                    # drain to free the conn
    except (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
    if r.status not in (401, 200):
        return None
    for k, v in r.getheaders():
        if k.lower() != "www-authenticate":
            continue
        # "Negotiate <base64>" or bare "Negotiate" (no challenge - Kerberos-only path)
        parts = v.strip().split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "negotiate":
            continue
        try:
            raw = base64.b64decode(parts[1].strip(), validate=False)
        except (ValueError, TypeError):
            continue
        info = _parse_ntlm_challenge(raw)
        if info:
            return info
    return None


def probe(ip: str, port: int = _HTTP_PORT, timeout: float = _TIMEOUT) -> dict:
    """Probe whatever port we were handed; auto-select TLS for 5986/443."""
    tls = port in (_HTTPS_PORT, 443)
    out: dict = {"reachable": False, "port": port, "tls": tls}
    r = _identify(ip, port, tls, timeout)
    if r is None:
        return out
    out.update(r)
    out["reachable"] = True
    # Structured version derived from ProductVersion (os_build/sp/stack) - kept as
    # a nested field so the raw "OS: X.Y.Z ..." string in out["version"] is
    # unchanged for existing consumers.
    if out.get("version"):
        pv = _parse_version(out["version"])
        if pv:
            out["version_parsed"] = pv
    # One extra credfree round-trip iff the server advertised Negotiate - MS-NLMP
    # Type-2 CHALLENGE_MESSAGE carries NetBIOS/DNS/AD-domain/OS-build for free.
    if "Negotiate" in (out.get("auth") or []):
        info = _ntlm_challenge(ip, port, tls, timeout)
        if info:
            out["ntlm_info"] = info
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

            # NTLM Type-2 CHALLENGE_MESSAGE info disclosure (MS-NLMP §2.2.1.2).
            # One extra POST unlocks NetBIOS/DNS names, AD domain/forest, server
            # clock, and OS build - the cheapest AD intel on the external surface.
            info = pr.get("ntlm_info") or {}
            if info:
                bits = []
                for k, label in (("netbios_computer", "NetBIOS name"),
                                 ("netbios_domain", "NetBIOS domain"),
                                 ("dns_computer", "DNS FQDN"),
                                 ("dns_domain", "AD DNS domain"),
                                 ("dns_tree", "AD forest"),
                                 ("os_version", "OS build")):
                    v = info.get(k)
                    if v:
                        bits.append(f"{label}={v}")
                if info.get("server_time_epoch"):
                    import datetime as _dt
                    bits.append("server clock=" + _dt.datetime.fromtimestamp(
                        info["server_time_epoch"], _dt.timezone.utc).isoformat())
                if bits:
                    out.append(_finding(
                        "low",
                        "WinRM pre-auth NTLM CHALLENGE leaks host/domain intel",
                        tgt,
                        "POST /wsman with Authorization: Negotiate <NTLMSSP "
                        "NEGOTIATE> returned a CHALLENGE_MESSAGE carrying: "
                        + "; ".join(bits) + ". Pre-auth, no credentials "
                        "required. Feeds NetBIOS/DNS names, AD domain and "
                        "forest, server clock (Kerberos skew) and exact OS "
                        "build for CVE mapping into the engagement store.",
                        "curl",
                        f"curl -kv -X POST http{'s' if tls else ''}://{h.ip}:"
                        f"{p.portid}/wsman -H 'Authorization: Negotiate "
                        "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAA='",
                        "Default Windows behavior; the only mitigation is "
                        "disabling NTLM entirely (Kerberos-only WinRM) or "
                        "restricting the listener to trusted management "
                        "networks so unauthenticated attackers cannot reach it.",
                        ["CWE-200"], kind="winrm_ntlm_info"))

            # Relay-target emission. A WinRM listener advertising Negotiate
            # (NTLM fallback) over plain HTTP is the canonical impacket
            # ntlmrelayx -t http://host:5985/wsman victim - no EPA is possible
            # without TLS, so a coerced NTLM authentication relays to a shell.
            if "Negotiate" in auth and not tls:
                out.append(_finding(
                    "high",
                    "WinRM speaks Negotiate/NTLM over plain HTTP — NTLM relay target",
                    tgt,
                    f"5985/tcp advertises Negotiate ({', '.join(auth)}) without "
                    "TLS, so Channel Binding (EPA, MS-WSMV §3.1.4.1.30) is not "
                    "applicable and any coerced NTLM authentication (PetitPotam, "
                    "printerbug, WebDAV) can be relayed straight to this host "
                    "for command execution as the coerced principal.",
                    "impacket ntlmrelayx",
                    f"ntlmrelayx.py -t http://{h.ip}:{p.portid}/wsman -smb2support "
                    "  # coerce, then win",
                    "Require HTTPS-only WinRM listener on 5986; enable Extended "
                    "Protection for Authentication (Service\\CbtHardeningLevel="
                    "Strict) so the NTLM MIC is bound to the TLS channel; "
                    "restrict WinRM to management networks.",
                    ["CWE-294", "CWE-522"], kind="winrm_relay_target"))

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
    by_ip = {h.ip: h for h in hosts}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["auth"] = pr.get("auth") or []
                t["vendor"] = pr.get("vendor", "")
                info = pr.get("ntlm_info") or {}
                if info:
                    t["ntlm_info"] = info
                    # Fold into the cross-service host.ntlm store (see
                    # core/known_hostnames.py, core/known_domains.py) so ldap /
                    # smb / kerberos / mssql readers pick up the AV_PAIR intel
                    # WinRM leaked. Only fill blanks - never clobber a value
                    # another module (SMB / LDAP) already established.
                    host = by_ip.get(t["ip"])
                    if host is not None:
                        merged = dict(host.ntlm or {})
                        for k in ("netbios_computer", "netbios_domain",
                                  "dns_computer", "dns_domain", "dns_tree",
                                  "os_version"):
                            v = info.get(k)
                            if v and not merged.get(k):
                                merged[k] = v
                        if info.get("dns_computer") and not merged.get("fqdn"):
                            merged["fqdn"] = info["dns_computer"]
                        host.ntlm = merged
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
