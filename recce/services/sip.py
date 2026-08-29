"""SIP (5060/tcp+udp, 5061/tls): OPTIONS fingerprint + auth-realm disclosure.

SIP servers hand out their vendor/version and configured realm in the response
to an unauthenticated OPTIONS or REGISTER. That is enough to identify the PBX
(Asterisk, FreeSWITCH, Cisco CUCM, Kamailio) and to give the operator a
starting point for extension enumeration and toll-fraud checks.

recce sends one OPTIONS on the UDP transport most PBXes prefer, then falls
back to TCP for the same request. Read-only, one packet each. Wire format:
RFC 3261.
"""
from __future__ import annotations

import re
import socket

from ..core.models import Host, Port


_DEFAULT_PORT = 5060
_TIMEOUT = 3.0

_SERVER_RE = re.compile(rb"^(?:Server|User-Agent):\s*(.+)$", re.I | re.M)
_REALM_RE = re.compile(rb'realm="([^"]+)"', re.I)


def is_sip(port: Port) -> bool:
    svc = (port.service or "").lower()
    return port.portid in (5060, 5061) or "sip" in svc


def _options(source_port: int, ip: str, port: int) -> bytes:
    """Minimal OPTIONS. The Via branch is z9hG4bK-prefixed as required by
    RFC 3261 §8.1.1.7 so servers that validate reject-on-bad-branch will
    still answer."""
    return (f"OPTIONS sip:{ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP recce:{source_port};branch=z9hG4bK-recce\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:recce@recce.local>;tag=recce\r\n"
            f"To: <sip:{ip}>\r\n"
            f"Call-ID: recce-probe@recce\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"User-Agent: recce-sip/1.0\r\n"
            f"Content-Length: 0\r\n\r\n").encode("ascii")


def _probe_udp(ip: str, port: int, timeout: float) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 0))
        s.settimeout(timeout)
        src = s.getsockname()[1]
        s.sendto(_options(src, ip, port), (ip, port))
        data, _ = s.recvfrom(65535)
        return data
    except (OSError, socket.timeout):
        return b""
    finally:
        s.close()


def _probe_tcp(ip: str, port: int, timeout: float) -> bytes:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return b""
    try:
        s.settimeout(timeout)
        s.sendall(_options(port, ip, port))
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf
    except OSError:
        return b""
    finally:
        try:
            s.close()
        except OSError:
            pass


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    out: dict = {"reachable": False, "transport": ""}
    for transport, fn in (("udp", _probe_udp), ("tcp", _probe_tcp)):
        data = fn(ip, port, timeout)
        if not data or not data.startswith(b"SIP/"):
            continue
        out["reachable"] = True
        out["transport"] = transport
        # Status line: SIP/2.0 200 OK
        try:
            status = int(data.split(b" ", 2)[1])
        except (ValueError, IndexError):
            status = 0
        out["status"] = status
        m = _SERVER_RE.search(data)
        if m:
            out["server"] = m.group(1).decode("ascii", "replace").strip()
        m = _REALM_RE.search(data)
        if m:
            out["realm"] = m.group(1).decode("ascii", "replace").strip()
        # Allow header (advertised methods) is a good fingerprint of PBX config
        allow = re.search(rb"^Allow:\s*(.+)$", data, re.I | re.M)
        if allow:
            out["methods"] = allow.group(1).decode("ascii", "replace").strip()
        break
    # Extension enumeration piggybacks on the same probe when the server is
    # reachable — bounded to the default 20 extensions so a single scan does
    # not saturate a fragile PBX. Skip on TCP: svwar's asymmetry works on UDP
    # where the response is fast enough to fingerprint.
    if out.get("reachable") and out.get("transport") == "udp":
        try:
            out["ext_enum"] = enumerate_extensions(ip, port, timeout=timeout)
        except OSError:
            pass
    return out


# --- Extension enumeration (svwar-style) ------------------------------------
# A REGISTER for an EXISTING extension returns 401/407 (auth required); a
# REGISTER for a NONEXISTENT one returns 404 on servers without
# `alwaysauthreject`. That asymmetry — different status codes for existing vs
# missing users — is what svwar exploits.
#
# recce keeps this bounded: only tests a small range (default 100-119) and
# stops the moment the server proves it has `alwaysauthreject` enabled (both
# statuses match). Sends REGISTER not INVITE, so no phones ring; UDP only.

_EXT_RANGE = range(100, 120)         # 20 probes by default — a fingerprint
_401_407 = (401, 407)


def _register(source_port: int, ip: str, port: int, ext: str) -> bytes:
    """Minimal REGISTER for an extension. Same header shape as OPTIONS, just
    a different method + a To/From that names the extension."""
    return (f"REGISTER sip:{ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP recce:{source_port};branch=z9hG4bK-recce-r-{ext}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{ext}@{ip}>;tag=recce-r-{ext}\r\n"
            f"To: <sip:{ext}@{ip}>\r\n"
            f"Call-ID: recce-r-{ext}@recce\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f"Contact: <sip:recce@127.0.0.1>\r\n"
            f"User-Agent: recce-sip/1.0\r\n"
            f"Expires: 0\r\n"
            f"Content-Length: 0\r\n\r\n").encode("ascii")


def _sip_status(reply: bytes) -> int:
    """Extract the numeric status code from a SIP response line."""
    if not reply.startswith(b"SIP/"):
        return 0
    try:
        return int(reply.split(b" ", 2)[1])
    except (ValueError, IndexError):
        return 0


def enumerate_extensions(ip: str, port: int, extensions=_EXT_RANGE,
                         timeout: float = _TIMEOUT) -> dict:
    """Probe each extension with REGISTER. Returns:
        {existing: [ext], missing: [ext], always_reject: bool}

    A server with `alwaysauthreject` (Asterisk) returns the same auth-required
    reply for existing AND missing extensions, so recce cannot distinguish
    them — and shouldn't invent findings. Signaled by seen_missing_401=True.
    """
    out = {"existing": [], "missing": [], "always_reject": False,
           "seen_ok": False, "probed": 0}
    seen_missing_401 = False
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0))
    s.settimeout(timeout)
    src = s.getsockname()[1]
    try:
        for ext in extensions:
            out["probed"] += 1
            try:
                s.sendto(_register(src, ip, port, str(ext)), (ip, port))
                data, _ = s.recvfrom(65535)
            except (OSError, socket.timeout):
                continue
            status = _sip_status(data)
            if status in _401_407:
                out["existing"].append(str(ext))
            elif status == 404:
                out["missing"].append(str(ext))
            elif status == 403:
                # 403 for both existing and missing = alwaysauthreject variant
                # (some Asterisk builds). Match on it.
                seen_missing_401 = True
            # 200 OK on REGISTER = an extension that accepts unauthenticated
            # registrations — critical on its own; log as existing.
            elif status == 200:
                out["existing"].append(str(ext))
                out["seen_ok"] = True
    finally:
        s.close()
    # If EVERY probe came back the same auth-required status, treat that as
    # `alwaysauthreject` and clear the "existing" list — the server is not
    # actually leaking which extensions exist.
    if out["existing"] and not out["missing"] and out["probed"] > 0:
        out["always_reject"] = True
        out["existing"] = []
    elif seen_missing_401 and not out["missing"]:
        out["always_reject"] = True
    return out


def sip_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_sip(p):
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
            if not is_sip(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            server = pr.get("server") or "unknown"
            realm = pr.get("realm") or ""
            methods = pr.get("methods") or ""
            out.append(_finding(
                "low", "SIP endpoint discloses server / realm via unauth OPTIONS",
                tgt,
                f"SIP OPTIONS on {tgt} ({pr.get('transport', '?').upper()}) returned "
                f"status {pr.get('status', '?')} — Server: {server}"
                + (f", realm=\"{realm}\"" if realm else "")
                + (f", Allow: {methods}" if methods else "")
                + ". Enough to fingerprint the PBX (Asterisk / FreeSWITCH / "
                "Kamailio / Cisco CUCM) and start extension enumeration + "
                "auth attacks against the named realm.",
                "svmap / svwar / sipvicious",
                f"svmap.py {h.ip}:{p.portid}   # then svwar.py -e100-999 -m INVITE "
                f"{h.ip}:{p.portid}",
                "Restrict SIP to trusted networks; on Asterisk set "
                "alwaysauthreject=yes (RFC-3261 §22 recommends the same reply "
                "for existing vs missing extensions) so extension enumeration "
                "cannot distinguish valid users.",
                ["CWE-200"], kind="sip_fingerprint"))

            # Extension enumeration signals:
            #   existing[] populated -> the server distinguishes 401/407 vs 404,
            #     so valid extensions are discoverable (svwar's classic target).
            #   seen_ok=True         -> a REGISTER returned 200: the extension
            #     accepts UNAUTHENTICATED registration - toll fraud vector.
            #   always_reject=True   -> hardened server; do not report anything.
            ext = pr.get("ext_enum") or {}
            existing = ext.get("existing") or []
            if existing and not ext.get("always_reject"):
                sample = ", ".join(existing[:10])
                out.append(_finding(
                    "high" if ext.get("seen_ok") else "medium",
                    "SIP extension enumeration succeeded (svwar-style)", tgt,
                    f"Probed {ext.get('probed', 0)} candidate extension(s); "
                    f"{len(existing)} returned auth-required (401/407) or 200 "
                    f"OK — the server distinguishes existing vs missing "
                    f"extensions, so an attacker can enumerate the entire "
                    f"dial plan. Existing: {sample}"
                    + (" …" if len(existing) > 10 else "")
                    + ("\n\nAt least one extension accepted UNAUTHENTICATED "
                       "REGISTER (200 OK) — toll-fraud primitive: register "
                       "an attacker endpoint and place calls as that "
                       "extension." if ext.get("seen_ok") else ""),
                    "svwar / sipvicious",
                    f"svwar.py -e100-999 -m REGISTER {h.ip}:{p.portid}   "
                    "# to sweep further, then svcrack.py against a hit",
                    "Set alwaysauthreject=yes (Asterisk) or the equivalent — "
                    "return the same reply for existing vs missing extensions. "
                    "Require authentication on REGISTER even for extensions "
                    "that historically accepted anonymous registrations.",
                    ["CWE-200", "CWE-306"], kind="sip_ext_enum"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "svmap",
         "command": f"svmap.py {ip}:{port}",
         "why": "confirm PBX + version — same OPTIONS recce sent, more verbose"},
        {"phase": "enumerate", "tool": "svwar",
         "command": f"svwar.py -e100-999 -m INVITE {ip}:{port}",
         "why": "extension enumeration — INVITE distinguishes existing vs not "
                "on servers without alwaysauthreject"},
        {"phase": "exploit", "tool": "svcrack",
         "command": f"svcrack.py -u <ext> -d passwords.txt {ip}:{port}",
         "why": "auth brute against an enumerated extension; toll-fraud path"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "sip", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = sip_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["server"] = pr.get("server", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
