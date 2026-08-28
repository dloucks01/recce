"""VNC (5900-5906/tcp) protocol fingerprint + auth-type probe.

VNC opens with a text version handshake ('RFB 003.008\\n') and then the
server sends a list of supported security types. Type 1 = None (no auth),
type 2 = VNC Authentication (weak DES-based, easily brute-forced), type
16 = Tight, type 18/19 = TLS variants.

Findings:
  * vnc_no_auth (CRITICAL) — server offers security type 1 (None).
    Anyone with TCP reach gets an interactive desktop session.
  * vnc_weak_auth (MEDIUM) — server offers only DES-based VNC auth
    (type 2). Historically 8-char DES challenge is offline-crackable
    from a captured handshake.
  * vnc_fingerprint (info) — always emitted with server version + accepted
    security types.

Airgap-safe: stdlib socket only. One TCP roundtrip, 4s timeout.
"""
from __future__ import annotations

import re
import socket

from ..core.models import Host, Port


_DEFAULT_PORT = 5900
_TIMEOUT = 4.0
_VERSION_RE = re.compile(rb"RFB (\d{3})\.(\d{3})")

_SECURITY_TYPES = {
    0: "Invalid",
    1: "None",
    2: "VNC Authentication (DES challenge)",
    5: "RA2",
    6: "RA2ne",
    16: "Tight",
    17: "Ultra",
    18: "TLS",
    19: "VeNCrypt",
    20: "GTK-VNC SASL",
    21: "MD5-Hash",
    22: "ColinDeanVeNCrypt",
    30: "Apple ARD",
}


def is_vnc(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (5900 <= port.portid <= 5906
            or "vnc" in svc or "vnc" in prod or "rfb" in svc)


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Return {reachable, version, security_types:[names]}."""
    out = {"reachable": False, "version": "", "security_types": [],
           "no_auth": False, "des_only": False}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # First 12 bytes = server version banner ("RFB 003.008\n").
            hdr = s.recv(12)
            if len(hdr) < 12:
                return out
            m = _VERSION_RE.match(hdr)
            if not m:
                return out
            major, minor = int(m.group(1)), int(m.group(2))
            out["reachable"] = True
            out["version"] = f"{major}.{minor}"
            # Reply with same-or-lower version we can speak (3.8 covers all).
            our_version = b"RFB 003.008\n"
            s.sendall(our_version)
            # Server responds with security-type list. RFB 3.7+ format:
            #   number_of_security_types (1 byte)
            #   security_type[N] (1 byte each)
            # RFB 3.3 format:
            #   security_type (4 bytes big-endian) — a single type
            if (major, minor) >= (3, 7):
                n_bytes = s.recv(1)
                if not n_bytes:
                    return out
                n = n_bytes[0]
                if n == 0:
                    # Server rejected — usually followed by a reason string.
                    return out
                types_bytes = s.recv(min(n, 32))
                types = list(types_bytes[:n])
            else:
                import struct
                buf = s.recv(4)
                if len(buf) < 4:
                    return out
                types = [struct.unpack(">I", buf)[0] & 0xff]
            out["security_types"] = [_SECURITY_TYPES.get(t, f"unknown({t})")
                                     for t in types if t != 0]
            out["no_auth"] = 1 in types
            # DES-only: type 2 is the ONLY thing offered
            out["des_only"] = types == [2] or (len(types) == 1 and types[0] == 2)
            return out
    except OSError:
        return out


def vnc_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_vnc(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "vncviewer", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_vnc(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            if pr.get("no_auth"):
                out.append(_finding(
                    "critical",
                    "VNC accepts security type 1 (no authentication)", tgt,
                    f"Server version RFB {pr.get('version','?')} offers 'None' as an "
                    f"accepted security type. Anyone who reaches this port opens an "
                    f"interactive desktop session — full KVM control over the console "
                    f"session (mouse, keyboard, screen).",
                    f"vncviewer {h.ip}::{p.portid}",
                    "Configure VNC with a password (VNC Auth type 2) or move to a "
                    "TLS/VeNCrypt-wrapping variant. Bind to loopback and tunnel over "
                    "SSH for remote access; never expose 590x to a network shared "
                    "with untrusted clients.",
                    ["CWE-306", "CWE-287"], kind="vnc_no_auth"))
            elif pr.get("des_only"):
                out.append(_finding(
                    "medium",
                    "VNC offers only DES-based VNC Authentication (weak)", tgt,
                    "Server only offers security type 2 (VNC Authentication) — an "
                    "8-byte DES challenge/response. A captured handshake is offline "
                    "crackable (hashcat -m 11600); the password itself is truncated "
                    "to 8 chars in the auth flow. On a shared network segment this "
                    "is a compromised session.",
                    f"vncviewer {h.ip}::{p.portid}",
                    "Move to a TLS/VeNCrypt-wrapping VNC variant (TigerVNC + VeNCrypt "
                    "+ x509plain). Tunnel over SSH as an alternative.",
                    ["CWE-326", "CWE-916"], kind="vnc_des_only"))
            out.append(_finding(
                "info", "VNC endpoint fingerprint", tgt,
                f"RFB {pr.get('version','?')} · security types: "
                f"{', '.join(pr.get('security_types') or [])}",
                f"vncviewer {h.ip}::{p.portid}",
                "Restrict VNC access; log connection attempts.",
                [], kind="vnc_fingerprint"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Fingerprint version + auth",
         "cmd": f"nmap -p {port} --script vnc-info {ip}"},
        {"step": "Attempt no-auth connect",
         "cmd": f"vncviewer {ip}::{port}"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "vnc", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = vnc_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["no_auth"] = pr.get("no_auth", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
