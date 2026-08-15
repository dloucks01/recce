"""Deep DNS enumeration (stdlib sockets, read-only).

Tests the classic DNS server exposure: an unauthenticated ZONE TRANSFER (AXFR) that
hands an attacker the full internal DNS zone (every host/service name + IP - an instant
network map). The zone names to try are derived from the engagement's own discovered
hostnames (no guessing / brute force). Also reads version.bind as a fingerprint.

Findings fold into the severity totals / Vulnerabilities sheet (source="dns").
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port

_PORTS = (53,)
_DEFAULT_PORT = 53
_TIMEOUT = 5.0
_QTYPE_AXFR = 252
_QTYPE_TXT = 16
_CLASS_IN = 1
_CLASS_CH = 3


def is_dns(port: Port) -> bool:
    if not port.is_open:
        return False
    svc = (port.service or "").lower()
    return port.portid in _PORTS or svc in ("domain", "dns")


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        lb = label.encode("idna") if label else b""
        out += bytes([len(lb)]) + lb
    return out + b"\x00"


def _query(name: str, qtype: int, qclass: int = _CLASS_IN, rd: bool = False) -> bytes:
    flags = 0x0100 if rd else 0x0000
    header = struct.pack("!HHHHHH", 0x1337, flags, 1, 0, 0, 0)
    q = _encode_name(name) + struct.pack("!HH", qtype, qclass)
    return header + q


def _tcp_dns(ip: str, port: int, msg: bytes, timeout: float) -> bytes | None:
    """Send one DNS message over TCP, return the FIRST response message body (or None)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(struct.pack("!H", len(msg)) + msg)
            hdr = _recvn(s, 2)
            if len(hdr) < 2:
                return None
            n = struct.unpack("!H", hdr)[0]
            return _recvn(s, n)
    except OSError:
        return None


def _recvn(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def axfr(ip: str, port: int, zone: str, timeout: float = _TIMEOUT) -> dict:
    """Attempt a zone transfer. Returns {ok, records, rcode}. ok=True means the server
    answered AXFR with records (NOERROR + answers) - the zone leaked."""
    resp = _tcp_dns(ip, port, _query(zone, _QTYPE_AXFR), timeout)
    if not resp or len(resp) < 12:
        return {"ok": False, "records": 0, "rcode": None}
    _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    rcode = flags & 0x000F
    return {"ok": rcode == 0 and an > 0, "records": an, "rcode": rcode}


def version_bind(ip: str, port: int, timeout: float = _TIMEOUT) -> str:
    resp = _tcp_dns(ip, port, _query("version.bind", _QTYPE_TXT, _CLASS_CH), timeout)
    if not resp or len(resp) < 12:
        return ""
    _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    if (flags & 0x000F) != 0 or an < 1:
        return ""
    # crude: the TXT rdata is a length-prefixed string near the end of the message
    tail = resp[-64:]
    for i in range(len(tail) - 1):
        ln = tail[i]
        if 1 <= ln <= len(tail) - i - 1:
            cand = tail[i + 1:i + 1 + ln]
            if cand and all(32 <= b < 127 for b in cand) and b"." in cand:
                return cand.decode("latin-1")
    return ""


def _zones_from_hosts(hosts: list[Host]) -> list[str]:
    """Candidate zones = the domain parts of the engagement's own discovered hostnames
    (dc01.contoso.local -> contoso.local). No brute forcing - only names we already saw."""
    zones: set = set()
    for h in hosts:
        for hn in (h.hostnames or []):
            parts = hn.strip(".").split(".")
            if len(parts) >= 2:
                zones.add(".".join(parts[1:]).lower())
    return sorted(zones)


def dns_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_dns(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "dig", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_dns(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            for z in pr.get("axfr_zones", []):
                out.append(_finding(
                    "high", f"DNS zone transfer allowed ({z})", tgt,
                    f"AXFR of '{z}' succeeded from an unauthenticated client "
                    f"({pr.get('records', {}).get(z, '?')} records) - the full internal "
                    "zone (every host/service name + IP) is exposed as an instant map.",
                    f"dig AXFR {z} @{h.ip}",
                    "Restrict zone transfers to authorized secondaries "
                    "(allow-transfer / xfer-out ACLs); disable AXFR to the world.",
                    ["CWE-200", "CWE-284"], kind="dns_axfr"))
            if pr.get("version") and "bind" in (pr.get("version") or "").lower():
                out.append(_finding(
                    "low", "DNS server version disclosed (version.bind)", tgt,
                    f"version.bind returned '{pr['version']}' - a precise server version "
                    "aids targeting.",
                    f"dig CH TXT version.bind @{h.ip}",
                    "Hide the version (options { version \"\"; }).",
                    ["CWE-200"], kind="dns_version"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [{"step": "Attempt zone transfer for each known domain",
             "cmd": f"dig AXFR <domain> @{ip}"},
            {"step": "Server version fingerprint",
             "cmd": f"dig CH TXT version.bind @{ip}"}]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "dns", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = dns_targets(hosts)
    zones = _zones_from_hosts(hosts)
    probes: dict = {}
    state: dict = {}

    def _probe(t):
        ver = version_bind(t["ip"], t["port"])
        axfr_zones, rec = [], {}
        for z in zones:
            r = axfr(t["ip"], t["port"], z)
            if r["ok"]:
                axfr_zones.append(z)
                rec[z] = r["records"]
        return {"reachable": True, "version": ver, "axfr_zones": axfr_zones, "records": rec}

    if active:
        for t, pr in svcprobe.iter_probe(targets, _probe, budget=budget,
                                         progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["axfr"] = bool(pr.get("axfr_zones"))
                t["version"] = pr.get("version", "") or t.get("version", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs), "zones": len(zones),
                      "stopped": state.get("stopped")}}
