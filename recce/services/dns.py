"""Deep DNS enumeration (stdlib sockets, read-only).

Tests the classic DNS server exposure: an unauthenticated ZONE TRANSFER (AXFR) that
hands an attacker the full internal DNS zone (every host/service name + IP - an instant
network map). The zone names to try are derived from the engagement's own discovered
hostnames (no guessing / brute force). Also reads version.bind as a fingerprint.

Findings fold into the severity totals / Vulnerabilities sheet (source="dns").
"""
from __future__ import annotations

import re
import socket
import struct

from ..core.models import Host, Port

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


# Common DKIM selectors — different providers pick different names. Not
# exhaustive; just enough to catch the most common deployments (Google Workspace,
# Office 365, Mailchimp, SendGrid, generic).
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "mail",
                   "k1", "k2", "s1", "s2", "dkim"]


def _txt_records(ip: str, port: int, name: str, timeout: float = _TIMEOUT) -> list[str]:
    """TXT lookup that returns the concatenated string content of each answer
    RR. Best-effort: parses only well-formed responses, returns [] otherwise."""
    resp = _tcp_dns(ip, port, _query(name, _QTYPE_TXT, rd=True), timeout)
    if not resp or len(resp) < 12:
        return []
    _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    if (flags & 0x000F) != 0 or an < 1:
        return []
    # Skip question section — recompute cursor after it.
    i = 12
    for _q in range(qd):
        # Skip compressed/uncompressed name until zero-length label.
        while i < len(resp):
            ln = resp[i]
            if ln == 0:
                i += 1; break
            if ln >= 0xC0:                # pointer, 2 bytes total
                i += 2; break
            i += ln + 1
        i += 4                            # QTYPE + QCLASS
    # Walk answers, extracting TXT rdata.
    txts: list[str] = []
    for _a in range(an):
        # Skip name (may be a compressed pointer).
        if i >= len(resp): break
        if resp[i] >= 0xC0:
            i += 2
        else:
            while i < len(resp) and resp[i] != 0:
                i += resp[i] + 1
            i += 1
        if i + 10 > len(resp): break
        rtype = struct.unpack("!H", resp[i:i + 2])[0]
        rdlen = struct.unpack("!H", resp[i + 8:i + 10])[0]
        i += 10
        rdata = resp[i:i + rdlen]
        i += rdlen
        if rtype == _QTYPE_TXT:
            # TXT rdata = length-prefixed strings concatenated.
            j = 0
            parts = []
            while j < len(rdata):
                ln = rdata[j]; j += 1
                parts.append(rdata[j:j + ln].decode("utf-8", "replace"))
                j += ln
            txts.append("".join(parts))
    return txts


def email_security_records(ip: str, port: int, zone: str,
                           timeout: float = _TIMEOUT) -> dict:
    """Look up SPF, DMARC, and common DKIM selectors for `zone`. Returns
    {spf, dmarc, dkim: {selector: record}} — string values empty when the
    record is missing. Every record is a plain string; caller decides
    whether it's weak/absent."""
    out = {"spf": "", "dmarc": "", "dkim": {}}
    for t in _txt_records(ip, port, zone, timeout):
        if t.lower().startswith("v=spf1"):
            out["spf"] = t[:400]
            break
    for t in _txt_records(ip, port, f"_dmarc.{zone}", timeout):
        if t.lower().startswith("v=dmarc1"):
            out["dmarc"] = t[:400]
            break
    for sel in _DKIM_SELECTORS:
        for t in _txt_records(ip, port, f"{sel}._domainkey.{zone}", timeout):
            if "v=dkim1" in t.lower() or "k=rsa" in t.lower() or "p=" in t.lower():
                out["dkim"][sel] = t[:400]
                break
    return out


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
            # Email-security posture per zone: SPF/DMARC absence or weakness
            # lets any external sender spoof mail from these domains.
            for z, es in (pr.get("email_sec") or {}).items():
                # Missing SPF entirely — any host can spoof mail as this domain.
                if not es.get("spf"):
                    out.append(_finding(
                        "medium", f"SPF record missing for {z}", tgt,
                        f"No SPF (v=spf1) TXT record for '{z}'. Receiving MTAs have no "
                        f"way to tell whether a sender IP is authorized to send mail as "
                        f"this domain — anyone can spoof From:.",
                        f"dig TXT {z} @{h.ip}",
                        "Publish SPF: 'v=spf1 <sources> -all' (or ~all for soft-fail).",
                        ["CWE-290", "CWE-346"], kind="dns_missing_spf"))
                elif re.search(r"[+?]all\b", es["spf"], re.I):
                    # Weak SPF — +all = pass everything; ?all = neutral.
                    out.append(_finding(
                        "low", f"Weak SPF policy for {z} ({es['spf'][:60]}...)", tgt,
                        f"SPF exists but its terminator is +all/?all — anyone still "
                        f"passes. Effectively equivalent to no SPF for spoofing purposes.",
                        f"dig TXT {z} @{h.ip}",
                        "Change the SPF terminator to -all (fail) or ~all (softfail).",
                        ["CWE-290"], kind="dns_weak_spf"))
                if not es.get("dmarc"):
                    out.append(_finding(
                        "medium", f"DMARC record missing for {z}", tgt,
                        f"No DMARC (v=DMARC1) TXT record at '_dmarc.{z}'. Without a "
                        f"DMARC policy, spoofed mail is not reported and is not blocked "
                        f"even if SPF/DKIM fail.",
                        f"dig TXT _dmarc.{z} @{h.ip}",
                        "Publish DMARC starting with 'v=DMARC1; p=none; rua=mailto:...' "
                        "for monitoring, then move to p=quarantine and p=reject.",
                        ["CWE-290", "CWE-346"], kind="dns_missing_dmarc"))
                elif "p=none" in es["dmarc"].lower():
                    out.append(_finding(
                        "low", f"DMARC in monitor-only mode for {z} (p=none)", tgt,
                        f"DMARC policy is p=none — receivers report spoofed mail but "
                        f"still deliver it. Effective for reporting, not enforcement.",
                        f"dig TXT _dmarc.{z} @{h.ip}",
                        "Advance policy to p=quarantine (bulk-folder) then p=reject.",
                        ["CWE-290"], kind="dns_dmarc_monitor"))
                # DKIM: presence is informational — its absence isn't a bug
                # per se (DMARC allows either SPF or DKIM to pass), so no
                # finding emitted, but the selectors are surfaced for the report.
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
        # Email-security posture per zone. Cheap: at most 12 TXT lookups per
        # zone (SPF + DMARC + 10 DKIM selectors). Zones with none of these
        # records skip cleanly with empty strings.
        email_sec = {}
        for z in zones:
            email_sec[z] = email_security_records(t["ip"], t["port"], z)
        return {"reachable": True, "version": ver, "axfr_zones": axfr_zones,
                "records": rec, "email_sec": email_sec}

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
