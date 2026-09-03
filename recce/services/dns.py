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
from typing import Any

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
    """Attempt a zone transfer. Returns {ok, records, rcode, data}.
    ok=True means the server answered AXFR with records (NOERROR + answers) - the
    zone leaked.

    `data` is a bucketed parse of the answer section from the FIRST AXFR message
    (see _bucket_rrs) — names, A/AAAA IPs, CNAME/NS/PTR targets, and MX/SRV
    tuples. AXFR can span multiple TCP messages (RFC 5936 §2.2); we only walk
    the first, so `data` is a best-effort SAMPLE, not a full-zone dump — but
    even a partial name/IP list is a strict superset of the old return value
    (which discarded the body entirely) and is what downstream scanners need
    for cross-service pivoting."""
    resp = _tcp_dns(ip, port, _query(zone, _QTYPE_AXFR), timeout)
    empty = {"names": [], "a": [], "aaaa": [], "cname": [],
             "ns": [], "ptr": [], "mx": [], "srv": []}
    if not resp or len(resp) < 12:
        return {"ok": False, "records": 0, "rcode": None, "data": empty}
    _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    rcode = flags & 0x000F
    data = empty
    if rcode == 0 and an > 0:
        i = _skip_question(resp, 12, qd)
        rrs, _ = _parse_rrs(resp, i, an)
        if rrs:
            data = _bucket_rrs(rrs)
    return {"ok": rcode == 0 and an > 0, "records": an, "rcode": rcode,
            "data": data}


_QTYPE_NSEC = 47
_QTYPE_ANY = 255
_MAX_NSEC_STEPS = 500       # bound: /24-sized zones fit, wildcards can't tarpit us
# Answer RR types we know how to parse out of AXFR / question responses.
# Kept minimal — the module only needs the types that carry hostnames or IPs.
_QTYPE_A = 1
_QTYPE_NS_ = 2
_QTYPE_CNAME = 5
_QTYPE_PTR = 12
_QTYPE_MX = 15
_QTYPE_AAAA = 28
_QTYPE_SRV = 33
# Canonical AD/Exchange/UC SRV anchors under a zone (RFC 2782). Kept short: these
# are the labels an authoritative AD/Exchange/SIP deployment MUST publish, so any
# hit is a high-signal service-discovery hint — the point is to feed cross-service
# scanners, not to fingerprint every possible protocol.
_WELL_KNOWN_SRV_LABELS = (
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_kpasswd._tcp",
    "_gc._tcp",
    "_autodiscover._tcp",
    "_sip._tcp",
    "_sip._udp",
    "_sipfederationtls._tcp",
)
# The subset whose presence together says "this zone is an AD-integrated domain".
_AD_ANCHOR_LABELS = ("_ldap._tcp", "_kerberos._tcp")


def _decode_name(msg: bytes, i: int) -> tuple[str, int]:
    """Decode a wire-format DNS name at offset i, following compression
    pointers. Returns (name, next_index_past_the_top_level_name).

    RFC 1035 §4.1.4: a name may be pure labels + a null terminator, a
    2-byte pointer, or labels + a pointer. `end` records the index AFTER
    the top-level name (past the pointer or the terminator) so the caller
    can keep parsing; pointer chains are followed for the name but the
    return index stays at the top-level end. Bounded to 30 hops to kill
    a malformed pointer loop cleanly."""
    labels: list[str] = []
    hops = 0
    end: int | None = None                          # top-level end, set once
    while i < len(msg) and hops < 30:
        lb = msg[i]
        if lb == 0:
            if end is None:
                end = i + 1
            return (".".join(labels) or "."), end
        if lb & 0xC0 == 0xC0:
            if i + 2 > len(msg):
                return ".".join(labels), (end if end is not None else i)
            ptr = ((lb & 0x3F) << 8) | msg[i + 1]
            if end is None:                         # top-level end is past ptr
                end = i + 2
            i = ptr
            hops += 1
            continue
        if i + 1 + lb > len(msg):
            return ".".join(labels), (end if end is not None else i)
        labels.append(msg[i + 1:i + 1 + lb].decode("ascii", "replace"))
        i += 1 + lb
    # Fell off the end without a terminator — return what we have and let
    # the caller decide whether to trust it.
    return ".".join(labels), (end if end is not None else i)


def _next_name(candidate: str) -> str:
    """Given an NSEC "next owner" name, produce the smallest name that
    would sort just AFTER it. Used to step the walk: query
    "candidate + \\x00" and the authoritative server hands us the NEXT
    NSEC record that covers the gap.

    Appends a null-label prefix (`\\x00.<candidate>`) - the DNS canonical
    ordering places a name with an extra label BEFORE any sibling, so a
    query for it lands in the "no such name" NSEC gap immediately after
    `candidate`."""
    candidate = candidate.strip(".")
    return "\x00." + candidate if candidate else "\x00"


def _skip_question(msg: bytes, i: int, qd: int) -> int:
    """Advance `i` past `qd` question entries. Each is name + QTYPE(2) + QCLASS(2).
    Compression-safe via _decode_name; bounded — never runs off the message end
    thanks to _decode_name's own end-guard."""
    for _ in range(qd):
        _, i = _decode_name(msg, i)
        i += 4
        if i > len(msg):
            return len(msg)
    return i


def _parse_rrs(msg: bytes, i: int, count: int) -> tuple[list[dict], int]:
    """Parse `count` resource records starting at offset `i`.

    Returns (rrs, next_index). Each rr is a plain dict:
        {"name": owner_name, "type": qtype_int, "value": <type-specific>}

    Malformed / short buffers stop the walk cleanly rather than raising —
    matches the module's read-only, best-effort posture. Only the RR types the
    module cares about (A/AAAA/CNAME/NS/PTR/MX/SRV/TXT) get a decoded `value`;
    other types get value=None but the walk still advances correctly using
    RDLENGTH so following RRs are readable.
    """
    rrs: list[dict] = []
    for _ in range(count):
        if i >= len(msg):
            break
        owner, i = _decode_name(msg, i)
        if i + 10 > len(msg):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[i:i + 10])
        i += 10
        rdata_end = i + rdlen
        if rdata_end > len(msg):
            break
        value: Any = None
        if rtype == _QTYPE_A and rdlen == 4:
            value = ".".join(str(b) for b in msg[i:i + 4])
        elif rtype == _QTYPE_AAAA and rdlen == 16:
            try:
                value = socket.inet_ntop(socket.AF_INET6, msg[i:i + 16])
            except (OSError, ValueError):
                value = None
        elif rtype in (_QTYPE_CNAME, _QTYPE_NS_, _QTYPE_PTR):
            if rdlen >= 1:
                value, _ = _decode_name(msg, i)
        elif rtype == _QTYPE_MX and rdlen >= 3:
            pref = struct.unpack("!H", msg[i:i + 2])[0]
            target, _ = _decode_name(msg, i + 2)
            value = (pref, target)
        elif rtype == _QTYPE_SRV and rdlen >= 7:
            pri, wt, port_ = struct.unpack("!HHH", msg[i:i + 6])
            target, _ = _decode_name(msg, i + 6)
            value = (pri, wt, port_, target)
        elif rtype == _QTYPE_TXT and rdlen >= 1:
            parts: list[str] = []
            j = i
            while j < rdata_end:
                ln = msg[j]
                j += 1
                if j + ln > rdata_end:
                    break
                parts.append(msg[j:j + ln].decode("utf-8", "replace"))
                j += ln
            value = "".join(parts)
        i = rdata_end
        rrs.append({"name": owner, "type": rtype, "value": value})
    return rrs, i


def _rr_query(ip: str, port: int, name: str, qtype: int,
              timeout: float = _TIMEOUT) -> list[dict]:
    """Recursive TCP query for a single (name, qtype); returns parsed answer RRs
    (best-effort). Empty list on transport error, non-NOERROR rcode, or no answers.

    Kept separate from nsec_walk/version_bind on purpose: those two want tight
    control of flags and rcodes; this one is the generic 'give me the answer
    section' helper used by srv_mx_ns() and by AXFR body parsing."""
    resp = _tcp_dns(ip, port, _query(name, qtype, rd=True), timeout)
    if not resp or len(resp) < 12:
        return []
    _id, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", resp[:12])
    if (flags & 0x000F) != 0 or an < 1:
        return []
    i = _skip_question(resp, 12, qd)
    rrs, _ = _parse_rrs(resp, i, an)
    return rrs


def open_recursion(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Detect an open recursive resolver — a server that accepts recursive
    queries from unauthorized clients (the primitive abused for DNS
    amplification / reflected DDoS).

    Sends ONE recursive A-query for a name under the RFC 6761 .invalid TLD.
    A locked-down authoritative server refuses cleanly (rcode REFUSED / NOTIMP)
    or drops the query; an open resolver echoes RA=1 and returns a non-refused
    rcode (NOERROR / NXDOMAIN / SERVFAIL — the server took the query even if
    upstream resolution failed).

    Returns {ok, ra, rcode}. ok=True is the "open resolver" signal
    (RA=1 AND rcode not in {NOTIMP=4, REFUSED=5}). Read-only, no writes,
    no state change — same probe shape as version.bind."""
    probe_name = "recursion-test.recce.invalid"
    resp = _tcp_dns(ip, port, _query(probe_name, _QTYPE_A, rd=True), timeout)
    if not resp or len(resp) < 12:
        return {"ok": False, "ra": False, "rcode": None}
    _id, flags, _qd, _an, _ns, _ar = struct.unpack("!HHHHHH", resp[:12])
    ra = bool(flags & 0x0080)
    rcode = flags & 0x000F
    # RA=1 alone is not enough (some auth servers echo the bit); pair with a
    # non-refused rcode so we only fire when the server actually processed
    # the recursive query.
    ok = ra and rcode not in (4, 5)
    return {"ok": ok, "ra": ra, "rcode": rcode}


def _bucket_rrs(rrs: list[dict]) -> dict:
    """Group parsed RRs into a shape convenient for probe blob + findings.

    Everything is a list of strings/tuples ready for JSON serialization:
        names   - every owner-name that appeared (unique, lowercased, apex-stripped)
        a       - [(owner, ipv4)]
        aaaa    - [(owner, ipv6)]
        cname   - [(owner, target)]
        ns      - [(owner, nsdname)]
        ptr     - [(owner, target)]
        mx      - [(owner, pref, target)]
        srv     - [(owner, pri, wt, port, target)]
    """
    out: dict = {"names": [], "a": [], "aaaa": [], "cname": [],
                 "ns": [], "ptr": [], "mx": [], "srv": []}
    seen_names: set[str] = set()
    for rr in rrs:
        owner = (rr.get("name") or "").strip(".").lower()
        if owner and owner not in seen_names:
            seen_names.add(owner)
            out["names"].append(owner)
        val = rr.get("value")
        if val is None:
            continue
        t = rr["type"]
        if t == _QTYPE_A:
            out["a"].append((owner, val))
        elif t == _QTYPE_AAAA:
            out["aaaa"].append((owner, val))
        elif t == _QTYPE_CNAME:
            out["cname"].append((owner, val))
        elif t == _QTYPE_NS_:
            out["ns"].append((owner, val))
        elif t == _QTYPE_PTR:
            out["ptr"].append((owner, val))
        elif t == _QTYPE_MX:
            pref, target = val
            out["mx"].append((owner, pref, target))
        elif t == _QTYPE_SRV:
            pri, wt, port_, target = val
            out["srv"].append((owner, pri, wt, port_, target))
    return out


def srv_mx_ns(ip: str, port: int, zone: str,
              timeout: float = _TIMEOUT) -> dict:
    """Enumerate the well-known SRV anchors under `zone` plus MX and NS at the apex.

    RFC 2782 SRV probes cover AD (_ldap/_kerberos/_gc/_kpasswd), Exchange
    autodiscover, and SIP UC. MX (RFC 1035 §3.3.9) and NS (§3.3.11) give mail
    routing + the true zone masters (which are the servers most likely to still
    allow AXFR when the recon-hit resolver refuses).

    Returns {srv: {label: [(pri, wt, port, target), ...]}, mx: [(pref, target), ...],
    ns: [nsdname, ...]}. Empty structures on refused / unauthoritative servers —
    nothing raises, air-gap safe (recursive lookup only; no follow-ups off the
    target).
    """
    out: dict = {"srv": {}, "mx": [], "ns": []}
    for label in _WELL_KNOWN_SRV_LABELS:
        qname = f"{label}.{zone.strip('.')}"
        entries = [rr for rr in _rr_query(ip, port, qname, _QTYPE_SRV, timeout)
                   if rr["type"] == _QTYPE_SRV and rr["value"]]
        if entries:
            out["srv"][label] = [rr["value"] for rr in entries]
    for rr in _rr_query(ip, port, zone, _QTYPE_MX, timeout):
        if rr["type"] == _QTYPE_MX and rr["value"]:
            out["mx"].append(rr["value"])
    for rr in _rr_query(ip, port, zone, _QTYPE_NS_, timeout):
        if rr["type"] == _QTYPE_NS_ and rr["value"]:
            out["ns"].append(rr["value"])
    return out


def nsec_walk(ip: str, port: int, zone: str, timeout: float = _TIMEOUT,
              max_steps: int = _MAX_NSEC_STEPS) -> dict:
    """Enumerate every name in a DNSSEC-signed zone by following the NSEC chain.

    NSEC records prove non-existence by naming the NEXT owner in canonical
    order - so a server that returns an NSEC for a nonexistent name has just
    told you what the next real name is. Repeat until the walk wraps back to
    the zone apex.

    Returns {ok, names, steps, wrapped}. `ok` is True when at least one
    NSEC record was returned; `wrapped` is True if the chain closed cleanly
    on the apex (a complete walk). Bounded by max_steps so a misconfigured
    zone that never wraps cannot pin the tester.
    """
    zone_norm = zone.strip(".").lower()
    out = {"ok": False, "names": [], "steps": 0, "wrapped": False}
    current = zone_norm
    seen: set[str] = set()
    for step in range(max_steps):
        # Ask for NSEC directly on `current` when it is the apex, and for a
        # nonexistent sibling everywhere else - both yield an NSEC covering
        # the gap after `current` on a DNSSEC-signed authoritative server.
        query_name = current if step == 0 else _next_name(current)
        resp = _tcp_dns(ip, port, _query(query_name, _QTYPE_NSEC, rd=False), timeout)
        if not resp or len(resp) < 12:
            break
        _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
        rcode = flags & 0x000F
        # An authoritative server without DNSSEC may return NOERROR + 0 answers
        # or REFUSED / NOTIMP - stop cleanly.
        if rcode not in (0, 3):                     # 0 NOERROR / 3 NXDOMAIN
            break
        # Skip the question section (variable-length name + 4 bytes qtype/qclass).
        i = 12
        _q_name, i = _decode_name(resp, i)
        i += 4
        next_owner = ""
        for _ in range(an + ns):
            _r_name, i = _decode_name(resp, i)
            if i + 10 > len(resp):
                break
            rtype, _rc, _ttl, rdlen = struct.unpack("!HHIH", resp[i:i + 10])
            i += 10
            if rtype == _QTYPE_NSEC:
                # RDATA of an NSEC is: next-domain-name (wire) + type-bitmaps.
                next_owner, _ = _decode_name(resp, i)
                break
            i += rdlen
        if not next_owner:
            break
        out["ok"] = True
        out["steps"] = step + 1
        owner_norm = next_owner.strip(".").lower()
        if owner_norm in seen or owner_norm == zone_norm and step > 0:
            out["wrapped"] = True
            break
        seen.add(owner_norm)
        out["names"].append(next_owner)
        current = next_owner
    return out


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


# --------------------------------------------------------------------------- #
# T2 helpers: safe proof-of-exploit for dns_axfr.
#
# AXFR itself is the exploit primitive — it is a read-only DNS request that
# succeeds only when the server allows the transfer, so parsing real hostname/IP
# records back out IS proof the primitive worked (no writes, no state change,
# just the standard AXFR handshake). The T2 promotion turns those parsed
# records into a deduped pivot list the operator can feed to downstream
# scanners immediately, and version-gates a small BIND CVE table against the
# co-disclosed version.bind fingerprint so no unverified CVE ever ships.
# --------------------------------------------------------------------------- #

# Curated BIND CVE table, keyed by (fixed_9_11_series, fixed_9_16_series).
# Every entry has to be version-gated (never emit a CVE without a version match),
# which is why the table only lists CVEs with published "fixed in" versions.
# Sources: ISC Knowledge Base security advisories (KB pages).
#   CVE-2020-8617  — TSIG buffer-overread crash, fixed in 9.11.19 / 9.16.3
#   CVE-2020-8623  — TCP-buffer assertion crash, fixed in 9.11.22 / 9.16.6
#   CVE-2020-8625  — GSSAPI/SPNEGO stack overflow, fixed in 9.11.28 / 9.16.12
_BIND_CVE_TABLE: tuple[tuple[str, str, tuple[int, int], tuple[int, int]], ...] = (
    ("CVE-2020-8617", "TSIG buffer over-read crashes named",
     (11, 19), (16, 3)),
    ("CVE-2020-8623", "TCP-buffer assertion crashes named",
     (11, 22), (16, 6)),
    ("CVE-2020-8625", "GSSAPI/SPNEGO stack buffer overflow",
     (11, 28), (16, 12)),
)

# BIND version strings look like "9.11.5-P4-5.1+deb10u5-Debian" or "9.16.1"
# or "BIND 9.16.6". We only match the numeric 9.MINOR.PATCH prefix and ignore
# vendor tags — safer than trying to decode every distro suffix.
_BIND_VERSION_RE = re.compile(r"\b9\.(\d+)\.(\d+)\b")


def _parse_bind_version(version_str: str) -> tuple[int, int] | None:
    """Extract (minor, patch) from a BIND version.bind string.

    Returns None when the string is empty or does not look like a 9.x.y BIND
    version — the CVE gate then never fires (fail-closed). Vendor suffixes
    like '-P4-5.1+deb10u5-Debian' are ignored on purpose because ISC does not
    publish a canonical mapping from distro rebuild tags to upstream patch
    levels, and mis-parsing them would risk emitting a CVE that has actually
    been backported."""
    if not version_str:
        return None
    m = _BIND_VERSION_RE.search(version_str)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


def _bind_cves(version_str: str) -> list[dict]:
    """Match a parsed BIND version against the curated CVE table.

    Returns [{cve, description}, ...] for vulns whose fix has NOT landed in the
    parsed 9.MINOR.PATCH. Empty list on unknown / patched / newer-than-table
    versions — the CVE reference is version-gated, never shipped by default."""
    parsed = _parse_bind_version(version_str)
    if not parsed:
        return []
    minor, patch = parsed
    hits: list[dict] = []
    for cve, desc, fx11, fx16 in _BIND_CVE_TABLE:
        # Only compare inside the version's own release train (9.11 vs 9.16 etc.);
        # ISC ships fixes to each maintenance branch independently.
        if minor == 11 and (minor, patch) < fx11:
            hits.append({"cve": cve, "description": desc})
        elif minor == 16 and (minor, patch) < fx16:
            hits.append({"cve": cve, "description": desc})
        elif minor < 11:
            # Pre-9.11 is EOL and never patched — anything before the 9.11 fix
            # applies verbatim.
            hits.append({"cve": cve, "description": desc})
    return hits


def _axfr_pivot_targets(zdata: dict) -> list[tuple[str, str]]:
    """Turn a bucketed AXFR record set into a deduped (hostname, ip) list.

    IPv4 first (A), then IPv6 (AAAA); apex-stripped, lowercased. This is the
    T2 evidence surface — the operator gets a ready-made list of internal
    hosts (with resolvable IPs) to feed to SMB/LDAP/kerb/HTTP scanners without
    round-tripping through a resolver."""
    seen: set[tuple[str, str]] = set()
    pivots: list[tuple[str, str]] = []
    for owner, ip in (zdata.get("a") or []):
        key = ((owner or "").strip(".").lower(), ip)
        if key[0] and key not in seen:
            seen.add(key)
            pivots.append(key)
    for owner, ip in (zdata.get("aaaa") or []):
        key = ((owner or "").strip(".").lower(), ip)
        if key[0] and key not in seen:
            seen.add(key)
            pivots.append(key)
    return pivots


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier="", output=""):
    f = {"severity": sev, "title": title, "target": target, "detail": detail,
         "tool": "dig", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind,
         "exploit_note": exploit_note, "depth_tier": depth_tier}
    if output:
        f["output"] = output
    return f


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
                # If we parsed the AXFR body, surface a small sample of the
                # leaked names in the finding text — turns "128 records" into
                # something the operator can act on immediately.
                zdata = (pr.get("axfr_data") or {}).get(z) or {}
                sample_names = (zdata.get("names") or [])[:8]
                sample_note = ""
                if sample_names:
                    sample_note = (" Sample leaked names: "
                                   + ", ".join(sample_names)
                                   + (" ..." if len(zdata.get("names") or []) > 8 else "")
                                   + ".")
                # T2 promotion: AXFR is itself a safe read-only exploit primitive,
                # so any parsed A/AAAA record proves it worked. Surface deduped
                # (hostname, ip) pivots and upgrade depth_tier=t2. If the AXFR
                # went through but no A/AAAA came back in the first message,
                # stay at t1 (we have the primitive but no concrete pivot yet).
                pivots = _axfr_pivot_targets(zdata)
                pivot_note = ""
                pivot_output = ""
                depth_tier = "t1"
                if pivots:
                    depth_tier = "t2"
                    head = pivots[:6]
                    pivot_note = (
                        " Pivot targets extracted from the AXFR body "
                        "(hostname=ip): "
                        + ", ".join(f"{hn}={ip}" for hn, ip in head)
                        + (f" (+{len(pivots) - len(head)} more)"
                           if len(pivots) > len(head) else "")
                        + ". Feed straight to downstream SMB/LDAP/kerb/HTTP scans.")
                    pivot_output = "\n".join(f"{hn}\t{ip}" for hn, ip in pivots)
                # Version-gated BIND CVE annotation — only fires when the server
                # co-disclosed a version.bind string that parses AND falls under
                # a curated fixed-in threshold. Never ships an unverified CVE.
                cve_hits = _bind_cves(pr.get("version") or "")
                cve_note = ""
                cwes = ["CWE-200", "CWE-284"]
                if cve_hits:
                    cve_note = (
                        " Server version.bind='" + (pr.get("version") or "")
                        + "' also matches known BIND CVEs: "
                        + ", ".join(f"{c['cve']} ({c['description']})"
                                    for c in cve_hits)
                        + ".")
                out.append(_finding(
                    "high", f"DNS zone transfer allowed ({z})", tgt,
                    f"AXFR of '{z}' succeeded from an unauthenticated client "
                    f"({pr.get('records', {}).get(z, '?')} records) - the full internal "
                    "zone (every host/service name + IP) is exposed as an instant map."
                    + sample_note + pivot_note + cve_note,
                    f"dig AXFR {z} @{h.ip}",
                    "Restrict zone transfers to authorized secondaries "
                    "(allow-transfer / xfer-out ACLs); disable AXFR to the world.",
                    cwes, kind="dns_axfr",
                    exploit_note=(
                        "dig AXFR <zone> @<ip> +tcp; ingest hostnames/IPs into "
                        "scope, then run: crackmapexec smb <new_ips> --gen-relay-list "
                        "relay.txt; kerbrute userenum -d <zone> users.txt --dc <ip>."
                    ),
                    depth_tier=depth_tier, output=pivot_output))
            # SRV/MX/NS discovery per zone. The AD anchor set (_ldap._tcp +
            # _kerberos._tcp under a zone) authoritatively identifies an
            # AD-integrated domain — high-value recon intel (points every
            # downstream AD scanner at the right DCs), so surface as an
            # info-severity discovery finding rather than a config bug.
            for z, sr in (pr.get("service_records") or {}).items():
                srv_map = sr.get("srv") or {}
                have_ad = all(lbl in srv_map for lbl in _AD_ANCHOR_LABELS)
                if have_ad:
                    dcs = sorted({tgt_[3].strip(".").lower()
                                  for tgt_ in srv_map.get("_ldap._tcp", [])
                                  if isinstance(tgt_, tuple) and len(tgt_) == 4})
                    out.append(_finding(
                        "info",
                        f"AD-integrated DNS domain discovered ({z})", tgt,
                        f"Zone '{z}' publishes both _ldap._tcp and _kerberos._tcp SRV "
                        "records under it (RFC 2782), which is how an Active Directory "
                        "domain advertises its Domain Controllers. Candidate DC "
                        f"hostname(s): {', '.join(dcs) if dcs else '(none decoded)'}.",
                        f"dig SRV _ldap._tcp.{z} @{h.ip}; dig SRV _kerberos._tcp.{z} @{h.ip}",
                        "Not a defect on its own; verify these SRV records are meant "
                        "to be publicly visible and that the exposed DCs are hardened.",
                        ["CWE-200"], kind="dns_ad_srv",
                        exploit_note=(
                            "kerbrute userenum -d <zone> --dc <dc_target> "
                            "users.txt; ldapsearch -x -H ldap://<dc> "
                            "-b DC=<zone_dc>,DC=<tld> '(objectClass=user)' "
                            "sAMAccountName."),
                        depth_tier="t0"))
            # NSEC walk — signed-zone enumeration without needing AXFR.
            for z, walk in (pr.get("nsec") or {}).items():
                names = walk.get("names") or []
                if not names:
                    continue
                sample = ", ".join(names[:10])
                closed = " (chain closed cleanly)" if walk.get("wrapped") else \
                         f" (walk truncated at {_MAX_NSEC_STEPS} steps — zone " \
                         "larger than the cap)"
                out.append(_finding(
                    "medium",
                    f"DNS zone enumerated via NSEC walk ({z})", tgt,
                    f"The signed zone '{z}' returns NSEC records for nonexistent "
                    f"names, so recce walked the NSEC chain and enumerated "
                    f"{len(names)} name(s) in {walk.get('steps', 0)} step(s){closed}. "
                    f"Sample: {sample}"
                    + (" …" if len(names) > 10 else "")
                    + ". Same disclosure as AXFR (every internal service name "
                    "leaks) without needing zone-transfer rights.",
                    f"dig NSEC {z} @{h.ip}   # then chase next-owners "
                    "(nsec3walker for NSEC3, nsec_walk-style tooling)",
                    "Serve NSEC3 with an opt-out flag AND a large iterations "
                    "count on public zones; better, use NSEC3 white-lies (RFC "
                    "7129 §5.5) or DNSSEC minimal-cover to answer 'no such name' "
                    "without disclosing neighbours.",
                    ["CWE-200"], kind="dns_nsec_walk",
                    exploit_note=(
                        "ldns-walk <zone> @<ip>; for NSEC3: nsec3walker "
                        "<zone> then hashcat -m 8300 nsec3.hashes "
                        "rockyou.txt to recover the hashed labels."),
                    # P0-1: T2 promotion — the walked NSEC chain returned
                    # concrete owner names harvested from the target's own
                    # NSEC RR sequence. Every name in the finding sample
                    # came from a real DNS reply, not an inference.
                    # (Follow-up capability: NSEC3 walker for hashed zones,
                    # documented in .recce-plan/audit/ as a P2-1 item.)
                    depth_tier="t2"))
            # Open recursive resolver — server processes recursive queries from
            # unauthorized clients (the DNS-amplification primitive: small query
            # → large answer reflected at a spoofed victim IP).
            oreq = pr.get("open_recursion") or {}
            if oreq.get("ok"):
                out.append(_finding(
                    "medium",
                    "DNS server is an open recursive resolver",
                    tgt,
                    f"Server answered a recursive query for a name outside its "
                    f"authoritative zones with RA=1 and rcode="
                    f"{oreq.get('rcode')} (not REFUSED/NOTIMP) — it accepts "
                    "recursion from arbitrary clients. Open resolvers are "
                    "the classic building block for DNS amplification / "
                    "reflected DDoS attacks (small spoofed request, large "
                    "response reflected at the victim).",
                    f"dig +recurse A recursion-test.recce.invalid @{h.ip}",
                    "Restrict recursion to authorized clients "
                    "(allow-recursion / allow-query-cache ACLs); "
                    "auth-only servers should disable recursion entirely "
                    "(options { recursion no; };).",
                    ["CWE-406"], kind="dns_open_recursion",
                    exploit_note=(
                        "dig ANY isc.org @<ip> +bufsize=4096; measure the "
                        "response/request byte ratio — a ratio >>1 with the "
                        "server willing to recurse for unauthorized clients "
                        "is the DNS amplification primitive. Report to "
                        "openresolverproject.org or equivalent."),
                    depth_tier="t1"))
            if pr.get("version") and "bind" in (pr.get("version") or "").lower():
                out.append(_finding(
                    "low", "DNS server version disclosed (version.bind)", tgt,
                    f"version.bind returned '{pr['version']}' - a precise server version "
                    "aids targeting.",
                    f"dig CH TXT version.bind @{h.ip}",
                    "Hide the version (options { version \"\"; }).",
                    ["CWE-200"], kind="dns_version",
                    exploit_note=(
                        "dig CH TXT version.bind @<ip>; compare against ISC "
                        "BIND security advisories; if <9.11.35 test with "
                        "'nmap --script dns-cache-snoop' for CVE-2020-8617."),
                    depth_tier="t0"))
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
                        ["CWE-290", "CWE-346"], kind="dns_missing_spf",
                        exploit_note=(
                            "swaks --to test@<zone> --from ceo@<zone> "
                            "--server <mx> --header 'Subject: spoof test'  "
                            "# proves receiving MTA accepts unsigned "
                            "spoofed mail."),
                        # P0-1: T2 promotion — the finding is a definitive
                        # server-side answer: the target's DNS resolver
                        # returned no v=spf1 record when asked for the
                        # zone's TXT set. A null-record reply is a real
                        # answer, not an inference. (Follow-up: T3 comes
                        # from actually delivering spoofed mail via the
                        # discovered MX, gated behind a future --safe-off.)
                        depth_tier="t2"))
                elif re.search(r"[+?]all\b", es["spf"], re.I):
                    # Weak SPF — +all = pass everything; ?all = neutral.
                    out.append(_finding(
                        "low", f"Weak SPF policy for {z} ({es['spf'][:60]}...)", tgt,
                        "SPF exists but its terminator is +all/?all — anyone still "
                        "passes. Effectively equivalent to no SPF for spoofing purposes.",
                        f"dig TXT {z} @{h.ip}",
                        "Change the SPF terminator to -all (fail) or ~all (softfail).",
                        ["CWE-290"], kind="dns_weak_spf",
                        exploit_note=(
                            "swaks --to test@<zone> --from spoof@<zone> "
                            "--server <mx>; check whether SPF-failing mail "
                            "lands in Inbox."),
                        # P0-1: T2 promotion — the finding title carries
                        # the ACTUAL SPF record string returned by the
                        # target's TXT lookup (es["spf"]). The weak
                        # terminator (+all / ?all) was extracted from real
                        # server content, not inferred.
                        depth_tier="t2"))
                if not es.get("dmarc"):
                    out.append(_finding(
                        "medium", f"DMARC record missing for {z}", tgt,
                        f"No DMARC (v=DMARC1) TXT record at '_dmarc.{z}'. Without a "
                        f"DMARC policy, spoofed mail is not reported and is not blocked "
                        f"even if SPF/DKIM fail.",
                        f"dig TXT _dmarc.{z} @{h.ip}",
                        "Publish DMARC starting with 'v=DMARC1; p=none; rua=mailto:...' "
                        "for monitoring, then move to p=quarantine and p=reject.",
                        ["CWE-290", "CWE-346"], kind="dns_missing_dmarc",
                        exploit_note=(
                            "swaks --to victim@<zone> --from ceo@<zone> "
                            "--server <mx>  # DMARC absent => spoofed "
                            "From: passes end-to-end."),
                        # P0-1: T2 promotion — same DNS-reply reasoning as
                        # dns_missing_spf: the target confirmed absence of
                        # any TXT at _dmarc.<zone>.
                        depth_tier="t2"))
                elif "p=none" in es["dmarc"].lower():
                    out.append(_finding(
                        "low", f"DMARC in monitor-only mode for {z} (p=none)", tgt,
                        "DMARC policy is p=none — receivers report spoofed mail but "
                        "still deliver it. Effective for reporting, not enforcement.",
                        f"dig TXT _dmarc.{z} @{h.ip}",
                        "Advance policy to p=quarantine (bulk-folder) then p=reject.",
                        ["CWE-290"], kind="dns_dmarc_monitor",
                        exploit_note=(
                            "swaks --to victim@<zone> --from cfo@<zone> "
                            "--server <mx>; delivery to Inbox proves "
                            "monitor-only enforcement."),
                        # P0-1: T2 promotion — the target's TXT reply
                        # returned an actual DMARC policy string
                        # containing "p=none". The policy value is real
                        # server-side content, not an inference.
                        depth_tier="t2"))
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
        axfr_zones, rec, axfr_data = [], {}, {}
        for z in zones:
            r = axfr(t["ip"], t["port"], z)
            if r["ok"]:
                axfr_zones.append(z)
                rec[z] = r["records"]
                axfr_data[z] = r.get("data") or {}
        # Email-security posture per zone. Cheap: at most 12 TXT lookups per
        # zone (SPF + DMARC + 10 DKIM selectors). Zones with none of these
        # records skip cleanly with empty strings.
        email_sec = {}
        for z in zones:
            email_sec[z] = email_security_records(t["ip"], t["port"], z)
        # NSEC walk per zone. Skipped for zones where AXFR already succeeded
        # (redundant — AXFR gives every record, NSEC only gives every name).
        # Bounded per zone by _MAX_NSEC_STEPS so a wildcard-heavy zone cannot
        # tarpit the probe.
        nsec = {}
        for z in zones:
            if z in axfr_zones:
                continue
            w = nsec_walk(t["ip"], t["port"], z)
            if w["ok"] and w["names"]:
                nsec[z] = w
        # SRV/MX/NS enumeration per zone. Skipped for zones where AXFR already
        # succeeded (the AXFR body already carried these RRs — no point paying
        # for the same records twice). Empty result skips cleanly.
        service_records: dict = {}
        for z in zones:
            if z in axfr_zones:
                continue
            data = srv_mx_ns(t["ip"], t["port"], z)
            if data["srv"] or data["mx"] or data["ns"]:
                service_records[z] = data
        # Open-resolver detection: one recursive query for a name outside any
        # of the target's likely zones (RFC 6761 .invalid). Read-only single
        # query — matches the version.bind probe shape.
        oreq = open_recursion(t["ip"], t["port"])
        return {"reachable": True, "version": ver, "axfr_zones": axfr_zones,
                "records": rec, "email_sec": email_sec, "nsec": nsec,
                "axfr_data": axfr_data, "service_records": service_records,
                "open_recursion": oreq}

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
