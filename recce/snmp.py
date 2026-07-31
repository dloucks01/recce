"""Deep SNMP enumeration (stdlib only).

SNMP v2c over UDP 161, hand-rolled on a raw socket - BER/ASN.1 with OID encoding, no
pysnmp. Airgapped, stdlib only.

  * **Community brute:** GET sysDescr with a list of common community strings
    (public/private/...) - the first that answers is a readable community.
  * **Walk:** the system group, then GETNEXT walks of the Windows LanManager user
    table, running processes, installed software and interfaces.

Every positive folds into the severity totals, the Vulnerabilities sheet, the
write-ups, a dedicated **SNMP** tab, and the enumerated Windows users become Account
objects that populate Users & Accounts. Safety posture: see SECURITY.md.
"""
from __future__ import annotations

import socket

from .models import Account, Host, Port

_DEFAULT_PORT = 161
_TIMEOUT = 1.5

# Common community strings, RO first. A write-capable community is usually named for
# it (private/write/manager/secret) - recce flags those higher but never sends a SET.
_COMMUNITIES = ["public", "private", "community", "manager", "snmp", "cisco", "admin",
                "default", "read", "monitor", "secret", "write", "security", "test",
                "public1", "san-fran"]
_RW_LIKELY = {"private", "write", "manager", "secret", "admin"}

_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_SYS_OBJECTID = "1.3.6.1.2.1.1.2.0"
_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
# Walk bases.
_LANMGR_USERS = "1.3.6.1.4.1.77.1.2.25"        # Windows local user accounts
_HR_SW_RUN = "1.3.6.1.2.1.25.4.2.1.2"          # running process names
_HR_SW_INSTALLED = "1.3.6.1.2.1.25.6.3.1.2"    # installed software names
_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"              # interface descriptions


def is_snmp(port: Port) -> bool:
    if port.portid == _DEFAULT_PORT:
        return True
    return "snmp" in f"{port.service} {port.product}".lower()


# --- BER / ASN.1 (SNMP subset) --------------------------------------------------

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(body)]) + bytes(body)


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    body = []
    m = n
    while m:
        body.insert(0, m & 0xFF)
        m >>= 8
    if body[0] & 0x80:
        body.insert(0, 0)
    return _tlv(0x02, bytes(body))


def _octet(s) -> bytes:
    return _tlv(0x04, s.encode() if isinstance(s, str) else s)


def _null() -> bytes:
    return b"\x05\x00"


def _base128(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    out = []
    while n:
        out.insert(0, n & 0x7F)
        n >>= 7
    for i in range(len(out) - 1):
        out[i] |= 0x80
    return bytes(out)


def encode_oid(oid: str) -> bytes:
    arcs = [int(x) for x in oid.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        body += _base128(a)
    return _tlv(0x06, body)


def _read_len(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = 0
    for _ in range(first & 0x7F):
        n = (n << 8) | data[i]
        i += 1
    return n, i


def _parse_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    tag = data[i]
    length, j = _read_len(data, i + 1)
    return tag, data[j:j + length], j + length


def decode_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    arcs = [first // 40, first % 40]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(n)
            n = 0
    return ".".join(str(a) for a in arcs)


# SNMP value tags -> python. Exceptions (noSuchObject/Instance, endOfMibView) => None.
def _decode_value(tag: int, value: bytes):
    if tag == 0x04:                                # OCTET STRING
        return value.decode("utf-8", "replace")
    if tag in (0x02, 0x41, 0x42, 0x43, 0x46):      # INTEGER / Counter / Gauge / Ticks
        n = 0
        for b in value:
            n = (n << 8) | b
        # ASN.1 INTEGER is two's-complement signed; sign-extend if the high bit is
        # set (Counters/Gauges/Ticks are unsigned, but a signed INTEGER can be < 0).
        if tag == 0x02 and value and (value[0] & 0x80):
            n -= 1 << (8 * len(value))
        return n
    if tag == 0x06:
        return decode_oid(value)
    if tag == 0x40 and len(value) == 4:            # IpAddress
        return ".".join(str(b) for b in value)
    return None                                    # NULL / exception markers


# --- request / response ---------------------------------------------------------

def build_request(community: str, oid: str, request_id: int,
                  pdu_tag: int = 0xA0) -> bytes:
    """SNMP v2c message. pdu_tag: 0xA0 GetRequest, 0xA1 GetNextRequest."""
    varbind = _tlv(0x30, encode_oid(oid) + _null())
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(pdu_tag, _int(request_id) + _int(0) + _int(0) + varbinds)
    return _tlv(0x30, _int(1) + _octet(community) + pdu)   # version 1 == v2c


def parse_response(data: bytes) -> tuple[int, list[tuple[str, object]]] | None:
    """(error_status, [(oid, value), ...]) from a GetResponse, or None if malformed."""
    try:
        _, msg, _ = _parse_tlv(data, 0)                    # outer SEQUENCE
        _, _ver, i = _parse_tlv(msg, 0)
        _, _comm, i = _parse_tlv(msg, i)
        _, pdu, _ = _parse_tlv(msg, i)                     # GetResponse [2] value
        _, _rid, j = _parse_tlv(pdu, 0)
        _, err, j = _parse_tlv(pdu, j)
        _, _eidx, j = _parse_tlv(pdu, j)
        _, vbs, _ = _parse_tlv(pdu, j)                     # varbind list
        out = []
        k = 0
        while k < len(vbs):
            _, vb, k = _parse_tlv(vbs, k)
            _, oid_b, m = _parse_tlv(vb, 0)
            vtag, vval, _ = _parse_tlv(vb, m)
            out.append((decode_oid(oid_b), _decode_value(vtag, vval)))
        error = 0
        for b in err:
            error = (error << 8) | b
        return error, out
    except (IndexError, ValueError):
        return None


# --- probe ----------------------------------------------------------------------

def _response_request_id(data: bytes):
    """The request-id echoed in a GetResponse, or None if unparseable."""
    try:
        _, msg, _ = _parse_tlv(data, 0)
        _, _ver, i = _parse_tlv(msg, 0)
        _, _comm, i = _parse_tlv(msg, i)
        _, pdu, _ = _parse_tlv(msg, i)
        _, rid_b, _ = _parse_tlv(pdu, 0)
        return int.from_bytes(rid_b, "big")
    except (IndexError, ValueError):
        return None


def _get(sock, ip: str, port: int, community: str, oid: str, timeout: float,
         request_id: int, pdu_tag: int = 0xA0):
    """One GET/GETNEXT. Returns [(oid, value)] or None (timeout / error). Correlates
    the reply by request-id so a stray/duplicate/out-of-order UDP datagram (connection-
    less) isn't accepted as the answer to a different OID."""
    try:
        sock.sendto(build_request(community, oid, request_id, pdu_tag), (ip, port))
        sock.settimeout(timeout)
        data = None
        for _ in range(4):                          # skip a few stale datagrams, bounded
            data, _ = sock.recvfrom(65535)
            rid = _response_request_id(data)
            if rid is None or rid == request_id:
                break
        else:
            return None
    except OSError:
        return None
    parsed = parse_response(data)
    if parsed is None or parsed[0] != 0:
        return None
    return parsed[1]


def _walk(sock, ip: str, port: int, community: str, base: str, timeout: float,
          start_id: int, cap: int = 256) -> list[str]:
    """GETNEXT walk of `base`; returns the string values found under it."""
    values: list[str] = []
    cur = base
    for n in range(cap):
        vb = _get(sock, ip, port, community, cur, timeout, start_id + n, 0xA1)
        if not vb:
            break
        oid, val = vb[0]
        if not (oid == base or oid.startswith(base + ".")):
            break                                          # left the subtree
        if val is None:                                    # endOfMibView / exception
            break
        if isinstance(val, str) and val.strip():
            values.append(val.strip())
        cur = oid
    return values


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          known_open: bool = False) -> dict | None:
    """Find a readable community, then read the system group + walk the high-value
    tables. Returns None if nothing answered. Read-only (no SET is ever sent)."""
    communities = _COMMUNITIES if known_open else _COMMUNITIES[:5]
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        community = None
        sys_descr = None
        for i, c in enumerate(communities):
            vb = _get(sock, ip, port, c, _SYS_DESCR, timeout, 1000 + i)
            if vb and vb[0][1] is not None:
                community, sys_descr = c, vb[0][1]
                break
        if community is None:
            return None
        out = {"ip": ip, "port": port, "community": community,
               "rw_likely": community in _RW_LIKELY, "sys_descr": sys_descr or ""}
        for key, oid in (("sys_name", _SYS_NAME), ("sys_contact", _SYS_CONTACT),
                         ("sys_location", _SYS_LOCATION)):
            vb = _get(sock, ip, port, community, oid, timeout, 2000)
            out[key] = (vb[0][1] if vb and isinstance(vb[0][1], str) else "") or ""
        out["users"] = _walk(sock, ip, port, community, _LANMGR_USERS, timeout, 3000)
        out["processes"] = _walk(sock, ip, port, community, _HR_SW_RUN, timeout, 4000)[:40]
        out["software"] = _walk(sock, ip, port, community, _HR_SW_INSTALLED, timeout, 5000)[:40]
        out["interfaces"] = _walk(sock, ip, port, community, _IF_DESCR, timeout, 6000)[:20]
        return out
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def snmp_targets(hosts: list[Host]) -> list[dict]:
    """One target per host at UDP 161 (SNMP discovery IS a GET, so a prior UDP scan
    isn't required), plus any host that already has an SNMP port discovered elsewhere."""
    out = []
    for h in hosts:
        seen = set()
        for p in h.open_ports:
            if is_snmp(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "known_open": True})
                seen.add(p.portid)
        if _DEFAULT_PORT not in seen:
            out.append({"ip": h.ip, "hostname": h.hostname, "port": _DEFAULT_PORT,
                        "known_open": False})
    return out


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "snmp_community": (
        "The device answers SNMP with a guessable community string, so anyone on the "
        "network reads its management data unauthenticated: the OS and exact build, "
        "hostname, contact/location, network interfaces and routes, ARP tables, running "
        "processes and installed software - a complete recon picture, and on Windows the "
        "local user accounts. SNMP v1/v2c has no real authentication and the community "
        "crosses the wire in cleartext."),
    "snmp_rw": (
        "The readable community is one conventionally provisioned read-WRITE. recce does "
        "NOT send a SET (it stays read-only), but a write community lets an attacker "
        "reconfigure the device - change routes/ACLs, download the running config (TFTP "
        "exfil), or brick it. Treat as a potential full-device compromise and verify the "
        "access level out-of-band."),
    "snmp_users": (
        "SNMP enumerated the host's local user accounts (the Windows LanManager MIB). An "
        "unauthenticated attacker now has a valid username list for password spraying or "
        "targeted attacks - no credentials required to obtain it."),
    "snmp_inventory": (
        "SNMP exposed the running processes and/or installed software inventory. That "
        "reveals the security stack (AV/EDR), unpatched or vulnerable software, and "
        "juicy targets - all pre-authentication reconnaissance."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Community brute (stdlib UDP)",
     "recce GETs sysDescr with a list of common community strings over UDP 161; the "
     "first that answers is a readable community. Read-only - no SET is ever sent."),
    ("2. System + inventory walk",
     "With a working community it reads the system group and GETNEXT-walks the Windows "
     "user table (LanManager MIB), running processes, installed software and interfaces."),
    ("3. Vulnerability identification",
     "A readable community = unauthenticated management disclosure (medium; higher when "
     "the community is one usually provisioned read-write). Enumerated Windows users "
     "become a spray list and Account rows; the software/process inventory is recon."),
    ("4. Runbook",
     "The exact follow-on commands (snmpwalk, snmp-check, onesixtyone, braa) are "
     "staged per host and community, pre-filled."),
]


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "snmp", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for pr in [probes.get((h.ip, p)) for p in {_DEFAULT_PORT,
                   *[x.portid for x in h.open_ports if is_snmp(x)]}]:
            if not pr:
                continue
            ip, port = pr["ip"], pr["port"]
            tgt = f"{ip}:{port}"
            ident = "; ".join(x for x in (pr.get("sys_name"), pr.get("sys_descr")) if x)
            out.append(_finding(
                "high" if pr.get("rw_likely") else "medium",
                "SNMP readable with a guessable community string", tgt,
                f"Community '{pr['community']}' returns SNMP data unauthenticated"
                + (f" - {ident}." if ident else ".")
                + (" This community name is conventionally read-WRITE (recce did NOT "
                   "send a SET; verify the access level)." if pr.get("rw_likely") else ""),
                "snmpwalk / snmp-check",
                f"snmpwalk -v2c -c {pr['community']} {ip}   # or snmp-check {ip} "
                f"-c {pr['community']}",
                "Disable SNMP if unused; otherwise move to SNMPv3 (auth+priv) and remove "
                "default/guessable communities.",
                ["CWE-1392", "CWE-306", "CWE-319"],
                kind="snmp_rw" if pr.get("rw_likely") else "snmp_community"))
            if pr.get("users"):
                names = ", ".join(pr["users"][:15])
                out.append(_finding(
                    "high", "SNMP exposes local user accounts", tgt,
                    f"SNMP enumerated {len(pr['users'])} local account(s) via the "
                    f"LanManager MIB: {names}. An unauthenticated spray list.",
                    "snmp-check",
                    f"snmp-check {ip} -c {pr['community']}   # users under "
                    "1.3.6.1.4.1.77.1.2.25",
                    "Restrict the SNMP view; move to SNMPv3; remove the LanManager MIB "
                    "exposure.", ["CWE-200"], kind="snmp_users"))
            inv = (pr.get("processes") or []) + (pr.get("software") or [])
            if inv:
                out.append(_finding(
                    "medium", "SNMP exposes process / software inventory", tgt,
                    f"SNMP returned {len(pr.get('processes') or [])} process(es) and "
                    f"{len(pr.get('software') or [])} installed package(s) - AV/EDR, "
                    "unpatched software and targets, all pre-auth.",
                    "snmpwalk",
                    f"snmpwalk -v2c -c {pr['community']} {ip} 1.3.6.1.2.1.25.6.3.1.2",
                    "Restrict the SNMP view to the OIDs actually needed.",
                    ["CWE-200"], kind="snmp_inventory"))
    return out


def accounts_from_probe(ip: str, probe_result: dict) -> list[Account]:
    """Windows local accounts read over SNMP -> Account rows (Users & Accounts)."""
    out = []
    for name in probe_result.get("users") or []:
        out.append(Account(ip=ip, source="snmp", kind="user", name=name,
                           detail="local account (SNMP LanManager MIB)"))
    return out


# --- runbook --------------------------------------------------------------------

def runbook(ip: str, community: str) -> list[dict]:
    c = community or "public"
    steps = [
        ("recon", "onesixtyone", f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/"
         f"snmp.txt {ip}", "Confirm/brute the community strings."),
        ("enumerate", "snmp-check", f"snmp-check {ip} -c {c}",
         "One-shot structured dump: system, users, processes, software, network."),
        ("enumerate", "snmpwalk", f"snmpwalk -v2c -c {c} {ip} .1",
         "Walk the entire MIB tree for anything the structured tools miss."),
        ("loot", "config", f"snmpwalk -v2c -c {c} {ip} 1.3.6.1.4.1.9.9.96   # Cisco "
         "config-copy: TFTP-exfil the running config if this is a RW community",
         "On network gear with a RW community, pull the running config (creds/keys)."),
    ]
    return [{"phase": ph, "tool": t, "command": cmd, "why": w}
            for ph, t, cmd, w in steps]


# --- proof + analyze ------------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "snmp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full SNMP analysis. Attaches enumerated Account objects onto their host in place
    (Users & Accounts / spray list). Returns {targets, findings, runbooks, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    host_by_ip = {h.ip: h for h in hosts}
    targets = snmp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                list(targets),
                lambda t: probe(t["ip"], t["port"], known_open=t.get("known_open", False)),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["community"] = pr["community"]
                t["sys_name"] = pr.get("sys_name", "")
                t["users"] = len(pr.get("users") or [])
                t["rw_likely"] = pr.get("rw_likely", False)
                h = host_by_ip.get(t["ip"])
                if h is not None:
                    accts = accounts_from_probe(t["ip"], pr)
                    h.accounts = [a for a in h.accounts if a.source != "snmp"] + accts
    # Drop blind targets that answered nothing (keep discovered-open ones for the report).
    targets = [t for t in targets
               if t.get("known_open") or (t["ip"], t["port"]) in probes]
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t.get("community", "public")),
                 "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
