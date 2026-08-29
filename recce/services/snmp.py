"""Deep SNMP enumeration (stdlib only).

SNMP v2c over UDP 161, hand-rolled on a raw socket - BER/ASN.1 with OID encoding, no
pysnmp. Airgapped, stdlib only.

  * **Community brute:** GET sysDescr with a list of common community strings
    (public/private/...) - the first that answers is a readable community.
  * **Walk:** the system group, then GETNEXT walks of the Windows LanManager user
    table, running processes, installed software and interfaces.

Every positive folds into the severity totals, the Vulnerabilities sheet, the
write-ups, a dedicated **SNMP** tab, and the enumerated Windows users become Account
objects that populate Users & Accounts.
"""
from __future__ import annotations

import socket

from ..core.models import Account, Host, Port
from .svccommon import finding_builder

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
_HR_SW_RUN_PARAMS = "1.3.6.1.2.1.25.4.2.1.5"   # process command-line arguments
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


def parse_response(data: bytes, raw: bool = False) -> tuple[int, list[tuple[str, object]]] | None:
    """(error_status, [(oid, value), ...]) from a GetResponse, or None if malformed.

    `raw=True` yields the undecoded (tag, bytes) instead of a decoded value. The
    ARP table returns a MAC as a 6-byte OCTET STRING, and the default decode runs
    OCTET STRING through utf-8/replace - which silently corrupts any byte over
    0x7f, i.e. most MACs.
    """
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
            out.append((decode_oid(oid_b),
                        (vtag, vval) if raw else _decode_value(vtag, vval)))
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
         request_id: int, pdu_tag: int = 0xA0, raw: bool = False):
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
    parsed = parse_response(data, raw=raw)
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


# --- network tables: the reason a read-only community is a pivot ----------------
# The system group tells you what a box IS. These two tell you what it can SEE.
# A readable router hands over the ARP cache and the routing table, which is a map
# of the internal estate - including hosts and whole segments recce has not
# discovered and may not be able to reach directly.
_ARP_PHYS = "1.3.6.1.2.1.4.22.1.2"      # ipNetToMediaPhysAddress: .<ifIndex>.<a.b.c.d> -> MAC
_ROUTE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"  # ipRouteNextHop:  .<dest> -> next hop
_ROUTE_MASK = "1.3.6.1.2.1.4.21.1.11"    # ipRouteMask:     .<dest> -> mask


def _walk_pairs(sock, ip: str, port: int, community: str, base: str, timeout: float,
                start_id: int, cap: int = 512, raw: bool = False) -> list[tuple[str, object]]:
    """GETNEXT walk returning (oid, value) pairs.

    The plain _walk() throws the OID away, which works for a list of user names
    but not for the network tables: ipNetToMediaPhysAddress encodes the IP in the
    OID SUFFIX and carries only the MAC as the value, so discarding the OID loses
    exactly half of each row.
    """
    out: list[tuple[str, object]] = []
    cur = base
    for n in range(cap):
        vb = _get(sock, ip, port, community, cur, timeout, start_id + n, 0xA1, raw=raw)
        if not vb:
            break
        oid, val = vb[0]
        if not (oid == base or oid.startswith(base + ".")):
            break                                          # left the subtree
        if val is None:
            break
        out.append((oid, val))
        cur = oid
    return out


def _suffix_arcs(oid: str, base: str) -> list[int]:
    tail = oid[len(base):].lstrip(".")
    if not tail:
        return []
    try:
        return [int(a) for a in tail.split(".")]
    except ValueError:
        return []


def _fmt_mac(value) -> str:
    """ipNetToMediaPhysAddress is a 6-byte OCTET STRING (tag, raw) pair."""
    if not (isinstance(value, tuple) and len(value) == 2):
        return ""
    tag, blob = value
    if tag != 0x04 or not isinstance(blob, (bytes, bytearray)) or len(blob) != 6:
        return ""
    return ":".join(f"{b:02x}" for b in blob)


def read_arp(sock, ip: str, port: int, community: str, timeout: float,
             start_id: int = 7000, cap: int = 512) -> list[dict]:
    """The ARP cache: every IP this device has recently talked to, plus its MAC."""
    rows = []
    for oid, val in _walk_pairs(sock, ip, port, community, _ARP_PHYS, timeout,
                                start_id, cap, raw=True):
        arcs = _suffix_arcs(oid, _ARP_PHYS)
        if len(arcs) < 5:                       # <ifIndex>.<a>.<b>.<c>.<d>
            continue
        neighbour = ".".join(str(a) for a in arcs[-4:])
        mac = _fmt_mac(val)
        if mac:
            rows.append({"ip": neighbour, "mac": mac, "ifindex": arcs[0]})
    return rows


def read_routes(sock, ip: str, port: int, community: str, timeout: float,
                start_id: int = 8000, cap: int = 512) -> list[dict]:
    """The routing table: destination -> next hop (+ mask), i.e. reachable segments."""
    hops = {}
    for oid, val in _walk_pairs(sock, ip, port, community, _ROUTE_NEXTHOP,
                                timeout, start_id, cap):
        arcs = _suffix_arcs(oid, _ROUTE_NEXTHOP)
        if len(arcs) >= 4 and isinstance(val, str):
            hops[".".join(str(a) for a in arcs[-4:])] = val
    masks = {}
    for oid, val in _walk_pairs(sock, ip, port, community, _ROUTE_MASK,
                                timeout, start_id + cap, cap):
        arcs = _suffix_arcs(oid, _ROUTE_MASK)
        if len(arcs) >= 4 and isinstance(val, str):
            masks[".".join(str(a) for a in arcs[-4:])] = val
    return [{"dest": d, "next_hop": h, "mask": masks.get(d, "")}
            for d, h in sorted(hops.items())]


# ipCidrRouteTable (RFC 2096) supersedes the RFC1213 ipRouteTable that read_routes()
# walks. Modern IOS-XE, Junos, ArubaOS and net-snmp populate CIDR only - the old
# ipRouteTable comes back empty on those, and recce would miss the routing table
# entirely without this fallback. The INDEX is dest.mask.tos.nextHop (13 arcs), so
# walking a single column (ipCidrRouteNextHop) recovers all four fields in one pass.
_CIDR_ROUTE_NH = "1.3.6.1.2.1.4.24.4.1.4"      # ipCidrRouteNextHop


def read_cidr_routes(sock, ip: str, port: int, community: str, timeout: float,
                     start_id: int = 9000, cap: int = 512) -> list[dict]:
    """RFC 2096 routing table. Same shape as read_routes() so downstream code that
    consumes 'routes' does not care which MIB the row came from."""
    out: list[dict] = []
    for oid, val in _walk_pairs(sock, ip, port, community, _CIDR_ROUTE_NH,
                                timeout, start_id, cap):
        arcs = _suffix_arcs(oid, _CIDR_ROUTE_NH)
        # Suffix is dest[4] . mask[4] . tos[1] . nextHop[4] = 13 arcs.
        if len(arcs) < 13 or not isinstance(val, str):
            continue
        dest = ".".join(str(a) for a in arcs[0:4])
        mask = ".".join(str(a) for a in arcs[4:8])
        out.append({"dest": dest, "next_hop": val, "mask": mask})
    return out


# --- SNMPv3 unauthenticated engine discovery (RFC 3411 §5, RFC 3414 §4) ---------
# Sending msgUserName="" with empty authoritative engine fields provokes a Report
# PDU whose msgSecurityParameters carry the agent's real engineID + boots + time.
# Zero credentials required. This is what makes a v3-only agent (which ignores v2c
# GETs entirely) show up as more than "closed" to recce.
_SNMPV3_MSG_MAX = 65507


def build_snmpv3_discovery(msg_id: int) -> bytes:
    """RFC 3414 §4 discovery: v3 header + empty USM security + empty scoped GET."""
    global_data = _tlv(0x30,
                       _int(msg_id) +
                       _int(_SNMPV3_MSG_MAX) +
                       _tlv(0x04, b"\x04") +               # msgFlags: reportable, no auth/priv
                       _int(3))                            # msgSecurityModel = USM
    usm = _tlv(0x30,
               _tlv(0x04, b"") +                           # msgAuthoritativeEngineID
               _int(0) +                                   # msgAuthoritativeEngineBoots
               _int(0) +                                   # msgAuthoritativeEngineTime
               _tlv(0x04, b"") +                           # msgUserName
               _tlv(0x04, b"") +                           # msgAuthenticationParameters
               _tlv(0x04, b""))                            # msgPrivacyParameters
    sec_params = _tlv(0x04, usm)                           # wrapped as OCTET STRING
    scoped = _tlv(0x30,
                  _tlv(0x04, b"") +                        # contextEngineID
                  _tlv(0x04, b"") +                        # contextName
                  _tlv(0xA0, _int(msg_id) + _int(0) + _int(0) + _tlv(0x30, b"")))
    return _tlv(0x30, _int(3) + global_data + sec_params + scoped)


def parse_snmpv3_report(data: bytes) -> dict | None:
    """Pull engineID / boots / time out of a v3 Report response. None if malformed."""
    try:
        _, msg, _ = _parse_tlv(data, 0)
        _, ver_b, i = _parse_tlv(msg, 0)
        version = int.from_bytes(ver_b, "big") if ver_b else 0
        if version != 3:
            return None
        _, _gd, i = _parse_tlv(msg, i)
        _, sec_blob, _ = _parse_tlv(msg, i)                # msgSecurityParameters
        _, usm, _ = _parse_tlv(sec_blob, 0)                # inner USM SEQUENCE
        _, eid, k = _parse_tlv(usm, 0)
        _, boots_b, k = _parse_tlv(usm, k)
        _, time_b, k = _parse_tlv(usm, k)
        return {"engine_id": bytes(eid).hex(),
                "boots": int.from_bytes(boots_b, "big") if boots_b else 0,
                "time": int.from_bytes(time_b, "big") if time_b else 0}
    except (IndexError, ValueError):
        return None


def _decode_engine_id(engine_id_hex: str) -> dict:
    """Best-effort RFC 3411 §5 breakdown. Format byte at offset 4 selects the layout:
    1=IPv4, 2=IPv6, 3=MAC, 4=text, 5=octets. Missing fields => empty strings."""
    out: dict[str, object] = {"enterprise": None, "format": None, "detail": ""}
    try:
        raw = bytes.fromhex(engine_id_hex)
    except ValueError:
        return out
    if len(raw) < 5:
        return out
    # First 4 bytes are the enterprise ID with the high bit of byte 0 set (post-RFC3411).
    ent = ((raw[0] & 0x7F) << 24) | (raw[1] << 16) | (raw[2] << 8) | raw[3]
    fmt = raw[4]
    body = raw[5:]
    out["enterprise"] = ent
    out["format"] = fmt
    if fmt == 1 and len(body) == 4:
        out["detail"] = ".".join(str(b) for b in body)
    elif fmt == 3 and len(body) == 6:
        out["detail"] = ":".join(f"{b:02x}" for b in body)
    elif fmt == 4:
        out["detail"] = body.decode("utf-8", "replace")
    return out


def snmpv3_discover(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
                    msg_id: int = 9999) -> dict | None:
    """RFC 3414 §4 unauthenticated engine discovery. Zero credentials."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(build_snmpv3_discovery(msg_id), (ip, port))
        sock.settimeout(timeout)
        for _ in range(4):
            try:
                data, _addr = sock.recvfrom(65535)
            except (OSError, socket.timeout):
                return None
            info = parse_snmpv3_report(data)
            if info is not None:
                info["engine"] = _decode_engine_id(info["engine_id"])
                return info
        return None
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# Substrings that indicate a cleartext credential passed on the command line.
# Kept intentionally narrow (avoid false positives on generic "-p" for port etc.):
# a match requires "password", explicit env-style KEY=, a known cred tool, or the
# mysql/postgres/redis inline password flag.
_CMDLINE_CRED_MARKERS = (
    "password=", "-password=", "--password=",
    "pgpassword=", "mysql_pwd=",
    "-p'", '-p"',                       # mysql -p'<pw>' / -p"<pw>"
    ":password", "://", "curl -u ", "curl --user ",
    "sshpass -p", "rsyncpassword=",
    "-w ", " --password ", "-p ",       # last two are broad; caller strips known-safe
)


def _cmdline_looks_credful(param: str) -> bool:
    """Heuristic: True iff `param` almost-certainly leaks a secret on argv."""
    if not param:
        return False
    low = param.lower()
    # Only flag "-p " / "-w " / "--password " when the tool that follows is a known
    # DB/cred consumer, otherwise "-p 8080" (port) would fire constantly.
    if "password" in low or "pgpassword=" in low or "sshpass -p" in low:
        return True
    if any(m in low for m in ("mysql -p", "mysqldump -p", "psql ", "redis-cli -a",
                              "curl -u ", "curl --user ", "ftp://", "http://",
                              "https://")):
        # Only credful if the URL/tool actually carries a ':' password segment.
        if "://" in low and "@" in low.split("://", 1)[1].split("/", 1)[0]:
            return True
        if "-a " in low or "-u " in low or "--user " in low or "-p" in low:
            return True
    return False


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
            # No v2c community answered. A v3-only agent still leaks its engineID
            # to an unauthenticated discovery message (RFC 3414 §4) - the same box
            # that returned nothing to sixteen v2c GETs may hand this over gladly.
            v3 = snmpv3_discover(ip, port, timeout)
            if v3 is not None:
                return {"ip": ip, "port": port, "community": None,
                        "rw_likely": False, "sys_descr": "",
                        "v3_engine": v3}
            return None
        out = {"ip": ip, "port": port, "community": community,
               "rw_likely": community in _RW_LIKELY, "sys_descr": sys_descr or ""}
        # v3 discovery runs regardless: many agents accept v2c AND expose v3.
        v3 = snmpv3_discover(ip, port, timeout)
        if v3 is not None:
            out["v3_engine"] = v3
        for key, oid in (("sys_name", _SYS_NAME), ("sys_contact", _SYS_CONTACT),
                         ("sys_location", _SYS_LOCATION)):
            vb = _get(sock, ip, port, community, oid, timeout, 2000)
            out[key] = (vb[0][1] if vb and isinstance(vb[0][1], str) else "") or ""
        out["users"] = _walk(sock, ip, port, community, _LANMGR_USERS, timeout, 3000)
        out["processes"] = _walk(sock, ip, port, community, _HR_SW_RUN, timeout, 4000)[:40]
        out["software"] = _walk(sock, ip, port, community, _HR_SW_INSTALLED, timeout, 5000)[:40]
        out["interfaces"] = _walk(sock, ip, port, community, _IF_DESCR, timeout, 6000)[:20]
        # Network tables last: they are the largest walks, so a budget/timeout cut
        # here still leaves the system + user data already collected above.
        out["arp"] = read_arp(sock, ip, port, community, timeout)[:400]
        out["routes"] = read_routes(sock, ip, port, community, timeout)[:200]
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


_finding = finding_builder("snmp", _NARRATIVE)


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

            # ARP cache. The severity is driven by what it reveals that recce did
            # NOT already have: a neighbour list that only repeats known hosts is
            # disclosure, but one naming unscanned addresses is free discovery of
            # segments the tester may not be able to reach directly.
            arp = pr.get("arp") or []
            if arp:
                known = {x.ip for x in hosts}
                fresh = sorted({r["ip"] for r in arp} - known)
                sample = ", ".join(fresh[:12]) or ", ".join(
                    r["ip"] for r in arp[:12])
                out.append(_finding(
                    "high" if fresh else "medium",
                    "SNMP exposes the ARP cache (internal host discovery)", tgt,
                    f"The ARP table returned {len(arp)} neighbour(s) with MAC addresses."
                    + (f" {len(fresh)} of them are NOT in this engagement's host list: "
                       f"{sample}{'...' if len(fresh) > 12 else ''}. Each is a live host "
                       f"this device has recently talked to - discovery for free, "
                       f"including addresses on segments not directly scanned."
                       if fresh else
                       f" All are already known hosts ({sample}). Still a MAC-address "
                       f"and adjacency disclosure."),
                    "snmpwalk",
                    f"snmpwalk -v2c -c {pr['community']} {ip} {_ARP_PHYS}",
                    "Restrict the SNMP view so the network tables (RFC1213 ip group) "
                    "are not world-readable; move to SNMPv3.",
                    ["CWE-200"], kind="snmp_arp"))

            routes = pr.get("routes") or []
            if routes:
                gws = sorted({r["next_hop"] for r in routes
                              if r["next_hop"] not in ("0.0.0.0", "")})
                nets = ", ".join(
                    f"{r['dest']}{'/' + r['mask'] if r['mask'] else ''}"
                    for r in routes[:10])
                out.append(_finding(
                    "medium",
                    "SNMP exposes the routing table (internal network map)", tgt,
                    f"The routing table returned {len(routes)} route(s) across "
                    f"{len(gws)} gateway(s): {nets}{'...' if len(routes) > 10 else ''}. "
                    f"This is the internal topology - which subnets exist, which are "
                    f"routed from here, and the gateways that reach them. On an "
                    f"internal it names scope the tester has not yet seen.",
                    "snmpwalk",
                    f"snmpwalk -v2c -c {pr['community']} {ip} {_ROUTE_NEXTHOP}",
                    "Restrict the SNMP view so the ip route group is not readable; "
                    "move to SNMPv3.",
                    ["CWE-200"], kind="snmp_routes"))
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
    from ..services.db import mssql
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
