"""BGP (179/tcp) OPEN probe — routing-plane fingerprint & disclosure.

BGP is rare on pure enterprise segments but common at colo/edge/DC-fabric
boundaries (iBGP mesh, MikroTik/OpenBSD/FRR test rigs, mis-segmented ToR
peering). An OPEN message is a rich passive disclosure: peer AS, BGP
version, hold-time, Router-ID (a real routable IPv4 on the peer), and the
capability set (MP-BGP AFI/SAFI, 4-byte AS, Route Refresh, Graceful
Restart, LLGR, BGPsec). A NOTIFICATION reply to a spoofed OPEN itself
leaks configuration — 'Bad Peer AS' commonly carries the expected local
AS, 'Bad BGP Identifier' hints at strict-neighbor config, 'Unsupported
Version' returns the peer's version ceiling.

Findings:
  * bgp_reachable (HIGH) — routing daemon on a scanned host.
  * bgp_no_neighbor_auth (HIGH) — session establishment did not require
    TCP-MD5 / TCP-AO / GTSM at the transport layer.
  * bgp_expected_as_disclosed (HIGH) — 'Bad Peer AS' NOTIFICATION carried
    the peer's configured neighbor AS.
  * bgp_peer_id (MEDIUM) — peer identification: AS, version, hold-time,
    Router-ID, capabilities.
  * bgp_router_id_pivot (MEDIUM) — Router-ID reveals another host address.
  * bgp_capabilities / bgp_afi_safi / bgp_graceful_restart /
    bgp_route_refresh (info) — stack + role fingerprint.
  * bgp_notification_leak (MEDIUM) — parsed NOTIFICATION disclosure.
  * bgp_md5_hint (LOW) — best-effort transport-auth requirement inference.
  * bgp_version_probe (LOW) — version-ceiling extraction.

Airgap-safe: stdlib socket + struct only. Bounded round-trips per host,
2-6 s timeouts, read-only (never writes UPDATEs).
"""
from __future__ import annotations

import socket
import struct

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 179
_TIMEOUT = 4.0

_MARKER = b"\xff" * 16
_HDR_LEN = 19
_MAX_MSG = 4096

_TYPE_OPEN = 1
_TYPE_UPDATE = 2
_TYPE_NOTIFICATION = 3
_TYPE_KEEPALIVE = 4
_TYPE_ROUTE_REFRESH = 5

# Optional Parameter type carrying capability triples (RFC 5492).
_OPT_PARM_CAPABILITY = 2

# Capability codes (IANA — subset we recognise by name).
_CAP_MP_BGP = 1
_CAP_ROUTE_REFRESH = 2
_CAP_EXTENDED_NEXT_HOP = 5
_CAP_BGPSEC = 45
_CAP_GRACEFUL_RESTART = 64
_CAP_FOUR_OCTET_AS = 65
_CAP_ENHANCED_RR = 70
_CAP_LLGR = 71

_CAP_NAMES = {
    1: "MP-BGP (multiprotocol AFI/SAFI, RFC 4760)",
    2: "Route Refresh (RFC 2918)",
    5: "Extended Next Hop Encoding (RFC 8950)",
    45: "BGPsec (RFC 8205)",
    64: "Graceful Restart (RFC 4724)",
    65: "4-octet AS Number (RFC 6793)",
    70: "Enhanced Route Refresh (RFC 7313)",
    71: "Long-Lived Graceful Restart",
}

# NOTIFICATION error codes / subcodes we decode (RFC 4271 sec. 4.5, 6; RFC 4486).
_NOTIF_CODES = {
    1: "Message Header Error",
    2: "OPEN Message Error",
    3: "UPDATE Message Error",
    4: "Hold Timer Expired",
    5: "Finite State Machine Error",
    6: "Cease",
    7: "ROUTE-REFRESH Message Error",
}

_NOTIF_OPEN_SUBCODES = {
    1: "Unsupported Version Number",
    2: "Bad Peer AS",
    3: "Bad BGP Identifier",
    4: "Unsupported Optional Parameter",
    5: "Authentication Failure (deprecated)",
    6: "Unacceptable Hold Time",
    7: "Unsupported Capability",
    11: "Role Mismatch",
}

_NOTIF_CEASE_SUBCODES = {
    1: "Maximum Number of Prefixes Reached",
    2: "Administrative Shutdown",
    3: "Peer De-configured",
    4: "Administrative Reset",
    5: "Connection Rejected",
    6: "Other Configuration Change",
    7: "Connection Collision Resolution",
    8: "Out of Resources",
    9: "Hard Reset",
    10: "BFD Down",
}

# AFI/SAFI names (subset — enough to name role) per IANA.
_AFI = {1: "IPv4", 2: "IPv6", 25: "L2VPN"}
_SAFI = {
    1: "unicast", 2: "multicast", 4: "MPLS labels",
    65: "VPLS", 70: "EVPN", 128: "MPLS-VPN unicast",
    129: "MPLS-VPN multicast", 132: "route-target constrain",
}


def is_bgp(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 179
            or "bgp" in svc or "border gateway" in prod or "bgp" in prod)


def _ip_to_int(ip: str) -> int:
    return struct.unpack(">I", socket.inet_aton(ip))[0]


def _int_to_ip(n: int) -> str:
    return socket.inet_ntoa(struct.pack(">I", n))


def _build_header(msg_type: int, body_len: int) -> bytes:
    total = _HDR_LEN + body_len
    return _MARKER + struct.pack(">HB", total, msg_type)


def _encode_capabilities(caps: list[tuple[int, bytes]]) -> bytes:
    """Wrap (code, value) capability triples as a single Optional Parameter
    (type 2, RFC 5492)."""
    inner = b""
    for code, value in caps:
        inner += struct.pack(">BB", code, len(value)) + value
    if not inner:
        return b""
    return struct.pack(">BB", _OPT_PARM_CAPABILITY, len(inner)) + inner


def _default_capabilities(my_as: int) -> list[tuple[int, bytes]]:
    """A minimal, realistic capability set — 4-octet AS + IPv4 unicast
    MP-BGP + route refresh. Advertising these makes the peer treat us as a
    modern speaker instead of dropping the session as unsupported."""
    four_as = struct.pack(">I", my_as if my_as > 0 else 0)
    mp_ipv4 = struct.pack(">HBB", 1, 0, 1)              # AFI 1 (IPv4), SAFI 1 (unicast)
    return [
        (_CAP_MP_BGP, mp_ipv4),
        (_CAP_ROUTE_REFRESH, b""),
        (_CAP_FOUR_OCTET_AS, four_as),
    ]


def _build_open(my_as: int, hold_time: int = 180,
                router_id: str = "192.0.2.1", version: int = 4,
                capabilities: list[tuple[int, bytes]] | None = None) -> bytes:
    """Well-formed BGP OPEN. `my_as` above 65535 is advertised as
    AS_TRANS (23456) in the 2-byte field per RFC 6793 sec. 4."""
    caps = _default_capabilities(my_as) if capabilities is None else capabilities
    opt = _encode_capabilities(caps)
    as2 = my_as if 0 < my_as < 65536 else 23456
    rid = _ip_to_int(router_id) if isinstance(router_id, str) else int(router_id)
    body = struct.pack(">BHHIB", version, as2, hold_time, rid, len(opt)) + opt
    return _build_header(_TYPE_OPEN, len(body)) + body


def _parse_header(data: bytes) -> dict | None:
    """Parse marker + length + type. Returns None on malformed frames."""
    if len(data) < _HDR_LEN:
        return None
    if data[:16] != _MARKER:
        return None
    length, msg_type = struct.unpack(">HB", data[16:19])
    if length < _HDR_LEN or length > _MAX_MSG:
        return None
    if msg_type < 1 or msg_type > 5:
        return None
    return {"length": length, "type": msg_type}


def _parse_capabilities(opt_params: bytes) -> list[dict]:
    """Walk RFC 5492 Optional Parameters (type 2 = capability), return
    [{code, name, value}] triples in on-the-wire order."""
    out: list[dict] = []
    i = 0
    while i + 2 <= len(opt_params):
        ptype = opt_params[i]
        plen = opt_params[i + 1]
        i += 2
        if i + plen > len(opt_params):
            break
        pval = opt_params[i:i + plen]
        i += plen
        if ptype != _OPT_PARM_CAPABILITY:
            continue
        j = 0
        while j + 2 <= len(pval):
            code = pval[j]
            clen = pval[j + 1]
            j += 2
            if j + clen > len(pval):
                break
            out.append({
                "code": code,
                "name": _CAP_NAMES.get(code, f"unknown ({code})"),
                "value": pval[j:j + clen],
            })
            j += clen
    return out


def _parse_mp_bgp(value: bytes) -> tuple[int, int, str, str] | None:
    """MP-BGP capability payload: AFI(2) reserved(1) SAFI(1) — RFC 4760."""
    if len(value) < 4:
        return None
    afi, _res, safi = struct.unpack(">HBB", value[:4])
    return afi, safi, _AFI.get(afi, f"AFI-{afi}"), _SAFI.get(safi, f"SAFI-{safi}")


def _parse_graceful_restart(value: bytes) -> dict | None:
    """Graceful Restart payload: flags(4b)+time(12b), then per-AFI/SAFI
    (AFI(2) SAFI(1) flags(1)) — RFC 4724 sec. 3."""
    if len(value) < 2:
        return None
    hdr = struct.unpack(">H", value[:2])[0]
    flags = (hdr >> 12) & 0xF
    restart_time = hdr & 0x0FFF
    afs: list[dict] = []
    i = 2
    while i + 4 <= len(value):
        afi, safi, af_flags = struct.unpack(">HBB", value[i:i + 4])
        afs.append({
            "afi": afi, "safi": safi,
            "afi_name": _AFI.get(afi, f"AFI-{afi}"),
            "safi_name": _SAFI.get(safi, f"SAFI-{safi}"),
            "forwarding_preserved": bool(af_flags & 0x80),
        })
        i += 4
    return {
        "restart_flags": flags,
        "restart_state": bool(flags & 0x8),
        "restart_time": restart_time,
        "address_families": afs,
    }


def _parse_open(body: bytes) -> dict | None:
    if len(body) < 10:
        return None
    version, as2, hold_time, router_id_int, opt_len = struct.unpack(">BHHIB", body[:10])
    if 10 + opt_len > len(body):
        return None
    opt_params = body[10:10 + opt_len]
    caps = _parse_capabilities(opt_params)
    asn = as2
    afi_safis: list[dict] = []
    gr: dict | None = None
    for c in caps:
        if c["code"] == _CAP_FOUR_OCTET_AS and len(c["value"]) == 4:
            asn = struct.unpack(">I", c["value"])[0]
        elif c["code"] == _CAP_MP_BGP:
            parsed = _parse_mp_bgp(c["value"])
            if parsed:
                afi, safi, afi_name, safi_name = parsed
                afi_safis.append({"afi": afi, "safi": safi,
                                  "afi_name": afi_name, "safi_name": safi_name})
        elif c["code"] == _CAP_GRACEFUL_RESTART:
            gr = _parse_graceful_restart(c["value"])
    return {
        "version": version,
        "asn": asn,
        "asn2": as2,                     # raw 2-byte AS field (AS_TRANS if 4-octet AS used)
        "hold_time": hold_time,
        "router_id": _int_to_ip(router_id_int),
        "capabilities": caps,
        "afi_safis": afi_safis,
        "graceful_restart": gr,
        "has_route_refresh": any(c["code"] in (_CAP_ROUTE_REFRESH, _CAP_ENHANCED_RR)
                                 for c in caps),
        "has_4byte_as": any(c["code"] == _CAP_FOUR_OCTET_AS for c in caps),
    }


def _subcode_name(code: int, subcode: int) -> str:
    if code == 2:
        return _NOTIF_OPEN_SUBCODES.get(subcode, f"subcode {subcode}")
    if code == 6:
        return _NOTIF_CEASE_SUBCODES.get(subcode, f"subcode {subcode}")
    return f"subcode {subcode}"


def _parse_notification(body: bytes) -> dict | None:
    if len(body) < 2:
        return None
    code, subcode = body[0], body[1]
    data = body[2:]
    disclosed = ""
    if code == 2 and subcode == 1 and len(data) >= 2:
        disclosed = f"peer max version = {struct.unpack('>H', data[:2])[0]}"
    elif code == 2 and subcode == 2 and len(data) >= 2:
        # RFC 4271 sec. 6.2: "The Data field is a 2-octet unsigned integer
        # that indicates the expected AS number." Newer speakers may
        # instead carry the 4-octet AS.
        if len(data) >= 4:
            disclosed = f"expected AS = {struct.unpack('>I', data[:4])[0]}"
        else:
            disclosed = f"expected AS = {struct.unpack('>H', data[:2])[0]}"
    elif code == 2 and subcode == 3 and len(data) >= 4:
        disclosed = f"expected BGP Identifier = {_int_to_ip(struct.unpack('>I', data[:4])[0])}"
    return {
        "code": code,
        "subcode": subcode,
        "code_name": _NOTIF_CODES.get(code, f"code {code}"),
        "subcode_name": _subcode_name(code, subcode),
        "data": data,
        "disclosed": disclosed,
    }


def _recv_message(sock: socket.socket, timeout: float) -> tuple[dict | None, bytes]:
    """Read one BGP message off `sock`. Returns (header_dict|None, full_bytes)."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < _HDR_LEN:
            chunk = sock.recv(4096)
            if not chunk:
                return None, buf
            buf += chunk
        hdr = _parse_header(buf[:_HDR_LEN])
        if not hdr:
            return None, buf
        while len(buf) < hdr["length"]:
            chunk = sock.recv(4096)
            if not chunk:
                return None, buf
            buf += chunk
        return hdr, buf[:hdr["length"]]
    except (socket.timeout, OSError):
        return None, buf


def _single_open(ip: str, port: int, my_as: int, timeout: float,
                 hold_time: int = 180, router_id: str = "192.0.2.1",
                 version: int = 4) -> dict:
    """One connect + OPEN send + read. Returns:
      {tcp_ok, wrote_open, peer_reply_kind, header, open, notification,
       peer_rst, error}
    peer_reply_kind: '' | 'open' | 'notification' | 'other' | 'silent'
    """
    out = {
        "tcp_ok": False, "wrote_open": False, "peer_reply_kind": "",
        "header": None, "open": None, "notification": None,
        "peer_rst": False, "error": "",
    }
    try:
        with socket.create_connection((ip, port), timeout=proxy.scaled(timeout)) as s:
            out["tcp_ok"] = True
            msg = _build_open(my_as, hold_time=hold_time, router_id=router_id,
                              version=version)
            try:
                s.sendall(msg)
                out["wrote_open"] = True
            except OSError as e:
                out["error"] = f"send: {e!r}"
                return out
            hdr, raw = _recv_message(s, proxy.scaled(timeout))
            if hdr is None:
                # No parseable frame — differentiate silent close/RST from
                # timeout by looking at the buffer we did receive.
                if not raw:
                    out["peer_reply_kind"] = "silent"
                    out["peer_rst"] = True
                else:
                    out["peer_reply_kind"] = "other"
                return out
            out["header"] = hdr
            body = raw[_HDR_LEN:]
            if hdr["type"] == _TYPE_OPEN:
                out["peer_reply_kind"] = "open"
                out["open"] = _parse_open(body)
            elif hdr["type"] == _TYPE_NOTIFICATION:
                out["peer_reply_kind"] = "notification"
                out["notification"] = _parse_notification(body)
            else:
                out["peer_reply_kind"] = "other"
    except OSError as e:
        out["error"] = f"connect: {e!r}"
    return out


# Candidate My-AS values for peer-AS enumeration. Ordered: an obviously
# wrong high private AS first (forces a 'Bad Peer AS' from a peer that has
# configured neighbor-AS at all), then RFC 6996 private-use, plus RFC 5398
# documentation AS. Bounded to <=6 tries per host.
_AS_CANDIDATES = (65001, 64512, 65534, 64496, 4200000000, 1)


def as_enumerate(ip: str, port: int = _DEFAULT_PORT,
                 timeout: float = _TIMEOUT,
                 candidates=_AS_CANDIDATES) -> dict:
    """Iterate candidate My-AS values. Returns:
      {tried: [int], expected_as: int|None, notification: dict|None,
       matching_my_as: int|None}
    The FIRST 'Bad Peer AS' NOTIFICATION whose data field decodes to a
    plausible AS wins."""
    out: dict = {"tried": [], "expected_as": None, "notification": None,
                 "matching_my_as": None}
    for my_as in candidates:
        out["tried"].append(my_as)
        r = _single_open(ip, port, my_as=my_as, timeout=timeout)
        n = r.get("notification")
        if r["peer_reply_kind"] == "open":
            # A successful OPEN means we happened to match — record the peer's
            # own AS (extracted from its OPEN) as the expected value.
            op = r["open"] or {}
            if op.get("asn"):
                out["expected_as"] = op["asn"]
                out["matching_my_as"] = my_as
            return out
        if not n:
            continue
        if n["code"] == 2 and n["subcode"] == 2:
            data = n["data"]
            if len(data) >= 4:
                out["expected_as"] = struct.unpack(">I", data[:4])[0]
            elif len(data) >= 2:
                out["expected_as"] = struct.unpack(">H", data[:2])[0]
            out["notification"] = n
            out["matching_my_as"] = my_as
            return out
    return out


def version_probe(ip: str, port: int = _DEFAULT_PORT,
                  timeout: float = _TIMEOUT) -> dict:
    """Send OPEN with version=5 (invalid). A well-behaved peer replies
    NOTIFICATION 2/1 'Unsupported Version' with a 2-byte data field
    holding its max supported version — RFC 4271 sec. 6.2."""
    out: dict = {"peer_max_version": None, "notification": None}
    r = _single_open(ip, port, my_as=65001, timeout=timeout, version=5)
    n = r.get("notification")
    if n and n["code"] == 2 and n["subcode"] == 1 and len(n["data"]) >= 2:
        out["peer_max_version"] = struct.unpack(">H", n["data"][:2])[0]
        out["notification"] = n
    return out


# --- T2 SAFE evidence: hijack-readiness proof via disclosed AS ---------------
# T1 signal for bgp_expected_as_disclosed is "peer NOTIFICATION 2/2 carried the
# configured expected local AS". T2 wants concrete server-side evidence in the
# finding output: a controlled re-OPEN with that expected AS + the peer's own
# AS pair, capturing the peer's REAL OPEN reply. If the peer replies its own
# OPEN, the session progressed to OpenConfirm (RFC 4271 sec. 8.2.2) — the
# session WOULD establish with a legitimate My-AS. Non-destructive: recce
# never sends KEEPALIVE, so the peer's FSM times out on OpenConfirm and drops
# the session; the RIB is untouched. Single controlled round-trip, timeout
# clamped to 2-6s (proxy.scaled inside _single_open). No writes, no state
# change to the RIB.
_T2_EVIDENCE_TIMEOUT_MIN = 2.0
_T2_EVIDENCE_TIMEOUT_MAX = 6.0


def _t2_bounded_timeout(timeout: float) -> float:
    """Clamp base timeout to 2-6s. _single_open applies proxy.scaled itself,
    so we clamp only — never pre-scale (would double-scale on proxy)."""
    return max(_T2_EVIDENCE_TIMEOUT_MIN, min(_T2_EVIDENCE_TIMEOUT_MAX, timeout))


def capture_hijack_ready_evidence(ip: str, port: int, expected_as: int,
                                  timeout: float = _TIMEOUT,
                                  router_id: str = "192.0.2.1") -> dict | None:
    """T2 SAFE proof: one controlled OPEN using the disclosed expected-AS.

    Returns {'peer_reply_kind': 'open', 'peer_asn', 'peer_router_id',
             'peer_version', 'peer_hold_time', 'my_as_used'} when the peer
    answers with its own OPEN — deterministic evidence the session WOULD
    establish for a legitimate peer-AS/local-AS pair (progresses to
    OpenConfirm per RFC 4271 sec. 8.2.2). Returns None on any non-OPEN reply
    (NOTIFICATION / silent / RST / timeout / socket error) — the T1 finding
    then stays T1. No UPDATE, no KEEPALIVE: the peer's FSM times out on
    OpenConfirm and drops the session — the RIB is not modified.
    """
    # Reject implausible AS values — a 0 or over-max AS in the NOTIFICATION
    # data would be a parse artefact, not a real configured value.
    if not isinstance(expected_as, int) or expected_as < 1 or expected_as > 0xFFFFFFFF:
        return None
    try:
        r = _single_open(ip, port, my_as=expected_as,
                         timeout=_t2_bounded_timeout(timeout),
                         router_id=router_id)
    except OSError:
        return None
    if not r or r.get("peer_reply_kind") != "open":
        return None
    op = r.get("open") or {}
    if not op:
        return None
    return {
        "peer_reply_kind": "open",
        "peer_asn": op.get("asn"),
        "peer_router_id": op.get("router_id"),
        "peer_version": op.get("version"),
        "peer_hold_time": op.get("hold_time"),
        "my_as_used": expected_as,
    }


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          my_as: int = 65001, router_id: str = "192.0.2.1") -> dict:
    """Primary probe: one BGP OPEN, capture the peer's reply, then a
    best-effort NOTIFICATION-driven expected-AS enumeration and a version
    probe if the first exchange didn't already surface those signals.

    Returns:
      {reachable, tcp_ok, peer_reply_kind, open, notification,
       expected_as, expected_as_my_as, peer_max_version, md5_hint}
    reachable = a parseable BGP frame came back (OPEN or NOTIFICATION);
    tcp_ok    = TCP handshake succeeded even if the BGP layer said nothing.
    """
    out: dict = {
        "reachable": False, "tcp_ok": False,
        "peer_reply_kind": "", "open": None, "notification": None,
        "expected_as": None, "expected_as_my_as": None,
        "peer_max_version": None, "md5_hint": False,
        "hijack_ready_evidence": None,
    }
    r = _single_open(ip, port, my_as=my_as, timeout=timeout,
                     router_id=router_id)
    out["tcp_ok"] = r["tcp_ok"]
    out["peer_reply_kind"] = r["peer_reply_kind"]
    out["open"] = r["open"]
    out["notification"] = r["notification"]
    if r["peer_reply_kind"] in ("open", "notification"):
        out["reachable"] = True
    # MD5 requirement hint: TCP handshake succeeded but the BGP layer
    # produced NO parseable frame (silent drop or RST immediately after
    # our OPEN). RFC 2385 / RFC 5925 rejection is one plausible cause
    # (also plain ACL mismatch) — record as a hint, not a hard claim.
    if r["tcp_ok"] and r["peer_reply_kind"] in ("silent", "other"):
        out["md5_hint"] = True
    # If the first OPEN already gave us a NOTIFICATION 'Bad Peer AS', we
    # have the expected AS without further round-trips.
    n = out["notification"]
    if n and n["code"] == 2 and n["subcode"] == 2:
        data = n["data"]
        if len(data) >= 4:
            out["expected_as"] = struct.unpack(">I", data[:4])[0]
        elif len(data) >= 2:
            out["expected_as"] = struct.unpack(">H", data[:2])[0]
        out["expected_as_my_as"] = my_as
    elif out["tcp_ok"] and out["reachable"] and out["expected_as"] is None:
        # Only sweep the small candidate list when the first probe reached
        # BGP at all — sweeping a silent port is just wasted round-trips.
        enum = as_enumerate(ip, port, timeout=timeout)
        if enum.get("expected_as"):
            out["expected_as"] = enum["expected_as"]
            out["expected_as_my_as"] = enum["matching_my_as"]
    # Version-ceiling probe: only fire when we've established the peer
    # speaks BGP but haven't yet observed its version-error handler.
    if out["reachable"] and out["peer_max_version"] is None:
        try:
            vp = version_probe(ip, port, timeout=timeout)
            if vp.get("peer_max_version"):
                out["peer_max_version"] = vp["peer_max_version"]
        except OSError:
            pass
    # T2 SAFE evidence capture: only when the peer disclosed an expected AS
    # via NOTIFICATION (i.e. the first probe did NOT already get a full OPEN
    # back). One controlled re-OPEN using that AS; if the peer replies its
    # own OPEN, session-hijack-readiness is proven with captured server-side
    # evidence in the finding output. No writes, no state change to the RIB.
    if (out["expected_as"]
            and out["peer_reply_kind"] != "open"
            and out["hijack_ready_evidence"] is None):
        try:
            ev = capture_hijack_ready_evidence(
                ip, port, out["expected_as"], timeout=timeout,
                router_id=router_id)
            if ev is not None:
                out["hijack_ready_evidence"] = ev
        except OSError:
            pass
    return out


def bgp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_bgp(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "bgp", "command": cmd, "remediation": rem, "cwes": cwes,
            "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def _cap_summary(caps: list[dict]) -> str:
    if not caps:
        return "(none advertised)"
    parts = []
    for c in caps:
        parts.append(f"{c['code']} {c['name'].split(' (')[0]}")
    return ", ".join(parts)


def _afi_safi_summary(afs: list[dict]) -> str:
    if not afs:
        return ""
    return ", ".join(f"{a['afi']}/{a['safi']} {a['afi_name']} {a['safi_name']}"
                     for a in afs)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_bgp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            if not pr.get("reachable"):
                if pr.get("md5_hint"):
                    out.append(_finding(
                        "low",
                        "BGP peer accepted TCP but did not reply to OPEN "
                        "(possible TCP-MD5 / ACL requirement)", tgt,
                        "TCP handshake to 179 completed, but the peer produced "
                        "no parseable BGP frame in response to a well-formed "
                        "OPEN — silent drop or immediate RST. RFC 2385 TCP-MD5, "
                        "RFC 5925 TCP-AO, or a plain source-address ACL are all "
                        "plausible causes; recce cannot disambiguate from user "
                        "space (raw sockets required). Treat as a hint.",
                        f"tcpdump -ni any host {h.ip} and tcp port {p.portid}",
                        "If TCP-MD5 / TCP-AO is required, add the neighbor "
                        "password on both peers. If the ACL should permit this "
                        "source, correct the neighbor statement.",
                        ["CWE-306"], kind="bgp_md5_hint",
                        exploit_note=(
                            "sudo tcpdump -ni any 'host <ip> and tcp port "
                            "179'; retry with 'ip xfrm policy' + TCP-MD5 "
                            "configured to disambiguate."),
                        depth_tier="t0"))
                continue

            op = pr.get("open") or {}
            n = pr.get("notification")

            # bgp_reachable — the primary finding.
            role_hint = ""
            afs = _afi_safi_summary(op.get("afi_safis") or [])
            if afs:
                role_hint = f" AFI/SAFI: {afs}."
            out.append(_finding(
                "high" if op else "medium",
                "BGP speaker reachable on TCP/179", tgt,
                f"Sent a BGP OPEN (version=4, my_as=65001, hold=180) and "
                f"received a valid {pr.get('peer_reply_kind','?').upper()} "
                f"reply. A BGP speaker reachable from a scanning host is a "
                f"segmentation exposure — the routing plane belongs on an "
                f"isolated infra network. Peer AS={op.get('asn','?')} "
                f"version={op.get('version','?')} hold_time={op.get('hold_time','?')} "
                f"Router-ID={op.get('router_id','?')}." + role_hint,
                f"nmap --script bgp-info -p {p.portid} {h.ip}",
                "Filter TCP/179 at the edge — BGP peering should only be "
                "reachable from configured neighbor addresses. Enforce GTSM "
                "(RFC 5082 TTL=255) and TCP-MD5 (RFC 2385) or TCP-AO "
                "(RFC 5925) on every eBGP session.",
                ["CWE-284", "CWE-306"], kind="bgp_reachable",
                exploit_note=(
                    "nmap --script bgp-info -p 179 <ip>; then correlate peer "
                    "AS with whois -h whois.arin.net 'a AS<n>' for ownership."
                ),
                depth_tier="t0"))

            # bgp_no_neighbor_auth — session establishment did not require
            # transport-layer authentication.
            if pr.get("peer_reply_kind") == "open":
                out.append(_finding(
                    "high",
                    "BGP peer accepts unauthenticated OPEN "
                    "(no TCP-MD5 / TCP-AO / GTSM enforcement)", tgt,
                    "The peer replied with its own OPEN — session "
                    "establishment did NOT require RFC 2385 TCP-MD5, "
                    "RFC 5925 TCP-AO, or an RFC 5082 GTSM TTL check at the "
                    "transport / IP layer. An internet-facing or "
                    "cross-tenant BGP speaker that will proceed with an "
                    "unauthenticated peer is a session-hijack risk: an "
                    "on-path attacker can inject or blackhole prefixes.",
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Require TCP-MD5 (RFC 2385) or TCP-AO (RFC 5925) on "
                    "every eBGP session. Enforce GTSM (TTL=255) between "
                    "single-hop peers. Move iBGP off any segment reachable "
                    "from tenants / users.",
                    ["CWE-306", "CWE-923"], kind="bgp_no_neighbor_auth",
                    exploit_note=(
                        "exabgp with 'neighbor <ip> {local-as <expected>; "
                        "peer-as <peer_asn>; router-id 192.0.2.1; family "
                        "{inet unicast;} static { route 198.51.100.0/32 "
                        "next-hop self; }}' — verify at looking-glass; do NOT "
                        "run without written ROE."
                    ),
                    depth_tier="t1"))

            # bgp_peer_id — parsed OPEN disclosure.
            if op:
                out.append(_finding(
                    "medium",
                    "BGP peer identification extracted "
                    "(AS, version, hold-time, Router-ID, capabilities)", tgt,
                    f"peer_as={op.get('asn')} version={op.get('version')} "
                    f"hold_time={op.get('hold_time')} "
                    f"router_id={op.get('router_id')!r} "
                    f"as2_field={op.get('asn2')} "
                    f"4byte_as_cap={op.get('has_4byte_as')} "
                    f"caps=[{_cap_summary(op.get('capabilities') or [])}]. "
                    "This is stable ownership + role fingerprint (RFC 4271 "
                    "sec. 4.2; RFC 6793 for the 4-octet AS capability).",
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Informational — pairs with bgp_reachable.",
                    ["CWE-200"], kind="bgp_peer_id",
                    exploit_note=(
                        "whois -h whois.arin.net 'a AS<peer_asn>'; check "
                        "bgp.tools/<peer_asn> for peering graph."),
                    depth_tier="t0"))

            # bgp_router_id_pivot — new host address from Router-ID.
            router_id = (op.get("router_id") or "").strip()
            if router_id and router_id != h.ip and not router_id.startswith("0."):
                out.append(_finding(
                    "medium",
                    "BGP Router-ID reveals additional host address "
                    "(management / loopback IP)", tgt,
                    f"The peer's BGP Identifier is {router_id}, distinct "
                    f"from the interface we connected to ({h.ip}). This is "
                    f"almost always a real routable address on the peer "
                    f"(typically a loopback used as the router's canonical "
                    f"management IP). Enqueue it as a new scan target.",
                    f"nmap -Pn -sS -p- {router_id}",
                    "Ensure loopback / management interfaces of routing "
                    "infrastructure are on a dedicated management network "
                    "unreachable from tenant segments.",
                    ["CWE-200"], kind="bgp_router_id_pivot",
                    exploit_note=(
                        "nmap -Pn -sS -p- <router_id>; then nxc ssh "
                        "<router_id> -u 'admin,cisco,root' -p "
                        "'admin,cisco,Cisco123,<vendor-defaults>'."),
                    depth_tier="t0"))

            # bgp_capabilities — one info finding summarising the set.
            caps = op.get("capabilities") or []
            if caps:
                out.append(_finding(
                    "info",
                    "BGP capabilities enumerated", tgt,
                    "Advertised capabilities: "
                    + "; ".join(f"code {c['code']} — {c['name']}" for c in caps),
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Informational — narrows product/vendor fingerprint.",
                    [], kind="bgp_capabilities",
                    exploit_note=(
                        "nmap --script bgp-info -p 179 <ip>; compare cap "
                        "set against vendor stacks (Cisco IOS-XR advertises "
                        "Enhanced Route Refresh; FRR advertises LLGR)."),
                    depth_tier="t0"))

            # bgp_afi_safi — role tag (edge vs PE vs EVPN leaf).
            if op.get("afi_safis"):
                out.append(_finding(
                    "info",
                    "BGP MP-BGP AFI/SAFI list enumerated", tgt,
                    f"Address families: {_afi_safi_summary(op['afi_safis'])}. "
                    "An EVPN or L3VPN AFI here says 'this is a PE / DC "
                    "fabric leaf', not an edge router.",
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Informational — role fingerprint for the graph.",
                    ["CWE-200"], kind="bgp_afi_safi",
                    exploit_note=(
                        "nmap --script bgp-info -p 179 <ip>; if EVPN "
                        "present, scan for L2/L3 tenant boundary bypass "
                        "with e.g. VXLAN scanner."),
                    depth_tier="t0"))

            # bgp_graceful_restart — production-vs-lab hint.
            gr = op.get("graceful_restart")
            if gr:
                out.append(_finding(
                    "info",
                    "BGP Graceful Restart advertised", tgt,
                    f"restart_flags={gr['restart_flags']:#x} "
                    f"restart_state={gr['restart_state']} "
                    f"restart_time={gr['restart_time']}s "
                    f"address_families={gr['address_families']}. "
                    "A non-zero Restart Time is a strong hint the peer is "
                    "production infrastructure rather than a lab rig.",
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Informational.",
                    [], kind="bgp_graceful_restart",
                    exploit_note=(
                        "nmap --script bgp-info -p 179 <ip>  # note "
                        "restart_time; large value = production."),
                    depth_tier="t0"))

            # bgp_route_refresh — fingerprint.
            if op.get("has_route_refresh"):
                out.append(_finding(
                    "info",
                    "BGP Route Refresh capability advertised", tgt,
                    "Peer advertises RFC 2918 Route Refresh (or RFC 7313 "
                    "Enhanced Route Refresh). Common on all modern stacks "
                    "— absence would itself be a fingerprint of very old "
                    "code.",
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Informational.",
                    [], kind="bgp_route_refresh",
                    exploit_note="nmap --script bgp-info -p 179 <ip>.",
                    depth_tier="t0"))

            # bgp_notification_leak — decoded NOTIFICATION disclosure.
            if n:
                disc = f" — {n['disclosed']}" if n.get("disclosed") else ""
                out.append(_finding(
                    "medium",
                    "BGP NOTIFICATION reply leaked peer configuration", tgt,
                    f"Peer replied NOTIFICATION code {n['code']} "
                    f"({n['code_name']}) subcode {n['subcode']} "
                    f"({n['subcode_name']}){disc}. Per RFC 4271 sec. 6.2 the "
                    "NOTIFICATION data field is populated with the "
                    "configured expected value — the peer discloses what "
                    "our OPEN got wrong.",
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Consider whether the NOTIFICATION data payload needs "
                    "to be populated on eBGP sessions with untrusted peers "
                    "(some implementations allow suppressing it).",
                    ["CWE-209", "CWE-200"], kind="bgp_notification_leak",
                    exploit_note=(
                        "Parse leaked value from finding; use in "
                        "bgp_expected_as_disclosed follow-up."),
                    # P0-1: T2 promotion — the NOTIFICATION reply carries a
                    # parsed code/subcode/disclosed payload extracted from
                    # the target's own protocol message (RFC 4271 §6.2). The
                    # `disclosed` value IS the server-side evidence.
                    depth_tier="t2"))

            # bgp_expected_as_disclosed — peer's configured neighbor AS.
            if pr.get("expected_as"):
                # T2 promotion: if a controlled re-OPEN with the disclosed AS
                # produced a full OPEN reply, we have concrete evidence the
                # session WOULD establish — attach it to the finding output
                # and lift depth_tier from t1 to t2.
                ev = pr.get("hijack_ready_evidence")
                ea_tier = "t2" if ev else "t1"
                ea_detail = (
                    f"Peer expects local AS = {pr['expected_as']} (extracted "
                    f"from NOTIFICATION 2/2 data field; matching My-AS in "
                    f"probe = {pr.get('expected_as_my_as')}). Combined with "
                    f"the peer's own AS ({op.get('asn','?')}) this is the "
                    f"full neighbor-AS pair — enough to complete a BGP "
                    f"session from any host that can reach 179.")
                if ev:
                    ea_detail += (
                        f" T2 evidence: a controlled re-OPEN using My-AS="
                        f"{ev.get('my_as_used')} produced a full OPEN reply "
                        f"from the peer (peer_asn={ev.get('peer_asn')}, "
                        f"router_id={ev.get('peer_router_id')!r}, "
                        f"version={ev.get('peer_version')}, hold_time="
                        f"{ev.get('peer_hold_time')}s) — session progressed "
                        f"to OpenConfirm (RFC 4271 sec. 8.2.2). recce sent "
                        f"NO KEEPALIVE and NO UPDATE, so the peer's FSM "
                        f"times out on OpenConfirm and drops the session "
                        f"with no change to the RIB.")
                f = _finding(
                    "high",
                    "BGP peer discloses expected local AS via NOTIFICATION "
                    "'Bad Peer AS'", tgt,
                    ea_detail,
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Restrict TCP/179 to configured neighbors. Require "
                    "TCP-MD5 / TCP-AO so knowing the AS pair alone is "
                    "insufficient to bring up a session.",
                    ["CWE-200", "CWE-307"], kind="bgp_expected_as_disclosed",
                    exploit_note=(
                        "With disclosed AS pair, exabgp neighbor <ip> "
                        "{peer-as <peer>; local-as <expected>; router-id "
                        "192.0.2.1;} — session comes up = full-hijack "
                        "primitive."
                    ),
                    depth_tier=ea_tier)
                if ev:
                    f["output"] = (
                        f"hijack-ready evidence: my_as_used="
                        f"{ev.get('my_as_used')}; peer replied OPEN with "
                        f"peer_asn={ev.get('peer_asn')} "
                        f"router_id={ev.get('peer_router_id')!r} "
                        f"version={ev.get('peer_version')} "
                        f"hold_time={ev.get('peer_hold_time')}s")
                out.append(f)

            # bgp_version_probe — extracted version ceiling.
            if pr.get("peer_max_version"):
                out.append(_finding(
                    "low",
                    "BGP peer discloses maximum supported version", tgt,
                    f"An OPEN advertising version=5 was answered with "
                    f"NOTIFICATION 2/1 'Unsupported Version Number' whose "
                    f"data field named the peer's maximum supported "
                    f"version: {pr['peer_max_version']}. Stack fingerprint "
                    f"— the peer follows RFC 4271 sec. 6.2 verbatim.",
                    f"nmap --script bgp-info -p {p.portid} {h.ip}",
                    "Informational.",
                    ["CWE-200"], kind="bgp_version_probe",
                    exploit_note="Included in probe automatically.",
                    depth_tier="t0"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "OPEN probe + capability parse",
         "cmd": f"nmap --script bgp-info -p {port} {ip}"},
        {"step": "Peer AS + Router-ID from a scripted OPEN (exabgp reference)",
         "cmd": (f"exabgp --env <(printf 'neighbor {ip} {{\\n  "
                 f"router-id 192.0.2.1;\\n  local-as 65001;\\n  peer-as 65000;\\n"
                 f"}}\\n')")},
        {"step": "Whois the disclosed AS for ownership attribution",
         "cmd": "whois -h whois.arin.net 'a AS<n>'"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "bgp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = bgp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                op = pr.get("open") or {}
                t["asn"] = op.get("asn")
                t["router_id"] = op.get("router_id")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
