"""STUN / TURN (3478 udp+tcp, 5349 tls) enumeration.

Four related exposures live on these ports and each takes a different packet:

  * **STUN Binding (RFC 8489 §6)** — an unauthenticated Binding Request
    returns the scanner's public IP+port in XOR-MAPPED-ADDRESS. Free NAT
    mapping disclosure and the reachability test at once.
  * **SOFTWARE attribute (RFC 8489 §14.10)** — coturn / eturnal / restund /
    pion identify themselves with a UTF-8 vendor+version string. Feeds the
    CVE mapper the same way SSH/HTTP banners do.
  * **TURN Allocate (RFC 8656 §7)** — an unauthenticated Allocate MUST be
    answered 401 with REALM + NONCE. The REALM is a free credentialless
    leak of the deployment's identity namespace (SIP domain / Kerberos
    realm / AD DNS domain). If a misconfigured server instead answers
    Allocate Success, that is an open relay.
  * **XOR-PEER-ADDRESS to internal (RFC 8656 §9)** — once a relay is
    allocated, CreatePermission toward 169.254.169.254 / 127.0.0.1 /
    RFC1918 SHOULD be refused. A server that accepts one is a bidirectional
    SSRF into the internal network — cloud metadata reach on cloud hosts.

Probes are single UDP datagrams where the protocol allows it; the TCP
transport check uses RFC 4571 2-byte length framing, and TURNS uses TLS
via stdlib ssl. Airgap-safe: stdlib socket + struct + ssl only.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import struct

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 3478
_TURNS_PORT = 5349
_TIMEOUT = 3.0

_MAGIC_COOKIE = 0x2112A442
_MAGIC_BYTES = struct.pack("!I", _MAGIC_COOKIE)

# Message types (method | class).
_MT_BINDING_REQUEST = 0x0001
_MT_BINDING_SUCCESS = 0x0101
_MT_ALLOCATE_REQUEST = 0x0003
_MT_ALLOCATE_SUCCESS = 0x0103
_MT_ALLOCATE_ERROR = 0x0113
_MT_CREATE_PERM_REQUEST = 0x0008
_MT_CREATE_PERM_SUCCESS = 0x0108
_MT_REFRESH_REQUEST = 0x0004

# Attributes.
_A_MAPPED_ADDRESS = 0x0001
_A_CHANGE_REQUEST = 0x0003
_A_ERROR_CODE = 0x0009
_A_LIFETIME = 0x000D
_A_REALM = 0x0014
_A_NONCE = 0x0015
_A_XOR_PEER_ADDRESS = 0x0012
_A_XOR_RELAYED_ADDRESS = 0x0016
_A_REQUESTED_TRANSPORT = 0x0019
_A_XOR_MAPPED_ADDRESS = 0x0020
_A_SOFTWARE = 0x8022
_A_OTHER_ADDRESS = 0x802C

_INTERNAL_PEERS = ("169.254.169.254", "127.0.0.1", "10.0.0.1")


def is_stun(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    if port.portid in (3478, 5349, 5350):
        return True
    return ("stun" in svc or "turn" in svc or "stun" in prod
            or "turn" in prod or "coturn" in prod)


def _txid() -> bytes:
    return os.urandom(12)


def _stun_message(msg_type: int, txid: bytes, attrs: bytes = b"") -> bytes:
    return struct.pack("!HH", msg_type, len(attrs)) + _MAGIC_BYTES + txid + attrs


def _pad4(data: bytes) -> bytes:
    r = len(data) % 4
    return data + (b"\x00" * (4 - r)) if r else data


def _attr(atype: int, value: bytes) -> bytes:
    return struct.pack("!HH", atype, len(value)) + _pad4(value)


def _binding_request(txid: bytes | None = None) -> bytes:
    return _stun_message(_MT_BINDING_REQUEST, txid or _txid())


def _legacy_binding_request() -> bytes:
    """RFC 3489 Binding Request: no magic cookie, 16-byte transaction ID."""
    return struct.pack("!HH", _MT_BINDING_REQUEST, 0) + os.urandom(16)


def _change_request(change_ip: bool, change_port: bool,
                    txid: bytes | None = None) -> bytes:
    flags = (0x04 if change_ip else 0) | (0x02 if change_port else 0)
    val = struct.pack("!I", flags)
    return _stun_message(_MT_BINDING_REQUEST, txid or _txid(),
                         _attr(_A_CHANGE_REQUEST, val))


def _allocate_request(txid: bytes | None = None) -> bytes:
    """TURN Allocate for UDP relay (RFC 8656 §7.1)."""
    body = _attr(_A_REQUESTED_TRANSPORT, bytes([17, 0, 0, 0]))
    return _stun_message(_MT_ALLOCATE_REQUEST, txid or _txid(), body)


def _create_perm_request(peer_ip: str, txid: bytes) -> bytes:
    """CreatePermission naming a single IPv4 peer via XOR-PEER-ADDRESS."""
    return _stun_message(_MT_CREATE_PERM_REQUEST, txid,
                         _attr(_A_XOR_PEER_ADDRESS, _xor_ipv4_value(peer_ip, txid)))


def _refresh_zero(txid: bytes) -> bytes:
    return _stun_message(_MT_REFRESH_REQUEST, txid,
                         _attr(_A_LIFETIME, struct.pack("!I", 0)))


def _xor_ipv4_value(ip: str, txid: bytes) -> bytes:
    """Encode a peer IPv4 as XOR-PEER-ADDRESS value: fam=1, xport=0."""
    parts = [int(x) for x in ip.split(".")]
    if len(parts) != 4:
        raise ValueError("ipv4 required")
    raw = bytes(parts)
    xaddr = bytes(a ^ b for a, b in zip(raw, _MAGIC_BYTES))
    return bytes([0x00, 0x01, 0x00, 0x00]) + xaddr


def _parse_header(pkt: bytes) -> tuple[int, int, bytes] | None:
    if len(pkt) < 20:
        return None
    msg_type, msg_len = struct.unpack("!HH", pkt[:4])
    # Top two bits of the message type MUST be zero (RFC 8489 §5).
    if msg_type & 0xC000:
        return None
    if len(pkt) < 20 + msg_len:
        return None
    return msg_type, msg_len, pkt[8:20]


def _iter_attrs(payload: bytes):
    i = 0
    while i + 4 <= len(payload):
        atype, alen = struct.unpack("!HH", payload[i:i + 4])
        i += 4
        end = i + alen
        if end > len(payload):
            return
        yield atype, payload[i:end]
        # attributes are padded to 4-byte boundaries
        pad = (4 - (alen % 4)) % 4
        i = end + pad


def _decode_xor_address(val: bytes, txid: bytes) -> tuple[str, int] | None:
    if len(val) < 8 or val[1] not in (0x01, 0x02):
        return None
    fam = val[1]
    xport = struct.unpack("!H", val[2:4])[0]
    port = xport ^ (_MAGIC_COOKIE >> 16)
    if fam == 0x01 and len(val) >= 8:
        xaddr = val[4:8]
        raw = bytes(a ^ b for a, b in zip(xaddr, _MAGIC_BYTES))
        return ".".join(str(b) for b in raw), port
    if fam == 0x02 and len(val) >= 20:
        xaddr = val[4:20]
        key = _MAGIC_BYTES + txid
        raw = bytes(a ^ b for a, b in zip(xaddr, key))
        return socket.inet_ntop(socket.AF_INET6, raw), port
    return None


def _decode_plain_address(val: bytes) -> tuple[str, int] | None:
    if len(val) < 8 or val[1] != 0x01:
        return None
    port = struct.unpack("!H", val[2:4])[0]
    return ".".join(str(b) for b in val[4:8]), port


def _decode_error(val: bytes) -> tuple[int, str]:
    if len(val) < 4:
        return 0, ""
    klass = val[2] & 0x07
    number = val[3]
    reason = val[4:].decode("utf-8", "replace") if len(val) > 4 else ""
    return klass * 100 + number, reason


def _parse_response(pkt: bytes) -> dict | None:
    hdr = _parse_header(pkt)
    if not hdr:
        return None
    msg_type, msg_len, txid = hdr
    # Magic cookie must be present for RFC 8489 responses.
    if pkt[4:8] != _MAGIC_BYTES:
        return None
    out: dict = {"msg_type": msg_type, "txid": txid, "attrs": {}}
    body = pkt[20:20 + msg_len]
    for atype, val in _iter_attrs(body):
        if atype == _A_XOR_MAPPED_ADDRESS:
            ap = _decode_xor_address(val, txid)
            if ap:
                out["attrs"]["xor_mapped_address"] = f"{ap[0]}:{ap[1]}"
        elif atype == _A_MAPPED_ADDRESS:
            ap = _decode_plain_address(val)
            if ap:
                out["attrs"]["mapped_address"] = f"{ap[0]}:{ap[1]}"
        elif atype == _A_SOFTWARE:
            out["attrs"]["software"] = val.decode("utf-8", "replace").rstrip("\x00")
        elif atype == _A_REALM:
            out["attrs"]["realm"] = val.decode("utf-8", "replace").rstrip("\x00")
        elif atype == _A_NONCE:
            out["attrs"]["nonce"] = val.decode("utf-8", "replace").rstrip("\x00")
        elif atype == _A_ERROR_CODE:
            code, reason = _decode_error(val)
            out["attrs"]["error_code"] = code
            out["attrs"]["error_reason"] = reason
        elif atype == _A_OTHER_ADDRESS:
            ap = _decode_plain_address(val)
            if ap:
                out["attrs"]["other_address"] = f"{ap[0]}:{ap[1]}"
        elif atype == _A_XOR_RELAYED_ADDRESS:
            ap = _decode_xor_address(val, txid)
            if ap:
                out["attrs"]["xor_relayed_address"] = f"{ap[0]}:{ap[1]}"
        elif atype == _A_LIFETIME and len(val) >= 4:
            out["attrs"]["lifetime"] = struct.unpack("!I", val[:4])[0]
    return out


def _parse_legacy_response(pkt: bytes) -> dict | None:
    """RFC 3489 responses have no magic cookie; MAPPED-ADDRESS is plaintext."""
    if len(pkt) < 20:
        return None
    msg_type, msg_len = struct.unpack("!HH", pkt[:4])
    if msg_type != _MT_BINDING_SUCCESS:
        return None
    body = pkt[20:20 + msg_len]
    for atype, val in _iter_attrs(body):
        if atype == _A_MAPPED_ADDRESS:
            ap = _decode_plain_address(val)
            if ap:
                return {"mapped_address": f"{ap[0]}:{ap[1]}"}
    return {"mapped_address": ""}


_SOFTWARE_RE = re.compile(
    r"(?P<prod>coturn|eturnal|restund|pion|aiortc|Asterisk|Cisco[\w\s-]*|Jitsi|"
    r"stunner|LiveKit)"
    r"[\s/v-]*(?P<ver>\d[\w.-]*)?", re.I)


def _parse_software(value: str) -> tuple[str, str] | None:
    if not value:
        return None
    m = _SOFTWARE_RE.search(value)
    if not m:
        return None
    return m.group("prod").strip(), (m.group("ver") or "").strip()


def _udp_exchange(ip: str, port: int, payload: bytes,
                  timeout: float) -> bytes | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(proxy.scaled(timeout))
    try:
        s.sendto(payload, (ip, port))
        try:
            data, _addr = s.recvfrom(4096)
        except (socket.timeout, OSError):
            return None
        return data
    finally:
        s.close()


def _tcp_exchange(ip: str, port: int, payload: bytes,
                  timeout: float, framed: bool = False) -> bytes | None:
    """TCP STUN transport. framed=True prepends RFC 4571 2-byte length."""
    try:
        s = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError:
        return None
    try:
        s.settimeout(proxy.scaled(timeout))
        wire = struct.pack("!H", len(payload)) + payload if framed else payload
        try:
            s.sendall(wire)
            data = s.recv(4096)
        except (socket.timeout, OSError):
            return None
        if not data:
            return None
        if framed and len(data) >= 2:
            plen = struct.unpack("!H", data[:2])[0]
            if len(data) >= 2 + plen:
                return data[2:2 + plen]
        return data
    finally:
        s.close()


def _tls_exchange(ip: str, port: int, payload: bytes,
                  timeout: float) -> tuple[bytes | None, dict]:
    """TLS handshake to a TURNS listener; returns (response, tls_meta)."""
    meta: dict = {}
    ctx = ssl._create_unverified_context()
    try:
        raw = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        meta["error"] = f"tcp: {e}"
        return None, meta
    try:
        raw.settimeout(proxy.scaled(timeout))
        try:
            tls = ctx.wrap_socket(raw, server_hostname=ip)
        except (ssl.SSLError, OSError) as e:
            meta["error"] = f"tls: {e}"
            return None, meta
        try:
            meta["tls_version"] = tls.version() or ""
            cs = tls.cipher()
            meta["cipher"] = cs[0] if cs else ""
            cert = tls.getpeercert(binary_form=False) or {}
            try:
                der = tls.getpeercert(binary_form=True) or b""
            except ValueError:
                der = b""
            _fill_cert_meta(meta, cert, der)
            wire = struct.pack("!H", len(payload)) + payload
            try:
                tls.sendall(wire)
                data = tls.recv(4096)
            except (socket.timeout, OSError):
                data = None
            if data and len(data) >= 2:
                plen = struct.unpack("!H", data[:2])[0]
                if len(data) >= 2 + plen:
                    return data[2:2 + plen], meta
            return data, meta
        finally:
            try:
                tls.close()
            except OSError:
                pass
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _fill_cert_meta(meta: dict, cert: dict, der: bytes) -> None:
    if not cert and not der:
        return
    subject = ""
    for tup in cert.get("subject", ()):
        for k, v in tup:
            if k == "commonName":
                subject = v
    issuer = ""
    for tup in cert.get("issuer", ()):
        for k, v in tup:
            if k == "commonName":
                issuer = v
    meta["cert_subject"] = subject
    meta["cert_issuer"] = issuer
    meta["cert_not_before"] = cert.get("notBefore", "")
    meta["cert_not_after"] = cert.get("notAfter", "")
    sans = []
    for k, v in cert.get("subjectAltName", ()) or ():
        sans.append(f"{k}:{v}")
    meta["cert_sans"] = sans
    meta["self_signed"] = bool(subject and issuer and subject == issuer)


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          tls: bool = False) -> dict:
    """Single-target STUN/TURN probe. UDP by default; when tls=True the module
    speaks TURNS on the given port (RFC 4571 framing over TLS)."""
    out: dict = {"reachable": False, "port": port, "tls": tls}

    if tls:
        return _probe_turns(ip, port, timeout, out)

    return _probe_udp_tcp(ip, port, timeout, out)


def _probe_udp_tcp(ip: str, port: int, timeout: float, out: dict) -> dict:
    txid = _txid()
    req = _binding_request(txid)
    reply = _udp_exchange(ip, port, req, timeout)
    parsed = _parse_response(reply) if reply else None
    if parsed and parsed.get("txid") == txid:
        out["reachable"] = True
        out["transport"] = "udp"
        out["request_bytes"] = len(req)
        out["response_bytes"] = len(reply)
        out["amplification"] = round(len(reply) / len(req), 2)
        _fold_binding(out, parsed)

    # TCP transport (RFC 6062 / RFC 4571 framing).
    tcp_reply = _tcp_exchange(ip, port, req, timeout, framed=True)
    if tcp_reply:
        parsed_tcp = _parse_response(tcp_reply)
        if parsed_tcp and parsed_tcp.get("msg_type") == _MT_BINDING_SUCCESS:
            out["reachable"] = True
            out["tcp_transport"] = True

    # RFC 3489 legacy: no magic cookie.
    legacy = _udp_exchange(ip, port, _legacy_binding_request(), timeout)
    legacy_parsed = _parse_legacy_response(legacy) if legacy else None
    if legacy_parsed and legacy_parsed.get("mapped_address"):
        out["classic_stun"] = True
        out["classic_mapped_address"] = legacy_parsed["mapped_address"]

    # RFC 5780: CHANGE-REQUEST to elicit OTHER-ADDRESS (many multi-homed
    # servers already return it in the plain Binding Response too — merged
    # by _fold_binding above).
    if out.get("reachable") and "other_address" not in out:
        cr = _udp_exchange(ip, port, _change_request(True, True), timeout)
        cr_parsed = _parse_response(cr) if cr else None
        if cr_parsed and cr_parsed.get("attrs", {}).get("other_address"):
            out["other_address"] = cr_parsed["attrs"]["other_address"]

    # TURN Allocate — realm/nonce disclosure + open-relay + internal-address
    # SSRF. All layered on the ONE nonce we receive back.
    _probe_turn(ip, port, timeout, out)
    return out


def _fold_binding(out: dict, parsed: dict) -> None:
    a = parsed.get("attrs", {})
    if a.get("xor_mapped_address"):
        out["external_mapping"] = a["xor_mapped_address"]
    if a.get("software"):
        out["software"] = a["software"]
        pv = _parse_software(a["software"])
        if pv:
            out["product"], out["version"] = pv
    if a.get("other_address"):
        out["other_address"] = a["other_address"]


def _probe_turn(ip: str, port: int, timeout: float, out: dict) -> None:
    txid = _txid()
    req = _allocate_request(txid)
    reply = _udp_exchange(ip, port, req, timeout)
    parsed = _parse_response(reply) if reply else None
    if not parsed:
        return
    out["speaks_turn"] = True
    a = parsed.get("attrs", {})
    if a.get("software") and "software" not in out:
        out["software"] = a["software"]
        pv = _parse_software(a["software"])
        if pv:
            out["product"], out["version"] = pv
    out["turn_request_bytes"] = len(req)
    out["turn_response_bytes"] = len(reply)
    out["turn_amplification"] = round(len(reply) / len(req), 2)

    mt = parsed.get("msg_type")
    if mt == _MT_ALLOCATE_ERROR:
        code = a.get("error_code", 0)
        out["turn_error_code"] = code
        if code == 401 and (a.get("realm") or a.get("nonce")):
            out["turn_realm"] = a.get("realm", "")
            out["turn_nonce"] = a.get("nonce", "")
    elif mt == _MT_ALLOCATE_SUCCESS:
        # Unauthenticated Allocate accepted — open relay.
        out["turn_open_relay"] = True
        if a.get("xor_relayed_address"):
            out["turn_relayed_address"] = a["xor_relayed_address"]
        _probe_internal_relay(ip, port, timeout, out)
        # Refresh with lifetime=0 to release the allocation immediately.
        try:
            _udp_exchange(ip, port, _refresh_zero(_txid()), min(timeout, 2.0))
        except OSError:
            pass


def _probe_internal_relay(ip: str, port: int, timeout: float,
                          out: dict) -> None:
    """After an open-relay Allocate, test whether CreatePermission accepts
    a forbidden peer (RFC 8656 §9). Accepting one is bidirectional SSRF."""
    accepted: list[str] = []
    for peer in _INTERNAL_PEERS:
        txid = _txid()
        try:
            req = _create_perm_request(peer, txid)
        except ValueError:
            continue
        reply = _udp_exchange(ip, port, req, timeout)
        parsed = _parse_response(reply) if reply else None
        if not parsed:
            continue
        if parsed.get("msg_type") == _MT_CREATE_PERM_SUCCESS:
            accepted.append(peer)
    if accepted:
        out["turn_internal_relay"] = accepted


def _probe_turns(ip: str, port: int, timeout: float, out: dict) -> dict:
    txid = _txid()
    req = _binding_request(txid)
    reply, meta = _tls_exchange(ip, port, req, timeout)
    out["tls_meta"] = meta
    if meta.get("tls_version"):
        out["reachable"] = True
        out["transport"] = "tls"
    parsed = _parse_response(reply) if reply else None
    if parsed and parsed.get("txid") == txid:
        _fold_binding(out, parsed)
    return out


def _is_weak_tls(v: str) -> bool:
    return v in ("SSLv3", "TLSv1", "TLSv1.1")


def stun_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_stun(p):
                tls = p.portid == _TURNS_PORT or (p.service or "").lower() in ("turns", "stuns")
                out.append({"ip": h.ip, "port": p.portid, "tls": tls,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "stun", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    port_status: dict[str, dict[int, dict]] = {}
    for (ip, port), pr in probes.items():
        port_status.setdefault(ip, {})[port] = pr

    for h in hosts:
        for p in h.open_ports:
            if not is_stun(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            if pr.get("turn_realm") or pr.get("turn_nonce"):
                out.append(_finding(
                    "medium",
                    "TURN Allocate discloses REALM and NONCE without authentication",
                    tgt,
                    f"An unauthenticated TURN Allocate request was answered 401 with "
                    f"REALM={pr.get('turn_realm','')!r} NONCE={pr.get('turn_nonce','')!r}. "
                    f"The REALM leaks the deployment's identity namespace "
                    f"(SIP domain / Kerberos realm / AD DNS domain) without credentials "
                    f"— feed it into ldap/kerberos/sip/smtp cross-service correlation.",
                    f"python3 -c \"import socket,struct,os;"
                    f"s=socket.socket(2,2);"
                    f"s.sendto(bytes.fromhex('000300082112a442')+os.urandom(12)+"
                    f"bytes.fromhex('0019000411000000'),('{h.ip}',{p.portid}));"
                    f"print(s.recvfrom(4096)[0].hex())\"",
                    "Restrict TURN to authenticated clients; the REALM leak is inherent "
                    "to RFC 8656 §7.2 — mitigate by placing TURN behind an ACL, or by "
                    "returning a generic realm that does not name the org.",
                    ["CWE-200"], kind="turn_realm_disclosure",
                    exploit_note=(
                        "python3 -c \"import socket,os;s=socket.socket(2,2);"
                        "s.sendto(bytes.fromhex('000300082112a442')+"
                        "os.urandom(12)+bytes.fromhex('0019000411000000'),"
                        f"('{h.ip}',{p.portid}));"
                        "print(s.recvfrom(4096)[0])\""),
                    depth_tier="t1"))

            if pr.get("turn_open_relay"):
                relayed = pr.get("turn_relayed_address") or "unknown"
                out.append(_finding(
                    "critical",
                    "TURN accepts allocations without authentication (open relay)",
                    tgt,
                    f"An Allocate request with NO MESSAGE-INTEGRITY was answered "
                    f"0x0103 Allocate Success (relayed address {relayed}). The server "
                    f"is an open relay: attackers get free egress bandwidth, source-IP "
                    f"laundering, and (if internal peer addresses are also accepted) "
                    f"a bidirectional SSRF pivot.",
                    f"# proof of the accepted Allocate; recce refreshed lifetime=0 "
                    f"immediately\n"
                    f"nmap -sU -p{p.portid} --script stun-info {h.ip}",
                    "Set `no-auth = false` (coturn) and require long-term credentials "
                    "on every allocation. Restrict TURN to authenticated clients only.",
                    ["CWE-306", "CWE-284"], kind="turn_open_relay",
                    exploit_note=(
                        f"turnutils_uclient -v -y {h.ip}  # or: python3 "
                        "stun-turn-toolkit / rfc5766-turn-server client to "
                        "send data via the open relay"),
                    depth_tier="t2"))

            if pr.get("turn_internal_relay"):
                peers = ", ".join(pr["turn_internal_relay"])
                out.append(_finding(
                    "critical",
                    "TURN allocation permits relay to internal / loopback / cloud-metadata peer",
                    tgt,
                    f"After the open-relay Allocate, CreatePermission was ACCEPTED for "
                    f"forbidden peers: {peers}. RFC 8656 §9 says the server MUST refuse "
                    f"these — accepting them turns TURN into a bidirectional SSRF into "
                    f"the internal network, with cloud metadata reach when 169.254.169.254 "
                    f"is in the list.",
                    f"# recce accepted a CreatePermission for {peers} but issued no Send",
                    "Set `denied-peer-ip` for RFC1918 / 127.0.0.0/8 / 169.254.0.0/16 "
                    "(coturn), or the equivalent peer-address ACL on the TURN server.",
                    ["CWE-918", "CWE-441"], kind="turn_internal_relay",
                    exploit_note=(
                        "Use TURN SEND indication to relay HTTP GET "
                        "/latest/meta-data/iam/security-credentials/ "
                        "toward 169.254.169.254; parse returned STS keys "
                        "via cloud_metadata."),
                    depth_tier="t2"))

            # Cleartext-creds channel: 3478 speaks TURN and no 5349 companion.
            if (pr.get("speaks_turn") and p.portid == _DEFAULT_PORT
                    and _TURNS_PORT not in port_status.get(h.ip, {})):
                out.append(_finding(
                    "high",
                    "TURN long-term credentials sent cleartext on 3478 with no TURNS (5349) alternative",
                    tgt,
                    "3478 speaks TURN (Allocate answered) and this host exposes no "
                    "5349/tls listener. Any client authenticating over 3478 sends the "
                    "MESSAGE-INTEGRITY HMAC — and its username / realm / nonce and "
                    "signaling payload — in the clear.",
                    f"openssl s_client -connect {h.ip}:5349   # confirms no TURNS",
                    "Deploy a TURNS listener on 5349/tls with a real certificate; "
                    "clients should use the turns: URI scheme (RFC 8656 §3.1). "
                    "Consider a firewall rule to force TURN to 5349.",
                    ["CWE-319"], kind="turn_cleartext_creds",
                    exploit_note=(
                        f"openssl s_client -connect {h.ip}:5349  "
                        "# confirms no TURNS; tcpdump -i any 'udp and "
                        "port 3478' to capture client hashes over time"),
                    depth_tier="t0"))

            if pr.get("software"):
                prod = pr.get("product") or ""
                ver = pr.get("version") or ""
                title_tail = f"{prod} {ver}".strip() or pr["software"]
                out.append(_finding(
                    "low",
                    f"STUN/TURN SOFTWARE attribute discloses server version: {title_tail}",
                    tgt,
                    f"The Binding / Allocate response carries a SOFTWARE attribute: "
                    f"{pr['software']!r}. That is free daemon fingerprinting for the "
                    f"CVE mapper and downstream modules.",
                    f"nmap -sU -p{p.portid} --script stun-version {h.ip}",
                    "Configure the TURN daemon to omit the SOFTWARE attribute (coturn: "
                    "`no-software-attribute`); it has no protocol function beyond "
                    "identification.",
                    ["CWE-200"], kind="stun_version_disclosure",
                    exploit_note=(
                        f"nmap -sU -p3478 --script stun-version {h.ip}"),
                    depth_tier="t0"))

            if pr.get("external_mapping"):
                out.append(_finding(
                    "info",
                    "STUN Binding Response reveals scanner's external IP mapping",
                    tgt,
                    f"XOR-MAPPED-ADDRESS returned {pr['external_mapping']} — the server's "
                    f"view of the scanner's NAT-translated address. Cross-correlation "
                    f"fact: matches the target's egress IP for outbound calls.",
                    f"nmap -sU -p{p.portid} --script stun-info {h.ip}",
                    "Informational; STUN Binding is designed to return this. Restrict "
                    "3478 to the WebRTC signaling network if disclosure to arbitrary "
                    "clients is not required.",
                    [], kind="stun_external_mapping",
                    exploit_note="n/a - informational",
                    depth_tier="t0"))

            if pr.get("classic_stun"):
                out.append(_finding(
                    "medium",
                    "STUN server responds to legacy RFC 3489 ClassicSTUN (outdated daemon)",
                    tgt,
                    f"An RFC 3489 Binding Request (no magic cookie) was answered with "
                    f"a MAPPED-ADDRESS attribute (plain, not XOR): "
                    f"{pr.get('classic_mapped_address', '?')}. RFC 5389/8489 servers "
                    f"MUST reject or ignore this — a legacy daemon is unpatched relative "
                    f"to two RFC generations of security work and offers a larger "
                    f"amplification surface.",
                    f"# raw RFC 3489 probe (no magic cookie)\n"
                    f"python3 -c \"import socket,os;"
                    f"s=socket.socket(2,2);"
                    f"s.sendto(bytes.fromhex('0001000000')+os.urandom(16),"
                    f"('{h.ip}',{p.portid}));print(s.recvfrom(4096)[0].hex())\"",
                    "Upgrade to a current STUN/TURN implementation (coturn 4.5+, "
                    "eturnal, restund); disable RFC 3489 compatibility mode.",
                    ["CWE-1104"], kind="stun_legacy_rfc3489",
                    exploit_note=(
                        "raw RFC 3489 probe (no magic cookie); confirm plain "
                        "MAPPED-ADDRESS"),
                    depth_tier="t0"))

            if pr.get("other_address"):
                out.append(_finding(
                    "low",
                    "STUN OTHER-ADDRESS discloses a second server IP (undiscovered listener)",
                    tgt,
                    f"OTHER-ADDRESS attribute (RFC 5780) returned {pr['other_address']} "
                    f"— a second interface / IP on this STUN server. Schedule a full "
                    f"portscan of that address; it is a live host recce did not "
                    f"discover through subnet enumeration.",
                    f"nmap -sU -p{p.portid} --script stun-info {h.ip}",
                    "Restrict RFC 5780 NAT-behavior-discovery responses; do not "
                    "expose secondary interfaces on Internet-facing STUN servers.",
                    ["CWE-200"], kind="stun_second_address_disclosure",
                    exploit_note=(
                        "nmap -sU -p3478 <other-address-ip>  # portscan the "
                        "second STUN interface"),
                    depth_tier="t0"))

            amp = pr.get("turn_amplification") or pr.get("amplification") or 0
            if amp >= 4.0:
                out.append(_finding(
                    "medium",
                    f"STUN/TURN reflective amplification factor {amp}x exceeds 4x",
                    tgt,
                    f"A single {pr.get('turn_request_bytes') or pr.get('request_bytes')}"
                    f"-byte request drew a "
                    f"{pr.get('turn_response_bytes') or pr.get('response_bytes')}"
                    f"-byte response ({amp}x). UDP + source-IP-spoofable = a reflective "
                    f"DDoS building block alongside ntp monlist, memcached stats, and "
                    f"DNS ANY.",
                    f"# measure amplification\n"
                    f"nmap -sU -p{p.portid} --script stun-info {h.ip}",
                    "Rate-limit STUN/TURN responses; restrict 3478 to authenticated "
                    "clients or the signaling network so the reflector cannot be "
                    "reached by arbitrary sources.",
                    ["CWE-406"], kind="stun_amplification",
                    exploit_note=(
                        "n/a - DDoS proof would be unsafe; report the ratio "
                        "only"),
                    depth_tier="t1"))

            # TURNS TLS posture on 5349.
            tls_meta = pr.get("tls_meta") or {}
            if tls_meta:
                weak = _is_weak_tls(tls_meta.get("tls_version", ""))
                selfsigned = tls_meta.get("self_signed")
                if weak or selfsigned:
                    parts = []
                    if weak:
                        parts.append(f"negotiated {tls_meta['tls_version']}")
                    if selfsigned:
                        parts.append("certificate is self-signed")
                    out.append(_finding(
                        "medium",
                        "TURNS TLS posture is weak (protocol version or certificate)",
                        tgt,
                        f"TURNS handshake on {tgt}: {', '.join(parts)} (cipher="
                        f"{tls_meta.get('cipher','?')}, subject="
                        f"{tls_meta.get('cert_subject','?')}, issuer="
                        f"{tls_meta.get('cert_issuer','?')}).",
                        f"openssl s_client -connect {h.ip}:{p.portid} -showcerts",
                        "Require TLS 1.2+ (prefer 1.3), disable RC4/3DES/CBC-SHA, and "
                        "issue a certificate from a trusted CA whose SAN covers the "
                        "signaling hostname.",
                        ["CWE-295", "CWE-326"], kind="turns_tls_weak",
                        exploit_note=(
                            f"openssl s_client -connect {h.ip}:{p.portid} "
                            "-showcerts"),
                        depth_tier="t0"))

            out.append(_finding(
                "info", "STUN/TURN endpoint reachable", tgt,
                f"STUN/TURN reachable via {pr.get('transport','?')}. "
                f"speaks_turn={pr.get('speaks_turn', False)} "
                f"software={pr.get('software','')!r} "
                f"tcp_transport={pr.get('tcp_transport', False)} "
                f"external_mapping={pr.get('external_mapping','')}",
                f"nmap -sU -p{p.portid} --script stun-info,stun-version {h.ip}",
                "Restrict STUN/TURN to the signaling network when not required "
                "externally.",
                [], kind="stun_fingerprint",
                exploit_note=(
                    f"nmap -sU -p{p.portid} --script stun-info,stun-version "
                    f"{h.ip}"),
                depth_tier="t0"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "nmap",
         "command": f"nmap -sU -p{port} --script stun-info,stun-version {ip}",
         "why": "STUN Binding + SOFTWARE fingerprint in one pass"},
        {"phase": "enumerate", "tool": "python3",
         "command": (f"python3 -c \"import socket,os;s=socket.socket(2,2);"
                     f"s.sendto(bytes.fromhex('000100002112a442')+os.urandom(12),"
                     f"('{ip}',{port}));print(s.recvfrom(4096)[0].hex())\""),
         "why": "raw STUN Binding when nmap script is unavailable (Kali ships no stun-client)"},
        {"phase": "enumerate", "tool": "python3",
         "command": (f"python3 -c \"import socket,os;s=socket.socket(2,2);"
                     f"s.sendto(bytes.fromhex('000300082112a442')+os.urandom(12)+"
                     f"bytes.fromhex('0019000411000000'),('{ip}',{port}));"
                     f"print(s.recvfrom(4096)[0].hex())\""),
         "why": "TURN Allocate — 401 answer carries REALM + NONCE (identity namespace leak)"},
        {"phase": "enumerate", "tool": "openssl",
         "command": f"openssl s_client -connect {ip}:5349 -showcerts",
         "why": "TURNS certificate + TLS version posture"},
        {"phase": "exploit", "tool": "hashcat",
         "command": "hashcat -m 31300 loot/turn.hash wordlist.txt",
         "why": "offline crack of any captured MESSAGE-INTEGRITY (long-term-credential HMAC-SHA1)"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "stun", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = stun_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], tls=t.get("tls", False)),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["speaks_turn"] = pr.get("speaks_turn", False)
                t["turn_realm"] = pr.get("turn_realm", "")
                t["turn_open_relay"] = pr.get("turn_open_relay", False)
                t["software"] = pr.get("software", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
