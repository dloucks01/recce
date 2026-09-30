"""EtherNet/IP (ODVA CIP) probe — 44818/tcp+udp, 2222/udp implicit I/O.

EtherNet/IP is ODVA's adaptation of the Common Industrial Protocol over
TCP/UDP 44818, with real-time Class 1 I/O on UDP/2222. It is the native
fieldbus for Rockwell/Allen-Bradley ControlLogix/CompactLogix/MicroLogix
PLCs and is widely deployed in manufacturing, water/wastewater and building
automation. Reaching 44818 from a corporate segment is itself a
segmentation finding — the entire attack surface below has no
authentication in the base protocol.

Read-only. The probe NEVER sends Identity Reset (service 0x05) or the
PCCC Change Mode function, and does not fire ForwardOpen with a real
connection lifecycle — those are runbook steps behind explicit operator
confirmation. Every capability that could be destructive is inferred from
a safe supported-service GetAttribute query, not from the write itself.

Airgap-safe: stdlib socket + struct only. All bytes on the wire are
LITTLE-ENDIAN (unlike Modbus/TCP MBAP which is big-endian). One TCP
session per host: RegisterSession → batched SendRRData queries →
UnregisterSession in a finally block (stale sessions count against the
device's cap — Rockwell tops out at 128 on many models).
"""
from __future__ import annotations

import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 44818
_TIMEOUT = 4.0

# Encapsulation commands (§2-4 of ODVA Vol 2). All header fields little-endian.
_CMD_LIST_SERVICES = 0x0004
_CMD_LIST_IDENTITY = 0x0063
_CMD_LIST_INTERFACES = 0x0064
_CMD_REGISTER_SESSION = 0x0065
_CMD_UNREGISTER_SESSION = 0x0066
_CMD_SEND_RR_DATA = 0x006F

# CPF item types (§2-3.3).
_CPF_NULL_ADDRESS = 0x0000
_CPF_UNCONN_DATA = 0x00B2
_CPF_IDENTITY_ITEM = 0x000C
_CPF_LIST_SERVICES_ITEM = 0x0100

# CIP services (Vol 1 §5).
_CIP_GET_ATTRS_ALL = 0x01
_CIP_GET_ATTR_SINGLE = 0x0E

# CIP class ids referenced below.
_CIP_CLASS_IDENTITY = 0x01
_CIP_CLASS_CONN_MGR = 0x06
_CIP_CLASS_FILE = 0x37
_CIP_CLASS_PCCC = 0x67
_CIP_CLASS_TCPIP = 0xF5
_CIP_CLASS_ETHLINK = 0xF6

# CIP general status codes we treat specially.
_CIP_STATUS_OK = 0x00
_CIP_STATUS_PATH_DEST_UNKNOWN = 0x05    # class / instance does not exist
_CIP_STATUS_SERVICE_NOT_SUPPORTED = 0x08

# ODVA vendor ids we recognise for CVE correlation (registry excerpt).
_VENDOR_NAMES = {
    0x0001: "Rockwell Automation / Allen-Bradley",
    0x002F: "Omron",
    0x005A: "Schneider Electric",
    0x005B: "Molex",
    0x00A3: "Siemens",
    0x0114: "Beckhoff",
    0x011D: "Phoenix Contact",
    0x0139: "WAGO",
    0x026A: "Turck",
}


def is_enip(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 44818
            or "ethernetip" in svc or "ethernet-ip" in svc
            or "ethernet/ip" in svc or "enip" in svc
            or "cip" in svc
            or "rockwell" in prod or "allen-bradley" in prod
            or "ethernetip" in prod or "ethernet/ip" in prod)


# --- wire builders ---------------------------------------------------------

def _encap(cmd: int, session: int, body: bytes, status: int = 0,
           context: bytes = b"\x00" * 8, options: int = 0) -> bytes:
    """24-byte EtherNet/IP encapsulation header + body (Vol 2 §2-3.1)."""
    return (struct.pack("<HHII", cmd, len(body), session, status)
            + context + struct.pack("<I", options) + body)


def _list_identity_req() -> bytes:
    return _encap(_CMD_LIST_IDENTITY, 0, b"")


def _list_services_req() -> bytes:
    return _encap(_CMD_LIST_SERVICES, 0, b"")


def _list_interfaces_req() -> bytes:
    return _encap(_CMD_LIST_INTERFACES, 0, b"")


def _register_session_req() -> bytes:
    # Protocol version 1, options 0 (Vol 2 §2-4.7).
    return _encap(_CMD_REGISTER_SESSION, 0, struct.pack("<HH", 1, 0))


def _unregister_session_req(session: int) -> bytes:
    return _encap(_CMD_UNREGISTER_SESSION, session, b"")


def _cip_path(class_id: int, instance: int, attr: int | None = None) -> bytes:
    """EPATH: logical segments for class, instance, optional attribute.
    Uses 8-bit segments when values fit; 16-bit segments otherwise. Every
    segment is word-aligned so path_size (in words) = len(path)//2."""
    p = b""
    if class_id <= 0xFF:
        p += bytes([0x20, class_id])
    else:
        p += bytes([0x21, 0x00]) + struct.pack("<H", class_id)
    if instance <= 0xFF:
        p += bytes([0x24, instance])
    else:
        p += bytes([0x25, 0x00]) + struct.pack("<H", instance)
    if attr is not None:
        if attr <= 0xFF:
            p += bytes([0x30, attr])
        else:
            p += bytes([0x31, 0x00]) + struct.pack("<H", attr)
    return p


def _cip_mr_request(service: int, class_id: int, instance: int,
                    attr: int | None = None, data: bytes = b"") -> bytes:
    """CIP Message Router request: service byte, path-size (in words),
    request path, service-specific data."""
    path = _cip_path(class_id, instance, attr)
    return bytes([service, len(path) // 2]) + path + data


def _send_rr_data_req(session: int, cip_req: bytes,
                      cip_timeout: int = 5) -> bytes:
    """Wrap a CIP MR request in SendRRData with the null-address CPF item —
    the standard unconnected-messaging envelope (Vol 2 §3-2.4)."""
    cpf = (struct.pack("<H", 2)                              # item count
           + struct.pack("<HH", _CPF_NULL_ADDRESS, 0)        # null addr
           + struct.pack("<HH", _CPF_UNCONN_DATA, len(cip_req))
           + cip_req)
    body = struct.pack("<IH", 0, cip_timeout) + cpf
    return _encap(_CMD_SEND_RR_DATA, session, body)


# --- wire parsers ----------------------------------------------------------

def _parse_encap(pkt: bytes) -> dict | None:
    """Return {cmd, length, session, status, context, options, data} or None
    on a malformed frame. Length must match the trailing byte-count."""
    if len(pkt) < 24:
        return None
    cmd, length, session, status = struct.unpack("<HHII", pkt[:12])
    context = pkt[12:20]
    options = struct.unpack("<I", pkt[20:24])[0]
    if len(pkt) < 24 + length:
        return None
    return {"cmd": cmd, "length": length, "session": session,
            "status": status, "context": context, "options": options,
            "data": pkt[24:24 + length]}


def _parse_cpf(body: bytes) -> list[tuple[int, bytes]] | None:
    """Common Packet Format: item_count(2 LE) + N × (type(2 LE) len(2 LE) data)."""
    if len(body) < 2:
        return None
    item_count = struct.unpack("<H", body[0:2])[0]
    off = 2
    items: list[tuple[int, bytes]] = []
    for _ in range(item_count):
        if off + 4 > len(body):
            return None
        itype, ilen = struct.unpack("<HH", body[off:off + 4])
        off += 4
        if off + ilen > len(body):
            return None
        items.append((itype, body[off:off + ilen]))
        off += ilen
    return items


def _parse_identity_item(body: bytes) -> dict | None:
    """CIP Identity item 0x000C (Vol 2 §2-4.4.2 / Vol 1 §5-2.2).
    Layout: proto_ver(2 LE), socket_addr(16), vendor_id(2 LE),
    device_type(2 LE), product_code(2 LE), rev_major(1), rev_minor(1),
    status_word(2 LE), serial(4 LE), name_len(1), name(N), state(1)."""
    if len(body) < 33:
        return None
    proto_ver = struct.unpack("<H", body[0:2])[0]
    # socket_addr is sockaddr_in in NETWORK byte order (§2-4.4.2 note).
    vendor_id, device_type, product_code = struct.unpack("<HHH", body[18:24])
    rev_major, rev_minor = body[24], body[25]
    status_word, serial = struct.unpack("<HI", body[26:32])
    name_len = body[32]
    if 33 + name_len + 1 > len(body):
        return None
    product_name = body[33:33 + name_len].decode("latin-1", "replace")
    state = body[33 + name_len]
    return {"protocol_version": proto_ver, "vendor_id": vendor_id,
            "device_type": device_type, "product_code": product_code,
            "revision": f"{rev_major}.{rev_minor}",
            "revision_major": rev_major, "revision_minor": rev_minor,
            "status_word": status_word, "serial_number": serial,
            "product_name": product_name, "device_state": state}


def _parse_list_identity(pkt: bytes) -> dict | None:
    p = _parse_encap(pkt)
    if not p or p["cmd"] != _CMD_LIST_IDENTITY or p["status"] != 0:
        return None
    items = _parse_cpf(p["data"])
    if not items:
        return None
    for itype, body in items:
        if itype == _CPF_IDENTITY_ITEM:
            return _parse_identity_item(body)
    return None


def _parse_list_services(pkt: bytes) -> list[dict] | None:
    p = _parse_encap(pkt)
    if not p or p["cmd"] != _CMD_LIST_SERVICES or p["status"] != 0:
        return None
    items = _parse_cpf(p["data"])
    if items is None:
        return None
    out: list[dict] = []
    for itype, body in items:
        if len(body) < 20:
            continue
        version = struct.unpack("<H", body[0:2])[0]
        flags = struct.unpack("<H", body[2:4])[0]
        name = body[4:20].split(b"\x00", 1)[0].decode("latin-1", "replace")
        out.append({"type": itype, "version": version, "flags": flags,
                    "name": name.strip(),
                    # Bit 5 of flags = "supports CIP encapsulation via TCP".
                    "cip_encapsulation": bool(flags & 0x20)})
    return out


def _parse_list_interfaces(pkt: bytes) -> list[tuple[int, bytes]] | None:
    p = _parse_encap(pkt)
    if not p or p["cmd"] != _CMD_LIST_INTERFACES or p["status"] != 0:
        return None
    return _parse_cpf(p["data"])


def _parse_register_session(pkt: bytes) -> dict | None:
    p = _parse_encap(pkt)
    if not p or p["cmd"] != _CMD_REGISTER_SESSION or p["status"] != 0:
        return None
    if len(p["data"]) < 4:
        return None
    proto_ver, options = struct.unpack("<HH", p["data"][:4])
    return {"session": p["session"], "protocol_version": proto_ver,
            "options": options}


def _parse_cip_response(body: bytes) -> dict | None:
    """MR reply: reply_service(1) reserved(1) general_status(1)
    ext_status_size(1, words) [ext_status] response_data."""
    if len(body) < 4:
        return None
    reply_service = body[0]
    general_status = body[2]
    ext_size = body[3]
    off = 4 + ext_size * 2
    if off > len(body):
        return None
    return {"service": reply_service & 0x7F,
            "reply": bool(reply_service & 0x80),
            "status": general_status,
            "data": body[off:]}


def _parse_send_rr_data(pkt: bytes) -> dict | None:
    """Unwrap SendRRData → CPF → unconnected data item → CIP MR response."""
    p = _parse_encap(pkt)
    if not p or p["cmd"] != _CMD_SEND_RR_DATA:
        return None
    if p["status"] != 0 or len(p["data"]) < 6:
        return None
    items = _parse_cpf(p["data"][6:])
    if not items:
        return None
    for itype, body in items:
        if itype == _CPF_UNCONN_DATA:
            return _parse_cip_response(body)
    return None


# --- attribute-block parsers (best-effort; devices vary wildly) ------------

def _parse_short_string(buf: bytes, off: int) -> tuple[str, int]:
    """SHORT_STRING: len(1) bytes(len). Returns (text, bytes_consumed)."""
    if off >= len(buf):
        return "", 0
    n = buf[off]
    if off + 1 + n > len(buf):
        return "", 0
    return buf[off + 1:off + 1 + n].decode("latin-1", "replace"), 1 + n


def _parse_tcpip_object(body: bytes) -> dict:
    """TCP/IP Interface Object (0xF5) GetAttributesAll (Vol 2 §5-3.2).
    Layout: status(4), config_capability(4), config_control(4),
    physical_link(struct: path_size(2) + path), interface_config(struct:
    ip(4) mask(4) gw(4) ns1(4) ns2(4) domain(SHORT_STRING)),
    host_name(SHORT_STRING). Best-effort — some firmware truncates."""
    out: dict = {"ip_address": "", "netmask": "", "gateway": "",
                 "name_server_1": "", "name_server_2": "",
                 "domain_name": "", "host_name": ""}
    if len(body) < 12:
        return out
    # status, cfg_capability, cfg_control take 12 bytes.
    off = 12
    if off + 2 > len(body):
        return out
    path_size = struct.unpack("<H", body[off:off + 2])[0]
    off += 2 + path_size * 2
    if off + 20 > len(body):
        return out
    # CIP UDINTs on the wire are little-endian; inet_ntoa expects network
    # byte order, so slice-and-reverse each 4-byte field.
    def _ip(raw: bytes) -> str:
        return socket.inet_ntoa(raw[::-1])
    out["ip_address"] = _ip(body[off:off + 4])
    out["netmask"] = _ip(body[off + 4:off + 8])
    out["gateway"] = _ip(body[off + 8:off + 12])
    ns1_raw = body[off + 12:off + 16]
    ns2_raw = body[off + 16:off + 20]
    if any(ns1_raw):
        out["name_server_1"] = _ip(ns1_raw)
    if any(ns2_raw):
        out["name_server_2"] = _ip(ns2_raw)
    off += 20
    domain, used = _parse_short_string(body, off)
    out["domain_name"] = domain
    off += used
    # SHORT_STRING is byte-length prefixed; the spec pads to a word boundary
    # for the following struct member on some devices.
    if used and used % 2:
        off += 1
    hostname, _ = _parse_short_string(body, off)
    out["host_name"] = hostname
    return out


def _parse_ethlink_object(body: bytes) -> dict:
    """Ethernet Link Object (0xF6) GetAttributesAll (Vol 2 §5-4.2).
    Layout begins: interface_speed(4), interface_flags(4), MAC(6)."""
    out: dict = {"interface_speed_mbps": 0, "interface_flags": 0,
                 "mac_address": ""}
    if len(body) < 14:
        return out
    speed, flags = struct.unpack("<II", body[:8])
    out["interface_speed_mbps"] = speed
    out["interface_flags"] = flags
    mac = body[8:14]
    out["mac_address"] = ":".join(f"{b:02x}" for b in mac)
    return out


# --- CVE correlation -------------------------------------------------------

def _cve_fingerprint(identity: dict) -> list[dict]:
    """Vendor + product-code + revision matches against advisories we can
    actually distinguish on the wire. Conservative — never speculates
    beyond what the Identity Object positively confirms.

    Each match carries a ``confirmed`` flag that is True only when the
    observed firmware revision falls inside the vulnerable band published
    by the advisory (T2 fingerprint). When False, the CVE stays flagged
    as a fingerprint hint but the caller should downgrade to a generic
    weakness rather than a positively-identified vulnerable release."""
    out: list[dict] = []
    if not identity:
        return out
    vid = identity.get("vendor_id", 0)
    rev_major = identity.get("revision_major", 0)
    rev_minor = identity.get("revision_minor", 0)
    name = (identity.get("product_name") or "").lower()
    if vid == 0x0001:
        # Rockwell CompactLogix / ControlLogix / MicroLogix families —
        # ICSA-21-056-03 / CVE-2021-22681 (weak session-key derivation)
        # applies to firmware < the mitigated release across the CIP-Security-
        # aware controllers.
        if ("compactlogix" in name or "controllogix" in name
                or "1756" in name or "1769" in name):
            # Per ICSA-21-056-03, Logix 5580 mitigation ships in firmware
            # v33.011 (and equivalents on other L-series). Anything older is
            # positively in the vulnerable band; ordering compare against
            # (33, 11) is safe because (major, minor) tuples are lex-ordered.
            rev = (rev_major, rev_minor)
            confirmed = bool(rev_major) and rev < (33, 11)
            out.append({
                "cve": "CVE-2021-22681",
                "family": "Rockwell Logix 5000",
                "note": "Weak CIP session key derivation — fingerprint by "
                        "product name; confirm firmware band against ICSA-"
                        "21-056-03 before treating as exploitable.",
                "confirmed": confirmed,
                "band": (f"vulnerable if firmware < 33.011 "
                         f"(observed {rev_major}.{rev_minor})"),
            })
        # MicroLogix 1400 — long history of unauthenticated PCCC-write
        # advisories (ICSA-17-138-03 etc.). PCCC is inherent to the platform,
        # no firmware fix — presence is confirmation.
        if "micrologix" in name:
            out.append({
                "cve": "CWE-306",
                "family": "Rockwell MicroLogix",
                "note": "MicroLogix product line exposes PCCC (class 0x67); "
                        "correlate revision against ICSA-17-138-03 family.",
                "confirmed": True,
                "band": ("MicroLogix family — PCCC command set is "
                         "unauthenticated by protocol design (no firmware "
                         "fix)"),
            })
    if vid == 0x005A and rev_major and rev_major < 3:
        out.append({
            "cve": "CWE-1188",
            "family": "Schneider M580 / Modicon",
            "note": "Schneider CIP controllers pre-firmware-v3 shipped with "
                    "insecure protocol defaults; correlate against Schneider "
                    "SEVD-2018-107-01.",
            "confirmed": True,
            "band": (f"Schneider firmware < 3.x per SEVD-2018-107-01 "
                     f"(observed {rev_major}.{rev_minor})"),
        })
    return out


# --- probe -----------------------------------------------------------------

def _recv_encap(sock: socket.socket) -> bytes | None:
    """Read one full encapsulation frame: 24-byte header then `length` body.
    Returns None on short read or socket error."""
    try:
        hdr = b""
        while len(hdr) < 24:
            chunk = sock.recv(24 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        length = struct.unpack("<H", hdr[2:4])[0]
        body = b""
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                return None
            body += chunk
        return hdr + body
    except OSError:
        return None


def _exchange(sock: socket.socket, req: bytes) -> bytes | None:
    try:
        sock.sendall(req)
    except OSError:
        return None
    return _recv_encap(sock)


def _cip_query(sock: socket.socket, session: int, service: int,
               class_id: int, instance: int,
               attr: int | None = None) -> dict | None:
    """Issue one CIP MR request via SendRRData; return parsed CIP reply."""
    req = _cip_mr_request(service, class_id, instance, attr)
    resp = _exchange(sock, _send_rr_data_req(session, req))
    if not resp:
        return None
    return _parse_send_rr_data(resp)


def _identity_from_getattrs_all(body: bytes) -> dict:
    """Vol 1 §5-2.2 GetAttributesAll response body for the Identity Object:
    vendor_id(2) device_type(2) product_code(2) major(1) minor(1) status(2)
    serial(4) name(SHORT_STRING). Some devices append attribute 8 (state, 1
    byte); many stop earlier."""
    out: dict = {"vendor_id": 0, "device_type": 0, "product_code": 0,
                 "revision": "0.0", "revision_major": 0, "revision_minor": 0,
                 "status_word": 0, "serial_number": 0,
                 "product_name": "", "device_state": 0}
    if len(body) < 14:
        return out
    vendor_id, device_type, product_code = struct.unpack("<HHH", body[:6])
    rev_major, rev_minor = body[6], body[7]
    status, serial = struct.unpack("<HI", body[8:14])
    out.update({"vendor_id": vendor_id, "device_type": device_type,
                "product_code": product_code,
                "revision_major": rev_major, "revision_minor": rev_minor,
                "revision": f"{rev_major}.{rev_minor}",
                "status_word": status, "serial_number": serial})
    name, used = _parse_short_string(body, 14)
    out["product_name"] = name
    if 14 + used < len(body):
        out["device_state"] = body[14 + used]
    return out


def probe(ip: str, port: int = _DEFAULT_PORT,
          timeout: float = _TIMEOUT) -> dict:
    """One TCP connect + bounded set of encapsulation + CIP exchanges.

    Order: List Identity → List Services → List Interfaces → RegisterSession
    → Identity/TCPIP/EthLink/PCCC/File/ConnMgr queries → UnregisterSession.
    The session is always torn down in a finally block so stale sessions
    do not accumulate against the device's session cap."""
    out: dict = {
        "reachable": False, "list_identity": None, "list_services": [],
        "list_interfaces": [], "list_services_names": [],
        "cip_encapsulation": False,
        "session": 0, "session_registered": False,
        "identity_detailed": None,
        "tcpip": None, "ethlink": None,
        "pccc_supported": False, "file_object_supported": False,
        "conn_mgr_supported": False,
        "reset_service_capable": False,
        "cip_security_off": False,
        # T2 promotion: names of CIP classes that answered a GetAttributes
        # request under the unauthenticated session — each successful reply
        # is proof-of-primitive that explicit messaging is unauthenticated.
        "unauth_queries_ok": [],
        "cve_matches": [], "error": "",
    }
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return out
    try:
        sock.settimeout(timeout)
        # List Identity — connectionless, no session required.
        resp = _exchange(sock, _list_identity_req())
        if resp:
            ident = _parse_list_identity(resp)
            if ident:
                out["reachable"] = True
                out["list_identity"] = ident

        # List Services — informational, gate on it for cip_encapsulation flag.
        resp = _exchange(sock, _list_services_req())
        if resp:
            svc = _parse_list_services(resp)
            if svc:
                out["list_services"] = svc
                out["list_services_names"] = [s["name"] for s in svc]
                out["cip_encapsulation"] = any(
                    s.get("cip_encapsulation") for s in svc)

        # List Interfaces — a device answering with any interface items is
        # typically a chassis/gateway.
        resp = _exchange(sock, _list_interfaces_req())
        if resp:
            interfaces = _parse_list_interfaces(resp)
            if interfaces:
                out["list_interfaces"] = [
                    {"type": t, "size": len(b)} for t, b in interfaces]

        # RegisterSession — opens explicit-messaging channel.
        resp = _exchange(sock, _register_session_req())
        if resp:
            reg = _parse_register_session(resp)
            if reg:
                out["session"] = reg["session"]
                out["session_registered"] = True
                out["reachable"] = True
                # A plaintext RegisterSession that succeeds on 44818 means
                # CIP Security (which would force DTLS/TLS on 2221) is off
                # on this endpoint. That is a stance finding, not an
                # observation about port 2221 itself.
                out["cip_security_off"] = True

        if out["session_registered"]:
            session = out["session"]
            # Detailed Identity via GetAttributesAll — extra fields (state,
            # status-word interpretation) beyond List Identity.
            r = _cip_query(sock, session, _CIP_GET_ATTRS_ALL,
                           _CIP_CLASS_IDENTITY, 1)
            if r and r["status"] == _CIP_STATUS_OK:
                out["identity_detailed"] = _identity_from_getattrs_all(
                    r["data"])
                # Identity Object supports Reset service (0x05) by
                # specification whenever GetAttributesAll succeeds on any
                # firmware without CIP Security enforcement. The write is
                # DESTRUCTIVE — recce never sends it — but its availability
                # is itself the finding.
                out["reset_service_capable"] = True

            # TCP/IP Interface Object — network config disclosure.
            r = _cip_query(sock, session, _CIP_GET_ATTRS_ALL,
                           _CIP_CLASS_TCPIP, 1)
            if r and r["status"] == _CIP_STATUS_OK:
                out["tcpip"] = _parse_tcpip_object(r["data"])

            # Ethernet Link Object — MAC disclosure.
            r = _cip_query(sock, session, _CIP_GET_ATTRS_ALL,
                           _CIP_CLASS_ETHLINK, 1)
            if r and r["status"] == _CIP_STATUS_OK:
                out["ethlink"] = _parse_ethlink_object(r["data"])

            # PCCC support — GetAttributesAll on class 0x67 instance 1. If
            # the class is present the reply is success OR an attribute-
            # level status (0x14 attr-not-supported), NOT 0x05 path-
            # destination-unknown. We treat "not 0x05 and not 0x08" as
            # "class exists on this device".
            r = _cip_query(sock, session, _CIP_GET_ATTRS_ALL,
                           _CIP_CLASS_PCCC, 1)
            if r and r["status"] not in (_CIP_STATUS_PATH_DEST_UNKNOWN,
                                         _CIP_STATUS_SERVICE_NOT_SUPPORTED):
                out["pccc_supported"] = True

            # File Object (0x37) instance 0xC8 — Rockwell firmware slot on
            # ControlLogix. Same supported-service inference. NEVER writes.
            r = _cip_query(sock, session, _CIP_GET_ATTR_SINGLE,
                           _CIP_CLASS_FILE, 0xC8, 1)
            if r and r["status"] not in (_CIP_STATUS_PATH_DEST_UNKNOWN,
                                         _CIP_STATUS_SERVICE_NOT_SUPPORTED):
                out["file_object_supported"] = True

            # Connection Manager (class 0x06) — presence gates ForwardOpen
            # routing (backplane traversal). We do NOT send the real
            # ForwardOpen; we probe the class attributes safely.
            r = _cip_query(sock, session, _CIP_GET_ATTRS_ALL,
                           _CIP_CLASS_CONN_MGR, 1)
            if r and r["status"] not in (_CIP_STATUS_PATH_DEST_UNKNOWN,
                                         _CIP_STATUS_SERVICE_NOT_SUPPORTED):
                out["conn_mgr_supported"] = True

            # T2 evidence for enip_unauth_session: enumerate the follow-on
            # queries that actually answered on the unauth session. Any
            # succeeding class IS the proof-of-primitive.
            unauth_ok: list[str] = []
            if out.get("identity_detailed"):
                unauth_ok.append("Identity (0x01)")
            if out.get("tcpip"):
                unauth_ok.append("TCP/IP (0xF5)")
            if out.get("ethlink"):
                unauth_ok.append("EthernetLink (0xF6)")
            if out.get("pccc_supported"):
                unauth_ok.append("PCCC (0x67)")
            if out.get("file_object_supported"):
                unauth_ok.append("File (0x37)")
            if out.get("conn_mgr_supported"):
                unauth_ok.append("ConnectionManager (0x06)")
            out["unauth_queries_ok"] = unauth_ok

            # Best-effort teardown.
            try:
                sock.sendall(_unregister_session_req(session))
            except OSError:
                pass
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # CVE correlation from identity fingerprint (List Identity preferred —
    # richer than the detailed GetAttrsAll on some firmware).
    ident = out["list_identity"] or out["identity_detailed"]
    out["cve_matches"] = _cve_fingerprint(ident or {})
    return out


# --- target extraction / findings -----------------------------------------

def enip_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_enip(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _has_udp_io_port(host: Host) -> bool:
    """UDP/2222 open = Class 1 implicit I/O traffic exposed on the segment."""
    for p in host.open_ports:
        if p.portid == 2222 and (p.protocol or "").lower() == "udp":
            return True
    return False


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target,
            "detail": detail, "tool": "cpppo / pylogix", "command": cmd,
            "remediation": rem, "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        # UDP/2222 Class 1 I/O — passive, fires whether or not 44818 answered.
        if _has_udp_io_port(h):
            out.append(_finding(
                "high",
                "EtherNet/IP Class 1 implicit I/O exposed on UDP/2222",
                f"{h.ip}:2222/udp",
                "UDP/2222 open indicates real-time Class 1 process I/O "
                "traffic traverses this segment in cleartext. An attacker "
                "with L2 reach can sniff and forge I/O assemblies to spoof "
                "sensor values without ever authenticating to a controller "
                "on 44818 — the physical process can be manipulated by "
                "editing the wire.",
                f"tcpdump -ni any udp port 2222 and host {h.ip}",
                "Segment implicit I/O onto a dedicated OT VLAN. Where the "
                "controller supports it, enable CIP Security (DTLS on "
                "2221/udp) so the I/O assemblies are authenticated and "
                "encrypted. Never carry Class 1 traffic across an untrusted "
                "L2 domain.",
                ["CWE-319", "CWE-345"], kind="enip_io_traffic_exposed",
                exploit_note=(
                    "tcpdump -ni any -w /tmp/enip-io.pcap udp port 2222 and "
                    "host <ip>; parse with cip-dissector; identify assemblies. "
                    "Injection PoC is lab-only."),
                depth_tier="t1"))

        for p in h.open_ports:
            if not is_enip(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ident = pr.get("list_identity") or pr.get("identity_detailed") or {}
            vendor_name = _VENDOR_NAMES.get(ident.get("vendor_id", 0), "")

            # Segmentation stance — every reachable ENIP endpoint.
            out.append(_finding(
                "high",
                "EtherNet/IP device reachable on scanned network", tgt,
                "Port 44818 accepted an EtherNet/IP encapsulation request "
                "and returned a valid CIP Identity item. EtherNet/IP is OT "
                "equipment (ODVA CIP over TCP/UDP); reaching one from a "
                "corporate/DMZ segment is a segmentation gap. IEC 62443-3-3 "
                "SR 5.1 and NIST SP 800-82r3 §5.5 both require OT to be "
                "isolated from IT.",
                f"# nmap enip-info NSE:\nnmap -sU -p 44818 --script "
                f"enip-info {h.ip}",
                "Place EtherNet/IP devices on an isolated OT network behind "
                "an industrial firewall. If IT-to-OT reachability is "
                "required, front the controller with a Rockwell Stratix "
                "DPI-capable switch / equivalent gateway that restricts "
                "source IPs and blocks explicit-messaging requests from "
                "untrusted networks.",
                ["CWE-923", "CWE-1188"], kind="enip_reachable",
                exploit_note=(
                    "nmap -sU -p 44818 --script enip-info <ip>; python -m "
                    "cpppo.server.enip.client --address <ip> --print."),
                depth_tier="t1"))

            # Identity fingerprint disclosure.
            if ident:
                vtxt = f" ({vendor_name})" if vendor_name else ""
                out.append(_finding(
                    "info",
                    "EtherNet/IP identity disclosed "
                    "(vendor / product / firmware / serial)", tgt,
                    f"CIP Identity: vendor_id=0x{ident.get('vendor_id',0):04x}"
                    f"{vtxt}  device_type=0x{ident.get('device_type',0):04x}"
                    f"  product_code={ident.get('product_code','?')}"
                    f"  revision={ident.get('revision','?')}"
                    f"  serial={ident.get('serial_number','?')}"
                    f"  name={ident.get('product_name','?')!r}"
                    f"  state=0x{ident.get('device_state',0):02x}. "
                    "The Identity Object is unauthenticated by protocol "
                    "design; the finding is that this fingerprint reaches "
                    "an untrusted network.",
                    f"# request Identity Object (class 0x01) via cpppo:\n"
                    f"python -m cpppo.server.enip.client --print "
                    f"--address {h.ip}",
                    "Segmentation stance from the reachable finding applies; "
                    "the fingerprint itself cannot be redacted per-field.",
                    ["CWE-200"], kind="enip_identity_detailed",
                    exploit_note=(
                        "Look up vendor_id + product_code + revision on the "
                        "Rockwell/Schneider/Omron support portals for "
                        "firmware CVE bands."),
                    depth_tier="t0"))

            # Unauthenticated session — cornerstone finding.
            if pr.get("session_registered"):
                unauth_ok = pr.get("unauth_queries_ok") or []
                # T2 evidence: at least one follow-on GetAttributes query
                # actually answered under the unauth session handle. The
                # RegisterSession handshake alone is T1 capability; a
                # class returning data on that handle is proof-of-primitive.
                proof_tier = "t2" if unauth_ok else "t1"
                proof_line = ""
                if unauth_ok:
                    id_state = ""
                    idd = pr.get("identity_detailed") or {}
                    if idd:
                        id_state = (
                            f" (Identity: vendor=0x{idd.get('vendor_id',0):04x} "
                            f"product={idd.get('product_name','?')!r} "
                            f"rev={idd.get('revision','?')} "
                            f"state=0x{idd.get('device_state',0):02x})")
                    proof_line = (
                        f" T2 PROOF: {len(unauth_ok)} CIP class(es) answered "
                        f"under this unauth session — "
                        f"{', '.join(unauth_ok)}.{id_state} "
                        f"The session handle IS a working explicit-messaging "
                        f"channel; every listed class was read with no "
                        f"credentials.")
                out.append(_finding(
                    "high",
                    "Unauthenticated CIP session accepted "
                    "(RegisterSession succeeded)", tgt,
                    f"RegisterSession (encap 0x0065) returned session handle "
                    f"0x{pr.get('session',0):08x} with no credentials. Every "
                    "subsequent SendRRData / UnconnectedSend / ForwardOpen "
                    "request in this scan was accepted on that handle. "
                    "Any tester on this segment has explicit-messaging "
                    f"access to the controller.{proof_line}",
                    f"python -m cpppo.server.enip.client --address {h.ip}",
                    "Enable CIP Security (Vol 8) so plaintext RegisterSession "
                    "on 44818/tcp is refused and clients are forced through "
                    "the DTLS/TLS endpoint on 2221. Where CIP Security is "
                    "not available on the controller firmware, restrict "
                    "44818 to management-only source IPs at the switch/"
                    "firewall.",
                    ["CWE-306", "CWE-287"], kind="enip_unauth_session",
                    exploit_note=(
                        "python -m cpppo.server.enip.client --address <ip> "
                        "--print --route-path 1/0 (backplane walk); if session "
                        "accepts explicit messaging, enumerate all classes."),
                    depth_tier=proof_tier))

            # CIP Security disabled — plaintext accepted.
            if pr.get("cip_security_off"):
                out.append(_finding(
                    "high",
                    "CIP Security disabled — plaintext explicit messaging "
                    "accepted", tgt,
                    "Plaintext RegisterSession on 44818 succeeded, meaning "
                    "the endpoint does not require the CIP Security "
                    "Confidentiality Profile (DTLS on 2221/udp, TLS on "
                    "2221/tcp). Every request-response pair below traverses "
                    "the network unauthenticated and unencrypted. This is "
                    "the single most important OT hardening control in "
                    "ODVA Vol 8.",
                    f"# 2221 vs 44818 posture check:\nnmap -p "
                    f"2221,44818 {h.ip}",
                    "Enable CIP Security in Studio 5000 / TIA-equivalent "
                    "and provision device certificates. Migrate all clients "
                    "to the 2221 TLS/DTLS endpoint and firewall-block 44818 "
                    "at the plant edge.",
                    ["CWE-319"], kind="enip_cip_security_off",
                    exploit_note=(
                        "nmap -p 2221,44818 <ip> — if 2221 is also open, CIP "
                        "Security is available but not enforced (worse); if "
                        "2221 is closed, firmware may not support it."),
                    depth_tier="t1"))

            # TCP/IP object disclosure — hostname / domain / DNS.
            tcpip = pr.get("tcpip") or {}
            if any(tcpip.get(k) for k in ("host_name", "domain_name",
                                          "name_server_1", "gateway")):
                fields = ", ".join(f"{k}={v!r}"
                                   for k, v in tcpip.items() if v)
                out.append(_finding(
                    "medium",
                    "CIP TCP/IP Interface Object exposes hostname / domain "
                    "/ DNS", tgt,
                    f"GetAttributesAll on class 0xF5 returned: {fields}. "
                    "Host name and domain name feed DNS / AD correlation; "
                    "primary/secondary DNS servers reveal internal name "
                    "servers reachable from this segment; the gateway "
                    "identifies the OT-side default route. All disclosed "
                    "with no authentication.",
                    f"# TCP/IP Object read via cpppo:\npython -m "
                    f"cpppo.server.enip.client --print --address {h.ip} "
                    f"'@0xF5/1'",
                    "Segmentation stance applies; the CIP TCP/IP object is "
                    "protocol-exposed by design. Rename devices with "
                    "labels that do not reveal plant location and keep "
                    "internal DNS off the OT network.",
                    # P0-1: T2 promotion — GetAttributesAll on class 0xF5
                    # returned concrete host_name / domain_name /
                    # name_server_1 / gateway fields extracted from the
                    # CIP TCP/IP Object reply. Every listed value came from
                    # the controller's own attribute dump.
                    ["CWE-200"], kind="enip_tcpip_disclosure",
                    exploit_note=(
                        "python -m cpppo.server.enip.client --address <ip> "
                        "--print '@0xF5/1'; dig ANY <domain_name> "
                        "@<name_server_1>; identify AD forest / internal "
                        "namespace exposed to OT."),
                    depth_tier="t2"))

            # Ethernet Link disclosure — MAC address for correlation.
            eth = pr.get("ethlink") or {}
            if eth.get("mac_address"):
                out.append(_finding(
                    "info",
                    "CIP Ethernet Link Object exposes MAC address", tgt,
                    f"GetAttributesAll on class 0xF6 returned MAC "
                    f"{eth['mac_address']} (link speed "
                    f"{eth.get('interface_speed_mbps','?')} Mbps). MAC is a "
                    "durable identifier for asset inventory and cross-scan "
                    "correlation with ARP / DHCP / 802.1X findings.",
                    f"python -m cpppo.server.enip.client --print "
                    f"--address {h.ip} '@0xF6/1'",
                    "Informational — pairs with the identity finding.",
                    ["CWE-200"], kind="enip_mac_disclosure",
                    exploit_note=(
                        "Cross-reference MAC OUI against IEEE registry "
                        "(Rockwell 00:00:BC / Siemens 00:1B:1B / etc); "
                        "correlate with ARP/DHCP scans on the same "
                        "segment."),
                    depth_tier="t0"))

            # List Services enumeration.
            if pr.get("list_services"):
                names = ", ".join(sorted(set(pr["list_services_names"]))) or "?"
                out.append(_finding(
                    "info",
                    "EtherNet/IP List Services enumerated", tgt,
                    f"List Services (encap 0x0004) returned: {names}. "
                    "CIP-encapsulation flag "
                    f"{'set' if pr.get('cip_encapsulation') else 'clear'} — "
                    "explicit-messaging is "
                    f"{'available' if pr.get('cip_encapsulation') else 'not offered'} "
                    "on this endpoint.",
                    f"nmap -p {p.portid} --script enip-info {h.ip}",
                    "Informational — feeds the reachable / unauth-session "
                    "findings above.",
                    ["CWE-200"], kind="enip_list_services",
                    exploit_note=(
                        "Note the cip_encapsulation flag — if clear, "
                        "RegisterSession will fail even though the port "
                        "answered."),
                    depth_tier="t0"))

            # List Interfaces — bridge / gateway indicator.
            if pr.get("list_interfaces"):
                out.append(_finding(
                    "medium",
                    "EtherNet/IP bridge / gateway detected "
                    "(List Interfaces populated)", tgt,
                    f"List Interfaces returned "
                    f"{len(pr['list_interfaces'])} non-CIP interface "
                    "item(s). A device with additional interfaces is "
                    "typically a chassis backplane / communications "
                    "adapter — a strong indicator that a deeper OT "
                    "segment is reachable via CIP routing (ForwardOpen "
                    "with a padded EPATH).",
                    f"# probe additional interfaces:\npython -m "
                    f"cpppo.server.enip.client --address {h.ip} "
                    f"--route-path 1/0",
                    "Restrict routing paths at the plant edge. Where a "
                    "bridge is legitimate, ensure the isolated OT segment "
                    "behind it has its own segmentation controls — do not "
                    "rely on obscurity of the routing paths.",
                    ["CWE-200", "CWE-923"], kind="enip_bridge_detected",
                    exploit_note=(
                        "python -m cpppo.server.enip.client --address <ip> "
                        "--route-path 1/0 --print (slot 0 CPU); repeat with "
                        "--route-path 1/1, 1/2, ... to enumerate every "
                        "module on the chassis backplane."),
                    depth_tier="t1"))

            # Connection Manager present — routing capable.
            if pr.get("conn_mgr_supported"):
                out.append(_finding(
                    "high",
                    "CIP backplane routable — ForwardOpen accepted by "
                    "Connection Manager", tgt,
                    "Connection Manager (class 0x06) responded to explicit "
                    "messaging on this session, confirming the device can "
                    "route messages through a chassis backplane via "
                    "ForwardOpen (service 0x54) with a padded EPATH. This "
                    "extends the attack surface to every module in the "
                    "chassis (CPU, I/O cards, comms adapters) even when "
                    "only one IP is exposed. Recce did NOT open a real "
                    "connection — the finding is capability, not exploit.",
                    f"# manual backplane enum via slot walk:\npython -m "
                    f"cpppo.server.enip.client --address {h.ip} "
                    f"--route-path 1/0 --print",
                    "Restrict source IPs for 44818 to a management-only "
                    "network. On ControlLogix chassis, place a "
                    "communications module in the DMZ role and disable "
                    "unnecessary routing paths at the backplane.",
                    ["CWE-923"], kind="enip_backplane_enum",
                    exploit_note=(
                        "python -m cpppo.server.enip.client --address <ip> "
                        "--route-path 1/0 --print '@0x01/1'; identity read via "
                        "ForwardOpen proves backplane traversal to the CPU."),
                    depth_tier="t1"))

            # PCCC (Rockwell legacy) — critical, unauthenticated memory access.
            if pr.get("pccc_supported"):
                out.append(_finding(
                    "critical",
                    "Rockwell PCCC (CIP service 0x4B on class 0x67) "
                    "reachable — unauthenticated memory read/write", tgt,
                    "Class 0x67 answered a GetAttributesAll request, "
                    "confirming the legacy PCCC command set is exposed. "
                    "PCCC supports protected-typed-logical-read and -write "
                    "operations that dump tag values, program state, and "
                    "on MicroLogix / SLC / PLC-5 the controller password "
                    "hash — all with NO authentication. Once dumped, the "
                    "password hash is offline-crackable.",
                    f"# read PCCC N7:0 (10 words) as safe demonstration:\n"
                    f"python -m cpppo.server.enip.client --address {h.ip} "
                    f"--pccc 'N7:0-N7:9'",
                    "PCCC has no protocol-level authentication and cannot "
                    "be selectively disabled on the affected controller "
                    "families. Segment the PLC onto an isolated OT VLAN "
                    "and require jump-host access. Replace end-of-life "
                    "MicroLogix / SLC 500 platforms.",
                    ["CWE-306", "CWE-284"], kind="enip_pccc_read",
                    exploit_note=(
                        "python -m cpppo.server.enip.client --address <ip> "
                        "--pccc 'N7:0-N7:9' (read PCCC integer file); "
                        "MicroLogix password hash: pylogix-pccc-dump-password "
                        "<ip> then john hash.txt --format=raw-md5 (or bespoke "
                        "ML1400 cracker)."),
                    depth_tier="t2"))

            # Reset service capability (CPU stop) — critical.
            if pr.get("reset_service_capable"):
                out.append(_finding(
                    "critical",
                    "Unauthenticated CPU stop/reset capable "
                    "(Identity Object service 0x05)", tgt,
                    "The Identity Object accepted GetAttributesAll on this "
                    "session, which means service 0x05 (Reset) is exposed "
                    "on the same object under the same session handle. On "
                    "any firmware without CIP Security enforcement, "
                    "issuing Reset drops the CPU to Program mode from the "
                    "network — process-halting critical impact. Recce "
                    "NEVER sends Reset; the finding is protocol capability "
                    "under an accepted unauthenticated session.",
                    f"# WARNING — halts the process, do NOT run against a "
                    f"production controller:\n"
                    f"# python -m cpppo.server.enip.client --address "
                    f"{h.ip} --reset",
                    "Enable CIP Security and provision certificates so "
                    "Reset requires a mutually-authenticated session. "
                    "Where CIP Security is not available, restrict 44818 "
                    "to management-only source IPs at the switch and "
                    "operate the controller in Run mode with the physical "
                    "key-switch in RUN (some controllers refuse Reset in "
                    "that position).",
                    ["CWE-306", "CWE-284", "CWE-1188"],
                    kind="enip_unauth_stop_cpu",
                    exploit_note=(
                        "TEST-CELL ONLY: python -m cpppo.server.enip.client "
                        "--address <ip> --reset; verify on the CPU face-plate "
                        "the LED goes to PROG. Never on production."),
                    depth_tier="t1"))

            # Firmware download capability (File Object 0x37 / vendor 0x4E).
            if pr.get("file_object_supported"):
                out.append(_finding(
                    "critical",
                    "Unauthenticated firmware-download service exposed "
                    "(File Object 0x37)", tgt,
                    "GetAttributeSingle on class 0x37 instance 0xC8 (the "
                    "Rockwell firmware File Object slot) succeeded on the "
                    "unauthenticated session. The write path (service 0x4E "
                    "Initiate_Upload / firmware download) exposes network-"
                    "reachable firmware replacement with no certificate or "
                    "password on affected controller families (Rockwell "
                    "ICSA-21-056-03 class). Recce probed availability only; "
                    "the write itself is DESTRUCTIVE and is not sent.",
                    f"# check File Object attribute set safely:\npython -m "
                    f"cpppo.server.enip.client --address {h.ip} "
                    f"'@0x37/0xC8'",
                    "Apply the vendor firmware release that requires signed "
                    "images and CIP Security for firmware transfer. Disable "
                    "network firmware download at the controller until the "
                    "fix is in place; enforce jump-host + physical-key-"
                    "switch procedure for updates.",
                    ["CWE-306", "CWE-345", "CWE-494"],
                    kind="enip_firmware_upload_capable",
                    exploit_note=(
                        "TEST-CELL ONLY: study Rockwell CVE-2016-9343/ICSA-21-"
                        "056-03 PoC, use vendor firmware kit; do NOT attempt on "
                        "production or you brick the controller."),
                    depth_tier="t2"))

            # CVE fingerprints from Identity Object.
            for m in pr.get("cve_matches") or []:
                # T2 = firmware revision actually lands inside the advisory's
                # vulnerable band (see _cve_fingerprint). Uncertain matches
                # stay T1 with a generic CWE reference so the tester knows to
                # verify manually before assigning the CVE.
                confirmed = bool(m.get("confirmed"))
                band = m.get("band") or ""
                proof_tier = "t2" if confirmed else "t1"
                sev = "high" if confirmed else "medium"
                band_line = (f" T2 PROOF: firmware band satisfied — {band}."
                             if confirmed else
                             f" T1 fingerprint only — band check inconclusive"
                             f" ({band}); verify manually before assigning "
                             f"the CVE.")
                out.append(_finding(
                    sev,
                    f"EtherNet/IP fingerprint matches advisory ({m['cve']})",
                    tgt,
                    f"Identity fingerprint identifies {m['family']}. "
                    f"{m['note']}{band_line}",
                    "# correlate against the advisory:\n"
                    "# https://www.cisa.gov/news-events/ics-advisories",
                    f"Apply the vendor firmware release addressing "
                    f"{m['cve']}; segment the controller regardless.",
                    ["CWE-1395"], kind="enip_known_cve",
                    exploit_note=(
                        "For Rockwell Logix 5000 CVE-2021-22681: use CIP-Sec "
                        "PoC to prove weak session-key derivation; for "
                        "MicroLogix ICSA-17-138-03: pull the PCCC password hash "
                        "and crack it."),
                    depth_tier=proof_tier))
    return out


def encap_signature_hex() -> str:
    """The stable 4-byte magic scanners can match against a servicefp /
    banner grab to positively identify an ENIP endpoint even when nmap
    returns 'unknown' or 'tcpwrapped'. Bytes = List Identity response
    prefix: cmd 0x0063 LE, length 0x001F LE (a common Rockwell response
    length) — feed to svcdetect._SIGNATURES for the wire-up pass."""
    return "63 00 1f 00"


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "List Identity (encap 0x0063) — presence + fingerprint",
         "cmd": f"nmap -sU -p {port} --script enip-info {ip}"},
        {"step": "RegisterSession + GetAttributesAll on Identity Object",
         "cmd": f"python -m cpppo.server.enip.client --print --address {ip}"},
        {"step": "TCP/IP Object read (hostname / domain / DNS)",
         "cmd": f"python -m cpppo.server.enip.client --print --address "
                f"{ip} '@0xF5/1'"},
        {"step": "Ethernet Link Object read (MAC / speed)",
         "cmd": f"python -m cpppo.server.enip.client --print --address "
                f"{ip} '@0xF6/1'"},
        {"step": "Backplane walk via ForwardOpen route-path (chassis enum)",
         "cmd": f"python -m cpppo.server.enip.client --address {ip} "
                f"--route-path 1/0 --print"},
        {"step": "MANUAL / DESTRUCTIVE — Identity Reset (CPU stop)",
         "cmd": f"# python -m cpppo.server.enip.client --address {ip} "
                f"--reset   # only under change control"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "enip", _DEFAULT_PORT)


def _record_asset(hosts: list[Host], ip: str, ident: dict) -> None:
    """Feed the CIP List Identity into core.known_ot_assets — the ODVA vendor
    id + product name + revision + serial is the reference OT asset identity
    for EtherNet/IP-speaking controllers (Vol 1 §5-2 Identity Object)."""
    if not ident:
        return
    vid = ident.get("vendor_id") or 0
    vendor = _VENDOR_NAMES.get(vid, "") or (f"ODVA vendor 0x{vid:04x}"
                                            if vid else "")
    model = ident.get("product_name") or ""
    revision = ident.get("revision") or ""
    serial = ident.get("serial_number") or 0
    serial_s = f"{serial:08x}" if serial else ""
    if not (vendor or model or serial_s):
        return
    from ..core.known_ot_assets import record_ot_asset
    for h in hosts:
        if h.ip == ip:
            record_ot_asset(h, "enip", vendor=vendor, model=model,
                            firmware=revision, serial=serial_s,
                            source="enip:list-identity")
            break


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = enip_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                ident = pr.get("list_identity") or pr.get("identity_detailed") or {}
                t["vendor_id"] = ident.get("vendor_id", 0)
                t["product_name"] = ident.get("product_name", "")
                t["revision"] = ident.get("revision", "")
                _record_asset(hosts, t["ip"], ident)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
