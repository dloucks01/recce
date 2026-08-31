"""OPC UA (4840/tcp) probe — ICS/IIoT interoperability plane.

OPC UA (IEC 62541) is the modern OT interoperability protocol: a binary UA
Connection Protocol (uacp) over TCP that negotiates a SecureChannel and
carries an object-oriented information model. The unauthenticated Discovery
services (GetEndpoints, FindServers) are MANDATED by the spec — every
conformant server answers them, and the answers include endpoint URLs,
security policies and modes, user token policies, application identity, and
the server's X.509 certificate.

Coverage here (all stdlib, no crypto — SecurityPolicy=None throughout):
  * HELLO/ACK handshake (uacp fingerprint, ACKF or ERRF magic)
  * OpenSecureChannel with SecurityPolicy=None (no crypto path)
  * GetEndpoints — parses every EndpointDescription
  * FindServers — sibling servers + discoveryUrls
  * FindServersOnNetwork — LDS-ME network inventory
  * RegisterServer — open-registration abuse (rogue-server primitive)
  * Deliberately-oversized HELLO for the ERR message SDK-name leak
  * X.509 certificate parse (subject/issuer CN, SANs, validity, key size,
    self-signed heuristic)

The exchange is intentionally kept out of the crypto path: SenderCertificate
and ReceiverCertificateThumbprint are null ByteStrings, so no key material
is required.

Deferred (need session establishment with client/server nonces):
  * anonymous CreateSession + ActivateSession + Browse
  * ServerStatus Read
  * UserName bruteforce (also needs RSA-OAEP against serverCertificate)

Airgap-safe: stdlib socket + struct only. Bounded timeouts on every recv.
"""
from __future__ import annotations

import socket
import struct

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 4840
_TIMEOUT = 4.0

# UACP message types (three ASCII bytes each).
_MT_HEL = b"HEL"
_MT_ACK = b"ACK"
_MT_ERR = b"ERR"
_MT_OPN = b"OPN"
_MT_MSG = b"MSG"
_MT_CLO = b"CLO"

# Chunk types.
_CT_FINAL = b"F"

# Well-known UA String constants.
_POLICY_NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"
_POLICY_BASIC128RSA15 = "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15"
_POLICY_BASIC256 = "http://opcfoundation.org/UA/SecurityPolicy#Basic256"

# Deprecated policies (2017 deprecation notice from the OPC Foundation).
_DEPRECATED_POLICIES = (_POLICY_BASIC128RSA15, _POLICY_BASIC256)

# ApplicationType enum (Part 4 §7.1).
_APP_TYPE = {0: "Server", 1: "Client", 2: "ClientAndServer", 3: "DiscoveryServer"}

# UserTokenType enum (Part 4 §7.36).
_TOKEN_TYPE = {0: "Anonymous", 1: "UserName", 2: "Certificate", 3: "IssuedToken"}

# MessageSecurityMode enum (Part 4 §7.15).
_SEC_MODE = {1: "None", 2: "Sign", 3: "SignAndEncrypt"}

# NodeId ObjectIds for the service requests we emit — encoded as FourByte
# NodeIds (encoding byte 0x01, namespace 0x00, identifier uint16 LE).
_ID_OPEN_SECURE_CHANNEL_REQ = 446
_ID_GET_ENDPOINTS_REQ = 428
_ID_FIND_SERVERS_REQ = 422
_ID_FIND_SERVERS_ON_NETWORK_REQ = 12208
_ID_REGISTER_SERVER_REQ = 437
_ID_CLOSE_SECURE_CHANNEL_REQ = 452


def is_opcua(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    if port.portid in (4840, 4843):
        return True
    return "opcua" in svc or "opc-ua" in svc or "opcua" in prod or "opc ua" in prod


# --- primitive encoders --------------------------------------------------------


def _u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _i32(v: int) -> bytes:
    return struct.pack("<i", v)


def _u16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF)


def _u8(v: int) -> bytes:
    return bytes([v & 0xFF])


def _pack_string(s: str | None) -> bytes:
    """UA String: int32 length (LE) + UTF-8 bytes. -1 = null."""
    if s is None:
        return _i32(-1)
    b = s.encode("utf-8")
    return _i32(len(b)) + b


def _pack_bytestring(b: bytes | None) -> bytes:
    if b is None:
        return _i32(-1)
    return _i32(len(b)) + b


def _pack_datetime_null() -> bytes:
    return b"\x00" * 8


def _pack_nodeid_fourbyte(identifier: int, namespace: int = 0) -> bytes:
    return b"\x01" + _u8(namespace) + _u16(identifier)


def _pack_nodeid_two_or_numeric(identifier: int, namespace: int = 0) -> bytes:
    if namespace == 0 and identifier < 0x100:
        return b"\x00" + _u8(identifier)
    if namespace < 0x100 and identifier < 0x10000:
        return b"\x01" + _u8(namespace) + _u16(identifier)
    return b"\x02" + _u16(namespace) + _u32(identifier)


def _pack_null_extension_object() -> bytes:
    # NodeId (TwoByte 0) + encoding byte 0 = "no body"
    return b"\x00\x00" + b"\x00"


def _pack_request_header(request_handle: int = 1,
                         timeout_ms: int = 5000) -> bytes:
    # authenticationToken: NodeId (TwoByte 0 = anonymous / initial)
    hdr = b"\x00\x00"
    hdr += _pack_datetime_null()          # timestamp
    hdr += _u32(request_handle)
    hdr += _u32(0)                        # returnDiagnostics
    hdr += _pack_string(None)             # auditEntryId
    hdr += _u32(timeout_ms)               # timeoutHint
    hdr += _pack_null_extension_object()  # additionalHeader
    return hdr


# --- message framing -----------------------------------------------------------


def _frame(message_type: bytes, body: bytes,
           chunk_type: bytes = _CT_FINAL) -> bytes:
    """MessageType(3) + ChunkType(1) + MessageSize uint32 LE + body."""
    size = 4 + 4 + len(body)
    return message_type + chunk_type + _u32(size) + body


def _hello_body(endpoint_url: str = "opc.tcp://recce/",
                protocol_version: int = 0,
                receive_buffer_size: int = 65536,
                send_buffer_size: int = 65536,
                max_message_size: int = 4194304,
                max_chunk_count: int = 64) -> bytes:
    return (_u32(protocol_version)
            + _u32(receive_buffer_size)
            + _u32(send_buffer_size)
            + _u32(max_message_size)
            + _u32(max_chunk_count)
            + _pack_string(endpoint_url))


def _opn_open_secure_channel(request_id: int = 1, request_handle: int = 1) -> bytes:
    """OPN body opening a SecureChannel with SecurityPolicy=None."""
    body = _u32(0)                            # SecureChannelId (0 = new channel)
    # AsymmetricAlgorithmSecurityHeader (SecurityPolicy=None, both certs null)
    body += _pack_string(_POLICY_NONE)
    body += _pack_bytestring(None)            # SenderCertificate
    body += _pack_bytestring(None)            # ReceiverCertificateThumbprint
    # SequenceHeader
    body += _u32(request_id)
    body += _u32(request_id)
    # Payload: OpenSecureChannelRequest
    body += _pack_nodeid_fourbyte(_ID_OPEN_SECURE_CHANNEL_REQ)
    body += _pack_request_header(request_handle=request_handle)
    body += _u32(0)                           # ClientProtocolVersion
    body += _u32(0)                           # RequestType: ISSUE
    body += _u32(1)                           # SecurityMode: None
    body += _pack_bytestring(None)            # ClientNonce (null under None)
    body += _u32(3_600_000)                   # RequestedLifetime (ms)
    return body


def _msg_body(secure_channel_id: int, token_id: int, sequence_number: int,
              request_id: int, payload: bytes) -> bytes:
    return (_u32(secure_channel_id)
            + _u32(token_id)
            + _u32(sequence_number)
            + _u32(request_id)
            + payload)


def _get_endpoints_payload(request_handle: int) -> bytes:
    body = _pack_nodeid_fourbyte(_ID_GET_ENDPOINTS_REQ)
    body += _pack_request_header(request_handle=request_handle)
    body += _pack_string("opc.tcp://recce/")   # endpointUrl
    body += _i32(-1)                           # localeIds (null array)
    body += _i32(-1)                           # profileUris (null array)
    return body


def _find_servers_payload(request_handle: int) -> bytes:
    body = _pack_nodeid_fourbyte(_ID_FIND_SERVERS_REQ)
    body += _pack_request_header(request_handle=request_handle)
    body += _pack_string("opc.tcp://recce/")
    body += _i32(-1)                           # localeIds
    body += _i32(-1)                           # serverUris
    return body


def _find_servers_on_network_payload(request_handle: int) -> bytes:
    # 12208 is out of FourByte range for identifier; fall through to Numeric.
    body = _pack_nodeid_two_or_numeric(_ID_FIND_SERVERS_ON_NETWORK_REQ)
    body += _pack_request_header(request_handle=request_handle)
    body += _u32(0)                            # startingRecordId
    body += _u32(0)                            # maxRecordsToReturn (0 = all)
    body += _i32(-1)                           # serverCapabilityFilter
    return body


def _register_server_payload(request_handle: int) -> bytes:
    body = _pack_nodeid_fourbyte(_ID_REGISTER_SERVER_REQ)
    body += _pack_request_header(request_handle=request_handle)
    # RegisteredServer:
    body += _pack_string("urn:recce:opcua:probe")   # serverUri
    body += _pack_string("urn:recce:probe")         # productUri
    # serverNames: int32 count + N LocalizedText (mask=0x02 text-only)
    body += _u32(1)
    body += b"\x02" + _pack_string("recce-probe")
    body += _u32(0)                                 # serverType: Server
    body += _pack_string(None)                      # gatewayServerUri
    body += _u32(1)                                 # discoveryUrls count
    body += _pack_string("opc.tcp://recce:4840/")
    body += _pack_string(None)                      # semaphoreFilePath
    body += b"\x01"                                 # isOnline: true
    return body


# --- primitive decoders --------------------------------------------------------


class _Cursor:
    """Bounded cursor over a bytes buffer — every read validates remaining length
    so a truncated/hostile message raises IndexError rather than returning junk."""

    __slots__ = ("buf", "off")

    def __init__(self, buf: bytes, off: int = 0):
        self.buf = buf
        self.off = off

    def _need(self, n: int) -> None:
        if self.off + n > len(self.buf):
            raise IndexError("uacp cursor overrun")

    def u8(self) -> int:
        self._need(1)
        v = self.buf[self.off]
        self.off += 1
        return v

    def u16(self) -> int:
        self._need(2)
        v = struct.unpack("<H", self.buf[self.off:self.off + 2])[0]
        self.off += 2
        return v

    def u32(self) -> int:
        self._need(4)
        v = struct.unpack("<I", self.buf[self.off:self.off + 4])[0]
        self.off += 4
        return v

    def i32(self) -> int:
        self._need(4)
        v = struct.unpack("<i", self.buf[self.off:self.off + 4])[0]
        self.off += 4
        return v

    def i64(self) -> int:
        self._need(8)
        v = struct.unpack("<q", self.buf[self.off:self.off + 8])[0]
        self.off += 8
        return v

    def take(self, n: int) -> bytes:
        self._need(n)
        v = self.buf[self.off:self.off + n]
        self.off += n
        return v

    def string(self) -> str | None:
        n = self.i32()
        if n < 0:
            return None
        return self.take(n).decode("utf-8", "replace")

    def bytestring(self) -> bytes | None:
        n = self.i32()
        if n < 0:
            return None
        return self.take(n)

    def datetime(self) -> int:
        return self.i64()

    def nodeid(self) -> tuple[int, int]:
        """Return (namespace, identifier). Raises on unsupported forms."""
        enc = self.u8() & 0x3F                # strip has-namespace-uri / server-idx bits
        if enc == 0x00:
            return (0, self.u8())
        if enc == 0x01:
            ns = self.u8()
            return (ns, self.u16())
        if enc == 0x02:
            ns = self.u16()
            return (ns, self.u32())
        if enc == 0x03:
            ns = self.u16()
            s = self.string()
            return (ns, s if s is not None else "")
        if enc == 0x04:
            ns = self.u16()
            self.take(16)
            return (ns, 0)
        if enc == 0x05:
            ns = self.u16()
            self.bytestring()
            return (ns, 0)
        raise ValueError(f"unknown NodeId encoding 0x{enc:02x}")

    def extension_object(self) -> None:
        self.nodeid()
        enc = self.u8()
        if enc == 0x01:
            self.bytestring()
        elif enc == 0x02:
            self.bytestring()

    def localized_text(self) -> str:
        mask = self.u8()
        locale = None
        text = None
        if mask & 0x01:
            locale = self.string()
        if mask & 0x02:
            text = self.string()
        return text or locale or ""


def _parse_frame_header(pkt: bytes) -> tuple[bytes, bytes, int] | None:
    """Return (message_type, chunk_type, size) or None if unrecognisable."""
    if len(pkt) < 8:
        return None
    mt = pkt[0:3]
    ct = pkt[3:4]
    size = struct.unpack("<I", pkt[4:8])[0]
    return mt, ct, size


def _parse_ack(body: bytes) -> dict:
    c = _Cursor(body)
    return {
        "protocol_version": c.u32(),
        "receive_buffer_size": c.u32(),
        "send_buffer_size": c.u32(),
        "max_message_size": c.u32(),
        "max_chunk_count": c.u32(),
    }


def _parse_err(body: bytes) -> dict:
    c = _Cursor(body)
    status = c.u32()
    try:
        reason = c.string() or ""
    except IndexError:
        reason = ""
    return {"status_code": status, "reason": reason}


def _parse_response_header(c: _Cursor) -> dict:
    ts = c.datetime()
    handle = c.u32()
    result = c.u32()
    _diag_mask = c.u8()
    # skip diagnostic-info body (encoded per mask bits) — best-effort: if
    # the mask is 0 (overwhelmingly the case) there is nothing more to skip.
    string_count = c.i32()
    for _ in range(max(0, string_count)):
        c.string()
    c.extension_object()
    return {"timestamp": ts, "request_handle": handle, "service_result": result}


def _parse_application_description(c: _Cursor) -> dict:
    return {
        "application_uri": c.string() or "",
        "product_uri": c.string() or "",
        "application_name": c.localized_text(),
        "application_type": c.u32(),
        "gateway_server_uri": c.string() or "",
        "discovery_profile_uri": c.string() or "",
        "discovery_urls": [c.string() or "" for _ in range(max(0, c.i32()))],
    }


def _parse_user_token_policy(c: _Cursor) -> dict:
    return {
        "policy_id": c.string() or "",
        "token_type": c.u32(),
        "issued_token_type": c.string() or "",
        "issuer_endpoint_url": c.string() or "",
        "security_policy_uri": c.string() or "",
    }


def _parse_endpoint_description(c: _Cursor) -> dict:
    endpoint_url = c.string() or ""
    server = _parse_application_description(c)
    cert = c.bytestring()
    security_mode = c.u32()
    security_policy_uri = c.string() or ""
    n_tokens = c.i32()
    tokens = [_parse_user_token_policy(c) for _ in range(max(0, n_tokens))]
    transport = c.string() or ""
    level = c.u8()
    return {
        "endpoint_url": endpoint_url,
        "server": server,
        "server_certificate": cert,
        "security_mode": security_mode,
        "security_policy_uri": security_policy_uri,
        "user_identity_tokens": tokens,
        "transport_profile_uri": transport,
        "security_level": level,
    }


def _parse_get_endpoints_response(body: bytes) -> dict:
    c = _Cursor(body)
    header = _parse_response_header(c)
    n = c.i32()
    endpoints = [_parse_endpoint_description(c) for _ in range(max(0, n))]
    return {"header": header, "endpoints": endpoints}


def _parse_find_servers_response(body: bytes) -> dict:
    c = _Cursor(body)
    header = _parse_response_header(c)
    n = c.i32()
    servers = [_parse_application_description(c) for _ in range(max(0, n))]
    return {"header": header, "servers": servers}


def _parse_find_servers_on_network_response(body: bytes) -> dict:
    c = _Cursor(body)
    header = _parse_response_header(c)
    c.datetime()                              # lastCounterResetTime
    n = c.i32()
    servers = []
    for _ in range(max(0, n)):
        servers.append({
            "record_id": c.u32(),
            "server_name": c.string() or "",
            "discovery_url": c.string() or "",
            "capabilities": [c.string() or "" for _ in range(max(0, c.i32()))],
        })
    return {"header": header, "servers": servers}


def _parse_register_server_response(body: bytes) -> dict:
    c = _Cursor(body)
    header = _parse_response_header(c)
    return {"header": header}


def _parse_open_secure_channel_response(body: bytes) -> dict:
    """OPN reply: SecureChannelId + security header + sequence header +
    NodeId + ResponseHeader + ServerProtocolVersion + SecurityToken +
    ServerNonce."""
    c = _Cursor(body)
    channel_id = c.u32()
    c.string()                                # SecurityPolicyUri (echoed)
    c.bytestring()                            # SenderCertificate
    c.bytestring()                            # ReceiverCertificateThumbprint
    c.u32()                                   # SequenceNumber
    c.u32()                                   # RequestId
    c.nodeid()                                # OpenSecureChannelResponse typeId
    _parse_response_header(c)
    c.u32()                                   # ServerProtocolVersion
    # SecurityToken
    sec_channel_id = c.u32()
    token_id = c.u32()
    c.datetime()                              # CreatedAt
    c.u32()                                   # RevisedLifetime
    return {
        "secure_channel_id": sec_channel_id or channel_id,
        "token_id": token_id,
    }


# --- socket helpers ------------------------------------------------------------


def _recv_frame(sock: socket.socket) -> bytes | None:
    """Read one uacp frame off the socket. Returns raw frame bytes or None."""
    try:
        header = _recv_exact(sock, 8)
        if header is None:
            return None
        size = struct.unpack("<I", header[4:8])[0]
        if size < 8 or size > 8 * 1024 * 1024:   # cap at 8 MB
            return None
        rest = _recv_exact(sock, size - 8)
        if rest is None:
            return None
        return header + rest
    except OSError:
        return None


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(min(65536, n - len(buf)))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# --- high-level probe steps ----------------------------------------------------


def _hello_ack(sock: socket.socket, endpoint_url: str = "opc.tcp://recce/",
               protocol_version: int = 0) -> dict | None:
    body = _hello_body(endpoint_url=endpoint_url,
                       protocol_version=protocol_version)
    try:
        sock.sendall(_frame(_MT_HEL, body))
    except OSError:
        return None
    frame = _recv_frame(sock)
    if not frame:
        return None
    hdr = _parse_frame_header(frame)
    if not hdr:
        return None
    mt, _ct, _size = hdr
    if mt == _MT_ACK:
        try:
            return {"kind": "ACK", **_parse_ack(frame[8:])}
        except (IndexError, struct.error):
            return {"kind": "ACK"}
    if mt == _MT_ERR:
        try:
            return {"kind": "ERR", **_parse_err(frame[8:])}
        except (IndexError, struct.error):
            return {"kind": "ERR"}
    return None


def _open_channel(sock: socket.socket) -> dict | None:
    try:
        sock.sendall(_frame(_MT_OPN, _opn_open_secure_channel()))
    except OSError:
        return None
    frame = _recv_frame(sock)
    if not frame:
        return None
    hdr = _parse_frame_header(frame)
    if not hdr:
        return None
    mt, _ct, _size = hdr
    if mt != _MT_OPN:
        return None
    try:
        return _parse_open_secure_channel_response(frame[8:])
    except (IndexError, struct.error, ValueError):
        return None


def _send_service(sock: socket.socket, channel: dict, request_id: int,
                  payload: bytes):
    body = _msg_body(channel["secure_channel_id"], channel["token_id"],
                     request_id, request_id, payload)
    try:
        sock.sendall(_frame(_MT_MSG, body))
    except OSError:
        return None
    frame = _recv_frame(sock)
    if not frame:
        return None
    hdr = _parse_frame_header(frame)
    if not hdr:
        return None
    mt, _ct, _size = hdr
    if mt != _MT_MSG:
        return None
    return frame[8:]


def _service_body_after_headers(msg_body: bytes) -> bytes | None:
    """Strip SecureChannelId + TokenId + SequenceHeader + NodeId to leave the
    ResponseHeader + service response body."""
    try:
        c = _Cursor(msg_body)
        c.u32()                               # SecureChannelId
        c.u32()                               # TokenId
        c.u32()                               # SequenceNumber
        c.u32()                               # RequestId
        c.nodeid()                            # response typeId
        return msg_body[c.off:]
    except (IndexError, struct.error, ValueError):
        return None


# --- X.509 minimal DER parser --------------------------------------------------


def _asn1_read(buf: bytes, off: int) -> tuple[int, int, int, int] | None:
    """Return (tag, header_len, content_len, content_off) or None."""
    if off >= len(buf):
        return None
    tag = buf[off]
    if off + 1 >= len(buf):
        return None
    ln = buf[off + 1]
    hoff = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or hoff + n > len(buf):
            return None
        ln = 0
        for i in range(n):
            ln = (ln << 8) | buf[hoff + i]
        hoff += n
    if hoff + ln > len(buf):
        return None
    return tag, hoff - off, ln, hoff


def _asn1_children(buf: bytes, off: int, end: int) -> list[tuple[int, int, int, int]]:
    """List (tag, hlen, clen, coff) for every child from off..end."""
    out = []
    while off < end:
        rec = _asn1_read(buf, off)
        if not rec:
            break
        tag, hlen, clen, coff = rec
        out.append(rec)
        off = coff + clen
    return out


# OIDs of interest, DER-encoded.
_OID_CN = bytes.fromhex("550403")
_OID_O = bytes.fromhex("55040A")
_OID_SAN = bytes.fromhex("551D11")
_OID_RSA = bytes.fromhex("2A864886F70D010101")


def _oid_string(data: bytes) -> str:
    if not data:
        return ""
    out = [str(data[0] // 40), str(data[0] % 40)]
    v = 0
    for b in data[1:]:
        v = (v << 7) | (b & 0x7F)
        if not (b & 0x80):
            out.append(str(v))
            v = 0
    return ".".join(out)


def _decode_name_cn(name_der: bytes, name_end: int) -> str:
    """Extract the first CN out of a Name (RDNSequence)."""
    for _, _, clen, coff in _asn1_children(name_der, 0, name_end):
        # each RDN is a SET containing a SEQUENCE {OID, value}
        for _, _, sclen, scoff in _asn1_children(name_der, coff, coff + clen):
            attr = _asn1_children(name_der, scoff, scoff + sclen)
            if len(attr) < 2:
                continue
            _t, _h, oclen, ocoff = attr[0]
            oid = name_der[ocoff:ocoff + oclen]
            if oid == _OID_CN:
                _t, _h, vclen, vcoff = attr[1]
                return name_der[vcoff:vcoff + vclen].decode("utf-8", "replace")
    return ""


def _decode_time(buf: bytes, tag: int) -> str:
    """UTCTime (13) / GeneralizedTime (15) — return YYYY-MM-DD."""
    s = buf.decode("ascii", "replace")
    if tag == 0x17 and len(s) >= 12:
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        return f"{year:04d}-{s[2:4]}-{s[4:6]}"
    if tag == 0x18 and len(s) >= 14:
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}"
    return s


def parse_certificate(der: bytes) -> dict:
    """Extract subject CN, issuer CN, validity, key algorithm/size, SAN entries.
    Returns {} on any parse failure (never raises)."""
    out: dict = {"subject_cn": "", "issuer_cn": "", "not_before": "",
                 "not_after": "", "key_algorithm": "", "key_bits": 0,
                 "san_dns": [], "san_uri": [], "self_signed": False,
                 "sha256": ""}
    try:
        import hashlib
        out["sha256"] = hashlib.sha256(der).hexdigest()
    except Exception:
        pass
    try:
        outer = _asn1_read(der, 0)
        if not outer or outer[0] != 0x30:
            return out
        _t, _h, olen, ooff = outer
        tbs = _asn1_read(der, ooff)
        if not tbs or tbs[0] != 0x30:
            return out
        _tt, _th, tlen, toff = tbs
        children = _asn1_children(der, toff, toff + tlen)
        idx = 0
        # optional version [0] EXPLICIT INTEGER
        if children and children[0][0] == 0xA0:
            idx += 1
        # serialNumber
        idx += 1
        # signatureAlgorithm
        idx += 1
        # issuer
        if idx >= len(children):
            return out
        _t, _h, iclen, icoff = children[idx]
        out["issuer_cn"] = _decode_name_cn(der[icoff:icoff + iclen], iclen)
        issuer_bytes = der[icoff:icoff + iclen]
        idx += 1
        # validity
        if idx >= len(children):
            return out
        _t, _h, vclen, vcoff = children[idx]
        val = _asn1_children(der, vcoff, vcoff + vclen)
        if len(val) >= 2:
            t1, _hh, c1, o1 = val[0]
            t2, _hh, c2, o2 = val[1]
            out["not_before"] = _decode_time(der[o1:o1 + c1], t1)
            out["not_after"] = _decode_time(der[o2:o2 + c2], t2)
        idx += 1
        # subject
        if idx >= len(children):
            return out
        _t, _h, sclen, scoff = children[idx]
        out["subject_cn"] = _decode_name_cn(der[scoff:scoff + sclen], sclen)
        subject_bytes = der[scoff:scoff + sclen]
        out["self_signed"] = issuer_bytes == subject_bytes
        idx += 1
        # subjectPublicKeyInfo
        if idx < len(children):
            _t, _h, spclen, spcoff = children[idx]
            spk_children = _asn1_children(der, spcoff, spcoff + spclen)
            if len(spk_children) >= 2:
                algid = spk_children[0]
                alg_ch = _asn1_children(der, algid[3], algid[3] + algid[2])
                if alg_ch:
                    _, _, aoclen, aocoff = alg_ch[0]
                    oid = der[aocoff:aocoff + aoclen]
                    if oid == _OID_RSA:
                        out["key_algorithm"] = "RSA"
                bitstr = spk_children[1]
                if bitstr[0] == 0x03 and bitstr[2] >= 1:
                    # BITSTRING: first content byte is unused-bit count, then RSA
                    # SubjectPublicKey = SEQUENCE { modulus INTEGER, exponent INTEGER }
                    inner = _asn1_read(der, bitstr[3] + 1)
                    if inner and inner[0] == 0x30:
                        rsa_ch = _asn1_children(der, inner[3], inner[3] + inner[2])
                        if rsa_ch and rsa_ch[0][0] == 0x02:
                            _, _, mclen, mcoff = rsa_ch[0]
                            mod = der[mcoff:mcoff + mclen]
                            # skip a leading zero byte (positive-INTEGER encoding)
                            if mod and mod[0] == 0x00:
                                mod = mod[1:]
                            out["key_bits"] = len(mod) * 8
        idx += 1
        # optional [3] EXPLICIT Extensions
        for tag, _h, clen, coff in children[idx:]:
            if tag == 0xA3:
                ext_seq = _asn1_read(der, coff)
                if not ext_seq or ext_seq[0] != 0x30:
                    continue
                _, _, eslen, esoff = ext_seq
                for _, _, elen, eoff in _asn1_children(der, esoff, esoff + eslen):
                    ext_ch = _asn1_children(der, eoff, eoff + elen)
                    if not ext_ch or ext_ch[0][0] != 0x06:
                        continue
                    _, _, oclen, ocoff = ext_ch[0]
                    oid = der[ocoff:ocoff + oclen]
                    if oid != _OID_SAN:
                        continue
                    # last child is OCTET STRING containing GeneralNames SEQ
                    _, _, oslen, osoff = ext_ch[-1]
                    inner = _asn1_read(der, osoff)
                    if not inner or inner[0] != 0x30:
                        continue
                    _, _, inlen, inoff = inner
                    for gt, _gh, gclen, gcoff in _asn1_children(der, inoff,
                                                                inoff + inlen):
                        val = der[gcoff:gcoff + gclen]
                        if gt == 0x82:                      # [2] dNSName IA5String
                            out["san_dns"].append(val.decode("ascii", "replace"))
                        elif gt == 0x86:                    # [6] URI IA5String
                            out["san_uri"].append(val.decode("ascii", "replace"))
    except (IndexError, struct.error, ValueError, UnicodeDecodeError):
        return out
    return out


# --- top-level probe -----------------------------------------------------------


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          *, do_find_servers: bool = True, do_find_on_network: bool = True,
          do_register_server: bool = True, do_err_banner: bool = True) -> dict:
    """Full passive/discovery probe. Returns:
      {reachable, hello_ack, endpoints, find_servers, on_network,
       register_server, err_banner}
    reachable=True iff HELLO/ACK completed (uacp confirmed)."""
    out: dict = {"reachable": False, "hello_ack": None, "endpoints": [],
                 "find_servers": [], "on_network": [], "register_server": None,
                 "err_banner": None}
    scaled = proxy.scaled(timeout)

    # First connection: HELLO/ACK + OPN + GetEndpoints (+ FindServers,
    # FindServersOnNetwork, RegisterServer over the same channel).
    try:
        with socket.create_connection((ip, port), timeout=scaled) as s:
            s.settimeout(scaled)
            ack = _hello_ack(s)
            if not ack or ack.get("kind") != "ACK":
                return out
            out["reachable"] = True
            out["hello_ack"] = ack
            channel = _open_channel(s)
            if not channel:
                return out
            # GetEndpoints
            resp = _send_service(s, channel, 2, _get_endpoints_payload(2))
            if resp is not None:
                inner = _service_body_after_headers(resp)
                if inner is not None:
                    try:
                        parsed = _parse_get_endpoints_response(inner)
                        out["endpoints"] = parsed["endpoints"]
                    except (IndexError, struct.error, ValueError):
                        pass
            # FindServers
            if do_find_servers:
                resp = _send_service(s, channel, 3, _find_servers_payload(3))
                if resp is not None:
                    inner = _service_body_after_headers(resp)
                    if inner is not None:
                        try:
                            parsed = _parse_find_servers_response(inner)
                            out["find_servers"] = parsed["servers"]
                        except (IndexError, struct.error, ValueError):
                            pass
            # FindServersOnNetwork (LDS-ME)
            if do_find_on_network:
                resp = _send_service(s, channel, 4,
                                     _find_servers_on_network_payload(4))
                if resp is not None:
                    inner = _service_body_after_headers(resp)
                    if inner is not None:
                        try:
                            parsed = _parse_find_servers_on_network_response(inner)
                            out["on_network"] = parsed["servers"]
                        except (IndexError, struct.error, ValueError):
                            pass
            # RegisterServer — a rejected registration is a good result; we
            # only flag it when the service returned Good (0).
            if do_register_server:
                resp = _send_service(s, channel, 5,
                                     _register_server_payload(5))
                if resp is not None:
                    inner = _service_body_after_headers(resp)
                    if inner is not None:
                        try:
                            c = _Cursor(inner)
                            header = _parse_response_header(c)
                            out["register_server"] = {
                                "service_result": header["service_result"],
                                "accepted": header["service_result"] == 0,
                            }
                        except (IndexError, struct.error, ValueError):
                            pass
    except OSError:
        return out

    # Second connection (kept independent so a hostile ERR path does not corrupt
    # the successful channel above): oversized-version HELLO for the ERR banner.
    if do_err_banner:
        try:
            with socket.create_connection((ip, port), timeout=scaled) as s:
                s.settimeout(scaled)
                ack = _hello_ack(s, protocol_version=99,
                                 endpoint_url="opc.tcp://recce/probe")
                if ack and ack.get("kind") == "ERR":
                    out["err_banner"] = {
                        "status_code": ack.get("status_code", 0),
                        "reason": ack.get("reason", ""),
                    }
        except OSError:
            pass

    return out


def opcua_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_opcua(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "opcua-client", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def _endpoint_short(ep: dict) -> str:
    mode = _SEC_MODE.get(ep.get("security_mode", 0), "?")
    pol = (ep.get("security_policy_uri") or "").rsplit("#", 1)[-1]
    return f"{ep.get('endpoint_url','?')} [mode={mode} policy={pol}]"


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_opcua(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            endpoints = pr.get("endpoints") or []
            # Reachable — the HELLO/ACK proves this is genuine uacp.
            out.append(_finding(
                "high",
                "OPC UA server reachable on OT/enterprise segment", tgt,
                f"uacp HELLO/ACK completed; {len(endpoints)} endpoint(s) "
                f"advertised via GetEndpoints. OPC UA is the ICS/IIoT "
                f"interoperability plane — its presence on a general segment "
                f"is a segmentation stance.",
                f"opcua-client discover opc.tcp://{h.ip}:{p.portid}",
                "Place OPC UA on an isolated OT VLAN. Restrict Discovery "
                "(GetEndpoints / FindServers) to trusted management hosts.",
                ["CWE-284", "CWE-306"], kind="opcua_reachable",
                exploit_note=(
                    "opcua-client discover opc.tcp://<ip>:4840; opcua-client "
                    "get-endpoints opc.tcp://<ip>:4840."),
                depth_tier="t1"))

            # Endpoint fingerprint (informational — feeds the other findings).
            if endpoints:
                out.append(_finding(
                    "info",
                    "OPC UA endpoints enumerated (GetEndpoints)", tgt,
                    f"{len(endpoints)} endpoint(s): "
                    + "; ".join(_endpoint_short(e) for e in endpoints[:8])
                    + (" …" if len(endpoints) > 8 else ""),
                    f"opcua-client get-endpoints opc.tcp://{h.ip}:{p.portid}",
                    "Informational — reduce the endpoint surface to only the "
                    "security policies/modes required by the deployed clients.",
                    ["CWE-200"], kind="opcua_endpoints_enumerated"))

            # Anonymous / SecurityMode None / cleartext creds / deprecated policy
            # are all read from the same EndpointDescription array.
            anon_eps: list[dict] = []
            mode_none_eps: list[dict] = []
            cleartext_creds_eps: list[dict] = []
            deprecated_eps: list[tuple[dict, str]] = []
            for ep in endpoints:
                if ep.get("security_mode") == 1:
                    mode_none_eps.append(ep)
                policy = ep.get("security_policy_uri") or ""
                if policy in _DEPRECATED_POLICIES:
                    deprecated_eps.append((ep, policy.rsplit("#", 1)[-1]))
                for tok in ep.get("user_identity_tokens") or []:
                    if tok.get("token_type") == 0:
                        anon_eps.append(ep)
                    if (tok.get("token_type") == 1
                            and (tok.get("security_policy_uri") or policy) == _POLICY_NONE
                            and ep.get("security_mode") == 1):
                        cleartext_creds_eps.append(ep)

            if anon_eps:
                # Deduplicate on endpoint URL.
                urls = sorted({e.get("endpoint_url", "") for e in anon_eps})
                out.append(_finding(
                    "critical",
                    "OPC UA endpoint allows Anonymous user identity", tgt,
                    f"{len(urls)} endpoint(s) advertise a UserTokenPolicy with "
                    f"tokenType=Anonymous — an unauthenticated Session can "
                    f"Browse and Read the OT information model (and Call/Write "
                    f"where per-node ACLs allow). Endpoints: "
                    + ", ".join(urls[:4]) + (" …" if len(urls) > 4 else ""),
                    f"opcua-client connect --anonymous opc.tcp://{h.ip}:{p.portid}",
                    "Remove the Anonymous UserTokenPolicy from every endpoint. "
                    "Require UserName + strong password, or X.509 certificate "
                    "identity, and pair with SecurityMode=SignAndEncrypt so "
                    "the identity cannot be intercepted.",
                    ["CWE-306", "CWE-284", "CWE-1263"],
                    kind="opcua_anonymous_allowed",
                    exploit_note=(
                        "opcua-client browse --anonymous opc.tcp://<ip>:4840/ "
                        "i=84; if browse returns children, opcua-client read "
                        "--anonymous opc.tcp://<ip>:4840/ 'ns=0;i=2258' "
                        "(ServerStatus) — dumps SDK build, start-time, "
                        "current-time — proves anon session works."),
                    depth_tier="t1"))

            if mode_none_eps:
                urls = sorted({e.get("endpoint_url", "") for e in mode_none_eps})
                out.append(_finding(
                    "high",
                    "OPC UA endpoint offers SecurityMode=None (unencrypted channel)",
                    tgt,
                    f"{len(urls)} endpoint(s) advertise MessageSecurityMode=None. "
                    f"The SecureChannel is neither signed nor encrypted — browse "
                    f"traffic, node values and (for UserName tokens whose policy "
                    f"is also None) cleartext credentials cross the wire in the "
                    f"open. Endpoints: " + ", ".join(urls[:4])
                    + (" …" if len(urls) > 4 else ""),
                    f"opcua-client connect --none opc.tcp://{h.ip}:{p.portid}",
                    "Disable SecurityMode=None on every endpoint; require Sign "
                    "or SignAndEncrypt with Basic256Sha256 or Aes*_Sha256_Rsa* "
                    "policies end-to-end.",
                    ["CWE-319", "CWE-311"], kind="opcua_security_mode_none",
                    exploit_note=(
                        "opcua-client connect --none opc.tcp://<ip>:4840 && "
                        "tcpdump -w /tmp/ua.pcap -i any 'host <ip> and port "
                        "4840' && Wireshark decode-as OPCUA — observe cleartext "
                        "ReadResponse bodies."),
                    depth_tier="t1"))

            if cleartext_creds_eps:
                urls = sorted({e.get("endpoint_url", "") for e in cleartext_creds_eps})
                out.append(_finding(
                    "high",
                    "OPC UA endpoint accepts UserName tokens over None security policy "
                    "(cleartext credentials)", tgt,
                    f"{len(urls)} endpoint(s) accept a UserName UserTokenPolicy "
                    f"whose SecurityPolicy is None while the channel itself is "
                    f"also None — the password field is NOT RSA-wrapped and "
                    f"crosses the wire in cleartext. Any on-path attacker (or "
                    f"later PCAP) recovers it. Endpoints: " + ", ".join(urls[:4])
                    + (" …" if len(urls) > 4 else ""),
                    f"tcpdump -w opcua-{h.ip}.pcap 'host {h.ip} and port {p.portid}'",
                    "Require a non-None SecurityPolicy for every UserName "
                    "UserTokenPolicy (Basic256Sha256 minimum) so the password "
                    "field is RSA-wrapped to the server certificate.",
                    ["CWE-319", "CWE-522"], kind="opcua_credentials_in_cleartext",
                    exploit_note=(
                        "tcpdump -w /tmp/ua.pcap 'host <ip> and port 4840'; "
                        "wait for legitimate operator login; extract password "
                        "from ActivateSessionRequest.UserIdentityToken (visible "
                        "ASCII in the None-policy path). Attempt harvested "
                        "creds against every OT system."),
                    depth_tier="t1"))

            if deprecated_eps:
                pols = sorted({name for _ep, name in deprecated_eps})
                out.append(_finding(
                    "medium",
                    "OPC UA endpoint offers deprecated security policy "
                    "(Basic128Rsa15 / Basic256)", tgt,
                    "Endpoint(s) offer deprecated SecurityPolicyUri(s): "
                    + ", ".join(pols)
                    + ". Basic128Rsa15 (PKCS#1 v1.5 padding) and Basic256 (SHA-1) "
                    "were deprecated by the OPC Foundation in 2017.",
                    f"opcua-client get-endpoints opc.tcp://{h.ip}:{p.portid}",
                    "Restrict endpoints to Basic256Sha256, Aes128_Sha256_RsaOaep, "
                    "or Aes256_Sha256_RsaPss.",
                    ["CWE-327", "CWE-326"], kind="opcua_deprecated_policy"))

            # Application identity (vendor fingerprint).
            first_server = None
            for ep in endpoints:
                if ep.get("server"):
                    first_server = ep["server"]
                    break
            if first_server:
                a_uri = first_server.get("application_uri", "")
                p_uri = first_server.get("product_uri", "")
                a_name = first_server.get("application_name", "")
                a_type = _APP_TYPE.get(first_server.get("application_type", 0),
                                       "?")
                out.append(_finding(
                    "info",
                    "OPC UA server discloses application and product identity "
                    "(vendor fingerprint)", tgt,
                    f"applicationUri={a_uri!r} productUri={p_uri!r} "
                    f"applicationName={a_name!r} applicationType={a_type}. "
                    f"productUri pins the target to a specific vendor CVE feed.",
                    f"opcua-client get-endpoints opc.tcp://{h.ip}:{p.portid}",
                    "Informational — feeds vendor/product CVE matching.",
                    ["CWE-200"], kind="opcua_application_id"))

            # Server certificate parse.
            for ep in endpoints:
                cert = ep.get("server_certificate")
                if not cert:
                    continue
                info = parse_certificate(cert)
                if not info.get("sha256"):
                    continue
                weak_key = 0 < info.get("key_bits", 0) < 2048
                self_signed = info.get("self_signed")
                sev = "medium" if (weak_key or self_signed) else "info"
                title = ("OPC UA server certificate is self-signed / weak-key"
                         if (weak_key or self_signed)
                         else "OPC UA server certificate captured")
                out.append(_finding(
                    sev, title, tgt,
                    f"subjectCN={info.get('subject_cn','?')!r} "
                    f"issuerCN={info.get('issuer_cn','?')!r} "
                    f"notBefore={info.get('not_before','?')} "
                    f"notAfter={info.get('not_after','?')} "
                    f"key={info.get('key_algorithm','?')}/{info.get('key_bits',0)}b "
                    f"self_signed={self_signed} "
                    f"sha256={info.get('sha256','')[:16]}… "
                    + (f"san_dns={info.get('san_dns')[:4]} "
                       if info.get('san_dns') else "")
                    + (f"san_uri={info.get('san_uri')[:4]}"
                       if info.get('san_uri') else ""),
                    f"openssl x509 -in server.der -inform DER -noout -text  "
                    f"# from opcua-client get-endpoints opc.tcp://{h.ip}:{p.portid}",
                    "Issue OPC UA server certificates from an internal PKI; "
                    "rotate self-signed factory certs; require RSA-2048+ or "
                    "ECC P-256 key sizes.",
                    ["CWE-295", "CWE-326", "CWE-298"],
                    kind="opcua_server_certificate"))
                break                          # one cert finding per host

            # FindServers — sibling discovery.
            find_servers = pr.get("find_servers") or []
            if find_servers:
                urls = []
                for s in find_servers:
                    for u in s.get("discovery_urls") or []:
                        urls.append(u)
                out.append(_finding(
                    "medium",
                    "OPC UA FindServers enumerated sibling servers and internal "
                    "discoveryUrls", tgt,
                    f"FindServersRequest returned {len(find_servers)} "
                    f"ApplicationDescription(s) and {len(urls)} discoveryUrl(s). "
                    f"Sample discoveryUrls: " + ", ".join(urls[:6])
                    + (" …" if len(urls) > 6 else ""),
                    f"opcua-client find-servers opc.tcp://{h.ip}:{p.portid}",
                    "Restrict FindServers to a trusted management network; do "
                    "not register internal-only OT hosts with an Internet-"
                    "reachable Discovery Server.",
                    ["CWE-200"], kind="opcua_find_servers"))

            # FindServersOnNetwork (LDS-ME).
            on_network = pr.get("on_network") or []
            if on_network:
                names = [s.get("server_name", "") for s in on_network]
                out.append(_finding(
                    "medium",
                    "OPC UA LDS-ME exposes network-wide server inventory "
                    "(FindServersOnNetwork)", tgt,
                    f"FindServersOnNetwork returned {len(on_network)} record(s) "
                    f"— every OPC UA app mDNS-registered with this LDS: "
                    + ", ".join(names[:8]) + (" …" if len(names) > 8 else ""),
                    f"opcua-client find-servers-on-network opc.tcp://{h.ip}:{p.portid}",
                    "Restrict access to the LDS-ME to a trusted management "
                    "segment; disable Multicast Extension where the mDNS "
                    "registry is not required.",
                    ["CWE-200"], kind="opcua_lds_me_inventory"))

            # RegisterServer open-registration.
            reg = pr.get("register_server") or {}
            if reg.get("accepted"):
                out.append(_finding(
                    "high",
                    "OPC UA Discovery Server accepts unauthenticated "
                    "RegisterServer (rogue-server primitive)", tgt,
                    "RegisterServerRequest sent from an anonymous SecureChannel "
                    "with SecurityPolicy=None returned Good — the LDS will "
                    "advertise a rogue server to every OPC UA client on the "
                    "segment (supply-chain / MITM primitive for auto-connect "
                    "clients).",
                    f"opcua-client register-server opc.tcp://{h.ip}:{p.portid}",
                    "Require an authenticated SecureChannel (SecurityMode=Sign+"
                    "SignAndEncrypt with a known client certificate) for "
                    "RegisterServer / RegisterServer2, or restrict the service "
                    "to loopback / an ACL of on-host registrants.",
                    ["CWE-345", "CWE-306"],
                    kind="opcua_open_lds_registration",
                    exploit_note=(
                        "Launch attacker OPC UA server (open62541 server_ctt) "
                        "on attacker IP; opcua-client register-server "
                        "opc.tcp://<lds>:4840 --serverUri urn:evil --discoveryUrl "
                        "opc.tcp://<attacker>:4840/. Wait for HMI connections in "
                        "Wireshark; harvest UserName tokens."),
                    depth_tier="t1"))

            # ERR banner (SDK version leak).
            err = pr.get("err_banner") or {}
            if err and err.get("reason"):
                out.append(_finding(
                    "low",
                    "OPC UA server leaks SDK / product version in ERR message",
                    tgt,
                    f"A HELLO with ProtocolVersion=99 drew an ERRF reply: "
                    f"status=0x{err.get('status_code',0):08x} "
                    f"reason={err['reason']!r}. Reason strings routinely name "
                    f"the SDK (e.g. 'open62541 1.3', 'UA-.NETStandard').",
                    f"printf '\\x48\\x45\\x4cF' | nc {h.ip} {p.portid}",
                    "Suppress SDK / build details from the ERR reason field "
                    "at the server (many stacks expose this as a build option); "
                    "restrict Discovery access to management hosts.",
                    ["CWE-209", "CWE-200"], kind="opcua_error_banner"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "uacp HELLO/ACK reachability",
         "cmd": f"opcua-client discover opc.tcp://{ip}:{port}"},
        {"step": "GetEndpoints (unauthenticated fingerprint)",
         "cmd": f"opcua-client get-endpoints opc.tcp://{ip}:{port}"},
        {"step": "FindServers (sibling discovery)",
         "cmd": f"opcua-client find-servers opc.tcp://{ip}:{port}"},
        {"step": "FindServersOnNetwork (LDS-ME inventory)",
         "cmd": f"opcua-client find-servers-on-network opc.tcp://{ip}:{port}"},
        {"step": "Anonymous browse (if UserTokenPolicy Anonymous)",
         "cmd": f"opcua-client browse --anonymous opc.tcp://{ip}:{port}/  RootFolder"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "opcua", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = opcua_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                eps = pr.get("endpoints") or []
                if eps and eps[0].get("server"):
                    srv = eps[0]["server"]
                    t["product_uri"] = srv.get("product_uri", "")
                    t["application_uri"] = srv.get("application_uri", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
