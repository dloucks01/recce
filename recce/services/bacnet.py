"""BACnet/IP (47808/udp) probe — building automation control plane.

BACnet (ASHRAE 135) is the wire protocol under HVAC, lighting, access control,
fire panels and metering in nearly every commercial and industrial site. The
base protocol has NO authentication — anyone who reaches 47808/udp can read
the Device object (vendor/model/firmware/facility name), enumerate every
point (chillers, dampers, door strikes), and — the critical primitive —
WriteProperty at priority 1 to any commandable point, which is direct
physical-process control.

Coverage here:
  * Who-Is / I-Am fingerprint (label 47808 as bacnet + capture device instance)
  * ReadProperty of Device object: vendor / model / firmware / object-name /
    max-APDU / segmentation
  * Object-list walk (ReadProperty of Device.object-list, property 76)
  * BBMD Read-BDT (0x02) + Read-FDT (0x06) topology dumps
  * Register-Foreign-Device (0x05) accept-check
  * Who-Is amplification ratio (single request → count I-Am replies)
  * WriteProperty dry-run: read present-value of an Analog-Value at priority
    16, write the SAME bytes back at priority 16. Positive SimpleAck proves
    unauthenticated write access WITHOUT changing physical state.
  * DeviceCommunicationControl with empty / vendor-default password (SimpleAck
    means the DoS primitive works — recce sends duration=1 minute, never 0).
  * ReinitializeDevice WARMSTART with a deliberately BAD password — any reply
    other than the "invalid password" error class means the primitive is open.
  * AtomicReadFile on any File object (type 10) found in the object list.
  * BACnet/SC (Annex AB TCP+TLS on 47820) downgrade heuristic — plaintext /IP
    still open while /SC is present.

Safety (mirrors modbus.py's read-only stance):
  * WriteProperty ONLY re-writes the value we just read, at priority 16.
  * ReinitializeDevice uses an intentionally-bad password (many bytes) so a
    device that would honour the correct default password still refuses.
  * DCC uses a 1-minute duration, never 0 (which would disable indefinitely).

Airgap-safe: stdlib socket + struct + os.urandom only. One UDP socket per
probe(), all recv()s bounded by a scaled timeout.
"""
from __future__ import annotations

import os
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port

_DEFAULT_PORT = 47808
_TIMEOUT = 4.0

# BVLC (Annex J) function codes.
_BVLC_RESULT = 0x00
_BVLC_READ_BDT = 0x02
_BVLC_READ_BDT_ACK = 0x03
_BVLC_REGISTER_FD = 0x05
_BVLC_READ_FDT = 0x06
_BVLC_READ_FDT_ACK = 0x07
_BVLC_ORIGINAL_UNICAST = 0x0A
_BVLC_ORIGINAL_BROADCAST = 0x0B

# APDU PDU-type (upper nibble).
_APDU_CONFIRMED = 0x00
_APDU_UNCONFIRMED = 0x10
_APDU_SIMPLE_ACK = 0x20
_APDU_COMPLEX_ACK = 0x30
_APDU_ERROR = 0x50
_APDU_REJECT = 0x60
_APDU_ABORT = 0x70

# Confirmed / unconfirmed service choices used here.
_SVC_I_AM = 0x00
_SVC_WHO_IS = 0x08
_SVC_READ_PROPERTY = 0x0C
_SVC_READ_PROPERTY_MULTIPLE = 0x0E
_SVC_WRITE_PROPERTY = 0x0F
_SVC_ATOMIC_READ_FILE = 0x06
_SVC_DEVICE_COMM_CONTROL = 0x11
_SVC_REINITIALIZE_DEVICE = 0x14

# Object types.
_OBJ_ANALOG_VALUE = 2
_OBJ_DEVICE = 8
_OBJ_FILE = 10

# Property identifiers.
_PROP_APP_SW_VERSION = 12
_PROP_FIRMWARE_REV = 44
_PROP_APDU_TIMEOUT = 11
_PROP_MAX_APDU = 62
_PROP_MODEL_NAME = 70
_PROP_APDU_RETRIES = 73
_PROP_OBJECT_LIST = 76
_PROP_OBJECT_NAME = 77
_PROP_PRESENT_VALUE = 85
_PROP_PRIORITY_ARRAY = 87
_PROP_SEGMENTATION = 107
_PROP_VENDOR_ID = 120
_PROP_VENDOR_NAME = 121
_PROP_DESCRIPTION = 28

# Default passwords tried against DCC / Reinitialize (documented BAS defaults).
_DEFAULT_PASSWORDS = ("", "bacnet", "filsinger", "12345678", "admin", "12345")

# BACnet Secure Connect default direct-connect port (Annex AB) — we only flag
# co-presence; the TLS side is out of scope for this UDP module.
_BACNET_SC_PORTS = (47820,)


def is_bacnet(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    if port.portid == _DEFAULT_PORT or 47809 <= port.portid <= 47823:
        return True
    return "bacnet" in svc or "bacnet" in prod


# --- BVLC / NPDU / APDU encoders -----------------------------------------------


def _bvlc(function: int, body: bytes) -> bytes:
    """BVLC header (0x81, function, length) with `length` including the header."""
    total = 4 + len(body)
    return bytes([0x81, function]) + struct.pack(">H", total) + body


def _npdu(expect_reply: bool = False) -> bytes:
    """Minimal NPDU: version 1, control byte. bit 2 = expecting reply."""
    return bytes([0x01, 0x04 if expect_reply else 0x00])


def _encode_object_id(obj_type: int, instance: int) -> bytes:
    return struct.pack(">I", ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF))


def _encode_ctx_unsigned(tag: int, value: int) -> bytes:
    if value < 0x100:
        return bytes([(tag << 4) | 0x08 | 0x01, value & 0xFF])
    if value < 0x10000:
        return bytes([(tag << 4) | 0x08 | 0x02]) + struct.pack(">H", value)
    if value < 0x1000000:
        return bytes([(tag << 4) | 0x08 | 0x03]) + struct.pack(">I", value)[1:]
    return bytes([(tag << 4) | 0x08 | 0x04]) + struct.pack(">I", value)


def _encode_ctx_octet(tag: int, data: bytes) -> bytes:
    if len(data) < 5:
        return bytes([(tag << 4) | 0x08 | len(data)]) + data
    if len(data) < 254:
        return bytes([(tag << 4) | 0x08 | 0x05, len(data)]) + data
    return bytes([(tag << 4) | 0x08 | 0x05, 254]) + struct.pack(">H", len(data)) + data


def _encode_ctx_enum(tag: int, value: int) -> bytes:
    return _encode_ctx_unsigned(tag, value)


def _encode_app_charstring(text: str) -> bytes:
    """Application tag 7 (character string). First value byte = encoding (0 = UTF-8)."""
    payload = b"\x00" + text.encode("utf-8", "replace")
    n = len(payload)
    if n < 5:
        return bytes([0x70 | n]) + payload
    if n < 254:
        return bytes([0x75, n]) + payload
    return bytes([0x75, 254]) + struct.pack(">H", n) + payload


def _encode_ctx_charstring(tag: int, text: str) -> bytes:
    """Context-tagged character string (rare — used inside DCC/Reinitialize
    services which context-wrap the password parameter)."""
    payload = b"\x00" + text.encode("utf-8", "replace")
    n = len(payload)
    if n < 5:
        return bytes([(tag << 4) | 0x08 | n]) + payload
    if n < 254:
        return bytes([(tag << 4) | 0x08 | 0x05, n]) + payload
    return bytes([(tag << 4) | 0x08 | 0x05, 254]) + struct.pack(">H", n) + payload


def _confirmed_apdu(invoke_id: int, service_choice: int, body: bytes) -> bytes:
    """Confirmed-Request PDU (unsegmented). max_apdu = 0x05 (1476 bytes)."""
    return bytes([_APDU_CONFIRMED, 0x05, invoke_id & 0xFF, service_choice]) + body


def _read_property_body(obj_type: int, instance: int, prop_id: int,
                        array_index: int | None = None) -> bytes:
    body = bytes([0x0C]) + _encode_object_id(obj_type, instance)
    if prop_id < 256:
        body += bytes([0x19, prop_id])
    else:
        body += bytes([0x1A]) + struct.pack(">H", prop_id)
    if array_index is not None:
        body += _encode_ctx_unsigned(2, array_index)
    return body


def _who_is_packet() -> bytes:
    """Unicast Who-Is (unbounded)."""
    apdu = bytes([_APDU_UNCONFIRMED, _SVC_WHO_IS])
    return _bvlc(_BVLC_ORIGINAL_UNICAST, _npdu() + apdu)


def _read_property_packet(invoke_id: int, obj_type: int, instance: int,
                          prop_id: int, array_index: int | None = None) -> bytes:
    apdu = _confirmed_apdu(invoke_id, _SVC_READ_PROPERTY,
                           _read_property_body(obj_type, instance, prop_id, array_index))
    return _bvlc(_BVLC_ORIGINAL_UNICAST, _npdu(expect_reply=True) + apdu)


def _write_property_packet(invoke_id: int, obj_type: int, instance: int,
                           prop_id: int, raw_value_tlv: bytes,
                           priority: int = 16) -> bytes:
    """WriteProperty of a single property. raw_value_tlv must already contain
    the application-tagged value bytes (as captured from a prior ReadProperty
    response — recce never synthesises new values)."""
    body = bytes([0x0C]) + _encode_object_id(obj_type, instance)
    body += bytes([0x19, prop_id]) if prop_id < 256 \
        else bytes([0x1A]) + struct.pack(">H", prop_id)
    # opening context tag 3, value bytes, closing context tag 3
    body += bytes([0x3E]) + raw_value_tlv + bytes([0x3F])
    body += _encode_ctx_unsigned(4, priority)
    apdu = _confirmed_apdu(invoke_id, _SVC_WRITE_PROPERTY, body)
    return _bvlc(_BVLC_ORIGINAL_UNICAST, _npdu(expect_reply=True) + apdu)


def _dcc_packet(invoke_id: int, password: str, duration_min: int = 1) -> bytes:
    """DeviceCommunicationControl. enable-disable = 1 (disable, but bounded by
    duration_min minutes — recce NEVER sends duration=0)."""
    body = _encode_ctx_unsigned(0, max(1, duration_min))
    body += _encode_ctx_enum(1, 1)  # 1 = disable
    if password is not None:
        body += _encode_ctx_charstring(2, password)
    apdu = _confirmed_apdu(invoke_id, _SVC_DEVICE_COMM_CONTROL, body)
    return _bvlc(_BVLC_ORIGINAL_UNICAST, _npdu(expect_reply=True) + apdu)


def _reinitialize_packet(invoke_id: int, password: str) -> bytes:
    """ReinitializeDevice WARMSTART (1). Note: recce deliberately passes a
    password even if empty is intended, so a device with the correct default
    also refuses — the probe distinguishes 'password check happens' from
    'no password check at all'."""
    body = _encode_ctx_enum(0, 1)  # 1 = warmstart
    body += _encode_ctx_charstring(1, password)
    apdu = _confirmed_apdu(invoke_id, _SVC_REINITIALIZE_DEVICE, body)
    return _bvlc(_BVLC_ORIGINAL_UNICAST, _npdu(expect_reply=True) + apdu)


def _atomic_read_file_packet(invoke_id: int, file_instance: int,
                             offset: int = 0, count: int = 64) -> bytes:
    body = bytes([0x0C]) + _encode_object_id(_OBJ_FILE, file_instance)
    # stream access: opening ctx tag 0, signed int offset, unsigned count, closing 0
    body += bytes([0x0E])
    body += bytes([0x31, offset & 0xFF])           # app tag 3 signed int, 1 byte
    body += bytes([0x21, count & 0xFF])            # app tag 2 unsigned int, 1 byte
    body += bytes([0x0F])
    apdu = _confirmed_apdu(invoke_id, _SVC_ATOMIC_READ_FILE, body)
    return _bvlc(_BVLC_ORIGINAL_UNICAST, _npdu(expect_reply=True) + apdu)


# --- decoders ------------------------------------------------------------------


def _parse_bvlc(pkt: bytes) -> tuple[int, bytes] | None:
    """Return (function, body_after_header) or None."""
    if len(pkt) < 4 or pkt[0] != 0x81:
        return None
    function = pkt[1]
    length = struct.unpack(">H", pkt[2:4])[0]
    if length != len(pkt):
        return None
    return function, pkt[4:]


def _strip_npdu(body: bytes) -> bytes | None:
    """Skip the NPDU header. Handles the destination/source specifier bits so
    a Forwarded / routed reply parses correctly."""
    if len(body) < 2 or body[0] != 0x01:
        return None
    ctrl = body[1]
    off = 2
    if ctrl & 0x20:                     # DNET/DLEN/DADR present
        if off + 3 > len(body):
            return None
        dlen = body[off + 2]
        off += 3 + dlen
    if ctrl & 0x08:                     # SNET/SLEN/SADR present
        if off + 3 > len(body):
            return None
        slen = body[off + 2]
        off += 3 + slen
    if ctrl & 0x20:                     # hop-count when DNET present
        off += 1
    if ctrl & 0x80:                     # network-layer message: no APDU
        return b""
    if off > len(body):
        return None
    return body[off:]


def _decode_tag(buf: bytes, off: int) -> tuple[int, bool, int, int] | None:
    """Return (tag_num, is_context, length_or_opening_closing, new_offset).

    length is -1 for an opening tag, -2 for a closing tag.
    """
    if off >= len(buf):
        return None
    b = buf[off]
    tag_num = (b >> 4) & 0x0F
    is_context = bool(b & 0x08)
    lvt = b & 0x07
    off += 1
    if tag_num == 0x0F:
        if off >= len(buf):
            return None
        tag_num = buf[off]
        off += 1
    if lvt == 6:
        return (tag_num, is_context, -1, off)
    if lvt == 7:
        return (tag_num, is_context, -2, off)
    length = lvt
    if lvt == 5:
        if off >= len(buf):
            return None
        length = buf[off]
        off += 1
        if length == 254:
            if off + 2 > len(buf):
                return None
            length = struct.unpack(">H", buf[off:off + 2])[0]
            off += 2
        elif length == 255:
            if off + 4 > len(buf):
                return None
            length = struct.unpack(">I", buf[off:off + 4])[0]
            off += 4
    return (tag_num, is_context, length, off)


def _decode_object_id(data: bytes) -> tuple[int, int]:
    v = struct.unpack(">I", data)[0]
    return (v >> 22) & 0x3FF, v & 0x3FFFFF


def _decode_unsigned(data: bytes) -> int:
    n = 0
    for b in data:
        n = (n << 8) | b
    return n


def _decode_charstring(data: bytes) -> str:
    if not data:
        return ""
    return data[1:].decode("utf-8", "replace")


def _parse_i_am(apdu: bytes) -> dict | None:
    """Parse an Unconfirmed-Request I-Am. Returns
    {device_instance, max_apdu, segmentation, vendor_id}."""
    if len(apdu) < 3 or apdu[0] != _APDU_UNCONFIRMED or apdu[1] != _SVC_I_AM:
        return None
    off = 2
    out: dict = {}
    t = _decode_tag(apdu, off)
    if not t or t[1] or t[0] != 12 or t[2] != 4:
        return None
    off = t[3]
    _, inst = _decode_object_id(apdu[off:off + 4])
    out["device_instance"] = inst
    off += 4
    t = _decode_tag(apdu, off)
    if not t or t[1] or t[0] != 2:
        return out
    off = t[3]
    out["max_apdu"] = _decode_unsigned(apdu[off:off + t[2]])
    off += t[2]
    t = _decode_tag(apdu, off)
    if not t or t[1] or t[0] != 9:
        return out
    off = t[3]
    out["segmentation"] = _decode_unsigned(apdu[off:off + t[2]])
    off += t[2]
    t = _decode_tag(apdu, off)
    if not t or t[1] or t[0] != 2:
        return out
    off = t[3]
    out["vendor_id"] = _decode_unsigned(apdu[off:off + t[2]])
    return out


def _parse_read_property_ack(apdu: bytes) -> dict | None:
    """Parse a Complex-ACK for ReadProperty. Returns
    {invoke_id, obj_type, instance, prop_id, value_bytes, value_apptag,
    value_decoded}. value_bytes is the raw TLV (application-tagged) so a
    subsequent WriteProperty can echo it byte-for-byte."""
    if len(apdu) < 3 or (apdu[0] & 0xF0) != _APDU_COMPLEX_ACK:
        return None
    invoke_id = apdu[1]
    if apdu[2] != _SVC_READ_PROPERTY:
        return None
    off = 3
    out: dict = {"invoke_id": invoke_id}
    # object-identifier: context tag 0, length 4
    t = _decode_tag(apdu, off)
    if not t or not t[1] or t[0] != 0 or t[2] != 4:
        return None
    off = t[3]
    otype, oinst = _decode_object_id(apdu[off:off + 4])
    out["obj_type"] = otype
    out["instance"] = oinst
    off += 4
    # property-identifier: context tag 1
    t = _decode_tag(apdu, off)
    if not t or not t[1] or t[0] != 1:
        return None
    off = t[3]
    out["prop_id"] = _decode_unsigned(apdu[off:off + t[2]])
    off += t[2]
    # optional array-index context tag 2
    t = _decode_tag(apdu, off)
    if t and t[1] and t[0] == 2:
        off = t[3] + max(0, t[2])
        t = _decode_tag(apdu, off)
    # opening tag 3 (0x3E)
    if not t or not t[1] or t[0] != 3 or t[2] != -1:
        return None
    off = t[3]
    values: list = []
    raw_start = off
    while True:
        t = _decode_tag(apdu, off)
        if not t:
            return None
        tag_num, is_ctx, length, new_off = t
        if is_ctx and tag_num == 3 and length == -2:
            raw_end = off
            break
        if length < 0:
            off = new_off
            continue
        if new_off + length > len(apdu):
            return None
        raw = apdu[new_off:new_off + length]
        if not is_ctx:
            if tag_num == 2:
                values.append(("unsigned", _decode_unsigned(raw)))
            elif tag_num == 7:
                values.append(("string", _decode_charstring(raw)))
            elif tag_num == 4 and length == 4:
                values.append(("real", struct.unpack(">f", raw)[0]))
            elif tag_num == 9:
                values.append(("enum", _decode_unsigned(raw)))
            elif tag_num == 12 and length == 4:
                values.append(("objectid", _decode_object_id(raw)))
            else:
                values.append((f"app{tag_num}", raw))
        off = new_off + length
    out["value_bytes"] = apdu[raw_start:raw_end]
    out["values"] = values
    return out


def _parse_error(apdu: bytes) -> dict | None:
    """Parse Error / Reject / Abort. Returns {kind, invoke_id, class, code}."""
    if len(apdu) < 2:
        return None
    ptype = apdu[0] & 0xF0
    if ptype == _APDU_ERROR:
        if len(apdu) < 3:
            return None
        invoke_id = apdu[1]
        # skip service-choice byte at apdu[2], then two enums (class, code)
        off = 3
        cls = code = -1
        t = _decode_tag(apdu, off)
        if t and not t[1] and t[0] == 9:
            cls = _decode_unsigned(apdu[t[3]:t[3] + t[2]])
            off = t[3] + t[2]
            t = _decode_tag(apdu, off)
            if t and not t[1] and t[0] == 9:
                code = _decode_unsigned(apdu[t[3]:t[3] + t[2]])
        return {"kind": "error", "invoke_id": invoke_id,
                "class": cls, "code": code}
    if ptype == _APDU_REJECT:
        return {"kind": "reject", "invoke_id": apdu[1],
                "class": -1, "code": apdu[2] if len(apdu) > 2 else -1}
    if ptype == _APDU_ABORT:
        return {"kind": "abort", "invoke_id": apdu[1],
                "class": -1, "code": apdu[2] if len(apdu) > 2 else -1}
    return None


def _apdu_from_reply(pkt: bytes) -> bytes | None:
    p = _parse_bvlc(pkt)
    if not p:
        return None
    fn, body = p
    if fn not in (_BVLC_ORIGINAL_UNICAST, _BVLC_ORIGINAL_BROADCAST):
        return None
    return _strip_npdu(body)


# --- socket helpers ------------------------------------------------------------


def _udp_send_recv(ip: str, port: int, pkt: bytes,
                   timeout: float) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(proxy.scaled(timeout))
    try:
        sock.sendto(pkt, (ip, port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return None
        return data
    except OSError:
        return None
    finally:
        sock.close()


def _udp_send_collect(ip: str, port: int, pkt: bytes, window: float,
                      max_replies: int = 32) -> list[bytes]:
    """Send one datagram, then read every reply that arrives in the next
    `window` seconds. Used by the amplification probe."""
    import time
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(proxy.scaled(window))
    out: list[bytes] = []
    try:
        sock.sendto(pkt, (ip, port))
        deadline = time.monotonic() + window
        while len(out) < max_replies:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break
            out.append(data)
    except OSError:
        pass
    finally:
        sock.close()
    return out


# --- high-level probe steps ----------------------------------------------------


def _next_invoke_id() -> int:
    return os.urandom(1)[0]


def who_is(ip: str, port: int = _DEFAULT_PORT,
           timeout: float = _TIMEOUT) -> dict | None:
    """Send Who-Is, parse I-Am. Returns None if no reply."""
    reply = _udp_send_recv(ip, port, _who_is_packet(), timeout)
    if reply is None:
        return None
    apdu = _apdu_from_reply(reply)
    if apdu is None:
        return None
    return _parse_i_am(apdu)


def read_property(ip: str, port: int, device_instance: int, obj_type: int,
                  instance: int, prop_id: int,
                  array_index: int | None = None,
                  timeout: float = _TIMEOUT) -> dict | None:
    iid = _next_invoke_id()
    pkt = _read_property_packet(iid, obj_type, instance, prop_id, array_index)
    reply = _udp_send_recv(ip, port, pkt, timeout)
    if reply is None:
        return None
    apdu = _apdu_from_reply(reply)
    if apdu is None:
        return None
    ack = _parse_read_property_ack(apdu)
    if ack:
        return ack
    return _parse_error(apdu)


def _read_bdt(ip: str, port: int, timeout: float) -> list[dict] | None:
    pkt = _bvlc(_BVLC_READ_BDT, b"")
    reply = _udp_send_recv(ip, port, pkt, timeout)
    if reply is None:
        return None
    p = _parse_bvlc(reply)
    if not p or p[0] != _BVLC_READ_BDT_ACK:
        return None
    body = p[1]
    entries = []
    for i in range(0, len(body), 10):
        chunk = body[i:i + 10]
        if len(chunk) != 10:
            break
        addr = ".".join(str(b) for b in chunk[0:4])
        udp_port = struct.unpack(">H", chunk[4:6])[0]
        mask = ".".join(str(b) for b in chunk[6:10])
        entries.append({"ip": addr, "port": udp_port, "mask": mask})
    return entries


def _read_fdt(ip: str, port: int, timeout: float) -> list[dict] | None:
    pkt = _bvlc(_BVLC_READ_FDT, b"")
    reply = _udp_send_recv(ip, port, pkt, timeout)
    if reply is None:
        return None
    p = _parse_bvlc(reply)
    if not p or p[0] != _BVLC_READ_FDT_ACK:
        return None
    body = p[1]
    entries = []
    for i in range(0, len(body), 10):
        chunk = body[i:i + 10]
        if len(chunk) != 10:
            break
        addr = ".".join(str(b) for b in chunk[0:4])
        udp_port = struct.unpack(">H", chunk[4:6])[0]
        ttl = struct.unpack(">H", chunk[6:8])[0]
        remain = struct.unpack(">H", chunk[8:10])[0]
        entries.append({"ip": addr, "port": udp_port,
                        "ttl": ttl, "remaining": remain})
    return entries


def _register_foreign_device(ip: str, port: int, ttl: int,
                             timeout: float) -> dict | None:
    body = struct.pack(">H", ttl)
    pkt = _bvlc(_BVLC_REGISTER_FD, body)
    reply = _udp_send_recv(ip, port, pkt, timeout)
    if reply is None:
        return None
    p = _parse_bvlc(reply)
    if not p or p[0] != _BVLC_RESULT or len(p[1]) < 2:
        return None
    code = struct.unpack(">H", p[1][:2])[0]
    return {"result_code": code, "accepted": code == 0x0000}


def _write_property_dry_run(ip: str, port: int, device_instance: int,
                            obj_type: int, obj_instance: int,
                            timeout: float) -> dict:
    """Read present-value, then write the SAME raw bytes back at priority 16.
    Returns {read_ok, write_ack, error, value_str}."""
    out: dict = {"read_ok": False, "write_ack": False, "error": "",
                 "value_str": ""}
    r = read_property(ip, port, device_instance, obj_type, obj_instance,
                      _PROP_PRESENT_VALUE, timeout=timeout)
    if not r or "value_bytes" not in r:
        out["error"] = "no present-value read"
        return out
    out["read_ok"] = True
    if r["values"]:
        out["value_str"] = str(r["values"][0])
    iid = _next_invoke_id()
    pkt = _write_property_packet(iid, obj_type, obj_instance,
                                 _PROP_PRESENT_VALUE, r["value_bytes"],
                                 priority=16)
    reply = _udp_send_recv(ip, port, pkt, timeout)
    if reply is None:
        out["error"] = "no reply"
        return out
    apdu = _apdu_from_reply(reply)
    if apdu is None or len(apdu) < 3:
        out["error"] = "malformed reply"
        return out
    ptype = apdu[0] & 0xF0
    if ptype == _APDU_SIMPLE_ACK and apdu[2] == _SVC_WRITE_PROPERTY:
        out["write_ack"] = True
        return out
    err = _parse_error(apdu)
    if err:
        out["error"] = f"{err['kind']} class={err['class']} code={err['code']}"
    else:
        out["error"] = f"unexpected pdu 0x{ptype:02x}"
    return out


def _dcc_probe(ip: str, port: int, timeout: float) -> dict:
    """Try DeviceCommunicationControl with each default password. Stops at the
    first SimpleAck. duration_min is fixed at 1 (never 0)."""
    out: dict = {"accepted_password": None, "attempts": [], "any_reply": False}
    for pw in _DEFAULT_PASSWORDS:
        iid = _next_invoke_id()
        pkt = _dcc_packet(iid, pw, duration_min=1)
        reply = _udp_send_recv(ip, port, pkt, timeout)
        if reply is None:
            out["attempts"].append({"password": pw, "result": "no-reply"})
            continue
        out["any_reply"] = True
        apdu = _apdu_from_reply(reply)
        if apdu is None or len(apdu) < 3:
            out["attempts"].append({"password": pw, "result": "malformed"})
            continue
        ptype = apdu[0] & 0xF0
        if ptype == _APDU_SIMPLE_ACK and apdu[2] == _SVC_DEVICE_COMM_CONTROL:
            out["attempts"].append({"password": pw, "result": "ack"})
            out["accepted_password"] = pw
            return out
        err = _parse_error(apdu)
        tag = (f"{err['kind']} c={err['class']} k={err['code']}"
               if err else f"pdu 0x{ptype:02x}")
        out["attempts"].append({"password": pw, "result": tag})
    return out


def _reinitialize_probe(ip: str, port: int, timeout: float) -> dict:
    """Try ReinitializeDevice WARMSTART with a deliberately bad password. A
    SimpleAck means the device didn't check — remote reboot is possible.
    Anything else (error / reject) is compared to the also-tried empty case
    so 'no password check' vs 'checked and refused' is distinguishable."""
    out: dict = {"unauth_accepted": False, "bad_pw_reply": "",
                 "empty_pw_reply": ""}
    for label, pw in (("bad", "recce-probe-not-a-real-password-XXXX"),
                      ("empty", "")):
        iid = _next_invoke_id()
        pkt = _reinitialize_packet(iid, pw)
        reply = _udp_send_recv(ip, port, pkt, timeout)
        if reply is None:
            out[f"{label}_pw_reply"] = "no-reply"
            continue
        apdu = _apdu_from_reply(reply)
        if apdu is None or len(apdu) < 3:
            out[f"{label}_pw_reply"] = "malformed"
            continue
        ptype = apdu[0] & 0xF0
        if ptype == _APDU_SIMPLE_ACK and apdu[2] == _SVC_REINITIALIZE_DEVICE:
            out[f"{label}_pw_reply"] = "ack"
            out["unauth_accepted"] = True
        else:
            err = _parse_error(apdu)
            out[f"{label}_pw_reply"] = (
                f"{err['kind']} c={err['class']} k={err['code']}"
                if err else f"pdu 0x{ptype:02x}")
    return out


def _amplification_probe(ip: str, port: int, timeout: float) -> dict:
    """Send one directed Who-Is; count replies inside the window."""
    pkt = _who_is_packet()
    replies = _udp_send_collect(ip, port, pkt, window=timeout,
                                max_replies=64)
    total_reply_bytes = sum(len(r) for r in replies)
    return {"request_bytes": len(pkt), "reply_bytes": total_reply_bytes,
            "reply_count": len(replies),
            "ratio": round(total_reply_bytes / max(1, len(pkt)), 2)}


def _object_list_walk(ip: str, port: int, device_instance: int,
                      timeout: float, max_entries: int = 32) -> list[tuple[int, int]]:
    """Walk Device.object-list by index (1..N). Uses array-index=0 first to
    learn the count; capped at `max_entries` to keep any single probe short."""
    r = read_property(ip, port, device_instance, _OBJ_DEVICE, device_instance,
                      _PROP_OBJECT_LIST, array_index=0, timeout=timeout)
    if not r or not r.get("values"):
        return []
    kind, count = r["values"][0]
    if kind != "unsigned":
        return []
    out: list[tuple[int, int]] = []
    for i in range(1, min(count, max_entries) + 1):
        r = read_property(ip, port, device_instance, _OBJ_DEVICE,
                          device_instance, _PROP_OBJECT_LIST,
                          array_index=i, timeout=timeout)
        if not r or not r.get("values"):
            continue
        v = r["values"][0]
        if v[0] == "objectid":
            out.append(v[1])
    return out


def _is_scannable_peer_ip(addr: str) -> bool:
    """Guardrail for BDT-peer chain probes. Skip 0.0.0.0/8, multicast
    (224.0.0.0/4) and 255.x — anything that's a broadcast/reserved address
    rather than a real host we should unicast at."""
    if not addr:
        return False
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    if octets[0] == 0 or octets[0] >= 224:
        return False
    if octets == [255, 255, 255, 255]:
        return False
    return True


def _bdt_peers_probe(bdt_entries: list[dict], self_ip: str, self_port: int,
                     timeout: float, max_peers: int = 3) -> list[dict]:
    """SAFE T2 proof for bacnet_bbmd_topology_disclosure.
    For each disclosed BDT peer (capped at max_peers), send ONE unicast
    Who-Is — the same read-only fingerprint we use for the primary target.
    A single I-Am reply proves the peer IP resolves to a live BACnet
    endpoint: the disclosed topology is actionable, not stale.
    Read-only, bounded (one packet per peer, one recv, timeout scaled)."""
    out: list[dict] = []
    tried = 0
    for entry in bdt_entries:
        if tried >= max_peers:
            break
        peer_ip = (entry.get("ip") or "").strip()
        peer_port = entry.get("port") or _DEFAULT_PORT
        if not _is_scannable_peer_ip(peer_ip):
            continue
        if peer_ip == self_ip and int(peer_port) == int(self_port):
            continue
        tried += 1
        try:
            iam = who_is(peer_ip, peer_port, timeout=timeout)
        except OSError:
            iam = None
        if iam and "device_instance" in iam:
            out.append({"ip": peer_ip, "port": peer_port,
                        "device_instance": iam.get("device_instance"),
                        "vendor_id": iam.get("vendor_id")})
    return out


def _atomic_read_file(ip: str, port: int, file_instance: int,
                      timeout: float) -> dict | None:
    """AtomicReadFile at offset 0, small count. Returns {bytes_hex, size}."""
    iid = _next_invoke_id()
    pkt = _atomic_read_file_packet(iid, file_instance, offset=0, count=32)
    reply = _udp_send_recv(ip, port, pkt, timeout)
    if reply is None:
        return None
    apdu = _apdu_from_reply(reply)
    if apdu is None or len(apdu) < 3:
        return None
    if (apdu[0] & 0xF0) != _APDU_COMPLEX_ACK or apdu[2] != _SVC_ATOMIC_READ_FILE:
        return None
    # Look for the octet-string application tag (tag 6) inside the response.
    off = 3
    while off < len(apdu):
        t = _decode_tag(apdu, off)
        if not t:
            break
        tag_num, is_ctx, length, new_off = t
        if length < 0:
            off = new_off
            continue
        if not is_ctx and tag_num == 6 and length >= 0:
            if new_off + length > len(apdu):
                break
            data = apdu[new_off:new_off + length]
            return {"bytes_hex": data[:64].hex(), "size": length}
        off = new_off + max(0, length)
    return {"bytes_hex": "", "size": 0}


# --- top-level probe -----------------------------------------------------------


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          *, do_write_dryrun: bool = True, do_dcc: bool = True,
          do_reinit: bool = True, do_bbmd: bool = True,
          do_amplification: bool = True, do_object_walk: bool = True,
          do_atomic_read: bool = True) -> dict:
    out: dict = {"reachable": False, "device_instance": None,
                 "max_apdu": 0, "segmentation": None, "vendor_id": None,
                 "identity": {}, "object_list": [], "bdt": [], "fdt": [],
                 "bdt_peers_live": [],
                 "foreign_reg": None, "amplification": None,
                 "write_dryrun": None, "dcc": None, "reinit": None,
                 "atomic_files": []}

    iam = who_is(ip, port, timeout=timeout)
    if not iam or "device_instance" not in iam:
        return out
    out["reachable"] = True
    out["device_instance"] = iam["device_instance"]
    out["max_apdu"] = iam.get("max_apdu", 0)
    out["segmentation"] = iam.get("segmentation")
    out["vendor_id"] = iam.get("vendor_id")
    dev = iam["device_instance"]

    identity: dict = {}
    for label, pid in (("object_name", _PROP_OBJECT_NAME),
                       ("vendor_name", _PROP_VENDOR_NAME),
                       ("model_name", _PROP_MODEL_NAME),
                       ("firmware_revision", _PROP_FIRMWARE_REV),
                       ("application_software", _PROP_APP_SW_VERSION),
                       ("vendor_id", _PROP_VENDOR_ID),
                       ("max_apdu", _PROP_MAX_APDU),
                       ("segmentation", _PROP_SEGMENTATION),
                       ("apdu_timeout", _PROP_APDU_TIMEOUT),
                       ("apdu_retries", _PROP_APDU_RETRIES)):
        r = read_property(ip, port, dev, _OBJ_DEVICE, dev, pid, timeout=timeout)
        if r and r.get("values"):
            kind, val = r["values"][0]
            identity[label] = val
    out["identity"] = identity

    if do_object_walk:
        try:
            out["object_list"] = _object_list_walk(ip, port, dev, timeout=timeout)
        except OSError:
            pass

    if do_bbmd:
        try:
            bdt = _read_bdt(ip, port, timeout=timeout)
            if bdt is not None:
                out["bdt"] = bdt
            fdt = _read_fdt(ip, port, timeout=timeout)
            if fdt is not None:
                out["fdt"] = fdt
            out["foreign_reg"] = _register_foreign_device(ip, port, ttl=60,
                                                          timeout=timeout)
        except OSError:
            pass
        # T2 chain probe: verify at least one BDT peer is a live BACnet
        # endpoint (safe unicast Who-Is, bounded to 3 peers).
        if out["bdt"]:
            try:
                out["bdt_peers_live"] = _bdt_peers_probe(
                    out["bdt"], ip, port, timeout=timeout)
            except OSError:
                pass

    if do_amplification:
        try:
            out["amplification"] = _amplification_probe(ip, port, timeout=timeout)
        except OSError:
            pass

    if do_write_dryrun and out["object_list"]:
        av = next((o for o in out["object_list"] if o[0] == _OBJ_ANALOG_VALUE), None)
        if av:
            try:
                out["write_dryrun"] = _write_property_dry_run(
                    ip, port, dev, av[0], av[1], timeout=timeout)
            except OSError:
                pass

    if do_dcc:
        try:
            out["dcc"] = _dcc_probe(ip, port, timeout=timeout)
        except OSError:
            pass

    if do_reinit:
        try:
            out["reinit"] = _reinitialize_probe(ip, port, timeout=timeout)
        except OSError:
            pass

    if do_atomic_read and out["object_list"]:
        files = [o for o in out["object_list"] if o[0] == _OBJ_FILE][:3]
        for fobj in files:
            try:
                r = _atomic_read_file(ip, port, fobj[1], timeout=timeout)
                if r:
                    out["atomic_files"].append({"instance": fobj[1], **r})
            except OSError:
                pass

    return out


def bacnet_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_bacnet(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "bacnet-stack", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def _has_bacnet_sc(host: Host) -> bool:
    for p in host.open_ports:
        if p.portid in _BACNET_SC_PORTS and (p.protocol or "tcp").lower() == "tcp":
            return True
    return False


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_bacnet(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            identity = pr.get("identity") or {}
            ident_str = " · ".join(f"{k}={v!r}" for k, v in identity.items()
                                   if k in ("vendor_name", "model_name",
                                            "firmware_revision", "object_name")
                                   and v)
            # 1. Reachable (info/high — a BACnet endpoint on scope IS a stance).
            out.append(_finding(
                "high",
                "BACnet/IP endpoint reachable (unauthenticated building-automation control plane)",
                tgt,
                f"Device instance {pr.get('device_instance')} answered Who-Is. "
                f"BACnet/IP has no authentication in the base protocol — anyone "
                f"who reaches this port can enumerate every point (HVAC, lighting, "
                f"access control) and, unless the device rejects WriteProperty "
                f"outright, write to commandable properties at priority 1. "
                + (f"{ident_str}." if ident_str else ""),
                f"bacnet-discover -a {h.ip} -p {p.portid}",
                "Place BACnet/IP on an isolated OT VLAN. If off-site management is "
                "required, front the segment with a BACnet-aware firewall / proxy "
                "and consider migrating to BACnet/SC (Annex AB, TLS-authenticated).",
                ["CWE-306", "CWE-284"], kind="bacnet_reachable",
                exploit_note=(
                    "bacnet-discover -a <ip>; then walk the object list "
                    "(bacwi -1 <ip>) and read Device object properties "
                    "(bacrp <ip> device <inst> object-name)."),
                depth_tier="t1"))

            # 2. Device identity disclosure.
            if identity:
                out.append(_finding(
                    "info", "BACnet device identity disclosed", tgt,
                    "Device object properties readable without auth: "
                    + ", ".join(f"{k}={v!r}" for k, v in identity.items() if v),
                    f"bacrp {pr.get('device_instance')} device "
                    f"{pr.get('device_instance')} object-name",
                    "Informational — feeds CPE / CVE mapping and correlates the "
                    "facility name across services (SNMP sysLocation, HTTP page "
                    "title on the vendor web UI).",
                    ["CWE-200"], kind="bacnet_device_identity",
                    exploit_note=(
                        "Cross-reference vendor/model against ICSA-* BAS "
                        "advisories; check the corresponding web UI on "
                        "80/443/8080 for default creds — Siemens Desigo: "
                        "admin/admin, JCI Metasys: MetasysSysAgent/"
                        "MetasysSysAgent."),
                    depth_tier="t0"))

            # 3. Object list.
            olist = pr.get("object_list") or []
            if olist:
                by_type: dict = {}
                for otype, oinst in olist:
                    by_type.setdefault(otype, []).append(oinst)
                summary = ", ".join(f"type{t}x{len(v)}" for t, v in sorted(by_type.items()))
                out.append(_finding(
                    "medium", "BACnet object inventory readable without authentication", tgt,
                    f"Device.object-list enumerated ({len(olist)} entries): {summary}. "
                    f"Each entry names a physical point (chiller, damper, door strike, "
                    f"schedule) an operator can target with ReadProperty / WriteProperty.",
                    f"bacwi -1 -p {p.portid} {h.ip}",
                    "Same containment as bacnet_reachable — the base protocol has no "
                    "auth to add here.",
                    ["CWE-200"], kind="bacnet_object_inventory",
                    exploit_note=(
                        "bacwi -1 <ip>; for each analog-value: bacrp <ip> "
                        "analog-value <inst> present-value; identify "
                        "high-value points (chillers, dampers, door-strikes) "
                        "by object-name field."),
                    depth_tier="t1"))

            # 4. BBMD BDT.
            bdt = pr.get("bdt") or []
            if bdt:
                live_peers = pr.get("bdt_peers_live") or []
                base_detail = (
                    f"Read-BDT returned {len(bdt)} peer BBMD(s): "
                    + ", ".join(f"{e['ip']}:{e['port']} mask {e['mask']}"
                                for e in bdt[:8])
                    + (" …" if len(bdt) > 8 else "")
                    + ". Each entry maps a peer BAS subnet — including sites "
                    "behind NAT that can be reached via Foreign-Device "
                    "registration or Distribute-Broadcast.")
                if live_peers:
                    # T2 SAFE PROOF: at least one disclosed BDT peer answered
                    # a unicast Who-Is with I-Am. Topology is not stale —
                    # cross-site BAS reachability is confirmed.
                    live_str = ", ".join(
                        f"{lp['ip']}:{lp['port']} "
                        f"(device #{lp['device_instance']}"
                        + (f", vendor={lp['vendor_id']}"
                           if lp.get("vendor_id") is not None else "")
                        + ")"
                        for lp in live_peers[:5])
                    detail = (
                        base_detail
                        + f" T2 chain probe: {len(live_peers)} of the "
                        f"disclosed peer BBMD(s) answered a unicast Who-Is "
                        f"with I-Am — live BAS endpoints reached from this "
                        f"host: {live_str}.")
                    depth_tier = "t2"
                else:
                    detail = base_detail
                    depth_tier = "t1"
                out.append(_finding(
                    "high",
                    "BACnet BBMD Broadcast-Distribution-Table readable (network topology disclosure)",
                    tgt, detail,
                    f"bvlc read-bdt {h.ip}:{p.portid}",
                    "Restrict BBMD peers to an explicit allow-list at the BAS controller and "
                    "at the network firewall; do not accept Read-BDT from untrusted sources.",
                    ["CWE-200"], kind="bacnet_bbmd_topology_disclosure",
                    exploit_note=(
                        "For each BDT entry, run bacnet-discover -a <peer_ip>; "
                        "the BDT maps the entire multi-site BAS. On corp-"
                        "reachable BBMDs this reveals sites behind NAT."),
                    depth_tier=depth_tier))

            # 5. BBMD FDT.
            fdt = pr.get("fdt") or []
            if fdt:
                out.append(_finding(
                    "medium",
                    "BACnet BBMD Foreign-Device-Table readable (remote-peer disclosure)",
                    tgt,
                    f"Read-FDT returned {len(fdt)} foreign device(s): "
                    + ", ".join(f"{e['ip']}:{e['port']} ttl={e['ttl']}" for e in fdt[:8])
                    + (" …" if len(fdt) > 8 else "")
                    + ". Each registered peer is typically an engineering laptop or a cloud "
                    "gateway — reachable pivot / lateral-movement targets.",
                    f"bvlc read-fdt {h.ip}:{p.portid}",
                    "Restrict Foreign-Device registration to allow-listed source IPs; disable "
                    "it entirely on Internet-reachable BBMDs.",
                    ["CWE-200"], kind="bacnet_fdt_disclosure",
                    exploit_note=(
                        "For each FDT entry, nmap -sV -p 80,443,8080,47808 "
                        "<peer_ip>; often the peer is an engineer's Windows "
                        "workstation with SMB/RDP open."),
                    depth_tier="t1"))

            # 6. Foreign-Device registration accepted.
            fr = pr.get("foreign_reg") or {}
            if fr.get("accepted"):
                out.append(_finding(
                    "high",
                    "BACnet Foreign-Device registration accepted from arbitrary host",
                    tgt,
                    "Register-Foreign-Device (0x05) succeeded (BVLC-Result 0x0000). "
                    "A registered foreign device receives every broadcast on the BACnet "
                    "segment AND can inject Distribute-Broadcast-to-Network (0x09) frames "
                    "— remote read/write access to the whole site.",
                    f"bacnet-fdr-register {h.ip}:{p.portid} --ttl 60",
                    "Configure the BBMD to accept Foreign-Device registration only from an "
                    "explicit allow-list, or disable the feature entirely if remote peers "
                    "are not required.",
                    ["CWE-284", "CWE-306"],
                    kind="bacnet_foreign_device_registration_permitted",
                    exploit_note=(
                        "bacnet-fdr-register <ip>:47808 --ttl 60; then broadcast "
                        "a Who-Is via the BBMD and receive I-Am from every peer "
                        "segment — proves segment-wide read from an off-site "
                        "host."),
                    depth_tier="t1"))

            # 7. Amplification.
            amp = pr.get("amplification") or {}
            if amp and amp.get("ratio", 0) >= 3.0 and amp.get("reply_count", 0) >= 2:
                out.append(_finding(
                    "medium",
                    "BACnet/IP acts as UDP amplification reflector (Who-Is/I-Am ratio)",
                    tgt,
                    f"One {amp['request_bytes']}-byte Who-Is drew {amp['reply_count']} "
                    f"I-Am replies totalling {amp['reply_bytes']} bytes "
                    f"(ratio {amp['ratio']}x). BACnet/IP is on the US-CERT TA14-017A "
                    "UDP-amplifier list; an Internet-exposed BBMD is abused for DDoS.",
                    f"bacnet-amp-check {h.ip}:{p.portid}",
                    "Do not expose 47808/udp to the Internet. Where segment reachability "
                    "is required, filter inbound Who-Is at the perimeter or rate-limit "
                    "responses at the BBMD.",
                    ["CWE-406"], kind="bacnet_amplification_reflector",
                    exploit_note=(
                        "hping3 -1 --spoof <victim> <ip> -d 12 -c 1 (with a "
                        "Who-Is payload) — DO NOT run at Internet scale; "
                        "corroborate the ratio only."),
                    depth_tier="t1"))

            # 8. Unauthenticated WriteProperty.
            wd = pr.get("write_dryrun") or {}
            if wd.get("write_ack"):
                out.append(_finding(
                    "critical",
                    "BACnet WriteProperty accepted without authentication (physical-process write)",
                    tgt,
                    f"Read present-value of an Analog-Value object, then re-wrote the "
                    f"SAME bytes at priority 16 (override-safe). The device returned "
                    f"SimpleAck — an attacker can WriteProperty at priority 1 to ANY "
                    f"commandable point on the site (setpoints, damper positions, door "
                    f"unlock schedules). Recorded value: {wd.get('value_str')!r}.",
                    f"bacwp -1 -p {p.portid} {h.ip} 2 <inst> 85 16 4 <val>",
                    "Deploy BACnet/SC (Annex AB) with certificate-based mutual auth, or "
                    "front the segment with a BACnet-aware firewall that blocks write "
                    "services (0x0F / 0x0E-WriteMultiple) from untrusted networks.",
                    ["CWE-306", "CWE-862"], kind="bacnet_unauth_write",
                    exploit_note=(
                        "TEST-CELL ONLY: bacwp -1 -p 47808 <ip> 2 <av_inst> 85 "
                        "1 4 <new_val>; verify with bacrp then restore. Never "
                        "against production."),
                    depth_tier="t2"))

            # 9. DCC accepted with default password.
            dcc = pr.get("dcc") or {}
            if dcc.get("accepted_password") is not None:
                pw = dcc["accepted_password"]
                out.append(_finding(
                    "high",
                    "BACnet DeviceCommunicationControl accepted with empty/default password (DoS primitive)",
                    tgt,
                    f"DCC (service 0x11) accepted with password={pw!r}. Recce sent "
                    f"duration=1 minute (NEVER 0). An attacker sending duration=0 "
                    f"disables device communication indefinitely — the classic BAS "
                    f"blackout. The same primitive at priority 1 also enables "
                    f"malicious-command hiding.",
                    f"bacdcc -p {p.portid} {h.ip} --disable --duration 1 --password {pw!r}",
                    "Set a strong non-default DCC password on every controller; where "
                    "the vendor supports it, disable DCC entirely from the network side.",
                    ["CWE-521", "CWE-1188"], kind="bacnet_dcc_default_password",
                    exploit_note=(
                        "TEST-CELL ONLY: bacdcc -p 47808 <ip> --disable "
                        "--duration 0 --password '<accepted_pw>' — brings the "
                        "controller offline until manual re-enable. Never on "
                        "production."),
                    depth_tier="t2"))

            # 10. Reinitialize reachable without valid password.
            ri = pr.get("reinit") or {}
            if ri.get("unauth_accepted"):
                out.append(_finding(
                    "high",
                    "BACnet ReinitializeDevice reachable without valid password (remote reboot)",
                    tgt,
                    f"ReinitializeDevice (0x14) WARMSTART returned SimpleAck for a "
                    f"deliberately BAD password (bad-pw reply={ri.get('bad_pw_reply')!r}, "
                    f"empty-pw reply={ri.get('empty_pw_reply')!r}). The device performed no "
                    f"password check — any client can remotely reboot the controller "
                    f"(coldstart) and drop every point offline while it comes back.",
                    f"bacrd -p {p.portid} {h.ip} warmstart",
                    "Set a strong non-default ReinitializeDevice password on every "
                    "controller. Where feasible, restrict the service to a management "
                    "VLAN only.",
                    ["CWE-306", "CWE-521"], kind="bacnet_reinitialize_permitted",
                    exploit_note=(
                        "TEST-CELL ONLY: bacrd -p 47808 <ip> warmstart; observe "
                        "the controller reboot and all points drop for the boot "
                        "cycle."),
                    depth_tier="t2"))

            # 11. AtomicReadFile.
            files = pr.get("atomic_files") or []
            if files:
                out.append(_finding(
                    "medium",
                    "BACnet AtomicReadFile returned file contents without authentication",
                    tgt,
                    f"AtomicReadFile (0x06) succeeded on {len(files)} File object(s). "
                    f"First bytes (hex, capped): "
                    + "; ".join(f"instance {f['instance']} size={f['size']} "
                                f"hex={f['bytes_hex']}" for f in files[:3])
                    + ". Controllers commonly expose config, backup and log files this "
                    "way with no auth.",
                    f"bacnet-atomic-read -p {p.portid} {h.ip} 10 <instance> 0 64",
                    "Restrict AtomicReadFile at a BACnet firewall; on the controller, "
                    "delete or ACL File objects that carry configuration or logs.",
                    ["CWE-200", "CWE-306"], kind="bacnet_atomic_file_read",
                    exploit_note=(
                        "bacnet-atomic-read -p 47808 <ip> 10 <file_inst> 0 "
                        "65535; save to disk and strings/hex it — look for "
                        "admin creds, WPA keys, BMS API keys embedded in "
                        "config backups."),
                    depth_tier="t2"))

            # 12. Stack fingerprint (segmentation + max APDU).
            seg = identity.get("segmentation")
            mapdu = identity.get("max_apdu") or pr.get("max_apdu")
            if seg is not None and mapdu:
                out.append(_finding(
                    "low", "BACnet stack fingerprint (max APDU + segmentation)", tgt,
                    f"max-APDU-length-accepted={mapdu} segmentation-supported={seg}. "
                    "Small max-APDU + segmented-both is a fingerprint of low-end "
                    "controllers whose parsers have historically shipped with vendor-"
                    "specific parser DoS bugs.",
                    f"bacepics -p {p.portid} {h.ip}",
                    "Track the concrete vendor / firmware against the vendor CVE feed; "
                    "apply firmware updates where available.",
                    ["CWE-200"], kind="bacnet_stack_fingerprint",
                    exploit_note=(
                        "Correlate small max-APDU + segmented-both against "
                        "BACnet-stack DoS CVEs — e.g. Trane/SmartX / "
                        "Cimetrics / Delta Controls parser bugs; do NOT fuzz "
                        "against production."),
                    depth_tier="t0"))

            # 13. BACnet/SC downgrade path.
            if _has_bacnet_sc(h):
                out.append(_finding(
                    "low",
                    "BACnet Secure Connect (BACnet/SC) present alongside plaintext BACnet/IP (downgrade path)",
                    tgt,
                    "This host serves BACnet/SC on 47820/tcp AND plaintext BACnet/IP on "
                    f"{p.portid}/udp. Leaving /IP up while /SC is deployed defeats the "
                    "TLS-authenticated Annex AB replacement — an attacker just talks to "
                    "the /IP port.",
                    f"nmap -p 47820,{p.portid} {h.ip}",
                    "Disable the plaintext BACnet/IP port on the controller once BACnet/SC "
                    "is in production; require /SC end-to-end.",
                    ["CWE-757", "CWE-319"], kind="bacnet_sc_downgrade",
                    exploit_note=(
                        "nmap -p 47820,47808 <ip>; confirm both open then "
                        "talk plaintext to 47808 to prove downgrade works "
                        "even though /SC exists on 47820."),
                    depth_tier="t1"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Who-Is / I-Am unicast identity",
         "cmd": f"bacnet-discover -a {ip} -p {port}"},
        {"step": "Read Device object identity",
         "cmd": f"bacrp -p {port} {ip} device <instance> object-name"},
        {"step": "Enumerate object-list",
         "cmd": f"bacwi -1 -p {port} {ip}"},
        {"step": "Dump BBMD Broadcast-Distribution-Table",
         "cmd": f"bvlc read-bdt {ip}:{port}"},
        {"step": "Dump BBMD Foreign-Device-Table",
         "cmd": f"bvlc read-fdt {ip}:{port}"},
        {"step": "Attempt Foreign-Device registration (60s TTL)",
         "cmd": f"bacnet-fdr-register {ip}:{port} --ttl 60"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "bacnet", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    from ..core.known_bacnet_networks import record_bacnet_network
    from ..core.known_ot_assets import record_ot_asset
    targets = bacnet_targets(hosts)
    by_ip = {h.ip: h for h in hosts}
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["device_instance"] = pr.get("device_instance")
                ident = pr.get("identity") or {}
                t["vendor"] = ident.get("vendor_name", "")
                t["model"] = ident.get("model_name", "")
                t["object_name"] = ident.get("object_name", "")
                host = by_ip.get(t["ip"])
                if host is not None:
                    # OT asset — firmware_versions projection consumes this.
                    if ident.get("vendor_name") or ident.get("firmware_revision"):
                        record_ot_asset(
                            host, "bacnet",
                            vendor=str(ident.get("vendor_name") or ""),
                            model=str(ident.get("model_name") or ""),
                            firmware=str(ident.get("firmware_revision") or ""),
                            source="bacnet:read-property")
                    # BBMD BDT topology — one row per disclosed peer.
                    for peer in pr.get("bdt") or []:
                        record_bacnet_network(
                            host, t["ip"], t["port"],
                            str(peer.get("ip") or ""),
                            int(peer.get("port") or 0),
                            mask=str(peer.get("mask") or ""))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
