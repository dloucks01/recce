"""CoAP (5683/udp plaintext, 5684/udp DTLS) endpoint probe.

CoAP endpoints publish an unauthenticated resource inventory at
/.well-known/core (RFC 6690) — the IoT equivalent of an MQTT wildcard
subscribe. A single 4-byte-header UDP request enumerates every sensor,
actuator, and config resource on the device. Anonymous PUT/POST to an
actuator path = physical-world write access; Observe (RFC 7641) leaks
live telemetry.

Covered:
  * coap_empty_ping                 (info)      — CON 0.00 -> RST fingerprint
  * coap_resource_inventory         (high)      — /.well-known/core dump
  * coap_actuator_exposed           (critical)  — anon write to an actuator
  * coap_device_disclosure          (high)      — /oic/d, /oic/p leak identity
  * coap_observe_leak               (high)      — live telemetry via Observe
  * coap_open_proxy                 (high)      — Proxy-Uri accepted (SSRF)
  * coap_amplifier                  (medium)    — response/request > 5x
  * coap_dtls_psk_hint              (medium)    — DTLS PSK identity hint leak
  * coap_dtls_weak                  (high)      — NULL / export cipher offered
  * coap_authgated                  (info)      — reachable, 4.01/4.03 gated
  * coap_oscore                     (info)      — OSCORE Option observed
  * coap_plaintext                  (medium)    — 5683/udp without DTLS

Airgap-safe: stdlib socket + struct only. Every socket op is bounded
through core.proxy.scaled().
"""
from __future__ import annotations

import os
import re
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 5683
_DTLS_PORT = 5684
_TIMEOUT = 4.0

# RFC 7252 §3 message types.
_T_CON = 0
_T_NON = 1
_T_ACK = 2
_T_RST = 3

# Method + response code helpers. RFC 7252 codes are 8-bit c.dd (3-bit class,
# 5-bit detail).
_M_GET = 0x01
_M_POST = 0x02
_M_PUT = 0x03
_M_DELETE = 0x04

# Option numbers (RFC 7252 §5.10 + RFC 7641 + RFC 7959 + RFC 8613).
_OPT_IF_MATCH = 1
_OPT_URI_HOST = 3
_OPT_ETAG = 4
_OPT_IF_NONE_MATCH = 5
_OPT_OBSERVE = 6
_OPT_URI_PORT = 7
_OPT_LOCATION_PATH = 8
_OPT_OSCORE = 9
_OPT_URI_PATH = 11
_OPT_CONTENT_FORMAT = 12
_OPT_MAX_AGE = 14
_OPT_URI_QUERY = 15
_OPT_ACCEPT = 17
_OPT_LOCATION_QUERY = 20
_OPT_BLOCK2 = 23
_OPT_BLOCK1 = 27
_OPT_SIZE2 = 28
_OPT_PROXY_URI = 35
_OPT_PROXY_SCHEME = 39
_OPT_SIZE1 = 60

_PAYLOAD_MARKER = 0xFF

# Content-Format registry subset used here (IANA CoAP Content-Formats).
_CT_TEXT = 0
_CT_LINK = 40
_CT_XML = 41
_CT_OCTET = 42
_CT_JSON = 50
_CT_CBOR = 60
_CT_SENML_JSON = 110
_CT_SENML_CBOR = 112

_CT_NAMES = {
    _CT_TEXT: "text/plain",
    _CT_LINK: "application/link-format",
    _CT_XML: "application/xml",
    _CT_OCTET: "application/octet-stream",
    _CT_JSON: "application/json",
    _CT_CBOR: "application/cbor",
    _CT_SENML_JSON: "application/senml+json",
    _CT_SENML_CBOR: "application/senml+cbor",
}

# Byte-safe (no CoAP option header can collide) — used to spot RST/ACK to a
# CON we sent when passively fingerprinting.
_VER = 1

# Resources whose payload names the device model/vendor for CVE mapping.
_DEVICE_RESOURCE_HINTS = ("/oic/d", "/oic/p", "/device", "/dev/info",
                          "/config", "/firmware")

# rt= namespaces that identify the underlying stack — feeds CVE mapper.
_RT_STACK_HINTS = {
    "oic.": ("iotivity", "OCF / iotivity-lite"),
    "snip.": ("espressif", "Espressif ESP-IDF"),
    "ipso.": ("ipso", "IPSO Smart Objects"),
    "contiki.": ("contiki-ng", "Contiki-NG"),
}

# Weakly-marked "actuator" or "writable" hints — write attempts on these
# only run when active=True AND a pre-value was successfully captured.
_ACTUATOR_HINTS = ("actuator", "switch", "relay", "light", "valve",
                   "oic.r.switch", "oic.a.", "core.a", "core.p")


def is_coap(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (_DEFAULT_PORT, _DTLS_PORT)
            or "coap" in svc or "coap" in prod)


# --- Wire codec -----------------------------------------------------------

def _encode_option_nibbles(delta: int, length: int) -> tuple[int, bytes]:
    """Return (header_byte, extension_bytes) for one option (RFC 7252 §3.1).

    Delta / length values 0-12 fit in the 4-bit nibble. 13 = 1-byte extension
    (value - 13). 14 = 2-byte extension (value - 269). 15 is reserved (delta)
    or reserved-must-not-appear (length)."""
    def _nibble(v: int) -> tuple[int, bytes]:
        if v < 13:
            return v, b""
        if v < 269:
            return 13, bytes([v - 13])
        if v < 65805:
            return 14, struct.pack(">H", v - 269)
        raise ValueError("option field too large")

    dn, dext = _nibble(delta)
    ln, lext = _nibble(length)
    return (dn << 4) | ln, dext + lext


def _encode_options(options: list[tuple[int, bytes]]) -> bytes:
    """Encode a list of (number, value) options. RFC 7252 requires ascending
    option-number order with cumulative delta encoding; caller supplies the
    values, we sort and emit."""
    out = bytearray()
    prev = 0
    for num, value in sorted(options, key=lambda x: x[0]):
        delta = num - prev
        prev = num
        header, ext = _encode_option_nibbles(delta, len(value))
        out.append(header)
        out += ext
        out += value
    return bytes(out)


def _encode_message(t: int, code: int, mid: int, token: bytes = b"",
                    options: list[tuple[int, bytes]] | None = None,
                    payload: bytes = b"") -> bytes:
    """Encode one CoAP message (RFC 7252 §3)."""
    if not (0 <= t <= 3):
        raise ValueError("bad message type")
    tkl = len(token)
    if tkl > 8:
        raise ValueError("token length > 8")
    header = bytes([(_VER << 6) | (t << 4) | tkl, code & 0xFF,
                    (mid >> 8) & 0xFF, mid & 0xFF])
    opts = _encode_options(options or [])
    body = header + token + opts
    if payload:
        body += bytes([_PAYLOAD_MARKER]) + payload
    return body


def _decode_option_field(data: bytes, i: int, nibble: int) -> tuple[int, int]:
    """Return (extended_value, new_offset) for a delta or length nibble."""
    if nibble < 13:
        return nibble, i
    if nibble == 13:
        if i >= len(data):
            raise ValueError("truncated option extension (13)")
        return data[i] + 13, i + 1
    if nibble == 14:
        if i + 2 > len(data):
            raise ValueError("truncated option extension (14)")
        return struct.unpack(">H", data[i:i + 2])[0] + 269, i + 2
    raise ValueError("reserved option nibble 15")


def _decode_message(pkt: bytes) -> dict:
    """Parse one CoAP message. Returns {ver,t,tkl,code,mid,token,options,payload}.
    Raises ValueError on malformed input."""
    if len(pkt) < 4:
        raise ValueError("short header")
    b0 = pkt[0]
    ver = (b0 >> 6) & 0x03
    t = (b0 >> 4) & 0x03
    tkl = b0 & 0x0F
    if ver != _VER:
        raise ValueError(f"unsupported version {ver}")
    if tkl > 8:
        raise ValueError("token length > 8")
    code = pkt[1]
    mid = (pkt[2] << 8) | pkt[3]
    i = 4
    if i + tkl > len(pkt):
        raise ValueError("truncated token")
    token = pkt[i:i + tkl]
    i += tkl
    options: list[tuple[int, bytes]] = []
    prev_num = 0
    while i < len(pkt):
        b = pkt[i]
        if b == _PAYLOAD_MARKER:
            i += 1
            return {"ver": ver, "t": t, "tkl": tkl, "code": code, "mid": mid,
                    "token": token, "options": options, "payload": pkt[i:]}
        i += 1
        d_nib = (b >> 4) & 0x0F
        l_nib = b & 0x0F
        delta, i = _decode_option_field(pkt, i, d_nib)
        length, i = _decode_option_field(pkt, i, l_nib)
        if i + length > len(pkt):
            raise ValueError("option value truncated")
        value = pkt[i:i + length]
        i += length
        num = prev_num + delta
        prev_num = num
        options.append((num, value))
    return {"ver": ver, "t": t, "tkl": tkl, "code": code, "mid": mid,
            "token": token, "options": options, "payload": b""}


def _code_str(code: int) -> str:
    """`code` → 'c.dd' (e.g. 0x45 -> '2.05')."""
    return f"{(code >> 5) & 0x07}.{code & 0x1F:02d}"


def _first_opt(options: list[tuple[int, bytes]], num: int) -> bytes | None:
    for n, v in options:
        if n == num:
            return v
    return None


def _all_opt(options: list[tuple[int, bytes]], num: int) -> list[bytes]:
    return [v for n, v in options if n == num]


def _content_format(options: list[tuple[int, bytes]]) -> int | None:
    v = _first_opt(options, _OPT_CONTENT_FORMAT)
    if v is None:
        return None
    if not v:
        return 0
    return int.from_bytes(v, "big")


def _uint_option(value: int) -> bytes:
    """CoAP uint option encoding (§3.2): shortest big-endian, empty for 0."""
    if value == 0:
        return b""
    n = (value.bit_length() + 7) // 8
    return value.to_bytes(n, "big")


def _uri_path_options(path: str) -> list[tuple[int, bytes]]:
    """Split a path like '/.well-known/core' into Uri-Path segments."""
    segments = [s for s in path.split("/") if s]
    return [(_OPT_URI_PATH, s.encode("utf-8")) for s in segments]


# --- CoAP UDP transport ---------------------------------------------------

def _open_udp(timeout: float) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(proxy.scaled(timeout))
    return s


def _txn(sock: socket.socket, ip: str, port: int, pkt: bytes,
         timeout: float, expect_mid: int | None = None) -> tuple[bytes, tuple] | tuple[None, None]:
    """Send one CoAP packet, receive one. Filters by MID when specified so a
    stale earlier reply cannot be misread as the answer to this request."""
    try:
        sock.sendto(pkt, (ip, port))
    except OSError:
        return None, None
    deadline = proxy.scaled(timeout)
    sock.settimeout(deadline)
    try:
        data, addr = sock.recvfrom(65535)
    except (socket.timeout, OSError):
        return None, None
    if expect_mid is not None and len(data) >= 4:
        rmid = (data[2] << 8) | data[3]
        if rmid != expect_mid:
            return None, None
    return data, addr


def _rand_mid() -> int:
    return int.from_bytes(os.urandom(2), "big")


def _rand_token(length: int = 4) -> bytes:
    return os.urandom(length)


# --- Capability: empty-CON ping (RFC 7252 §4.3) ---------------------------

def empty_ping(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Send an empty CON. RFC 7252 requires an RST with matching MID; a NON-
    CoAP endpoint will either not answer or answer with something else."""
    out = {"ok": False, "reply_type": None, "matching_mid": False}
    mid = _rand_mid()
    pkt = _encode_message(_T_CON, 0x00, mid)
    sock = _open_udp(timeout)
    try:
        data, _ = _txn(sock, ip, port, pkt, timeout, expect_mid=mid)
    finally:
        sock.close()
    if not data or len(data) < 4:
        return out
    try:
        msg = _decode_message(data)
    except ValueError:
        return out
    out["reply_type"] = msg["t"]
    out["matching_mid"] = msg["mid"] == mid
    out["ok"] = msg["mid"] == mid and msg["t"] in (_T_RST, _T_ACK) and msg["code"] == 0x00
    return out


# --- Capability: /.well-known/core resource dump (RFC 6690) --------------

def _build_get(path: str, token: bytes, mid: int,
               accept: int | None = None,
               extra_options: list[tuple[int, bytes]] | None = None,
               block2: tuple[int, int, int] | None = None) -> bytes:
    """CON GET request."""
    opts = _uri_path_options(path)
    if accept is not None:
        opts.append((_OPT_ACCEPT, _uint_option(accept)))
    if block2 is not None:
        num, m, szx = block2
        v = (num << 4) | ((m & 1) << 3) | (szx & 0x07)
        opts.append((_OPT_BLOCK2, _uint_option(v)))
    if extra_options:
        opts.extend(extra_options)
    return _encode_message(_T_CON, _M_GET, mid, token, opts)


def _decode_block2(value: bytes) -> tuple[int, int, int]:
    """(block-num, more-flag, szx)."""
    n = int.from_bytes(value, "big") if value else 0
    return n >> 4, (n >> 3) & 1, n & 0x07


def get_resource(ip: str, port: int, path: str,
                 timeout: float = _TIMEOUT,
                 accept: int | None = None,
                 max_blocks: int = 16,
                 block_size_szx: int = 6) -> dict:
    """CoAP GET with automatic Block2 reassembly (RFC 7959) bounded to
    max_blocks * (16 << szx) bytes."""
    out = {"reachable": False, "code": 0, "code_str": "", "payload": b"",
           "content_format": None, "options": [], "truncated": False}
    sock = _open_udp(timeout)
    try:
        block_num = 0
        assembled = bytearray()
        block_ct: int | None = None
        while block_num < max_blocks:
            token = _rand_token()
            mid = _rand_mid()
            pkt = _build_get(path, token, mid, accept=accept,
                             block2=(block_num, 0, block_size_szx))
            data, _ = _txn(sock, ip, port, pkt, timeout, expect_mid=mid)
            if not data:
                if block_num == 0:
                    return out
                out["truncated"] = True
                break
            try:
                msg = _decode_message(data)
            except ValueError:
                return out
            out["reachable"] = True
            out["code"] = msg["code"]
            out["code_str"] = _code_str(msg["code"])
            if block_num == 0:
                out["options"] = msg["options"]
                block_ct = _content_format(msg["options"])
                out["content_format"] = block_ct
            assembled += msg["payload"]
            b2 = _first_opt(msg["options"], _OPT_BLOCK2)
            if b2 is None:
                break
            _num, more, szx = _decode_block2(b2)
            if not more:
                break
            block_size_szx = szx
            block_num += 1
        else:
            out["truncated"] = True
        out["payload"] = bytes(assembled)
    finally:
        sock.close()
    return out


# --- CoRE Link Format parser (RFC 6690) -----------------------------------

def parse_link_format(text: str) -> list[dict]:
    """Parse the /.well-known/core body. Returns a list of
    {path, rt, if, ct, sz, obs, raw} dicts."""
    out: list[dict] = []
    # Split at commas that are NOT inside quotes.
    entries = _split_top(text, ",")
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        parts = _split_top(entry, ";")
        head = parts[0].strip()
        m = re.match(r"^<([^>]*)>$", head)
        if not m:
            continue
        rec: dict = {"path": m.group(1), "raw": entry,
                     "rt": "", "if": "", "ct": "", "sz": "", "obs": False}
        for p in parts[1:]:
            p = p.strip()
            if not p:
                continue
            if p == "obs":
                rec["obs"] = True
                continue
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            v = v.strip().strip('"')
            if k in rec:
                rec[k] = v
        out.append(rec)
    return out


def _split_top(text: str, sep: str) -> list[str]:
    """Split on `sep` while respecting double-quoted spans."""
    out = []
    buf = []
    in_q = False
    for ch in text:
        if ch == '"':
            in_q = not in_q
            buf.append(ch)
        elif ch == sep and not in_q:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return out


# --- Capability: resource GET sweep ---------------------------------------

def resource_sweep(ip: str, port: int, resources: list[dict],
                   timeout: float = _TIMEOUT, max_resources: int = 100,
                   snippet: int = 256) -> list[dict]:
    """GET each resource; record code, size, snippet."""
    out: list[dict] = []
    for rec in resources[:max_resources]:
        path = rec.get("path") or ""
        if not path or path == "/.well-known/core":
            continue
        ct_hint = rec.get("ct")
        accept = None
        if ct_hint and ct_hint.isdigit():
            accept = int(ct_hint)
        r = get_resource(ip, port, path, timeout=timeout, accept=accept,
                         max_blocks=4)
        if not r["reachable"]:
            continue
        out.append({
            "path": path,
            "code": r["code_str"],
            "code_num": r["code"],
            "ct": r["content_format"],
            "size": len(r["payload"]),
            "snippet": r["payload"][:snippet],
        })
    return out


# --- Capability: PUT/POST permission test ---------------------------------

def _build_put(path: str, token: bytes, mid: int, payload: bytes,
               content_format: int | None = None) -> bytes:
    opts = _uri_path_options(path)
    if content_format is not None:
        opts.append((_OPT_CONTENT_FORMAT, _uint_option(content_format)))
    return _encode_message(_T_CON, _M_PUT, mid, token, opts, payload)


def write_permission_test(ip: str, port: int, path: str,
                          pre_value: bytes,
                          pre_content_format: int | None,
                          timeout: float = _TIMEOUT) -> dict:
    """Attempt an anonymous PUT with a benign marker. On 2.01/2.04 response,
    IMMEDIATELY roll back to `pre_value`. Skip write attempts when we did NOT
    manage to read a pre-value (write-only resources; caller decides)."""
    out = {"attempted": False, "writable": False, "code": "",
           "rolled_back": False, "error": ""}
    marker = ("recce-probe-" + os.urandom(4).hex()).encode("ascii")
    mid = _rand_mid()
    token = _rand_token()
    pkt = _build_put(path, token, mid, marker, content_format=pre_content_format)
    sock = _open_udp(timeout)
    try:
        out["attempted"] = True
        data, _ = _txn(sock, ip, port, pkt, timeout, expect_mid=mid)
        if not data:
            out["error"] = "no reply"
            return out
        try:
            msg = _decode_message(data)
        except ValueError:
            out["error"] = "malformed reply"
            return out
        out["code"] = _code_str(msg["code"])
        cls = (msg["code"] >> 5) & 0x07
        if cls == 2:
            out["writable"] = True
            # Roll back to the pre-value we captured.
            rb_mid = _rand_mid()
            rb_pkt = _build_put(path, _rand_token(), rb_mid, pre_value,
                                content_format=pre_content_format)
            rb_data, _ = _txn(sock, ip, port, rb_pkt, timeout,
                              expect_mid=rb_mid)
            if rb_data:
                try:
                    rb_msg = _decode_message(rb_data)
                    if ((rb_msg["code"] >> 5) & 0x07) == 2:
                        out["rolled_back"] = True
                except ValueError:
                    pass
    finally:
        sock.close()
    return out


# --- Capability: Observe (RFC 7641) ---------------------------------------

def observe_resource(ip: str, port: int, path: str,
                     window: float = 3.0, max_notifications: int = 5,
                     timeout: float = _TIMEOUT) -> dict:
    """Register an Observe (Observe option = 0), collect notifications for
    `window` seconds, deregister with Observe = 1 before closing."""
    out = {"registered": False, "notifications": [],
           "code": "", "error": ""}
    token = _rand_token()
    mid = _rand_mid()
    opts = _uri_path_options(path) + [(_OPT_OBSERVE, _uint_option(0))]
    pkt = _encode_message(_T_CON, _M_GET, mid, token, opts)
    sock = _open_udp(timeout)
    try:
        try:
            sock.sendto(pkt, (ip, port))
        except OSError as e:
            out["error"] = f"send: {e}"
            return out
        end = _monotonic_deadline(window)
        got_any = False
        while len(out["notifications"]) < max_notifications:
            remaining = end - _monotonic()
            if remaining <= 0:
                break
            sock.settimeout(proxy.scaled(min(remaining, 1.5)))
            try:
                data, _ = sock.recvfrom(65535)
            except (socket.timeout, OSError):
                break
            try:
                msg = _decode_message(data)
            except ValueError:
                continue
            if msg["token"] != token:
                continue
            if not got_any:
                out["registered"] = True
                out["code"] = _code_str(msg["code"])
                got_any = True
            obs = _first_opt(msg["options"], _OPT_OBSERVE)
            if obs is None and got_any and out["notifications"]:
                break
            out["notifications"].append({
                "code": _code_str(msg["code"]),
                "observe": int.from_bytes(obs or b"", "big"),
                "size": len(msg["payload"]),
                "snippet": msg["payload"][:128],
            })
        # Deregister (Observe = 1). Best-effort — the server may already have
        # dropped the observation when the client stopped ACKing CONs.
        try:
            dereg_opts = _uri_path_options(path) + [(_OPT_OBSERVE, _uint_option(1))]
            dereg = _encode_message(_T_CON, _M_GET, _rand_mid(), token, dereg_opts)
            sock.sendto(dereg, (ip, port))
        except OSError:
            pass
    finally:
        sock.close()
    return out


def _monotonic() -> float:
    import time
    return time.monotonic()


def _monotonic_deadline(window: float) -> float:
    return _monotonic() + window


# --- Capability: Proxy-Uri open-relay test --------------------------------

def proxy_relay_test(ip: str, port: int, proxy_uri: str,
                     timeout: float = _TIMEOUT) -> dict:
    """Send a GET with Proxy-Uri set. A 2.xx response or anything other than
    5.05 Proxying Not Supported / 4.05 Method Not Allowed = the endpoint
    attempted the proxy request."""
    out = {"attempted": False, "proxied": False, "code": "", "error": ""}
    mid = _rand_mid()
    token = _rand_token()
    opts = [(_OPT_PROXY_URI, proxy_uri.encode("utf-8"))]
    pkt = _encode_message(_T_CON, _M_GET, mid, token, opts)
    sock = _open_udp(timeout)
    try:
        out["attempted"] = True
        data, _ = _txn(sock, ip, port, pkt, timeout, expect_mid=mid)
        if not data:
            out["error"] = "no reply"
            return out
        try:
            msg = _decode_message(data)
        except ValueError:
            out["error"] = "malformed reply"
            return out
        out["code"] = _code_str(msg["code"])
        # RFC 7252 §5.7.2: proxy MUST reply 5.05 when it cannot / will not
        # forward, and 4.05 for Method Not Allowed. Everything else means the
        # request WAS interpreted as a proxy request.
        if out["code"] not in ("5.05", "4.05"):
            out["proxied"] = True
    finally:
        sock.close()
    return out


# --- Capability: DTLS ClientHello fingerprint (5684/udp) ------------------
# Minimal DTLS 1.2 ClientHello with PSK ciphers offered. We only parse the
# server response looking for HelloVerifyRequest, ServerHello, and PSK
# identity hint bytes — never establish a real session (that requires PSK).

# DTLS record: type(1) version(2) epoch(2) seq(6) length(2) fragment(...)
_DTLS_CONTENT_HANDSHAKE = 22
_DTLS_HS_HELLO_VERIFY = 3
_DTLS_HS_SERVER_HELLO = 2
_DTLS_HS_SERVER_KEY_EXCHANGE = 12

_DTLS12 = b"\xfe\xfd"           # DTLS 1.2 wire version

# Cipher suite IDs (subset relevant to CoAP/IoT profiles):
_PSK_CIPHERS = (
    (0xC0, 0xA8),  # TLS_PSK_WITH_AES_128_CCM_8 (RFC 7925 MTI)
    (0xC0, 0xA9),  # TLS_PSK_WITH_AES_256_CCM_8
    (0x00, 0x8C),  # TLS_PSK_WITH_AES_128_CBC_SHA
    (0x00, 0x8D),  # TLS_PSK_WITH_AES_256_CBC_SHA
    (0xC0, 0x37),  # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
    (0xC0, 0x35),  # TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA (alt)
    (0xC0, 0x2B),  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (RFC 7925 RPK)
)

_WEAK_CIPHERS = {
    (0x00, 0x00): "TLS_NULL_WITH_NULL_NULL",
    (0x00, 0x01): "TLS_RSA_WITH_NULL_MD5",
    (0x00, 0x02): "TLS_RSA_WITH_NULL_SHA",
    (0x00, 0x2C): "TLS_PSK_WITH_NULL_SHA",
    (0x00, 0x2D): "TLS_DHE_PSK_WITH_NULL_SHA",
    (0x00, 0x2E): "TLS_RSA_PSK_WITH_NULL_SHA",
}


def _build_dtls_client_hello() -> bytes:
    """A minimal DTLS 1.2 ClientHello offering the PSK IoT-profile ciphers."""
    random_bytes = b"\x00" * 4 + os.urandom(28)   # unix time + 28 random
    session_id = b""
    cookie = b""
    cipher_body = b"".join(bytes(c) for c in _PSK_CIPHERS)
    cipher_suites = struct.pack(">H", len(cipher_body)) + cipher_body
    compression = bytes([1, 0])                   # 1 method, null
    # No extensions.
    body = (_DTLS12
            + random_bytes
            + bytes([len(session_id)]) + session_id
            + bytes([len(cookie)]) + cookie
            + cipher_suites
            + compression)
    hs_type = 1                                    # ClientHello
    hs_len = len(body)
    # DTLS handshake header: type(1) length(3) seq(2) frag_off(3) frag_len(3)
    hs_header = (bytes([hs_type])
                 + hs_len.to_bytes(3, "big")
                 + b"\x00\x00"
                 + b"\x00\x00\x00"
                 + hs_len.to_bytes(3, "big"))
    handshake = hs_header + body
    # DTLS record header: type(1) version(2) epoch(2) seq(6) length(2)
    record = (bytes([_DTLS_CONTENT_HANDSHAKE])
              + _DTLS12
              + b"\x00\x00"
              + b"\x00\x00\x00\x00\x00\x00"
              + struct.pack(">H", len(handshake)))
    return record + handshake


def _iter_dtls_records(data: bytes):
    """Yield (content_type, version, fragment) for each DTLS record."""
    i = 0
    while i + 13 <= len(data):
        ctype = data[i]
        version = data[i + 1:i + 3]
        length = struct.unpack(">H", data[i + 11:i + 13])[0]
        frag = data[i + 13:i + 13 + length]
        if len(frag) != length:
            return
        yield ctype, version, frag
        i += 13 + length


def _parse_dtls_handshakes(records) -> list[tuple[int, bytes]]:
    """Yield (handshake_type, body_bytes) from a stream of handshake records."""
    out = []
    for ctype, _version, frag in records:
        if ctype != _DTLS_CONTENT_HANDSHAKE:
            continue
        i = 0
        while i + 12 <= len(frag):
            hs_type = frag[i]
            hs_len = int.from_bytes(frag[i + 1:i + 4], "big")
            body = frag[i + 12:i + 12 + hs_len]
            if len(body) != hs_len:
                return out
            out.append((hs_type, body))
            i += 12 + hs_len
    return out


def dtls_fingerprint(ip: str, port: int = _DTLS_PORT,
                     timeout: float = _TIMEOUT) -> dict:
    """Send one DTLS 1.2 ClientHello, parse whatever comes back. Best-effort:
    HelloVerifyRequest, ServerHello (cipher selection), ServerKeyExchange
    (PSK identity hint)."""
    out = {"reachable": False, "hello_verify": False,
           "server_cipher": None, "server_cipher_name": "",
           "psk_identity_hint": "", "weak_cipher": False}
    ch = _build_dtls_client_hello()
    sock = _open_udp(timeout)
    try:
        try:
            sock.sendto(ch, (ip, port))
        except OSError:
            return out
        try:
            data, _ = sock.recvfrom(65535)
        except (socket.timeout, OSError):
            return out
        if not data:
            return out
        out["reachable"] = True
        records = list(_iter_dtls_records(data))
        handshakes = _parse_dtls_handshakes(records)
        for hs_type, body in handshakes:
            if hs_type == _DTLS_HS_HELLO_VERIFY:
                out["hello_verify"] = True
            elif hs_type == _DTLS_HS_SERVER_HELLO and len(body) >= 38:
                # version(2) random(32) sess_id_len(1) sess_id(N) cipher(2) ...
                i = 2 + 32
                sid_len = body[i]
                i += 1 + sid_len
                if i + 2 <= len(body):
                    cs = (body[i], body[i + 1])
                    out["server_cipher"] = cs
                    if cs in _WEAK_CIPHERS:
                        out["server_cipher_name"] = _WEAK_CIPHERS[cs]
                        out["weak_cipher"] = True
            elif hs_type == _DTLS_HS_SERVER_KEY_EXCHANGE and len(body) >= 2:
                # PSK ServerKeyExchange (RFC 4279 §2): opaque psk_identity_hint<0..2^16-1>
                hint_len = struct.unpack(">H", body[:2])[0]
                if 2 + hint_len <= len(body):
                    out["psk_identity_hint"] = body[2:2 + hint_len].decode(
                        "utf-8", "replace")
    finally:
        sock.close()
    return out


# --- Capability: OSCORE Option observation --------------------------------

def _has_oscore_option(options: list[tuple[int, bytes]]) -> bool:
    return any(n == _OPT_OSCORE for n, _ in options)


# --- Full probe -----------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          active: bool = True,
          observe_window: float = 2.0,
          proxy_probe_uri: str = "coap://192.0.2.1/recce-relay-probe",
          test_write: bool = False) -> dict:
    """Full CoAP probe. `test_write` gates the PUT/POST permission test; it
    only ever writes with a pre-value captured from an earlier successful GET
    and always rolls back."""
    out: dict = {
        "reachable": False,
        "transport": "coap",
        "empty_ping": {},
        "resources": [],
        "readable": [],
        "writable": [],
        "observe": [],
        "dtls": {},
        "proxy": {},
        "amp_ratio": 0.0,
        "oscore": False,
        "product": "",
        "version_str": "",
        "authgated": False,
        "wellknown_code": "",
        "error": "",
    }

    if port == _DTLS_PORT:
        # 5684 speaks DTLS; running the CoAP probes without a session is
        # pointless. Fingerprint the handshake and return.
        out["transport"] = "coaps"
        out["dtls"] = dtls_fingerprint(ip, port, timeout=timeout)
        out["reachable"] = out["dtls"].get("reachable", False)
        return out

    # Empty-CON ping (cheapest fingerprint).
    ping = empty_ping(ip, port, timeout=timeout)
    out["empty_ping"] = ping
    if ping.get("ok"):
        out["reachable"] = True

    # /.well-known/core dump. Even when the ping missed, the GET can succeed
    # (some stacks ignore empty CONs).
    wk = get_resource(ip, port, "/.well-known/core", timeout=timeout,
                      accept=_CT_LINK, max_blocks=16)
    if wk["reachable"]:
        out["reachable"] = True
        out["wellknown_code"] = wk["code_str"]
        out["oscore"] = out["oscore"] or _has_oscore_option(wk.get("options") or [])
        req_size_est = 24                     # 4 hdr + tok + 2 opts (path)
        if wk["payload"]:
            out["amp_ratio"] = round(len(wk["payload"]) / max(req_size_est, 1), 2)
        if wk["code_str"].startswith("2."):
            body = wk["payload"].decode("utf-8", "replace")
            out["resources"] = parse_link_format(body)
        elif wk["code_str"] in ("4.01", "4.03"):
            out["authgated"] = True

    if not out["reachable"]:
        return out

    if active and out["resources"]:
        out["readable"] = resource_sweep(ip, port, out["resources"],
                                         timeout=timeout)
        # Pull vendor/model out of well-known device resources.
        for entry in out["readable"]:
            if entry["path"] in _DEVICE_RESOURCE_HINTS or any(
                    hint in entry["path"] for hint in _DEVICE_RESOURCE_HINTS):
                out["version_str"] = out["version_str"] or entry["snippet"].decode(
                    "utf-8", "replace")[:200]
        # Detect stack from rt= namespaces.
        for rec in out["resources"]:
            rt = rec.get("rt") or ""
            for prefix, (prod, _desc) in _RT_STACK_HINTS.items():
                if rt.startswith(prefix) and not out["product"]:
                    out["product"] = prod

        # OSCORE observation from any of the reads.
        for entry in out["readable"]:
            if entry.get("code") in ("4.01",) and entry.get("size", 0) > 0:
                # Not a strong signal on its own; kept as an info marker only.
                pass

        # Observe sweep: at most 1 resource marked obs (bounded).
        for rec in out["resources"]:
            if rec.get("obs"):
                obs = observe_resource(ip, port, rec["path"],
                                       window=observe_window, timeout=timeout)
                if obs.get("registered") and obs.get("notifications"):
                    out["observe"].append({"path": rec["path"], **obs})
                if len(out["observe"]) >= 1:
                    break

        # Write permission test: only actuator-ish resources, only when we
        # actually captured a pre-value from the sweep.
        if test_write:
            reads = {e["path"]: e for e in out["readable"]}
            for rec in out["resources"]:
                path = rec.get("path", "")
                rt = (rec.get("rt") or "").lower()
                interf = (rec.get("if") or "").lower()
                looks_writable = (any(h in path.lower() for h in _ACTUATOR_HINTS)
                                  or any(h in rt for h in _ACTUATOR_HINTS)
                                  or any(h in interf for h in _ACTUATOR_HINTS))
                if not looks_writable:
                    continue
                pre = reads.get(path)
                if not pre or not pre.get("snippet"):
                    continue
                wr = write_permission_test(ip, port, path, pre["snippet"],
                                           pre.get("ct"), timeout=timeout)
                if wr.get("attempted"):
                    out["writable"].append({"path": path, **wr})
                if len(out["writable"]) >= 3:
                    break

    if active:
        try:
            out["proxy"] = proxy_relay_test(ip, port, proxy_probe_uri,
                                            timeout=timeout)
        except OSError:
            out["proxy"] = {}

    return out


# --- Targeting / findings / runbook / analyze -----------------------------

def coap_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_coap(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "coap-client", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_coap(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            # DTLS path (5684).
            if p.portid == _DTLS_PORT:
                dtls = pr.get("dtls") or {}
                hint = dtls.get("psk_identity_hint") or ""
                if hint:
                    out.append(_finding(
                        "medium",
                        "CoAP-DTLS ServerKeyExchange leaks PSK identity hint",
                        tgt,
                        f"DTLS 1.2 ClientHello reply carried a PSK identity hint "
                        f"'{hint}'. Vendor default hints frequently name the device "
                        f"serial, MAC, or model — enumerating the device roster "
                        f"before authentication.",
                        f"openssl s_client -dtls1_2 -psk_identity '{hint}' -psk "
                        f"deadbeef -connect {h.ip}:{p.portid}",
                        "Configure the DTLS stack to omit the PSK identity hint "
                        "(RFC 4279 §5.2 permits it) or set it to a value that does "
                        "not disclose device identity.",
                        ["CWE-200"], kind="coap_dtls_psk_hint"))
                if dtls.get("weak_cipher"):
                    out.append(_finding(
                        "high",
                        "CoAP-DTLS server selected a weak / NULL cipher",
                        tgt,
                        f"Server accepted cipher suite {dtls.get('server_cipher_name')} "
                        f"in the DTLS handshake. NULL / export ciphers provide no "
                        f"confidentiality — traffic is effectively plaintext.",
                        f"openssl s_client -dtls1_2 -connect {h.ip}:{p.portid} "
                        "-cipher 'NULL'",
                        "Restrict the CoAP-DTLS cipher list to AES-CCM_8 / GCM per "
                        "RFC 7925 §4.2 — TLS_PSK_WITH_AES_128_CCM_8 is the IoT MTI.",
                        ["CWE-326", "CWE-327"], kind="coap_dtls_weak"))
                out.append(_finding(
                    "info", "CoAP-DTLS endpoint reachable", tgt,
                    f"DTLS 1.2 ClientHello returned "
                    f"{'HelloVerifyRequest' if dtls.get('hello_verify') else 'ServerHello'}. "
                    f"Cipher selected: {dtls.get('server_cipher_name') or '(unknown)'}. "
                    f"PSK identity hint: {hint or '(none)'}.",
                    f"openssl s_client -dtls1_2 -connect {h.ip}:{p.portid}",
                    "Restrict CoAP-DTLS to a trusted management VLAN.",
                    [], kind="coap_dtls_fingerprint"))
                continue

            # Plaintext path (5683).
            resources = pr.get("resources") or []
            if resources:
                sample = ", ".join(r["path"] for r in resources[:8])
                actuators = [r for r in resources
                             if any(h in (r.get("rt") or "").lower()
                                    or h in (r.get("path") or "").lower()
                                    for h in _ACTUATOR_HINTS)]
                sev = "critical" if actuators else "high"
                out.append(_finding(
                    sev,
                    "CoAP endpoint exposes resource inventory via /.well-known/core",
                    tgt,
                    f"Unauthenticated GET /.well-known/core returned "
                    f"{len(resources)} resource(s). Sample paths: {sample}"
                    + (f". Actuator-typed resources: "
                       f"{', '.join(a['path'] for a in actuators[:5])}"
                       if actuators else "")
                    + ". The inventory reveals every sensor, actuator, and config "
                    "endpoint the device serves — the RFC 6690 equivalent of an "
                    "unauthenticated MQTT wildcard subscribe.",
                    f"coap-client -m get coap://{h.ip}:{p.portid}/.well-known/core",
                    "Require authentication on /.well-known/core (OSCORE / DTLS-PSK) "
                    "or restrict the device to a management VLAN. Do not publish "
                    "actuator resources anonymously.",
                    ["CWE-200", "CWE-306"], kind="coap_resource_inventory"))

            # Anonymous write to an actuator (critical).
            for wr in (pr.get("writable") or []):
                if not wr.get("writable"):
                    continue
                rb = "rolled back" if wr.get("rolled_back") else "NOT rolled back"
                out.append(_finding(
                    "critical",
                    "CoAP endpoint accepts anonymous PUT to an actuator resource",
                    tgt,
                    f"PUT to {wr['path']} returned {wr.get('code')} — an "
                    f"unauthenticated client can control the physical actuator. "
                    f"Recce's marker write was {rb}.",
                    f"coap-client -m put -e 'x' coap://{h.ip}:{p.portid}{wr['path']}",
                    "Require authentication (OSCORE / DTLS-PSK) on every writable "
                    "resource; expose actuators only to authorised principals.",
                    ["CWE-284", "CWE-306", "CWE-862"], kind="coap_actuator_exposed"))

            # Device disclosure via /oic/d etc.
            for entry in (pr.get("readable") or []):
                if not any(h in entry["path"] for h in _DEVICE_RESOURCE_HINTS):
                    continue
                if not entry.get("code", "").startswith("2."):
                    continue
                snippet_txt = entry.get("snippet", b"").decode("utf-8", "replace")[:200]
                out.append(_finding(
                    "high",
                    "CoAP endpoint discloses device identity / firmware "
                    "via device resource",
                    tgt,
                    f"GET {entry['path']} returned {entry['code']} "
                    f"({_CT_NAMES.get(entry.get('ct') or -1, 'unknown ct')}, "
                    f"{entry.get('size')} bytes). Snippet: {snippet_txt!r}. "
                    "Device model / firmware version feeds CVE mapping and "
                    "identifies whether the device is end-of-life.",
                    f"coap-client -m get coap://{h.ip}:{p.portid}{entry['path']}",
                    "Restrict device-info resources to authenticated principals; "
                    "do not publish vendor/firmware strings on unauthenticated "
                    "endpoints.",
                    ["CWE-200"], kind="coap_device_disclosure"))

            # Observe telemetry leak.
            for obs in (pr.get("observe") or []):
                notes = obs.get("notifications") or []
                out.append(_finding(
                    "high",
                    "CoAP endpoint leaks live telemetry via Observe (RFC 7641)",
                    tgt,
                    f"Observe registration on {obs['path']} accepted; "
                    f"{len(notes)} notification(s) captured in "
                    "the bounded window without authentication.",
                    f"coap-client -m get -s 5 coap://{h.ip}:{p.portid}{obs['path']}",
                    "Require authentication on observable resources; enforce ACLs "
                    "so unauthenticated clients cannot subscribe.",
                    ["CWE-200", "CWE-306"], kind="coap_observe_leak"))

            # Proxy relay abuse.
            pxy = pr.get("proxy") or {}
            if pxy.get("proxied"):
                out.append(_finding(
                    "high",
                    "CoAP endpoint acts as an open proxy (Proxy-Uri accepted)",
                    tgt,
                    f"GET with Proxy-Uri returned {pxy.get('code')} — the endpoint "
                    "attempted to forward the request. An attacker can pivot to "
                    "internal HTTP / CoAP services otherwise unreachable (SSRF-class).",
                    f"coap-client -m get -P coap://{h.ip}:{p.portid} "
                    "coap://internal.target/path",
                    "Disable proxy forwarding on the CoAP stack, or restrict the "
                    "allowed proxy targets with an explicit allowlist.",
                    ["CWE-918", "CWE-441"], kind="coap_open_proxy"))

            # UDP amplifier.
            ratio = pr.get("amp_ratio") or 0.0
            if ratio > 5.0:
                out.append(_finding(
                    "medium",
                    "CoAP endpoint is a viable UDP amplifier",
                    tgt,
                    f"GET /.well-known/core produced a response/request byte ratio "
                    f"of {ratio:.1f}x. CoAP is on the US-CERT TA14-017A list of "
                    "UDP amplification protocols; an attacker who can spoof source "
                    "IPs on the same network can weaponise this endpoint.",
                    f"coap-client -m get coap://{h.ip}:{p.portid}/.well-known/core",
                    "Do not expose CoAP endpoints on the public internet. Rate-limit "
                    "unauthenticated requests per source; require DTLS to establish "
                    "an authenticated session before large responses.",
                    ["CWE-406"], kind="coap_amplifier"))

            # Authorization enforced (info).
            if pr.get("authgated"):
                out.append(_finding(
                    "info",
                    "CoAP endpoint reachable, authorization enforced",
                    tgt,
                    "The endpoint replied to /.well-known/core with 4.01/4.03 — "
                    "target for harvested OSCORE / DTLS-PSK material.",
                    f"coap-client -m get coap://{h.ip}:{p.portid}/.well-known/core",
                    "Keep the authorization check in place; ensure the credential "
                    "store is not itself exposed anonymously (retained MQTT, etc.).",
                    [], kind="coap_authgated"))

            # OSCORE observed.
            if pr.get("oscore"):
                out.append(_finding(
                    "info", "CoAP endpoint uses OSCORE (RFC 8613)", tgt,
                    "OSCORE Option observed in a response — payloads are "
                    "application-layer encrypted. DTLS-PSK results tell nothing "
                    "about OSCORE-protected content.",
                    f"coap-client coap://{h.ip}:{p.portid}/.well-known/core",
                    "Keep OSCORE enabled; document the OSCORE master secret "
                    "distribution.",
                    [], kind="coap_oscore"))

            # Plaintext 5683 without DTLS.
            if p.portid == _DEFAULT_PORT:
                out.append(_finding(
                    "medium", "CoAP endpoint on 5683/udp (plaintext, no DTLS)", tgt,
                    "IoT control traffic exposed on the plaintext IANA port. Any "
                    "credential material / device state traverses the network in "
                    "the clear.",
                    f"coap-client coap://{h.ip}:{p.portid}/.well-known/core",
                    "Move the endpoint to 5684/udp with DTLS-PSK (RFC 7925 §4.2) "
                    "or wrap application payloads with OSCORE (RFC 8613).",
                    ["CWE-319"], kind="coap_plaintext"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    if port == _DTLS_PORT:
        return [
            {"phase": "enumerate", "tool": "openssl s_client",
             "command": f"openssl s_client -dtls1_2 -connect {ip}:{port}",
             "why": "capture ServerHello + PSK identity hint"},
            {"phase": "enumerate", "tool": "coap-client",
             "command": (f"coap-client -m get -u <psk-id> -k <psk> "
                         f"coaps://{ip}:{port}/.well-known/core"),
             "why": "credentialed resource inventory (once PSK known)"},
        ]
    return [
        {"phase": "enumerate", "tool": "coap-client",
         "command": f"coap-client -m get coap://{ip}:{port}/.well-known/core",
         "why": "RFC 6690 resource inventory (sensors, actuators, config)"},
        {"phase": "enumerate", "tool": "aiocoap-client",
         "command": f"aiocoap-client coap://{ip}:{port}/oic/d",
         "why": "OCF device info (vendor, model, firmware) if present"},
        {"phase": "enumerate", "tool": "coap-client",
         "command": f"coap-client -s 5 coap://{ip}:{port}/<obs-resource>",
         "why": "Observe (RFC 7641) - live telemetry stream"},
        {"phase": "exploit", "tool": "coap-client",
         "command": f"coap-client -m put -e '<value>' coap://{ip}:{port}/<actuator>",
         "why": "anonymous actuator write test - physical-world impact"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "coap", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            test_write: bool = False) -> dict:
    """Analyze CoAP targets. `test_write` gates the actuator PUT test —
    default False (destructive-adjacent, only opt-in even when active=True)."""
    from . import svcprobe
    targets = coap_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], active=True,
                                test_write=test_write),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["resources"] = len(pr.get("resources") or [])
                t["writable"] = len(pr.get("writable") or [])
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
