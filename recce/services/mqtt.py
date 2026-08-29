"""MQTT (1883/tcp, 8883/tcp) broker probe.

MQTT is a lightweight publish/subscribe protocol widely deployed on IoT/OT
gear. An open broker leaks the entire topic namespace, retained messages
(device state, tokens, config), Last-Will payloads, and the ClientID roster.

Findings covered:
  * mqtt_anonymous_connect   (high)      — CONNACK 0x00 with no credentials
  * mqtt_empty_clientid      (high)      — broker accepts an empty ClientID
  * mqtt_retained_messages   (critical)  — # wildcard subscribe replays secrets
  * mqtt_live_topics         (high)      — # wildcard subscribe leaks live traffic
  * mqtt_sys_topics          (high)      — $SYS/# leaks broker version / metrics
  * mqtt_anonymous_publish   (critical)  — anonymous PUBLISH accepted (write bus)
  * mqtt_weak_credential     (critical)  — a weak/default credential authenticates
  * mqtt_will_message        (medium)    — a captured LWT identifies a device/secret
  * mqtt_authgated           (info)      — reachable but CONNACK 0x04/0x05
  * mqtt_plaintext           (medium)    — 1883 (no TLS) exposes creds on the wire

Airgap-safe: stdlib socket + struct only. Every socket op has a bounded
timeout scaled through core.proxy.
"""
from __future__ import annotations

import os
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 1883
_TLS_PORT = 8883
_TIMEOUT = 4.0

# MQTT control packet types (spec §2.2.1)
_CONNECT = 1
_CONNACK = 2
_PUBLISH = 3
_PUBACK = 4
_SUBSCRIBE = 8
_SUBACK = 9
_DISCONNECT = 14

# v3.1.1 CONNACK reason codes (§3.2.2.3)
_CONNACK_ACCEPTED = 0x00
_CONNACK_UNACCEPTABLE_PROTO = 0x01
_CONNACK_IDENT_REJECTED = 0x02
_CONNACK_SERVER_UNAVAILABLE = 0x03
_CONNACK_BAD_USER_PASS = 0x04
_CONNACK_NOT_AUTHORISED = 0x05

# Weak/default credential pairs. Kept small — MQTT rarely rate-limits, but
# 40+ round trips per broker in a /24 sweep is enough. Order matters: broker-
# specific defaults first, then vendor-neutral.
_WEAK_PASSWORDS = ("", "mqtt", "admin", "password", "changeme", "1883")


def is_mqtt(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (1883, 8883, 1884)
            or "mqtt" in svc or "mqtt" in prod
            or svc == "secure-mqtt")


# --- Wire encoding / decoding ---------------------------------------------

def _encode_remlen(n: int) -> bytes:
    """MQTT variable byte integer (§2.2.3): 7 bits/byte, MSB = continuation.
    Range 0..268_435_455."""
    if n < 0 or n > 268_435_455:
        raise ValueError("remaining length out of range")
    out = bytearray()
    while True:
        digit = n & 0x7F
        n >>= 7
        if n:
            out.append(digit | 0x80)
        else:
            out.append(digit)
            break
    return bytes(out)


def _decode_remlen(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return (value, bytes_consumed). Raises ValueError on malformed input."""
    multiplier = 1
    value = 0
    consumed = 0
    while True:
        if offset + consumed >= len(data):
            raise ValueError("remlen truncated")
        b = data[offset + consumed]
        consumed += 1
        value += (b & 0x7F) * multiplier
        if not (b & 0x80):
            return value, consumed
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            raise ValueError("remlen too large")


def _utf8(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _parse_utf8_at(data: bytes, i: int) -> tuple[str, int]:
    if i + 2 > len(data):
        raise ValueError("utf8 length truncated")
    n = struct.unpack(">H", data[i:i + 2])[0]
    if i + 2 + n > len(data):
        raise ValueError("utf8 body truncated")
    return data[i + 2:i + 2 + n].decode("utf-8", "replace"), i + 2 + n


def _build_connect(client_id: str = "", username: str | None = None,
                   password: str | None = None, protocol_level: int = 0x04,
                   clean_session: bool = True, keepalive: int = 30,
                   will_topic: str | None = None,
                   will_payload: bytes | None = None) -> bytes:
    """Build a CONNECT (§3.1). protocol_level 0x04 = MQTT 3.1.1, 0x05 = MQTT 5."""
    flags = 0
    if clean_session:
        flags |= 0x02
    if will_topic is not None:
        flags |= 0x04
    if username is not None:
        flags |= 0x80
    if password is not None:
        flags |= 0x40

    var_header = _utf8("MQTT") + bytes([protocol_level, flags]) + struct.pack(">H", keepalive)
    if protocol_level == 0x05:
        # v5 requires a Properties field (varint length + properties). Empty is fine.
        var_header += _encode_remlen(0)

    payload = _utf8(client_id)
    if will_topic is not None:
        if protocol_level == 0x05:
            payload += _encode_remlen(0)                # will properties: none
        payload += _utf8(will_topic)
        wp = will_payload or b""
        payload += struct.pack(">H", len(wp)) + wp
    if username is not None:
        payload += _utf8(username)
    if password is not None:
        pw = password.encode("utf-8")
        payload += struct.pack(">H", len(pw)) + pw

    body = var_header + payload
    return bytes([_CONNECT << 4]) + _encode_remlen(len(body)) + body


def _build_subscribe(packet_id: int, topics: list[tuple[str, int]],
                     protocol_level: int = 0x04) -> bytes:
    """SUBSCRIBE (§3.8). topics = [(filter, qos)]. Reserved flags nibble = 0x2."""
    var_header = struct.pack(">H", packet_id)
    if protocol_level == 0x05:
        var_header += _encode_remlen(0)                 # empty properties
    payload = b""
    for filt, qos in topics:
        payload += _utf8(filt) + bytes([qos & 0x03])
    body = var_header + payload
    return bytes([(_SUBSCRIBE << 4) | 0x02]) + _encode_remlen(len(body)) + body


def _build_publish(topic: str, payload: bytes, qos: int = 0,
                   retain: bool = False, packet_id: int | None = None,
                   protocol_level: int = 0x04) -> bytes:
    """PUBLISH (§3.3)."""
    flags = 0
    if retain:
        flags |= 0x01
    flags |= (qos & 0x03) << 1
    var_header = _utf8(topic)
    if qos > 0:
        if packet_id is None:
            raise ValueError("QoS>0 requires packet_id")
        var_header += struct.pack(">H", packet_id)
    if protocol_level == 0x05:
        var_header += _encode_remlen(0)                 # empty properties
    body = var_header + payload
    return bytes([(_PUBLISH << 4) | flags]) + _encode_remlen(len(body)) + body


def _build_disconnect(protocol_level: int = 0x04) -> bytes:
    if protocol_level == 0x05:
        # v5 DISCONNECT can carry a reason code + properties; 0-length body is fine.
        return bytes([_DISCONNECT << 4, 0])
    return bytes([_DISCONNECT << 4, 0])


# --- Packet reader --------------------------------------------------------

def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return buf
        if not chunk:
            return buf
        buf += chunk
    return buf


def _read_packet(sock: socket.socket, timeout: float) -> tuple[int, int, bytes] | None:
    """Read one MQTT packet. Returns (type_flags_byte, remaining_length, body)
    or None on EOF / timeout / truncation."""
    try:
        sock.settimeout(timeout)
        first = _recvn(sock, 1)
        if len(first) != 1:
            return None
        # Read the variable-byte remaining length.
        rem_bytes = bytearray()
        while True:
            b = _recvn(sock, 1)
            if len(b) != 1:
                return None
            rem_bytes.append(b[0])
            if not (b[0] & 0x80):
                break
            if len(rem_bytes) > 4:
                return None
        rem_len, _ = _decode_remlen(bytes(rem_bytes))
        if rem_len < 0 or rem_len > 10_000_000:
            return None
        body = _recvn(sock, rem_len) if rem_len else b""
        if len(body) != rem_len:
            return None
        return first[0], rem_len, body
    except (OSError, ValueError):
        return None


# --- CONNACK parsing ------------------------------------------------------

def _parse_connack(body: bytes, protocol_level: int) -> dict | None:
    """CONNACK (§3.2). Returns {session_present, reason, properties}."""
    if len(body) < 2:
        return None
    session_present = bool(body[0] & 0x01)
    reason = body[1]
    properties: dict = {}
    if protocol_level == 0x05 and len(body) > 2:
        try:
            prop_len, consumed = _decode_remlen(body, 2)
            p_start = 2 + consumed
            p_end = p_start + prop_len
            if p_end <= len(body):
                properties = _parse_v5_properties(body[p_start:p_end])
        except ValueError:
            pass
    return {"session_present": session_present, "reason": reason,
            "properties": properties}


# v5 CONNACK properties we care about (§3.2.2.3)
_V5_PROP_SESSION_EXPIRY_INTERVAL = 0x11
_V5_PROP_ASSIGNED_CLIENT_ID = 0x12
_V5_PROP_SERVER_KEEP_ALIVE = 0x13
_V5_PROP_AUTH_METHOD = 0x15
_V5_PROP_RESPONSE_INFO = 0x1A
_V5_PROP_SERVER_REFERENCE = 0x1C
_V5_PROP_REASON_STRING = 0x1F
_V5_PROP_RECEIVE_MAXIMUM = 0x21
_V5_PROP_TOPIC_ALIAS_MAX = 0x22
_V5_PROP_MAXIMUM_QOS = 0x24
_V5_PROP_RETAIN_AVAILABLE = 0x25
_V5_PROP_MAX_PACKET_SIZE = 0x27
_V5_PROP_WILDCARD_SUB_AVAILABLE = 0x28
_V5_PROP_SUBSCRIPTION_ID_AVAILABLE = 0x29
_V5_PROP_SHARED_SUB_AVAILABLE = 0x2A


def _parse_v5_properties(data: bytes) -> dict:
    """Best-effort parse of the v5 property section. Unknown properties abort
    the parse and return what we have."""
    out: dict = {}
    i = 0
    while i < len(data):
        pid = data[i]
        i += 1
        try:
            if pid in (_V5_PROP_MAXIMUM_QOS, _V5_PROP_RETAIN_AVAILABLE,
                       _V5_PROP_WILDCARD_SUB_AVAILABLE,
                       _V5_PROP_SUBSCRIPTION_ID_AVAILABLE,
                       _V5_PROP_SHARED_SUB_AVAILABLE):
                out[pid] = data[i]; i += 1
            elif pid in (_V5_PROP_SERVER_KEEP_ALIVE, _V5_PROP_TOPIC_ALIAS_MAX,
                         _V5_PROP_RECEIVE_MAXIMUM):
                out[pid] = struct.unpack(">H", data[i:i + 2])[0]; i += 2
            elif pid in (_V5_PROP_SESSION_EXPIRY_INTERVAL,
                         _V5_PROP_MAX_PACKET_SIZE):
                out[pid] = struct.unpack(">I", data[i:i + 4])[0]; i += 4
            elif pid in (_V5_PROP_ASSIGNED_CLIENT_ID, _V5_PROP_AUTH_METHOD,
                         _V5_PROP_RESPONSE_INFO, _V5_PROP_SERVER_REFERENCE,
                         _V5_PROP_REASON_STRING):
                val, i = _parse_utf8_at(data, i)
                out[pid] = val
            else:
                return out
        except (IndexError, struct.error, ValueError):
            return out
    return out


# --- PUBLISH parsing ------------------------------------------------------

def _parse_publish(flags: int, body: bytes, protocol_level: int) -> dict | None:
    """Extract topic + payload from a PUBLISH packet body."""
    qos = (flags >> 1) & 0x03
    retain = bool(flags & 0x01)
    try:
        topic, i = _parse_utf8_at(body, 0)
        if qos > 0:
            if i + 2 > len(body):
                return None
            i += 2                                       # packet id (unused here)
        if protocol_level == 0x05 and i < len(body):
            prop_len, consumed = _decode_remlen(body, i)
            i += consumed + prop_len
            if i > len(body):
                return None
        payload = body[i:]
        return {"topic": topic, "payload": payload,
                "retain": retain, "qos": qos}
    except (ValueError, struct.error):
        return None


# --- CONNECT handshake ----------------------------------------------------

def _connect_and_read(ip: str, port: int, connect_pkt: bytes,
                      protocol_level: int, timeout: float) -> tuple[socket.socket | None, dict | None, str]:
    """Open a TCP socket, send CONNECT, read CONNACK. Returns
    (socket, parsed connack, error). Socket is left open on success — caller
    must close it. Socket is None on transport / handshake failure."""
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        return None, None, f"connect: {e}"
    try:
        sock.settimeout(proxy.scaled(timeout))
        sock.sendall(connect_pkt)
        pkt = _read_packet(sock, proxy.scaled(timeout))
    except OSError as e:
        try: sock.close()
        except OSError: pass
        return None, None, f"send/recv: {e}"
    if not pkt:
        try: sock.close()
        except OSError: pass
        return None, None, "no CONNACK"
    tfb, _rlen, body = pkt
    if (tfb >> 4) != _CONNACK:
        try: sock.close()
        except OSError: pass
        return None, None, f"unexpected packet type {tfb >> 4}"
    ack = _parse_connack(body, protocol_level)
    if ack is None:
        try: sock.close()
        except OSError: pass
        return None, None, "malformed CONNACK"
    return sock, ack, ""


def _random_client_id() -> str:
    return "recce-" + os.urandom(3).hex()


# --- SUBSCRIBE window (retained + live capture) ---------------------------

def _subscribe_and_drain(sock: socket.socket, topic_filter: str,
                         protocol_level: int, timeout: float,
                         max_topics: int = 200, max_bytes_per_topic: int = 256,
                         packet_id: int = 1) -> dict:
    """SUBSCRIBE to one filter, drain PUBLISH packets until quiet for `timeout`
    seconds or caps hit. Returns {suback_reasons, retained, live, aborted}.

    Retained messages are those with RETAIN=1 (broker replays on subscribe).
    Live traffic is RETAIN=0 packets arriving in the window (LWTs fire here)."""
    out: dict = {"suback_reasons": [], "retained": [], "live": [],
                 "aborted": False}
    try:
        sock.sendall(_build_subscribe(packet_id, [(topic_filter, 0)],
                                      protocol_level=protocol_level))
    except OSError as e:
        out["aborted"] = True
        out["error"] = f"subscribe send: {e}"
        return out

    seen_topics = 0
    scaled = proxy.scaled(timeout)
    while seen_topics < max_topics:
        pkt = _read_packet(sock, scaled)
        if not pkt:
            break
        tfb, _rlen, body = pkt
        ptype = tfb >> 4
        if ptype == _SUBACK:
            # SUBACK payload = packet_id(2) + [reason codes] (v5 has properties)
            if len(body) >= 2:
                i = 2
                if protocol_level == 0x05:
                    try:
                        plen, consumed = _decode_remlen(body, i)
                        i += consumed + plen
                    except ValueError:
                        pass
                out["suback_reasons"] = list(body[i:])
            continue
        if ptype == _PUBLISH:
            parsed = _parse_publish(tfb & 0x0F, body, protocol_level)
            if not parsed:
                continue
            payload = parsed["payload"]
            snippet = payload[:max_bytes_per_topic]
            entry = {"topic": parsed["topic"], "size": len(payload),
                     "snippet": snippet, "qos": parsed["qos"]}
            if parsed["retain"]:
                out["retained"].append(entry)
            else:
                out["live"].append(entry)
            seen_topics += 1
    if seen_topics >= max_topics:
        out["aborted"] = True
    return out


# --- High-level operations ------------------------------------------------

def _anonymous_connect(ip: str, port: int, timeout: float,
                       protocol_level: int = 0x04,
                       client_id: str | None = None) -> dict:
    """Send an anonymous CONNECT, return {sock, connack, error}.
    Caller closes sock (may be None)."""
    cid = _random_client_id() if client_id is None else client_id
    pkt = _build_connect(client_id=cid, protocol_level=protocol_level)
    sock, ack, err = _connect_and_read(ip, port, pkt, protocol_level, timeout)
    return {"sock": sock, "connack": ack, "error": err, "client_id": cid}


def _cred_connect(ip: str, port: int, user: str, password: str,
                  timeout: float, protocol_level: int = 0x04) -> dict:
    """CONNECT with credentials. Closes the socket immediately after CONNACK."""
    pkt = _build_connect(client_id=_random_client_id(),
                         username=user, password=password,
                         protocol_level=protocol_level)
    sock, ack, err = _connect_and_read(ip, port, pkt, protocol_level, timeout)
    if sock is not None:
        try:
            sock.sendall(_build_disconnect(protocol_level))
        except OSError:
            pass
        try: sock.close()
        except OSError: pass
    return {"connack": ack, "error": err}


def _empty_clientid_check(ip: str, port: int, timeout: float,
                          protocol_level: int = 0x04) -> dict:
    """CONNECT with an empty ClientID + CleanSession=1. Broker MUST accept per
    §3.1.3.1 when CleanSession=1, but should reject when the deployment forbids
    it. Return {reason, accepted}."""
    pkt = _build_connect(client_id="", protocol_level=protocol_level,
                         clean_session=True)
    sock, ack, err = _connect_and_read(ip, port, pkt, protocol_level, timeout)
    if sock is not None:
        try: sock.close()
        except OSError: pass
    if ack is None:
        return {"accepted": False, "reason": None, "error": err}
    return {"accepted": ack["reason"] == _CONNACK_ACCEPTED,
            "reason": ack["reason"], "error": err}


def _publish_permission_test(sock: socket.socket, protocol_level: int,
                             timeout: float) -> dict:
    """PUBLISH a benign marker at QoS 1, wait for PUBACK, then clear the
    canary with a zero-byte retained PUBLISH. Return {write_accepted, error}."""
    canary_id = os.urandom(8).hex()
    topic = f"recce/probe/{canary_id}"
    payload = f"recce-probe-{canary_id}".encode("utf-8")
    try:
        sock.sendall(_build_publish(topic, payload, qos=1, packet_id=2,
                                    protocol_level=protocol_level))
    except OSError as e:
        return {"write_accepted": False, "error": f"publish send: {e}"}
    pkt = _read_packet(sock, proxy.scaled(timeout))
    if not pkt:
        return {"write_accepted": False, "error": "no PUBACK"}
    tfb, _rlen, body = pkt
    if (tfb >> 4) != _PUBACK or len(body) < 2:
        return {"write_accepted": False,
                "error": f"unexpected reply type={tfb >> 4}"}
    puback_id = struct.unpack(">H", body[:2])[0]
    if puback_id != 2:
        return {"write_accepted": False, "error": "packet id mismatch"}
    # v5 PUBACK reason code: 0x00 = success, >=0x80 = failure
    if protocol_level == 0x05 and len(body) >= 3 and body[2] >= 0x80:
        return {"write_accepted": False,
                "error": f"puback reason {body[2]:#04x}"}
    # Cleanup: publish empty retained message to clear the canary.
    try:
        sock.sendall(_build_publish(topic, b"", qos=0, retain=True,
                                    protocol_level=protocol_level))
    except OSError:
        pass
    return {"write_accepted": True, "topic": topic, "error": ""}


# --- Full probe -----------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          active: bool = True, subscribe_window: float = 2.0,
          users: list[str] | None = None,
          passwords: list[str] | None = None,
          max_creds: int = 40,
          test_write: bool = True) -> dict:
    """Full MQTT probe. Returns a dict with the fields consumed by findings().

    Passive path (active=False): just a v3.1.1 CONNECT nudge to fingerprint the
    broker (reason code + version property when v5 answers).
    Active path: wildcard subscribe, $SYS scrape, credential spray, publish test.
    """
    out: dict = {
        "reachable": False,
        "version": "",                          # broker product/version
        "protocol_level": 0,                    # 4 or 5 = highest speaker
        "anon_ok": False,
        "empty_clientid_ok": False,
        "publish_ok": False,
        "sys": {},                              # $SYS/# scrape
        "retained": [],
        "live": [],
        "reason": None,
        "v5_properties": {},
        "cred": None,                           # {user, password} on hit
        "error": "",
        "server_version_str": "",               # extracted from $SYS/broker/version or property
    }

    # Version probe: try v5 first, fall back to v3.1.1.
    ack_v5 = None
    conn_v5 = _anonymous_connect(ip, port, timeout, protocol_level=0x05)
    if conn_v5["connack"] is not None:
        out["reachable"] = True
        ack_v5 = conn_v5["connack"]
        out["protocol_level"] = 5
        out["v5_properties"] = ack_v5.get("properties") or {}
        out["reason"] = ack_v5["reason"]
        if _V5_PROP_REASON_STRING in out["v5_properties"]:
            out["server_version_str"] = out["v5_properties"][_V5_PROP_REASON_STRING]
    # Always close the v5 test socket — the main working session is v3.1.1
    # (broadest support) unless the broker refused it later.
    if conn_v5["sock"] is not None:
        try: conn_v5["sock"].close()
        except OSError: pass

    # Now the actual working handshake in v3.1.1.
    conn = _anonymous_connect(ip, port, timeout, protocol_level=0x04)
    if conn["connack"] is None:
        if not out["reachable"]:
            out["error"] = conn["error"]
            return out
        # v5 answered but v3.1.1 did not — record error and use v5 for follow-up.
        out["error"] = conn["error"] or "v3.1.1 CONNECT refused"
        # For the active window we would need a session — bail and just report
        # what we have from v5.
        return out

    out["reachable"] = True
    ack = conn["connack"]
    if out["protocol_level"] == 0:
        out["protocol_level"] = 4
    out["reason"] = ack["reason"] if out["reason"] is None else out["reason"]
    out["anon_ok"] = ack["reason"] == _CONNACK_ACCEPTED
    sock = conn["sock"]

    try:
        if out["anon_ok"] and active:
            # Empty ClientID check — needs a fresh connection.
            try:
                emp = _empty_clientid_check(ip, port, timeout, protocol_level=0x04)
                out["empty_clientid_ok"] = emp["accepted"]
            except OSError:
                pass

            # $SYS scrape first (many brokers filter $SYS out of '#').
            sys_scrape = _subscribe_and_drain(sock, "$SYS/#", 0x04,
                                              timeout=subscribe_window,
                                              max_topics=60, packet_id=10)
            sys_map: dict[str, str] = {}
            for entry in sys_scrape["retained"] + sys_scrape["live"]:
                try:
                    sys_map[entry["topic"]] = entry["snippet"].decode("utf-8", "replace")
                except Exception:
                    sys_map[entry["topic"]] = entry["snippet"].hex()
            out["sys"] = sys_map
            v = sys_map.get("$SYS/broker/version")
            if v:
                out["server_version_str"] = v

            # Wildcard '#' capture — retained + live traffic.
            wild = _subscribe_and_drain(sock, "#", 0x04,
                                        timeout=subscribe_window,
                                        max_topics=200, packet_id=11)
            out["retained"] = wild["retained"]
            out["live"] = wild["live"]

            # Anonymous PUBLISH permission test — only when SUBACK on '#'
            # wasn't a blanket reject (0x80). If subscription failed, write
            # is very likely also gated so skip.
            sub_ok = bool(wild["suback_reasons"] and
                          all(r < 0x80 for r in wild["suback_reasons"]))
            if test_write and sub_ok:
                pub = _publish_permission_test(sock, 0x04, timeout)
                out["publish_ok"] = pub["write_accepted"]

        # Credential spray — only if anonymous was refused (auth-gated broker).
        if active and not out["anon_ok"] and users:
            pws = list(passwords) if passwords else list(_WEAK_PASSWORDS)
            attempts = 0
            for u in users:
                for pw in pws:
                    if attempts >= max_creds:
                        break
                    attempts += 1
                    r = _cred_connect(ip, port, u, pw, timeout,
                                      protocol_level=0x04)
                    ack2 = r["connack"]
                    if ack2 and ack2["reason"] == _CONNACK_ACCEPTED:
                        out["cred"] = {"user": u, "password": pw}
                        break
                if out["cred"]:
                    break
    finally:
        try:
            sock.sendall(_build_disconnect(0x04))
        except OSError:
            pass
        try: sock.close()
        except OSError: pass

    # Version pinning — prefer $SYS/broker/version, fall back to reason string.
    if out["server_version_str"]:
        out["version"] = _pin_product(out["server_version_str"])

    return out


_KNOWN_VENDOR_KEYWORDS = ("mosquitto", "emqx", "hivemq", "vernemq",
                          "rabbitmq", "aedes", "flashmq", "nanomq")


def _pin_product(text: str) -> str:
    """Turn a version string like 'mosquitto version 2.0.15' into 'mosquitto 2.0.15'."""
    if not text:
        return ""
    low = text.lower()
    for vendor in _KNOWN_VENDOR_KEYWORDS:
        if vendor in low:
            # find first digits-with-dots after the vendor
            i = low.find(vendor) + len(vendor)
            tail = text[i:]
            ver = ""
            digits: list[str] = []
            for ch in tail:
                if ch.isdigit() or ch == ".":
                    digits.append(ch)
                elif digits:
                    break
            ver = "".join(digits).strip(".")
            return f"{vendor} {ver}".strip()
    return text.strip()


# --- Public helpers -------------------------------------------------------

def mqtt_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_mqtt(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "mosquitto_sub", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


_REASON_TXT = {
    0x00: "accepted",
    0x01: "unacceptable protocol version",
    0x02: "identifier rejected",
    0x03: "server unavailable",
    0x04: "bad user name or password",
    0x05: "not authorised",
}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_mqtt(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            # 1. Anonymous CONNECT accepted (headline high).
            if pr.get("anon_ok"):
                proto = "v5" if pr.get("protocol_level") == 5 else "v3.1.1"
                out.append(_finding(
                    "high",
                    "MQTT broker accepts anonymous CONNECT",
                    tgt,
                    f"An MQTT {proto} CONNECT with no username/password returned "
                    "CONNACK 0x00 (accepted). The broker is a public bus — any "
                    "client on the network can subscribe to retained messages, "
                    "WILL payloads, and live telemetry. Enumerate topics with: "
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -t '#' -v -W 3",
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -t '#' -v -W 3",
                    "Require authentication on the listener; disable anonymous "
                    "access (mosquitto: 'allow_anonymous false'; EMQX: "
                    "'listeners.tcp.default.enable_authn = true'). Bind to a "
                    "private interface.",
                    ["CWE-306", "CWE-284"], kind="mqtt_anonymous_connect"))

            # 2. Empty ClientID accepted (§3.1.3.1 says allowed only when
            # CleanSession=1; many brokers accept it unconditionally, and
            # concurrent empty-ClientID sessions get stolen from each other).
            if pr.get("empty_clientid_ok"):
                out.append(_finding(
                    "high",
                    "MQTT broker accepts empty ClientID",
                    tgt,
                    "CONNECT with a zero-length ClientID returned CONNACK 0x00. "
                    "Concurrent clients sending an empty ClientID have their "
                    "sessions collide — one client's session steals another's, "
                    "and the broker cannot distinguish them for auditing.",
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -i '' -t '#' -v -W 2",
                    "Configure the broker to require a non-empty ClientID "
                    "(mosquitto: 'per_listener_settings true' + reject empty).",
                    ["CWE-287", "CWE-778"], kind="mqtt_empty_clientid"))

            # 3. Wildcard '#' subscribe: retained (critical) or live (high).
            retained = pr.get("retained") or []
            if retained:
                topic_sample = ", ".join(sorted({r["topic"] for r in retained})[:10])
                total_bytes = sum(r.get("size", 0) for r in retained)
                out.append(_finding(
                    "critical",
                    "MQTT broker leaks retained messages on wildcard subscribe (#)",
                    tgt,
                    f"SUBSCRIBE '#' returned {len(retained)} retained message(s) "
                    f"totalling {total_bytes} byte(s). Retained payloads routinely "
                    f"contain device configuration, cleartext credentials, JWTs, "
                    f"and API tokens ('config bus' anti-pattern). Sample topics: "
                    f"{topic_sample}. Capture full payloads with: "
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -t '#' -v -W 5",
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -t '#' -v -W 5",
                    "Enforce topic ACLs so anonymous / low-privilege principals "
                    "cannot subscribe to '#'; publish secrets on their own topic "
                    "with a per-topic ACL; never store secrets as retained "
                    "messages.",
                    ["CWE-200", "CWE-522", "CWE-284"], kind="mqtt_retained_messages"))

            live = pr.get("live") or []
            # Live '#' traffic minus $SYS is separately valuable (LWTs land here).
            live_non_sys = [l for l in live if not l["topic"].startswith("$SYS/")]
            if live_non_sys and not retained:
                topics = ", ".join(sorted({l["topic"] for l in live_non_sys})[:10])
                out.append(_finding(
                    "high",
                    "MQTT broker leaks live traffic on wildcard subscribe (#)",
                    tgt,
                    f"SUBSCRIBE '#' captured {len(live_non_sys)} live PUBLISH "
                    f"packet(s) — device telemetry, commands, or LWTs. Sample "
                    f"topics: {topics}.",
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -t '#' -v",
                    "Enforce topic ACLs on the '#' wildcard; segregate device "
                    "telemetry from operator commands with per-topic auth.",
                    ["CWE-200", "CWE-284"], kind="mqtt_live_topics"))

            # 3b. Will messages captured in the live stream. These are worth
            # calling out even when the wildcard finding fired because they
            # identify device identity + often carry a token.
            wills = [l for l in live_non_sys
                     if b"will" in l["snippet"].lower()
                     or b"lwt" in l["snippet"].lower()
                     or l["topic"].endswith("/status")
                     or l["topic"].endswith("/online")]
            if wills:
                names = ", ".join(sorted({w["topic"] for w in wills})[:8])
                out.append(_finding(
                    "medium",
                    "MQTT Will/Status messages disclose device identity",
                    tgt,
                    f"{len(wills)} device status/LWT topic(s) observed: {names}. "
                    "Will payloads regularly embed device tokens and internal "
                    "hostnames — cross-service loot for the device roster.",
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -t '+/status' -v",
                    "Configure devices to publish status via a per-device ACL "
                    "and strip credentials from the Will payload.",
                    ["CWE-200"], kind="mqtt_will_message"))

            # 4. $SYS/# scrape.
            sys = pr.get("sys") or {}
            if sys:
                keys = ", ".join(sorted(sys.keys())[:10])
                version = sys.get("$SYS/broker/version") or ""
                clients = sys.get("$SYS/broker/clients/connected") or \
                    sys.get("$SYS/broker/clients/total") or ""
                out.append(_finding(
                    "high",
                    "MQTT broker exposes $SYS metrics (version, clients, uptime)",
                    tgt,
                    f"$SYS/# subscribe returned {len(sys)} topic(s): {keys}. "
                    f"Broker version: {version or '(unknown)'}. Connected "
                    f"clients: {clients or '(unknown)'}. $SYS discloses vendor + "
                    "version (feeds CVE mapping) and often the live client roster.",
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -t '\\$SYS/#' -v -W 3",
                    "Restrict $SYS to a dedicated admin principal; deny "
                    "anonymous subscribe on $SYS.",
                    ["CWE-200"], kind="mqtt_sys_topics"))

            # 5. Anonymous PUBLISH accepted (critical — attacker can inject
            # commands to subscribing devices).
            if pr.get("publish_ok"):
                out.append(_finding(
                    "critical",
                    "MQTT broker accepts anonymous PUBLISH (public write bus)",
                    tgt,
                    "A QoS 1 PUBLISH from an anonymous client was ACKed by the "
                    "broker. Any subscribing device (home automation, industrial "
                    "controls, telemetry) will accept commands from the network. "
                    "The probe published to 'recce/probe/<uuid>' and cleared the "
                    "canary with a zero-byte retained publish.",
                    f"mosquitto_pub -h {h.ip} -p {p.portid} -t 'test/rw' -m x",
                    "Set write ACLs on every topic; disable anonymous publish; "
                    "prefer per-device credentials.",
                    ["CWE-306", "CWE-284", "CWE-77"], kind="mqtt_anonymous_publish"))

            # 6. Credential spray hit.
            cred = pr.get("cred")
            if cred:
                pw_repr = cred["password"] or "<empty>"
                out.append(_finding(
                    "critical",
                    "MQTT credential accepted via low-effort spray",
                    tgt,
                    f"CONNECT with username '{cred['user']}' and password "
                    f"'{pw_repr}' returned CONNACK 0x00. The credential is a "
                    "documented default / weak value — treat as an unauthenticated "
                    "endpoint from now on.",
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -u {cred['user']} "
                    f"-P '{pw_repr}' -t '#' -v -W 3",
                    "Rotate the credential; enforce a password policy (min length "
                    "+ complexity); disable default vendor accounts.",
                    ["CWE-521", "CWE-798"], kind="mqtt_weak_credential"))

            # 7. Plaintext (1883 without TLS).
            if p.portid == 1883:
                out.append(_finding(
                    "medium",
                    "MQTT broker on 1883/tcp (plaintext)",
                    tgt,
                    "Broker exposed on the plaintext IANA port. Any credential or "
                    "sensitive payload traverses the network in the clear.",
                    f"openssl s_client -connect {h.ip}:8883 -alpn mqtt </dev/null",
                    "Move the broker to 8883/tcp with TLS 1.2+; require client "
                    "certificate authentication or channel binding.",
                    ["CWE-319"], kind="mqtt_plaintext"))

            # 8. Auth-gated info finding (symmetric with kafka_saslgated).
            reason = pr.get("reason")
            if reason in (_CONNACK_BAD_USER_PASS, _CONNACK_NOT_AUTHORISED):
                out.append(_finding(
                    "info",
                    "MQTT broker reachable, authentication enforced",
                    tgt,
                    f"CONNECT was refused with reason {reason:#04x} "
                    f"({_REASON_TXT.get(reason,'?')}). Broker enforces auth — "
                    "any looted MQTT/IoT credential should be sprayed against "
                    "this endpoint.",
                    f"mosquitto_sub -h {h.ip} -p {p.portid} -u <user> -P <pass> "
                    "-t '$SYS/#'",
                    "Keep authentication enforcement on; rate-limit failed "
                    "CONNECTs.",
                    [], kind="mqtt_authgated"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Anonymous wildcard subscribe (topic tree + retained)",
         "cmd": f"mosquitto_sub -h {ip} -p {port} -t '#' -v -W 3"},
        {"step": "Broker version + client roster ($SYS)",
         "cmd": f"mosquitto_sub -h {ip} -p {port} -t '\\$SYS/#' -v -W 3"},
        {"step": "Anonymous publish permission test",
         "cmd": f"mosquitto_pub -h {ip} -p {port} -t recce/probe -m marker"},
        {"step": "Credentialed subscribe (once a cred is known)",
         "cmd": f"mosquitto_sub -h {ip} -p {port} -u <user> -P <pass> -t '#' -v"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "mqtt", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            users: list[str] | None = None,
            passwords: list[str] | None = None) -> dict:
    """Analyze MQTT targets. `users`/`passwords` override the spray inputs;
    when None, recce sprays a small vendor default matrix."""
    from . import svcprobe
    targets = mqtt_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], active=True,
                                users=users, passwords=passwords),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["anon_ok"] = pr.get("anon_ok", False)
                t["retained"] = len(pr.get("retained") or [])
                t["publish_ok"] = pr.get("publish_ok", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
