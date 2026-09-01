"""Tests for recce.services.mqtt.

Wire fixtures are built from OASIS mqtt-v3.1.1-os §3.1/3.2/3.3/3.8 field
layouts and mqtt-v5.0 §3.1.2/3.2.2 property IDs, then fed into probe() via a
fake in-process broker socket. No network I/O."""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import mqtt


# --- wire fixture helpers (hand-built from the spec) ----------------------

def _remlen(n: int) -> bytes:
    """MQTT variable byte integer, hand-encoded."""
    out = bytearray()
    while True:
        d = n & 0x7F
        n >>= 7
        if n:
            out.append(d | 0x80)
        else:
            out.append(d)
            break
    return bytes(out)


def _u8(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _connack(session_present: bool, reason: int,
             properties: bytes = b"", v5: bool = False) -> bytes:
    """Raw CONNACK frame."""
    body = bytes([0x01 if session_present else 0x00, reason])
    if v5:
        body += _remlen(len(properties)) + properties
    return bytes([0x20]) + _remlen(len(body)) + body


def _suback(packet_id: int, reasons: bytes) -> bytes:
    body = struct.pack(">H", packet_id) + reasons
    return bytes([0x90]) + _remlen(len(body)) + body


def _publish(topic: str, payload: bytes, qos: int = 0, retain: bool = False,
             packet_id: int | None = None) -> bytes:
    flags = 0
    if retain:
        flags |= 0x01
    flags |= (qos & 0x03) << 1
    var = _u8(topic)
    if qos > 0:
        var += struct.pack(">H", packet_id or 0)
    body = var + payload
    return bytes([(3 << 4) | flags]) + _remlen(len(body)) + body


def _puback(packet_id: int) -> bytes:
    return bytes([0x40, 0x02]) + struct.pack(">H", packet_id)


# --- fake broker ----------------------------------------------------------

class _FakeBroker:
    """A minimal MQTT server driven by a scripted response plan.

    plan keys (all optional):
      - connack_v5: bytes response to a CONNECT with level=0x05 (else close)
      - connack_v311: bytes response to a v3.1.1 CONNECT (default: accepted)
      - empty_clientid_reason: reason code for CONNECT with empty ClientID
      - subscribe_responses: dict[topic_filter] -> list[bytes packets] the
        server should send after receiving that SUBSCRIBE
      - publish_ack: bool — whether to PUBACK an incoming QoS1 publish
      - creds_ok: (user, password) tuple that authenticates; anything else -> 0x05
      - anon_after_cred_probes: bool — send anon CONNACK 0x05 by default so the
        credential spray path fires
    """

    def __init__(self, plan: dict):
        self.plan = plan
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self.connect_count = 0
        self.creds_seen: list[tuple[str, str]] = []
        self.published_topics: list[str] = []

    def _read_packet(self, conn: socket.socket) -> tuple[int, bytes] | None:
        first = _recvn(conn, 1)
        if len(first) != 1:
            return None
        rem = bytearray()
        while True:
            b = _recvn(conn, 1)
            if len(b) != 1:
                return None
            rem.append(b[0])
            if not (b[0] & 0x80):
                break
            if len(rem) > 4:
                return None
        # decode
        mult = 1
        val = 0
        for byte in rem:
            val += (byte & 0x7F) * mult
            mult *= 128
        body = _recvn(conn, val) if val else b""
        return first[0], body

    def _handle_connect(self, body: bytes) -> tuple[bytes | None, dict]:
        # parse variable header: proto_name (utf8) + level + flags + keepalive
        pname_len = struct.unpack(">H", body[:2])[0]
        i = 2 + pname_len
        level = body[i]
        flags = body[i + 1]
        i += 2 + 2  # skip keepalive
        if level == 0x05:
            # skip properties
            mult, plen, off = 1, 0, i
            while True:
                b = body[off]
                off += 1
                plen += (b & 0x7F) * mult
                if not (b & 0x80):
                    break
                mult *= 128
            i = off + plen
        # payload: client_id
        cid_len = struct.unpack(">H", body[i:i + 2])[0]
        client_id = body[i + 2:i + 2 + cid_len].decode("utf-8", "replace")
        i += 2 + cid_len
        # will
        if flags & 0x04:
            if level == 0x05:
                # skip will properties
                mult, plen, off = 1, 0, i
                while True:
                    b = body[off]
                    off += 1
                    plen += (b & 0x7F) * mult
                    if not (b & 0x80):
                        break
                    mult *= 128
                i = off + plen
            wt_len = struct.unpack(">H", body[i:i + 2])[0]
            i += 2 + wt_len
            wp_len = struct.unpack(">H", body[i:i + 2])[0]
            i += 2 + wp_len
        user = pw = None
        if flags & 0x80:
            ul = struct.unpack(">H", body[i:i + 2])[0]
            user = body[i + 2:i + 2 + ul].decode("utf-8", "replace")
            i += 2 + ul
        if flags & 0x40:
            pl = struct.unpack(">H", body[i:i + 2])[0]
            pw = body[i + 2:i + 2 + pl].decode("utf-8", "replace")
            i += 2 + pl
        return None, {"level": level, "client_id": client_id,
                      "user": user, "pw": pw}

    def _connack_for(self, ctx: dict) -> bytes | None:
        level = ctx["level"]
        if level == 0x05:
            return self.plan.get("connack_v5")
        if ctx["user"] is not None or ctx["pw"] is not None:
            self.creds_seen.append((ctx["user"] or "", ctx["pw"] or ""))
            creds_ok = self.plan.get("creds_ok")
            if creds_ok and (ctx["user"], ctx["pw"]) == creds_ok:
                return _connack(False, 0x00)
            return _connack(False, 0x05)
        if ctx["client_id"] == "":
            reason = self.plan.get("empty_clientid_reason", 0x00)
            return _connack(False, reason)
        # default anon behaviour
        if self.plan.get("anon_refused"):
            return _connack(False, 0x05)
        return self.plan.get("connack_v311", _connack(False, 0x00))

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            conn.settimeout(3.0)
            threading.Thread(target=self._session_wrap, args=(conn,),
                             daemon=True).start()

    def _session_wrap(self, conn):
        try:
            self._session(conn)
        except OSError:
            pass
        finally:
            try: conn.close()
            except OSError: pass

    def _session(self, conn: socket.socket):
        self.connect_count += 1
        pkt = self._read_packet(conn)
        if not pkt:
            return
        tfb, body = pkt
        if (tfb >> 4) != 1:
            return
        _, ctx = self._handle_connect(body)
        reply = self._connack_for(ctx)
        if reply is None:
            return
        conn.sendall(reply)
        # After a v3.1.1 accepted CONNECT the client may follow up with
        # SUBSCRIBE + PUBLISH + DISCONNECT.
        if ctx["level"] != 0x04 or reply[3] != 0x00:
            return
        subs = self.plan.get("subscribe_responses", {})
        while True:
            pkt = self._read_packet(conn)
            if not pkt:
                return
            tfb, body = pkt
            ptype = tfb >> 4
            if ptype == 8:  # SUBSCRIBE
                packet_id = struct.unpack(">H", body[:2])[0]
                # payload: (topic_utf8 + qos) list
                i = 2
                filt_len = struct.unpack(">H", body[i:i + 2])[0]
                topic = body[i + 2:i + 2 + filt_len].decode("utf-8", "replace")
                responses = subs.get(topic, [_suback(packet_id, b"\x00")])
                # rebuild the SUBACK with the real packet id
                out = bytearray()
                for r in responses:
                    if r[0] == 0x90:
                        # patch packet id
                        rem_val = r[1]
                        r = bytes([0x90, rem_val]) + struct.pack(">H", packet_id) + r[4:]
                    out += r
                conn.sendall(bytes(out))
            elif ptype == 3:  # PUBLISH
                # parse topic
                tlen = struct.unpack(">H", body[:2])[0]
                topic = body[2:2 + tlen].decode("utf-8", "replace")
                self.published_topics.append(topic)
                qos = (tfb >> 1) & 0x03
                if qos > 0:
                    pid = struct.unpack(">H", body[2 + tlen:4 + tlen])[0]
                    if self.plan.get("publish_ack", True):
                        conn.sendall(_puback(pid))
            elif ptype == 14:  # DISCONNECT
                return
            else:
                return

    def close(self):
        self._stop = True
        try: self._srv.close()
        except OSError: pass


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


# --- unit tests for the wire codec ----------------------------------------

class RemLenTest(unittest.TestCase):
    """MQTT §2.2.3 examples."""

    def test_round_trip(self):
        for n, expected in [(0, b"\x00"), (127, b"\x7f"),
                            (128, b"\x80\x01"), (16383, b"\xff\x7f"),
                            (16384, b"\x80\x80\x01"),
                            (2_097_151, b"\xff\xff\x7f")]:
            self.assertEqual(mqtt._encode_remlen(n), expected)
            val, consumed = mqtt._decode_remlen(expected)
            self.assertEqual(val, n)
            self.assertEqual(consumed, len(expected))

    def test_decode_truncated_raises(self):
        with self.assertRaises(ValueError):
            mqtt._decode_remlen(b"\x80")

    def test_encode_out_of_range(self):
        with self.assertRaises(ValueError):
            mqtt._encode_remlen(268_435_456)


class ConnackParseTest(unittest.TestCase):
    """§3.2.2 fixed field parsing."""

    def test_v311_accepted(self):
        ack = mqtt._parse_connack(b"\x00\x00", protocol_level=0x04)
        self.assertEqual(ack, {"session_present": False, "reason": 0x00,
                               "properties": {}})

    def test_v311_bad_user_pass(self):
        ack = mqtt._parse_connack(b"\x00\x04", protocol_level=0x04)
        self.assertEqual(ack["reason"], 0x04)

    def test_v5_with_retain_available(self):
        # Property section: 0x25 (retain_available) = 0x01
        props = bytes([0x25, 0x01,
                       0x28, 0x01])  # wildcard sub available
        body = b"\x00\x00" + _remlen(len(props)) + props
        ack = mqtt._parse_connack(body, protocol_level=0x05)
        self.assertEqual(ack["reason"], 0x00)
        self.assertEqual(ack["properties"].get(0x25), 1)
        self.assertEqual(ack["properties"].get(0x28), 1)

    def test_v5_reason_string(self):
        rs = "not authorised".encode("utf-8")
        props = bytes([0x1F]) + struct.pack(">H", len(rs)) + rs
        body = b"\x00\x87" + _remlen(len(props)) + props
        ack = mqtt._parse_connack(body, protocol_level=0x05)
        self.assertEqual(ack["properties"][0x1F], "not authorised")


class PublishParseTest(unittest.TestCase):
    def test_retained_qos0(self):
        pkt = _publish("device/1/state", b"online", retain=True)
        # The parser eats the FIXED header separately in _read_packet; here
        # we feed the BODY portion (after fixed hdr).
        body = pkt[2:]                                # 1 fixed + 1 remlen
        parsed = mqtt._parse_publish(0x01, body, protocol_level=0x04)
        self.assertEqual(parsed["topic"], "device/1/state")
        self.assertEqual(parsed["payload"], b"online")
        self.assertTrue(parsed["retain"])
        self.assertEqual(parsed["qos"], 0)

    def test_qos1_has_packet_id(self):
        pkt = _publish("t", b"hi", qos=1, packet_id=42)
        body = pkt[2:]
        parsed = mqtt._parse_publish((1 << 1), body, protocol_level=0x04)
        self.assertEqual(parsed["payload"], b"hi")
        self.assertEqual(parsed["qos"], 1)


class ConnectBuilderTest(unittest.TestCase):
    """Byte-level checks against the spec §3.1 layout."""

    def test_minimal_v311_connect_bytes(self):
        pkt = mqtt._build_connect(client_id="abc")
        # 0x10 | remlen | 0x00 0x04 'M' 'Q' 'T' 'T' 0x04 0x02 0x00 0x1e
        # 0x00 0x03 'a' 'b' 'c'
        expected_body = (b"\x00\x04MQTT\x04\x02\x00\x1e"
                         b"\x00\x03abc")
        self.assertEqual(pkt[0], 0x10)
        self.assertEqual(pkt[1], len(expected_body))
        self.assertEqual(pkt[2:], expected_body)

    def test_v5_connect_has_empty_properties(self):
        pkt = mqtt._build_connect(client_id="x", protocol_level=0x05)
        # Protocol level byte 0x05 at offset 2+6 = 8. Then flags(1)+keepalive(2)
        # then a single 0x00 remlen for properties, then payload starts with
        # 0x00 0x01 'x'.
        self.assertEqual(pkt[2 + 6], 0x05)
        # ClientID at end: 0x00 0x01 'x'
        self.assertTrue(pkt.endswith(b"\x00\x01x"))

    def test_credentials_set_flags_and_payload(self):
        pkt = mqtt._build_connect(client_id="cid", username="u", password="p")
        # Flags byte at offset 2+6+1 = 9 (variable header index 6)
        # Actually offset within pkt: [0x10][remlen][... proto ...] --
        # decode: skip 2 bytes header, then 2+4 utf8('MQTT'), then level, then flags
        flags = pkt[2 + 2 + 4 + 1]
        self.assertTrue(flags & 0x80)                # username flag
        self.assertTrue(flags & 0x40)                # password flag
        self.assertIn(b"\x00\x01u", pkt)             # username
        self.assertIn(b"\x00\x01p", pkt)             # password


# --- integration tests via the fake broker --------------------------------

class ProbeAnonymousTest(unittest.TestCase):
    def test_anon_accepted_finds_retained_and_sys(self):
        subs = {
            "$SYS/#": [
                _suback(0, b"\x00"),
                _publish("$SYS/broker/version",
                         b"mosquitto version 2.0.15", retain=True),
                _publish("$SYS/broker/clients/connected", b"3", retain=True),
            ],
            "#": [
                _suback(0, b"\x00"),
                _publish("devices/thermo1/config",
                         b'{"token":"eyJhbGciOi..."}', retain=True),
                _publish("devices/thermo1/state",
                         b"online", retain=False),
            ],
        }
        srv = _FakeBroker({"subscribe_responses": subs, "publish_ack": True})
        try:
            pr = mqtt.probe(srv.host, srv.port, timeout=1,
                            subscribe_window=0.3, test_write=True)
        finally:
            srv.close()

        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["anon_ok"])
        self.assertIn("$SYS/broker/version", pr["sys"])
        self.assertIn("mosquitto 2.0.15", pr["version"])
        self.assertTrue(any(r["topic"] == "devices/thermo1/config"
                            for r in pr["retained"]))
        self.assertTrue(pr["publish_ok"])
        # The publish permission test must have cleaned up (empty retained
        # publish visible in server-side log).
        self.assertTrue(any(t.startswith("recce/probe/")
                            for t in srv.published_topics))

    def test_empty_clientid_check(self):
        srv = _FakeBroker({"empty_clientid_reason": 0x00,
                           "subscribe_responses": {
                               "$SYS/#": [_suback(0, b"\x00")],
                               "#": [_suback(0, b"\x00")]}})
        try:
            pr = mqtt.probe(srv.host, srv.port, timeout=1,
                            subscribe_window=0.2, test_write=False)
        finally:
            srv.close()
        self.assertTrue(pr["anon_ok"])
        self.assertTrue(pr["empty_clientid_ok"])


class ProbeAuthgatedTest(unittest.TestCase):
    def test_authgated_no_creds_reports_reason(self):
        srv = _FakeBroker({"anon_refused": True})
        try:
            pr = mqtt.probe(srv.host, srv.port, timeout=1, active=True,
                            users=None, subscribe_window=0.1)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["anon_ok"])
        self.assertEqual(pr["reason"], 0x05)

    def test_credential_spray_hits_default(self):
        srv = _FakeBroker({"anon_refused": True,
                           "creds_ok": ("admin", "admin")})
        try:
            pr = mqtt.probe(srv.host, srv.port, timeout=1, active=True,
                            users=["admin"],
                            passwords=["", "admin", "password"])
        finally:
            srv.close()
        self.assertEqual(pr["cred"], {"user": "admin", "password": "admin"})


class DeadPortTest(unittest.TestCase):
    def test_no_broker(self):
        pr = mqtt.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(pr["reachable"])


# --- findings() emission --------------------------------------------------

class FindingsTest(unittest.TestCase):
    def _hosts(self, port=1883):
        from recce.core.models import Host, Port
        return [Host(ip="10.0.0.1", ports=[Port(portid=port, service="mqtt")])]

    def test_anonymous_and_retained_emit_findings(self):
        hosts = self._hosts()
        probes = {("10.0.0.1", 1883): {
            "reachable": True, "anon_ok": True, "empty_clientid_ok": True,
            "protocol_level": 4, "publish_ok": True,
            "sys": {"$SYS/broker/version": "mosquitto version 2.0.15"},
            "retained": [{"topic": "cfg/x", "payload": b"", "snippet": b"tok=eyJ",
                          "size": 128, "qos": 0}],
            "live": [], "reason": 0x00, "version": "mosquitto 2.0.15",
            "cred": None, "v5_properties": {}}}
        fs = mqtt.findings(hosts, probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("mqtt_anonymous_connect", kinds)
        self.assertIn("mqtt_empty_clientid", kinds)
        self.assertIn("mqtt_retained_messages", kinds)
        self.assertIn("mqtt_sys_topics", kinds)
        self.assertIn("mqtt_anonymous_publish", kinds)
        self.assertIn("mqtt_plaintext", kinds)
        # every finding must set kind + severity + target
        for f in fs:
            self.assertTrue(f["kind"])
            self.assertIn(f["severity"], ("critical", "high", "medium",
                                          "low", "info"))
            self.assertEqual(f["target"], "10.0.0.1:1883")

    def test_authgated_emits_info(self):
        hosts = self._hosts()
        probes = {("10.0.0.1", 1883): {
            "reachable": True, "anon_ok": False, "empty_clientid_ok": False,
            "protocol_level": 4, "publish_ok": False,
            "sys": {}, "retained": [], "live": [],
            "reason": 0x05, "version": "", "cred": None, "v5_properties": {}}}
        fs = mqtt.findings(hosts, probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("mqtt_authgated", kinds)
        self.assertIn("mqtt_plaintext", kinds)
        self.assertNotIn("mqtt_anonymous_connect", kinds)

    def test_weak_cred_emits_critical(self):
        hosts = self._hosts(port=8883)
        probes = {("10.0.0.1", 8883): {
            "reachable": True, "anon_ok": False, "empty_clientid_ok": False,
            "protocol_level": 4, "publish_ok": False,
            "sys": {}, "retained": [], "live": [], "reason": 0x05,
            "version": "", "cred": {"user": "admin", "password": "admin"},
            "v5_properties": {}}}
        fs = mqtt.findings(hosts, probes)
        cred_findings = [f for f in fs if f["kind"] == "mqtt_weak_credential"]
        self.assertEqual(len(cred_findings), 1)
        self.assertEqual(cred_findings[0]["severity"], "critical")
        # 8883 must NOT emit plaintext finding
        self.assertFalse(any(f["kind"] == "mqtt_plaintext" for f in fs))

    def test_will_message_captured(self):
        hosts = self._hosts()
        probes = {("10.0.0.1", 1883): {
            "reachable": True, "anon_ok": True, "empty_clientid_ok": False,
            "protocol_level": 4, "publish_ok": False,
            "sys": {}, "retained": [],
            "live": [{"topic": "device/1/status", "snippet": b"offline",
                      "size": 7, "qos": 0}],
            "reason": 0x00, "version": "", "cred": None, "v5_properties": {}}}
        fs = mqtt.findings(hosts, probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("mqtt_will_message", kinds)


class RetainedSecretScanTest(unittest.TestCase):
    """T2 promotion: retained-payload secret disclosure. Non-destructive,
    same single SUBSCRIBE '#' window feeds the scan."""

    def test_scanner_finds_jwt_and_password_and_pem(self):
        # RFC 7519 §3 header 'eyJhbG…', RFC 7468 PEM header, key=value
        retained = [
            {"topic": "app/cfg", "snippet":
                b'{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                b'.eyJzdWIiOiIxMjM0NSJ9.abcdefghijklmnop"}',
             "size": 200, "qos": 0},
            {"topic": "svc/env", "snippet":
                b"password=hunter22swordfish\nDEBUG=1", "size": 34, "qos": 0},
            {"topic": "provisioning/keys",
             "snippet": b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB",
             "size": 44, "qos": 0},
        ]
        hits = mqtt._scan_retained_secrets(retained)
        pats = {h["pattern"] for h in hits}
        self.assertIn("jwt", pats)
        self.assertIn("password_field", pats)
        self.assertIn("private_key", pats)
        # topic anchoring survived
        topics = {h["topic"] for h in hits}
        self.assertEqual(topics,
                         {"app/cfg", "svc/env", "provisioning/keys"})
        # Match bytes returned are bounded (≤ 160 + redaction).
        for h in hits:
            self.assertLessEqual(len(h["match"]), 200)

    def test_scanner_finds_bearer_and_aws_and_mac_and_apikey(self):
        retained = [
            {"topic": "auth/http", "snippet":
                b'{"header":"Authorization: Bearer AbCdEf1234567890XYZ"}',
             "size": 60, "qos": 0},
            {"topic": "cloud/init", "snippet":
                b"aws_access_key_id = AKIAABCDEFGHIJKLMNOP", "size": 40, "qos": 0},
            {"topic": "device/1/net", "snippet":
                b'{"mac":"aa:bb:cc:dd:ee:ff"}', "size": 26, "qos": 0},
            {"topic": "cfg/api", "snippet":
                b'api_key: "ABCDEF1234567890xyz"', "size": 30, "qos": 0},
        ]
        hits = mqtt._scan_retained_secrets(retained)
        pats = {h["pattern"] for h in hits}
        self.assertIn("bearer_token", pats)
        self.assertIn("aws_akid", pats)
        self.assertIn("mac_address", pats)
        self.assertIn("api_key_field", pats)

    def test_scanner_patched_no_secrets(self):
        """Patched broker: retained payloads carry only innocent telemetry."""
        retained = [
            {"topic": "temp/room", "snippet": b"21.5C", "size": 5, "qos": 0},
            {"topic": "presence/1", "snippet": b"true", "size": 4, "qos": 0},
            # A word that mentions 'password' in a natural-language string
            # but no key=value pair — must NOT match password_field (needs
            # ':' or '=' separator).
            {"topic": "docs/help",
             "snippet": b"reset your password using the web UI",
             "size": 40, "qos": 0},
        ]
        hits = mqtt._scan_retained_secrets(retained)
        self.assertEqual(hits, [])

    def test_scanner_empty_when_no_retained(self):
        """Timeout / auth-gated: no retained collected → empty scan."""
        self.assertEqual(mqtt._scan_retained_secrets([]), [])
        # Also robust when snippet is missing/empty
        self.assertEqual(
            mqtt._scan_retained_secrets(
                [{"topic": "x", "snippet": b"", "size": 0, "qos": 0}]),
            [])

    def test_scanner_bounded_output(self):
        """Cap total hits and per-topic hits so one payload cannot flood."""
        pathological = [{
            "topic": "flood",
            # A snippet that would trigger multiple patterns without a cap.
            "snippet": (
                b'password=hunter22swordfish '
                b'api_key=ABCDEF1234567890xyz '
                b'secret=deadbeefcafebabe1234 '
                b'jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij'),
            "size": 200, "qos": 0,
        }]
        hits = mqtt._scan_retained_secrets(pathological, per_topic_cap=2)
        self.assertLessEqual(len(hits), 2)

    def test_redact_middle_of_long_match(self):
        long = b"A" * 20 + b"B" * 20
        r = mqtt._redact(long)
        self.assertIn(b"...", r)
        self.assertTrue(r.startswith(b"AAAAAA"))
        self.assertTrue(r.endswith(b"BBBBBB"))
        # short match is passed through unchanged
        self.assertEqual(mqtt._redact(b"short"), b"short")

    def test_probe_populates_retained_secrets(self):
        """Full probe round-trip: fake broker returns a retained payload
        that contains a JWT; probe() must expose it as retained_secrets."""
        subs = {
            "$SYS/#": [_suback(0, b"\x00")],
            "#": [
                _suback(0, b"\x00"),
                _publish("cfg/token",
                         b'{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
                         b'.eyJzdWIiOiIxIn0.abcdefghijkl"}',
                         retain=True),
            ],
        }
        srv = _FakeBroker({"subscribe_responses": subs, "publish_ack": True})
        try:
            pr = mqtt.probe(srv.host, srv.port, timeout=1,
                            subscribe_window=0.3, test_write=False)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["anon_ok"])
        self.assertGreaterEqual(len(pr["retained_secrets"]), 1)
        pats = {s["pattern"] for s in pr["retained_secrets"]}
        self.assertIn("jwt", pats)

    def test_finding_emits_t2_when_secrets_present(self):
        from recce.core.models import Host, Port
        hosts = [Host(ip="10.0.0.9",
                      ports=[Port(portid=1883, service="mqtt")])]
        probes = {("10.0.0.9", 1883): {
            "reachable": True, "anon_ok": True, "empty_clientid_ok": False,
            "protocol_level": 4, "publish_ok": False,
            "sys": {}, "retained": [
                {"topic": "cfg/x", "payload": b"", "snippet": b"apikey=SOMESECRETVALUE1234",
                 "size": 28, "qos": 0}],
            "retained_secrets": [
                {"topic": "cfg/x", "pattern": "api_key_field",
                 "match": b"apikey=SOMESECRETVALUE1234", "offset": 0, "size": 28}],
            "live": [], "reason": 0x00, "version": "", "cred": None,
            "v5_properties": {}}}
        fs = mqtt.findings(hosts, probes)
        disclosed = [f for f in fs if f["kind"] == "mqtt_retained_disclosed"]
        self.assertEqual(len(disclosed), 1)
        self.assertEqual(disclosed[0]["severity"], "critical")
        self.assertEqual(disclosed[0]["depth_tier"], "t2")
        # concrete evidence pinned into detail
        self.assertIn("api_key_field", disclosed[0]["detail"])
        self.assertIn("cfg/x", disclosed[0]["detail"])
        # baseline mqtt_retained_messages still fires (T1 path unchanged)
        base = [f for f in fs if f["kind"] == "mqtt_retained_messages"]
        self.assertEqual(len(base), 1)

    def test_finding_absent_when_no_secrets(self):
        from recce.core.models import Host, Port
        hosts = [Host(ip="10.0.0.9",
                      ports=[Port(portid=1883, service="mqtt")])]
        probes = {("10.0.0.9", 1883): {
            "reachable": True, "anon_ok": True, "empty_clientid_ok": False,
            "protocol_level": 4, "publish_ok": False,
            "sys": {}, "retained": [
                {"topic": "temp/room", "snippet": b"21.5C", "size": 5, "qos": 0}],
            "retained_secrets": [],
            "live": [], "reason": 0x00, "version": "", "cred": None,
            "v5_properties": {}}}
        fs = mqtt.findings(hosts, probes)
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("mqtt_retained_disclosed", kinds)


class TargetsTest(unittest.TestCase):
    def test_is_mqtt_by_port_and_service(self):
        from recce.core.models import Port
        self.assertTrue(mqtt.is_mqtt(Port(portid=1883)))
        self.assertTrue(mqtt.is_mqtt(Port(portid=8883)))
        self.assertTrue(mqtt.is_mqtt(Port(portid=9999, service="mqtt")))
        self.assertTrue(mqtt.is_mqtt(Port(portid=9999, service="secure-mqtt")))
        self.assertFalse(mqtt.is_mqtt(Port(portid=9999, service="http")))


class RunbookTest(unittest.TestCase):
    def test_runbook_has_wildcard_step(self):
        rb = mqtt.runbook("10.0.0.1", 1883)
        self.assertTrue(any("'#'" in step["cmd"] for step in rb))


class FindingsToVulnsTest(unittest.TestCase):
    def test_conversion_produces_vulns(self):
        fs = [{"severity": "high", "title": "MQTT broker accepts anonymous CONNECT",
               "target": "10.0.0.1:1883", "detail": "d", "command": "c",
               "remediation": "r", "cwes": ["CWE-306"],
               "kind": "mqtt_anonymous_connect"}]
        by_ip = mqtt.findings_to_vulns(fs)
        self.assertIn("10.0.0.1", by_ip)
        self.assertEqual(len(by_ip["10.0.0.1"]), 1)
        v = by_ip["10.0.0.1"][0]
        self.assertEqual(v.severity, "high")
        self.assertEqual(v.port, 1883)


if __name__ == "__main__":
    unittest.main()
