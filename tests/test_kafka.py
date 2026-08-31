"""Tests for recce.services.kafka — MetadataRequest v0 probe.

Serve a canned MetadataResponse v0 body over TCP; verify probe() parses
brokers and topics. Also verify the "reachable but no response" path
(SASL-gated broker that closes the connection)."""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import kafka


def _build_string(s: str) -> bytes:
    b = s.encode("utf-8"); return struct.pack(">h", len(b)) + b


def _build_metadata_response(brokers: list[dict], topics: list[str]) -> bytes:
    """Assemble a synthetic MetadataResponse v1 body suitable for
    _read_response to return (post-size, keep correlation_id at start).

    v1 vs v0: brokers gain a rack (nullable_string, -1 = null), an int32
    controller_id follows the brokers array, and topics gain an is_internal
    bool between name and partitions."""
    body = struct.pack(">i", 1)                      # correlation_id
    body += struct.pack(">i", len(brokers))
    for b in brokers:
        body += struct.pack(">i", b["node_id"])
        body += _build_string(b["host"])
        body += struct.pack(">i", b["port"])
        body += struct.pack(">h", -1)                # rack = null
    body += struct.pack(">i", 1)                     # controller_id
    body += struct.pack(">i", len(topics))
    for t in topics:
        body += struct.pack(">h", 0)                 # error
        body += _build_string(t)
        body += b"\x00"                              # is_internal = false
        body += struct.pack(">i", 0)                 # no partitions
    return struct.pack(">i", len(body)) + body


class _KafkaServer:
    """Accept ONE connection, read the request, send a fixed response, close."""
    def __init__(self, response_bytes: bytes):
        self._resp = response_bytes
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        # Two exchanges per connection: ApiVersions handshake first (probe
        # sends this to be compatible with modern Kafka), then MetadataRequest.
        # We reply with a small valid ApiVersions response, then the fixture
        # response for the second request.
        api_versions_resp = self._build_api_versions_v0()
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                # ApiVersions
                sz = conn.recv(4)
                if len(sz) == 4:
                    n = struct.unpack(">i", sz)[0]
                    if 0 <= n <= 65536:
                        conn.recv(n)
                    conn.sendall(api_versions_resp)
                # MetadataRequest
                sz = conn.recv(4)
                if len(sz) == 4:
                    n = struct.unpack(">i", sz)[0]
                    if 0 <= n <= 65536:
                        conn.recv(n)
                    if self._resp:
                        conn.sendall(self._resp)
            except OSError:
                pass
            finally:
                try: conn.close()
                except OSError: pass

    @staticmethod
    def _build_api_versions_v0() -> bytes:
        """Minimal ApiVersionsResponse v0: no error, one api (Metadata v0-v9)."""
        # Body: correlation_id(4) + error(2) + num_apis(4) + [key(2)+min(2)+max(2)]
        body = struct.pack(">i", 100)                 # correlation_id
        body += struct.pack(">h", 0)                  # error
        body += struct.pack(">i", 1)                  # 1 api advertised
        body += struct.pack(">h", 3) + struct.pack(">h", 0) + struct.pack(">h", 9)
        return struct.pack(">i", len(body)) + body

    def close(self):
        self._stop = True
        try: self._srv.close()
        except OSError: pass


def _build_api_versions_response(apis: list[tuple[int, int, int]],
                                 correlation_id: int = 100,
                                 error_code: int = 0) -> bytes:
    """Assemble a synthetic ApiVersionsResponse v0 body (post-size).

    Wire (KIP-35 / ApiVersionsResponse v0):
      correlation_id(int32) + error_code(int16)
      + num_apis(int32) + [api_key(int16), min(int16), max(int16)]*
    """
    body = struct.pack(">i", correlation_id)
    body += struct.pack(">h", error_code)
    body += struct.pack(">i", len(apis))
    for k, mn, mx in apis:
        body += struct.pack(">hhh", k, mn, mx)
    return struct.pack(">i", len(body)) + body


def _build_sasl_handshake_response(mechanisms: list[str],
                                   correlation_id: int = 2,
                                   error_code: int = 33) -> bytes:
    """Assemble a synthetic SaslHandshakeResponse v1 body (post-size).

    Wire (KIP-43 §Server response):
      correlation_id(int32) + error_code(int16)
      + num_mechanisms(int32) + [STRING]*
    error_code=33 (UNSUPPORTED_SASL_MECHANISM) is what a broker returns to a
    probe with a nonsense mechanism, and the enabled_mechanisms array is
    populated on that path as well as the success path."""
    body = struct.pack(">i", correlation_id)
    body += struct.pack(">h", error_code)
    body += struct.pack(">i", len(mechanisms))
    for m in mechanisms:
        body += _build_string(m)
    return struct.pack(">i", len(body)) + body


class _KafkaSaslServer:
    """Serve the SASL-gated flow: empty metadata reply on connection #1, then a
    canned SaslHandshakeResponse on connection #2 (probe() opens a fresh
    connection for the SASL probe when metadata was refused)."""

    def __init__(self, sasl_response: bytes):
        self._sasl_resp = sasl_response
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._connections = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        apiv = _KafkaServer._build_api_versions_v0()
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            self._connections += 1
            first_conn = self._connections == 1
            try:
                # ApiVersions
                sz = conn.recv(4)
                if len(sz) == 4:
                    n = struct.unpack(">i", sz)[0]
                    if 0 <= n <= 65536:
                        conn.recv(n)
                    conn.sendall(apiv)
                # Second exchange: metadata on conn #1 (empty reply => gated);
                # SaslHandshake on conn #2 (canned mechanisms).
                sz = conn.recv(4)
                if len(sz) == 4:
                    n = struct.unpack(">i", sz)[0]
                    if 0 <= n <= 65536:
                        conn.recv(n)
                    if first_conn:
                        pass                             # send nothing = gated
                    else:
                        conn.sendall(self._sasl_resp)
            except OSError:
                pass
            finally:
                try: conn.close()
                except OSError: pass

    def close(self):
        self._stop = True
        try: self._srv.close()
        except OSError: pass


class ApiVersionsParseTest(unittest.TestCase):
    """Unit tests for _parse_api_versions and _fingerprint. Wire format is
    KIP-35 ApiVersionsResponse v0/v1."""

    def test_parse_roundtrip(self):
        body = _build_api_versions_response(
            [(0, 0, 10), (1, 0, 13), (3, 0, 12), (18, 0, 3), (68, 0, 0)])
        # Strip the outer int32 size that _read_response would consume.
        post_size = body[4:]
        parsed = kafka._parse_api_versions(post_size)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["error"], 0)
        self.assertEqual(parsed["apis"][0], (0, 10))
        self.assertEqual(parsed["apis"][68], (0, 0))

    def test_parse_truncated(self):
        self.assertIsNone(kafka._parse_api_versions(b"\x00\x00\x00\x01"))

    def test_parse_rejects_absurd_count(self):
        # 100_000 apis claimed — sanity cap must reject.
        body = struct.pack(">i", 1) + struct.pack(">h", 0) + struct.pack(">i", 100000)
        self.assertIsNone(kafka._parse_api_versions(body))

    def test_fingerprint_bands(self):
        # KIP-848 ConsumerGroupHeartbeat is Kafka 3.7+
        self.assertEqual(kafka._fingerprint({68: (0, 0)}), ">=3.7")
        # Produce max v10 arrived in Kafka 3.0
        self.assertEqual(kafka._fingerprint({0: (0, 10), 60: (0, 0)}), ">=3.0")
        # DescribeCluster (KIP-700) is Kafka 2.8+
        self.assertEqual(kafka._fingerprint({60: (0, 0)}), ">=2.8")
        # DescribeUserScramCredentials (KIP-554) is Kafka 2.7+
        self.assertEqual(kafka._fingerprint({50: (0, 0)}), ">=2.7")
        # Nothing distinctive => empty label, never a false claim.
        self.assertEqual(kafka._fingerprint({3: (0, 9)}), "")
        self.assertEqual(kafka._fingerprint({}), "")


class SaslHandshakeParseTest(unittest.TestCase):
    """Unit tests for _parse_sasl_handshake. Wire format is KIP-43
    SaslHandshakeResponse v0/v1."""

    def test_parse_mechanisms(self):
        body = _build_sasl_handshake_response(
            ["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", "OAUTHBEARER"])
        post_size = body[4:]
        parsed = kafka._parse_sasl_handshake(post_size)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["error"], 33)
        self.assertEqual(parsed["mechanisms"],
                         ["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", "OAUTHBEARER"])

    def test_parse_empty_mechanisms(self):
        body = _build_sasl_handshake_response([], error_code=0)
        parsed = kafka._parse_sasl_handshake(body[4:])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["mechanisms"], [])

    def test_parse_truncated(self):
        self.assertIsNone(kafka._parse_sasl_handshake(b""))
        self.assertIsNone(kafka._parse_sasl_handshake(b"\x00" * 4))

    def test_parse_rejects_absurd_count(self):
        body = struct.pack(">i", 1) + struct.pack(">h", 0) + struct.pack(">i", 999)
        self.assertIsNone(kafka._parse_sasl_handshake(body))


class SaslHandshakeProbeTest(unittest.TestCase):
    """End-to-end: metadata refused => probe opens a second connection and
    enumerates SASL mechanisms via SaslHandshake (KIP-43)."""

    def test_saslgated_enumerates_mechanisms(self):
        srv = _KafkaSaslServer(_build_sasl_handshake_response(
            ["PLAIN", "SCRAM-SHA-512", "GSSAPI"]))
        try:
            p = kafka.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["brokers"], [])
        self.assertEqual(p["sasl_mechanisms"],
                         ["PLAIN", "SCRAM-SHA-512", "GSSAPI"])

    def test_saslgated_emits_mechanisms_finding(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.7", ports=[Port(portid=9093, service="kafka")])
        probes = {("10.0.0.7", 9093): {
            "reachable": True, "brokers": [], "topics": [],
            "api_versions": {}, "fingerprint": "",
            "sasl_mechanisms": ["PLAIN", "SCRAM-SHA-256"],
            "error": "no metadata response — SASL/mTLS may be required",
        }}
        fs = kafka.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("kafka_saslgated", kinds)
        self.assertIn("kafka_sasl_mechanisms_enumerated", kinds)
        # Severity of the mechanisms finding is medium (info-only for
        # saslgated, but the mechanism list is a real spray primitive).
        mech_f = next(f for f in fs
                      if f["kind"] == "kafka_sasl_mechanisms_enumerated")
        self.assertEqual(mech_f["severity"], "medium")
        self.assertIn("PLAIN", mech_f["detail"])


class FingerprintFindingTest(unittest.TestCase):
    def test_fingerprint_finding_emitted(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.9", ports=[Port(portid=9092, service="kafka")])
        probes = {("10.0.0.9", 9092): {
            "reachable": True,
            "brokers": [{"node_id": 1, "host": "b1", "port": 9092}],
            "topics": ["billing"],
            "api_versions": {0: (0, 10), 68: (0, 0)},
            "fingerprint": ">=3.7",
            "sasl_mechanisms": [],
            "error": "",
        }}
        fs = kafka.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("kafka_metadata_leaked", kinds)
        self.assertIn("kafka_version_fingerprint", kinds)
        fp = next(f for f in fs if f["kind"] == "kafka_version_fingerprint")
        self.assertIn(">=3.7", fp["title"])
        self.assertEqual(fp["severity"], "info")


class ProbeTest(unittest.TestCase):
    def test_metadata_leak_parsed(self):
        resp = _build_metadata_response(
            brokers=[{"node_id": 1, "host": "broker1", "port": 9092},
                     {"node_id": 2, "host": "broker2", "port": 9092}],
            topics=["billing-events", "user-pii-prod", "audit-log", "__consumer_offsets"])
        srv = _KafkaServer(resp)
        try:
            p = kafka.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(len(p["brokers"]), 2)
        self.assertEqual(p["brokers"][0]["host"], "broker1")
        self.assertIn("billing-events", p["topics"])
        self.assertIn("user-pii-prod", p["topics"])

    def test_saslgated_returns_reachable_no_data(self):
        # Empty response = server accepted TCP + read the request but closed
        # instead of answering (typical of SASL_SSL brokers when SASL handshake
        # is expected first).
        srv = _KafkaServer(b"")
        try:
            p = kafka.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["brokers"], [])
        self.assertEqual(p["topics"], [])
        self.assertIn("SASL", p["error"] or "")

    def test_dead_port(self):
        p = kafka.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


def _build_fetch_response_v4(topic: str, error_code: int = 0,
                             high_watermark: int = 1234,
                             records: bytes = b"",
                             correlation_id: int = 3) -> bytes:
    """Assemble a synthetic FetchResponse v4 body (size-prefixed).

    Wire (Kafka Fetch v4):
      correlation_id: int32
      throttle_time_ms: int32
      responses: [
        topic: STRING
        partition_responses: [
          partition: int32
          error_code: int16
          high_watermark: int64
          last_stable_offset: int64
          aborted_transactions: nullable_array (-1 = null)
          record_set: BYTES (int32 length + bytes; -1 = null)
        ]
      ]
    Bytes are hand-assembled from the wire spec — no recce encoder involved.
    """
    body = struct.pack(">i", correlation_id)
    body += struct.pack(">i", 0)                          # throttle_time_ms
    body += struct.pack(">i", 1)                          # 1 topic
    body += _build_string(topic)
    body += struct.pack(">i", 1)                          # 1 partition
    body += struct.pack(">i", 0)                          # partition = 0
    body += struct.pack(">h", error_code)
    body += struct.pack(">q", high_watermark)
    body += struct.pack(">q", high_watermark)             # last_stable_offset
    body += struct.pack(">i", -1)                         # aborted_txns = null
    body += struct.pack(">i", len(records))
    body += records
    return struct.pack(">i", len(body)) + body


class _KafkaFetchServer:
    """Accept TWO connections:
      #1: ApiVersions + Metadata (canned metadata reply — one topic)
      #2: ApiVersions + Fetch    (canned fetch reply)
    probe() opens a fresh connection for _probe_fetch (matches SASL flow)."""

    def __init__(self, metadata_bytes: bytes, fetch_bytes: bytes | None,
                 apiv_bytes: bytes | None = None):
        self._meta = metadata_bytes
        self._fetch = fetch_bytes
        # Default ApiVersions advertises Metadata v0-v9 and Fetch (key=1) v0-v11
        # so probe() thinks Fetch v4 is supported.
        self._apiv = apiv_bytes or _build_api_versions_response(
            [(1, 0, 11), (3, 0, 9), (18, 0, 3)])
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._connections = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            self._connections += 1
            first_conn = self._connections == 1
            try:
                # ApiVersions
                sz = conn.recv(4)
                if len(sz) == 4:
                    n = struct.unpack(">i", sz)[0]
                    if 0 <= n <= 65536:
                        conn.recv(n)
                    conn.sendall(self._apiv)
                # Second exchange
                sz = conn.recv(4)
                if len(sz) == 4:
                    n = struct.unpack(">i", sz)[0]
                    if 0 <= n <= 65536:
                        conn.recv(n)
                    if first_conn:
                        if self._meta:
                            conn.sendall(self._meta)
                    else:
                        if self._fetch:
                            conn.sendall(self._fetch)
            except OSError:
                pass
            finally:
                try: conn.close()
                except OSError: pass

    def close(self):
        self._stop = True
        try: self._srv.close()
        except OSError: pass


class FetchParseTest(unittest.TestCase):
    """Unit tests for _build_fetch_v4 and _parse_fetch_v4 (Kafka Fetch v4)."""

    def test_request_shape(self):
        """Byte-level: request framing has the expected header + body layout."""
        req = kafka._build_fetch_v4("billing-events")
        # Length-prefixed
        size = struct.unpack(">i", req[:4])[0]
        self.assertEqual(size, len(req) - 4)
        # api_key = 1 (Fetch), api_version = 4
        self.assertEqual(struct.unpack(">h", req[4:6])[0], 1)
        self.assertEqual(struct.unpack(">h", req[6:8])[0], 4)
        # Topic name appears verbatim in the request body
        self.assertIn(b"billing-events", req)

    def test_parse_valid_records(self):
        # Craft a 40-byte "record batch" placeholder — parser doesn't crack v2
        # record format, it just captures size and preserves bytes for evidence.
        fake_recs = b"\x00" * 40
        body = _build_fetch_response_v4(
            "billing-events", error_code=0,
            high_watermark=9001, records=fake_recs)
        parsed = kafka._parse_fetch_v4(body[4:])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["topic"], "billing-events")
        self.assertEqual(parsed["error"], 0)
        self.assertEqual(parsed["high_watermark"], 9001)
        self.assertEqual(len(parsed["records"]), 40)

    def test_parse_empty_topic_valid(self):
        # error==0 but no records is legitimate (topic exists, offset 0 empty).
        body = _build_fetch_response_v4(
            "empty-topic", error_code=0, high_watermark=0, records=b"")
        parsed = kafka._parse_fetch_v4(body[4:])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["error"], 0)
        self.assertEqual(parsed["records"], b"")

    def test_parse_auth_denied(self):
        # TOPIC_AUTHORIZATION_FAILED = 29
        body = _build_fetch_response_v4(
            "billing-events", error_code=29, high_watermark=0, records=b"")
        parsed = kafka._parse_fetch_v4(body[4:])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["error"], 29)

    def test_parse_truncated(self):
        self.assertIsNone(kafka._parse_fetch_v4(b""))
        self.assertIsNone(kafka._parse_fetch_v4(b"\x00" * 8))


class FetchProbeTest(unittest.TestCase):
    """End-to-end: metadata leaks topics, Fetch v4 confirms unauth read."""

    def test_fetch_upgrades_probe_to_t2_evidence(self):
        meta = _build_metadata_response(
            brokers=[{"node_id": 1, "host": "b1", "port": 9092}],
            topics=["billing-events", "__consumer_offsets"])
        fake_recs = b"\x01\x02\x03\x04" * 8
        fetch = _build_fetch_response_v4(
            "billing-events", error_code=0,
            high_watermark=42, records=fake_recs)
        srv = _KafkaFetchServer(meta, fetch)
        try:
            p = kafka.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertIn("billing-events", p["topics"])
        self.assertIn("fetch", p)
        self.assertEqual(p["fetch"]["error"], 0)
        self.assertEqual(p["fetch"]["high_watermark"], 42)
        self.assertGreater(len(p["fetch"]["records"]), 0)
        # Internal topic (__consumer_offsets) must NOT have been chosen.
        self.assertEqual(p["fetch"]["topic"], "billing-events")

    def test_fetch_finding_upgraded_to_t2(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.9", ports=[Port(portid=9092, service="kafka")])
        probes = {("10.0.0.9", 9092): {
            "reachable": True,
            "brokers": [{"node_id": 1, "host": "b1", "port": 9092}],
            "topics": ["billing-events"],
            "api_versions": {1: (0, 11)},
            "fingerprint": "",
            "sasl_mechanisms": [],
            "fetch": {"topic": "billing-events", "error": 0,
                      "high_watermark": 42, "records": b"x" * 32},
            "error": "",
        }}
        fs = kafka.findings([h], probes)
        leaked = next(f for f in fs if f["kind"] == "kafka_metadata_leaked")
        self.assertEqual(leaked["depth_tier"], "t2")
        self.assertIn("T2 proof-of-read", leaked["detail"])
        self.assertIn("billing-events", leaked["detail"])
        self.assertIn("high_watermark=42", leaked["detail"])

    def test_fetch_auth_denied_stays_t1(self):
        # If the broker returned an error_code (e.g. 29 = TOPIC_AUTHORIZATION_FAILED)
        # the Fetch DID NOT succeed. Finding must stay T1 — no proof of read.
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.9", ports=[Port(portid=9092, service="kafka")])
        probes = {("10.0.0.9", 9092): {
            "reachable": True,
            "brokers": [{"node_id": 1, "host": "b1", "port": 9092}],
            "topics": ["billing-events"],
            "api_versions": {1: (0, 11)},
            "fingerprint": "",
            "sasl_mechanisms": [],
            "fetch": {"topic": "billing-events", "error": 29,
                      "high_watermark": 0, "records": b""},
            "error": "",
        }}
        fs = kafka.findings([h], probes)
        leaked = next(f for f in fs if f["kind"] == "kafka_metadata_leaked")
        self.assertEqual(leaked["depth_tier"], "t1")
        self.assertNotIn("T2 proof-of-read", leaked["detail"])

    def test_no_fetch_data_stays_t1(self):
        # Backwards path: metadata parsed, no Fetch attempted (or blocked).
        # Existing T1 behaviour must be preserved.
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.9", ports=[Port(portid=9092, service="kafka")])
        probes = {("10.0.0.9", 9092): {
            "reachable": True,
            "brokers": [{"node_id": 1, "host": "b1", "port": 9092}],
            "topics": ["billing-events"],
            "api_versions": {},
            "fingerprint": "",
            "sasl_mechanisms": [],
            "error": "",
        }}
        fs = kafka.findings([h], probes)
        leaked = next(f for f in fs if f["kind"] == "kafka_metadata_leaked")
        self.assertEqual(leaked["depth_tier"], "t1")

    def test_fetch_probe_clean_timeout_on_dead_port(self):
        # Bounded: probe against a closed port returns None cleanly (no hang).
        result = kafka._probe_fetch("127.0.0.1", 1, "any-topic", timeout=1)
        self.assertIsNone(result)

    def test_fetch_probe_skipped_when_no_user_topics(self):
        # Only __consumer_offsets present — internal, must not be probed.
        meta = _build_metadata_response(
            brokers=[{"node_id": 1, "host": "b1", "port": 9092}],
            topics=["__consumer_offsets"])
        srv = _KafkaFetchServer(meta, fetch_bytes=None)
        try:
            p = kafka.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertNotIn("fetch", p)

    def test_fetch_probe_gated_on_apiversions_support(self):
        # If ApiVersions advertises Fetch max < 4, the probe skips Fetch.
        meta = _build_metadata_response(
            brokers=[{"node_id": 1, "host": "b1", "port": 9092}],
            topics=["billing-events"])
        # Advertise Fetch max=3 (< 4). Metadata + ApiVersions still fine.
        apiv = _build_api_versions_response(
            [(1, 0, 3), (3, 0, 9), (18, 0, 3)])
        srv = _KafkaFetchServer(meta, fetch_bytes=None, apiv_bytes=apiv)
        try:
            p = kafka.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertNotIn("fetch", p)


if __name__ == "__main__":
    unittest.main()
