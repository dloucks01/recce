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


if __name__ == "__main__":
    unittest.main()
