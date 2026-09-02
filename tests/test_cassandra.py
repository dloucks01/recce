"""Tests for recce.services.db.cassandra - deep CQL probe.

Wire fixtures are hand-encoded byte strings that match the CQL native protocol
v4 frame layout (Apache Cassandra spec doc/native_protocol_v4.spec). Every
response is a `_frame(version=0x84, ...)`-compatible packet - the parser sees
exactly what a real server would put on the wire.

A `_FakeSock` monkeypatched into `socket.create_connection` replays each frame
in order. No real sockets, no threads.
"""
from __future__ import annotations

import struct
import unittest
from unittest import mock

from recce.core.models import Host, Port
from recce.services.db import cassandra as ca


# --- CQL wire encoders (independent of the module under test) ------------------

_RESP_VER = 0x84                        # native v4 response


def _frame(opcode: int, body: bytes, stream: int = 1) -> bytes:
    # [version:1][flags:1][stream:2 signed][opcode:1][length:4]
    return struct.pack(">BBhBI", _RESP_VER, 0, stream, opcode, len(body)) + body


def _cql_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _rows_frame(cols: list[tuple[str, int]], rows: list[list[bytes | None]],
                ks: str = "system_schema", tb: str = "keyspaces",
                stream: int = 3) -> bytes:
    """Build a Rows RESULT frame with global-tables-spec set. Each column is
    (name, type_id). Each row cell is bytes or None (NULL)."""
    body = b""
    body += struct.pack(">I", 0x0002)           # kind = Rows
    body += struct.pack(">I", 0x0001)           # flags = has global tables spec
    body += struct.pack(">I", len(cols))
    body += _cql_string(ks) + _cql_string(tb)
    for name, type_id in cols:
        body += _cql_string(name) + struct.pack(">H", type_id)
    body += struct.pack(">I", len(rows))
    for row in rows:
        for cell in row:
            if cell is None:
                body += struct.pack(">i", -1)
            else:
                body += struct.pack(">i", len(cell)) + cell
    return _frame(0x08, body, stream=stream)    # 0x08 = RESULT


def _ready_frame(stream: int = 1) -> bytes:
    return _frame(0x02, b"", stream=stream)     # 0x02 = READY, empty body


# --- Fake socket that replays a pre-baked script -------------------------------

class _FakeSock:
    """Minimal socket stand-in. `responses` is a list of bytes objects. Each
    call to `sendall` triggers appending the next response to the recv buffer;
    `recv` returns up to n bytes off that buffer."""
    def __init__(self, responses: list[bytes]):
        self._responses = list(responses)
        self._buf = b""
        self.sent: list[bytes] = []

    def settimeout(self, _t):
        pass

    def sendall(self, data):
        self.sent.append(data)
        if self._responses:
            self._buf += self._responses.pop(0)

    def recv(self, n):
        if not self._buf:
            return b""
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _patch_socket(responses: list[bytes]):
    """Return a mock.patch context manager that swaps create_connection."""
    fake = _FakeSock(responses)
    return mock.patch.object(ca.socket, "create_connection",
                             return_value=fake), fake


# --- Fixtures ------------------------------------------------------------------

# system.local Rows response: 4 columns, 1 row.
_SYS_LOCAL_ROWS = _rows_frame(
    cols=[("release_version", 0x000D), ("cluster_name", 0x000D),
          ("data_center", 0x000D), ("partitioner", 0x000D)],
    rows=[[b"4.0.1", b"MyCluster", b"dc1",
           b"org.apache.cassandra.dht.Murmur3Partitioner"]],
    ks="system", tb="local", stream=2,
)

# system_schema.keyspaces Rows response: 1 column, mix of system + user names.
_KEYSPACES_MIXED = _rows_frame(
    cols=[("keyspace_name", 0x000D)],
    rows=[[b"system"], [b"system_schema"], [b"system_auth"],
          [b"my_app"], [b"analytics_prod"]],
    stream=3,
)

# system_schema.keyspaces Rows response: ONLY system keyspaces (patched cluster
# that removed all app data / brand new node) - probe should not emit the
# user-keyspaces finding.
_KEYSPACES_SYSTEM_ONLY = _rows_frame(
    cols=[("keyspace_name", 0x000D)],
    rows=[[b"system"], [b"system_schema"], [b"system_auth"],
          [b"system_traces"], [b"system_distributed"]],
    stream=3,
)


# --- Tests ---------------------------------------------------------------------

class ParseKeyspacesTest(unittest.TestCase):
    def test_extracts_all_names_first_column(self):
        # Strip the 9-byte frame header - _parse_keyspaces takes the body only.
        body = _KEYSPACES_MIXED[9:]
        got = ca._parse_keyspaces(body)
        self.assertEqual(got, ["system", "system_schema", "system_auth",
                               "my_app", "analytics_prod"])

    def test_system_only_returns_only_system(self):
        body = _KEYSPACES_SYSTEM_ONLY[9:]
        got = ca._parse_keyspaces(body)
        self.assertEqual(got, ["system", "system_schema", "system_auth",
                               "system_traces", "system_distributed"])
        # Filter step (the same one probe() applies) drops them all.
        self.assertEqual([n for n in got if n not in ca._SYS_KEYSPACES], [])

    def test_malformed_body_returns_empty(self):
        # Not a Rows kind (kind = ERROR marker 0x00000000).
        self.assertEqual(ca._parse_keyspaces(b"\x00\x00\x00\x00"), [])
        # Truncated bytes.
        self.assertEqual(ca._parse_keyspaces(b""), [])


class ProbeUserKeyspacesTest(unittest.TestCase):
    """probe() drives STARTUP -> READY -> system.local -> system_schema.keyspaces."""

    def test_unauth_with_user_keyspaces(self):
        responses = [_ready_frame(stream=1), _SYS_LOCAL_ROWS, _KEYSPACES_MIXED]
        patcher, fake = _patch_socket(responses)
        with patcher:
            r = ca.probe("10.0.0.9", 9042, timeout=1.0)
        self.assertTrue(r["reachable"])
        self.assertTrue(r["is_cassandra"])
        self.assertTrue(r["no_auth"])
        self.assertEqual(r["version"], "4.0.1")
        self.assertEqual(r["cluster"], "MyCluster")
        self.assertEqual(r["user_keyspaces"], ["my_app", "analytics_prod"])
        # Sanity: three writes went out (STARTUP, system.local QUERY, keyspaces QUERY).
        self.assertEqual(len(fake.sent), 3)

    def test_unauth_without_user_keyspaces(self):
        responses = [_ready_frame(stream=1), _SYS_LOCAL_ROWS,
                     _KEYSPACES_SYSTEM_ONLY]
        patcher, _ = _patch_socket(responses)
        with patcher:
            r = ca.probe("10.0.0.9", 9042, timeout=1.0)
        self.assertTrue(r["no_auth"])
        self.assertEqual(r["user_keyspaces"], [])
        # System keyspaces still populated for downstream tooling.
        self.assertIn("system", r["keyspaces"])


class FindingsUserKeyspacesTest(unittest.TestCase):
    """findings() emits a medium finding iff user_keyspaces is non-empty."""

    def _host(self):
        return Host(ip="10.0.0.9", hostnames=[],
                    ports=[Port(portid=9042, protocol="tcp", state="open",
                                service="cassandra")])

    def test_vulnerable_target_emits_finding(self):
        h = self._host()
        probes = {("10.0.0.9", 9042): {
            "reachable": True, "is_cassandra": True, "no_auth": True,
            "authenticator": "AllowAllAuthenticator", "version": "4.0.1",
            "cluster": "MyCluster", "datacenter": "dc1", "partitioner": "",
            "keyspaces": ["system", "system_schema", "my_app", "analytics_prod"],
            "user_keyspaces": ["my_app", "analytics_prod"], "error": "",
        }}
        fs = ca.findings([h], probes)
        kinds = [f["kind"] for f in fs]
        self.assertIn("cassandra_user_keyspaces", kinds)
        f = next(f for f in fs if f["kind"] == "cassandra_user_keyspaces")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("my_app", f["detail"])
        self.assertIn("analytics_prod", f["detail"])
        # exploit_note carries the tester_next_step advisory.
        self.assertIn("system_auth.roles", f["exploit_note"])
        self.assertIn("hashcat", f["exploit_note"])
        # CWE tagging: info-disclosure + missing access control.
        self.assertIn("CWE-200", f["cwes"])
        self.assertIn("CWE-284", f["cwes"])

    def test_patched_target_no_finding(self):
        # Authenticated cluster (no_auth=False) -> no user-keyspaces finding
        # even if some list happened to be populated.
        h = self._host()
        probes = {("10.0.0.9", 9042): {
            "reachable": True, "is_cassandra": True, "no_auth": False,
            "authenticator": "PasswordAuthenticator", "version": "4.0.11",
            "cluster": "", "datacenter": "", "partitioner": "",
            "keyspaces": [], "user_keyspaces": [], "error": "",
        }}
        fs = ca.findings([h], probes)
        self.assertNotIn("cassandra_user_keyspaces",
                         [f["kind"] for f in fs])

    def test_unauth_but_no_user_keyspaces_no_finding(self):
        # AllowAll cluster on a brand-new node with only system keyspaces:
        # emit the noauth finding (expected) but NOT the user-keyspaces one.
        h = self._host()
        probes = {("10.0.0.9", 9042): {
            "reachable": True, "is_cassandra": True, "no_auth": True,
            "authenticator": "AllowAllAuthenticator", "version": "4.0.11",
            "cluster": "", "datacenter": "", "partitioner": "",
            "keyspaces": ["system", "system_schema"], "user_keyspaces": [],
            "error": "",
        }}
        fs = ca.findings([h], probes)
        kinds = [f["kind"] for f in fs]
        self.assertIn("cassandra_noauth", kinds)
        self.assertNotIn("cassandra_user_keyspaces", kinds)


if __name__ == "__main__":
    unittest.main()
