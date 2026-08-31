"""Tests for recce.services.zookeeper — Zookeeper 4LW probe.

Stand up a tiny loopback TCP server that mimics a real Zookeeper's 4LW
responses (per-command, with the right data-leak signatures). Verify:

* probe() marks reachable ONLY when `ruok` returns `imok`
* leaks_data flag fires when dumping-category commands respond
* leaks_admin flag fires when wchc/wchp respond
* transport failure returns unreachable, no exceptions
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import zookeeper as zk


class _ZK4LWServer:
    """Serve a per-command response map. Each connection reads exactly one
    4-letter command (+ optional trailing newline), then writes the matching
    response and closes. Mimics real Zookeeper 4LW behavior."""

    def __init__(self, responses: dict[str, bytes]):
        self._resp = {k.lower(): v for k, v in responses.items()}
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                data = conn.recv(16).strip().decode("ascii", "replace").lower()[:4]
                resp = self._resp.get(data, b"")
                if resp:
                    conn.sendall(resp)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


class ProbeTest(unittest.TestCase):
    def test_reachable_flags_data_leak(self):
        srv = _ZK4LWServer({
            "ruok": b"imok",
            "srvr": b"Zookeeper version: 3.8.0-abc\nLatency min/avg/max: 0/0/0\n",
            "conf": b"clientPort=2181\ndataDir=/data\ntickTime=2000\n",
            "dump": b"SessionTracker dump:\n  0x100000000: /clients/1\n",
            "cons": b"127.0.0.1:12345[0](queued=0,recved=1,sent=0)\n",
            "stat": b"Zookeeper version: 3.8.0-abc\nClients:\n /127.0.0.1:12345\n",
        })
        try:
            p = zk.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"], "ruok=imok should mark reachable")
        self.assertIn("3.8", p["version"], f"version parse failed: {p['version']!r}")
        self.assertTrue(p["leaks_data"], "conf/dump/cons should trigger leaks_data")
        self.assertFalse(p["leaks_admin"], "no wchc/wchp response -> no admin leak")
        # exposed_commands should include everything that answered
        self.assertIn("dump", p["exposed_commands"])
        self.assertIn("stat", p["exposed_commands"])

    def test_hardened_server_reachable_no_leaks(self):
        srv = _ZK4LWServer({
            "ruok": b"imok",
            # Only safe commands; everything else times out (empty response).
            "stat": b"Zookeeper version: 3.8.0-locked\n",
        })
        try:
            p = zk.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["leaks_data"])
        self.assertFalse(p["leaks_admin"])

    def test_unreachable_returns_clean(self):
        # closed port 1 — should not raise, must return reachable=False
        p = zk.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])
        self.assertEqual(p["exposed_commands"], {})


class _ZKClientServer:
    """Loopback fake of ZK's client-protocol handshake.

    Reads one length-prefixed ConnectRequest, replies with a ConnectResponse
    that carries `session_id` (0 = server-rejects behaviour), then optionally
    handles one length-prefixed getChildren request and replies with
    `children` (None to close after ConnectResponse, [] to reply with an
    empty vector, list to reply with those names).
    """

    def __init__(self, session_id: int, children: list[str] | None,
                 corrupt_children_reply: bool = False,
                 negotiated_timeout: int = 4000):
        self._sid = session_id
        self._children = children
        self._corrupt = corrupt_children_reply
        self._negotiated = negotiated_timeout
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _read_frame(self, conn: socket.socket) -> bytes:
        hdr = b""
        while len(hdr) < 4:
            b = conn.recv(4 - len(hdr))
            if not b:
                return b""
            hdr += b
        (length,) = struct.unpack(">i", hdr)
        if length <= 0 or length > 4096:
            return b""
        buf = b""
        while len(buf) < length:
            b = conn.recv(length - len(buf))
            if not b:
                return b""
            buf += b
        return buf

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(2.0)
                cr_body = self._read_frame(conn)
                if not cr_body:
                    continue
                # ConnectResponse: proto(4) timeout(4) sessionId(8) passwd(4+16)
                cr = (
                    struct.pack(">i", 0)
                    + struct.pack(">i", self._negotiated)
                    + struct.pack(">q", self._sid)
                    + struct.pack(">i", 16) + b"\x00" * 16
                )
                conn.sendall(struct.pack(">i", len(cr)) + cr)
                if self._sid == 0:
                    continue
                # Expect a getChildren request; ignore contents.
                _ = self._read_frame(conn)
                if self._children is None:
                    continue
                if self._corrupt:
                    # Reply header claims success but the vector is truncated.
                    body = (
                        struct.pack(">i", 1)          # xid
                        + struct.pack(">q", 42)       # zxid
                        + struct.pack(">i", 0)        # err=OK
                        + struct.pack(">i", 5)        # claim 5 children
                        # …but send no strings at all — parser must reject.
                    )
                else:
                    body = (
                        struct.pack(">i", 1)          # xid
                        + struct.pack(">q", 42)       # zxid
                        + struct.pack(">i", 0)        # err=OK
                        + struct.pack(">i", len(self._children))
                    )
                    for name in self._children:
                        nb = name.encode("utf-8")
                        body += struct.pack(">i", len(nb)) + nb
                conn.sendall(struct.pack(">i", len(body)) + body)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


class ClientSessionProbeTest(unittest.TestCase):
    def test_session_ok_returns_children(self):
        srv = _ZKClientServer(session_id=0x12345678AABBCCDD,
                              children=["zookeeper", "app-a", "app-b"])
        try:
            r = zk.zk_client_session_probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(r["session_ok"])
        self.assertEqual(r["session_id"], 0x12345678AABBCCDD)
        self.assertEqual(r["children"], ["zookeeper", "app-a", "app-b"])
        self.assertEqual(r["err"], 0)

    def test_zero_session_id_means_rejected(self):
        # ZK signals "session not established" with sessionId==0.
        srv = _ZKClientServer(session_id=0, children=None)
        try:
            r = zk.zk_client_session_probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertFalse(r["session_ok"])
        self.assertIsNone(r["children"])

    def test_corrupt_children_reply_leaves_children_none(self):
        srv = _ZKClientServer(session_id=0x1, children=[],
                              corrupt_children_reply=True)
        try:
            r = zk.zk_client_session_probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(r["session_ok"])
        self.assertIsNone(r["children"])  # parser rejects truncated vector

    def test_unreachable_returns_clean(self):
        r = zk.zk_client_session_probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(r["session_ok"])
        self.assertIsNone(r["children"])

    def test_timeout_is_clean(self):
        # Bind a socket that accepts but never replies.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        _, port = srv.getsockname()
        try:
            r = zk.zk_client_session_probe("127.0.0.1", port, timeout=0.4)
        finally:
            srv.close()
        self.assertFalse(r["session_ok"])
        self.assertIsNone(r["children"])


class FindingsTierTest(unittest.TestCase):
    def _host(self, ip: str, port: int) -> object:
        # Minimal duck-typed host that findings() iterates.
        class _P:
            def __init__(self, portid):
                self.portid = portid
                self.service = "zookeeper"
                self.product = ""
                self.version = ""

        class _H:
            def __init__(self, ip, port):
                self.ip = ip
                self.open_ports = [_P(port)]
        return _H(ip, port)

    def test_t2_when_client_session_reads_children(self):
        host = self._host("10.0.0.1", 2181)
        probes = {("10.0.0.1", 2181): {
            "reachable": True, "version": "3.8.0",
            "exposed_commands": {"dump": "SessionTracker dump:\n",
                                  "conf": "clientPort=2181\n",
                                  "cons": "127.0.0.1:1[0](queued=0,...)\n"},
            "leaks_data": True, "leaks_admin": False,
            "client_session": {"session_ok": True,
                                "session_id": 0x0FEE1DEAD1234567,
                                "negotiated_timeout": 4000,
                                "children": ["zookeeper", "app"],
                                "err": 0},
        }}
        fs = zk.findings([host], probes)
        dump = [f for f in fs if f.get("kind") == "zk_dump"]
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0]["depth_tier"], "t2")
        self.assertIn("T2 PROOF", dump[0]["detail"])
        self.assertIn("'zookeeper'", dump[0]["detail"])
        self.assertIn("0x0fee1dead1234567", dump[0]["detail"])

    def test_t1_stays_when_client_session_absent(self):
        host = self._host("10.0.0.2", 2181)
        probes = {("10.0.0.2", 2181): {
            "reachable": True, "version": "3.5.1",
            "exposed_commands": {"conf": "clientPort=2181\n",
                                  "dump": "SessionTracker dump:\n"},
            "leaks_data": True, "leaks_admin": False,
            "client_session": None,
        }}
        fs = zk.findings([host], probes)
        dump = [f for f in fs if f.get("kind") == "zk_dump"]
        self.assertEqual(len(dump), 1)
        self.assertEqual(dump[0]["depth_tier"], "t1")
        self.assertNotIn("T2 PROOF", dump[0]["detail"])


if __name__ == "__main__":
    unittest.main()
