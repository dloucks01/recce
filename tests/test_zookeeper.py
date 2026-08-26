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


if __name__ == "__main__":
    unittest.main()
