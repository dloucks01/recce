"""Tests for recce.services.etcd — unauthenticated etcd read probe.

Stand up a tiny loopback HTTP server that mimics an etcd endpoint.
Verify probe() correctly identifies:

* An unauth-readable v3 store (POST /v3/kv/range returns kvs list)
* An unauth-readable v2 store (GET /v2/keys returns node tree)
* An auth-protected etcd (all reads return 401/403 but /version works)
* A dead/non-etcd port (no crash, reachable=False)
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import etcd


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _EtcdBase(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass


class ProbeTest(unittest.TestCase):
    def test_v3_unauth_read_detected(self):
        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = json.dumps({"etcdserver": "3.5.9", "etcdcluster": "3.5.0"}).encode()
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                elif self.path.startswith("/v2/keys"):
                    self.send_response(404); self.end_headers()
                else:
                    self.send_response(404); self.end_headers()
            def do_POST(self):
                if self.path == "/v3/kv/range":
                    body = json.dumps({"kvs": [
                        {"key": "L2Zvb28=", "value": "YmFy"},
                        {"key": "L2Jheg==", "value": "cXV1eA=="},
                        {"key": "L3NlY3JldA==", "value": "cHc="},
                    ]}).encode()
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "3.5.9")
        self.assertTrue(p["v3_readable"])
        self.assertEqual(p["v3_keys"], 3)
        self.assertFalse(p["v2_readable"])

    def test_v2_unauth_read_detected(self):
        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = b'{"etcdserver":"2.3.8","etcdcluster":"2.3.0"}'
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                elif self.path.startswith("/v2/keys"):
                    body = json.dumps({
                        "action": "get",
                        "node": {"key": "/", "dir": True, "nodes": [
                            {"key": "/foo", "value": "bar"},
                            {"key": "/dir", "dir": True, "nodes": [
                                {"key": "/dir/x", "value": "1"},
                                {"key": "/dir/y", "value": "2"},
                            ]},
                        ]}}).encode()
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(404); self.end_headers()
            def do_POST(self):
                self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["v2_readable"])
        # root + /foo + /dir + /dir/x + /dir/y = 5 nodes (root has key "/")
        self.assertEqual(p["v2_keys"], 5)

    def test_auth_protected_flagged_reachable_no_read(self):
        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}'
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(401); self.end_headers()
            def do_POST(self):
                self.send_response(401); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["v2_readable"])
        self.assertFalse(p["v3_readable"])

    def test_dead_port_returns_unreachable(self):
        p = etcd.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


if __name__ == "__main__":
    unittest.main()
