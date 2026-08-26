"""Tests for recce.services.consul — unauthenticated Consul read probe."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import consul


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass


class ProbeTest(unittest.TestCase):
    def test_acl_disabled_all_endpoints_readable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"Config": {"Version": "1.16.0"},
                                       "DebugConfig": {"ACLDefaultPolicy": "allow"}}).encode()
                elif self.path == "/v1/catalog/services":
                    body = json.dumps({"consul": [], "web": ["prod"], "redis": ["cache"]}).encode()
                elif self.path == "/v1/catalog/nodes":
                    body = json.dumps([{"Node": "n1"}, {"Node": "n2"}]).encode()
                elif self.path.startswith("/v1/kv"):
                    body = json.dumps([
                        {"Key": "app/db_password", "Value": "..."},
                        {"Key": "app/api_token", "Value": "..."},
                    ]).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "1.16.0")
        self.assertFalse(p["acl_enabled"], "default-allow ACL should register as disabled")
        self.assertIn("web", p["services"])
        self.assertEqual(p["nodes"], 2)
        self.assertEqual(p["kv_keys"], 2)

    def test_acl_enforcing_falls_back_to_leader(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/status/leader":
                    body = b'"10.0.0.1:8300"'
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["acl_enabled"], "403 on /agent/self should mark ACL enforcing")
        self.assertEqual(p["leader"], "10.0.0.1:8300")
        self.assertEqual(p["services"], [])

    def test_dead_port(self):
        p = consul.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


if __name__ == "__main__":
    unittest.main()
