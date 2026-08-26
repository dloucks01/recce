"""Tests for recce.services.docker_registry."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import docker_registry as reg


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass


class ProbeTest(unittest.TestCase):
    def test_anonymous_catalog_readable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v2/":
                    self.send_response(200)
                    self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
                    self.send_header("Content-Length", "2"); self.end_headers()
                    self.wfile.write(b"{}")
                elif self.path.startswith("/v2/_catalog"):
                    body = json.dumps({"repositories": [
                        "backend/api", "backend/worker", "frontend/webapp",
                        "internal/secrets-svc"]}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body))); self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = reg.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["auth_required"])
        self.assertEqual(p["repositories"], 4)
        self.assertIn("backend/api", p["catalog"])

    def test_auth_required_marked(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v2/":
                    self.send_response(401)
                    self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
                    self.send_header("Www-Authenticate", 'Bearer realm="https://auth"')
                    self.end_headers()
                else:
                    self.send_response(401); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = reg.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["auth_required"])
        self.assertEqual(p["catalog"], [])

    def test_non_registry_service_not_flagged(self):
        class H(_Base):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length","2")
                self.end_headers(); self.wfile.write(b"ok")
        srv, _t = _serve(H)
        try:
            p = reg.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        # No Docker-Distribution-Api-Version header + no 401 = not a registry.
        self.assertFalse(p["reachable"])

    def test_dead_port(self):
        p = reg.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


if __name__ == "__main__":
    unittest.main()
