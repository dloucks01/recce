"""Tests for recce.services.nomad — unauthenticated Nomad read probe."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import nomad


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass


class ProbeTest(unittest.TestCase):
    def test_acl_disabled_jobs_readable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.2",
                                                  "ACL": {"Enabled": False}}}).encode()
                elif self.path == "/v1/jobs":
                    body = json.dumps([{"ID": "webapp-prod", "Name": "webapp-prod",
                                        "Type": "service", "Status": "running"},
                                       {"ID": "batch-etl", "Name": "batch-etl",
                                        "Type": "batch", "Status": "pending"}]).encode()
                elif self.path == "/v1/allocations":
                    body = json.dumps([{"ID": "a1"}, {"ID": "a2"}, {"ID": "a3"}]).encode()
                elif self.path == "/v1/nodes":
                    body = json.dumps([{"ID": "n1"}, {"ID": "n2"}]).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["acl_enabled"])
        self.assertEqual(len(p["jobs"]), 2)
        self.assertEqual(p["allocations"], 3)
        self.assertEqual(p["nodes"], 2)

    def test_acl_enforcing_falls_back_to_leader(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/status/leader":
                    body = b'"10.0.0.1:4647"'
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["acl_enabled"])
        self.assertEqual(p["leader"], "10.0.0.1:4647")

    def test_dead_port(self):
        p = nomad.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


if __name__ == "__main__":
    unittest.main()
