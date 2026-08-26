"""Tests for recce.services.prometheus."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import prometheus as prom


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass


class ProbeTest(unittest.TestCase):
    def test_open_prometheus_full_readable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                elif self.path == "/api/v1/status/buildinfo":
                    body = json.dumps({"status":"success",
                                       "data":{"version":"2.48.1"}}).encode()
                elif self.path == "/api/v1/status/config":
                    yaml_txt = ("scrape_configs:\n"
                                "  - job_name: 'internal'\n"
                                "    static_configs:\n"
                                "      - targets: ['10.0.0.1:9100','10.0.0.2:9100']\n"
                                "    bearer_token: eyJHIDDEN\n")
                    body = json.dumps({"status":"success","data":{"yaml":yaml_txt}}).encode()
                elif self.path == "/api/v1/query?query=up":
                    body = json.dumps({"status":"success",
                                       "data":{"resultType":"vector","result":[]}}).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length",str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                if self.path == "/-/reload":
                    self.send_response(200); self.send_header("Content-Length","0")
                    self.end_headers()
                else:
                    self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["config_readable"])
        self.assertTrue(p["query_open"])
        self.assertTrue(p["admin_writable"])
        self.assertGreaterEqual(p["scrape_targets_hint"], 1)

    def test_locked_down_prometheus_reachable_only(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                    self.send_response(200); self.send_header("Content-Length",str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(403); self.end_headers()
            def do_POST(self):
                self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["config_readable"])
        self.assertFalse(p["admin_writable"])

    def test_non_prometheus_service_not_flagged(self):
        class H(_Base):
            def do_GET(self):
                body = b"OK"
                self.send_response(200); self.send_header("Content-Length","2")
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p["reachable"])

    def test_dead_port(self):
        p = prom.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


if __name__ == "__main__":
    unittest.main()
