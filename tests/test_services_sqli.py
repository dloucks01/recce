"""Tests for recce.services.sqli — active SQL injection tester (C5).

Uses a loopback HTTP server that simulates the three canonical SQLi
signals we detect (error-based, boolean-blind, time-based) plus a
control endpoint that has no injection to confirm we don't false-positive.

Also verifies the opt-in gate rejects unauthorized use.
"""
from __future__ import annotations

import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from recce.services import sqli


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class GateTest(unittest.TestCase):
    def test_gate_rejects_by_default(self):
        # Ensure env var is not set
        os.environ.pop("RECCE_ACTIVE_ATTACKS", None)
        with self.assertRaises(sqli.ActiveAttacksDisabled):
            sqli.test_url_param("http://127.0.0.1/?id=1")

    def test_gate_accepts_env_var(self):
        os.environ["RECCE_ACTIVE_ATTACKS"] = "1"
        try:
            # No target so it just returns [] fast — the gate call itself
            # must not raise.
            r = sqli.test_url_param("http://127.0.0.1:1/?id=1")
            self.assertEqual(r, [])
        finally:
            os.environ.pop("RECCE_ACTIVE_ATTACKS", None)

    def test_gate_accepts_explicit_true(self):
        os.environ.pop("RECCE_ACTIVE_ATTACKS", None)
        r = sqli.test_url_param("http://127.0.0.1:1/?id=1", active_attacks=True)
        self.assertEqual(r, [])

    def test_gate_rejects_explicit_false(self):
        os.environ["RECCE_ACTIVE_ATTACKS"] = "1"      # would normally allow
        try:
            with self.assertRaises(sqli.ActiveAttacksDisabled):
                sqli.test_url_param("http://127.0.0.1/?id=1", active_attacks=False)
        finally:
            os.environ.pop("RECCE_ACTIVE_ATTACKS", None)


class ErrorBasedTest(unittest.TestCase):
    def test_mysql_error_detected(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a, **k): pass
            def do_GET(self):
                q = parse_qs(urlparse(self.path).query)
                val = (q.get("id") or [""])[0]
                if "'" in val:
                    body = b"<html>You have an error in your SQL syntax; check the manual...</html>"
                else:
                    body = b"<html>ok</html>"
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            hits = sqli.test_url_param(
                f"http://{srv.server_address[0]}:{srv.server_address[1]}/products?id=42",
                active_attacks=True)
        finally:
            srv.shutdown()
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["technique"], "error-based")
        self.assertEqual(hits[0]["db"], "mysql")
        self.assertEqual(hits[0]["param"], "id")


class BooleanBlindTest(unittest.TestCase):
    def test_material_length_delta_detected(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a, **k): pass
            def do_GET(self):
                q = parse_qs(urlparse(self.path).query)
                val = (q.get("id") or [""])[0]
                # Simulate real boolean-based SQLi: TRUE returns full record,
                # FALSE returns empty result. Length differs materially.
                if "1'='1" in val:
                    body = b"<html><body>" + b"<row>" * 100 + b"</body></html>"
                elif "1'='2" in val:
                    body = b"<html><body>no results</body></html>"
                else:
                    body = b"<html><body>" + b"<row>" * 100 + b"</body></html>"
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            hits = sqli.test_url_param(
                f"http://{srv.server_address[0]}:{srv.server_address[1]}/products?id=42",
                active_attacks=True)
        finally:
            srv.shutdown()
        # Boolean-blind should hit (delta of hundreds of bytes).
        self.assertTrue(any(h["technique"] == "boolean-blind" for h in hits),
                        f"expected boolean-blind hit, got {hits}")


class NoFalsePositivesTest(unittest.TestCase):
    def test_clean_endpoint_yields_no_hits(self):
        """A server that returns the same static page regardless of input
        must NOT produce any hits."""
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a, **k): pass
            def do_GET(self):
                body = b"<html><body>static content</body></html>"
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            hits = sqli.test_url_param(
                f"http://{srv.server_address[0]}:{srv.server_address[1]}/x?id=42",
                active_attacks=True)
        finally:
            srv.shutdown()
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
