"""Tests for recce.services.http — the deep-HTTP scan module.

Stand up a tiny loopback HTTP server that mimics the three shapes we care about:

* **Fixed responses per path** — a normal web server. Covers path_enum happy
  path (hit reported, non-hit skipped) and fingerprint (title/generator/cookie
  extraction).
* **SPA catch-all** — 200 index.html for every unknown path. Covers the
  catch-all detector: real hits should be filtered.
* **Redirect from /** — 302 to /login, so the fingerprint has to follow the
  redirect to get the actual page title, and pre-redirect cookies (PHPSESSID)
  need to survive the follow.

All servers live in-process on 127.0.0.1:$random and are torn down per test.
"""
from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import http as svc_http


def _serve(handler_cls) -> tuple[ThreadingHTTPServer, threading.Thread]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _FixedHandler(BaseHTTPRequestHandler):
    """Serves a fixed map of path -> (status, headers, body)."""
    ROUTES: dict[str, tuple[int, list[tuple[str, str]], bytes]] = {}

    def log_message(self, *a, **k):
        pass

    def do_GET(self):
        r = self.ROUTES.get(self.path)
        if r is None:
            self.send_response(404); self.end_headers(); return
        status, extra, body = r
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


class PathEnumTest(unittest.TestCase):
    def test_hit_reported_miss_dropped(self):
        class H(_FixedHandler):
            ROUTES = {
                "/robots.txt":  (200, [("Content-Type", "text/plain")], b"Disallow: /admin\n"),
                "/.env":        (200, [("Content-Type", "text/plain")], b"SECRET=abc\n"),
                "/admin":       (403, [("Content-Type", "text/html")], b"nope"),
                "/manager/html": (401, [("Content-Type", "text/html")], b"auth"),
                # everything else -> default 404
            }
        srv, _t = _serve(H)
        try:
            hits = svc_http.path_enum("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        by_path = {h["path"]: h for h in hits}
        self.assertIn("/robots.txt", by_path)
        self.assertIn("/.env", by_path)
        self.assertIn("/admin", by_path)          # 403 = "exists but restricted" — still reported
        self.assertIn("/manager/html", by_path)   # 401 same story
        # Severity downgrade: 403 on a disclosure path shouldn't stay critical.
        self.assertEqual(by_path["/admin"]["severity"], "info")
        # 200 .env on the other hand IS a real critical finding.
        self.assertEqual(by_path["/.env"]["severity"], "critical")
        # A path we DIDN'T register shouldn't appear.
        self.assertNotIn("/dump.sql", by_path)

    def test_spa_catchall_suppresses_false_positives(self):
        """A server that 200s /anything with the same index.html body should
        yield ZERO path-enum hits — every match is the catch-all."""
        body = b"<html><head><title>SPA</title></head><body id=root></body></html>"

        class H(_FixedHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=UTF-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        srv, _t = _serve(H)
        try:
            sig = svc_http._catchall_signature("127.0.0.1", srv.server_address[1], False)
            hits = svc_http.path_enum("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertIsNotNone(sig, "catch-all should be detected on a 200-everything server")
        self.assertEqual(hits, [], f"catch-all should suppress all hits; got {[h['path'] for h in hits]}")


class FingerprintTest(unittest.TestCase):
    def test_title_generator_and_technology(self):
        html = (b"<!doctype html><html><head>"
                b'<title>My WP Site</title>'
                b'<meta name="generator" content="WordPress 6.4.1">'
                b'</head><body>/wp-content/themes/foo</body></html>')

        class H(_FixedHandler):
            ROUTES = {"/": (200, [("Content-Type", "text/html"),
                                  ("Server", "nginx/1.24.0"),
                                  ("Set-Cookie", "PHPSESSID=abc123; path=/")], html)}

        srv, _t = _serve(H)
        try:
            fp = svc_http.fingerprint("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertEqual(fp["title"], "My WP Site")
        self.assertEqual(fp["generator"], "WordPress 6.4.1")
        self.assertIn("WordPress", fp["technologies"])
        self.assertEqual(fp["cookies"].get("PHPSESSID"), "PHP")
        self.assertIn("nginx", fp["server"])

    def test_redirect_follow_preserves_pre_redirect_cookie(self):
        """DVWA/PHP idiom: / -> 302 /login.php with Set-Cookie: PHPSESSID.
        The fingerprint must follow the redirect AND remember the pre-redirect
        cookie so PHPSESSID still surfaces in fp['cookies']."""
        login_html = b'<title>Login :: Damn Vulnerable Web Application (DVWA)</title>'

        class H(_FixedHandler):
            ROUTES = {
                "/":          (302, [("Location", "login.php"),
                                     ("Set-Cookie", "PHPSESSID=xyz; path=/")], b""),
                "/login.php": (200, [("Content-Type", "text/html")], login_html),
            }

        srv, _t = _serve(H)
        try:
            fp = svc_http.fingerprint("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertEqual(fp["title"][:5], "Login")
        self.assertIn("DVWA", fp["technologies"])
        # Pre-redirect PHPSESSID must survive the follow.
        self.assertEqual(fp["cookies"].get("PHPSESSID"), "PHP")

    def test_transport_failure_returns_empty(self):
        """A dead endpoint mustn't raise — must degrade to {}."""
        fp = svc_http.fingerprint("127.0.0.1", 1, False)  # port 1 = tcpmux, unbound
        self.assertEqual(fp, {})


if __name__ == "__main__":
    unittest.main()
