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


class MethodsTest(unittest.TestCase):
    def test_trace_reflection_detected(self):
        class H(_FixedHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length","2")
                self.end_headers(); self.wfile.write(b"OK")
            def do_TRACE(self):
                # Echo the request line + headers back — real XST behavior.
                echo = b"TRACE / HTTP/1.1\r\nHost: x\r\nUser-Agent: recce-probe/1.0\r\n\r\n"
                self.send_response(200); self.send_header("Content-Length", str(len(echo)))
                self.end_headers(); self.wfile.write(echo)
        srv, _t = _serve(H)
        try:
            m = svc_http.methods_probe("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertIn("TRACE", m["accepted"])
        self.assertTrue(m["trace_reflected"])

    def test_spa_catchall_suppresses_methods(self):
        """SPA that 200s every method with the same body must NOT report every
        verb as accepted."""
        body = b"<html>index</html>"
        class H(_FixedHandler):
            def do_GET(self): self._reply()
            def do_OPTIONS(self): self._reply()
            def do_PUT(self): self._reply()
            def do_DELETE(self): self._reply()
            def _reply(self):
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            m = svc_http.methods_probe("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        # OPTIONS/PUT/DELETE all echo the exact GET / body — should be filtered.
        self.assertEqual(m["accepted"], [], f"expected empty, got {m['accepted']}")


class CorsTest(unittest.TestCase):
    def test_reflection_with_credentials_flagged(self):
        class H(_FixedHandler):
            def do_GET(self):
                origin = self.headers.get("Origin","")
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
                self.send_header("Content-Length","2")
                self.end_headers(); self.wfile.write(b"OK")
        srv, _t = _serve(H)
        try:
            c = svc_http.cors_probe("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertTrue(c["reflects_origin"])
        self.assertTrue(c["credentials"])


class RobotsSitemapTest(unittest.TestCase):
    def test_disallow_paths_extracted(self):
        class H(_FixedHandler):
            ROUTES = {
                "/robots.txt": (200, [("Content-Type","text/plain")],
                                b"User-agent: *\nDisallow: /admin\nDisallow: /internal/\nAllow: /public\n"),
                "/sitemap.xml": (200, [("Content-Type","application/xml")],
                                 b"<urlset><url><loc>/secret-report</loc></url></urlset>"),
            }
        srv, _t = _serve(H)
        try:
            paths = svc_http.free_paths_from_index("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertIn("/admin", paths)
        self.assertIn("/internal/", paths)
        self.assertIn("/public", paths)
        self.assertIn("/secret-report", paths)
        # Bare "/" must be filtered (dev servers often "Disallow: /").
        self.assertNotIn("/", paths)


class ApiSpecTest(unittest.TestCase):
    def test_openapi_json_detected(self):
        spec = (b'{"openapi": "3.0.0", "info": {"title": "T"}, "paths": {'
                b'"/users": {"get": {}}, "/orders": {"post": {}}, "/health": {"get": {}}'
                b'}}')
        class H(_FixedHandler):
            ROUTES = {"/openapi.json": (200, [("Content-Type","application/json")], spec)}
        srv, _t = _serve(H)
        try:
            r = svc_http.api_spec_probe("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertIsNotNone(r)
        self.assertEqual(r["kind"], "openapi")
        self.assertEqual(r["path"], "/openapi.json")
        self.assertGreaterEqual(r["endpoint_count"], 3)


class FormDiscoveryTest(unittest.TestCase):
    def test_login_form_with_csrf_and_default_creds(self):
        html = (b'<html><head><title>Login :: Damn Vulnerable Web Application (DVWA)</title></head>'
                b'<body><form method="POST" action="login.php">'
                b'<input name="username" type="text">'
                b'<input name="password" type="password">'
                b'<input name="Login" type="submit" value="Login">'
                b'<input name="user_token" type="hidden" value="abc123">'
                b'</form></body></html>')
        class H(_FixedHandler):
            ROUTES = {
                "/":          (302, [("Location", "login.php")], b""),
                "/login.php": (200, [("Content-Type", "text/html")], html),
            }
        srv, _t = _serve(H)
        try:
            fp = svc_http.fingerprint("127.0.0.1", srv.server_address[1], False)
            forms = svc_http.discover_forms("127.0.0.1", srv.server_address[1], False, fp=fp)
        finally:
            srv.shutdown()
        self.assertTrue(any(f["login"] for f in forms), f"no login form detected in {forms}")
        login = next(f for f in forms if f["login"])
        self.assertEqual(login["username_field"], "username")
        self.assertEqual(login["password_field"], "password")
        self.assertTrue(login["has_csrf"], "user_token should register as csrf hint")
        self.assertIn(("admin", "password"), login["default_creds"],
                      f"DVWA default admin:password should be flagged, got {login['default_creds']}")

    def test_non_login_form_not_flagged(self):
        html = (b'<form action="/search"><input name="q" type="text"><input type="submit"></form>')
        class H(_FixedHandler):
            ROUTES = {"/": (200, [("Content-Type","text/html")], html)}
        srv, _t = _serve(H)
        try:
            forms = svc_http.discover_forms("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        # A search form has no password field — should not be classified as login.
        for f in forms:
            self.assertFalse(f["login"], f"non-login form wrongly flagged: {f}")


class WordlistExpansionTest(unittest.TestCase):
    """The bundled `_PATHS` list has to actually contain the new high-value
    entries we added (recent CVEs, terraform/cloud/CI secrets, debug/profiler)
    or path_enum would silently regress the moment someone reorders the file."""

    def test_new_wordlist_entries_present(self):
        paths = {entry[0] for entry in svc_http._PATHS}
        for p in ("/terraform.tfstate", "/.aws/credentials", "/.ssh/id_rsa",
                   "/.git/index", "/docker-compose.yml", "/.gitlab-ci.yml",
                   "/debug/pprof/", "/metrics", "/jolokia/list",
                   "/_cluster/settings", "/api/v1/pods",
                   "/mgmt/tm/util/bash", "/api/v2/cmdb/system/admin",
                   "/autodiscover/autodiscover.json",
                   "/setup/setupadministrator.action",
                   "/actuator/gateway/routes"):
            self.assertIn(p, paths, f"wordlist regressed — {p} missing")

    def test_terraform_tfstate_hit_is_critical(self):
        class H(_FixedHandler):
            ROUTES = {
                "/terraform.tfstate": (200, [("Content-Type", "application/json")],
                                        b'{"version":4,"terraform_version":"1.5.0"}'),
            }
        srv, _t = _serve(H)
        try:
            hits = svc_http.path_enum("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        by_path = {h["path"]: h for h in hits}
        self.assertIn("/terraform.tfstate", by_path)
        self.assertEqual(by_path["/terraform.tfstate"]["severity"], "critical")


class OpenRedirectTest(unittest.TestCase):
    def test_redirect_echoing_param_flagged(self):
        """Server that reflects `next=` into Location is an open redirect."""
        from urllib.parse import urlparse, parse_qs

        class H(_FixedHandler):
            def do_GET(self):
                q = parse_qs(urlparse(self.path).query)
                nxt = (q.get("next") or q.get("url") or q.get("redirect") or [""])[0]
                if nxt and self.path.startswith("/login"):
                    self.send_response(302)
                    self.send_header("Location", nxt)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200); self.send_header("Content-Length","2")
                self.end_headers(); self.wfile.write(b"OK")

        srv, _t = _serve(H)
        try:
            hits = svc_http.open_redirect_probe("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        # /login with any of the enumerated param names should trigger exactly one hit
        login_hits = [h for h in hits if h["path"] == "/login"]
        self.assertEqual(len(login_hits), 1,
                         f"expected exactly one /login hit, got {hits}")
        self.assertIn(svc_http._OPEN_REDIRECT_CANARY, login_hits[0]["location"])

    def test_non_redirecting_server_returns_empty(self):
        """A server that never issues 3xx must not produce open-redirect hits."""
        class H(_FixedHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length", "2")
                self.end_headers(); self.wfile.write(b"OK")

        srv, _t = _serve(H)
        try:
            hits = svc_http.open_redirect_probe("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertEqual(hits, [])


class CrlfInjectionTest(unittest.TestCase):
    """Requires a raw-socket server — BaseHTTPRequestHandler validates
    outbound header names and would strip the injected line."""

    def test_injected_header_detected(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(5)
        port = s.getsockname()[1]

        def serve():
            while True:
                try:
                    c, _ = s.accept()
                except OSError:
                    return
                try:
                    data = c.recv(4096) or b""
                    first_line = data.split(b"\r\n", 1)[0]
                    # Simulate a naive server that URL-decodes ?x= into a
                    # response header — the CRLF splits headers.
                    if b"%0d%0a" in first_line.lower():
                        resp = (b"HTTP/1.1 200 OK\r\n"
                                b"X-Recce-Canary: recce-crlf-canary\r\n"
                                b"Content-Length: 2\r\n\r\nOK")
                    else:
                        resp = (b"HTTP/1.1 200 OK\r\n"
                                b"Content-Length: 2\r\n\r\nOK")
                    c.sendall(resp)
                except OSError:
                    pass
                finally:
                    try:
                        c.close()
                    except OSError:
                        pass

        thr = threading.Thread(target=serve, daemon=True)
        thr.start()
        try:
            hit = svc_http.crlf_injection_probe("127.0.0.1", port, False)
        finally:
            s.close()
        self.assertIsNotNone(hit, "vulnerable server must yield a hit")
        self.assertIn("recce-crlf-canary", hit["injected_value"])

    def test_safe_server_returns_none(self):
        """A server that echoes nothing back must not false-positive."""
        class H(_FixedHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length", "2")
                self.end_headers(); self.wfile.write(b"OK")

        srv, _t = _serve(H)
        try:
            hit = svc_http.crlf_injection_probe("127.0.0.1", srv.server_address[1], False)
        finally:
            srv.shutdown()
        self.assertIsNone(hit)


if __name__ == "__main__":
    unittest.main()
