"""Content/directory discovery + virtual-host enumeration (recce/web.py).

Drives the two new active-web passes against real stdlib HTTP servers: content
discovery must surface exposed files (individually) and other paths (rolled up) while
NOT flooding on a 200-everything SPA; vhost enumeration must spot a Host-header-served
site that differs from the default response.
"""
from __future__ import annotations

import http.server
import socketserver
import threading
import unittest

from recce.services import web
from recce.core.models import Port


def _serve(handler):
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _reply(h, status, body):
    h.send_response(status)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


class ContentDiscovery(unittest.TestCase):
    def test_surfaces_exposed_and_protected_paths(self):
        routes = {
            "/admin": (403, b"forbidden"),
            "/phpinfo.php": (200, b"<title>phpinfo()</title>PHP Version 8.1"),
            "/swagger.json": (200, b'{"openapi":"3.0.0"}'),
            "/api": (200, b"api root"),
        }

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                _reply(self, *routes.get(self.path, (404, b"nope")))

        srv, pn = _serve(H)
        try:
            f = web._content_discovery("127.0.0.1", Port(portid=pn, service="http", state="open"),
                                       f"http://127.0.0.1:{pn}", None)
        finally:
            srv.shutdown()
        titles = " ".join(v.title for v in f)
        self.assertIn("phpinfo", titles)                    # exposed file -> its own finding
        self.assertTrue(any(v.severity == "high" for v in f))
        self.assertIn("Content discovery", titles)          # /admin[403] + /api[200] rolled up

    def test_catch_all_spa_produces_no_findings(self):
        class SPA(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                _reply(self, 200, b"<html><title>SPA</title>app</html>")

        srv, pn = _serve(SPA)
        try:
            f = web._content_discovery("127.0.0.1", Port(portid=pn, service="http", state="open"),
                                       f"http://127.0.0.1:{pn}", None)
        finally:
            srv.shutdown()
        self.assertEqual(f, [])                             # 200-everything guard


class VhostEnum(unittest.TestCase):
    def test_distinct_vhost_discovered(self):
        class VH(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                if self.headers.get("Host", "").startswith("secret.corp"):
                    _reply(self, 200, b"<title>Internal Admin</title>" + b"x" * 400)
                else:
                    _reply(self, 200, b"<title>Default</title>default")

        srv, pn = _serve(VH)
        try:
            vf, vhosts = web._discover_vhosts("127.0.0.1", Port(portid=pn, service="http", state="open"),
                                              f"http://127.0.0.1:{pn}",
                                              host_hint="secret.corp.local", auth=None)
        finally:
            srv.shutdown()
        self.assertEqual(vhosts, ["secret.corp.local"])
        self.assertTrue(vf and vf[0].script_id == "web-vhost")

    def test_no_vhost_when_identical(self):
        class Same(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                _reply(self, 200, b"<title>Same</title>identical for every host")

        srv, pn = _serve(Same)
        try:
            vf, vhosts = web._discover_vhosts("127.0.0.1", Port(portid=pn, service="http", state="open"),
                                              f"http://127.0.0.1:{pn}",
                                              host_hint="other.corp.local", auth=None)
        finally:
            srv.shutdown()
        self.assertEqual((vf, vhosts), ([], []))            # same content -> not a distinct vhost


if __name__ == "__main__":
    unittest.main()
