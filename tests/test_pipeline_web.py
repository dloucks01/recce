"""Offline tests split out of tests/test_pipeline.py.

Every test class here is what the original monolith called it. Shared
helpers (header_index, _docx_text, _self_response) live in _pipeline_helpers."""
"""Offline tests for the enumeration pipeline (no network / nmap needed)."""

import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce import ad
from recce.core import parser, scanner
from recce.vuln import exploits
from recce.core import tracking as tr
from recce.report.formats import xlsx
from recce.core.models import Account, Host, Port, Script, Vuln
from recce.report.excel import (build_workbook, read_workbook_tracking,
                                       update_workbook)
from recce.core.store import Store
from recce.core.targets import apply_exclusions, load_targets

SAMPLE = os.path.join(os.path.dirname(parser.__file__), "sample_scan.xml")


from _pipeline_helpers import header_index, _docx_text, _self_response, SAMPLE  # noqa: F401





class WebPutProofTest(unittest.TestCase):
    """Gap-2: the dangerous-methods finding is PROVEN by a PUT round-trip."""
    @classmethod
    def setUpClass(cls):
        import http.server
        import threading
        cls.store = {}

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Allow", "GET, PUT, DELETE, POST")
                self.end_headers()

            def do_PUT(self):
                n = int(self.headers.get("Content-Length", 0))
                cls.store[self.path] = self.rfile.read(n)
                self.send_response(201)
                self.end_headers()

            def do_GET(self):
                b = cls.store.get(self.path, b"index")
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_DELETE(self):
                cls.store.pop(self.path, None)
                self.send_response(204)
                self.end_headers()
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_put_write_is_proven_and_reverted(self):
        from recce.services import web
        from recce.vuln import proofs
        _profile, vulns = web.scan_endpoint("127.0.0.1",
                                            Port(portid=self.port, service="http",
                                                 state="open"), active=True)
        proven = [v for v in vulns if v.script_id == "web-methods"
                  and "proven" in v.title.lower()]
        self.assertTrue(proven, "PUT write should be proven")
        self.assertEqual(proven[0].confidence, "confirmed")
        self.assertIn("returned the uploaded marker", proven[0].output)
        self.assertNotIn("/recce_put_probe.txt", self.store)     # cleaned up
        # The prove engine reads it as CONFIRMED, not LIKELY.
        h = Host(ip="127.0.0.1", ports=[Port(portid=self.port, state="open")],
                 vulns=[proven[0]])
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.CONFIRMED)




class WebJwtNoneProofTest(unittest.TestCase):
    """Gap-3: alg:none is PROVEN by forging an unsigned token and replaying it."""
    @classmethod
    def setUpClass(cls):
        import http.server
        import threading
        import base64 as _b64
        import json as _json
        import re as _re

        def _b64u(obj):
            return _b64.urlsafe_b64encode(
                _json.dumps(obj).encode()).rstrip(b"=").decode()
        # A session token the app issues with the insecure alg:none.
        cls.valid = f'{_b64u({"alg": "none", "typ": "JWT"})}.{_b64u({"user": "admin"})}.'

        def _decode(seg):
            return _b64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                authed = False
                m = _re.search(r"session=([A-Za-z0-9_\-.]+)",
                               self.headers.get("Cookie", ""))
                if m:
                    parts = m.group(1).split(".")
                    if len(parts) >= 2:
                        try:                    # the bug: trust claims, never verify sig
                            hdr = _json.loads(_decode(parts[0]))
                            pl = _json.loads(_decode(parts[1]))
                            if str(hdr.get("alg", "")).lower() == "none" and pl.get("user"):
                                authed = True
                        except Exception:
                            pass
                body = (b"WELCOME ADMIN - secret dashboard: users, billing, settings, logs "
                        b"and much more privileged content here" if authed
                        else b"please log in")
                self.send_response(200)
                self.send_header("Set-Cookie", f"session={cls.valid}; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_alg_none_is_proven_by_replay(self):
        from recce.services import web
        from recce.vuln import proofs
        _profile, vulns = web.scan_endpoint("127.0.0.1",
                                            Port(portid=self.port, service="http",
                                                 state="open"), active=True)
        proven = [v for v in vulns if v.script_id == "web-jwt"
                  and "proven" in v.title.lower()]
        self.assertTrue(proven, "alg:none acceptance should be proven")
        self.assertEqual(proven[0].confidence, "confirmed")
        self.assertEqual(proven[0].severity, "high")
        self.assertIn("same authenticated response", proven[0].output)
        h = Host(ip="127.0.0.1", ports=[Port(portid=self.port, state="open")],
                 vulns=[proven[0]])
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.CONFIRMED)

    def test_alg_none_rejected_is_not_a_finding(self):
        # A server that ignores the forged token (rejects unsigned) must NOT be flagged
        # as exploitable - the forge-and-replay downgrades it.
        from recce.services import web
        import http.server
        import threading
        import base64 as _b64
        import json as _json

        def _b64u(obj):
            return _b64.urlsafe_b64encode(_json.dumps(obj).encode()).rstrip(b"=").decode()
        tok = f'{_b64u({"alg": "none"})}.{_b64u({"user": "admin"})}.'

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                # Always the same page regardless of token -> not gated / rejects it.
                body = b"please log in"
                self.send_response(200)
                self.send_header("Set-Cookie", f"session={tok}; Path=/")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            _p, vulns = web.scan_endpoint("127.0.0.1",
                                          Port(portid=port, service="http", state="open"),
                                          active=True)
        finally:
            httpd.shutdown()
        proven = [v for v in vulns if v.script_id == "web-jwt" and "proven" in v.title.lower()]
        self.assertFalse(proven, "an ungated server must not be reported as proven")




class WebModuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import http.server
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", extra=None):
                self.send_response(code)
                self.send_header("Server", "Apache/2.4.49 (Unix)")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_HEAD(self):
                self._send(200)

            def do_OPTIONS(self):
                self._send(200, extra={"Allow": "GET, POST, PUT, OPTIONS"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                body = self.rfile.read(length) if length else b""
                if self.path == "/graphql" and b"__schema" in body:
                    return self._send(200, b'{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
                return self._send(404, b"nope")

            def do_GET(self):
                if self.path == "/reflect":
                    return self._send(200, (self.headers.get("X-Test", "none")).encode())
                if self.path == "/metrics":
                    return self._send(200, b"# HELP go_gc_duration_seconds ...\n# TYPE x gauge\n")
                if self.path == "/crossdomain.xml":
                    return self._send(200, b'<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>')
                if self.path == "/actuator":
                    return self._send(200, b'{"_links":{"env":{"href":"/actuator/env"}}}')
                if self.path == "/actuator/env":
                    return self._send(200, b'{"propertySources":[{"properties":{"db.password":{"value":"S3cr3tPass"}}}]}')
                if self.path == "/actuator/heapdump":
                    return self._send(200, b"JAVA PROFILE 1.0.2\x00" + b"\x00" * 32,
                                      extra={"Content-Type": "application/octet-stream"})
                if self.path == "/.git/config":
                    return self._send(200, b"[core]\n\trepositoryformatversion = 0\n")
                if self.path == "/backup.sql":
                    return self._send(200, b"-- MySQL dump\nCREATE TABLE users (id int);\n")
                if self.path == "/private":
                    if "Authorization" not in self.headers:
                        return self._send(401, b"auth", extra={"WWW-Authenticate": 'Basic realm="x"'})
                    return self._send(200, b"secret area")
                if self.path.startswith("/?rc="):
                    from urllib.parse import unquote
                    val = unquote(self.path.split("=", 1)[1])
                    # Evaluate {{7*7}} like a vulnerable template engine.
                    rendered = val.replace("{{7*7}}", "49")
                    return self._send(200, ("<html>" + rendered + "</html>").encode())
                if self.path == "/app.js":
                    return self._send(200, b"var k='AIzaSyA1234567890abcdefghijklmnopqrstuvw';")
                if self.path == "/readme.html":
                    return self._send(200, b"<h1>WordPress</h1> Version 6.4.2")
                if self.path == "/wp-content/plugins/woocommerce/readme.txt":
                    return self._send(200, b"=== WooCommerce ===\nStable tag: 8.3.1\n")
                if self.path == "/jwt":
                    return self._send(200, b"token=eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYSJ9.")
                if self.path == "/.git/HEAD":
                    return self._send(200, b"ref: refs/heads/main\n")
                if self.path == "/.env":
                    return self._send(200, b"APP_KEY=base64:x\nDB_PASSWORD=secret\n")
                if self.path == "/":
                    body = (b"<html><head><title>My Site</title>"
                            b"<script src=\"/app.js\"></script></head><body>"
                            b"<a href=\"/page2?q=1\">next</a>"
                            b"<form method=post action=/login>"
                            b"<input type=text name=user><input type=password name=pw></form>"
                            b"Directory listing for /  wp-content/themes</body></html>")
                    return self._send(200, body, extra={"Set-Cookie": "PHPSESSID=abc; path=/"})
                if self.path.startswith("/page2"):
                    return self._send(200, b"<html><body>page two</body></html>")
                return self._send(404, b"nope")

        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _port(self):
        return Port(portid=self.port, service="http", state="open")

    def test_fingerprint_from_headers_and_body(self):
        from recce.services import web
        fp = web.fingerprint({"server": "nginx", "set-cookie": "JSESSIONID=1"},
                             "<title>Home</title> wp-content")
        self.assertIn("server=nginx", fp["tech"])
        self.assertIn("Java/Servlet", fp["tech"])
        self.assertIn("WordPress", fp["tech"])
        self.assertEqual(fp["title"], "Home")

    def test_deep_scan_finds_git_env_listing_methods_cookie(self):
        from recce.services import web
        profile, findings = web.scan_endpoint("127.0.0.1", self._port(), active=True)
        sids = {v.script_id for v in findings}
        self.assertIn("web-git", sids)          # exposed .git
        self.assertIn("web-dotenv", sids)       # exposed .env
        self.assertIn("web-dirlisting", sids)   # directory listing
        self.assertIn("web-methods", sids)      # PUT advertised
        self.assertIn("web-cookie", sids)       # no HttpOnly
        self.assertIn("WordPress", profile["tech"])
        # The .git finding is high severity and carries the exact URL.
        git = next(v for v in findings if v.script_id == "web-git")
        self.assertEqual(git.severity, "high")
        self.assertIn("/.git/HEAD", git.output)

    def test_high_value_exposures(self):
        from recce.services import web
        _, findings = web.scan_endpoint("127.0.0.1", self._port(), active=True)
        sids = {v.script_id for v in findings}
        self.assertIn("web-metrics", sids)        # Prometheus /metrics
        self.assertIn("web-crossdomain", sids)    # permissive crossdomain.xml
        self.assertIn("web-graphql", sids)        # GraphQL introspection (POST)

    def test_deep_actuator_backup_gitconfig_and_secret_extraction(self):
        from recce.services import web
        _, findings = web.scan_endpoint("127.0.0.1", self._port(), active=True)
        by = {v.script_id: v for v in findings}
        self.assertIn("web-actuator", by)               # actuator index
        self.assertIn("web-actuator-env", by)           # /env
        self.assertIn("web-actuator-heapdump", by)      # downloadable heapdump
        self.assertIn("web-gitconfig", by)              # .git/config
        self.assertIn("web-backup", by)                 # backup.sql
        # /env leaked secret is surfaced REDACTED (not the raw value).
        self.assertIn("db.password=", by["web-actuator-env"].output)
        self.assertNotIn("S3cr3tPass", by["web-actuator-env"].output)

    def test_default_creds_probe_opt_in(self):
        from recce.services import web
        # Without creds=True, the Basic-auth endpoint isn't brute-tried.
        _, f0 = web.scan_endpoint("127.0.0.1", self._port(), active=True, creds=False)
        self.assertNotIn("web-default-creds", {v.script_id for v in f0})
        # The bounded default list finds admin:admin on /private... but our server
        # only 200s WITH any Authorization header, so admin:admin (first try) works.
        found = web._basic_auth_defaults("127.0.0.1", self._port(),
                                         web.url_for("127.0.0.1", self._port()), ["/private"])
        self.assertTrue(any(v.script_id == "web-default-creds" for v in found))

    def test_product_version_fingerprint(self):
        from recce.services import web
        self.assertEqual(web.product_version({"x-jenkins": "2.401.1"}, ""), ("Jenkins", "2.401.1"))
        prod, ver = web.product_version({}, '<meta name="generator" content="WordPress 6.4.2">')
        self.assertEqual(prod, "WordPress")
        self.assertEqual(ver, "6.4.2")


    def test_ssti_js_secret_and_wordpress_enum(self):
        from recce.services import web
        _, findings = web.scan_endpoint("127.0.0.1", self._port(), active=True)
        sids = {v.script_id for v in findings}
        self.assertIn("web-ssti", sids)          # {{7*7}} -> 49 in the reflected page
        self.assertIn("web-js-secret", sids)     # AIza… key in /app.js
        self.assertIn("web-wp-version", sids)    # readme.html -> 6.4.2
        self.assertIn("web-wp-plugin", sids)     # woocommerce readme
        js = next(v for v in findings if v.script_id == "web-js-secret")
        self.assertIn("Google API key", js.title)

    def test_authenticated_crawl_discovers_pages_forms_and_params(self):
        from recce.services import web
        cres = web.crawl("127.0.0.1", self._port(), auth={"Cookie": "PHPSESSID=abc"})
        paths = {p["path"] for p in cres["pages"]}
        self.assertIn("/page2?q=1", paths)                     # followed the link
        self.assertIn(("/page2", "q"), cres["params"])         # captured the param
        self.assertTrue(any(f["password"] for f in cres["forms"]))   # parsed the login form

    def test_crawl_flags_cleartext_login_and_reflected_param(self):
        from recce.services import web
        cres = web.crawl("127.0.0.1", self._port())
        fs = web._crawl_findings("127.0.0.1", self._port(), cres)
        self.assertIn("web-cleartext-login", {v.script_id for v in fs})   # pw form over HTTP
        # discovered-param reflection: the server evaluates {{7*7}} on ?rc=
        ref = web._reflect_param("127.0.0.1", self._port(), "/", "rc", None)
        self.assertEqual(ref[0].script_id, "web-ssti")

    def test_jwt_alg_none_detected(self):
        from recce.services import web
        # A header.payload.sig where header = {"alg":"none"}.
        findings = web._scan_jwts("1.1.1.1", Port(portid=443, service="https"),
                                  {"set-cookie": "t=eyJhbGciOiJub25lIn0.eyJ1IjoiYSJ9."}, "")
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("alg:none", findings[0].title.lower())
        # Proof engine renders a verdict + jwt_tool step.
        from recce.vuln import proofs
        r = proofs.recipe_for(findings[0])
        self.assertEqual(r["id"], "web-jwt")

    def test_passive_mode_skips_path_probes(self):
        from recce.services import web
        _, findings = web.scan_endpoint("127.0.0.1", self._port(), active=False)
        self.assertNotIn("web-git", {v.script_id for v in findings})

    def test_web_endpoints_categorization_and_bridge(self):
        from recce.services import web
        h = Host(ip="127.0.0.1", ports=[self._port(),
                                        Port(portid=445, service="microsoft-ds", state="open")])
        h.vulns = web_git = []
        eps = web.web_endpoints([h])
        self.assertEqual(len(eps), 1)                    # only the http port
        self.assertIn("whatweb", eps[0]["commands"])
        self.assertIn("nikto", eps[0]["commands"])

    def test_auth_headers_are_sent(self):
        from recce.services import web
        r = web._fetch("127.0.0.1", self._port(), "/reflect", auth={"X-Test": "hello"})
        self.assertIsNotNone(r)
        self.assertEqual(r[2], "hello")            # server echoed our auth header
        r2 = web._fetch("127.0.0.1", self._port(), "/reflect")
        self.assertEqual(r2[2], "none")            # no header without auth

    def test_non_http_port_skips_active_probes(self):
        from recce.services import web
        # A closed/non-HTTP port: root fetch fails -> no path probes, no crash.
        dead = Port(portid=1, service="https", state="open")     # nothing listening
        profile, findings = web.scan_endpoint("127.0.0.1", dead, active=True)
        self.assertIsNone(profile["status"])
        self.assertNotIn("web-git", {v.script_id for v in findings})

    def test_web_proof_and_poc_wiring(self):
        from recce.act import poc
        from recce.vuln import proofs
        v = Vuln(ip="1.1.1.1", port=80, protocol="tcp", script_id="web-git",
                 title="Exposed Git repository (.git) - source/secret disclosure",
                 output="GET http://1.1.1.1/.git/HEAD -> HTTP 200", source="web")
        r = proofs.recipe_for(v)
        self.assertEqual(r["id"], "web-exposure")
        self.assertEqual(r["fn"](Host(ip="1.1.1.1"), None, v)[0], proofs.CONFIRMED)
        self.assertEqual(poc.recipe_key_for(v.title), "web")




class WebTier1Test(unittest.TestCase):
    """Tier-1 niche-app signatures: fingerprints, unauth exposure paths, form/JSON
    default-credential logins, and the prove-engine verdicts for each."""

    @classmethod
    def setUpClass(cls):
        import http.server
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", extra=None):
                self.send_response(code)
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_POST(self):
                import json as _j
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length) if length else b""
                if self.path == "/login":                       # Grafana form login
                    try:
                        d = _j.loads(raw or b"{}")
                    except ValueError:
                        d = {}
                    if d.get("user") == "admin" and d.get("password") == "admin":
                        return self._send(200, b'{"message":"Logged in"}',
                                          extra={"Set-Cookie": "grafana_session=1; Path=/"})
                    return self._send(401, b'{"message":"Invalid username or password"}')
                if self.path == "/api/v1/login":                # MinIO console login
                    if b"minioadmin" in raw:
                        return self._send(204, b"", extra={"Set-Cookie": "token=x; Path=/"})
                    return self._send(401, b"bad creds")
                return self._send(404, b"nope")

            def do_GET(self):
                import base64
                p = self.path
                if p == "/script":                              # Jenkins script console
                    return self._send(200, b"<h1>Script Console</h1><form>"
                                           b"<textarea name='script'></textarea></form>")
                if p == "/admin/master/console/":               # Keycloak admin console
                    return self._send(200, b'<html><script>var authServerUrl="/auth";'
                                           b' kc-context</script>Keycloak Administration</html>')
                if p.endswith("etc/passwd"):                    # Grafana CVE-2021-43798
                    return self._send(200, b"root:x:0:0:root:/root:/bin/bash\n")
                if p == "/v1/sys/seal-status":                  # Vault
                    return self._send(200, b'{"type":"shamir","sealed":false,'
                                           b'"version":"1.12.0","initialized":true}')
                if p.startswith("/_cat/indices"):               # Elasticsearch
                    return self._send(200, b'[{"health":"green","index":"users","docs.count":"42"}]')
                if p == "/api/status":                          # Kibana
                    return self._send(200, b'{"name":"kibana","version":{"number":"7.10.0"}}')
                if p == "/api/whoami":                           # RabbitMQ mgmt (Basic)
                    auth = self.headers.get("Authorization", "")
                    if auth.startswith("Basic "):
                        try:
                            u, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
                        except Exception:
                            u = pw = ""
                        if (u, pw) == ("guest", "guest"):
                            return self._send(200, b'{"name":"guest","tags":["administrator"]}')
                    return self._send(401, b"auth", extra={"WWW-Authenticate": 'Basic realm="RabbitMQ Management"'})
                if p == "/":
                    return self._send(200, b"<html><head><title>Grafana</title></head>"
                                           b"<body>grafana MinIO Console</body></html>")
                return self._send(404, b"nope")

        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _port(self):
        return Port(portid=self.port, service="http", state="open")

    def test_fingerprints(self):
        from recce.services import web
        fp = web.fingerprint({}, "grafana MinIO Console")
        self.assertIn("Grafana", fp["tech"])
        self.assertIn("MinIO", fp["tech"])
        es = web.fingerprint({}, '{"cluster_name":"docker-cluster"} You Know, for Search')
        self.assertIn("Elasticsearch", es["tech"])
        prod, ver = web.product_version({}, '{"cluster_name":"x","version":{"number":"7.10.2"}}')
        self.assertEqual((prod, ver), ("Elasticsearch", "7.10.2"))

    def test_unauth_exposure_paths(self):
        from recce.services import web
        _, findings = web.scan_endpoint("127.0.0.1", self._port(), active=True)
        sids = {v.script_id for v in findings}
        self.assertIn("web-jenkins-script", sids)     # critical - unauth Groovy RCE
        self.assertIn("web-keycloak-console", sids)   # admin console reachable
        self.assertIn("web-grafana-lfi", sids)        # CVE-2021-43798 file read
        self.assertIn("web-vault-status", sids)       # Vault reachable
        self.assertIn("web-elastic-open", sids)       # unauth ES data read
        self.assertIn("web-kibana", sids)             # Kibana version
        jenk = next(v for v in findings if v.script_id == "web-jenkins-script")
        self.assertEqual(jenk.severity, "critical")

    def test_form_and_basic_default_creds(self):
        from recce.services import web
        base = web.url_for("127.0.0.1", self._port())
        # Form/JSON logins (opt-in): Grafana admin/admin + MinIO minioadmin.
        forms = web._form_login_defaults("127.0.0.1", self._port(), base, ["Grafana", "MinIO"])
        titles = " ".join(v.title for v in forms)
        self.assertIn("Grafana", titles)
        self.assertIn("MinIO", titles)
        self.assertTrue(all(v.severity == "critical" for v in forms))
        # HTTP Basic default guest/guest against the RabbitMQ mgmt path.
        basic = web._basic_auth_defaults("127.0.0.1", self._port(), base, ["/api/whoami"])
        self.assertTrue(any("guest:guest" in v.output for v in basic))

    def test_creds_flag_gates_form_login(self):
        from recce.services import web
        # Without creds=True the form-login probe never runs.
        _, f0 = web.scan_endpoint("127.0.0.1", self._port(), active=True, creds=False)
        self.assertNotIn("web-default-creds", {v.script_id for v in f0})
        _, f1 = web.scan_endpoint("127.0.0.1", self._port(), active=True, creds=True)
        self.assertIn("web-default-creds", {v.script_id for v in f1})

    def test_prove_confirms_tier1(self):
        from recce.services import web
        from recce.vuln import proofs
        _, findings = web.scan_endpoint("127.0.0.1", self._port(), active=True)
        h = Host(ip="127.0.0.1", ports=[self._port()])
        h.vulns = findings
        recs = proofs.verify_host(h)
        vuln_ids = {r["vuln"] for r in recs}
        self.assertIn("Exposed application (unauthenticated access / default credentials)", vuln_ids)
        # The Tier-1 app findings adjudicate CONFIRMED.
        app = [r for r in recs if "unauthenticated access" in r["vuln"]]
        self.assertTrue(app and all(r["verdict"] == proofs.CONFIRMED for r in app))




class WebSqliTest(unittest.TestCase):
    """SQL injection (error / boolean / FP-safety) and form-field fuzzing over a mock
    app: an error-based GET param, a boolean-based GET param, a dynamic page that must
    NOT false-positive, a POST search form (error-based) and a reflected form field."""

    @classmethod
    def setUpClass(cls):
        import http.server
        import threading
        from urllib.parse import urlparse, parse_qs

        cls.hit_delete = False

        class H(http.server.BaseHTTPRequestHandler):
            counter = 0

            def log_message(self, *a):
                pass

            def _send(self, code, body):
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self):
                u = urlparse(self.path)
                idv = parse_qs(u.query, keep_blank_values=True).get("id", [""])[0]
                if u.path == "/prod":                       # error-based (MySQL)
                    if any(c in idv for c in ("'", '"', "\\")):
                        return self._send(200, b"You have an error in your SQL syntax; "
                                          b"check the manual that corresponds to your MySQL "
                                          b"server version for the right syntax near '''")
                    return self._send(200, b"<html>Product page for a valid id.</html>")
                if u.path == "/boolsqli":                   # boolean-based blind
                    s = idv.replace(" ", "")
                    false = ("1=2" in s) or ("'1'='2" in s)
                    if false:
                        return self._send(200, b"<html>No matching record found.</html>")
                    return self._send(200, b"<html>Record: ACME Widget, in stock.</html>")
                if u.path == "/dyn":                        # highly dynamic -> no FP
                    H.counter += 1
                    blob = (b"A" if H.counter % 2 else b"B") * 400
                    return self._send(200, b"<html>" + blob + b"</html>")
                if u.path == "/":
                    return self._send(200,
                        b"<html><body><a href='/prod?id=1'>p</a>"
                        b"<form method=post action=/search><input name=q></form>"
                        b"<form method=post action=/reflectform><input name=name></form>"
                        b"<form method=post action=/account/delete><input name=x></form>"
                        b"</body></html>")
                return self._send(404, b"no")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length).decode() if length else ""
                d = parse_qs(raw, keep_blank_values=True)
                if self.path == "/search":                  # error-based (MSSQL)
                    q = d.get("q", [""])[0]
                    if any(c in q for c in ("'", '"', "\\")):
                        return self._send(200, b"Microsoft SQL Server error: Unclosed "
                                          b"quotation mark after the character string")
                    return self._send(200, b"<html>search results</html>")
                if self.path == "/reflectform":             # reflects + evaluates {{7*7}}
                    name = d.get("name", [""])[0].replace("{{7*7}}", "49")
                    return self._send(200, ("<html>hello " + name + "</html>").encode())
                if self.path == "/account/delete":          # destructive - must be skipped
                    cls.hit_delete = True
                    return self._send(200, b"DELETED")
                return self._send(404, b"no")

        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _port(self):
        return Port(portid=self.port, service="http", state="open")

    def test_error_based_get(self):
        from recce.services import web
        send = web._make_sender("127.0.0.1", self._port(), "get", "/prod", "id", None)
        fs = web._sqli_via("127.0.0.1", self._port(), "param 'id' on /prod", send)
        self.assertTrue(fs and fs[0].script_id == "web-sqli")
        self.assertIn("error-based", fs[0].title)
        self.assertIn("MySQL", fs[0].title)

    def test_boolean_based_get(self):
        from recce.services import web
        send = web._make_sender("127.0.0.1", self._port(), "get", "/boolsqli", "id", None)
        fs = web._sqli_via("127.0.0.1", self._port(), "param 'id' on /boolsqli", send)
        self.assertTrue(fs and fs[0].script_id == "web-sqli")
        self.assertIn("boolean-based", fs[0].title)

    def test_dynamic_page_no_false_positive(self):
        from recce.services import web
        send = web._make_sender("127.0.0.1", self._port(), "get", "/dyn", "id", None)
        fs = web._sqli_via("127.0.0.1", self._port(), "param 'id' on /dyn", send)
        self.assertEqual(fs, [])            # a page that changes every request must not FP

    def test_form_risk_classifier_skips_side_effecting_forms(self):
        from recce.services import web

        def form(action, fields):
            return {"action": action, "method": "post", "inputs": [f[0] for f in fields],
                    "fields": fields}
        # State-changing / transactional / content / upload -> not submitted.
        self.assertTrue(web._form_risk(form("/account/delete", [("id", "text")])))
        self.assertTrue(web._form_risk(form("/checkout", [("card", "text")])))
        self.assertTrue(web._form_risk(form("/contact", [("email", "text"),
                                                         ("message", "textarea")])))
        upload = form("/profile", [("avatar", "file")])
        self.assertTrue(web._form_risk(upload))
        self.assertTrue(web._form_risk(upload, allow_risky=True))   # uploads NEVER submitted
        # --fuzz-risky-forms relaxes the state-change/transaction guards.
        self.assertFalse(web._form_risk(form("/account/delete", [("id", "text")]),
                                        allow_risky=True))
        # Login / search forms (where injection lives) stay fuzzable by default.
        self.assertFalse(web._form_risk(form("/login", [("user", "text"), ("pw", "password")])))
        self.assertFalse(web._form_risk(form("/search", [("q", "text")])))

    def test_risky_form_is_recorded_not_submitted(self):
        from recce.services import web
        # scan_crawl over the mock root, whose forms include /account/delete.
        h = Host(ip="127.0.0.1", ports=[self._port()])
        web.scan_crawl(h)
        sids = {v.script_id for v in h.vulns}
        self.assertIn("web-form-unfuzzed", sids)         # the delete form was recorded
        note = next(v for v in h.vulns if v.script_id == "web-form-unfuzzed")
        self.assertIn("/account/delete", note.output)
        self.assertFalse(WebSqliTest.hit_delete)         # and never actually submitted

    def test_form_field_fuzzing_via_scan_crawl(self):
        from recce.services import web
        h = Host(ip="127.0.0.1", ports=[self._port()])
        pages, added = web.scan_crawl(h)
        sids = {v.script_id for v in h.vulns}
        self.assertIn("web-sqli", sids)     # /prod GET param + /search POST field
        self.assertIn("web-ssti", sids)     # /reflectform field evaluated {{7*7}}
        # A form field injection came from the POST search form.
        self.assertTrue(any(v.script_id == "web-sqli" and "field 'q'" in v.title
                            for v in h.vulns))
        # The destructive form (action=/account/delete) is never submitted.
        self.assertFalse(WebSqliTest.hit_delete)

    def test_prove_confirms_sqli(self):
        from recce.services import web
        from recce.vuln import proofs
        send = web._make_sender("127.0.0.1", self._port(), "get", "/prod", "id", None)
        fs = web._sqli_via("127.0.0.1", self._port(), "param 'id' on /prod", send)
        h = Host(ip="127.0.0.1", ports=[self._port()])
        h.vulns = fs
        recs = proofs.verify_host(h)
        self.assertTrue(recs and recs[0]["verdict"] == proofs.CONFIRMED)
        self.assertEqual(proofs.recipe_for(fs[0])["id"], "web-sqli")




class WebCookieRedirectLfiTest(unittest.TestCase):
    """Cookie hardening (SameSite / prefix / cleartext / broad Domain), open redirect,
    and generic path traversal - detection, FP-safety, and prove verdicts."""

    @classmethod
    def setUpClass(cls):
        import http.server
        import threading
        from urllib.parse import urlparse, parse_qs

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                u = urlparse(self.path)
                qs = parse_qs(u.query, keep_blank_values=True)
                if u.path == "/download":                   # path traversal
                    f = qs.get("file", [""])[0]
                    if "etc/passwd" in f:
                        return self._send(200, b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1")
                    if "win.ini" in f:
                        return self._send(200, b"[fonts]\n[extensions]\n")
                    return self._send(200, b"<html>file: readme contents</html>")
                if u.path == "/go":                          # open redirect (reflects target)
                    nxt = qs.get("next", [""])[0]
                    if nxt.startswith(("http://", "https://", "//", "/\\")):
                        return self._send(302, b"", {"Location": nxt})
                    return self._send(200, b"<html>home</html>")
                if u.path == "/safe":                        # redirects, but to a FIXED path
                    return self._send(302, b"", {"Location": "/dashboard"})
                if u.path == "/":
                    return self._send(200,
                        b"<html><body><a href='/download?file=readme'>d</a>"
                        b"<a href='/go?next=/home'>g</a></body></html>",
                        {"Set-Cookie": "sessionid=abc123; Path=/"})   # weak session cookie
                return self._send(404, b"no")

            def _send(self, code, body=b"", extra=None):
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if body:
                    self.wfile.write(body)

        cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _port(self):
        return Port(portid=self.port, service="http", state="open")

    # --- cookies (unit) ---------------------------------------------------------
    def test_cookie_hardening_checks(self):
        from recce.services import web
        tls = Port(portid=443, service="https", state="open")
        titles = {v.title.split(":")[0] for v in
                  web._cookie_findings("1.1.1.1", tls, "sessionid=x; Path=/")}
        self.assertIn("Cookie without HttpOnly", titles)
        self.assertIn("Cookie without Secure (served over HTTPS)", titles)
        self.assertIn("Cookie without SameSite (CSRF / cross-site surface)", titles)
        # SameSite=None without Secure -> medium.
        none = web._cookie_findings("1.1.1.1", tls, "sid=x; HttpOnly; SameSite=None")
        self.assertTrue(any(v.title.startswith("Cookie SameSite=None without Secure")
                            and v.severity == "medium" for v in none))
        # A session cookie over cleartext HTTP is called out as wire-exposed.
        http = Port(portid=80, service="http", state="open")
        clear = web._cookie_findings("1.1.1.1", http, "authtoken=x; Path=/")
        self.assertTrue(any("cleartext HTTP" in v.title for v in clear))
        # Broad parent-domain scope.
        dom = web._cookie_findings("1.1.1.1", tls, "id=x; Domain=.example.com; Secure; "
                                                   "HttpOnly; SameSite=Lax")
        self.assertTrue(any("broad parent Domain" in v.title for v in dom))

    def test_cookie_findings_surface_in_scan_endpoint(self):
        from recce.services import web
        _, findings = web.scan_endpoint("127.0.0.1", self._port(), active=True)
        self.assertIn("web-cookie", {v.script_id for v in findings})

    # --- open redirect ----------------------------------------------------------
    def test_open_redirect_detected(self):
        from recce.services import web
        send = web._make_sender("127.0.0.1", self._port(), "get", "/go", "next", None)
        fs = web._open_redirect_via("127.0.0.1", self._port(), "param 'next' on /go", send)
        self.assertTrue(fs and fs[0].script_id == "web-openredirect")

    def test_open_redirect_no_fp_on_fixed_target(self):
        from recce.services import web
        # /safe always redirects to /dashboard regardless of input -> not open.
        send = web._make_sender("127.0.0.1", self._port(), "get", "/safe", "next", None)
        self.assertEqual(web._open_redirect_via("127.0.0.1", self._port(),
                                                "param 'next' on /safe", send), [])

    # --- path traversal ---------------------------------------------------------
    def test_traversal_detected_on_fileish_param(self):
        from recce.services import web
        send = web._make_sender("127.0.0.1", self._port(), "get", "/download", "file", None)
        fs = web._traversal_via("127.0.0.1", self._port(), "param 'file' on /download",
                                "file", send)
        self.assertTrue(fs and fs[0].script_id == "web-lfi")
        self.assertEqual(fs[0].severity, "high")

    def test_traversal_skips_non_fileish_param(self):
        from recce.services import web
        # A param that doesn't look like a file/path is not traversal-tested (budget/FP).
        send = web._make_sender("127.0.0.1", self._port(), "get", "/download", "q", None)
        self.assertEqual(web._traversal_via("127.0.0.1", self._port(),
                                            "param 'q' on /download", "q", send), [])

    # --- integration + prove ----------------------------------------------------
    def test_scan_crawl_finds_redirect_and_lfi(self):
        from recce.services import web
        from recce.vuln import proofs
        h = Host(ip="127.0.0.1", ports=[self._port()])
        web.scan_crawl(h)
        sids = {v.script_id for v in h.vulns}
        self.assertIn("web-openredirect", sids)
        self.assertIn("web-lfi", sids)
        recs = {r["vuln"]: r["verdict"] for r in proofs.verify_host(h)}
        self.assertEqual(recs.get("Path traversal / local file read"), proofs.CONFIRMED)
        self.assertEqual(recs.get("Open redirect"), proofs.CONFIRMED)
