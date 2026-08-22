"""Plaintext credential loot from exposed web config/secret files.

Unlike a DB hash, an embedded .git/config token, a .env DB password, or an .aws
key pair is cleartext and directly sprayable, so recce lifts it into the credential
store. These tests exercise the real extractor (`_web_credentials`) and the full
`scan_endpoint` path against a live stdlib HTTP server serving the leaked files.
"""
from __future__ import annotations

import http.server
import re
import shutil
import subprocess
import threading
import time
import unittest
from pathlib import Path

from recce import web
from recce.models import Port, Vuln


# ------------------------------- pure extractor ----------------------------------

def test_git_config_embedded_url_credential():
    body = (
        "[core]\n\trepositoryformatversion = 0\n"
        '[remote "origin"]\n'
        "\turl = https://deploybot:ghp_DEADBEEFcafe0011@github.com/acme/webapp.git\n"
    )
    creds = web._web_credentials("web-gitconfig", body, "10.0.0.9", 80)
    assert len(creds) == 1
    c = creds[0]
    assert c.username == "deploybot" and c.secret == "ghp_DEADBEEFcafe0011"
    assert c.kind == "password" and c.source == "web-loot" and c.origin_ip == "10.0.0.9"


def test_dotenv_pairs_db_user_and_password():
    body = ("APP_ENV=production\nDB_HOST=10.10.10.20\n"
            "DB_USER=webapp\nDB_PASSWORD=Sup3rS3cr3t!DB\nREDIS_PASSWORD=redis-pw-9911\n")
    creds = web._web_credentials("web-dotenv", body, "10.0.0.9", 8080)
    secrets = {c.secret for c in creds}
    assert "Sup3rS3cr3t!DB" in secrets and "redis-pw-9911" in secrets
    # the DB password is attributed to the DB_USER that leaked alongside it
    dbc = next(c for c in creds if c.secret == "Sup3rS3cr3t!DB")
    assert dbc.username == "webapp"


def test_aws_credentials_key_pair():
    body = ("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
    creds = web._web_credentials("web-aws", body, "10.0.0.9", 443)
    assert len(creds) == 1
    assert creds[0].username == "AKIAIOSFODNN7EXAMPLE"
    assert creds[0].secret.endswith("EXAMPLEKEY")


def test_placeholder_secrets_are_ignored():
    # a committed template with no real secret must not pollute the credential store
    body = "DB_USER=app\nDB_PASSWORD=your_password_here\nAPI_KEY=changeme\n"
    assert web._web_credentials("web-dotenv", body, "10.0.0.9", 80) == []


def test_non_secret_file_yields_nothing():
    assert web._web_credentials("web-robots", "Disallow: /admin\n", "10.0.0.9", 80) == []


# ------------------------------ live scan_endpoint -------------------------------

def _serve(root: Path):
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(root), **k)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_scan_endpoint_loots_git_and_env(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / ".git" / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n"
        '[remote "origin"]\n'
        "\turl = https://ci:s3cr3t-token-99@git.acme.io/acme/app.git\n")
    (tmp_path / ".env").write_text("DB_USER=svc_web\nDB_PASSWORD=Pa55w0rd-Prod\n")
    srv = _serve(tmp_path)
    try:
        port = srv.server_address[1]
        p = Port(portid=port, service="http", state="open")
        profile, _findings = web.scan_endpoint("127.0.0.1", p, active=True)
    finally:
        srv.shutdown()
    looted = {c.secret for c in profile.get("credentials", [])}
    assert "s3cr3t-token-99" in looted        # .git/config embedded token
    assert "Pa55w0rd-Prod" in looted           # .env DB password
    # notes carry a clean host:port, not a Port repr
    assert all(str(port) in c.notes and "Port(" not in c.notes
               for c in profile["credentials"])


# --------------------------- full .git reconstruction ----------------------------

def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class GitDumpReconstruction(unittest.TestCase):
    """An exposed .git is reconstructed over HTTP: source tree + secrets recovered,
    not just the .git/config remote URL."""

    def setUp(self):
        if not shutil.which("git"):
            self.skipTest("git not available")

    def test_scan_endpoint_reconstructs_git_and_mines_source(self):
        import tempfile
        d = Path(tempfile.mkdtemp())
        _git(["init", "-q"], d)
        _git(["config", "user.email", "x@x"], d)
        _git(["config", "user.name", "x"], d)
        (d / "config").mkdir()
        (d / "config" / "settings.env").write_text(
            "DB_PASSWORD=Sup3rSecret123\n"
            "DATABASE_URL=postgres://svc:hunter2@db.internal:5432/app\n")
        (d / "app.py").write_text("api_key = 'sk_live_deadbeefcafe1234567890'\n")
        _git(["add", "-A"], d)

        srv = _serve(d)
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            profile, findings = web.scan_endpoint("127.0.0.1", p, active=True)
        finally:
            srv.shutdown()

        # the dedicated reconstruction finding fired
        self.assertTrue(any(f.script_id == "web-git-dump" for f in findings),
                        "no web-git-dump finding")
        dump = next(f for f in findings if f.script_id == "web-git-dump")
        self.assertIn("settings.env", dump.output)          # tracked source recovered

        # secrets mined from the RECOVERED SOURCE (not present in .git/config)
        looted = {c.secret for c in profile.get("credentials", [])}
        self.assertIn("Sup3rSecret123", looted)             # from config/settings.env
        self.assertIn("hunter2", looted)                    # connection string in source
        self.assertTrue(any(c.source == "web-git-loot" for c in profile["credentials"]))


if __name__ == "__main__":
    unittest.main()


# --------------------------- source-map reconstruction ---------------------------

class SourceMapReconstruction(unittest.TestCase):
    """An exposed .js.map ships the original source inline -> recover it + mine secrets."""

    def test_scan_endpoint_recovers_source_from_map(self):
        import json as _json
        import tempfile
        d = Path(tempfile.mkdtemp())
        (d / "index.html").write_text('<html><script src="/app.js"></script></html>')
        (d / "app.js").write_text("console.log(1);\n//# sourceMappingURL=app.js.map\n")
        (d / "app.js.map").write_text(_json.dumps({
            "version": 3,
            "sources": ["webpack://src/config.js"],
            "sourcesContent": [
                "const API_KEY = 'sk_live_abc123def456';\n"
                "const DB_PASSWORD = 'S3cr3tMapPw';\n"
                "const url = 'mysql://root:maproot123@db.internal:3306/app';\n"],
        }))
        srv = _serve(d)
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            profile, findings = web.scan_endpoint("127.0.0.1", p, active=True)
        finally:
            srv.shutdown()
        self.assertTrue(any(f.script_id == "web-sourcemap" for f in findings),
                        "no web-sourcemap finding")
        dump = next(f for f in findings if f.script_id == "web-sourcemap")
        self.assertIn("config.js", dump.output)
        looted = {c.secret for c in profile.get("credentials", [])}
        self.assertIn("S3cr3tMapPw", looted)             # from recovered source
        self.assertIn("maproot123", looted)              # connection string in source
        self.assertTrue(any(c.source == "web-sourcemap-loot" for c in profile["credentials"]))


# ------------------------------ SSRF + headers -----------------------------------

class SsrfDetection(unittest.TestCase):
    """SSRF is confirmed when a URL-ish param makes the server fetch cloud metadata."""

    def test_imds_credentials_ssrf(self):
        def send(payload):
            if "169.254.169.254" in payload and "iam/security-credentials" in payload:
                body = ('{"Code":"Success","AccessKeyId":"ASIAEXAMPLE",'
                        '"SecretAccessKey":"sk","Token":"tok","Expiration":"2030"}')
                return ((200, {}, body), 0.05)
            return ((200, {}, "nothing here"), 0.05)
        p = Port(portid=80, service="http", state="open")
        fs = web._ssrf_via("1.1.1.1", p, "query 'url'", "url", send)
        self.assertTrue(fs)
        self.assertEqual(fs[0].script_id, "web-ssrf")
        self.assertEqual(fs[0].severity, "critical")     # IAM creds via IMDS

    def test_non_url_param_skipped(self):
        def send(payload):
            return ((200, {}, "root:x:0:0:"), 0.05)      # would match file:// marker
        p = Port(portid=80, service="http", state="open")
        self.assertEqual(web._ssrf_via("1.1.1.1", p, "query 'q'", "q", send), [])

    def test_benign_response_no_finding(self):
        def send(payload):
            return ((200, {}, "totally normal page"), 0.05)
        p = Port(portid=80, service="http", state="open")
        self.assertEqual(web._ssrf_via("1.1.1.1", p, "query 'url'", "url", send), [])


class SecurityHeaders(unittest.TestCase):
    def test_missing_headers_flagged_medium(self):
        p = Port(portid=80, service="http", state="open")
        fs = web._security_headers("1.1.1.1", p, {"server": "nginx"})
        self.assertTrue(fs and fs[0].script_id == "web-security-headers")
        self.assertEqual(fs[0].severity, "medium")       # CSP + clickjacking missing
        self.assertIn("Content-Security-Policy", fs[0].output)

    def test_all_present_no_finding(self):
        p = Port(portid=80, service="http", state="open")
        ok = {"content-security-policy": "default-src 'self'", "x-frame-options": "DENY",
              "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
              "permissions-policy": "geolocation=()"}
        self.assertEqual(web._security_headers("1.1.1.1", p, ok), [])


# ------------------------------ JWT HMAC crack -----------------------------------

class JwtHmacCrack(unittest.TestCase):
    """Offline HMAC brute of an HS* JWT: recover a weak secret -> forge arbitrary tokens."""

    def _jwt(self, secret, claims, alg="HS256"):
        import base64 as _b, hashlib as _h, hmac as _hm, json as _j
        def b64(x): return _b.urlsafe_b64encode(x).rstrip(b"=").decode()
        head = b64(_j.dumps({"alg": alg, "typ": "JWT"}).encode())
        pay = b64(_j.dumps(claims).encode())
        mod = {"HS256": _h.sha256, "HS384": _h.sha384}[alg]
        sig = b64(_hm.new(secret.encode(), f"{head}.{pay}".encode(), mod).digest())
        return f"{head}.{pay}.{sig}"

    def test_weak_secret_cracked(self):
        tok = self._jwt("secret", {"user": "bob", "admin": False})
        self.assertEqual(web._jwt_crack_hs(tok), "secret")

    def test_strong_secret_not_cracked(self):
        tok = self._jwt("Zx9!k3jf-a-long-random-256-bit-secret-value", {"user": "bob"})
        self.assertIsNone(web._jwt_crack_hs(tok))

    def test_forged_token_verifies_and_escalates(self):
        import base64 as _b, hashlib as _h, hmac as _hm, json as _j
        tok = self._jwt("changeme", {"user": "bob", "admin": False})
        forged = web._forge_hs(tok, "changeme", {"admin": True})
        h, p, s = forged.split(".")
        exp = _b.urlsafe_b64encode(_hm.new(b"changeme", f"{h}.{p}".encode(),
                                           _h.sha256).digest()).rstrip(b"=").decode()
        self.assertEqual(s, exp)                             # signature valid under the secret
        claims = _j.loads(_b.urlsafe_b64decode(p + "==="))
        self.assertTrue(claims["admin"])                    # escalated claim

    def test_scan_emits_critical_when_cracked(self):
        tok = self._jwt("jwt_secret", {"sub": "u1"})
        p = Port(portid=80, service="http", state="open")
        fs = web._scan_jwts("1.1.1.1", p, {"set-cookie": f"session={tok}; Path=/"}, "")
        crit = [f for f in fs if f.severity == "critical" and "cracked" in f.title]
        self.assertTrue(crit)
        self.assertEqual(crit[0].confidence, "confirmed")


# --------------------------- authenticated auto-login ----------------------------

_LOGIN_FORM = (
    '<html><body><form method="post" action="/login">'
    '<input type="hidden" name="csrf" value="tok123">'
    '<input type="text" name="username">'
    '<input type="password" name="password">'
    '<button type="submit">Login</button></form></body></html>')


class _LoginHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/dashboard"):
            self.send_response(200); self.end_headers()
            self.wfile.write(b"<html>Welcome admin - dashboard</html>")
        else:
            self.send_response(200); self.end_headers()
            self.wfile.write(_LOGIN_FORM.encode())

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        import urllib.parse as up
        data = up.parse_qs(self.rfile.read(n).decode())
        u = (data.get("username") or [""])[0]
        p = (data.get("password") or [""])[0]
        csrf = (data.get("csrf") or [""])[0]
        if u == "admin" and p == "Hunter2map" and csrf == "tok123":
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "session=SESSION123; Path=/")
            self.end_headers()
        else:
            self.send_response(200); self.end_headers()
            self.wfile.write((_LOGIN_FORM + "<p>Invalid credentials</p>").encode())


class AuthenticatedAutoLogin(unittest.TestCase):
    """Auto-login: a harvested credential is submitted to the login form; on success
    the session is used to scan the authenticated surface."""

    def _serve(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LoginHandler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_form_login_finds_session_with_harvested_cred(self):
        srv = self._serve()
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            r = web._fetch("127.0.0.1", p, "/")
            # a wrong cred first, then the real harvested one
            creds = [("wrong", "nope"), ("admin", "Hunter2map")]
            auth, used = web._form_login("127.0.0.1", p, r[2], creds)
        finally:
            srv.shutdown()
        self.assertIsNotNone(auth)
        self.assertEqual(used, ("admin", "Hunter2map"))
        self.assertIn("session=SESSION123", auth.get("Cookie", ""))

    def test_no_login_when_all_creds_wrong(self):
        srv = self._serve()
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            r = web._fetch("127.0.0.1", p, "/")
            auth, used = web._form_login("127.0.0.1", p, r[2],
                                         [("admin", "wrongpw"), ("root", "x")])
        finally:
            srv.shutdown()
        self.assertIsNone(auth)

    def test_autologin_host_helper(self):
        from recce.models import Host
        srv = self._serve()
        try:
            port = srv.server_address[1]
            h = Host(ip="127.0.0.1", up_reason="syn-ack",
                     ports=[Port(portid=port, service="http", state="open")])
            sess = web.autologin(h, [("admin", "Hunter2map")])
        finally:
            srv.shutdown()
        self.assertIsNotNone(sess)
        self.assertEqual(sess["user"], "admin")
        self.assertIn("session=SESSION123", sess["auth"].get("Cookie", ""))


# ------------------------------ OS command injection -----------------------------

class CommandInjection(unittest.TestCase):
    """Output-based cmdi is confirmed by a shell-COMPUTED marker reflection can't fake."""

    def test_output_based_confirmed(self):
        import re

        def send(payload):                                    # a fake shell-backed endpoint
            body = payload
            m = re.search(r"cmdi\$\(\((\d+)\*(\d+)\)\)", payload)
            if m:
                body = payload.replace(m.group(0), "cmdi" + str(int(m.group(1)) * int(m.group(2))))
            return ((200, {}, f"out: {body}"), 0.05)
        p = Port(portid=80, service="http", state="open")
        fs = web._cmdi_via("1.1.1.1", p, "query 'cmd'", "cmd", send)
        self.assertTrue(fs)
        self.assertEqual(fs[0].script_id, "web-cmdi")
        self.assertEqual(fs[0].severity, "critical")
        self.assertEqual(fs[0].confidence, "confirmed")

    def test_reflection_is_not_flagged(self):
        # an endpoint that echoes the LITERAL payload (no shell) must NOT be flagged -
        # the computed marker can only come from real execution.
        def send(payload):
            return ((200, {}, f"echo: {payload}"), 0.05)
        p = Port(portid=80, service="http", state="open")
        self.assertEqual(web._cmdi_via("1.1.1.1", p, "query 'cmd'", "cmd", send), [])


# --------------------------- framework debug exposure ----------------------------

class FrameworkDebugExposure(unittest.TestCase):
    """Exposed debuggers / debug pages: Werkzeug (RCE), Laravel Ignition, Symfony."""

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path.startswith("/_ignition/health-check"):
                self.send_response(200); self.end_headers()
                self.wfile.write(b'{"can_execute_commands":true}')
            elif self.path == "/_profiler":
                self.send_response(200); self.end_headers()
                self.wfile.write(b'<html>Symfony Profiler<div class="sf-toolbar"></div></html>')
            else:
                self.send_response(500); self.end_headers()
                self.wfile.write(b"<title>Werkzeug Debugger</title><div class=__debugger__>x")

    def test_detects_debuggers(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            fs = web._scan_debug("127.0.0.1", p, f"http://127.0.0.1:{port}", None)
        finally:
            srv.shutdown()
        ids = {f.script_id for f in fs}
        self.assertIn("web-werkzeug-debug", ids)      # RCE (critical)
        self.assertIn("web-ignition", ids)            # CVE-2021-3129 (critical)
        self.assertIn("web-symfony-profiler", ids)    # disclosure
        self.assertEqual(next(f for f in fs if f.script_id == "web-werkzeug-debug").severity,
                         "critical")

    def test_clean_server_no_findings(self):
        class Clean(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(404); self.end_headers()
                self.wfile.write(b"<html>Not Found</html>")
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Clean)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            p = Port(portid=srv.server_address[1], service="http", state="open")
            self.assertEqual(web._scan_debug("127.0.0.1", p, "http://x", None), [])
        finally:
            srv.shutdown()


# --------------------------- SSTI engine identification --------------------------

class SstiEngineId(unittest.TestCase):
    """Confirmed SSTI is escalated: identify the engine + give the exact RCE payload."""

    def test_jinja2_identified_critical(self):
        def send(payload):
            b = payload.replace("{{7*7}}", "49").replace("{{7*'7'}}", "7777777")
            return ((200, {}, f"page {b}"), 0.05)
        p = Port(portid=80, service="http", state="open")
        fs = web._reflect_via("1.1.1.1", p, "query 'q'", send)
        self.assertTrue(fs)
        self.assertIn("Jinja2", fs[0].title)
        self.assertEqual(fs[0].severity, "critical")
        self.assertIn("popen", fs[0].output)             # the concrete RCE payload

    def test_twig_identified(self):
        def send(payload):
            # Twig: {{7*7}}->49 and {{7*'7'}}->49 (numeric coercion)
            b = payload.replace("{{7*7}}", "49").replace("{{7*'7'}}", "49")
            return ((200, {}, f"page {b}"), 0.05)
        p = Port(portid=80, service="http", state="open")
        fs = web._reflect_via("1.1.1.1", p, "query 'q'", send)
        self.assertIn("Twig", fs[0].title)

    def test_unknown_engine_stays_high_generic(self):
        def send(payload):
            return ((200, {}, payload.replace("{{7*7}}", "49")), 0.05)
        p = Port(portid=80, service="http", state="open")
        fs = web._reflect_via("1.1.1.1", p, "query 'q'", send)
        self.assertEqual(fs[0].severity, "high")
        self.assertNotIn("—", fs[0].title)


# --------------------------- NoSQL auth bypass -----------------------------------

class NoSqlAuthBypass(unittest.TestCase):
    """MongoDB-style operator injection on a login form logs in without credentials."""

    _FORM = ('<form method="post" action="/login">'
             '<input type="text" name="username">'
             '<input type="password" name="password"><button>Login</button></form>')

    def _make(self, vulnerable):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200); self.end_headers()
                self.wfile.write(outer._FORM.encode())

            def do_POST(self):
                import json as _j
                n = int(self.headers.get("content-length", 0))
                raw = self.rfile.read(n).decode()
                hit = False
                if vulnerable and "json" in self.headers.get("content-type", ""):
                    try:
                        d = _j.loads(raw)
                        hit = isinstance(d.get("username"), dict) or isinstance(d.get("password"), dict)
                    except Exception:
                        hit = False
                if hit:
                    self.send_response(302); self.send_header("Location", "/home")
                    self.send_header("Set-Cookie", "sess=OK"); self.end_headers()
                else:
                    self.send_response(200); self.end_headers()
                    self.wfile.write((outer._FORM + "<p>Invalid credentials</p>").encode())
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_json_operator_bypass_confirmed(self):
        srv = self._make(vulnerable=True)
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            body = web._fetch("127.0.0.1", p, "/")[2]
            fs = web._scan_nosql("127.0.0.1", p, f"http://127.0.0.1:{port}", body, None)
        finally:
            srv.shutdown()
        self.assertTrue(fs)
        self.assertEqual(fs[0].script_id, "web-nosqli")
        self.assertEqual(fs[0].severity, "critical")

    def test_non_vulnerable_not_flagged(self):
        srv = self._make(vulnerable=False)
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            body = web._fetch("127.0.0.1", p, "/")[2]
            self.assertEqual(web._scan_nosql("127.0.0.1", p, "http://x", body, None), [])
        finally:
            srv.shutdown()


# --------------------------------- XXE -------------------------------------------

class XxeFileRead(unittest.TestCase):
    """XXE is confirmed only when the referenced file's content comes back (zero-FP)."""

    def _make(self, vulnerable):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(200); self.end_headers(); self.wfile.write(b"<html/>")

            def do_POST(self):
                n = int(self.headers.get("content-length", 0))
                raw = self.rfile.read(n).decode()
                self.send_response(200); self.end_headers()
                if vulnerable and "file:///etc/passwd" in raw and self.path == "/api":
                    self.wfile.write(b"<r>root:x:0:0:root:/root:/bin/bash</r>")
                else:
                    self.wfile.write(b"<ok/>")            # entity NOT resolved (echoes nothing)
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_confirmed_file_read(self):
        srv = self._make(vulnerable=True)
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            fs = web._scan_xxe("127.0.0.1", p, f"http://127.0.0.1:{port}", None)
        finally:
            srv.shutdown()
        self.assertTrue(fs)
        self.assertEqual(fs[0].script_id, "web-xxe")
        self.assertEqual(fs[0].severity, "critical")

    def test_no_entity_resolution_not_flagged(self):
        srv = self._make(vulnerable=False)
        try:
            p = Port(portid=srv.server_address[1], service="http", state="open")
            self.assertEqual(web._scan_xxe("127.0.0.1", p, "http://x", None), [])
        finally:
            srv.shutdown()


# --------------------------- CSP + subdomain takeover ----------------------------

class CspAnalysis(unittest.TestCase):
    def test_weak_csp_flagged_medium(self):
        p = Port(portid=80, service="http", state="open")
        fs = web._csp_findings("1.1.1.1", p, {
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' *"})
        self.assertTrue(fs and fs[0].script_id == "web-csp")
        self.assertEqual(fs[0].severity, "medium")
        self.assertIn("unsafe-inline", fs[0].output)
        self.assertIn("wildcard", fs[0].output)

    def test_strong_csp_clean(self):
        p = Port(portid=80, service="http", state="open")
        self.assertEqual(web._csp_findings("1.1.1.1", p, {
            "content-security-policy":
            "default-src 'none'; script-src 'self' 'nonce-x'; object-src 'none'; base-uri 'self'"}), [])

    def test_missing_csp_not_here(self):
        p = Port(portid=80, service="http", state="open")
        self.assertEqual(web._csp_findings("1.1.1.1", p, {}), [])   # handled by header audit


class SubdomainTakeover(unittest.TestCase):
    def test_fingerprints(self):
        self.assertEqual(web._takeover_service("There isn't a GitHub Pages site here."),
                         "GitHub Pages")
        self.assertEqual(web._takeover_service("<Error><Code>NoSuchBucket</Code></Error>"),
                         "AWS S3")
        self.assertEqual(web._takeover_service("<h1>Welcome to my blog</h1>"), "")

    def test_takeover_finding_shape(self):
        p = Port(portid=80, service="http", state="open")
        f = web._takeover_finding("1.1.1.1", p, "http://x", "sub.acme.com", "Heroku")
        self.assertEqual(f.script_id, "web-takeover")
        self.assertEqual(f.severity, "high")
        self.assertIn("sub.acme.com", f.output)


# --------------------- JWT RS256->HS256 algorithm confusion ----------------------

class JwtAlgConfusion(unittest.TestCase):
    """From an RS256 JWT + the server's JWKS, mint a forged HS256 token that uses the
    RSA public key as the HMAC secret (RS256->HS256 confusion)."""

    _N = ("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFx"
          "uhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_"
          "RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQv"
          "RL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_"
          "xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")

    def _jwt_rs256(self):
        import base64 as _b, json as _j
        def b64(x): return _b.urlsafe_b64encode(x).rstrip(b"=").decode()
        h = b64(_j.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        p = b64(_j.dumps({"sub": "bob", "admin": False}).encode())
        return f"{h}.{p}.fakesignature"

    class _JwksHandler(http.server.BaseHTTPRequestHandler):
        N = None

        def log_message(self, *a):
            pass

        def do_GET(self):
            if "jwks" in self.path:
                self.send_response(200)
                self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(('{"keys":[{"kty":"RSA","kid":"1","n":"%s","e":"AQAB"}]}'
                                  % self.N).encode())
            else:
                self.send_response(404); self.end_headers()

    def _serve(self):
        handler = type("H", (self._JwksHandler,), {"N": self._N})
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_forge_signs_with_reconstructed_pubkey(self):
        import base64 as _b, hashlib as _h, hmac as _hm, json as _j
        pem = web._rsa_pubkey_pem(web._b64url_uint(self._N), web._b64url_uint("AQAB"))
        forged = web._forge_alg_confusion(self._jwt_rs256(), pem)
        h, p, s = forged.split(".")
        exp = _b.urlsafe_b64encode(_hm.new(pem.encode(), f"{h}.{p}".encode(),
                                           _h.sha256).digest()).rstrip(b"=").decode()
        self.assertEqual(s, exp)                                  # signed with the pubkey PEM
        self.assertTrue(_j.loads(_b.urlsafe_b64decode(p + "==="))["admin"])   # escalated

    def test_scan_mints_forged_token(self):
        srv = self._serve()
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            tok = self._jwt_rs256()
            fs = web._scan_jwts("127.0.0.1", p, {"set-cookie": f"jwt={tok}"}, "",
                                active=False)
        finally:
            srv.shutdown()
        conf = [f for f in fs if "algorithm-confusion" in f.title.lower()
                or "algorithm confusion" in f.title.lower()]
        self.assertTrue(conf, "no alg-confusion finding emitted")
        self.assertIn("orged", conf[0].output)                   # forged token in evidence


# --------------------- CORS null-origin + GraphQL batching/suggestion -------------

class CorsGraphqlDeep(unittest.TestCase):
    """Null-Origin CORS acceptance, GraphQL query batching, and field-suggestion
    schema leak (introspection disabled)."""

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=b"", extra=None):
            self.send_response(code)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            origin = self.headers.get("Origin", "")
            extra = {"Content-Type": "text/html"}
            if origin == "null":                       # reflect null + credentials
                extra["Access-Control-Allow-Origin"] = "null"
                extra["Access-Control-Allow-Credentials"] = "true"
            self._send(200, b"<html><title>app</title></html>", extra)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode("utf-8", "replace")
            if self.path != "/graphql":
                self._send(404); return
            if raw.startswith("["):                    # batching: array in, array out
                self._send(200, b'[{"data":{"__typename":"Query"}},'
                                b'{"data":{"__typename":"Query"}}]',
                           {"Content-Type": "application/json"}); return
            if "__schema" in raw:                      # introspection disabled
                self._send(400, b'{"errors":[{"message":"introspection disabled"}]}',
                           {"Content-Type": "application/json"}); return
            if "__typenamee" in raw:                   # field-suggestion leak
                self._send(400, b'{"errors":[{"message":"Cannot query field '
                                b'\\"__typenamee\\". Did you mean \\"__typename\\"?"}]}',
                           {"Content-Type": "application/json"}); return
            self._send(200, b'{"data":{"__typename":"Query"}}',
                       {"Content-Type": "application/json"})

    def test_cors_null_and_graphql(self):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            _profile, fs = web.scan_endpoint("127.0.0.1", p, active=True)
        finally:
            srv.shutdown()
        titles = [f.title.lower() for f in fs]
        self.assertTrue(any("null origin" in t for t in titles), titles)
        self.assertTrue(any("batching" in t for t in titles), titles)
        self.assertTrue(any("field-suggestion" in t for t in titles), titles)
        # every one still gets a prove verdict (web-exposure recipe)
        from recce import proofs
        for f in fs:
            if f.script_id in ("web-cors", "web-graphql", "web-graphql-batch"):
                self.assertIsNotNone(proofs.recipe_for(f), f.title)


# --------------------- Insecure deserialization markers --------------------------

class DeserialMarkers(unittest.TestCase):
    """Java / PHP / .NET-ViewState serialized-object markers in cookies & fields."""

    def _p(self):
        return Port(portid=8080, service="http", state="open")

    def test_java_in_cookie(self):
        h = {"set-cookie": "session=rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA; Path=/"}
        fs = web._scan_deserial("127.0.0.1", self._p(), h, "")
        self.assertTrue(any(f.script_id == "web-deserial" and "Java" in f.title for f in fs))
        self.assertEqual(fs[0].severity, "high")

    def test_php_object_in_cookie(self):
        h = {"set-cookie": 'data=O:4:"User":1:{s:4:"name";s:3:"bob";}; Path=/'}
        fs = web._scan_deserial("127.0.0.1", self._p(), h, "")
        self.assertTrue(any("PHP serialized object" in f.title for f in fs))

    def test_unencrypted_viewstate(self):
        import base64 as _b
        vs = _b.b64encode(b"\xff\x01\x0f\x0fpayloaddata").decode()
        body = f'<form><input type="hidden" name="__VIEWSTATE" value="{vs}" /></form>'
        fs = web._scan_deserial("127.0.0.1", self._p(), {}, body)
        self.assertTrue(any("ViewState is not encrypted" in f.title for f in fs))
        self.assertEqual(fs[0].severity, "medium")

    def test_encrypted_viewstate_not_flagged(self):
        import base64 as _b
        vs = _b.b64encode(b"\x00\x01encryptedopaqueblob").decode()   # no FF 01 marker
        body = f'<input name="__VIEWSTATE" value="{vs}" />'
        fs = web._scan_deserial("127.0.0.1", self._p(), {}, body)
        self.assertEqual(fs, [])

    def test_clean_no_markers(self):
        h = {"set-cookie": "sessionid=abc123def456; HttpOnly"}
        fs = web._scan_deserial("127.0.0.1", self._p(), h, "<html>ok</html>")
        self.assertEqual(fs, [])

    def test_every_marker_has_prove_recipe(self):
        from recce import proofs
        for title in ("Java serialized object in client-controllable data",
                      "PHP serialized object in client-controllable data",
                      "ASP.NET ViewState is not encrypted"):
            v = Vuln(ip="1.1.1.1", port=8080, protocol="tcp", script_id="web-deserial",
                     title=title, output="")
            r = proofs.recipe_for(v)
            self.assertIsNotNone(r, title)
            self.assertEqual(r["id"], "web-deserial")


# --------------------- Web cache poisoning (unkeyed header) ----------------------

class CachePoison(unittest.TestCase):
    """Unkeyed X-Forwarded-Host reflected into a cacheable response = poisonable."""

    class _Vuln(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            xfh = self.headers.get("X-Forwarded-Host", "localhost")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "public, max-age=60")
            self.send_header("X-Cache", "miss")
            self.end_headers()
            self.wfile.write(f'<script src="https://{xfh}/app.js"></script>'.encode())

    class _Safe(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            xfh = self.headers.get("X-Forwarded-Host", "localhost")   # reflects...
            self.send_response(200)
            self.send_header("Cache-Control", "no-store, private")    # ...but not cacheable
            self.end_headers()
            self.wfile.write(f'<a href="https://{xfh}/">home</a>'.encode())

    def _run(self, handler):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            return web._scan_cache_poison("127.0.0.1", p, None)
        finally:
            srv.shutdown()

    def test_reflected_and_cacheable_flags(self):
        fs = self._run(self._Vuln)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].script_id, "web-cache-poison")
        self.assertEqual(fs[0].severity, "high")
        self.assertIn("CWE-349", fs[0].cwes)
        from recce import proofs
        self.assertEqual(proofs.recipe_for(fs[0])["id"], "web-cache-poison")

    def test_reflected_but_not_cacheable_no_finding(self):
        self.assertEqual(self._run(self._Safe), [])


# --------------------- File upload -> webshell (gated proof) ----------------------

_UPLOAD_FORM = (b'<html><body><form method="post" enctype="multipart/form-data" '
                b'action="/upload"><input type="hidden" name="csrf" value="tok123">'
                b'<input type="file" name="f"><input type="submit"></form></body></html>')


class UploadShell(unittest.TestCase):
    """--upload-shell: benign server-computed-marker payload proves RCE end to end."""

    class _Exec(http.server.BaseHTTPRequestHandler):
        store: dict = {}

        def log_message(self, *a):
            pass

        def do_GET(self):
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html"); self.end_headers()
                self.wfile.write(_UPLOAD_FORM); return
            fn = self.path.rsplit("/", 1)[-1]
            if self.path.startswith("/uploads/") and fn in self.store:
                payload = self.store[fn]
                self.send_response(200); self.end_headers()
                if fn.rsplit(".", 1)[-1] in ("php", "phtml", "php5", "pht"):
                    # Simulate the PHP engine: echo tag + (7*7), never the source.
                    m = re.search(r"echo '([^']+)'\.\(7\*7\)", payload)
                    self.wfile.write((m.group(1) + "49").encode() if m else b"")
                else:
                    self.wfile.write(payload.encode())        # served verbatim
                return
            self.send_response(404); self.end_headers()

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n).decode("latin-1")
            fm = re.search(r'filename="([^"]+)"', raw)
            cm = re.search(r'filename="[^"]+"\r\nContent-Type:[^\r]*\r\n\r\n(.*?)\r\n------',
                           raw, re.S)
            if fm and cm:
                self.store[fm.group(1)] = cm.group(1)
                self.send_response(200); self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"Saved to /uploads/{fm.group(1)}".encode()); return
            self.send_response(400); self.end_headers()

    class _StoreOnly(_Exec):
        def do_GET(self):                                     # serves .php verbatim (no exec)
            if self.path == "/":
                self.send_response(200); self.end_headers(); self.wfile.write(_UPLOAD_FORM)
                return
            fn = self.path.rsplit("/", 1)[-1]
            if self.path.startswith("/uploads/") and fn in self.store:
                self.send_response(200); self.end_headers()
                self.wfile.write(self.store[fn].encode()); return
            self.send_response(404); self.end_headers()

    def _run(self, handler, **kw):
        handler.store = {}
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            p = Port(portid=port, service="http", state="open")
            base = web.url_for("127.0.0.1", p)
            return web._scan_upload("127.0.0.1", p, base, _UPLOAD_FORM.decode(), None, **kw)
        finally:
            srv.shutdown()

    def test_lead_only_without_prove(self):
        fs = self._run(self._Exec, prove=False)
        self.assertEqual([f.script_id for f in fs], ["web-upload-form"])
        self.assertEqual(fs[0].confidence, "potential")

    def test_rce_confirmed_with_prove(self):
        fs = self._run(self._Exec, prove=True)
        rce = [f for f in fs if f.script_id == "web-upload-rce"]
        self.assertTrue(rce, [f.script_id for f in fs])
        self.assertEqual(rce[0].severity, "critical")
        self.assertEqual(rce[0].confidence, "confirmed")
        from recce import proofs
        self.assertEqual(proofs.recipe_for(rce[0])["fn"](None, 80, rce[0])[0], "CONFIRMED")

    def test_stored_not_executed_is_medium(self):
        fs = self._run(self._StoreOnly, prove=True)
        up = [f for f in fs if f.script_id == "web-upload"]
        self.assertTrue(up, [f.script_id for f in fs])
        self.assertEqual(up[0].severity, "medium")

    def test_no_form_no_finding(self):
        p = Port(portid=8080, service="http", state="open")
        self.assertEqual(web._scan_upload("127.0.0.1", p, "http://x", "<html>hi</html>",
                                          None, prove=True), [])


# --------------------- HTTP request smuggling (gated timing probe) ----------------

class SmuggleTiming(unittest.TestCase):
    """CL.TE/TE.CL timing probe: a request bearing both CL and TE stalls; control is fast."""

    def _server(self, stall_on_te: bool):
        import socketserver

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request.recv(4096)
                if stall_on_te and b"Transfer-Encoding" in data:
                    time.sleep(3.0)                          # never answer promptly
                self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

        srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def test_stall_flags_smuggling(self):
        srv = self._server(stall_on_te=True)
        try:
            p = Port(portid=srv.server_address[1], service="http", state="open")
            fs = web._scan_smuggle("127.0.0.1", p, timeout=2.0)
        finally:
            srv.shutdown()
        self.assertTrue(any(f.script_id == "web-smuggle" for f in fs), [f.title for f in fs])
        self.assertEqual(fs[0].severity, "high")

    def test_fast_server_not_flagged(self):
        srv = self._server(stall_on_te=False)                # answers everything promptly
        try:
            p = Port(portid=srv.server_address[1], service="http", state="open")
            fs = web._scan_smuggle("127.0.0.1", p, timeout=2.0)
        finally:
            srv.shutdown()
        self.assertEqual(fs, [])
