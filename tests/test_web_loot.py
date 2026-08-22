"""Plaintext credential loot from exposed web config/secret files.

Unlike a DB hash, an embedded .git/config token, a .env DB password, or an .aws
key pair is cleartext and directly sprayable, so recce lifts it into the credential
store. These tests exercise the real extractor (`_web_credentials`) and the full
`scan_endpoint` path against a live stdlib HTTP server serving the leaked files.
"""
from __future__ import annotations

import http.server
import shutil
import subprocess
import threading
import unittest
from pathlib import Path

from recce import web
from recce.models import Port


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
