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
