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
