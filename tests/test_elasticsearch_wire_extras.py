"""Three elasticsearch capability gaps the audit flagged critical:

  * _get() now honours an Authorization header derived from analyze()'s creds
    (HTTP Basic per ES Reference "Basic authentication"; ApiKey / Bearer per
    "API keys"). Previously creds were dropped on the floor.
  * A 401 on / no longer means "secured, stop": probe() now hits
    /_security/_authenticate and, if the effective username is "_anonymous"
    (or authentication_type == "anonymous"), raises the es_anonymous finding.
  * /_snapshot/_all already returns each repository's type + settings block
    (bucket / endpoint / base_path for repository-s3, container for -azure,
    location for -fs, ...) — those cloud-storage pivot pointers are now
    captured on the probe and folded into the es_unauth finding detail.

The fake servers speak enough of the ES HTTP API to exercise each new branch.
"""
from __future__ import annotations

import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from recce.core.models import Host, Port
from recce.services.db import elasticsearch as es


def _http_server(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _host(port: int) -> Host:
    return Host(ip="127.0.0.1",
                ports=[Port(portid=port, service="elasticsearch", state="open")])


# ================================ _auth_headers ==============================


class AuthHeaders(unittest.TestCase):
    """`_auth_headers()` translates recce cred dicts into ES Authorization values."""

    def test_basic_from_username_password(self):
        h = es._auth_headers({"username": "elastic", "password": "changeme"})
        expected = "Basic " + base64.b64encode(b"elastic:changeme").decode()
        self.assertEqual(h["Authorization"], expected)

    def test_basic_accepts_user_pass_aliases(self):
        h = es._auth_headers({"user": "kibana_system", "pass": "s3cret"})
        self.assertTrue(h["Authorization"].startswith("Basic "))
        raw = base64.b64decode(h["Authorization"].split(" ", 1)[1])
        self.assertEqual(raw, b"kibana_system:s3cret")

    def test_apikey_id_secret_form_is_base64_encoded(self):
        h = es._auth_headers({"api_key": "myid:mysecret"})
        self.assertEqual(
            h["Authorization"],
            "ApiKey " + base64.b64encode(b"myid:mysecret").decode())

    def test_apikey_bare_token_passes_through(self):
        h = es._auth_headers({"api_key": "alreadyb64token"})
        # Bare token (no ':' -> presumed pre-encoded) is sent verbatim.
        self.assertEqual(h["Authorization"], "ApiKey alreadyb64token")

    def test_bearer_takes_precedence(self):
        h = es._auth_headers({"bearer": "abc", "username": "u", "password": "p"})
        self.assertEqual(h["Authorization"], "Bearer abc")

    def test_missing_or_bad_creds_yield_empty(self):
        self.assertEqual(es._auth_headers(None), {})
        self.assertEqual(es._auth_headers({}), {})
        self.assertEqual(es._auth_headers({"password": "only"}), {})
        self.assertEqual(es._auth_headers("not a dict"), {})  # type: ignore[arg-type]


# ============================ _get() Authorization ==========================


class GetSendsAuthorization(unittest.TestCase):
    """`_get(..., headers=...)` merges the Authorization header over the default
    Accept / User-Agent so credentialed calls actually reach the wire. Regression
    test for the "creds dropped on the floor" gap."""

    def setUp(self):
        seen: list[str] = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                seen.append(self.headers.get("Authorization", ""))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

        self.seen = seen
        self.srv, self.port = _http_server(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_headers_kwarg_reaches_wire(self):
        auth = "Basic " + base64.b64encode(b"elastic:x").decode()
        es._get("127.0.0.1", self.port, "/", tls=False,
                headers={"Authorization": auth})
        self.assertEqual(self.seen[-1], auth)

    def test_probe_passes_creds_through(self):
        hdrs = es._auth_headers({"username": "elastic", "password": "changeme"})
        es.probe("127.0.0.1", self.port, headers=hdrs)
        # /'s GET should carry the Authorization header (first request).
        self.assertTrue(self.seen[0].startswith("Basic "),
                        f"expected Basic auth on first GET, saw {self.seen!r}")

    def test_no_creds_sends_no_authorization(self):
        es._get("127.0.0.1", self.port, "/", tls=False)
        self.assertEqual(self.seen[-1], "")


# ==================== /_security/_authenticate anonymous role ===============


class AnonymousRoleDetection(unittest.TestCase):
    """A cluster that answers 401 on / but 200 on /_security/_authenticate with
    username '_anonymous' is *not* secured — xpack.security.authc.anonymous.roles
    is granting a role to every unauthenticated request. Previously scored as
    'secured', now surfaces as es_anonymous."""

    def setUp(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/":
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"security_exception"}')
                elif self.path == "/_security/_authenticate":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "username": "_anonymous",
                        "authentication_type": "anonymous",
                        "roles": ["anonymous_read"],
                    }).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

        self.srv, self.port = _http_server(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_probe_flags_anonymous(self):
        pr = es.probe("127.0.0.1", self.port)
        # Still "secured" (401 on /) BUT anonymous access is active.
        self.assertTrue(pr.get("secured"))
        self.assertTrue(pr.get("anonymous"))
        self.assertEqual(pr.get("anonymous_username"), "_anonymous")
        self.assertIn("anonymous_read", pr.get("anonymous_roles") or [])

    def test_finding_emitted(self):
        pr = es.probe("127.0.0.1", self.port)
        fs = es.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("es_anonymous", kinds)
        anon = [f for f in fs if f["kind"] == "es_anonymous"][0]
        self.assertEqual(anon["severity"], "high")
        self.assertIn("_anonymous", anon["detail"])
        self.assertIn("anonymous_read", anon["detail"])


class NoAnonymousWhenAuthTypeReal(unittest.TestCase):
    """A cluster whose /_security/_authenticate returns a real username must not
    trip the anonymous branch (guards against false positives when creds slipped
    through some other layer)."""

    def setUp(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/":
                    self.send_response(401)
                    self.end_headers()
                elif self.path == "/_security/_authenticate":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "username": "elastic",
                        "authentication_type": "realm",
                        "roles": ["superuser"],
                    }).encode())
                else:
                    self.send_response(404)
                    self.end_headers()

        self.srv, self.port = _http_server(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_no_anonymous_flag(self):
        pr = es.probe("127.0.0.1", self.port)
        self.assertTrue(pr.get("secured"))
        self.assertFalse(pr.get("anonymous"))


# =========================== snapshot repo settings =========================


class SnapshotRepoSettings(unittest.TestCase):
    """/_snapshot/_all inline settings block gets lifted into a structured
    snapshot_repo_settings dict and folded into the es_unauth finding detail —
    the cloud-storage / SMB pivot pointer."""

    def setUp(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _j(self, obj, status=200):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(obj).encode())

            def do_GET(self):
                if self.path == "/":
                    self._j({"name": "es01", "cluster_name": "prod",
                             "version": {"number": "7.10.0"},
                             "tagline": "You Know, for Search"})
                elif self.path.startswith("/_cat/indices"):
                    self._j([{"index": "orders", "docs.count": "42"}])
                elif self.path == "/_cluster/health":
                    self._j({"status": "green", "number_of_nodes": 1})
                elif self.path.startswith("/_nodes/_local"):
                    self._j({"nodes": {"n": {"os": {"pretty_name": "RHEL 8"},
                                             "jvm": {"version": "17"}}}})
                elif self.path == "/_snapshot/_all":
                    # Wire shape per ES Reference "Snapshot and Restore":
                    # {name: {type, settings, uuid}}
                    self._j({
                        "s3_backups": {
                            "type": "s3",
                            "settings": {
                                "bucket": "prod-es-snaps",
                                "endpoint": "s3.us-east-1.amazonaws.com",
                                "region": "us-east-1",
                                "base_path": "cluster-a",
                                "client": "default",
                            },
                        },
                        "local_fs": {
                            "type": "fs",
                            "settings": {"location": "/mnt/nfs/es-snaps",
                                         "compress": True},
                        },
                    })
                else:
                    self.send_response(404)
                    self.end_headers()

        self.srv, self.port = _http_server(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_settings_lifted_from_all_response(self):
        pr = es.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        rs = pr.get("snapshot_repo_settings") or {}
        self.assertIn("s3_backups", rs)
        s3 = rs["s3_backups"]
        self.assertEqual(s3["type"], "s3")
        self.assertEqual(s3["settings"]["bucket"], "prod-es-snaps")
        self.assertEqual(s3["settings"]["endpoint"], "s3.us-east-1.amazonaws.com")
        self.assertEqual(s3["settings"]["base_path"], "cluster-a")
        fs_repo = rs["local_fs"]
        self.assertEqual(fs_repo["type"], "fs")
        self.assertEqual(fs_repo["settings"]["location"], "/mnt/nfs/es-snaps")
        # Backwards-compat: the old repo-name list is still populated.
        self.assertIn("s3_backups", pr.get("snapshot_repos") or [])

    def test_finding_detail_includes_pivot_pointers(self):
        pr = es.probe("127.0.0.1", self.port)
        fs = es.findings([_host(self.port)], {("127.0.0.1", self.port): pr})
        unauth = [f for f in fs if f["kind"] == "es_unauth"][0]
        d = unauth["detail"]
        self.assertIn("Snapshot repo config", d)
        self.assertIn("prod-es-snaps", d)
        self.assertIn("s3.us-east-1.amazonaws.com", d)
        self.assertIn("/mnt/nfs/es-snaps", d)


if __name__ == "__main__":
    unittest.main()
