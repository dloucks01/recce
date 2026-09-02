"""Tests for recce.services.minio.

Fixtures model the real MinIO / S3 wire protocol:
  * GET  /minio/health/live         -> 200 empty, Server: MinIO[/RELEASE...]
  * GET  /                          -> XML <ListAllMyBucketsResult> (public)
                                       OR XML <Error><Code>AccessDenied</Code>
                                       (locked). AWS4-signed variant with
                                       admin cred returns the listing.
  * POST /minio/bootstrap/v1/verify -> 200 JSON {"Env":{"MINIO_ROOT_USER":
                                       "minioadmin", ...}} on pre-fix builds

Every test uses a real background HTTP server bound to 127.0.0.1:0.
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import minio


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass


_BUCKET_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    '<Owner><ID>02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4</ID>'
    '<DisplayName>minio</DisplayName></Owner>'
    '<Buckets>'
    '<Bucket><Name>backups</Name><CreationDate>2024-01-01T00:00:00Z</CreationDate></Bucket>'
    '<Bucket><Name>images</Name><CreationDate>2024-01-02T00:00:00Z</CreationDate></Bucket>'
    '<Bucket><Name>logs</Name><CreationDate>2024-01-03T00:00:00Z</CreationDate></Bucket>'
    '</Buckets>'
    '</ListAllMyBucketsResult>'
)

_ACCESS_DENIED_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Error><Code>AccessDenied</Code><Message>Access Denied.</Message>'
    '<Resource>/</Resource><RequestId>x</RequestId>'
    '<HostId>minio-host-id</HostId></Error>'
)


def _send(handler, status, body, ctype="application/xml", extra_headers=None):
    body_b = body.encode("utf-8") if isinstance(body, str) else body
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body_b)))
    for k, v in (extra_headers or {}).items():
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body_b)


def _make_handler(server_header="MinIO",
                  public_listing=False,
                  accept_default_cred=False,
                  cve_leak=False,
                  block_health=False):
    """Compose a MinIO-like server.

    `server_header`         — value sent in Server on /minio/health/live.
    `public_listing`        — GET / returns the bucket XML without auth.
    `accept_default_cred`   — an AWS4 Authorization header with the
                              minioadmin access key returns the bucket
                              listing.
    `cve_leak`              — POST /minio/bootstrap/v1/verify returns the
                              env dict (CVE-2023-28432).
    `block_health`          — /minio/health/live returns 403 so the XML
                              fingerprint fallback is exercised.
    """

    class H(_Base):
        def do_GET(self):
            if self.path == "/minio/health/live":
                if block_health:
                    self.send_response(403); self.end_headers(); return
                self.send_response(200)
                self.send_header("Server", server_header)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/":
                auth = self.headers.get("Authorization", "")
                is_admin = (accept_default_cred and auth.startswith(
                    "AWS4-HMAC-SHA256")
                    and f"Credential={minio._DEFAULT_ADMIN_USER}/" in auth)
                if is_admin or public_listing:
                    _send(self, 200, _BUCKET_XML,
                          extra_headers={"Server": server_header})
                else:
                    _send(self, 403, _ACCESS_DENIED_XML,
                          extra_headers={"Server": server_header})
                return
            self.send_response(404); self.end_headers()

        def do_POST(self):
            if self.path == "/minio/bootstrap/v1/verify":
                if cve_leak:
                    body = json.dumps({"Env": {
                        "MINIO_ROOT_USER": "minioadmin",
                        "MINIO_ROOT_PASSWORD": "minioadmin",
                        "MINIO_KMS_MASTER_KEY": "my-minio-key:xxxx",
                    }})
                    _send(self, 200, body, ctype="application/json")
                else:
                    self.send_response(403); self.end_headers()
                return
            self.send_response(404); self.end_headers()

    return H


class ProbeTest(unittest.TestCase):

    def test_open_minio_full_disclosure(self):
        """Default MinIO with minioadmin still active + public root
        listing + CVE-2023-28432 env leak — the classic 'walk-in' box.
        Every risky finding should fire."""
        srv, _t = _serve(_make_handler(
            server_header="MinIO/RELEASE.2022-05-04T07-45-27Z",
            public_listing=True, accept_default_cred=True, cve_leak=True))
        try:
            p = minio.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "RELEASE.2022-05-04T07-45-27Z")
        self.assertTrue(p["anonymous_listing"])
        self.assertEqual(p["bucket_count"], 3)
        self.assertIn("backups", p["buckets"])
        self.assertTrue(p["default_admin_creds"])
        self.assertEqual(p["default_creds_status"], 200)
        self.assertTrue(p["cve_2023_28432"])
        self.assertEqual(p["cve_root_user"], "minioadmin")
        self.assertTrue(p["cve_has_root_secret"])

    def test_hardened_minio_no_default_cred_no_public_root_no_cve(self):
        """A hardened MinIO: default cred rejected, / access-denied,
        bootstrap endpoint 403. Fingerprint fires but risky findings
        do not."""
        srv, _t = _serve(_make_handler(
            server_header="MinIO/RELEASE.2024-01-16T16-07-38Z",
            public_listing=False, accept_default_cred=False, cve_leak=False))
        try:
            p = minio.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "RELEASE.2024-01-16T16-07-38Z")
        self.assertFalse(p["anonymous_listing"])
        self.assertFalse(p["default_admin_creds"])
        self.assertFalse(p["cve_2023_28432"])

    def test_default_cred_probe_is_single_shot(self):
        """Safety guarantee: the default-cred probe sends EXACTLY ONE
        AWS4-signed GET / with the minioadmin access key."""
        signed_hits: list = []

        class H(_Base):
            def do_GET(self):
                if self.path == "/minio/health/live":
                    self.send_response(200)
                    self.send_header("Server", "MinIO")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/":
                    auth = self.headers.get("Authorization", "")
                    if auth.startswith("AWS4-HMAC-SHA256"):
                        signed_hits.append(auth)
                        _send(self, 403, _ACCESS_DENIED_XML,
                              extra_headers={"Server": "MinIO"})
                    else:
                        _send(self, 403, _ACCESS_DENIED_XML,
                              extra_headers={"Server": "MinIO"})
                    return
                self.send_response(404); self.end_headers()

            def do_POST(self):
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        try:
            minio.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        # Exactly one signed request, and it MUST reference minioadmin.
        self.assertEqual(len(signed_hits), 1)
        self.assertIn(f"Credential={minio._DEFAULT_ADMIN_USER}/",
                      signed_hits[0])
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date",
                      signed_hits[0])

    def test_cve_2023_28432_fingerprint_gated_on_env_dict(self):
        """CVE finding only fires when the bootstrap endpoint actually
        leaks the env — a 200 with an unrelated body does NOT fire."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/minio/health/live":
                    self.send_response(200)
                    self.send_header("Server", "MinIO")
                    self.send_header("Content-Length", "0")
                    self.end_headers(); return
                if self.path == "/":
                    _send(self, 403, _ACCESS_DENIED_XML,
                          extra_headers={"Server": "MinIO"}); return
                self.send_response(404); self.end_headers()

            def do_POST(self):
                if self.path == "/minio/bootstrap/v1/verify":
                    _send(self, 200, '{"ok":true}',
                          ctype="application/json"); return
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = minio.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["cve_2023_28432"])

    def test_xml_fingerprint_fallback_when_health_blocked(self):
        """/minio/health/live can be gated behind a fronting proxy;
        the S3 XML error grammar on GET / still tells us this is
        MinIO — probe must catch it and mark reachable=True (though
        version will be empty when Server isn't set)."""
        srv, _t = _serve(_make_handler(
            server_header="", block_health=True, public_listing=False))
        try:
            p = minio.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["default_admin_creds"])

    def test_non_minio_service_not_flagged(self):
        """A generic 200 without MinIO Server header AND without the
        S3 XML grammar must NOT be flagged."""
        class H(_Base):
            def do_GET(self):
                _send(self, 200, "<html>hi</html>", ctype="text/html")

            def do_POST(self):
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = minio.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p["reachable"])

    def test_dead_port_returns_all_false(self):
        p = minio.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])
        self.assertFalse(p["default_admin_creds"])
        self.assertFalse(p["cve_2023_28432"])
        self.assertFalse(p["anonymous_listing"])


class FindingsTest(unittest.TestCase):
    """Finding-emission wiring for the emitted kinds."""

    def _host_with_probe(self, probe_dict, port=9000):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.9", ports=[Port(portid=port, state="open",
                                             service="minio")])
        probes = {("10.0.0.9", port):
                  {"reachable": True,
                   "version": "RELEASE.2024-01-16T16-07-38Z",
                   **probe_dict}}
        return [h], probes

    def test_reachable_and_version_always_fire(self):
        hosts, probes = self._host_with_probe({})
        fs = minio.findings(hosts, probes)
        kinds = {f.get("kind") for f in fs}
        self.assertIn("minio_reachable", kinds)
        self.assertIn("minio_version", kinds)
        self.assertNotIn("minio_default_creds_admin", kinds)
        self.assertNotIn("minio_anonymous_root", kinds)
        self.assertNotIn("minio_cve_2023_28432", kinds)
        for f in fs:
            self.assertIn("kind", f)
            self.assertIn("severity", f)
            self.assertIn("depth_tier", f)
            self.assertIn("exploit_note", f)
            self.assertIn("cwes", f)

    def test_default_creds_finding_wire_format(self):
        hosts, probes = self._host_with_probe({
            "default_admin_creds": True, "default_creds_status": 200,
            "default_creds_bucket_count": 5})
        fs = minio.findings(hosts, probes)
        d = [f for f in fs if f.get("kind") == "minio_default_creds_admin"]
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["severity"], "critical")
        self.assertEqual(d[0]["depth_tier"], "t1")
        self.assertIn("minioadmin", d[0]["command"])
        self.assertIn("CWE-798", d[0]["cwes"])

    def test_anonymous_root_finding_lists_buckets(self):
        hosts, probes = self._host_with_probe({
            "anonymous_listing": True, "bucket_count": 2,
            "buckets": ["backups", "images"]})
        fs = minio.findings(hosts, probes)
        r = [f for f in fs if f.get("kind") == "minio_anonymous_root"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["severity"], "high")
        self.assertEqual(r[0]["depth_tier"], "t2")
        self.assertIn("backups", r[0]["detail"])
        self.assertIn("images", r[0]["detail"])

    def test_cve_2023_28432_finding_wire_format(self):
        hosts, probes = self._host_with_probe({
            "version": "RELEASE.2022-05-04T07-45-27Z",
            "cve_2023_28432": True,
            "cve_root_user": "minioadmin",
            "cve_has_root_secret": True})
        fs = minio.findings(hosts, probes)
        c = [f for f in fs if f.get("kind") == "minio_cve_2023_28432"]
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0]["severity"], "critical")
        self.assertIn("CWE-306", c[0]["cwes"])
        # Version disclosure row must ALSO elevate for the old build.
        v = [f for f in fs if f.get("kind") == "minio_version"]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["severity"], "high")

    def test_findings_to_vulns_wires_up(self):
        hosts, probes = self._host_with_probe({
            "default_admin_creds": True,
            "anonymous_listing": True, "bucket_count": 1,
            "buckets": ["public"],
            "cve_2023_28432": True, "cve_root_user": "minioadmin",
            "cve_has_root_secret": True,
        })
        fs = minio.findings(hosts, probes)
        by_ip = minio.findings_to_vulns(fs)
        self.assertIn("10.0.0.9", by_ip)
        self.assertGreaterEqual(len(by_ip["10.0.0.9"]), 4)


class HelpersTest(unittest.TestCase):

    def test_extract_version_finds_release(self):
        self.assertEqual(
            minio._extract_version("MinIO/RELEASE.2023-03-20T20-16-18Z"),
            "RELEASE.2023-03-20T20-16-18Z")
        self.assertEqual(minio._extract_version("MinIO"), "")
        self.assertEqual(minio._extract_version(""), "")

    def test_parse_release_date_tuple(self):
        self.assertEqual(
            minio._parse_release_date("RELEASE.2023-03-20T20-16-18Z"),
            (2023, 3, 20))
        self.assertIsNone(minio._parse_release_date(""))
        self.assertIsNone(minio._parse_release_date("dev"))

    def test_minio_targets_matches_module_scope(self):
        """minio_targets must live at MODULE scope."""
        self.assertEqual(minio.minio_targets.__qualname__, "minio_targets")

        from recce.core.models import Host, Port
        hosts = [
            Host(ip="1.1.1.1", ports=[Port(portid=9000, state="open",
                                            service="")]),
            Host(ip="2.2.2.2", ports=[Port(portid=9001, state="open",
                                            service="")]),
            # Detected by service name even on a non-default port.
            Host(ip="3.3.3.3", ports=[Port(portid=8080, state="open",
                                            service="minio")]),
            # Not MinIO.
            Host(ip="4.4.4.4", ports=[Port(portid=80, state="open",
                                            service="http")]),
        ]
        tgts = minio.minio_targets(hosts)
        ips = {t["ip"] for t in tgts}
        self.assertEqual(ips, {"1.1.1.1", "2.2.2.2", "3.3.3.3"})

    def test_narrative_covers_every_emitted_kind(self):
        expected = {"minio_reachable", "minio_version",
                    "minio_anonymous_root", "minio_default_creds_admin",
                    "minio_cve_2023_28432"}
        self.assertTrue(expected.issubset(set(minio._NARRATIVE)))

    def test_default_admin_creds_are_minioadmin(self):
        """Safety marker: hard-coded default cred MUST be minioadmin."""
        self.assertEqual(minio._DEFAULT_ADMIN_USER, "minioadmin")
        self.assertEqual(minio._DEFAULT_ADMIN_SECRET, "minioadmin")

    def test_aws4_signature_is_deterministic_shape(self):
        """AWS4 headers must carry the three canonical bits: authoriza-
        tion, x-amz-date, x-amz-content-sha256; the signed-headers list
        must match host+content-sha256+date."""
        hdrs = minio._aws4_sign_get_root("127.0.0.1:9000",
                                         "minioadmin", "minioadmin")
        self.assertIn("Authorization", hdrs)
        self.assertIn("x-amz-date", hdrs)
        self.assertIn("x-amz-content-sha256", hdrs)
        self.assertTrue(hdrs["Authorization"].startswith("AWS4-HMAC-SHA256"))
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date",
                      hdrs["Authorization"])
        # Empty-body sha256.
        self.assertEqual(hdrs["x-amz-content-sha256"], minio._EMPTY_SHA256)


if __name__ == "__main__":
    unittest.main()
