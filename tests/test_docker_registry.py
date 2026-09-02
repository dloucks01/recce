"""Tests for recce.services.docker_registry."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.core.models import Host, Port
from recce.services import docker_registry as reg


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass


class ProbeTest(unittest.TestCase):
    def test_anonymous_catalog_readable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v2/":
                    self.send_response(200)
                    self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
                    self.send_header("Content-Length", "2"); self.end_headers()
                    self.wfile.write(b"{}")
                elif self.path.startswith("/v2/_catalog"):
                    body = json.dumps({"repositories": [
                        "backend/api", "backend/worker", "frontend/webapp",
                        "internal/secrets-svc"]}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body))); self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = reg.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["auth_required"])
        self.assertEqual(p["repositories"], 4)
        self.assertIn("backend/api", p["catalog"])

    def test_auth_required_marked(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v2/":
                    self.send_response(401)
                    self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
                    self.send_header("Www-Authenticate", 'Bearer realm="https://auth"')
                    self.end_headers()
                else:
                    self.send_response(401); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = reg.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["auth_required"])
        self.assertEqual(p["catalog"], [])

    def test_non_registry_service_not_flagged(self):
        class H(_Base):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Length","2")
                self.end_headers(); self.wfile.write(b"ok")
        srv, _t = _serve(H)
        try:
            p = reg.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        # No Docker-Distribution-Api-Version header + no 401 = not a registry.
        self.assertFalse(p["reachable"])

    def test_dead_port(self):
        p = reg.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


# ---------------------------------------------------------------------------
# T2 promotion: dockerreg_manifest_readable
#
# T2 is a strict superset of T1 — after anon /v2/_catalog succeeds, an
# additional unauth GET of /v2/<repo>/manifests/<tag> must also return 200
# with an actually-parseable manifest for the T2 finding to fire.
# ---------------------------------------------------------------------------


# A minimal but wire-realistic Docker Registry v2 manifest (schemaVersion 2,
# vnd.docker.distribution.manifest.v2+json) with one config blob and two
# layer blobs. Digest values are illustrative sha256 hexes.
_V2_MANIFEST = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {
        "mediaType": "application/vnd.docker.container.image.v1+json",
        "size": 7023,
        "digest": ("sha256:b5b2b2c507a0944348e0303114d8d93a"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    },
    "layers": [
        {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 32654,
         "digest": ("sha256:e692418e4cbaf90ca69d05a66403747ba"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
        {"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": 16724,
         "digest": ("sha256:3c3a4604a545cdc127456d94e421cd35"
                    "5bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")},
    ],
}


class _RegBase(_Base):
    """A fixture handler that answers /v2/, /v2/_catalog, /v2/<repo>/tags/list
    and /v2/<repo>/manifests/<tag> like a real Docker Registry v2. Subclass
    and set `manifest_status` / `tags_status` to model patched-halfway
    configurations."""

    manifest_status = 200
    tags_status = 200
    manifest_body = json.dumps(_V2_MANIFEST).encode()
    manifest_ctype = "application/vnd.docker.distribution.manifest.v2+json"
    catalog_body = json.dumps({"repositories": [
        "team/backend", "team/frontend"]}).encode()
    tags_body = json.dumps({
        "name": "team/backend",
        "tags": ["1.0.0", "1.0.1", "latest"]}).encode()

    def do_GET(self):
        p = self.path
        if p == "/v2/":
            self.send_response(200)
            self.send_header("Docker-Distribution-Api-Version", "registry/2.0")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        if p.startswith("/v2/_catalog"):
            self.send_response(200)
            self.send_header("Content-Length", str(len(self.catalog_body)))
            self.end_headers()
            self.wfile.write(self.catalog_body)
            return
        if p.endswith("/tags/list"):
            self.send_response(self.tags_status)
            if self.tags_status == 200:
                self.send_header("Content-Length", str(len(self.tags_body)))
                self.end_headers()
                self.wfile.write(self.tags_body)
            else:
                self.send_header("Www-Authenticate", 'Bearer realm="a"')
                self.end_headers()
            return
        if "/manifests/" in p:
            self.send_response(self.manifest_status)
            if self.manifest_status == 200:
                self.send_header("Content-Type", self.manifest_ctype)
                self.send_header(
                    "Docker-Content-Digest",
                    "sha256:0123456789abcdef0123456789abcdef"
                    "0123456789abcdef0123456789abcdef")
                self.send_header("Content-Length", str(len(self.manifest_body)))
                self.end_headers()
                self.wfile.write(self.manifest_body)
            else:
                self.send_header("Www-Authenticate", 'Bearer realm="a"')
                self.end_headers()
            return
        self.send_response(404)
        self.end_headers()


def _mk_host(ip, port):
    """Build a Host with one open docker-registry port for findings()."""
    return Host(ip=ip, ports=[Port(portid=port, protocol="tcp",
                                   service="docker-registry",
                                   product="Docker Registry")])


class T2ManifestPromotionTest(unittest.TestCase):
    def test_vulnerable_manifest_readable_emits_t2_finding(self):
        srv, _t = _serve(_RegBase)
        port = srv.server_address[1]
        try:
            pr = reg.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        # T1 catalog still fires.
        self.assertTrue(pr["reachable"])
        self.assertGreater(pr["repositories"], 0)
        # T2 evidence populated from real server manifest.
        ev = pr["manifest_evidence"]
        self.assertTrue(ev, "manifest_evidence should be non-empty")
        self.assertEqual(ev["repo"], "team/backend")
        # "latest" wins tie-break when present in tag list.
        self.assertEqual(ev["tag"], "latest")
        self.assertEqual(ev["layers"], 2)
        self.assertEqual(ev["total_bytes"], 32654 + 16724)
        self.assertTrue(ev["config_digest"].startswith("sha256:"))
        self.assertIn("manifest.v2", ev["media_type"])

        # findings() emits BOTH T1 and T2 for this probe. Note: findings()
        # gates on is_docker_registry(port) which requires portid in a fixed
        # list (5000/5001/5002/443/5443) — the test HTTP server bound to a
        # dynamic port. Rekey the probes dict under portid=5000 and shape a
        # matching Host so we exercise the emission path with real probe data.
        hosts = [_mk_host("127.0.0.1", 5000)]
        fs = reg.findings(hosts, {("127.0.0.1", 5000): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("dockerreg_anonymous_catalog", kinds)
        self.assertIn("dockerreg_manifest_readable", kinds)
        t1 = next(f for f in fs if f["kind"] == "dockerreg_anonymous_catalog")
        t2 = next(f for f in fs if f["kind"] == "dockerreg_manifest_readable")
        self.assertEqual(t1["depth_tier"], "t1")
        self.assertEqual(t2["depth_tier"], "t2")
        self.assertEqual(t2["severity"], "high")
        # Evidence blob captured on output field, not just detail.
        self.assertIn("output", t2)
        self.assertIn("layers:", t2["output"])
        self.assertIn("config.digest:", t2["output"])
        self.assertIn("team/backend", t2["output"])
        # Confirmed exploit_note names the real repo+tag.
        self.assertIn("team/backend:latest", t2["exploit_note"])

    def test_patched_manifest_requires_auth_no_t2_finding(self):
        # Half-patched: /v2/_catalog stays anon (T1 fires), but /manifests/
        # requires auth. T2 must stay silent so it never claims exploitability
        # that isn't there.
        class H(_RegBase):
            manifest_status = 401
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = reg.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["reachable"])
        self.assertGreater(pr["repositories"], 0)
        self.assertEqual(pr["manifest_evidence"], {})

        hosts = [_mk_host("127.0.0.1", 5000)]
        fs = reg.findings(hosts, {("127.0.0.1", 5000): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("dockerreg_anonymous_catalog", kinds)
        self.assertNotIn("dockerreg_manifest_readable", kinds)

    def test_tags_list_gated_no_t2_finding(self):
        # Some deployments gate per-repo enumeration even when catalog is anon.
        # T2 must not fire, and must not attempt manifest fetch anyway.
        class H(_RegBase):
            tags_status = 401
            # If code incorrectly still tried the manifest, this would fire.
            manifest_status = 500
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = reg.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(pr["manifest_evidence"], {})
        hosts = [_mk_host("127.0.0.1", 5000)]
        fs = reg.findings(hosts, {("127.0.0.1", 5000): pr})
        self.assertNotIn("dockerreg_manifest_readable",
                         [f["kind"] for f in fs])

    def test_t2_probe_timeout_no_crash(self):
        # Simulate the T2 chain HTTP call timing out — probe must still
        # return a T1 shape without raising, manifest_evidence empty.
        import recce.services.docker_registry as mod

        def _boom(*a, **kw):
            raise OSError("simulated timeout")

        orig = mod._http_get_with_headers
        mod._http_get_with_headers = _boom
        try:
            srv, _t = _serve(_RegBase)
            port = srv.server_address[1]
            try:
                pr = mod.probe("127.0.0.1", port, timeout=2)
            finally:
                srv.shutdown()
        finally:
            mod._http_get_with_headers = orig
        self.assertTrue(pr["reachable"])
        self.assertGreater(pr["repositories"], 0)
        self.assertEqual(pr["manifest_evidence"], {})

    def test_t1_shape_unchanged_when_no_catalog(self):
        # Registry answers /v2/ 200 but /v2/_catalog returns something
        # non-JSON — original behaviour is empty catalog, no auth_required.
        # T2 must not trigger the manifest chain (would need a repo).
        class H(_Base):
            def do_GET(self):
                if self.path == "/v2/":
                    self.send_response(200)
                    self.send_header("Docker-Distribution-Api-Version",
                                     "registry/2.0")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
                elif self.path.startswith("/v2/_catalog"):
                    self.send_response(200)
                    self.send_header("Content-Length", "3")
                    self.end_headers()
                    self.wfile.write(b"not")
                else:
                    self.send_response(404)
                    self.end_headers()
        srv, _t = _serve(H)
        try:
            pr = reg.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["catalog"], [])
        self.assertEqual(pr["manifest_evidence"], {})


class T2InputHardeningTest(unittest.TestCase):
    """The catalog listing is server-supplied; a hostile registry could try to
    smuggle path-escapes or header-splitting bytes through the manifest URL."""

    def test_safe_repo_rejects_dotdot(self):
        self.assertEqual(reg._safe_repo("../etc/passwd"), "")
        self.assertEqual(reg._safe_repo("team/../evil"), "")
        self.assertEqual(reg._safe_repo("team/./evil"), "")
        self.assertEqual(reg._safe_repo("team/backend"), "team/backend")

    def test_safe_repo_rejects_bad_chars(self):
        self.assertEqual(reg._safe_repo("team/backend\r\nHost: x"), "")
        self.assertEqual(reg._safe_repo("team backend"), "")
        self.assertEqual(reg._safe_repo("team/backend?admin"), "")
        self.assertEqual(reg._safe_repo(""), "")

    def test_safe_tag_rejects_bad_chars(self):
        self.assertEqual(reg._safe_tag("latest"), "latest")
        self.assertEqual(reg._safe_tag("1.0.0-rc1"), "1.0.0-rc1")
        self.assertEqual(reg._safe_tag("v/1"), "")
        self.assertEqual(reg._safe_tag("bad\r\ntag"), "")
        self.assertEqual(reg._safe_tag("-nope"), "")  # first char must be alnum/_
        self.assertEqual(reg._safe_tag(""), "")

    def test_hostile_repo_short_circuits_before_network(self):
        # If the first catalog entry is unsafe, _t2_manifest_evidence must
        # bail without touching the network at all.
        calls = []

        def _spy(*a, **kw):
            calls.append(a)
            return (200, {}, b"{}")

        orig = reg._http_get_with_headers
        reg._http_get_with_headers = _spy
        try:
            ev = reg._t2_manifest_evidence("127.0.0.1", 1, ["../evil"])
        finally:
            reg._http_get_with_headers = orig
        self.assertEqual(ev, {})
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
