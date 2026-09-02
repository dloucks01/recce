"""Tests for recce.services.gitlab.

Fixtures model a realistic GitLab HTTP surface: /users/sign_in (fingerprint
carrier via body + Set-Cookie), /api/v4/version, /-/health surface,
/api/v4/projects?visibility=public, /api/v4/broadcast_messages, and
/explore/projects. Each test asserts a specific emitted kind (or its absence)
so the version-gated CVE markers can never regress into unverified emits.
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.core.models import Host, Port
from recce.services import gitlab


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass


def _send(handler, status, body=b"", ctype="text/html; charset=utf-8",
          set_cookie: str | None = None):
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    if set_cookie:
        handler.send_header("Set-Cookie", set_cookie)
    handler.end_headers()
    if body:
        handler.wfile.write(body)


# --- Handler builders --------------------------------------------------------

def _make_gitlab_handler(*, version="15.7.1", public_projects=None,
                         health_ok=True, broadcast_count=0,
                         version_status=200, signin_ok=True):
    """Build a handler class that mimics a GitLab install with the knobs
    the caller sets. Fingerprint always presents via the Set-Cookie header
    on the sign-in page (matches real GitLab)."""
    public_projects = public_projects or []

    class H(_Base):
        def do_GET(self):
            p = self.path
            if p == "/users/sign_in":
                body = (
                    b"<html><head><title>Sign in - GitLab</title></head>"
                    b"<body><form><input name=\"user[login]\">"
                    b"GitLab Community Edition</form></body></html>"
                ) if signin_ok else b"<html>nothing here</html>"
                _send(self, 200, body,
                      set_cookie="_gitlab_session=abc123; Path=/; HttpOnly")
                return
            if p == "/api/v4/version":
                if version_status != 200:
                    _send(self, version_status, b"{\"message\":\"401\"}",
                          ctype="application/json")
                    return
                body = json.dumps({"version": version,
                                   "revision": "deadbeef"}).encode()
                _send(self, 200, body, ctype="application/json")
                return
            if p in ("/-/health", "/-/readiness", "/-/liveness"):
                if health_ok:
                    _send(self, 200,
                          f"GitLab OK - version {version}".encode(),
                          ctype="text/plain")
                else:
                    _send(self, 404, b"nope")
                return
            if p.startswith("/api/v4/projects"):
                body = json.dumps(public_projects).encode()
                _send(self, 200, body, ctype="application/json")
                return
            if p.startswith("/api/v4/broadcast_messages"):
                msgs = [{"id": i, "message": f"m{i}"}
                        for i in range(broadcast_count)]
                _send(self, 200, json.dumps(msgs).encode(),
                      ctype="application/json")
                return
            if p == "/explore/projects":
                _send(self, 200, b"<html><title>GitLab</title></html>")
                return
            _send(self, 404, b"")

    return H


def _mk_host(ip, port):
    return Host(ip=ip, ports=[Port(portid=port, protocol="tcp",
                                   service="http", product="")])


# --- Fingerprint / reachability ---------------------------------------------

class FingerprintTest(unittest.TestCase):
    def test_signin_body_and_cookie_are_fingerprint(self):
        H = _make_gitlab_handler()
        srv, _t = _serve(H)
        try:
            pr = gitlab.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["signin_present"])

    def test_non_gitlab_service_not_flagged(self):
        class H(_Base):
            def do_GET(self):
                _send(self, 200, b"<html>totally unrelated app</html>")

        srv, _t = _serve(H)
        try:
            pr = gitlab.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        # No "GitLab" in body and no session cookie -> must not claim reachable.
        self.assertFalse(pr["reachable"])
        self.assertEqual(pr["version"], "")

    def test_dead_port(self):
        pr = gitlab.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(pr["reachable"])


# --- Version parsing + CVE gating -------------------------------------------

class VersionAndCVETest(unittest.TestCase):
    def test_vulnerable_version_marks_cve_2021_22205(self):
        H = _make_gitlab_handler(version="13.10.2")
        srv, _t = _serve(H)
        try:
            pr = gitlab.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(pr["version"], "13.10.2")
        self.assertTrue(pr["cve_2021_22205"])
        self.assertFalse(pr["cve_2023_2825"])

    def test_patched_version_does_not_mark_cve_2021_22205(self):
        H = _make_gitlab_handler(version="13.10.3")
        srv, _t = _serve(H)
        try:
            pr = gitlab.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(pr["version"], "13.10.3")
        self.assertFalse(pr["cve_2021_22205"])

    def test_16_0_0_marks_cve_2023_2825(self):
        H = _make_gitlab_handler(version="16.0.0")
        srv, _t = _serve(H)
        try:
            pr = gitlab.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["cve_2023_2825"])
        # 16.0.0 is post 13.10.3 => NOT vulnerable to 2021-22205.
        self.assertFalse(pr["cve_2021_22205"])

    def test_16_0_1_does_not_mark_cve_2023_2825(self):
        H = _make_gitlab_handler(version="16.0.1")
        srv, _t = _serve(H)
        try:
            pr = gitlab.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(pr["cve_2023_2825"])

    def test_no_version_no_cve_flags(self):
        # Version endpoint 401 (real modern deployment) + no version-bearing
        # health body -> CVE gates MUST stay silent, not fire on defaults.
        H = _make_gitlab_handler(version_status=401, health_ok=False)
        srv, _t = _serve(H)
        try:
            pr = gitlab.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version"], "")
        self.assertFalse(pr["cve_2021_22205"])
        self.assertFalse(pr["cve_2023_2825"])


# --- findings() emission ----------------------------------------------------

class FindingsTest(unittest.TestCase):
    def test_vulnerable_emits_gitlab_cve_2021_22205_finding(self):
        H = _make_gitlab_handler(version="13.5.0")
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = gitlab.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        # findings() gates on is_gitlab_http, which only accepts the module's
        # HTTP port set. Rekey under 80 to exercise emission.
        fs = gitlab.findings([_mk_host("127.0.0.1", 80)],
                             {("127.0.0.1", 80): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("gitlab_cve_2021_22205", kinds)
        crit = next(f for f in fs if f["kind"] == "gitlab_cve_2021_22205")
        self.assertEqual(crit["severity"], "critical")
        self.assertEqual(crit["depth_tier"], "t0")
        # Version disclosure kind lifts to high in the presence of an active CVE.
        v = next(f for f in fs if f["kind"] == "gitlab_version")
        self.assertEqual(v["severity"], "high")

    def test_patched_does_not_emit_cve_findings(self):
        H = _make_gitlab_handler(version="16.5.0",
                                 public_projects=[], broadcast_count=0)
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = gitlab.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        fs = gitlab.findings([_mk_host("127.0.0.1", 80)],
                             {("127.0.0.1", 80): pr})
        kinds = [f["kind"] for f in fs]
        self.assertNotIn("gitlab_cve_2021_22205", kinds)
        self.assertNotIn("gitlab_cve_2023_2825", kinds)
        # Reachable + version + signin + health still emitted.
        self.assertIn("gitlab_reachable", kinds)
        self.assertIn("gitlab_version", kinds)
        v = next(f for f in fs if f["kind"] == "gitlab_version")
        self.assertEqual(v["severity"], "info")

    def test_public_projects_and_broadcasts_emit_findings(self):
        proj = [{"name": "team/backend",
                 "name_with_namespace": "Team / backend",
                 "web_url": "http://x/team/backend"},
                {"name": "team/frontend",
                 "name_with_namespace": "Team / frontend",
                 "web_url": "http://x/team/frontend"}]
        H = _make_gitlab_handler(version="16.5.0",
                                 public_projects=proj, broadcast_count=3)
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = gitlab.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(pr["public_projects_count"], 2)
        self.assertEqual(pr["broadcast_messages"], 3)
        fs = gitlab.findings([_mk_host("127.0.0.1", 80)],
                             {("127.0.0.1", 80): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("gitlab_public_projects", kinds)
        self.assertIn("gitlab_broadcast_messages", kinds)
        self.assertIn("gitlab_health_endpoint", kinds)
        self.assertIn("gitlab_signin_present", kinds)

    def test_findings_to_vulns_round_trip(self):
        H = _make_gitlab_handler(version="13.5.0")
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = gitlab.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        fs = gitlab.findings([_mk_host("127.0.0.1", 80)],
                             {("127.0.0.1", 80): pr})
        vulns = gitlab.findings_to_vulns(fs)
        self.assertIn("127.0.0.1", vulns)
        titles = [v.title for v in vulns["127.0.0.1"]]
        self.assertTrue(any("CVE-2021-22205" in t for t in titles),
                        f"expected CVE-2021-22205 in titles, got {titles}")


# --- Module-scope target function guard -------------------------------------

class ModuleScopeTest(unittest.TestCase):
    def test_gitlab_targets_is_module_scoped(self):
        # scan.py's _module_scoped_check rejects class-nested `_targets`.
        # gitlab_targets must be module-scope for the WebUI to see it.
        fn = gitlab.gitlab_targets
        self.assertNotIn(".", fn.__qualname__)

    def test_gitlab_targets_returns_open_ports_only(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=443, protocol="tcp", state="open",
                             service="http"),
                        Port(portid=22, protocol="tcp", state="open",
                             service="ssh")])
        tgts = gitlab.gitlab_targets([h])
        # Only the HTTP-ish port should be listed.
        self.assertEqual([(t["ip"], t["port"]) for t in tgts],
                         [("10.0.0.5", 443)])


if __name__ == "__main__":
    unittest.main()
