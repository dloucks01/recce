"""Tests for recce.services.grafana.

Fixtures model the real Grafana HTTP API (v8..v11) —
https://grafana.com/docs/grafana/latest/developers/http_api/:
  * GET  /api/health       -> {"commit":"...","database":"ok","version":"11.2.2"}
  * GET  /                 -> HTML shell with `data-app-info` on <script>
  * GET  /api/gnet/plugins -> {"items":[{"slug":"grafana-worldmap-panel",...}, ...]}
  * GET  /api/orgs         -> [{"id":1,"name":"Main Org.","...":"..."}]

Every test uses a real background HTTP server bound to 127.0.0.1:0.
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import grafana


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass


def _send_json(handler, status, payload):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _send_html(handler, status, html: str):
    body = html.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _make_handler(version="11.2.2",
                  accept_default_cred=False,
                  plugin_list=True,
                  block_health=False):
    """Compose a Grafana-like server. `version` drives /api/health;
    `accept_default_cred` controls whether the admin/admin Basic probe
    is accepted on /api/orgs; `plugin_list` toggles /api/gnet/plugins
    exposure; `block_health` returns 403 on /api/health so the HTML
    fingerprint fallback is exercised."""

    class H(_Base):
        def do_GET(self):
            if self.path == "/api/health":
                if block_health:
                    self.send_response(403); self.end_headers(); return
                _send_json(self, 200, {
                    "commit": "abc1234",
                    "database": "ok",
                    "version": version,
                })
            elif self.path == "/":
                # Real Grafana login shell — the operative marker is the
                # `data-app-info` attribute the app uses to init.
                _send_html(self, 200,
                    "<!DOCTYPE html><html><head><title>Grafana</title></head>"
                    "<body><div id=\"reactRoot\"></div>"
                    "<script data-app-info=\"grafana\"></script>"
                    "</body></html>")
            elif self.path == "/login":
                _send_html(self, 200,
                    "<html><head><title>Grafana</title></head>"
                    "<body><script data-app-info=\"grafana\"></script>"
                    "</body></html>")
            elif self.path == "/api/gnet/plugins":
                if not plugin_list:
                    self.send_response(401); self.end_headers(); return
                _send_json(self, 200, {"items": [
                    {"slug": "grafana-worldmap-panel", "name": "Worldmap"},
                    {"slug": "grafana-piechart-panel", "name": "Pie chart"},
                    {"slug": "grafana-clock-panel", "name": "Clock"},
                ]})
            elif self.path == "/api/orgs":
                auth = self.headers.get("Authorization", "")
                if (accept_default_cred and auth ==
                        f"Basic {grafana._DEFAULT_ADMIN_BASIC}"):
                    _send_json(self, 200, [
                        {"id": 1, "name": "Main Org.",
                         "url": "/orgs/edit/1"},
                    ])
                else:
                    _send_json(self, 401, {"message": "Unauthorized"})
            else:
                self.send_response(404); self.end_headers()

        def do_POST(self):
            self.send_response(404); self.end_headers()

    return H


class ProbeTest(unittest.TestCase):

    def test_open_grafana_full_disclosure(self):
        """Default Grafana with admin:admin still active + public plugin
        list — the classic 'walk-in' box. All non-CVE kinds fire."""
        srv, _t = _serve(_make_handler(version="11.2.2",
                                       accept_default_cred=True,
                                       plugin_list=True))
        try:
            p = grafana.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "11.2.2")
        self.assertEqual(p["database"], "ok")
        self.assertTrue(p["plugin_list_exposed"])
        self.assertEqual(p["plugin_count"], 3)
        self.assertIn("grafana-worldmap-panel", p["plugins"])
        self.assertTrue(p["default_admin_creds"])
        # 11.2.2 is inside CVE-2024-9264 window (11.2.0..<11.2.3).
        self.assertTrue(p["cve_2024_9264"])
        self.assertFalse(p["cve_2021_43798"])

    def test_hardened_grafana_no_default_cred_no_plugins(self):
        """A hardened Grafana: default cred rejected, /api/gnet/plugins
        gated. Fingerprint fires but the risky findings do not."""
        srv, _t = _serve(_make_handler(version="11.2.3",   # patched
                                       accept_default_cred=False,
                                       plugin_list=False))
        try:
            p = grafana.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "11.2.3")
        self.assertFalse(p["default_admin_creds"])
        self.assertFalse(p["plugin_list_exposed"])
        self.assertFalse(p["cve_2024_9264"])
        self.assertFalse(p["cve_2021_43798"])

    def test_cve_2021_43798_gated_vulnerable(self):
        """Grafana 8.3.0 is in the traversal window. CVE fires."""
        srv, _t = _serve(_make_handler(version="8.3.0"))
        try:
            p = grafana.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["cve_2021_43798"])
        self.assertFalse(p["cve_2024_9264"])

        # And the finding wire-format matches expectations.
        from recce.core.models import Host, Port
        hosts = [Host(ip="127.0.0.1", ports=[Port(
            portid=srv.server_address[1], state="open", service="grafana")])]
        probes = {("127.0.0.1", srv.server_address[1]): p}
        fs = grafana.findings(hosts, probes)
        cve = [f for f in fs if f.get("kind") == "grafana_cve_2021_43798"]
        self.assertEqual(len(cve), 1)
        self.assertEqual(cve[0]["severity"], "critical")
        self.assertIn("8.3.1", cve[0]["detail"])
        self.assertIn("CWE-22", cve[0]["cwes"])

    def test_cve_2021_43798_gated_patched_backport(self):
        """8.0.7 IS the backport fix for the 8.0 line — CVE must NOT
        fire, even though it's below 8.3.1."""
        srv, _t = _serve(_make_handler(version="8.0.7"))
        try:
            p = grafana.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["cve_2021_43798"])

    def test_cve_2024_9264_gated_vulnerable_and_patched(self):
        """Version 11.0.5 vulnerable; 11.0.6 patched."""
        srv1, _ = _serve(_make_handler(version="11.0.5"))
        try:
            p1 = grafana.probe("127.0.0.1", srv1.server_address[1], timeout=2)
        finally:
            srv1.shutdown()
        self.assertTrue(p1["cve_2024_9264"])

        srv2, _ = _serve(_make_handler(version="11.0.6"))
        try:
            p2 = grafana.probe("127.0.0.1", srv2.server_address[1], timeout=2)
        finally:
            srv2.shutdown()
        self.assertTrue(p2["reachable"])
        self.assertFalse(p2["cve_2024_9264"])

    def test_default_cred_probe_is_single_shot(self):
        """Correctness safeguard: the default-cred probe must send
        EXACTLY ONE request against /api/orgs (no loop over a cred
        list). Counts the actual requests seen by the server."""
        orgs_hits: list = []

        class H(_Base):
            def do_GET(self):
                if self.path == "/api/health":
                    _send_json(self, 200,
                        {"commit": "x", "database": "ok",
                         "version": "10.4.1"})
                elif self.path == "/api/gnet/plugins":
                    _send_json(self, 200, {"items": []})
                elif self.path == "/api/orgs":
                    orgs_hits.append(self.headers.get("Authorization", ""))
                    self.send_response(401); self.end_headers()
                else:
                    self.send_response(404); self.end_headers()

            def do_POST(self):
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            grafana.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()

        # Exactly one probe, and it MUST carry the admin:admin Basic
        # value — no other cred attempted.
        self.assertEqual(len(orgs_hits), 1)
        self.assertEqual(orgs_hits[0],
                         f"Basic {grafana._DEFAULT_ADMIN_BASIC}")

    def test_default_cred_rejects_401_no_finding(self):
        """401 from /api/orgs means the default cred does NOT work —
        the default-creds finding must NOT fire, even on an otherwise
        wide-open Grafana."""
        srv, _t = _serve(_make_handler(version="10.4.1",
                                       accept_default_cred=False,
                                       plugin_list=True))
        try:
            p = grafana.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["default_admin_creds"])
        self.assertEqual(p["default_creds_status"], 401)

        from recce.core.models import Host, Port
        hosts = [Host(ip="127.0.0.1", ports=[Port(
            portid=srv.server_address[1], state="open", service="grafana")])]
        probes = {("127.0.0.1", srv.server_address[1]): p}
        fs = grafana.findings(hosts, probes)
        kinds = {f.get("kind") for f in fs}
        self.assertNotIn("grafana_default_creds_admin", kinds)

    def test_html_fingerprint_fallback_when_health_blocked(self):
        """/api/health can be gated behind a fronting proxy; the HTML
        login shell's `data-app-info` meta is still the tell — probe
        must catch it and mark reachable=True (though with empty
        version, so CVE gates stay silent)."""
        srv, _t = _serve(_make_handler(block_health=True))
        try:
            p = grafana.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "")
        self.assertFalse(p["cve_2021_43798"])
        self.assertFalse(p["cve_2024_9264"])

    def test_non_grafana_service_not_flagged(self):
        """A generic web service on port 3000 that returns
        'grafana' as a substring but no health JSON and no data-app-
        info must NOT be flagged. Fingerprint requires the shape."""
        class H(_Base):
            def do_GET(self):
                _send_html(self, 200,
                    "<html><body>hi from a grafana-fan blog</body></html>")

            def do_POST(self):
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = grafana.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p["reachable"])

    def test_dead_port(self):
        """Connect refused → all-false, no crash."""
        p = grafana.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])
        self.assertFalse(p["default_admin_creds"])
        self.assertFalse(p["cve_2021_43798"])


class FindingsTest(unittest.TestCase):
    """Finding-emission wiring for the emitted kinds."""

    def _host_with_probe(self, probe_dict, port=3000):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.7", ports=[Port(portid=port, state="open",
                                             service="grafana")])
        probes = {("10.0.0.7", port):
                  {"reachable": True, "version": "11.2.2", **probe_dict}}
        return [h], probes

    def test_reachable_and_version_always_fire(self):
        hosts, probes = self._host_with_probe({})
        fs = grafana.findings(hosts, probes)
        kinds = {f.get("kind") for f in fs}
        self.assertIn("grafana_reachable", kinds)
        self.assertIn("grafana_version", kinds)
        self.assertNotIn("grafana_default_creds_admin", kinds)
        self.assertNotIn("grafana_plugin_list", kinds)
        # Every finding carries mandatory metadata.
        for f in fs:
            self.assertIn("kind", f)
            self.assertIn("severity", f)
            self.assertIn("depth_tier", f)
            self.assertIn("exploit_note", f)
            self.assertIn("cwes", f)

    def test_default_creds_finding_wire_format(self):
        hosts, probes = self._host_with_probe({
            "default_admin_creds": True, "default_creds_status": 200})
        fs = grafana.findings(hosts, probes)
        d = [f for f in fs if f.get("kind") == "grafana_default_creds_admin"]
        self.assertEqual(len(d), 1)
        self.assertEqual(d[0]["severity"], "critical")
        self.assertEqual(d[0]["depth_tier"], "t1")
        # Must reference the safe single-shot probe, not a spray.
        self.assertIn("admin:admin", d[0]["command"])
        self.assertIn("CWE-798", d[0]["cwes"])

    def test_plugin_list_finding_lists_slugs(self):
        hosts, probes = self._host_with_probe({
            "plugin_list_exposed": True, "plugin_count": 2,
            "plugins": ["grafana-clock-panel", "grafana-piechart-panel"]})
        fs = grafana.findings(hosts, probes)
        p = [f for f in fs if f.get("kind") == "grafana_plugin_list"]
        self.assertEqual(len(p), 1)
        self.assertEqual(p[0]["severity"], "info")
        self.assertIn("grafana-clock-panel", p[0]["detail"])
        self.assertIn("grafana-piechart-panel", p[0]["detail"])

    def test_version_finding_elevates_severity_on_cve_match(self):
        """A CVE-vulnerable version elevates the info version-disclosure
        row so old fleets show up loudly on the report."""
        hosts, probes = self._host_with_probe({"cve_2021_43798": True})
        fs = grafana.findings(hosts, probes)
        v = [f for f in fs if f.get("kind") == "grafana_version"]
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["severity"], "high")

    def test_findings_to_vulns_wires_up(self):
        """findings_to_vulns must produce a per-ip vuln dict — smoke-
        test the report pipeline contract."""
        hosts, probes = self._host_with_probe({
            "default_admin_creds": True,
            "plugin_list_exposed": True,
            "plugin_count": 1,
            "plugins": ["grafana-piechart-panel"],
            "cve_2024_9264": True,
        })
        fs = grafana.findings(hosts, probes)
        by_ip = grafana.findings_to_vulns(fs)
        self.assertIn("10.0.0.7", by_ip)
        self.assertTrue(len(by_ip["10.0.0.7"]) >= 4)


class HelpersTest(unittest.TestCase):

    def test_parse_version_accepts_grafana_shapes(self):
        self.assertEqual(grafana._parse_version("8.3.0"), (8, 3, 0))
        self.assertEqual(grafana._parse_version("v11.2.2"), (11, 2, 2))
        self.assertEqual(grafana._parse_version("10.4.1-security-01"),
                         (10, 4, 1))

    def test_parse_version_rejects_garbage(self):
        self.assertIsNone(grafana._parse_version(""))
        self.assertIsNone(grafana._parse_version("dev"))
        self.assertIsNone(grafana._parse_version(None))
        self.assertIsNone(grafana._parse_version("8.3"))  # need three parts

    def test_in_range_boundaries(self):
        """CVE range windows are half-open [lo, hi) — the fix version
        itself must NOT be flagged."""
        # CVE-2021-43798: 8.3.0 vulnerable, 8.3.1 patched.
        self.assertTrue(grafana._in_range(
            (8, 3, 0), grafana._CVE_2021_43798_RANGES))
        self.assertFalse(grafana._in_range(
            (8, 3, 1), grafana._CVE_2021_43798_RANGES))
        # Backport fixes on other minors.
        self.assertTrue(grafana._in_range(
            (8, 0, 6), grafana._CVE_2021_43798_RANGES))
        self.assertFalse(grafana._in_range(
            (8, 0, 7), grafana._CVE_2021_43798_RANGES))
        # Above the whole window.
        self.assertFalse(grafana._in_range(
            (9, 0, 0), grafana._CVE_2021_43798_RANGES))
        # CVE-2024-9264 boundaries.
        self.assertTrue(grafana._in_range(
            (11, 3, 1), grafana._CVE_2024_9264_RANGES))
        self.assertFalse(grafana._in_range(
            (11, 3, 2), grafana._CVE_2024_9264_RANGES))
        self.assertFalse(grafana._in_range(
            (10, 4, 0), grafana._CVE_2024_9264_RANGES))

    def test_grafana_targets_matches_module_scope(self):
        """grafana_targets must live at MODULE scope (not nested in a
        class) — the _module_scoped_check qualname rule."""
        self.assertEqual(grafana.grafana_targets.__qualname__,
                         "grafana_targets")

        from recce.core.models import Host, Port
        hosts = [
            Host(ip="1.1.1.1", ports=[Port(portid=3000, state="open",
                                            service="")]),
            # Detected by service name even on a non-default port.
            Host(ip="2.2.2.2", ports=[Port(portid=8080, state="open",
                                            service="grafana")]),
            # Not Grafana.
            Host(ip="3.3.3.3", ports=[Port(portid=80, state="open",
                                            service="http")]),
        ]
        tgts = grafana.grafana_targets(hosts)
        ips = {t["ip"] for t in tgts}
        self.assertEqual(ips, {"1.1.1.1", "2.2.2.2"})

    def test_narrative_covers_every_emitted_kind(self):
        """_NARRATIVE must carry a prose entry for every kind emitted."""
        expected = {"grafana_reachable", "grafana_version",
                    "grafana_default_creds_admin", "grafana_plugin_list",
                    "grafana_cve_2021_43798", "grafana_cve_2024_9264"}
        self.assertTrue(expected.issubset(set(grafana._NARRATIVE)))

    def test_default_cred_basic_value_is_admin_admin(self):
        """Safety marker: the hard-coded default-cred Basic string
        MUST decode to admin:admin. Any other value would be a
        cred-spray in disguise."""
        import base64
        decoded = base64.b64decode(grafana._DEFAULT_ADMIN_BASIC).decode()
        self.assertEqual(decoded, "admin:admin")


if __name__ == "__main__":
    unittest.main()
