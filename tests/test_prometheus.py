"""Tests for recce.services.prometheus."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import prometheus as prom


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass


class ProbeTest(unittest.TestCase):
    def test_open_prometheus_full_readable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                elif self.path == "/api/v1/status/buildinfo":
                    body = json.dumps({"status":"success",
                                       "data":{"version":"2.48.1"}}).encode()
                elif self.path == "/api/v1/status/config":
                    yaml_txt = ("scrape_configs:\n"
                                "  - job_name: 'internal'\n"
                                "    static_configs:\n"
                                "      - targets: ['10.0.0.1:9100','10.0.0.2:9100']\n"
                                "    bearer_token: eyJHIDDEN\n")
                    body = json.dumps({"status":"success","data":{"yaml":yaml_txt}}).encode()
                elif self.path == "/api/v1/query?query=up":
                    body = json.dumps({"status":"success",
                                       "data":{"resultType":"vector","result":[]}}).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length",str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                if self.path == "/-/reload":
                    self.send_response(200); self.send_header("Content-Length","0")
                    self.end_headers()
                else:
                    self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["config_readable"])
        self.assertTrue(p["query_open"])
        self.assertTrue(p["admin_writable"])
        self.assertGreaterEqual(p["scrape_targets_hint"], 1)

    def test_locked_down_prometheus_reachable_only(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                    self.send_response(200); self.send_header("Content-Length",str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(403); self.end_headers()
            def do_POST(self):
                self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["config_readable"])
        self.assertFalse(p["admin_writable"])

    def test_non_prometheus_service_not_flagged(self):
        class H(_Base):
            def do_GET(self):
                body = b"OK"
                self.send_response(200); self.send_header("Content-Length","2")
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p["reachable"])

    def test_dead_port(self):
        p = prom.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])

    def test_federate_open_exposition_body(self):
        # Fixture models a real Prometheus /federate response: text/plain
        # exposition format with # HELP / # TYPE comment lines and sample
        # lines "metric{labels} value timestamp". A permissive matcher
        # dumps every series; three samples here stand in for many.
        federate_body = (
            b"# HELP up Was the last scrape successful.\n"
            b"# TYPE up gauge\n"
            b"up{instance=\"node-a:9100\",job=\"node\"} 1 1735689600000\n"
            b"up{instance=\"node-b:9100\",job=\"node\"} 1 1735689600000\n"
            b"scrape_duration_seconds{instance=\"node-a:9100\",job=\"node\"} "
            b"0.0031 1735689600000\n"
        )
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                if self.path.startswith("/federate"):
                    self.send_response(200)
                    self.send_header(
                        "Content-Type",
                        "text/plain; version=0.0.4; charset=utf-8")
                    self.send_header("Content-Length", str(len(federate_body)))
                    self.end_headers(); self.wfile.write(federate_body); return
                self.send_response(404); self.end_headers()
            def do_POST(self):
                self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["federate_open"])
        # Three non-comment lines in the fixture body.
        self.assertGreaterEqual(p["federate_series_hint"], 3)
        self.assertFalse(p["pprof_cmdline"])

    def test_federate_locked_403(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(403); self.end_headers()
            def do_POST(self):
                self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["federate_open"])
        self.assertEqual(p["federate_series_hint"], 0)

    def test_federate_json_200_not_a_false_positive(self):
        # A fronting proxy answering 200 JSON on /federate must not trip
        # the open flag. Real Prometheus returns text/plain exposition;
        # anything else is refused.
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                if self.path.startswith("/federate"):
                    body = b'{"error":"blocked"}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(404); self.end_headers()
            def do_POST(self):
                self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p["federate_open"])

    def test_pprof_cmdline_open_leaks_argv(self):
        # net/http/pprof's cmdline handler mirrors /proc/self/cmdline:
        # NUL-separated argv. Fixture is what a Prometheus instance
        # started with lifecycle + config-file flags actually returns.
        cmdline = (
            b"/usr/local/bin/prometheus\x00"
            b"--config.file=/etc/prometheus/prometheus.yml\x00"
            b"--storage.tsdb.path=/var/lib/prometheus\x00"
            b"--web.enable-lifecycle\x00"
            b"--web.listen-address=0.0.0.0:9090\x00"
        )
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                if self.path == "/debug/pprof/cmdline":
                    self.send_response(200)
                    self.send_header("Content-Type",
                                     "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(cmdline)))
                    self.end_headers(); self.wfile.write(cmdline); return
                self.send_response(404); self.end_headers()
            def do_POST(self):
                self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["pprof_cmdline"])
        self.assertIn("prometheus", p["cmdline_sample"].lower())
        self.assertIn("--config.file", p["cmdline_sample"])

    def test_pprof_absent_404(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/-/healthy":
                    body = b"Prometheus Server is Healthy.\n"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(404); self.end_headers()
            def do_POST(self):
                self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = prom.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p["pprof_cmdline"])
        self.assertEqual(p["cmdline_sample"], "")


class FindingsTest(unittest.TestCase):
    """Verify finding-emission wiring for the new capabilities and the
    corrected /-/reload flag attribution."""

    def _host_with_probe(self, probe_dict):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.5", ports=[Port(portid=9090, state="open",
                                            service="prometheus")])
        probes = {("10.0.0.5", 9090): {"reachable": True, **probe_dict}}
        return [h], probes

    def test_admin_writable_finding_attributes_lifecycle_flag(self):
        # Correctness fix: prom_admin_writable must reference
        # --web.enable-lifecycle, NOT --web.enable-admin-api.
        hosts, probes = self._host_with_probe(
            {"admin_writable": True, "version": "2.48.1"})
        fs = prom.findings(hosts, probes)
        aw = [f for f in fs if f.get("kind") == "prom_admin_writable"]
        self.assertEqual(len(aw), 1)
        self.assertIn("--web.enable-lifecycle", aw[0]["detail"])
        # And must not mis-attribute to the admin-api flag as its cause.
        self.assertNotIn("started with --web.enable-admin-api",
                         aw[0]["detail"])

    def test_federate_finding_emitted_when_open(self):
        hosts, probes = self._host_with_probe(
            {"federate_open": True, "federate_series_hint": 42,
             "version": "2.48.1"})
        fs = prom.findings(hosts, probes)
        fed = [f for f in fs if f.get("kind") == "prom_federate_open"]
        self.assertEqual(len(fed), 1)
        self.assertEqual(fed[0]["severity"], "critical")
        self.assertIn("42", fed[0]["detail"])

    def test_pprof_finding_emitted_when_leaking(self):
        hosts, probes = self._host_with_probe(
            {"pprof_cmdline": True,
             "cmdline_sample": "/usr/local/bin/prometheus "
                               "--config.file=/etc/prometheus/prometheus.yml",
             "version": "2.48.1"})
        fs = prom.findings(hosts, probes)
        pf = [f for f in fs if f.get("kind") == "prom_pprof_cmdline"]
        self.assertEqual(len(pf), 1)
        self.assertEqual(pf[0]["severity"], "critical")
        self.assertIn("--config.file", pf[0]["detail"])

    def test_no_new_findings_when_locked_down(self):
        hosts, probes = self._host_with_probe({"version": "2.48.1"})
        fs = prom.findings(hosts, probes)
        kinds = {f.get("kind") for f in fs}
        self.assertNotIn("prom_federate_open", kinds)
        self.assertNotIn("prom_pprof_cmdline", kinds)
        self.assertNotIn("prom_admin_writable", kinds)
        # Fingerprint still emitted for report visibility.
        self.assertIn("prom_fingerprint", kinds)


if __name__ == "__main__":
    unittest.main()
