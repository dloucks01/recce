"""Tests for recce.services.ollama.

Fixtures model the real Ollama HTTP API (v0.x) — see
https://github.com/ollama/ollama/blob/main/docs/api.md:
  * GET  /api/version  -> {"version": "0.1.34"}
  * GET  /api/tags     -> {"models": [{name, size, modified_at, ...}, ...]}
  * POST /api/generate -> for a nonexistent model, 404 with
    {"error":"model '...' not found, try pulling it first"}

Every test uses a real background HTTP server bound to 127.0.0.1:0.
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import ollama


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


class ProbeTest(unittest.TestCase):
    def test_open_ollama_full_disclosure(self):
        """Default-config Ollama: version + tags + generate all open.
        Emits ollama_reachable, ollama_version, ollama_models_disclosed
        and ollama_generate_open — the classic exposed default."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/api/version":
                    _send_json(self, 200, {"version": "0.3.10"})
                elif self.path == "/api/tags":
                    _send_json(self, 200, {"models": [
                        {"name": "llama3.1:8b",
                         "size": 4661211808,
                         "modified_at": "2024-08-01T12:00:00Z"},
                        {"name": "internal-legal-rag:latest",
                         "size": 8000000000,
                         "modified_at": "2024-08-02T09:00:00Z"},
                    ]})
                else:
                    self.send_response(404); self.end_headers()

            def do_POST(self):
                if self.path == "/api/generate":
                    # Canonical Ollama "unknown model" response.
                    _send_json(self, 404, {"error":
                        f"model '{ollama._PROBE_MODEL}' not found, "
                        "try pulling it first"})
                else:
                    self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = ollama.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "0.3.10")
        self.assertTrue(p["models_exposed"])
        self.assertEqual(p["model_count"], 2)
        names = {m["name"] for m in p["models"]}
        self.assertIn("llama3.1:8b", names)
        self.assertIn("internal-legal-rag:latest", names)
        self.assertTrue(p["generate_open"])
        # 0.3.10 is well above 0.1.34 fix → CVE gate stays quiet.
        self.assertFalse(p["cve_2024_37032"])

    def test_locked_down_ollama_only_version(self):
        """A hardened deployment — /api/version answers but /api/tags and
        /api/generate are gated by a fronting proxy (403). Only the
        reachable + version findings fire; no models or generate ones."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/api/version":
                    _send_json(self, 200, {"version": "0.3.10"})
                else:
                    self.send_response(403); self.end_headers()

            def do_POST(self):
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = ollama.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "0.3.10")
        self.assertFalse(p["models_exposed"])
        self.assertFalse(p["generate_open"])
        self.assertFalse(p["cve_2024_37032"])

    def test_cve_2024_37032_gated_vulnerable(self):
        """Version 0.1.32 is below the 0.1.34 fix → CVE finding fires."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/api/version":
                    _send_json(self, 200, {"version": "0.1.32"})
                else:
                    self.send_response(404); self.end_headers()

            def do_POST(self):
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = ollama.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["cve_2024_37032"])

        # Verify the finding wire-format.
        from recce.core.models import Host, Port
        hosts = [Host(ip="127.0.0.1", ports=[Port(
            portid=srv.server_address[1], state="open", service="ollama")])]
        probes = {("127.0.0.1", srv.server_address[1]): p}
        fs = ollama.findings(hosts, probes)
        cve = [f for f in fs if f.get("kind") == "ollama_cve_2024_37032"]
        self.assertEqual(len(cve), 1)
        self.assertEqual(cve[0]["severity"], "critical")
        self.assertIn("0.1.34", cve[0]["detail"])
        self.assertIn("CWE-22", cve[0]["cwes"])

    def test_cve_2024_37032_gated_patched(self):
        """Version 0.1.34 IS the fix — CVE finding must NOT fire."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/api/version":
                    _send_json(self, 200, {"version": "0.1.34"})
                else:
                    self.send_response(404); self.end_headers()

            def do_POST(self):
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = ollama.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["cve_2024_37032"])

    def test_cve_2024_37032_gated_unknown_version_stays_silent(self):
        """Un-parseable version string → CVE gate stays silent (never
        ship an unverified CVE). Fingerprint alone insufficient."""
        # An Ollama-like response with a non-standard version string.
        class H(_Base):
            def do_GET(self):
                if self.path == "/api/version":
                    _send_json(self, 200, {"version": "custom-build"})
                else:
                    self.send_response(404); self.end_headers()

            def do_POST(self):
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = ollama.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        # Version has no dot → probe rejects it as not-really-Ollama;
        # reachable stays false so nothing is over-emitted.
        self.assertFalse(p["reachable"])
        self.assertFalse(p["cve_2024_37032"])

    def test_non_ollama_service_not_flagged(self):
        """A generic web service on port 11434 (a squatting proxy) must
        NOT be flagged as Ollama. Fingerprint requires the JSON version
        body, not just a 200 OK."""
        class H(_Base):
            def do_GET(self):
                body = b"<html><body>hi</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = ollama.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p["reachable"])

    def test_dead_port(self):
        """Connect refused → all-false probe, no crash."""
        p = ollama.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])
        self.assertFalse(p["generate_open"])
        self.assertFalse(p["models_exposed"])

    def test_generate_probe_uses_invalid_model_name(self):
        """Correctness safeguard: the /api/generate reachability probe
        must send a syntactically-marked, obviously-invalid model name
        (never a real one), so the daemon short-circuits with an error
        before running any inference — non-destructive by construction."""
        seen_payloads: list = []

        class H(_Base):
            def do_GET(self):
                if self.path == "/api/version":
                    _send_json(self, 200, {"version": "0.3.10"})
                else:
                    self.send_response(404); self.end_headers()

            def do_POST(self):
                if self.path == "/api/generate":
                    ln = int(self.headers.get("Content-Length") or 0)
                    seen_payloads.append(self.rfile.read(ln))
                    _send_json(self, 404, {"error": "model not found"})
                else:
                    self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            ollama.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(len(seen_payloads), 1)
        req = json.loads(seen_payloads[0].decode("utf-8"))
        # The probe must use the sentinel invalid-model constant.
        self.assertEqual(req["model"], ollama._PROBE_MODEL)
        self.assertIn("recce-nonexistent", req["model"])
        # And it must set stream: false so the server errors immediately
        # instead of holding a long-lived streaming connection.
        self.assertFalse(req["stream"])

    def test_generate_open_finding_fires_on_error_signature(self):
        """A 404 with the canonical model-not-found error IS the proof
        the endpoint is unauth-open — the finding must fire."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/api/version":
                    _send_json(self, 200, {"version": "0.3.10"})
                else:
                    self.send_response(404); self.end_headers()

            def do_POST(self):
                _send_json(self, 404, {"error":
                    "model 'x' not found, try pulling it first"})

        srv, _t = _serve(H)
        try:
            p = ollama.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["generate_open"])

        from recce.core.models import Host, Port
        hosts = [Host(ip="127.0.0.1", ports=[Port(
            portid=srv.server_address[1], state="open", service="ollama")])]
        probes = {("127.0.0.1", srv.server_address[1]): p}
        fs = ollama.findings(hosts, probes)
        g = [f for f in fs if f.get("kind") == "ollama_generate_open"]
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]["severity"], "high")
        self.assertEqual(g[0]["depth_tier"], "t2")


class FindingsTest(unittest.TestCase):
    """Finding-emission wiring for the four/five kinds."""

    def _host_with_probe(self, probe_dict, port=11434):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.5", ports=[Port(portid=port, state="open",
                                             service="ollama")])
        probes = {("10.0.0.5", port):
                  {"reachable": True, "version": "0.3.10", **probe_dict}}
        return [h], probes

    def test_reachable_and_version_always_fire(self):
        hosts, probes = self._host_with_probe({})
        fs = ollama.findings(hosts, probes)
        kinds = {f.get("kind") for f in fs}
        self.assertIn("ollama_reachable", kinds)
        self.assertIn("ollama_version", kinds)
        # No optional caps → no other findings.
        self.assertNotIn("ollama_models_disclosed", kinds)
        self.assertNotIn("ollama_generate_open", kinds)
        self.assertNotIn("ollama_cve_2024_37032", kinds)
        # Every finding carries the mandatory metadata fields.
        for f in fs:
            self.assertIn("kind", f)
            self.assertIn("severity", f)
            self.assertIn("depth_tier", f)
            self.assertIn("exploit_note", f)
            self.assertIn("cwes", f)

    def test_models_disclosed_finding_lists_names(self):
        hosts, probes = self._host_with_probe({
            "models_exposed": True,
            "model_count": 3,
            "models": [
                {"name": "mistral:7b", "size": 4113301024,
                 "modified_at": "2024-08-01"},
                {"name": "codellama:13b", "size": 7365960936,
                 "modified_at": "2024-08-02"},
                {"name": "acme-support-bot:latest", "size": 0,
                 "modified_at": "2024-08-03"},
            ],
        })
        fs = ollama.findings(hosts, probes)
        m = [f for f in fs if f.get("kind") == "ollama_models_disclosed"]
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["severity"], "medium")
        self.assertEqual(m[0]["depth_tier"], "t2")
        self.assertIn("mistral:7b", m[0]["detail"])
        self.assertIn("acme-support-bot:latest", m[0]["detail"])
        self.assertIn("3", m[0]["detail"])  # count

    def test_findings_to_vulns_wires_up(self):
        """The module's findings_to_vulns must produce a per-ip vuln
        dict keyed by our target IP — smoke-test the report pipeline
        contract (findings → vulns → workbook)."""
        hosts, probes = self._host_with_probe({
            "models_exposed": True, "model_count": 1,
            "models": [{"name": "llama3", "size": 0, "modified_at": ""}],
            "generate_open": True, "generate_status": 404,
            "generate_error": "model not found",
        })
        fs = ollama.findings(hosts, probes)
        by_ip = ollama.findings_to_vulns(fs)
        self.assertIn("10.0.0.5", by_ip)
        self.assertTrue(len(by_ip["10.0.0.5"]) >= 2)


class HelpersTest(unittest.TestCase):
    def test_parse_version_accepts_ollama_shapes(self):
        self.assertEqual(ollama._parse_version("0.1.32"), (0, 1, 32))
        self.assertEqual(ollama._parse_version("0.1.34"), (0, 1, 34))
        self.assertEqual(ollama._parse_version("v0.3.10"), (0, 3, 10))
        # Pre-release suffix still yields the base tuple.
        self.assertEqual(ollama._parse_version("0.1.34-rc1"), (0, 1, 34))

    def test_parse_version_rejects_garbage(self):
        self.assertIsNone(ollama._parse_version(""))
        self.assertIsNone(ollama._parse_version("custom-build"))
        self.assertIsNone(ollama._parse_version(None))
        self.assertIsNone(ollama._parse_version("0.1"))  # need three parts

    def test_ollama_targets_matches_module_scope(self):
        """ollama_targets must live at MODULE scope (not nested in a
        class) — the _module_scoped_check qualname rule. This test also
        exercises the port + service detection."""
        # Qualname of a module-level function is just its bare name.
        self.assertEqual(ollama.ollama_targets.__qualname__, "ollama_targets")

        from recce.core.models import Host, Port
        hosts = [
            Host(ip="1.1.1.1", ports=[Port(portid=11434, state="open",
                                            service="")]),
            # Detected by service name even on a non-default port.
            Host(ip="2.2.2.2", ports=[Port(portid=8000, state="open",
                                            service="ollama")]),
            # Not Ollama.
            Host(ip="3.3.3.3", ports=[Port(portid=80, state="open",
                                            service="http")]),
        ]
        tgts = ollama.ollama_targets(hosts)
        ips = {t["ip"] for t in tgts}
        self.assertEqual(ips, {"1.1.1.1", "2.2.2.2"})

    def test_narrative_covers_every_emitted_kind(self):
        """_NARRATIVE must carry an operator-facing entry for every
        kind the module emits, so the report renderer never has a
        missing-entry blank."""
        expected = {"ollama_reachable", "ollama_version",
                    "ollama_models_disclosed", "ollama_generate_open",
                    "ollama_cve_2024_37032"}
        self.assertTrue(expected.issubset(set(ollama._NARRATIVE)))


if __name__ == "__main__":
    unittest.main()
