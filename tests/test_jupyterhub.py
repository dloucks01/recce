"""Tests for recce.services.jupyterhub.

Fixtures model a realistic Jupyter Server / JupyterHub HTTP surface
using a threaded stdlib HTTPServer:

  * GET /api        — returns {"version": "..."} for fingerprint + version
  * GET /hub/api/info — returns JupyterHub identity (multi-tenant flag)
  * GET /api/kernels  — 200 + JSON list on the unauth path; 403 when
                        auth is enforced. WE NEVER POST — the probe
                        must confirm the RCE primitive using the GET.
  * GET /api/contents — 200 + JSON dict on the unauth path; 403 when
                        auth is enforced.

Every test asserts a specific emitted `kind` (or its absence) so an
unauth signal can never regress silently — and so the "GET-only proof"
contract for the RCE finding is enforced by construction (the fake
server never accepts POST).
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.core.models import Host, Port
from recce.services import jupyterhub


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    # A test handler that fails loudly on POST — the probe MUST NEVER
    # invoke POST /api/kernels (that would actually spawn a kernel).
    def do_POST(self):  # pragma: no cover - reached only on a regression
        raise AssertionError(
            "recce.services.jupyterhub probe issued a POST — SAFE-probe "
            "contract violated (would have spawned a kernel).")

    def log_message(self, *a, **k):
        pass


def _send(handler, status, body=b"", ctype="application/json",
          server_header: str | None = "TornadoServer/6.2"):
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    if server_header:
        handler.send_header("Server", server_header)
    handler.end_headers()
    if body:
        handler.wfile.write(body)


# --- Handler builders --------------------------------------------------------

def _make_jupyter_handler(*, version="2.11.2", is_hub=False,
                          kernels_unauth=True, contents_unauth=True,
                          api_status=200,
                          server_header="TornadoServer/6.2"):
    class H(_Base):
        def do_GET(self):
            p = self.path
            if p == "/api":
                if api_status != 200:
                    _send(self, api_status, b"{}",
                          server_header=server_header)
                    return
                body = json.dumps({"version": version}).encode()
                _send(self, 200, body, server_header=server_header)
                return
            if p == "/hub/api/info":
                if is_hub:
                    body = json.dumps({"version": version,
                                       "python": "3.11"}).encode()
                    _send(self, 200, body, server_header=server_header)
                    return
                _send(self, 404, b"", server_header=server_header)
                return
            if p == "/api/kernels":
                if kernels_unauth:
                    # Realistic Jupyter response: JSON list (empty when
                    # no kernel is running).
                    _send(self, 200, b"[]", server_header=server_header)
                else:
                    _send(self, 403, b'{"message":"forbidden"}',
                          server_header=server_header)
                return
            if p == "/api/contents":
                if contents_unauth:
                    body = json.dumps({
                        "name": "", "path": "", "type": "directory",
                        "content": [
                            {"name": "secrets.ipynb", "path": "secrets.ipynb",
                             "type": "notebook"},
                        ],
                    }).encode()
                    _send(self, 200, body, server_header=server_header)
                else:
                    _send(self, 403, b'{"message":"forbidden"}',
                          server_header=server_header)
                return
            if p == "/tree":
                _send(self, 200, b"<html><title>Jupyter</title></html>",
                      ctype="text/html", server_header=server_header)
                return
            _send(self, 404, b"", server_header=server_header)


    return H


def _mk_host(ip, port):
    return Host(ip=ip, ports=[Port(portid=port, protocol="tcp",
                                   service="http", product="")])


# --- Fingerprint / reachability ---------------------------------------------

class FingerprintTest(unittest.TestCase):
    def test_tornado_header_and_version_are_fingerprint(self):
        H = _make_jupyter_handler(version="2.11.2")
        srv, _t = _serve(H)
        try:
            pr = jupyterhub.probe("127.0.0.1", srv.server_address[1],
                                  timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version"], "2.11.2")
        self.assertEqual(pr["version_source"], "/api")
        self.assertIn("TornadoServer", pr["server_header"])

    def test_non_jupyter_service_not_flagged(self):
        class H(_Base):
            def do_GET(self):
                # Body has no "jupyter"/"hub", header names something else.
                _send(self, 200, b"<html>unrelated app</html>",
                      ctype="text/html", server_header="nginx/1.25")

        srv, _t = _serve(H)
        try:
            pr = jupyterhub.probe("127.0.0.1", srv.server_address[1],
                                  timeout=2)
        finally:
            srv.shutdown()
        # No Tornado header and no jupyter/hub body -> stays silent.
        self.assertFalse(pr["reachable"])
        self.assertEqual(pr["version"], "")
        self.assertFalse(pr["kernels_no_auth"])
        self.assertFalse(pr["contents_no_auth"])

    def test_dead_port(self):
        pr = jupyterhub.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(pr["reachable"])


# --- Unauth kernel / contents oracles ---------------------------------------

class UnauthOraclesTest(unittest.TestCase):
    def test_unauth_kernels_and_contents_detected(self):
        H = _make_jupyter_handler(kernels_unauth=True, contents_unauth=True)
        srv, _t = _serve(H)
        try:
            pr = jupyterhub.probe("127.0.0.1", srv.server_address[1],
                                  timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["kernels_no_auth"])
        self.assertTrue(pr["contents_no_auth"])

    def test_auth_enforced_kernels_and_contents_not_flagged(self):
        H = _make_jupyter_handler(kernels_unauth=False, contents_unauth=False)
        srv, _t = _serve(H)
        try:
            pr = jupyterhub.probe("127.0.0.1", srv.server_address[1],
                                  timeout=2)
        finally:
            srv.shutdown()
        # /api still fingerprints (200 + version), but the RCE + contents
        # oracles must stay silent when the server enforces auth.
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["kernels_no_auth"])
        self.assertFalse(pr["contents_no_auth"])


# --- JupyterHub detection ---------------------------------------------------

class HubDetectTest(unittest.TestCase):
    def test_hub_endpoint_detected(self):
        H = _make_jupyter_handler(is_hub=True, version="4.0.2")
        srv, _t = _serve(H)
        try:
            pr = jupyterhub.probe("127.0.0.1", srv.server_address[1],
                                  timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["is_hub"])
        self.assertEqual(pr["version"], "4.0.2")

    def test_single_user_server_not_flagged_as_hub(self):
        H = _make_jupyter_handler(is_hub=False)
        srv, _t = _serve(H)
        try:
            pr = jupyterhub.probe("127.0.0.1", srv.server_address[1],
                                  timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["is_hub"])


# --- findings() emission ----------------------------------------------------

class FindingsTest(unittest.TestCase):
    def test_unauth_kernels_emits_critical_and_lifts_version_severity(self):
        H = _make_jupyter_handler(version="2.11.2",
                                  kernels_unauth=True,
                                  contents_unauth=True)
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = jupyterhub.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        # findings() gates on is_jupyter_http, which only accepts the
        # module's HTTP port set. Rekey under 8888 for emission.
        fs = jupyterhub.findings([_mk_host("127.0.0.1", 8888)],
                                 {("127.0.0.1", 8888): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("jupyter_no_auth_kernel_spawn", kinds)
        self.assertIn("jupyter_contents_listable", kinds)
        self.assertIn("jupyter_version", kinds)
        self.assertIn("jupyter_reachable", kinds)

        crit = next(f for f in fs
                    if f["kind"] == "jupyter_no_auth_kernel_spawn")
        self.assertEqual(crit["severity"], "critical")
        self.assertEqual(crit["depth_tier"], "t2")

        contents = next(f for f in fs
                        if f["kind"] == "jupyter_contents_listable")
        self.assertEqual(contents["severity"], "high")
        self.assertEqual(contents["depth_tier"], "t2")

        # Version disclosure severity lifts to high when RCE finding fires.
        v = next(f for f in fs if f["kind"] == "jupyter_version")
        self.assertEqual(v["severity"], "high")

    def test_patched_authed_deployment_emits_no_unauth_findings(self):
        H = _make_jupyter_handler(version="2.14.0",
                                  kernels_unauth=False,
                                  contents_unauth=False)
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = jupyterhub.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        fs = jupyterhub.findings([_mk_host("127.0.0.1", 8888)],
                                 {("127.0.0.1", 8888): pr})
        kinds = [f["kind"] for f in fs]
        # Reachable + version are still fine, but the unauth oracles must
        # stay silent — this is the "auth enforced" regression guard.
        self.assertIn("jupyter_reachable", kinds)
        self.assertIn("jupyter_version", kinds)
        self.assertNotIn("jupyter_no_auth_kernel_spawn", kinds)
        self.assertNotIn("jupyter_contents_listable", kinds)
        v = next(f for f in fs if f["kind"] == "jupyter_version")
        # Without RCE gate, version stays informational.
        self.assertEqual(v["severity"], "info")

    def test_hub_finding_emitted_when_hub_detected(self):
        H = _make_jupyter_handler(is_hub=True, version="4.0.2",
                                  kernels_unauth=False,
                                  contents_unauth=False)
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = jupyterhub.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        fs = jupyterhub.findings([_mk_host("127.0.0.1", 8888)],
                                 {("127.0.0.1", 8888): pr})
        kinds = [f["kind"] for f in fs]
        self.assertIn("jupyterhub_present", kinds)

    def test_findings_to_vulns_round_trip(self):
        H = _make_jupyter_handler(kernels_unauth=True)
        srv, _t = _serve(H)
        port = srv.server_address[1]
        try:
            pr = jupyterhub.probe("127.0.0.1", port, timeout=2)
        finally:
            srv.shutdown()
        fs = jupyterhub.findings([_mk_host("127.0.0.1", 8888)],
                                 {("127.0.0.1", 8888): pr})
        vulns = jupyterhub.findings_to_vulns(fs)
        self.assertIn("127.0.0.1", vulns)
        titles = [v.title for v in vulns["127.0.0.1"]]
        self.assertTrue(any("kernels" in t.lower() for t in titles),
                        f"expected kernels finding in vulns, got {titles}")
        # The critical Vuln keeps the critical severity across conversion.
        sevs = [v.severity for v in vulns["127.0.0.1"]]
        self.assertIn("critical", sevs)


# --- Module-scope target function guard -------------------------------------

class ModuleScopeTest(unittest.TestCase):
    def test_jupyterhub_targets_is_module_scoped(self):
        # scan.py's _module_scoped_check rejects class-nested `_targets`.
        # jupyterhub_targets must be module-scope for the WebUI to see it.
        fn = jupyterhub.jupyterhub_targets
        self.assertNotIn(".", fn.__qualname__)

    def test_jupyterhub_targets_returns_only_http_ports(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=8888, protocol="tcp", state="open",
                             service="http"),
                        Port(portid=8000, protocol="tcp", state="open",
                             service="http-alt"),
                        Port(portid=22, protocol="tcp", state="open",
                             service="ssh")])
        tgts = jupyterhub.jupyterhub_targets([h])
        # Only the HTTP-ish ports (8888/8000, from the module's _HTTP_PORTS)
        # should be listed; ssh must be excluded.
        got = sorted((t["ip"], t["port"]) for t in tgts)
        self.assertEqual(got, [("10.0.0.5", 8000), ("10.0.0.5", 8888)])


if __name__ == "__main__":
    unittest.main()
