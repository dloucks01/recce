"""T2 promotion for api_anon_list — bounded /api/v1/pods?limit=10 canary.

Covers:
  * _probe_pods_canary parses the pod list, records namespace/name/image
    triples, ignores malformed items, caps the sample.
  * probe() attaches pods_evidence on the apiserver branch when anon LIST
    is confirmed (real HTTP fake — vulnerable server path).
  * findings() upgrades the api_anon_list depth_tier to "t2" and appends
    a T2 proof line to detail when evidence is present; stays "t1"
    (patched) when the canary returned nothing.
  * probe() does not surface pods_evidence when anon LIST is refused
    (403 patched path) — canary must gate on anon_list.
"""
from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce.core.models import Host, Port
from recce.services import kubernetes as k8s


# --- wire fixtures ---------------------------------------------------------

# A minimal PodList as returned by kube-apiserver's /api/v1/pods?limit=10.
# Real byte-shape lifted from a stock v1.28 cluster.
_PODLIST_BODY = json.dumps({
    "kind": "PodList",
    "apiVersion": "v1",
    "metadata": {"resourceVersion": "12345"},
    "items": [
        {"metadata": {"name": "coredns-abc123", "namespace": "kube-system"},
         "spec": {"containers": [
             {"name": "coredns", "image": "registry.k8s.io/coredns/coredns:v1.10.1"},
         ]}},
        {"metadata": {"name": "prometheus-0", "namespace": "monitoring"},
         "spec": {"containers": [
             {"name": "prometheus", "image": "prom/prometheus:v2.45.0"},
             {"name": "config-reloader", "image": "quay.io/prometheus-operator/prometheus-config-reloader:v0.68"},
         ]}},
        {"metadata": {"name": "web-7d9c6f", "namespace": "default"},
         "spec": {"containers": [
             {"name": "nginx", "image": "nginx:1.25"},
         ]}},
    ],
}).encode()

_NS_BODY = json.dumps({
    "kind": "NamespaceList", "apiVersion": "v1",
    "items": [{"metadata": {"name": "default"}},
              {"metadata": {"name": "kube-system"}}],
}).encode()

_VERSION_BODY = json.dumps({"gitVersion": "v1.28.2"}).encode()

# Empty-items list — a probe response that looks legit but has no pods; must
# NOT upgrade to T2 (no real evidence).
_EMPTY_PODLIST = json.dumps({
    "kind": "PodList", "apiVersion": "v1",
    "metadata": {"resourceVersion": "1"}, "items": [],
}).encode()


# --- helpers ---------------------------------------------------------------

class _ThreadedHTTP:
    """Minimal one-off HTTP fake with per-path (method, path) -> (status, bytes)."""

    def __init__(self, routes):
        self.routes = routes

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self_):
                key = (self_.command, self_.path)
                status, body = self.routes.get(key, (404, b""))
                self_.send_response(status)
                self_.send_header("Content-Length", str(len(body)))
                self_.send_header("Content-Type", "application/json"
                                  if body.startswith(b"{") else "text/html")
                self_.end_headers()
                if body:
                    self_.wfile.write(body)
                cl = int(self_.headers.get("Content-Length") or 0)
                if cl and self_.command != "POST":
                    self_.rfile.read(cl)

            def do_GET(self_): self_._send()

            def do_POST(self_):
                cl = int(self_.headers.get("Content-Length") or 0)
                if cl:
                    self_.rfile.read(cl)
                self_._send()

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def _vulnerable_apiserver():
    """A cluster with anon LIST + bounded pods canary returning 3 real pods."""
    return _ThreadedHTTP({
        ("GET", "/version"): (200, _VERSION_BODY),
        ("GET", "/api/v1/namespaces"): (200, _NS_BODY),
        ("GET", "/api/v1/secrets"): (403, b"Forbidden"),
        ("GET", "/api/v1/configmaps"): (403, b"Forbidden"),
        ("GET", "/api/v1/serviceaccounts"): (403, b"Forbidden"),
        ("GET", "/api/v1/nodes"): (403, b"Forbidden"),
        ("GET", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"):
            (403, b"Forbidden"),
        # NB: unlimited /api/v1/pods (called by the escape-count block) and the
        # bounded /api/v1/pods?limit=10 canary are DISTINCT keys.
        ("GET", "/api/v1/pods"): (200, _PODLIST_BODY),
        ("GET", "/api/v1/pods?limit=10"): (200, _PODLIST_BODY),
        ("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreview"):
            (403, b"Forbidden"),
    })


def _patched_apiserver():
    """A cluster with anonymous LIST refused everywhere (403)."""
    return _ThreadedHTTP({
        ("GET", "/version"): (200, _VERSION_BODY),
        ("GET", "/api/v1/namespaces"): (403, b"Forbidden"),
        ("GET", "/api/v1/pods?limit=10"): (403, b"Forbidden"),
        ("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreview"):
            (403, b"Forbidden"),
    })


def _empty_pods_apiserver():
    """Vulnerable anon LIST, but the pods canary returned an empty PodList —
    T1 must be kept (no real evidence)."""
    return _ThreadedHTTP({
        ("GET", "/version"): (200, _VERSION_BODY),
        ("GET", "/api/v1/namespaces"): (200, _NS_BODY),
        ("GET", "/api/v1/pods"): (200, _EMPTY_PODLIST),
        ("GET", "/api/v1/pods?limit=10"): (200, _EMPTY_PODLIST),
        ("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreview"):
            (403, b"Forbidden"),
    })


# --- direct unit test for the canary --------------------------------------

class PodsCanaryUnitTest(unittest.TestCase):
    def test_parses_pods_sample_and_caps(self):
        srv = _vulnerable_apiserver()
        try:
            ev = k8s._probe_pods_canary("127.0.0.1", srv.port,
                                        tls=False, timeout=3.0)
        finally:
            srv.close()
        self.assertIsNotNone(ev)
        self.assertEqual(ev["endpoint"], "/api/v1/pods?limit=10")
        self.assertEqual(ev["count"], 3)
        sample = ev["sample"]
        self.assertEqual(len(sample), 3)
        # namespace + name + image survive
        self.assertEqual(sample[0]["namespace"], "kube-system")
        self.assertEqual(sample[0]["name"], "coredns-abc123")
        self.assertIn("coredns", sample[0]["images"][0])
        # multi-container pod records both images
        self.assertEqual(len(sample[1]["images"]), 2)

    def test_returns_none_on_empty_items(self):
        srv = _empty_pods_apiserver()
        try:
            ev = k8s._probe_pods_canary("127.0.0.1", srv.port,
                                        tls=False, timeout=3.0)
        finally:
            srv.close()
        self.assertIsNone(ev)

    def test_returns_none_on_403(self):
        srv = _patched_apiserver()
        try:
            ev = k8s._probe_pods_canary("127.0.0.1", srv.port,
                                        tls=False, timeout=3.0)
        finally:
            srv.close()
        self.assertIsNone(ev)

    def test_returns_none_on_timeout(self):
        # No server bound at this port — connection refused / times out.
        # 127.0.0.1:1 is reliably closed on Linux CI runners.
        ev = k8s._probe_pods_canary("127.0.0.1", 1, tls=False, timeout=1.0)
        self.assertIsNone(ev)


# --- probe() integration --------------------------------------------------

class ProbeAttachesEvidenceTest(unittest.TestCase):
    def _run_probe(self, srv):
        orig = k8s.role
        k8s.role = lambda p: "apiserver"
        try:
            return k8s.probe("127.0.0.1", srv.port, timeout=3.0)
        finally:
            k8s.role = orig

    def test_vulnerable_apiserver_attaches_pods_evidence(self):
        srv = _vulnerable_apiserver()
        try:
            pr = self._run_probe(srv)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertTrue(pr.get("anon_list"))
        ev = pr.get("pods_evidence")
        self.assertIsNotNone(ev, f"expected pods_evidence, got {pr!r}")
        self.assertEqual(ev["endpoint"], "/api/v1/pods?limit=10")
        self.assertEqual(ev["count"], 3)

    def test_patched_apiserver_no_evidence(self):
        srv = _patched_apiserver()
        try:
            pr = self._run_probe(srv)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertFalse(pr.get("anon_list"))
        # canary must not run when anon_list is False
        self.assertIsNone(pr.get("pods_evidence"))

    def test_empty_pods_apiserver_no_evidence(self):
        srv = _empty_pods_apiserver()
        try:
            pr = self._run_probe(srv)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        self.assertTrue(pr.get("anon_list"))
        # empty pods list = no real evidence, canary returns None
        self.assertIsNone(pr.get("pods_evidence"))


# --- findings() tier upgrade + detail line --------------------------------

class FindingsTierUpgradeTest(unittest.TestCase):
    def _host(self):
        return Host(ip="10.0.0.90", ports=[Port(portid=6443, state="open")])

    def test_evidence_present_upgrades_to_t2_and_writes_proof_line(self):
        host = self._host()
        pr = {("10.0.0.90", 6443): {
            "role": "apiserver", "version": "v1.28.2",
            "anon_list": True, "anon_status": 200,
            "pods_evidence": {
                "endpoint": "/api/v1/pods?limit=10",
                "count": 3,
                "sample": [
                    {"namespace": "kube-system",
                     "name": "coredns-abc123",
                     "images": ["registry.k8s.io/coredns/coredns:v1.10.1"]},
                    {"namespace": "monitoring",
                     "name": "prometheus-0",
                     "images": ["prom/prometheus:v2.45.0"]},
                    {"namespace": "default",
                     "name": "web-7d9c6f",
                     "images": ["nginx:1.25"]},
                ],
            },
        }}
        fs = k8s.findings([host], pr)
        matched = [f for f in fs if f.get("kind") == "api_anon_list"]
        self.assertEqual(len(matched), 1)
        f = matched[0]
        self.assertEqual(f["depth_tier"], "t2")
        # concrete namespace/name/image lands in the detail body
        self.assertIn("T2 proof", f["detail"])
        self.assertIn("/api/v1/pods?limit=10", f["detail"])
        self.assertIn("kube-system/coredns-abc123", f["detail"])
        self.assertIn("coredns", f["detail"])
        self.assertIn("3 live pod", f["detail"])

    def test_no_evidence_stays_t1(self):
        host = self._host()
        pr = {("10.0.0.90", 6443): {
            "role": "apiserver", "version": "v1.28.2",
            "anon_list": True, "anon_status": 200}}
        fs = k8s.findings([host], pr)
        matched = [f for f in fs if f.get("kind") == "api_anon_list"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["depth_tier"], "t1")
        self.assertNotIn("T2 proof", matched[0]["detail"])

    def test_secrets_still_critical_when_t2(self):
        # T2 upgrade must not alter the severity gate — anon_secrets still
        # controls critical-vs-high.
        host = self._host()
        pr = {("10.0.0.90", 6443): {
            "role": "apiserver", "version": "v1.28.2",
            "anon_list": True, "anon_secrets": True, "anon_status": 200,
            "pods_evidence": {
                "endpoint": "/api/v1/pods?limit=10", "count": 1,
                "sample": [{"namespace": "default", "name": "p1",
                            "images": ["nginx:1.25"]}]},
        }}
        fs = k8s.findings([host], pr)
        f = next(f for f in fs if f.get("kind") == "api_anon_list")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("incl. Secrets", f["title"])


if __name__ == "__main__":
    unittest.main()
