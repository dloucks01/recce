"""Tests for kubernetes.py capability gaps landed in the audit-driven pass:

  * kubelet /logs/ directory-listing probe   (CVE-2020-8557, CVE-2024-9042)
  * apiserver SelfSubjectRulesReview probe   (anon RBAC map, definitive)

Both are covered end-to-end from the raw wire response (fixtures are byte-level
directory HTML / SSRR JSON) up through probe() + findings() emission.
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

# Directory index a kubelet with --enable-debugging-handlers=true (default)
# serves for /logs/. Real byte-shape lifted from a stock Ubuntu Kubernetes
# node: a <pre>-wrapped hyperlink list under a `<title>Index of /logs/</title>`.
_LOGS_INDEX = (
    b"<!DOCTYPE html>\n"
    b"<html>\n<head><title>Index of /logs/</title></head>\n"
    b"<body>\n<h1>Index of /logs/</h1>\n<pre>\n"
    b"<a href=\"kube-apiserver.log\">kube-apiserver.log</a>\n"
    b"<a href=\"kube-controller-manager.log\">kube-controller-manager.log</a>\n"
    b"<a href=\"kubelet.log\">kubelet.log</a>\n"
    b"<a href=\"pods/\">pods/</a>\n"
    b"</pre>\n</body>\n</html>\n"
)

# SelfSubjectRulesReview response from a cluster with anon bound to a broad
# ClusterRole (rbac.authorization.k8s.io/v1). Real wire shape.
_SSRR_MUTATING = json.dumps({
    "kind": "SelfSubjectRulesReview",
    "apiVersion": "authorization.k8s.io/v1",
    "status": {
        "resourceRules": [
            {"verbs": ["get", "list", "watch"], "apiGroups": [""],
             "resources": ["pods", "namespaces"]},
            {"verbs": ["create"], "apiGroups": ["batch"],
             "resources": ["cronjobs"]},
            {"verbs": ["impersonate"], "apiGroups": [""],
             "resources": ["users", "groups", "serviceaccounts"]},
        ],
        "nonResourceRules": [
            {"verbs": ["get"], "nonResourceURLs": ["/healthz"]},
        ],
        "incomplete": False,
    },
}).encode()

_SSRR_READONLY = json.dumps({
    "kind": "SelfSubjectRulesReview",
    "apiVersion": "authorization.k8s.io/v1",
    "status": {
        "resourceRules": [
            {"verbs": ["get", "list"], "apiGroups": [""], "resources": ["pods"]},
        ],
        "nonResourceRules": [],
        "incomplete": False,
    },
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
                # drain request body if present so keep-alive doesn't jam
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


# --- kubelet /logs/ ---------------------------------------------------------

class KubeletLogsDirProbeTest(unittest.TestCase):
    def test_looks_like_dir_listing_positive(self):
        self.assertTrue(k8s._looks_like_dir_listing(
            _LOGS_INDEX.decode("utf-8", "replace")))

    def test_looks_like_dir_listing_rejects_empty_and_html_error(self):
        self.assertFalse(k8s._looks_like_dir_listing(""))
        self.assertFalse(k8s._looks_like_dir_listing(None))  # non-str
        self.assertFalse(k8s._looks_like_dir_listing(
            "<html><body>Unauthorized</body></html>"))
        self.assertFalse(k8s._looks_like_dir_listing("{}"))

    def test_probe_captures_logs_dir_on_kubelet(self):
        srv = _ThreadedHTTP({
            ("GET", "/pods"): (401, b"Unauthorized"),
            ("GET", "/stats/summary"): (401, b"Unauthorized"),
            ("GET", "/logs/"): (200, _LOGS_INDEX),
        })
        try:
            orig = k8s.role
            k8s.role = lambda p: "kubelet"
            try:
                pr = k8s.probe("127.0.0.1", srv.port, timeout=3.0)
            finally:
                k8s.role = orig
            self.assertIsNotNone(pr)
            self.assertTrue(pr.get("anon_logs_dir"),
                            f"expected anon_logs_dir=True, got {pr!r}")
        finally:
            srv.close()

    def test_findings_emit_kubelet_logs_dir_critical(self):
        host = Host(ip="10.0.0.90", ports=[Port(portid=10250, state="open")])
        pr = {("10.0.0.90", 10250): {"role": "kubelet", "anon_logs_dir": True}}
        fs = k8s.findings([host], pr)
        matched = [f for f in fs if f.get("kind") == "kubelet_logs_dir"]
        self.assertEqual(len(matched), 1)
        f = matched[0]
        self.assertEqual(f["severity"], "critical")
        self.assertIn("CWE-22", f["cwes"])
        self.assertIn("CWE-306", f["cwes"])
        self.assertIn("/logs/", f["detail"])


# --- SSRR ------------------------------------------------------------------

class ApiserverSSRRProbeTest(unittest.TestCase):
    def _apiserver_srv(self, ssrr_body):
        return _ThreadedHTTP({
            ("GET", "/version"): (200, json.dumps(
                {"gitVersion": "v1.28.2"}).encode()),
            ("GET", "/api/v1/namespaces"): (403, b"Forbidden"),
            ("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreview"):
                (201, ssrr_body),
        })

    def test_probe_captures_mutating_verbs(self):
        srv = self._apiserver_srv(_SSRR_MUTATING)
        try:
            orig = k8s.role
            k8s.role = lambda p: "apiserver"
            try:
                pr = k8s.probe("127.0.0.1", srv.port, timeout=3.0)
            finally:
                k8s.role = orig
            self.assertIsNotNone(pr)
            self.assertEqual(pr.get("anon_ssrr_rules"), 4)   # 3 + 1 nonres
            verbs = pr.get("anon_ssrr_verbs") or []
            for v in ("get", "list", "watch", "create", "impersonate"):
                self.assertIn(v, verbs)
        finally:
            srv.close()

    def test_findings_ssrr_dangerous_is_critical(self):
        host = Host(ip="10.0.0.90", ports=[Port(portid=6443, state="open")])
        pr = {("10.0.0.90", 6443): {
            "role": "apiserver", "version": "v1.28",
            "anon_list": False, "anon_status": 403,
            "anon_ssrr_rules": 3,
            "anon_ssrr_verbs": ["create", "get", "impersonate", "list"]}}
        fs = k8s.findings([host], pr)
        matched = [f for f in fs if f.get("kind") == "api_anon_ssrr"]
        self.assertEqual(len(matched), 1)
        f = matched[0]
        self.assertEqual(f["severity"], "critical")
        # mutating verbs surface in the detail body
        self.assertIn("create", f["detail"])
        self.assertIn("impersonate", f["detail"])
        self.assertIn("CWE-269", f["cwes"])

    def test_findings_ssrr_readonly_is_high_not_critical(self):
        host = Host(ip="10.0.0.90", ports=[Port(portid=6443, state="open")])
        pr = {("10.0.0.90", 6443): {
            "role": "apiserver", "version": "v1.28",
            "anon_list": True, "anon_status": 200,
            "anon_ssrr_rules": 1, "anon_ssrr_verbs": ["get", "list"]}}
        fs = k8s.findings([host], pr)
        matched = [f for f in fs if f.get("kind") == "api_anon_ssrr"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["severity"], "high")
        # existing api_anon_list finding is not disturbed
        self.assertTrue(any(f.get("kind") == "api_anon_list" for f in fs))

    def test_findings_no_ssrr_no_finding(self):
        host = Host(ip="10.0.0.90", ports=[Port(portid=6443, state="open")])
        pr = {("10.0.0.90", 6443): {"role": "apiserver", "version": "v1.28",
                                     "anon_status": 200, "anon_list": True}}
        fs = k8s.findings([host], pr)
        self.assertFalse(any(f.get("kind") == "api_anon_ssrr" for f in fs))

    def test_findings_to_vulns_bridges_ssrr(self):
        host = Host(ip="10.0.0.90", ports=[Port(portid=6443, state="open")])
        pr = {("10.0.0.90", 6443): {
            "role": "apiserver", "version": "v1.28",
            "anon_list": False, "anon_status": 403,
            "anon_ssrr_rules": 2, "anon_ssrr_verbs": ["create", "get"]}}
        fs = k8s.findings([host], pr)
        by = k8s.findings_to_vulns(fs)
        vs = by.get("10.0.0.90", [])
        self.assertTrue(any(v.script_id.startswith("k8s:") and
                            "SelfSubjectRulesReview" in v.title for v in vs))


if __name__ == "__main__":
    unittest.main()
