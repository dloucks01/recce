"""admission_webhook_disclosure — SAFE read of admissionregistration.k8s.io.

Covers:
  * _probe_admission_webhooks parses mutating + validating webhook
    configurations, records name/failurePolicy/timeoutSeconds triples,
    caps the sample, tolerates malformed items, treats 403/404 as absent.
  * probe() attaches anon_webhooks when the /api/v1/pods anonymous read
    succeeded — the guidance gate; skips it when pods were refused.
  * findings() emits k8s_webhook_disclosure (medium, t1, CWE-200) with the
    webhook names + failure_policy + timeout_seconds, and calls out any
    mutating webhook whose failurePolicy=Ignore.
  * absent case (patched cluster): no anon_webhooks, no finding.

Wire-derived fixtures — no live network; monkeypatched via a stdlib HTTP
fake bound to 127.0.0.1.
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

# Real-shape MutatingWebhookConfigurationList from admissionregistration.k8s.io/v1
_MWC_BODY = json.dumps({
    "kind": "MutatingWebhookConfigurationList",
    "apiVersion": "admissionregistration.k8s.io/v1",
    "items": [
        {"metadata": {"name": "sidecar-injector"},
         "webhooks": [
             {"name": "sidecar.injector.example.com",
              "failurePolicy": "Ignore",
              "timeoutSeconds": 5,
              "clientConfig": {"service": {"name": "sidecar-injector",
                                           "namespace": "kube-system"}}},
         ]},
        {"metadata": {"name": "pod-mutation"},
         "webhooks": [
             {"name": "mutate.pods.example.com",
              "failurePolicy": "Fail",
              "timeoutSeconds": 10,
              "clientConfig": {"url": "https://pod-mutation.svc/mutate"}},
         ]},
    ],
}).encode()

_VWC_BODY = json.dumps({
    "kind": "ValidatingWebhookConfigurationList",
    "apiVersion": "admissionregistration.k8s.io/v1",
    "items": [
        {"metadata": {"name": "pod-security"},
         "webhooks": [
             {"name": "validate.podsecurity.example.com",
              "failurePolicy": "Fail",
              "timeoutSeconds": 10},
             {"name": "validate.imagepolicy.example.com",
              "failurePolicy": "Ignore"},  # unset timeoutSeconds
         ]},
    ],
}).encode()

_EMPTY_LIST = json.dumps({
    "kind": "MutatingWebhookConfigurationList",
    "apiVersion": "admissionregistration.k8s.io/v1", "items": [],
}).encode()

_PODLIST_BODY = json.dumps({
    "kind": "PodList", "apiVersion": "v1",
    "items": [{"metadata": {"name": "p1", "namespace": "default"},
               "spec": {"containers": [{"name": "c", "image": "nginx:1.25"}]}}],
}).encode()

_NS_BODY = json.dumps({
    "kind": "NamespaceList", "apiVersion": "v1",
    "items": [{"metadata": {"name": "default"}}],
}).encode()

_VERSION_BODY = json.dumps({"gitVersion": "v1.28.2"}).encode()

_MWC_PATH = ("/apis/admissionregistration.k8s.io/v1/"
             "mutatingwebhookconfigurations")
_VWC_PATH = ("/apis/admissionregistration.k8s.io/v1/"
             "validatingwebhookconfigurations")


class _ThreadedHTTP:
    """Minimal HTTP fake keyed by (method, path) -> (status, bytes)."""

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
                                  if body.startswith(b"{") else "text/plain")
                self_.end_headers()
                if body:
                    self_.wfile.write(body)

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
    """Anon LIST works; /api/v1/pods returns pods; both webhook lists disclosed."""
    return _ThreadedHTTP({
        ("GET", "/version"): (200, _VERSION_BODY),
        ("GET", "/api/v1/namespaces"): (200, _NS_BODY),
        ("GET", "/api/v1/secrets"): (403, b"Forbidden"),
        ("GET", "/api/v1/configmaps"): (403, b"Forbidden"),
        ("GET", "/api/v1/serviceaccounts"): (403, b"Forbidden"),
        ("GET", "/api/v1/nodes"): (403, b"Forbidden"),
        ("GET", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"):
            (403, b"Forbidden"),
        ("GET", "/api/v1/pods"): (200, _PODLIST_BODY),
        ("GET", "/api/v1/pods?limit=10"): (200, _PODLIST_BODY),
        ("GET", _MWC_PATH): (200, _MWC_BODY),
        ("GET", _VWC_PATH): (200, _VWC_BODY),
        ("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreview"):
            (403, b"Forbidden"),
    })


def _patched_apiserver():
    """Anon LIST is 403 everywhere — no webhook probe should fire."""
    return _ThreadedHTTP({
        ("GET", "/version"): (200, _VERSION_BODY),
        ("GET", "/api/v1/namespaces"): (403, b"Forbidden"),
        ("GET", "/api/v1/pods"): (403, b"Forbidden"),
        ("GET", "/api/v1/pods?limit=10"): (403, b"Forbidden"),
        ("GET", _MWC_PATH): (403, b"Forbidden"),
        ("GET", _VWC_PATH): (403, b"Forbidden"),
        ("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreview"):
            (403, b"Forbidden"),
    })


def _absent_webhooks_apiserver():
    """Anon LIST + pods work, but webhook endpoints refuse (403). anon_webhooks
    must be an empty list — no finding."""
    return _ThreadedHTTP({
        ("GET", "/version"): (200, _VERSION_BODY),
        ("GET", "/api/v1/namespaces"): (200, _NS_BODY),
        ("GET", "/api/v1/pods"): (200, _PODLIST_BODY),
        ("GET", "/api/v1/pods?limit=10"): (200, _PODLIST_BODY),
        ("GET", _MWC_PATH): (403, b"Forbidden"),
        ("GET", _VWC_PATH): (403, b"Forbidden"),
        ("POST", "/apis/authorization.k8s.io/v1/selfsubjectrulesreview"):
            (403, b"Forbidden"),
    })


# --- direct unit tests for the helper -------------------------------------

class ProbeAdmissionWebhooksUnitTest(unittest.TestCase):
    def test_parses_mutating_and_validating(self):
        srv = _vulnerable_apiserver()
        try:
            got = k8s._probe_admission_webhooks(
                "127.0.0.1", srv.port, tls=False, timeout=3.0)
        finally:
            srv.close()
        by_name = {w["name"]: w for w in got}
        self.assertIn("sidecar.injector.example.com", by_name)
        self.assertIn("mutate.pods.example.com", by_name)
        self.assertIn("validate.podsecurity.example.com", by_name)
        self.assertIn("validate.imagepolicy.example.com", by_name)

        inject = by_name["sidecar.injector.example.com"]
        self.assertEqual(inject["kind"], "mutating")
        self.assertEqual(inject["failure_policy"], "Ignore")
        self.assertEqual(inject["timeout_seconds"], 5)
        self.assertEqual(inject["config"], "sidecar-injector")

        val = by_name["validate.imagepolicy.example.com"]
        self.assertEqual(val["kind"], "validating")
        self.assertEqual(val["failure_policy"], "Ignore")
        # timeoutSeconds unset in the fixture — recorded as None
        self.assertIsNone(val["timeout_seconds"])

    def test_returns_empty_on_403(self):
        srv = _patched_apiserver()
        try:
            got = k8s._probe_admission_webhooks(
                "127.0.0.1", srv.port, tls=False, timeout=3.0)
        finally:
            srv.close()
        self.assertEqual(got, [])

    def test_returns_empty_on_empty_items(self):
        srv = _ThreadedHTTP({
            ("GET", _MWC_PATH): (200, _EMPTY_LIST),
            ("GET", _VWC_PATH): (200, _EMPTY_LIST),
        })
        try:
            got = k8s._probe_admission_webhooks(
                "127.0.0.1", srv.port, tls=False, timeout=3.0)
        finally:
            srv.close()
        self.assertEqual(got, [])

    def test_tolerates_malformed_items(self):
        bad = json.dumps({
            "kind": "MutatingWebhookConfigurationList",
            "items": [
                "not-a-dict",
                {"metadata": {"name": "ok"},
                 "webhooks": ["not-a-dict",
                              {"name": "good.example.com",
                               "failurePolicy": "Fail",
                               "timeoutSeconds": 7}]},
            ],
        }).encode()
        srv = _ThreadedHTTP({
            ("GET", _MWC_PATH): (200, bad),
            ("GET", _VWC_PATH): (404, b""),
        })
        try:
            got = k8s._probe_admission_webhooks(
                "127.0.0.1", srv.port, tls=False, timeout=3.0)
        finally:
            srv.close()
        names = [w["name"] for w in got]
        self.assertEqual(names, ["good.example.com"])

    def test_returns_empty_on_connection_refused(self):
        got = k8s._probe_admission_webhooks(
            "127.0.0.1", 1, tls=False, timeout=1.0)
        self.assertEqual(got, [])


# --- probe() integration --------------------------------------------------

class ProbeAttachesWebhooksTest(unittest.TestCase):
    def _run_probe(self, srv):
        orig = k8s.role
        k8s.role = lambda p: "apiserver"
        try:
            return k8s.probe("127.0.0.1", srv.port, timeout=3.0)
        finally:
            k8s.role = orig

    def test_vulnerable_apiserver_attaches_webhooks(self):
        srv = _vulnerable_apiserver()
        try:
            pr = self._run_probe(srv)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        wh = pr.get("anon_webhooks") or []
        self.assertTrue(wh, f"expected anon_webhooks, got {pr!r}")
        # both mutating and validating parsed
        kinds = {w["kind"] for w in wh}
        self.assertEqual(kinds, {"mutating", "validating"})
        # at least one Ignore-failurePolicy hit for the finding path
        self.assertTrue(any(w["failure_policy"] == "Ignore"
                            and w["kind"] == "mutating" for w in wh))

    def test_patched_apiserver_no_webhooks(self):
        srv = _patched_apiserver()
        try:
            pr = self._run_probe(srv)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        # anon LIST refused -> probe skipped entirely
        self.assertNotIn("anon_webhooks", pr)

    def test_absent_apiserver_empty_webhooks(self):
        srv = _absent_webhooks_apiserver()
        try:
            pr = self._run_probe(srv)
        finally:
            srv.close()
        self.assertIsNotNone(pr)
        # the probe ran (pods was 200) but returned nothing
        self.assertEqual(pr.get("anon_webhooks"), [])


# --- findings() ------------------------------------------------------------

class WebhookFindingTest(unittest.TestCase):
    def _host(self):
        return Host(ip="10.0.0.91", ports=[Port(portid=6443, state="open")])

    def test_emits_medium_t1_finding_with_details(self):
        host = self._host()
        pr = {("10.0.0.91", 6443): {
            "role": "apiserver", "version": "v1.28.2",
            "anon_list": True, "anon_status": 200,
            "anon_webhooks": [
                {"kind": "mutating", "config": "sidecar-injector",
                 "name": "sidecar.injector.example.com",
                 "failure_policy": "Ignore", "timeout_seconds": 5},
                {"kind": "validating", "config": "pod-security",
                 "name": "validate.podsecurity.example.com",
                 "failure_policy": "Fail", "timeout_seconds": 10},
            ],
        }}
        fs = k8s.findings([host], pr)
        matched = [f for f in fs if f.get("kind") == "k8s_webhook_disclosure"]
        self.assertEqual(len(matched), 1)
        f = matched[0]
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["depth_tier"], "t1")
        self.assertIn("CWE-200", f["cwes"])
        # webhook names appear in the detail
        self.assertIn("sidecar.injector.example.com", f["detail"])
        self.assertIn("validate.podsecurity.example.com", f["detail"])
        # failure policy + timeout rendered
        self.assertIn("fp=Ignore", f["detail"])
        self.assertIn("fp=Fail", f["detail"])
        self.assertIn("to=5s", f["detail"])
        self.assertIn("to=10s", f["detail"])
        # Ignore-mutating call-out
        self.assertIn("failurePolicy=Ignore", f["detail"])

    def test_absent_when_no_webhooks(self):
        host = self._host()
        pr = {("10.0.0.91", 6443): {
            "role": "apiserver", "version": "v1.28.2",
            "anon_list": True, "anon_status": 200,
            "anon_webhooks": [],
        }}
        fs = k8s.findings([host], pr)
        self.assertFalse(
            [f for f in fs if f.get("kind") == "k8s_webhook_disclosure"])

    def test_no_ignore_hits_omits_ignore_callout(self):
        host = self._host()
        pr = {("10.0.0.91", 6443): {
            "role": "apiserver", "version": "v1.28.2",
            "anon_list": True, "anon_status": 200,
            "anon_webhooks": [
                {"kind": "mutating", "config": "c", "name": "m1",
                 "failure_policy": "Fail", "timeout_seconds": 10},
                {"kind": "validating", "config": "c", "name": "v1",
                 "failure_policy": "Fail", "timeout_seconds": 10},
            ],
        }}
        fs = k8s.findings([host], pr)
        f = next(f for f in fs if f.get("kind") == "k8s_webhook_disclosure")
        self.assertNotIn("failurePolicy=Ignore", f["detail"])


if __name__ == "__main__":
    unittest.main()
