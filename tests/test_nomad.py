"""Tests for recce.services.nomad — unauthenticated Nomad read probe."""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import nomad


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass


class ProbeTest(unittest.TestCase):
    def test_acl_disabled_jobs_readable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.2",
                                                  "ACL": {"Enabled": False}}}).encode()
                elif self.path == "/v1/jobs":
                    body = json.dumps([{"ID": "webapp-prod", "Name": "webapp-prod",
                                        "Type": "service", "Status": "running"},
                                       {"ID": "batch-etl", "Name": "batch-etl",
                                        "Type": "batch", "Status": "pending"}]).encode()
                elif self.path == "/v1/allocations":
                    body = json.dumps([{"ID": "a1"}, {"ID": "a2"}, {"ID": "a3"}]).encode()
                elif self.path == "/v1/nodes":
                    body = json.dumps([{"ID": "n1"}, {"ID": "n2"}]).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["acl_enabled"])
        self.assertEqual(len(p["jobs"]), 2)
        self.assertEqual(p["allocations"], 3)
        self.assertEqual(p["nodes"], 2)

    def test_acl_enforcing_falls_back_to_leader(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/status/leader":
                    body = b'"10.0.0.1:4647"'
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["acl_enabled"])
        self.assertEqual(p["leader"], "10.0.0.1:4647")

    def test_dead_port(self):
        p = nomad.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


class IntegrationTokenLeakTest(unittest.TestCase):
    def test_vault_and_consul_tokens_extracted_from_agent_self(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {
                        "Version": "1.7.5",
                        "ACL": {"Enabled": True},
                        "Vault": {"Address": "https://vault.corp:8200",
                                  "Token": "hvs.CAESIJexampleVaultToken",
                                  "Namespace": "admin"},
                        "Consul": {"Address": "http://consul.corp:8500",
                                   "Token": "b5c31f6a-consul-token-xyz"},
                    }}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                    return
                self.send_response(403); self.end_headers()
            def do_POST(self):
                # bootstrap: already done
                self.send_response(400); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["acl_enabled"])
        self.assertEqual(p["vault"]["address"], "https://vault.corp:8200")
        self.assertEqual(p["vault"]["token"], "hvs.CAESIJexampleVaultToken")
        self.assertEqual(p["vault"]["namespace"], "admin")
        self.assertEqual(p["consul"]["token"], "b5c31f6a-consul-token-xyz")

    def test_finding_emitted_when_integration_token_present(self):
        from recce.core.models import Host, Port
        host = Host(ip="10.0.0.5", ports=[Port(portid=4646, service="nomad")])
        probes = {("10.0.0.5", 4646): {
            "reachable": True, "version": "1.7.5", "acl_enabled": True,
            "jobs": [], "allocations": 0, "nodes": 0, "leader": "10.0.0.5:4647",
            "vault": {"address": "https://v", "token": "hvs.SECRET", "namespace": ""},
            "consul": {}, "vars": [], "acl_bootstrap_token": "",
        }}
        fs = nomad.findings([host], probes)
        kinds = [f["kind"] for f in fs]
        self.assertIn("nomad_integration_token_leak", kinds)
        leak = next(f for f in fs if f["kind"] == "nomad_integration_token_leak")
        self.assertEqual(leak["severity"], "critical")
        self.assertIn("Vault", leak["detail"])

    def test_no_finding_when_no_integration_token(self):
        from recce.core.models import Host, Port
        host = Host(ip="10.0.0.5", ports=[Port(portid=4646, service="nomad")])
        probes = {("10.0.0.5", 4646): {
            "reachable": True, "version": "1.7.5", "acl_enabled": True,
            "jobs": [], "allocations": 0, "nodes": 0, "leader": "x",
            "vault": {}, "consul": {}, "vars": [], "acl_bootstrap_token": "",
        }}
        fs = nomad.findings([host], probes)
        self.assertNotIn("nomad_integration_token_leak",
                         [f["kind"] for f in fs])


class ACLBootstrapTest(unittest.TestCase):
    def test_bootstrap_succeeds_when_uninitialized(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/status/leader":
                    body = b'"10.0.0.9:4647"'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(403); self.end_headers()
            def do_POST(self):
                if self.path == "/v1/acl/bootstrap":
                    body = json.dumps({
                        "AccessorID": "b5d1772c-b16b-9cf5-8620-5c68b32247d5",
                        "SecretID": "3b3a80cd-1c8b-6fe6-7db1-5f01f6c0d0d7",
                        "Name": "Bootstrap Token",
                        "Type": "management",
                        "Global": True,
                    }).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["acl_enabled"])
        self.assertEqual(p["acl_bootstrap_token"],
                         "3b3a80cd-1c8b-6fe6-7db1-5f01f6c0d0d7")

    def test_bootstrap_already_done_yields_no_token(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/status/leader":
                    body = b'"10.0.0.9:4647"'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(403); self.end_headers()
            def do_POST(self):
                body = b"ACL bootstrap already done (reset index: 42)"
                self.send_response(400)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["acl_bootstrap_token"], "")

    def test_finding_emitted_on_bootstrap_token(self):
        from recce.core.models import Host, Port
        host = Host(ip="10.1.1.1", ports=[Port(portid=4646, service="nomad")])
        probes = {("10.1.1.1", 4646): {
            "reachable": True, "version": "1.7.2", "acl_enabled": True,
            "jobs": [], "allocations": 0, "nodes": 0, "leader": "x",
            "vault": {}, "consul": {}, "vars": [],
            "acl_bootstrap_token": "3b3a80cd-1c8b-6fe6-7db1-5f01f6c0d0d7",
        }}
        fs = nomad.findings([host], probes)
        boot = [f for f in fs if f["kind"] == "nomad_acl_bootstrap_available"]
        self.assertEqual(len(boot), 1)
        self.assertEqual(boot[0]["severity"], "critical")
        self.assertIn("CWE-306", boot[0]["cwes"])

    def test_bootstrap_not_attempted_when_token_supplied(self):
        posts_seen = []

        class H(_Base):
            def do_GET(self):
                self.send_response(403); self.end_headers()
            def do_POST(self):
                posts_seen.append(self.path)
                self.send_response(200)
                body = b'{}'
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)

        # /v1/agent/self returns 403 for both — no leader either. Reachable=False.
        # So bootstrap wouldn't even run. Instead simulate leader OK.
        class H2(_Base):
            def do_GET(self):
                if self.path == "/v1/status/leader":
                    body = b'"x"'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(403); self.end_headers()
            def do_POST(self):
                posts_seen.append(self.path)
                body = json.dumps({"SecretID": "should-not-see"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)

        srv, _t = _serve(H2)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1],
                            timeout=2, token="supplied-token")
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["acl_bootstrap_token"], "")
        self.assertNotIn("/v1/acl/bootstrap", posts_seen)


class VariablesEnumTest(unittest.TestCase):
    def test_variables_readable_pulls_items(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.5",
                                                  "ACL": {"Enabled": False}}}).encode()
                elif self.path == "/v1/vars":
                    body = json.dumps([
                        {"Namespace": "default", "Path": "nomad/jobs/webapp"},
                        {"Namespace": "default", "Path": "secrets/api-keys"},
                    ]).encode()
                elif self.path.startswith("/v1/var/nomad/jobs/webapp"):
                    body = json.dumps({"Namespace": "default",
                                       "Path": "nomad/jobs/webapp",
                                       "Items": {"DB_PASSWORD": "hunter2",
                                                 "API_KEY": "abc123"}}).encode()
                elif self.path.startswith("/v1/var/secrets/api-keys"):
                    body = json.dumps({"Namespace": "default",
                                       "Path": "secrets/api-keys",
                                       "Items": {"STRIPE": "sk_test_x"}}).encode()
                else:
                    # jobs/allocs/nodes not the point of this test
                    body = b"[]"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(len(p["vars"]), 2)
        paths = {v["path"] for v in p["vars"]}
        self.assertEqual(paths, {"nomad/jobs/webapp", "secrets/api-keys"})
        for v in p["vars"]:
            self.assertTrue(v["values_readable"])
            self.assertTrue(v["keys"])

    def test_variables_gated_returns_empty(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.5",
                                                  "ACL": {"Enabled": True}}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                # deny everything else including /v1/vars
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(p["vars"], [])

    def test_variables_finding_severity_reflects_readability(self):
        from recce.core.models import Host, Port
        host = Host(ip="10.2.2.2", ports=[Port(portid=4646, service="nomad")])
        probes = {("10.2.2.2", 4646): {
            "reachable": True, "version": "1.7.5", "acl_enabled": False,
            "jobs": [], "allocations": 0, "nodes": 0, "leader": "",
            "vault": {}, "consul": {}, "acl_bootstrap_token": "",
            "vars": [{"path": "secrets/x", "namespace": "default",
                      "keys": ["DB_PASSWORD"], "values_readable": True}],
        }}
        fs = nomad.findings([host], probes)
        vf = [f for f in fs if f["kind"] == "nomad_variables_readable"]
        self.assertEqual(len(vf), 1)
        self.assertEqual(vf[0]["severity"], "critical")

        probes[("10.2.2.2", 4646)]["vars"] = [
            {"path": "meta/x", "namespace": "default",
             "keys": [], "values_readable": False}]
        fs = nomad.findings([host], probes)
        vf = [f for f in fs if f["kind"] == "nomad_variables_readable"]
        self.assertEqual(len(vf), 1)
        self.assertEqual(vf[0]["severity"], "high")


class JobSpecFetchTest(unittest.TestCase):
    """Wire-shape derived from developer.hashicorp.com/nomad/api-docs/jobs
    (GET /v1/job/:job_id)."""

    def test_job_spec_env_templates_and_vault_extracted(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.5",
                                                  "ACL": {"Enabled": False}}}).encode()
                elif self.path == "/v1/jobs":
                    body = json.dumps([{"ID": "webapp", "Name": "webapp",
                                        "Type": "service", "Status": "running"}]).encode()
                elif self.path == "/v1/job/webapp":
                    body = json.dumps({
                        "ID": "webapp",
                        "TaskGroups": [{
                            "Name": "web",
                            "Meta": {"env": "prod", "team": "platform"},
                            "Tasks": [{
                                "Name": "server",
                                "Env": {"DB_PASSWORD": "hunter2",
                                        "AWS_SECRET_ACCESS_KEY": "AKIA..."},
                                "Templates": [
                                    {"DestPath": "secrets/db.env",
                                     "EmbeddedTmpl": "DB_URL={{ ... }}"},
                                    {"DestPath": "local/app.conf"},
                                ],
                                "Vault": {"Policies": ["app-prod", "kv-read"],
                                          "Namespace": "engineering"},
                            }],
                        }],
                    }).encode()
                elif self.path in ("/v1/allocations", "/v1/nodes", "/v1/vars"):
                    body = b"[]"
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(len(p["job_specs"]), 1)
        spec = p["job_specs"][0]
        self.assertEqual(spec["id"], "webapp")
        self.assertIn("DB_PASSWORD", spec["env_keys"])
        self.assertIn("AWS_SECRET_ACCESS_KEY", spec["env_keys"])
        self.assertIn("secrets/db.env", spec["template_dests"])
        self.assertEqual(len(spec["vault_refs"]), 1)
        self.assertIn("app-prod", spec["vault_refs"][0]["policies"])
        self.assertEqual(spec["vault_refs"][0]["namespace"], "engineering")
        self.assertIn("env", spec["meta_keys"])

    def test_job_spec_gated_returns_empty(self):
        """Anon list works, but /v1/job/:id is ACL-gated — spec list empty."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.5",
                                                  "ACL": {"Enabled": True}}}).encode()
                elif self.path == "/v1/jobs":
                    body = json.dumps([{"ID": "webapp", "Name": "webapp",
                                        "Type": "service", "Status": "running"}]).encode()
                elif self.path.startswith("/v1/job/"):
                    self.send_response(403); self.end_headers(); return
                else:
                    body = b"[]"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(p["job_specs"], [])

    def test_finding_emitted_when_specs_carry_env(self):
        from recce.core.models import Host, Port
        host = Host(ip="10.3.3.3", ports=[Port(portid=4646, service="nomad")])
        probes = {("10.3.3.3", 4646): {
            "reachable": True, "version": "1.7.5", "acl_enabled": False,
            "jobs": [{"name": "webapp", "type": "service", "status": "running"}],
            "allocations": 0, "nodes": 0, "leader": "",
            "vault": {}, "consul": {}, "vars": [], "acl_bootstrap_token": "",
            "job_submit": "",
            "job_specs": [{"id": "webapp",
                           "env_keys": ["DB_PASSWORD"],
                           "template_dests": ["secrets/db.env"],
                           "vault_refs": [], "meta_keys": []}],
        }}
        fs = nomad.findings([host], probes)
        js = [f for f in fs if f["kind"] == "nomad_job_spec_secrets"]
        self.assertEqual(len(js), 1)
        self.assertEqual(js[0]["severity"], "critical")
        self.assertIn("DB_PASSWORD", js[0]["detail"])

    def test_no_spec_finding_when_env_and_templates_empty(self):
        from recce.core.models import Host, Port
        host = Host(ip="10.3.3.3", ports=[Port(portid=4646, service="nomad")])
        probes = {("10.3.3.3", 4646): {
            "reachable": True, "version": "1.7.5", "acl_enabled": False,
            "jobs": [{"name": "j1", "type": "service", "status": "running"}],
            "allocations": 0, "nodes": 0, "leader": "",
            "vault": {}, "consul": {}, "vars": [], "acl_bootstrap_token": "",
            "job_submit": "",
            "job_specs": [{"id": "j1", "env_keys": [], "template_dests": [],
                           "vault_refs": [], "meta_keys": ["region"]}],
        }}
        fs = nomad.findings([host], probes)
        self.assertNotIn("nomad_job_spec_secrets", [f["kind"] for f in fs])


class JobSubmitProbeTest(unittest.TestCase):
    """Nomad /v1/jobs/parse — parser-only, no side effects."""

    def test_parse_200_marks_writable(self):
        seen = []
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.5",
                                                  "ACL": {"Enabled": False}}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                body = b"[]"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                if self.path == "/v1/jobs/parse":
                    length = int(self.headers.get("Content-Length") or 0)
                    payload = self.rfile.read(length)
                    seen.append(payload)
                    # parsed job canonicalized — real Nomad returns a big object
                    body = json.dumps({"ID": "recce-probe",
                                       "Name": "recce-probe"}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(p["job_submit"], "writable")
        # Payload really was JSON with a JobHCL key — not just a probe by URL.
        self.assertTrue(seen)
        parsed = json.loads(seen[0])
        self.assertIn("JobHCL", parsed)
        self.assertTrue(parsed.get("Canonicalize"))

    def test_parse_403_marks_gated(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.5",
                                                  "ACL": {"Enabled": True}}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(403); self.end_headers()
            def do_POST(self):
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = nomad.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(p["job_submit"], "gated")

    def test_finding_only_when_writable(self):
        from recce.core.models import Host, Port
        host = Host(ip="10.4.4.4", ports=[Port(portid=4646, service="nomad")])
        base = {"reachable": True, "version": "1.7.5", "acl_enabled": False,
                "jobs": [], "allocations": 0, "nodes": 0, "leader": "",
                "vault": {}, "consul": {}, "vars": [],
                "acl_bootstrap_token": "", "job_specs": []}
        for submit_val in ("gated", "", None):
            probes = {("10.4.4.4", 4646): {**base, "job_submit": submit_val}}
            fs = nomad.findings([host], probes)
            self.assertNotIn("nomad_job_submit_rce", [f["kind"] for f in fs])
        probes = {("10.4.4.4", 4646): {**base, "job_submit": "writable"}}
        fs = nomad.findings([host], probes)
        sf = [f for f in fs if f["kind"] == "nomad_job_submit_rce"]
        self.assertEqual(len(sf), 1)
        self.assertEqual(sf[0]["severity"], "critical")
        self.assertIn("CWE-94", sf[0]["cwes"])


class CredsWiringTest(unittest.TestCase):
    def test_extract_token_from_various_shapes(self):
        self.assertEqual(nomad._extract_token(None), "")
        self.assertEqual(nomad._extract_token({}), "")
        self.assertEqual(nomad._extract_token({"nomad_token": "t1"}), "t1")
        self.assertEqual(nomad._extract_token({"token": "t2"}), "t2")
        self.assertEqual(
            nomad._extract_token({"nomad": {"secret_id": "t3"}}), "t3")
        self.assertEqual(
            nomad._extract_token({"nomad": {"SecretID": "t4"}}), "t4")
        # top-level nomad_token wins over nested
        self.assertEqual(
            nomad._extract_token({"nomad_token": "top",
                                  "nomad": {"token": "nested"}}), "top")

    def test_analyze_sends_x_nomad_token_when_creds_present(self):
        seen_headers = []

        class H(_Base):
            def do_GET(self):
                seen_headers.append(dict(self.headers))
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.5",
                                                  "ACL": {"Enabled": True}}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                body = b"[]"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                seen_headers.append(dict(self.headers))
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        from recce.core.models import Host, Port
        try:
            port = srv.server_address[1]
            host = Host(ip="127.0.0.1", ports=[Port(portid=port, service="nomad")])
            result = nomad.analyze([host], creds={"nomad_token": "the-secret-id"},
                                   active=True)
        finally:
            srv.shutdown()
        # Every request that reached the server carried the header we set.
        tokened = [h for h in seen_headers
                   if h.get("X-Nomad-Token") == "the-secret-id"]
        self.assertGreater(len(tokened), 0)
        # Credentialed runbook steps are now populated (were unconditionally []).
        rb = result["runbooks"][0]
        self.assertTrue(rb["credentialed"])
        self.assertTrue(any("X-Nomad-Token" in step["cmd"]
                            for step in rb["credentialed"]))

    def test_analyze_omits_header_and_credentialed_when_no_creds(self):
        seen_headers = []

        class H(_Base):
            def do_GET(self):
                seen_headers.append(dict(self.headers))
                if self.path == "/v1/agent/self":
                    body = json.dumps({"config": {"Version": "1.7.5",
                                                  "ACL": {"Enabled": True}}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                body = b"[]"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        from recce.core.models import Host, Port
        try:
            port = srv.server_address[1]
            host = Host(ip="127.0.0.1", ports=[Port(portid=port, service="nomad")])
            result = nomad.analyze([host], creds=None, active=True)
        finally:
            srv.shutdown()
        for h in seen_headers:
            self.assertNotIn("X-Nomad-Token", h)
        self.assertEqual(result["runbooks"][0]["credentialed"], [])


if __name__ == "__main__":
    unittest.main()
