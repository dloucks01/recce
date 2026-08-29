"""Tests for recce.services.cloud_metadata — link-local IMDS probe.

Every fixture is a real HTTP handler emitting the provider's on-wire dialect
(bytes that match AWS/GCP/Azure/Alibaba/DO metadata responses documented in
their public schemas), served from 127.0.0.1 on an ephemeral port. The probes
under test are pointed at that server via their host/port arguments — no
network egress, no dependency on 169.254.169.254 actually being present.
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import cloud_metadata as cm


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Silent(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


class AWSProbeTest(unittest.TestCase):
    def test_full_aws_sweep_captures_creds_userdata_and_identity(self):
        identity_doc = {
            "accountId": "123456789012", "region": "us-east-1",
            "availabilityZone": "us-east-1a", "instanceId": "i-0abc",
            "instanceType": "t3.small", "imageId": "ami-0deadbeef",
            "privateIp": "10.0.0.5", "architecture": "x86_64",
        }
        role_creds = {
            "AccessKeyId": "ASIAEXAMPLEKEY1", "SecretAccessKey": "s3cret+key/EXAMPLE",
            "Token": "IQoJb3JpZ2luX2VjE...", "Expiration": "2030-01-01T00:00:00Z",
            "Code": "Success",
        }
        user_data = (
            "#!/bin/bash\n"
            "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            'db_password="hunter2hunter2"\n'
        )
        put_calls: list[str] = []

        class H(_Silent):
            def do_PUT(self):
                if self.path == "/latest/api/token":
                    put_calls.append(
                        self.headers.get("X-aws-ec2-metadata-token-ttl-seconds", ""))
                    self._send(200, b"AQAEXAMPLEIMDSV2TOKEN==")
                else:
                    self._send(404)

            def do_GET(self):
                p = self.path
                if p == "/latest/meta-data/":
                    self._send(200,
                               b"ami-id\niam/\ninstance-id\npublic-keys/\n")
                elif p == "/latest/meta-data/iam/security-credentials/":
                    self._send(200, b"my-app-role")
                elif p == "/latest/meta-data/iam/security-credentials/my-app-role":
                    self._send(200, json.dumps(role_creds).encode())
                elif p == "/latest/dynamic/instance-identity/document":
                    self._send(200, json.dumps(identity_doc).encode())
                elif p == "/latest/user-data":
                    self._send(200, user_data.encode())
                elif p == "/latest/meta-data/public-keys/":
                    self._send(200, b"0=my-key\n")
                elif p == "/latest/meta-data/public-keys/0/openssh-key":
                    self._send(200,
                               b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC example\n")
                elif p == "/latest/meta-data/hostname":
                    self._send(200, b"ip-10-0-0-5.ec2.internal")
                elif p == "/latest/meta-data/local-ipv4":
                    self._send(200, b"10.0.0.5")
                elif p.startswith("/latest/meta-data/"):
                    self._send(200, b"")
                else:
                    self._send(404)

        srv, _t = _serve(H)
        try:
            out = cm.aws_probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()

        self.assertTrue(out["reachable"])
        self.assertTrue(out["imdsv1_open"], "200 on /latest/meta-data/ without token = v1")
        self.assertEqual(out["imdsv2_token"], "AQAEXAMPLEIMDSV2TOKEN==")
        self.assertEqual(put_calls, ["21600"])
        self.assertEqual(out["roles"], ["my-app-role"])
        self.assertEqual(len(out["credentials"]), 1)
        self.assertEqual(out["credentials"][0]["access_key_id"], "ASIAEXAMPLEKEY1")
        self.assertEqual(out["identity_doc"]["accountId"], "123456789012")
        self.assertIn("AKIAIOSFODNN7EXAMPLE", out["user_data"])
        kinds = {s["kind"] for s in out["user_data_secrets"]}
        self.assertIn("aws_access_key_id", kinds)
        self.assertIn("aws_secret_access_key", kinds)
        self.assertIn("password_assignment", kinds)
        self.assertIn("hostname", out["meta_data"])
        self.assertEqual(out["meta_data"]["local-ipv4"], "10.0.0.5")
        self.assertEqual(len(out["ssh_public_keys"]), 1)

    def test_imdsv2_only_v1_returns_401(self):
        class H(_Silent):
            def do_PUT(self):
                if self.path == "/latest/api/token":
                    self._send(200, b"TOKEN==")
                else:
                    self._send(404)

            def do_GET(self):
                if self.headers.get("X-aws-ec2-metadata-token") != "TOKEN==":
                    self._send(401)
                    return
                if self.path == "/latest/meta-data/iam/security-credentials/":
                    self._send(200, b"")
                else:
                    self._send(200, b"ok")

        srv, _t = _serve(H)
        try:
            out = cm.aws_probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()

        self.assertTrue(out["reachable"])
        self.assertFalse(out["imdsv1_open"], "401 without token must NOT flag v1 open")
        self.assertEqual(out["imdsv2_token"], "TOKEN==")

    def test_dead_endpoint(self):
        out = cm.aws_probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(out["reachable"])


class GCPProbeTest(unittest.TestCase):
    def test_gcp_sa_token_and_project(self):
        class H(_Silent):
            def do_GET(self):
                if self.headers.get("Metadata-Flavor") != "Google":
                    self._send(403)
                    return
                p = self.path
                if p == "/computeMetadata/v1/project/project-id":
                    self._send(200, b"my-gcp-project")
                elif p == "/computeMetadata/v1/project/numeric-project-id":
                    self._send(200, b"111222333444")
                elif p == "/computeMetadata/v1/instance/hostname":
                    self._send(200, b"vm.c.my-gcp-project.internal")
                elif p == "/computeMetadata/v1/instance/zone":
                    self._send(200, b"projects/111222333444/zones/us-central1-a")
                elif p == ("/computeMetadata/v1/instance/service-accounts/"
                           "default/email"):
                    self._send(200, b"111-compute@developer.gserviceaccount.com")
                elif p == ("/computeMetadata/v1/instance/service-accounts/"
                           "default/scopes"):
                    self._send(200,
                               b"https://www.googleapis.com/auth/cloud-platform\n"
                               b"https://www.googleapis.com/auth/devstorage.read_write\n")
                elif p == ("/computeMetadata/v1/instance/service-accounts/"
                           "default/token"):
                    self._send(200, json.dumps({
                        "access_token": "ya29.exampleGCPtoken",
                        "expires_in": 3599, "token_type": "Bearer",
                    }).encode())
                else:
                    self._send(404)

        srv, _t = _serve(H)
        try:
            out = cm.gcp_probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()

        self.assertTrue(out["reachable"])
        self.assertEqual(out["project_id"], "my-gcp-project")
        self.assertEqual(out["numeric_project_id"], "111222333444")
        self.assertEqual(out["service_account_email"],
                         "111-compute@developer.gserviceaccount.com")
        self.assertIn("https://www.googleapis.com/auth/cloud-platform",
                      out["service_account_scopes"])
        self.assertEqual(out["access_token"], "ya29.exampleGCPtoken")

    def test_gcp_requires_metadata_flavor_header(self):
        seen: list[str] = []

        class H(_Silent):
            def do_GET(self):
                seen.append(self.headers.get("Metadata-Flavor", ""))
                if self.headers.get("Metadata-Flavor") != "Google":
                    self._send(403)
                else:
                    self._send(404)

        srv, _t = _serve(H)
        try:
            out = cm.gcp_probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()

        self.assertFalse(out["reachable"])
        self.assertTrue(seen and all(s == "Google" for s in seen))


class AzureProbeTest(unittest.TestCase):
    def test_azure_instance_and_msi_token(self):
        instance = {
            "compute": {
                "subscriptionId": "00000000-0000-0000-0000-000000000001",
                "resourceGroupName": "prod-rg",
                "vmId": "vm-guid-1234", "vmSize": "Standard_D2s_v3",
                "location": "eastus",
                "osProfile": {"computerName": "web01"},
            },
            "network": {"interface": []},
        }

        class H(_Silent):
            def do_GET(self):
                if self.headers.get("Metadata") != "true":
                    self._send(400, b"Metadata header required")
                    return
                p = self.path
                if p.startswith("/metadata/instance"):
                    self._send(200, json.dumps(instance).encode())
                elif p.startswith("/metadata/identity/oauth2/token"):
                    self._send(200, json.dumps({
                        "access_token": "eyJ0.exampleAzureBearer",
                        "expires_in": "3600", "resource": "urn:x",
                        "token_type": "Bearer",
                    }).encode())
                else:
                    self._send(404)

        srv, _t = _serve(H)
        try:
            out = cm.azure_probe("127.0.0.1", srv.server_address[1], timeout=2,
                                 resources=("https://management.azure.com/",))
        finally:
            srv.shutdown()

        self.assertTrue(out["reachable"])
        self.assertEqual(out["subscription_id"],
                         "00000000-0000-0000-0000-000000000001")
        self.assertEqual(out["resource_group"], "prod-rg")
        self.assertEqual(out["computer_name"], "web01")
        self.assertIn("https://management.azure.com/", out["tokens"])
        self.assertTrue(out["tokens"]["https://management.azure.com/"].startswith(
            "eyJ0.exampleAzure"))


class AlibabaProbeTest(unittest.TestCase):
    def test_alibaba_ram_creds_and_userdata(self):
        role_creds = {
            "AccessKeyId": "STS.example-ali", "AccessKeySecret": "aliSecretExample",
            "SecurityToken": "CAIS...token", "Expiration": "2030-01-01T00:00:00Z",
            "Code": "Success",
        }
        user_data = (
            "#cloud-config\n"
            "runcmd:\n"
            "  - echo AKIAIOSFODNN7EXAMPLE >> /tmp/oops\n"
        )

        class H(_Silent):
            def do_GET(self):
                p = self.path
                if p == "/latest/meta-data/":
                    self._send(200, b"instance-id\nram/\nregion-id\n")
                elif p == "/latest/meta-data/instance-id":
                    self._send(200, b"i-alibaba-example")
                elif p == "/latest/meta-data/region-id":
                    self._send(200, b"cn-hangzhou")
                elif p == "/latest/meta-data/owner-account-id":
                    self._send(200, b"5555555555555555")
                elif p == "/latest/meta-data/ram/security-credentials/":
                    self._send(200, b"MyEcsRole")
                elif p == "/latest/meta-data/ram/security-credentials/MyEcsRole":
                    self._send(200, json.dumps(role_creds).encode())
                elif p == "/latest/user-data":
                    self._send(200, user_data.encode())
                else:
                    self._send(404)

        srv, _t = _serve(H)
        try:
            out = cm.alibaba_probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()

        self.assertTrue(out["reachable"])
        self.assertEqual(out["instance_id"], "i-alibaba-example")
        self.assertEqual(out["region_id"], "cn-hangzhou")
        self.assertEqual(out["owner_account_id"], "5555555555555555")
        self.assertEqual(len(out["credentials"]), 1)
        self.assertEqual(out["credentials"][0]["access_key_id"], "STS.example-ali")
        self.assertTrue(any(s["kind"] == "aws_access_key_id"
                            for s in out["user_data_secrets"]))


class DigitalOceanProbeTest(unittest.TestCase):
    def test_do_metadata_v1_json(self):
        blob = {
            "droplet_id": 987654321, "hostname": "web-do-01", "region": "nyc3",
            "public_keys": [
                "ssh-rsa AAAAB3NzaC1yc2EAAAABBBB opsuser",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI operator",
            ],
            "user_data": (
                "#!/bin/bash\n"
                "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
            ),
        }

        class H(_Silent):
            def do_GET(self):
                if self.path == "/metadata/v1.json":
                    self._send(200, json.dumps(blob).encode())
                else:
                    self._send(404)

        srv, _t = _serve(H)
        try:
            out = cm.do_probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()

        self.assertTrue(out["reachable"])
        self.assertEqual(out["droplet_id"], "987654321")
        self.assertEqual(out["region"], "nyc3")
        self.assertEqual(len(out["public_keys"]), 2)
        self.assertTrue(any(s["kind"] == "github_token"
                            for s in out["user_data_secrets"]))


class FingerprintTest(unittest.TestCase):
    def test_fingerprint_prefers_aws_on_latest_index(self):
        class H(_Silent):
            def do_GET(self):
                if self.path == "/latest/":
                    self._send(200, b"dynamic\nmeta-data\nuser-data\n")
                else:
                    self._send(404)
        srv, _t = _serve(H)
        try:
            got = cm.fingerprint("127.0.0.1", srv.server_address[1], timeout=1)
        finally:
            srv.shutdown()
        self.assertEqual(got, "aws")

    def test_fingerprint_azure_via_instance_endpoint(self):
        class H(_Silent):
            def do_GET(self):
                if self.headers.get("Metadata-Flavor") == "Google":
                    self._send(403); return
                if self.path.startswith("/metadata/instance") \
                        and self.headers.get("Metadata") == "true":
                    self._send(200,
                               b'{"compute":{"vmId":"x"},"network":{}}')
                    return
                self._send(404)
        srv, _t = _serve(H)
        try:
            got = cm.fingerprint("127.0.0.1", srv.server_address[1], timeout=1)
        finally:
            srv.shutdown()
        self.assertEqual(got, "azure")

    def test_fingerprint_digitalocean(self):
        class H(_Silent):
            def do_GET(self):
                if self.path == "/metadata/v1/id":
                    self._send(200, b"12345678")
                elif self.headers.get("Metadata-Flavor") == "Google":
                    self._send(403)
                elif self.headers.get("Metadata") == "true":
                    self._send(400)
                else:
                    self._send(404)
        srv, _t = _serve(H)
        try:
            got = cm.fingerprint("127.0.0.1", srv.server_address[1], timeout=1)
        finally:
            srv.shutdown()
        self.assertEqual(got, "digitalocean")


class ProxyFrontedTest(unittest.TestCase):
    def test_proxy_absolute_form_reaches_imds(self):
        """Fake HTTP forward proxy: accepts GET http://<target>/... absolute-URI
        form and echoes a canned AWS meta-data listing back — the Capital One
        2019 pattern in miniature."""
        seen: list[str] = []

        class H(_Silent):
            def do_GET(self):
                seen.append(self.path)
                if self.path.startswith("http://") and \
                        "/latest/meta-data/" in self.path:
                    self._send(200,
                               b"ami-id\ninstance-id\niam/\npublic-keys/\n")
                else:
                    self._send(404)

        srv, _t = _serve(H)
        try:
            out = cm.proxy_fronted_probe(
                "127.0.0.1", srv.server_address[1],
                target_host="169.254.169.254", timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(out["absolute_form_ok"])
        self.assertTrue(any(u.startswith("http://169.254.169.254")
                            for u in seen))
        fs = cm.proxy_findings(out)
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["kind"], "imds_reachable_via_proxy")
        self.assertEqual(fs[0]["severity"], "critical")


class ExploitViaSSRFTest(unittest.TestCase):
    def test_ssrf_chains_to_full_credential_pull(self):
        """The SSRF sender returns the metadata BODY, not the target-app body —
        this is the crawl.py handoff: once the SSRF is proven, recce hits the
        metadata paths through the same vulnerable parameter."""
        role_creds = {
            "AccessKeyId": "ASIA-ssrf-EXAMPLE", "SecretAccessKey": "ssrf/secret",
            "Token": "ssrf-session-token", "Expiration": "2030-01-01T00:00:00Z",
        }
        identity = {"accountId": "999888777666", "region": "eu-west-1"}
        user_data = 'password="hunter2hunter2"\nAKIAIOSFODNN7EXAMPLE\n'

        def sender(path, headers, method):
            if method == "PUT" and path == "/latest/api/token":
                return b"SSRF-TOKEN=="
            if path == "/latest/meta-data/iam/security-credentials/":
                return b"role-via-ssrf"
            if path == "/latest/meta-data/iam/security-credentials/role-via-ssrf":
                return json.dumps(role_creds).encode()
            if path == "/latest/dynamic/instance-identity/document":
                return json.dumps(identity).encode()
            if path == "/latest/user-data":
                return user_data.encode()
            return b""

        out = cm.exploit_via_ssrf(sender, provider="aws")
        self.assertTrue(out["reachable"])
        self.assertEqual(len(out["credentials"]), 1)
        self.assertEqual(out["credentials"][0]["access_key_id"],
                         "ASIA-ssrf-EXAMPLE")
        self.assertEqual(out["identity_doc"]["accountId"], "999888777666")
        self.assertTrue(any(s["kind"] == "password_assignment"
                            for s in out["user_data_secrets"]))
        fs = cm.findings(out)
        self.assertTrue(any(f["kind"] == "web_ssrf_reaches_imds_credentials"
                            for f in fs))
        self.assertTrue(any(f["severity"] == "critical" for f in fs))

    def test_ssrf_gcp_mints_sa_token(self):
        def sender(path, headers, method):
            if path == "/computeMetadata/v1/instance/service-accounts/default/token":
                return json.dumps({"access_token": "ya29.ssrfGCPtoken",
                                   "expires_in": 3599}).encode()
            return b""
        out = cm.exploit_via_ssrf(sender, provider="gcp")
        self.assertTrue(out["reachable"])
        self.assertEqual(out["credentials"][0]["access_token"], "ya29.ssrfGCPtoken")


class FindingsTest(unittest.TestCase):
    def test_findings_aws_v1_open_and_creds(self):
        pr = {
            "reachable": True, "providers": ["aws"],
            "aws": {
                "reachable": True, "imdsv1_open": True, "imdsv2_token": "T",
                "roles": ["r1"],
                "credentials": [{"role": "r1", "access_key_id": "ASIAEXAMPLE",
                                 "secret_access_key": "x", "session_token": "t",
                                 "expiration": ""}],
                "user_data": "AKIAIOSFODNN7EXAMPLE",
                "user_data_secrets": [{"kind": "aws_access_key_id",
                                       "match": "AKIAIOSFODNN7EXAMPLE"}],
                "identity_doc": {"accountId": "1", "region": "us-east-1",
                                 "instanceId": "i", "instanceType": "t",
                                 "imageId": "a"},
                "ssh_public_keys": ["ssh-rsa AAAA"],
                "meta_data": {},
            },
            "gcp": {}, "azure": {}, "alibaba": {}, "digitalocean": {},
        }
        fs = cm.findings(pr, target_label="10.0.0.5")
        kinds = {f["kind"]: f["severity"] for f in fs}
        self.assertEqual(kinds.get("imds_v1_enabled"), "critical")
        self.assertEqual(kinds.get("imds_iam_credentials_exposed"), "critical")
        self.assertEqual(kinds.get("imds_user_data_secrets"), "critical")
        self.assertEqual(kinds.get("imds_reachable_from_host"), "high")
        self.assertEqual(kinds.get("instance_identity_disclosed"), "medium")
        self.assertEqual(kinds.get("imds_ssh_public_keys_disclosed"), "low")
        for f in fs:
            self.assertTrue(f["title"] and f["kind"])
            self.assertIsInstance(f["cwes"], list)

    def test_findings_gcp_and_azure_tokens(self):
        pr = {
            "reachable": True, "providers": ["gcp", "azure"],
            "aws": {},
            "gcp": {"reachable": True, "access_token": "ya29.tok",
                    "service_account_email": "sa@x.iam", "project_id": "proj",
                    "numeric_project_id": "1", "zone": "z", "hostname": "h",
                    "service_account_scopes": []},
            "azure": {"reachable": True, "subscription_id": "sub-1",
                      "resource_group": "rg", "vm_id": "v", "vm_size": "s",
                      "location": "loc", "computer_name": "c",
                      "tokens": {"https://management.azure.com/": "eyJ"}},
            "alibaba": {}, "digitalocean": {},
        }
        fs = cm.findings(pr)
        kinds = {f["kind"] for f in fs}
        self.assertIn("gcp_service_account_token_exposed", kinds)
        self.assertIn("azure_managed_identity_token_exposed", kinds)

    def test_findings_alibaba_and_digitalocean(self):
        pr = {
            "reachable": True, "providers": ["alibaba", "digitalocean"],
            "aws": {}, "gcp": {}, "azure": {},
            "alibaba": {"reachable": True,
                        "credentials": [{"role": "r", "access_key_id": "STS.a"}],
                        "user_data": "", "user_data_secrets": []},
            "digitalocean": {"reachable": True, "droplet_id": "1",
                             "region": "nyc3", "hostname": "h",
                             "public_keys": [], "user_data_secrets": []},
        }
        fs = cm.findings(pr)
        kinds = {f["kind"] for f in fs}
        self.assertIn("alibaba_ram_credentials_exposed", kinds)
        self.assertIn("instance_identity_disclosed", kinds)

    def test_findings_empty_when_unreachable(self):
        self.assertEqual(cm.findings({"reachable": False}), [])
        self.assertEqual(cm.findings({}), [])

    def test_findings_to_vulns_shape(self):
        pr = {"reachable": True, "providers": ["aws"],
              "aws": {"reachable": True, "imdsv1_open": True,
                      "roles": [], "credentials": [], "user_data": "",
                      "user_data_secrets": [], "identity_doc": {},
                      "ssh_public_keys": [], "meta_data": {}, "imdsv2_token": ""},
              "gcp": {}, "azure": {}, "alibaba": {}, "digitalocean": {}}
        fs = cm.findings(pr, target_label="10.0.0.5")
        by_ip = cm.findings_to_vulns(fs)
        self.assertIn("10.0.0.5", by_ip)
        vulns = by_ip["10.0.0.5"]
        self.assertTrue(any(v.severity == "critical" and
                            v.script_id.startswith("cloud_metadata:") for v in vulns))


class ReachabilityTest(unittest.TestCase):
    def test_tcp_reachable_true(self):
        srv, _t = _serve(_Silent)
        try:
            self.assertTrue(cm._tcp_reachable(
                "127.0.0.1", srv.server_address[1], timeout=1))
        finally:
            srv.shutdown()

    def test_tcp_reachable_false_on_dead_port(self):
        self.assertFalse(cm._tcp_reachable("127.0.0.1", 1, timeout=1))


class SecretScanTest(unittest.TestCase):
    def test_scans_all_pattern_families(self):
        text = (
            "AKIAIOSFODNN7EXAMPLE and ASIA0123456789ABCDEF\n"
            'aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
            'password="topsecretpw"\n'
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
            "xoxb-1111-2222-abcdef\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n"
        )
        hits = cm._scan_secrets(text)
        kinds = {h["kind"] for h in hits}
        for expected in ("aws_access_key_id", "aws_temp_access_key_id",
                         "aws_secret_access_key", "password_assignment",
                         "github_token", "slack_token", "private_key_block"):
            self.assertIn(expected, kinds)


if __name__ == "__main__":
    unittest.main()
