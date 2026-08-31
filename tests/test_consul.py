"""Tests for recce.services.consul — unauthenticated Consul read probe."""
from __future__ import annotations

import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.core.models import Host, Port
from recce.services import consul


def _b64(s: bytes | str) -> str:
    if isinstance(s, str):
        s = s.encode()
    return base64.b64encode(s).decode()


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass


class ProbeTest(unittest.TestCase):
    def test_acl_disabled_all_endpoints_readable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"Config": {"Version": "1.16.0"},
                                       "DebugConfig": {"ACLDefaultPolicy": "allow"}}).encode()
                elif self.path == "/v1/catalog/services":
                    body = json.dumps({"consul": [], "web": ["prod"], "redis": ["cache"]}).encode()
                elif self.path == "/v1/catalog/nodes":
                    body = json.dumps([{"Node": "n1"}, {"Node": "n2"}]).encode()
                elif self.path.startswith("/v1/kv"):
                    body = json.dumps([
                        {"Key": "app/db_password", "Value": "..."},
                        {"Key": "app/api_token", "Value": "..."},
                    ]).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)
        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "1.16.0")
        self.assertFalse(p["acl_enabled"], "default-allow ACL should register as disabled")
        self.assertIn("web", p["services"])
        self.assertEqual(p["nodes"], 2)
        self.assertEqual(p["kv_keys"], 2)

    def test_acl_enforcing_falls_back_to_leader(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/status/leader":
                    body = b'"10.0.0.1:8300"'
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(403); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["acl_enabled"], "403 on /agent/self should mark ACL enforcing")
        self.assertEqual(p["leader"], "10.0.0.1:8300")
        self.assertEqual(p["services"], [])

    def test_dead_port(self):
        p = consul.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


class KVSecretExtractionTest(unittest.TestCase):
    def test_probe_extracts_and_classifies_kv_secrets(self):
        entries = [
            {"Key": "app/config/version", "Value": _b64("1.2.3")},
            {"Key": "app/db_password", "Value": _b64("hunter2")},
            {"Key": "cloud/aws.txt", "Value": _b64("AKIAABCDEFGHIJKLMNOP is the key")},
            {"Key": "misc/nothing", "Value": _b64("boring")},
            {"Key": "svc/pki/cert",
             "Value": _b64("-----BEGIN RSA PRIVATE KEY-----\nabc==\n"
                           "-----END RSA PRIVATE KEY-----")},
            {"Key": "svc/jwt", "Value": _b64(
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123xyz789def456ghi")},
            {"Key": "svc/legacy", "Value": _b64("postgres://user:secret@db:5432/x")},
        ]

        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"Config": {"Version": "1.16.0"},
                                       "DebugConfig": {"ACLDefaultPolicy": "allow"}}).encode()
                elif self.path == "/v1/catalog/services":
                    body = b"{}"
                elif self.path == "/v1/catalog/nodes":
                    body = b"[]"
                elif self.path.startswith("/v1/kv"):
                    body = json.dumps(entries).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)

        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(p["kv_keys"], 7)
        hits = p["kv_secrets"]
        keys = {h["key"] for h in hits}
        self.assertIn("app/db_password", keys)
        self.assertIn("cloud/aws.txt", keys)
        self.assertIn("svc/pki/cert", keys)
        self.assertIn("svc/jwt", keys)
        self.assertIn("svc/legacy", keys)
        self.assertNotIn("app/config/version", keys)
        self.assertNotIn("misc/nothing", keys)
        kinds = {k for h in hits for k in h["kinds"]}
        self.assertIn("aws_access_key", kinds)
        self.assertIn("private_key_pem", kinds)
        self.assertIn("jwt", kinds)
        self.assertIn("db_uri", kinds)

    def test_finding_emitted_for_kv_secrets(self):
        host = Host(ip="10.0.0.5", ports=[
            Port(portid=8500, protocol="tcp", service="consul")])
        probes = {("10.0.0.5", 8500): {
            "reachable": True, "version": "1.16.0", "acl_enabled": False,
            "services": [], "nodes": 0, "kv_keys": 3, "leader": "",
            "kv_secrets": [
                {"key": "app/db_pass", "kinds": ["key_name"], "size": 5, "preview": "x"},
                {"key": "cloud/aws", "kinds": ["aws_access_key"], "size": 40,
                 "preview": "AKIA..."},
            ],
        }}
        fs = consul.findings([host], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("consul_unauth_read", kinds)
        self.assertIn("consul_kv_secrets", kinds)
        kv = next(f for f in fs if f["kind"] == "consul_kv_secrets")
        self.assertEqual(kv["severity"], "critical")
        self.assertIn("app/db_pass", kv["detail"])
        self.assertIn("CWE-200", kv["cwes"])


class TokenPlumbingTest(unittest.TestCase):
    def test_extract_token_shapes(self):
        self.assertEqual(consul._extract_token(None), "")
        self.assertEqual(consul._extract_token({}), "")
        self.assertEqual(consul._extract_token({"consul_token": "tok1"}), "tok1")
        self.assertEqual(consul._extract_token({"token": "tok2"}), "tok2")
        self.assertEqual(
            consul._extract_token({"consul": {"token": "sub-tok"}}), "sub-tok")
        self.assertEqual(
            consul._extract_token({"consul": {"SecretID": "aaa-bbb"}}), "aaa-bbb")

    def test_probe_sends_x_consul_token_header(self):
        seen = {"headers": []}

        class H(_Base):
            def do_GET(self):
                seen["headers"].append(self.headers.get("X-Consul-Token"))
                if self.path == "/v1/agent/self":
                    body = json.dumps({"Config": {"Version": "1.18.0"},
                                       "DebugConfig": {"ACLDefaultPolicy": "deny"}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(200); self.send_header("Content-Length", "2")
                self.end_headers(); self.wfile.write(b"[]")

        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2,
                             token="the-mgmt-token")
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["authed"])
        self.assertTrue(any(h == "the-mgmt-token" for h in seen["headers"]))

    def test_analyze_plumbs_token_from_creds(self):
        seen = {"token": ""}

        def fake_probe(ip, port, token=""):
            seen["token"] = token
            return {"reachable": True, "version": "1.17.0", "acl_enabled": True,
                    "services": [], "nodes": 0, "kv_keys": 0, "kv_secrets": [],
                    "leader": "10.0.0.1", "gossip_encrypted": None,
                    "tls_min_version": "", "authed": bool(token)}

        real_probe = consul.probe
        consul.probe = fake_probe
        try:
            host = Host(ip="10.0.0.5", ports=[
                Port(portid=8500, protocol="tcp", service="consul")])
            consul.analyze([host], creds={"consul_token": "abc123"},
                           active=True, budget=None)
        finally:
            consul.probe = real_probe
        self.assertEqual(seen["token"], "abc123")


class AgentSelfEnrichmentTest(unittest.TestCase):
    def test_probe_extracts_dc_server_encrypt_tls(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({
                        "Config": {"Version": "1.16.0", "Datacenter": "dc1",
                                   "Server": True, "NodeName": "srv-1",
                                   "NodeID": "abcdef12-3456"},
                        "DebugConfig": {
                            "ACLDefaultPolicy": "allow",
                            "EncryptKey": "",
                            "TLSMinVersion": "tls10",
                            "RaftProtocol": 3,
                        },
                    }).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(200); self.send_header("Content-Length", "2")
                self.end_headers(); self.wfile.write(b"[]")

        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(p["datacenter"], "dc1")
        self.assertIs(p["server"], True)
        self.assertEqual(p["node_name"], "srv-1")
        self.assertEqual(p["tls_min_version"], "tls10")
        self.assertEqual(p["raft_protocol"], 3)
        self.assertIs(p["gossip_encrypted"], False)

    def test_probe_detects_gossip_encryption_present(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({
                        "Config": {"Version": "1.17.0", "Datacenter": "dc2",
                                   "Server": False},
                        "DebugConfig": {"ACLDefaultPolicy": "deny",
                                        "EncryptKey": "hidden-key-blob",
                                        "TLSMinVersion": "tls12"},
                    }).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(403); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertIs(p["gossip_encrypted"], True)
        self.assertEqual(p["tls_min_version"], "tls12")

    def test_findings_emit_gossip_and_weak_tls(self):
        host = Host(ip="10.0.0.9", ports=[
            Port(portid=8500, protocol="tcp", service="consul")])
        probes = {("10.0.0.9", 8500): {
            "reachable": True, "version": "1.16.0", "acl_enabled": True,
            "services": [], "nodes": 0, "kv_keys": 0, "kv_secrets": [],
            "leader": "10.0.0.1", "datacenter": "dc1",
            "gossip_encrypted": False, "tls_min_version": "TLSv10",
        }}
        fs = consul.findings([host], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("consul_gossip_unencrypted", kinds)
        self.assertIn("consul_weak_tls", kinds)
        gossip = next(f for f in fs if f["kind"] == "consul_gossip_unencrypted")
        self.assertEqual(gossip["severity"], "high")
        tls = next(f for f in fs if f["kind"] == "consul_weak_tls")
        self.assertEqual(tls["severity"], "medium")

    def test_gossip_not_flagged_when_unknown(self):
        host = Host(ip="10.0.0.9", ports=[
            Port(portid=8500, protocol="tcp", service="consul")])
        probes = {("10.0.0.9", 8500): {
            "reachable": True, "version": "1.16.0", "acl_enabled": True,
            "services": [], "nodes": 0, "kv_keys": 0, "kv_secrets": [],
            "leader": "10.0.0.1", "gossip_encrypted": None,
            "tls_min_version": "tls13",
        }}
        fs = consul.findings([host], probes)
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("consul_gossip_unencrypted", kinds)
        self.assertNotIn("consul_weak_tls", kinds)


class KvOpenT2ProofTest(unittest.TestCase):
    """T2 SAFE proof-of-exploit: /v1/agent/members canary for consul_kv_open."""

    # Wire-shaped members response — matches the shape Consul returns on
    # GET /v1/agent/members. NOT built via recce encoders.
    _MEMBERS_WIRE = [
        {"Name": "srv-1", "Addr": "10.0.0.11", "Port": 8301, "Tags": {},
         "Status": 1, "ProtocolMin": 1, "ProtocolMax": 5, "ProtocolCur": 2,
         "DelegateMin": 2, "DelegateMax": 5, "DelegateCur": 4},
        {"Name": "srv-2", "Addr": "10.0.0.12", "Port": 8301, "Tags": {},
         "Status": 1},
        {"Name": "web-1", "Addr": "10.0.0.21", "Port": 8301, "Tags": {},
         "Status": 1},
    ]

    def test_probe_captures_members_when_acl_disabled(self):
        """(a) Vulnerable target: probe fires + tier upgrades to T2."""
        wire = self._MEMBERS_WIRE
        saw = {"members_hits": 0}

        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"Config": {"Version": "1.16.0"},
                                       "DebugConfig": {"ACLDefaultPolicy": "allow"}}).encode()
                elif self.path == "/v1/catalog/services":
                    body = json.dumps({"consul": [], "web": ["prod"]}).encode()
                elif self.path == "/v1/catalog/nodes":
                    body = json.dumps([{"Node": "n1"}]).encode()
                elif self.path.startswith("/v1/kv"):
                    body = json.dumps([{"Key": "app/x", "Value": _b64("v")}]).encode()
                elif self.path == "/v1/agent/members":
                    saw["members_hits"] += 1
                    body = json.dumps(wire).encode()
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)

        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(saw["members_hits"], 1,
                         "members probe should fire exactly once when vulnerable")
        ev = p.get("members_evidence")
        self.assertIsNotNone(ev, "members_evidence should be populated")
        self.assertEqual(ev["count"], 3)
        self.assertEqual(ev["endpoint"], "/v1/agent/members")
        names = {m["name"] for m in ev["sample"]}
        self.assertIn("srv-1", names)
        self.assertIn("srv-2", names)
        # findings should carry depth_tier=t2 with the evidence baked in
        host = Host(ip="10.0.0.5", ports=[
            Port(portid=8500, protocol="tcp", service="consul")])
        pr = dict(p)  # copy
        probes = {("10.0.0.5", 8500): pr}
        fs = consul.findings([host], probes)
        unauth = next(f for f in fs if f["kind"] == "consul_unauth_read")
        self.assertEqual(unauth["depth_tier"], "t2",
                         "vulnerable target should upgrade depth_tier to t2")
        self.assertIn("T2 proof", unauth["detail"])
        self.assertIn("srv-1", unauth["detail"])
        self.assertIn("/v1/agent/members", unauth["detail"])

    def test_probe_quiet_and_tier_stays_t1_when_members_forbidden(self):
        """(b) Patched target: /agent/members 403s -> tier stays T1."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"Config": {"Version": "1.16.0"},
                                       "DebugConfig": {"ACLDefaultPolicy": "allow"}}).encode()
                elif self.path == "/v1/catalog/services":
                    body = json.dumps({"web": ["prod"]}).encode()
                elif self.path == "/v1/catalog/nodes":
                    body = json.dumps([{"Node": "n1"}]).encode()
                elif self.path.startswith("/v1/kv"):
                    body = json.dumps([{"Key": "app/x", "Value": _b64("v")}]).encode()
                elif self.path == "/v1/agent/members":
                    self.send_response(403); self.end_headers(); return
                else:
                    self.send_response(404); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", str(len(body)))
                self.end_headers(); self.wfile.write(body)

        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertIsNone(p.get("members_evidence"))
        host = Host(ip="10.0.0.5", ports=[
            Port(portid=8500, protocol="tcp", service="consul")])
        fs = consul.findings([host], {("10.0.0.5", 8500): p})
        unauth = next(f for f in fs if f["kind"] == "consul_unauth_read")
        self.assertEqual(unauth["depth_tier"], "t1",
                         "no T2 evidence should keep depth_tier at t1")
        self.assertNotIn("T2 proof", unauth["detail"])

    def test_probe_skipped_when_acl_enforcing(self):
        """T2 probe should not even fire when ACL enforces reads."""
        saw = {"members_hits": 0}

        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/self":
                    body = json.dumps({"Config": {"Version": "1.18.0"},
                                       "DebugConfig": {"ACLDefaultPolicy": "deny"}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                if self.path == "/v1/agent/members":
                    saw["members_hits"] += 1
                # everything else returns empty listing
                self.send_response(200); self.send_header("Content-Length", "2")
                self.end_headers(); self.wfile.write(b"[]")

        srv, _t = _serve(H)
        try:
            p = consul.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertEqual(saw["members_hits"], 0,
                         "T2 probe must not fire when ACL enforces")
        self.assertIsNone(p.get("members_evidence"))

    def test_members_probe_timeout_clean(self):
        """(c) Timeout is clean — helper returns None, probe stays quiet."""
        # Route to a closed port on localhost so connect() fails fast.
        # Explicitly exercises the socket-error path (OSError) of _http().
        ev = consul._probe_members_canary("127.0.0.1", 1, timeout=1.0)
        self.assertIsNone(ev)

    def test_members_probe_returns_none_on_malformed_json(self):
        """Malformed body must not raise; returns None -> no upgrade."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/members":
                    body = b"not-json{{"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            ev = consul._probe_members_canary(
                "127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertIsNone(ev)

    def test_members_probe_returns_none_on_empty_list(self):
        """Empty member list -> no T2 evidence emitted."""
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/agent/members":
                    body = b"[]"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body); return
                self.send_response(404); self.end_headers()

        srv, _t = _serve(H)
        try:
            ev = consul._probe_members_canary(
                "127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertIsNone(ev)


if __name__ == "__main__":
    unittest.main()
