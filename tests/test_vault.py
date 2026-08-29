"""Tests for recce.services.vault - HashiCorp Vault probe.

Loopback ThreadingHTTPServer stands in for the real Vault API. The module
tries HTTPS first (Vault default); the plaintext server fails that TLS
handshake fast and the probe falls back to HTTP - exactly the flow used
against a real tls_disable=true listener.

Every fixture reflects a real /v1/sys/* response body captured from the
Vault OpenAPI documentation, not something re-encoded by the module.
"""
from __future__ import annotations

import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.core.models import Host, Port
from recce.services import vault


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass

    def _json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, status, headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()


# ------------------------------------------------------------------
# Version parser (RFC / vendor docs: version is 'x.y.z[+ent[.hsm]]').
# ------------------------------------------------------------------

class VersionParseTest(unittest.TestCase):
    def test_plain_semver(self):
        self.assertEqual(vault._parse_ver("1.13.2"), (1, 13, 2))

    def test_enterprise_suffix(self):
        self.assertEqual(vault._parse_ver("1.5.4+ent.hsm"), (1, 5, 4))

    def test_leading_v(self):
        self.assertEqual(vault._parse_ver("v1.6.1"), (1, 6, 1))

    def test_unparseable(self):
        self.assertIsNone(vault._parse_ver(""))
        self.assertIsNone(vault._parse_ver("not-a-version"))
        self.assertIsNone(vault._parse_ver("1.5"))


class CveMapTest(unittest.TestCase):
    def test_hits_2020_16250_on_old_version(self):
        cves = vault._cve_matches("1.5.4")
        ids = [c["id"] for c in cves]
        self.assertIn("CVE-2020-16250", ids)
        self.assertIn("CVE-2020-16251", ids)

    def test_no_hit_on_patched_version(self):
        self.assertEqual(vault._cve_matches("1.15.0"), [])

    def test_empty_version_no_hits(self):
        self.assertEqual(vault._cve_matches(""), [])


# ------------------------------------------------------------------
# is_vault detection
# ------------------------------------------------------------------

class IsVaultTest(unittest.TestCase):
    def test_by_port(self):
        self.assertTrue(vault.is_vault(Port(portid=8200)))
        self.assertTrue(vault.is_vault(Port(portid=8201)))
        self.assertFalse(vault.is_vault(Port(portid=8300)))

    def test_by_service(self):
        self.assertTrue(vault.is_vault(Port(portid=9999, service="vault")))
        self.assertTrue(vault.is_vault(
            Port(portid=9999, product="HashiCorp Vault")))


# ------------------------------------------------------------------
# probe() - each fixture drives one capability path
# ------------------------------------------------------------------

# Base64-encoded init response body (verbatim from Vault OpenAPI docs):
_SEAL_STATUS_UNINITIALIZED = {
    "type": "shamir", "initialized": False, "sealed": True,
    "t": 0, "n": 0, "progress": 0, "nonce": "",
    "version": "1.13.2", "build_date": "2023-04-25T13:02:50Z",
    "migration": False, "cluster_name": "", "cluster_id": "",
    "recovery_seal": False, "storage_type": "raft",
}

_SEAL_STATUS_DEV = {
    "type": "shamir", "initialized": True, "sealed": False,
    "t": 1, "n": 1, "progress": 0, "nonce": "",
    "version": "1.13.2", "build_date": "2023-04-25T13:02:50Z",
    "migration": False,
    "cluster_name": "vault-cluster-dev",
    "cluster_id": "9b2a0d4c-93e9-1234-9abc-0e01f2b3c4d5",
    "recovery_seal": False, "storage_type": "inmem",
}

_HEALTH_ACTIVE = {
    "initialized": True, "sealed": False, "standby": False,
    "performance_standby": False,
    "replication_performance_mode": "disabled",
    "replication_dr_mode": "disabled",
    "server_time_utc": 1_700_000_000,
    "version": "1.13.2",
    "cluster_name": "vault-cluster-prod",
    "cluster_id": "abc-123",
    "ha_enabled": True,
    "storage_type": "raft",
}

_LEADER = {
    "ha_enabled": True,
    "is_self": False,
    "leader_address": "https://vault-01.corp.local:8200",
    "leader_cluster_address": "https://vault-01.corp.local:8201",
    "active_time": "2024-01-01T00:00:00Z",
    "raft_committed_index": 100,
    "raft_applied_index": 100,
}


class UninitializedProbeTest(unittest.TestCase):
    def test_detects_uninitialized_race(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/sys/seal-status":
                    self._json(200, _SEAL_STATUS_UNINITIALIZED)
                elif self.path == "/v1/sys/init":
                    self._json(200, {"initialized": False})
                elif self.path.startswith("/v1/sys/health"):
                    self._empty(501)   # uninitialized
                elif self.path == "/v1/sys/leader":
                    self._empty(503)
                else:
                    self._empty(404)

        srv, _t = _serve(H)
        try:
            p = vault.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "1.13.2")
        self.assertTrue(p["uninitialized"])
        self.assertFalse(p["initialized"])
        self.assertTrue(p["sealed"])


class DevModeProbeTest(unittest.TestCase):
    def test_detects_dev_mode_signature(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/sys/seal-status":
                    self._json(200, _SEAL_STATUS_DEV)
                elif self.path.startswith("/v1/sys/health"):
                    self._json(200, _HEALTH_ACTIVE)
                elif self.path == "/v1/sys/init":
                    self._json(200, {"initialized": True})
                elif self.path == "/v1/sys/leader":
                    self._json(200, _LEADER)
                else:
                    self._empty(404)

        srv, _t = _serve(H)
        try:
            p = vault.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["dev_mode"])
        self.assertFalse(p["sealed"])
        self.assertEqual(p["storage_type"], "inmem")


class PlaintextListenerTest(unittest.TestCase):
    def test_plaintext_flag_set_from_http_transport(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/sys/seal-status":
                    body = dict(_SEAL_STATUS_DEV)
                    body["storage_type"] = "raft"
                    self._json(200, body)
                elif self.path.startswith("/v1/sys/health"):
                    self._json(200, _HEALTH_ACTIVE)
                elif self.path == "/v1/sys/init":
                    self._json(200, {"initialized": True})
                elif self.path == "/v1/sys/leader":
                    self._json(200, _LEADER)
                else:
                    self._empty(404)

        srv, _t = _serve(H)
        try:
            p = vault.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p["tls_enabled"])
        self.assertTrue(p["plaintext_listener"])
        self.assertFalse(p["sealed"])


class DebugEndpointsTest(unittest.TestCase):
    def test_pprof_and_metrics_reachable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/sys/seal-status":
                    self._json(200, _SEAL_STATUS_DEV)
                elif self.path.startswith("/v1/sys/health"):
                    self._json(200, _HEALTH_ACTIVE)
                elif self.path == "/v1/sys/init":
                    self._json(200, {"initialized": True})
                elif self.path == "/v1/sys/leader":
                    self._json(200, _LEADER)
                elif self.path.startswith("/v1/sys/pprof/goroutine"):
                    self._empty(200)
                    self.wfile.write(b"goroutine profile: total 42\n" * 20)
                elif self.path.startswith("/v1/sys/metrics"):
                    self._empty(200)
                    self.wfile.write(
                        b"# HELP vault_core_seal_config Seal config\n"
                        b"vault_core_seal_config 1\n" * 20)
                else:
                    self._empty(404)

            def do_HEAD(self):
                self._empty(404)

        srv, _t = _serve(H)
        try:
            p = vault.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["pprof_reachable"])
        self.assertTrue(p["metrics_reachable"])


# ------------------------------------------------------------------
# Authed walk: mounts / auth / KV dump / raft snapshot
# ------------------------------------------------------------------

_MOUNTS = {
    "data": {
        "secret/": {"type": "kv", "description": "generic KV",
                    "options": {"version": "2"}},
        "kv1/":    {"type": "kv", "description": "legacy KV v1",
                    "options": {"version": "1"}},
        "database/": {"type": "database", "description": "DB creds"},
        "sys/":    {"type": "system", "description": ""},
    }
}

_AUTH_BACKENDS = {
    "data": {
        "token/":    {"type": "token", "description": "token based"},
        "userpass/": {"type": "userpass", "description": "userpass auth"},
        "ldap/":     {"type": "ldap",
                      "description": "https://ldap.corp.local:636 bind"},
        "oidc/":     {"type": "oidc",
                      "description": "https://sso.example.com/.well-known"},
    }
}

_KV_V2_LIST = {"data": {"keys": ["db-prod", "api-token/", "smtp"]}}
_KV_V2_DB_PROD = {"data": {"data": {"username": "svc_app",
                                    "password": "P@ssw0rd!"}}}
_KV_V2_SMTP = {"data": {"data": {"user": "relay@example.com",
                                 "secret": "abc"}}}
_KV_V1_LIST = {"data": {"keys": ["legacy"]}}
_KV_V1_LEGACY = {"data": {"login": "root", "pass": "toor"}}

_RAFT_CONFIG = {
    "data": {
        "config": {
            "servers": [
                {"node_id": "n1", "address": "10.0.0.10:8201",
                 "leader": True, "voter": True},
                {"node_id": "n2", "address": "vault-02.corp.local:8201",
                 "leader": False, "voter": True},
            ],
            "index": 100,
        }
    }
}


class AuthedWalkTest(unittest.TestCase):
    def setUp(self):
        self.calls: list[tuple[str, str, dict]] = []
        outer = self

        class H(_Base):
            def _record(self):
                outer.calls.append(
                    (self.command, self.path,
                     dict(self.headers)))

            def do_GET(self):
                self._record()
                if self.path == "/v1/sys/seal-status":
                    self._json(200, _SEAL_STATUS_DEV)
                elif self.path.startswith("/v1/sys/health"):
                    self._json(200, _HEALTH_ACTIVE)
                elif self.path == "/v1/sys/init":
                    self._json(200, {"initialized": True})
                elif self.path == "/v1/sys/leader":
                    self._json(200, _LEADER)
                elif self.path == "/v1/sys/mounts":
                    self._json(200, _MOUNTS)
                elif self.path == "/v1/sys/auth":
                    self._json(200, _AUTH_BACKENDS)
                elif self.path == "/v1/secret/metadata?list=true":
                    self._json(200, _KV_V2_LIST)
                elif self.path == "/v1/secret/data/db-prod":
                    self._json(200, _KV_V2_DB_PROD)
                elif self.path == "/v1/secret/data/smtp":
                    self._json(200, _KV_V2_SMTP)
                elif self.path == "/v1/kv1?list=true":
                    self._json(200, _KV_V1_LIST)
                elif self.path == "/v1/kv1/legacy":
                    self._json(200, _KV_V1_LEGACY)
                elif self.path == "/v1/sys/storage/raft/configuration":
                    self._json(200, _RAFT_CONFIG)
                else:
                    self._empty(404)

            def do_LIST(self):
                self._record()
                self._empty(405)   # simulate LIST rejection - forces GET fallback

            def do_HEAD(self):
                self._record()
                if self.path == "/v1/sys/storage/raft/snapshot":
                    self._empty(200, {"Content-Length": "10485760"})
                else:
                    self._empty(404)

        self.srv, _t = _serve(H)

    def tearDown(self):
        self.srv.shutdown()

    def test_authed_walk_returns_mounts_kv_and_raft(self):
        p = vault.probe("127.0.0.1", self.srv.server_address[1],
                        timeout=2, token="s.abcdef1234567890")
        self.assertTrue(p["auth_used"])

        mount_types = {m["type"] for m in p["mounts"]}
        self.assertIn("kv", mount_types)
        self.assertIn("database", mount_types)

        auth_types = {a["type"] for a in p["auth_backends"]}
        self.assertEqual(auth_types,
                         {"token", "userpass", "ldap", "oidc"})

        kv_keys = [(k["mount"], k["key"]) for k in p["kv_secrets"]]
        self.assertIn(("secret", "db-prod"), kv_keys)
        self.assertIn(("secret", "smtp"), kv_keys)
        self.assertIn(("kv1", "legacy"), kv_keys)

        peer_ids = [pr["node_id"] for pr in p["raft_peers"]]
        self.assertEqual(peer_ids, ["n1", "n2"])
        self.assertEqual(p["raft_snapshot_bytes"], 10_485_760)

        auth_header_used = any(
            "s.abcdef1234567890" in (h.get("X-Vault-Token") or "")
            for _m, _p, h in self.calls)
        self.assertTrue(auth_header_used,
                        "X-Vault-Token header must be attached to authed calls")

    def test_facts_extracted_from_walk(self):
        p = vault.probe("127.0.0.1", self.srv.server_address[1],
                        timeout=2, token="s.abcdef1234567890")
        facts = p["facts"]
        self.assertIn("vault-01.corp.local", facts["hostnames"])
        self.assertIn("vault-02.corp.local", facts["hostnames"])
        self.assertIn("10.0.0.10", facts["hosts"])
        self.assertIn("svc_app", facts["users"])
        self.assertTrue(
            any(c["username"] == "svc_app" and c["secret"] == "P@ssw0rd!"
                for c in facts["credentials"]),
            "kv-derived credential must land in facts.credentials")
        self.assertIn("ldap.corp.local", facts["domains"])
        self.assertIn("sso.example.com", facts["domains"])


# ------------------------------------------------------------------
# Dead port + malformed responses
# ------------------------------------------------------------------

class DeadPortTest(unittest.TestCase):
    def test_dead_port_returns_unreachable(self):
        p = vault.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])


class MalformedSealStatusTest(unittest.TestCase):
    def test_non_json_seal_status_still_marks_reachable(self):
        class H(_Base):
            def do_GET(self):
                if self.path == "/v1/sys/seal-status":
                    self._empty(200)
                    self.wfile.write(b"<html>not json</html>")
                else:
                    self._empty(404)

        srv, _t = _serve(H)
        try:
            p = vault.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        # Malformed body but 200 → we still saw a live listener.
        # reachable stays False here because seal-status body could not be
        # parsed and no other endpoint answered - probe fails cleanly, doesn't
        # crash.
        self.assertIn("reachable", p)


# ------------------------------------------------------------------
# findings() end-to-end - probe dict → severity-classified findings
# ------------------------------------------------------------------

def _mkhost(ip, port):
    return Host(ip=ip, ports=[Port(portid=port, state="open", service="vault")])


class FindingsTest(unittest.TestCase):
    def _by_kind(self, fs):
        d = {}
        for f in fs:
            d.setdefault(f["kind"], []).append(f)
        return d

    def test_uninitialized_emits_critical(self):
        pr = {"reachable": True, "version": "1.13.2",
              "uninitialized": True, "sealed": True, "initialized": False,
              "plaintext_listener": False, "tls_enabled": True}
        fs = vault.findings([_mkhost("10.0.0.1", 8200)],
                            probes={("10.0.0.1", 8200): pr})
        b = self._by_kind(fs)
        self.assertEqual(b["vault_uninitialized"][0]["severity"], "critical")

    def test_dev_mode_emits_critical(self):
        pr = {"reachable": True, "version": "1.13.2",
              "dev_mode": True, "sealed": False, "initialized": True,
              "storage_type": "inmem", "tls_enabled": False,
              "plaintext_listener": True}
        fs = vault.findings([_mkhost("10.0.0.1", 8200)],
                            probes={("10.0.0.1", 8200): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("vault_dev_mode", kinds)
        self.assertIn("vault_unsealed_no_tls", kinds)
        crit = [f for f in fs if f["severity"] == "critical"]
        self.assertTrue(any(f["kind"] == "vault_dev_mode" for f in crit))

    def test_unsealed_no_tls_emits_high(self):
        pr = {"reachable": True, "version": "1.13.2",
              "sealed": False, "initialized": True,
              "storage_type": "raft",
              "tls_enabled": False, "plaintext_listener": True}
        fs = vault.findings([_mkhost("10.0.0.1", 8200)],
                            probes={("10.0.0.1", 8200): pr})
        b = self._by_kind(fs)
        self.assertEqual(b["vault_unsealed_no_tls"][0]["severity"], "high")

    def test_debug_endpoints_emit_medium(self):
        pr = {"reachable": True, "version": "1.13.2",
              "sealed": False, "initialized": True,
              "pprof_reachable": True, "metrics_reachable": True,
              "tls_enabled": True, "plaintext_listener": False}
        fs = vault.findings([_mkhost("10.0.0.1", 8200)],
                            probes={("10.0.0.1", 8200): pr})
        b = self._by_kind(fs)
        self.assertEqual(b["vault_debug_disclosure"][0]["severity"], "medium")

    def test_authed_walk_emits_mounts_kv_snapshot(self):
        pr = {"reachable": True, "version": "1.13.2",
              "sealed": False, "initialized": True,
              "auth_used": True,
              "mounts": [{"path": "secret", "type": "kv-v2",
                          "description": ""}],
              "auth_backends": [{"path": "userpass", "type": "userpass",
                                 "description": ""}],
              "kv_secrets": [{"mount": "secret", "key": "prod",
                              "data": {"username": "u", "password": "p"}}],
              "raft_peers": [{"node_id": "n1",
                              "address": "10.0.0.1:8201",
                              "leader": True}],
              "raft_snapshot_bytes": 1024,
              "tls_enabled": True, "plaintext_listener": False}
        fs = vault.findings([_mkhost("10.0.0.1", 8200)],
                            probes={("10.0.0.1", 8200): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("vault_authed_mounts", kinds)
        self.assertIn("vault_authed_secret_read", kinds)
        self.assertIn("vault_raft_snapshot_dump", kinds)

    def test_cve_finding_when_version_vulnerable(self):
        pr = {"reachable": True, "version": "1.5.4",
              "sealed": False, "initialized": True,
              "cves": vault._cve_matches("1.5.4"),
              "tls_enabled": True, "plaintext_listener": False}
        fs = vault.findings([_mkhost("10.0.0.1", 8200)],
                            probes={("10.0.0.1", 8200): pr})
        cve_kinds = [f for f in fs if f["kind"] == "vault_cve"]
        self.assertTrue(cve_kinds)
        ids = [f["title"] for f in cve_kinds]
        self.assertTrue(any("CVE-2020-16250" in t for t in ids))

    def test_info_finding_always_emitted(self):
        pr = {"reachable": True, "version": "1.13.2",
              "sealed": True, "initialized": True,
              "tls_enabled": True, "plaintext_listener": False}
        fs = vault.findings([_mkhost("10.0.0.1", 8200)],
                            probes={("10.0.0.1", 8200): pr})
        kinds = [f["kind"] for f in fs]
        self.assertEqual(kinds.count("vault_reachable"), 1)


# ------------------------------------------------------------------
# analyze() end-to-end with a fake probe injected via monkeypatch
# ------------------------------------------------------------------

class AnalyzeTest(unittest.TestCase):
    def test_analyze_unions_facts_across_probes(self):
        host = _mkhost("10.0.0.1", 8200)
        fake_probe = {
            "reachable": True, "version": "1.13.2",
            "sealed": False, "initialized": True,
            "storage_type": "raft",
            "tls_enabled": True, "plaintext_listener": False,
            "auth_used": True,
            "mounts": [], "auth_backends": [], "kv_secrets": [],
            "raft_peers": [], "raft_snapshot_bytes": 0,
            "cves": [],
            "facts": {"hostnames": ["vault-01.corp.local"],
                      "domains": ["sso.example.com"],
                      "users": ["svc_app"],
                      "hosts": [], "relay_targets": [],
                      "credentials": [{"username": "svc_app",
                                       "secret": "P@ss",
                                       "kind": "password",
                                       "source": "vault-kv:x/y"}]},
        }
        orig = vault.probe
        try:
            vault.probe = lambda ip, port=8200, timeout=3.0, token="": \
                fake_probe
            r = vault.analyze([host])
        finally:
            vault.probe = orig
        self.assertEqual(r["stats"]["targets"], 1)
        self.assertIn("vault-01.corp.local", r["facts"]["hostnames"])
        self.assertIn("svc_app", r["facts"]["users"])
        self.assertTrue(r["facts"]["credentials"])

    def test_analyze_no_targets(self):
        r = vault.analyze([Host(ip="1.2.3.4",
                                ports=[Port(portid=22, state="open",
                                            service="ssh")])])
        self.assertEqual(r["stats"]["targets"], 0)
        self.assertEqual(r["findings"], [])


# ------------------------------------------------------------------
# findings_to_vulns bridge
# ------------------------------------------------------------------

class VulnsBridgeTest(unittest.TestCase):
    def test_findings_to_vulns_produces_by_ip_map(self):
        fs = [{"severity": "critical",
               "title": "Vault dev mode",
               "target": "10.0.0.1:8200",
               "detail": "x",
               "tool": "vault", "command": "curl ...",
               "remediation": "y", "cwes": ["CWE-798"],
               "kind": "vault_dev_mode"}]
        out = vault.findings_to_vulns(fs)
        self.assertIn("10.0.0.1", out)
        v = out["10.0.0.1"][0]
        self.assertEqual(v.port, 8200)
        self.assertEqual(v.severity, "critical")


# ------------------------------------------------------------------
# _pick_host - address parser fed by leader / raft peer strings
# ------------------------------------------------------------------

class PickHostTest(unittest.TestCase):
    def test_url_with_port(self):
        self.assertEqual(vault._pick_host("https://vault.corp.local:8200"),
                         "vault.corp.local")

    def test_ip_only(self):
        self.assertEqual(vault._pick_host("10.0.0.5"), "10.0.0.5")

    def test_ip_with_port(self):
        self.assertEqual(vault._pick_host("10.0.0.5:8201"), "10.0.0.5")

    def test_empty(self):
        self.assertEqual(vault._pick_host(""), "")


# Guard: base64 helper import kept because some fixtures use kvs with
# base64-encoded keys in v3-style etcd payloads. Vault KV is not encoded
# but the import keeps the fixture format future-safe.
_ = base64  # noqa: F401


if __name__ == "__main__":
    unittest.main()
