"""Tests for recce.services.etcd — unauthenticated etcd read probe.

Stand up a tiny loopback HTTP server that mimics an etcd endpoint.
Verify probe() correctly identifies:

* An unauth-readable v3 store (POST /v3/kv/range returns kvs list)
* An unauth-readable v2 store (GET /v2/keys returns node tree)
* An auth-protected etcd (all reads return 401/403 but /version works)
* A dead/non-etcd port (no crash, reachable=False)
"""
from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.services import etcd


def _serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thr = threading.Thread(target=srv.serve_forever, daemon=True)
    thr.start()
    return srv, thr


class _EtcdBase(BaseHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass


class ProbeTest(unittest.TestCase):
    def test_v3_unauth_read_detected(self):
        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = json.dumps({"etcdserver": "3.5.9", "etcdcluster": "3.5.0"}).encode()
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                elif self.path.startswith("/v2/keys"):
                    self.send_response(404); self.end_headers()
                else:
                    self.send_response(404); self.end_headers()
            def do_POST(self):
                if self.path == "/v3/kv/range":
                    body = json.dumps({"kvs": [
                        {"key": "L2Zvb28=", "value": "YmFy"},
                        {"key": "L2Jheg==", "value": "cXV1eA=="},
                        {"key": "L3NlY3JldA==", "value": "cHc="},
                    ]}).encode()
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["version"], "3.5.9")
        self.assertTrue(p["v3_readable"])
        self.assertEqual(p["v3_keys"], 3)
        self.assertFalse(p["v2_readable"])

    def test_v2_unauth_read_detected(self):
        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = b'{"etcdserver":"2.3.8","etcdcluster":"2.3.0"}'
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                elif self.path.startswith("/v2/keys"):
                    body = json.dumps({
                        "action": "get",
                        "node": {"key": "/", "dir": True, "nodes": [
                            {"key": "/foo", "value": "bar"},
                            {"key": "/dir", "dir": True, "nodes": [
                                {"key": "/dir/x", "value": "1"},
                                {"key": "/dir/y", "value": "2"},
                            ]},
                        ]}}).encode()
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(404); self.end_headers()
            def do_POST(self):
                self.send_response(404); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["v2_readable"])
        # root + /foo + /dir + /dir/x + /dir/y = 5 nodes (root has key "/")
        self.assertEqual(p["v2_keys"], 5)

    def test_auth_protected_flagged_reachable_no_read(self):
        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}'
                    self.send_response(200); self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(401); self.end_headers()
            def do_POST(self):
                self.send_response(401); self.end_headers()
        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["v2_readable"])
        self.assertFalse(p["v3_readable"])

    def test_dead_port_returns_unreachable(self):
        p = etcd.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])

    def test_snapshot_download_detected(self):
        """POST /v3/maintenance/snapshot returning the gRPC-JSON stream
        `{"result":{"blob":"<base64>","remaining_bytes":"0"}}` — the etcd
        maintenance.proto Snapshot RPC wire format via grpc-gateway — must
        set snapshot_ok=True and count decoded blob bytes."""
        import base64 as _b64
        blob_bytes = b"BBOLT-FIXTURE-PAYLOAD-\x00\x01\x02\x03" * 4
        frame = json.dumps({"result": {
            "header": {"cluster_id": "1", "member_id": "2",
                       "revision": "1", "raft_term": "1"},
            "remaining_bytes": "0",
            "blob": _b64.b64encode(blob_bytes).decode(),
        }}).encode()

        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(404); self.end_headers()

            def do_POST(self):
                if self.path == "/v3/maintenance/snapshot":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(frame)))
                    self.end_headers(); self.wfile.write(frame)
                else:
                    # kv/range and authenticate both fail — snapshot is the
                    # only positive primitive on this fixture, matching the
                    # real-world case where the maintenance permission tier
                    # is misconfigured independently of kv perms.
                    self.send_response(401); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["v3_readable"])
        self.assertTrue(p["snapshot_ok"])
        self.assertEqual(p["snapshot_bytes"], len(blob_bytes))

    def test_snapshot_not_flagged_on_401(self):
        """A 401 on /v3/maintenance/snapshot must NOT be treated as positive,
        so the existing auth-protected fixture remains a clean 'reachable
        only' report even with the new probe steps active."""
        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(401); self.end_headers()

            def do_POST(self):
                self.send_response(401); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertFalse(p.get("snapshot_ok"))
        self.assertNotIn("default_cred_user", p)

    def test_default_cred_authenticate_detected(self):
        """POST /v3/auth/authenticate {"name":"root","password":"root"} on an
        auth-enabled etcd whose root password is the deploy-template default —
        the auth.proto Authenticate RPC returns
        {"header":{...},"token":"<jwt>"} on success. Probe must surface the
        successful (user, password) pair."""

        class H(_EtcdBase):
            def do_GET(self):
                if self.path == "/version":
                    body = b'{"etcdserver":"3.5.9","etcdcluster":"3.5.0"}'
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers(); self.wfile.write(body)
                else:
                    self.send_response(401); self.end_headers()

            def do_POST(self):
                if self.path == "/v3/auth/authenticate":
                    length = int(self.headers.get("Content-Length") or "0")
                    body = self.rfile.read(length) if length else b""
                    try:
                        req = json.loads(body.decode())
                    except ValueError:
                        req = {}
                    if req.get("name") == "root" and req.get("password") == "etcd":
                        resp = json.dumps({
                            "header": {"cluster_id": "1", "member_id": "2",
                                       "revision": "2", "raft_term": "2"},
                            "token": "sJ2ELpmzGZBBnUlq.42",
                        }).encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(resp)))
                        self.end_headers(); self.wfile.write(resp)
                        return
                    # Wrong password — mimic the grpc-gateway 400 error shape.
                    err = json.dumps({
                        "error": "etcdserver: authentication failed, "
                                 "invalid user ID or password",
                        "code": 3, "message": "authentication failed",
                    }).encode()
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err)))
                    self.end_headers(); self.wfile.write(err)
                    return
                self.send_response(401); self.end_headers()

        srv, _t = _serve(H)
        try:
            p = etcd.probe("127.0.0.1", srv.server_address[1], timeout=2)
        finally:
            srv.shutdown()
        self.assertTrue(p["reachable"])
        self.assertFalse(p["v3_readable"])
        self.assertEqual(p.get("default_cred_user"), "root")
        self.assertEqual(p.get("default_cred_pass"), "etcd")


class FindingsTest(unittest.TestCase):
    """findings() must emit the new critical kinds from a synthesized probe
    dict — no server needed, this pins the finding-shape/kind contract."""

    def _hosts(self, portid=2379):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.1")
        h.ports.append(Port(portid=portid, service="etcd"))
        return [h]

    def test_snapshot_finding_emitted(self):
        hosts = self._hosts()
        probes = {("10.0.0.1", 2379): {
            "reachable": True, "version": "3.5.9",
            "v2_readable": False, "v3_readable": False,
            "v2_keys": 0, "v3_keys": 0,
            "snapshot_ok": True, "snapshot_bytes": 4096,
        }}
        fs = etcd.findings(hosts, probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("etcd_snapshot_download", kinds)
        snap = [f for f in fs if f["kind"] == "etcd_snapshot_download"][0]
        self.assertEqual(snap["severity"], "critical")
        self.assertIn("CWE-306", snap["cwes"])
        self.assertIn("CWE-200", snap["cwes"])
        self.assertIn("10.0.0.1:2379", snap["target"])

    def test_default_cred_finding_emitted_when_no_unauth_read(self):
        hosts = self._hosts()
        probes = {("10.0.0.1", 2379): {
            "reachable": True, "version": "3.5.9",
            "v2_readable": False, "v3_readable": False,
            "v2_keys": 0, "v3_keys": 0,
            "snapshot_ok": False, "snapshot_bytes": 0,
            "default_cred_user": "root", "default_cred_pass": "root",
        }}
        fs = etcd.findings(hosts, probes)
        kinds = {f["kind"] for f in fs}
        # Must NOT double-emit the info 'reachable' finding when default creds
        # are the story on this port; the critical takes over the branch.
        self.assertIn("etcd_default_creds", kinds)
        self.assertNotIn("etcd_authed", kinds)
        dc = [f for f in fs if f["kind"] == "etcd_default_creds"][0]
        self.assertEqual(dc["severity"], "critical")
        self.assertIn("CWE-798", dc["cwes"])

    def test_default_cred_suppressed_when_unauth_read_present(self):
        """When kv/range is already open the critical is `etcd_unauth_read`;
        the default-cred branch must not fire on top of it."""
        hosts = self._hosts()
        probes = {("10.0.0.1", 2379): {
            "reachable": True, "version": "3.5.9",
            "v2_readable": False, "v3_readable": True,
            "v2_keys": 0, "v3_keys": 5,
            "snapshot_ok": False, "snapshot_bytes": 0,
            # A stale default_cred_user should never appear here because probe()
            # skips the credential step when v3 is readable, but pin it anyway.
        }}
        fs = etcd.findings(hosts, probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("etcd_unauth_read", kinds)
        self.assertNotIn("etcd_default_creds", kinds)


if __name__ == "__main__":
    unittest.main()
