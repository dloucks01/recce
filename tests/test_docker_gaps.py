"""Coverage for docker.py additions: env-var secret harvest, namespace/cap
escape enablers, and version-gated CVEs (docker engine + runc)."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce.core.models import Host, Port
from recce.services import docker


class _JSON(BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        m = self.routes.get(path)
        if m is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        status, body = m
        raw = json.dumps(body).encode() if isinstance(body, (dict, list)) \
            else (body.encode() if isinstance(body, str) else body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def _serve(routes):
    handler = type("H", (_JSON,), {"routes": routes})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _host(port: int) -> Host:
    return Host(ip="127.0.0.1",
                ports=[Port(portid=port, service="docker", state="open")])


def _finds(kind: str, fs):
    return [f for f in fs if f.get("kind") == kind]


class SemverParseTest(unittest.TestCase):
    def test_parse_semver_matches_common_shapes(self):
        self.assertEqual(docker._parse_semver("24.0.5"), (24, 0, 5))
        self.assertEqual(docker._parse_semver("v1.1.12"), (1, 1, 12))
        self.assertEqual(docker._parse_semver("27.1.0-beta"), (27, 1, 0))
        self.assertIsNone(docker._parse_semver(""))
        self.assertIsNone(docker._parse_semver("abcdef1"))


class EngineCveVersionGateTest(unittest.TestCase):
    def test_cve_2024_41110_windows(self):
        # Vulnerable ranges: <23.0.14, 24.x, 25.x, 26.x<26.1.4, 27.0.x<27.1.0
        for v in ("22.0.0", "23.0.13", "24.0.5", "25.0.0",
                  "26.1.3", "27.0.9"):
            hits = docker._engine_cves(v)
            self.assertTrue(any(h["cve"] == "CVE-2024-41110" for h in hits),
                            f"expected CVE-2024-41110 hit for {v}")

    def test_cve_2024_41110_fixed_versions_clean(self):
        for v in ("23.0.14", "26.1.4", "27.1.0", "27.2.0", "28.0.0"):
            hits = docker._engine_cves(v)
            self.assertFalse(any(h["cve"] == "CVE-2024-41110" for h in hits),
                             f"unexpected CVE-2024-41110 hit for {v}")

    def test_engine_cves_never_fires_without_a_version(self):
        # Never guess: an unparseable version yields no CVE finding.
        self.assertEqual(docker._engine_cves(""), [])
        self.assertEqual(docker._engine_cves("dev"), [])


class RuncCveVersionGateTest(unittest.TestCase):
    def test_cve_2024_21626_vulnerable(self):
        hits = docker._runc_cves("v1.1.7-0-g860f061")
        self.assertTrue(any(h["cve"] == "CVE-2024-21626" for h in hits))

    def test_cve_2024_21626_fixed(self):
        hits = docker._runc_cves("v1.1.12-0-g51d5e94")
        self.assertFalse(any(h["cve"] == "CVE-2024-21626" for h in hits))

    def test_runc_bare_commit_yields_nothing(self):
        # A bare git commit hash tells us nothing about the version - never guess.
        self.assertEqual(docker._runc_cves("51d5e94"), [])
        self.assertEqual(docker._runc_cves(""), [])


class NsEscapeClassifierTest(unittest.TestCase):
    def test_host_namespace_shares_flagged(self):
        hits = docker._classify_ns_escape({"NetworkMode": "host",
                                           "PidMode": "host",
                                           "IpcMode": "host"})
        self.assertIn("NetworkMode=host", hits)
        self.assertIn("PidMode=host", hits)
        self.assertIn("IpcMode=host", hits)

    def test_bridge_namespace_not_flagged(self):
        self.assertEqual(
            docker._classify_ns_escape({"NetworkMode": "bridge",
                                        "PidMode": "", "IpcMode": ""}), [])

    def test_dangerous_capabilities_flagged(self):
        hits = docker._classify_ns_escape(
            {"CapAdd": ["CAP_SYS_ADMIN", "SYS_PTRACE", "NET_RAW"]})
        self.assertTrue(any("SYS_ADMIN" in h for h in hits))
        self.assertTrue(any("SYS_PTRACE" in h for h in hits))
        # NET_RAW is in the default capability set and NOT in _DANGER_CAPS.
        self.assertFalse(any("NET_RAW" in h for h in hits))

    def test_secopt_unconfined_flagged(self):
        hits = docker._classify_ns_escape(
            {"SecurityOpt": ["seccomp=unconfined", "label=disable"]})
        self.assertTrue(any("unconfined" in h for h in hits))

    def test_dangerous_devices_flagged(self):
        hits = docker._classify_ns_escape(
            {"Devices": [{"PathOnHost": "/dev/mem"},
                         {"PathOnHost": "/dev/sda1"},
                         {"PathOnHost": "/dev/null"}]})
        self.assertTrue(any("/dev/mem" in h for h in hits))
        self.assertTrue(any("/dev/sda1" in h for h in hits))
        self.assertFalse(any("/dev/null" in h for h in hits))


class EnvSecretScannerTest(unittest.TestCase):
    def test_common_secret_keys_flagged_value_masked(self):
        found = docker._scan_env_secrets([
            "POSTGRES_PASSWORD=hunter2secret",
            "AWS_SECRET_ACCESS_KEY=abcd1234efgh5678",
            "GITHUB_TOKEN=ghp_deadbeef",
            "JWT_SECRET=x",
            "PATH=/usr/bin",
            "APP_MODE=production",
        ])
        keys = {h["key"] for h in found}
        self.assertEqual(keys, {"POSTGRES_PASSWORD", "AWS_SECRET_ACCESS_KEY",
                                "GITHUB_TOKEN", "JWT_SECRET"})
        # Preview masks the middle of the value; short value survives whole.
        by = {h["key"]: h for h in found}
        self.assertEqual(by["JWT_SECRET"]["preview"], "x")
        self.assertIn("***", by["POSTGRES_PASSWORD"]["preview"])
        # Full value stays on the finding dict for the loot pool.
        self.assertEqual(by["POSTGRES_PASSWORD"]["value"], "hunter2secret")

    def test_empty_and_malformed_entries_skipped(self):
        self.assertEqual(docker._scan_env_secrets(
            ["", "NO_EQUALS_HERE", "DB_PASSWORD=", "=orphan"]), [])

    def test_non_list_input_is_safe(self):
        self.assertEqual(docker._scan_env_secrets(None), [])
        self.assertEqual(docker._scan_env_secrets("PASSWORD=x"), [])


# --- integration: probe + findings across the new capabilities -----------

def _routes_full():
    return {
        "/version": (200, {"Version": "24.0.5", "ApiVersion": "1.43",
                           "Os": "linux", "Arch": "amd64",
                           "KernelVersion": "6.1.0"}),
        "/info": (200, {"Name": "dockerhost", "Containers": 2,
                        "ContainersRunning": 2, "Images": 5,
                        "ServerVersion": "24.0.5",
                        "RuncCommit": {"ID": "v1.1.7-0-g860f061",
                                       "Expected": "v1.1.7-0-g860f061"}}),
        "/containers/json": (200, [
            {"Id": "aaaa", "Image": "webapp:1", "Names": ["/web"],
             "State": "running"},
            {"Id": "bbbb", "Image": "worker:1", "Names": ["/worker"],
             "State": "running"},
        ]),
        "/containers/aaaa/json": (200, {
            "HostConfig": {"Binds": [], "Privileged": False,
                           "NetworkMode": "bridge"},
            "Config": {"Env": ["APP_ENV=prod",
                               "POSTGRES_PASSWORD=hunter2secret",
                               "AWS_SECRET_ACCESS_KEY=AKIA_deadbeef_key"]},
        }),
        "/containers/bbbb/json": (200, {
            "HostConfig": {"Binds": [], "Privileged": False,
                           "NetworkMode": "host", "PidMode": "host",
                           "CapAdd": ["SYS_ADMIN"],
                           "SecurityOpt": ["seccomp=unconfined"]},
            "Config": {"Env": ["MODE=worker"]},
        }),
        "/images/json": (200, []),
    }


class DockerProbeAndFindingsGapTest(unittest.TestCase):
    def test_probe_collects_env_secrets_ns_escapes_and_cves(self):
        srv, port = _serve(_routes_full())
        try:
            pr = docker.probe("127.0.0.1", port, timeout=3.0)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIsNotNone(pr)
        self.assertTrue(pr["exposed"])
        # engine + runc CVE gates fired from already-fetched strings.
        self.assertTrue(any(c["cve"] == "CVE-2024-41110"
                            for c in pr["engine_cves"]))
        self.assertTrue(any(c["cve"] == "CVE-2024-21626"
                            for c in pr["runc_cves"]))
        # namespace escape recorded on the worker, not on web.
        by_container = {e["container"]: e for e in pr["ns_escapes"]}
        self.assertIn("worker", by_container)
        self.assertNotIn("web", by_container)
        self.assertTrue(any("NetworkMode=host" in x
                            for x in by_container["worker"]["enablers"]))
        # env-var credentials picked up on web only.
        by_env = {e["container"]: e for e in pr["env_secrets"]}
        self.assertIn("web", by_env)
        self.assertNotIn("worker", by_env)
        keys = {h["key"] for h in by_env["web"]["hits"]}
        self.assertEqual(keys, {"POSTGRES_PASSWORD", "AWS_SECRET_ACCESS_KEY"})

    def test_findings_emit_new_kinds(self):
        srv, port = _serve(_routes_full())
        try:
            pr = docker.probe("127.0.0.1", port, timeout=3.0)
        finally:
            srv.shutdown()
            srv.server_close()
        fs = docker.findings([_host(port)],
                             {("127.0.0.1", port): pr})
        # Existing findings still emitted.
        self.assertTrue(_finds("docker_api", fs))
        # New kinds each produce exactly one finding.
        env_f = _finds("docker_env_secrets", fs)
        self.assertEqual(len(env_f), 1)
        self.assertIn("POSTGRES_PASSWORD", env_f[0]["detail"])
        # value must be masked in the detail text, not leaked to reporting.
        self.assertNotIn("hunter2secret", env_f[0]["detail"])
        ns_f = _finds("docker_ns_escape", fs)
        self.assertEqual(len(ns_f), 1)
        self.assertIn("worker", ns_f[0]["detail"])
        cve_engine = _finds("docker_engine_cve", fs)
        self.assertEqual(len(cve_engine), 1)
        self.assertEqual(cve_engine[0]["cves"], ["CVE-2024-41110"])
        self.assertEqual(cve_engine[0]["severity"], "critical")
        cve_runc = _finds("docker_runc_cve", fs)
        self.assertEqual(len(cve_runc), 1)
        self.assertEqual(cve_runc[0]["cves"], ["CVE-2024-21626"])

    def test_findings_no_new_kinds_when_daemon_is_current(self):
        routes = _routes_full()
        # Patch to a fixed engine + runc; keep other data.
        routes["/info"] = (200, {"Name": "dockerhost", "Containers": 2,
                                 "ContainersRunning": 2, "Images": 5,
                                 "ServerVersion": "27.1.0",
                                 "RuncCommit": {"ID": "v1.1.12-0-g51d5e94",
                                                "Expected": "v1.1.12-0-g51d5e94"}})
        srv, port = _serve(routes)
        try:
            pr = docker.probe("127.0.0.1", port, timeout=3.0)
        finally:
            srv.shutdown()
            srv.server_close()
        fs = docker.findings([_host(port)], {("127.0.0.1", port): pr})
        self.assertEqual(_finds("docker_engine_cve", fs), [])
        self.assertEqual(_finds("docker_runc_cve", fs), [])
        # Existing behavior unchanged.
        self.assertTrue(_finds("docker_api", fs))

    def test_env_scan_and_ns_scan_skip_when_no_containers(self):
        routes = {
            "/version": (200, {"Version": "24.0.5"}),
            "/info": (200, {"ServerVersion": "24.0.5"}),
            "/containers/json": (200, []),
        }
        srv, port = _serve(routes)
        try:
            pr = docker.probe("127.0.0.1", port, timeout=3.0)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertTrue(pr["exposed"])
        # containers/json returned empty → per-container aggregates empty.
        self.assertEqual(pr.get("env_secrets", []), [])
        self.assertEqual(pr.get("ns_escapes", []), [])
        # And no per-container findings are emitted downstream.
        fs = docker.findings([_host(port)], {("127.0.0.1", port): pr})
        self.assertEqual(_finds("docker_env_secrets", fs), [])
        self.assertEqual(_finds("docker_ns_escape", fs), [])


if __name__ == "__main__":
    unittest.main()
