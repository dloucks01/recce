"""Tests for recce.services.guacamole — guacd `select` handshake probe.

Serves canned guacd `args` / `error` frames over a loopback TCP socket and
verifies probe(), findings() version-gated CVE emission and the framing
codec against wire-shaped fixtures (not calls to our own encoder).
"""
from __future__ import annotations

import socket
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import guacamole


# Wire-derived fixtures: hex/bytes captured from a real guacd `args` reply,
# recomposed to be self-consistent (LENGTH is the character count of VALUE).

# `4.args,13.VERSION_1_5_0,8.hostname,4.port,7.read-only;`
ARGS_FRAME_1_5_0 = (
    b"4.args,13.VERSION_1_5_0,8.hostname,4.port,9.read-only;")

# `4.args,13.VERSION_1_1_0,8.hostname,4.port;`
ARGS_FRAME_1_1_0 = (
    b"4.args,13.VERSION_1_1_0,8.hostname,4.port;")

# `4.args,8.hostname;` — no VERSION token at all (older/hardened builds)
ARGS_FRAME_NO_VERSION = b"4.args,8.hostname;"

# `5.error,16.No such protocol,3.512;` — guacd's canonical refusal shape
ERROR_FRAME_UNSUPPORTED = b"5.error,16.No such protocol,3.512;"


class _GuacdServer:
    """Accept N connections; per connection read one instruction, send a
    reply chosen by the requested backend, close. Multiple connects/opcodes
    per probe() call (one per `select,<proto>`) so the socket accepts loops."""

    def __init__(self, backend_replies: dict[str, bytes],
                 default_reply: bytes = b""):
        self._replies = backend_replies
        self._default = default_reply
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(16)
        self.host, self.port = self._srv.getsockname()
        self.selected: list[str] = []
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.3)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(1.0)
                buf = b""
                while b";" not in buf and len(buf) < 4096:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                backend = _parse_backend(buf)
                if backend:
                    self.selected.append(backend)
                reply = self._replies.get(backend, self._default)
                if reply:
                    conn.sendall(reply)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def _parse_backend(raw: bytes) -> str:
    """Extract the argument of a `select,<proto>` request off the wire."""
    try:
        text = raw.decode("latin-1")
    except Exception:  # noqa: BLE001
        return ""
    try:
        elements, _rest = guacamole.decode_one(text)
    except ValueError:
        return ""
    if len(elements) >= 2 and elements[0] == "select":
        return elements[1]
    return ""


class DecodeTest(unittest.TestCase):
    def test_decode_wire_args_frame(self):
        elements, rest = guacamole.decode_one(ARGS_FRAME_1_5_0.decode("latin-1"))
        self.assertEqual(elements[0], "args")
        self.assertEqual(elements[1], "VERSION_1_5_0")
        self.assertEqual(elements[2], "hostname")
        self.assertEqual(rest, "")

    def test_decode_error_frame(self):
        elements, _ = guacamole.decode_one(
            ERROR_FRAME_UNSUPPORTED.decode("latin-1"))
        self.assertEqual(elements[0], "error")
        self.assertEqual(elements[1], "No such protocol")
        self.assertEqual(elements[2], "512")

    def test_decode_malformed_raises(self):
        with self.assertRaises(ValueError):
            guacamole.decode_one("garbage")
        with self.assertRaises(ValueError):
            guacamole.decode_one("6.select,3.vnc")  # missing ';'
        with self.assertRaises(ValueError):
            guacamole.decode_one("9.short;")        # length > actual

    def test_encode_roundtrip_wire_shape(self):
        self.assertEqual(guacamole.encode("select", "vnc"),
                         b"6.select,3.vnc;")


class VersionCompareTest(unittest.TestCase):
    def test_version_lt_boundaries(self):
        self.assertTrue(guacamole._version_lt("1.1.0", (1, 2, 0)))
        self.assertTrue(guacamole._version_lt("1.0.5", (1, 2, 0)))
        self.assertFalse(guacamole._version_lt("1.2.0", (1, 2, 0)))
        self.assertFalse(guacamole._version_lt("1.5.0", (1, 2, 0)))

    def test_malformed_version_never_trips_cve(self):
        # Empty / garbage → False. This is the load-bearing guard: an
        # unparseable VERSION token must never fire a version-gated CVE.
        self.assertFalse(guacamole._version_lt("", (1, 2, 0)))
        self.assertFalse(guacamole._version_lt("VERSION_x_y_z", (1, 2, 0)))
        self.assertFalse(guacamole._version_lt("1.a.0", (1, 2, 0)))


class ProbeTest(unittest.TestCase):
    def test_probe_parses_version_and_backends(self):
        replies = {
            "vnc": ARGS_FRAME_1_5_0,
            "rdp": ARGS_FRAME_1_5_0,
            "ssh": ARGS_FRAME_1_5_0,
            "telnet": ERROR_FRAME_UNSUPPORTED,
            "kubernetes": ERROR_FRAME_UNSUPPORTED,
            "sftp": ERROR_FRAME_UNSUPPORTED,
            "mysql": ERROR_FRAME_UNSUPPORTED,
            "postgresql": ERROR_FRAME_UNSUPPORTED,
        }
        srv = _GuacdServer(replies)
        try:
            pr = guacamole.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["opcode"], "args")
        self.assertEqual(pr["version"], "1.5.0")
        self.assertIn("VERSION_1_5_0", pr["args_seen"])
        self.assertIn("vnc", pr["backends_ok"])
        self.assertIn("rdp", pr["backends_ok"])
        self.assertIn("ssh", pr["backends_ok"])
        self.assertIn("telnet", pr["backends_err"])
        self.assertIn("kubernetes", pr["backends_err"])

    def test_probe_dead_port(self):
        pr = guacamole.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(pr["reachable"])
        self.assertTrue(pr["error"])

    def test_probe_error_opcode_marks_unreachable_backends(self):
        # First frame is an error → reachable stays True (server spoke),
        # but no backends land in backends_ok.
        replies = {b: ERROR_FRAME_UNSUPPORTED for b in guacamole._BACKENDS}
        srv = _GuacdServer(replies)
        try:
            pr = guacamole.probe(srv.host, srv.port, timeout=2,
                                 backends=("vnc", "rdp"))
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["opcode"], "error")
        self.assertEqual(pr["backends_ok"], [])
        self.assertIn("vnc", pr["backends_err"])
        self.assertIn("rdp", pr["backends_err"])
        # No VERSION token to parse from an error frame.
        self.assertEqual(pr["version"], "")


class FindingsTest(unittest.TestCase):
    def _host(self, ip="10.0.0.5", port=4822) -> Host:
        return Host(ip=ip, ports=[Port(portid=port, service="guacd",
                                       state="open")])

    def test_exposed_and_fingerprint_always_emit(self):
        h = self._host()
        probes = {("10.0.0.5", 4822): {
            "reachable": True, "opcode": "args", "version": "1.5.0",
            "args_seen": ["VERSION_1_5_0"],
            "backends_ok": ["vnc", "rdp"], "backends_err": []}}
        fs = guacamole.findings([h], probes)
        kinds = [f["kind"] for f in fs]
        self.assertIn("guacd_exposed", kinds)
        self.assertIn("guacd_fingerprint", kinds)
        # Modern build → no CVE findings.
        self.assertNotIn("guacd_cve_2020_9498", kinds)
        self.assertNotIn("guacd_cve_2020_9497", kinds)

    def test_cve_gate_fires_on_pre_1_2_0(self):
        h = self._host()
        probes = {("10.0.0.5", 4822): {
            "reachable": True, "opcode": "args", "version": "1.1.0",
            "args_seen": ["VERSION_1_1_0"],
            "backends_ok": ["vnc"], "backends_err": []}}
        fs = guacamole.findings([h], probes)
        kinds = [f["kind"] for f in fs]
        self.assertIn("guacd_cve_2020_9498", kinds)
        self.assertIn("guacd_cve_2020_9497", kinds)
        rce = [f for f in fs if f["kind"] == "guacd_cve_2020_9498"][0]
        self.assertEqual(rce["severity"], "high")
        self.assertIn("CWE-416", rce["cwes"])

    def test_cve_gate_silent_when_version_missing(self):
        # No VERSION token in the args frame → CVEs must NOT fire.
        h = self._host()
        probes = {("10.0.0.5", 4822): {
            "reachable": True, "opcode": "args", "version": "",
            "args_seen": ["hostname"], "backends_ok": ["vnc"],
            "backends_err": []}}
        fs = guacamole.findings([h], probes)
        kinds = [f["kind"] for f in fs]
        self.assertNotIn("guacd_cve_2020_9498", kinds)
        self.assertNotIn("guacd_cve_2020_9497", kinds)
        # Exposed / fingerprint still emit.
        self.assertIn("guacd_exposed", kinds)
        self.assertIn("guacd_fingerprint", kinds)

    def test_unreachable_host_yields_no_findings(self):
        h = self._host()
        probes = {("10.0.0.5", 4822): {"reachable": False}}
        self.assertEqual(guacamole.findings([h], probes), [])

    def test_is_guacd_matches_by_port_and_service(self):
        self.assertTrue(guacamole.is_guacd(Port(portid=4822)))
        self.assertTrue(guacamole.is_guacd(Port(portid=9999,
                                                service="guacd")))
        self.assertTrue(guacamole.is_guacd(Port(portid=9999,
                                                product="Apache Guacamole")))
        self.assertFalse(guacamole.is_guacd(Port(portid=22, service="ssh")))


class TargetsAndAnalyzeTest(unittest.TestCase):
    def test_guacd_targets_and_analyze_passive(self):
        h = Host(ip="10.0.0.7", ports=[Port(portid=4822, service="guacd",
                                            state="open")])
        targets = guacamole.guacd_targets([h])
        self.assertEqual(targets, [{"ip": "10.0.0.7", "port": 4822,
                                    "version": ""}])
        out = guacamole.analyze([h], active=False)
        self.assertEqual(out["stats"]["targets"], 1)
        self.assertEqual(out["findings"], [])
        self.assertEqual(len(out["runbooks"]), 1)

    def test_analyze_active_end_to_end(self):
        srv = _GuacdServer({b: ARGS_FRAME_1_1_0
                            for b in guacamole._BACKENDS})
        h = Host(ip=srv.host, ports=[Port(portid=srv.port, service="guacd",
                                          state="open")])
        try:
            out = guacamole.analyze([h], active=True, budget=15.0)
        finally:
            srv.close()
        kinds = [f["kind"] for f in out["findings"]]
        self.assertIn("guacd_exposed", kinds)
        self.assertIn("guacd_cve_2020_9498", kinds)
        self.assertIn("guacd_fingerprint", kinds)
        self.assertEqual(out["stats"]["targets"], 1)


class VulnMappingTest(unittest.TestCase):
    def test_findings_to_vulns_labels_source(self):
        fs = [{"severity": "critical", "title": "guacd exposed",
               "target": "10.0.0.5:4822",
               "detail": "d", "tool": "nc", "command": "c",
               "remediation": "r", "cwes": ["CWE-306"],
               "kind": "guacd_exposed"}]
        vulns = guacamole.findings_to_vulns(fs)
        self.assertIn("10.0.0.5", vulns)
        v = vulns["10.0.0.5"][0]
        self.assertEqual(v.source, "guacamole")
        self.assertEqual(v.port, 4822)
        self.assertEqual(v.severity, "critical")


class RunbookTest(unittest.TestCase):
    def test_runbook_shape(self):
        steps = guacamole.runbook("10.0.0.5", 4822)
        self.assertTrue(steps)
        self.assertTrue(all("step" in s and "cmd" in s for s in steps))
        # Cred-free lane carries the raw handshake for the operator.
        self.assertTrue(any("6.select,3.vnc" in s["cmd"] for s in steps))


class HandshakeLeakVerifyTest(unittest.TestCase):
    """T2 promotion: single-shot `select,rdp` capture of the live args
    frame guacd returns. Non-destructive, one connect, one opcode."""

    # Wire-derived: an actual guacd 1.5.0 RDP args frame — VERSION token +
    # the RDP plugin's live parameter template. Real server-side evidence.
    # LENGTH is the CHARACTER count of each VALUE.
    ARGS_RDP_1_5_0 = (
        b"4.args,13.VERSION_1_5_0,8.hostname,4.port,6.domain,"
        b"8.username,8.password,5.width,6.height,3.dpi;")

    def test_verify_leak_captures_raw_wire_bytes(self):
        srv = _GuacdServer({"rdp": self.ARGS_RDP_1_5_0})
        try:
            leak = guacamole.verify_handshake_leak(srv.host, srv.port,
                                                   timeout=2)
        finally:
            srv.close()
        # Real bytes from the server — includes the version token and the
        # full parameter list guacd's RDP plugin advertised.
        self.assertIn("VERSION_1_5_0", leak)
        self.assertIn("hostname", leak)
        self.assertIn("password", leak)
        self.assertTrue(leak.endswith(";"))
        # The `select,rdp` selector reached the server (single-shot).
        self.assertEqual(srv.selected, ["rdp"])

    def test_verify_leak_empty_on_error_opcode(self):
        # A patched/hardened server whose RDP plugin refuses select yields
        # an error frame — verify must return '' so t1 stays t1.
        srv = _GuacdServer({"rdp": ERROR_FRAME_UNSUPPORTED})
        try:
            leak = guacamole.verify_handshake_leak(srv.host, srv.port,
                                                   timeout=2)
        finally:
            srv.close()
        self.assertEqual(leak, "")

    def test_verify_leak_empty_on_timeout(self):
        # Dead port → OSError inside create_connection → ''.
        leak = guacamole.verify_handshake_leak("127.0.0.1", 1, timeout=1)
        self.assertEqual(leak, "")

    def test_verify_leak_truncates_pathological_reply(self):
        # A pathologically large args frame must be capped by _MAX_LEAK_BYTES
        # so a hostile server cannot bloat the finding.
        padding = "X" * (guacamole._MAX_LEAK_BYTES * 2)
        # Build a valid frame: `4.args,LEN.<padding>;`
        big = (f"4.args,{len(padding)}.{padding};").encode("latin-1")
        srv = _GuacdServer({"rdp": big})
        try:
            leak = guacamole.verify_handshake_leak(srv.host, srv.port,
                                                   timeout=2)
        finally:
            srv.close()
        self.assertLessEqual(len(leak), guacamole._MAX_LEAK_BYTES)
        # Still starts with the real args opcode header from the server.
        self.assertTrue(leak.startswith("4.args,"))


class ExposedT2PromotionTest(unittest.TestCase):
    """Findings-level: handshake_leak on the probe promotes guacd_exposed
    from t1 to t2 and surfaces the raw wire text in `output`."""

    def _host(self, ip="10.0.0.5", port=4822) -> Host:
        return Host(ip=ip, ports=[Port(portid=port, service="guacd",
                                       state="open")])

    def test_exposed_stays_t1_without_leak(self):
        h = self._host()
        probes = {("10.0.0.5", 4822): {
            "reachable": True, "opcode": "args", "version": "1.5.0",
            "args_seen": ["VERSION_1_5_0"],
            "backends_ok": ["vnc", "rdp"], "backends_err": []}}
        fs = guacamole.findings([h], probes)
        exposed = [f for f in fs if f["kind"] == "guacd_exposed"][0]
        self.assertEqual(exposed["depth_tier"], "t1")
        self.assertNotIn("output", exposed)

    def test_exposed_promoted_to_t2_with_leak(self):
        leak = ("4.args,13.VERSION_1_5_0,8.hostname,4.port,"
                "6.domain,8.username,8.password;")
        h = self._host()
        probes = {("10.0.0.5", 4822): {
            "reachable": True, "opcode": "args", "version": "1.5.0",
            "args_seen": ["VERSION_1_5_0"],
            "backends_ok": ["vnc", "rdp"], "backends_err": [],
            "handshake_leak": leak}}
        fs = guacamole.findings([h], probes)
        exposed = [f for f in fs if f["kind"] == "guacd_exposed"][0]
        self.assertEqual(exposed["depth_tier"], "t2")
        # Raw server-side evidence surfaced in output.
        self.assertEqual(exposed["output"], leak)
        # T2 note appears in the detail so the operator sees WHY it upgraded.
        self.assertIn("T2 verify", exposed["detail"])

    def test_analyze_active_captures_leak_end_to_end(self):
        # Wire the leak all the way through analyze(): probe -> verify ->
        # findings emits guacd_exposed at t2 with the raw frame in output.
        rdp_frame = (b"4.args,13.VERSION_1_5_0,8.hostname,4.port,"
                     b"6.domain,8.username,8.password;")
        replies = {b: ARGS_FRAME_1_5_0 for b in guacamole._BACKENDS}
        replies["rdp"] = rdp_frame
        srv = _GuacdServer(replies)
        try:
            h = Host(ip=srv.host,
                     ports=[Port(portid=srv.port, service="guacd",
                                 state="open")])
            out = guacamole.analyze([h], active=True, budget=15.0)
        finally:
            srv.close()
        exposed = [f for f in out["findings"]
                   if f["kind"] == "guacd_exposed"][0]
        self.assertEqual(exposed["depth_tier"], "t2")
        self.assertIn("VERSION_1_5_0", exposed.get("output", ""))
        self.assertIn("password", exposed.get("output", ""))


if __name__ == "__main__":
    unittest.main()
