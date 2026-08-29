"""Tests for recce.services.zabbix.

Wire-derived fixtures: the ZBXD header is a fixed 13-byte layout — 4-byte magic
'ZBXD', 1-byte flag (0x01 plaintext / 0x03 zlib), 8-byte little-endian body
length. The raw bytes in these tests were computed against that spec and are
asserted against `bytes.fromhex(...)` constants derived from the protocol doc,
NOT against the module's own encoder.
"""
from __future__ import annotations

import json
import socket
import socketserver
import struct
import threading
import unittest
import zlib

from recce.core.models import Host, Port
from recce.services import zabbix as z


def _wire(payload: bytes, flag: int = 0x01) -> bytes:
    return b"ZBXD" + bytes([flag]) + struct.pack("<Q", len(payload)) + payload


class _StopServer:
    def __init__(self, srv):
        self.srv = srv

    def __enter__(self):
        return self.srv

    def __exit__(self, *exc):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except OSError:
            pass


def _start(handler_cls):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler_cls)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _read_zbxd(sock: socket.socket) -> bytes:
    hdr = b""
    while len(hdr) < 13:
        c = sock.recv(13 - len(hdr))
        if not c:
            break
        hdr += c
    length = struct.unpack("<Q", hdr[5:13])[0]
    body = b""
    while len(body) < length:
        c = sock.recv(min(4096, length - len(body)))
        if not c:
            break
        body += c
    return body


def _agent_handler(responses: dict[str, bytes | None]):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            key = _read_zbxd(self.request).decode("utf-8", "replace")
            resp = responses.get(key, responses.get("*"))
            if resp is None:
                return
            self.request.sendall(_wire(resp))
    return H


def _trapper_handler(reply_fn):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            body = _read_zbxd(self.request)
            try:
                obj = json.loads(body.decode("utf-8", "replace"))
            except ValueError:
                return
            r = reply_fn(obj)
            if r is None:
                return
            self.request.sendall(_wire(json.dumps(r).encode("utf-8")))
    return H


class FrameTests(unittest.TestCase):
    """The wire format is exactly ZBXD + flag(1) + LE length(8) + body."""

    def test_frame_shape_matches_hex_fixture(self):
        # ZBXD magic + 0x01 plaintext flag + LE 8-byte body length + body.
        expected = (bytes.fromhex("5a425844")            # 'ZBXD'
                    + bytes.fromhex("01")                # flag 0x01 plaintext
                    + bytes.fromhex("0500000000000000")  # length 5, LE
                    + b"6.4.7")
        self.assertEqual(z._frame(b"6.4.7"), expected)

    def test_recv_frame_reads_plaintext_body(self):
        wire = (bytes.fromhex("5a425844")               # 'ZBXD'
                + bytes.fromhex("01")
                + bytes.fromhex("0300000000000000")     # length 3
                + b"6.4")

        class Fake:
            def __init__(self, buf): self.buf = buf
            def recv(self, n):
                out, self.buf = self.buf[:n], self.buf[n:]
                return out

        self.assertEqual(z._recv_frame(Fake(wire)), b"6.4")

    def test_recv_frame_reads_compressed_body(self):
        payload = b'{"response":"success"}'
        compressed = zlib.compress(payload)
        wire = (bytes.fromhex("5a425844")
                + bytes.fromhex("03")                   # flag 0x03 = compressed
                + struct.pack("<Q", len(compressed))
                + compressed)

        class Fake:
            def __init__(self, buf): self.buf = buf
            def recv(self, n):
                out, self.buf = self.buf[:n], self.buf[n:]
                return out

        self.assertEqual(z._recv_frame(Fake(wire)), payload)

    def test_recv_frame_rejects_bad_magic(self):
        wire = b"NOPE\x01" + struct.pack("<Q", 3) + b"6.4"

        class Fake:
            def __init__(self, buf): self.buf = buf
            def recv(self, n):
                out, self.buf = self.buf[:n], self.buf[n:]
                return out

        self.assertIsNone(z._recv_frame(Fake(wire)))

    def test_recv_frame_rejects_unknown_flag(self):
        wire = bytes.fromhex("5a425844") + bytes.fromhex("77") \
               + struct.pack("<Q", 1) + b"x"

        class Fake:
            def __init__(self, buf): self.buf = buf
            def recv(self, n):
                out, self.buf = self.buf[:n], self.buf[n:]
                return out

        self.assertIsNone(z._recv_frame(Fake(wire)))


class PredicateTests(unittest.TestCase):
    def test_agent_matches_port_10050(self):
        self.assertTrue(z.is_zabbix_agent(Port(portid=10050)))
        self.assertTrue(z.is_zabbix(Port(portid=10050)))

    def test_trapper_matches_port_10051(self):
        self.assertTrue(z.is_zabbix_trapper(Port(portid=10051)))
        self.assertTrue(z.is_zabbix(Port(portid=10051)))

    def test_service_name_labels_agent(self):
        self.assertTrue(z.is_zabbix_agent(
            Port(portid=15000, service="zabbix-agent")))

    def test_unrelated_port_is_not_zabbix(self):
        self.assertFalse(z.is_zabbix(Port(portid=22, service="ssh")))


class AgentGetTests(unittest.TestCase):
    def test_agent_get_notsupported_returns_none(self):
        srv = _start(_agent_handler({"vfs.file.contents[/nope]": b"ZBX_NOTSUPPORTED\x00No such file"}))
        with _StopServer(srv):
            r = z.agent_get("127.0.0.1", srv.server_address[1],
                            "vfs.file.contents[/nope]", timeout=2.0)
        self.assertIsNone(r)

    def test_agent_get_value_returned(self):
        srv = _start(_agent_handler({"agent.version": b"6.4.7"}))
        with _StopServer(srv):
            r = z.agent_get("127.0.0.1", srv.server_address[1],
                            "agent.version", timeout=2.0)
        self.assertEqual(r, "6.4.7")


class ProbeAgentTests(unittest.TestCase):
    def test_agent_fingerprint_captures_version_hostname_ping(self):
        srv = _start(_agent_handler({
            "agent.version": b"6.4.7",
            "agent.hostname": b"web01.corp.local",
            "agent.ping": b"1",
            "*": b"ZBX_NOTSUPPORTED\x00Item does not exist",
        }))
        with _StopServer(srv):
            pr = z.probe_agent("127.0.0.1", srv.server_address[1],
                               timeout=2.0, inventory=False, file_read=False)
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version"], "6.4.7")
        self.assertEqual(pr["hostname"], "web01.corp.local")
        self.assertEqual(pr["ping"], "1")

    def test_inventory_and_listener_parsing(self):
        listen_json = json.dumps([{"port": 22, "ip": "0.0.0.0"},
                                  {"port": 3306, "ip": "127.0.0.1"}]).encode()
        srv = _start(_agent_handler({
            "agent.version": b"6.0.20",
            "agent.hostname": b"db01",
            "agent.ping": b"1",
            "system.uname": b"Linux db01 5.15.0-generic x86_64",
            "system.users.num": b"2",
            "net.tcp.listen": listen_json,
            "*": None,
        }))
        with _StopServer(srv):
            pr = z.probe_agent("127.0.0.1", srv.server_address[1],
                               timeout=2.0, inventory=True, file_read=False)
        self.assertTrue(pr["reachable"])
        self.assertIn("system.uname", pr["inventory"])
        self.assertEqual(pr["inventory"]["system.users.num"], "2")
        self.assertEqual(sorted(pr["listeners"]), [22, 3306])

    def test_file_read_and_topology_parse(self):
        conf = (b"# example\n"
                b"Server=10.0.0.5, 10.0.0.6\n"
                b"ServerActive=zbx-proxy.corp:10051\n"
                b"Hostname=agent01\n")
        srv = _start(_agent_handler({
            "agent.version": b"6.4.7",
            "agent.hostname": b"agent01",
            "agent.ping": b"1",
            "vfs.file.contents[/etc/passwd]": b"root:x:0:0:root:/root:/bin/bash\n",
            "vfs.file.contents[/etc/zabbix/zabbix_agentd.conf]": conf,
            "*": None,
        }))
        with _StopServer(srv):
            pr = z.probe_agent("127.0.0.1", srv.server_address[1],
                               timeout=2.0, inventory=False, file_read=True)
        self.assertIn("/etc/passwd", pr["files"])
        self.assertIn("/etc/zabbix/zabbix_agentd.conf", pr["files"])
        self.assertEqual(sorted(pr["server_ips"]),
                         ["10.0.0.5", "10.0.0.6", "zbx-proxy.corp"])

    def test_rce_probe_disabled_when_exploit_false(self):
        seen: list[str] = []

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                key = _read_zbxd(self.request).decode("utf-8", "replace")
                seen.append(key)
                if key == "agent.version":
                    self.request.sendall(_wire(b"6.4.7"))
                else:
                    self.request.sendall(_wire(b"ZBX_NOTSUPPORTED\x00denied"))

        srv = _start(H)
        with _StopServer(srv):
            pr = z.probe_agent("127.0.0.1", srv.server_address[1],
                               timeout=2.0, inventory=False, file_read=False,
                               exploit=False)
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["remote_commands"])
        self.assertFalse(any(k.startswith("system.run[") for k in seen))

    def test_rce_probe_marker_detected(self):
        marker = "recce-run-check"

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                key = _read_zbxd(self.request).decode("utf-8", "replace")
                if key == "agent.version":
                    self.request.sendall(_wire(b"6.4.7"))
                elif key == f"system.run[echo {marker}]":
                    self.request.sendall(_wire(marker.encode() + b"\n"))
                elif key == "system.run[id]":
                    self.request.sendall(_wire(
                        b"uid=0(root) gid=0(root) groups=0(root)"))
                else:
                    self.request.sendall(_wire(b""))

        srv = _start(H)
        with _StopServer(srv):
            pr = z.probe_agent("127.0.0.1", srv.server_address[1],
                               timeout=2.0, inventory=False, file_read=False,
                               exploit=True)
        self.assertTrue(pr["remote_commands"])
        self.assertIn(marker, pr["rce_output"])
        self.assertIn("uid=0(root)", pr["run_as"])

    def test_dead_port_returns_unreachable(self):
        pr = z.probe_agent("127.0.0.1", 1, timeout=1.0)
        self.assertFalse(pr["reachable"])


class ProbeTrapperTests(unittest.TestCase):
    def test_trapper_fingerprint_extracts_version_and_role(self):
        srv = _start(_trapper_handler(lambda o: {
            "response": "failed",
            "info": ("host [recce-probe] not found (server 6.0.20 refused)"),
        }))
        with _StopServer(srv):
            pr = z.probe_trapper("127.0.0.1", srv.server_address[1],
                                 timeout=2.0)
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["response"], "failed")
        self.assertEqual(pr["role"], "server")
        self.assertEqual(pr["version"], "6.0.20")
        self.assertFalse(pr["tls_required"])

    def test_trapper_proxy_role(self):
        srv = _start(_trapper_handler(lambda o: {
            "response": "failed",
            "info": "proxy 6.4.7 does not know host [x]",
        }))
        with _StopServer(srv):
            pr = z.probe_trapper("127.0.0.1", srv.server_address[1],
                                 timeout=2.0)
        self.assertEqual(pr["role"], "proxy")

    def test_trapper_tls_required(self):
        srv = _start(_trapper_handler(lambda o: {
            "response": "failed",
            "info": "connection of type \"unencrypted\" is not allowed for TLS-required",
        }))
        with _StopServer(srv):
            pr = z.probe_trapper("127.0.0.1", srv.server_address[1],
                                 timeout=2.0)
        self.assertTrue(pr["tls_required"])

    def test_autoreg_accepted_when_exploit_true(self):
        def reply(o):
            if "host_metadata" in o:
                return {"response": "success",
                        "data": [{"key": "agent.ping", "delay": "60s"}]}
            return {"response": "failed",
                    "info": "host [recce-probe] not found"}
        srv = _start(_trapper_handler(reply))
        with _StopServer(srv):
            pr = z.probe_trapper("127.0.0.1", srv.server_address[1],
                                 timeout=2.0, exploit=True)
        self.assertTrue(pr["autoreg_accepted"])

    def test_autoreg_gated_off_when_exploit_false(self):
        seen: list[dict] = []

        def reply(o):
            seen.append(o)
            return {"response": "failed",
                    "info": "host [recce-probe] not found"}
        srv = _start(_trapper_handler(reply))
        with _StopServer(srv):
            pr = z.probe_trapper("127.0.0.1", srv.server_address[1],
                                 timeout=2.0, exploit=False)
        self.assertFalse(pr["autoreg_accepted"])
        self.assertTrue(all("host_metadata" not in o for o in seen))


class FindingsTests(unittest.TestCase):
    def test_full_agent_findings_shape(self):
        p = Port(portid=10050, state="open", service="zabbix-agent")
        h = Host(ip="10.0.0.10", ports=[p])
        pr = {
            "reachable": True, "version": "6.4.7", "hostname": "web01",
            "ping": "1", "inventory": {"system.uname": "Linux web01"},
            "files": {"/etc/passwd": "root:x:0:0::/root:/bin/bash",
                      "/etc/shadow": "root:$6$abc$hash:19000::::::",
                      "/etc/zabbix/zabbix_agentd.conf":
                          "Server=10.0.0.5\nServerActive=10.0.0.5:10051\n"},
            "server_ips": ["10.0.0.5"], "listeners": [22, 80],
            "tls_required": False, "remote_commands": True,
            "rce_output": "recce-run-check\n",
            "run_as": "uid=0(root)",
        }
        fs = z.findings([h], {("10.0.0.10", 10050): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("zabbix_agent_allowlist_bypass", kinds)
        self.assertIn("zabbix_agent_inventory_disclosure", kinds)
        self.assertIn("zabbix_agent_file_read", kinds)
        self.assertIn("zabbix_agent_rce", kinds)
        self.assertIn("zabbix_agent_topology_leak", kinds)
        self.assertIn("zabbix_plaintext", kinds)
        rce = [f for f in fs if f["kind"] == "zabbix_agent_rce"][0]
        self.assertEqual(rce["severity"], "critical")
        # /etc/shadow readable -> the file-read detail flags it explicitly.
        fr = [f for f in fs if f["kind"] == "zabbix_agent_file_read"][0]
        self.assertIn("shadow", fr["detail"].lower())

    def test_trapper_findings_include_autoreg_and_fingerprint(self):
        p = Port(portid=10051, state="open", service="zabbix-trapper")
        h = Host(ip="10.0.0.20", ports=[p])
        pr = {"reachable": True, "role": "server", "version": "6.0.20",
              "response": "success", "info": "host created",
              "tls_required": False, "autoreg_accepted": True}
        fs = z.findings([h], {("10.0.0.20", 10051): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("zabbix_autoreg_accepted", kinds)
        self.assertIn("zabbix_trapper_fingerprint", kinds)
        self.assertIn("zabbix_plaintext", kinds)
        crit = [f for f in fs if f["kind"] == "zabbix_autoreg_accepted"][0]
        self.assertEqual(crit["severity"], "critical")
        self.assertIn("CWE-89", crit["cwes"])

    def test_trapper_tls_required_suppresses_plaintext_finding(self):
        p = Port(portid=10051, state="open", service="zabbix-trapper")
        h = Host(ip="10.0.0.30", ports=[p])
        pr = {"reachable": True, "role": "server", "version": "",
              "response": "failed",
              "info": "connection of type unencrypted is not allowed",
              "tls_required": True, "autoreg_accepted": False}
        fs = z.findings([h], {("10.0.0.30", 10051): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("zabbix_trapper_tls_enforced", kinds)
        self.assertNotIn("zabbix_plaintext", kinds)
        self.assertNotIn("zabbix_autoreg_accepted", kinds)

    def test_unreachable_probe_produces_no_findings(self):
        p = Port(portid=10050, state="open", service="zabbix-agent")
        h = Host(ip="10.0.0.40", ports=[p])
        fs = z.findings([h], {("10.0.0.40", 10050): {"reachable": False}})
        self.assertEqual(fs, [])


class AnalyzeAndRunbookTests(unittest.TestCase):
    def test_analyze_end_to_end_with_agent_server(self):
        srv = _start(_agent_handler({
            "agent.version": b"6.4.7",
            "agent.hostname": b"e2e-host",
            "agent.ping": b"1",
            "*": None,
        }))
        port = srv.server_address[1]

        class DummyPort(Port):
            pass

        p = Port(portid=port, state="open", service="zabbix-agent")
        h = Host(ip="127.0.0.1", ports=[p])
        with _StopServer(srv):
            result = z.analyze([h], active=True, exploit=False, budget=10.0)
        self.assertEqual(len(result["targets"]), 1)
        self.assertTrue(result["targets"][0]["reachable"])
        self.assertGreaterEqual(result["stats"]["findings"], 1)
        self.assertTrue(result["runbooks"])

    def test_findings_to_vulns_bridges_to_vuln_model(self):
        fs = [{"severity": "critical", "title": "T", "target": "1.2.3.4:10050",
               "detail": "d", "tool": "zabbix_get", "command": "c",
               "remediation": "r", "cwes": ["CWE-78"],
               "kind": "zabbix_agent_rce", "narrative": ""}]
        v = z.findings_to_vulns(fs)
        self.assertIn("1.2.3.4", v)
        self.assertEqual(v["1.2.3.4"][0].severity, "critical")
        self.assertEqual(v["1.2.3.4"][0].port, 10050)

    def test_runbook_agent_and_trapper_differ(self):
        agent = z.runbook("1.2.3.4", 10050)
        trapper = z.runbook("1.2.3.4", 10051)
        self.assertTrue(any("zabbix_get" in s["cmd"] for s in agent))
        self.assertTrue(any("ZBXD" in s["cmd"] for s in trapper))

    def test_targets_split_by_role(self):
        pa = Port(portid=10050, state="open", service="zabbix-agent")
        pt = Port(portid=10051, state="open", service="zabbix-trapper")
        h = Host(ip="10.0.0.99", ports=[pa, pt])
        tgts = z.zabbix_targets([h])
        roles = sorted(t["role"] for t in tgts)
        self.assertEqual(roles, ["agent", "trapper"])


if __name__ == "__main__":
    unittest.main()
