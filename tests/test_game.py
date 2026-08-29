"""Tests for recce.services.minecraft — the Minecraft Java Edition SLP probe
plus the Source-RCON companion check.

Wire fixtures are built here independently of the module's encoders so the
tests exercise the module's PARSING path rather than round-tripping through
its own emission code. VarInt bytes are constructed by an in-test helper that
implements the wire format straight off wiki.vg's Server List Ping spec.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import threading
import unittest
from dataclasses import dataclass

from recce.core.models import Host, Port
from recce.services import minecraft


# --- Independent wire encoders (do NOT call minecraft.* from here) ---------

def enc_varint(n: int) -> bytes:
    """VarInt encoding per wiki.vg Server List Ping."""
    if n < 0:
        n += 1 << 32
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out


def enc_string(s: str) -> bytes:
    body = s.encode("utf-8")
    return enc_varint(len(body)) + body


def enc_status_response(json_obj: dict) -> bytes:
    payload = json.dumps(json_obj).encode("utf-8")
    inner = enc_varint(0x00) + enc_varint(len(payload)) + payload   # packet id + string
    return enc_varint(len(inner)) + inner                            # outer frame


def make_png(w: int = 64, h: int = 64) -> bytes:
    """Minimal PNG bytes: signature + IHDR chunk (correct width/height fields).
    The rest of the file is padding so the base64 has realistic length."""
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
    tail = b"\x00" * 256
    return sig + ihdr + tail


def make_favicon_uri(png: bytes) -> str:
    return "data:image/png;base64," + base64.b64encode(png).decode("ascii")


# --- Sample SLP JSON blobs (wire-derived; version.name strings are copied
#     verbatim from real vanilla/Paper/Forge/BungeeCord SLP responses). ------

PAPER_1_16_5 = {
    "version": {"name": "Paper 1.16.5", "protocol": 754},
    "players": {
        "max": 40, "online": 2,
        "sample": [
            {"name": "alice", "id": "11111111-2222-3333-4444-555555555555"},
            {"name": "bob",   "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
        ],
    },
    "description": {
        "text": "§4CorpNet §rDev Realm — ",
        "extra": [{"text": "admin: ops@internal.corp.example"}],
    },
}

VANILLA_1_19_4 = {
    "version": {"name": "1.19.4", "protocol": 762},
    "players": {"max": 20, "online": 0, "sample": []},
    "description": "A Minecraft Server",
    "enforcesSecureChat": True,
    "previewsChat": False,
}

FORGE_1_12_2 = {
    "version": {"name": "Forge 1.12.2-14.23.5.2860", "protocol": 340},
    "players": {"max": 10, "online": 0, "sample": []},
    "description": "Modded fun",
    "modinfo": {
        "type": "FML",
        "modList": [
            {"modid": "minecraft",    "version": "1.12.2"},
            {"modid": "forge",        "version": "14.23.5.2860"},
            {"modid": "jei",          "version": "4.16.1.301"},
        ],
    },
}

BUNGEECORD = {
    "version": {"name": "BungeeCord 1.8.x-1.20.x", "protocol": 47},
    "players": {"max": 1000, "online": 3, "sample": []},
    "description": "§bBungee!",
}


# --- Loopback TCP server that plays a canned SLP response ------------------

@dataclass
class _CannedTCP:
    payload: bytes
    port: int
    sock: socket.socket
    thread: threading.Thread
    stop: threading.Event

    def close(self):
        self.stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def _start_canned_server(payload: bytes) -> _CannedTCP:
    """Accept one client, drain a handshake+request (best effort), send payload."""
    ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssock.bind(("127.0.0.1", 0))
    ssock.listen(4)
    _host, port = ssock.getsockname()
    stop = threading.Event()

    def _serve():
        ssock.settimeout(0.5)
        while not stop.is_set():
            try:
                cs, _addr = ssock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                cs.settimeout(1.0)
                try:
                    cs.recv(2048)
                except (socket.timeout, OSError):
                    pass
                try:
                    cs.sendall(payload)
                except OSError:
                    pass
            finally:
                try: cs.close()
                except OSError: pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return _CannedTCP(payload=payload, port=port, sock=ssock, thread=t, stop=stop)


# --- probe() / slp_probe() tests -------------------------------------------

class SlpProbeTest(unittest.TestCase):

    def _probe(self, obj):
        srv = _start_canned_server(enc_status_response(obj))
        try:
            return minecraft.slp_probe("127.0.0.1", srv.port, timeout=3.0)
        finally:
            srv.close()

    def test_paper_1_16_5_parsed_and_log4shell_range(self):
        pr = self._probe(PAPER_1_16_5)
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version_name"], "Paper 1.16.5")
        self.assertEqual(pr["protocol_number"], 754)
        self.assertEqual(pr["players_online"], 2)
        self.assertEqual(pr["players_max"], 40)
        # MOTD flattening strips § codes and joins nested extras
        self.assertIn("CorpNet", pr["motd_text"])
        self.assertIn("Dev Realm", pr["motd_text"])
        self.assertIn("ops@internal.corp.example", pr["motd_text"])
        # Player sample carries usernames + UUIDs
        names = [p["name"] for p in pr["players_sample"]]
        self.assertEqual(names, ["alice", "bob"])
        # No section-sign remains
        self.assertNotIn("§", pr["motd_text"])

    def test_vanilla_1_19_4_not_log4shell(self):
        # slp_probe does not classify; go through probe() (but with no RCON).
        srv = _start_canned_server(enc_status_response(VANILLA_1_19_4))
        try:
            pr = minecraft.probe("127.0.0.1", srv.port, timeout=3.0,
                                 check_rcon=False)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version_name"], "1.19.4")
        self.assertEqual(pr["java_edition_version"], "1.19.4")
        self.assertFalse(pr["log4shell_vulnerable"])
        self.assertTrue(pr.get("enforces_secure_chat"))
        self.assertFalse(pr.get("previews_chat"))

    def test_paper_log4shell_classification(self):
        srv = _start_canned_server(enc_status_response(PAPER_1_16_5))
        try:
            pr = minecraft.probe("127.0.0.1", srv.port, timeout=3.0,
                                 check_rcon=False)
        finally:
            srv.close()
        self.assertEqual(pr["java_edition_version"], "1.16.5")
        self.assertTrue(pr["log4shell_vulnerable"])

    def test_forge_modinfo_extracted(self):
        pr = self._probe(FORGE_1_12_2)
        mods = pr["forge_mods"]
        ids = sorted(m["id"] for m in mods)
        self.assertEqual(ids, ["forge", "jei", "minecraft"])
        # Version strings preserved on FML1
        by_id = {m["id"]: m["version"] for m in mods}
        self.assertEqual(by_id["jei"], "4.16.1.301")

    def test_bungeecord_detected_and_range_not_classified_as_vulnerable(self):
        srv = _start_canned_server(enc_status_response(BUNGEECORD))
        try:
            pr = minecraft.probe("127.0.0.1", srv.port, timeout=3.0,
                                 check_rcon=False)
        finally:
            srv.close()
        self.assertEqual(pr["proxy_kind"], "bungeecord")
        # Proxy range strings ("1.8.x-1.20.x") must NOT be single-pinned as
        # vulnerable — the punch list forbids unverified CVE flags.
        self.assertFalse(pr["log4shell_vulnerable"])
        self.assertEqual(pr["java_edition_version"], "")

    def test_favicon_hash_and_dimensions(self):
        png = make_png(w=64, h=64)
        expected_sha = hashlib.sha256(png).hexdigest()
        obj = dict(VANILLA_1_19_4)
        obj["favicon"] = make_favicon_uri(png)
        pr = self._probe(obj)
        self.assertEqual(pr["favicon_sha256"], expected_sha)
        self.assertEqual(pr["favicon_dims"], (64, 64))
        self.assertEqual(pr["favicon_bytes"], len(png))

    def test_favicon_malformed_returns_empty(self):
        obj = dict(VANILLA_1_19_4)
        obj["favicon"] = "not a data uri"
        pr = self._probe(obj)
        self.assertEqual(pr["favicon_sha256"], "")
        self.assertEqual(pr["favicon_bytes"], 0)
        self.assertIsNone(pr["favicon_dims"])

    def test_dead_port_unreachable(self):
        # 127.0.0.2:1 — reserved, never listening.
        pr = minecraft.slp_probe("127.0.0.1", 1, timeout=1.0)
        self.assertFalse(pr["reachable"])
        self.assertTrue(pr.get("error"))

    def test_frame_length_out_of_range(self):
        # An absurd length prefix (varint 0xFF FF FF FF 0x07 → very large int)
        # must be rejected without allocating.
        bad = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x07])
        srv = _start_canned_server(bad)
        try:
            pr = minecraft.slp_probe("127.0.0.1", srv.port, timeout=1.5)
        finally:
            srv.close()
        self.assertFalse(pr["reachable"])
        self.assertIn("frame length", pr.get("error", ""))


# --- RCON tests ------------------------------------------------------------

def _rcon_reply(request_id: int, ptype: int, payload: bytes = b"") -> bytes:
    body = struct.pack("<ii", request_id, ptype) + payload + b"\x00\x00"
    return struct.pack("<i", len(body)) + body


class _RconServer:
    """Loopback TCP responder for one RCON auth exchange."""

    def __init__(self, reply_maker):
        self._reply_maker = reply_maker
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        _h, self.port = self.sock.getsockname()
        self.stop = threading.Event()
        self.captured_rid: int | None = None
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        self.sock.settimeout(0.5)
        while not self.stop.is_set():
            try:
                cs, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                cs.settimeout(1.0)
                header = cs.recv(4)
                if len(header) == 4:
                    (size,) = struct.unpack("<i", header)
                    rest = cs.recv(max(0, size))
                    if len(rest) >= 8:
                        rid, _ptype = struct.unpack("<ii", rest[:8])
                        self.captured_rid = rid
                        cs.sendall(self._reply_maker(rid))
            except (socket.timeout, OSError):
                pass
            finally:
                try: cs.close()
                except OSError: pass

    def close(self):
        self.stop.set()
        try: self.sock.close()
        except OSError: pass


class RconProbeTest(unittest.TestCase):
    def test_empty_password_accepted_when_rid_echoes(self):
        srv = _RconServer(lambda rid: _rcon_reply(rid, 2))
        try:
            r = minecraft.rcon_probe("127.0.0.1", srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertTrue(r["speaks_rcon"])
        self.assertTrue(r["empty_password_accepted"])

    def test_empty_password_rejected_when_rid_minus_one(self):
        srv = _RconServer(lambda _rid: _rcon_reply(-1, 2))
        try:
            r = minecraft.rcon_probe("127.0.0.1", srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["speaks_rcon"])
        self.assertFalse(r["empty_password_accepted"])

    def test_no_rcon_service(self):
        r = minecraft.rcon_probe("127.0.0.1", 1, timeout=0.8)
        self.assertFalse(r["reachable"])


# --- findings() + analyze() tests -----------------------------------------

def _make_host_with_mc(port: int) -> Host:
    return Host(ip="10.0.0.5",
                ports=[Port(portid=port, protocol="tcp", state="open",
                            service="minecraft")])


def _fake_probe_result(**overrides) -> dict:
    base = {
        "reachable": True,
        "version_name": "Paper 1.16.5",
        "protocol_number": 754,
        "players_online": 2, "players_max": 40,
        "players_sample": [
            {"name": "alice", "id": "11111111-2222-3333-4444-555555555555"}],
        "motd_text": "Dev realm — jira.internal.corp.example",
        "motd_json": None,
        "favicon_sha256": "a" * 64,
        "favicon_bytes": 512, "favicon_dims": (64, 64),
        "forge_mods": [],
        "java_edition_version": "1.16.5",
        "log4shell_vulnerable": True,
        "proxy_kind": "",
    }
    base.update(overrides)
    return base


class FindingsTest(unittest.TestCase):
    def test_log4shell_and_roster_and_hostname_findings(self):
        h = _make_host_with_mc(25565)
        pr = _fake_probe_result()
        fs = minecraft.findings([h], {(h.ip, 25565): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("minecraft_log4shell", kinds)
        self.assertIn("minecraft_player_roster", kinds)
        self.assertIn("minecraft_motd_hostnames", kinds)
        self.assertIn("minecraft_fingerprint", kinds)
        # High severity for Log4Shell (per punch list).
        log4 = next(f for f in fs if f["kind"] == "minecraft_log4shell")
        self.assertEqual(log4["severity"], "high")
        self.assertIn("CVE-2021-44228", log4["title"])
        self.assertIn("CWE-502", log4["cwes"])
        # Player roster names must appear in detail
        roster = next(f for f in fs if f["kind"] == "minecraft_player_roster")
        self.assertIn("alice", roster["detail"])

    def test_no_log4shell_finding_when_version_recent(self):
        h = _make_host_with_mc(25565)
        pr = _fake_probe_result(version_name="1.19.4",
                                java_edition_version="1.19.4",
                                log4shell_vulnerable=False,
                                motd_text="A Minecraft Server",
                                players_sample=[])
        fs = minecraft.findings([h], {(h.ip, 25565): pr})
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("minecraft_log4shell", kinds)
        self.assertNotIn("minecraft_player_roster", kinds)
        # But the info-level fingerprint always fires.
        self.assertIn("minecraft_fingerprint", kinds)

    def test_rcon_findings_emitted_on_open_and_empty_password(self):
        h = _make_host_with_mc(25565)
        pr = _fake_probe_result(
            rcon={"reachable": True, "speaks_rcon": True,
                  "empty_password_accepted": True, "error": ""},
        )
        fs = minecraft.findings([h], {(h.ip, 25565): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("minecraft_rcon_open", kinds)

        pr2 = _fake_probe_result(
            rcon={"reachable": True, "speaks_rcon": True,
                  "empty_password_accepted": False, "error": ""},
        )
        fs2 = minecraft.findings([h], {(h.ip, 25565): pr2})
        kinds2 = {f["kind"] for f in fs2}
        self.assertIn("minecraft_rcon_exposed", kinds2)
        self.assertNotIn("minecraft_rcon_open", kinds2)

    def test_proxy_finding_when_bungeecord(self):
        h = _make_host_with_mc(25565)
        pr = _fake_probe_result(version_name="BungeeCord 1.8.x-1.20.x",
                                java_edition_version="",
                                log4shell_vulnerable=False,
                                proxy_kind="bungeecord")
        fs = minecraft.findings([h], {(h.ip, 25565): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("minecraft_proxy", kinds)
        self.assertNotIn("minecraft_log4shell", kinds)


class AnalyzeFanoutTest(unittest.TestCase):
    def test_fanout_appends_hostname_and_populates_port_product(self):
        h = _make_host_with_mc(25565)
        # Feed a canned SLP JSON via a loopback server so analyze() runs
        # the real probe() path end-to-end (no monkeypatch needed).
        obj = dict(PAPER_1_16_5)
        # Use FQDN token in MOTD so fanout has something to add.
        obj["description"] = "welcome — visit wiki.dev.corp.example"
        srv = _start_canned_server(enc_status_response(obj))
        try:
            # Point the Host at the loopback listener.
            h.ip = "127.0.0.1"
            h.ports[0].portid = srv.port
            result = minecraft.analyze([h], active=True, budget=5.0)
        finally:
            srv.close()

        # Hostname fanout happened (idempotent lower-case dedup)
        hostnames_lower = [n.lower() for n in h.hostnames]
        self.assertIn("wiki.dev.corp.example", hostnames_lower)
        added = result["fanout"]["hostnames_added"]
        self.assertTrue(any(n.lower() == "wiki.dev.corp.example"
                            for _ip, n in added))

        # Port product/version populated for the CVE mapper.
        p = h.ports[0]
        self.assertTrue(p.product.startswith("Minecraft "))
        self.assertEqual(p.version, "1.16.5")
        self.assertEqual(p.service, "minecraft")

        # Identities emitted for cross-service pivot.
        ids = result["fanout"]["identities"]
        names = sorted(x["username"] for x in ids)
        self.assertEqual(names, ["alice", "bob"])

    def test_analyze_no_targets_returns_empty(self):
        h = Host(ip="10.0.0.6",
                 ports=[Port(portid=22, protocol="tcp", state="open",
                             service="ssh")])
        result = minecraft.analyze([h], active=True, budget=2.0)
        self.assertEqual(result["targets"], [])
        self.assertEqual(result["findings"], [])


class ClassifierTest(unittest.TestCase):
    def test_java_version_parser_handles_common_prefixes(self):
        cases = {
            "Paper 1.16.5": "1.16.5",
            "Spigot 1.7.10": "1.7.10",
            "Forge 1.12.2-14.23.5.2860": "1.12.2",
            "1.19.4": "1.19.4",
            "BungeeCord 1.8.x-1.20.x": "",
            "": "",
            "SomeOtherServer": "",
        }
        for name, expected in cases.items():
            self.assertEqual(
                minecraft._parse_java_edition_version(name), expected,
                f"failed on {name!r}")

    def test_log4shell_range_edges(self):
        # 1.7.0 through 1.18.0 inclusive → vulnerable.
        # 1.18.1+ → not vulnerable.
        vuln, _ = minecraft._is_log4shell_vulnerable("Paper 1.18.0")
        self.assertTrue(vuln)
        vuln, _ = minecraft._is_log4shell_vulnerable("Paper 1.18.1")
        self.assertFalse(vuln)
        vuln, _ = minecraft._is_log4shell_vulnerable("Spigot 1.7.10")
        self.assertTrue(vuln)
        vuln, _ = minecraft._is_log4shell_vulnerable("1.19.4")
        self.assertFalse(vuln)


if __name__ == "__main__":
    unittest.main()
