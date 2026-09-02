"""T2 SAFE promotion for `minecraft_player_roster`: a single controlled
GameSpy Query (UDP) round-trip against a server whose operator left
`enable-query=true` in server.properties. Returns real server-side evidence
(full roster + plugin list + world name) beyond what SLP's sample field
carries, and does so read-only.

Coverage:
  * vulnerable  — query responder answers with a full-stat payload; probe
    captures `query_evidence` and the roster finding lifts to depth_tier=t2
    with a `T2 proof` block naming the extra players the SLP sample hid.
  * patched     — query responder silent (`enable-query=false`); probe leaves
    `query_evidence` absent, the roster finding stays at depth_tier=t1, and
    the base T1 detail is unchanged.
  * timeout     — handshake reply never arrives; probe returns cleanly, no
    evidence attached, no crash.
  * bounded     — `_t2_bounded_timeout` clamps to [2, 6] s then proxy-scales.

Fixtures are hand-rolled straight off the GameSpy Query spec (fenix.mojang.com
"Query" / the original Gamespy4 write-up) — building the reply here rather
than calling minecraft.query_probe's encoder ensures a decoder bug is not
masked by a symmetric encoder bug in the fixture.
"""
from __future__ import annotations

import socket
import struct
import threading
import time
import unittest

from recce.core.models import Host, Port
from recce.services import minecraft


# --- Independent GameSpy Query wire helpers --------------------------------

_MAGIC = b"\xfe\xfd"
_TYPE_HANDSHAKE = 0x09
_TYPE_STAT = 0x00


def _handshake_reply(session_id: int, token: int) -> bytes:
    """0x09 + session_id (BE i32) + null-terminated ASCII decimal token."""
    return (struct.pack(">Bi", _TYPE_HANDSHAKE, session_id)
            + str(token).encode("ascii") + b"\x00")


def _full_stat_reply(session_id: int, kv: dict, players: list) -> bytes:
    """0x00 + session_id + 11-byte splitnum preamble + k\\0v\\0… +
    \\x00\\x01player_\\x00\\x00 + name\\0…\\x00\\x00."""
    preamble = b"splitnum\x00\x80\x00"                    # 11 bytes total
    kv_blob = b""
    for k, v in kv.items():
        kv_blob += k.encode("utf-8") + b"\x00" + v.encode("utf-8") + b"\x00"
    marker = b"\x00\x01player_\x00\x00"
    players_blob = b"".join(p.encode("utf-8") + b"\x00" for p in players) + b"\x00"
    return (struct.pack(">Bi", _TYPE_STAT, session_id)
            + preamble + kv_blob + marker + players_blob)


class _QueryResponder(threading.Thread):
    """UDP responder that plays a canned two-packet Query exchange.

    Options:
      * `silent_handshake` — never reply to the handshake (client times out).
      * `silent_stat`      — reply to handshake, drop the full-stat request.
      * `wrong_sid`        — reply to handshake with a garbled session id
        (verifies the probe's session-id validation).
    """
    daemon = True

    def __init__(self, kv: dict, players: list, *,
                 silent_handshake: bool = False, silent_stat: bool = False,
                 wrong_sid: bool = False):
        super().__init__()
        self.kv = kv
        self.players = players
        self.silent_handshake = silent_handshake
        self.silent_stat = silent_stat
        self.wrong_sid = wrong_sid
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(3.0)
        _h, self.port = self.sock.getsockname()
        self._stop = False
        self.token = 9513307

    def run(self) -> None:
        end = time.time() + 5.0
        while not self._stop and time.time() < end:
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            if len(data) < 7 or not data.startswith(_MAGIC):
                continue
            ptype = data[2]
            sid = struct.unpack(">i", data[3:7])[0]
            if ptype == _TYPE_HANDSHAKE:
                if self.silent_handshake:
                    continue
                # XOR into a different session id, then mask to signed int32.
                mangled = (sid ^ 0x5A5A5A5A) & 0xFFFFFFFF
                if mangled & 0x80000000:
                    mangled -= 0x100000000
                reply_sid = mangled if self.wrong_sid else sid
                self.sock.sendto(_handshake_reply(reply_sid, self.token), addr)
            elif ptype == _TYPE_STAT:
                if self.silent_stat:
                    continue
                # Optional: verify challenge token matches; we don't gate on it
                # so a malformed request is still visible to the probe as a
                # replied full-stat (matches how mc-server behaves in practice).
                self.sock.sendto(
                    _full_stat_reply(sid, self.kv, self.players), addr)

    def stop(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def _start(**kw) -> _QueryResponder:
    r = _QueryResponder(
        kv=kw.pop("kv", {"hostname": "A Minecraft Server", "version": "1.20.4",
                         "plugins": "Paper on 1.20.4: WorldEdit 7.2.15; "
                                    "LuckPerms 5.4.108",
                         "map": "world", "numplayers": "3", "maxplayers": "40"}),
        players=kw.pop("players", ["alice", "bob", "carol"]),
        **kw)
    r.start()
    time.sleep(0.05)
    return r


# --- query_probe() ---------------------------------------------------------

class QueryProbeTest(unittest.TestCase):
    def test_vulnerable_full_stat_captured(self):
        r = _start()
        try:
            q = minecraft.query_probe("127.0.0.1", r.port, timeout=2.0)
        finally:
            r.stop()
        self.assertTrue(q["reachable"])
        self.assertEqual(q["players"], ["alice", "bob", "carol"])
        self.assertEqual(q["world"], "world")
        self.assertIn("WorldEdit", q["plugins"])
        self.assertEqual(q["numplayers"], "3")
        self.assertEqual(q["hostname"], "A Minecraft Server")

    def test_patched_silent_handshake_yields_error_not_crash(self):
        r = _start(silent_handshake=True)
        try:
            q = minecraft.query_probe("127.0.0.1", r.port, timeout=2.0)
        finally:
            r.stop()
        self.assertFalse(q["reachable"])
        self.assertTrue(q.get("error"))

    def test_timeout_between_handshake_and_stat(self):
        """Handshake answers, full-stat is dropped — recvfrom times out."""
        r = _start(silent_stat=True)
        try:
            q = minecraft.query_probe("127.0.0.1", r.port, timeout=2.0)
        finally:
            r.stop()
        self.assertFalse(q["reachable"])
        self.assertTrue(q.get("error"))

    def test_wrong_session_id_rejected(self):
        r = _start(wrong_sid=True)
        try:
            q = minecraft.query_probe("127.0.0.1", r.port, timeout=2.0)
        finally:
            r.stop()
        self.assertFalse(q["reachable"])
        self.assertIn("session-id", q.get("error", ""))

    def test_dead_port_unreachable(self):
        """Nothing bound — recvfrom must fail cleanly, not raise."""
        q = minecraft.query_probe("127.0.0.1", 1, timeout=2.0)
        self.assertFalse(q["reachable"])
        self.assertTrue(q.get("error"))


# --- findings() promotion --------------------------------------------------

def _base_pr(**overrides) -> dict:
    base = {
        "reachable": True,
        "version_name": "Paper 1.20.4",
        "protocol_number": 765,
        "players_online": 3, "players_max": 40,
        "players_sample": [
            {"name": "alice", "id": "11111111-2222-3333-4444-555555555555"},
            {"name": "bob",   "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
        ],
        "motd_text": "welcome",
        "motd_json": None,
        "favicon_sha256": "", "favicon_bytes": 0, "favicon_dims": None,
        "forge_mods": [],
        "java_edition_version": "1.20.4",
        "log4shell_vulnerable": False,
        "proxy_kind": "",
    }
    base.update(overrides)
    return base


def _mc_host() -> Host:
    return Host(ip="10.0.0.5",
                ports=[Port(portid=25565, protocol="tcp", state="open",
                            service="minecraft")])


class FindingsPromotionTest(unittest.TestCase):
    def test_roster_promotes_to_t2_when_query_evidence_present(self):
        h = _mc_host()
        pr = _base_pr(query_evidence={
            "reachable": True, "error": "",
            "hostname": "A Minecraft Server",
            "version": "1.20.4",
            "plugins": "Paper on 1.20.4: WorldEdit; EssentialsX",
            "world": "world_the_end",
            "players": ["alice", "bob", "carol", "dave"],
            "numplayers": "4", "maxplayers": "40", "raw_kv": {}})
        fs = minecraft.findings([h], {(h.ip, 25565): pr})
        f = next(f for f in fs if f["kind"] == "minecraft_player_roster")
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("T2 proof", f["detail"])
        # extra players (carol, dave) surface in the T2 proof block
        self.assertIn("carol", f["detail"])
        self.assertIn("dave", f["detail"])
        # world + plugin evidence surfaces too
        self.assertIn("world_the_end", f["detail"])
        self.assertIn("WorldEdit", f["detail"])

    def test_roster_stays_t1_without_query_evidence(self):
        h = _mc_host()
        pr = _base_pr()                                  # no query_evidence
        fs = minecraft.findings([h], {(h.ip, 25565): pr})
        f = next(f for f in fs if f["kind"] == "minecraft_player_roster")
        self.assertEqual(f["depth_tier"], "t1")
        self.assertNotIn("T2 proof", f["detail"])

    def test_query_unreachable_does_not_promote(self):
        h = _mc_host()
        pr = _base_pr(query_evidence={
            "reachable": False, "error": "handshake reply malformed",
            "hostname": "", "players": [], "raw_kv": {}})
        fs = minecraft.findings([h], {(h.ip, 25565): pr})
        f = next(f for f in fs if f["kind"] == "minecraft_player_roster")
        self.assertEqual(f["depth_tier"], "t1")
        self.assertNotIn("T2 proof", f["detail"])

    def test_no_roster_no_query_no_finding(self):
        """T1 semantics unchanged: empty sample = no roster finding, and
        query_evidence on its own does not synthesise one."""
        h = _mc_host()
        pr = _base_pr(players_sample=[], query_evidence={
            "reachable": True, "players": ["ghost"], "raw_kv": {}})
        fs = minecraft.findings([h], {(h.ip, 25565): pr})
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("minecraft_player_roster", kinds)


# --- probe() wiring: guard is on non-empty roster --------------------------

class ProbeWiringTest(unittest.TestCase):
    def test_probe_attaches_query_evidence_when_sample_present(self):
        """Full end-to-end: canned SLP TCP server + live UDP query responder.
        probe() must chain both single-shot reads and attach query_evidence."""
        # Import the SLP TCP-canned helpers already used by test_game.py; they
        # aren't a public API so we inline the tiny bits we need.
        import json as _json

        def _varint(n: int) -> bytes:
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

        slp_json = _json.dumps({
            "version": {"name": "Paper 1.20.4", "protocol": 765},
            "players": {"max": 40, "online": 2,
                        "sample": [{"name": "alice",
                                    "id": "11111111-2222-3333-4444-555555555555"}]},
            "description": "A Minecraft Server",
        }).encode("utf-8")
        inner = _varint(0x00) + _varint(len(slp_json)) + slp_json
        payload = _varint(len(inner)) + inner

        ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ss.bind(("127.0.0.1", 0))
        ss.listen(4)
        _h, tcp_port = ss.getsockname()
        stop = threading.Event()

        def _serve_tcp():
            ss.settimeout(0.5)
            while not stop.is_set():
                try:
                    cs, _ = ss.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    cs.settimeout(1.0)
                    try: cs.recv(2048)
                    except (socket.timeout, OSError): pass
                    try: cs.sendall(payload)
                    except OSError: pass
                finally:
                    try: cs.close()
                    except OSError: pass

        # Match the query responder to the same TCP port — real MC does too.
        udp = _QueryResponder(kv={"hostname": "A Minecraft Server",
                                  "version": "1.20.4", "plugins": "",
                                  "map": "world", "numplayers": "2",
                                  "maxplayers": "40"},
                              players=["alice", "shadowbanned_admin"])
        # Rebind UDP responder to the SAME port as TCP so probe(ip, tcp_port)
        # hits both. Close the auto-assigned socket first.
        udp.sock.close()
        udp.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.sock.bind(("127.0.0.1", tcp_port))
        except OSError:
            # If SO_REUSEADDR isn't in effect the bind can collide; skip in that
            # case — the finding-level tests above already prove the promotion.
            udp.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.sock.bind(("127.0.0.1", 0))
            _h, udp.port = udp.sock.getsockname()
            self.skipTest("could not co-bind UDP on the SLP TCP port")
        udp.port = tcp_port
        udp.sock.settimeout(3.0)

        t = threading.Thread(target=_serve_tcp, daemon=True)
        t.start()
        udp.start()
        try:
            pr = minecraft.probe("127.0.0.1", tcp_port, timeout=3.0,
                                 check_rcon=False)
        finally:
            stop.set()
            udp.stop()
            try: ss.close()
            except OSError: pass

        self.assertTrue(pr["reachable"])
        q = pr.get("query_evidence")
        self.assertIsNotNone(q, "query_evidence should be attached when the "
                                "roster sample is non-empty and the server "
                                "answers query")
        self.assertTrue(q["reachable"])
        self.assertIn("shadowbanned_admin", q["players"])

    def test_probe_skips_query_when_sample_empty(self, ):
        """Empty SLP sample — probe() must NOT open the UDP socket at all,
        preserving the T1-only latency footprint for hidden-roster servers."""
        called = {"n": 0}
        real_query = minecraft.query_probe

        def _spy(*a, **kw):
            called["n"] += 1
            return real_query(*a, **kw)

        # Build a stub slp_probe that reports reachable with an empty sample,
        # and monkeypatch query_probe to count invocations.
        import unittest.mock as mock
        with mock.patch.object(minecraft, "slp_probe",
                               return_value={"reachable": True,
                                             "version_name": "1.20.4",
                                             "protocol_number": 765,
                                             "players_online": 0,
                                             "players_max": 20,
                                             "players_sample": [],
                                             "motd_text": "", "motd_json": None,
                                             "favicon_sha256": "",
                                             "favicon_bytes": 0,
                                             "favicon_dims": None,
                                             "forge_mods": [],
                                             "raw_json_len": 42}), \
             mock.patch.object(minecraft, "query_probe", side_effect=_spy):
            pr = minecraft.probe("127.0.0.1", 25565, timeout=1.0,
                                 check_rcon=False)
        self.assertTrue(pr["reachable"])
        self.assertNotIn("query_evidence", pr)
        self.assertEqual(called["n"], 0)


# --- bounded timeout contract ---------------------------------------------

class BoundedTimeoutTest(unittest.TestCase):
    def test_t2_bounded_timeout_clamps_and_scales(self):
        import unittest.mock as mock
        with mock.patch.object(minecraft.proxy, "scaled", lambda s: s):
            self.assertEqual(minecraft._t2_bounded_timeout(0.5), 2.0)   # up
            self.assertEqual(minecraft._t2_bounded_timeout(10.0), 6.0)  # down
            self.assertEqual(minecraft._t2_bounded_timeout(3.0), 3.0)
        with mock.patch.object(minecraft.proxy, "scaled", lambda s: s * 2.5):
            self.assertEqual(minecraft._t2_bounded_timeout(3.0), 7.5)


if __name__ == "__main__":
    unittest.main()
