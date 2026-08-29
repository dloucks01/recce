"""Tests for recce.services.bgp — BGP OPEN probe.

Every fixture is either raw hex from the RFC 4271 wire format or built
with struct against the exact byte layout — never routed through
bgp._build_open, so the parser cannot rubber-stamp its own encoder.
Sockets are faked entirely via a threaded loopback server.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import bgp


_MARKER = b"\xff" * 16


def _frame(msg_type: int, body: bytes) -> bytes:
    total = 19 + len(body)
    return _MARKER + struct.pack(">HB", total, msg_type) + body


def _build_open_wire(version: int, my_as: int, hold_time: int,
                     router_id_ip: str, capabilities: bytes = b"") -> bytes:
    """Assemble a BGP OPEN by hand — do NOT delegate to bgp._build_open."""
    if capabilities:
        opt = struct.pack(">BB", 2, len(capabilities)) + capabilities
    else:
        opt = b""
    rid = struct.unpack(">I", socket.inet_aton(router_id_ip))[0]
    body = (struct.pack(">BHHIB", version, my_as, hold_time, rid, len(opt))
            + opt)
    return _frame(1, body)


def _cap_triple(code: int, value: bytes) -> bytes:
    return struct.pack(">BB", code, len(value)) + value


def _build_notification_wire(code: int, subcode: int,
                             data: bytes = b"") -> bytes:
    return _frame(3, struct.pack(">BB", code, subcode) + data)


class _BgpServer:
    """Threaded loopback TCP server. Handler gets the raw first-read bytes
    and returns response bytes (may be b'' to send nothing)."""

    def __init__(self, handler):
        self._handler = handler
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.host, self.port = self._srv.getsockname()
        self.received: list[bytes] = []
        self._stop = False
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(1.0)
                try:
                    data = conn.recv(4096)
                except (socket.timeout, OSError):
                    data = b""
                if data:
                    self.received.append(data)
                    resp = self._handler(data)
                    if resp:
                        try:
                            conn.sendall(resp)
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


class HeaderTest(unittest.TestCase):
    def test_marker_check_rejects_wrong_marker(self):
        bad = b"\x00" * 16 + struct.pack(">HB", 19, 4)
        self.assertIsNone(bgp._parse_header(bad))

    def test_short_frame(self):
        self.assertIsNone(bgp._parse_header(b"\xff" * 5))

    def test_valid_header(self):
        hdr = bgp._parse_header(_MARKER + struct.pack(">HB", 19, 4))
        self.assertEqual(hdr, {"length": 19, "type": 4})

    def test_rejects_bad_length(self):
        self.assertIsNone(bgp._parse_header(_MARKER + struct.pack(">HB", 5, 1)))
        self.assertIsNone(bgp._parse_header(_MARKER + struct.pack(">HB", 9999, 1)))

    def test_rejects_unknown_type(self):
        self.assertIsNone(bgp._parse_header(_MARKER + struct.pack(">HB", 19, 9)))


class OpenParseTest(unittest.TestCase):
    def test_parse_basic_open(self):
        wire = _build_open_wire(4, 65000, 180, "10.1.2.3")
        body = wire[19:]
        op = bgp._parse_open(body)
        self.assertIsNotNone(op)
        self.assertEqual(op["version"], 4)
        self.assertEqual(op["asn"], 65000)
        self.assertEqual(op["asn2"], 65000)
        self.assertEqual(op["hold_time"], 180)
        self.assertEqual(op["router_id"], "10.1.2.3")
        self.assertEqual(op["capabilities"], [])
        self.assertFalse(op["has_4byte_as"])

    def test_parse_open_with_4byte_as(self):
        # 4-octet AS capability (65) with a 32-bit AS value.
        caps = _cap_triple(65, struct.pack(">I", 4200000001))
        wire = _build_open_wire(4, 23456, 90, "192.0.2.9", caps)
        op = bgp._parse_open(wire[19:])
        self.assertTrue(op["has_4byte_as"])
        self.assertEqual(op["asn"], 4200000001)
        self.assertEqual(op["asn2"], 23456)

    def test_parse_open_with_mp_bgp_and_gr(self):
        mp_v4 = _cap_triple(1, struct.pack(">HBB", 1, 0, 1))          # IPv4 unicast
        mp_evpn = _cap_triple(1, struct.pack(">HBB", 25, 0, 70))      # L2VPN EVPN
        rr = _cap_triple(2, b"")
        # GR: flags=0x8 (restart state) | time=120s; then per-AFI IPv4/unicast, flags=0x80
        gr_hdr = struct.pack(">H", (0x8 << 12) | 120)
        gr_af = struct.pack(">HBB", 1, 1, 0x80)
        gr = _cap_triple(64, gr_hdr + gr_af)
        caps = mp_v4 + mp_evpn + rr + gr
        wire = _build_open_wire(4, 65001, 180, "203.0.113.5", caps)
        op = bgp._parse_open(wire[19:])
        self.assertTrue(op["has_route_refresh"])
        afi_pairs = [(a["afi"], a["safi"]) for a in op["afi_safis"]]
        self.assertIn((1, 1), afi_pairs)
        self.assertIn((25, 70), afi_pairs)
        gr = op["graceful_restart"]
        self.assertTrue(gr["restart_state"])
        self.assertEqual(gr["restart_time"], 120)
        self.assertEqual(gr["address_families"][0]["afi"], 1)
        self.assertTrue(gr["address_families"][0]["forwarding_preserved"])

    def test_truncated_open_returns_none(self):
        self.assertIsNone(bgp._parse_open(b"\x04\x00"))

    def test_truncated_opt_params(self):
        # opt_parm_len says 20 bytes follow, but the buffer holds fewer.
        body = struct.pack(">BHHIB", 4, 65000, 180,
                           struct.unpack(">I", socket.inet_aton("1.1.1.1"))[0],
                           20) + b"\x02\x02"
        self.assertIsNone(bgp._parse_open(body))


class NotificationParseTest(unittest.TestCase):
    def test_bad_peer_as_4byte(self):
        data = struct.pack(">I", 65500)
        wire = _build_notification_wire(2, 2, data)
        n = bgp._parse_notification(wire[19:])
        self.assertEqual(n["code"], 2)
        self.assertEqual(n["subcode"], 2)
        self.assertEqual(n["code_name"], "OPEN Message Error")
        self.assertEqual(n["subcode_name"], "Bad Peer AS")
        self.assertIn("expected AS = 65500", n["disclosed"])

    def test_bad_peer_as_2byte(self):
        data = struct.pack(">H", 65000)
        n = bgp._parse_notification(struct.pack(">BB", 2, 2) + data)
        self.assertIn("expected AS = 65000", n["disclosed"])

    def test_bad_bgp_identifier(self):
        data = struct.pack(">I",
                           struct.unpack(">I", socket.inet_aton("10.0.0.1"))[0])
        n = bgp._parse_notification(struct.pack(">BB", 2, 3) + data)
        self.assertIn("10.0.0.1", n["disclosed"])
        self.assertEqual(n["subcode_name"], "Bad BGP Identifier")

    def test_unsupported_version(self):
        data = struct.pack(">H", 4)
        n = bgp._parse_notification(struct.pack(">BB", 2, 1) + data)
        self.assertIn("peer max version = 4", n["disclosed"])
        self.assertEqual(n["subcode_name"], "Unsupported Version Number")

    def test_cease_subcode_names(self):
        n = bgp._parse_notification(struct.pack(">BB", 6, 2))
        self.assertEqual(n["code_name"], "Cease")
        self.assertEqual(n["subcode_name"], "Administrative Shutdown")

    def test_truncated_notification(self):
        self.assertIsNone(bgp._parse_notification(b"\x02"))


class CapabilityParseTest(unittest.TestCase):
    def test_ignores_unknown_optional_parameter_types(self):
        # Optional Parameter type 99 (not capabilities) — should be skipped.
        params = struct.pack(">BB", 99, 4) + b"\x00\x00\x00\x00"
        caps = bgp._parse_capabilities(params)
        self.assertEqual(caps, [])

    def test_parses_multiple_capabilities_in_one_parameter(self):
        inner = _cap_triple(2, b"") + _cap_triple(65, struct.pack(">I", 12345))
        params = struct.pack(">BB", 2, len(inner)) + inner
        caps = bgp._parse_capabilities(params)
        self.assertEqual([c["code"] for c in caps], [2, 65])
        self.assertEqual(caps[1]["value"], struct.pack(">I", 12345))

    def test_truncated_inner_capability_stops_parsing(self):
        # Declares clen=8 but only 2 bytes remain.
        inner = struct.pack(">BB", 65, 8) + b"\x00\x00"
        params = struct.pack(">BB", 2, len(inner)) + inner
        caps = bgp._parse_capabilities(params)
        self.assertEqual(caps, [])


class MpBgpAndGrParseTest(unittest.TestCase):
    def test_mp_bgp_evpn(self):
        got = bgp._parse_mp_bgp(struct.pack(">HBB", 25, 0, 70))
        self.assertEqual(got, (25, 70, "L2VPN", "EVPN"))

    def test_mp_bgp_short(self):
        self.assertIsNone(bgp._parse_mp_bgp(b"\x00"))

    def test_gr_no_families(self):
        gr = bgp._parse_graceful_restart(struct.pack(">H", 60))
        self.assertEqual(gr["restart_time"], 60)
        self.assertFalse(gr["restart_state"])
        self.assertEqual(gr["address_families"], [])


class OpenBuilderTest(unittest.TestCase):
    def test_build_open_round_trips_through_parser(self):
        # The BUILDER is an implementation detail we DO test, since probe()
        # depends on it — but the wire OPENs the parser eats come from
        # hand-built bytes in the other tests.
        wire = bgp._build_open(65001, hold_time=180, router_id="192.0.2.1")
        hdr = bgp._parse_header(wire[:19])
        self.assertEqual(hdr["type"], 1)
        op = bgp._parse_open(wire[19:hdr["length"]])
        self.assertEqual(op["version"], 4)
        self.assertEqual(op["asn"], 65001)          # 4-byte-AS capability wins
        self.assertEqual(op["hold_time"], 180)
        self.assertEqual(op["router_id"], "192.0.2.1")
        self.assertTrue(op["has_route_refresh"])
        self.assertTrue(op["has_4byte_as"])

    def test_build_open_large_as_uses_as_trans_in_2byte_field(self):
        wire = bgp._build_open(4200000001, hold_time=90,
                               router_id="192.0.2.1")
        op = bgp._parse_open(wire[19:])
        self.assertEqual(op["asn2"], 23456)         # AS_TRANS
        self.assertEqual(op["asn"], 4200000001)


class ProbeIntegrationTest(unittest.TestCase):
    """Live loopback socket exchanges — no external network."""

    def test_probe_reads_real_peer_open(self):
        caps = (_cap_triple(1, struct.pack(">HBB", 1, 0, 1))
                + _cap_triple(2, b"")
                + _cap_triple(65, struct.pack(">I", 65123)))
        peer_open = _build_open_wire(4, 23456, 90, "10.9.9.9", caps)

        srv = _BgpServer(lambda _req: peer_open)
        try:
            r = bgp._single_open(srv.host, srv.port, my_as=65001, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["tcp_ok"])
        self.assertEqual(r["peer_reply_kind"], "open")
        self.assertEqual(r["open"]["asn"], 65123)
        self.assertEqual(r["open"]["router_id"], "10.9.9.9")

    def test_probe_reads_notification(self):
        notif = _build_notification_wire(2, 2, struct.pack(">I", 65500))
        srv = _BgpServer(lambda _req: notif)
        try:
            r = bgp._single_open(srv.host, srv.port, my_as=65001, timeout=2.0)
        finally:
            srv.close()
        self.assertEqual(r["peer_reply_kind"], "notification")
        self.assertEqual(r["notification"]["code"], 2)
        self.assertEqual(r["notification"]["subcode"], 2)

    def test_probe_silent_peer(self):
        # Handler returns nothing — client should see silent/RST.
        srv = _BgpServer(lambda _req: b"")
        try:
            r = bgp._single_open(srv.host, srv.port, my_as=65001, timeout=1.0)
        finally:
            srv.close()
        self.assertTrue(r["tcp_ok"])
        self.assertIn(r["peer_reply_kind"], ("silent", "other"))

    def test_probe_dead_port(self):
        r = bgp._single_open("127.0.0.1", 1, my_as=65001, timeout=0.5)
        self.assertFalse(r["tcp_ok"])
        self.assertEqual(r["peer_reply_kind"], "")


class HighLevelProbeTest(unittest.TestCase):
    """The high-level probe() orchestrates _single_open + as_enumerate +
    version_probe — verified with the low-level substituted out."""

    def setUp(self):
        self._orig = bgp._single_open

    def tearDown(self):
        bgp._single_open = self._orig

    def test_probe_extracts_expected_as_from_first_notification(self):
        n_body = struct.pack(">BB", 2, 2) + struct.pack(">I", 65500)

        def fake(ip, port, my_as, timeout, hold_time=180,
                 router_id="192.0.2.1", version=4):
            return {"tcp_ok": True, "wrote_open": True,
                    "peer_reply_kind": "notification",
                    "header": {"length": 19 + len(n_body), "type": 3},
                    "open": None,
                    "notification": bgp._parse_notification(n_body),
                    "peer_rst": False, "error": ""}
        bgp._single_open = fake

        r = bgp.probe("10.0.0.1", 179, timeout=1.0)
        self.assertTrue(r["reachable"])
        self.assertEqual(r["expected_as"], 65500)
        self.assertEqual(r["expected_as_my_as"], 65001)

    def test_probe_reads_peer_open_and_then_extracts_version(self):
        peer_open = _build_open_wire(4, 65200, 90, "10.0.0.9")
        version_notif = struct.pack(">BB", 2, 1) + struct.pack(">H", 4)

        def fake(ip, port, my_as, timeout, hold_time=180,
                 router_id="192.0.2.1", version=4):
            if version == 5:
                return {"tcp_ok": True, "wrote_open": True,
                        "peer_reply_kind": "notification", "header": None,
                        "open": None,
                        "notification": bgp._parse_notification(version_notif),
                        "peer_rst": False, "error": ""}
            return {"tcp_ok": True, "wrote_open": True,
                    "peer_reply_kind": "open",
                    "header": {"length": len(peer_open), "type": 1},
                    "open": bgp._parse_open(peer_open[19:]),
                    "notification": None, "peer_rst": False, "error": ""}
        bgp._single_open = fake

        r = bgp.probe("10.0.0.1", 179, timeout=1.0)
        self.assertTrue(r["reachable"])
        self.assertEqual(r["open"]["asn"], 65200)
        self.assertEqual(r["peer_max_version"], 4)

    def test_probe_md5_hint_on_silent_peer(self):
        def fake(ip, port, my_as, timeout, hold_time=180,
                 router_id="192.0.2.1", version=4):
            return {"tcp_ok": True, "wrote_open": True,
                    "peer_reply_kind": "silent", "header": None,
                    "open": None, "notification": None,
                    "peer_rst": True, "error": ""}
        bgp._single_open = fake
        r = bgp.probe("10.0.0.1", 179, timeout=1.0)
        self.assertFalse(r["reachable"])
        self.assertTrue(r["md5_hint"])

    def test_as_enumerate_stops_on_first_bad_peer_as(self):
        n_body = struct.pack(">BB", 2, 2) + struct.pack(">I", 65432)
        calls = []

        def fake(ip, port, my_as, timeout, hold_time=180,
                 router_id="192.0.2.1", version=4):
            calls.append(my_as)
            if my_as == 64512:
                return {"tcp_ok": True, "wrote_open": True,
                        "peer_reply_kind": "notification", "header": None,
                        "open": None,
                        "notification": bgp._parse_notification(n_body),
                        "peer_rst": False, "error": ""}
            return {"tcp_ok": True, "wrote_open": True,
                    "peer_reply_kind": "silent", "header": None,
                    "open": None, "notification": None,
                    "peer_rst": False, "error": ""}
        bgp._single_open = fake
        r = bgp.as_enumerate("10.0.0.1", 179, timeout=1.0)
        self.assertEqual(r["expected_as"], 65432)
        self.assertEqual(r["matching_my_as"], 64512)
        # Stopped at the winning candidate (65001 first, then 64512).
        self.assertEqual(calls[:2], [65001, 64512])
        self.assertEqual(len(calls), 2)


class FindingsTest(unittest.TestCase):
    def _host_with_bgp(self, ip="10.0.0.1"):
        h = Host(ip=ip)
        h.ports.append(Port(portid=179, service="bgp", state="open"))
        return h

    def test_findings_include_reachable_and_unauth_when_peer_replies_with_open(self):
        h = self._host_with_bgp()
        caps = [{"code": 1, "name": _cap_name(1),
                 "value": struct.pack(">HBB", 1, 0, 1)},
                {"code": 2, "name": _cap_name(2), "value": b""}]
        probes = {(h.ip, 179): {
            "reachable": True, "tcp_ok": True, "peer_reply_kind": "open",
            "open": {"version": 4, "asn": 65100, "asn2": 65100,
                     "hold_time": 180, "router_id": "10.9.9.9",
                     "capabilities": caps,
                     "afi_safis": [{"afi": 1, "safi": 1,
                                    "afi_name": "IPv4", "safi_name": "unicast"}],
                     "graceful_restart": None,
                     "has_route_refresh": True, "has_4byte_as": False},
            "notification": None,
            "expected_as": None, "expected_as_my_as": None,
            "peer_max_version": None, "md5_hint": False,
        }}
        fs = bgp.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("bgp_reachable", kinds)
        self.assertIn("bgp_no_neighbor_auth", kinds)
        self.assertIn("bgp_peer_id", kinds)
        self.assertIn("bgp_router_id_pivot", kinds)
        self.assertIn("bgp_capabilities", kinds)
        self.assertIn("bgp_afi_safi", kinds)
        self.assertIn("bgp_route_refresh", kinds)

    def test_expected_as_finding_and_notification_leak(self):
        h = self._host_with_bgp()
        n = bgp._parse_notification(struct.pack(">BB", 2, 2)
                                    + struct.pack(">I", 65500))
        probes = {(h.ip, 179): {
            "reachable": True, "tcp_ok": True,
            "peer_reply_kind": "notification",
            "open": None, "notification": n,
            "expected_as": 65500, "expected_as_my_as": 65001,
            "peer_max_version": None, "md5_hint": False,
        }}
        fs = bgp.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("bgp_expected_as_disclosed", kinds)
        self.assertIn("bgp_notification_leak", kinds)
        # Must NOT claim unauthenticated OPEN — peer refused.
        self.assertNotIn("bgp_no_neighbor_auth", kinds)

    def test_md5_hint_when_bgp_layer_silent(self):
        h = self._host_with_bgp()
        probes = {(h.ip, 179): {
            "reachable": False, "tcp_ok": True, "peer_reply_kind": "silent",
            "open": None, "notification": None,
            "expected_as": None, "expected_as_my_as": None,
            "peer_max_version": None, "md5_hint": True,
        }}
        fs = bgp.findings([h], probes)
        self.assertEqual([f["kind"] for f in fs], ["bgp_md5_hint"])

    def test_router_id_matching_target_ip_is_not_pivot(self):
        h = self._host_with_bgp("10.9.9.9")
        probes = {(h.ip, 179): {
            "reachable": True, "tcp_ok": True, "peer_reply_kind": "open",
            "open": {"version": 4, "asn": 65100, "asn2": 65100,
                     "hold_time": 180, "router_id": "10.9.9.9",
                     "capabilities": [], "afi_safis": [],
                     "graceful_restart": None,
                     "has_route_refresh": False, "has_4byte_as": False},
            "notification": None,
            "expected_as": None, "expected_as_my_as": None,
            "peer_max_version": None, "md5_hint": False,
        }}
        fs = bgp.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("bgp_router_id_pivot", kinds)

    def test_version_probe_finding(self):
        h = self._host_with_bgp()
        probes = {(h.ip, 179): {
            "reachable": True, "tcp_ok": True, "peer_reply_kind": "open",
            "open": {"version": 4, "asn": 65100, "asn2": 65100,
                     "hold_time": 180, "router_id": "10.9.9.9",
                     "capabilities": [], "afi_safis": [],
                     "graceful_restart": None,
                     "has_route_refresh": False, "has_4byte_as": False},
            "notification": None,
            "expected_as": None, "expected_as_my_as": None,
            "peer_max_version": 4, "md5_hint": False,
        }}
        fs = bgp.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("bgp_version_probe", kinds)

    def test_findings_to_vulns_shape(self):
        h = self._host_with_bgp()
        probes = {(h.ip, 179): {
            "reachable": True, "tcp_ok": True, "peer_reply_kind": "open",
            "open": {"version": 4, "asn": 65100, "asn2": 65100,
                     "hold_time": 180, "router_id": "10.9.9.9",
                     "capabilities": [], "afi_safis": [],
                     "graceful_restart": None,
                     "has_route_refresh": False, "has_4byte_as": False},
            "notification": None,
            "expected_as": None, "expected_as_my_as": None,
            "peer_max_version": None, "md5_hint": False,
        }}
        fs = bgp.findings([h], probes)
        by_ip = bgp.findings_to_vulns(fs)
        self.assertIn(h.ip, by_ip)
        self.assertTrue(any(v.script_id.startswith("bgp:") for v in by_ip[h.ip]))


class BgpTargetsTest(unittest.TestCase):
    def test_bgp_targets_matches_179_and_service_name(self):
        h1 = Host(ip="10.0.0.1")
        h1.ports.append(Port(portid=179, service="", state="open"))
        h2 = Host(ip="10.0.0.2")
        h2.ports.append(Port(portid=17900, service="bgp", state="open"))
        h3 = Host(ip="10.0.0.3")
        h3.ports.append(Port(portid=80, service="http", state="open"))
        targets = bgp.bgp_targets([h1, h2, h3])
        ips = sorted(t["ip"] for t in targets)
        self.assertEqual(ips, ["10.0.0.1", "10.0.0.2"])


def _cap_name(code: int) -> str:
    return bgp._CAP_NAMES.get(code, f"unknown ({code})")


if __name__ == "__main__":
    unittest.main()
