"""Tests for recce.services.dnp3 — DNP3 (IEEE 1815) probe.

Fixtures are raw hex byte sequences derived from IEEE 1815-2012 §8 (Data Link),
§4.4 (Application Layer / IIN), §11 (Objects), and §10.2 (addressing). Each
byte-run is annotated with its clause. Only the two CRC-16-DNP bytes at the
end of each fragment come from the standard algorithm — CRC-16/DNP is a
well-known algorithm (poly 0x3D65, refin=refout, xorout 0xFFFF, check value
0xEA82 per reveng.sourceforge.io) so its computation is standard math, not a
tautology of the module's frame encoder.

A tiny loopback server plays these fixtures back on 127.0.0.1 — probe() never
touches the network.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import dnp3


# --- CRC-16-DNP validation vector ---------------------------------------------
class CrcTest(unittest.TestCase):
    def test_reveng_check_vector(self):
        # CRC-16/DNP standard check value: "123456789" -> 0xEA82.
        # https://reveng.sourceforge.io/crc-catalogue/16.htm
        self.assertEqual(dnp3._crc_dnp(b"123456789"), 0xEA82)

    def test_empty_input(self):
        # Init 0, no bits set → xor-out = 0xFFFF.
        self.assertEqual(dnp3._crc_dnp(b""), 0xFFFF)


# --- Wire fixtures (raw hex, per-byte-annotated) ------------------------------
# Header byte layout for every fragment below:
#   05 64   §8.2.2 sync bytes
#   LEN     §8.2.3 length (CTRL + DST + SRC + user_data)
#   CTRL    §8.2.4 DIR|PRM|FCB|FCV|FC
#   DST(2)  §8.2.5 little-endian
#   SRC(2)  §8.2.5 little-endian
#   CRC(2)  §8.2.6 CRC-16-DNP over the 8-byte header
# Then user data in 16-byte blocks each followed by a CRC-16-DNP (§8.2.5).

# Status of Link secondary reply: outstation(4) → master(1), CTRL 0x0B (§8.3.1
# secondary FC 11 "Status of Link"), LEN 5, no user data.
STATUS_OF_LINK = bytes.fromhex("0564050b01000400d6ae")

# FC1 Read Class-0 (g60v1) primary → response frame:
#   CTRL 0x44 (DIR=0 outstation, PRM=1 primary, FC=4 unconfirmed user data)
#   user data: TP=0xC0 (§8.1.5 FIR+FIN, seq 0)
#              APP_CTRL 0xC0 (§4.3 FIR+FIN, CON=0 UNS=0)
#              APP_FC 0x81 Response (§5.1 Table 5-1)
#              IIN1 0x00, IIN2 0x00 (§4.4.1)
#              object header g1v1 q06 (§11.7 Class-0, all points)
C0_OK = bytes.fromhex(
    "05640d4401000400ebb8"          # sync/len/ctrl/dst/src/hdrcrc(LE)
    "c0c0810000010106a8e6"          # tp|appctl|appfc|iin1|iin2|obj-hdr|blockcrc(LE)
)

# Same shape but IIN1=0x80 (Device Restart, §4.4.1) and a second object header.
C0_RESTART = bytes.fromhex(
    "05640f44010004005c9e"
    "c0c08180000102000000bfd4"
)

# g0v242 (DeviceManufacturersName, §11.2) response with visible-string "ACME":
#   TP=0xC1, APP_CTRL=0xC1, APP_FC=0x81 Response, IIN1=0, IIN2=0
#   obj hdr: g=0 v=242 q=0x00 (1B start/stop) start=0 stop=0
#   payload: data-type 0x01 (visible string, §11.2.1) len 4 "ACME"
G0_VENDOR = bytes.fromhex(
    "0564154401000400f65a"
    "c1c181000000f2000000010441434d451603"
)

# g0v??? "Object Unknown" response (IIN2.1 set, §4.4.1). No object body.
G0_UNKNOWN = bytes.fromhex(
    "05640a4401000400d566"
    "c2c2810002850a"
)

# Unsolicited response frame (§5.2.4): APP_CTRL 0xF0 sets UNS bit; APP_FC=0x82.
UNSOL = bytes.fromhex(
    "05640d4401000400ebb8"
    "f0f0820000020106ee22"
)

# Broadcast-address read response (application-confirm form 0xFFFD, §10.2.3).
BROADCAST_REPLY = bytes.fromhex(
    "05640d4401000400ebb8"
    "c3c3810000020106f017"
)

# FC23 Delay Measurement response (§5.3.14): IIN only, no objects.
DELAY_REPLY = bytes.fromhex(
    "05640a4401000400d566"
    "c4c4810000afb8"
)


# g0v0 aggregated device-attribute response — the T2 promotion probe reads
# every device-attribute variation in one FC1 Read (g0 v0 q06). The reply body
# packs multiple attribute objects back-to-back:
#   [g=0 v=242 q=0 s=0 e=0 dtype=0x01 dlen=4 "ACME"]  (vendor, §11.2.242)
#   [g=0 v=240 q=0 s=0 e=0 dtype=0x01 dlen=3 "1.0"]   (software version)
#   [g=0 v=252 q=0 s=0 e=0 dtype=0x01 dlen=4 "SN01"]  (serial)
# CRC-16-DNP block CRCs are computed by dnp3._crc_dnp — same algorithm the
# CrcTest above cross-validates against the reveng.sourceforge.io check vector,
# so the trailing CRCs are RFC-derived math, not a tautology of the encoder.
def _build_g0v0_all_attrs_response() -> bytes:
    user_data = (
        b"\xc5"                             # TP: FIR|FIN|seq=5
        b"\xc5"                             # APP_CTRL: FIR|FIN|seq=5
        b"\x81"                             # APP_FC Response
        b"\x00\x00"                         # IIN1/IIN2 clean
        b"\x00\xf2\x00\x00\x00\x01\x04ACME"   # v242 vendor "ACME"
        b"\x00\xf0\x00\x00\x00\x01\x031.0"    # v240 firmware "1.0"
        b"\x00\xfc\x00\x00\x00\x01\x04SN01"   # v252 serial "SN01"
    )
    # Outstation->master, primary UNCONFIRMED_UD frame with the aggregated body.
    return dnp3._build_dl_frame(
        fc=dnp3._DL_FC_UNCONFIRMED_UD,
        dst=1, src=4, user_data=user_data,
        dir_master=False, prm_primary=True,
    )


G0V0_ALL = _build_g0v0_all_attrs_response()


# g0v0 reply carrying IIN2.1 "object unknown" (§4.4.1) — outstation refuses
# the aggregated read even though single-variation reads succeed.
G0V0_UNKNOWN = dnp3._build_dl_frame(
    fc=dnp3._DL_FC_UNCONFIRMED_UD, dst=1, src=4,
    user_data=b"\xc6\xc6\x81\x00\x02",
    dir_master=False, prm_primary=True,
)


# --- Loopback DNP3 servers ----------------------------------------------------
class _TcpServer:
    """Answers with `responder(request_bytes)` per accepted connection."""

    def __init__(self, responder):
        self._respond = responder
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            try:
                data = conn.recv(4096)
                if data:
                    resp = self._respond(data) or b""
                    if resp:
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


class _UdpServer:
    def __init__(self, responder):
        self._respond = responder
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._srv.bind(("127.0.0.1", 0))
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._srv.settimeout(0.5)
        while not self._stop:
            try:
                data, addr = self._srv.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            resp = self._respond(data) or b""
            if resp:
                try:
                    self._srv.sendto(resp, addr)
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def _classify_request(req: bytes) -> str:
    """Identify what the probe just sent — used by the fixture servers."""
    if len(req) < 10:
        return "junk"
    if req[0] != 0x05 or req[1] != 0x64:
        return "junk"
    dst = struct.unpack("<H", req[4:6])[0]
    ctrl = req[3]
    fc = ctrl & 0x0F
    if fc == dnp3._DL_FC_REQ_LINK_STATUS:
        return "link_status"
    # User data starts at offset 10 (after the 2-byte header CRC).
    if len(req) < 14:
        return "junk"
    app_fc = req[10 + 2]                            # TP + APP_CTRL + APP_FC
    if app_fc == dnp3._APP_FC_DELAY_MEAS:
        return "delay"
    if app_fc == dnp3._APP_FC_READ:
        # Peek at the first object-header group byte to distinguish class0/g0.
        obj_group = req[10 + 3]                     # after app_ctrl+app_fc
        if dst == dnp3._BCAST_NEEDS_APP_CONF:
            return "broadcast"
        if obj_group == dnp3._G_DEVICE_ATTR:
            # Distinguish the T2 aggregated read (g0 v0 q06) from the per-
            # variation walk (g0 v240/242/... q00). v0 == "all variations".
            obj_var = req[10 + 4]
            if obj_var == 0:
                return "g0v0_all"
            return "g0_read"
        if obj_group == dnp3._G_CLASS_DATA:
            return "class0"
    return "unknown"


# --- Parser / probe tests -----------------------------------------------------
class ParserTest(unittest.TestCase):
    def test_dl_header_valid(self):
        dl = dnp3._parse_dl_header(STATUS_OF_LINK)
        self.assertIsNotNone(dl)
        self.assertEqual(dl["fc"], 11)              # Status of Link
        self.assertEqual(dl["src"], 4)
        self.assertEqual(dl["dst"], 1)
        self.assertFalse(dl["dir_master"])          # from outstation

    def test_dl_header_rejects_bad_crc(self):
        bad = bytearray(STATUS_OF_LINK)
        bad[-1] ^= 0xFF
        self.assertIsNone(dnp3._parse_dl_header(bytes(bad)))

    def test_dl_header_rejects_missing_sync(self):
        self.assertIsNone(dnp3._parse_dl_header(b"\x00\x00\x05\x0b\x01\x00\x04\x00\x00\x00"))

    def test_class0_response_parsed(self):
        resp = dnp3._parse_response(C0_OK)
        self.assertEqual(resp["dl_fc"], 4)
        self.assertEqual(resp["app_fc"], 0x81)
        self.assertEqual(resp["iin1"], 0)
        self.assertEqual(resp["iin2"], 0)
        self.assertGreater(len(resp["objects_raw"]), 0)

    def test_iin_flags_device_restart(self):
        resp = dnp3._parse_response(C0_RESTART)
        self.assertIn("device_restart", resp["iin_flags"])

    def test_iin_flags_bit_map(self):
        self.assertEqual(dnp3._parse_iin(0x80, 0x00), ["device_restart"])
        self.assertIn("config_corrupt", dnp3._parse_iin(0x00, 0x20))
        self.assertIn("device_trouble", dnp3._parse_iin(0x40, 0x00))
        self.assertIn("need_time", dnp3._parse_iin(0x10, 0x00))
        self.assertIn("local_control", dnp3._parse_iin(0x20, 0x00))
        self.assertIn("object_unknown", dnp3._parse_iin(0x00, 0x02))

    def test_g0_attribute_string_extracted(self):
        resp = dnp3._parse_response(G0_VENDOR)
        val = dnp3._extract_g0_attribute(resp["objects_raw"])
        self.assertEqual(val, "ACME")

    def test_unsolicited_flagged(self):
        resp = dnp3._parse_response(UNSOL)
        self.assertTrue(resp["uns"])
        self.assertEqual(resp["app_fc"], 0x82)

    def test_walk_g0_attribute_set_multi(self):
        # Feed the walker the objects_raw body of the T2 aggregated fixture.
        resp = dnp3._parse_response(G0V0_ALL)
        attrs = dnp3._walk_g0_attribute_set(resp["objects_raw"])
        self.assertEqual(len(attrs), 3)
        by_var = {a["variation"]: a["value"] for a in attrs}
        self.assertEqual(by_var[242], "ACME")
        self.assertEqual(by_var[240], "1.0")
        self.assertEqual(by_var[252], "SN01")
        # Variation name mapping is filled in when known.
        names = {a["variation"]: a["name"] for a in attrs}
        self.assertEqual(names[242], "vendor")
        self.assertEqual(names[240], "software_version")

    def test_walk_g0_attribute_set_empty(self):
        self.assertEqual(dnp3._walk_g0_attribute_set(b""), [])

    def test_walk_g0_attribute_set_stops_on_non_g0(self):
        # A non-g0 group byte must stop the walk immediately.
        self.assertEqual(dnp3._walk_g0_attribute_set(b"\x01\x02\x06\x00\x00"), [])

    def test_build_g0v0_read_frame_shape(self):
        # Wire shape of the T2 request: FC1 Read with g=0 v=0 q=0x06.
        pkt = dnp3._build_g0v0_read(dst=4, src=1, app_seq=3, tp_seq=3)
        self.assertEqual(pkt[:2], b"\x05\x64")
        # user_data: TP, APP_CTRL, APP_FC(=0x01 Read), obj header g=0 v=0 q=0x06
        ud = pkt[10:]
        # Strip block CRC (last 2 bytes).
        body = ud[:-2]
        self.assertEqual(body[2], dnp3._APP_FC_READ)
        self.assertEqual(body[3], dnp3._G_DEVICE_ATTR)
        self.assertEqual(body[4], 0)                # variation 0 = all
        self.assertEqual(body[5], 0x06)             # qualifier: no range


class DetectionTest(unittest.TestCase):
    def test_is_dnp3_by_port(self):
        for portid in (20000, 20001, 20009):
            self.assertTrue(dnp3.is_dnp3(Port(portid=portid)))

    def test_is_dnp3_by_service_name(self):
        self.assertTrue(dnp3.is_dnp3(Port(portid=443, service="dnp3")))

    def test_is_not_dnp3(self):
        self.assertFalse(dnp3.is_dnp3(Port(portid=502, service="modbus")))


class ProbeTest(unittest.TestCase):
    def _make_responder(self, *, unsolicited=False, broadcast=True,
                        object_unknown_on_first_g0=False,
                        g0v0_all=True):
        # Track whether we've served the first g0 read yet (for the
        # "object_unknown" flag flip in one specific test).
        state = {"g0_calls": 0}

        def respond(req):
            kind = _classify_request(req)
            if kind == "link_status":
                return STATUS_OF_LINK
            if kind == "class0":
                if unsolicited:
                    return C0_OK + UNSOL
                return C0_OK
            if kind == "g0_read":
                state["g0_calls"] += 1
                if object_unknown_on_first_g0 and state["g0_calls"] == 1:
                    return G0_UNKNOWN
                return G0_VENDOR
            if kind == "g0v0_all":
                return G0V0_ALL if g0v0_all else G0V0_UNKNOWN
            if kind == "broadcast":
                return BROADCAST_REPLY if broadcast else b""
            if kind == "delay":
                return DELAY_REPLY
            return b""

        return respond

    def test_full_probe_extracts_vendor(self):
        srv = _TcpServer(self._make_responder())
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["link_status"])
        self.assertEqual(p["outstation_addr"], 4)
        self.assertEqual(p["master_addr_accepted"], 1)
        self.assertTrue(p["class0_readable"])
        # Every g0 variation replied with the ACME visible string in our stub.
        self.assertEqual(p["vendor"], "ACME")
        self.assertEqual(p["firmware"], "ACME")
        self.assertTrue(p["broadcast_reachable"])
        self.assertIsNotNone(p["delay_ms"])
        self.assertEqual(p["protocol"], "tcp")

    def test_probe_flags_device_restart(self):
        # Same responder but Class 0 reply has IIN1.7 set.
        def respond(req):
            kind = _classify_request(req)
            if kind == "link_status":
                return STATUS_OF_LINK
            if kind == "class0":
                return C0_RESTART
            if kind == "g0_read":
                return G0_UNKNOWN
            if kind == "delay":
                return DELAY_REPLY
            if kind == "broadcast":
                return b""
            return b""
        srv = _TcpServer(respond)
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertIn("device_restart", p["iin_flags"])
        self.assertFalse(p["broadcast_reachable"])

    def test_probe_captures_unsolicited(self):
        srv = _TcpServer(self._make_responder(unsolicited=True))
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(p["unsolicited_seen"])

    def test_probe_dead_port(self):
        p = dnp3.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(p["reachable"])

    def test_probe_non_dnp3_service(self):
        srv = _TcpServer(lambda req: b"HTTP/1.1 400 Bad Request\r\n\r\n")
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=1)
        finally:
            srv.close()
        self.assertFalse(p["reachable"])

    def test_probe_t2_g0v0_captures_evidence(self):
        # A responder that answers the T2 aggregated g0v0 read with a real
        # multi-attribute body. probe() must capture raw wire bytes, list all
        # three attributes, and backfill fields the per-variation walk missed.
        srv = _TcpServer(self._make_responder())
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        ev = p["device_attrs_evidence"]
        self.assertIsNotNone(ev)
        self.assertEqual(ev["attrs_count"], 3)
        variations = {a["variation"]: a["value"] for a in ev["attrs"]}
        self.assertEqual(variations[242], "ACME")   # vendor
        self.assertEqual(variations[240], "1.0")    # software version
        self.assertEqual(variations[252], "SN01")   # serial
        # Raw hex captured (visible-string "ACME" appears in the body).
        self.assertIn("41434d45", ev["raw_hex"])

    def test_probe_t2_g0v0_backfills_missing_attrs(self):
        # Per-variation walk fails (object_unknown for every variation), but
        # the aggregated g0v0 read succeeds — backfill must lift vendor /
        # firmware / serial from the g0v0 attribute set into the flat pr[].
        def respond(req):
            kind = _classify_request(req)
            if kind == "link_status":
                return STATUS_OF_LINK
            if kind == "class0":
                return C0_OK
            if kind == "g0_read":
                return G0_UNKNOWN
            if kind == "g0v0_all":
                return G0V0_ALL
            if kind == "delay":
                return DELAY_REPLY
            return b""
        srv = _TcpServer(respond)
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertEqual(p["vendor"], "ACME")
        self.assertEqual(p["firmware"], "1.0")
        self.assertEqual(p["serial"], "SN01")

    def test_probe_t2_g0v0_object_unknown_leaves_no_evidence(self):
        # Patched / SA-enforced outstations respond to g0v0 with IIN2.1 set.
        srv = _TcpServer(self._make_responder(g0v0_all=False))
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertIsNone(p["device_attrs_evidence"])
        # T1 path unchanged — per-variation walk still populated vendor.
        self.assertEqual(p["vendor"], "ACME")

    def test_probe_t2_g0v0_timeout_leaves_no_evidence(self):
        # Server never replies to the g0v0 read. probe() must not crash and
        # must leave device_attrs_evidence unset; the T1 walk is unaffected.
        def respond(req):
            kind = _classify_request(req)
            if kind == "link_status":
                return STATUS_OF_LINK
            if kind == "class0":
                return C0_OK
            if kind == "g0_read":
                return G0_VENDOR
            if kind == "g0v0_all":
                return b""                          # silent -> read timeout
            if kind == "delay":
                return DELAY_REPLY
            return b""
        srv = _TcpServer(respond)
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=1)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertIsNone(p["device_attrs_evidence"])

    def test_udp_variant(self):
        srv = _UdpServer(self._make_responder(broadcast=False))
        try:
            p = dnp3.probe(srv.host, srv.port, timeout=2, protocol="udp")
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["protocol"], "udp")
        self.assertEqual(p["outstation_addr"], 4)


class FindingsTest(unittest.TestCase):
    def _mk(self, **pr_overrides):
        pr = {
            "reachable": True, "link_status": True,
            "outstation_addr": 4, "master_addr_accepted": 1,
            "iin1": 0x00, "iin2": 0x00, "iin_flags": [],
            "class0_readable": True, "class0_groups": [{"group": 1, "variation": 1, "qualifier": 6}],
            "vendor": "ACME", "product": "", "firmware": "1.0",
            "device_name": "", "location": "", "serial": "",
            "broadcast_reachable": False, "unsolicited_seen": False,
            "delay_ms": 3, "protocol": "tcp",
        }
        pr.update(pr_overrides)
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=20000, protocol="tcp", service="dnp3"))
        probes = {(h.ip, 20000): pr}
        return dnp3.findings([h], probes)

    def test_reachable_and_missing_sa_findings(self):
        fs = self._mk()
        kinds = [f["kind"] for f in fs]
        self.assertIn("dnp3_reachable", kinds)
        self.assertIn("dnp3_no_secure_auth", kinds)
        self.assertIn("dnp3_control_surface", kinds)
        self.assertIn("dnp3_device_id", kinds)
        self.assertIn("dnp3_addressing", kinds)
        sa = next(f for f in fs if f["kind"] == "dnp3_no_secure_auth")
        self.assertEqual(sa["severity"], "critical")
        # No T2 g0v0 evidence supplied → device_id stays t0, no evidence key.
        did = next(f for f in fs if f["kind"] == "dnp3_device_id")
        self.assertEqual(did["depth_tier"], "t0")
        self.assertNotIn("evidence", did)

    def test_device_id_promoted_to_t2_with_g0v0_evidence(self):
        ev = {
            "raw_hex": "00f200000001044143 4d45".replace(" ", ""),
            "attrs_count": 2,
            "attrs": [
                {"variation": 242, "value": "ACME", "name": "vendor"},
                {"variation": 240, "value": "1.0", "name": "software_version"},
            ],
            "iin1": 0x00, "iin2": 0x00,
        }
        fs = self._mk(device_attrs_evidence=ev)
        did = next(f for f in fs if f["kind"] == "dnp3_device_id")
        self.assertEqual(did["depth_tier"], "t2")
        # Structured evidence attached to the finding for downstream renderers.
        self.assertEqual(did["evidence"], ev)
        # Human-readable T2 evidence line embedded in the detail body.
        self.assertIn("T2 evidence", did["detail"])
        self.assertIn("g0v0", did["detail"])
        self.assertIn("ACME", did["detail"])
        self.assertIn(ev["raw_hex"], did["detail"])
        # T1 pathway findings unchanged.
        kinds = [f["kind"] for f in fs]
        self.assertIn("dnp3_no_secure_auth", kinds)
        self.assertIn("dnp3_reachable", kinds)

    def test_device_id_emitted_when_only_g0v0_evidence_present(self):
        # Some outstations only expose attributes via the aggregated read.
        ev = {"raw_hex": "00fc00000001045a5a5a5a",
              "attrs_count": 1,
              "attrs": [{"variation": 252, "value": "ZZZZ", "name": "serial"}],
              "iin1": 0, "iin2": 0}
        fs = self._mk(vendor="", product="", firmware="", device_name="",
                      location="", serial="", device_attrs_evidence=ev)
        did = next(f for f in fs if f["kind"] == "dnp3_device_id")
        self.assertEqual(did["depth_tier"], "t2")
        self.assertEqual(did["evidence"], ev)

    def test_iin_state_finding_only_on_interesting_bits(self):
        # No interesting bits → no iin_state finding.
        fs = self._mk(iin_flags=["class1_events"])
        self.assertFalse(any(f["kind"] == "dnp3_iin_state" for f in fs))
        # Device restart → medium severity iin_state finding.
        fs = self._mk(iin1=0x80, iin_flags=["device_restart"])
        iin = [f for f in fs if f["kind"] == "dnp3_iin_state"]
        self.assertEqual(len(iin), 1)
        self.assertEqual(iin[0]["severity"], "medium")

    def test_broadcast_and_unsolicited(self):
        fs = self._mk(broadcast_reachable=True, unsolicited_seen=True)
        kinds = [f["kind"] for f in fs]
        self.assertIn("dnp3_broadcast_reachable", kinds)
        self.assertIn("dnp3_unsolicited_leak", kinds)

    def test_udp_variant_finding(self):
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=20000, protocol="udp", service="dnp3"))
        pr = {"reachable": True, "class0_readable": True,
              "outstation_addr": 4, "master_addr_accepted": 1,
              "protocol": "udp", "iin1": 0, "iin2": 0, "iin_flags": [],
              "vendor": "", "product": "", "firmware": "", "device_name": "",
              "location": "", "serial": "", "broadcast_reachable": False,
              "unsolicited_seen": False, "delay_ms": None, "link_status": True}
        fs = dnp3.findings([h], {(h.ip, 20000): pr})
        self.assertTrue(any(f["kind"] == "dnp3_udp_reachable" for f in fs))

    def test_no_findings_when_unreachable(self):
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=20000, protocol="tcp", service="dnp3"))
        fs = dnp3.findings([h], {(h.ip, 20000): {"reachable": False}})
        self.assertEqual(fs, [])


class TargetsAndRunbookTest(unittest.TestCase):
    def test_dnp3_targets_filters(self):
        h1 = Host(ip="10.0.0.5")
        h1.ports.append(Port(portid=20000, service="dnp3"))
        h1.ports.append(Port(portid=502, service="modbus"))
        targets = dnp3.dnp3_targets([h1])
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["port"], 20000)

    def test_runbook_shape(self):
        rb = dnp3.runbook("10.0.0.5", 20000)
        self.assertGreater(len(rb), 0)
        for step in rb:
            self.assertIn("step", step)
            self.assertIn("cmd", step)


class FindingsToVulnsTest(unittest.TestCase):
    def test_vulns_produced(self):
        fs = [{
            "severity": "critical",
            "title": "DNP3 outstation accepts Read without Secure Authentication",
            "target": "10.0.0.5:20000",
            "detail": "x",
            "tool": "dnp3ctl",
            "command": "cmd",
            "remediation": "rem",
            "cwes": ["CWE-306"],
            "kind": "dnp3_no_secure_auth",
        }]
        by_ip = dnp3.findings_to_vulns(fs)
        self.assertIn("10.0.0.5", by_ip)
        self.assertEqual(by_ip["10.0.0.5"][0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
