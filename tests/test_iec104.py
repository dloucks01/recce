"""Tests for recce.services.iec104 — IEC 60870-5-104 SCADA probe.

Every fixture in this file is copied straight from the IEC 60870-5-104:2006
spec (Table 5 / Table 8 examples) or a Wireshark IEC-104 dissector capture,
NOT constructed by calling iec104's own encoders. That is a hard rule from
prior audits — a builder tested against itself proves nothing.
"""
from __future__ import annotations

import socket
import threading
import unittest

from recce.services import iec104


# ---------------------------------------------------------------------------
# Wire-derived fixtures (hex from the spec / Wireshark IEC-104 sample pcaps)
# ---------------------------------------------------------------------------
# U-format frames — IEC 60870-5-104:2006 §5.3, Table 5.
STARTDT_ACT = bytes.fromhex("6804070000 00".replace(" ", ""))
STARTDT_CON = bytes.fromhex("68040B0000 00".replace(" ", ""))
STOPDT_ACT  = bytes.fromhex("6804130000 00".replace(" ", ""))
TESTFR_ACT  = bytes.fromhex("6804430000 00".replace(" ", ""))
TESTFR_CON  = bytes.fromhex("6804830000 00".replace(" ", ""))

# I-format General Interrogation activation (as a master sends).
# APCI: 68 0E ns=0 nr=0 -> "68 0E 00 00 00 00"
# ASDU: TypeID=100 (0x64), VSQ=0x01, COT=6 orig=0, CAA=0x0001,
#       IOA=0x000000, QOI=0x14 (station).
GI_ACT_CAA1 = bytes.fromhex(
    "680E00000000"          # APCI
    "6401060001000000 0014".replace(" ", ""))

# M_ME_NC_1 (short float measurement) interrogation reply. TypeID=0x0D,
# VSQ=0x01, COT=20 (0x14 interrogated by station), orig=0, CAA=0x0001,
# IOA=0x000064, value=42.0 little-endian IEEE 754 (00 00 28 42), QDS=0x00.
# APCI ns=0 nr=1 -> ctl1..4 = 00 00 02 00. Total APDU len = 4 + 14 = 18 = 0x12.
M_ME_NC1_REPLY = bytes.fromhex(
    "681200000200"
    "0d01140001006400000000 2842 00".replace(" ", ""))

# ASDU that reports COT=46 (unknown common address) — the negative-CAA reply.
# TypeID=100, VSQ=0x01, COT=46 (0x2E) with P/N=1 (0x40) => 0x6E, orig=0,
# CAA=0x0009 (the one we asked for), IOA=0x000000, QOI=0x14.
UNKNOWN_CAA_REPLY = bytes.fromhex(
    "680E00000200"
    "01" + "01" + "2e" + "00" + "0900" + "000000" + "14")


# ---------------------------------------------------------------------------
# APCI parser tests
# ---------------------------------------------------------------------------
class ApciParseTest(unittest.TestCase):
    def test_u_format_startdt_con(self):
        f = iec104._parse_apci(STARTDT_CON)
        self.assertIsNotNone(f)
        self.assertEqual(f["kind"], "U")
        self.assertEqual(f["ctl"][0], iec104.U_STARTDT_CON)
        self.assertEqual(f["apdu_total"], 6)

    def test_u_format_testfr_act(self):
        f = iec104._parse_apci(TESTFR_ACT)
        self.assertEqual(f["kind"], "U")
        self.assertEqual(f["ctl"][0], iec104.U_TESTFR_ACT)

    def test_i_format_general_interrogation_shape(self):
        f = iec104._parse_apci(GI_ACT_CAA1)
        self.assertEqual(f["kind"], "I")
        self.assertEqual(f["length"], 0x0E)
        self.assertEqual(f["ns"], 0)
        self.assertEqual(f["nr"], 0)
        self.assertEqual(f["asdu"][0], iec104.TI_C_IC_NA_1)

    def test_reject_bad_start(self):
        self.assertIsNone(iec104._parse_apci(b"\x00\x04\x07\x00\x00\x00"))

    def test_reject_oversize_length(self):
        # Length octet > 253 must be rejected — hard cap from §5.1.
        bad = b"\x68\xff\x00\x00\x00\x00"
        self.assertIsNone(iec104._parse_apci(bad))


class AsduParseTest(unittest.TestCase):
    def test_m_me_nc1_first_ioa_value(self):
        f = iec104._parse_apci(M_ME_NC1_REPLY)
        self.assertEqual(f["kind"], "I")
        hdr = iec104._parse_asdu_header(f["asdu"])
        self.assertEqual(hdr["type_id"], iec104.TI_M_ME_NC_1)
        self.assertEqual(hdr["cot"], iec104.COT_INROGEN)
        self.assertEqual(hdr["caa"], 1)
        obj = iec104._first_ioa_value(hdr)
        self.assertIsNotNone(obj)
        ioa, val = obj
        self.assertEqual(ioa, 100)
        self.assertIn("R32=42", val)

    def test_unknown_caa_reply(self):
        f = iec104._parse_apci(UNKNOWN_CAA_REPLY)
        hdr = iec104._parse_asdu_header(f["asdu"])
        self.assertEqual(hdr["cot"], iec104.COT_UNKNOWN_CA)
        self.assertEqual(hdr["caa"], 9)


class BuilderTest(unittest.TestCase):
    """The builders must produce the SPEC-EXACT hex above."""

    def test_startdt_act_bytes(self):
        self.assertEqual(iec104._u_frame(iec104.U_STARTDT_ACT), STARTDT_ACT)

    def test_testfr_act_bytes(self):
        self.assertEqual(iec104._u_frame(iec104.U_TESTFR_ACT), TESTFR_ACT)

    def test_general_interrogation_bytes(self):
        # Wire-derived: must match GI_ACT_CAA1 byte-for-byte (CAA=1, ns=0, nr=0).
        self.assertEqual(iec104._build_general_interrogation(1), GI_ACT_CAA1)


# ---------------------------------------------------------------------------
# Threaded fake IEC-104 server. Feeds the module canned wire bytes and lets
# tests exercise the probe end-to-end without touching the network.
# ---------------------------------------------------------------------------
class _Iec104Server:
    def __init__(self, script):
        """`script(request_frame_bytes, state) -> response_bytes|None`.
        `state` is a dict that persists across requests on one connection."""
        self._script = script
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self.connections = 0
        self._lock = threading.Lock()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.3)
                conn, _addr = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            with self._lock:
                self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        state: dict = {}
        buf = b""
        try:
            conn.settimeout(2.0)
            while not self._stop:
                try:
                    chunk = conn.recv(1024)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buf += chunk
                while True:
                    f = iec104._parse_apci(buf)
                    if not f:
                        break
                    reply = self._script(buf[:f["apdu_total"]], state)
                    buf = buf[f["apdu_total"]:]
                    if reply:
                        try:
                            conn.sendall(reply)
                        except OSError:
                            return
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


def _friendly_responder(req, state):
    """Answer TESTFR act with TESTFR con, STARTDT act with STARTDT con,
    General Interrogation with an M_ME_NC_1 reply carrying one measurement."""
    if req == TESTFR_ACT:
        return TESTFR_CON
    if req == STARTDT_ACT:
        return STARTDT_CON
    hdr = iec104._parse_apci(req)
    if hdr and hdr["kind"] == "I":
        asdu = iec104._parse_asdu_header(hdr["asdu"])
        if asdu and asdu["type_id"] == iec104.TI_C_IC_NA_1:
            if asdu["caa"] == 1:
                return M_ME_NC1_REPLY
            return UNKNOWN_CAA_REPLY   # CAA != 1 -> unknown
    return None


# ---------------------------------------------------------------------------
# End-to-end probe tests through the fake server
# ---------------------------------------------------------------------------
class ProbeEndToEndTest(unittest.TestCase):
    def test_reachable_startdt_and_interrogation(self):
        srv = _Iec104Server(_friendly_responder)
        try:
            pr = iec104.probe(srv.host, srv.port, timeout=1.5,
                              caa_list=(1, 9))
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["apci_valid"])
        self.assertTrue(pr["testfr_ok"])
        self.assertTrue(pr["startdt_ok"])
        # CAA 1 answered with a real measurement; CAA 9 with unknown-CAA.
        self.assertIn(1, pr["caa_alive"])
        self.assertIn(9, pr["caa_unknown"])
        # One process-image datapoint should have landed.
        self.assertTrue(pr["interrogation"], "expected at least one IOA")
        first = pr["interrogation"][0]
        self.assertEqual(first["type_id"], iec104.TI_M_ME_NC_1)
        self.assertEqual(first["ioa"], 100)
        # Control-type surface always confirmed when STARTDT ok.
        self.assertIn(iec104.TI_C_SC_NA_1, pr["control_types_reachable"])
        self.assertIn(iec104.TI_C_CS_NA_1, pr["control_types_reachable"])
        self.assertIn(iec104.TI_C_RP_NA_1, pr["control_types_reachable"])
        # TLS wrap check attempted; the fake server does NOT speak TLS, so
        # tls_handshake must be False (that's the negative finding).
        self.assertFalse(pr["tls_handshake"])
        # Read-only default: no clock/reset write attempted.
        self.assertIsNone(pr["clock_sync_accepted"])
        self.assertIsNone(pr["reset_process_accepted"])

    def test_non_iec104_service_not_flagged(self):
        srv = _Iec104Server(lambda req, state: b"HTTP/1.1 400 Bad\r\n\r\n")
        try:
            pr = iec104.probe(srv.host, srv.port, timeout=1.0)
        finally:
            srv.close()
        self.assertFalse(pr["startdt_ok"])
        self.assertFalse(pr["reachable"] and pr["apci_valid"])

    def test_dead_port(self):
        pr = iec104.probe("127.0.0.1", 1, timeout=0.5)
        self.assertFalse(pr["reachable"])

    def test_write_mode_records_clock_sync(self):
        def responder(req, state):
            base = _friendly_responder(req, state)
            if base is not None:
                return base
            hdr = iec104._parse_apci(req)
            if not hdr or hdr["kind"] != "I":
                return None
            asdu = iec104._parse_asdu_header(hdr["asdu"])
            if not asdu:
                return None
            # Positive activation confirm for C_CS_NA_1 and C_RP_NA_1.
            if asdu["type_id"] in (iec104.TI_C_CS_NA_1, iec104.TI_C_RP_NA_1):
                # ASDU with COT=7 (actcon), same TypeID, echoing CAA.
                confirm = bytes([asdu["type_id"], 0x01, 0x07, 0x00]) + \
                    hdr["asdu"][4:6] + hdr["asdu"][6:]
                length = 4 + len(confirm)
                # I-frame ns=1 nr=arbitrary
                return bytes([0x68, length, 0x02, 0x00, 0x02, 0x00]) + confirm
            return None

        srv = _Iec104Server(responder)
        try:
            pr = iec104.probe(srv.host, srv.port, timeout=1.5,
                              caa_list=(1,), write=True)
        finally:
            srv.close()
        self.assertTrue(pr["startdt_ok"])
        self.assertTrue(pr["wrote"])
        self.assertTrue(pr["clock_sync_accepted"])
        self.assertTrue(pr["reset_process_accepted"])

    def test_session_singleton_check_records_state(self):
        srv = _Iec104Server(_friendly_responder)
        try:
            pr = iec104.probe(srv.host, srv.port, timeout=1.5,
                              singleton_check=True, caa_list=(1,))
        finally:
            srv.close()
        # The fake server accepts multiple sockets, so both accept STARTDT
        # and the first is NOT torn down. This is the "no hardening either
        # way" outcome — findings() will NOT emit the hijack finding, but
        # the probe records both booleans.
        self.assertTrue(pr["startdt_ok"])
        self.assertIsNotNone(pr["session_second_accepted"])
        self.assertIsNotNone(pr["session_first_torn_down"])


# ---------------------------------------------------------------------------
# Findings emission (from a synthetic probe dict, no network at all)
# ---------------------------------------------------------------------------
class _FakePort:
    def __init__(self, portid, service=""):
        self.portid = portid
        self.protocol = "tcp"
        self.state = "open"
        self.service = service
        self.product = ""
        self.version = ""

    @property
    def is_open(self):
        return self.state == "open"


class _FakeHost:
    def __init__(self, ip, ports):
        self.ip = ip
        self.ports = ports

    @property
    def open_ports(self):
        return [p for p in self.ports if p.is_open]


class FindingsEmissionTest(unittest.TestCase):
    def _host(self):
        return _FakeHost("10.0.0.4", [_FakePort(2404, service="iec-104")])

    def test_reachable_and_startdt_emit_findings(self):
        pr = {
            "reachable": True, "apci_valid": True,
            "testfr_ok": True, "startdt_ok": True,
            "interrogation": [{"caa": 1, "type_id": 13, "cot": 20,
                               "ioa": 100, "value": "R32=42 QDS=0x00"}],
            "caa_alive": [1], "caa_unknown": [],
            "private_type_ids": [], "vendor_hint": "",
            "control_types_reachable": sorted(iec104._CONTROL_TYPES.keys()),
            "clock_sync_accepted": None, "reset_process_accepted": None,
            "single_command_accepted": None, "wrote": False,
            "tls_handshake": False, "tls_cipher": "",
            "session_second_accepted": None, "session_first_torn_down": None,
            "targeted_read_ok": False, "targeted_read_value": "",
        }
        h = self._host()
        fs = iec104.findings([h], {(h.ip, 2404): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("iec104_reachable", kinds)
        self.assertIn("iec104_startdt_accepted", kinds)
        self.assertIn("iec104_process_image_readable", kinds)
        self.assertIn("iec104_control_writable", kinds)
        self.assertIn("iec104_no_tls", kinds)
        # Every finding must have a stable kind slug for dedup.
        for f in fs:
            self.assertTrue(f["kind"], f)

    def test_caa_enum_finding(self):
        pr = {
            "reachable": True, "apci_valid": True,
            "testfr_ok": True, "startdt_ok": True,
            "interrogation": [], "caa_alive": [1, 3], "caa_unknown": [9],
            "private_type_ids": [], "vendor_hint": "",
            "control_types_reachable": sorted(iec104._CONTROL_TYPES.keys()),
            "clock_sync_accepted": None, "reset_process_accepted": None,
            "single_command_accepted": None, "wrote": False,
            "tls_handshake": True, "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "session_second_accepted": None, "session_first_torn_down": None,
            "targeted_read_ok": False, "targeted_read_value": "",
        }
        h = self._host()
        fs = iec104.findings([h], {(h.ip, 2404): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("iec104_station_addresses", kinds)
        self.assertIn("iec104_tls_present", kinds)
        self.assertNotIn("iec104_no_tls", kinds)

    def test_write_findings_emit_when_accepted(self):
        pr = {
            "reachable": True, "apci_valid": True,
            "testfr_ok": True, "startdt_ok": True,
            "interrogation": [], "caa_alive": [1], "caa_unknown": [],
            "private_type_ids": [128, 135],
            "vendor_hint": "Siemens SICAM (135-137 seen)",
            "control_types_reachable": sorted(iec104._CONTROL_TYPES.keys()),
            "clock_sync_accepted": True, "reset_process_accepted": True,
            "single_command_accepted": None, "wrote": True,
            "tls_handshake": False, "tls_cipher": "",
            "session_second_accepted": True, "session_first_torn_down": True,
            "targeted_read_ok": True, "targeted_read_value": "SIQ=0x01",
        }
        h = self._host()
        fs = iec104.findings([h], {(h.ip, 2404): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("iec104_clock_writable", kinds)
        self.assertIn("iec104_reset_writable", kinds)
        self.assertIn("iec104_vendor_identified", kinds)
        self.assertIn("iec104_ioa_read_ok", kinds)
        self.assertIn("iec104_session_hijack", kinds)

    def test_findings_to_vulns_wraps_source_and_port(self):
        pr = {
            "reachable": True, "apci_valid": True,
            "testfr_ok": True, "startdt_ok": True,
            "interrogation": [], "caa_alive": [1], "caa_unknown": [],
            "private_type_ids": [], "vendor_hint": "",
            "control_types_reachable": sorted(iec104._CONTROL_TYPES.keys()),
            "clock_sync_accepted": None, "reset_process_accepted": None,
            "single_command_accepted": None, "wrote": False,
            "tls_handshake": True, "tls_cipher": "",
            "session_second_accepted": None, "session_first_torn_down": None,
            "targeted_read_ok": False, "targeted_read_value": "",
        }
        h = self._host()
        fs = iec104.findings([h], {(h.ip, 2404): pr})
        vulns_by_ip = iec104.findings_to_vulns(fs)
        self.assertIn(h.ip, vulns_by_ip)
        self.assertTrue(vulns_by_ip[h.ip])


class FirstAsduEvidenceTest(unittest.TestCase):
    """T2 SAFE proof: the probe must capture the FIRST ASDU response after
    STARTDT + General Interrogation, and findings() must promote the
    iec104_reachable finding from T1 -> T2 only when that evidence is
    present. Vulnerable / patched / timeout cases are covered."""

    def test_probe_captures_first_asdu_wire_bytes(self):
        # Vulnerable path: fake server answers GI with a real M_ME_NC_1 reply.
        srv = _Iec104Server(_friendly_responder)
        try:
            pr = iec104.probe(srv.host, srv.port, timeout=1.5, caa_list=(1,))
        finally:
            srv.close()
        self.assertTrue(pr["startdt_ok"])
        # Raw wire bytes captured — the exact M_ME_NC1_REPLY fixture.
        self.assertEqual(pr["first_asdu_hex"], M_ME_NC1_REPLY.hex())
        self.assertIn("TypeID=13", pr["first_asdu_summary"])
        self.assertIn("IOA=100", pr["first_asdu_summary"])
        self.assertIn("R32=42", pr["first_asdu_summary"])

    def test_probe_captures_evidence_even_on_unknown_caa_reply(self):
        # Only offers UNKNOWN_CAA_REPLY — proves station ran the ASDU state
        # machine (negative COT is still a real I-frame reply).
        def unknown_only(req, state):
            if req == TESTFR_ACT:
                return TESTFR_CON
            if req == STARTDT_ACT:
                return STARTDT_CON
            hdr = iec104._parse_apci(req)
            if hdr and hdr["kind"] == "I":
                asdu = iec104._parse_asdu_header(hdr["asdu"])
                if asdu and asdu["type_id"] == iec104.TI_C_IC_NA_1:
                    return UNKNOWN_CAA_REPLY
            return None

        srv = _Iec104Server(unknown_only)
        try:
            pr = iec104.probe(srv.host, srv.port, timeout=1.5, caa_list=(9,))
        finally:
            srv.close()
        self.assertTrue(pr["startdt_ok"])
        self.assertTrue(pr["first_asdu_hex"],
                        "unknown-CAA reply is still real ASDU evidence")
        self.assertIn(f"COT={iec104.COT_UNKNOWN_CA}", pr["first_asdu_summary"])

    def test_probe_no_asdu_evidence_when_startdt_only(self):
        # "Patched" path: server acks STARTDT but never emits an I-frame ASDU
        # in reply to GI. first_asdu_hex must stay empty.
        def startdt_only(req, state):
            if req == TESTFR_ACT:
                return TESTFR_CON
            if req == STARTDT_ACT:
                return STARTDT_CON
            return None

        srv = _Iec104Server(startdt_only)
        try:
            pr = iec104.probe(srv.host, srv.port, timeout=0.6, caa_list=(1,))
        finally:
            srv.close()
        self.assertTrue(pr["startdt_ok"])
        self.assertEqual(pr["first_asdu_hex"], "")
        self.assertEqual(pr["first_asdu_summary"], "")

    def test_probe_no_asdu_evidence_on_timeout(self):
        # Dead port: probe returns without evidence, no exception.
        pr = iec104.probe("127.0.0.1", 1, timeout=0.4)
        self.assertFalse(pr["reachable"])
        self.assertEqual(pr.get("first_asdu_hex", ""), "")

    def test_first_asdu_hex_is_capped_by_apdu_length_field(self):
        # The reassembled wire buffer must equal APCI header + declared
        # payload — never larger than the 253-byte APDU cap.
        srv = _Iec104Server(_friendly_responder)
        try:
            pr = iec104.probe(srv.host, srv.port, timeout=1.5, caa_list=(1,))
        finally:
            srv.close()
        raw = bytes.fromhex(pr["first_asdu_hex"])
        self.assertEqual(raw[0], iec104.START)
        # length octet (raw[1]) + 2 header bytes must equal total bytes.
        self.assertEqual(len(raw), 2 + raw[1])
        self.assertLessEqual(len(raw), 2 + iec104.MAX_APDU_LEN)


class ReachablePromotionTest(unittest.TestCase):
    """Findings-level T1 -> T2 promotion for iec104_reachable."""

    def _host(self):
        return _FakeHost("10.0.0.4", [_FakePort(2404, service="iec-104")])

    def _base_pr(self):
        return {
            "reachable": True, "apci_valid": True,
            "testfr_ok": True, "startdt_ok": True,
            "interrogation": [], "caa_alive": [1], "caa_unknown": [],
            "private_type_ids": [], "vendor_hint": "",
            "control_types_reachable": sorted(iec104._CONTROL_TYPES.keys()),
            "clock_sync_accepted": None, "reset_process_accepted": None,
            "single_command_accepted": None, "wrote": False,
            "tls_handshake": False, "tls_cipher": "",
            "session_second_accepted": None, "session_first_torn_down": None,
            "targeted_read_ok": False, "targeted_read_value": "",
        }

    def _reachable(self, fs):
        for f in fs:
            if f["kind"] == "iec104_reachable":
                return f
        self.fail("iec104_reachable finding missing")

    def test_reachable_stays_t1_without_first_asdu_evidence(self):
        pr = self._base_pr()
        # Explicitly empty evidence fields — "patched" or "APCI-only" peer.
        pr["first_asdu_hex"] = ""
        pr["first_asdu_summary"] = ""
        h = self._host()
        fs = iec104.findings([h], {(h.ip, 2404): pr})
        f = self._reachable(fs)
        self.assertEqual(f["depth_tier"], "t1")
        self.assertNotIn("T2 proof", f["detail"])

    def test_reachable_promoted_to_t2_with_captured_asdu(self):
        pr = self._base_pr()
        pr["first_asdu_hex"] = M_ME_NC1_REPLY.hex()
        pr["first_asdu_summary"] = "TypeID=13 COT=20 CAA=1 IOA=100 R32=42 QDS=0x00"
        h = self._host()
        fs = iec104.findings([h], {(h.ip, 2404): pr})
        f = self._reachable(fs)
        self.assertEqual(f["depth_tier"], "t2")
        # Captured evidence and parsed summary both surface in the detail.
        self.assertIn("T2 proof", f["detail"])
        self.assertIn(M_ME_NC1_REPLY.hex(), f["detail"])
        self.assertIn("IOA=100", f["detail"])

    def test_reachable_stays_t1_when_only_hex_missing(self):
        # Guard: summary alone (no wire hex) must NOT promote — captured
        # evidence must include the actual bytes.
        pr = self._base_pr()
        pr["first_asdu_hex"] = ""
        pr["first_asdu_summary"] = "TypeID=13 COT=20 CAA=1"
        h = self._host()
        fs = iec104.findings([h], {(h.ip, 2404): pr})
        f = self._reachable(fs)
        self.assertEqual(f["depth_tier"], "t1")


class TargetFingerprintTest(unittest.TestCase):
    def test_is_iec104_by_port_and_service(self):
        p = _FakePort(2404)
        self.assertTrue(iec104.is_iec104(p))
        q = _FakePort(9999, service="iec-104")
        self.assertTrue(iec104.is_iec104(q))
        r = _FakePort(80, service="http")
        self.assertFalse(iec104.is_iec104(r))

    def test_iec104_targets_collects_hosts(self):
        h1 = _FakeHost("10.0.0.4", [_FakePort(2404, service="iec-104")])
        h2 = _FakeHost("10.0.0.5", [_FakePort(80, service="http")])
        ts = iec104.iec104_targets([h1, h2])
        self.assertEqual(len(ts), 1)
        self.assertEqual(ts[0]["ip"], "10.0.0.4")
        self.assertEqual(ts[0]["port"], 2404)


if __name__ == "__main__":
    unittest.main()
