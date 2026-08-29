"""Tests for recce.services.s7 — Siemens S7COMM / ISO-TSAP probe.

Response fixtures are hand-assembled from the RFC 1006 (TPKT), ITU-T X.224
(COTP) and S7COMM (Wireshark packet-s7comm.c) protocol references — NOT by
calling the module's own encoders. A local TCP server replays them in
sequence per socket connect.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import s7
from recce.core.models import Host, Port


# ------------------------------------------------------------------ fixtures

# COTP Connection Confirm (0xD0). Wire layout matches ITU-T X.224 §13.4:
#   TPKT: 03 00 <len:2>
#   COTP: LI TPDU-code=D0 dst-ref src-ref class-option [+variable params]
# 22-byte frame with echoed TSAP variables — the same shape a real S7-300
# CPU sends back in Wireshark captures on port 102/tcp.
_CC_D0 = bytes.fromhex(
    "0300001611d0"                          # TPKT len=22, LI=17, TPDU=CC
    "0001" "0000" "00"                     # dst-ref, src-ref, class
    "c0010a"                               # TPDU size = 1024
    "c1020100"                             # src TSAP (echo)
    "c2020102"                             # dst TSAP (echo)
)


def _tpkt(payload):
    return b"\x03\x00" + struct.pack(">H", 4 + len(payload)) + payload


def _cotp_dt(payload):
    return b"\x02\xf0\x80" + payload


def _s7_ackdata(pdu_ref, param, data):
    """Classic S7COMM Ack_Data (ROSCTR=3) — 12-byte header including the
    2-byte err_class/err_code trailer. Assembled from the protocol reference,
    NOT from s7._s7_frame."""
    return (b"\x32\x03\x00\x00"
            + struct.pack(">H", pdu_ref)
            + struct.pack(">HH", len(param), len(data))
            + b"\x00\x00"                           # err_class, err_code
            + param + data)


def _szl_response_body(szl_id, szl_index, records, record_size):
    """SZL response data body: FF 09 <len> <szl_id> <idx> <part_len> <cnt>
    + records. Layout is from the Siemens S7-300/400 System Software
    Reference Manual §SZL."""
    part_count = len(records)
    body = b"".join(records)
    inner_len = 4 + 4 + len(body)              # id+idx + partlen+cnt + records
    return (b"\xff\x09" + struct.pack(">H", inner_len)
            + struct.pack(">HH", szl_id, szl_index)
            + struct.pack(">HH", record_size, part_count)
            + body)


def _setup_comm_ack(pdu_ref):
    """Ack_Data for Setup Communication (function 0xF0). Parameter echoes
    F0 00 with negotiated max amq / PDU size."""
    param = b"\xf0\x00\x00\x01\x00\x01\x03\xc0"
    return _tpkt(_cotp_dt(_s7_ackdata(pdu_ref, param, b"")))


def _szl_ack(pdu_ref, szl_id, szl_index, records, record_size):
    """Ack_Data for a UserData READ_SZL. Response parameter shape from
    Wireshark packet-s7comm.c: 00 01 12 08 12 84 01 01 00 00 00 00."""
    param = b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00"
    data = _szl_response_body(szl_id, szl_index, records, record_size)
    # Note: UserData response uses ROSCTR=7, but we mirror the shape recce
    # tolerates — ACKDATA framing exercises the header path.
    return _tpkt(_cotp_dt(_userdata_frame(pdu_ref, param, data)))


def _userdata_frame(pdu_ref, param, data):
    """S7COMM UserData response (ROSCTR=7) — 10-byte header (no err trailer)."""
    return (b"\x32\x07\x00\x00"
            + struct.pack(">H", pdu_ref)
            + struct.pack(">HH", len(param), len(data))
            + param + data)


def _read_var_ok_ack(pdu_ref):
    """Function 0x04 (Read Var) Ack_Data — 1-byte read, return_code 0xFF."""
    param = b"\x04\x01"
    data = b"\xff\x04\x00\x08" + b"\x00"     # return=OK, transport=BYTE, len=8 bits, one byte
    return _tpkt(_cotp_dt(_s7_ackdata(pdu_ref, param, data)))


def _block_list_ack(pdu_ref):
    """UserData block list response — records of {block_type_ascii:2, count:2}."""
    param = b"\x00\x01\x12\x08\x12\x84\x01\x01\x00\x00\x00\x00"
    records = (b"OB" + struct.pack(">H", 4)
               + b"DB" + struct.pack(">H", 12)
               + b"FC" + struct.pack(">H", 3))
    data = b"\xff\x09" + struct.pack(">H", 4 + len(records)) + records
    return _tpkt(_cotp_dt(_userdata_frame(pdu_ref, param, data)))


def _module_id_records():
    """SZL 0x0011: index(2) MLFB(20) BGTyp(2) Ausbg1(2) Ausbg2(2) = 28 bytes."""
    mlfb = b"6ES7 315-2EH14-0AB0 "                 # exactly 20 bytes
    assert len(mlfb) == 20
    return [
        struct.pack(">H", 0x0001) + mlfb
        + struct.pack(">HHH", 0x0000, 0x0104, 0x0305),   # HW 0104, FW V3.5
    ]


def _component_records():
    """SZL 0x001C: index(2) string(32) = 34 bytes."""
    def rec(idx, text):
        s = text.encode("ascii").ljust(32, b"\x00")
        return struct.pack(">H", idx) + s
    return [
        rec(1, "PLC_LINE_A"),
        rec(2, "CPU 315-2 PN/DP"),
        rec(3, "Boiler House 3"),
        rec(5, "S C-C7UM12345678"),
        rec(8, "Room B-204"),
    ]


def _protection_records():
    """SZL 0x0232 idx 4 — protection level = 1 (no password)."""
    # index(2) reserved(2) level(1) mode(1) reserved(2..) — 8-byte record.
    return [struct.pack(">H", 0x0004) + b"\x00\x00" + b"\x01\x01" + b"\x00\x00"]


def _putget_records():
    """SZL 0x0131 idx 3 — record presence = PUT/GET communication capability."""
    return [struct.pack(">H", 0x0003) + b"\x00\x00" + b"\x00\x00"]


def _legacy_password_record():
    """SZL 0x0132 idx 3 — 8-byte obfuscated password block. The values here
    are the SIMATIC obfuscation of 'Test' (V0.5 tool reference)."""
    # Deobfuscation: out[0] = raw[0]^0x55^0x21; out[1] = raw[1]^0x55^0x36;
    # out[i>=2] = raw[i]^0x55^out[i-2]. We invert to build raw bytes for
    # cleartext b"TestPass".
    clear = b"TestPass"
    raw = bytearray(8)
    raw[0] = clear[0] ^ 0x55 ^ 0x21
    raw[1] = clear[1] ^ 0x55 ^ 0x36
    for i in range(2, 8):
        raw[i] = clear[i] ^ 0x55 ^ clear[i - 2]
    return [struct.pack(">H", 0x0003) + bytes(raw)]


# ------------------------------------------------------------------ server

class _S7Server:
    """Replay canned bytes per request. Each new socket connect gets the
    scripted sequence; the request bytes are ignored (we've assembled
    responses to match the fixed request order recce sends)."""

    def __init__(self, script, per_connect=None):
        # `script` = list-of-bytes replayed in order. `per_connect` = optional
        # dict of {seen_connections: [scripts]} for the CR/CC enum phase.
        self._script = script
        self._per_connect = per_connect or []
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._connects = 0
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop:
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except (socket.timeout, OSError):
                continue
            idx = self._connects
            self._connects += 1
            if self._per_connect and idx < len(self._per_connect):
                script = self._per_connect[idx]
            else:
                script = self._script
            try:
                for resp in script:
                    if not resp:
                        # Empty entry = close after read (simulates CR refusal).
                        try:
                            conn.recv(1024)
                        except OSError:
                            pass
                        break
                    try:
                        conn.recv(1024)
                    except OSError:
                        break
                    conn.sendall(resp)
            except OSError:
                pass
            finally:
                try: conn.close()
                except OSError: pass

    def close(self):
        self._stop = True
        try: self._srv.close()
        except OSError: pass


# ------------------------------------------------------------------ tests

class WireBuilderTest(unittest.TestCase):
    def test_tpkt_length_field(self):
        # RFC 1006 §6: length includes the TPKT header itself.
        pkt = s7._tpkt(b"\x00\x00")
        self.assertEqual(pkt[:2], b"\x03\x00")
        self.assertEqual(struct.unpack(">H", pkt[2:4])[0], 6)

    def test_cotp_cr_shape(self):
        # LI is the length of the header not including LI itself.
        cr = s7._cotp_cr(0x0100, 0x0102)
        self.assertEqual(cr[0], len(cr) - 1)
        self.assertEqual(cr[1], 0xE0)                    # CR TPDU

    def test_szl_request_parses_back(self):
        req = s7._build_szl_request(0x0009, 0x0011, 0x0001)
        parsed = s7._parse_tpkt_cotp(req)
        self.assertIsNotNone(parsed)
        cotp, payload = parsed
        self.assertEqual(cotp, 0xF0)                     # DT
        self.assertEqual(payload[0], 0x32)               # classic S7 opcode

    def test_parse_cc_accepts_D0(self):
        self.assertTrue(s7._parse_cc(_CC_D0))

    def test_parse_cc_rejects_bad_frame(self):
        self.assertFalse(s7._parse_cc(b"\x00\x00\x00\x00"))

    def test_parse_szl_records_extracts_records(self):
        recs = _module_id_records()
        body = _szl_response_body(0x0011, 0x0000, recs, 28)
        _plen, _cnt, out = s7._parse_szl_records(body)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0], recs[0])

    def test_parse_module_id_extracts_mlfb(self):
        recs = _module_id_records()
        mi = s7._parse_module_id(recs)
        self.assertIn("6ES7 315-2EH14-0AB0", mi["order_code"])
        self.assertTrue(mi["fw_version"].startswith("V"))

    def test_parse_component_id_extracts_plant(self):
        ci = s7._parse_component_id(_component_records())
        self.assertEqual(ci["plc_name"], "PLC_LINE_A")
        self.assertEqual(ci["plant_designation"], "Boiler House 3")
        self.assertEqual(ci["location"], "Room B-204")

    def test_parse_protection_level_one(self):
        p = s7._parse_protection_level(_protection_records())
        self.assertEqual(p["level"], 1)

    def test_parse_put_get_record_present(self):
        p = s7._parse_put_get(_putget_records())
        self.assertTrue(p["record_seen"])
        self.assertTrue(p["put_get_enabled"])

    def test_parse_block_list_records(self):
        # data body starting FF 09 <len> then records.
        records = (b"OB" + struct.pack(">H", 4)
                   + b"DB" + struct.pack(">H", 12))
        data = b"\xff\x09" + struct.pack(">H", 4 + len(records)) + records
        out = s7._parse_block_list(b"\x00\x01\x12\x08", data)
        self.assertEqual(out.get("OB"), 4)
        self.assertEqual(out.get("DB"), 12)

    def test_parse_read_var_ok_true(self):
        param = b"\x04\x01"
        data = b"\xff\x04\x00\x08\x00"
        self.assertTrue(s7._parse_read_var_ok(param, data))

    def test_parse_read_var_ok_false_on_error_code(self):
        param = b"\x04\x01"
        data = b"\x0a\x00\x00\x00\x00"                   # 0x0A = access denied
        self.assertFalse(s7._parse_read_var_ok(param, data))

    def test_deobfuscate_roundtrip(self):
        clear = b"Password"
        raw = bytearray(8)
        raw[0] = clear[0] ^ 0x55 ^ 0x21
        raw[1] = clear[1] ^ 0x55 ^ 0x36
        for i in range(2, 8):
            raw[i] = clear[i] ^ 0x55 ^ clear[i - 2]
        self.assertEqual(s7._deobfuscate_s7_password(bytes(raw)), "Password")

    def test_cve_fingerprint_s7_1500(self):
        matches = s7._cve_fingerprint("6ES7 516-3AN01-0AB0", "V2.9")
        cves = [m["cve"] for m in matches]
        self.assertIn("CVE-2022-38465", cves)

    def test_cve_fingerprint_s7_300(self):
        matches = s7._cve_fingerprint("6ES7 315-2EH14-0AB0", "V3.2")
        cves = [m["cve"] for m in matches]
        self.assertIn("CVE-2015-2177", cves)
        self.assertIn("CVE-2016-9159", cves)

    def test_is_s7_predicate(self):
        self.assertTrue(s7.is_s7(Port(portid=102, service="iso-tsap")))
        self.assertTrue(s7.is_s7(Port(portid=102, service="unknown")))
        self.assertTrue(s7.is_s7(Port(portid=5000, service="s7comm")))
        self.assertFalse(s7.is_s7(Port(portid=80, service="http")))


class ProbeEndToEndTest(unittest.TestCase):
    def test_full_probe_extracts_fingerprint(self):
        # Enumerate phase closes each socket after the CR/CC exchange, so
        # every TSAP attempt is its own connection. The session phase then
        # opens ONE more connection and pipelines: CR/CC, setup comm,
        # SZL 0x0011, SZL 0x001C, SZL 0x0232, SZL 0x0131, SZL 0x0132,
        # block list, read var.
        cr_confirm = [_CC_D0]                            # single reply per connect
        per_connect = []
        # Six TSAPs in _DEFAULT_TSAPS: give CC on the first, refuse the rest
        # (close without reply) so `dst_tsap` is deterministic.
        per_connect.append(cr_confirm)                    # TSAP 0x0102 accepts
        for _ in range(len(s7._DEFAULT_TSAPS) - 1):
            per_connect.append([b""])                    # refuse
        # Working-session connect:
        session = [
            _CC_D0,                                       # CR/CC
            _setup_comm_ack(1),                           # setup comm ack
            _szl_ack(2, 0x0011, 0x0000, _module_id_records(), 28),
            _szl_ack(3, 0x001C, 0x0000, _component_records(), 34),
            _szl_ack(4, 0x0232, 0x0004, _protection_records(), 8),
            _szl_ack(5, 0x0131, 0x0003, _putget_records(), 6),
            _szl_ack(6, 0x0132, 0x0003, _legacy_password_record(), 10),
            _block_list_ack(7),
            _read_var_ok_ack(8),
        ]
        per_connect.append(session)
        srv = _S7Server(script=session, per_connect=per_connect)
        try:
            pr = s7.probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()

        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["cotp_reachable"])
        self.assertTrue(pr["s7_stack"])
        self.assertFalse(pr["s7_plus"])
        self.assertEqual(pr["dst_tsap"], 0x0102)
        self.assertIn("6ES7 315-2EH14-0AB0", pr["order_code"])
        self.assertTrue(pr["fw_version"].startswith("V"))
        self.assertEqual(pr["component"].get("plant_designation"), "Boiler House 3")
        self.assertEqual(pr["protection_level"], 1)
        self.assertTrue(pr["put_get_enabled"])
        self.assertTrue(pr["read_var_ok"])
        self.assertEqual(pr["blocks"].get("OB"), 4)
        leg = pr["legacy_password_readout"]
        self.assertIsNotNone(leg)
        self.assertEqual(leg["cleartext_guess"], "TestPass")
        # CVE fingerprint on S7-300 order code:
        cves = [m["cve"] for m in pr["cve_matches"]]
        self.assertIn("CVE-2015-2177", cves)
        self.assertIn("CVE-2016-9159", cves)

    def test_dead_port(self):
        pr = s7.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(pr["reachable"])
        self.assertFalse(pr["cotp_reachable"])

    def test_non_s7_service_not_flagged(self):
        # Server sends garbage — probe must not raise or flag it.
        per = [[b"HTTP/1.1 400 Bad Request\r\n\r\n"]] * (len(s7._DEFAULT_TSAPS) + 1)
        srv = _S7Server(script=per[0], per_connect=per)
        try:
            pr = s7.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertFalse(pr["reachable"])

    def test_s7_plus_detected(self):
        # S7-1500 answers Setup Communication with S7COMM-PLUS opcode 0x72.
        plus_body = _tpkt(_cotp_dt(b"\x72\x01\x00\x00\x00\x00\x00\x00"))
        session = [_CC_D0, plus_body]
        per = [_CC_D0 and [_CC_D0]]                       # first CR/CC accepts
        per += [[b""]] * (len(s7._DEFAULT_TSAPS) - 1)     # rest refuse
        per.append(session)
        srv = _S7Server(script=session, per_connect=per)
        try:
            pr = s7.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["cotp_reachable"])
        self.assertTrue(pr["s7_plus"])
        self.assertFalse(pr["s7_stack"])


class FindingsTest(unittest.TestCase):
    def _host(self):
        return Host(ip="10.0.0.5",
                    ports=[Port(portid=102, service="iso-tsap")])

    def test_findings_emit_segmentation_and_fingerprint(self):
        h = self._host()
        probes = {("10.0.0.5", 102): {
            "reachable": True, "cotp_reachable": True, "s7_stack": True,
            "s7_plus": False, "dst_tsap": 0x0102,
            "tsaps_confirmed": [0x0102, 0x0201],
            "order_code": "6ES7 315-2EH14-0AB0", "fw_version": "V3.2",
            "hw_version": "0104",
            "component": {"plant_designation": "Boiler House 3",
                          "location": "Room B-204"},
            "protection_level": 1, "password_set": False,
            "put_get_enabled": True, "put_get_seen": True,
            "read_var_ok": True, "blocks": {"OB": 4, "DB": 12},
            "legacy_password_readout": {"obfuscated_hex": "00" * 8,
                                        "cleartext_guess": "TestPass"},
            "cve_matches": [{"cve": "CVE-2016-9159", "family": "S7-300",
                             "note": "password readout"}],
        }}
        fs = s7.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("s7_reachable", kinds)
        self.assertIn("s7_module_identification", kinds)
        self.assertIn("s7_component_identification", kinds)
        self.assertIn("s7_put_get_enabled", kinds)
        self.assertIn("s7_read_var_ok", kinds)
        self.assertIn("s7_protection_level", kinds)
        self.assertIn("s7_legacy_password_readout", kinds)
        self.assertIn("s7_stop_start_possible", kinds)
        self.assertIn("s7_block_list", kinds)
        self.assertIn("s7_firmware_cve", kinds)
        self.assertIn("s7_tsap_enumerated", kinds)
        # Every finding has severity + stable kind slug (dedup).
        for f in fs:
            self.assertIn(f["severity"],
                          ("info", "low", "medium", "high", "critical"))
            self.assertTrue(f["kind"])

    def test_findings_empty_when_no_probe(self):
        h = self._host()
        self.assertEqual(s7.findings([h], {}), [])

    def test_analyze_stack_shape(self):
        # Passive path (active=False): no probe traffic, empty findings.
        h = self._host()
        out = s7.analyze([h], active=False)
        self.assertIn("targets", out)
        self.assertIn("findings", out)
        self.assertIn("runbooks", out)
        self.assertEqual(len(out["targets"]), 1)
        self.assertEqual(out["targets"][0]["ip"], "10.0.0.5")

    def test_findings_to_vulns_returns_dict(self):
        fs = [{"severity": "critical", "title": "t", "target": "10.0.0.5:102",
               "detail": "d", "tool": "snap7", "command": "c",
               "remediation": "r", "cwes": ["CWE-306"], "kind": "s7_reachable"}]
        v = s7.findings_to_vulns(fs)
        self.assertIsInstance(v, dict)
        self.assertIn("10.0.0.5", v)


if __name__ == "__main__":
    unittest.main()
