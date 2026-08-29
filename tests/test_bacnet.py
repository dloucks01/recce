"""Tests for recce.services.bacnet — BACnet/IP probe.

Fixtures are raw hex byte sequences copied from ASHRAE 135 Annex J packet
diagrams and public Wireshark captures — NOT built by calling the module's
own encoders. A tiny UDP responder plays them back on 127.0.0.1.
"""
from __future__ import annotations

import socket
import threading
import time
import unittest

from recce.core.models import Host, Port
from recce.services import bacnet


# --- raw wire fixtures ---------------------------------------------------------
# Every constant below is bytes.fromhex(...) of a real BACnet/IP packet as it
# appears on the wire. Comments trace the byte layout to ASHRAE 135 clauses.

# I-Am reply for device instance 260, vendor 66, max-APDU 1476, seg=3.
# BVLC 81 0a 00 14 : Original-Unicast-NPDU, total length 0x14 (20 bytes)
# NPDU 01 00       : version 1, control 0
# APDU 10 00       : Unconfirmed-Request PDU, service 0 (I-Am)
#      c4 02 00 01 04 : app tag 12 (object-id) len 4, device #260
#      22 05 c4       : app tag 2 (unsigned) len 2, max-APDU 1476
#      91 03          : app tag 9 (enum) len 1, segmentation 3
#      21 42          : app tag 2 (unsigned) len 1, vendor-id 66
_I_AM_BYTES = bytes.fromhex(
    "810a00140100" "1000c4020001042205c491032142")

# ReadProperty-Ack for Device object-name (property 77) = "TEST-DEV".
# APDU: 30 01 0c 0c 02 00 01 04 19 4d 3e 75 09 00 54 45 53 54 2d 44 45 56 3f
_READ_OBJECT_NAME_ACK = bytes.fromhex(
    "810a001d0100" "30010c0c02000104194d3e750900544553542d4445563f")

# ReadProperty-Ack for Device vendor-name (property 121) = "Acme".
_READ_VENDOR_NAME_ACK = bytes.fromhex(
    "810a00190100" "30020c0c020001041979" "3e7505004163" "6d65" "3f")

# ReadProperty-Ack Device model-name (property 70) = "M1".
# Char string TLV: 73 00 4d 31 (tag 7 embedded length 3, encoding + "M1").
_READ_MODEL_NAME_ACK = bytes.fromhex(
    "810a00160100" "30030c0c020001041946" "3e" "73004d31" "3f")

# ReadProperty-Ack Device firmware-revision (property 44) = "10".
_READ_FIRMWARE_ACK = bytes.fromhex(
    "810a00160100" "30040c0c02000104192c" "3e" "73003130" "3f")

# ReadProperty-Ack for property 62 (max-APDU) = 1476 unsigned.
_READ_MAX_APDU_ACK = bytes.fromhex(
    "810a00150100" "30050c0c02000104193e" "3e" "2205c4" "3f")

# ReadProperty-Ack property 107 (segmentation) = 3 enumerated.
_READ_SEG_ACK = bytes.fromhex(
    "810a00140100" "30060c0c02000104196b" "3e" "9103" "3f")

# ReadProperty-Ack for Device.object-list index 0 = 2 (unsigned count).
_READ_OBJECT_LIST_COUNT_ACK = bytes.fromhex(
    "810a00160100" "30070c0c02000104194c" "2900" "3e" "2102" "3f")

# ReadProperty-Ack for Device.object-list index 1 = objectid (Device,260).
_READ_OBJECT_LIST_1_ACK = bytes.fromhex(
    "810a00190100" "30080c0c02000104194c" "2901" "3e" "c402000104" "3f")

# ReadProperty-Ack for Device.object-list index 2 = objectid (AnalogValue,7).
# type 2 << 22 | 7 = 0x00800007
_READ_OBJECT_LIST_2_ACK = bytes.fromhex(
    "810a00190100" "30090c0c02000104194c" "2902" "3e" "c400800007" "3f")

# ReadProperty-Ack AV#7 present-value (property 85) = 72.5 real.
# 72.5 as IEEE-754 big-endian = 0x42910000
_READ_AV_PRESENT_VALUE_ACK = bytes.fromhex(
    "810a00170100" "300a0c0c008000071955" "3e" "4442910000" "3f")

# SimpleAck for WriteProperty (service 0x0f), invoke-id 0x0b
# BVLC 81 0a 00 09
# NPDU 01 00
# APDU 20 0b 0f
_WRITE_PROPERTY_ACK = bytes.fromhex("810a0009" "0100" "200b0f")

# SimpleAck for DeviceCommunicationControl (0x11), invoke-id 0x0c
_DCC_ACK = bytes.fromhex("810a0009" "0100" "200c11")

# SimpleAck for ReinitializeDevice (0x14), invoke-id 0x0d
_REINIT_ACK = bytes.fromhex("810a0009" "0100" "200d14")

# Read-BDT-Ack (BVLC 0x03): two entries.
#   entry: ip(4) port(2) mask(4) = 10 bytes
#   192.168.1.10:47808 mask 255.255.255.255
#   10.0.0.1:47808 mask 255.255.255.0
# BVLC length 4 + 20 = 24 = 0x18
_READ_BDT_ACK = bytes.fromhex(
    "8103" "0018"
    "c0a8010a" "bac0" "ffffffff"
    "0a000001" "bac0" "ffffff00")

# Read-FDT-Ack (BVLC 0x07): one entry.
#   ip(4) port(2) ttl(2) remaining(2) = 10 bytes
# BVLC length 4 + 10 = 14 = 0x0e
_READ_FDT_ACK = bytes.fromhex(
    "8107" "000e"
    "0a010203" "bac0" "003c" "0028")

# BVLC-Result success: BVLC 81 00 00 06 00 00
_BVLC_RESULT_OK = bytes.fromhex("810000060000")

# BVLC-Result failure (Register-Foreign-Device NAK = 0x0030)
_BVLC_RESULT_FAIL = bytes.fromhex("810000060030")

# AtomicReadFile-Ack (Complex-ACK, service 0x06), invoke-id 0x22
# BVLC 81 0a 00 <len>, NPDU 01 00, APDU:
#   30 22 06       Complex-ACK: PDU type + invoke-id + service ACK choice
#   10             app tag 1 (boolean) LVT 0 = false (end-of-file)
#   0e             opening ctx tag 0
#   31 00          app tag 3 (signed int) len 1 val 0 (offset)
#   65 04 de ad be ef   app tag 6 (octet string) ext len 4 = deadbeef
#   0f             closing ctx tag 0
_ATOMIC_READ_FILE_ACK = bytes.fromhex(
    "810a0014" "0100" "302206" "10" "0e" "3100" "6504deadbeef" "0f")


# --- fake UDP server -----------------------------------------------------------


class _BacnetServer:
    """UDP responder. `responder(req)` returns bytes to send back — or a list
    of bytes for multiple replies (amplification), or None for silence."""

    def __init__(self, responder):
        self._respond = responder
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.settimeout(0.2)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                data, addr = self._srv.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                resp = self._respond(data)
            except Exception:
                resp = None
            if resp is None:
                continue
            if isinstance(resp, list):
                for r in resp:
                    try:
                        self._srv.sendto(r, addr)
                    except OSError:
                        pass
                    time.sleep(0.005)
            else:
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


# --- helpers -------------------------------------------------------------------


def _detect_request(pkt: bytes) -> str:
    """Classify an incoming request so the responder can pick the right canned
    reply. Reads bytes only — no imports from bacnet's encoders."""
    if len(pkt) < 4 or pkt[0] != 0x81:
        return "unknown"
    fn = pkt[1]
    if fn == 0x02:
        return "read-bdt"
    if fn == 0x05:
        return "register-fd"
    if fn == 0x06:
        return "read-fdt"
    if fn != 0x0a:
        return "unknown"
    # Original-Unicast — parse NPDU + APDU header.
    # NPDU is at least 2 bytes (version + control).
    apdu = pkt[6:] if len(pkt) > 6 else b""
    if not apdu:
        return "unknown"
    pdu_type = apdu[0] & 0xF0
    if pdu_type == 0x10 and len(apdu) >= 2 and apdu[1] == 0x08:
        return "who-is"
    if pdu_type == 0x00 and len(apdu) >= 4:
        svc = apdu[3]
        if svc == 0x0C:
            # ReadProperty — extract property id (context tag 1) to pick reply
            # apdu = [type, maxapdu, iid, svc, 0c, 4-byte-oid, 19, propid, ...]
            if len(apdu) >= 11 and apdu[4] == 0x0C and apdu[9] == 0x19:
                prop = apdu[10]
                idx = None
                if len(apdu) >= 13 and apdu[11] == 0x29:
                    idx = apdu[12]
                return f"read-property:{prop}:{idx}"
            return "read-property:unknown"
        if svc == 0x0F:
            return "write-property"
        if svc == 0x11:
            return "dcc"
        if svc == 0x14:
            return "reinit"
        if svc == 0x06:
            return "atomic-read-file"
    return "unknown"


def _rewrite_invoke_id(canned: bytes, request: bytes) -> bytes:
    """Copy the request's invoke-id into a canned response so parsers that
    match on it don't need per-request pre-baked fixtures."""
    if len(request) < 9 or request[6] & 0xF0 != 0x00:
        return canned
    iid = request[8]
    b = bytearray(canned)
    # APDU header starts at byte 6 (BVLC 4 + NPDU 2). Complex-ACK / Simple-ACK /
    # Error PDU carries invoke-id at APDU offset 1 -> absolute offset 7.
    if len(b) > 7:
        b[7] = iid
    return bytes(b)


# --- unit tests ----------------------------------------------------------------


class DecoderTest(unittest.TestCase):
    def test_parse_i_am(self):
        # Strip BVLC + NPDU to feed the APDU parser directly.
        apdu = _I_AM_BYTES[6:]
        info = bacnet._parse_i_am(apdu)
        self.assertEqual(info["device_instance"], 260)
        self.assertEqual(info["max_apdu"], 1476)
        self.assertEqual(info["segmentation"], 3)
        self.assertEqual(info["vendor_id"], 66)

    def test_parse_read_property_object_name(self):
        apdu = _READ_OBJECT_NAME_ACK[6:]
        ack = bacnet._parse_read_property_ack(apdu)
        self.assertEqual(ack["obj_type"], 8)
        self.assertEqual(ack["instance"], 260)
        self.assertEqual(ack["prop_id"], 77)
        self.assertEqual(ack["values"][0], ("string", "TEST-DEV"))

    def test_bvlc_read_bdt_parse(self):
        p = bacnet._parse_bvlc(_READ_BDT_ACK)
        self.assertIsNotNone(p)
        fn, body = p
        self.assertEqual(fn, 0x03)
        # 2 entries, 10 bytes each
        self.assertEqual(len(body), 20)

    def test_error_parse(self):
        # Manually assemble an Error PDU: [50 iid svc][91 <class>][91 <code>]
        apdu = bytes.fromhex("500114" "9101" "9105")
        err = bacnet._parse_error(apdu)
        self.assertEqual(err["kind"], "error")
        self.assertEqual(err["class"], 1)
        self.assertEqual(err["code"], 5)


class WhoIsTest(unittest.TestCase):
    def test_who_is_returns_device_identity(self):
        def responder(req):
            if _detect_request(req) == "who-is":
                return _I_AM_BYTES
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet.who_is(srv.host, srv.port, timeout=1.5)
        finally:
            srv.close()
        self.assertEqual(r["device_instance"], 260)
        self.assertEqual(r["vendor_id"], 66)


class ReadPropertyTest(unittest.TestCase):
    def test_read_object_name_via_socket(self):
        def responder(req):
            kind = _detect_request(req)
            if kind == "read-property:77:None":
                return _rewrite_invoke_id(_READ_OBJECT_NAME_ACK, req)
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet.read_property(srv.host, srv.port, 260, 8, 260, 77,
                                     timeout=1.5)
        finally:
            srv.close()
        self.assertEqual(r["values"][0], ("string", "TEST-DEV"))


class BbmdTest(unittest.TestCase):
    def test_read_bdt(self):
        def responder(req):
            if _detect_request(req) == "read-bdt":
                return _READ_BDT_ACK
            return None
        srv = _BacnetServer(responder)
        try:
            entries = bacnet._read_bdt(srv.host, srv.port, timeout=1.5)
        finally:
            srv.close()
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["ip"], "192.168.1.10")
        self.assertEqual(entries[0]["port"], 47808)
        self.assertEqual(entries[1]["ip"], "10.0.0.1")

    def test_read_fdt(self):
        def responder(req):
            if _detect_request(req) == "read-fdt":
                return _READ_FDT_ACK
            return None
        srv = _BacnetServer(responder)
        try:
            entries = bacnet._read_fdt(srv.host, srv.port, timeout=1.5)
        finally:
            srv.close()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip"], "10.1.2.3")
        self.assertEqual(entries[0]["ttl"], 60)

    def test_register_foreign_device_accepted(self):
        def responder(req):
            if _detect_request(req) == "register-fd":
                return _BVLC_RESULT_OK
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet._register_foreign_device(srv.host, srv.port, ttl=60,
                                                timeout=1.5)
        finally:
            srv.close()
        self.assertTrue(r["accepted"])
        self.assertEqual(r["result_code"], 0)

    def test_register_foreign_device_refused(self):
        def responder(req):
            if _detect_request(req) == "register-fd":
                return _BVLC_RESULT_FAIL
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet._register_foreign_device(srv.host, srv.port, ttl=60,
                                                timeout=1.5)
        finally:
            srv.close()
        self.assertFalse(r["accepted"])


class AmplificationTest(unittest.TestCase):
    def test_who_is_amplification_counts_multiple_replies(self):
        # Server sends TWO I-Am replies to one Who-Is.
        def responder(req):
            if _detect_request(req) == "who-is":
                return [_I_AM_BYTES, _I_AM_BYTES]
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet._amplification_probe(srv.host, srv.port, timeout=0.6)
        finally:
            srv.close()
        self.assertGreaterEqual(r["reply_count"], 2)
        self.assertGreater(r["ratio"], 1.0)


class WritePropertyDryRunTest(unittest.TestCase):
    def test_readback_and_writeproperty_ack(self):
        def responder(req):
            kind = _detect_request(req)
            if kind == "read-property:85:None":
                return _rewrite_invoke_id(_READ_AV_PRESENT_VALUE_ACK, req)
            if kind == "write-property":
                return _rewrite_invoke_id(_WRITE_PROPERTY_ACK, req)
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet._write_property_dry_run(srv.host, srv.port, 260,
                                                bacnet._OBJ_ANALOG_VALUE,
                                                7, timeout=1.5)
        finally:
            srv.close()
        self.assertTrue(r["read_ok"])
        self.assertTrue(r["write_ack"])
        self.assertEqual(r["error"], "")


class DccTest(unittest.TestCase):
    def test_dcc_default_password_accepted(self):
        def responder(req):
            if _detect_request(req) == "dcc":
                return _rewrite_invoke_id(_DCC_ACK, req)
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet._dcc_probe(srv.host, srv.port, timeout=1.0)
        finally:
            srv.close()
        # First tried password is the empty string.
        self.assertEqual(r["accepted_password"], "")


class ReinitTest(unittest.TestCase):
    def test_reinit_ack_flags_unauth(self):
        def responder(req):
            if _detect_request(req) == "reinit":
                return _rewrite_invoke_id(_REINIT_ACK, req)
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet._reinitialize_probe(srv.host, srv.port, timeout=1.0)
        finally:
            srv.close()
        self.assertTrue(r["unauth_accepted"])


class AtomicReadFileTest(unittest.TestCase):
    def test_atomic_read_file_extracts_bytes(self):
        def responder(req):
            if _detect_request(req) == "atomic-read-file":
                return _rewrite_invoke_id(_ATOMIC_READ_FILE_ACK, req)
            return None
        srv = _BacnetServer(responder)
        try:
            r = bacnet._atomic_read_file(srv.host, srv.port, 1, timeout=1.0)
        finally:
            srv.close()
        self.assertEqual(r["bytes_hex"], "deadbeef")
        self.assertEqual(r["size"], 4)


class FullProbeTest(unittest.TestCase):
    def test_probe_full_walkthrough_emits_findings(self):
        def responder(req):
            kind = _detect_request(req)
            if kind == "who-is":
                return _I_AM_BYTES
            if kind == "read-property:77:None":
                return _rewrite_invoke_id(_READ_OBJECT_NAME_ACK, req)
            if kind == "read-property:121:None":
                return _rewrite_invoke_id(_READ_VENDOR_NAME_ACK, req)
            if kind == "read-property:70:None":
                return _rewrite_invoke_id(_READ_MODEL_NAME_ACK, req)
            if kind == "read-property:44:None":
                return _rewrite_invoke_id(_READ_FIRMWARE_ACK, req)
            if kind == "read-property:62:None":
                return _rewrite_invoke_id(_READ_MAX_APDU_ACK, req)
            if kind == "read-property:107:None":
                return _rewrite_invoke_id(_READ_SEG_ACK, req)
            if kind == "read-property:76:0":
                return _rewrite_invoke_id(_READ_OBJECT_LIST_COUNT_ACK, req)
            if kind == "read-property:76:1":
                return _rewrite_invoke_id(_READ_OBJECT_LIST_1_ACK, req)
            if kind == "read-property:76:2":
                return _rewrite_invoke_id(_READ_OBJECT_LIST_2_ACK, req)
            if kind == "read-property:85:None":
                return _rewrite_invoke_id(_READ_AV_PRESENT_VALUE_ACK, req)
            if kind == "read-bdt":
                return _READ_BDT_ACK
            if kind == "read-fdt":
                return _READ_FDT_ACK
            if kind == "register-fd":
                return _BVLC_RESULT_OK
            if kind == "write-property":
                return _rewrite_invoke_id(_WRITE_PROPERTY_ACK, req)
            if kind == "dcc":
                return _rewrite_invoke_id(_DCC_ACK, req)
            if kind == "reinit":
                return _rewrite_invoke_id(_REINIT_ACK, req)
            if kind == "atomic-read-file":
                return _rewrite_invoke_id(_ATOMIC_READ_FILE_ACK, req)
            return None
        srv = _BacnetServer(responder)
        try:
            pr = bacnet.probe(srv.host, srv.port, timeout=1.5)
        finally:
            srv.close()

        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["device_instance"], 260)
        self.assertEqual(pr["identity"]["object_name"], "TEST-DEV")
        self.assertEqual(pr["identity"]["vendor_name"], "Acme")
        self.assertEqual(pr["identity"]["model_name"], "M1")
        self.assertIn((bacnet._OBJ_ANALOG_VALUE, 7), pr["object_list"])
        self.assertEqual(len(pr["bdt"]), 2)
        self.assertEqual(len(pr["fdt"]), 1)
        self.assertTrue(pr["foreign_reg"]["accepted"])
        self.assertTrue(pr["write_dryrun"]["write_ack"])
        self.assertEqual(pr["dcc"]["accepted_password"], "")
        self.assertTrue(pr["reinit"]["unauth_accepted"])

        # Drive findings() with a host whose port matches.
        host = Host(ip=srv.host, ports=[Port(portid=srv.port, protocol="udp",
                                              state="open", service="bacnet")])
        fs = bacnet.findings([host], {(srv.host, srv.port): pr})
        kinds = {f["kind"] for f in fs}
        for expected in ("bacnet_reachable", "bacnet_device_identity",
                         "bacnet_object_inventory",
                         "bacnet_bbmd_topology_disclosure",
                         "bacnet_fdt_disclosure",
                         "bacnet_foreign_device_registration_permitted",
                         "bacnet_unauth_write", "bacnet_dcc_default_password",
                         "bacnet_reinitialize_permitted",
                         "bacnet_stack_fingerprint"):
            self.assertIn(expected, kinds, f"missing {expected}: got {kinds}")


class SCDowngradeTest(unittest.TestCase):
    def test_bacnet_sc_downgrade_flagged_when_both_ports_open(self):
        host = Host(ip="10.0.0.1", ports=[
            Port(portid=47808, protocol="udp", state="open", service="bacnet"),
            Port(portid=47820, protocol="tcp", state="open", service="bacnet-sc"),
        ])
        probes = {("10.0.0.1", 47808): {
            "reachable": True, "device_instance": 1, "identity": {},
            "object_list": [], "bdt": [], "fdt": [], "foreign_reg": None,
            "amplification": None, "write_dryrun": None, "dcc": None,
            "reinit": None, "atomic_files": []}}
        fs = bacnet.findings([host], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("bacnet_sc_downgrade", kinds)


class BacnetTargetsTest(unittest.TestCase):
    def test_is_bacnet_matches_port_and_service(self):
        self.assertTrue(bacnet.is_bacnet(Port(portid=47808, protocol="udp")))
        self.assertTrue(bacnet.is_bacnet(Port(portid=47812, protocol="udp")))
        self.assertTrue(bacnet.is_bacnet(Port(portid=9999, service="bacnet")))
        self.assertFalse(bacnet.is_bacnet(Port(portid=161, service="snmp")))

    def test_findings_to_vulns_shape(self):
        host = Host(ip="10.0.0.1", ports=[Port(portid=47808, protocol="udp",
                                                state="open", service="bacnet")])
        probes = {("10.0.0.1", 47808): {
            "reachable": True, "device_instance": 3, "identity": {},
            "object_list": [], "bdt": [], "fdt": [], "foreign_reg": None,
            "amplification": None, "write_dryrun": None, "dcc": None,
            "reinit": None, "atomic_files": []}}
        fs = bacnet.findings([host], probes)
        vs = bacnet.findings_to_vulns(fs)
        self.assertIn("10.0.0.1", vs)
        self.assertTrue(all(v.source == "bacnet" for v in vs["10.0.0.1"]))


if __name__ == "__main__":
    unittest.main()
