"""Tests for recce.services.enip — EtherNet/IP (ODVA CIP) probe.

Response fixtures are hand-assembled from the ODVA CIP Vol 1 / Vol 2 spec
(§2-3.1 encapsulation, §2-4.4 List Identity, §5-2.2 Identity Object,
§5-3.2 TCP/IP Interface Object, §5-4.2 Ethernet Link Object) — NOT by
calling the module's own encoders. A local TCP server replays them in
sequence per socket connect.

Every field on the wire is little-endian, so the fixtures use `<` struct
formats throughout — the exact opposite of Modbus/TCP MBAP.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import enip
from recce.core.models import Host, Port


# ---------------------------------------------------------------- fixtures

# Encapsulation header commands (mirrored from ODVA Vol 2 §2-4).
_CMD_LIST_SERVICES = 0x0004
_CMD_LIST_IDENTITY = 0x0063
_CMD_LIST_INTERFACES = 0x0064
_CMD_REGISTER_SESSION = 0x0065
_CMD_SEND_RR_DATA = 0x006F


def _encap_header(cmd, length, session=0, status=0):
    """24-byte encap header per ODVA Vol 2 §2-3.1 (all LE)."""
    return (struct.pack("<HHII", cmd, length, session, status)
            + b"\x00" * 8                          # sender context
            + struct.pack("<I", 0))                # options


def _list_identity_response(vendor_id, device_type, product_code,
                            rev_major, rev_minor, status, serial,
                            product_name, state):
    """Build a wire List Identity reply — encap header + CPF item 0x000C
    carrying the Identity payload. Layout copied from Vol 2 §2-4.4.2."""
    name = product_name.encode("latin-1")
    # sockaddr_in in network byte order: sin_family(2 BE), sin_port(2 BE),
    # sin_addr(4 BE), sin_zero(8). Values are cosmetic here.
    sockaddr = (struct.pack(">H", 2)                       # AF_INET
                + struct.pack(">H", 44818)
                + b"\xc0\xa8\x01\x64"                      # 192.168.1.100
                + b"\x00" * 8)
    identity = (struct.pack("<H", 1)                       # encap proto ver
                + sockaddr
                + struct.pack("<HHH", vendor_id, device_type, product_code)
                + bytes([rev_major, rev_minor])
                + struct.pack("<HI", status, serial)
                + bytes([len(name)]) + name
                + bytes([state]))
    cpf = (struct.pack("<H", 1)                            # item count
           + struct.pack("<HH", 0x000C, len(identity))
           + identity)
    return _encap_header(_CMD_LIST_IDENTITY, len(cpf)) + cpf


def _list_services_response(name="Communications", flags=0x0120):
    """Encap 0x0004 reply — one Communications item (type 0x0100). Layout
    from Vol 2 §2-4.5: item type/len + version(2 LE) + flags(2 LE) +
    name_string(16, NUL padded)."""
    name_field = name.encode("latin-1").ljust(16, b"\x00")[:16]
    item_body = struct.pack("<HH", 1, flags) + name_field
    cpf = (struct.pack("<H", 1)
           + struct.pack("<HH", 0x0100, len(item_body))
           + item_body)
    return _encap_header(_CMD_LIST_SERVICES, len(cpf)) + cpf


def _list_interfaces_response():
    """Encap 0x0064 reply — one arbitrary item indicating a non-CIP
    interface behind the endpoint (i.e. a gateway/bridge)."""
    body = b"\x00\x00\x00\x00"
    cpf = (struct.pack("<H", 1)
           + struct.pack("<HH", 0x0001, len(body))
           + body)
    return _encap_header(_CMD_LIST_INTERFACES, len(cpf)) + cpf


def _register_session_response(session_handle):
    """Encap 0x0065 reply — protocol version 1, options 0."""
    body = struct.pack("<HH", 1, 0)
    return (_encap_header(_CMD_REGISTER_SESSION, len(body),
                          session=session_handle) + body)


def _cip_mr_reply(request_service, status, payload=b""):
    """CIP Message Router reply: reply_service (request | 0x80),
    reserved 0, general_status, ext_status_size 0, then payload."""
    return bytes([request_service | 0x80, 0x00, status, 0x00]) + payload


def _send_rr_data_reply(session, cip_reply):
    """SendRRData 0x006F reply — CPF with null-address + unconnected-data
    item wrapping the CIP MR reply."""
    cpf = (struct.pack("<H", 2)
           + struct.pack("<HH", 0x0000, 0)                 # null address
           + struct.pack("<HH", 0x00B2, len(cip_reply))    # unconn data
           + cip_reply)
    body = struct.pack("<IH", 0, 5) + cpf                  # iface handle, timeout
    return _encap_header(_CMD_SEND_RR_DATA, len(body), session=session) + body


def _identity_getattrs_all_payload():
    """Vol 1 §5-2.2 GetAttributesAll payload for Identity Object."""
    name = b"1756-EN2T/A"
    return (struct.pack("<HHH", 0x0001, 0x000C, 0x00BE)    # vid, dtype, pcode
            + bytes([32, 11])                              # rev major/minor
            + struct.pack("<HI", 0x0030, 0x12345678)       # status, serial
            + bytes([len(name)]) + name
            + bytes([0x03]))                               # state = Operational


def _tcpip_getattrs_all_payload():
    """Vol 2 §5-3.2 GetAttributesAll payload for TCP/IP Interface Object.
    Fields: status(4) cfg_cap(4) cfg_ctrl(4) phys_link{path_size(2) path(0)}
    interface_config{ip(4) mask(4) gw(4) ns1(4) ns2(4) domain(SHORT_STRING)}
    host_name(SHORT_STRING)."""
    ip = socket.inet_aton("192.168.1.100")[::-1]           # LE
    mask = socket.inet_aton("255.255.255.0")[::-1]
    gw = socket.inet_aton("192.168.1.1")[::-1]
    ns1 = socket.inet_aton("192.168.1.10")[::-1]
    ns2 = b"\x00" * 4
    domain = b"corp.local"
    hostname = b"CLX-Line5-North"
    return (struct.pack("<III", 1, 0x94, 0)                # status, cap, ctrl
            + struct.pack("<H", 0)                         # phys link path_size=0
            + ip + mask + gw + ns1 + ns2
            + bytes([len(domain)]) + domain
            # SHORT_STRING is padded so total field (length byte + N) is even
            # (ODVA Vol 2 §5-3.2) — pad when N is even, do not when odd.
            + (b"\x00" if len(domain) % 2 == 0 else b"")
            + bytes([len(hostname)]) + hostname)


def _ethlink_getattrs_all_payload():
    """Vol 2 §5-4.2 first three attributes: speed(4 LE), flags(4 LE), MAC(6)."""
    return (struct.pack("<II", 100, 0x03)                  # 100 Mbps, link up
            + bytes.fromhex("aabbccddeeff"))


# ---------------------------------------------------------------- server

class _ENIPServer:
    """Replay canned bytes per TCP connect. Each new socket gets the
    scripted sequence; request bytes are ignored (fixtures are ordered
    to match recce's fixed request order)."""

    def __init__(self, script, per_connect=None):
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
            script = (self._per_connect[idx]
                      if idx < len(self._per_connect)
                      else self._script)
            try:
                for resp in script:
                    if resp is None:
                        break
                    try:
                        conn.recv(4096)
                    except OSError:
                        break
                    if resp:
                        try:
                            conn.sendall(resp)
                        except OSError:
                            break
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


# ---------------------------------------------------------------- tests

class WireBuilderTest(unittest.TestCase):
    def test_encap_header_is_little_endian(self):
        pkt = enip._encap(0x0063, 0, b"")
        # cmd LE, length LE, session LE, status LE — 4 bytes cmd+len at pkt[0:4]
        cmd, length = struct.unpack("<HH", pkt[:4])
        self.assertEqual(cmd, 0x0063)
        self.assertEqual(length, 0)
        self.assertEqual(len(pkt), 24)

    def test_cip_path_8bit_segments(self):
        # Identity object class 0x01 instance 1 encodes to 0x20 0x01 0x24 0x01.
        self.assertEqual(enip._cip_path(0x01, 1), b"\x20\x01\x24\x01")

    def test_cip_path_16bit_class(self):
        # A class > 0xFF triggers the 16-bit class segment 0x21 0x00.
        p = enip._cip_path(0x0100, 1)
        self.assertEqual(p[:2], b"\x21\x00")
        self.assertEqual(struct.unpack("<H", p[2:4])[0], 0x0100)

    def test_cip_path_with_attribute(self):
        p = enip._cip_path(0xF5, 1, 3)
        self.assertEqual(p, b"\x20\xf5\x24\x01\x30\x03")

    def test_cip_mr_request_shape(self):
        r = enip._cip_mr_request(0x01, 0x01, 1)
        self.assertEqual(r[0], 0x01)         # service
        self.assertEqual(r[1], 2)            # path_size in words (4 bytes / 2)
        self.assertEqual(r[2:], b"\x20\x01\x24\x01")


class ParserTest(unittest.TestCase):
    def test_parse_encap_rejects_short_frame(self):
        self.assertIsNone(enip._parse_encap(b"\x00" * 10))

    def test_parse_list_identity_extracts_all_fields(self):
        pkt = _list_identity_response(
            vendor_id=0x0001, device_type=0x000C, product_code=0xBE,
            rev_major=32, rev_minor=11, status=0x0030,
            serial=0xDEADBEEF, product_name="1756-EN2T/A",
            state=0x03)
        ident = enip._parse_list_identity(pkt)
        self.assertIsNotNone(ident)
        self.assertEqual(ident["vendor_id"], 0x0001)
        self.assertEqual(ident["product_code"], 0xBE)
        self.assertEqual(ident["revision"], "32.11")
        self.assertEqual(ident["serial_number"], 0xDEADBEEF)
        self.assertEqual(ident["product_name"], "1756-EN2T/A")
        self.assertEqual(ident["device_state"], 0x03)

    def test_parse_list_services_extracts_cip_encapsulation_flag(self):
        # Flag bit 5 (0x20) set = CIP encapsulation supported.
        pkt = _list_services_response(name="Communications", flags=0x0120)
        svc = enip._parse_list_services(pkt)
        self.assertEqual(len(svc), 1)
        self.assertEqual(svc[0]["name"], "Communications")
        self.assertTrue(svc[0]["cip_encapsulation"])

    def test_parse_register_session_extracts_handle(self):
        pkt = _register_session_response(session_handle=0xCAFEBABE)
        reg = enip._parse_register_session(pkt)
        self.assertEqual(reg["session"], 0xCAFEBABE)
        self.assertEqual(reg["protocol_version"], 1)

    def test_parse_send_rr_data_unwraps_cip_reply(self):
        reply = _cip_mr_reply(0x01, 0x00, _identity_getattrs_all_payload())
        pkt = _send_rr_data_reply(0xCAFEBABE, reply)
        cip = enip._parse_send_rr_data(pkt)
        self.assertIsNotNone(cip)
        self.assertEqual(cip["service"], 0x01)
        self.assertEqual(cip["status"], 0x00)

    def test_parse_tcpip_object_extracts_hostname_and_domain(self):
        body = _tcpip_getattrs_all_payload()
        parsed = enip._parse_tcpip_object(body)
        self.assertEqual(parsed["ip_address"], "192.168.1.100")
        self.assertEqual(parsed["gateway"], "192.168.1.1")
        self.assertEqual(parsed["name_server_1"], "192.168.1.10")
        self.assertEqual(parsed["domain_name"], "corp.local")
        self.assertEqual(parsed["host_name"], "CLX-Line5-North")

    def test_parse_ethlink_extracts_mac(self):
        body = _ethlink_getattrs_all_payload()
        parsed = enip._parse_ethlink_object(body)
        self.assertEqual(parsed["mac_address"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed["interface_speed_mbps"], 100)

    def test_cve_fingerprint_rockwell_compactlogix(self):
        matches = enip._cve_fingerprint(
            {"vendor_id": 0x0001, "revision_major": 32,
             "product_name": "1769-L18ER CompactLogix"})
        cves = [m["cve"] for m in matches]
        self.assertIn("CVE-2021-22681", cves)

    def test_cve_fingerprint_empty_on_unknown_vendor(self):
        matches = enip._cve_fingerprint(
            {"vendor_id": 0xFFFF, "revision_major": 1,
             "product_name": "generic"})
        self.assertEqual(matches, [])


class IsEnipTest(unittest.TestCase):
    def test_matches_port_44818(self):
        self.assertTrue(enip.is_enip(Port(portid=44818, service="unknown")))

    def test_matches_service_name(self):
        self.assertTrue(enip.is_enip(
            Port(portid=8888, service="EtherNet/IP")))

    def test_rejects_http(self):
        self.assertFalse(enip.is_enip(Port(portid=80, service="http")))


class ProbeEndToEndTest(unittest.TestCase):
    def _full_session_script(self, pccc_ok=True, file_ok=True,
                             conn_mgr_ok=True):
        session = 0xCAFEBABE
        script = [
            # List Identity
            _list_identity_response(
                vendor_id=0x0001, device_type=0x000C, product_code=0xBE,
                rev_major=32, rev_minor=11, status=0x0030,
                serial=0xDEADBEEF,
                product_name="1756-EN2T/A CompactLogix",
                state=0x03),
            # List Services
            _list_services_response(flags=0x0120),
            # List Interfaces
            _list_interfaces_response(),
            # Register Session
            _register_session_response(session),
            # Identity Object GetAttributesAll
            _send_rr_data_reply(session,
                _cip_mr_reply(0x01, 0x00, _identity_getattrs_all_payload())),
            # TCP/IP Object GetAttributesAll
            _send_rr_data_reply(session,
                _cip_mr_reply(0x01, 0x00, _tcpip_getattrs_all_payload())),
            # Ethernet Link GetAttributesAll
            _send_rr_data_reply(session,
                _cip_mr_reply(0x01, 0x00, _ethlink_getattrs_all_payload())),
            # PCCC: reply with attribute-error (0x14) — class exists.
            _send_rr_data_reply(session,
                _cip_mr_reply(0x01, 0x14 if pccc_ok else 0x05)),
            # File Object 0x37 instance 0xC8 attr 1: success.
            _send_rr_data_reply(session,
                _cip_mr_reply(0x0E, 0x00 if file_ok else 0x05, b"\x01")),
            # Connection Manager class 0x06 GetAttributesAll.
            _send_rr_data_reply(session,
                _cip_mr_reply(0x01, 0x00 if conn_mgr_ok else 0x05,
                              b"\x00\x00")),
            # UnregisterSession request has no reply.
        ]
        return script

    def test_full_probe_extracts_everything(self):
        srv = _ENIPServer(script=self._full_session_script())
        try:
            pr = enip.probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertIsNotNone(pr["list_identity"])
        self.assertEqual(pr["list_identity"]["vendor_id"], 0x0001)
        self.assertTrue(pr["cip_encapsulation"])
        self.assertEqual(len(pr["list_interfaces"]), 1)
        self.assertTrue(pr["session_registered"])
        self.assertEqual(pr["session"], 0xCAFEBABE)
        self.assertTrue(pr["cip_security_off"])
        self.assertIsNotNone(pr["identity_detailed"])
        self.assertEqual(pr["tcpip"]["host_name"], "CLX-Line5-North")
        self.assertEqual(pr["tcpip"]["domain_name"], "corp.local")
        self.assertEqual(pr["ethlink"]["mac_address"], "aa:bb:cc:dd:ee:ff")
        self.assertTrue(pr["pccc_supported"])
        self.assertTrue(pr["file_object_supported"])
        self.assertTrue(pr["conn_mgr_supported"])
        self.assertTrue(pr["reset_service_capable"])
        cves = [m["cve"] for m in pr["cve_matches"]]
        self.assertIn("CVE-2021-22681", cves)

    def test_dead_port(self):
        pr = enip.probe("127.0.0.1", 1, timeout=1)
        self.assertFalse(pr["reachable"])

    def test_non_enip_service_not_flagged(self):
        srv = _ENIPServer(script=[b"HTTP/1.1 400 Bad Request\r\n\r\n"])
        try:
            pr = enip.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertFalse(pr["reachable"])
        self.assertFalse(pr["session_registered"])

    def test_pccc_absent_when_path_dest_unknown(self):
        srv = _ENIPServer(script=self._full_session_script(pccc_ok=False))
        try:
            pr = enip.probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        self.assertFalse(pr["pccc_supported"])


class FindingsTest(unittest.TestCase):
    def _host_with_probe(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=44818, service="ethernetip"),
                        Port(portid=2222, protocol="udp",
                             service="EtherNet/IP-2")])
        return h

    def test_findings_emit_all_capabilities(self):
        h = self._host_with_probe()
        probes = {("10.0.0.5", 44818): {
            "reachable": True,
            "list_identity": {"vendor_id": 0x0001, "device_type": 0x000C,
                              "product_code": 0xBE, "revision": "32.11",
                              "revision_major": 32, "revision_minor": 11,
                              "serial_number": 0xDEADBEEF,
                              "product_name": "1756-EN2T/A CompactLogix",
                              "device_state": 3, "status_word": 0x0030},
            "list_services": [{"name": "Communications", "flags": 0x0120,
                               "cip_encapsulation": True, "version": 1,
                               "type": 0x0100}],
            "list_services_names": ["Communications"],
            "cip_encapsulation": True,
            "list_interfaces": [{"type": 1, "size": 4}],
            "session": 0xCAFEBABE, "session_registered": True,
            "cip_security_off": True,
            "identity_detailed": {"vendor_id": 0x0001},
            "tcpip": {"ip_address": "192.168.1.100", "netmask": "",
                      "gateway": "192.168.1.1",
                      "name_server_1": "192.168.1.10", "name_server_2": "",
                      "domain_name": "corp.local",
                      "host_name": "CLX-Line5-North"},
            "ethlink": {"mac_address": "aa:bb:cc:dd:ee:ff",
                        "interface_speed_mbps": 100, "interface_flags": 3},
            "pccc_supported": True, "file_object_supported": True,
            "conn_mgr_supported": True, "reset_service_capable": True,
            "cve_matches": [{"cve": "CVE-2021-22681",
                             "family": "Rockwell Logix 5000", "note": "..."}],
        }}
        fs = enip.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        expected = {
            "enip_reachable", "enip_identity_detailed",
            "enip_unauth_session", "enip_cip_security_off",
            "enip_tcpip_disclosure", "enip_mac_disclosure",
            "enip_list_services", "enip_bridge_detected",
            "enip_backplane_enum", "enip_pccc_read",
            "enip_unauth_stop_cpu", "enip_firmware_upload_capable",
            "enip_known_cve", "enip_io_traffic_exposed",
        }
        self.assertTrue(expected.issubset(kinds),
                        f"missing: {expected - kinds}")
        for f in fs:
            self.assertIn(f["severity"],
                          ("info", "low", "medium", "high", "critical"))
            self.assertTrue(f["kind"])

    def test_findings_empty_when_no_probe(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=44818, service="ethernetip")])
        self.assertEqual(enip.findings([h], {}), [])

    def test_udp_2222_alone_still_emits_io_exposure(self):
        # No 44818, just UDP/2222 open — the passive finding must still fire.
        h = Host(ip="10.0.0.6",
                 ports=[Port(portid=2222, protocol="udp",
                             service="EtherNet/IP-2")])
        fs = enip.findings([h], {})
        kinds = {f["kind"] for f in fs}
        self.assertIn("enip_io_traffic_exposed", kinds)

    def test_analyze_shape(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=44818, service="ethernetip")])
        out = enip.analyze([h], active=False)
        self.assertIn("targets", out)
        self.assertIn("findings", out)
        self.assertIn("runbooks", out)
        self.assertEqual(len(out["targets"]), 1)

    def test_findings_to_vulns_returns_dict(self):
        fs = [{"severity": "critical", "title": "t",
               "target": "10.0.0.5:44818", "detail": "d",
               "tool": "cpppo", "command": "c", "remediation": "r",
               "cwes": ["CWE-306"], "kind": "enip_reachable"}]
        v = enip.findings_to_vulns(fs)
        self.assertIsInstance(v, dict)
        self.assertIn("10.0.0.5", v)


class UnauthSessionT2PromotionTest(unittest.TestCase):
    """T2 promotion: unauth_queries_ok tracks which follow-on CIP queries
    succeeded under the unauthenticated RegisterSession handle. Any
    successful class read on that handle IS proof-of-primitive; the
    enip_unauth_session finding upgrades to t2 and gains a T2 PROOF line.
    Empty follow-on set leaves the finding at t1 (session capability only)."""

    def _base_probe(self, unauth_ok):
        return {
            "reachable": True,
            "list_identity": {
                "vendor_id": 0x0001, "device_type": 0x000C,
                "product_code": 0xBE, "revision": "32.11",
                "revision_major": 32, "revision_minor": 11,
                "serial_number": 0xDEAD, "product_name": "1756-EN2T/A",
                "device_state": 3, "status_word": 0x0030,
            },
            "list_services": [], "list_services_names": [],
            "cip_encapsulation": True, "list_interfaces": [],
            "session": 0xCAFEBABE, "session_registered": True,
            "cip_security_off": True,
            "identity_detailed": ({"vendor_id": 0x0001,
                                    "product_name": "1756-EN2T/A",
                                    "revision": "32.11", "device_state": 3}
                                   if "Identity" in " ".join(unauth_ok)
                                   else None),
            "tcpip": None, "ethlink": None,
            "pccc_supported": "PCCC" in " ".join(unauth_ok),
            "file_object_supported": False, "conn_mgr_supported": False,
            "reset_service_capable": "Identity" in " ".join(unauth_ok),
            "unauth_queries_ok": unauth_ok,
            "cve_matches": [],
        }

    def test_probe_populates_unauth_queries_ok_from_full_flow(self):
        # The full-session script from ProbeEndToEndTest succeeds on Identity,
        # TCP/IP, EthLink, PCCC (attr-error 0x14 still means class present),
        # File Object, and Connection Manager.
        srv = _ENIPServer(script=ProbeEndToEndTest()._full_session_script())
        try:
            pr = enip.probe(srv.host, srv.port, timeout=3)
        finally:
            srv.close()
        classes = pr["unauth_queries_ok"]
        self.assertIn("Identity (0x01)", classes)
        self.assertIn("TCP/IP (0xF5)", classes)
        self.assertIn("EthernetLink (0xF6)", classes)
        self.assertIn("PCCC (0x67)", classes)
        self.assertIn("File (0x37)", classes)
        self.assertIn("ConnectionManager (0x06)", classes)

    def test_unauth_session_t2_when_follow_on_queries_answer(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=44818, service="ethernetip")])
        pr = self._base_probe(["Identity (0x01)", "PCCC (0x67)"])
        fs = enip.findings([h], {("10.0.0.5", 44818): pr})
        session_findings = [f for f in fs if f["kind"] == "enip_unauth_session"]
        self.assertEqual(len(session_findings), 1)
        self.assertEqual(session_findings[0]["depth_tier"], "t2")
        self.assertIn("T2 PROOF", session_findings[0]["detail"])
        self.assertIn("Identity (0x01)", session_findings[0]["detail"])
        self.assertIn("PCCC (0x67)", session_findings[0]["detail"])

    def test_unauth_session_stays_t1_when_no_follow_on_queries_succeed(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=44818, service="ethernetip")])
        pr = self._base_probe([])
        fs = enip.findings([h], {("10.0.0.5", 44818): pr})
        session_findings = [f for f in fs if f["kind"] == "enip_unauth_session"]
        self.assertEqual(len(session_findings), 1)
        self.assertEqual(session_findings[0]["depth_tier"], "t1")
        self.assertNotIn("T2 PROOF", session_findings[0]["detail"])

    def test_probe_of_dead_target_leaves_unauth_queries_ok_empty(self):
        pr = enip.probe("127.0.0.1", 1, timeout=1)
        self.assertEqual(pr["unauth_queries_ok"], [])


class KnownCveT2PromotionTest(unittest.TestCase):
    """T2 promotion: _cve_fingerprint tags each match with confirmed=True/False
    based on the advisory's mitigated firmware band. Confirmed matches emit
    enip_known_cve at t2 with severity high; unconfirmed matches stay at
    t1 with severity medium and a note that the tester must verify."""

    def test_rockwell_logix_below_33_11_is_confirmed_t2(self):
        matches = enip._cve_fingerprint(
            {"vendor_id": 0x0001, "revision_major": 32, "revision_minor": 11,
             "product_name": "1756-L83E ControlLogix"})
        self.assertEqual(len(matches), 1)
        self.assertTrue(matches[0]["confirmed"])
        self.assertIn("< 33.011", matches[0]["band"])

    def test_rockwell_logix_at_or_above_33_11_is_unconfirmed(self):
        matches = enip._cve_fingerprint(
            {"vendor_id": 0x0001, "revision_major": 33, "revision_minor": 11,
             "product_name": "1756-L83E ControlLogix"})
        self.assertEqual(len(matches), 1)
        self.assertFalse(matches[0]["confirmed"])
        matches2 = enip._cve_fingerprint(
            {"vendor_id": 0x0001, "revision_major": 34, "revision_minor": 0,
             "product_name": "1769-L18ER CompactLogix"})
        self.assertFalse(matches2[0]["confirmed"])

    def test_micrologix_pccc_is_always_confirmed(self):
        matches = enip._cve_fingerprint(
            {"vendor_id": 0x0001, "revision_major": 21, "revision_minor": 6,
             "product_name": "MicroLogix 1400"})
        # PCCC is inherent to the platform — no firmware band gate.
        self.assertTrue(any(m["cve"] == "CWE-306" and m["confirmed"]
                            for m in matches))

    def test_finding_promotes_to_t2_when_cve_confirmed(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=44818, service="ethernetip")])
        pr = {
            "reachable": True,
            "list_identity": {"vendor_id": 0x0001, "revision_major": 32,
                              "revision_minor": 11,
                              "product_name": "1756-L83E ControlLogix"},
            "list_services": [], "list_services_names": [],
            "cip_encapsulation": True, "list_interfaces": [],
            "session": 0, "session_registered": False,
            "cip_security_off": False,
            "identity_detailed": None, "tcpip": None, "ethlink": None,
            "pccc_supported": False, "file_object_supported": False,
            "conn_mgr_supported": False, "reset_service_capable": False,
            "unauth_queries_ok": [],
            "cve_matches": [{
                "cve": "CVE-2021-22681",
                "family": "Rockwell Logix 5000",
                "note": "Weak CIP session key derivation.",
                "confirmed": True,
                "band": "vulnerable if firmware < 33.011 (observed 32.11)",
            }],
        }
        fs = enip.findings([h], {("10.0.0.5", 44818): pr})
        cve_findings = [f for f in fs if f["kind"] == "enip_known_cve"]
        self.assertEqual(len(cve_findings), 1)
        self.assertEqual(cve_findings[0]["depth_tier"], "t2")
        self.assertEqual(cve_findings[0]["severity"], "high")
        self.assertIn("T2 PROOF", cve_findings[0]["detail"])
        self.assertIn("< 33.011", cve_findings[0]["detail"])

    def test_finding_stays_t1_when_cve_band_unconfirmed(self):
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=44818, service="ethernetip")])
        pr = {
            "reachable": True,
            "list_identity": {"vendor_id": 0x0001, "revision_major": 34,
                              "revision_minor": 0,
                              "product_name": "1756-L83E ControlLogix"},
            "list_services": [], "list_services_names": [],
            "cip_encapsulation": True, "list_interfaces": [],
            "session": 0, "session_registered": False,
            "cip_security_off": False,
            "identity_detailed": None, "tcpip": None, "ethlink": None,
            "pccc_supported": False, "file_object_supported": False,
            "conn_mgr_supported": False, "reset_service_capable": False,
            "unauth_queries_ok": [],
            "cve_matches": [{
                "cve": "CVE-2021-22681",
                "family": "Rockwell Logix 5000",
                "note": "Weak CIP session key derivation.",
                "confirmed": False,
                "band": "vulnerable if firmware < 33.011 (observed 34.0)",
            }],
        }
        fs = enip.findings([h], {("10.0.0.5", 44818): pr})
        cve_findings = [f for f in fs if f["kind"] == "enip_known_cve"]
        self.assertEqual(len(cve_findings), 1)
        self.assertEqual(cve_findings[0]["depth_tier"], "t1")
        self.assertEqual(cve_findings[0]["severity"], "medium")
        self.assertIn("band check inconclusive", cve_findings[0]["detail"])


if __name__ == "__main__":
    unittest.main()
