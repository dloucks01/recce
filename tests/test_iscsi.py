"""Tests for recce.services.iscsi.

Fixtures are hand-crafted from RFC 7143 (iSCSI), SPC-4 (INQUIRY), and SBC-3
(READ CAPACITY (10)) field layouts - not produced by the module's own encoder.
The socket layer is stubbed with a scripted fake that returns pre-built PDUs
in response to each sendall(), so no test touches the network.
"""
from __future__ import annotations

import struct
import unittest
from unittest import mock

from recce.core.models import Host, Port
from recce.services import iscsi


# ---------------------------------------------------------------------------
# Wire-derived fixtures.
# ---------------------------------------------------------------------------

def _login_response_bhs(t: int, csg: int, nsg: int, status_class: int,
                        version_active: int, tsih: int, dsl: int) -> bytes:
    """Hand-craft a 48-byte iSCSI Login Response BHS from RFC 7143 §11.13.

    Byte layout (all offsets in hex):
      00 opcode=0x23   01 T|C|CSG|NSG   02 Version-max   03 Version-active
      04 TotalAHSLen   05-07 DataSegmentLength (3 bytes BE)
      08-0d ISID       0e-0f TSIH
      10-13 ITT        14-17 reserved
      18-1b StatSN     1c-1f ExpCmdSN
      20-23 MaxCmdSN   24 StatusClass  25 StatusDetail  26-2f reserved
    """
    flags = ((t & 1) << 7) | ((csg & 3) << 2) | (nsg & 3)
    return struct.pack(
        ">BBBBB3s6sHIIIIIBBH8s",
        0x23, flags, 0x00, version_active & 0xFF,
        0x00, dsl.to_bytes(3, "big"),
        b"\x80\x00\x00\x00\x00\x01",             # ISID (random-format)
        tsih & 0xFFFF,
        0x00000000,                              # ITT (echo of client's 0)
        0x00000000,                              # reserved
        0x00000001,                              # StatSN
        0x00000001,                              # ExpCmdSN
        0x00000005,                              # MaxCmdSN
        status_class & 0xFF, 0x00,               # StatusClass, StatusDetail
        0x0000, b"\x00" * 8,                     # reserved
    )


def _text_response_bhs(f: int, c: int, dsl: int, ttt: int = 0xFFFFFFFF) -> bytes:
    """Text Response BHS (opcode 0x24), RFC 7143 §11.11.
      01: F|C|reserved   14: TTT (bytes 20-23)
    """
    flags = ((f & 1) << 7) | ((c & 1) << 6)
    return struct.pack(
        ">BBBBB3s8sIIIII12s",
        0x24, flags, 0x00, 0x00,
        0x00, dsl.to_bytes(3, "big"),
        b"\x00" * 8,                             # LUN
        0x00000000,                              # ITT
        ttt & 0xFFFFFFFF,                        # TTT
        0x00000001,                              # StatSN
        0x00000002,                              # ExpCmdSN
        0x00000005,                              # MaxCmdSN
        b"\x00" * 12,                            # reserved (36-47)
    )


def _scsi_data_in_bhs(final: int, dsl: int) -> bytes:
    """SCSI Data-In BHS (opcode 0x25), RFC 7143 §11.7.
    Byte 1 bit 0x80 = F (Final); no S bit set so status arrives separately."""
    flags = 0x80 if final else 0x00
    # Layout (RFC 7143 §11.7): DataSN(4) + BufferOffset(4) + ResidualCount(4)
    # in the trailing 12 bytes of the 48-byte BHS.
    return struct.pack(
        ">BBBBB3s8sIIIII12s",
        0x25, flags, 0x00, 0x00,
        0x00, dsl.to_bytes(3, "big"),
        b"\x00" * 8,                             # LUN / reserved
        0x00000000,                              # ITT
        0xFFFFFFFF,                              # TTT
        0x00000001,                              # StatSN
        0x00000002,                              # ExpCmdSN
        0x00000005,                              # MaxCmdSN
        b"\x00" * 12,                            # DataSN + BufferOffset + Residual
    )


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * ((4 - len(data) % 4) % 4)


# INQUIRY response (SPC-4 §6.6): peripheral type in byte 0, vendor 8-15,
# product 16-31, revision 32-35. Hand-built here as raw wire hex.
_INQUIRY_WIRE = (
    bytes([
        0x00,                                   # 00: dev type 0x00 = direct-access block
        0x00, 0x05, 0x02,                       # 01-03: RMB / version / response fmt
        0x1F, 0x00, 0x00, 0x00,                 # 04-07: add'l length + reserved
    ])
    + b"LIO-ORG "                               # 08-15: vendor (8B)
    + b"IBLOCK          "                       # 16-31: product (16B)
    + b"4.0 "                                   # 32-35: revision (4B)
)


# READ CAPACITY (10) response (SBC-3 §5.15): last-LBA(4B BE) + block-size(4B BE).
# 4194303 * 512 = 2 GiB - 512 bytes; last_lba=0x003FFFFF, block=0x00000200.
_READCAP10_WIRE = bytes.fromhex("003fffff00000200")


# ---------------------------------------------------------------------------
# Scripted fake socket (no real network traffic).
# ---------------------------------------------------------------------------

class ScriptedSock:
    """Fake socket: each sendall() dequeues the next queued response into a
    read buffer that recv() drains. Supports context-manager use so a `with
    socket.create_connection(...)` block works."""

    def __init__(self, responses):
        self._responses = list(responses)
        self._buf = b""
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        if self._responses:
            self._buf += self._responses.pop(0)

    def recv(self, n: int) -> bytes:
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk

    def settimeout(self, _t) -> None:
        pass

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        self.close()


def _install_connections(monkeypatch, sockets: list[ScriptedSock]) -> list:
    """Patch iscsi.socket.create_connection to hand out `sockets` in order."""
    queue = list(sockets)

    def fake_create(addr, timeout=None):
        if not queue:
            raise AssertionError(f"unexpected extra connection to {addr!r}")
        return queue.pop(0)

    monkeypatch.setattr(iscsi.socket, "create_connection", fake_create)
    return queue


# ---------------------------------------------------------------------------
# Parser unit tests.
# ---------------------------------------------------------------------------

class ParseIqnTest(unittest.TestCase):
    def test_rfc7143_standard_form(self):
        info = iscsi.parse_iqn("iqn.2001-04.com.example:storage.sql01")
        self.assertEqual(info["date"], "2001-04")
        self.assertEqual(info["reversed_domain"], "com.example")
        self.assertEqual(info["domain"], "example.com")
        self.assertEqual(info["tail"], "storage.sql01")
        self.assertEqual(info["host"], "sql01.storage")

    def test_no_tail(self):
        info = iscsi.parse_iqn("iqn.2016-03.io.example")
        self.assertEqual(info["domain"], "example.io")
        self.assertEqual(info["host"], "")

    def test_bad_string_returns_empty(self):
        self.assertEqual(iscsi.parse_iqn("not-an-iqn"), {})


class ParseTargetAddressTest(unittest.TestCase):
    def test_ipv4_with_port_and_portalgroup(self):
        self.assertEqual(iscsi._parse_target_address("10.0.0.5:3260,1"),
                         ("10.0.0.5", 3260, "1"))

    def test_ipv4_bare(self):
        self.assertEqual(iscsi._parse_target_address("10.0.0.5"),
                         ("10.0.0.5", 3260, ""))

    def test_ipv6_bracketed(self):
        host, port, pg = iscsi._parse_target_address("[fe80::1]:3260,2")
        self.assertEqual(host, "fe80::1")
        self.assertEqual(port, 3260)
        self.assertEqual(pg, "2")


class ParseSendTargetsTest(unittest.TestCase):
    def test_groups_targetname_and_addresses(self):
        kv = [("TargetName", "iqn.2001-04.com.example:s1"),
              ("TargetAddress", "10.0.0.5:3260,1"),
              ("TargetAddress", "192.168.99.10:3260,1"),
              ("TargetName", "iqn.2001-04.com.example:s2"),
              ("TargetAddress", "10.0.0.6:3260,1")]
        out = iscsi._parse_sendtargets(kv)
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["iqn"], "iqn.2001-04.com.example:s1")
        self.assertEqual(len(out[0]["addresses"]), 2)
        self.assertEqual(out[0]["addresses"][0]["ip"], "10.0.0.5")
        self.assertEqual(out[1]["iqn"], "iqn.2001-04.com.example:s2")


class KVParserTest(unittest.TestCase):
    def test_null_separated_pairs(self):
        # RFC 7143 §5.1: text keys are NUL-terminated.
        data = b"AuthMethod=None\x00SessionType=Discovery\x00"
        pairs = iscsi._parse_kvpairs(data)
        self.assertIn(("AuthMethod", "None"), pairs)
        self.assertIn(("SessionType", "Discovery"), pairs)


class InquiryParseTest(unittest.TestCase):
    def test_vendor_product_revision_extracted(self):
        info = iscsi._parse_inquiry(_INQUIRY_WIRE)
        self.assertEqual(info["device_type"], 0x00)
        self.assertEqual(info["vendor"], "LIO-ORG")
        self.assertEqual(info["product"], "IBLOCK")
        self.assertEqual(info["revision"], "4.0")


class ReadCapacityParseTest(unittest.TestCase):
    def test_last_lba_and_block_size(self):
        info = iscsi._parse_read_capacity10(_READCAP10_WIRE)
        self.assertEqual(info["last_lba"], 0x003FFFFF)
        self.assertEqual(info["blocks"], 0x00400000)
        self.assertEqual(info["block_size"], 512)
        self.assertEqual(info["capacity_bytes"], 0x00400000 * 512)


class LoginResponseParseTest(unittest.TestCase):
    def test_parses_status_and_stage_flags(self):
        data = b"AuthMethod=None\x00"
        bhs = _login_response_bhs(t=1, csg=0, nsg=1, status_class=0,
                                  version_active=0, tsih=0x0001,
                                  dsl=len(data))
        resp = iscsi._parse_login_response(bhs, data)
        self.assertEqual(resp["opcode"], 0x23)
        self.assertTrue(resp["T"])
        self.assertEqual(resp["csg"], 0)
        self.assertEqual(resp["nsg"], 1)
        self.assertEqual(resp["status_class"], 0)
        self.assertEqual(resp["tsih"], 1)
        self.assertIn(("AuthMethod", "None"), resp["kv"])


# ---------------------------------------------------------------------------
# probe() end-to-end via scripted socket.
# ---------------------------------------------------------------------------

class ProbeDiscoveryTest(unittest.TestCase):
    def test_auth_none_discovery_and_sendtargets(self):
        # 1) Login Response: AuthMethod=None chosen, T=1, NSG=1 (already in OpNeg
        #    from the server's PoV -> our code skips the extra transition PDU).
        login_data = b"AuthMethod=None\x00"
        login_pdu = (_login_response_bhs(t=1, csg=0, nsg=1, status_class=0,
                                         version_active=0, tsih=0x0001,
                                         dsl=len(login_data))
                     + _pad4(login_data))

        # 2) Text Response (F=1) draining SendTargets. TargetName + TargetAddress
        #    for two targets, with one out-of-scope portal.
        text_data = (b"TargetName=iqn.2001-04.com.example:storage.sql01\x00"
                     b"TargetAddress=10.0.0.5:3260,1\x00"
                     b"TargetName=iqn.2001-04.com.example:backup.bkp02\x00"
                     b"TargetAddress=192.168.99.10:3260,1\x00")
        text_pdu = _text_response_bhs(f=1, c=0, dsl=len(text_data)) + _pad4(text_data)

        # 3) Normal-session Login Response on a SECOND connection: T=1 NSG=3 to
        #    jump straight to FullFeaturePhase.
        normal_login_pdu = _login_response_bhs(
            t=1, csg=0, nsg=3, status_class=0, version_active=0,
            tsih=0x0002, dsl=0)

        # 4) INQUIRY - one Data-In with F=1.
        inq_pdu = (_scsi_data_in_bhs(final=1, dsl=len(_INQUIRY_WIRE))
                   + _pad4(_INQUIRY_WIRE))

        # 5) READ CAPACITY (10) - one Data-In with F=1 carrying 8 bytes.
        rc_pdu = (_scsi_data_in_bhs(final=1, dsl=len(_READCAP10_WIRE))
                  + _pad4(_READCAP10_WIRE))

        sock1 = ScriptedSock([login_pdu, text_pdu])
        sock2 = ScriptedSock([normal_login_pdu, inq_pdu, rc_pdu])
        # The T2 SendTargets verify sweep probes disclosed IQNs beyond the
        # first. This second disclosed target is on an out-of-scope portal;
        # a scripted empty response makes the verify return False cleanly
        # without exercising T2 promotion (that's covered elsewhere).
        sock3 = ScriptedSock([])

        with mock.patch.object(iscsi.socket, "create_connection",
                               side_effect=[sock1, sock2, sock3]):
            pr = iscsi.probe("10.0.0.5", 3260, timeout=1.0)

        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["is_iscsi"])
        self.assertTrue(pr["discovery_no_auth"])
        self.assertEqual(pr["auth_selected"], "None")
        self.assertEqual(len(pr["targets"]), 2)
        self.assertEqual(pr["targets"][0]["iqn"],
                         "iqn.2001-04.com.example:storage.sql01")
        self.assertEqual(pr["targets"][0]["addresses"][0]["ip"], "10.0.0.5")
        self.assertEqual(pr["normal_login"]["full_feature"], True)
        self.assertEqual(pr["inquiry"]["vendor"], "LIO-ORG")
        self.assertEqual(pr["inquiry"]["product"], "IBLOCK")
        self.assertEqual(pr["read_capacity"]["block_size"], 512)
        self.assertEqual(pr["read_capacity"]["blocks"], 0x00400000)


class ProbeChapTest(unittest.TestCase):
    def test_chap_challenge_captured(self):
        # 1) Login Response: AuthMethod=CHAP selected (target refuses None).
        d1 = b"AuthMethod=CHAP\x00"
        pdu1 = _login_response_bhs(t=0, csg=0, nsg=0, status_class=0,
                                   version_active=0, tsih=0x0001,
                                   dsl=len(d1)) + _pad4(d1)
        # 2) After CHAP_A=5, target answers with CHAP_A + CHAP_I + CHAP_C.
        d2 = (b"CHAP_A=5\x00"
              b"CHAP_I=42\x00"
              b"CHAP_C=0xdeadbeefcafebabe0011223344556677\x00")
        pdu2 = _login_response_bhs(t=0, csg=0, nsg=0, status_class=0,
                                   version_active=0, tsih=0x0001,
                                   dsl=len(d2)) + _pad4(d2)
        sock1 = ScriptedSock([pdu1, pdu2])
        with mock.patch.object(iscsi.socket, "create_connection",
                               side_effect=[sock1]):
            pr = iscsi.probe("10.0.0.9", 3260, timeout=1.0, do_inquiry=False)
        self.assertTrue(pr["is_iscsi"])
        self.assertFalse(pr["discovery_no_auth"])
        self.assertEqual(pr["chap"]["id"], "42")
        self.assertEqual(pr["chap"]["challenge"],
                         "0xdeadbeefcafebabe0011223344556677")
        self.assertEqual(pr["chap"]["hashcat_mode"], 4800)
        self.assertTrue(pr["chap_one_way"])


class ProbeUnreachableTest(unittest.TestCase):
    def test_no_response_returns_unreachable(self):
        # No queued responses - the first _recv_exact reads b"" and _read_pdu
        # returns (None, None) so probe() reports no Login Response.
        sock = ScriptedSock([])
        with mock.patch.object(iscsi.socket, "create_connection",
                               side_effect=[sock]):
            pr = iscsi.probe("127.0.0.1", 3260, timeout=1.0, do_inquiry=False)
        self.assertFalse(pr["reachable"])
        self.assertEqual(pr["error"], "no Login Response")


# ---------------------------------------------------------------------------
# findings() emits the right kinds for each capability.
# ---------------------------------------------------------------------------

class FindingsEmissionTest(unittest.TestCase):
    def _host(self, ip="10.0.0.5"):
        return Host(ip=ip, ports=[Port(portid=3260, protocol="tcp", state="open",
                                       service="iscsi")])

    def test_all_capability_kinds_emitted(self):
        host = self._host()
        pr = {
            "is_iscsi": True, "reachable": True,
            "auth_methods": ["None", "CHAP"],
            "auth_selected": "None",
            "discovery_no_auth": True, "operational_reached": True,
            "targets": [
                {"iqn": "iqn.2001-04.com.example:storage.sql01",
                 "addresses": [{"ip": "10.0.0.5", "port": 3260, "portal_group": "1"},
                               {"ip": "192.168.99.10", "port": 3260, "portal_group": "1"}]},
            ],
            "op_params": {"HeaderDigest": "None", "DataDigest": "None"},
            "chap": {"id": "1", "challenge": "0xabc", "algorithm": "5",
                     "hashcat_mode": 4800},
            "chap_one_way": True,
            "version_max": 2, "version_active": 2, "legacy_version": True,
            "normal_login": {"security_ok": True, "full_feature": True},
            "inquiry": {"vendor": "LIO-ORG", "product": "IBLOCK", "revision": "4.0",
                        "device_type": 0},
            "read_capacity": {"last_lba": 0x003FFFFF, "blocks": 0x00400000,
                              "block_size": 512, "capacity_bytes": 0x80000000},
        }
        fs = iscsi.findings([host], {("10.0.0.5", 3260): pr},
                            scope_ips={"10.0.0.5"})
        kinds = {f["kind"] for f in fs}
        for expected in (
            "iscsi_reachable",
            "iscsi_auth_none_discovery",
            "iscsi_targets_disclosed",
            "iscsi_auth_none_normal",
            "iscsi_inquiry_leak",
            "iscsi_lun_readable",
            "iscsi_chap_challenge_captured",
            "iscsi_chap_one_way",
            "iscsi_no_digest",
            "iscsi_legacy_version",
            "iscsi_iqn_hostinfo",
            "iscsi_pivot_portal",
        ):
            self.assertIn(expected, kinds, f"missing finding kind: {expected}")

        # Critical severity on the raw-LUN-mount finding.
        crit = [f for f in fs if f["kind"] == "iscsi_auth_none_normal"]
        self.assertEqual(crit[0]["severity"], "critical")

        # Pivot finding names the out-of-scope portal, not the in-scope host.
        pivot = [f for f in fs if f["kind"] == "iscsi_pivot_portal"][0]
        self.assertIn("192.168.99.10", pivot["detail"])

    def test_hardened_target_no_findings_beyond_reachable(self):
        host = self._host()
        pr = {"is_iscsi": True, "reachable": True,
              "auth_methods": ["KRB5"], "auth_selected": "",
              "discovery_no_auth": False, "operational_reached": False,
              "targets": [], "op_params": {}, "chap": {},
              "chap_one_way": False, "legacy_version": False,
              "normal_login": {}, "inquiry": {}, "read_capacity": {}}
        fs = iscsi.findings([host], {("10.0.0.5", 3260): pr}, scope_ips={"10.0.0.5"})
        kinds = {f["kind"] for f in fs}
        self.assertEqual(kinds, {"iscsi_reachable"})


class TargetsSelectionTest(unittest.TestCase):
    def test_iscsi_targets_lists_open_3260(self):
        h = Host(ip="10.0.0.5", ports=[
            Port(portid=3260, protocol="tcp", state="open", service="iscsi"),
            Port(portid=22, protocol="tcp", state="open", service="ssh"),
        ])
        targets = iscsi.iscsi_targets([h])
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["port"], 3260)


class SendTargetsT2PromotionTest(unittest.TestCase):
    """iscsi_targets_disclosed T1 -> T2 promotion via _verify_normal_login.

    The T2 proof for the SendTargets disclosure is: verify that at least one
    of the disclosed IQNs actually accepts an unauthenticated Normal-session
    Login. When the sweep shows real access, tier goes to 't2' and the
    verified IQN list is baked into `detail`. When the sweep stays quiet, the
    finding remains T1 unchanged.
    """

    def _host(self, ip="10.0.0.5"):
        return Host(ip=ip, ports=[Port(portid=3260, protocol="tcp", state="open",
                                       service="iscsi")])

    def test_probe_verifies_additional_targets_and_records_full_feature(self):
        # Discovery Login: AuthMethod=None, T=1, NSG=1.
        d1 = b"AuthMethod=None\x00"
        pdu1 = (_login_response_bhs(t=1, csg=0, nsg=1, status_class=0,
                                    version_active=0, tsih=0x0001,
                                    dsl=len(d1)) + _pad4(d1))
        # SendTargets returns THREE targets, all sharing the same portal.
        td = (b"TargetName=iqn.2001-04.com.example:s1\x00"
              b"TargetAddress=10.0.0.5:3260,1\x00"
              b"TargetName=iqn.2001-04.com.example:s2\x00"
              b"TargetAddress=10.0.0.5:3260,1\x00"
              b"TargetName=iqn.2001-04.com.example:s3\x00"
              b"TargetAddress=10.0.0.5:3260,1\x00")
        pdu2 = _text_response_bhs(f=1, c=0, dsl=len(td)) + _pad4(td)

        # First-target Normal Login on second connection: T=1 NSG=3 straight
        # to FullFeaturePhase. INQUIRY + READ CAPACITY responses follow.
        norm1 = _login_response_bhs(t=1, csg=0, nsg=3, status_class=0,
                                    version_active=0, tsih=0x0002, dsl=0)
        inq_pdu = (_scsi_data_in_bhs(final=1, dsl=len(_INQUIRY_WIRE))
                   + _pad4(_INQUIRY_WIRE))
        rc_pdu = (_scsi_data_in_bhs(final=1, dsl=len(_READCAP10_WIRE))
                  + _pad4(_READCAP10_WIRE))

        # Verify-only Normal Login for s2 succeeds (T=1 NSG=3, dsl=0).
        verify_s2 = _login_response_bhs(t=1, csg=0, nsg=3, status_class=0,
                                        version_active=0, tsih=0x0003, dsl=0)
        # Verify-only Normal Login for s3 refuses (status_class=2 = initiator
        # error - a legitimate ACL denial that must NOT count as verified).
        verify_s3 = _login_response_bhs(t=0, csg=0, nsg=0, status_class=2,
                                        version_active=0, tsih=0x0000, dsl=0)

        sock1 = ScriptedSock([pdu1, pdu2])                # discovery + sendtargets
        sock2 = ScriptedSock([norm1, inq_pdu, rc_pdu])    # first-target normal login
        sock3 = ScriptedSock([verify_s2])                 # verify s2 (success)
        sock4 = ScriptedSock([verify_s3])                 # verify s3 (denied)

        with mock.patch.object(iscsi.socket, "create_connection",
                               side_effect=[sock1, sock2, sock3, sock4]):
            pr = iscsi.probe("10.0.0.5", 3260, timeout=1.0)

        self.assertEqual(len(pr["targets"]), 3)
        verified = pr["verified_targets"]
        self.assertEqual(len(verified), 3)
        self.assertEqual(verified[0]["iqn"], "iqn.2001-04.com.example:s1")
        self.assertTrue(verified[0]["full_feature"])
        self.assertEqual(verified[1]["iqn"], "iqn.2001-04.com.example:s2")
        self.assertTrue(verified[1]["full_feature"])
        self.assertEqual(verified[2]["iqn"], "iqn.2001-04.com.example:s3")
        self.assertFalse(verified[2]["full_feature"])

    def test_sendtargets_finding_upgraded_to_t2_when_verified(self):
        host = self._host()
        pr = {
            "is_iscsi": True, "reachable": True,
            "auth_methods": ["None"], "auth_selected": "None",
            "discovery_no_auth": True, "operational_reached": True,
            "targets": [
                {"iqn": "iqn.2001-04.com.example:s1",
                 "addresses": [{"ip": "10.0.0.5", "port": 3260,
                                "portal_group": "1"}]},
                {"iqn": "iqn.2001-04.com.example:s2",
                 "addresses": [{"ip": "10.0.0.5", "port": 3260,
                                "portal_group": "1"}]},
            ],
            "op_params": {}, "chap": {}, "chap_one_way": False,
            "version_max": 0, "version_active": 0, "legacy_version": False,
            "normal_login": {"security_ok": True, "full_feature": True},
            "inquiry": {}, "read_capacity": {},
            "verified_targets": [
                {"iqn": "iqn.2001-04.com.example:s1", "full_feature": True},
                {"iqn": "iqn.2001-04.com.example:s2", "full_feature": True},
            ],
        }
        fs = iscsi.findings([host], {("10.0.0.5", 3260): pr},
                            scope_ips={"10.0.0.5"})
        sd = [f for f in fs if f["kind"] == "iscsi_targets_disclosed"]
        self.assertEqual(len(sd), 1)
        self.assertEqual(sd[0]["depth_tier"], "t2")
        # Verified IQNs are the T2 evidence baked into detail.
        self.assertIn("Proof-of-exploit (T2)", sd[0]["detail"])
        self.assertIn("iqn.2001-04.com.example:s1", sd[0]["detail"])
        self.assertIn("iqn.2001-04.com.example:s2", sd[0]["detail"])
        self.assertIn("2/2", sd[0]["detail"])

    def test_sendtargets_finding_stays_t1_when_verify_finds_nothing(self):
        host = self._host()
        pr = {
            "is_iscsi": True, "reachable": True,
            "auth_methods": ["None"], "auth_selected": "None",
            "discovery_no_auth": True, "operational_reached": True,
            "targets": [
                {"iqn": "iqn.2001-04.com.example:s1",
                 "addresses": [{"ip": "10.0.0.5", "port": 3260,
                                "portal_group": "1"}]},
            ],
            "op_params": {}, "chap": {}, "chap_one_way": False,
            "version_max": 0, "version_active": 0, "legacy_version": False,
            # Discovery succeeded and IQN was disclosed, but the array's ACL
            # refused Normal Login - the T1 disclosure still lands, no T2.
            "normal_login": {"security_ok": True},
            "inquiry": {}, "read_capacity": {},
            "verified_targets": [
                {"iqn": "iqn.2001-04.com.example:s1", "full_feature": False},
            ],
        }
        fs = iscsi.findings([host], {("10.0.0.5", 3260): pr},
                            scope_ips={"10.0.0.5"})
        sd = [f for f in fs if f["kind"] == "iscsi_targets_disclosed"]
        self.assertEqual(len(sd), 1)
        self.assertEqual(sd[0]["depth_tier"], "t1")
        self.assertNotIn("Proof-of-exploit", sd[0]["detail"])

    def test_verify_normal_login_returns_true_on_full_feature(self):
        # Login SecNeg -> T=1, NSG=1 (moves to OpNeg); OpNeg response T=1,
        # NSG=3 (moves to FullFeaturePhase). Real Login Response bytes.
        pdu1 = _login_response_bhs(t=1, csg=0, nsg=1, status_class=0,
                                   version_active=0, tsih=0x0001, dsl=0)
        pdu2 = _login_response_bhs(t=1, csg=1, nsg=3, status_class=0,
                                   version_active=0, tsih=0x0001, dsl=0)
        sock = ScriptedSock([pdu1, pdu2])
        with mock.patch.object(iscsi.socket, "create_connection",
                               side_effect=[sock]):
            ok = iscsi._verify_normal_login("10.0.0.5", 3260,
                                            "iqn.2001-04.com.example:s2", 1.0)
        self.assertTrue(ok)

    def test_verify_normal_login_returns_false_on_status_class_error(self):
        # StatusClass=2 (initiator error) - a real ACL denial.
        pdu = _login_response_bhs(t=0, csg=0, nsg=0, status_class=2,
                                  version_active=0, tsih=0x0000, dsl=0)
        sock = ScriptedSock([pdu])
        with mock.patch.object(iscsi.socket, "create_connection",
                               side_effect=[sock]):
            ok = iscsi._verify_normal_login("10.0.0.5", 3260,
                                            "iqn.2001-04.com.example:s2", 1.0)
        self.assertFalse(ok)

    def test_verify_normal_login_returns_false_on_socket_timeout(self):
        def _boom(addr, timeout=None):
            raise socket_timeout()
        with mock.patch.object(iscsi.socket, "create_connection",
                               side_effect=_boom):
            ok = iscsi._verify_normal_login("10.0.0.5", 3260,
                                            "iqn.2001-04.com.example:s2", 1.0)
        self.assertFalse(ok)


def socket_timeout():
    import socket as _s
    return _s.timeout("verify timeout")


if __name__ == "__main__":
    unittest.main()
