"""Tests for recce.services.nbd_ndmp.

Fixtures are hand-derived from the NBD protocol doc (Handshake / Options)
and SNIA NDMP v4 (§3.3 message framing, §3.6 CONFIG_GET_* replies). The
socket layer is stubbed with a scripted fake that returns pre-built PDUs
in response to each sendall() / recv(); no test touches the network.
"""
from __future__ import annotations

import struct
import unittest
from unittest import mock

from recce.core.models import Host, Port
from recce.services import nbd_ndmp as nn


# ---------------------------------------------------------------------------
# Scripted fake socket (no network traffic).
# ---------------------------------------------------------------------------

class ScriptedSock:
    """Each sendall() dequeues the next queued response into a read buffer
    that recv() drains. When the client should be able to send several
    frames before receiving anything, seed with `initial_buf`."""

    def __init__(self, responses=None, initial_buf: bytes = b""):
        self._responses = list(responses or [])
        self._buf = bytes(initial_buf)
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))
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


def _install_connections(monkeypatch, sockets):
    queue = list(sockets)

    def fake_create(_addr, timeout=None):
        if not queue:
            raise AssertionError("unexpected extra connection")
        return queue.pop(0)

    monkeypatch.setattr(nn.socket, "create_connection", fake_create)
    return queue


# ---------------------------------------------------------------------------
# NBD wire helpers - derived from NBD proto.md
# ---------------------------------------------------------------------------

def _nbd_greet_fixed(handshake_flags: int = 0x0001) -> bytes:
    """Fixed-newstyle server greeting: NBDMAGIC + IHAVEOPT + 16-bit flags."""
    return nn.NBD_MAGIC + nn.NBD_IHAVEOPT + struct.pack(">H", handshake_flags)


def _nbd_reply(option: int, reply_type: int, data: bytes = b"") -> bytes:
    """20-byte NBD option reply header + data.
       magic(8) + option(4) + reply_type(4) + dlen(4) + data."""
    return (struct.pack(">Q", nn.NBD_REP_MAGIC)
            + struct.pack(">III", option, reply_type, len(data))
            + data)


def _nbd_server_entry(name: str, description: str = "") -> bytes:
    """NBD_REP_SERVER payload = name-len(4) + name + description."""
    n = name.encode()
    d = description.encode()
    return struct.pack(">I", len(n)) + n + d


def _nbd_info_export(size: int, flags: int) -> bytes:
    """NBD_INFO_EXPORT payload: info_type(2) + size(8) + flags(2)."""
    return struct.pack(">HQH", nn.NBD_INFO_EXPORT, size, flags)


def _nbd_info_block_size(mn: int, pref: int, mx: int) -> bytes:
    return struct.pack(">HIII", nn.NBD_INFO_BLOCK_SIZE, mn, pref, mx)


# ---------------------------------------------------------------------------
# NBD tests
# ---------------------------------------------------------------------------

class NBDHandshakeTest(unittest.TestCase):
    def test_fixed_newstyle_handshake_parses(self):
        greet = _nbd_greet_fixed(0x0001)
        sock = ScriptedSock(initial_buf=greet)
        # settimeout on socket happens via _recvn's caller.
        hs = nn._nbd_handshake(sock)
        self.assertTrue(hs["ok"])
        self.assertEqual(hs["style"], "fixed-newstyle")
        self.assertEqual(hs["handshake_flags"], 0x0001)
        # We should have echoed our client flags (uint32 BE).
        self.assertEqual(len(sock.sent), 1)
        self.assertEqual(len(sock.sent[0]), 4)

    def test_bad_magic_returns_error(self):
        sock = ScriptedSock(initial_buf=b"NOTMAGIC" + b"\x00" * 10)
        hs = nn._nbd_handshake(sock)
        self.assertFalse(hs["ok"])
        self.assertIn("magic", hs["error"])


class NBDReplyParseTest(unittest.TestCase):
    def test_server_entry_decoded(self):
        # Two REP_SERVER + ACK sequence.
        greet = _nbd_greet_fixed()
        rep1 = _nbd_reply(nn.NBD_OPT_LIST, nn.NBD_REP_SERVER,
                          _nbd_server_entry("backups", "nightly rsnapshot"))
        rep2 = _nbd_reply(nn.NBD_OPT_LIST, nn.NBD_REP_SERVER,
                          _nbd_server_entry("vm01"))
        rep3 = _nbd_reply(nn.NBD_OPT_LIST, nn.NBD_REP_ACK)
        # Client sends: client-flags(4), then OPT_LIST(16), then OPT_ABORT(16)
        # in the finally block. Responses are appended on the first sendall.
        # We supply the full stream up front so no back-pressure.
        sock = ScriptedSock(initial_buf=greet + rep1 + rep2 + rep3)
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            out = nn.nbd_list_exports("10.0.0.5", 10809, timeout=1.0)
        self.assertTrue(out["reachable"])
        self.assertEqual(out["style"], "fixed-newstyle")
        self.assertEqual(len(out["exports"]), 2)
        self.assertEqual(out["exports"][0]["name"], "backups")
        self.assertEqual(out["exports"][0]["description"], "nightly rsnapshot")
        self.assertEqual(out["exports"][1]["name"], "vm01")


class NBDExportInfoTest(unittest.TestCase):
    def test_read_only_flag_extracted(self):
        greet = _nbd_greet_fixed()
        # NBD_INFO_EXPORT with 2 GiB size and READ_ONLY|HAS_FLAGS set.
        size = 2 * 1024 * 1024 * 1024
        flags = nn.NBD_FLAG_HAS_FLAGS | nn.NBD_FLAG_READ_ONLY
        rep_info = _nbd_reply(nn.NBD_OPT_INFO, nn.NBD_REP_INFO,
                              _nbd_info_export(size, flags))
        rep_bs = _nbd_reply(nn.NBD_OPT_INFO, nn.NBD_REP_INFO,
                            _nbd_info_block_size(512, 4096, 33554432))
        rep_ack = _nbd_reply(nn.NBD_OPT_INFO, nn.NBD_REP_ACK)
        sock = ScriptedSock(initial_buf=greet + rep_info + rep_bs + rep_ack)
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            out = nn.nbd_export_info("10.0.0.5", 10809, "backups", timeout=1.0)
        self.assertEqual(out["size"], size)
        self.assertIn("READ_ONLY", out["flags"])
        self.assertIn("HAS_FLAGS", out["flags"])
        self.assertEqual(out["block_min"], 512)
        self.assertEqual(out["block_preferred"], 4096)
        self.assertEqual(out["block_max"], 33554432)

    def test_writable_when_read_only_missing(self):
        greet = _nbd_greet_fixed()
        flags = nn.NBD_FLAG_HAS_FLAGS | nn.NBD_FLAG_SEND_TRIM
        rep_info = _nbd_reply(nn.NBD_OPT_INFO, nn.NBD_REP_INFO,
                              _nbd_info_export(1 << 40, flags))
        rep_ack = _nbd_reply(nn.NBD_OPT_INFO, nn.NBD_REP_ACK)
        sock = ScriptedSock(initial_buf=greet + rep_info + rep_ack)
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            out = nn.nbd_export_info("10.0.0.5", 10809, "vm01", timeout=1.0)
        self.assertNotIn("READ_ONLY", out["flags"])
        self.assertIn("SEND_TRIM", out["flags"])


class NBDTLSPostureTest(unittest.TestCase):
    def test_tls_supported_ack(self):
        greet = _nbd_greet_fixed()
        # OPT_LIST answered with ACK immediately (no entries).
        rep_list_ack = _nbd_reply(nn.NBD_OPT_LIST, nn.NBD_REP_ACK)
        rep_tls_ack = _nbd_reply(nn.NBD_OPT_STARTTLS, nn.NBD_REP_ACK)
        sock = ScriptedSock(initial_buf=greet + rep_list_ack + rep_tls_ack)
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            out = nn.nbd_tls_posture("10.0.0.5", 10809, timeout=1.0)
        self.assertTrue(out["tls_supported"])
        self.assertFalse(out["list_before_tls"])

    def test_tls_refused_by_policy(self):
        greet = _nbd_greet_fixed()
        # OPT_LIST returned an entry BEFORE TLS - export names leak cleartext.
        rep_srv = _nbd_reply(nn.NBD_OPT_LIST, nn.NBD_REP_SERVER,
                             _nbd_server_entry("public"))
        rep_ack = _nbd_reply(nn.NBD_OPT_LIST, nn.NBD_REP_ACK)
        rep_tls = _nbd_reply(nn.NBD_OPT_STARTTLS, nn.NBD_REP_ERR_POLICY)
        sock = ScriptedSock(initial_buf=greet + rep_srv + rep_ack + rep_tls)
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            out = nn.nbd_tls_posture("10.0.0.5", 10809, timeout=1.0)
        self.assertFalse(out["tls_supported"])
        self.assertTrue(out["list_before_tls"])


class NBDBlock0FingerprintTest(unittest.TestCase):
    def _fingerprint_with_block(self, block: bytes) -> dict:
        greet = _nbd_greet_fixed()
        # NBD_OPT_GO replies: INFO_EXPORT, then ACK.
        info_go = _nbd_reply(nn.NBD_OPT_GO, nn.NBD_REP_INFO,
                             _nbd_info_export(1 << 30, nn.NBD_FLAG_HAS_FLAGS))
        ack_go = _nbd_reply(nn.NBD_OPT_GO, nn.NBD_REP_ACK)
        # Transmission-phase reply: simple reply magic + err(4) + handle(8) + 4096 bytes.
        # Handle must match request (1).
        assert len(block) == 4096
        read_reply = (struct.pack(">IIQ", nn.NBD_SIMPLE_REPLY_MAGIC, 0, 1)
                      + block)
        sock = ScriptedSock(initial_buf=greet + info_go + ack_go + read_reply)
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            return nn.nbd_block0_fingerprint("10.0.0.5", 10809, "vm01",
                                             timeout=1.0)

    def test_luks_magic(self):
        block = b"LUKS\xba\xbe\x00\x01" + b"\x00" * (4096 - 8)
        out = self._fingerprint_with_block(block)
        self.assertEqual(out["error"], "")
        self.assertIn("LUKS", out["label"])

    def test_mbr_55aa_signature(self):
        block = bytearray(b"\x00" * 4096)
        block[0:11] = b"\xEB\x58\x90MSDOS5.0"
        block[0x1FE:0x200] = b"\x55\xAA"
        out = self._fingerprint_with_block(bytes(block))
        # 55AA at end of first sector => MBR partition table.
        self.assertEqual(out["label"], "MBR partition table")

    def test_ext4_magic_at_0x438(self):
        block = bytearray(b"\x00" * 4096)
        block[0x438:0x43A] = b"\x53\xEF"
        out = self._fingerprint_with_block(bytes(block))
        self.assertIn("ext", out["label"])

    def test_unknown_block_returns_empty_label(self):
        out = self._fingerprint_with_block(b"\xAA" * 4096)
        self.assertEqual(out["label"], "")


# ---------------------------------------------------------------------------
# NDMP wire helpers - derived from SNIA NDMP v4 §3.3 (framing) + §3.6
# ---------------------------------------------------------------------------

def _ndmp_header(seq: int, msg_type: int, message: int,
                 reply_sequence: int = 0, error: int = 0) -> bytes:
    """24-byte NDMP header: seq, timestamp, msg_type, message, reply_seq, error."""
    return struct.pack(">IIIIII", seq, 0, msg_type, message,
                       reply_sequence, error)


def _xdr_str(s: bytes | str) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    pad = (4 - len(s) % 4) % 4
    return struct.pack(">I", len(s)) + s + b"\x00" * pad


def _ndmp_frame(payload: bytes) -> bytes:
    """RFC 5531 record marking: high bit set + 31-bit size, then payload."""
    return struct.pack(">I", 0x80000000 | len(payload)) + payload


def _ndmp_reply(request_seq: int, request_msg: int, body: bytes,
                error: int = 0, seq: int = 100) -> bytes:
    payload = _ndmp_header(seq, nn.NDMP_MSGTYPE_REPLY, request_msg,
                           reply_sequence=request_seq, error=error) + body
    return _ndmp_frame(payload)


class NDMPXDRTest(unittest.TestCase):
    def test_string_roundtrip_with_padding(self):
        wire = _xdr_str("netapp01.corp")
        s, off = nn._xdr_read_string(wire, 0)
        self.assertEqual(s, b"netapp01.corp")
        # Off must consume padding to a 4-byte boundary.
        self.assertEqual(off, len(wire))

    def test_uquad_big_endian(self):
        wire = struct.pack(">II", 0x00000001, 0x00000000)
        v, off = nn._xdr_read_uquad(wire, 0)
        self.assertEqual(v, 1 << 32)
        self.assertEqual(off, 8)


class NDMPProbeTest(unittest.TestCase):
    def test_server_info_and_auth_types_parsed(self):
        # v4 CONNECT_OPEN reply: error(4) = 0.
        open_body = struct.pack(">I", 0)
        # CONFIG_GET_SERVER_INFO reply: err + vendor + product + rev + auth_types<>.
        srv_body = (struct.pack(">I", 0)
                    + _xdr_str("NetApp")
                    + _xdr_str("OnTap")
                    + _xdr_str("9.11.1")
                    + struct.pack(">I", 2)      # count
                    + struct.pack(">I", nn.NDMP_AUTH_TEXT)
                    + struct.pack(">I", nn.NDMP_AUTH_MD5))
        # CONFIG_GET_HOST_INFO reply: err + hostname + os_type + os_vers + hostid.
        host_body = (struct.pack(">I", 0)
                     + _xdr_str("netapp01.corp.example")
                     + _xdr_str("NetApp Release")
                     + _xdr_str("9.11.1")
                     + _xdr_str("0123456789"))
        # FS_INFO reply: err + count=1 + one fs entry (subset).
        fs_body = (struct.pack(">I", 0)
                   + struct.pack(">I", 1)
                   + struct.pack(">I", 0)                 # invalid flags
                   + _xdr_str("wafl")                     # fs_type
                   + _xdr_str("/vol/vol0")                # logical
                   + _xdr_str("/dev/sd0")                 # physical
                   + struct.pack(">II", 0, 0)             # total 0
                   + struct.pack(">II", 0, 0)             # used
                   + struct.pack(">II", 0, 0)             # avail
                   + struct.pack(">II", 0, 0)             # total inodes
                   + struct.pack(">II", 0, 0)             # used inodes
                   + struct.pack(">I", 0)                 # env count = 0
                   + _xdr_str(""))                        # status
        tape_body = struct.pack(">II", 0, 0)              # err=0, count=0
        scsi_body = struct.pack(">II", 0, 0)
        # AUTH_ATTR (MD5) reply: err + auth_type + 64-byte challenge.
        challenge = bytes(range(64))
        auth_body = (struct.pack(">I", 0)
                     + struct.pack(">I", nn.NDMP_AUTH_MD5)
                     + challenge)

        frames = [
            _ndmp_reply(1, nn.NDMP_CONNECT_OPEN, open_body),
            _ndmp_reply(2, nn.NDMP_CONFIG_GET_SERVER_INFO, srv_body),
            _ndmp_reply(3, nn.NDMP_CONFIG_GET_HOST_INFO, host_body),
            _ndmp_reply(4, nn.NDMP_CONFIG_GET_FS_INFO, fs_body),
            _ndmp_reply(5, nn.NDMP_CONFIG_GET_TAPE_INFO, tape_body),
            _ndmp_reply(6, nn.NDMP_CONFIG_GET_SCSI_INFO, scsi_body),
            _ndmp_reply(7, nn.NDMP_CONFIG_GET_AUTH_ATTR, auth_body),
        ]
        sock = ScriptedSock(initial_buf=b"".join(frames))
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            pr = nn.ndmp_probe("10.0.0.5", 10000, timeout=1.0)

        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version"], 4)
        self.assertFalse(pr["downgraded"])
        si = pr["server_info"]
        self.assertEqual(si["vendor"], "NetApp")
        self.assertEqual(si["product"], "OnTap")
        self.assertEqual(si["revision"], "9.11.1")
        self.assertIn(nn.NDMP_AUTH_TEXT, si["auth_types"])
        self.assertIn(nn.NDMP_AUTH_MD5, si["auth_types"])
        hi = pr["host_info"]
        self.assertEqual(hi["hostname"], "netapp01.corp.example")
        fs = pr["fs_info"]["filesystems"]
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["logical_device"], "/vol/vol0")
        aa = pr["auth_attr_md5"]
        self.assertEqual(aa["auth_type"], nn.NDMP_AUTH_MD5)
        self.assertEqual(aa["challenge"], challenge)

    def test_version_downgrade_v3(self):
        # v4 CONNECT_OPEN denied (error != 0), v3 accepted.
        v4_deny = _ndmp_reply(1, nn.NDMP_CONNECT_OPEN,
                              struct.pack(">I", 4))
        v3_ok = _ndmp_reply(2, nn.NDMP_CONNECT_OPEN,
                            struct.pack(">I", 0))
        # No further CONFIG replies — the sock will EOF and probe stops.
        sock = ScriptedSock(initial_buf=v4_deny + v3_ok)
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            pr = nn.ndmp_probe("10.0.0.5", 10000, timeout=1.0)
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version"], 3)
        self.assertTrue(pr["downgraded"])


class NDMPMD5CaptureTest(unittest.TestCase):
    def test_captures_64_byte_challenge(self):
        open_ok = _ndmp_reply(1, nn.NDMP_CONNECT_OPEN, struct.pack(">I", 0))
        challenge = b"\xAB" * 64
        auth_body = (struct.pack(">I", 0)
                     + struct.pack(">I", nn.NDMP_AUTH_MD5)
                     + challenge)
        auth_reply = _ndmp_reply(2, nn.NDMP_CONFIG_GET_AUTH_ATTR, auth_body)
        client_auth_reply = _ndmp_reply(3, nn.NDMP_CONNECT_CLIENT_AUTH,
                                        struct.pack(">I", 6),  # err
                                        error=6)
        sock = ScriptedSock(initial_buf=open_ok + auth_reply + client_auth_reply)
        with mock.patch.object(nn.socket, "create_connection",
                               return_value=sock):
            cap = nn.ndmp_capture_md5("10.0.0.5", 10000, "backup", timeout=1.0)
        self.assertTrue(cap["captured"])
        self.assertEqual(cap["username"], "backup")
        self.assertEqual(bytes.fromhex(cap["challenge_hex"]), challenge)
        self.assertEqual(len(bytes.fromhex(cap["response_hex"])), 16)
        line = nn.hashcat_ndmp_md5_line("backup", cap["challenge_hex"],
                                        cap["response_hex"])
        self.assertTrue(line.endswith(":backup"))
        # hashcat 50 shape: <response>:<challenge>:<user>
        parts = line.split(":")
        self.assertEqual(len(parts), 3)
        self.assertEqual(parts[0], cap["response_hex"])
        self.assertEqual(parts[1], cap["challenge_hex"])


# ---------------------------------------------------------------------------
# Target detection + findings
# ---------------------------------------------------------------------------

class DetectTest(unittest.TestCase):
    def test_is_nbd_by_port(self):
        p = Port(portid=10809, service="unknown")
        self.assertTrue(nn.is_nbd(p))
        self.assertFalse(nn.is_ndmp(p))

    def test_is_ndmp_by_service(self):
        p = Port(portid=10000, service="ndmp")
        self.assertTrue(nn.is_ndmp(p))

    def test_is_ndmp_by_port_only_when_service_unknown(self):
        # webmin on 10000/http should NOT be treated as ndmp.
        p = Port(portid=10000, service="http", product="MiniServ")
        self.assertFalse(nn.is_ndmp(p))
        # blank service => the port name wins.
        self.assertTrue(nn.is_ndmp(Port(portid=10000, service="")))
        self.assertTrue(nn.is_ndmp(Port(portid=10000, service="tcpwrapped")))

    def test_nbd_signature_via_banner(self):
        p = Port(portid=6667, service="unknown", banner="NBDMAGIC")
        self.assertTrue(nn.is_nbd(p))


class FindingsTest(unittest.TestCase):
    def _mk_host(self, port_id: int, service: str = "") -> Host:
        return Host(ip="10.0.0.5",
                    ports=[Port(portid=port_id, service=service, state="open")])

    def test_nbd_findings_full_set(self):
        host = self._mk_host(10809)
        probes = {("10.0.0.5", 10809): {
            "reachable": True,
            "style": "fixed-newstyle",
            "exports": [
                {"name": "backups", "description": "nightly",
                 "size": 100 * 1024 ** 3,
                 "flags_raw": nn.NBD_FLAG_HAS_FLAGS,
                 "flags": ["HAS_FLAGS"],
                 "block0_label": "LUKS-encrypted volume"},
                {"name": "vm01", "description": "",
                 "size": 40 * 1024 ** 3,
                 "flags_raw": nn.NBD_FLAG_HAS_FLAGS | nn.NBD_FLAG_READ_ONLY,
                 "flags": ["HAS_FLAGS", "READ_ONLY"]},
            ],
            "tls": {"tls_supported": False, "list_before_tls": True},
        }}
        fs = nn.findings([host], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("nbd_export_list", kinds)
        self.assertIn("nbd_export_writable", kinds)
        self.assertIn("nbd_export_fingerprint", kinds)
        self.assertIn("nbd_cleartext", kinds)
        # Every finding has a stable kind + severity + target.
        for f in fs:
            self.assertTrue(f["kind"])
            self.assertEqual(f["target"], "10.0.0.5:10809")
            self.assertIn(f["severity"], ("critical", "high", "medium",
                                          "low", "info"))

    def test_ndmp_findings_and_cross_service(self):
        host = self._mk_host(10000, "ndmp")
        probes = {("10.0.0.5", 10000): {
            "reachable": True, "version": 4, "downgraded": False,
            "server_info": {"vendor": "NetApp", "product": "OnTap",
                            "revision": "9.11.1",
                            "auth_types": [nn.NDMP_AUTH_NONE,
                                           nn.NDMP_AUTH_TEXT,
                                           nn.NDMP_AUTH_MD5],
                            "auth_type_names": ["NONE", "TEXT", "MD5"]},
            "host_info": {"hostname": "netapp01.corp.example",
                          "os_type": "NetApp", "os_vers": "9.11.1",
                          "hostid": "0123"},
            "fs_info": {"filesystems": [{"logical_device": "/vol/vol0"}]},
            "tape_info": {"tapes": [{"model": "IBM TS4300", "devices": []}]},
            "scsi_info": {"scsi": []},
            "md5_capture": {"captured": True, "username": "backup",
                            "challenge_hex": "aa" * 64,
                            "response_hex": "00" * 16, "error_code": 6},
        }}
        fs = nn.findings([host], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("ndmp_info_unauth", kinds)
        self.assertIn("ndmp_unauth", kinds)                    # AUTH_NONE => critical
        self.assertIn("ndmp_cleartext_auth", kinds)            # AUTH_TEXT
        self.assertIn("ndmp_host_info", kinds)
        self.assertIn("ndmp_inventory_leak", kinds)
        self.assertIn("ndmp_md5_challenge_capture", kinds)
        self.assertIn("ndmp_session_hijack_surface", kinds)
        # One critical for AUTH_NONE + one critical for hijack surface.
        crits = [f for f in fs if f["severity"] == "critical"]
        self.assertGreaterEqual(len(crits), 2)
        # Cross-service wire folds hostname + hash.
        wire = nn.wire_cross_service([host], probes)
        self.assertIn("netapp01.corp.example", host.hostnames)
        self.assertEqual(len(wire["hashes"]), 1)
        self.assertEqual(wire["hashes"][0]["hashcat_mode"], 50)
        self.assertIn("backup", wire["usernames"])

    def test_downgrade_v3_reported(self):
        host = self._mk_host(10000, "ndmp")
        probes = {("10.0.0.5", 10000): {
            "reachable": True, "version": 3, "downgraded": True,
        }}
        fs = nn.findings([host], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("ndmp_legacy_version", kinds)


class NBDExportListT2PromotionTest(unittest.TestCase):
    """T1->T2 SAFE proof promotion for nbd_export_list.

    T2 evidence is a single controlled NBD_OPT_INFO round-trip past the T1
    NBD_OPT_LIST enumeration. When the server hands back a real
    NBD_INFO_EXPORT block (size + transmission-flag bits) for at least one
    listed export, that is server-side wire evidence of a read succeeding
    without authentication; depth_tier lifts to "t2" and the finding
    detail carries the proof line. When only the list came back (INFO
    never ran / returned nothing), the finding stays at "t1"."""

    def _mk_host(self) -> Host:
        return Host(ip="10.0.0.5",
                    ports=[Port(portid=10809, service="", state="open")])

    def _get_list_finding(self, fs: list[dict]) -> dict:
        matches = [f for f in fs if f["kind"] == "nbd_export_list"]
        self.assertEqual(len(matches), 1, "expected exactly one export_list "
                         f"finding, got {len(matches)}")
        return matches[0]

    def test_promotes_to_t2_when_info_evidence_present(self):
        # Vulnerable path: OPT_LIST + OPT_INFO both returned real bytes.
        host = self._mk_host()
        probes = {("10.0.0.5", 10809): {
            "reachable": True, "style": "fixed-newstyle",
            "exports": [
                {"name": "backups", "description": "nightly",
                 "size": 100 * 1024 ** 3,
                 "flags_raw": nn.NBD_FLAG_HAS_FLAGS | nn.NBD_FLAG_READ_ONLY,
                 "flags": ["HAS_FLAGS", "READ_ONLY"]},
            ],
        }}
        f = self._get_list_finding(nn.findings([host], probes))
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("T2 proof", f["detail"])
        self.assertIn("NBD_OPT_INFO", f["detail"])
        self.assertIn("'backups'", f["detail"])
        # Real wire evidence bytes surface: flags list + hex flags_raw.
        self.assertIn("READ_ONLY", f["detail"])
        # HAS_FLAGS(1) | READ_ONLY(2) = 0x0003.
        self.assertIn("0x0003", f["detail"])

    def test_promotes_when_size_alone_present(self):
        # Some servers hand back size with no additional flag decoding.
        host = self._mk_host()
        probes = {("10.0.0.5", 10809): {
            "reachable": True, "style": "fixed-newstyle",
            "exports": [
                {"name": "vol0", "description": "",
                 "size": 512 * 1024 * 1024,
                 "flags_raw": 0, "flags": []},
            ],
        }}
        f = self._get_list_finding(nn.findings([host], probes))
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("T2 proof", f["detail"])
        self.assertIn("'vol0'", f["detail"])

    def test_stays_t1_when_info_never_ran(self):
        # Patched-ish / degraded path: server listed exports but NBD_OPT_INFO
        # returned nothing (no size, no flags decoded, empty flags list).
        host = self._mk_host()
        probes = {("10.0.0.5", 10809): {
            "reachable": True, "style": "fixed-newstyle",
            "exports": [
                {"name": "hidden", "description": "",
                 "size": 0, "flags_raw": 0, "flags": []},
            ],
        }}
        f = self._get_list_finding(nn.findings([host], probes))
        self.assertEqual(f["depth_tier"], "t1")
        self.assertNotIn("T2 proof", f["detail"])

    def test_no_finding_when_probe_timed_out(self):
        # Timeout / unreachable: no exports at all -> no export_list finding.
        host = self._mk_host()
        probes = {("10.0.0.5", 10809): {
            "reachable": False, "style": "", "exports": [], "error": "timeout",
        }}
        fs = nn.findings([host], probes)
        self.assertFalse(
            any(f["kind"] == "nbd_export_list" for f in fs),
            "no finding should be emitted when the probe returned no exports")


class RunbookAndF2VTest(unittest.TestCase):
    def test_runbook_nbd_shape(self):
        rb = nn.runbook("10.0.0.5", 10809)
        self.assertTrue(all("phase" in s and "command" in s for s in rb))
        self.assertTrue(any("nbd-client" in s["command"] for s in rb))

    def test_runbook_ndmp_shape(self):
        rb = nn.runbook("10.0.0.5", 10000)
        self.assertTrue(any("hashcat" in s["command"] for s in rb))

    def test_findings_to_vulns_shape(self):
        f = [{"category": "nbd_ndmp", "severity": "high",
              "title": "T", "target": "10.0.0.5:10000",
              "detail": "d", "tool": "x", "command": "c",
              "remediation": "r", "cwes": ["CWE-306"], "kind": "ndmp_unauth",
              "narrative": ""}]
        by_ip = nn.findings_to_vulns(f)
        self.assertIn("10.0.0.5", by_ip)
        v = by_ip["10.0.0.5"][0]
        self.assertEqual(v.port, 10000)
        self.assertEqual(v.severity, "high")


if __name__ == "__main__":
    unittest.main()
