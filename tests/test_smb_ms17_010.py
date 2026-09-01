"""T2 promotion: MS17-010 (EternalBlue) wire-signature probe.

Covers the packet builders (correct SMB1 shape + expected commands + null-session
+ IPC$ tree connect + Trans PeekNamedPipe with invalid FID) and the four decision
paths of `probe_ms17_010`: vulnerable / patched / unknown-status / socket-timeout.
Also asserts that a vulnerable verdict promotes the emitted finding to critical +
depth_tier=t2 with the observed wire evidence attached.
"""
from __future__ import annotations

import socket
import struct

from recce.services import smb


# --- helpers: build a synthetic SMB1 server response ----------------------------

def _resp(cmd: int, status: int, uid: int = 0, tid: int = 0,
          wct: int = 0, words: bytes = b"", bcc_payload: bytes = b"") -> bytes:
    """Frame one canned SMB1 response with the requested NT status.

    Enough of the header to pass `_parse_smb1_status`: protocol + cmd + status
    + flags + reserved + TID + PID + UID + MID. Body: word count (0) + byte
    count (0). Prefixed with the 4-byte NetBIOS length."""
    hdr = (b"\xffSMB"
           + bytes([cmd])
           + struct.pack("<I", status)
           + b"\x98"                                     # Flags: response bit
           + struct.pack("<H", 0xC843)
           + b"\x00\x00"
           + b"\x00" * 8
           + b"\x00\x00"
           + struct.pack("<HHHH", tid, 0xFEFF, uid, 0))
    body = bytes([wct]) + words + struct.pack("<H", len(bcc_payload)) + bcc_payload
    smb = hdr + body
    return struct.pack(">I", len(smb)) + smb


class _FakeSock:
    """Minimal socket stub: hands out queued responses on `.recv()` in NetBIOS
    frame order and records everything `.sendall()` sees for assertion."""

    def __init__(self, replies: list[bytes]):
        self._replies = list(replies)
        self._buf = b""
        self.sent: list[bytes] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        if self._replies:
            self._buf += self._replies.pop(0)

    def recv(self, n: int) -> bytes:
        if not self._buf:
            return b""
        take, self._buf = self._buf[:n], self._buf[n:]
        return take

    def settimeout(self, _t: float) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _install_fake(monkeypatch, replies: list[bytes]) -> _FakeSock:
    fake = _FakeSock(replies)

    def _fake_connect(addr, timeout=None):
        assert addr[1] == 445
        return fake

    monkeypatch.setattr(smb.socket, "create_connection", _fake_connect)
    return fake


# --- packet builders ------------------------------------------------------------

def test_ms17_negotiate_offers_only_nt_lm_012():
    p = smb._ms17_negotiate()
    assert struct.unpack(">I", p[:4])[0] == len(p) - 4
    assert p[4:8] == b"\xffSMB"
    assert p[8] == 0x72                        # SMB_COM_NEGOTIATE
    assert b"\x02NT LM 0.12\x00" in p         # exact MS17-010 dialect string


def test_ms17_session_setup_is_null_session():
    p = smb._ms17_session_setup()
    assert p[4:8] == b"\xffSMB"
    assert p[8] == 0x73                        # SMB_COM_SESSION_SETUP_ANDX
    # word count 13; OEM + Unicode password lengths are both 0 (null creds)
    smb_pdu = p[4:]
    wct = smb_pdu[32]
    assert wct == 13
    # Word 8/9 are OEM/Unicode password lengths (each 2 bytes) in our layout
    # struct: BBHHHHIHHII -> offsets: 0(1)+1(1)+2(2)+4(2)+6(2)+8(2)+10(4)+
    # 14(2 OEM)+16(2 UNI)+18(4)+22(4). Both zero => null session.
    words = smb_pdu[33:33 + 26]
    oem_len = struct.unpack("<H", words[14:16])[0]
    uni_len = struct.unpack("<H", words[16:18])[0]
    assert oem_len == 0 and uni_len == 0


def test_ms17_tree_connect_targets_ipc_share():
    p = smb._ms17_tree_connect(uid=0x0800, ip="10.1.2.3")
    assert p[8] == 0x75                        # SMB_COM_TREE_CONNECT_ANDX
    # UID field at header offset 28..30
    smb_pdu = p[4:]
    uid = struct.unpack("<H", smb_pdu[28:30])[0]
    assert uid == 0x0800
    # Unicode path "\\10.1.2.3\IPC$" must be in the byte block
    assert "\\\\10.1.2.3\\IPC$".encode("utf-16-le") in p
    assert b"?????\x00" in p                  # service string


def test_ms17_trans_peek_uses_invalid_fid_and_pipe_name():
    p = smb._ms17_trans_peek(uid=0x0800, tid=0x1000)
    assert p[8] == 0x25                        # SMB_COM_TRANSACTION
    # setup field carries PeekNamedPipe(0x0023) + FID=0
    assert struct.pack("<HH", 0x0023, 0x0000) in p
    assert b"\\PIPE\\\x00" in p


# --- probe verdicts -------------------------------------------------------------

_NEG_OK = _resp(0x72, 0x00000000, uid=0)
_SES_OK = _resp(0x73, 0x00000000, uid=0x0800)
_TREE_OK = _resp(0x75, 0x00000000, uid=0x0800, tid=0x1000)


def test_probe_ms17_010_vulnerable(monkeypatch):
    trans_vuln = _resp(0x25, smb._MS17_VULN_STATUS, uid=0x0800, tid=0x1000)
    _install_fake(monkeypatch, [_NEG_OK, _SES_OK, _TREE_OK, trans_vuln])
    r = smb.probe_ms17_010("10.1.2.3")
    assert r is not None
    assert r["vulnerable"] is True
    assert r["status"] == 0xC0000205
    assert r["status_label"] == "STATUS_INSUFF_SERVER_RESOURCES"
    assert "0xc0000205" in r["evidence"].lower()


def test_probe_ms17_010_patched(monkeypatch):
    trans_patch = _resp(0x25, smb._MS17_PATCHED_STATUS, uid=0x0800, tid=0x1000)
    _install_fake(monkeypatch, [_NEG_OK, _SES_OK, _TREE_OK, trans_patch])
    r = smb.probe_ms17_010("10.1.2.3")
    assert r is not None
    assert r["vulnerable"] is False
    assert r["status_label"] == "STATUS_INVALID_HANDLE"


def test_probe_ms17_010_unknown_status(monkeypatch):
    trans_other = _resp(0x25, 0xC0000022, uid=0x0800, tid=0x1000)   # ACCESS_DENIED
    _install_fake(monkeypatch, [_NEG_OK, _SES_OK, _TREE_OK, trans_other])
    r = smb.probe_ms17_010("10.1.2.3")
    assert r is not None
    assert r["vulnerable"] is None
    assert "UNKNOWN" in r["status_label"]


def test_probe_ms17_010_null_session_refused_short_circuits(monkeypatch):
    sess_denied = _resp(0x73, 0xC0000022, uid=0)                    # ACCESS_DENIED
    fake = _install_fake(monkeypatch, [_NEG_OK, sess_denied])
    r = smb.probe_ms17_010("10.1.2.3")
    assert r["vulnerable"] is None
    assert r["phase"] == "session_setup"
    # only two requests should have been sent (no tree_connect, no trans)
    assert len(fake.sent) == 2


def test_probe_ms17_010_timeout_returns_none(monkeypatch):
    def _boom(addr, timeout=None):
        raise socket.timeout("read timed out")
    monkeypatch.setattr(smb.socket, "create_connection", _boom)
    assert smb.probe_ms17_010("10.1.2.3") is None


# --- finding promotion ----------------------------------------------------------

def _mk_host(ip: str = "10.1.2.3"):
    from recce.core.models import Host, Port
    return Host(ip=ip, hostnames=[], ports=[Port(portid=445, state="open", protocol="tcp")])


def test_vulnerable_verdict_promotes_finding_to_t2_critical():
    h = _mk_host()
    probes = {(h.ip, 445): {
        "smbv1": True, "dialect": 0x0202, "dialect_name": "SMB 2.0.2",
        "signing_enabled": True, "signing_required": True,
        "ms17_010": {"vulnerable": True, "status": 0xC0000205,
                     "status_label": "STATUS_INSUFF_SERVER_RESOURCES",
                     "phase": "trans",
                     "evidence": "SMB1 PeekNamedPipe(FID=0) returned STATUS_INSUFF_..."}}}
    fs = [f for f in smb.findings([h], probes) if f["kind"] == "smbv1"]
    assert len(fs) == 1
    f = fs[0]
    assert f["depth_tier"] == "t2"
    assert f["severity"] == "critical"
    assert "VULNERABLE" in f["title"]
    assert "T2 wire evidence" in f["detail"]


def test_patched_verdict_still_promotes_to_t2_high():
    h = _mk_host()
    probes = {(h.ip, 445): {
        "smbv1": True,
        "ms17_010": {"vulnerable": False, "status": 0xC0000008,
                     "status_label": "STATUS_INVALID_HANDLE", "phase": "trans",
                     "evidence": "SMB1 PeekNamedPipe(FID=0) returned STATUS_INVALID_HANDLE"}}}
    fs = [f for f in smb.findings([h], probes) if f["kind"] == "smbv1"]
    assert len(fs) == 1
    f = fs[0]
    assert f["depth_tier"] == "t2"
    assert f["severity"] == "high"
    assert "patched" in f["title"].lower()
    assert "STATUS_INVALID_HANDLE" in f["detail"]


def test_unknown_verdict_stays_t1_and_carries_probe_note():
    h = _mk_host()
    probes = {(h.ip, 445): {
        "smbv1": True,
        "ms17_010": {"vulnerable": None, "status": 0xC0000022,
                     "status_label": "0xc0000022", "phase": "session_setup",
                     "evidence": "null-session SESSION_SETUP refused (status=0xc0000022)"}}}
    fs = [f for f in smb.findings([h], probes) if f["kind"] == "smbv1"]
    assert len(fs) == 1
    f = fs[0]
    assert f["depth_tier"] == "t1"
    assert f["severity"] == "high"
    assert "did not reach a decisive verdict" in f["detail"]


def test_no_ms17_result_keeps_original_t1_finding():
    """Original T1 path unchanged when the MS17-010 probe wasn't run."""
    h = _mk_host()
    probes = {(h.ip, 445): {"smbv1": True}}
    fs = [f for f in smb.findings([h], probes) if f["kind"] == "smbv1"]
    assert len(fs) == 1
    assert fs[0]["depth_tier"] == "t1"
    assert fs[0]["severity"] == "high"
