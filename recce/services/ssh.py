"""SSH (22/tcp, 2222/tcp, 830/tcp netconf) deep enumeration.

Reads the RFC 4253 identification string and then does one SSH_MSG_KEXINIT
exchange to inventory the server's kex / hostkey / cipher / MAC / compression
lists. Optionally does one more round of Diffie-Hellman group14 to capture
the host key blob (K_S) and produce MD5 + SHA256 fingerprints matching
`ssh-keygen -l` output.

Every posture finding below reads from the same KEXINIT snapshot:

  * legacy SSH-1.x / SSH-1.99 dual-stack (RFC 4253 §5.1 / CVE-2001-0144)
  * weak KEX (group1-sha1, group14-sha1, gex-sha1)          - RFC 8270 / 9142
  * weak ciphers (arcfour*, *-cbc, 3des, blowfish, cast128)  - RFC 8758
  * weak MACs (hmac-md5*, hmac-sha1-96, umac-64, none)       - CWE-327
  * hostkey algo posture (ssh-rsa SHA-1, ssh-dss)            - RFC 8332
  * Terrapin (chacha20/etm-cbc without kex-strict)           - CVE-2023-48795
  * known-bad OpenSSH versions in the regreSSHion window     - CVE-2024-6387
  * banner distro tag ('Ubuntu-3ubuntu0.10' etc.) leak

Airgap-safe: stdlib socket + struct + hashlib. Every socket op is bounded
by `proxy.scaled(_TIMEOUT)`.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import socket
import struct

from ..core import proxy
from ..core.known_hostkeys import known_hostkeys, record_hostkey
from ..core.models import Host, Port
from .svccommon import finding_builder
from .svcdetect import parse_product_version


_DEFAULT_PORT = 22
_ALT_PORTS = (22, 2222, 830)
_TIMEOUT = 6.0

_CLIENT_IDENT = b"SSH-2.0-recce_0.2\r\n"

SSH_MSG_DISCONNECT = 1
SSH_MSG_KEXINIT = 20
SSH_MSG_NEWKEYS = 21
SSH_MSG_KEXDH_INIT = 30
SSH_MSG_KEXDH_REPLY = 31

# RFC 3526 §3 - 2048-bit MODP Group 14. Copied verbatim from the RFC.
_DH_GROUP14_P_HEX = (
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
)
_DH_GROUP14_P = int(_DH_GROUP14_P_HEX.replace(" ", ""), 16)
_DH_GROUP14_G = 2

# RFC 2409 §6.2 - 1024-bit MODP "Second Oakley Group" (SSH group1). Used
# only by the T2 weak-KEX completion probe below to actually drive a
# diffie-hellman-group1-sha1 handshake to KEXDH_REPLY when the initial
# KEXINIT enumeration advertised it.
_DH_GROUP1_P_HEX = (
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
    "FFFFFFFF FFFFFFFF"
)
_DH_GROUP1_P = int(_DH_GROUP1_P_HEX.replace(" ", ""), 16)
_DH_GROUP1_G = 2


# --- posture tables (used by findings()) ----------------------------------------

_WEAK_KEX = {
    "diffie-hellman-group1-sha1":            ("high",   "1024-bit MODP + SHA-1"),
    "diffie-hellman-group14-sha1":           ("medium", "2048-bit MODP + SHA-1 (RFC 9142 discourages)"),
    "diffie-hellman-group-exchange-sha1":    ("high",   "GEX with SHA-1"),
    "rsa1024-sha1":                          ("high",   "1024-bit RSA transport KEX"),
    "gss-group1-sha1-":                      ("high",   "GSS-API over 1024-bit MODP"),
}

# Any *-cbc AND known-broken stream ciphers.
_WEAK_CIPHERS_EXACT = {
    "arcfour":       ("high",   "RC4 (RFC 8758 deprecated)"),
    "arcfour128":    ("high",   "RC4-128 (RFC 8758 deprecated)"),
    "arcfour256":    ("high",   "RC4-256 (RFC 8758 deprecated)"),
    "3des-cbc":      ("high",   "3DES-CBC (64-bit block + CBC plaintext recovery)"),
    "3des-ctr":      ("medium", "3DES-CTR (64-bit block, Sweet32-class)"),
    "blowfish-cbc":  ("high",   "Blowfish-CBC (64-bit block + CBC)"),
    "cast128-cbc":   ("high",   "CAST128-CBC (64-bit block + CBC)"),
    "des-cbc":       ("high",   "56-bit DES"),
    "none":          ("high",   "Null cipher"),
}

_WEAK_MACS_EXACT = {
    "hmac-md5":            ("medium", "HMAC-MD5"),
    "hmac-md5-96":         ("medium", "HMAC-MD5-96 (truncated)"),
    "hmac-md5-etm@openssh.com":    ("medium", "HMAC-MD5 (EtM)"),
    "hmac-md5-96-etm@openssh.com": ("medium", "HMAC-MD5-96 (EtM, truncated)"),
    "hmac-sha1-96":        ("medium", "HMAC-SHA1-96 (truncated)"),
    "umac-64@openssh.com": ("medium", "UMAC-64 (64-bit tag)"),
    "umac-64-etm@openssh.com": ("medium", "UMAC-64 EtM (64-bit tag)"),
    "none":                ("high",   "Null MAC"),
}

_WEAK_HOSTKEY = {
    "ssh-rsa":       ("medium", "SSH-RSA (SHA-1 signature) - disabled by default from OpenSSH 8.7"),
    "ssh-dss":       ("high",   "DSA / 1024-bit DSS - broken"),
    "ssh-dss-sha1":  ("high",   "DSA-SHA1"),
    "ecdsa-sha2-nistp256-cert-v01@openssh.com": ("low", "NIST-P256 ECDSA (potentially backdoored curve)"),
}

# Terrapin: chacha20 or any *-cbc-etm without kex-strict.
_TERRAPIN_CIPHER_RE = re.compile(r"^(chacha20-poly1305@openssh\.com)$")
_TERRAPIN_MAC_RE = re.compile(r"^.*-cbc.*-etm@openssh\.com$")
_KEX_STRICT = ("kex-strict-s-v00@openssh.com", "kex-strict-c-v00@openssh.com")

# Banner comment tokens that carry a distro build tag.
_DISTRO_TAG_RE = re.compile(
    r"\b((?:Ubuntu|Debian|FreeBSD|Raspbian|Alpine|CentOS|Rocky|RHEL|Fedora|SUSE|Arch)"
    r"[-+.\w]*)", re.I)

# regreSSHion (CVE-2024-6387) - portable OpenSSH 8.5p1 .. 9.7p1 on glibc.
_REGRESSHION_RE = re.compile(
    r"^OpenSSH_(?:8\.[5-9]|9\.[0-7])p\d+$", re.I)


# --- protocol helpers -----------------------------------------------------------

def _pack_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def _pack_namelist(names) -> bytes:
    return _pack_string(",".join(names).encode("ascii"))


def _pack_mpint(n: int) -> bytes:
    if n == 0:
        return b"\x00\x00\x00\x00"
    length = (n.bit_length() + 7) // 8
    b = n.to_bytes(length, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return struct.pack(">I", len(b)) + b


def _wrap_packet(payload: bytes) -> bytes:
    """SSH binary packet framing (RFC 4253 §6), no MAC (pre-NEWKEYS).

    (packet_length_field + padding_length + payload + padding) must be a
    multiple of 8, padding must be at least 4 bytes and no more than 255.
    """
    n = 5 + len(payload)                        # includes 4B length + 1B pad_len
    pad = 8 - (n % 8)
    if pad < 4:
        pad += 8
    pkt_len = 1 + len(payload) + pad
    return struct.pack(">I", pkt_len) + bytes([pad]) + payload + b"\x00" * pad


def _parse_name_list(blob: bytes, offset: int) -> tuple[list[str], int]:
    (n,) = struct.unpack_from(">I", blob, offset)
    offset += 4
    s = blob[offset:offset + n].decode("ascii", "replace")
    offset += n
    return ([x for x in s.split(",") if x], offset)


def _parse_kexinit(payload: bytes) -> dict:
    """SSH_MSG_KEXINIT payload -> the 10 name lists + flags. Payload starts
    at the msg-type byte (should be 20)."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        return {}
    if len(payload) < 1 + 16 + 4:
        return {}
    offset = 1 + 16                              # skip msg + cookie
    labels = ("kex", "hostkey", "cipher_cs", "cipher_sc",
              "mac_cs", "mac_sc", "comp_cs", "comp_sc",
              "lang_cs", "lang_sc")
    out: dict = {}
    for label in labels:
        lst, offset = _parse_name_list(payload, offset)
        out[label] = lst
    if offset < len(payload):
        out["first_kex_packet_follows"] = bool(payload[offset])
    return out


# --- buffered socket reader -----------------------------------------------------

class _Reader:
    """Minimal buffered reader over a socket. read()/readline() raise on
    EOF or timeout - the callers wrap in try/except and mark unreachable."""

    def __init__(self, sock: socket.socket, timeout: float):
        self.sock = sock
        self.timeout = timeout
        self.buf = b""

    def _pull(self) -> bytes:
        self.sock.settimeout(self.timeout)
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError
        return chunk

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            self.buf += self._pull()
        out = self.buf[:n]
        self.buf = self.buf[n:]
        return out

    def readline(self, maxlen: int = 512) -> bytes:
        while b"\n" not in self.buf:
            self.buf += self._pull()
            if b"\n" not in self.buf and len(self.buf) > maxlen:
                raise ValueError("ssh ident line exceeds maxlen")
        idx = self.buf.index(b"\n")
        if idx + 1 > maxlen:
            raise ValueError("ssh ident line exceeds maxlen")
        line, self.buf = self.buf[:idx + 1], self.buf[idx + 1:]
        return line


def _read_ident(rd: _Reader) -> str:
    """RFC 4253 §4.2 - server MAY send informational lines before the
    'SSH-<protoversion>-<softwareversion>[ <comments>]' line."""
    for _ in range(16):
        line = rd.readline(255)
        stripped = line.rstrip(b"\r\n")
        if stripped.startswith(b"SSH-"):
            return stripped.decode("latin-1", "replace")
    raise ValueError("no SSH- identification line")


def _read_packet(rd: _Reader) -> bytes:
    hdr = rd.read(4)
    (pkt_len,) = struct.unpack(">I", hdr)
    if pkt_len < 5 or pkt_len > 262144:
        raise ValueError(f"absurd ssh packet length {pkt_len}")
    body = rd.read(pkt_len)
    pad_len = body[0]
    if pad_len + 1 > len(body):
        raise ValueError("padding_length larger than packet body")
    return body[1:len(body) - pad_len]


# --- our client KEXINIT ---------------------------------------------------------

def _build_client_kexinit() -> bytes:
    """A rich client KEXINIT that any modern server can negotiate with.
    We prefer diffie-hellman-group14-sha1/sha256 first so a follow-on
    KEXDH_INIT for hostkey capture succeeds without a second connection."""
    cookie = os.urandom(16)
    payload = bytes([SSH_MSG_KEXINIT]) + cookie
    payload += _pack_namelist([
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ext-info-c",
    ])
    payload += _pack_namelist([
        "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa",
        "ecdsa-sha2-nistp256", "ssh-ed25519",
    ])
    ciphers = ["aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com",
               "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]
    payload += _pack_namelist(ciphers)
    payload += _pack_namelist(ciphers)
    macs = ["hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"]
    payload += _pack_namelist(macs)
    payload += _pack_namelist(macs)
    payload += _pack_namelist(["none"])
    payload += _pack_namelist(["none"])
    payload += _pack_namelist([])
    payload += _pack_namelist([])
    payload += bytes([0])                          # first_kex_packet_follows
    payload += b"\x00\x00\x00\x00"                 # reserved
    return payload


# --- hostkey fingerprint capture (DH group14) -----------------------------------

def _capture_hostkey(rd: _Reader, sock: socket.socket, server_kex: list[str],
                     server_hostkey: list[str]) -> dict | None:
    """After the KEXINIT exchange, if server advertises DH group14 and any
    hostkey type we advertised (both first in our lists), send KEXDH_INIT
    and read K_S out of KEXDH_REPLY. Returns
    {key_type, blob, fp_md5, fp_sha256} or None."""
    if not any(k in server_kex for k in
               ("diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1")):
        return None

    # Client secret x - 512-bit random is fine for a probe.
    x = int.from_bytes(os.urandom(64), "big") | 1
    e = pow(_DH_GROUP14_G, x, _DH_GROUP14_P)
    kexdh_init = bytes([SSH_MSG_KEXDH_INIT]) + _pack_mpint(e)
    sock.sendall(_wrap_packet(kexdh_init))

    # Server may send SSH_MSG_EXT_INFO (7) or ignore (2) first; skip them.
    for _ in range(4):
        try:
            payload = _read_packet(rd)
        except (EOFError, OSError, ValueError):
            return None
        if not payload:
            continue
        if payload[0] == SSH_MSG_KEXDH_REPLY:
            break
    else:
        return None

    # KEXDH_REPLY = byte(31) string(K_S) mpint(f) string(sig)
    if len(payload) < 5:
        return None
    (ks_len,) = struct.unpack_from(">I", payload, 1)
    if ks_len == 0 or 5 + ks_len > len(payload):
        return None
    k_s = payload[5:5 + ks_len]

    # K_S itself starts with a string(key_type). Extract it for reporting.
    if len(k_s) < 4:
        return None
    (kt_len,) = struct.unpack_from(">I", k_s, 0)
    if 4 + kt_len > len(k_s):
        return None
    key_type = k_s[4:4 + kt_len].decode("ascii", "replace")

    fp_md5 = ":".join(f"{b:02x}" for b in hashlib.md5(k_s).digest())
    fp_sha256 = "SHA256:" + base64.b64encode(
        hashlib.sha256(k_s).digest()).decode("ascii").rstrip("=")
    return {"key_type": key_type, "blob": k_s,
            "fp_md5": f"MD5:{fp_md5}", "fp_sha256": fp_sha256,
            "hostkey_offered": server_hostkey}


# --- T2 proof: weak-KEX end-to-end completion -----------------------------------

_WEAK_KEX_T2_ALGO = "diffie-hellman-group1-sha1"


def _build_restricted_kexinit(kex_name: str) -> bytes:
    """KEXINIT restricted to a single kex_algorithms name, with broad
    hostkey/cipher/MAC lists so the ONLY negotiation constraint is the
    kex - used by _probe_weak_kex_completion to force the server to
    either accept the weak KEX or send DISCONNECT."""
    cookie = os.urandom(16)
    payload = bytes([SSH_MSG_KEXINIT]) + cookie
    payload += _pack_namelist([kex_name])
    payload += _pack_namelist([
        "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa",
        "ecdsa-sha2-nistp256", "ssh-ed25519", "ssh-dss",
    ])
    ciphers = ["aes128-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc",
               "aes128-gcm@openssh.com", "chacha20-poly1305@openssh.com"]
    payload += _pack_namelist(ciphers)
    payload += _pack_namelist(ciphers)
    macs = ["hmac-sha2-256", "hmac-sha1", "hmac-md5", "hmac-sha1-96"]
    payload += _pack_namelist(macs)
    payload += _pack_namelist(macs)
    payload += _pack_namelist(["none"])
    payload += _pack_namelist(["none"])
    payload += _pack_namelist([])
    payload += _pack_namelist([])
    payload += bytes([0])
    payload += b"\x00\x00\x00\x00"
    return payload


def _probe_weak_kex_completion(ip: str, port: int = _DEFAULT_PORT,
                               timeout: float = _TIMEOUT) -> dict:
    """T2 proof for ssh_weak_kex.

    Opens a fresh, second connection whose client KEXINIT offers ONLY
    diffie-hellman-group1-sha1 for kex_algorithms and drives the exchange
    all the way to KEXDH_REPLY. A server that merely *lists* the weak
    method but refuses it at negotiation time answers with SSH_MSG_DISCONNECT
    reason KEY_EXCHANGE_FAILED (RFC 4253 §11.1). A server that really
    accepts it returns SSH_MSG_KEXDH_REPLY carrying the K_S blob - that
    packet is the T2 evidence: the negotiation succeeded end-to-end, not
    merely on paper.

    Single roundtrip on a single controlled socket, bounded by
    proxy.scaled(timeout). No shell-out, no state change, connection is
    closed immediately after evidence is captured.

    Returns {"attempted", "completed", "kex", "key_type", "reason"}.
    """
    out: dict = {"attempted": False, "completed": False,
                 "kex": _WEAK_KEX_T2_ALGO,
                 "key_type": "", "reason": ""}
    t = proxy.scaled(timeout)
    try:
        sock = socket.create_connection((ip, port), timeout=t)
    except OSError as exc:
        out["reason"] = f"connect: {exc!r}"
        return out
    try:
        rd = _Reader(sock, t)
        try:
            _ = _read_ident(rd)
        except (EOFError, ValueError, OSError) as exc:
            out["reason"] = f"ident: {exc!r}"
            return out
        try:
            sock.sendall(_CLIENT_IDENT)
            sock.sendall(_wrap_packet(
                _build_restricted_kexinit(_WEAK_KEX_T2_ALGO)))
        except OSError as exc:
            out["reason"] = f"send-kexinit: {exc!r}"
            return out
        out["attempted"] = True

        # Server KEXINIT (or DISCONNECT if it refuses ident-level).
        server_kex: list[str] = []
        for _ in range(4):
            try:
                payload = _read_packet(rd)
            except (EOFError, OSError, ValueError, struct.error) as exc:
                out["reason"] = f"read-kexinit: {exc!r}"
                return out
            if not payload:
                continue
            if payload[0] == SSH_MSG_DISCONNECT:
                out["reason"] = "server DISCONNECT before KEXDH"
                return out
            if payload[0] == SSH_MSG_KEXINIT:
                server_kex = _parse_kexinit(payload).get("kex", [])
                break
        else:
            out["reason"] = "no server KEXINIT"
            return out

        if _WEAK_KEX_T2_ALGO not in server_kex:
            out["reason"] = f"server did not offer {_WEAK_KEX_T2_ALGO}"
            return out

        # KEXDH_INIT: e = g^x mod p (group1 1024-bit MODP).
        x = int.from_bytes(os.urandom(64), "big") | 1
        e = pow(_DH_GROUP1_G, x, _DH_GROUP1_P)
        try:
            sock.sendall(_wrap_packet(
                bytes([SSH_MSG_KEXDH_INIT]) + _pack_mpint(e)))
        except OSError as exc:
            out["reason"] = f"send-kexdh_init: {exc!r}"
            return out

        # KEXDH_REPLY (or DISCONNECT if the server refuses at this point).
        for _ in range(4):
            try:
                payload = _read_packet(rd)
            except (EOFError, OSError, ValueError, struct.error) as exc:
                out["reason"] = f"read-kexdh_reply: {exc!r}"
                return out
            if not payload:
                continue
            if payload[0] == SSH_MSG_DISCONNECT:
                out["reason"] = "server DISCONNECT after KEXDH_INIT"
                return out
            if payload[0] == SSH_MSG_KEXDH_REPLY:
                if len(payload) < 5:
                    out["reason"] = "KEXDH_REPLY too short"
                    return out
                (ks_len,) = struct.unpack_from(">I", payload, 1)
                if ks_len == 0 or 5 + ks_len > len(payload):
                    out["reason"] = "KEXDH_REPLY K_S length invalid"
                    return out
                k_s = payload[5:5 + ks_len]
                if len(k_s) >= 4:
                    (kt_len,) = struct.unpack_from(">I", k_s, 0)
                    if 4 + kt_len <= len(k_s):
                        out["key_type"] = k_s[4:4 + kt_len].decode(
                            "ascii", "replace")
                out["completed"] = True
                out["reason"] = "KEXDH_REPLY received"
                return out
        out["reason"] = "no KEXDH_REPLY"
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --- detection ------------------------------------------------------------------

def is_ssh(port: Port) -> bool:
    if not port.is_open:
        return False
    if port.portid in _ALT_PORTS:
        return True
    label = f"{port.service} {port.product}".lower()
    return "ssh" in label or "dropbear" in label or "libssh" in label


def ssh_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_ssh(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- probe ----------------------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          capture_hostkey: bool = True) -> dict | None:
    """Banner + KEXINIT enum + optional hostkey fingerprint.

    Returns a dict:
      {reachable, banner, ident, softversion, comment, product, version,
       protocol_version, kex, hostkey, cipher_cs, cipher_sc,
       mac_cs, mac_sc, comp_cs, comp_sc, hostkey_capture}
    hostkey_capture is a nested dict when a group14 KEX succeeded, else None.
    Returns None if the port didn't speak SSH at all.
    """
    out: dict = {"reachable": False, "banner": "", "ident": "",
                 "softversion": "", "comment": "", "protocol_version": "",
                 "product": "", "version": "",
                 "kex": [], "hostkey": [],
                 "cipher_cs": [], "cipher_sc": [],
                 "mac_cs": [], "mac_sc": [],
                 "comp_cs": [], "comp_sc": [],
                 "hostkey_capture": None}
    t = proxy.scaled(timeout)
    try:
        sock = socket.create_connection((ip, port), timeout=t)
    except OSError:
        return None
    try:
        rd = _Reader(sock, t)
        try:
            ident = _read_ident(rd)
        except (EOFError, ValueError, OSError):
            return None
        out["reachable"] = True
        out["banner"] = ident
        out["ident"] = ident
        m = re.match(r"^SSH-([\d.]+)-(\S+)(?:\s+(.*))?$", ident)
        if m:
            out["protocol_version"] = m.group(1)
            out["softversion"] = m.group(2)
            out["comment"] = (m.group(3) or "").strip()
        pv = parse_product_version(ident)
        if pv:
            out["product"], out["version"] = pv

        # Send our ident + KEXINIT.
        try:
            sock.sendall(_CLIENT_IDENT)
            sock.sendall(_wrap_packet(_build_client_kexinit()))
        except OSError:
            return out

        # Read packets until we see the server's KEXINIT. Servers may send
        # a few informational packets first (they shouldn't, but a wire lab
        # sometimes does).
        server_kexinit: dict = {}
        for _ in range(4):
            try:
                payload = _read_packet(rd)
            except (EOFError, OSError, ValueError):
                return out
            if not payload:
                continue
            if payload[0] == SSH_MSG_KEXINIT:
                server_kexinit = _parse_kexinit(payload)
                break

        if not server_kexinit:
            return out
        for k in ("kex", "hostkey", "cipher_cs", "cipher_sc",
                  "mac_cs", "mac_sc", "comp_cs", "comp_sc"):
            out[k] = server_kexinit.get(k, [])

        if capture_hostkey:
            try:
                hk = _capture_hostkey(rd, sock, out["kex"], out["hostkey"])
            except (EOFError, OSError, ValueError, struct.error):
                hk = None
            if hk:
                # Don't ship the raw blob in the returned dict - it's not
                # useful to callers and clutters JSON dumps.
                out["hostkey_capture"] = {
                    "key_type": hk["key_type"],
                    "fp_md5": hk["fp_md5"],
                    "fp_sha256": hk["fp_sha256"],
                }
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --- auth methods probe (shell-out) ---------------------------------------------

def auth_methods(ip: str, port: int = _DEFAULT_PORT, user: str = "root",
                 timeout: float = 8.0) -> dict:
    """Best-effort userauth 'none' probe via the local `ssh` binary.

    OpenSSH with PreferredAuthentications=none prints
    'Permission denied (publickey,password,keyboard-interactive).' to
    stderr - we grep the parenthesised methods list. Returns
    {reachable, user, methods: [str], stderr}. `methods` is empty when
    the client is missing or the server rejected the exchange.
    """
    import shutil
    import subprocess
    out: dict = {"reachable": False, "user": user, "methods": [], "stderr": ""}
    ssh = shutil.which("ssh")
    if not ssh:
        out["stderr"] = "no local ssh binary"
        return out
    argv = [ssh, "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=none",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "PubkeyAuthentication=no",
            "-o", f"ConnectTimeout={int(max(timeout, 3))}",
            "-p", str(port), f"{user}@{ip}", "true"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout + 2)
    except (OSError, subprocess.SubprocessError) as e:
        out["stderr"] = repr(e)
        return out
    stderr = proc.stderr or ""
    out["stderr"] = stderr[-512:]
    m = re.search(r"Permission denied\s*\(([^)]+)\)", stderr)
    if m:
        out["reachable"] = True
        out["methods"] = [x.strip() for x in m.group(1).split(",") if x.strip()]
    elif "no matching" in stderr or "kex_exchange" in stderr:
        out["reachable"] = True                   # server spoke, just wouldn't KEX
    return out


# --- Terrapin heuristic ---------------------------------------------------------

def _terrapin_applies(server_kex: list[str], cipher_sc: list[str],
                      mac_sc: list[str]) -> tuple[bool, list[str]]:
    """Return (applies, offending_ciphers). Terrapin (CVE-2023-48795)
    applies when a vulnerable cipher/MAC pairing is offered AND
    kex-strict is NOT advertised in kex_algorithms."""
    if any(s in server_kex for s in _KEX_STRICT):
        return False, []
    hits: list[str] = []
    for c in cipher_sc:
        if _TERRAPIN_CIPHER_RE.match(c):
            hits.append(c)
    if any(_TERRAPIN_MAC_RE.match(m) for m in mac_sc) and any(
            c.endswith("-cbc") for c in cipher_sc):
        hits.append("cbc + etm@openssh.com")
    return (bool(hits), hits)


# --- narratives -----------------------------------------------------------------

_NARRATIVE = {
    "ssh_banner": (
        "The SSH identification string carries the softwareversion and a "
        "distro build tag - that pair CPE-maps to a concrete patch level "
        "for CVE lookup, and often leaks the operating system to callers "
        "that had not yet identified it."),
    "ssh_legacy_proto": (
        "SSH-1 (or SSH-1.99 dual-stack) allows the trivially broken v1 "
        "transport - CRC-32 compensation attack, no MAC. A client can "
        "downgrade to v1 and MitM sessions in place."),
    "ssh_algo_inventory": (
        "The full server-offered kex / hostkey / cipher / MAC / compression "
        "lists are the foundation for grading cryptographic posture and "
        "for identifying downgrade-attack surface."),
    "ssh_weak_kex": (
        "The server accepts a weak key-exchange method. Group1 (1024-bit "
        "MODP) is within nation-state precomputation range; SHA-1 in KEX "
        "is superseded by RFC 9142."),
    "ssh_weak_cipher": (
        "The server accepts a broken or discouraged cipher - RC4, CBC-mode "
        "with the SSH-CBC plaintext-recovery attack, or 64-bit block sizes "
        "vulnerable to Sweet32. A downgrade forces the session into it."),
    "ssh_weak_mac": (
        "The server accepts a truncated / MD5-based MAC. The truncation "
        "cuts the tag to 64/96 bits and MD5 is a broken hash family."),
    "ssh_hostkey_posture": (
        "ssh-rsa (SHA-1 signature) has been disabled by default since "
        "OpenSSH 8.7; ssh-dss / DSA is broken. Clients that still trust "
        "these host keys accept a downgrade a modern client would refuse."),
    "ssh_hostkey_fingerprint": (
        "The captured host key fingerprint is the primary correlator for "
        "cross-network SSH-pivot detection, host cloning (identical keys "
        "on distinct IPs = golden image), and as a MitM baseline."),
    "ssh_terrapin": (
        "Terrapin (CVE-2023-48795) is a prefix-truncation attack against "
        "the ChaCha20-Poly1305 and CBC-EtM modes when the transport did "
        "not negotiate the kex-strict extension. An attacker in the "
        "network path can silently drop the first messages the client "
        "sends after NEWKEYS, disabling algorithms the client asked for."),
    "ssh_known_bad_build": (
        "This exact OpenSSH build is affected by a public pre-auth RCE "
        "or supply-chain backdoor. Treat the host as compromised until "
        "the upgrade path is verified."),
    "ssh_auth_methods": (
        "The server named the authentication methods it will accept for "
        "this username via the RFC 4252 §5.2 'none' probe."),
    "ssh_password_auth": (
        "Interactive password authentication is exposed to the network - "
        "spraying and brute-force are viable and the transport layer "
        "cannot enforce MFA."),
    "ssh_root_login": (
        "Root login is reachable over SSH - a spray or a key-in-loot "
        "reuse against 'root' can grant full host control directly."),
    "ssh_hostkey_reused": (
        "The same SSH host key fingerprint is presented by more than one "
        "IP. That is the on-wire signature of a golden-image clone, a VM "
        "template stamped without regenerating /etc/ssh/ssh_host_*_key, "
        "or a single instance NAT-fronted behind multiple addresses. If "
        "the hosts are supposed to be independent it is instead a MitM "
        "baseline: whoever holds the private key can transparently "
        "impersonate every host that shares it."),
}


_finding = finding_builder("ssh", _NARRATIVE)


# --- findings -------------------------------------------------------------------

def findings(hosts: list[Host], probes: dict | None = None,
             auth_probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    auth_probes = auth_probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_ssh(p):
                continue
            tgt = f"{h.ip}:{p.portid}"
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr.get("reachable"):
                continue

            softver = pr.get("softversion", "")
            comment = pr.get("comment", "")
            proto = pr.get("protocol_version", "")

            # --- legacy protocol version (SSH-1.x / SSH-1.99 dual stack) -----
            if proto and (proto.startswith("1.") or proto == "1.99"):
                sev = "high" if proto != "1.99" else "high"
                out.append(_finding(
                    sev, f"SSH legacy protocol version {proto} enabled", tgt,
                    f"Server identification string advertises SSH-{proto}. "
                    "SSH-1 transport is broken (CRC-32 compensation attack, "
                    "no MAC); 1.99 means the server also speaks SSH-1 and "
                    "a client can downgrade.",
                    "openssh",
                    f"ssh -1 -oProtocol=1 -p {p.portid} {h.ip}",
                    "Disable SSH-1 entirely (Protocol 2 only in sshd_config).",
                    ["CWE-327"], kind="ssh_legacy_proto",
                    exploit_note=(
                        "ssh -1 -oProtocol=1 -oStrictHostKeyChecking=no "
                        "-p <port> nobody@<ip>  # if it negotiates, capture "
                        "with tcpdump and try CRC32-compensation MitM "
                        "(Ettercap ssh1 plugin, still in the tree)."),
                    # P0-1: T2 promotion — the server's identification
                    # string ("SSH-1.x…" / "SSH-1.99-…") IS the target's
                    # first byte-string on a fresh connection. Direct
                    # server-side content, not a heuristic.
                    depth_tier="t2"))

            # --- banner distro tag leak (low, informational) -----------------
            if comment:
                dm = _DISTRO_TAG_RE.search(comment)
                if dm:
                    out.append(_finding(
                        "low", "SSH banner leaks OS distribution / patch tag", tgt,
                        f"Server identification comment '{comment}' carries the "
                        f"distro build tag '{dm.group(1)}' - CPE-maps to a "
                        "concrete patch level for CVE targeting.",
                        "openssh",
                        f"ssh -v -p {p.portid} {h.ip} 2>&1 | grep 'remote software'",
                        "Set DebianBanner no (Debian/Ubuntu) or a generic ident "
                        "in sshd_config to suppress the build tag.",
                        ["CWE-200"], kind="ssh_banner"))

            # --- known-bad build: regreSSHion (CVE-2024-6387) ---------------
            if _REGRESSHION_RE.match(softver or ""):
                out.append(_finding(
                    "critical",
                    "SSH regreSSHion pre-auth RCE window (CVE-2024-6387)", tgt,
                    f"Server softwareversion '{softver}' falls in the OpenSSH "
                    "8.5p1 - 9.7p1 portable range affected by a race in the "
                    "signal handler on glibc-based Linux. Pre-auth RCE as root "
                    f"when the target is glibc; the banner comment "
                    f"'{comment}' suggests the distro to confirm.",
                    "openssh",
                    "searchsploit CVE-2024-6387   # PoC + patch matrix",
                    "Upgrade to OpenSSH 9.8p1 or newer, or apply the "
                    "distribution's backported fix; set LoginGraceTime 0 "
                    "as an interim mitigation.",
                    ["CWE-364", "CWE-362"], kind="ssh_known_bad_build",
                    exploit_note=(
                        "python3 CVE-2024-6387_PoC/hikvision_exploit.py "
                        "<ip> <port>  # burl.io/qualys-cve-2024-6387 - only "
                        "against lab targets; the exploit crashes sshd "
                        "children by design and can wedge the host under "
                        "load."),
                    depth_tier="t0"))

            # --- KEXINIT-derived posture -----------------------------------
            kex = pr.get("kex") or []
            hostkey = pr.get("hostkey") or []
            cipher_sc = pr.get("cipher_sc") or []
            cipher_cs = pr.get("cipher_cs") or []
            mac_sc = pr.get("mac_sc") or []
            mac_cs = pr.get("mac_cs") or []

            if kex or hostkey:
                out.append(_finding(
                    "info", "SSH algorithm inventory captured", tgt,
                    f"kex={kex}\nhostkey={hostkey}\n"
                    f"cipher_sc={cipher_sc}\nmac_sc={mac_sc}",
                    "openssh", f"nmap -p {p.portid} --script ssh2-enum-algos {h.ip}",
                    "Restrict kex/cipher/mac lists in sshd_config to the "
                    "modern subset (curve25519-sha256, aes*-gcm/ctr, "
                    "hmac-sha2-*, ed25519 host keys).",
                    [], kind="ssh_algo_inventory"))

            # Weak KEX.
            weak_k = [k for k in kex if k in _WEAK_KEX]
            if weak_k:
                worst = max((_WEAK_KEX[k][0] for k in weak_k),
                            key=lambda s: ("low", "medium", "high").index(s))
                weak_kex_detail = (
                    "Server-offered kex_algorithms includes deprecated methods: "
                    + "; ".join(f"{k} - {_WEAK_KEX[k][1]}" for k in weak_k))
                # T2 promotion: if the second-connection completion probe
                # drove KEXDH group1-sha1 all the way to KEXDH_REPLY, the
                # server proved end-to-end acceptance (not just advertisement).
                wkc = pr.get("weak_kex_completion") or {}
                weak_kex_tier = "t1"
                if wkc.get("completed") and wkc.get("kex") in weak_k:
                    weak_kex_tier = "t2"
                    weak_kex_detail += (
                        f"\n\nT2 proof: a second controlled connection whose "
                        f"KEXINIT offered only '{wkc['kex']}' drove the exchange "
                        f"to SSH_MSG_KEXDH_REPLY - the server returned a K_S of "
                        f"type '{wkc.get('key_type') or '?'}'. Negotiation "
                        "succeeded end-to-end, not merely on paper.")
                elif wkc.get("attempted") and wkc.get("reason"):
                    weak_kex_detail += (
                        f"\n\nT2 completion probe attempted "
                        f"({wkc['kex']}): not completed - {wkc['reason']}.")
                out.append(_finding(
                    worst,
                    f"SSH weak key exchange offered: {', '.join(weak_k)}", tgt,
                    weak_kex_detail,
                    "openssh", f"ssh -oKexAlgorithms={weak_k[0]} -p {p.portid} {h.ip}",
                    "Remove weak KEX methods from sshd_config KexAlgorithms; "
                    "prefer curve25519-sha256 and diffie-hellman-group16-sha512+.",
                    ["CWE-326", "CWE-327"], kind="ssh_weak_kex",
                    exploit_note=(
                        "ssh -oKexAlgorithms=diffie-hellman-group1-sha1 "
                        "-oHostKeyAlgorithms=+ssh-rsa -vv -p <port> "
                        "nobody@<ip> 2>&1 | grep 'kex: algorithm'"),
                    depth_tier=weak_kex_tier))

            # Weak ciphers (union of s->c and c->s to cover asymmetric offers).
            weak_c = sorted({c for c in cipher_sc + cipher_cs
                             if c in _WEAK_CIPHERS_EXACT
                             or c.endswith("-cbc")})
            if weak_c:
                worst = "high" if any(c.endswith("-cbc") or c.startswith("arcfour")
                                      or c in ("none", "3des-cbc", "des-cbc")
                                      for c in weak_c) else "medium"
                out.append(_finding(
                    worst,
                    f"SSH weak cipher(s) offered: {', '.join(weak_c[:5])}"
                    + (" ..." if len(weak_c) > 5 else ""), tgt,
                    "Server-offered encryption list includes: "
                    + ", ".join(weak_c) + ". Any *-cbc is subject to the "
                    "SSH-CBC plaintext-recovery attack; arcfour is deprecated "
                    "by RFC 8758; 3des/blowfish/cast128 are 64-bit block "
                    "ciphers (Sweet32-class).",
                    "openssh", f"ssh -c {weak_c[0]} -p {p.portid} {h.ip}",
                    "Restrict Ciphers in sshd_config to aes*-gcm@openssh.com, "
                    "chacha20-poly1305@openssh.com, and aes*-ctr only.",
                    ["CWE-327"], kind="ssh_weak_cipher",
                    exploit_note=(
                        "ssh -c 3des-cbc -oHostKeyAlgorithms=+ssh-rsa -vv "
                        "-p <port> nobody@<ip>; if it reaches userauth, CBC "
                        "is really wired."),
                    depth_tier="t1"))

            # Weak MACs.
            weak_m = sorted({m for m in mac_sc + mac_cs
                             if m in _WEAK_MACS_EXACT})
            if weak_m:
                worst = "high" if "none" in weak_m else "medium"
                out.append(_finding(
                    worst,
                    f"SSH weak MAC(s) offered: {', '.join(weak_m[:5])}"
                    + (" ..." if len(weak_m) > 5 else ""), tgt,
                    "Server-offered MAC list includes: "
                    + ", ".join(weak_m) + ".",
                    "openssh", f"ssh -m {weak_m[0]} -p {p.portid} {h.ip}",
                    "Restrict MACs in sshd_config to hmac-sha2-256/512-etm@ "
                    "openssh.com (or the AEAD ciphers, which supply their own "
                    "integrity).",
                    ["CWE-327"], kind="ssh_weak_mac",
                    exploit_note=(
                        "ssh -m <weak-mac> -p <port> <user>@<ip>  # confirm "
                        "the server actually completes KEX with the weak MAC; "
                        "then Wireshark to observe the ETM/EtM absence."),
                    # P0-1: T2 promotion — the weak MAC list came from the
                    # server's KEXINIT `mac_algorithms_server_to_client`
                    # advertisement — a real algorithm-negotiation packet.
                    depth_tier="t2"))

            # Hostkey posture.
            weak_hk = [k for k in hostkey if k in _WEAK_HOSTKEY]
            if weak_hk:
                worst = max((_WEAK_HOSTKEY[k][0] for k in weak_hk),
                            key=lambda s: ("low", "medium", "high").index(s))
                out.append(_finding(
                    worst,
                    f"SSH deprecated host key algorithm(s) offered: "
                    f"{', '.join(weak_hk)}", tgt,
                    "server_host_key_algorithms includes: "
                    + "; ".join(f"{k} - {_WEAK_HOSTKEY[k][1]}" for k in weak_hk),
                    "openssh", f"ssh -oHostKeyAlgorithms={weak_hk[0]} -p {p.portid} {h.ip}",
                    "Remove ssh-rsa and ssh-dss from HostKeyAlgorithms in "
                    "sshd_config; issue new ed25519 host keys and rely on "
                    "rsa-sha2-256/512 for legacy clients.",
                    ["CWE-327"], kind="ssh_hostkey_posture",
                    exploit_note=(
                        "ssh-keyscan -t rsa,dsa -p <port> <ip> | "
                        "ssh-keygen -lf -   # confirms the algorithm is "
                        "really held"),
                    # P0-1: T2 promotion — the deprecated hostkey list
                    # came from the server's KEXINIT
                    # `server_host_key_algorithms` advertisement.
                    depth_tier="t2"))

            # Terrapin.
            terr, terr_hits = _terrapin_applies(kex, cipher_sc, mac_sc)
            if terr:
                out.append(_finding(
                    "high",
                    "SSH vulnerable to Terrapin prefix truncation (CVE-2023-48795)",
                    tgt,
                    f"Server offers {', '.join(terr_hits)} AND does not "
                    "advertise the kex-strict-s-v00@openssh.com extension in "
                    "kex_algorithms - Terrapin (CVE-2023-48795) applies.",
                    "openssh",
                    "python3 -m terrapin_scanner --host "
                    f"{h.ip} --port {p.portid}",
                    "Upgrade to OpenSSH 9.6+ (or the vendor patch that adds "
                    "kex-strict); as a stopgap, disable chacha20-poly1305@ "
                    "openssh.com and every -cbc cipher.",
                    ["CWE-354"], kind="ssh_terrapin",
                    exploit_note=(
                        "git clone https://github.com/RUB-NDS/"
                        "Terrapin-Scanner && ./Terrapin-Scanner -connect "
                        "<ip>:<port>   # or the python one-shot "
                        "terrapin_scanner --host <ip> --port <port>"),
                    depth_tier="t1"))

            # Hostkey fingerprint capture (info-level; correlator).
            # T2 evidence: K_S was pulled off SSH_MSG_KEXDH_REPLY on a single
            # controlled connection - no auth attempt, no shell-out - so the
            # fingerprint is a genuine cryptographic artifact of the server
            # (not a banner claim). depth_tier is lifted to t2 when the
            # capture landed; falls back to t1 if only a claimed value was
            # ever seen (currently unreachable: the field is only populated
            # by a successful KEXDH_REPLY).
            hk = pr.get("hostkey_capture")
            if hk:
                out.append(_finding(
                    "info", "SSH host key fingerprint captured", tgt,
                    f"key_type={hk['key_type']} {hk['fp_sha256']} {hk['fp_md5']}"
                    f"\n\nT2 proof: the KEXINIT exchange was driven forward "
                    f"to SSH_MSG_KEXDH_REPLY (RFC 4253 §8) on a single "
                    f"controlled socket; the server returned a K_S blob of "
                    f"key_type '{hk['key_type']}' from which the SHA256 and "
                    f"MD5 fingerprints above were computed with hashlib. "
                    f"Non-destructive: no userauth, no writes, no state "
                    f"change on the target - the connection was closed after "
                    f"K_S was captured.",
                    "openssh",
                    f"ssh-keyscan -p {p.portid} {h.ip} | ssh-keygen -lf -",
                    "Correlate this fingerprint across the estate to detect "
                    "golden-image / clone hosts and MitM baselines.",
                    [], kind="ssh_hostkey_fingerprint",
                    depth_tier="t2"))

            # --- auth methods (shell-out, best-effort) -----------------------
            am = auth_probes.get((h.ip, p.portid)) or {}
            for user_key, ares in am.items():
                methods = ares.get("methods") or []
                if not methods:
                    continue
                out.append(_finding(
                    "info",
                    f"SSH auth methods for {user_key}: {', '.join(methods)}", tgt,
                    f"userauth 'none' for '{user_key}' returned: "
                    + ", ".join(methods),
                    "openssh",
                    f"ssh -o PreferredAuthentications=none -o BatchMode=yes "
                    f"-p {p.portid} {user_key}@{h.ip}",
                    "Configure sshd for the minimum viable method set - "
                    "usually publickey only.",
                    [], kind="ssh_auth_methods"))
                if any(m in methods for m in ("password", "keyboard-interactive")):
                    out.append(_finding(
                        "medium",
                        "SSH password authentication permitted (network-exposed)",
                        tgt,
                        f"Server offers '{', '.join(methods)}' for user "
                        f"'{user_key}' - password spray and brute-force are "
                        "viable and the transport cannot enforce MFA.",
                        "hydra / medusa",
                        f"hydra -L users.txt -P passwords.txt ssh://{h.ip}:{p.portid}",
                        "Set PasswordAuthentication no and "
                        "KbdInteractiveAuthentication no in sshd_config; "
                        "require publickey (or gssapi in a Kerberos realm).",
                        ["CWE-521", "CWE-307"], kind="ssh_password_auth"))
                if user_key.lower() == "root" and methods:
                    out.append(_finding(
                        "high", "SSH root login permitted (auth methods reachable)",
                        tgt,
                        f"userauth 'none' for 'root' returned '{', '.join(methods)}' - "
                        "PermitRootLogin is enabled (or not 'no'); root is "
                        "reachable for spray and for stolen-key re-use.",
                        "openssh",
                        f"ssh -p {p.portid} root@{h.ip}",
                        "Set PermitRootLogin no (or prohibit-password with "
                        "hardware-token-backed keys); force admin work through "
                        "an unprivileged account + sudo.",
                        ["CWE-250"], kind="ssh_root_login",
                        exploit_note=(
                            "ssh -oPreferredAuthentications=password -p "
                            "<port> root@<ip>; on shell: cat /root/.ssh/id_* "
                            "/root/.ssh/known_hosts /etc/shadow, then loot "
                            "~/.aws ~/.docker/config.json /root/.gnupg."),
                        depth_tier="t1"))

    # --- cross-host hostkey reuse correlator (T4) ---------------------------
    # Read-only consumer of the engagement-wide fingerprint store
    # (`known_hostkeys(hosts).reused`) populated by every SSH probe that
    # captured a K_S. One finding per endpoint that shares its fingerprint
    # with another IP - lets a golden-image clone / VM template stamp / MitM
    # baseline surface next to each affected host in the report. No probes,
    # no network, no state change - pure correlation over what earlier
    # protocol reads already recorded.
    reuse_entries = known_hostkeys(hosts).get("reused") or []
    for entry in reuse_entries:
        fp = entry.get("fingerprint") or ""
        kt = entry.get("key_type") or ""
        ips = entry.get("ips") or []
        endpoints = entry.get("endpoints") or []
        if not fp or len(ips) < 2:
            continue
        peer_summary = ", ".join(ips)
        endpoint_summary = ", ".join(endpoints)
        for ep in endpoints:
            ep_ip, _, ep_port = ep.rpartition(":")
            ep_ip = ep_ip or ep
            ep_port = ep_port if ep_port.isdigit() else str(_DEFAULT_PORT)
            out.append(_finding(
                "info",
                f"SSH host key reused across {len(ips)} IPs: {fp}", ep,
                f"Fingerprint {fp} (key_type={kt or '?'}) is presented by "
                f"more than one IP in this engagement.\n"
                f"IPs sharing this key: {peer_summary}\n"
                f"Endpoints observed: {endpoint_summary}\n\n"
                "Two distinct machines returning the same K_S over "
                "SSH_MSG_KEXDH_REPLY means they hold the same private "
                "host key on disk - golden-image clone, VM template "
                "stamped without regenerating /etc/ssh/ssh_host_*_key, "
                "or the same instance NAT-fronted behind multiple "
                "addresses. If the hosts are supposed to be independent, "
                "the shared private key is a MitM key.",
                "openssh",
                f"ssh-keyscan -p {ep_port} {ep_ip} | ssh-keygen -lf -",
                "Regenerate host keys per host (`rm /etc/ssh/ssh_host_*_key* "
                "&& ssh-keygen -A && systemctl restart ssh`) so each host "
                "presents a unique identity; re-pin known_hosts entries "
                "and audit the image / template pipeline that produced "
                "the shared key.",
                ["CWE-262", "CWE-1394"], kind="ssh_hostkey_reused",
                exploit_note=(
                    "Compare fingerprints across the estate: "
                    "`for ip in " + " ".join(ips) + "; do ssh-keyscan "
                    "$ip 2>/dev/null | ssh-keygen -lf -; done | sort -u`. "
                    "If any host is compromised, the shared private key "
                    "lets you MitM every other IP on this list."),
                depth_tier="t4"))
    return out


# --- runbooks -------------------------------------------------------------------

def _fill(text: str, ip: str, port: int, creds: dict | None) -> str:
    creds = creds or {}
    return (text.replace("<ip>", ip).replace("<port>", str(port))
            .replace("<user>", creds.get("user") or "<user>")
            .replace("<pass>", creds.get("secret") or "<pass>"))


def credfree_runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE",
         "nmap -p<port> --script ssh2-enum-algos,ssh-auth-methods,ssh-hostkey <ip>",
         "Algorithm inventory, auth-methods, host-key fingerprints."),
        ("recon", "auth methods",
         "ssh -o PreferredAuthentications=none -o BatchMode=yes -p <port> root@<ip>",
         "Enumerate what auth methods sshd advertises for root."),
        ("recon", "ssh-audit",
         "ssh-audit -p <port> <ip>",
         "Structured posture grade (kex/cipher/mac/hostkey) with references."),
        ("recon", "keyscan",
         "ssh-keyscan -p <port> <ip> | ssh-keygen -lf -",
         "Capture SHA256 host-key fingerprints for cross-host correlation."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, None), "why": w}
            for ph, t, c, w in steps]


def cred_runbook(ip: str, port: int, creds: dict | None) -> list[dict]:
    steps = [
        ("access", "login",
         "ssh -p <port> <user>@<ip>",
         "Interactive session with the recovered credentials."),
        ("loot", "sftp",
         "sftp -P <port> <user>@<ip>",
         "Exfil files off the target once you have a session."),
        ("escalate", "sudo -l",
         "ssh -p <port> <user>@<ip> sudo -n -l",
         "List the sudo rules the account has been granted (privesc surface)."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, creds), "why": w}
            for ph, t, c, w in steps]


# --- glue -----------------------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "ssh", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full SSH analysis. Returns {targets, findings, runbooks, probes, stats}."""
    from . import svcprobe
    targets = ssh_targets(hosts)
    probes: dict = {}
    auth: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr and pr.get("reachable"):
                probes[(t["ip"], t["port"])] = pr
                t["banner"] = pr.get("banner", "")
                t["softversion"] = pr.get("softversion", "")
                hk_cap = pr.get("hostkey_capture") or {}
                t["hostkey_fp"] = hk_cap.get("fp_sha256", "")
                # T2 promotion for ssh_weak_kex: if the initial KEXINIT
                # enumeration advertised diffie-hellman-group1-sha1, run one
                # controlled second-connection completion probe.
                if _WEAK_KEX_T2_ALGO in (pr.get("kex") or []):
                    try:
                        wkc = _probe_weak_kex_completion(t["ip"], t["port"])
                    except OSError:
                        wkc = None
                    if wkc:
                        pr["weak_kex_completion"] = wkc
                # Feed the cross-service correlator so a fingerprint
                # observed here can be spotted on other IPs (clone / MitM).
                if hk_cap.get("fp_sha256"):
                    for h in hosts:
                        if h.ip == t["ip"]:
                            record_hostkey(h, t["ip"], t["port"],
                                           hk_cap["fp_sha256"],
                                           hk_cap.get("key_type", ""),
                                           source="ssh")
                            break
                # Best-effort auth-methods probe for a small set of names.
                users = ["root"]
                if creds and creds.get("user"):
                    users.append(creds["user"])
                per_user: dict = {}
                for u in users:
                    a = auth_methods(t["ip"], t["port"], user=u)
                    if a.get("methods") or a.get("reachable"):
                        per_user[u] = a
                if per_user:
                    auth[(t["ip"], t["port"])] = per_user
    fs = findings(hosts, probes, auth)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": credfree_runbook(t["ip"], t["port"]),
                 "credentialed": cred_runbook(t["ip"], t["port"], creds)}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": {**v, "hostkey_capture":
                                          v.get("hostkey_capture")}
                       for k, v in probes.items()},
            "auth_methods": {f"{k[0]}:{k[1]}": v for k, v in auth.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
