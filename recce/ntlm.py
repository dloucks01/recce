"""Minimal NTLMSSP (NTLMv2) for authenticated / pass-the-hash binds - stdlib only.

Modern OpenSSL drops MD4, so hashlib.new('md4') fails on a stock Kali; this ships a
compact pure-Python MD4 so a *password* can still be turned into an NT hash offline.
For **pass-the-hash** the NT hash is supplied directly and no MD4 is needed at all.

Implements just enough of MS-NLMP to drive an LDAP SASL (GSS-SPNEGO) bind:
  * NEGOTIATE (Type 1), CHALLENGE (Type 2) parse, AUTHENTICATE (Type 3),
  * the NTLMv2 response (HMAC-MD5 over the server challenge + a target-info blob).

Validated against the worked example in MS-NLMP 4.2.4 (see tests). For a bind on
plaintext 389 it can also negotiate **SIGN+SEAL** (key exchange, RC4 sealing, HMAC-MD5
signature) via `type3_sealed` + `SecurityContext`, so a DC that enforces LDAP signing /
channel binding accepts the enumeration without TLS. Over LDAPS the TLS channel already
protects the traffic, so no NTLM sealing is applied there.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time

_SIG = b"NTLMSSP\x00"

# Type 1 negotiate flags: Unicode | RequestTarget | NTLM | AlwaysSign | ExtendedSec.
# Deliberately NO Sign/Seal - we authenticate only and do not sign later messages.
NEGOTIATE_UNICODE = 0x00000001
NEGOTIATE_REQUEST_TARGET = 0x00000004
NEGOTIATE_NTLM = 0x00000200
NEGOTIATE_SIGN = 0x00000010
NEGOTIATE_SEAL = 0x00000020
NEGOTIATE_ALWAYS_SIGN = 0x00008000
NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NEGOTIATE_128 = 0x20000000
NEGOTIATE_56 = 0x80000000
NEGOTIATE_KEY_EXCH = 0x40000000
_TYPE1_FLAGS = (NEGOTIATE_UNICODE | NEGOTIATE_REQUEST_TARGET | NEGOTIATE_NTLM
                | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY)
# For a sealed bind on plaintext 389 we additionally negotiate sign+seal, a strong
# session key (128) and key exchange - so the DC's "LDAP signing required" is met.
_SEAL_FLAGS = (_TYPE1_FLAGS | NEGOTIATE_SIGN | NEGOTIATE_SEAL | NEGOTIATE_128
               | NEGOTIATE_56 | NEGOTIATE_KEY_EXCH)

# MS-NLMP 3.4.5.2 sign/seal key derivation magic constants (NUL-terminated ASCII).
_C2S_SIGN = b"session key to client-to-server signing key magic constant\x00"
_S2C_SIGN = b"session key to server-to-client signing key magic constant\x00"
_C2S_SEAL = b"session key to client-to-server sealing key magic constant\x00"
_S2C_SEAL = b"session key to server-to-client sealing key magic constant\x00"


# --- MD4 (pure Python; RFC 1320) ------------------------------------------------

def md4(data: bytes) -> bytes:
    """MD4 digest - hashlib no longer provides it on modern OpenSSL builds."""
    try:
        return hashlib.new("md4", data).digest()      # use the fast path if present
    except (ValueError, TypeError):
        pass
    mask = 0xFFFFFFFF

    def lr(x, n):
        return ((x << n) | (x >> (32 - n))) & mask

    msg = bytearray(data)
    bitlen = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack("<Q", bitlen)
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", bytes(msg[off:off + 64]))
        A, B, C, D = a0, b0, c0, d0
        for i in range(0, 16, 4):                      # round 1
            A = lr((A + ((B & C) | (~B & D)) + X[i]) & mask, 3)
            D = lr((D + ((A & B) | (~A & C)) + X[i + 1]) & mask, 7)
            C = lr((C + ((D & A) | (~D & B)) + X[i + 2]) & mask, 11)
            B = lr((B + ((C & D) | (~C & A)) + X[i + 3]) & mask, 19)
        for i in range(4):                             # round 2
            A = lr((A + ((B & C) | (B & D) | (C & D)) + X[i] + 0x5a827999) & mask, 3)
            D = lr((D + ((A & B) | (A & C) | (B & C)) + X[i + 4] + 0x5a827999) & mask, 5)
            C = lr((C + ((D & A) | (D & B) | (A & B)) + X[i + 8] + 0x5a827999) & mask, 9)
            B = lr((B + ((C & D) | (C & A) | (D & A)) + X[i + 12] + 0x5a827999) & mask, 13)
        for i in (0, 2, 1, 3):                         # round 3
            A = lr((A + (B ^ C ^ D) + X[i] + 0x6ed9eba1) & mask, 3)
            D = lr((D + (A ^ B ^ C) + X[i + 8] + 0x6ed9eba1) & mask, 9)
            C = lr((C + (D ^ A ^ B) + X[i + 4] + 0x6ed9eba1) & mask, 11)
            B = lr((B + (C ^ D ^ A) + X[i + 12] + 0x6ed9eba1) & mask, 15)
        a0 = (a0 + A) & mask
        b0 = (b0 + B) & mask
        c0 = (c0 + C) & mask
        d0 = (d0 + D) & mask
    return struct.pack("<4I", a0, b0, c0, d0)


def nt_hash(password: str) -> bytes:
    """NTOWFv1: MD4 of the UTF-16LE password (the 16-byte 'NT hash')."""
    return md4(password.encode("utf-16-le"))


def normalize_nt_hash(value: str) -> bytes:
    """Accept 'aad3b435...:8846f7ea...' (LM:NT) or a bare 32-hex NT hash -> 16 bytes."""
    v = value.strip()
    if ":" in v:
        v = v.split(":")[-1]
    return bytes.fromhex(v)


# --- NTLMv2 response ------------------------------------------------------------

def _ntv2_key(user: str, domain: str, nthash: bytes) -> bytes:
    """ResponseKeyNT = HMAC-MD5(NT hash, UNICODE(UPPER(user) + domain))."""
    return hmac.new(nthash, (user.upper() + domain).encode("utf-16-le"),
                    hashlib.md5).digest()


def _blob(target_info: bytes, timestamp: int, client_challenge: bytes) -> bytes:
    return (b"\x01\x01" + b"\x00" * 6 + struct.pack("<Q", timestamp)
            + client_challenge + b"\x00\x00\x00\x00" + target_info + b"\x00\x00\x00\x00")


def ntlmv2_response(user: str, domain: str, nthash: bytes, server_challenge: bytes,
                    target_info: bytes, timestamp: int | None = None,
                    client_challenge: bytes | None = None) -> bytes:
    """NtChallengeResponse = NTProofStr(16) + blob, where NTProofStr =
    HMAC-MD5(ResponseKeyNT, server_challenge + blob)."""
    key = _ntv2_key(user, domain, nthash)
    if client_challenge is None:
        client_challenge = os.urandom(8)
    if timestamp is None:
        timestamp = int((time.time() + 11644473600) * 10_000_000)   # Windows FILETIME
    blob = _blob(target_info, timestamp, client_challenge)
    proof = hmac.new(key, server_challenge + blob, hashlib.md5).digest()
    return proof + blob


# --- NTLMSSP messages -----------------------------------------------------------

def type1(flags: int = _TYPE1_FLAGS) -> bytes:
    """NEGOTIATE_MESSAGE with empty domain/workstation. Pass _SEAL_FLAGS to also
    negotiate sign+seal (for a sealed bind on plaintext 389)."""
    return (_SIG + struct.pack("<I", 1) + struct.pack("<I", flags)
            + struct.pack("<HHI", 0, 0, 0)          # DomainNameFields
            + struct.pack("<HHI", 0, 0, 0))         # WorkstationFields


def parse_type2(msg: bytes) -> dict | None:
    """Extract {challenge, target_info, flags} from a CHALLENGE_MESSAGE. Tolerates a
    SPNEGO/GSS wrapper by locating the NTLMSSP signature."""
    if not msg:
        return None
    if msg[:8] != _SIG:
        idx = msg.find(_SIG)                        # unwrap SPNEGO/GSS if needed
        if idx < 0:
            return None
        msg = msg[idx:]
    if len(msg) < 32 or struct.unpack("<I", msg[8:12])[0] != 2:
        return None
    flags = struct.unpack("<I", msg[20:24])[0]
    challenge = msg[24:32]
    ti_len = struct.unpack("<H", msg[40:42])[0] if len(msg) >= 48 else 0
    ti_off = struct.unpack("<I", msg[44:48])[0] if len(msg) >= 48 else 0
    target_info = msg[ti_off:ti_off + ti_len] if ti_len and ti_off + ti_len <= len(msg) else b""
    return {"challenge": challenge, "target_info": target_info, "flags": flags}


def type3(user: str, domain: str, nthash: bytes, challenge: dict,
          workstation: str = "RECCE", timestamp: int | None = None,
          client_challenge: bytes | None = None) -> bytes:
    """AUTHENTICATE_MESSAGE carrying the NTLMv2 response for (user, domain, nthash)."""
    nt_resp = ntlmv2_response(user, domain, nthash, challenge["challenge"],
                              challenge.get("target_info", b""), timestamp,
                              client_challenge)
    lm_resp = b"\x00" * 24                           # NTLMv2: LM response unused
    dom_b = domain.encode("utf-16-le")
    usr_b = user.encode("utf-16-le")
    ws_b = workstation.encode("utf-16-le")
    flags = challenge.get("flags", _TYPE1_FLAGS)
    # Fixed header = 8 sig + 4 type + 6*8 fields + 4 flags = 64 bytes; payload follows.
    off = 64
    fields = b""
    payload = b""
    for data in (lm_resp, nt_resp, dom_b, usr_b, ws_b, b""):   # LM, NT, Dom, User, WS, SessKey
        fields += struct.pack("<HHI", len(data), len(data), off)
        off += len(data)
        payload += data
    return _SIG + struct.pack("<I", 3) + fields + struct.pack("<I", flags) + payload


# --- RC4 (RFC 6229) -------------------------------------------------------------

class RC4:
    """Stateful RC4 keystream (stdlib dropped ARC4); one instance per direction."""

    def __init__(self, key: bytes):
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        self._s, self._i, self._j = S, 0, 0

    def update(self, data: bytes) -> bytes:
        S, i, j = self._s, self._i, self._j
        out = bytearray(len(data))
        for k, b in enumerate(data):
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out[k] = b ^ S[(S[i] + S[j]) & 0xFF]
        self._i, self._j = i, j
        return bytes(out)


def rc4k(key: bytes, data: bytes) -> bytes:
    """One-shot RC4 (fresh keystream) - for encrypting the exchanged session key."""
    return RC4(key).update(data)


# --- session-key derivation + a sign/seal security context ----------------------

def _session_base_key(user: str, domain: str, nthash: bytes, nt_proof: bytes) -> bytes:
    # NTLMv2: SessionBaseKey = HMAC-MD5(ResponseKeyNT, NTProofStr).
    return hmac.new(_ntv2_key(user, domain, nthash), nt_proof, hashlib.md5).digest()


def _derive_key(exported: bytes, magic: bytes) -> bytes:
    return hashlib.md5(exported + magic).digest()


class SecurityContext:
    """NTLM SIGN+SEAL session (Extended Session Security). wrap()/unwrap() apply the
    per-message RC4 sealing + HMAC-MD5 signature that a signing-required DC expects on
    plaintext 389. Client and server use independent keys and RC4 keystreams."""

    def __init__(self, exported_session_key: bytes):
        self.client_sign = _derive_key(exported_session_key, _C2S_SIGN)
        self.server_sign = _derive_key(exported_session_key, _S2C_SIGN)
        self.client_seal = RC4(_derive_key(exported_session_key, _C2S_SEAL))
        self.server_seal = RC4(_derive_key(exported_session_key, _S2C_SEAL))
        self.send_seq = 0
        self.recv_seq = 0

    @staticmethod
    def _checksum(sign_key: bytes, seq: int, message: bytes) -> bytes:
        return hmac.new(sign_key, struct.pack("<I", seq) + message,
                        hashlib.md5).digest()[:8]

    def wrap(self, message: bytes) -> bytes:
        """SEAL(message) -> signature(16) + sealed(message). The RC4 handle seals the
        message first, then the checksum (one continuous keystream), per MS-NLMP."""
        sealed = self.client_seal.update(message)
        chk = self._checksum(self.client_sign, self.send_seq, message)
        sealed_chk = self.client_seal.update(chk)
        sig = b"\x01\x00\x00\x00" + sealed_chk + struct.pack("<I", self.send_seq)
        self.send_seq += 1
        return sig + sealed

    def unwrap(self, token: bytes) -> bytes:
        """Reverse of wrap for a server token (signature(16) + sealed message). The
        server sealed message-then-checksum, so decrypt in that stream order."""
        sealed_chk, seq_b, sealed = token[4:12], token[12:16], token[16:]
        message = self.server_seal.update(sealed)          # message first (stream order)
        got_chk = self.server_seal.update(sealed_chk)      # then the checksum
        seq = struct.unpack("<I", seq_b)[0]
        want = self._checksum(self.server_sign, seq, message)
        if got_chk != want:
            raise ValueError("NTLM seal: signature mismatch")
        self.recv_seq += 1
        return message


def type3_sealed(user: str, domain: str, nthash: bytes, challenge: dict,
                 workstation: str = "RECCE") -> tuple[bytes, SecurityContext]:
    """AUTHENTICATE with SIGN+SEAL negotiated + key exchange: returns (type3 bytes, a
    SecurityContext) for wrapping the post-bind LDAP traffic. The client generates the
    ExportedSessionKey and ships it RC4-encrypted with the KeyExchangeKey."""
    nt_resp = ntlmv2_response(user, domain, nthash, challenge["challenge"],
                              challenge.get("target_info", b""))
    nt_proof = nt_resp[:16]
    key_exchange_key = _session_base_key(user, domain, nthash, nt_proof)  # v2: == base key
    exported = os.urandom(16)
    enc_session_key = rc4k(key_exchange_key, exported)      # EncryptedRandomSessionKey

    lm_resp = b"\x00" * 24
    dom_b = domain.encode("utf-16-le")
    usr_b = user.encode("utf-16-le")
    ws_b = workstation.encode("utf-16-le")
    off = 64
    fields = b""
    payload = b""
    for data in (lm_resp, nt_resp, dom_b, usr_b, ws_b, enc_session_key):
        fields += struct.pack("<HHI", len(data), len(data), off)
        off += len(data)
        payload += data
    msg = _SIG + struct.pack("<I", 3) + fields + struct.pack("<I", _SEAL_FLAGS) + payload
    return msg, SecurityContext(exported)
