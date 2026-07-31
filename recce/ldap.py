"""Deep LDAP / Active Directory enumeration (stdlib only).

Modelled on recce/smb.py and recce/ftp.py. A hand-rolled BER/ASN.1 LDAP client on
a raw socket - no python-ldap, no ldap3 - so it runs on a stock airgapped Kali.
Safety posture: see SECURITY.md.

Against a Directory port (389/636/3268/3269) recce:

  * attempts an **anonymous simple bind** (name "", password "") - RFC 4513 - to see
    whether the server hands out an anonymous session at all;
  * reads the **RootDSE** (base "", scope base, filter (objectClass=*)): naming
    contexts, the domain/forest DNS names, the DC's dnsHostName, the domain/forest
    **functional level**, and the supported SASL mechanisms - the crown jewel of
    anonymous LDAP recon and readable on virtually every DC;
  * tries to **read the base naming-context object anonymously** - if attributes come
    back, the directory leaks objects to an unauthenticated client (a real misconfig,
    not the default AD posture);
  * flags **cleartext LDAP** when a simple bind is accepted on 389 with no LDAPS/StartTLS
    - a credential-sniffing and NTLM-relay surface.

Every positive becomes a finding that folds into the main severity totals, the
Vulnerabilities sheet, the write-ups, the prove engine, and a dedicated **LDAP**
workbook tab. Airgapped-safe; degrades cleanly when the port doesn't speak LDAP.
"""
from __future__ import annotations

import re
import socket
import struct

from .models import Host, Port

_DEFAULT_PORT = 389
_LDAPS = 636
_GC, _GCS = 3268, 3269          # Global Catalog (plain / TLS)
_TIMEOUT = 6.0
_TLS_PORTS = (_LDAPS, _GCS)

# RootDSE attributes worth pulling (all readable pre-auth on a normal DC).
_ROOTDSE_ATTRS = [
    "defaultNamingContext", "rootDomainNamingContext", "namingContexts",
    "configurationNamingContext", "schemaNamingContext", "dnsHostName",
    "serverName", "ldapServiceName", "domainFunctionality", "forestFunctionality",
    "domainControllerFunctionality", "supportedLDAPVersion",
    "supportedSASLMechanisms", "supportedControl", "supportedCapabilities",
    "isGlobalCatalogReady", "currentTime",
]

# msDS-Behavior-Version -> Windows Server release (domain/forest/DC functional level).
_FUNC_LEVEL = {"0": "2000", "1": "2003 interim", "2": "2003", "3": "2008",
               "4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016"}


def is_ldap(port: Port) -> bool:
    if port.state != "open":
        return False
    if port.portid in (_DEFAULT_PORT, _LDAPS, _GC, _GCS):
        return True
    return "ldap" in f"{port.service} {port.product}".lower()


def _is_tls_port(port: int) -> bool:
    return port in _TLS_PORTS


# --- BER / ASN.1 encoding (just what LDAP needs) --------------------------------

def _ber_len(n: int) -> bytes:
    """Definite-form length: short form < 128, else long form (0x80|count + bytes)."""
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(body)]) + bytes(body)


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def _int(n: int) -> bytes:
    if n == 0:
        return _tlv(0x02, b"\x00")
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    if body[0] & 0x80:              # keep it positive
        body.insert(0, 0)
    return _tlv(0x02, bytes(body))


def _octet(s) -> bytes:
    return _tlv(0x04, s.encode() if isinstance(s, str) else s)


def _enum(n: int) -> bytes:
    return _tlv(0x0A, bytes([n]))


def _boolean(b: bool) -> bytes:
    return _tlv(0x01, b"\xff" if b else b"\x00")


def build_bind_request(msgid: int = 1, dn: str = "", password: str = "") -> bytes:
    """LDAPMessage{ msgid, [APPLICATION 0] BindRequest{ version 3, name, simple pw } }.
    Empty name + empty password = an anonymous bind (RFC 4513)."""
    simple = _tlv(0x80, password.encode())          # authentication CHOICE simple [0]
    bindreq = _tlv(0x60, _int(3) + _octet(dn) + simple)  # [APPLICATION 0] constructed
    return _tlv(0x30, _int(msgid) + bindreq)


def build_sasl_bind(msgid: int, mechanism: str, credentials: bytes = b"") -> bytes:
    """LDAPMessage{ msgid, [APPLICATION 0] BindRequest{ 3, "", sasl [3]{ mech, creds } } }.
    Used for the GSS-SPNEGO / NTLM exchange (pass-the-hash)."""
    sasl = _octet(mechanism) + (_octet(credentials) if credentials else b"")
    auth = _tlv(0xA3, sasl)                          # authentication CHOICE sasl [3]
    bindreq = _tlv(0x60, _int(3) + _octet("") + auth)
    return _tlv(0x30, _int(msgid) + bindreq)


def sasl_creds(msg: bytes) -> bytes:
    """serverSaslCreds [7] from a BindResponse (the NTLM CHALLENGE), or b''."""
    try:
        _, body, _ = _parse_tlv(msg, 0)
        _, _mid, i = _parse_tlv(body, 0)
        _, op, _ = _parse_tlv(body, i)              # [APPLICATION 1] bindResponse value
        j = 0
        for _ in range(3):                          # resultCode, matchedDN, errorMessage
            _, _v, j = _parse_tlv(op, j)
        while j < len(op):
            tag, val, j = _parse_tlv(op, j)
            if tag == 0x87:                         # serverSaslCreds [7]
                return val
        return b""
    except (IndexError, ValueError):
        return b""


def build_search_request(msgid: int, base: str, scope: int,
                         attributes: list[str], filt: bytes | None = None,
                         size_limit: int = 0, cookie: bytes | None = None,
                         page_size: int = 0) -> bytes:
    """LDAPMessage{ msgid, [APPLICATION 3] SearchRequest{...}, [0] controls? }.

    scope: 0 base / 1 one-level / 2 subtree. `filt` is raw Filter bytes (default the
    present filter (objectClass=*)). Pass page_size (+ a cookie from a previous page)
    to attach the SimplePagedResults control - required to walk past AD's MaxPageSize."""
    if filt is None:
        filt = _tlv(0x87, b"objectClass")           # present filter [7] "objectClass"
    attrs = _tlv(0x30, b"".join(_octet(a) for a in attributes))
    body = (_octet(base) + _enum(scope) + _enum(0)  # derefAliases = neverDerefAliases
            + _int(size_limit) + _int(0) + _boolean(False)   # sizeLimit, timeLimit, typesOnly
            + filt + attrs)
    searchreq = _tlv(0x63, body)                    # [APPLICATION 3] constructed
    msg = _int(msgid) + searchreq
    if page_size:
        msg += _paged_control(page_size, cookie or b"")
    return _tlv(0x30, msg)


# --- Filter encoders (RFC 4511 4.5.1) -------------------------------------------

def f_equal(attr: str, value: str) -> bytes:
    """equalityMatch [3] SEQUENCE{ attributeDesc, assertionValue }."""
    return _tlv(0xA3, _octet(attr) + _octet(value))


def f_present(attr: str) -> bytes:
    """present [7] AttributeDescription."""
    return _tlv(0x87, attr.encode())


def f_and(*subs: bytes) -> bytes:
    return _tlv(0xA0, b"".join(subs))               # and [0]


def f_or(*subs: bytes) -> bytes:
    return _tlv(0xA1, b"".join(subs))               # or [1]


def f_not(sub: bytes) -> bytes:
    return _tlv(0xA2, sub)                           # not [2]


# LDAP_MATCHING_RULE_BIT_AND - test individual userAccountControl bits.
_RULE_BIT_AND = "1.2.840.113556.1.4.803"


def f_bitand(attr: str, bit: int, rule: str = _RULE_BIT_AND) -> bytes:
    """extensibleMatch [9] MatchingRuleAssertion - e.g. a userAccountControl bit test
    (AS-REP: userAccountControl:1.2.840.113556.1.4.803:=4194304)."""
    return _tlv(0xA9, _tlv(0x81, rule.encode())     # matchingRule [1]
                + _tlv(0x82, attr.encode())         # type [2]
                + _tlv(0x83, str(bit).encode()))    # matchValue [3]


# --- SimplePagedResults control (1.2.840.113556.1.4.319) ------------------------

_PAGED_OID = "1.2.840.113556.1.4.319"


def _paged_control(page_size: int, cookie: bytes = b"") -> bytes:
    val = _tlv(0x30, _int(page_size) + _octet(cookie))    # realSearchControlValue
    control = _tlv(0x30, _octet(_PAGED_OID) + _octet(val))
    return _tlv(0xA0, control)                             # controls [0] SEQ OF Control


def _extract_cookie(done_msg: bytes) -> bytes:
    """The paged-results cookie from a searchResDone's response controls (b'' = done)."""
    try:
        _, body, _ = _parse_tlv(done_msg, 0)
        _, _mid, i = _parse_tlv(body, 0)
        _, _op, i = _parse_tlv(body, i)             # protocolOp (searchResDone)
        if i >= len(body):
            return b""
        tag, controls, _ = _parse_tlv(body, i)      # controls [0]
        if tag != 0xA0:
            return b""
        j = 0
        while j < len(controls):
            _, ctl, j = _parse_tlv(controls, j)     # one Control SEQUENCE
            _, ctype, k = _parse_tlv(ctl, 0)
            if ctype.decode("latin-1") != _PAGED_OID:
                continue
            # value is the last OCTET STRING in the control (criticality may precede).
            last = None
            while k < len(ctl):
                t, v, k = _parse_tlv(ctl, k)
                if t == 0x04:
                    last = v
            if last is None:
                return b""
            _, inner, _ = _parse_tlv(last, 0)        # SEQ{ size, cookie }
            _, _size, m = _parse_tlv(inner, 0)
            _, cookie, _ = _parse_tlv(inner, m)
            return cookie
        return b""
    except (IndexError, ValueError):
        return b""


# --- BER decoding ---------------------------------------------------------------

def _read_len(data: bytes, i: int) -> tuple[int, int]:
    first = data[i]
    i += 1
    if first < 0x80:
        return first, i
    n = 0
    for _ in range(first & 0x7F):
        n = (n << 8) | data[i]
        i += 1
    return n, i


def _parse_tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Return (tag, value_bytes, next_index) for the TLV at `i`."""
    tag = data[i]
    length, j = _read_len(data, i + 1)
    return tag, data[j:j + length], j + length


def result_code(msg: bytes):
    """resultCode from a response LDAPMessage (bind/search-done), or None. `msg` is
    None when the server closed the socket or sent a short/garbage frame."""
    if not msg:
        return None
    try:
        _, body, _ = _parse_tlv(msg, 0)             # outer SEQUENCE
        _, _msgid, i = _parse_tlv(body, 0)          # messageID
        _, op, _ = _parse_tlv(body, i)              # protocolOp (a *Response)
        _, rc, _ = _parse_tlv(op, 0)                # resultCode ENUMERATED
        return rc[0] if rc else None
    except (IndexError, ValueError, TypeError):
        return None


def _op_tag(msg: bytes):
    """The protocolOp application tag of a response LDAPMessage (0x61 bindResponse,
    0x64 searchResEntry, 0x65 searchResDone), or None."""
    try:
        _, body, _ = _parse_tlv(msg, 0)
        _, _msgid, i = _parse_tlv(body, 0)
        return body[i]
    except (IndexError, ValueError):
        return None


def parse_search_entry(msg: bytes) -> tuple[str, dict]:
    """(objectName, {attr: [values]}) from a searchResEntry LDAPMessage."""
    _, body, _ = _parse_tlv(msg, 0)
    _, _msgid, i = _parse_tlv(body, 0)
    _, op, _ = _parse_tlv(body, i)                  # [APPLICATION 4] value
    _, objname, k = _parse_tlv(op, 0)               # objectName
    obj = objname.decode("utf-8", "replace")
    _, attrseq, _ = _parse_tlv(op, k)               # PartialAttributeList SEQUENCE
    attrs: dict[str, list[str]] = {}
    j = 0
    while j < len(attrseq):
        _, one, j = _parse_tlv(attrseq, j)          # SEQUENCE{ type, vals }
        _, atype, m = _parse_tlv(one, 0)
        name = atype.decode("utf-8", "replace")
        _, vset, _ = _parse_tlv(one, m)             # SET OF values
        vals, n = [], 0
        while n < len(vset):
            _, v, n = _parse_tlv(vset, n)
            vals.append(v.decode("utf-8", "replace"))
        attrs[name] = vals
    return obj, attrs


# --- socket I/O -----------------------------------------------------------------

def _recvn(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_message(sock, timeout: float) -> bytes | None:
    """Read exactly one LDAPMessage (a top-level SEQUENCE) off the socket."""
    sock.settimeout(timeout)
    try:
        first = _recvn(sock, 2)
        if len(first) < 2 or first[0] != 0x30:
            return None
        if first[1] < 0x80:
            return first + _recvn(sock, first[1])
        nbytes = first[1] & 0x7F
        lenb = _recvn(sock, nbytes)
        if len(lenb) < nbytes:
            return None
        length = int.from_bytes(lenb, "big")
        if length > 8 * 1024 * 1024:                # sanity cap
            return None
        return first + lenb + _recvn(sock, length)
    except OSError:
        return None


def _read_search(sock, timeout: float, cap: int = 64) -> list[dict]:
    """Collect searchResEntry attribute dicts until searchResDone / cap / EOF."""
    return _read_search_paged(sock, timeout, cap)[0]


def _read_search_paged(sock, timeout: float,
                       cap: int = 4000) -> tuple[list[dict], bytes]:
    """Collect one page of searchResEntry attribute dicts; return (entries, cookie).
    cookie is the SimplePagedResults cookie off the searchResDone (b'' = last page)."""
    entries: list[dict] = []
    for _ in range(cap):
        msg = _read_message(sock, timeout)
        if msg is None:
            break
        op = _op_tag(msg)
        if op == 0x64:                              # searchResEntry
            try:
                _obj, attrs = parse_search_entry(msg)
                entries.append(attrs)
            except (IndexError, ValueError):
                continue
        elif op == 0x65:                            # searchResDone
            return entries, _extract_cookie(msg)
    return entries, b""


# --- credential-free probe ------------------------------------------------------

def _dn_to_domain(dn: str) -> str:
    parts = [p[3:] for p in dn.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts)


def _first(d: dict, key: str, default: str = "") -> str:
    v = d.get(key)
    return v[0] if v else default


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict | None:
    """Anonymous bind + RootDSE + anonymous naming-context read. No credentials.
    Returns None if the port didn't answer LDAP."""
    if _is_tls_port(port):
        return _probe_tls(ip, port, timeout)
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            return _run_probe(s, ip, port, timeout)
    except OSError:
        return None


def _probe_tls(ip: str, port: int, timeout: float) -> dict | None:
    """LDAPS (636/3269): wrap the socket in TLS (unverified - we're reaching an
    exposed/self-signed DC), then run the same LDAP probe."""
    import ssl
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        ctx = ssl._create_unverified_context()
        with ctx.wrap_socket(raw, server_hostname=ip) as s:
            return _run_probe(s, ip, port, timeout)
    except (OSError, ssl.SSLError, ValueError):
        try:
            raw.close()
        except OSError:
            pass
        return None


def _run_probe(s, ip: str, port: int, timeout: float) -> dict | None:
    # 1. anonymous simple bind.
    s.sendall(build_bind_request(1, "", ""))
    bind_resp = _read_message(s, timeout)
    if bind_resp is None:
        return None                                 # didn't speak LDAP
    anon_bind = result_code(bind_resp) == 0

    # 2. RootDSE (base "", scope base). Readable even when the bind was refused on
    #    some servers, so always try it.
    s.sendall(build_search_request(2, "", 0, _ROOTDSE_ATTRS))
    root_entries = _read_search(s, timeout)
    rootdse = root_entries[0] if root_entries else {}

    default_nc = _first(rootdse, "defaultNamingContext")
    naming = default_nc or _first(rootdse, "namingContexts")
    domain = _dn_to_domain(default_nc or naming)
    forest = _dn_to_domain(_first(rootdse, "rootDomainNamingContext")) or domain

    # 3. anonymous directory read: read the naming-context base object. If attributes
    #    come back, an unauthenticated client can read directory objects.
    anon_read, sample = False, {}
    if anon_bind and naming:
        s.sendall(build_search_request(3, naming, 0,
                                       ["objectClass", "objectSid", "ms-DS-MachineAccountQuota"]))
        nc = _read_search(s, timeout)
        if nc and nc[0]:
            anon_read = True
            sample = {k: v for k, v in nc[0].items()}

    def _lvl(key: str) -> str:
        return _FUNC_LEVEL.get(_first(rootdse, key), _first(rootdse, key))

    return {
        "ip": ip, "port": port, "tls": _is_tls_port(port),
        "anon_bind": anon_bind, "anon_read": anon_read,
        "domain": domain, "forest": forest,
        "dc_dns": _first(rootdse, "dnsHostName"),
        "server_name": _first(rootdse, "serverName"),
        "naming_context": naming,
        "domain_level": _lvl("domainFunctionality"),
        "forest_level": _lvl("forestFunctionality"),
        "dc_level": _lvl("domainControllerFunctionality"),
        "sasl": rootdse.get("supportedSASLMechanisms") or [],
        "is_gc": _first(rootdse, "isGlobalCatalogReady").upper() == "TRUE",
        "rootdse_ok": bool(rootdse),
        "sample_attrs": sample,
    }


def ldap_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_ldap(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- authenticated enumeration (stdlib) -----------------------------------------

# userAccountControl bits (MS-ADTS 2.2.16).
_UAC_DISABLED = 0x0002
_UAC_DONT_EXPIRE = 0x10000
_UAC_TRUSTED_FOR_DELEG = 0x80000        # unconstrained delegation
_UAC_DONT_REQ_PREAUTH = 0x400000        # AS-REP roastable
_UAC_TRUSTED_TO_AUTH = 0x1000000        # constrained delegation w/ protocol transition

_USER_ATTRS = ["sAMAccountName", "userPrincipalName", "userAccountControl",
               "servicePrincipalName", "memberOf", "adminCount", "description",
               "msDS-AllowedToDelegateTo"]
_COMPUTER_ATTRS = ["sAMAccountName", "dNSHostName", "operatingSystem",
                   "userAccountControl", "msDS-AllowedToDelegateTo"]
_DOMAIN_ATTRS = ["ms-DS-MachineAccountQuota", "minPwdLength", "lockoutThreshold",
                 "maxPwdAge"]
# Description/comment fields that look like they hold a secret.
_PW_HINT = ("pass", "pwd", "pw=", "pw:", "secret", "cred", "kennwort", "mot de passe")
# Word-boundary match so a description doesn't fire on bypass/compass/passport (pass),
# accredited/incredible (cred), or passenger/passive - only on an actual credential hint.
_PW_DESC_RE = re.compile(
    r"\b(pass(word|wd)?|pwd|secret|cred(ential)?|kennwort|mot\s+de\s+passe)\b"
    r"|pw\s*[:=]", re.I)


def _open(ip: str, port: int, timeout: float):
    """A connected (TLS-wrapped for 636/3269) socket, or None. Caller closes."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    if not _is_tls_port(port):
        return raw
    import ssl
    try:
        return ssl._create_unverified_context().wrap_socket(raw, server_hostname=ip)
    except (OSError, ssl.SSLError, ValueError):
        try:
            raw.close()
        except OSError:
            pass
        return None


def _bind_dn(creds: dict) -> str:
    """AD accepts a userPrincipalName for a simple bind; build user@domain unless the
    operator already passed a UPN / DOMAIN\\user / full DN."""
    user = creds.get("user", "")
    domain = creds.get("domain", "")
    if any(c in user for c in ("@", "\\", "=")):
        return user
    return f"{user}@{domain}" if domain else user


def _paged_search(sock, base: str, filt: bytes, attrs: list[str], timeout: float,
                  msgid_start: int = 10, page_size: int = 200,
                  max_pages: int = 500) -> list[dict]:
    """Subtree search walking every SimplePagedResults page (past AD's MaxPageSize)."""
    out: list[dict] = []
    cookie, mid = b"", msgid_start
    for _ in range(max_pages):
        sock.sendall(build_search_request(mid, base, 2, attrs, filt=filt,
                                          cookie=cookie, page_size=page_size))
        entries, cookie = _read_search_paged(sock, timeout)
        out.extend(entries)
        mid += 1
        if not cookie:
            break
    return out


_SASL_IN_PROGRESS = 14


class _SealedStream:
    """Wraps a socket so that, after a sealed NTLM bind, every LDAP PDU is transparently
    NTLM sign+seal wrapped on send and unwrapped on recv (each SASL buffer is a 4-byte
    big-endian length prefix + token). Presents the same recv/sendall/settimeout/close
    the BER reader uses, so the search code is unchanged."""

    def __init__(self, sock, ctx, timeout: float):
        self._sock, self._ctx, self._timeout = sock, ctx, timeout
        self._buf = b""

    def settimeout(self, t):
        self._sock.settimeout(t)

    def sendall(self, data: bytes):
        wrapped = self._ctx.wrap(data)
        self._sock.sendall(struct.pack(">I", len(wrapped)) + wrapped)

    def recv(self, n: int) -> bytes:
        while len(self._buf) < n:
            hdr = _recvn(self._sock, 4)
            if len(hdr) < 4:
                break
            frame = _recvn(self._sock, struct.unpack(">I", hdr)[0])
            if not frame:
                break
            try:
                self._buf += self._ctx.unwrap(frame)
            except (struct.error, ValueError):
                # A truncated/tampered sealed frame (short token or a signature
                # mismatch) must degrade to a clean short read, not crash the module.
                break
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        self._sock.close()


def _ntlm_bind(sock, user: str, domain: str, nthash: bytes, timeout: float,
               seal: bool):
    """SASL GSS-SPNEGO NTLM bind (pass-the-hash): NEGOTIATE -> CHALLENGE -> AUTHENTICATE.
    When `seal`, negotiates sign+seal and returns (resultCode, SecurityContext) so the
    caller can wrap the post-bind traffic (satisfies a signing-required DC on 389).
    Returns (resultCode, ctx_or_None)."""
    from . import ntlm
    flags = ntlm._SEAL_FLAGS if seal else ntlm._TYPE1_FLAGS
    sock.sendall(build_sasl_bind(1, "GSS-SPNEGO", ntlm.type1(flags)))
    resp = _read_message(sock, timeout)
    if result_code(resp) != _SASL_IN_PROGRESS:
        return result_code(resp), None              # rejected outright / no NTLM
    chal = ntlm.parse_type2(sasl_creds(resp))
    if chal is None:
        return None, None
    if seal:
        type3, ctx = ntlm.type3_sealed(user, domain, nthash, chal)
    else:
        type3, ctx = ntlm.type3(user, domain, nthash, chal), None
    sock.sendall(build_sasl_bind(2, "GSS-SPNEGO", type3))
    return result_code(_read_message(sock, timeout)), ctx


def _authenticate(sock, creds: dict, timeout: float, seal: bool) -> tuple[bool, str, object]:
    """Bind with the supplied credential. Pass-the-hash (creds['hash']) uses an NTLM
    SASL bind (sign+seal on plaintext 389); otherwise a simple bind with the password.
    Returns (ok, method, security_context_or_None)."""
    from . import ntlm
    if creds.get("hash"):
        rc, ctx = _ntlm_bind(sock, creds.get("user", ""), creds.get("domain", ""),
                             ntlm.normalize_nt_hash(creds["hash"]), timeout, seal)
        method = "NTLM sealed (pass-the-hash)" if ctx else "NTLM (pass-the-hash)"
        return rc == 0, method, ctx
    sock.sendall(build_bind_request(1, _bind_dn(creds), creds.get("secret", "")))
    return result_code(_read_message(sock, timeout)) == 0, "simple bind", None


def enum_authenticated(ip: str, port: int, base: str, creds: dict,
                       timeout: float = _TIMEOUT) -> dict:
    """Authenticated LDAP enumeration over the stdlib client: bind with creds (simple
    bind with a password, or an NTLM SASL bind for pass-the-hash - sign+sealed on
    plaintext 389 so a signing-required DC accepts it), then paged-search users +
    computers + the domain object. {users, computers, domain, error}."""
    sock = _open(ip, port, timeout)
    if sock is None:
        return {"error": "connect failed"}
    try:
        sock.settimeout(timeout)
        # Seal an NTLM bind on plaintext 389 (LDAPS already protects the channel).
        seal = bool(creds.get("hash")) and not _is_tls_port(port)
        ok, method, ctx = _authenticate(sock, creds, timeout, seal)
        if not ok:
            return {"error": f"authenticated bind rejected ({method})",
                    "bind_dn": _bind_dn(creds), "bind_method": method}
        if ctx is not None:                          # seal all post-bind LDAP traffic
            sock = _SealedStream(sock, ctx, timeout)
        users = _paged_search(sock, base,
                              f_and(f_equal("objectCategory", "person"),
                                    f_equal("objectClass", "user")),
                              _USER_ATTRS, timeout, msgid_start=10)
        computers = _paged_search(sock, base, f_equal("objectClass", "computer"),
                                  _COMPUTER_ATTRS, timeout, msgid_start=1000)
        sock.sendall(build_search_request(9000, base, 0, _DOMAIN_ATTRS))
        dom = _read_search(sock, timeout)
        return {"users": users, "computers": computers,
                "domain": dom[0] if dom else {}, "bind_dn": _bind_dn(creds),
                "bind_method": method, "error": None}
    except (OSError, struct.error, ValueError, TypeError) as e:
        # struct.error/ValueError/TypeError can surface from a truncated/tampered
        # sealed frame or a None response on the pass-the-hash path - degrade to
        # "bind failed", never crash the module.
        return {"error": f"enumeration error: {e}"}
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _uac(attrs: dict) -> int:
    try:
        return int(_first(attrs, "userAccountControl", "0"))
    except ValueError:
        return 0


def _dn_cn(dn: str) -> str:
    head = dn.split(",", 1)[0]
    return head[3:] if head[:3].upper() == "CN=" else head


def _user_account(attrs: dict, domain: str, dc_ip: str) -> "object | None":
    from .models import Account
    name = _first(attrs, "sAMAccountName")
    if not name:
        return None
    uac = _uac(attrs)
    a: dict = {"uac": str(uac)}
    spns = attrs.get("servicePrincipalName") or []
    if spns and name.lower() != "krbtgt":
        a["spn"] = spns[0] if len(spns) == 1 else "; ".join(spns[:4])
    if uac & _UAC_DONT_REQ_PREAUTH:
        a["asrep_roastable"] = "yes"
    if _first(attrs, "adminCount") == "1":
        a["admincount"] = "1"
    mo = attrs.get("memberOf") or []
    if mo:
        a["memberof"] = "; ".join(_dn_cn(g) for g in mo[:8])
    deleg = attrs.get("msDS-AllowedToDelegateTo") or []
    if uac & _UAC_TRUSTED_FOR_DELEG:
        a["delegation"] = "unconstrained"
    elif deleg:
        a["delegation"] = "constrained -> " + "; ".join(deleg[:3])
    elif uac & _UAC_TRUSTED_TO_AUTH:
        a["delegation"] = "constrained (protocol transition)"
    a["enabled"] = "false" if uac & _UAC_DISABLED else "true"
    desc = _first(attrs, "description")
    if desc:
        a["description"] = desc
    return Account(ip=dc_ip, source="ldap", kind="user", name=name, domain=domain,
                   detail=_first(attrs, "userPrincipalName") or desc, attrs=a)


def _computer_account(attrs: dict, domain: str, dc_ip: str) -> "object | None":
    """Only computers with delegation are worth an Account row (they are attack-path
    pivots); the rest would just flood Users & Accounts."""
    from .models import Account
    name = _first(attrs, "sAMAccountName")
    uac = _uac(attrs)
    deleg = attrs.get("msDS-AllowedToDelegateTo") or []
    kind = ("unconstrained" if uac & _UAC_TRUSTED_FOR_DELEG
            else ("constrained -> " + "; ".join(deleg[:3]) if deleg else ""))
    if not name or not kind:
        return None
    return Account(ip=dc_ip, source="ldap", kind="computer", name=name, domain=domain,
                   detail=_first(attrs, "dNSHostName") or _first(attrs, "operatingSystem"),
                   attrs={"delegation": kind, "uac": str(uac)})


def apply_enum(host, domain: str, dc_ip: str, port: int, en: dict) -> tuple[dict, list]:
    """Fold an authenticated-enum result onto a DC host: (re)build its LDAP accounts and
    return (summary_for_target, module_findings). Refreshes source='ldap' accounts so a
    re-run doesn't duplicate."""
    users = en.get("users") or []
    computers = en.get("computers") or []
    accts = [a for a in (_user_account(u, domain, dc_ip) for u in users) if a]
    accts += [a for a in (_computer_account(c, domain, dc_ip) for c in computers) if a]
    if host is not None:
        host.accounts = [a for a in host.accounts if a.source != "ldap"] + accts
        if not host.ntlm.get("dns_domain") and domain:
            host.ntlm = {**host.ntlm, "dns_domain": domain}

    kerb = [a for a in accts if a.kind == "user" and a.attrs.get("spn")]
    asrep = [a for a in accts if a.attrs.get("asrep_roastable") == "yes"]
    uncon = [a for a in accts if a.attrs.get("delegation") == "unconstrained"]
    pw_desc = [a for a in accts if a.kind == "user"
               and _PW_DESC_RE.search(a.attrs.get("description", ""))]

    dom = en.get("domain") or {}
    try:
        maq = int(_first(dom, "ms-DS-MachineAccountQuota", "0"))
    except ValueError:
        maq = 0
    try:
        lockout = int(_first(dom, "lockoutThreshold", "-1"))
    except ValueError:
        lockout = -1

    tgt = f"{dc_ip}:{port}"
    fs = [_finding(
        "info", "Authenticated LDAP enumeration", tgt,
        f"Bound as {en.get('bind_dn', '')} via {en.get('bind_method', 'simple bind')} "
        f"and enumerated {len(users)} user(s) and "
        f"{len(computers)} computer(s): {len(kerb)} kerberoastable, {len(asrep)} "
        f"AS-REP-roastable, {len(uncon)} with unconstrained delegation. These populate "
        "the Users & Accounts, AD Quick Wins, Kerberoast and AS-REP report views.",
        "ldapsearch / netexec",
        f"nxc ldap {dc_ip} -u <user> -p <pass> --users --kerberoasting kerb.txt",
        "Review privileged accounts, SPNs and delegation; this is expected read access "
        "for an authenticated principal.", ["CWE-200"], kind="")]
    if maq > 0:
        fs.append(_finding(
            "medium", "Machine account quota allows adding computers", tgt,
            f"ms-DS-MachineAccountQuota = {maq}: any authenticated user can join up to "
            f"{maq} computer account(s) to the domain - the primitive behind RBCD and "
            "several coercion->relay chains.", "netexec / addcomputer",
            f"nxc ldap {dc_ip} -u <user> -p <pass> -M maq   # or impacket-addcomputer",
            "Set ms-DS-MachineAccountQuota to 0 and delegate machine-join to a specific "
            "group.", ["CWE-284"], kind="ldap_maq"))
    if lockout == 0:
        fs.append(_finding(
            "medium", "No account lockout threshold (password-spray friendly)", tgt,
            "The domain lockoutThreshold is 0 - accounts never lock, so an attacker can "
            "password-spray the whole user list recce just enumerated with no risk of "
            "lockout.", "netexec (spray)",
            f"nxc ldap {dc_ip} -u users.txt -p 'Season2025!' --continue-on-success",
            "Set a lockout threshold (e.g. 5-10) with an observation window.",
            ["CWE-307"], kind="ldap_lockout"))
    if pw_desc:
        names = ", ".join(a.name for a in pw_desc[:12])
        fs.append(_finding(
            "high", "Passwords in LDAP description/comment fields", tgt,
            f"{len(pw_desc)} account description(s) look like they contain a credential "
            f"(e.g. {names}). Descriptions are world-readable to any authenticated user - "
            "a classic source of valid passwords.", "ldapsearch",
            f"ldapsearch -x -H ldap://{dc_ip} -D '<user>@{domain}' -w '<pass>' -b '<base>' "
            "'(description=*)' sAMAccountName description",
            "Remove secrets from description/info attributes; rotate the exposed passwords.",
            ["CWE-522", "CWE-200"], kind="ldap_pw_desc"))

    summary = {"auth_ok": True, "auth_users": len(users),
               "auth_computers": len(computers), "kerberoastable": len(kerb),
               "asrep": len(asrep), "unconstrained_deleg": len(uncon),
               "maq": maq, "lockout": lockout}
    return summary, fs


# --- narratives -----------------------------------------------------------------

_NARRATIVE = {
    "ldap_anon_bind": (
        "The directory accepted an anonymous simple bind (empty username and password), "
        "handing out an unauthenticated LDAP session. Even when object ACLs restrict "
        "what that session can read, it is a foothold for reconnaissance and, combined "
        "with an anonymous read, leaks users, groups and policy. Disable anonymous binds "
        "unless a specific application requires them."),
    "ldap_anon_read": (
        "An unauthenticated client can READ directory objects: recce bound anonymously "
        "and the naming context returned attributes. That typically exposes the full "
        "user and group population, service-principal names (kerberoast targets), the "
        "machine-account quota, and descriptions that frequently contain passwords - all "
        "without a single credential. This is a serious misconfiguration on a domain "
        "directory (the default AD posture denies it)."),
    "ldap_rootdse": (
        "The RootDSE is world-readable (by design), but it fingerprints the directory "
        "pre-authentication: the domain and forest DNS names, the domain controller's "
        "FQDN, the domain/forest functional level (hence the minimum DC OS - a low level "
        "flags legacy, unsupported controllers), and the offered SASL mechanisms. It is "
        "the first pivot for an AD attack and confirms a reachable, unauthenticated DC."),
    "ldap_cleartext": (
        "This directory answers on cleartext 389 and accepts a simple bind, so a real "
        "credentialed bind here transmits the username and password in the clear - "
        "anyone sniffing the segment captures them verbatim. The same missing transport "
        "protection is what lets an attacker relay coerced NTLM authentication to LDAP "
        "(ntlmrelayx) to create machine accounts or grant DCSync. Require LDAPS/StartTLS "
        "and enforce LDAP signing + channel binding."),
    "ldap_maq": (
        "The domain's ms-DS-MachineAccountQuota lets an ordinary authenticated user "
        "create computer accounts. An attacker with any domain credential adds a machine "
        "account they control, which is the primitive behind resource-based constrained "
        "delegation (RBCD) and several coercion->relay privilege-escalation chains. Set "
        "the quota to 0 and delegate machine-join to a named group."),
    "ldap_lockout": (
        "The domain enforces no account-lockout threshold, so credentials never lock on "
        "repeated failures. Against the full user list recce just enumerated, an attacker "
        "can password-spray common passwords indefinitely with no risk of locking anyone "
        "out - a reliable path to a first valid credential. Set a lockout threshold and "
        "observation window."),
    "ldap_pw_desc": (
        "Account description/info attributes contain what look like passwords. Those "
        "fields are readable by every authenticated user, so a single low-privileged "
        "credential harvests them - a recurring source of valid, often privileged, "
        "passwords. Remove secrets from directory attributes and rotate anything exposed."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Credential-free probe (stdlib BER/ASN.1 client)",
     "recce speaks LDAP directly on a raw socket - no python-ldap. It sends an anonymous "
     "simple bind, then a base-scoped RootDSE search, then tries to read the naming "
     "context anonymously. LDAPS (636/3269) is wrapped in TLS first."),
    ("2. Vulnerability identification",
     "Anonymous bind accepted -> unauthenticated session. Naming context readable "
     "anonymously -> directory disclosure (users/SPNs/quota). Cleartext 389 -> "
     "credential-sniffing + LDAP-relay surface. RootDSE -> domain/forest/DC + functional "
     "level (legacy DC flag). Each folds into the totals and the prove engine adjudicates."),
    ("3. RootDSE recon",
     "The domain and forest DNS names, DC FQDN, functional level and SASL mechanisms are "
     "captured pre-auth and pre-filled into the follow-on ldapsearch / netexec commands."),
    ("4. Authenticated enumeration (with -u/-p/-d, or --hash for pass-the-hash)",
     "The same stdlib client binds with the supplied credential - a simple bind with a "
     "password, or an NTLM SASL (GSS-SPNEGO) bind for pass-the-hash (sign+sealed on "
     "plaintext 389, so a signing-required DC accepts it) - and PAGES the "
     "directory (past AD's MaxPageSize) for users, computers and the domain object, "
     "deriving kerberoastable / AS-REP-roastable / delegation / privileged accounts from "
     "the userAccountControl bits - in-house, no nxc/bloodhound hand-off. The accounts "
     "populate Users & Accounts, AD Quick Wins, Kerberoast and AS-REP directly."),
    ("5. Runbook",
     "The exact anonymous and credentialed follow-on commands (ldapsearch, nxc ldap "
     "--kerberoasting/--asreproast, bloodhound-python for the full graph) are staged per DC."),
]


# --- findings -------------------------------------------------------------------

def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "ldap", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def _rootdse_summary(pr: dict) -> str:
    bits = []
    if pr.get("domain"):
        bits.append(f"domain {pr['domain']}")
    if pr.get("forest") and pr["forest"] != pr.get("domain"):
        bits.append(f"forest {pr['forest']}")
    if pr.get("dc_dns"):
        bits.append(f"DC {pr['dc_dns']}")
    if pr.get("dc_level"):
        bits.append(f"functional level Server {pr['dc_level']}")
    if pr.get("is_gc"):
        bits.append("Global Catalog")
    return ", ".join(bits)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_ldap(p):
                continue
            tgt = f"{h.ip}:{p.portid}"
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr:
                continue
            summary = _rootdse_summary(pr)
            if pr.get("anon_read"):
                out.append(_finding(
                    "high", "Anonymous LDAP directory read", tgt,
                    "recce bound anonymously and the naming context "
                    f"({pr.get('naming_context', '')}) returned attributes - an "
                    "unauthenticated client can read directory objects. "
                    + (f"Directory: {summary}." if summary else ""),
                    "ldapsearch / netexec",
                    f"ldapsearch -x -H ldap://{h.ip}:{p.portid} -b '{pr.get('naming_context', '')}' "
                    "'(objectClass=user)' sAMAccountName servicePrincipalName description",
                    "Deny anonymous read on the directory (dsHeuristics / anonymous ACLs); "
                    "require authentication for all reads.",
                    ["CWE-306", "CWE-200"], kind="ldap_anon_read"))
            if pr.get("anon_bind"):
                out.append(_finding(
                    "medium", "Anonymous LDAP bind allowed", tgt,
                    "The server accepted a simple bind with an empty username and "
                    "password (anonymous session). "
                    + (f"Directory: {summary}." if summary else ""),
                    "ldapsearch / netexec",
                    f"ldapsearch -x -H ldap://{h.ip}:{p.portid} -s base -b '' "
                    "'(objectClass=*)'   # anonymous RootDSE, then try -b the naming context",
                    "Disable anonymous LDAP binds unless a specific application needs them.",
                    ["CWE-287", "CWE-306"], kind="ldap_anon_bind"))
                if not pr.get("tls") and p.portid == _DEFAULT_PORT:
                    out.append(_finding(
                        "medium", "LDAP over cleartext (no TLS on 389)", tgt,
                        "A simple bind is accepted on cleartext 389, so credentialed "
                        "binds transmit the password in the clear (sniffable) and the "
                        "missing transport protection is an NTLM->LDAP relay surface.",
                        "wireshark / ntlmrelayx",
                        "ntlmrelayx.py -t ldap://<ip> --escalate-user <user>   # relay coerced auth",
                        "Require LDAPS/StartTLS; enforce LDAP signing and channel binding "
                        "(LdapEnforceChannelBinding).",
                        ["CWE-319", "CWE-522"], kind="ldap_cleartext"))
            if pr.get("rootdse_ok") and summary:
                out.append(_finding(
                    "info", "LDAP RootDSE information disclosure", tgt,
                    f"Pre-authentication RootDSE read exposes: {summary}. Supported SASL: "
                    + (", ".join(pr.get("sasl") or []) or "n/a") + ".",
                    "ldapsearch",
                    f"ldapsearch -x -H ldap{'s' if pr.get('tls') else ''}://{h.ip}:{p.portid} "
                    "-s base -b '' '(objectClass=*)' '*' +",
                    "Expected for a DC; ensure a low functional level isn't flagging a "
                    "legacy/unsupported controller.",
                    ["CWE-200"], kind="ldap_rootdse"))
    return out


# --- runbooks -------------------------------------------------------------------

def _fill(text: str, ip: str, port: int, base: str, creds: dict | None) -> str:
    creds = creds or {}
    return (text.replace("<ip>", ip).replace("<port>", str(port))
            .replace("<base>", base or "<base>")
            .replace("<user>", creds.get("user") or "<user>")
            .replace("<pass>", creds.get("secret") or "<pass>")
            .replace("<domain>", creds.get("domain") or "<domain>"))


def credfree_runbook(ip: str, port: int, base: str = "") -> list[dict]:
    scheme = "ldaps" if port in _TLS_PORTS else "ldap"
    steps = [
        ("recon", "nmap NSE", "nmap -p<port> --script ldap-rootdse,ldap-search <ip>",
         "RootDSE + any anonymously-readable objects."),
        ("recon", "ldapsearch", f"ldapsearch -x -H {scheme}://<ip>:<port> -s base -b '' "
         "'(objectClass=*)' '*' +", "Read the RootDSE (domain/forest/DC/functional level)."),
        ("enumerate", "ldapsearch", f"ldapsearch -x -H {scheme}://<ip>:<port> -b '<base>' "
         "'(objectClass=user)' sAMAccountName servicePrincipalName description memberOf",
         "Anonymously enumerate users/SPNs/descriptions if reads are allowed."),
        ("enumerate", "netexec", "nxc ldap <ip> -u '' -p '' --users --groups",
         "Null-session user/group enumeration via netexec."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, base, None), "why": w}
            for ph, t, c, w in steps]


def cred_runbook(ip: str, port: int, base: str, creds: dict | None) -> list[dict]:
    steps = [
        ("enumerate", "netexec", "nxc ldap <ip> -u <user> -p <pass> -d <domain> "
         "--users --groups --kerberoasting kerb.txt --asreproast asrep.txt",
         "Full authenticated AD enumeration + roastable accounts in one pass."),
        ("collect", "bloodhound", "bloodhound-python -u <user> -p <pass> -d <domain> "
         "-dc <ip> -c All --zip", "Collect the graph for attack-path analysis."),
        ("loot", "ldapsearch", "ldapsearch -x -H ldap://<ip>:<port> -D '<user>@<domain>' "
         "-w '<pass>' -b '<base>' '(objectClass=user)' description",
         "Hunt credentials stashed in description / info attributes."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, base, creds), "why": w}
            for ph, t, c, w in steps]


# --- proof screenshot -----------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="ldap> ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """LDAP findings -> {ip: [Vuln]} (source='ldap')."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "ldap", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full LDAP analysis. Returns {targets, findings, runbooks, probes, stats}.

    When creds are supplied and active, also runs AUTHENTICATED enumeration per DC
    (paged users/computers/domain) and folds the resulting Account objects onto the
    matching host in place - so they populate Users & Accounts, AD Quick Wins,
    Kerberoast and AS-REP without a hand-off to nxc/bloodhound-python.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per DC. The whole
    per-DC unit (probe + paged auth enum) runs under the budget/Ctrl-C guard, so a slow
    authenticated enum can't overrun unbounded and a Ctrl-C keeps partial results."""
    from . import svcprobe
    targets = ldap_targets(hosts)
    host_by_ip = {h.ip: h for h in hosts}
    probes: dict = {}
    auth_fs: list[dict] = []
    state: dict = {}

    def _one(t):
        pr = probe(t["ip"], t["port"])
        if pr:
            probes[(t["ip"], t["port"])] = pr
            t["domain"] = pr.get("domain", "")
            t["dc_dns"] = pr.get("dc_dns", "")
            t["anon_bind"] = pr.get("anon_bind", False)
            t["anon_read"] = pr.get("anon_read", False)
            t["dc_level"] = pr.get("dc_level", "")
            t["naming_context"] = pr.get("naming_context", "")
        base = t.get("naming_context") or (pr or {}).get("naming_context") or ""
        if creds and base:
            en = enum_authenticated(t["ip"], t["port"], base, creds)
            if en.get("error"):
                t["auth_error"] = en["error"]
            else:
                summary, afs = apply_enum(host_by_ip.get(t["ip"]),
                                          t.get("domain", ""), t["ip"], t["port"], en)
                t.update(summary)
                auth_fs.extend(afs)
        return pr

    if active:
        for _t, _pr in svcprobe.iter_probe(targets, _one, budget=budget,
                                           progress=progress, state=state):
            pass
    fs = findings(hosts, probes) + auth_fs
    runbooks = []
    for t in targets:
        base = t.get("naming_context", "")
        runbooks.append({"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                         "credfree": credfree_runbook(t["ip"], t["port"], base),
                         "credentialed": cred_runbook(t["ip"], t["port"], base, creds)})
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
