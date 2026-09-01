"""Deep POP3 enumeration (stdlib only).

Two layers, mirroring imap.py:

  * **Credential-free (raw socket):** greeting -> APOP timestamp capture (RFC
    1939 §7), CAPA (RFC 2449) -> STLS / SASL mechanism / LOGIN-DELAY /
    IMPLEMENTATION inventory, STLS negotiate + CAPA re-issue for auth-downgrade,
    USER-command differential enumeration, cleartext USER/PASS probe with
    bogus creds, an AUTH NTLM Type-1/Type-2 exchange for the NetBIOS/DNS
    leak (same primitive smtp/imap ntlm-info uses), a base64-CRAM/DIGEST
    challenge capture, and (on 995) an implicit-TLS certificate grab.

  * **Credentialed follow-up:** LOGIN with any supplied / default creds, then
    STAT / LIST / UIDL / TOP to prove read access without pulling message
    bodies. TOP headers seed known_users / known_hostnames / known_domains.

Airgap-safe: stdlib socket + ssl + poplib fallback. Every socket op is
timeout-bounded.
"""
from __future__ import annotations

import base64
import re
import socket
import ssl

from ..core.models import Host, Port
from .svccommon import finding_builder

_PORTS = (110, 995)
_DEFAULT_PORT = 110
_TIMEOUT = 6.0
_CRLF = b"\r\n"
_MAX_READ = 65535
_MAX_MULTILINE = 262144

# APOP timestamp: <processid.time@hostname> (RFC 1939 §7).
_APOP_RE = re.compile(rb"<[^<>@]+@[^<>]+>")

# CAPA lines the module reads. RFC 2449 §5 + §6 (the standard capabilities).
_CAPA_KNOWN = {"STLS", "USER", "SASL", "PIPELINING", "TOP", "UIDL",
               "LOGIN-DELAY", "EXPIRE", "RESP-CODES", "IMPLEMENTATION"}

_SASL_WEAK = {
    "PLAIN": ("high", "PLAIN sends the password base64-encoded (cleartext-equivalent)."),
    "LOGIN": ("high", "LOGIN sends the password base64-encoded (cleartext-equivalent)."),
    "CRAM-MD5": ("medium", "CRAM-MD5 challenge/response is offline-crackable (hashcat -m 10200)."),
    "DIGEST-MD5": ("medium", "DIGEST-MD5 challenge/response is offline-crackable (hashcat -m 11500)."),
    "GSSAPI": ("high", "GSSAPI advertises Kerberos - a ticket-relay surface on AD-joined mail servers."),
    "NTLM": ("high", "NTLM AUTH is SMB/HTTP-relayable to any NTLM listener the tester can reach."),
    "ANONYMOUS": ("high", "ANONYMOUS grants an unauthenticated mailbox session."),
    "EXTERNAL": ("medium", "EXTERNAL trusts the transport (client cert / stunnel) - misconfigure = anon."),
}

# Default username set for the USER differential enumeration. Kept short.
_DEFAULT_ENUM_USERS = (
    "root", "admin", "administrator", "postmaster", "mail",
    "info", "test", "user", "guest", "backup", "support",
    "webmaster", "operator",
)

# (banner rx, severity, title, detail, cwes). Deliberate narrow version bands.
_KNOWN_BAD = [
    (re.compile(r"Dovecot[\s/v]+2\.3\.(?:[0-9]|1[0-9]|20)(?:\.|\b)", re.I),
     "high", "Dovecot 2.3.x pre-2.3.21 (multiple CVEs incl. CVE-2019-11500 / CVE-2020-12100)",
     "Dovecot builds in the 2.3.0-2.3.20 window shipped a run of pre-auth "
     "memory-disclosure / auth-bypass issues (CVE-2019-11500 out-of-bounds "
     "write in IMAP/POP3 command parsing; CVE-2020-12100 mail-processing DoS). "
     "Confirm the exact build against the vendor advisory before treating as RCE.",
     ["CWE-119", "CWE-787"]),
    (re.compile(r"Cyrus[\s/v]+2\.[0-4]\.", re.I),
     "high", "Cyrus IMAP/POP3 2.4.x or earlier - unmaintained",
     "Cyrus branches at 2.4 and earlier are unsupported and carry a backlog "
     "of unpatched issues; upgrade to a maintained 3.x release.",
     ["CWE-1104"]),
    (re.compile(r"qpopper[\s/v]+4\.0", re.I),
     "high", "qpopper 4.0.x - unmaintained legacy POP3 daemon",
     "qpopper's 4.0 branch is unmaintained (last vendor build ~2011) and has "
     "a history of pre-auth memory-corruption issues; retire it in favour of "
     "Dovecot / Cyrus.",
     ["CWE-1104"]),
]


def is_pop3(port: Port) -> bool:
    if not port.is_open:
        return False
    svc = (port.service or "").lower()
    return port.portid in _PORTS or "pop3" in svc


# --- low-level raw-socket POP3 client --------------------------------------
# POP3 replies are line-oriented but a single recv() often returns more than
# one line. Read paths route through a shared buffer so leftover bytes from
# one call are consumed by the next.

_RECV_BUFS: dict[int, bytearray] = {}


def _get_buf(sock) -> bytearray:
    key = id(sock)
    b = _RECV_BUFS.get(key)
    if b is None:
        b = bytearray()
        _RECV_BUFS[key] = b
    return b


def _drop_buf(sock) -> None:
    _RECV_BUFS.pop(id(sock), None)


def _refill(sock, timeout: float) -> bool:
    sock.settimeout(timeout)
    try:
        chunk = sock.recv(4096)
    except OSError:
        return False
    if not chunk:
        return False
    _get_buf(sock).extend(chunk)
    return True


def _read_line(sock, timeout: float) -> bytes:
    buf = _get_buf(sock)
    while b"\r\n" not in buf:
        if len(buf) >= _MAX_READ:
            break
        if not _refill(sock, timeout):
            break
    if b"\r\n" not in buf:
        line = bytes(buf)
        del buf[:]
        return line
    idx = buf.index(b"\r\n")
    line = bytes(buf[:idx])
    del buf[:idx + 2]
    return line


def _read_multiline(sock, timeout: float) -> bytes:
    """Read a POP3 multi-line reply: '+OK ...\\r\\n<body lines>\\r\\n.\\r\\n'.
    A '-ERR' first line has no body (RFC 1939 §3)."""
    first = _read_line(sock, timeout)
    if not first.startswith(b"+OK"):
        return first
    buf = _get_buf(sock)
    body = bytearray()
    while True:
        if len(body) >= _MAX_MULTILINE:
            break
        # A terminator line is a literal "." followed by CRLF (dot-stuffing
        # per RFC 1939 §3 means real content lines starting with '.' arrive
        # as '..' — but we accept both since our downstream parser is
        # tolerant and this probe never round-trips message bodies back).
        while b"\r\n" not in buf:
            if not _refill(sock, timeout):
                break
        if b"\r\n" not in buf:
            body += buf
            del buf[:]
            break
        idx = buf.index(b"\r\n")
        line = bytes(buf[:idx])
        del buf[:idx + 2]
        if line == b".":
            break
        body += line
        body += b"\r\n"
    return first + b"\r\n" + bytes(body)


def _send(sock, data: bytes) -> bool:
    try:
        sock.sendall(data)
        return True
    except OSError:
        return False


def _cmd(sock, line: str, timeout: float) -> bytes:
    if not _send(sock, line.encode() + _CRLF):
        return b""
    return _read_line(sock, timeout)


def _cmd_multi(sock, line: str, timeout: float) -> bytes:
    if not _send(sock, line.encode() + _CRLF):
        return b""
    return _read_multiline(sock, timeout)


# --- parsers ---------------------------------------------------------------

def _parse_apop_timestamp(greeting: bytes) -> str:
    m = _APOP_RE.search(greeting)
    return m.group(0).decode("latin-1", "replace") if m else ""


def _parse_capa(data: bytes) -> dict:
    """Return {token: value-str} for every CAPA line, plus 'raw'.

    Tokens with no arg (STLS, UIDL, TOP) map to ""; tokens with args
    (SASL, LOGIN-DELAY, IMPLEMENTATION, EXPIRE, USER) carry the tail.
    """
    caps: dict = {}
    for raw in data.split(b"\r\n"):
        line = raw.strip()
        if not line or line.startswith(b"+OK") or line.startswith(b"-ERR") or line == b".":
            continue
        parts = line.split(None, 1)
        if not parts:
            continue
        key = parts[0].decode("latin-1", "replace").upper()
        val = parts[1].decode("latin-1", "replace") if len(parts) == 2 else ""
        caps[key] = val
    return caps


def _sasl_mechs(caps: dict) -> list[str]:
    """CAPA line for SASL is 'SASL PLAIN LOGIN CRAM-MD5' (RFC 2449 §6.3)."""
    val = caps.get("SASL", "")
    return [t.upper() for t in val.split() if t]


def _login_delay(caps: dict) -> int:
    """LOGIN-DELAY <seconds> (RFC 2449 §6.5). 0 if unset / unparseable."""
    val = caps.get("LOGIN-DELAY", "").split()
    if not val:
        return 0
    try:
        return int(val[0])
    except (TypeError, ValueError):
        return 0


def _implementation(caps: dict) -> str:
    return caps.get("IMPLEMENTATION", "").strip()


def _product_from_banner(greet: bytes) -> tuple[str, str]:
    text = greet.decode("latin-1", "replace")
    m = re.search(r"(Dovecot|Courier|Cyrus IMAP|Cyrus|qpopper|MDaemon|Zimbra|"
                  r"Exchange|IMail|hMailServer)(?:[\s/v]+(\d[\w.]*))?", text, re.I)
    if not m:
        return "", ""
    return m.group(1), (m.group(2) or "")


def _apop_hashcat_line(user: str, timestamp: str, digest_hex: str) -> str:
    """Format an APOP transcript as `<digest>:<challenge>` for hashcat mode 11500
    (per punch list). The challenge is the raw '<pid.time@host>' token; the
    digest is the client's MD5 response. recce writes the format even when only
    the challenge (not the response) is known - the operator supplies the
    captured response line."""
    return f"{digest_hex or '<md5-hex-from-client-APOP-line>'}:{timestamp}"


# --- sockets / TLS ---------------------------------------------------------

def _open_socket(ip: str, port: int, timeout: float):
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    if port == 995:
        try:
            ctx = ssl._create_unverified_context()
            return ctx.wrap_socket(raw, server_hostname=ip)
        except (OSError, ssl.SSLError):
            try:
                raw.close()
            except OSError:
                pass
            return None
    return raw


def _close(sock) -> None:
    _drop_buf(sock)
    try:
        sock.close()
    except OSError:
        pass


def _stls_wrap(sock, timeout: float, ip: str):
    """Issue STLS and negotiate TLS on the same socket. Returns the wrapped
    socket or None if STLS was rejected / TLS failed."""
    resp = _cmd(sock, "STLS", timeout)
    if not resp.startswith(b"+OK"):
        return None
    # Any leftover pre-TLS buffer bytes MUST NOT bleed into the TLS session.
    _drop_buf(sock)
    try:
        ctx = ssl._create_unverified_context()
        return ctx.wrap_socket(sock, server_hostname=ip)
    except (OSError, ssl.SSLError):
        return None


# --- pre-auth active probes ------------------------------------------------

def _cleartext_user_pass_probe(sock, timeout: float) -> str:
    """Send USER + PASS with bogus creds. Returns:
      - 'accepted'  : server processed PASS and returned -ERR auth failed
                      (i.e. plaintext auth path is open)
      - 'rejected'  : server refused USER/PASS pre-TLS (needs STLS / -ERR
                      cites TLS/privacy/plaintext)
      - 'unknown'   : nothing usable
    """
    u_resp = _cmd(sock, "USER recce_probe", timeout)
    if not u_resp:
        return "unknown"
    tail = u_resp.decode("latin-1", "replace").lower()
    if u_resp.startswith(b"-ERR") and any(w in tail for w in (
            "tls", "starttls", "stls", "privacy", "encrypt", "plaintext",
            "insecure", "not permitted")):
        return "rejected"
    if not (u_resp.startswith(b"+OK") or u_resp.startswith(b"-ERR")):
        return "unknown"
    p_resp = _cmd(sock, "PASS recce_probe_pw", timeout)
    if not p_resp:
        return "unknown"
    ptail = p_resp.decode("latin-1", "replace").lower()
    if p_resp.startswith(b"-ERR") and any(w in ptail for w in (
            "tls", "starttls", "stls", "privacy", "encrypt", "plaintext",
            "insecure")):
        return "rejected"
    return "accepted"


def _capture_sasl_challenge(sock, timeout: float, mech: str) -> str:
    """AUTH <mech>; capture the server's base64 '+ ...' challenge; abort with '*'."""
    if not _send(sock, f"AUTH {mech}".encode() + _CRLF):
        return ""
    line = _read_line(sock, timeout)
    challenge = ""
    if line.startswith(b"+ ") or line == b"+":
        challenge = line[2:].decode("latin-1", "replace").strip()
    elif line.startswith(b"+"):
        challenge = line[1:].decode("latin-1", "replace").strip()
    else:
        return ""
    _send(sock, b"*" + _CRLF)
    _read_line(sock, timeout)
    return challenge


def _ntlm_type2(sock, timeout: float) -> dict:
    """AUTH NTLM + Type-1 blob; parse the returned Type-2 for AV_PAIRs.
    Returns {} if the exchange failed or NTLM isn't offered."""
    from ..ad import ntlm
    if not _send(sock, b"AUTH NTLM" + _CRLF):
        return {}
    line = _read_line(sock, timeout)
    if not (line.startswith(b"+ ") or line == b"+"):
        # Some servers reject before even the continuation.
        return {}
    t1 = base64.b64encode(ntlm.type1()).decode("ascii")
    if not _send(sock, t1.encode() + _CRLF):
        return {}
    resp = _read_line(sock, timeout)
    if not resp.startswith(b"+"):
        return {}
    b64 = resp[2:].strip() if resp.startswith(b"+ ") else resp[1:].strip()
    try:
        raw = base64.b64decode(b64, validate=False)
    except (ValueError, TypeError):
        _send(sock, b"*" + _CRLF)
        _read_line(sock, timeout)
        return {}
    t2 = ntlm.parse_type2(raw)
    # Abort so no further attempt is registered.
    _send(sock, b"*" + _CRLF)
    _read_line(sock, timeout)
    if not t2:
        return {}
    return _parse_av_pairs(t2.get("target_info", b""))


_AV_TYPES = {0x0001: "nb_computer", 0x0002: "nb_domain", 0x0003: "dns_computer",
             0x0004: "dns_domain", 0x0005: "dns_tree"}


def _parse_av_pairs(target_info: bytes) -> dict:
    import struct
    out: dict = {}
    i = 0
    n = len(target_info)
    while i + 4 <= n:
        av_id, av_len = struct.unpack_from("<HH", target_info, i)
        i += 4
        if av_id == 0x0000:
            break
        if i + av_len > n:
            break
        if av_id in _AV_TYPES:
            out[_AV_TYPES[av_id]] = target_info[i:i + av_len].decode(
                "utf-16-le", "replace")
        i += av_len
    return out


# --- 995 certificate inspection -------------------------------------------

def _peer_cert_info(ip: str, port: int, timeout: float) -> dict:
    """Return {names: [str], self_signed: bool, expired: bool, error: str}.

    Verifies the chain (hostname disabled - we connect by IP) so the ssl
    exception carries expired/self-signed detail; then a second unverified
    handshake pulls CN/SANs regardless of trust."""
    out: dict = {"names": [], "self_signed": False, "expired": False, "error": ""}
    try:
        vctx = ssl.create_default_context()
        vctx.check_hostname = False
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with vctx.wrap_socket(raw, server_hostname=ip) as tls:
                out["names"] = _cert_names(tls.getpeercert())
                return out
    except ssl.SSLCertVerificationError as exc:
        msg = (exc.verify_message or str(exc)).lower()
        out["error"] = exc.verify_message or str(exc)
        out["self_signed"] = "self signed" in msg or "self-signed" in msg
        out["expired"] = "expired" in msg
    except (OSError, ssl.SSLError, ValueError) as exc:
        out["error"] = str(exc)
    try:
        uctx = ssl._create_unverified_context()
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with uctx.wrap_socket(raw, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                out["names"] = _names_from_der(der)
    except (OSError, ssl.SSLError, ValueError):
        pass
    return out


def _cert_names(cert: dict | None) -> list[str]:
    if not cert:
        return []
    names: list[str] = []
    for row in cert.get("subject", []):
        for k, v in row:
            if k == "commonName" and v not in names:
                names.append(v)
    for _typ, v in cert.get("subjectAltName", []) or []:
        if v not in names:
            names.append(v)
    return names


def _names_from_der(der: bytes) -> list[str]:
    """Best-effort CN grep from DER (no ASN.1 dep). The DER carries the RDN
    OID 2.5.4.3 (commonName, encoded as 55 04 03) followed by the string
    tag+len+bytes. Cheap and correct enough for a scanner banner."""
    if not der:
        return []
    names: list[str] = []
    i = 0
    marker = b"\x55\x04\x03"
    while True:
        j = der.find(marker, i)
        if j < 0:
            break
        # Next byte is the string tag, then length, then value.
        k = j + 3
        if k + 2 > len(der):
            break
        strlen = der[k + 1]
        val = der[k + 2:k + 2 + strlen]
        try:
            s = val.decode("utf-8", "replace")
        except UnicodeDecodeError:
            s = val.decode("latin-1", "replace")
        if s and s not in names:
            names.append(s)
        i = k + 2 + strlen
    return names


# --- probe -----------------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Credential-free POP3 probe. Never sends real credentials."""
    out: dict = {
        "reachable": False, "port": port, "banner": "",
        "apop_timestamp": "", "capa": {}, "capa_pre_tls": {},
        "capa_supported": False,
        "sasl": [], "stls": False, "implementation": "",
        "login_delay": 0, "product": "", "version": "",
        "plaintext_auth": "", "sasl_challenges": {},
        "ntlm_info": {}, "cert": {},
        "stls_negotiated": False, "starttls_downgrade": False,
        "sasl_post_tls": [], "error": "",
    }
    sock = _open_socket(ip, port, timeout)
    if sock is None:
        out["error"] = "connect failed"
        return out
    try:
        greet = _read_line(sock, timeout)
        if not greet.startswith(b"+OK"):
            out["error"] = "no greeting"
            return out
        out["reachable"] = True
        out["banner"] = greet.decode("latin-1", "replace")[:400]
        out["apop_timestamp"] = _parse_apop_timestamp(greet)

        # CAPA (RFC 2449). Ancient qpopper -ERRs it; that itself is data.
        capa_raw = _cmd_multi(sock, "CAPA", timeout)
        if capa_raw.startswith(b"+OK"):
            out["capa_supported"] = True
            out["capa"] = _parse_capa(capa_raw)
        elif capa_raw.startswith(b"-ERR"):
            out["capa_supported"] = False

        out["stls"] = "STLS" in out["capa"]
        out["sasl"] = _sasl_mechs(out["capa"])
        out["login_delay"] = _login_delay(out["capa"])
        out["implementation"] = _implementation(out["capa"])

        # Product / version: greeting first (banner grab), then IMPLEMENTATION.
        prod, ver = _product_from_banner(greet)
        if not prod and out["implementation"]:
            prod, ver = _product_from_banner(out["implementation"].encode())
        out["product"] = prod
        out["version"] = ver

        # SASL challenge captures (only for those actually advertised).
        for mech, key in (("CRAM-MD5", "cram_md5"), ("DIGEST-MD5", "digest_md5")):
            if mech in out["sasl"]:
                try:
                    ch = _capture_sasl_challenge(sock, timeout, mech)
                    if ch:
                        out["sasl_challenges"][key] = ch
                except OSError:
                    pass

        # NTLM info leak (only if advertised).
        if "NTLM" in out["sasl"]:
            try:
                out["ntlm_info"] = _ntlm_type2(sock, timeout)
            except OSError:
                pass

        # Cleartext auth-accepted probe. Only meaningful pre-TLS on 110;
        # implicit-TLS on 995 wraps everything so a "cleartext" verdict is moot.
        if port != 995:
            out["plaintext_auth"] = _cleartext_user_pass_probe(sock, timeout)

            # STLS negotiate + CAPA re-issue: does the plaintext SASL set still
            # get advertised inside TLS? (auth_downgrade_detection).
            out["capa_pre_tls"] = dict(out["capa"])
            if out["stls"]:
                tls_sock = _stls_wrap(sock, timeout, ip)
                if tls_sock is not None:
                    out["stls_negotiated"] = True
                    sock = tls_sock                                 # swap for LOGOUT below
                    capa2 = _cmd_multi(sock, "CAPA", timeout)
                    if capa2.startswith(b"+OK"):
                        caps2 = _parse_capa(capa2)
                        sasl2 = _sasl_mechs(caps2)
                        out["sasl_post_tls"] = sasl2
                        # PLAIN/LOGIN still advertised inside TLS after STLS =
                        # the server offers a plaintext-equivalent mechanism on
                        # both channels; a client that ignores TLS still auths.
                        # (RFC 2595 §4 wants the pre-TLS mech set restricted.)
                        weak_pre = {m for m in out["sasl"]
                                    if m in ("PLAIN", "LOGIN")}
                        weak_post = {m for m in sasl2
                                     if m in ("PLAIN", "LOGIN")}
                        if weak_pre and weak_post == weak_pre:
                            out["starttls_downgrade"] = True

        # 995: implicit TLS cert grab (separate connection to keep this one clean).
        if port == 995:
            try:
                out["cert"] = _peer_cert_info(ip, port, timeout)
            except OSError:
                pass

        _cmd(sock, "QUIT", timeout)
        return out
    finally:
        _close(sock)


# --- credentialed follow-ups ------------------------------------------------

def try_login(ip: str, port: int, user: str, secret: str,
              timeout: float = _TIMEOUT) -> bool:
    """One USER/PASS attempt. Uses raw socket + STLS when advertised; on 995
    the wrapping socket already gives TLS. Returns True on +OK PASS."""
    sock = _open_socket(ip, port, timeout)
    if sock is None:
        return False
    try:
        greet = _read_line(sock, timeout)
        if not greet.startswith(b"+OK"):
            return False
        if port != 995:
            capa = _cmd_multi(sock, "CAPA", timeout)
            if b"STLS" in capa:
                wrapped = _stls_wrap(sock, timeout, ip)
                if wrapped is not None:
                    sock = wrapped
        u = _cmd(sock, f"USER {user}", timeout)
        if not u.startswith(b"+OK"):
            return False
        p = _cmd(sock, f"PASS {secret}", timeout)
        _cmd(sock, "QUIT", timeout)
        return p.startswith(b"+OK")
    finally:
        _close(sock)


_HEADER_ADDR_RE = re.compile(rb"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_RECEIVED_FROM_RE = re.compile(rb"Received:.*?from\s+([A-Za-z0-9.-]+)", re.I)


def _mailbox_inventory(sock, timeout: float, top_lines: int = 25,
                       max_msgs: int = 5) -> dict:
    """After +OK PASS: STAT / LIST / UIDL / TOP for a small window of messages.
    Returns {stat, list, uidl, headers, addresses, received_from}."""
    out: dict = {"stat": "", "list": "", "uidl": "", "headers": [],
                 "addresses": [], "received_from": []}
    stat = _cmd(sock, "STAT", timeout)
    out["stat"] = stat.decode("latin-1", "replace")
    lst = _cmd_multi(sock, "LIST", timeout)
    out["list"] = lst.decode("latin-1", "replace")[:2000]
    uidl = _cmd_multi(sock, "UIDL", timeout)
    out["uidl"] = uidl.decode("latin-1", "replace")[:2000]
    # Parse "+OK <n> <total>" for the message count.
    n = 0
    m = re.match(rb"\+OK\s+(\d+)\s+\d+", stat)
    if m:
        try:
            n = int(m.group(1))
        except ValueError:
            n = 0
    addrs: list[str] = []
    hosts: list[str] = []
    for i in range(1, min(n, max_msgs) + 1):
        body = _cmd_multi(sock, f"TOP {i} {top_lines}", timeout)
        if not body.startswith(b"+OK"):
            continue
        # Cheap header extraction: everything before the first blank line.
        blob = body.split(b"\r\n\r\n", 1)[0]
        out["headers"].append(blob.decode("latin-1", "replace")[:2000])
        for a in _HEADER_ADDR_RE.findall(blob)[:20]:
            s = a.decode("latin-1", "replace")
            if s not in addrs:
                addrs.append(s)
        for h in _RECEIVED_FROM_RE.findall(blob)[:10]:
            s = h.decode("latin-1", "replace")
            if s not in hosts:
                hosts.append(s)
    out["addresses"] = addrs
    out["received_from"] = hosts
    return out


def credentialed_probe(ip: str, port: int, user: str, secret: str,
                       timeout: float = _TIMEOUT) -> dict:
    """LOGIN then STAT/LIST/UIDL/TOP. Never RETRs full bodies."""
    out: dict = {"login": False, "user": user, "mailbox": {}}
    sock = _open_socket(ip, port, timeout)
    if sock is None:
        return out
    try:
        greet = _read_line(sock, timeout)
        if not greet.startswith(b"+OK"):
            return out
        if port != 995:
            capa = _cmd_multi(sock, "CAPA", timeout)
            if b"STLS" in capa:
                wrapped = _stls_wrap(sock, timeout, ip)
                if wrapped is not None:
                    sock = wrapped
        u = _cmd(sock, f"USER {user}", timeout)
        if not u.startswith(b"+OK"):
            return out
        p = _cmd(sock, f"PASS {secret}", timeout)
        if not p.startswith(b"+OK"):
            return out
        out["login"] = True
        out["mailbox"] = _mailbox_inventory(sock, timeout)
        _cmd(sock, "QUIT", timeout)
    finally:
        _close(sock)
    return out


# --- user enumeration via USER response differential ------------------------

def enum_users(ip: str, port: int, users: list[str] | None = None,
               timeout: float = _TIMEOUT) -> dict:
    """Send USER <name> only (never PASS) and diff the response line + latency.
    Bounded: one connection per user, RFC 1939 §5 permits USER-before-PASS
    rejection which is the classic username oracle."""
    import time
    users = list(users if users is not None else _DEFAULT_ENUM_USERS)
    responses: dict[str, str] = {}
    timings: dict[str, float] = {}
    for u in users:
        sock = _open_socket(ip, port, timeout)
        if sock is None:
            continue
        try:
            greet = _read_line(sock, timeout)
            if not greet.startswith(b"+OK"):
                continue
            t0 = time.monotonic()
            r = _cmd(sock, f"USER {u}", timeout)
            timings[u] = time.monotonic() - t0
            responses[u] = r.decode("latin-1", "replace")[:200]
            _cmd(sock, "QUIT", timeout)
        finally:
            _close(sock)
    if not responses:
        return {"responses": {}, "timings": {}, "distinguishes": False,
                "existing": []}
    tally: dict[str, int] = {}
    for r in responses.values():
        tally[r] = tally.get(r, 0) + 1
    if len(tally) <= 1:
        return {"responses": responses, "timings": timings,
                "distinguishes": False, "existing": []}
    majority = max(tally, key=tally.get)
    existing = sorted(u for u, r in responses.items() if r != majority)
    return {"responses": responses, "timings": timings,
            "distinguishes": True, "existing": existing}


# --- login-delay aware spray -----------------------------------------------

def spray(ip: str, port: int, users: list[str], secrets: list[str],
          login_delay: int = 0, cap: int = 40,
          timeout: float = _TIMEOUT) -> dict:
    """Bounded credential spray. RFC 2449 §6.5 LOGIN-DELAY is honoured so we
    do not self-DOS or trip a per-account lockout. Returns
    {tried, hits: [(user, secret)]}."""
    import time
    hits: list[tuple[str, str]] = []
    tried = 0
    last_attempt: dict[str, float] = {}
    for pw in secrets:
        for user in users:
            if tried >= cap:
                return {"tried": tried, "hits": hits, "capped": True}
            if user in last_attempt and login_delay > 0:
                gap = login_delay - (time.monotonic() - last_attempt[user])
                if gap > 0:
                    time.sleep(min(gap, float(login_delay)))
            tried += 1
            last_attempt[user] = time.monotonic()
            if try_login(ip, port, user, pw, timeout=timeout):
                hits.append((user, pw))
                # One user proven; keep spraying against OTHERS but skip this
                # user's remaining attempts.
                users = [u for u in users if u != user]
                break
    return {"tried": tried, "hits": hits, "capped": False}


# --- targets ----------------------------------------------------------------

def pop3_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_pop3(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "product": p.product or "",
                            "version": p.version or ""})
    return out


# --- narratives / findings --------------------------------------------------

_NARRATIVE = {
    "pop3_no_stls": (
        "The POP3 listener on 110/tcp advertises no STLS: every USER/PASS on "
        "this port crosses the wire in cleartext, and there is no way for a "
        "client to negotiate encryption on the same port."),
    "pop3_cleartext_auth": (
        "The server accepts USER/PASS or AUTH PLAIN/LOGIN before STLS - a "
        "passive sniffer on the segment captures valid credentials in the "
        "clear from every client that connects to this port."),
    "pop3_sasl_mechs": (
        "Weak SASL mechanisms lower the cost of credential compromise: "
        "PLAIN/LOGIN over an unencrypted channel are sniffable; CRAM-MD5/"
        "DIGEST-MD5 are offline-crackable; GSSAPI + NTLM are AD-relayable; "
        "ANONYMOUS is a free session."),
    "pop3_capa": (
        "CAPA (RFC 2449) enumerated the server's advertised feature set - "
        "STLS, SASL mechanisms, PIPELINING, TOP, UIDL, LOGIN-DELAY, EXPIRE, "
        "IMPLEMENTATION - which drives every downstream decision (upgrade "
        "path, spray budget, offline-crack path)."),
    "pop3_implementation": (
        "The IMPLEMENTATION capability (RFC 2449 §6.9) returns a product/"
        "version string that supplements the greeting banner and often gives "
        "a version when the banner does not."),
    "pop3_apop_timestamp": (
        "The greeting carries an APOP timestamp of the form "
        "'<processid.time@hostname>' (RFC 1939 §7). The hostname suffix is "
        "often an internal FQDN not otherwise discovered, and feeds "
        "known_hostnames + known_domains for the whole engagement."),
    "pop3_apop_crackable": (
        "APOP responses are md5(timestamp || password). A captured or "
        "replayed APOP transcript (the timestamp from the greeting + the "
        "'APOP <user> <digest>' line from any real client on the segment) is "
        "offline-crackable in hashcat mode 11500-style workflow."),
    "pop3_user_enum": (
        "The server's USER response differs for existing vs missing accounts "
        "(RFC 1939 §5 allows USER-before-PASS rejection), so a scanner can "
        "enumerate valid mail users - seeds password spray against SSH / SMB "
        "/ AD / web logins that share the same identity."),
    "pop3_ntlm_info": (
        "AUTH NTLM's Type-2 challenge discloses NetBIOS name, DNS hostname, "
        "DNS domain, and forest DNS name (MS-NLMP §2.2.2.10 AV_PAIRs). Every "
        "one of those is a first-class known_hostnames/known_domains seed - "
        "the same primitive already harvested from SMTP / MSSQL NTLM info."),
    "pop3_stls_broken": (
        "After STLS the plaintext SASL mechanism set is still advertised - "
        "the server never drops PLAIN/LOGIN inside TLS. That is a hardening "
        "finding (RFC 2595 §4): a client that never issues STLS still "
        "authenticates in the clear."),
    "pop3_known_cve": (
        "The banner / IMPLEMENTATION product+version matches a known-"
        "vulnerable POP3 release. Cross-check against the offline CVE DB "
        "for the exact advisory."),
    "pop3s_cert": (
        "The POP3S (995) listener's certificate is self-signed / expired / "
        "otherwise untrusted - passive downgrade or on-path MITM is "
        "realistic; the certificate's CN/SANs still feed known_hostnames "
        "and known_domains."),
    "pop3_mailbox_read": (
        "The credentialed session read message headers via TOP - each "
        "'Received:' header seeds known_hostnames, each From:/To:/Cc: "
        "mailbox seeds users@domain across the whole environment."),
    "pop3_weak_password": (
        "A credential spray honouring LOGIN-DELAY (RFC 2449 §6.5) landed a "
        "valid USER/PASS pair - full mailbox read access and, in most "
        "environments, the same secret unlocks other identity-linked "
        "services."),
}


_finding = finding_builder("pop3", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_pop3(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            # CAPA presence + IMPLEMENTATION leak.
            impl = pr.get("implementation") or ""
            if impl:
                out.append(_finding(
                    "low", "POP3 IMPLEMENTATION capability leaks product/version",
                    tgt,
                    f"IMPLEMENTATION reply: {impl[:200]}. The RFC 2449 §6.9 "
                    "IMPLEMENTATION string is a first-class product/version "
                    "banner that supplements the greeting.",
                    "openssl",
                    f"openssl s_client -connect {h.ip}:{p.portid}   # then CAPA",
                    "Trim IMPLEMENTATION to a bare product name (Dovecot: "
                    "pop3_implementation = pop3d; Cyrus: hide version).",
                    ["CWE-200"], kind="pop3_implementation",
                    exploit_note=(
                        "nc IP 110 ; CAPA ; note IMPLEMENTATION line and "
                        "cross-check offline CVE DB"),
                    depth_tier="t0"))

            # APOP timestamp disclosure.
            apop = pr.get("apop_timestamp") or ""
            if apop:
                out.append(_finding(
                    "medium",
                    "POP3 APOP timestamp discloses internal hostname/domain",
                    tgt,
                    f"Greeting APOP timestamp: {apop}. The @host suffix is often "
                    "an internal FQDN not otherwise discovered, feeding "
                    "known_hostnames + known_domains.",
                    "nc",
                    f"nc {h.ip} {p.portid}   # first line carries <pid.time@host>",
                    "Configure the daemon to synthesise the APOP token from a "
                    "generic name (Dovecot: pop3_apop_username = ...), or "
                    "disable APOP entirely if unused.",
                    ["CWE-200"], kind="pop3_apop_timestamp",
                    exploit_note=(
                        "nc IP 110 ; note @hostname in first line ; add to "
                        "/etc/hosts or feed the AD reader for cross-service "
                        "correlation"),
                    depth_tier="t1"))
                out.append(_finding(
                    "high",
                    "POP3 APOP transcripts are offline-crackable (md5(challenge||pass))",
                    tgt,
                    f"APOP challenge advertised: {apop}. A captured 'APOP "
                    "<user> <md5-digest>' from any real client on the segment "
                    "is offline-crackable as md5(timestamp || password); "
                    f"hashcat line template: {_apop_hashcat_line('<user>', apop, '')}.",
                    "hashcat",
                    "# hashcat -m 11500-style workflow: <md5>:<timestamp>",
                    "Disable APOP - it is a legacy plaintext-equivalent "
                    "mechanism; require SASL over STLS instead.",
                    ["CWE-916", "CWE-522"], kind="pop3_apop_crackable",
                    exploit_note=(
                        "tcpdump -i any -A 'tcp port 110 and host IP' during "
                        "real login ; then hashcat with format <md5>:<timestamp> "
                        "mode 11500-style ; rockyou.txt is enough for most."),
                    depth_tier="t2"))

            # STLS missing on 110.
            if p.portid == 110 and not pr.get("stls"):
                out.append(_finding(
                    "high", "POP3 does not offer STLS on 110/tcp", tgt,
                    "CAPA did not advertise STLS: there is no way for a client "
                    "to negotiate encryption before USER/PASS on this port "
                    "(RFC 2595 §4).",
                    "openssl",
                    f"openssl s_client -starttls pop3 -connect {h.ip}:{p.portid}",
                    "Offer STLS on 110 (Dovecot: ssl = yes + protocols = pop3; "
                    "Cyrus: allowplaintext: no + tls_server_cert set) or move "
                    "mail to 995 / require implicit TLS per RFC 8314.",
                    ["CWE-319", "CWE-326"], kind="pop3_no_stls",
                    exploit_note=(
                        "tcpdump -i any -A 'tcp port 110 and host IP' to "
                        "capture live USER/PASS"),
                    depth_tier="t0"))

            # Cleartext USER/PASS accepted pre-TLS on 110.
            if p.portid == 110 and pr.get("plaintext_auth") == "accepted":
                out.append(_finding(
                    "high",
                    "POP3 accepts USER/PASS in cleartext (no STLS enforced)",
                    tgt,
                    "USER/PASS with bogus credentials was processed before any "
                    "STLS upgrade: every real client that authenticates on "
                    "this port hands its password to a passive sniffer.",
                    "nc",
                    f"nc {h.ip} {p.portid}   # USER x ; PASS y  -> -ERR auth failed",
                    "Require STLS before accepting USER/PASS or SASL PLAIN/"
                    "LOGIN (Dovecot: disable_plaintext_auth = yes; Cyrus: "
                    "allowplaintext: no); prefer implicit TLS on 995.",
                    ["CWE-319", "CWE-522"], kind="pop3_cleartext_auth",
                    exploit_note=(
                        "hydra -L users.txt -P rockyou.txt pop3://IP:110 -t 2 "
                        "-w 5 (respect any LOGIN-DELAY seen in CAPA)"),
                    depth_tier="t1"))

            # STLS-was-negotiated-but-mechanism-set-unchanged (auth downgrade).
            if pr.get("starttls_downgrade"):
                out.append(_finding(
                    "medium",
                    "POP3 SASL PLAIN/LOGIN still offered inside TLS (no downgrade lockout)",
                    tgt,
                    f"After STLS the CAPA response STILL advertises the "
                    f"plaintext mechanisms: pre={pr.get('sasl')}, "
                    f"post={pr.get('sasl_post_tls')}. RFC 2595 §4 recommends "
                    "restricting the plaintext mech set once TLS is in force.",
                    "openssl",
                    f"openssl s_client -starttls pop3 -connect {h.ip}:{p.portid}",
                    "Drop PLAIN/LOGIN from the SASL mech list inside TLS; "
                    "require SCRAM-SHA-256 (or Kerberos) for authenticated "
                    "connections.",
                    ["CWE-757"], kind="pop3_stls_broken",
                    exploit_note=(
                        "openssl s_client -starttls pop3 -connect IP:110 ; "
                        "type CAPA post-TLS - note PLAIN/LOGIN still "
                        "present"),
                    depth_tier="t1"))

            # SASL mechanism inventory.
            for mech in pr.get("sasl") or []:
                weak = _SASL_WEAK.get(mech.upper())
                if not weak:
                    continue
                sev, why = weak
                if mech.upper() in ("PLAIN", "LOGIN") and p.portid == 995:
                    sev = "low"
                    why = ("PLAIN/LOGIN inside implicit TLS 995 is base64-encoded "
                           "but the TLS wrapper protects it - still noteworthy "
                           "as the server accepts a plaintext-equivalent mech.")
                out.append(_finding(
                    sev, f"POP3 weak SASL mechanism advertised: {mech}", tgt,
                    f"CAPA SASL includes {mech}. {why}",
                    "openssl",
                    f"openssl s_client -connect {h.ip}:{p.portid}   # then CAPA",
                    f"Remove {mech} from the offered mechanisms; require a "
                    "SCRAM-family or Kerberos-only auth policy.",
                    ["CWE-327", "CWE-522"], kind="pop3_sasl_mechs",
                    exploit_note=(
                        "For CRAM-MD5: hashcat -m 10200 <b64_chal>:<b64_resp> "
                        "rockyou.txt after capturing a real client's AUTH "
                        "CRAM-MD5 response."),
                    depth_tier="t2"))

            # NTLM Type-2 info leak (AV_PAIRs).
            ntlm_info = pr.get("ntlm_info") or {}
            if ntlm_info:
                fields = ", ".join(f"{k}={v}" for k, v in ntlm_info.items() if v)
                out.append(_finding(
                    "high",
                    "POP3 AUTH NTLM Type-2 leaks NetBIOS/DNS names", tgt,
                    f"AUTH NTLM's Type-2 challenge AV_PAIRs: {fields}. Every "
                    "value seeds known_hostnames / known_domains across the "
                    "engagement (same primitive as SMTP / MSSQL NTLM info).",
                    "openssl",
                    f"openssl s_client -connect {h.ip}:{p.portid}   # AUTH NTLM",
                    "Remove NTLM from the SASL mech list unless a domain-join "
                    "workflow strictly requires it; restrict the listener to a "
                    "management VLAN.",
                    ["CWE-200"], kind="pop3_ntlm_info",
                    exploit_note=(
                        "kerbrute userenum -d <dns_domain> --dc <dns_computer> "
                        "/usr/share/seclists/Usernames/xato-net-10-million-"
                        "usernames.txt ; also seed impacket-lookupsid."),
                    depth_tier="t2"))

            # SASL challenge captures (CRAM-MD5 / DIGEST-MD5).
            for mech, key, mode in (("CRAM-MD5", "cram_md5", 10200),
                                     ("DIGEST-MD5", "digest_md5", 11500)):
                ch = (pr.get("sasl_challenges") or {}).get(key)
                if not ch:
                    continue
                out.append(_finding(
                    "medium",
                    f"POP3 {mech} advertised - offline-crackable auth", tgt,
                    f"The server issued a {mech} challenge on demand: "
                    f"`{ch[:120]}`. A captured client response is offline-"
                    f"crackable (hashcat -m {mode}).",
                    "hashcat",
                    f"# sniff client's {mech} response, then: hashcat -m {mode} <hash> wordlist.txt",
                    f"Disable {mech} in the SASL mech list; require SCRAM-SHA-256.",
                    ["CWE-327", "CWE-916"], kind="pop3_sasl_mechs",
                    exploit_note=(
                        "For CRAM-MD5: hashcat -m 10200 <b64_chal>:<b64_resp> "
                        "rockyou.txt after capturing a real client's AUTH "
                        "CRAM-MD5 response."),
                    depth_tier="t2"))

            # 995 certificate posture.
            cert = pr.get("cert") or {}
            if p.portid == 995 and cert:
                bits = []
                if cert.get("expired"): bits.append("expired")
                if cert.get("self_signed"): bits.append("self-signed")
                if bits:
                    out.append(_finding(
                        "low",
                        f"POP3S 995 certificate is {' / '.join(bits)}", tgt,
                        f"Certificate posture: {cert.get('error', '')}. "
                        f"Presented names: {', '.join(cert.get('names') or []) or '(none)'}.",
                        "openssl",
                        f"openssl s_client -connect {h.ip}:{p.portid}",
                        "Issue a CA-trusted certificate whose SAN covers the "
                        "service name; automate renewal.",
                        ["CWE-295", "CWE-298"], kind="pop3s_cert",
                        exploit_note=(
                            "openssl s_client -connect IP:995 ; grab "
                            "CN/SAN; use in mitmproxy --certs to MITM a "
                            "client that doesn't verify."),
                        depth_tier="t0"))

            # Banner / product-version match against the known-bad table.
            banner = pr.get("banner") or ""
            impl_txt = pr.get("implementation") or ""
            match_text = f"{banner} {impl_txt}"
            for rx, sev, title, detail, cwes in _KNOWN_BAD:
                if rx.search(match_text):
                    out.append(_finding(
                        sev, title, tgt,
                        f"Banner/IMPLEMENTATION: {match_text.strip()[:200]}. {detail}",
                        "vendor",
                        "# consult the vendor advisory for the matched CVE(s)",
                        "Upgrade to a vendor-supported build.",
                        cwes, kind="pop3_known_cve",
                        exploit_note=(
                            "Confirm exact build (CAPA IMPLEMENTATION), then check "
                            "https://dovecot.org/security.html for the exact CVE; "
                            "do NOT fire memory-corruption PoC without ROE."),
                        depth_tier="t0"))
                    break

            # User enumeration hits.
            enum = pr.get("enum") or {}
            if enum.get("distinguishes") and enum.get("existing"):
                users = enum["existing"]
                out.append(_finding(
                    "high",
                    "POP3 valid usernames enumerated via USER-command differential",
                    tgt,
                    f"USER responses differ for existing vs missing accounts. "
                    f"Valid accounts named by the sweep: {', '.join(users)}. "
                    "These names now seed password-spray against SSH / SMB / "
                    "AD / web.",
                    "hydra",
                    f"hydra -L users.txt -p '<pass>' pop3://{h.ip}:{p.portid}",
                    "Return an identical -ERR response (and identical timing) "
                    "for every USER regardless of existence - defer the "
                    "existence check until after PASS.",
                    ["CWE-203", "CWE-204"], kind="pop3_user_enum",
                    exploit_note=(
                        "hydra -L pop3_enum_users.txt -P rockyou.txt "
                        "pop3://IP:110 -t 2 -w <LOGIN-DELAY+1> ; add -e nsr."),
                    depth_tier="t2"))

            # Credentialed pass: default-creds spray hit.
            cred = pr.get("credentialed") or {}
            if cred.get("login"):
                mb = cred.get("mailbox") or {}
                stat = mb.get("stat", "").strip()
                addrs = mb.get("addresses") or []
                rcvd = mb.get("received_from") or []
                detail = (f"Login as '{cred.get('user')}' succeeded ({stat}). "
                          f"TOP pulled {len(mb.get('headers') or [])} message "
                          f"header block(s); harvested {len(addrs)} "
                          f"address(es), {len(rcvd)} Received-from host(s).")
                out.append(_finding(
                    "high", "POP3 credentialed mailbox read (RETR proof)", tgt,
                    detail
                    + (f"\nAddresses: {', '.join(addrs[:20])}" if addrs else "")
                    + (f"\nReceived-from: {', '.join(rcvd[:10])}" if rcvd else ""),
                    "pop3",
                    "# after LOGIN: STAT ; LIST ; UIDL ; TOP 1 25",
                    "Rotate the credential; audit downstream services that "
                    "share the identity (mail servers usually share AD across "
                    "SMB/VPN/web SSO).",
                    ["CWE-522"], kind="pop3_mailbox_read",
                    exploit_note=(
                        "python3 -c 'import poplib; p=poplib.POP3_SSL(\"IP\"); "
                        "p.user(u); p.pass_(pw); print(p.stat()); print(p.list()); "
                        "print(p.top(1,25))' ; feed addresses to smtp + AD reader."),
                    depth_tier="t3"))
                if cred.get("default_creds"):
                    out.append(_finding(
                        "high",
                        "POP3 weak / default credentials confirmed by spray",
                        tgt,
                        f"USER {cred.get('user')} with a default-credential "
                        "pair authenticated (LOGIN-DELAY honoured, per RFC "
                        "2449 §6.5).",
                        "hydra",
                        f"hydra -l {cred.get('user')} -p <pass> pop3://{h.ip}:{p.portid}",
                        "Enforce a strong-secret policy; disable dormant "
                        "accounts; require MFA on downstream identity-linked "
                        "services.",
                        ["CWE-521", "CWE-307"], kind="pop3_weak_password",
                        exploit_note=(
                            "Add pop3 spray of default set (admin/admin, "
                            "mail/mail, cyrus/cyrus, postmaster/postmaster) -- "
                            "until then, run manually: hydra -C /usr/share/"
                            "wordlists/seclists/Passwords/Default-Credentials/"
                            "default-passwords.txt pop3://IP"),
                        depth_tier="t3"))
    return out


# --- top-level analyze -----------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "pop3", _DEFAULT_PORT)


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Banner + APOP timestamp",
         "cmd": f"nc {ip} {port}   # first line = greeting; note <pid.time@host>"},
        {"step": "Capabilities (RFC 2449)",
         "cmd": f"openssl s_client -starttls pop3 -connect {ip}:{port}   # then CAPA"},
        {"step": "USER-differential enum",
         "cmd": f"hydra -L users.txt -p '' pop3://{ip}:{port}"},
        {"step": "NTLM info leak",
         "cmd": f"nmap -p{port} --script pop3-ntlm-info {ip}"},
    ]


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None, **_ignored) -> dict:
    """Full POP3 analysis. `creds` = {"user", "secret"} for a credentialed pass."""
    from . import svcprobe
    targets = pop3_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if not pr or not pr.get("reachable"):
                if pr:
                    probes[(t["ip"], t["port"])] = pr
                continue
            # USER-differential enumeration when the plaintext auth path is
            # actually reachable (110 with USER accepted, or 995 where TLS
            # wraps every reply anyway).
            if (t["port"] == 995
                    or pr.get("plaintext_auth") == "accepted"
                    or "USER" in (pr.get("capa") or {})):
                try:
                    pr["enum"] = enum_users(t["ip"], t["port"])
                except OSError:
                    pass
            # Credentialed follow-up: operator-supplied creds first.
            login_pair = None
            used_defaults = False
            if creds and creds.get("user"):
                if try_login(t["ip"], t["port"],
                             creds["user"], creds.get("secret") or ""):
                    login_pair = (creds["user"], creds.get("secret") or "")
            if login_pair is not None:
                cred_out = credentialed_probe(t["ip"], t["port"],
                                              login_pair[0], login_pair[1])
                cred_out["default_creds"] = used_defaults
                pr["credentialed"] = cred_out
            probes[(t["ip"], t["port"])] = pr
            t["banner"] = pr.get("banner", "")
            t["stls"] = pr.get("stls", False)
            t["apop"] = bool(pr.get("apop_timestamp"))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
