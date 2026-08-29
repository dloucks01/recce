"""SIP (5060/tcp+udp, 5061/tls): OPTIONS fingerprint + auth-realm disclosure.

SIP servers hand out their vendor/version and configured realm in the response
to an unauthenticated OPTIONS or REGISTER. That is enough to identify the PBX
(Asterisk, FreeSWITCH, Cisco CUCM, Kamailio) and to give the operator a
starting point for extension enumeration and toll-fraud checks.

recce sends one OPTIONS on the UDP transport most PBXes prefer, then falls
back to TCP for the same request. Read-only, one packet each. Wire format:
RFC 3261.
"""
from __future__ import annotations

import ipaddress
import re
import socket

from ..core.models import Host, Port


_DEFAULT_PORT = 5060
_TIMEOUT = 3.0

_SERVER_RE = re.compile(rb"^(?:Server|User-Agent):\s*(.+)$", re.I | re.M)
_REALM_RE = re.compile(rb'realm="([^"]+)"', re.I)
# RFC 3261 §22.4 / RFC 8760 auth-param syntax: token = quoted-string OR token.
# One regex covers both forms so nonce="..." and algorithm=MD5 both parse.
_AUTH_PARAM_RE = re.compile(
    rb'(?P<k>[A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"(?P<qv>[^"]*)"|(?P<tv>[^\s,]+))', re.I)
# Via received=/rport= (RFC 3581 + RFC 3261 §18.2.1). rport may be a bare
# token (echoing the port) or a number.
_VIA_RECEIVED_RE = re.compile(rb";\s*received=([^;\s,]+)", re.I)
_VIA_RPORT_RE = re.compile(rb";\s*rport=(\d+)", re.I)
# Contact: <sip:user@host:port> OR sip:user@host — pull the host token.
_CONTACT_HOST_RE = re.compile(
    rb"^Contact:\s*(?:[^<]*<)?sips?:(?:[^@>]*@)?([^:;>\s]+)", re.I | re.M)
# Vendor tokens we normalise into a stable (vendor, product_version) tuple so a
# CVE consumer can key on them. Order matters: longer/more-specific patterns
# first so "FPBX" hits before we fall through to "Asterisk".
_VENDOR_PATTERNS = (
    # (vendor slug, compiled regex — group(1) = version)
    ("freepbx", re.compile(r"\bFPBX[-\s]*([\w.]+)", re.I)),
    ("cisco-cucm", re.compile(r"\bCisco[-\s_]*CUCM\s*([\w.]+)", re.I)),
    ("asterisk", re.compile(r"\bAsterisk(?:\s*PBX)?\s*([\w.]+)", re.I)),
    ("kamailio", re.compile(r"\bKamailio[^\d]*(\d[\w.]*)", re.I)),
    ("opensips", re.compile(r"\bOpenSIPS[^\d]*(\d[\w.]*)", re.I)),
    ("freeswitch", re.compile(r"\bFreeSWITCH[^\d]*(\d[\w.]*)", re.I)),
    ("3cx", re.compile(r"\b3CX(?:PhoneSystem)?\s*([\w.]+)", re.I)),
    ("yate", re.compile(r"\bYATE(?:/|\s+)([\w.]+)", re.I)),
)


def _parse_digest_challenge(reply: bytes) -> dict:
    """Extract the full Digest challenge from WWW-Authenticate / Proxy-Authenticate.

    Returns fields per RFC 3261 §22.4 and RFC 8760: realm, nonce, opaque, qop,
    algorithm (upper-cased). Absent params are omitted so callers can `.get()`
    without wading through empty strings.
    """
    line = None
    for hdr in (b"WWW-Authenticate", b"Proxy-Authenticate"):
        m = re.search(rb"^" + hdr + rb":\s*(.+)$", reply, re.I | re.M)
        if m:
            line = m.group(1)
            break
    if not line:
        return {}
    out: dict = {}
    for pm in _AUTH_PARAM_RE.finditer(line):
        k = pm.group("k").decode("ascii", "replace").lower()
        v = (pm.group("qv") if pm.group("qv") is not None
             else pm.group("tv")).decode("ascii", "replace")
        if k in ("realm", "nonce", "opaque", "qop", "algorithm",
                 "stale", "domain"):
            out[k] = v
    if "algorithm" in out:
        # RFC 8760 lists MD5 / SHA-256 / SHA-512-256 (uppercased); normalise so
        # a "sha-256" reply is comparable to an "SHA-256" advertisement.
        out["algorithm"] = out["algorithm"].upper()
    return out


def _normalise_vendor(server: str) -> tuple[str, str]:
    """Split a Server / User-Agent free-form string into (vendor_slug, version).

    Returns ("", "") when nothing recognisable matched — the caller MUST NOT
    fabricate a match, because a CVE consumer keys on these tuples.
    """
    if not server:
        return "", ""
    for slug, rx in _VENDOR_PATTERNS:
        m = rx.search(server)
        if m:
            return slug, m.group(1)
    return "", ""


def _is_private_ip(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).is_private
    except ValueError:
        return False


def is_sip(port: Port) -> bool:
    svc = (port.service or "").lower()
    return port.portid in (5060, 5061) or "sip" in svc


def _options(source_port: int, ip: str, port: int) -> bytes:
    """Minimal OPTIONS. The Via branch is z9hG4bK-prefixed as required by
    RFC 3261 §8.1.1.7 so servers that validate reject-on-bad-branch will
    still answer."""
    return (f"OPTIONS sip:{ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP recce:{source_port};branch=z9hG4bK-recce\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:recce@recce.local>;tag=recce\r\n"
            f"To: <sip:{ip}>\r\n"
            f"Call-ID: recce-probe@recce\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"User-Agent: recce-sip/1.0\r\n"
            f"Content-Length: 0\r\n\r\n").encode("ascii")


def _probe_udp(ip: str, port: int, timeout: float) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("", 0))
        s.settimeout(timeout)
        src = s.getsockname()[1]
        s.sendto(_options(src, ip, port), (ip, port))
        data, _ = s.recvfrom(65535)
        return data
    except (OSError, socket.timeout):
        return b""
    finally:
        s.close()


def _probe_tcp(ip: str, port: int, timeout: float) -> bytes:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return b""
    try:
        s.settimeout(timeout)
        s.sendall(_options(port, ip, port))
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf
    except OSError:
        return b""
    finally:
        try:
            s.close()
        except OSError:
            pass


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    out: dict = {"reachable": False, "transport": ""}
    for transport, fn in (("udp", _probe_udp), ("tcp", _probe_tcp)):
        data = fn(ip, port, timeout)
        if not data or not data.startswith(b"SIP/"):
            continue
        out["reachable"] = True
        out["transport"] = transport
        # Status line: SIP/2.0 200 OK
        try:
            status = int(data.split(b" ", 2)[1])
        except (ValueError, IndexError):
            status = 0
        out["status"] = status
        m = _SERVER_RE.search(data)
        if m:
            out["server"] = m.group(1).decode("ascii", "replace").strip()
            # (vendor slug, product_version) tuple for the CVE consumer.
            # Empty strings when the free-form banner isn't recognised —
            # the consumer MUST NOT invent a match from thin air.
            vendor, prodver = _normalise_vendor(out["server"])
            if vendor:
                out["vendor"] = vendor
                out["product_version"] = prodver
        m = _REALM_RE.search(data)
        if m:
            out["realm"] = m.group(1).decode("ascii", "replace").strip()
        # Full Digest challenge (RFC 3261 §22.4 + RFC 8760): realm/nonce/qop/
        # algorithm/opaque. Enables sipcrack/hashcat feed + MD5-only weak-crypto.
        digest = _parse_digest_challenge(data)
        if digest:
            out["digest"] = digest
            # Prefer the parsed realm (handles single-quoted or spaced values
            # that the strict WWW-Authenticate regex may have skipped).
            if digest.get("realm") and not out.get("realm"):
                out["realm"] = digest["realm"]
        # Allow header (advertised methods) is a good fingerprint of PBX config
        allow = re.search(rb"^Allow:\s*(.+)$", data, re.I | re.M)
        if allow:
            out["methods"] = allow.group(1).decode("ascii", "replace").strip()
        # Via received= / rport= (RFC 3581 + RFC 3261 §18.2.1): the server
        # rewrote the top Via with the source IP+port it observed. When that
        # differs from what we sent + is routable, it discloses NAT topology.
        via = re.search(rb"^Via:\s*(.+)$", data, re.I | re.M)
        if via:
            vm = _VIA_RECEIVED_RE.search(via.group(1))
            if vm:
                out["via_received"] = vm.group(1).decode("ascii", "replace")
            rm = _VIA_RPORT_RE.search(via.group(1))
            if rm:
                out["via_rport"] = int(rm.group(1))
        # Contact URI host = the PBX's own address. Often the internal
        # RFC1918 IP even when reached over a public/edge address.
        cm = _CONTACT_HOST_RE.search(data)
        if cm:
            host_tok = cm.group(1).decode("ascii", "replace")
            out["contact_host"] = host_tok
            if _is_private_ip(host_tok):
                out["contact_internal_ip"] = host_tok
        break
    # Extension enumeration piggybacks on the same probe when the server is
    # reachable — bounded to the default 20 extensions so a single scan does
    # not saturate a fragile PBX. Skip on TCP: svwar's asymmetry works on UDP
    # where the response is fast enough to fingerprint.
    if out.get("reachable") and out.get("transport") == "udp":
        try:
            out["ext_enum"] = enumerate_extensions(ip, port, timeout=timeout)
        except OSError:
            pass
    return out


# --- Extension enumeration (svwar-style) ------------------------------------
# A REGISTER for an EXISTING extension returns 401/407 (auth required); a
# REGISTER for a NONEXISTENT one returns 404 on servers without
# `alwaysauthreject`. That asymmetry — different status codes for existing vs
# missing users — is what svwar exploits.
#
# recce keeps this bounded: only tests a small range (default 100-119) and
# stops the moment the server proves it has `alwaysauthreject` enabled (both
# statuses match). Sends REGISTER not INVITE, so no phones ring; UDP only.

_EXT_RANGE = range(100, 120)         # 20 probes by default — a fingerprint
_401_407 = (401, 407)


def _register(source_port: int, ip: str, port: int, ext: str) -> bytes:
    """Minimal REGISTER for an extension. Same header shape as OPTIONS, just
    a different method + a To/From that names the extension."""
    return (f"REGISTER sip:{ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP recce:{source_port};branch=z9hG4bK-recce-r-{ext}\r\n"
            f"Max-Forwards: 70\r\n"
            f"From: <sip:{ext}@{ip}>;tag=recce-r-{ext}\r\n"
            f"To: <sip:{ext}@{ip}>\r\n"
            f"Call-ID: recce-r-{ext}@recce\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f"Contact: <sip:recce@127.0.0.1>\r\n"
            f"User-Agent: recce-sip/1.0\r\n"
            f"Expires: 0\r\n"
            f"Content-Length: 0\r\n\r\n").encode("ascii")


def _sip_status(reply: bytes) -> int:
    """Extract the numeric status code from a SIP response line."""
    if not reply.startswith(b"SIP/"):
        return 0
    try:
        return int(reply.split(b" ", 2)[1])
    except (ValueError, IndexError):
        return 0


def enumerate_extensions(ip: str, port: int, extensions=_EXT_RANGE,
                         timeout: float = _TIMEOUT) -> dict:
    """Probe each extension with REGISTER. Returns:
        {existing: [ext], missing: [ext], always_reject: bool}

    A server with `alwaysauthreject` (Asterisk) returns the same auth-required
    reply for existing AND missing extensions, so recce cannot distinguish
    them — and shouldn't invent findings. Signaled by seen_missing_401=True.
    """
    out = {"existing": [], "missing": [], "always_reject": False,
           "seen_ok": False, "probed": 0}
    seen_missing_401 = False
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0))
    s.settimeout(timeout)
    src = s.getsockname()[1]
    try:
        for ext in extensions:
            out["probed"] += 1
            try:
                s.sendto(_register(src, ip, port, str(ext)), (ip, port))
                data, _ = s.recvfrom(65535)
            except (OSError, socket.timeout):
                continue
            status = _sip_status(data)
            if status in _401_407:
                out["existing"].append(str(ext))
            elif status == 404:
                out["missing"].append(str(ext))
            elif status == 403:
                # 403 for both existing and missing = alwaysauthreject variant
                # (some Asterisk builds). Match on it.
                seen_missing_401 = True
            # 200 OK on REGISTER = an extension that accepts unauthenticated
            # registrations — critical on its own; log as existing.
            elif status == 200:
                out["existing"].append(str(ext))
                out["seen_ok"] = True
    finally:
        s.close()
    # If EVERY probe came back the same auth-required status, treat that as
    # `alwaysauthreject` and clear the "existing" list — the server is not
    # actually leaking which extensions exist.
    if out["existing"] and not out["missing"] and out["probed"] > 0:
        out["always_reject"] = True
        out["existing"] = []
    elif seen_missing_401 and not out["missing"]:
        out["always_reject"] = True
    return out


def sip_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_sip(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_sip(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            server = pr.get("server") or "unknown"
            realm = pr.get("realm") or ""
            methods = pr.get("methods") or ""
            out.append(_finding(
                "low", "SIP endpoint discloses server / realm via unauth OPTIONS",
                tgt,
                f"SIP OPTIONS on {tgt} ({pr.get('transport', '?').upper()}) returned "
                f"status {pr.get('status', '?')} — Server: {server}"
                + (f", realm=\"{realm}\"" if realm else "")
                + (f", Allow: {methods}" if methods else "")
                + ". Enough to fingerprint the PBX (Asterisk / FreeSWITCH / "
                "Kamailio / Cisco CUCM) and start extension enumeration + "
                "auth attacks against the named realm.",
                "svmap / svwar / sipvicious",
                f"svmap.py {h.ip}:{p.portid}   # then svwar.py -e100-999 -m INVITE "
                f"{h.ip}:{p.portid}",
                "Restrict SIP to trusted networks; on Asterisk set "
                "alwaysauthreject=yes (RFC-3261 §22 recommends the same reply "
                "for existing vs missing extensions) so extension enumeration "
                "cannot distinguish valid users.",
                ["CWE-200"], kind="sip_fingerprint"))

            # Extension enumeration signals:
            #   existing[] populated -> the server distinguishes 401/407 vs 404,
            #     so valid extensions are discoverable (svwar's classic target).
            #   seen_ok=True         -> a REGISTER returned 200: the extension
            #     accepts UNAUTHENTICATED registration - toll fraud vector.
            #   always_reject=True   -> hardened server; do not report anything.
            ext = pr.get("ext_enum") or {}
            existing = ext.get("existing") or []
            if existing and not ext.get("always_reject"):
                sample = ", ".join(existing[:10])
                out.append(_finding(
                    "high" if ext.get("seen_ok") else "medium",
                    "SIP extension enumeration succeeded (svwar-style)", tgt,
                    f"Probed {ext.get('probed', 0)} candidate extension(s); "
                    f"{len(existing)} returned auth-required (401/407) or 200 "
                    f"OK — the server distinguishes existing vs missing "
                    f"extensions, so an attacker can enumerate the entire "
                    f"dial plan. Existing: {sample}"
                    + (" …" if len(existing) > 10 else "")
                    + ("\n\nAt least one extension accepted UNAUTHENTICATED "
                       "REGISTER (200 OK) — toll-fraud primitive: register "
                       "an attacker endpoint and place calls as that "
                       "extension." if ext.get("seen_ok") else ""),
                    "svwar / sipvicious",
                    f"svwar.py -e100-999 -m REGISTER {h.ip}:{p.portid}   "
                    "# to sweep further, then svcrack.py against a hit",
                    "Set alwaysauthreject=yes (Asterisk) or the equivalent — "
                    "return the same reply for existing vs missing extensions. "
                    "Require authentication on REGISTER even for extensions "
                    "that historically accepted anonymous registrations.",
                    ["CWE-200", "CWE-306"], kind="sip_ext_enum"))

            # Internal-IP disclosure via Via received= or Contact URI. Only
            # fire when the leaked address is a) RFC1918/private and b) DIFFERENT
            # from the address recce reached out to — otherwise it's just the
            # host echoing its own routable address, no leak (mirrors the
            # ftp_pasv_internal_ip pattern).
            leaked = pr.get("contact_internal_ip") or ""
            src_leak = ""
            recv = pr.get("via_received") or ""
            if recv and _is_private_ip(recv) and recv != h.ip:
                src_leak = f"Via received={recv}"
            if leaked and leaked != h.ip:
                if src_leak:
                    src_leak += f"; Contact host {leaked}"
                else:
                    src_leak = f"Contact host {leaked}"
            if src_leak:
                out.append(_finding(
                    "medium", "SIP response discloses internal IP address", tgt,
                    f"SIP response from {tgt} leaked a private-network address "
                    f"({src_leak}) that differs from the reached IP. Per RFC 3581 "
                    "the server echoes the observed source in Via received=; per "
                    "RFC 3261 §20.10 Contact carries the PBX's own address — a "
                    "NAT'd or dual-homed PBX exposes its internal-subnet address "
                    "here, which downstream pivots can target.",
                    "sngrep / sipsak",
                    f"sipsak -vv -s sip:{h.ip}:{p.portid}   # inspect Via / Contact "
                    "on the OPTIONS reply",
                    "Rewrite Contact / Via on the SBC or edge NAT; on Kamailio use "
                    "nathelper (fix_contact / fix_nated_contact), on Asterisk set "
                    "externaddr / localnet so the PBX advertises its routable "
                    "address instead of the internal one.",
                    ["CWE-200"], kind="sip_internal_ip_disclosure"))

            # Digest algorithm advertisement (RFC 3261 §22.4 + RFC 8760). The
            # base spec only requires MD5; RFC 8760 (2020) added SHA-256 and
            # SHA-512-256 with an explicit "algorithms MUST be listed in order
            # of preference" and MD5 SHOULD NOT be the sole option. A server
            # that either omits algorithm= (defaults to MD5 per RFC 2617) or
            # names MD5 exclusively is running the weak variant.
            digest = pr.get("digest") or {}
            if digest.get("nonce"):
                algo = (digest.get("algorithm") or "MD5").upper()
                if algo in ("MD5", "MD5-SESS"):
                    out.append(_finding(
                        "low",
                        "SIP Digest authentication offers MD5 only (no RFC 8760 SHA-256)",
                        tgt,
                        f"WWW-Authenticate on {tgt} advertises algorithm={algo} "
                        f"(realm=\"{digest.get('realm', '')}\", qop="
                        f"{digest.get('qop', '(none)')}). RFC 8760 (2020) adds "
                        "SHA-256 / SHA-512-256 Digest for SIP; MD5-only servers "
                        "are the weak-hash variant, feed sipcrack/hashcat mode "
                        "11400 directly, and cannot upgrade responders that "
                        "would otherwise negotiate SHA-256.",
                        "sipcrack / hashcat",
                        f"# feed challenge to hashcat mode 11400:\n"
                        f"echo '$sip$***{digest.get('realm', '')}***"
                        f"{digest.get('nonce', '')}***MD5***<user>***<uri>***"
                        f"{digest.get('qop', '')}***<response>' | hashcat -m 11400 - wordlist",
                        "Enable RFC 8760 SHA-256 / SHA-512-256 Digest challenges "
                        "(Kamailio auth_db config, Asterisk res_pjsip auth "
                        "algorithms) and remove MD5 from the offered set once "
                        "endpoints support the upgrade.",
                        ["CWE-327", "CWE-916"], kind="sip_digest_md5_only"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "svmap",
         "command": f"svmap.py {ip}:{port}",
         "why": "confirm PBX + version — same OPTIONS recce sent, more verbose"},
        {"phase": "enumerate", "tool": "svwar",
         "command": f"svwar.py -e100-999 -m INVITE {ip}:{port}",
         "why": "extension enumeration — INVITE distinguishes existing vs not "
                "on servers without alwaysauthreject"},
        {"phase": "exploit", "tool": "svcrack",
         "command": f"svcrack.py -u <ext> -d passwords.txt {ip}:{port}",
         "why": "auth brute against an enumerated extension; toll-fraud path"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "sip", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = sip_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["server"] = pr.get("server", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
