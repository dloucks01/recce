"""Pure-Python enrichment probes - stdlib only, airgapped-safe.

nmap's `-sV`/`-sC` tells you *what* is listening; these probes add a light
active layer that stock Kali would need extra tooling (testssl.sh, nikto,
httpx) to produce. Everything here uses only http.client / socket / ssl, so it
runs on an airgapped Kali with nothing installed.

Two probe families:
  * HTTP security-header analysis - flags missing HSTS / CSP / X-Frame-Options
    / X-Content-Type-Options / Referrer-Policy and leaky Server banners.
  * TLS certificate & protocol analysis - flags expired / self-signed / soon-to-
    expire certs, hostname mismatch, and negotiable SSLv3/TLS 1.0/1.1.

Findings come back as models.Vuln with CWE references, so they flow into the
same Vulnerabilities sheet as everything else. Connections are strictly
timeout-bounded and best-effort: any failure yields no finding, never an
exception that would stall a scan.
"""

from __future__ import annotations

import calendar
import http.client
import socket
import ssl
import time
import warnings

from ..core.models import Host, Port, Vuln
from ..core import proxy

# Ports we treat as HTTP/HTTPS even if nmap's service name is fuzzy.
_TLS_HINTS = ("https", "ssl", "tls")
_HTTP_HINTS = ("http", "www")
_COMMON_TLS_PORTS = {443, 8443, 9443, 4443, 10443, 993, 995, 465, 636, 989, 990, 5986}
_COMMON_HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8888, 5000, 3000, 9000, 5985}

_TIMEOUT = 6.0        # per-connection ceiling (seconds)
_EXPIRY_WARN_DAYS = 30


# --- port classification --------------------------------------------------------

def _is_tls(port: Port) -> bool:
    # Only the nmap service + tunnel decide TLS - NOT the product name. Substring-
    # matching the product wrongly flagged "SimpleHTTPServer" (contains "https"),
    # "*ssl*" builds, etc. as TLS, so a plain-HTTP 8080 got scanned as HTTPS and every
    # web finding was missed. An explicit plain 'http' service is authoritative: not TLS.
    svc = (port.service or "").lower()
    tunnel = (port.tunnel or "").lower()
    if tunnel == "ssl" or "ssl" in svc or "tls" in svc or "https" in svc:
        return True
    if svc in ("http", "http-proxy", "http-alt", "www"):
        return False                       # nmap says plaintext HTTP - trust it
    return port.portid in _COMMON_TLS_PORTS


def _is_http(port: Port) -> bool:
    blob = f"{port.service} {port.product}".lower()
    if any(h in blob for h in _HTTP_HINTS):
        return True
    return port.portid in _COMMON_HTTP_PORTS or _is_tls(port)


def _mk(host_ip: str, port: Port, sid: str, sev: str, title: str,
        cwes: list[str], output: str, remediation: str,
        depth_tier: str = "", exploit_note: str = "") -> Vuln:
    return Vuln(
        ip=host_ip, port=port.portid, protocol=port.protocol,
        script_id=sid, state="finding", title=title, output=output,
        severity=sev, cwes=cwes, source="probe", remediation=remediation,
        confidence="confirmed", depth_tier=depth_tier, exploit_note=exploit_note,
    )


# --- HTTP security headers ------------------------------------------------------

# header (lowercase) -> (finding title, severity, CWEs, remediation)
_HEADER_CHECKS = {
    "strict-transport-security": (
        "Missing HSTS header", "low", ["CWE-319"],
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."),
    "content-security-policy": (
        "Missing Content-Security-Policy header", "low", ["CWE-693", "CWE-1021"],
        "Define a Content-Security-Policy to constrain script/frame sources."),
    "x-frame-options": (
        "Missing X-Frame-Options / frame-ancestors (clickjacking)", "low",
        ["CWE-1021"],
        "Set 'X-Frame-Options: DENY' or a CSP frame-ancestors directive."),
    "x-content-type-options": (
        "Missing X-Content-Type-Options header (MIME sniffing)", "low",
        ["CWE-693", "CWE-16"],
        "Set 'X-Content-Type-Options: nosniff'."),
}


def _fetch_headers(host_ip: str, port: Port, use_tls: bool):
    """Return (status, headers-dict-lowercased) or None on any failure."""
    conn = None
    try:
        if use_tls:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(
                host_ip, port.portid, timeout=proxy.scaled(_TIMEOUT), context=ctx)
        else:
            conn = http.client.HTTPConnection(host_ip, port.portid, timeout=proxy.scaled(_TIMEOUT))
        conn.request("HEAD", "/", headers={"User-Agent": "recce-probe/1.0",
                                           "Connection": "close"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        status = resp.status
        # Some servers reject HEAD; retry once with GET if that looks the case.
        if status in (400, 405, 501):
            conn.close()
            conn = (http.client.HTTPSConnection(host_ip, port.portid, timeout=proxy.scaled(_TIMEOUT),
                                                context=ssl._create_unverified_context())
                    if use_tls else
                    http.client.HTTPConnection(host_ip, port.portid, timeout=proxy.scaled(_TIMEOUT)))
            conn.request("GET", "/", headers={"User-Agent": "recce-probe/1.0",
                                              "Connection": "close"})
            resp = conn.getresponse()
            resp.read(2048)
            headers = {k.lower(): v for k, v in resp.getheaders()}
            status = resp.status
        return status, headers
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def http_findings(host_ip: str, port: Port) -> list[Vuln]:
    use_tls = _is_tls(port)
    result = _fetch_headers(host_ip, port, use_tls)
    if result is None:
        return []
    status, headers = result
    findings: list[Vuln] = []

    missing = []
    for name, (title, sev, cwes, fix) in _HEADER_CHECKS.items():
        # HSTS only matters over TLS.
        if name == "strict-transport-security" and not use_tls:
            continue
        if name not in headers:
            missing.append(name)
            findings.append(_mk(
                host_ip, port, "http-headers", sev, title, cwes,
                f"HTTP {status}: response is missing the '{name}' header.", fix,
                depth_tier="t1",
                exploit_note=(
                    f"curl -sI http{'s' if use_tls else ''}://{host_ip}:{port.portid}/ | "
                    f"grep -i '{name}' — confirm still absent, then check whether the "
                    "missing header actually enables a real primitive on this app "
                    "(e.g. CSP-absent + reflected input → XSS; HSTS-absent + cleartext "
                    "80 open → SSL-strip on same LAN).")))

    # Server / X-Powered-By banner disclosure (version leakage).
    banner = "; ".join(
        f"{h}: {headers[h]}" for h in ("server", "x-powered-by", "x-aspnet-version")
        if h in headers)
    if banner and any(c.isdigit() for c in banner):
        findings.append(_mk(
            host_ip, port, "http-headers", "info",
            "Server banner discloses software version", ["CWE-200"],
            f"HTTP {status}: {banner}",
            "Suppress version details in Server/X-Powered-By response headers.",
            depth_tier="t0",
            exploit_note=(f"searchsploit '{banner[:60]}' — cross-reference the disclosed "
                          "version against public CVEs. If any CVE has a public POC, "
                          "run recce prove or the matching msf module.")))

    # Deep HTTP: bundled path enum + framework fingerprint. Lives in
    # services.http because it will grow with each Tier-A HTTP item (methods,
    # CORS, robots, JS secret scan, Swagger discovery, vhost enum).
    # Import lazily so probes.py doesn't take the extra load unless the port
    # is actually HTTP.
    try:
        from . import http as _svc_http
        findings.extend(_svc_http.enum_findings(host_ip, port))
    except Exception:                             # never let deep-scan break header checks
        pass

    return findings


# --- TLS certificate & protocol -------------------------------------------------

# Use TLSVersion (not the deprecated PROTOCOL_* constants): _accepts_protocol
# pins min==max to the exact version, so a handshake succeeds only if the server
# truly speaks it - a PROTOCOL_TLSv1 context can silently negotiate UP to TLS 1.2
# and falsely report legacy support.
_LEGACY_PROTOCOLS = [
    ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None), ["CWE-327"], "high"),
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None), ["CWE-326"], "medium"),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), ["CWE-326"], "medium"),
]

_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}


def _parse_cert_time(value: str) -> float | None:
    """Parse OpenSSL 'notAfter' ('Jun  1 12:00:00 2025 GMT') to epoch seconds.

    Avoids strptime %b locale surprises by mapping month names ourselves.
    """
    try:
        parts = value.replace("GMT", "").split()
        mon = _MONTHS.get(parts[0])
        day = int(parts[1])
        hh, mm, sec = (int(x) for x in parts[2].split(":"))
        year = int(parts[3])
        # notAfter is GMT/UTC; timegm treats the tuple as UTC. mktime would read it as
        # LOCAL time, shifting the expiry window by the runner's UTC offset.
        return calendar.timegm((year, mon or 1, day, hh, mm, sec, 0, 0, 0))
    except (ValueError, IndexError, TypeError):
        return None


def _peer_cert(host_ip: str, port: Port):
    """Fetch (verified_cert_or_None, unverified_cert_dict, verify_error)."""
    # First a verifying handshake to learn whether the chain/hostname is valid.
    verify_error = ""
    try:
        vctx = ssl.create_default_context()
        # We connect by IP, so hostname verification would fail for essentially
        # every real cert (the IP is rarely in the SAN) - flooding a spurious
        # "hostname mismatch" finding on every TLS service AND leaving getpeercert()
        # empty so the expiry check below can never fire. Verify the chain (still
        # catches expired/self-signed/untrusted) but not the hostname.
        vctx.check_hostname = False
        with socket.create_connection((host_ip, port.portid), timeout=proxy.scaled(_TIMEOUT)) as raw:
            with vctx.wrap_socket(raw, server_hostname=host_ip) as tls:
                return tls.getpeercert(), tls.version(), ""
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError, ValueError):
        verify_error = ""
    # Fall back to an unverified handshake so we can still record the negotiated
    # protocol even when the chain doesn't validate. getpeercert() returns {}
    # without verification, so cert-expiry detail comes only from the verified
    # path above; the verify_error already captures expired/self-signed here.
    try:
        uctx = ssl._create_unverified_context()
        with socket.create_connection((host_ip, port.portid), timeout=proxy.scaled(_TIMEOUT)) as raw:
            with uctx.wrap_socket(raw, server_hostname=host_ip) as tls:
                return {}, tls.version(), verify_error or "unverified"
    except (OSError, ssl.SSLError, ValueError):
        return None, "", verify_error


def tls_findings(host_ip: str, port: Port,
                 known_names: list[str] | None = None) -> list[Vuln]:
    if not _is_tls(port):
        return []
    findings: list[Vuln] = []
    cert, proto, verify_error = _peer_cert(host_ip, port)
    if cert is None and not verify_error:
        return []   # not actually TLS / unreachable

    # Certificate validity (from the verified handshake, which populates cert).
    if verify_error and verify_error != "unverified":
        low = verify_error.lower()
        if "expired" in low:
            findings.append(_mk(
                host_ip, port, "tls-cert", "low", "Expired TLS certificate",
                ["CWE-298", "CWE-295"], verify_error,
                "Renew the certificate; automate renewal.",
                depth_tier="t1",
                exploit_note=(f"openssl s_client -connect {host_ip}:{port.portid} </dev/null 2>/dev/null "
                              "| openssl x509 -noout -dates — confirm; if the client "
                              "trusts anyway, note as MitM-substitution risk.")))
        elif "self signed" in low or "self-signed" in low:
            findings.append(_mk(
                host_ip, port, "tls-cert", "low", "Self-signed TLS certificate",
                ["CWE-295"], verify_error,
                "Use a certificate from a trusted CA (internal PKI is fine).",
                depth_tier="t1",
                exploit_note=(f"openssl s_client -connect {host_ip}:{port.portid} </dev/null "
                              "| openssl x509 -noout -issuer -subject — same issuer as subject "
                              "confirms self-signed. Substitute-cert MitM against a client that "
                              "pinned to the self-signed cert is trivial once you can route.")))
        elif "hostname mismatch" in low or "doesn't match" in low:
            findings.append(_mk(
                host_ip, port, "tls-cert", "low", "TLS certificate hostname mismatch",
                ["CWE-297"], verify_error,
                "Issue a certificate whose SAN matches the service name.",
                depth_tier="t1",
                exploit_note=(f"openssl s_client -connect {host_ip}:{port.portid} -servername <name> "
                              "— confirm SAN mismatch. If a downstream service ignores hostname "
                              "verification, MitM substitution works with any cert this CA signs.")))
        else:
            findings.append(_mk(
                host_ip, port, "tls-cert", "low", "TLS certificate not trusted",
                ["CWE-295"], verify_error,
                "Ensure the presented chain is complete and CA-trusted.",
                depth_tier="t1",
                exploit_note=(f"openssl s_client -showcerts -connect {host_ip}:{port.portid} "
                              "</dev/null — inspect the chain. Missing intermediate is fixable; "
                              "unknown-CA at leaf = client bypasses verification or is broken.")))

    if isinstance(cert, dict) and known_names:
        # Certificate SAN coverage against every hostname recce has learned
        # for this host from OTHER sources (LDAP dnsHostName, PTR, NTLM,
        # SMB, on-target enum). If none of those names appear in the SAN,
        # an attacker able to route traffic for that name can present a
        # substituted certificate without triggering client-side warnings
        # against THIS server — the operator's own PKI thinks the name
        # doesn't exist here. Skip when we have no learned names (the
        # default hostname-mismatch handling above already covers the
        # IP-in-URL case).
        from ..core.known_hostnames import cert_covers
        sans = [v for typ, v in (cert.get("subjectAltName") or [])
                if typ.lower() == "dns"]
        if sans:
            uncovered = [n for n in known_names if not cert_covers(sans, n)]
            if uncovered:
                findings.append(_mk(
                    host_ip, port, "tls-cert", "info",
                    "TLS certificate does not cover known hostname(s)",
                    ["CWE-297", "CWE-295"],
                    f"SAN: {', '.join(sans[:5])}. "
                    f"Uncovered: {', '.join(uncovered[:5])}",
                    "Re-issue the certificate with the missing name(s) in the "
                    "SAN, or move the name(s) to a service that presents a "
                    "matching cert. An attacker able to route traffic for an "
                    "uncovered name can present a substituted certificate "
                    "without detection.",
                    depth_tier="t1",
                    exploit_note=(f"getent hosts {uncovered[0]} — confirm the name resolves; "
                                  "if clients actually reach the service by it, MitM "
                                  "substitution with a valid cert on THAT name is undetected.")))

    if isinstance(cert, dict):
        not_after = cert.get("notAfter")
        if not_after:
            exp = _parse_cert_time(not_after)
            if exp is not None:
                remaining = exp - time.time()
                if 0 < remaining < _EXPIRY_WARN_DAYS * 86400:
                    days = int(remaining // 86400)
                    findings.append(_mk(
                        host_ip, port, "tls-cert", "info",
                        "TLS certificate expiring soon", ["CWE-298"],
                        f"Certificate expires in ~{days} day(s): {not_after}",
                        "Renew before expiry to avoid outage/trust warnings.",
                        depth_tier="t0",
                        exploit_note=("(engagement-hygiene finding — schedule renewal; not a "
                                      "primitive to exploit unless the org still runs the cert "
                                      "after expiry and clients bypass verification.)")))

    # Negotiated protocol from the default handshake.
    if proto in ("SSLv3", "TLSv1", "TLSv1.0"):
        findings.append(_mk(
            host_ip, port, "tls-proto", "medium",
            f"Weak TLS protocol negotiated ({proto})", ["CWE-326", "CWE-327"],
            f"Default handshake negotiated {proto}.",
            "Disable SSLv3/TLS 1.0/1.1; require TLS 1.2+.",
            depth_tier="t1",
            exploit_note=(f"testssl.sh {host_ip}:{port.portid} — confirm. If SSLv3/TLSv1 "
                          "accepted, POODLE / BEAST / Lucky13 depending on cipher set. "
                          "sslscan {host_ip}:{port.portid} for the full cipher matrix.")))

    # Actively probe whether legacy protocols are still accepted.
    for name, protocol_const, cwes, sev in _LEGACY_PROTOCOLS:
        if protocol_const is None:
            continue   # this Python/OpenSSL build can't even offer it
        if _accepts_protocol(host_ip, port.portid, protocol_const):
            findings.append(_mk(
                host_ip, port, "tls-proto", sev,
                f"Server accepts legacy {name}", cwes,
                f"A {name} handshake succeeded.",
                f"Disable {name} on this service; require TLS 1.2+.",
                depth_tier="t1",
                exploit_note=(f"testssl.sh -p -U {host_ip}:{port.portid} — confirm the "
                              f"{name}-only handshake and enumerate the ciphersuites the "
                              "server offers there. Chain to CVE-2014-3566 (POODLE-SSLv3) "
                              "or the appropriate downgrade attack for the protocol.")))
    return findings


def _accepts_protocol(host_ip: str, portid: int, version) -> bool:
    """True only if the server completes a handshake at EXACTLY `version`.

    Pins min==max to that TLSVersion so OpenSSL cannot negotiate up to a modern
    version and report a false legacy accept. If the local OpenSSL build refuses
    to offer the old version at all (ValueError) that is a clean False, not a
    legacy accept."""
    if version is None:
        return False
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Pinning min==max to SSLv3/TLSv1/TLSv1.1 makes Python emit a
        # DeprecationWarning. Negotiating an obsolete version is the POINT here -
        # it is how we detect a server that still accepts one - so the warning is
        # Python objecting to intentional behaviour. Suppress it at exactly this
        # assignment; anything else deprecated still warns normally.
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore", message=r"ssl\.TLSVersion\.\w+ is deprecated",
                category=DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
        # Modern OpenSSL disables legacy ciphers by default (SECLEVEL 2), which
        # would fail the handshake even against a server that DOES speak the old
        # version - a false negative. Lower the security level so those ciphers
        # are offered; best-effort (some builds reject the directive).
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with socket.create_connection((host_ip, portid), timeout=proxy.scaled(_TIMEOUT)) as raw:
            with ctx.wrap_socket(raw, server_hostname=host_ip):
                return True
    except (OSError, ssl.SSLError, ValueError, AttributeError):
        return False


# --- orchestration --------------------------------------------------------------

def probe_port(host_ip: str, port: Port,
               known_names: list[str] | None = None) -> list[Vuln]:
    if not port.is_open:
        return []
    findings: list[Vuln] = []
    if _is_http(port):
        findings.extend(http_findings(host_ip, port))
    if _is_tls(port):
        findings.extend(tls_findings(host_ip, port, known_names=known_names))
    return findings


def probe_host(host: Host) -> int:
    """Run HTTP/TLS probes over a host's open ports, appending Vulns in place.

    Returns the number of new findings added. Deduped against existing vulns by
    Vuln.key so re-runs are idempotent.
    """
    from ..core.known_hostnames import hostnames_for
    known_names = hostnames_for(host, only_fqdn=True)
    existing = {v.key for v in host.vulns}
    added = 0
    for port in host.open_ports:
        for vuln in probe_port(host.ip, port, known_names=known_names):
            if vuln.key in existing:
                continue
            existing.add(vuln.key)
            host.vulns.append(vuln)
            added += 1
    return added
