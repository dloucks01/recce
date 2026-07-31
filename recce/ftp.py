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
Airgapped, stdlib only (the write proof uses `ftplib`). Safety posture: see SECURITY.md.
"""
from __future__ import annotations

import re
import socket

from .models import Host, Port

_DEFAULT_PORT = 21
_TIMEOUT = 6.0
_PROBE_MARK = "recce_ftp_probe"

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
]


def is_ftp(port: Port) -> bool:
    if port.state != "open":
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
            _cmd(s, "QUIT", timeout)
            return {"ip": ip, "port": port, "banner": banner, "anonymous": anon,
                    "auth_tls": auth_tls, "syst": syst}
    except OSError:
        return None


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
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


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

def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "ftp", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


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
                    out.append(_finding(
                        sev, title, tgt, f"Banner: {banner}. {detail}", "metasploit",
                        cmd, "Upgrade to a vendor-clean build immediately; the current "
                        "one is compromised/vulnerable.", cwes, kind=kind))
                    break
            if pr.get("anonymous"):
                out.append(_finding(
                    "high", "Anonymous FTP login allowed", tgt,
                    "Anonymous login permitted: the server returned a 230 to "
                    "anonymous/PASS during recce's probe. It grants an unauthenticated "
                    "session to the FTP root.",
                    "ftp / nmap",
                    "ftp <ip>   # user 'anonymous', any password; or nmap --script "
                    "ftp-anon -p21 <ip>",
                    "Disable anonymous access unless the content is deliberately public "
                    "and read-only.", ["CWE-306", "CWE-287"], kind="anon_ftp"))
                if pr.get("auth_tls") is False:
                    out.append(_finding(
                        "medium", "FTP authentication is cleartext (no AUTH TLS)", tgt,
                        "The server advertises no AUTH TLS/FTPS in FEAT, so credentials "
                        "and file transfers cross the network unencrypted and are "
                        "sniffable.", "wireshark / tcpdump",
                        "tcpdump -i <iface> 'tcp port 21'   # USER/PASS appear in clear",
                        "Require FTPS (explicit AUTH TLS) or replace FTP with SFTP/SCP.",
                        ["CWE-319"], kind="cleartext_ftp"))
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
        "from any web root.", ["CWE-732", "CWE-434"], kind="writable_ftp")


# --- proof screenshot -----------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
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
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": credfree_runbook(t["ip"], t["port"]),
                 "credentialed": cred_runbook(t["ip"], t["port"], creds)}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
