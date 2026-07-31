"""Fold on-target local-enum output back into the workbook.

The `ingest` phase parses the text a tester brings back from running the bundled
recce-enum.sh (Linux) or recce-enum.ps1 (Windows) on a compromised host, and
turns its `[!]` findings into Priv-Esc rows for the matching host. No network,
no tools - just text parsing of output recce itself produced, so it stays
airgapped-safe.

Both scripts share one line grammar:
    recce-enum  host=<name>  user=<u>  <date>   <- banner (identifies the tool)
    ==== Section title ====                      <- section header
    [!] a finding worth attention                <- a finding (what we harvest)
The 'How to exploit' reference section is skipped so its guidance lines are
never mistaken for findings.
"""

from __future__ import annotations

import re

from .models import Port, Vuln

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_SEC = re.compile(r"^=+\s*(.*?)\s*=+$")
_FIND = re.compile(r"^\[!\]\s+(.*\S)\s*$")
_BANNER = re.compile(r"recce-enum\b.*?host=(\S+)(?:.*?user=(\S+))?", re.I)

# Strong per-OS markers so we can label the host even when the tester didn't
# pass --os. Counted across the whole loot; the higher count wins.
_WIN_MARKERS = ("seimpersonate", "alwaysinstallelevated", "whoami /priv",
                "computername", "c:\\windows", "unquoted service", "printspoofer",
                "ntlm", "hklm\\", "named pipe")
_LINUX_MARKERS = ("/etc/passwd", "/etc/shadow", "suid", "sudo", "uid=",
                  "gtfobins", "ld_preload", "docker", "/etc/sudoers", "capability")

# Map a finding's section header to the short Priv-Esc "Category" tag.
# New themed sections first so they win over generic needles (e.g. a "Persistence
# footholds (writable ...)" header is persistence, not "writable").
_SECTION_CATEGORY = [
    ("lateral", "lateral"), ("pivot", "lateral"),
    ("persistence", "persistence"),
    ("restricted", "escape"), ("escape", "escape"),
    ("sudo", "sudo"), ("suid", "suid"), ("capab", "suid"),
    ("kernel", "kernel"), ("system", "kernel"),
    ("cron", "cron"), ("timer", "cron"),
    ("service", "service"), ("process", "service"),
    ("writable", "writable"), ("path", "writable"),
    ("container", "container"), ("docker", "container"),
    ("credential", "creds"), ("password", "creds"), ("ssh", "creds"),
    ("network", "network"), ("nfs", "network"),
    ("privilege", "token"), ("token", "token"), ("context", "token"),
    ("alwaysinstall", "installer"), ("autorun", "autorun"),
    ("harden", "hardening"), ("av", "av"), ("pipe", "ipc"), ("ifeo", "ipc"),
    ("software", "software"),
]


def _categorize(section: str) -> str:
    low = (section or "").lower()
    for needle, tag in _SECTION_CATEGORY:
        if needle in low:
            return tag
    return "local"


def _detect_os(text: str) -> str:
    low = text.lower()
    win = sum(low.count(m) for m in _WIN_MARKERS)
    lin = sum(low.count(m) for m in _LINUX_MARKERS)
    if win > lin:
        return "windows"
    if lin > win:
        return "linux"
    return ""


def parse_loot(text: str) -> dict:
    """Parse recce-enum.sh/.ps1 output. Returns:
        {"is_recce": bool, "hostname": str, "os": "linux"|"windows"|"",
         "findings": [{"section": str, "category": str, "text": str}]}
    Duplicate findings (same section+text) are collapsed.
    """
    hostname = ""
    is_recce = False
    section = ""
    in_howto = False
    seen: set[tuple[str, str]] = set()
    findings: list[dict] = []
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).strip()
        if not line:
            continue
        b = _BANNER.search(line)
        if b:
            is_recce = True
            if not hostname and b.group(1):
                hostname = b.group(1)
            continue
        m = _SEC.match(line)
        if m:
            section = m.group(1).strip()
            in_howto = "how to exploit" in section.lower()
            continue
        if in_howto:
            continue
        fm = _FIND.match(line)
        if fm:
            text_ = fm.group(1).strip()
            key = (section, text_)
            if key in seen:
                continue
            seen.add(key)
            findings.append({"section": section, "category": _categorize(section),
                             "text": text_})
    return {"is_recce": is_recce, "hostname": hostname,
            "os": _detect_os(text), "findings": findings}


def extract_defenses(text: str) -> list[str]:
    """Pull AV/EDR products and key defensive-posture signals out of recce-enum
    output (mainly recce-enum.ps1). Detection only - this exists so the tester
    KNOWS what's watching a host, not to evade it. Returns short labels, e.g.
    'EDR/AV: CSFalcon (process)', 'Defender RTP=True', 'Sysmon present (logging)'."""
    out: list[str] = []
    seen: set[str] = set()

    def add(s: str) -> None:
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    for raw in text.splitlines():
        line = _ANSI.sub("", raw).strip()
        if not line:
            continue
        m = re.search(r"\bAV product:\s*(.+)", line, re.I)
        if m:
            add(f"AV: {m.group(1).strip()}")
        m = re.search(r"EDR/AV (process|service):\s*(.+)", line, re.I)
        if m:
            add(f"EDR/AV: {m.group(2).strip()} ({m.group(1).lower()})")
        m = re.search(r"Defender:\s*RealTime=(\w+)\s+Tamper=(\w+)", line, re.I)
        if m:
            add(f"Defender RTP={m.group(1)} Tamper={m.group(2)}")
        if re.search(r"\bSysmon\b.*present", line, re.I):
            add("Sysmon present (logging)")
        if re.search(r"RunAsPPL\)?\s*=\s*1", line):
            add("LSASS protected (RunAsPPL)")
        if re.search(r"AppLocker policy present", line, re.I):
            add("AppLocker enforced")
        if re.search(r"ScriptBlock(Logging)?\s*=\s*1", line, re.I):
            add("PS script-block logging on")
        if re.search(r"Credential/Device Guard running services:\s*\S", line, re.I):
            add("Credential/Device Guard on")
    return out


def to_local_findings(parsed: dict, source: str) -> list[dict]:
    """Shape parsed findings into the dicts stored on Host.local_findings."""
    return [{"category": f["category"], "vector": f["text"],
             "section": f["section"], "source": source}
            for f in parsed["findings"]]


# High-signal on-target findings worth promoting to first-class Vulnerabilities
# (so they count toward severity totals and get a write-up), not just a Priv-Esc
# row. Each: (regex over the finding text, severity, cwes, short title, remediation).
# These are confirmed local observations of an exploitable misconfiguration -
# deliberately a curated shortlist; weaker signals stay Priv-Esc-only.
_PROMOTE = [
    (r"/etc/passwd is writable", "critical", ["CWE-732"],
     "Writable /etc/passwd (add a UID 0 user)",
     "Restrict /etc/passwd to root:root 0644."),
    (r"/etc/shadow is writable", "critical", ["CWE-732"],
     "Writable /etc/shadow", "Restrict /etc/shadow to root:shadow 0640."),
    (r"/etc/shadow is readable", "high", ["CWE-732"],
     "Readable /etc/shadow (offline hash cracking)",
     "Restrict /etc/shadow to root:shadow 0640."),
    (r"/etc/sudoers is writable", "critical", ["CWE-732"],
     "Writable /etc/sudoers", "Restrict sudoers to root:root 0440."),
    (r"nopasswd|sudo grants \(all\)", "high", ["CWE-250", "CWE-732"],
     "Sudo misconfiguration -> root (NOPASSWD / ALL)",
     "Remove NOPASSWD/ALL grants; scope sudo to specific commands."),
    (r"ld_preload", "high", ["CWE-426"],
     "LD_PRELOAD preserved in sudo env -> library injection to root",
     "Remove env_keep+=LD_PRELOAD from sudoers."),
    (r"suid .*gtfobins|gtfobins escalation", "high", ["CWE-269"],
     "SUID GTFOBins escalation candidate",
     "Remove the SUID bit or replace the binary."),
    (r"suid path-hijack|suid env-injection|suid reads a writable", "high", ["CWE-426", "CWE-269"],
     "Custom SUID binary -> hijackable (PATH / env / writable input)",
     "Use absolute paths + sanitized env in the SUID binary; remove the SUID bit."),
    (r"\bcapability\b.*privesc|cap_setuid|cap_sys_admin", "high", ["CWE-269"],
     "Dangerous file capability -> privesc",
     "Strip the capability (setcap -r) or restrict the binary."),
    (r"docker\.sock|docker group|in the 'docker' group", "high", ["CWE-250"],
     "Docker access -> trivial host root",
     "Remove the user from the docker group; protect the socket."),
    (r"lxd/lxc group|'lxd|'lxc", "high", ["CWE-250"],
     "lxd/lxc group -> root via privileged container",
     "Remove the user from the lxd/lxc group."),
    (r"'disk' group", "high", ["CWE-732"],
     "disk group -> raw device read (/etc/shadow)",
     "Remove the user from the disk group."),
    (r"pwnkit|cve-2021-4034", "critical", ["CWE-269"],
     "PwnKit (CVE-2021-4034, pkexec) local root",
     "Patch polkit/pkexec (fixed Jan-2022)."),
    (r"dirty pipe|cve-2022-0847", "high", ["CWE-269"],
     "Dirty Pipe (CVE-2022-0847) kernel LPE",
     "Patch the kernel (fixed 5.16.11/5.15.25/5.10.102)."),
    (r"writable cron|writable .*timer|world/.*writable cron", "high", ["CWE-732"],
     "Writable cron/timer script -> root code exec",
     "Fix ownership/permissions on the scheduled job."),
    (r"writable service unit|runs a writable binary", "high", ["CWE-732"],
     "Writable service/binary run as root",
     "Restrict write access on the unit/binary."),
    (r"no_root_squash", "high", ["CWE-269"],
     "NFS no_root_squash -> remote root via SUID",
     "Set root_squash on the NFS export."),
    (r"writable dir in path", "medium", ["CWE-426"],
     "Writable directory in PATH (binary planting)",
     "Remove the writable directory from PATH."),
    # Windows
    (r"seimpersonate|seassignprimarytoken", "high", ["CWE-269", "CWE-250"],
     "SeImpersonate/SeAssignPrimaryToken -> Potato -> SYSTEM",
     "Remove the privilege from the service account where feasible."),
    (r"alwaysinstallelevated", "high", ["CWE-269"],
     "AlwaysInstallElevated -> malicious MSI as SYSTEM",
     "Disable the AlwaysInstallElevated policy (HKLM+HKCU)."),
    (r"unquoted service path", "high", ["CWE-428"],
     "Unquoted service path with writable parent",
     "Quote the ImagePath; restrict write on the parent directory."),
    (r"writable service binary exploitable|writable service registry key exploitable",
     "high", ["CWE-732"],
     "Writable service binary/registry -> SYSTEM",
     "Restrict write access on the service binary and its registry key."),
    (r"dll hijack|writable directory in system path|writable app dir",
     "high", ["CWE-427"],
     "DLL hijack (writable dir on a privileged process's search path)",
     "Restrict write access on the directory; use fully-qualified DLL loads."),
    (r"sebackup|serestore|setakeownership|seloaddriver|sedebug", "high", ["CWE-269"],
     "Dangerous Windows privilege held -> SYSTEM",
     "Remove the privilege from the account."),
    (r"cpassword|gpp password", "high", ["CWE-256", "CWE-260"],
     "GPP cpassword (decryptable domain credential)",
     "Remove the GPP; rotate the exposed credential."),
    (r"cleartext|stored credential|autologon.*password", "high", ["CWE-256"],
     "Stored/cleartext credential on host",
     "Remove the stored secret; rotate it."),
    # Lateral movement / AD (confirmed local observations of a reusable path).
    (r"unconstrained-delegation", "high", ["CWE-266"],
     "Unconstrained delegation host (TGT capture)",
     "Remove unconstrained delegation; prefer constrained/RBCD."),
    (r"kerberoastable", "medium", ["CWE-262", "CWE-522"],
     "Kerberoastable service account (SPN set)",
     "Use gMSA / long managed passwords; minimise SPNs."),
    (r"as-rep roastable", "medium", ["CWE-262"],
     "AS-REP roastable account (no Kerberos pre-auth)",
     "Require Kerberos pre-authentication on the account."),
    (r"ssh-agent socket live", "medium", ["CWE-522"],
     "Live ssh-agent -> onward auth reuse",
     "Avoid agent forwarding to untrusted hosts."),
    (r"kubernetes service-account token|kubeconfig readable", "high", ["CWE-522"],
     "Kubernetes credentials on host (cluster pivot)",
     "Scope service-account RBAC; protect kubeconfig files."),
    # Persistence / login-hook footholds.
    (r"writable ~/.ssh/authorized_keys|writable login-time|writable powershell profile|"
     r"writable hkcu com|accessibility hijack", "medium", ["CWE-732"],
     "Writable auto-exec hook (persistence / escalation)",
     "Fix ownership/permissions on the auto-run hook."),
]
_PROMOTE = [(re.compile(rx, re.I), sev, cwes, title, rem)
            for rx, sev, cwes, title, rem in _PROMOTE]


# --- per-service enumeration output (recce/scripts/recce-service.sh) -----------
# The service scripts print one header per target - "==== SMB  ->  10.0.0.5:445 ===="
# - then [!] findings under it. We fold those into the datastore as confirmed
# service-enum vulns on that host:port. Advisory-phrased prompts ("Test/verify X")
# are kept as low-confidence 'potential' so they don't inflate the findings report.
_SVC_HDR = re.compile(r"^=+\s*(\S+)\s+->\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\s*=+$")
_SVC_SEV = [
    (r"eternalblue|ms17-010|ms08-067|smbghost|bluekeep|backdoor|unauthenticated .*rce|"
     r"remote root|-> rce", "critical"),
    (r"anonymous .*(login|ftp)|null session|unauth|no auth|without auth|"
     r"signing not required|cpassword|zone transfer allowed|community string works|"
     r"is readable|is writable|writable|world-readable|open recursion|"
     r"unauthenticated", "high"),
    (r"cleartext|without starttls|no starttls|weak|sslv|tls1\.0|poodle|"
     r"dangerous http methods|nla off", "medium"),
]


def _svc_sev(text: str) -> str:
    low = text.lower()
    for rx, sev in _SVC_SEV:
        if re.search(rx, low):
            return sev
    return "medium"   # a flagged [!] line is worth attention by default


def _svc_conf(text: str) -> str:
    """Observed finding vs an advisory prompt. 'Test/verify/check X' phrasing is
    kept 'potential' (off the default findings report); everything else is a real
    observation (empty confidence == real)."""
    if re.match(r"(test |verify |check |consider |still test)", text.strip().lower()):
        return "potential"
    return ""


def parse_service_output(text: str) -> dict:
    """Parse recce-service.sh output. Returns
        {"is_service": bool, "findings": [{ip, port, service, text, ...}]}
    Harvests the [!] lines under each "==== NAME -> ip:port ====" header; sub-section
    headers keep the current host:port. Duplicates (ip, port, text) collapse."""
    ip = ""
    port = 0
    service = ""
    is_service = False
    seen: set[tuple] = set()
    findings: list[dict] = []
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).strip()
        if not line:
            continue
        h = _SVC_HDR.match(line)
        if h:
            is_service = True
            service, ip, port = h.group(1).lower(), h.group(2), int(h.group(3))
            continue
        fm = _FIND.match(line)
        if fm and ip:
            t = fm.group(1).strip()
            key = (ip, port, t)
            if key in seen:
                continue
            seen.add(key)
            findings.append({"ip": ip, "port": port, "service": service, "text": t})
    return {"is_service": is_service, "findings": findings}


def service_findings_to_vulns(parsed: dict) -> list[Vuln]:
    """Turn parsed per-service findings into confirmed service-enum Vulns."""
    out: list[Vuln] = []
    for f in parsed["findings"]:
        out.append(Vuln(
            ip=f["ip"], port=f["port"], protocol="tcp",
            script_id=f"service-{f['service']}", state="finding",
            title=f["text"][:120], severity=_svc_sev(f["text"]),
            source="service-enum", confidence=_svc_conf(f["text"]),
            output=f"recce-service.sh ({f['service']}): {f['text']}"))
    return out


# --- listening-service backfill (on-target ground truth) ------------------------
# recce-enum.sh/.ps1 emit one machine-parseable line per listener, e.g.
#   LISTEN proto=tcp addr=0.0.0.0 port=80 pid=1337 proc=nginx bin=/usr/sbin/nginx
#   LISTEN proto=tcp addr=0.0.0.0 port=5985 pid=1200 proc=svchost svc=WinRM bin=C:\...\svchost.exe
# The on-target view sees things the network scan can't: the exact backing binary,
# the owning process/service, and loopback-only listeners a remote scan never
# reaches. We fold these onto the host's ports with detect_source="local" so the
# sheet shows where the fact came from.
_LISTEN = re.compile(
    r"^LISTEN\s+proto=(?P<proto>\w+)\s+addr=(?P<addr>\S*)\s+port=(?P<port>\d+)\s+"
    r"pid=(?P<pid>\d*)\s+proc=(?P<proc>\S*)(?:\s+svc=(?P<svc>\S*))?\s+bin=(?P<bin>.*?)\s*$")

_LOOPBACK = ("127.", "::1", "localhost", "0:0:0:0:0:0:0:1")


def _is_loopback(addr: str) -> bool:
    a = (addr or "").strip().lower().strip("[]")
    return a.startswith("127.") or a in _LOOPBACK


def parse_listeners(text: str) -> list[dict]:
    """Parse the 'LISTEN proto=... port=... proc=... bin=...' lines the on-target
    scripts emit. Returns a de-duplicated list of
        {proto, addr, port(int), pid, proc, svc, bin, loopback(bool)}
    (empty when the loot has no such section - older loot just skips it)."""
    out: list[dict] = []
    seen: set[tuple] = set()
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).strip()
        m = _LISTEN.match(line)
        if not m:
            continue
        d = m.groupdict()
        proto = d["proto"].lower()
        port = int(d["port"])
        addr = d["addr"]
        key = (proto, port, addr)
        if key in seen:
            continue
        seen.add(key)
        out.append({"proto": proto, "addr": addr, "port": port,
                    "pid": d["pid"] or "", "proc": d["proc"] or "",
                    "svc": (d["svc"] or "").strip(), "bin": (d["bin"] or "").strip(),
                    "loopback": _is_loopback(addr)})
    return out


def backfill_ports(host, listeners: list[dict]) -> tuple[int, int]:
    """Fold on-target listener facts onto host.ports. For a port the scan already
    has, fill the backing binary / owning service without ever overwriting nmap's
    service name. For a listener the scan never saw (typically loopback-only), add
    a new open Port tagged detect_source="local". Returns (added, enriched)."""
    idx = {(p.protocol, p.portid): p for p in host.ports}
    added = enriched = 0
    for ls in listeners:
        if ls["port"] <= 0:
            continue
        cur = idx.get((ls["proto"], ls["port"]))
        # A svc name (Windows service) is the best "service" label; else the proc.
        label = ls["svc"] or ls["proc"]
        note = "on-target: loopback-only" if ls["loopback"] else "on-target listener"
        if cur is not None:
            touched = False
            if ls["bin"] and not cur.binary:
                cur.binary = ls["bin"]
                touched = True
            if ls["svc"] and ls["svc"].lower() not in cur.extrainfo.lower():
                cur.extrainfo = (f"{cur.extrainfo}; svc={ls['svc']}".lstrip("; ")
                                 if cur.extrainfo else f"svc={ls['svc']}")
                touched = True
            # Only name the service if the scan left it blank/unknown - nmap wins.
            if label and cur.service in ("", "unknown", "tcpwrapped"):
                cur.service = label
                if cur.detect_source != "nmap":
                    cur.detect_source = "local"
                touched = True
            if touched:
                enriched += 1
        else:
            host.ports.append(Port(
                portid=ls["port"], protocol=ls["proto"], state="open",
                service=label or "unknown", binary=ls["bin"],
                detect_source="local", extrainfo=note))
            idx[(ls["proto"], ls["port"])] = host.ports[-1]
            added += 1
    return added, enriched


import ipaddress as _ipaddr

_NET_IFACE = re.compile(r"^NET-IFACE\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})", re.I)
_NET_ROUTE = re.compile(r"^NET-ROUTE\s+(\S+)(?:\s+via\s+(\S+))?(?:\s+dev\s+(\S+))?", re.I)
_NET_NEIGH = re.compile(r"^NET-NEIGH\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+(\S+))?", re.I)
_NET_PEER = re.compile(r"^NET-PEER\s+(\d{1,3}(?:\.\d{1,3}){3}):(\d+)(?:\s+(\S+))?", re.I)


def _routable(ip: str) -> bool:
    try:
        a = _ipaddr.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)


def parse_topology(text: str) -> dict:
    """Parse the machine-readable NETWORK block an on-target enum emits (recce-enum or
    the Sköll linpriv/winpriv enum) into observed topology:

        NET-IFACE <name> <ip>/<prefix>          this box's own interface (-> subnet)
        NET-ROUTE <dest|default> [via gw] [dev]  a route it holds
        NET-NEIGH <ip> [mac]                     an ARP neighbour it actually talked to
        NET-PEER  <ip>:<port> [state]            a live/known connection to another host

    Returns {interfaces, routes, neighbors, peers} (empty dict when the loot has no
    such block). ARP neighbours and peers are GROUND TRUTH for host-to-host
    reachability — the box demonstrably reached those addresses."""
    ifaces, routes, neigh, peers = [], [], [], []
    nseen, pseen = set(), set()
    for raw in text.splitlines():
        line = _ANSI.sub("", raw).strip()
        m = _NET_IFACE.match(line)
        if m:
            name, ip, prefix = m.group(1), m.group(2), int(m.group(3))
            if not _routable(ip):
                continue
            try:
                subnet = str(_ipaddr.ip_network(f"{ip}/{prefix}", strict=False))
            except ValueError:
                subnet = ""
            ifaces.append({"name": name, "ip": ip, "prefix": prefix, "subnet": subnet})
            continue
        m = _NET_ROUTE.match(line)
        if m:
            routes.append({"dest": m.group(1), "gw": m.group(2) or "",
                           "iface": m.group(3) or ""})
            continue
        m = _NET_NEIGH.match(line)
        if m:
            ip = m.group(1)
            if _routable(ip) and ip not in nseen:
                nseen.add(ip)
                neigh.append(ip)
            continue
        m = _NET_PEER.match(line)
        if m:
            ip, port = m.group(1), int(m.group(2))
            if _routable(ip) and (ip, port) not in pseen:
                pseen.add((ip, port))
                peers.append({"ip": ip, "port": port, "state": m.group(3) or ""})
    out = {}
    if ifaces:
        out["interfaces"] = ifaces
    if routes:
        out["routes"] = routes
    if neigh:
        out["neighbors"] = neigh
    if peers:
        out["peers"] = peers
    return out


def promote_to_vulns(ip: str, findings: list[dict]) -> list[Vuln]:
    """Turn the high-signal on-target findings into first-class Vulns (confirmed
    local observations), so they show up in severity totals and get write-ups.
    Findings that don't match the curated shortlist stay Priv-Esc-only. Each
    distinct (title) is emitted once per host."""
    out: list[Vuln] = []
    seen: set[str] = set()
    for f in findings:
        text = f.get("vector") or f.get("text") or ""
        for rx, sev, cwes, title, rem in _PROMOTE:
            if rx.search(text) and title not in seen:
                seen.add(title)
                out.append(Vuln(
                    ip=ip, port=None, protocol="tcp", script_id="local-enum",
                    state="finding", title=title, severity=sev, source="local",
                    confidence="confirmed", cwes=list(cwes),
                    output=f"On-target enum: {text}", remediation=rem))
                break
    return out
