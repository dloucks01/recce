"""Credentialed (authenticated) enumeration - the `credenum` phase.

Everything the *un*authenticated nmap/NSE passes can't see once you have valid
creds: authenticated SMB (shares/users/sessions/logged-on/password-policy and,
crucially, *local-admin access*), Kerberos roasting with real hashes, and
host-level Linux checks over SSH (sudo, SUID, kernel).

All of it is **optional and tool-gated**, exactly like searchsploit: recce shells
out to tools that already ship on Kali - `netexec`/`nxc` (or crackmapexec), the
`impacket` scripts, and `ssh` - and skips cleanly (with a logged note) when a
tool isn't present. No Python packages are required at runtime; the parsers are
pure-stdlib and independently testable.

Results fold into the normal model: accounts land in Users & Accounts, roastable
accounts flow into AD Quick Wins, and access/weakness findings become Vulns.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from .models import Account, Host, Script, Vuln

_TIMEOUT = 180   # per external-tool invocation (seconds)


# --- tool detection -------------------------------------------------------------

def _which_any(names: list[str]) -> str | None:
    for n in names:
        if shutil.which(n):
            return n
    return None


def smb_tool() -> str | None:
    """netexec is the modern name; fall back to crackmapexec."""
    return _which_any(["nxc", "netexec", "crackmapexec", "cme"])


def impacket_tool(script: str) -> str | None:
    """Kali installs impacket scripts as e.g. `impacket-GetUserSPNs` and also as
    `GetUserSPNs.py`; accept either."""
    return _which_any([f"impacket-{script}", f"{script}.py", script])


def ssh_tool() -> str | None:
    return shutil.which("ssh")


def sshpass_tool() -> str | None:
    return shutil.which("sshpass")


def available_tools() -> dict[str, str | None]:
    return {
        "netexec": smb_tool(),
        "impacket-GetUserSPNs": impacket_tool("GetUserSPNs"),
        "impacket-GetNPUsers": impacket_tool("GetNPUsers"),
        "impacket-secretsdump": impacket_tool("secretsdump"),
        "ssh": ssh_tool(),
        "sshpass": sshpass_tool(),
    }


def _run(cmd: list[str], timeout: int = _TIMEOUT) -> tuple[str, str | None]:
    """Run a tool; return (combined output, error-or-None). Never raises."""
    from .util import run_tool
    return run_tool(cmd, timeout)


# --- netexec / crackmapexec SMB output ------------------------------------------

_NXC_LINE = re.compile(r"^\s*(\w+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(.*)$")


def parse_nxc_smb(output: str) -> dict:
    """Parse `nxc smb ... --shares --users --sessions --loggedon-users --pass-pol`.

    Tolerant of version differences: keys off the message text, not columns.
    """
    result: dict = {"admin": False, "auth": False, "host_info": "", "shares": [],
                    "users": [], "sessions": [], "loggedon": [], "passpol": {}}
    section = None
    for raw in output.splitlines():
        m = _NXC_LINE.match(raw)
        if not m:
            continue
        msg = m.group(5).rstrip()
        low = msg.lower()

        # Section switches come first - their banners can start with [+] or [*].
        if "enumerated shares" in low:
            section = "shares"; continue
        if "enumerated domain user" in low or "enumerated users" in low:
            section = "users"; continue
        if "password info" in low or "dumping password" in low:
            section = "passpol"; continue
        if "enumerated sessions" in low or ("sessions" in low and msg.startswith("[*]")):
            section = "sessions"; continue
        if "logged" in low and msg.startswith(("[*]", "[+]")):
            section = "loggedon"; continue
        # Auth / admin marker: netexec/cme print the successful auth as
        # "[+] domain\user:pass" and flag LOCAL ADMIN on that same line as
        # "(Pwn3d!)" - and nowhere else. Key off that token alone. A loose
        # "(admin)" substring also matched share/session/host-info text (a DC's
        # output is share/session-heavy), flipping plain domain users to admin and
        # producing false "Local admin confirmed" findings on domain controllers.
        if msg.startswith("[+]"):
            result["auth"] = True
            if "pwn3d" in low:
                result["admin"] = True
            continue
        if msg.startswith("[*]") and ("windows" in low or "unix" in low
                                      or "build" in low):
            result["host_info"] = msg[3:].strip()
            section = None
            continue
        if msg.startswith(("[-]", "[!]")):
            continue

        if section == "passpol":
            pm = re.match(r"(minimum password length|password history length|"
                          r"account lockout threshold|maximum password age|"
                          r"minimum password age|account lockout duration)\s*:?\s*(.+)",
                          low)
            if pm:
                result["passpol"][pm.group(1)] = pm.group(2).strip()
            continue
        if section == "shares":
            if low.startswith(("share", "-----")) or not msg.strip():
                continue
            parts = msg.split()
            perms = next((p for p in parts[1:]
                          if re.fullmatch(r"(READ|WRITE|,)+", p, re.I)), "")
            result["shares"].append({"name": parts[0], "perms": perms})
            continue
        if section == "users":
            um = re.search(r"([\w.-]+)\\([\w.$-]+)", msg)
            if um:
                result["users"].append({"domain": um.group(1), "name": um.group(2)})
            continue
        if section in ("sessions", "loggedon"):
            result[section].append(msg.strip())
    return result


# --- impacket roasting ----------------------------------------------------------

_SPN_HASH = re.compile(r"\$krb5tgs\$\S+")
_ASREP_HASH = re.compile(r"\$krb5asrep\$\d+\$([^@]+)@\S+")


def parse_getuserspns(output: str) -> list[dict]:
    """Kerberoast results: SPN table rows + any `$krb5tgs$` hashes (with -request)."""
    accounts: list[dict] = []
    by_name: dict[str, dict] = {}
    for raw in output.splitlines():
        line = raw.rstrip()
        # Table row: "SPN  Name  MemberOf  PasswordLastSet ..."
        tm = re.match(r"^(\S+/\S+)\s+([\w.$-]+)\s+", line)
        if tm and "ServicePrincipalName" not in line:
            name = tm.group(2)
            rec = by_name.setdefault(name, {"name": name, "spn": tm.group(1),
                                            "hash": ""})
            accounts.append(rec) if rec not in accounts else None
        hm = _SPN_HASH.search(line)
        if hm:
            # Hash line contains the account: $krb5tgs$23$*name$REALM$spn*...
            nm = re.search(r"\$krb5tgs\$\d+\$\*([^$]+)\$", line)
            name = nm.group(1) if nm else ""
            rec = by_name.setdefault(name, {"name": name, "spn": "", "hash": ""})
            rec["hash"] = hm.group(0)
            if rec not in accounts:
                accounts.append(rec)
    return accounts


def parse_getnpusers(output: str) -> list[dict]:
    """AS-REP roast results: `$krb5asrep$` lines -> accounts with hashes."""
    out: list[dict] = []
    seen: set[str] = set()
    for raw in output.splitlines():
        m = _ASREP_HASH.search(raw)
        if m:
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                out.append({"name": name, "hash": m.group(0).strip()})
    return out


# NTLM hash rows: user:rid:lmhash:nthash::: (secretsdump SAM/NTDS output).
_HASH_ROW = re.compile(r"^([^:]+):(\d+):([0-9a-f]{32}):([0-9a-f]{32}):::", re.I)


def parse_secretsdump(output: str) -> list[dict]:
    """Extract user:rid:lm:nt hash rows from secretsdump output."""
    out: list[dict] = []
    for raw in output.splitlines():
        m = _HASH_ROW.match(raw.strip())
        if m:
            out.append({"name": m.group(1), "rid": m.group(2),
                        "nt": m.group(4)})
    return out


# --- SSH local checks -----------------------------------------------------------

_SSH_SCRIPT = (
    'echo "===ID==="; id; '
    'echo "===SUDO==="; sudo -n -l 2>/dev/null; '
    'echo "===UNAME==="; uname -a; '
    'echo "===OS==="; (cat /etc/os-release 2>/dev/null | head -2); '
    'echo "===SUID==="; find / -perm -4000 -type f 2>/dev/null | head -40'
)


def parse_ssh_enum(output: str) -> dict:
    """Parse the section-delimited output of the SSH local-check one-liner."""
    facts: dict = {"id": "", "sudo": [], "kernel": "", "os": "", "suid": []}
    section = None
    for raw in output.splitlines():
        line = raw.rstrip()
        if line.startswith("===") and line.endswith("==="):
            section = line.strip("= ").lower()
            continue
        if not line:
            continue
        if section == "id":
            facts["id"] = facts["id"] or line
        elif section == "sudo":
            if "may run" in line.lower() or line.strip().startswith(("(", "/")):
                facts["sudo"].append(line.strip())
        elif section == "uname":
            facts["kernel"] = facts["kernel"] or line
        elif section == "os":
            facts["os"] = (facts["os"] + " " + line).strip()
        elif section == "suid":
            facts["suid"].append(line.strip())
    return facts


# --- orchestration: run the tools against a host and fold results in ------------

def _creds_ok(creds: dict | None) -> bool:
    return bool(creds and creds.get("username"))


def _smb_ports(host: Host) -> bool:
    return any(p.portid in (139, 445) for p in host.open_ports)


def _is_dc(host: Host) -> bool:
    return any("domain controller" in r.lower() for r in host.roles) or \
        any(p.portid in (88, 389, 636) for p in host.open_ports)


def _ssh_port(host: Host) -> bool:
    return any(p.portid == 22 or (p.service or "").lower() == "ssh"
               for p in host.open_ports)


def _nxc_cmd(tool: str, ip: str, creds: dict) -> list[str]:
    cmd = [tool, "smb", ip, "-u", creds["username"], "-p", creds.get("password", "")]
    if creds.get("domain"):
        cmd += ["-d", creds["domain"]]
    cmd += ["--shares", "--users", "--sessions", "--loggedon-users", "--pass-pol"]
    return cmd


def run_nxc_smb(ip: str, creds: dict) -> tuple[dict | None, str | None]:
    tool = smb_tool()
    if not tool:
        return None, None
    out, err = _run(_nxc_cmd(tool, ip, creds))
    if err:
        return None, err
    return parse_nxc_smb(out), None


def _fold_nxc(host: Host, data: dict, label: str = "supplied credentials",
              admin_only: bool = False) -> None:
    dom = (data.get("host_info") or "")
    # A successful authenticated session (or confirmed local admin) IS a foothold -
    # record it so the Access step auto-ticks and status/reports reflect it.
    if data.get("admin"):
        host.access_gained = True
        host.access_detail = f"SMB local admin (Pwn3d!) - {label}"
    elif data.get("auth") and not host.access_gained:
        host.access_gained = True
        host.access_detail = f"SMB authenticated - {label}"
    if not admin_only:            # the admin re-run only records reach, no re-fold
        for sh in data.get("shares", []):
            host.accounts.append(Account(ip=host.ip, source="netexec", kind="share",
                                         name=sh["name"], detail=sh.get("perms", "")))
        for u in data.get("users", []):
            host.accounts.append(Account(ip=host.ip, source="netexec", kind="user",
                                         name=u["name"], domain=u.get("domain", "")))
        for s in data.get("loggedon", []):
            host.accounts.append(Account(ip=host.ip, source="netexec", kind="session",
                                         name=s, detail="logged-on"))
    if data.get("admin"):
        # A low-priv "user account" holding admin is notable (over-privileged); the
        # privileged account holding admin is expected reach - both worth recording.
        host.vulns.append(Vuln(
            ip=host.ip, port=445, protocol="tcp",
            script_id=f"cred-smb-admin-{label.split()[0]}",
            state="VULNERABLE", title=f"Local admin confirmed - {label}",
            severity="high", source="cred", confidence="confirmed",
            cwes=["CWE-269"],
            output=f"netexec reported admin (Pwn3d!) on {host.ip} with the "
                   f"{label}. {dom}".strip(),
            remediation="Restrict local-admin rights; review credential exposure."))
    pol = data.get("passpol", {})
    thr = pol.get("account lockout threshold", "")
    if thr and thr.lower() in ("none", "0"):
        host.vulns.append(Vuln(
            ip=host.ip, port=445, protocol="tcp", script_id="cred-passpol",
            state="finding", title="No account lockout threshold (spray-friendly)",
            severity="medium", source="cred", cwes=["CWE-307"],
            output="; ".join(f"{k}: {v}" for k, v in pol.items()),
            remediation="Set an account lockout threshold to slow password spraying."))


def run_kerberoast(dc_ip: str, creds: dict) -> tuple[list[dict], str | None]:
    tool = impacket_tool("GetUserSPNs")
    if not tool or not creds.get("domain"):
        return [], None
    target = f"{creds['domain']}/{creds['username']}:{creds.get('password', '')}"
    out, err = _run([tool, target, "-dc-ip", dc_ip, "-request"])
    if err:
        return [], err
    return parse_getuserspns(out), None


def run_asrep(dc_ip: str, creds: dict) -> tuple[list[dict], str | None]:
    tool = impacket_tool("GetNPUsers")
    if not tool or not creds.get("domain"):
        return [], None
    target = f"{creds['domain']}/{creds['username']}:{creds.get('password', '')}"
    out, err = _run([tool, target, "-dc-ip", dc_ip, "-request", "-no-pass"])
    if err:
        return [], err
    return parse_getnpusers(out), None


def _fold_roast(host: Host, spns: list[dict], asreps: list[dict], domain: str) -> None:
    for a in spns:
        host.accounts.append(Account(
            ip=host.ip, source="impacket", kind="user", name=a["name"],
            domain=domain, detail="kerberoastable",
            attrs={"spn": a.get("spn", "-"), "hash": a.get("hash", "")}))
    for a in asreps:
        host.accounts.append(Account(
            ip=host.ip, source="impacket", kind="user", name=a["name"],
            domain=domain, detail="AS-REP roastable",
            attrs={"asrep_roastable": "yes", "hash": a.get("hash", "")}))


def run_secretsdump(ip: str, creds: dict) -> tuple[list[dict], str | None]:
    """Aggressive: dump SAM/LSA/NTDS hashes with impacket secretsdump (needs
    local-admin / DA)."""
    tool = impacket_tool("secretsdump")
    if not tool:
        return [], None
    dom = creds.get("domain", "") or "."
    target = f"{dom}/{creds['username']}:{creds.get('password', '')}@{ip}"
    out, err = _run([tool, target])
    if err:
        return [], err
    return parse_secretsdump(out), None


def _fold_secrets(host: Host, dumped: list[dict], domain: str) -> None:
    if not dumped:
        return
    for d in dumped:
        host.accounts.append(Account(
            ip=host.ip, source="secretsdump", kind="user", name=d["name"],
            domain=domain, rid=d.get("rid", ""), detail="NT hash recovered",
            attrs={"nt": d.get("nt", "")}))
    host.vulns.append(Vuln(
        ip=host.ip, port=445, protocol="tcp", script_id="cred-secretsdump",
        state="VULNERABLE", title=f"Credential hashes dumped ({len(dumped)} accounts)",
        severity="critical", source="cred", confidence="confirmed",
        cwes=["CWE-522"],
        output=f"secretsdump recovered {len(dumped)} NTLM hash(es) from {host.ip}",
        remediation="These credentials are compromised; rotate and investigate."))


def _ssh_cmd(ip: str, ssh: dict) -> list[str] | None:
    user = ssh.get("username")
    if not user:
        return None
    base = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10"]
    if ssh.get("key"):
        cmd = base + ["-i", ssh["key"], f"{user}@{ip}", _SSH_SCRIPT]
    elif ssh.get("password") and sshpass_tool():
        # BatchMode disables password prompts; drop it and let sshpass feed the pw.
        cmd = ["sshpass", "-p", ssh["password"], "ssh", "-o",
               "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10",
               f"{user}@{ip}", _SSH_SCRIPT]
    else:
        return None
    return cmd


def run_ssh_local(ip: str, ssh: dict) -> tuple[dict | None, str | None]:
    if not ssh_tool():
        return None, None
    cmd = _ssh_cmd(ip, ssh)
    if cmd is None:
        return None, None
    out, err = _run(cmd, timeout=60)
    if err:
        return None, err
    # _run folds stderr into `out`, and parse_ssh_enum always returns a (truthy)
    # fixed-key dict, so a failed auth ("Permission denied") or unreachable host
    # ("Connection refused") would otherwise be recorded as an SSH foothold
    # (access_gained + auth:True). The remote script emits `===ID===` as its first
    # marker, so its presence is proof the login actually succeeded and the enum ran.
    if "===ID===" not in out:
        return None, "ssh: auth failed / no shell (enum did not run)"
    return parse_ssh_enum(out), None


def _fold_ssh(host: Host, facts: dict) -> None:
    # Reaching here means the SSH credential authenticated and the local-enum ran -
    # that is a foothold on this host.
    host.access_gained = True
    host.access_detail = host.access_detail or "SSH credentialed access"
    summary = (f"id: {facts.get('id', '')}\nkernel: {facts.get('kernel', '')}\n"
               f"os: {facts.get('os', '')}").strip()
    if summary:
        host.host_scripts.append(Script(id="ssh-local-enum", output=summary))
    sudo = facts.get("sudo", [])
    if any("nopasswd" in s.lower() or "(all" in s.lower() for s in sudo):
        host.vulns.append(Vuln(
            ip=host.ip, port=22, protocol="tcp", script_id="ssh-sudo",
            state="finding", title="Sudo rights allow privilege escalation",
            severity="high", source="cred", cwes=["CWE-250", "CWE-269"],
            output="sudo -l:\n" + "\n".join(sudo),
            remediation="Review sudoers; remove NOPASSWD / overly broad rules."))
    suid = [s for s in facts.get("suid", [])
            if not re.search(r"/(sudo|mount|umount|passwd|su|ping|pkexec|"
                             r"newgrp|chsh|chfn|gpasswd)$", s)]
    if suid:
        host.vulns.append(Vuln(
            ip=host.ip, port=22, protocol="tcp", script_id="ssh-suid",
            state="finding", title="Unusual SUID binaries (check GTFOBins)",
            severity="medium", source="cred", cwes=["CWE-250"],
            output="\n".join(suid[:40]),
            remediation="Audit SUID binaries; strip the bit where not required."))


def enrich_host(host: Host, creds: dict | None, ssh: dict | None,
                aggressive: bool = False,
                admin_creds: dict | None = None) -> tuple[list[dict], dict]:
    """Run every applicable credentialed check against one host, folding results
    in place. Returns (issues, auth): a list of issue dicts for tools that
    errored, plus a per-account authentication-outcome map for the summary table.

    Two credential sets are supported, matching a real engagement:
      * `creds`       - a normal/low-privilege account: does the broad enumeration
                        (shares, users, sessions, password policy, roasting). If it
                        turns out to grant local admin, that itself is a finding.
      * `admin_creds` - a privileged account: does the admin-only power moves
                        (confirm local-admin reach, dump hashes with secretsdump),
                        labelled so the report shows what the privileged account
                        reached that the user account did not.
    """
    issues: list[dict] = []
    # Per-account authentication outcome, so the phase can print a loud
    # success/fail table: label -> {"tried", "auth", "admin", "error"}. We only
    # record a cell when the tool actually ran and returned a verdict - a missing
    # tool (data and err both None) leaves the cell blank, so the table never
    # reports "FAIL" (and never tells the operator to check creds) for a tooling
    # gap. `error` marks an attempt that errored out (unreachable/timeout) - a
    # different thing from credentials being rejected.
    auth: dict[str, dict] = {}

    def note(phase, err):
        if err:
            issues.append({"phase": phase, "level": "warning",
                           "message": f"{phase}: {err}"})

    def rec_smb(label, data, err):
        if data is not None:
            # Holding local admin necessarily means the bind authenticated, so
            # admin implies auth even if the parser only flagged the Pwn3d! line.
            authed = bool(data.get("auth") or data.get("admin"))
            auth[label] = {"tried": True, "auth": authed,
                           "admin": bool(data.get("admin")), "error": False}
        elif err is not None:
            auth[label] = {"tried": True, "auth": False, "admin": False,
                           "error": True}
        # else: tool absent - leave the cell unrecorded ("-").

    if _creds_ok(creds) and _smb_ports(host):
        data, err = run_nxc_smb(host.ip, creds)
        note("cred-smb", err)
        rec_smb("user", data, err)
        if data:
            _fold_nxc(host, data, label="user account")
    if _creds_ok(creds) and _is_dc(host):
        spns, err1 = run_kerberoast(host.ip, creds)
        note("kerberoast", err1)
        asreps, err2 = run_asrep(host.ip, creds)
        note("asrep", err2)
        if spns or asreps:
            _fold_roast(host, spns, asreps, creds.get("domain", ""))
    if ssh and ssh.get("username") and _ssh_port(host):
        facts, err = run_ssh_local(host.ip, ssh)
        note("ssh-local", err)
        if facts is not None:
            auth["ssh"] = {"tried": True, "auth": True, "admin": False,
                           "error": False}
        elif err is not None:
            auth["ssh"] = {"tried": True, "auth": False, "admin": False,
                           "error": True}
        if facts:
            _fold_ssh(host, facts)

    # Privileged account: confirm admin reach + the hash-dump power move. Providing
    # admin_creds signals intent, so secretsdump runs with them even without
    # --aggressive; without admin_creds, secretsdump only runs when aggressive.
    dump_creds = admin_creds if _creds_ok(admin_creds) else (creds if aggressive else None)
    if _creds_ok(admin_creds) and _smb_ports(host):
        data, err = run_nxc_smb(host.ip, admin_creds)
        note("cred-smb-admin", err)
        rec_smb("admin", data, err)
        if data:
            _fold_nxc(host, data, label="privileged account", admin_only=True)
    # Only attempt the hash dump where the account we'd use actually authenticated
    # over SMB - a doomed secretsdump on a rejected/erroring bind wastes a run and
    # would misleadingly imply we had access.
    dump_label = "admin" if dump_creds is admin_creds else "user"
    dump_ok = auth.get(dump_label, {}).get("auth", False)
    if _creds_ok(dump_creds) and _smb_ports(host) and dump_ok:
        dumped, err = run_secretsdump(host.ip, dump_creds)
        note("secretsdump", err)
        _fold_secrets(host, dumped, dump_creds.get("domain", ""))

    host.cred_enumerated = True
    return issues, auth
