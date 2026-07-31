"""Deep rsync-daemon enumeration (stdlib only).

Speaks the rsync daemon protocol (TCP 873) directly on a raw socket - no rsync
binary. Airgapped, stdlib only, read-only.

  * **@RSYNCD handshake + module list:** every daemon answers `#list` with its share
    ("module") names and comments, with no credential - that inventory alone leaks the
    server's layout (backups/, home/, srv/, ...).
  * **Per-module anonymous-access probe:** for each module recce opens a fresh
    connection and requests it. `@RSYNCD: OK` means the module is readable with NO
    authentication - anyone on the network can pull (and often push) every file in it
    (backups, configs, source, secrets). `@RSYNCD: AUTHREQD` means a password is
    required (reported reachable-but-locked, not a finding). recce reads the OK/AUTHREQD
    line and stops - it never transfers a file.

Positive findings fold into the severity totals, the Vulnerabilities sheet, the
write-ups, a dedicated **rsync** tab, and the prove engine. Safety posture: SECURITY.md.
"""
from __future__ import annotations

import socket

from .models import Host, Port

_PORTS = (873,)
_DEFAULT_PORT = 873
_TIMEOUT = 6.0
_MAX_MODULES = 200
_MAX_LINE = 4096


def is_rsync(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    return "rsync" in f"{port.service} {port.product}".lower()


class _LineReader:
    """A buffered line reader over a socket - the rsync daemon sends several control
    lines in one packet, so bytes read past one newline must be kept for the next."""

    def __init__(self, sock: socket.socket, timeout: float):
        self.sock = sock
        self.timeout = timeout
        self.buf = b""
        self.eof = False

    def line(self) -> str:
        """Next '\\n'-terminated line without the newline, or '' on EOF/overflow."""
        self.sock.settimeout(self.timeout)
        while b"\n" not in self.buf:
            if len(self.buf) > _MAX_LINE or self.eof:
                break
            try:
                chunk = self.sock.recv(1024)
            except (socket.timeout, OSError):
                self.eof = True
                break
            if not chunk:
                self.eof = True
                break
            self.buf += chunk
        line, sep, rest = self.buf.partition(b"\n")
        if not sep:                                    # no newline left
            self.buf = b""
            return line.decode("utf-8", "replace").rstrip("\r")
        self.buf = rest
        return line.decode("utf-8", "replace").rstrip("\r")


def _greeting_version(line: str) -> str:
    """'@RSYNCD: 31.0' -> '31.0'."""
    if line.startswith("@RSYNCD:"):
        return line.split(":", 1)[1].strip()
    return ""


def list_modules(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Handshake and read the module list. Returns
    {reachable, version, modules:[{name,comment}], error}."""
    out: dict = {"reachable": False, "modules": []}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as e:
        return {"reachable": False, "error": str(e)}
    try:
        reader = _LineReader(sock, timeout)
        greet = reader.line()
        ver = _greeting_version(greet)
        if not ver:
            return {"reachable": False, "error": "no @RSYNCD greeting"}
        out["reachable"] = True
        out["version"] = ver
        # Echo a compatible version, then ask for the module list.
        sock.sendall(f"@RSYNCD: {ver}\n".encode())
        sock.sendall(b"#list\n")
        mods = []
        while len(mods) < _MAX_MODULES:
            line = reader.line()
            if not line or line.startswith("@RSYNCD: EXIT") or line.startswith("@ERROR"):
                break
            if line.startswith("@RSYNCD:"):
                continue
            # 'name          comment' - rsync pads the name with spaces (or a tab).
            if "\t" in line:
                name, comment = line.split("\t", 1)
            else:
                parts = line.split("  ", 1)
                name = parts[0].strip()
                comment = parts[1].strip() if len(parts) > 1 else ""
            if name:
                mods.append({"name": name.strip(), "comment": comment.strip()})
        out["modules"] = mods
        return out
    except OSError as e:
        out["error"] = str(e)
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_module(ip: str, port: int, module: str, timeout: float = _TIMEOUT) -> str:
    """Request a module and read the daemon's verdict. Returns 'open' (anonymous
    access granted), 'auth' (password required), or 'unknown'. Read-only - recce
    stops at the OK/AUTHREQD line and never enters the transfer protocol."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return "unknown"
    try:
        reader = _LineReader(sock, timeout)
        greet = reader.line()
        ver = _greeting_version(greet)
        if not ver:
            return "unknown"
        sock.sendall(f"@RSYNCD: {ver}\n".encode())
        sock.sendall(f"{module}\n".encode())
        while True:
            line = reader.line()
            if not line:
                return "unknown"
            up = line.upper()
            if "AUTHREQD" in up:
                return "auth"
            if line.startswith("@RSYNCD: OK"):
                return "open"
            if line.startswith("@ERROR"):
                return "unknown"
            # Ignore MOTD / other @RSYNCD lines until a verdict appears.
    except OSError:
        return "unknown"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def rsync_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_rsync(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "rsync_list": (
        "The rsync daemon lists its shared modules to anyone with no credential. Even "
        "when the modules themselves need a password, the inventory of share names and "
        "comments leaks the server's layout (backup targets, home directories, web "
        "roots) and is a map for the next step. Restrict access with hosts allow / a "
        "firewall, and consider 'list = false'."),
    "rsync_open": (
        "The rsync module is readable with NO authentication - anyone on the network "
        "can pull every file in it (and, if 'read only = false', push files too). That "
        "is straight data exfiltration of whatever it exposes: backups, configuration, "
        "source code, credentials. Require 'auth users' + a secrets file, set 'read "
        "only = true', and restrict with hosts allow / a firewall immediately."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Handshake (stdlib rsync daemon protocol)",
     "recce speaks the rsync daemon protocol directly - no rsync binary. It reads the "
     "@RSYNCD greeting and echoes a compatible protocol version."),
    ("2. Module inventory",
     "It sends #list and records every module name + comment the daemon returns "
     "without a credential."),
    ("3. Per-module anonymous-access test",
     "For each module it opens a fresh connection and requests it: @RSYNCD: OK means "
     "anonymous read access (critical/high exposure); AUTHREQD means a password is "
     "enforced (reachable but locked - not a finding). recce reads the verdict line "
     "and stops - it never transfers a file."),
    ("4. Runbook",
     "The exact follow-on commands (rsync --list-only, the recursive pull) are staged "
     "per module."),
]


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "rsync", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_rsync(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            mods = pr.get("modules") or []
            open_mods = [m for m in mods if m.get("access") == "open"]
            if open_mods:
                names = ", ".join(m["name"] for m in open_mods[:12])
                out.append(_finding(
                    "high", "rsync module readable without authentication", tgt,
                    f"{len(open_mods)} module(s) grant access with no credential: "
                    f"{names}. Unauthenticated read (and, if not read-only, write) "
                    "access to every file they expose.",
                    "rsync",
                    f"rsync --list-only rsync://{h.ip}:{p.portid}/{open_mods[0]['name']}/ ; "
                    f"rsync -av rsync://{h.ip}:{p.portid}/{open_mods[0]['name']}/ loot/",
                    "Require 'auth users' + a secrets file on every module, set 'read "
                    "only = true', and restrict with 'hosts allow' / a firewall.",
                    ["CWE-306", "CWE-284"], kind="rsync_open"))
            if mods:
                names = ", ".join(m["name"] for m in mods[:12])
                out.append(_finding(
                    "medium", "rsync modules enumerable without authentication", tgt,
                    f"The daemon lists {len(mods)} module(s) with no credential: {names}."
                    " The share inventory leaks the server's layout.",
                    "rsync",
                    f"rsync rsync://{h.ip}:{p.portid}/",
                    "Set 'list = false' and restrict access with 'hosts allow' / a "
                    "firewall.",
                    ["CWE-200"], kind="rsync_list"))
    return out


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "rsync", f"rsync rsync://{ip}:{port}/",
         "List every module without a credential."),
        ("enumerate", "rsync", f"rsync --list-only rsync://{ip}:{port}/<module>/",
         "List a module's files (confirms anonymous read)."),
        ("loot", "rsync", f"rsync -av rsync://{ip}:{port}/<module>/ loot/<module>/",
         "Pull the whole module (backups / configs / source / secrets)."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "rsync", _DEFAULT_PORT)


def _probe_one(t: dict) -> dict:
    """List a daemon's modules and, for each, its anonymous-access verdict."""
    pr = list_modules(t["ip"], t["port"])
    if pr and pr.get("reachable"):
        for m in pr.get("modules") or []:
            m["access"] = probe_module(t["ip"], t["port"], m["name"])
    return pr


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full rsync analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = rsync_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(targets, _probe_one, budget=budget,
                                         progress=progress, state=state):
            if pr and pr.get("reachable"):
                probes[(t["ip"], t["port"])] = pr
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["modules"] = len(pr.get("modules") or [])
                t["open"] = sum(1 for m in pr.get("modules") or []
                                if m.get("access") == "open")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
