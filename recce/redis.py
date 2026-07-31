"""Deep Redis enumeration (stdlib only).

Speaks the Redis serialization protocol (RESP) directly on a raw socket - no
redis-py. Airgapped, stdlib only.

  * **PING / INFO:** version, OS, role (always answerable on an open port).
  * **INFO WITHOUT authentication:** the discriminator. If `INFO` returns the server
    stats with no `AUTH`, the instance is exposed unauthenticated - anyone on the
    network reads every key and, because Redis lets a client rewrite `dir` +
    `dbfilename` and `SAVE`, usually escalates to arbitrary file write / RCE (SSH
    `authorized_keys`, a cron entry, a web shell, or a malicious module). A
    `-NOAUTH Authentication required` reply means auth is enforced (recce reports it
    reachable-but-locked, not a finding).
  * **CONFIG GET dir / dbfilename / requirepass / protected-mode:** confirms the
    write-primitive preconditions and the exposure cause.

Positive findings fold into the severity totals, the Vulnerabilities sheet, the
write-ups, a dedicated **Redis** tab, and the prove engine. Read-only: recce never
writes a key, rewrites the config, or calls SAVE. Safety posture: see SECURITY.md.
"""
from __future__ import annotations

import socket

from .models import Host, Port

_PORTS = (6379, 6380, 16379)
_DEFAULT_PORT = 6379
_TIMEOUT = 5.0
_MAX_REPLY = 512 * 1024            # INFO is a few KB; cap the read so a hostile or
                                  # confused peer can't make us buffer unbounded.
_MAX_DEPTH = 32


def is_redis(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    return "redis" in f"{port.service} {port.product}".lower()


# --- RESP (REdis Serialization Protocol) ----------------------------------------

class _Err(str):
    """A RESP error reply ('-NOAUTH ...'), distinguishable from a normal string."""


class _Incomplete(Exception):
    """The buffer doesn't yet hold a complete reply - read more bytes."""


def _parse(buf: bytes, i: int = 0, depth: int = 0):
    """Parse one RESP value at `buf[i:]`. Returns (value, next_index). Raises
    _Incomplete if more bytes are needed, ValueError on a malformed frame."""
    if depth > _MAX_DEPTH:
        raise ValueError("RESP nested too deep")
    if i >= len(buf):
        raise _Incomplete
    marker = buf[i:i + 1]
    nl = buf.find(b"\r\n", i)
    if nl == -1:
        raise _Incomplete
    line = buf[i + 1:nl].decode("utf-8", "replace")
    after = nl + 2
    if marker == b"+":                                 # simple string
        return line, after
    if marker == b"-":                                 # error
        return _Err(line), after
    if marker == b":":                                 # integer
        try:
            return int(line), after
        except ValueError:
            raise ValueError("bad RESP integer")
    if marker == b"$":                                 # bulk string
        try:
            n = int(line)
        except ValueError:
            raise ValueError("bad RESP bulk length")
        if n == -1:
            return None, after
        if n < 0 or n > _MAX_REPLY:
            raise ValueError("RESP bulk length out of range")
        end = after + n
        if end + 2 > len(buf):
            raise _Incomplete
        return buf[after:end].decode("utf-8", "replace"), end + 2
    if marker == b"*":                                 # array
        try:
            n = int(line)
        except ValueError:
            raise ValueError("bad RESP array length")
        if n == -1:
            return None, after
        if n < 0 or n > 1024:
            raise ValueError("RESP array length out of range")
        out, j = [], after
        for _ in range(n):
            val, j = _parse(buf, j, depth + 1)
            out.append(val)
        return out, j
    raise ValueError("unknown RESP marker")


def _command(sock: socket.socket, *args: str) -> bytes:
    """Encode a command as a RESP array of bulk strings and send it."""
    parts = [f"*{len(args)}\r\n".encode()]
    for a in args:
        b = a.encode("utf-8")
        parts.append(f"${len(b)}\r\n".encode() + b + b"\r\n")
    payload = b"".join(parts)
    sock.sendall(payload)
    return payload


def _read_reply(sock: socket.socket, timeout: float = _TIMEOUT):
    """Read bytes until one complete RESP reply parses, the peer closes, the cap is
    hit, or the socket goes idle. Returns the parsed value (or None)."""
    buf = b""
    sock.settimeout(timeout)
    # Allow a little headroom over _MAX_REPLY so a bulk string AT the cap can still
    # buffer its framing ($<len>\r\n ... \r\n) instead of truncating to None.
    while len(buf) < _MAX_REPLY + 64:
        try:
            val, _ = _parse(buf, 0)
            return val
        except _Incomplete:
            pass
        except ValueError:
            return None
        try:
            chunk = sock.recv(8192)
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return None


def _info_dict(text: str) -> dict:
    """Parse an INFO bulk-string ('key:value' lines, '# Section' headers)."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def _config_value(reply) -> str:
    """CONFIG GET returns a flat array [name, value, ...]; return the first value."""
    if isinstance(reply, list) and len(reply) >= 2:
        return str(reply[1])
    return ""


# --- live probe -----------------------------------------------------------------

def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Connect and (read-only) fingerprint a Redis endpoint. Returns
    {reachable, unauth, version, os, role, keys, dir, dbfilename, protected_mode,
     requirepass, ssl, error} - empty dict if not Redis / unreachable."""
    out: dict = {"reachable": False, "unauth": False}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError as e:
        return {"reachable": False, "error": str(e)}
    try:
        _command(sock, "PING")
        pong = _read_reply(sock, timeout)
        if pong is None:
            return {"reachable": False, "error": "no PING reply"}
        out["reachable"] = True
        # A plaintext PING against a TLS-only listener (6380) yields an error/garbage;
        # note it but still try INFO.
        _command(sock, "INFO")
        info = _read_reply(sock, timeout)
        if isinstance(info, _Err):
            # -NOAUTH / -ERR: auth enforced (or protected). Reachable but locked.
            out["error"] = str(info)
            if "NOAUTH" in str(info).upper() or "AUTH" in str(info).upper():
                out["auth_required"] = True
            return out
        if isinstance(info, str):
            d = _info_dict(info)
            # Only claim an unauthenticated Redis when the peer positively looks like
            # Redis (PONG to PING, or an INFO carrying redis_version) - so a non-Redis
            # service on 6379 that happens to emit a RESP-shaped reply is not a false
            # critical.
            if pong != "PONG" and not d.get("redis_version"):
                out["error"] = "not a Redis service (no PONG / redis_version)"
                return out
            out["unauth"] = True
            out["version"] = d.get("redis_version", "")
            out["os"] = d.get("os", "")
            out["role"] = d.get("role", "")
            out["mode"] = d.get("redis_mode", "")
            # Total keys across all keyspace db lines (db0:keys=N,...).
            keys = 0
            for k, v in d.items():
                if k.startswith("db") and "keys=" in v:
                    try:
                        keys += int(v.split("keys=")[1].split(",")[0])
                    except (ValueError, IndexError):
                        pass
            out["keys"] = keys
            # Config preconditions for the write-primitive (read-only GETs).
            for name, key in (("dir", "dir"), ("dbfilename", "dbfilename"),
                              ("requirepass", "requirepass"),
                              ("protected-mode", "protected_mode")):
                _command(sock, "CONFIG", "GET", name)
                out[key] = _config_value(_read_reply(sock, timeout))
        return out
    except OSError as e:
        out["error"] = str(e)
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


def redis_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_redis(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "redis_unauth": (
        "The Redis instance accepts commands with no authentication - recce read the "
        "server's INFO without a credential. That is full read/write access to every "
        "key (dump or tamper with cached sessions, tokens, queues and app data). Worse, "
        "an unauthenticated client can rewrite `dir` + `dbfilename` and call SAVE to "
        "write an arbitrary file - the classic escalation to RCE: an SSH "
        "authorized_keys entry, a root cron job, a web shell in the docroot, or loading "
        "a malicious module. Require a strong password (requirepass / ACLs), enable "
        "protected-mode, and bind the listener to a trusted interface immediately."),
    "redis_version": (
        "The Redis build is old / end-of-life. Beyond the missing security fixes, "
        "several Lua-sandbox-escape and module-load RCE issues affect older lines - "
        "confirm the running version and upgrade."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Handshake (stdlib RESP)",
     "recce speaks the Redis wire protocol directly - no redis-py. It sends PING and "
     "reads the +PONG to confirm the service."),
    ("2. Unauthenticated access test",
     "It runs INFO with no credential. If the server stats come back, the instance is "
     "exposed unauthenticated (critical); a -NOAUTH reply means auth is enforced "
     "(reachable but locked - not a finding)."),
    ("3. Write-primitive preconditions",
     "On an exposed instance it reads (never sets) CONFIG dir / dbfilename / "
     "requirepass / protected-mode - the settings an attacker would rewrite to turn "
     "read/write into arbitrary file write / RCE."),
    ("4. Runbook",
     "The exact follow-on commands (redis-cli INFO, KEYS *, the CONFIG SET dir + SAVE "
     "file-write chain, nmap redis-info) are staged per endpoint."),
]


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "redis", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def _old_version(ver: str) -> bool:
    try:
        parts = [int(x) for x in ver.split(".")[:2]]
        return parts < [6, 0]                          # < 6.0 predates ACLs; EOL
    except (ValueError, IndexError):
        return False


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_redis(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            if pr.get("unauth"):
                keys = pr.get("keys", 0)
                rce = ""
                if pr.get("dir") or pr.get("dbfilename"):
                    rce = (f" Write primitive available (dir={pr.get('dir', '?')}, "
                           f"dbfilename={pr.get('dbfilename', '?')}) -> arbitrary file "
                           "write / RCE.")
                out.append(_finding(
                    "critical", "Redis exposed without authentication", tgt,
                    "recce read INFO with no credential"
                    + (f" (version {ver})" if ver else "")
                    + (f"; keyspace holds {keys} key(s)" if keys else "")
                    + ". Full unauthenticated read/write access to every key."
                    + rce,
                    "redis-cli",
                    f"redis-cli -h {h.ip} -p {p.portid} INFO ; "
                    f"redis-cli -h {h.ip} -p {p.portid} KEYS '*'   # then the "
                    "CONFIG SET dir + dbfilename + SAVE file-write chain for RCE",
                    "Set a strong requirepass / ACL, enable protected-mode, disable or "
                    "rename CONFIG/SAVE for untrusted clients, and bind to a trusted "
                    "interface only.",
                    ["CWE-306", "CWE-284"], kind="redis_unauth"))
            if ver and _old_version(ver):
                out.append(_finding(
                    "medium", "Redis end-of-life / legacy build", tgt,
                    f"Redis {ver} predates the 6.0 ACL line and is past end-of-life - "
                    "missing security fixes (incl. Lua-sandbox / module-load RCEs).",
                    "redis-cli",
                    f"redis-cli -h {h.ip} -p {p.portid} INFO server",
                    "Upgrade to a supported Redis release.",
                    ["CWE-1104"], kind="redis_version"))
    return out


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", f"nmap -p{port} --script redis-info {ip}",
         "Server info (confirms unauth if it answers)."),
        ("enumerate", "redis-cli", f"redis-cli -h {ip} -p {port} INFO ; "
         f"redis-cli -h {ip} -p {port} KEYS '*'",
         "Read server stats and every key without a credential."),
        ("loot", "redis-cli", f"redis-cli -h {ip} -p {port} --scan | head ; "
         f"redis-cli -h {ip} -p {port} DUMP <key>",
         "Enumerate and dump keys (sessions, tokens, cached data)."),
        ("escalate", "CONFIG + SAVE", f"redis-cli -h {ip} -p {port} CONFIG SET dir "
         "/var/lib/redis ; ... CONFIG SET dbfilename x ; ... SAVE   # authorized_keys "
         "/ cron / webshell file-write -> RCE (only within scope)",
         "Turn read/write into arbitrary file write / code execution."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="> ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "redis", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full Redis analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = redis_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["unauth"] = pr.get("unauth", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["keys"] = pr.get("keys", 0)
                t["auth_required"] = pr.get("auth_required", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
