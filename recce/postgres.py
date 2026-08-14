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
                out.append(_finding(
                    "high", "PostgreSQL trust authentication (no password required)", tgt,
                    "The server accepted a v3 startup for user 'postgres' with NO "
                    "password (AuthenticationOk / `trust` in pg_hba.conf)"
                    + (f"; server_version {ver}" if ver else "")
                    + ". Anyone who can reach this port has full database access.",
                    f"psql 'host={h.ip} port={p.portid} user=postgres dbname=postgres'",
                    "Replace `trust` in pg_hba.conf with scram-sha-256 (or md5); bind to "
                    "localhost / a private interface; require TLS for remote access.",
                    ["CWE-306", "CWE-287"], kind="pg_trust_auth"))
    return out


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
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["unauth"] = pr.get("unauth", False)
                t["auth_required"] = pr.get("auth_required", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
