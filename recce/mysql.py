"""Deep MySQL/MariaDB enumeration (stdlib, read-only).

Reads the server handshake (version) and tests the highest-impact misconfiguration:
an account that logs in with an EMPTY password (classic `root` with no password, or an
anonymous ''@'%' account). We speak just enough of the MySQL protocol to send a
HandshakeResponse41 with a zero-length auth response and read the OK/ERR - no query is
ever run, nothing is written.

Findings fold into the severity totals / Vulnerabilities sheet (source="mysql").
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port

_PORTS = (3306, 3307, 33060)
_DEFAULT_PORT = 3306
_TIMEOUT = 5.0
_MAX_PKT = 64 * 1024

# client capability flags
_CLIENT_LONG_PASSWORD = 0x00000001
_CLIENT_PROTOCOL_41 = 0x00000200
_CLIENT_SECURE_CONNECTION = 0x00008000
_CLIENT_PLUGIN_AUTH = 0x00080000
_CAPS = (_CLIENT_LONG_PASSWORD | _CLIENT_PROTOCOL_41
         | _CLIENT_SECURE_CONNECTION | _CLIENT_PLUGIN_AUTH)


def is_mysql(port: Port) -> bool:
    if not port.is_open:
        return False
    svc = (port.service or "").lower()
    return port.portid in _PORTS or "mysql" in svc or "mariadb" in svc


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_packet(sock: socket.socket):
    """Return (payload_bytes, seq) or (None, 0)."""
    hdr = _recvn(sock, 4)
    if len(hdr) < 4:
        return None, 0
    length = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16)
    seq = hdr[3]
    return _recvn(sock, min(length, _MAX_PKT)), seq


def _server_version(payload: bytes) -> str:
    # payload: [protocol_version:1][server_version:null-terminated]...
    if not payload or payload[0] != 10:
        return ""
    end = payload.find(b"\x00", 1)
    if end < 0:
        return ""
    return payload[1:end].decode("utf-8", "replace")


def _handshake_response(user: str) -> bytes:
    # HandshakeResponse41 with an EMPTY auth response (empty password).
    body = struct.pack("<IIB", _CAPS, _MAX_PKT, 0x21)      # caps, max packet, utf8 charset
    body += b"\x00" * 23                                   # reserved
    body += user.encode() + b"\x00"                        # username
    body += b"\x00"                                        # auth-response length = 0 (empty)
    body += b"mysql_native_password\x00"                   # auth plugin name
    return body


def _login_empty(ip: str, port: int, user: str, timeout: float) -> dict:
    """Attempt an empty-password login. Returns {reachable, version, ok, err}."""
    res = {"reachable": False, "version": "", "ok": False, "err": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError as e:
        res["err"] = str(e)
        return res
    try:
        payload, seq = _read_packet(sock)
        if payload is None:
            res["err"] = "no handshake"
            return res
        if payload[:1] == b"\xff":                         # server greeted with an error
            res["reachable"] = True
            res["err"] = "server error on connect (host blocked?)"
            return res
        res["reachable"] = True
        res["version"] = _server_version(payload)
        resp = _handshake_response(user)
        sock.sendall(struct.pack("<I", len(resp))[:3] + bytes([seq + 1]) + resp)
        reply, _ = _read_packet(sock)
        if not reply:
            res["err"] = "no login reply"
        elif reply[0] == 0x00:                             # OK packet
            res["ok"] = True
        elif reply[0] == 0xFF:                             # ERR packet
            code = struct.unpack("<H", reply[1:3])[0] if len(reply) >= 3 else 0
            res["err"] = f"ERR {code}"
        else:                                              # AuthSwitch(0xFE)/MoreData(0x01)
            res["err"] = "auth negotiation required"
        return res
    except OSError as e:
        res["err"] = str(e)
        return res
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    res = {"reachable": False, "unauth": False, "auth_required": False,
           "version": "", "user": "", "error": ""}
    for user in ("root", ""):                              # empty-password root, then anon
        r = _login_empty(ip, port, user, timeout)
        if r["reachable"]:
            res["reachable"] = True
            res["version"] = res["version"] or r["version"]
        if r["ok"]:
            res["unauth"] = True
            res["user"] = user or "<anonymous>"
            return res
        if not r["reachable"]:
            res["error"] = r["err"]
            return res
    res["auth_required"] = True
    return res


def mysql_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_mysql(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "mysql", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_mysql(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            if pr.get("unauth"):
                who = pr.get("user") or "root"
                ver = pr.get("version") or ""
                out.append(_finding(
                    "high", f"MySQL '{who}' login with empty password", tgt,
                    f"The account '{who}' authenticated with an EMPTY password"
                    + (f" (server {ver})" if ver else "")
                    + " - full database access without a credential.",
                    f"mysql -h {h.ip} -P {p.portid} -u {who or 'root'}",
                    "Set a strong password on every account (esp. root); remove anonymous "
                    "''@'%' accounts; bind to localhost / a private interface.",
                    ["CWE-521", "CWE-306"], kind="mysql_empty_password"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [{"step": "Test empty-password root / anonymous login",
             "cmd": f"mysql -h {ip} -P {port} -u root   ;   mysql -h {ip} -P {port} -u ''"},
            {"step": "If in: read users + hashes",
             "cmd": "SELECT user,host,authentication_string FROM mysql.user;"}]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "mysql", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = mysql_targets(hosts)
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
