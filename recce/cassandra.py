"""Deep Apache Cassandra / ScyllaDB enumeration (stdlib only).

Cassandra speaks the CQL binary protocol on TCP 9042 and defaults to
AllowAllAuthenticator - NO authentication. recce speaks the CQL native protocol
directly (no cassandra-driver) to CONFIRM the exposure and fingerprint the server,
read-only:

  * **STARTUP frame**  - the discriminator. A READY response means the cluster accepts
                         CQL with no credential (AllowAllAuthenticator); an AUTHENTICATE
                         response means PasswordAuthenticator is enforced (and names the
                         authenticator class).
  * **QUERY system.local** - on an unauthenticated node, read release_version,
                         cluster_name, data_center and partitioner (the fingerprint).

An open, unauthenticated 9042 is a confirmed exposure: full CQL read/write, and -
with user-defined functions enabled - the Nashorn sandbox-escape RCE (CVE-2021-44521).
recce only issues SELECTs against system tables; it never writes. Authorized testing
only.
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port
from .svccommon import finding_builder

_PORTS = (9042, 9142)              # 9042 CQL, 9142 CQL-over-TLS (native SSL)
_DEFAULT_PORT = 9042
_TIMEOUT = 6.0
_MAX_BODY = 256 * 1024

# CQL frame opcodes.
_OP_ERROR, _OP_STARTUP, _OP_READY, _OP_AUTHENTICATE = 0x00, 0x01, 0x02, 0x03
_OP_OPTIONS, _OP_SUPPORTED, _OP_QUERY, _OP_RESULT = 0x05, 0x06, 0x07, 0x08
_REQ_VERSION = 0x04                # native protocol v4 request; response is 0x84.


def is_cassandra(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    blob = f"{port.service} {port.product}".lower()
    return "cassandra" in blob or "scylla" in blob or "cql" in blob


def cassandra_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_cassandra(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- CQL native protocol (stdlib) ----------------------------------------------

def _frame(opcode: int, body: bytes, stream: int = 1) -> bytes:
    # [version:1][flags:1][stream:2][opcode:1][length:4][body]
    return struct.pack(">BBhBI", _REQ_VERSION, 0, stream, opcode, len(body)) + body


def _string(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def _string_map(m: dict) -> bytes:
    out = struct.pack(">H", len(m))
    for k, v in m.items():
        out += _string(k) + _string(v)
    return out


def _long_string(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">I", len(b)) + b


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _read_frame(sock: socket.socket):
    """Read one CQL response frame. Returns (opcode, body) or (None, b'')."""
    head = _recv_exact(sock, 9)
    if len(head) < 9:
        return None, b""
    _ver, _flags, _stream, opcode, length = struct.unpack(">BBhBI", head)
    if length > _MAX_BODY:
        length = _MAX_BODY
    body = _recv_exact(sock, length)
    return opcode, body


def _read_cql_string(body: bytes, i: int):
    if i + 2 > len(body):
        return "", i
    (n,) = struct.unpack_from(">H", body, i)
    i += 2
    s = body[i:i + n].decode("utf-8", "replace")
    return s, i + n


def _parse_error(body: bytes) -> str:
    # [code:4][message: string]
    if len(body) < 6:
        return "error"
    msg, _ = _read_cql_string(body, 4)
    return msg


def _parse_system_local(body: bytes) -> dict:
    """Best-effort parse of a Rows RESULT for SELECT release_version,cluster_name,
    data_center,partitioner FROM system.local. Returns the first row's values keyed by
    column name. Tolerates malformed frames (returns what it could read)."""
    out: dict[str, str] = {}
    try:
        (kind,) = struct.unpack_from(">I", body, 0)
        if kind != 0x0002:                      # not Rows
            return out
        i = 4
        (flags,) = struct.unpack_from(">I", body, i); i += 4
        (col_count,) = struct.unpack_from(">I", body, i); i += 4
        has_global = bool(flags & 0x0001)
        no_metadata = bool(flags & 0x0004)
        if no_metadata:
            return out
        if has_global:
            _ks, i = _read_cql_string(body, i)
            _tb, i = _read_cql_string(body, i)
        cols = []
        for _ in range(col_count):
            if not has_global:
                _ks, i = _read_cql_string(body, i)
                _tb, i = _read_cql_string(body, i)
            name, i = _read_cql_string(body, i)
            (opt_id,) = struct.unpack_from(">H", body, i); i += 2
            # custom(0x0000) carries a class-name string; collection types carry a
            # nested option. Our query returns only simple scalar types, so no nested
            # option follows - but skip a custom type's class name if present.
            if opt_id == 0x0000:
                _cn, i = _read_cql_string(body, i)
            cols.append(name)
        (row_count,) = struct.unpack_from(">I", body, i); i += 4
        if row_count < 1:
            return out
        for name in cols:                       # first row only
            if i + 4 > len(body):
                break
            (vlen,) = struct.unpack_from(">i", body, i); i += 4
            if vlen < 0:                        # NULL
                out[name] = ""
                continue
            val = body[i:i + vlen]; i += vlen
            out[name] = val.decode("utf-8", "replace")
    except (struct.error, IndexError, UnicodeDecodeError):
        pass
    return out


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """STARTUP -> READY/AUTHENTICATE, then (if unauth) read system.local. Returns
    {reachable, is_cassandra, no_auth, authenticator, version, cluster, datacenter,
    partitioner, error}."""
    res: dict = {"reachable": False, "is_cassandra": False, "no_auth": False,
                 "authenticator": "", "version": "", "cluster": "", "datacenter": "",
                 "partitioner": "", "error": ""}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            res["reachable"] = True
            sock.sendall(_frame(_OP_STARTUP, _string_map({"CQL_VERSION": "3.0.0"})))
            opcode, body = _read_frame(sock)
            if opcode is None:
                res["error"] = "no CQL response"
                return res
            op = opcode & 0x7F if opcode & 0x80 else opcode
            if op == _OP_AUTHENTICATE:
                res["is_cassandra"] = True
                res["authenticator"], _ = _read_cql_string(body, 0)
                return res
            if op == _OP_ERROR:
                res["error"] = _parse_error(body)
                # A protocol-version error still proves a CQL server is listening.
                if "protocol" in res["error"].lower() or "version" in res["error"].lower():
                    res["is_cassandra"] = True
                return res
            if op != _OP_READY:
                res["error"] = f"unexpected opcode {op:#x}"
                return res
            # READY: unauthenticated CQL access (AllowAllAuthenticator).
            res["is_cassandra"] = True
            res["no_auth"] = True
            res["authenticator"] = "AllowAllAuthenticator"
            # Best-effort fingerprint via system.local.
            query = ("SELECT release_version,cluster_name,data_center,partitioner "
                     "FROM system.local")
            qbody = _long_string(query) + struct.pack(">HB", 0x0001, 0x00)  # consistency ONE, no flags
            sock.sendall(_frame(_OP_QUERY, qbody, stream=2))
            opcode, body = _read_frame(sock)
            if opcode is not None and (opcode & 0x7F) == _OP_RESULT:
                row = _parse_system_local(body)
                res["version"] = row.get("release_version", "")
                res["cluster"] = row.get("cluster_name", "")
                res["datacenter"] = row.get("data_center", "")
                res["partitioner"] = row.get("partitioner", "")
    except (OSError, socket.timeout, struct.error) as e:
        res["error"] = res["error"] or str(e)
    return res


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "cassandra_noauth": (
        "The Cassandra node accepts CQL with NO authentication - recce completed the "
        "STARTUP handshake and read system.local without a credential (the default "
        "AllowAllAuthenticator). That is full read/write to every keyspace: dump or "
        "tamper with application data. If user-defined functions are enabled it is also "
        "an RCE primitive - the Nashorn sandbox escape CVE-2021-44521 - and the JMX "
        "management port (7199) is a further RCE vector. Switch to "
        "PasswordAuthenticator, firewall 9042/7000/7199, and lock down UDF permissions."),
    "cassandra_version": (
        "The Cassandra build may be affected by the UDF sandbox-escape RCE "
        "(CVE-2021-44521) and other fixed issues - confirm the release_version and "
        "upgrade / restrict FUNCTION permissions."),
}

TESTING_NARRATIVE = [
    ("1. STARTUP handshake (stdlib CQL)",
     "recce speaks the CQL native binary protocol directly (no driver). It sends a "
     "STARTUP frame and reads the response opcode."),
    ("2. Authentication discriminator",
     "A READY response means the node accepts CQL with no credential (AllowAll - a "
     "confirmed finding); an AUTHENTICATE response means PasswordAuthenticator is "
     "enforced and names the authenticator class (locked - not a finding)."),
    ("3. Fingerprint (unauth only)",
     "On an open node it runs SELECT ... FROM system.local to read release_version, "
     "cluster_name, data_center and partitioner - proving real query access."),
    ("4. Runbook",
     "The follow-on cqlsh commands (DESCRIBE KEYSPACES, the UDF/CVE-2021-44521 check, "
     "the JMX 7199 vector) are staged per endpoint."),
]

_finding = finding_builder("cassandra", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_cassandra(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr or not pr.get("is_cassandra"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            if pr.get("no_auth"):
                fp = []
                if ver:
                    fp.append(f"version {ver}")
                if pr.get("cluster"):
                    fp.append(f"cluster '{pr['cluster']}'")
                if pr.get("datacenter"):
                    fp.append(f"DC {pr['datacenter']}")
                fp_txt = (" (" + ", ".join(fp) + ")") if fp else ""
                out.append(_finding(
                    "high", "Apache Cassandra exposed - no authentication (AllowAll)", tgt,
                    "recce completed a CQL STARTUP and read system.local with no "
                    "credential" + fp_txt + ". Full CQL read/write to every keyspace; "
                    "with UDFs enabled this is RCE (CVE-2021-44521), and JMX 7199 is a "
                    "further RCE vector.",
                    "cqlsh",
                    f"cqlsh {h.ip} {p.portid}   # DESCRIBE KEYSPACES ; then SELECT/COPY, "
                    f"and check CREATE FUNCTION (UDF) permission for CVE-2021-44521",
                    "Set authenticator: PasswordAuthenticator + authorizer: "
                    "CassandraAuthorizer; firewall 9042/7000/7199; restrict FUNCTION perms.",
                    ["CWE-306", "CWE-284"], kind="cassandra_noauth"))
            if ver and _old_version(ver):
                out.append(_finding(
                    "medium", "Apache Cassandra - UDF RCE / legacy build", tgt,
                    f"Cassandra {ver} predates the CVE-2021-44521 fix line; with "
                    "scripted UDFs enabled the Nashorn sandbox can be escaped for RCE.",
                    "cqlsh", f"cqlsh {h.ip} {p.portid} -e \"SELECT release_version FROM "
                    "system.local\"",
                    "Upgrade Cassandra (3.0.26 / 3.11.12 / 4.0.2+) and restrict UDF perms.",
                    ["CWE-94"], kind="cassandra_version"))
    return out


def _old_version(ver: str) -> bool:
    from . import vulndb
    try:
        if not ver:
            return False
        # Fixed in 3.0.26 / 3.11.12 / 4.0.2. Flag anything below 4.0.2 on the 3.x/4.0 line.
        return vulndb._cmp(ver, "4.0.2") < 0
    except Exception:      # noqa: BLE001
        return False


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", f"nmap -p{port} --script cassandra-info {ip}",
         "Cluster/version info (confirms unauth if it answers)."),
        ("enumerate", "cqlsh",
         f"cqlsh {ip} {port} -e 'DESCRIBE KEYSPACES' ; "
         f"cqlsh {ip} {port} -e 'SELECT * FROM system.local'",
         "List keyspaces and read system metadata with no credential."),
        ("loot", "cqlsh",
         f"cqlsh {ip} {port} -e 'DESCRIBE KEYSPACE <ks>' ; SELECT * FROM <ks>.<table> LIMIT 20",
         "Dump application data from every keyspace."),
        ("escalate", "UDF / JMX",
         "# CVE-2021-44521: if CREATE FUNCTION is permitted, a scripted UDF escapes the\n"
         "# Nashorn sandbox -> RCE. Also check JMX on 7199 (mbean deploy).",
         "Turn CQL access into remote code execution via UDFs or JMX (in scope only)."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="cqlsh> ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "cassandra", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full Cassandra analysis. Returns {targets, findings, runbooks, probes, stats}."""
    from . import svcprobe
    targets = cassandra_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["unauth"] = pr.get("no_auth", False)
                t["cluster"] = pr.get("cluster", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
