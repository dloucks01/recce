"""Deep MongoDB enumeration (stdlib only).

MongoDB wire protocol (OP_MSG, opcode 2013) with a minimal BSON encoder/decoder,
hand-rolled on a raw socket - no pymongo. Airgapped, stdlib only.

  * **hello / buildInfo:** version, replica-set role (always answerable).
  * **listDatabases WITHOUT authentication:** the discriminator. If it returns the
    database list, the instance is exposed unauthenticated - anyone on the network
    reads (and usually writes) every database. If it errors "not authorized", auth is
    enforced (recce reports it reachable-but-locked, not a finding).

Positive findings fold into the severity totals, the Vulnerabilities sheet, the
write-ups, a dedicated **MongoDB** tab, and the prove engine. Safety posture: see
SECURITY.md.
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port

_PORTS = (27017, 27018, 27019)
_DEFAULT_PORT = 27017
_TIMEOUT = 5.0
_MAX_BSON_DEPTH = 100                                  # real replies nest a few levels;
                                                       # anything deeper is hostile.


def is_mongodb(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    return "mongo" in f"{port.service} {port.product}".lower()


# --- minimal BSON ---------------------------------------------------------------

def _cstr(s: str) -> bytes:
    return s.encode("utf-8") + b"\x00"


def _e_int32(name: str, v: int) -> bytes:
    return b"\x10" + _cstr(name) + struct.pack("<i", v)


def _e_str(name: str, v: str) -> bytes:
    b = v.encode("utf-8") + b"\x00"
    return b"\x02" + _cstr(name) + struct.pack("<i", len(b)) + b


def bson_doc(*elements: bytes) -> bytes:
    body = b"".join(elements)
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def bson_parse(data: bytes, i: int = 0, _depth: int = 0) -> tuple[dict, int]:
    """Parse a BSON document at offset i. Returns (dict, index-after-document).
    Hardened against a hostile/corrupt document: a negative or non-advancing length
    field is rejected instead of spinning the loop forever, and nesting is capped so
    a maliciously deep document can't blow the Python stack with a RecursionError
    that the caller (command) doesn't catch."""
    length = struct.unpack_from("<i", data, i)[0]
    if length < 5:                                     # a BSON doc is >= 5 bytes
        return {}, i + 4
    end = min(i + length, len(data))
    if _depth > _MAX_BSON_DEPTH:                        # refuse hostile nesting depth
        return {}, end
    i += 4
    out: dict = {}
    while i < end - 1:
        etype = data[i]
        i += 1
        j = data.index(0, i)
        name = data[i:j].decode("utf-8", "replace")
        i = j + 1
        if etype == 0x01:                              # double
            out[name] = struct.unpack_from("<d", data, i)[0]
            i += 8
        elif etype == 0x02:                            # string
            slen = struct.unpack_from("<i", data, i)[0]
            i += 4
            if slen < 1:                               # reject negative/zero -> no loop stall
                break
            out[name] = data[i:i + slen - 1].decode("utf-8", "replace")
            i += slen
        elif etype == 0x03:                            # embedded document
            out[name], i = bson_parse(data, i, _depth + 1)
        elif etype == 0x04:                            # array (doc with "0","1",... keys)
            sub, i = bson_parse(data, i, _depth + 1)
            # BSON arrays use decimal string keys; a hostile daemon could send
            # non-numeric ones. Sort numeric keys, keep any stragglers by insertion
            # order, rather than letting int() blow away the whole reply.
            out[name] = [sub[k] for k in sorted(sub, key=lambda x: (0, int(x))
                                                if x.isdigit() else (1, 0))]
        elif etype == 0x05:                            # binary
            blen = struct.unpack_from("<i", data, i)[0]
            if blen < 0:
                break
            i += 4 + 1 + blen
            out[name] = None
        elif etype == 0x07:                            # ObjectId
            out[name] = data[i:i + 12].hex()
            i += 12
        elif etype == 0x08:                            # bool
            out[name] = bool(data[i])
            i += 1
        elif etype == 0x09:                            # UTC datetime
            out[name] = struct.unpack_from("<q", data, i)[0]
            i += 8
        elif etype == 0x0A:                            # null
            out[name] = None
        elif etype == 0x10:                            # int32
            out[name] = struct.unpack_from("<i", data, i)[0]
            i += 4
        elif etype == 0x11:                            # timestamp
            out[name] = struct.unpack_from("<Q", data, i)[0]
            i += 8
        elif etype == 0x12:                            # int64
            out[name] = struct.unpack_from("<q", data, i)[0]
            i += 8
        else:                                          # unknown type - stop safely
            break
    return out, end


# --- OP_MSG wire ----------------------------------------------------------------

def op_msg(request_id: int, doc: bytes) -> bytes:
    body = struct.pack("<I", 0) + b"\x00" + doc        # flagBits=0, section kind 0 (body)
    header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013)
    return header + body


def _recvn(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def command(sock, doc: bytes, request_id: int, timeout: float) -> dict | None:
    """Send one OP_MSG command, return the parsed BSON reply (or None)."""
    try:
        sock.sendall(op_msg(request_id, doc))
        sock.settimeout(timeout)
        hdr = _recvn(sock, 4)
        if len(hdr) < 4:
            return None
        length = struct.unpack("<i", hdr)[0]
        if length < 5 or length > 16 * 1024 * 1024:    # sane bound; a hostile daemon
            return None                                 # can't make us buffer ~2 GB
        rest = _recvn(sock, length - 4)
        msg = hdr + rest
        # The BSON body offset depends on the reply opcode: OP_MSG (2013) has
        # header(16) + flagBits(4) + kind(1) = 21; legacy OP_REPLY (1) has a 20-byte
        # reply header after the 16-byte msg header = 36. Read the opcode (bytes
        # 12..16) instead of assuming OP_MSG so pre-3.6 servers still fingerprint.
        opcode = struct.unpack_from("<i", msg, 12)[0]
        body_at = 36 if opcode == 1 else 21
        reply, _ = bson_parse(msg, body_at)
        return reply
    except (OSError, struct.error, IndexError, ValueError):
        return None


def _hello(sock, rid, timeout):
    return command(sock, bson_doc(_e_int32("hello", 1), _e_str("$db", "admin")),
                   rid, timeout)


def _build_info(sock, rid, timeout):
    return command(sock, bson_doc(_e_int32("buildInfo", 1), _e_str("$db", "admin")),
                   rid, timeout)


def _list_databases(sock, rid, timeout):
    return command(sock, bson_doc(_e_int32("listDatabases", 1), _e_str("$db", "admin")),
                   rid, timeout)


# --- probe ----------------------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict | None:
    """Unauthenticated MongoDB probe. Returns None if the port didn't speak MongoDB."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            hello = _hello(s, 1, timeout)
            if not isinstance(hello, dict) or "maxWireVersion" not in hello:
                return None                            # not MongoDB
            out = {"ip": ip, "port": port,
                   "primary": bool(hello.get("isWritablePrimary")
                                   or hello.get("ismaster")),
                   "set_name": hello.get("setName", ""),
                   "max_wire": hello.get("maxWireVersion")}
            bi = _build_info(s, 2, timeout)
            out["version"] = (bi or {}).get("version", "")
            ld = _list_databases(s, 3, timeout)
            if isinstance(ld, dict) and ld.get("ok") == 1.0 and "databases" in ld:
                out["unauth"] = True
                out["databases"] = [{"name": d.get("name", ""),
                                     "size": d.get("sizeOnDisk", 0)}
                                    for d in ld["databases"] if isinstance(d, dict)]
                out["total_size"] = ld.get("totalSize", 0)
            else:
                out["unauth"] = False
                out["auth_error"] = (ld or {}).get("errmsg", "") if isinstance(ld, dict) else ""
            return out
    except OSError:
        return None


def mongodb_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_mongodb(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "mongo_unauth": (
        "The MongoDB instance accepts commands with no authentication - recce listed "
        "every database without a credential. That means full read (and, by default, "
        "write) access to all data: dump collections, exfiltrate PII/secrets, tamper "
        "with or ransom the data. This is one of the most common and highest-impact "
        "internet/intranet exposures. Enable authentication (--auth) and bind the "
        "listener to a trusted interface immediately."),
    "mongo_version": (
        "The MongoDB build is old / end-of-life. Beyond the missing security fixes, "
        "pre-2.6 defaults exposed the HTTP/REST interfaces and pre-3.0 shipped with no "
        "authentication out of the box - confirm the running config and upgrade."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Handshake (stdlib OP_MSG / BSON)",
     "recce speaks the MongoDB wire protocol directly - no pymongo. It sends hello + "
     "buildInfo to read the version and replica-set role."),
    ("2. Unauthenticated access test",
     "It runs listDatabases with no credential. If the database list comes back, the "
     "instance is exposed unauthenticated (critical); an 'authorized' error means auth "
     "is enforced (reachable but locked - not a finding)."),
    ("3. Vulnerability identification",
     "An unauthenticated instance is a CONFIRMED critical exposure with the database "
     "inventory captured. An old/EOL build is flagged for its default-open history."),
    ("4. Runbook",
     "The exact follow-on commands (mongosh, mongodump, nmap mongodb-databases) are "
     "staged per endpoint."),
]


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "mongodb", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def _old_version(ver: str) -> bool:
    try:
        major = int(ver.split(".")[0])
        return major < 4
    except (ValueError, IndexError):
        return False


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_mongodb(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            if pr.get("unauth"):
                dbs = pr.get("databases") or []
                names = ", ".join(d["name"] for d in dbs[:12])
                out.append(_finding(
                    "critical", "MongoDB exposed without authentication", tgt,
                    f"recce listed {len(dbs)} database(s) with no credential"
                    + (f" (version {ver})" if ver else "") + f": {names}. Full "
                    "unauthenticated read/write access to all data.",
                    "mongosh / mongodump",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval 'db.adminCommand("
                    "{listDatabases:1})'   # then mongodump --host "
                    f"{h.ip} --port {p.portid} --out loot/",
                    "Enable authentication (security.authorization: enabled), create "
                    "admin users, and bind the listener to a trusted interface only.",
                    ["CWE-306", "CWE-284"], kind="mongo_unauth"))
            if ver and _old_version(ver):
                out.append(_finding(
                    "medium", "MongoDB end-of-life / legacy build", tgt,
                    f"MongoDB {ver} is past end-of-life - missing security fixes, and the "
                    "pre-3.0 line shipped auth-off by default.",
                    "mongosh",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval 'db.version()'",
                    "Upgrade to a supported MongoDB release.",
                    ["CWE-1104"], kind="mongo_version"))
    return out


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", f"nmap -p{port} --script mongodb-info,mongodb-databases "
         f"{ip}", "Server info + database list (confirms unauth)."),
        ("enumerate", "mongosh", f"mongosh mongodb://{ip}:{port}/ --eval "
         "'db.adminCommand({listDatabases:1})'", "List databases without credentials."),
        ("loot", "mongodump", f"mongodump --host {ip} --port {port} --out loot/mongo/",
         "Dump every database to disk for offline analysis."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="> ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "mongodb", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full MongoDB analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = mongodb_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["unauth"] = pr.get("unauth", False)
                t["version"] = pr.get("version", "")
                t["databases"] = len(pr.get("databases") or [])
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
