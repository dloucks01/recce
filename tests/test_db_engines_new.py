"""High-fidelity tests for the new native database deep modules.

Each engine is driven against a REAL in-process fake server speaking its actual wire
protocol (memcached text, CouchDB/InfluxDB HTTP, Cassandra CQL binary, Oracle TNS,
Db2 DRDA/DDM) - so the stdlib probe, the findings, and the vuln conversion are all
exercised end to end, not mocked. Fast (localhost); not a real-nmap `slow` suite.
"""
import json
import socket
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from recce import cassandra, couchdb, db2, influxdb, memcached, oracle, vulndb
from recce.models import Host, Port


def _host(port, service):
    return Host(ip="127.0.0.1", ports=[Port(portid=port, service=service, state="open")])


def _tcp_once(handler):
    """Start a one-shot TCP server that hands each connection to `handler(conn)`. Returns
    the bound port. Serves in a daemon thread until the test process exits."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3)
                try:
                    handler(conn)
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return port


def _http_server(handler_cls):
    srv = HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


class Memcached(unittest.TestCase):
    def setUp(self):
        def handle(conn):
            buf = b""
            while True:
                data = conn.recv(1024)
                if not data:
                    return
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    cmd = line.decode().strip()
                    if cmd == "version":
                        conn.sendall(b"VERSION 1.4.15\r\n")
                    elif cmd == "stats":
                        conn.sendall(b"STAT version 1.4.15\r\nSTAT curr_items 2\r\n"
                                     b"STAT pointer_size 64\r\nEND\r\n")
                    elif cmd == "stats items":
                        conn.sendall(b"STAT items:1:number 2\r\nEND\r\n")
                    elif cmd.startswith("stats cachedump"):
                        conn.sendall(b"ITEM session:abc [9 b; 0 s]\r\n"
                                     b"ITEM apikey:x [4 b; 0 s]\r\nEND\r\n")
                    else:
                        conn.sendall(b"ERROR\r\n")
        self.port = _tcp_once(handle)

    def test_probe_and_findings(self):
        pr = memcached.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["version"], "1.4.15")
        self.assertIn("session:abc", pr["sample_keys"])
        fs = memcached.findings([_host(self.port, "memcached")],
                                {("127.0.0.1", self.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("memcached_unauth", kinds)
        self.assertIn("memcached_version", kinds)          # 1.4.15 < 1.4.32
        self.assertTrue(memcached.findings_to_vulns(fs))


class CouchDB(unittest.TestCase):
    def setUp(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _j(self, code, obj):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(obj).encode())

            def do_GET(self):
                if self.path == "/":
                    self._j(200, {"couchdb": "Welcome", "version": "2.1.0",
                                  "vendor": {"name": "Apache"}})
                elif self.path == "/_all_dbs":
                    self._j(200, ["_users", "customers", "secrets"])
                elif self.path in ("/_node/_local/_config", "/_config"):
                    self._j(200, {"admins": {}})            # admin party
                else:
                    self._j(404, {"error": "not_found"})
        self.port = _http_server(H)

    def test_admin_party_and_dbs(self):
        pr = couchdb.probe("127.0.0.1", self.port)
        self.assertTrue(pr["is_couchdb"] and pr["admin_party"] and pr["unauth_dbs"])
        self.assertEqual(pr["version"], "2.1.0")
        fs = couchdb.findings([_host(self.port, "couchdb")],
                              {("127.0.0.1", self.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertEqual({"couchdb_admin_party", "couchdb_unauth_dbs", "couchdb_version"},
                         kinds)
        crit = [f for f in fs if f["kind"] == "couchdb_admin_party"]
        self.assertEqual(crit[0]["severity"], "critical")


class InfluxDB(unittest.TestCase):
    def setUp(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/ping":
                    self.send_response(204)
                    self.send_header("X-Influxdb-Version", "1.6.4")
                    self.end_headers()
                elif self.path.startswith("/query"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(
                        {"results": [{"series": [{"columns": ["name"],
                         "values": [["_internal"], ["telemetry"]]}]}]}).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
        self.port = _http_server(H)

    def test_unauth_and_jwt(self):
        pr = influxdb.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["version"], "1.6.4")
        self.assertIn("telemetry", pr["dbs"])
        fs = influxdb.findings([_host(self.port, "influxdb")],
                               {("127.0.0.1", self.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("influxdb_unauth", kinds)
        self.assertIn("influxdb_jwt_bypass", kinds)          # 1.6.4 < 1.7.6


class Cassandra(unittest.TestCase):
    def setUp(self):
        def cqlstr(s):
            b = s.encode()
            return struct.pack(">H", len(b)) + b

        def frame(op, body, stream):
            return struct.pack(">BBhBI", 0x84, 0, stream, op, len(body)) + body

        def rows():
            cols = ["release_version", "cluster_name", "data_center", "partitioner"]
            vals = ["4.0.1", "Test Cluster", "dc1", "Murmur3Partitioner"]
            body = struct.pack(">I", 0x0002) + struct.pack(">I", 0x0001)
            body += struct.pack(">I", len(cols)) + cqlstr("system") + cqlstr("local")
            for c in cols:
                body += cqlstr(c) + struct.pack(">H", 0x000D)
            body += struct.pack(">I", 1)
            for v in vals:
                vb = v.encode()
                body += struct.pack(">i", len(vb)) + vb
            return body

        def handle(conn):
            head = conn.recv(9)
            _v, _f, s, _op, ln = struct.unpack(">BBhBI", head)
            conn.recv(ln)
            conn.sendall(frame(0x02, b"", s))                # READY
            head = conn.recv(9)
            _v, _f, s, _op, ln = struct.unpack(">BBhBI", head)
            conn.recv(ln)
            conn.sendall(frame(0x08, rows(), s))             # RESULT rows
        self.port = _tcp_once(handle)

    def test_noauth_and_fingerprint(self):
        pr = cassandra.probe("127.0.0.1", self.port)
        self.assertTrue(pr["no_auth"])
        self.assertEqual(pr["version"], "4.0.1")
        self.assertEqual(pr["cluster"], "Test Cluster")
        fs = cassandra.findings([_host(self.port, "cassandra")],
                                {("127.0.0.1", self.port): pr})
        self.assertIn("cassandra_noauth", {f["kind"] for f in fs})

    def test_authenticate_is_not_a_finding(self):
        # a node that requires auth must NOT be flagged as no_auth.
        def cqlstr(s):
            b = s.encode()
            return struct.pack(">H", len(b)) + b

        def handle(conn):
            head = conn.recv(9)
            _v, _f, s, _op, ln = struct.unpack(">BBhBI", head)
            conn.recv(ln)
            body = cqlstr("org.apache.cassandra.auth.PasswordAuthenticator")
            conn.sendall(struct.pack(">BBhBI", 0x84, 0, s, 0x03, len(body)) + body)
        port = _tcp_once(handle)
        pr = cassandra.probe("127.0.0.1", port)
        self.assertTrue(pr["is_cassandra"])
        self.assertFalse(pr["no_auth"])
        self.assertIn("PasswordAuthenticator", pr["authenticator"])


class OracleTNS(unittest.TestCase):
    def setUp(self):
        def handle(conn):
            conn.recv(4096)
            banner = (b" TNSLSNR for Linux: Version 19.3.0.0.0 - Production")
            pkt = bytearray(b"\x00\x00\x00\x00\x04\x00\x00\x00")   # type=4 REFUSE
            pkt += banner
            struct.pack_into(">H", pkt, 0, len(pkt))
            conn.sendall(bytes(pkt))
        self.port = _tcp_once(handle)

    def test_listener_confirmed_and_version_leak(self):
        pr = oracle.probe("127.0.0.1", self.port)
        self.assertTrue(pr["is_oracle"])
        self.assertEqual(pr["tns_type"], "REFUSE")
        self.assertEqual(pr["version"], "19.3.0.0.0")
        fs = oracle.findings([_host(self.port, "oracle-tns")],
                             {("127.0.0.1", self.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("oracle_tns_exposed", kinds)
        self.assertIn("oracle_version_leak", kinds)


class Db2DRDA(unittest.TestCase):
    def setUp(self):
        def ddm(cp, data):
            return struct.pack(">HH", len(data) + 4, cp) + data

        def handle(conn):
            conn.recv(4096)
            inner = (ddm(0x115E, b"DB2SERVER") + ddm(0x1147, b"QDB2/LINUXX8664")
                     + ddm(0x115A, b"SQL11055"))
            excsatrd = ddm(0x1443, inner)
            dss = struct.pack(">HBBH", len(excsatrd) + 6, 0xD0, 0x02, 1) + excsatrd
            conn.sendall(dss)
        self.port = _tcp_once(handle)

    def test_excsat_identity(self):
        pr = db2.probe("127.0.0.1", self.port)
        self.assertTrue(pr["is_db2"])
        self.assertEqual(pr["srvclsnm"], "QDB2/LINUXX8664")
        self.assertEqual(pr["version"], "11.5.5")
        fs = db2.findings([_host(self.port, "drda")], {("127.0.0.1", self.port): pr})
        self.assertIn("db2_exposed", {f["kind"] for f in fs})


class VulnDbSignatures(unittest.TestCase):
    """The version->CVE engine must map the new engines' banners to findings."""

    def _titles(self, service, version):
        p = Port(portid=1, service=service, product=service, version=version, state="open")
        return [v.title for v in vulndb.assess_host(Host(ip="1.1.1.1", ports=[p]))]

    def test_new_engine_cves(self):
        self.assertTrue(any("CouchDB" in t for t in self._titles("couchdb", "2.1.0")))
        self.assertTrue(any("InfluxDB" in t for t in self._titles("influxdb", "1.7.0")))
        self.assertTrue(any("Cassandra" in t for t in self._titles("cassandra", "")))
        self.assertTrue(any("Oracle" in t for t in self._titles("oracle-tns", "")))
        self.assertTrue(any("Db2" in t for t in self._titles("ibm-db2", "")))
        self.assertTrue(any("Memcached" in t for t in self._titles("memcached", "1.4.20")))

    def test_postgres_copy_program_and_redis_lua(self):
        self.assertTrue(any("COPY" in t for t in self._titles("postgresql", "14.2")))
        self.assertTrue(any("Lua" in t or "module-load" in t
                            for t in self._titles("redis", "7.0.0")))


class PostgresDeepRce(unittest.TestCase):
    """Trust-auth + superuser/COPY-FROM-PROGRAM capability -> a critical RCE finding."""

    def test_findings_emit_pg_rce_when_capable(self):
        from recce import postgres
        h = _host(5432, "postgresql")
        probes = {("127.0.0.1", 5432): {
            "unauth": True, "version": "16.2",
            "loot": {"databases": ["app"], "roles": [{"name": "postgres", "super": True}],
                     "hashes": [], "current_user": "postgres", "is_superuser": True,
                     "can_rce": True, "can_write_files": True,
                     "extensions": ["plpython3u"]}}}
        fs = postgres.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("pg_trust_auth", kinds)
        self.assertIn("pg_rce", kinds)
        rce = [f for f in fs if f["kind"] == "pg_rce"][0]
        self.assertEqual(rce["severity"], "critical")
        self.assertIn("COPY", rce["title"])

    def test_no_rce_finding_when_not_superuser(self):
        from recce import postgres
        h = _host(5432, "postgresql")
        probes = {("127.0.0.1", 5432): {"unauth": True, "version": "16.2",
                  "loot": {"databases": ["app"], "roles": [], "hashes": [],
                           "can_rce": False}}}
        fs = postgres.findings([h], probes)
        self.assertNotIn("pg_rce", {f["kind"] for f in fs})

    def test_loot_reads_rce_capability_over_the_wire(self):
        # Full v3 server: trust auth, then answer loot()'s queries in order so the
        # superuser / COPY-FROM-PROGRAM / extension capability is read live.
        from recce import postgres

        def msg(t, body):
            return t + struct.pack("!I", len(body) + 4) + body

        def datarow(vals):
            b = struct.pack("!H", len(vals))
            for v in vals:
                bb = v.encode()
                b += struct.pack("!i", len(bb)) + bb
            return msg(b"D", b)

        def result(rows):
            return b"".join(datarow(r) for r in rows) + msg(b"C", b"SELECT\x00") + msg(b"Z", b"I")

        # loot() query order: databases, pg_shadow, ident, pg_has_role, pg_extension.
        answers = [
            [["app_prod"], ["billing"]],
            [["postgres", "SCRAM-SHA-256$x", "t"]],
            [["postgres", "on", "PostgreSQL 16.2"]],
            [["t", "f", "t"]],                       # exec_program=t, read=f, write=t
            [["plpython3u"]],
        ]

        state = {"n": 0}

        def handle(conn):
            conn.recv(4096)                          # StartupMessage
            conn.sendall(msg(b"R", struct.pack("!I", 0)))
            conn.sendall(msg(b"S", b"server_version\x0016.2\x00"))
            conn.sendall(msg(b"Z", b"I"))
            while state["n"] < len(answers):
                data = conn.recv(65536)
                if not data:
                    return
                for _q in data.split(b"Q")[1:]:
                    if state["n"] < len(answers):
                        conn.sendall(result(answers[state["n"]]))
                        state["n"] += 1
        port = _tcp_once(handle)
        lt = postgres.loot("127.0.0.1", port)
        self.assertEqual(lt["databases"], ["app_prod", "billing"])
        self.assertTrue(lt["is_superuser"])
        self.assertTrue(lt["can_rce"])
        self.assertTrue(lt["can_copy_program"])
        self.assertTrue(lt["can_write_files"])
        self.assertIn("plpython3u", lt["extensions"])


class ScramVector(unittest.TestCase):
    """The SCRAM client must match the RFC 5802 published test vector."""

    def test_rfc5802_sha1(self):
        from recce import scram
        c = scram.ScramClient("user", "pencil", "SCRAM-SHA-1",
                              nonce="fyko+d2lbbFgONRv9qkxdawL")
        self.assertEqual(c.first_message(), "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL")
        sf = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
        self.assertEqual(
            c.final_message(sf),
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,"
            "p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=")
        self.assertTrue(c.verify("v=rmF9pqV8S7suAoZWja4dJRkFsKQ="))


import base64 as _b64
import hashlib as _hl
import hmac as _hm


def _scram_server(password, salt=b"recce-salt-16byt", iters=4096):
    """A minimal server-side SCRAM-SHA-256 verifier for the fake Postgres/Mongo servers:
    given the client-first-bare + client-final, confirm the proof and return the server
    signature (proving the client computed a correct proof against the real password)."""
    def server_first(client_nonce):
        snonce = client_nonce + "SRVnonce123"
        return f"r={snonce},s={_b64.b64encode(salt).decode()},i={iters}", snonce

    def verify_and_sign(cfb, sf, client_final):
        proof_b64 = dict(f.split("=", 1) for f in client_final.split(",") if "=" in f)["p"]
        cf_noproof = client_final.rsplit(",p=", 1)[0]
        auth = f"{cfb},{sf},{cf_noproof}"
        salted = _hl.pbkdf2_hmac("sha256", password.encode(), salt, iters)
        client_key = _hm.new(salted, b"Client Key", "sha256").digest()
        stored = _hl.sha256(client_key).digest()
        csig = _hm.new(stored, auth.encode(), "sha256").digest()
        recovered = bytes(a ^ b for a, b in zip(_b64.b64decode(proof_b64), csig))
        ok = _hl.sha256(recovered).digest() == stored
        server_key = _hm.new(salted, b"Server Key", "sha256").digest()
        ssig = _hm.new(server_key, auth.encode(), "sha256").digest()
        return ok, _b64.b64encode(ssig).decode()
    return server_first, verify_and_sign


class PostgresScramCredentialed(unittest.TestCase):
    """Credentialed follow-through: SCRAM-SHA-256 login with a supplied credential, then
    the full loot + RCE-capability read - all over a real handshake."""

    def setUp(self):
        server_first, verify_and_sign = _scram_server("Hunter2!")

        def msg(t, body):
            return t + struct.pack("!I", len(body) + 4) + body

        def datarow(vals):
            b = struct.pack("!H", len(vals))
            for v in vals:
                bb = v.encode()
                b += struct.pack("!i", len(bb)) + bb
            return msg(b"D", b)

        def result(rows):
            return b"".join(datarow(r) for r in rows) + msg(b"C", b"SELECT\x00") \
                + msg(b"Z", b"I")

        answers = [
            [["app_prod"]],                                  # databases
            [["postgres", "SCRAM-SHA-256$x", "t"]],          # pg_shadow
            [["app_svc", "on", "PostgreSQL 16.2"]],          # ident (superuser)
            [["t", "f", "f"]],                               # pg_has_role
            [["plpython3u"]],                                # extensions
        ]

        def read_msg(conn):
            hdr = conn.recv(1)
            if not hdr:
                return None, b""
            ln = struct.unpack("!I", conn.recv(4))[0]
            return hdr, conn.recv(ln - 4)

        def handle(conn):
            # startup (no type byte)
            ln = struct.unpack("!I", conn.recv(4))[0]
            conn.recv(ln - 4)
            conn.sendall(msg(b"R", struct.pack("!I", 10) + b"SCRAM-SHA-256\x00\x00"))
            _t, body = read_msg(conn)                        # SASLInitialResponse
            if not body or b"\x00" not in body:              # probe disconnected (unauth check)
                return
            mech, rest = body.split(b"\x00", 1)
            first = rest[4:].decode()
            cfb = first[3:] if first.startswith("n,,") else first
            client_nonce = dict(f.split("=", 1) for f in cfb.split(",") if "=" in f)["r"]
            sf, _snonce = server_first(client_nonce)
            conn.sendall(msg(b"R", struct.pack("!I", 11) + sf.encode()))
            _t, body = read_msg(conn)                        # SASLResponse (client-final)
            ok, ssig = verify_and_sign(cfb, sf, body.decode())
            if not ok:
                conn.sendall(msg(b"E", b"SFATAL\x00Cinvalid\x00Mbad proof\x00\x00"))
                return
            conn.sendall(msg(b"R", struct.pack("!I", 12) + f"v={ssig}".encode()))
            conn.sendall(msg(b"R", struct.pack("!I", 0)))    # AuthenticationOk
            conn.sendall(msg(b"S", b"server_version\x0016.2\x00"))
            conn.sendall(msg(b"Z", b"I"))
            n = 0
            while n < len(answers):
                t, _b = read_msg(conn)
                if t is None:
                    return
                if t == b"Q":
                    conn.sendall(result(answers[n])); n += 1
        self.port = _tcp_once(handle)

    def test_authenticate_and_loot(self):
        from recce import postgres
        self.assertTrue(postgres.authenticate("127.0.0.1", self.port, "app_svc", "Hunter2!"))
        self.assertFalse(postgres.authenticate("127.0.0.1", self.port, "app_svc", "wrong"))

    def test_credentialed_analyze_emits_rce(self):
        from recce import postgres
        h = _host(self.port, "postgresql")
        # probe() will see SASL -> auth_required; analyze sprays the supplied credential.
        analysis = postgres.analyze([h], creds=[{"username": "app_svc", "secret": "Hunter2!"}])
        kinds = {f["kind"] for f in analysis["findings"]}
        self.assertIn("pg_cred_access", kinds)
        self.assertIn("pg_rce", kinds)                       # is_superuser -> COPY FROM PROGRAM
        # the pg_shadow hash was captured as a credential
        self.assertTrue(any(c.username == "postgres" for c in analysis["credentials"]))


def _pg_trust_server(dispatch):
    """A trust-auth Postgres server that answers each simple query via dispatch(sql) ->
    list-of-rows (each row a list of str). Used for datamine / prove-RCE tests."""
    def msg(t, body):
        return t + struct.pack("!I", len(body) + 4) + body

    def datarow(vals):
        b = struct.pack("!H", len(vals))
        for v in vals:
            bb = str(v).encode()
            b += struct.pack("!i", len(bb)) + bb
        return msg(b"D", b)

    def result(rows):
        return b"".join(datarow(r) for r in rows) + msg(b"C", b"SELECT\x00") + msg(b"Z", b"I")

    def read_msg(conn):
        hdr = conn.recv(1)
        if not hdr:
            return None, b""
        ln = struct.unpack("!I", conn.recv(4))[0]
        return hdr, conn.recv(ln - 4)

    def handle(conn):
        ln = struct.unpack("!I", conn.recv(4))[0]             # StartupMessage length
        conn.recv(ln - 4)                                     # StartupMessage body
        conn.sendall(msg(b"R", struct.pack("!I", 0)))         # AuthenticationOk (trust)
        conn.sendall(msg(b"S", b"server_version\x0016.2\x00"))
        conn.sendall(msg(b"Z", b"I"))
        while True:
            t, body = read_msg(conn)
            if t is None or t == b"X":
                return
            if t == b"Q":
                sql = body.rstrip(b"\x00").decode("utf-8", "replace")
                conn.sendall(result(dispatch(sql)))
    return _tcp_once(handle)


class PostgresDatamine(unittest.TestCase):
    """Exfil: mine sensitive columns, sample redacted rows, harvest connection strings."""

    def _dispatch(self, sql):
        s = sql.lower()
        if "pg_database" in s:
            return [["app_prod"]]
        if "pg_shadow" in s:
            return [["postgres", "SCRAM-SHA-256$x", "t"]]
        if "current_user" in s:
            return [["postgres", "on", "PostgreSQL 16.2"]]
        if "pg_has_role" in s:
            return [["t", "f", "f"]]
        if "pg_extension" in s:
            return [["plpython3u"]]
        if "information_schema.columns" in s:
            return [["public", "users", "password"], ["public", "users", "email"],
                    ["public", "config", "conn_str"], ["public", "orders", "qty"]]
        if 'from "public"."users"' in s:
            return [["Sup3rSecret!", "alice@corp.example"]]
        if 'from "public"."config"' in s:
            return [["postgres://svc:hunter2@db2.internal:5432/app"]]
        return []

    def test_datamine_extracts_and_harvests(self):
        from recce import postgres
        port = _pg_trust_server(self._dispatch)
        dm = postgres.datamine("127.0.0.1", port, ["app_prod"], user="postgres")
        tables = {c["table"] for c in dm["secret_columns"]}
        self.assertIn("public.users", tables)
        self.assertIn("public.config", tables)
        # 'qty' is not sensitive
        self.assertFalse(any(c["column"] == "qty" for c in dm["secret_columns"]))
        # a sample was pulled and the value is REDACTED (not the full secret)
        self.assertTrue(dm["samples"])
        flat = str(dm["samples"])
        self.assertNotIn("Sup3rSecret!", flat)
        # the embedded connection string was harvested
        self.assertIn("postgres://svc:hunter2@db2.internal:5432/app", dm["harvested"])

    def test_analyze_emits_datamine_finding_and_cred(self):
        from recce import postgres
        port = _pg_trust_server(self._dispatch)
        h = _host(port, "postgresql")
        analysis = postgres.analyze([h])
        kinds = {f["kind"] for f in analysis["findings"]}
        self.assertIn("pg_datamine", kinds)
        dmf = [f for f in analysis["findings"] if f["kind"] == "pg_datamine"][0]
        self.assertIn("sensitive", dmf["title"].lower())
        # harvested connection string became a sprayable credential
        self.assertTrue(any(c.source == "postgres-datamine" for c in analysis["credentials"]))


class PostgresRceProof(unittest.TestCase):
    """Foothold: opt-in benign COPY-FROM-PROGRAM `id` proof confirms RCE."""

    def _dispatch(self, sql):
        s = sql.lower()
        if "select o from recce_rce" in s:
            return [["uid=114(postgres) gid=120(postgres) groups=120(postgres)"]]
        if "pg_database" in s:
            return [["app_prod"]]
        if "pg_shadow" in s:
            return [["postgres", "x", "t"]]
        if "current_user" in s:
            return [["postgres", "on", "PostgreSQL 16.2"]]
        if "pg_has_role" in s:
            return [["t", "f", "f"]]
        if "pg_extension" in s or "information_schema" in s:
            return []
        return []

    def test_prove_rce_runs_id(self):
        from recce import postgres
        port = _pg_trust_server(self._dispatch)
        out = postgres.prove_rce("127.0.0.1", port, user="postgres")
        self.assertIn("uid=114(postgres)", out)

    def test_analyze_prove_confirms_rce(self):
        from recce import postgres
        port = _pg_trust_server(self._dispatch)
        h = _host(port, "postgresql")
        analysis = postgres.analyze([h], prove=True, datamine_data=False)
        rce = [f for f in analysis["findings"] if f["kind"] == "pg_rce"]
        self.assertTrue(rce)
        self.assertIn("RCE CONFIRMED", rce[0]["detail"])
        self.assertIn("uid=114(postgres)", rce[0]["detail"])

    def test_default_analyze_does_not_prove(self):
        # RCE proof is OPT-IN: a plain analyze() must NOT execute COPY FROM PROGRAM.
        from recce import postgres
        port = _pg_trust_server(self._dispatch)
        h = _host(port, "postgresql")
        analysis = postgres.analyze([h], datamine_data=False)   # prove defaults False
        rce = [f for f in analysis["findings"] if f["kind"] == "pg_rce"]
        self.assertTrue(rce)                                    # capability still reported
        self.assertNotIn("RCE CONFIRMED", rce[0]["detail"])     # but not executed


class PostgresProveEngine(unittest.TestCase):
    """The prove/verify engine recognizes the postgres RCE / datamine / access findings."""

    def _verdict(self, title, output=""):
        from recce import proofs
        from recce.models import Vuln
        v = Vuln(ip="1.1.1.1", port=5432, protocol="tcp", script_id="postgres",
                 title=title, output=output)
        r = proofs.recipe_for(v)
        self.assertIsNotNone(r, f"no recipe for {title!r}")
        verdict, lines = r["fn"](None, 5432, v)
        return r["id"], verdict, " ".join(lines)

    def test_rce_recipe_confirms_and_mentions_proof(self):
        rid, verdict, text = self._verdict(
            "PostgreSQL unauthenticated RCE (trust-auth superuser -> COPY FROM PROGRAM)",
            "RCE CONFIRMED (recce ran a benign `id` ...): uid=114(postgres)")
        self.assertEqual(rid, "postgres-rce")
        self.assertEqual(verdict, proofs_CONFIRMED())
        self.assertIn("RCE CONFIRMED", text)

    def test_datamine_recipe(self):
        rid, verdict, text = self._verdict(
            "PostgreSQL sensitive data exposed (PII / secrets / credentials)")
        self.assertEqual(rid, "postgres-datamine")
        self.assertIn("sampled rows", text)

    def test_access_recipe(self):
        rid, _v, _t = self._verdict("PostgreSQL trust authentication (no password required)")
        self.assertEqual(rid, "postgres-access")


def proofs_CONFIRMED():
    from recce import proofs
    return proofs.CONFIRMED


class RedisDeepPrimitives(unittest.TestCase):
    """Deep probe surfaces which RCE primitives are actually reachable."""

    def _resp_read(self, conn):
        buf = b""
        while b"\r\n" not in buf:
            d = conn.recv(1024)
            if not d:
                return None
            buf += d
        line, rest = buf.split(b"\r\n", 1)
        n = int(line[1:])
        args = []
        while len(args) < n:
            while rest.count(b"\r\n") < 2:
                rest += conn.recv(1024)
            _len, rest = rest.split(b"\r\n", 1)
            val, rest = rest.split(b"\r\n", 1)
            args.append(val.decode())
        return args

    def test_module_load_and_replication_surface(self):
        from recce import redis
        info = ("# Server\r\nredis_version:6.2.7\r\nos:Linux\r\n"
                "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n"
                "# Keyspace\r\ndb0:keys=3,expires=0\r\n")

        def handle(conn):
            while True:
                cmd = self._resp_read(conn)
                if not cmd:
                    return
                name = cmd[0].upper()
                sub = cmd[1].upper() if len(cmd) > 1 else ""
                if name == "PING":
                    conn.sendall(b"+PONG\r\n")
                elif name == "INFO":
                    b = info.encode()
                    conn.sendall(b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n")
                elif name == "CONFIG" and sub == "GET":
                    val = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb",
                           "appendonly": "no", "save": "3600 1"}.get(cmd[2], "")
                    conn.sendall(b"*2\r\n$" + str(len(cmd[2])).encode() + b"\r\n"
                                 + cmd[2].encode() + b"\r\n$" + str(len(val)).encode()
                                 + b"\r\n" + val.encode() + b"\r\n")
                elif name == "MODULE" and sub == "LIST":
                    # one loaded module, RESP array-of-array
                    conn.sendall(b"*1\r\n*4\r\n$4\r\nname\r\n$6\r\nsearch\r\n"
                                 b"$3\r\nver\r\n:20000\r\n")
                elif name == "ACL" and sub == "WHOAMI":
                    conn.sendall(b"$7\r\ndefault\r\n")
                elif name == "ACL" and sub == "LIST":
                    conn.sendall(b"*1\r\n$28\r\nuser default on nopass ~* +@all\r\n")
                else:
                    conn.sendall(b"+OK\r\n")
        port = _tcp_once(handle)
        pr = redis.probe("127.0.0.1", port)
        self.assertTrue(pr["unauth"])
        self.assertTrue(pr["module_load"])
        self.assertIn("search", pr["modules"])
        self.assertEqual(pr["acl_user"], "default")
        self.assertTrue(pr["acl_default_nopass"])
        self.assertTrue(pr["persistence"])           # save = "3600 1"
        fs = redis.findings([_host(port, "redis")], {("127.0.0.1", port): pr})
        detail = [f for f in fs if f["kind"] == "redis_unauth"][0]["detail"]
        self.assertIn("MODULE LOAD", detail)
        self.assertIn("SLAVEOF", detail)
        self.assertIn("search", detail)


class MongoDeepLoot(unittest.TestCase):
    """Unauth MongoDB deep pass: captured users, replica-set members, config leak."""

    def setUp(self):
        from recce import mongodb as M

        def e_double(n, v):
            return b"\x01" + M._cstr(n) + struct.pack("<d", v)

        def e_bool(n, v):
            return b"\x08" + M._cstr(n) + bytes([1 if v else 0])

        def e_doc(n, d):
            return b"\x03" + M._cstr(n) + d

        def e_array(n, docs):
            inner = M.bson_doc(*[e_doc(str(i), d) for i, d in enumerate(docs)])
            return b"\x04" + M._cstr(n) + inner

        hello = M.bson_doc(e_bool("isWritablePrimary", True),
                           M._e_int32("maxWireVersion", 17), e_double("ok", 1.0))
        build = M.bson_doc(M._e_str("version", "6.0.1"),
                           M._e_str("javascriptEngine", "mozjs"), e_double("ok", 1.0))
        listdbs = M.bson_doc(
            e_array("databases", [M.bson_doc(M._e_str("name", "prod"),
                                             e_double("sizeOnDisk", 9990.0))]),
            e_double("totalSize", 9990.0), e_double("ok", 1.0))
        admin_user = M.bson_doc(
            M._e_str("user", "admin"), M._e_str("db", "admin"),
            e_array("roles", [M.bson_doc(M._e_str("role", "root"),
                                         M._e_str("db", "admin"))]),
            e_doc("credentials", M.bson_doc(e_doc("SCRAM-SHA-256", M.bson_doc(
                M._e_int32("iterationCount", 15000))))))
        usersinfo = M.bson_doc(e_array("users", [admin_user]), e_double("ok", 1.0))
        replstatus = M.bson_doc(
            M._e_str("set", "rs0"),
            e_array("members", [M.bson_doc(M._e_str("name", "mongo1:27017")),
                                M.bson_doc(M._e_str("name", "mongo2:27017"))]),
            e_double("ok", 1.0))
        cmdlineopts = M.bson_doc(
            e_doc("parsed", M.bson_doc(e_doc("net", M.bson_doc(
                M._e_str("bindIp", "0.0.0.0"))))), e_double("ok", 1.0))
        self._replies = {"hello": hello, "buildInfo": build, "listDatabases": listdbs,
                         "usersInfo": usersinfo, "replSetGetStatus": replstatus,
                         "getCmdLineOpts": cmdlineopts}

        def handle(conn):
            while True:
                hdr = M._recvn(conn, 16)
                if len(hdr) < 16:
                    return
                length = struct.unpack("<i", hdr[:4])[0]
                rid = struct.unpack("<i", hdr[4:8])[0]
                body = M._recvn(conn, length - 16)
                doc, _ = M.bson_parse(hdr + body, 16 + 4 + 1)
                cmd = next(iter(doc), "")
                reply = self._replies.get(cmd) or M.bson_doc(
                    M._e_str("errmsg", "no such command"), e_double("ok", 0.0))
                conn.sendall(M.op_msg(rid, reply))
        self.port = _tcp_once(handle)

    def test_deep_fields_captured(self):
        from recce import mongodb as M
        pr = M.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["js_engine"], "mozjs")
        self.assertEqual([u["user"] for u in pr["users"]], ["admin"])
        self.assertIn("SCRAM-SHA-256", pr["users"][0]["mechanisms"])
        self.assertIn("root", pr["users"][0]["roles"])
        self.assertEqual(pr["replset"], "rs0")
        self.assertIn("mongo2:27017", pr["replset_members"])
        self.assertFalse(pr["auth_configured"])
        fs = M.findings([_host(self.port, "mongodb")], {("127.0.0.1", self.port): pr})
        detail = fs[0]["detail"]
        self.assertIn("CAPTURED 1 user", detail)
        self.assertIn("Replica set 'rs0'", detail)
        self.assertIn("mozjs", detail)


class MssqlNtlmLeak(unittest.TestCase):
    """Native pre-auth NTLM-over-TDS leak (no nmap): domain / FQDN / OS from Type-2."""

    def _type2(self):
        def av(av_id, s):
            b = s.encode("utf-16-le")
            return struct.pack("<HH", av_id, len(b)) + b
        target_info = (av(0x0002, "CONTOSO") + av(0x0001, "SQL01")
                       + av(0x0004, "contoso.local") + av(0x0003, "sql01.contoso.local")
                       + struct.pack("<HH", 0x0000, 0))          # EOL
        flags = 0x02000000 | 0x00000001                          # NEGOTIATE_VERSION | UNICODE
        version = bytes([10, 0]) + struct.pack("<H", 17763) + b"\x00\x00\x00\x0f"
        ti_off = 56
        msg = (b"NTLMSSP\x00" + struct.pack("<I", 2)
               + struct.pack("<HHI", 0, 0, 56)                   # TargetName fields (empty)
               + struct.pack("<I", flags)
               + b"\x11\x22\x33\x44\x55\x66\x77\x88"             # ServerChallenge
               + b"\x00" * 8                                     # Reserved
               + struct.pack("<HHI", len(target_info), len(target_info), ti_off)
               + version + target_info)
        return msg

    def setUp(self):
        t2 = self._type2()

        def handle(conn):
            conn.recv(4096)                                      # PRELOGIN
            # minimal PRELOGIN response (version option + encryption off)
            pre = struct.pack(">BHH", 0x00, 8 + 5 + 1, 6) + b"\xff" \
                + bytes([16, 0]) + struct.pack(">H", 4711) + b"\x00\x00"
            conn.sendall(struct.pack(">BBHHBB", 0x04, 0x01, 8 + len(pre), 0, 0, 0) + pre)
            conn.recv(65536)                                     # LOGIN7
            payload = b"\xed" + struct.pack("<H", len(t2)) + t2  # SSPI token wrapper
            conn.sendall(struct.pack(">BBHHBB", 0x04, 0x01, 8 + len(payload), 0, 0, 0)
                         + payload)
        self.port = _tcp_once(handle)

    def test_ntlm_info_extracts_identity(self):
        from recce import mssql
        nt = mssql.ntlm_info("127.0.0.1", self.port)
        self.assertEqual(nt["nb_domain"], "CONTOSO")
        self.assertEqual(nt["nb_computer"], "SQL01")
        self.assertEqual(nt["dns_domain"], "contoso.local")
        self.assertEqual(nt["dns_computer"], "sql01.contoso.local")
        self.assertEqual(nt["os_version"], "10.0.17763")

    def test_finding_uses_native_ntlm(self):
        from recce import mssql
        nt = mssql.ntlm_info("127.0.0.1", self.port)
        h = _host(1433, "ms-sql-s")
        fs = mssql.findings([h], {"127.0.0.1:1433": {"ntlm": nt, "prelogin": {}}})
        nd = [f for f in fs if f["kind"] == "ntlm_disclosure"]
        self.assertTrue(nd)
        self.assertIn("CONTOSO", nd[0]["detail"])
        self.assertIn("sql01.contoso.local", nd[0]["detail"])


class MysqlGreetingDepth(unittest.TestCase):
    """Handshake parsing surfaces the auth plugin + TLS capability; no-TLS is flagged."""

    def test_greeting_parses_ssl_and_plugin(self):
        from recce import mysql
        # v10 greeting: version, conn id, auth1(8), filler, caps_lo(SSL+PLUGIN_AUTH),
        # charset, status, caps_hi, ...  ending in the auth-plugin name.
        caps_lo = 0x0800 | 0x0200          # CLIENT_SSL | CLIENT_PROTOCOL_41
        payload = (bytes([10]) + b"8.0.36\x00" + struct.pack("<I", 7)
                   + b"\x00" * 8 + b"\x00"
                   + struct.pack("<H", caps_lo) + b"\x21" + struct.pack("<H", 2)
                   + struct.pack("<H", 0x0008)          # caps_hi -> CLIENT_PLUGIN_AUTH
                   + bytes([21]) + b"\x00" * 10 + b"\x00" * 13
                   + b"caching_sha2_password\x00")
        g = mysql._greeting(payload)
        self.assertTrue(g["ssl"])
        self.assertEqual(g["auth_plugin"], "caching_sha2_password")

    def test_no_tls_finding(self):
        from recce import mysql
        h = _host(3306, "mysql")
        probes = {("127.0.0.1", 3306): {"reachable": True, "version": "5.7.30",
                  "ssl": False, "unauth": False, "auth_required": True}}
        fs = mysql.findings([h], probes)
        self.assertIn("mysql_no_tls", {f["kind"] for f in fs})


class ElasticDeep(unittest.TestCase):
    """Unauth ES deep pass adds node OS/JVM + snapshot-repo enumeration to the finding."""

    def setUp(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _j(self, obj):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(obj).encode())

            def do_GET(self):
                if self.path == "/":
                    self._j({"name": "es01", "cluster_name": "logs",
                             "version": {"number": "7.10.0"},
                             "tagline": "You Know, for Search"})
                elif self.path.startswith("/_cat/indices"):
                    self._j([{"index": "app-logs", "docs.count": "9000"}])
                elif self.path == "/_cluster/health":
                    self._j({"status": "green", "number_of_nodes": 3})
                elif self.path.startswith("/_nodes/_local"):
                    self._j({"nodes": {"x": {"os": {"pretty_name": "Ubuntu 20.04"},
                                             "jvm": {"version": "15.0.1"}}}})
                elif self.path == "/_snapshot/_all":
                    self._j({"backups": {"type": "fs"}})
                else:
                    self.send_response(404)
                    self.end_headers()
        self.port = _http_server(H)

    def test_deep_fields_in_finding(self):
        from recce import elasticsearch as es
        pr = es.probe("127.0.0.1", self.port)
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["os_name"], "Ubuntu 20.04")
        self.assertEqual(pr["jvm_version"], "15.0.1")
        self.assertIn("backups", pr["snapshot_repos"])
        fs = es.findings([_host(self.port, "elasticsearch")], {("127.0.0.1", self.port): pr})
        detail = fs[0]["detail"]
        self.assertIn("Ubuntu 20.04", detail)
        self.assertIn("Snapshot repositories", detail)


class MongoScramCredentialed(unittest.TestCase):
    """SCRAM login + hashcat-format extraction of MongoDB SCRAM credentials."""

    def test_hashcat_format(self):
        from recce import mongodb as M
        line = M._scram_hashcat("admin", "SCRAM-SHA-256",
                                {"iterationCount": 15000, "salt": "c2FsdA==",
                                 "serverKey": "c2s=", "storedKey": "c3Q="})
        self.assertTrue(line.startswith("$mongodb-scram$*1*"))   # *1* = SHA-256 (24200)
        self.assertIn("*15000*", line)
        self.assertIn("c2FsdA==", line)
        line1 = M._scram_hashcat("u", "SCRAM-SHA-1",
                                 {"iterationCount": 10000, "salt": "s", "serverKey": "k"})
        self.assertTrue(line1.startswith("$mongodb-scram$*0*"))  # *0* = SHA-1 (24100)
        self.assertEqual(M._scram_hashcat("u", "SCRAM-SHA-1", {}), "")  # missing material

    def _server(self, password, want_creds=True):
        from recce import mongodb as M
        server_first, verify_and_sign = _scram_server(password)

        def e_double(n, v):
            return b"\x01" + M._cstr(n) + struct.pack("<d", v)

        def e_doc(n, d):
            return b"\x03" + M._cstr(n) + d

        def e_array(n, docs):
            return b"\x04" + M._cstr(n) + M.bson_doc(*[e_doc(str(i), d)
                                                       for i, d in enumerate(docs)])
        unauth_err = M.bson_doc(e_double("ok", 0.0), M._e_int32("code", 13),
                                M._e_str("errmsg", "command requires authentication"))

        def handle(conn):
            st = {"authed": False, "cfb": None, "snonce": None}   # per-connection

            def reply_for(doc):
                cmd = next(iter(doc), "")
                if cmd == "hello":
                    return M.bson_doc(M._e_int32("maxWireVersion", 17), e_double("ok", 1.0))
                if cmd == "buildInfo":
                    return M.bson_doc(M._e_str("version", "6.0.1"), e_double("ok", 1.0))
                if cmd == "saslStart":
                    cf = doc["payload"].decode()
                    cfb = cf[3:] if cf.startswith("n,,") else cf
                    cnonce = dict(f.split("=", 1) for f in cfb.split(",") if "=" in f)["r"]
                    sf, _sn = server_first(cnonce)
                    st["snonce"], st["cfb"] = sf, cfb
                    return M.bson_doc(M._e_int32("conversationId", 1),
                                      M._e_bool("done", False),
                                      M._e_binary("payload", sf.encode()), e_double("ok", 1.0))
                if cmd == "saslContinue":
                    cfinal = doc["payload"].decode()
                    if not cfinal:
                        return M.bson_doc(M._e_bool("done", True), e_double("ok", 1.0))
                    ok, ssig = verify_and_sign(st["cfb"], st["snonce"], cfinal)
                    if not ok:
                        return M.bson_doc(e_double("ok", 0.0),
                                          M._e_str("errmsg", "auth failed"))
                    st["authed"] = True
                    return M.bson_doc(M._e_int32("conversationId", 1),
                                      M._e_bool("done", True),
                                      M._e_binary("payload", f"v={ssig}".encode()),
                                      e_double("ok", 1.0))
                # everything below requires authentication (this instance has auth on).
                if not st["authed"]:
                    return unauth_err
                if cmd == "listDatabases":
                    return M.bson_doc(e_array("databases",
                        [M.bson_doc(M._e_str("name", "prod"), e_double("sizeOnDisk", 9.0))]),
                        e_double("ok", 1.0))
                if cmd == "usersInfo":
                    cred = M.bson_doc(M._e_int32("iterationCount", 15000),
                                      M._e_str("salt", "c2FsdA=="),
                                      M._e_str("serverKey", "c2VydmVyS2V5"),
                                      M._e_str("storedKey", "c3RvcmVk")) if want_creds \
                        else M.bson_doc()
                    user = M.bson_doc(M._e_str("user", "admin"), M._e_str("db", "admin"),
                                      e_array("roles", [M.bson_doc(M._e_str("role", "root"),
                                                                   M._e_str("db", "admin"))]),
                                      e_doc("credentials",
                                            M.bson_doc(e_doc("SCRAM-SHA-256", cred))))
                    return M.bson_doc(e_array("users", [user]), e_double("ok", 1.0))
                return M.bson_doc(M._e_str("errmsg", "no such command"), e_double("ok", 0.0))

            while True:
                hdr = M._recvn(conn, 16)
                if len(hdr) < 16:
                    return
                length = struct.unpack("<i", hdr[:4])[0]
                rid = struct.unpack("<i", hdr[4:8])[0]
                body = M._recvn(conn, length - 16)
                doc, _ = M.bson_parse(hdr + body, 16 + 4 + 1)
                conn.sendall(M.op_msg(rid, reply_for(doc)))
        return _tcp_once(handle)

    def test_authenticate(self):
        from recce import mongodb as M
        port = self._server("Secret1!")
        self.assertTrue(M.authenticate("127.0.0.1", port, "admin", "Secret1!"))
        self.assertFalse(M.authenticate("127.0.0.1", port, "admin", "wrong"))

    def test_credentialed_probe_extracts_hashcat(self):
        from recce import mongodb as M
        port = self._server("Secret1!")
        cp = M.probe_creds("127.0.0.1", port, "admin", "Secret1!")
        self.assertTrue(cp["cred_access"])
        self.assertEqual([u["user"] for u in cp["users"]], ["admin"])
        self.assertTrue(cp["hashes"])
        self.assertTrue(cp["hashes"][0]["hashcat"].startswith("$mongodb-scram$*1*"))

    def test_analyze_credentialed_finding_and_loot(self):
        from recce import mongodb as M
        port = self._server("Secret1!")
        # probe() (unauth listDatabases) will fail auth -> analyze sprays the credential.
        h = _host(port, "mongodb")
        analysis = M.analyze([h], creds=[{"username": "admin", "secret": "Secret1!"}])
        kinds = {f["kind"] for f in analysis["findings"]}
        self.assertIn("mongo_cred_access", kinds)
        self.assertTrue(any(c.kind == "hash" and "24200" in (c.notes or "")
                            for c in analysis["credentials"]))


class MongoDatamine(unittest.TestCase):
    """Exfil: sample documents, flag sensitive fields, harvest connection strings."""

    def setUp(self):
        from recce import mongodb as M

        def e_double(n, v):
            return b"\x01" + M._cstr(n) + struct.pack("<d", v)

        def e_doc(n, d):
            return b"\x03" + M._cstr(n) + d

        def e_array(n, docs):
            return b"\x04" + M._cstr(n) + M.bson_doc(*[e_doc(str(i), d)
                                                       for i, d in enumerate(docs)])

        def cursor(docs):
            return M.bson_doc(e_doc("cursor", M.bson_doc(e_array("firstBatch", docs))),
                              e_double("ok", 1.0))

        hello = M.bson_doc(M._e_int32("maxWireVersion", 17), e_double("ok", 1.0))
        listdbs = M.bson_doc(e_array("databases", [M.bson_doc(M._e_str("name", "prod"),
                             e_double("sizeOnDisk", 9.0))]), e_double("ok", 1.0))
        collections = cursor([M.bson_doc(M._e_str("name", "customers")),
                              M.bson_doc(M._e_str("name", "system.indexes"))])
        doc = M.bson_doc(
            M._e_str("email", "alice@corp.example"),
            M._e_str("ssn", "123-45-6789"),
            e_doc("meta", M.bson_doc(M._e_str("api_token", "SEKRET-TOKEN-9999"))),
            M._e_str("note", "backup at mongodb://svc:hunter2@m2.internal:27017/prod"))
        find = cursor([doc])

        def handle(conn):
            while True:
                hdr = M._recvn(conn, 16)
                if len(hdr) < 16:
                    return
                length = struct.unpack("<i", hdr[:4])[0]
                rid = struct.unpack("<i", hdr[4:8])[0]
                body = M._recvn(conn, length - 16)
                d, _ = M.bson_parse(hdr + body, 16 + 4 + 1)
                cmd = next(iter(d), "")
                reply = {"hello": hello, "buildInfo": M.bson_doc(
                            M._e_str("version", "6.0.1"), e_double("ok", 1.0)),
                         "listDatabases": listdbs, "listCollections": collections,
                         "find": find}.get(cmd) or M.bson_doc(
                             M._e_str("errmsg", "no"), e_double("ok", 0.0))
                conn.sendall(M.op_msg(rid, reply))
        self.port = _http_or_tcp = _tcp_once(handle)

    def test_datamine_fields_and_harvest(self):
        from recce import mongodb as M
        dm = M.datamine("127.0.0.1", self.port, ["prod"])
        fields = {f["field"] for f in dm["secret_fields"]}
        self.assertIn("email", fields)
        self.assertIn("ssn", fields)
        self.assertIn("meta.api_token", fields)          # nested field flattened
        self.assertNotIn("note", fields)                 # name not sensitive...
        self.assertIn("mongodb://svc:hunter2@m2.internal:27017/prod", dm["harvested"])
        # values are redacted, not dumped in full
        self.assertNotIn("SEKRET-TOKEN-9999", str(dm["samples"]))

    def test_analyze_emits_datamine_finding_and_cred(self):
        from recce import mongodb as M
        h = _host(self.port, "mongodb")
        analysis = M.analyze([h])
        kinds = {f["kind"] for f in analysis["findings"]}
        self.assertIn("mongo_datamine", kinds)
        self.assertTrue(any(c.source == "mongodb-datamine" for c in analysis["credentials"]))


def _mysql_server(dispatch, password=None):
    """Fake MySQL server: v10 handshake (with a real salt), optional native-password
    scramble verification, and COM_QUERY result sets via dispatch(sql) -> list-of-rows."""
    salt = bytes((i % 250) + 1 for i in range(20))

    def pkt(payload, seq):
        return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload

    def lenstr(s):
        b = str(s).encode()
        return bytes([len(b)]) + b

    def result_set(rows):
        ncol = len(rows[0]) if rows else 1
        eof = b"\xfe\x00\x00\x02\x00"
        out = pkt(bytes([ncol]), 1)
        seq = 2
        for _ in range(ncol):
            out += pkt(b"\x03def", seq); seq += 1
        out += pkt(eof, seq); seq += 1
        for row in rows:
            body = b"".join(b"\xfb" if v is None else lenstr(v) for v in row)
            out += pkt(body, seq); seq += 1
        out += pkt(eof, seq)
        return out

    def greeting():
        auth1, auth2 = salt[:8], salt[8:20] + b"\x00"
        return (bytes([10]) + b"8.0.36\x00" + struct.pack("<I", 7) + auth1 + b"\x00"
                + struct.pack("<H", 0x0200) + b"\x21" + struct.pack("<H", 2)
                + struct.pack("<H", 0x0008) + bytes([21]) + b"\x00" * 10 + auth2
                + b"mysql_native_password\x00")

    def read_pkt(conn):
        hdr = conn.recv(4)
        if len(hdr) < 4:
            return None
        ln = struct.unpack("<I", hdr[:3] + b"\x00")[0]
        return conn.recv(ln)

    def verify(resp):
        # HandshakeResponse41: caps(4) maxpkt(4) charset(1) reserved(23) user\0 tokenlen token ...
        i = 4 + 4 + 1 + 23
        j = resp.index(b"\x00", i)
        i = j + 1
        tlen = resp[i]; i += 1
        token = resp[i:i + tlen]
        if password is None:
            return True                                # empty-password server accepts all
        import hashlib
        stored = hashlib.sha1(hashlib.sha1(password.encode()).digest()).digest()
        recovered = bytes(a ^ b for a, b in
                          zip(token, hashlib.sha1(salt[:20] + stored).digest()))
        return hashlib.sha1(recovered).digest() == stored

    def handle(conn):
        conn.sendall(pkt(greeting(), 0))
        resp = read_pkt(conn)
        if resp is None:
            return
        if not verify(resp):
            conn.sendall(pkt(b"\xff\x15\x04Access denied", 2))     # ERR
            return
        conn.sendall(pkt(b"\x00\x00\x00\x02\x00\x00\x00", 2))      # OK
        while True:
            p = read_pkt(conn)
            if p is None:
                return
            if p[:1] == b"\x03":
                conn.sendall(result_set(dispatch(p[1:].decode("utf-8", "replace"))))
    return _tcp_once(handle)


class MysqlCredentialedDatamine(unittest.TestCase):
    """MySQL: credentialed login, FILE-privilege privesc, and data exfiltration."""

    def _dispatch(self, sql):
        s = sql.lower()
        if "mysql.user" in s:
            return [["root", "localhost", "*ABC", "mysql_native_password"]]
        if "show databases" in s:
            return [["app"], ["information_schema"]]
        if "current_user()" in s:
            return [["root@localhost", "", "/usr/lib/mysql/plugin/", "linux"]]
        if "show grants" in s:
            return [["GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost'"]]
        if "information_schema.columns" in s:
            return [["app", "users", "password"], ["app", "users", "email"],
                    ["app", "orders", "qty"]]
        if "from `app`.`users`" in s:
            return [["Secr3tValue!", "alice@corp.example"]]
        return []

    def test_native_scramble_and_authenticate(self):
        from recce import mysql
        port = _mysql_server(self._dispatch, password="Hunter2x")
        self.assertTrue(mysql.authenticate("127.0.0.1", port, "root", "Hunter2x"))
        self.assertFalse(mysql.authenticate("127.0.0.1", port, "root", "wrong"))

    def test_loot_detects_file_priv(self):
        from recce import mysql
        port = _mysql_server(self._dispatch)
        lt = mysql.loot("127.0.0.1", port, user="root")
        self.assertTrue(lt["file_priv"])
        self.assertEqual(lt["secure_file_priv"], "")

    def test_datamine_and_finding(self):
        from recce import mysql
        port = _mysql_server(self._dispatch)
        dm = mysql.datamine("127.0.0.1", port, ["app"], user="root")
        cols = {c["column"] for c in dm["secret_columns"]}
        self.assertIn("password", cols)
        self.assertIn("email", cols)
        self.assertNotIn("qty", cols)
        self.assertNotIn("Secr3tValue!", str(dm["samples"]))       # redacted
        # analyze emits the file-priv + datamine findings
        h = _host(port, "mysql")
        analysis = mysql.analyze([h])
        kinds = {f["kind"] for f in analysis["findings"]}
        self.assertIn("mysql_file_priv", kinds)
        self.assertIn("mysql_datamine", kinds)


class DbPocRecipes(unittest.TestCase):
    """Confirmed DB findings must scaffold an initial-PoC harness (the poc phase)."""

    def test_finding_text_maps_to_recipe(self):
        from recce import poc
        cases = {
            "Redis exposed without authentication. Write primitive available "
            "(dir=/var/lib/redis) -> arbitrary file write / RCE.": "redis_rce",
            "Apache CouchDB 'admin party' (no admin configured)": "couchdb_rce",
            "PostgreSQL trust authentication (no password required)": "postgres_rce",
            "memcached exposed without authentication; 3 items cached": "db_unauth_read",
            "Apache Cassandra exposed - no authentication (AllowAll)": "db_unauth_read",
            "InfluxDB exposed - unauthenticated query API": "db_unauth_read",
        }
        for text, expected in cases.items():
            self.assertEqual(poc.recipe_key_for(text), expected, text[:50])

    def test_recipes_write_runnable_files(self):
        import os
        import tempfile
        from recce import poc
        recipes = {k: poc.RECIPES[k] for k in
                   ("redis_rce", "couchdb_rce", "postgres_rce", "db_unauth_read")}
        d = tempfile.mkdtemp()
        written = poc.write_files(d, recipes)
        names = {os.path.basename(f) for f in written}
        self.assertIn("recce_poc_redis_rce.sh", names)
        self.assertIn("recce_poc_db_read.sh", names)
        for f in written:
            with open(f) as fh:
                self.assertIn("#!/bin/sh", fh.read())


if __name__ == "__main__":
    unittest.main()
