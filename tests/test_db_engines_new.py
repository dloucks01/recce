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
