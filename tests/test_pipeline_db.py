"""Offline tests split out of tests/test_pipeline.py.

Every test class here is what the original monolith called it. Shared
helpers (header_index, _docx_text, _self_response) live in _pipeline_helpers."""
"""Offline tests for the enumeration pipeline (no network / nmap needed)."""

import contextlib
import io
import os
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce import ad, exploits, parser, scanner
from recce import tracking as tr
from recce import xlsx
from recce.models import Account, Host, Port, Script, Vuln
from recce.report_excel import (build_workbook, read_workbook_tracking,
                                       update_workbook)
from recce.store import Store
from recce.targets import apply_exclusions, load_targets

SAMPLE = os.path.join(os.path.dirname(parser.__file__), "sample_scan.xml")


from _pipeline_helpers import header_index, _docx_text, _self_response, SAMPLE  # noqa: F401





class DatabaseModuleTest(unittest.TestCase):
    def test_engine_detection(self):
        from recce import db
        self.assertEqual(db.engine_for(Port(portid=3306)), "mysql")
        self.assertEqual(db.engine_for(Port(portid=1433)), "mssql")
        self.assertEqual(db.engine_for(Port(portid=9999, service="postgresql")), "postgresql")
        self.assertIsNone(db.engine_for(Port(portid=80, service="http")))

    def test_db_instances(self):
        from recce import db
        from recce.models import Vuln
        h = Host(ip="10.0.0.9", ports=[Port(portid=3306, service="mysql",
                 product="MySQL", version="5.7.38")])
        h.vulns = [Vuln(ip="10.0.0.9", port=3306, protocol="tcp",
                        script_id="mysql-empty-password", title="Database account "
                        "with empty password", severity="high")]
        inst = db.db_instances([h])
        self.assertEqual(len(inst), 1)
        self.assertEqual(inst[0]["engine"], "mysql")
        self.assertEqual(inst[0]["auth"], "EMPTY PASSWORD")

    def test_script_selection_aggressive(self):
        from recce import db
        safe = db.script_selection(False)
        aggr = db.script_selection(True)
        self.assertIn("mysql-info", safe)
        self.assertNotIn("mysql-brute", safe)
        self.assertIn("mysql-brute", aggr)




class MongodbTest(unittest.TestCase):
    """Deep MongoDB module: BSON round-trip, a mock wire-protocol server (hello /
    buildInfo / listDatabases), unauth detection, findings, prove, `recce mongodb`."""

    @classmethod
    def setUpClass(cls):
        import socketserver
        import threading
        import struct
        from recce import mongodb as M

        def e_double(name, v):
            return b"\x01" + M._cstr(name) + struct.pack("<d", v)

        def e_bool(name, v):
            return b"\x08" + M._cstr(name) + bytes([1 if v else 0])

        def e_doc(name, doc):
            return b"\x03" + M._cstr(name) + doc

        def e_array(name, docs):
            inner = M.bson_doc(*[e_doc(str(i), d) for i, d in enumerate(docs)])
            return b"\x04" + M._cstr(name) + inner

        hello = M.bson_doc(e_bool("isWritablePrimary", True),
                           M._e_int32("maxWireVersion", 17),
                           e_double("ok", 1.0))
        build = M.bson_doc(M._e_str("version", "6.0.1"), e_double("ok", 1.0))
        dbs = e_array("databases", [
            M.bson_doc(M._e_str("name", "admin"), e_double("sizeOnDisk", 4096.0)),
            M.bson_doc(M._e_str("name", "config"), e_double("sizeOnDisk", 8192.0)),
            M.bson_doc(M._e_str("name", "loot"), e_double("sizeOnDisk", 999.0)),
        ])
        listdbs = M.bson_doc(dbs, e_double("totalSize", 12288.0), e_double("ok", 1.0))
        cls._replies = {"hello": hello, "buildInfo": build, "listDatabases": listdbs}

        replies = cls._replies

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                while True:
                    hdr = M._recvn(sock, 16)
                    if len(hdr) < 16:
                        return
                    length, rid = struct.unpack("<i", hdr[:4])[0], \
                        struct.unpack("<i", hdr[4:8])[0]
                    body = M._recvn(sock, length - 16)
                    msg = hdr + body
                    try:
                        doc, _ = M.bson_parse(msg, 16 + 4 + 1)
                    except (IndexError, ValueError, struct.error):
                        return
                    cmd = next(iter(doc), "")
                    reply = replies.get(cmd)
                    if reply is None:
                        reply = M.bson_doc(M._e_str("errmsg", "no such command"),
                                           e_double("ok", 0.0))
                    sock.sendall(M.op_msg(rid, reply))

        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_bson_roundtrip(self):
        from recce import mongodb as M
        doc = M.bson_doc(M._e_int32("a", 7), M._e_str("b", "hi"))
        parsed, _ = M.bson_parse(doc, 0)
        self.assertEqual(parsed, {"a": 7, "b": "hi"})

    def test_probe_detects_unauth(self):
        from recce import mongodb as M
        pr = M.probe("127.0.0.1", self.port, timeout=3.0)
        self.assertIsNotNone(pr)
        self.assertEqual(pr["version"], "6.0.1")
        self.assertTrue(pr["unauth"])
        self.assertEqual([d["name"] for d in pr["databases"]],
                         ["admin", "config", "loot"])

    def test_findings_and_prove(self):
        from recce import mongodb as M, proofs
        pr = M.probe("127.0.0.1", self.port, timeout=3.0)
        h = Host(ip="10.0.7.7",
                 ports=[Port(portid=27017, service="mongodb", state="open")])
        fs = M.findings([h], {("10.0.7.7", 27017): pr})
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("MongoDB exposed without authentication", titles)
        crit = [f for f in fs if f["severity"] == "critical"]
        self.assertTrue(crit)
        h.vulns = M.findings_to_vulns(fs)["10.0.7.7"]
        verdicts = [r["verdict"] for r in proofs.verify_host(h)]
        self.assertIn(proofs.CONFIRMED, verdicts)

    def test_cmd_mongodb_end_to_end(self):
        from recce import cli, xlsx, mongodb as M
        from recce.store import Store
        orig = M.is_mongodb
        M.is_mongodb = lambda p: (p.state == "open"
                                  and (p.portid == self.port or orig(p)))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=self.port, state="open",
                                                service="mongodb")]))
                st.close()
                rc = cli.main(["mongodb", "-o", out])
                self.assertEqual(rc, 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("MongoDB", sheets)
                vtxt = "\n".join(" ".join(map(str, r))
                                 for r in sheets["Vulnerabilities"])
                self.assertIn("MongoDB", vtxt)
                st = Store(os.path.join(out, "results.sqlite"))
                h = st.get_host("127.0.0.1")
                st.close()
                self.assertTrue([v for v in h.vulns if v.source == "mongodb"])
        finally:
            M.is_mongodb = orig

    def test_no_endpoints_is_graceful(self):
        from recce import cli
        from recce.store import Store
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "eng")
            os.makedirs(out)
            st = Store(os.path.join(out, "results.sqlite"))
            st.upsert_host(Host(ip="10.0.0.9", ports=[Port(portid=22, service="ssh")]))
            st.close()
            self.assertEqual(cli.main(["mongodb", "-o", out, "--no-probe"]), 0)




class RedisTest(unittest.TestCase):
    """Deep Redis module: RESP parse, a mock RESP server (PING/INFO/CONFIG), unauth
    detection, findings, prove, `recce redis`."""

    @classmethod
    def setUpClass(cls):
        import socketserver
        import threading

        def bulk(s):
            b = s.encode()
            return b"$" + str(len(b)).encode() + b"\r\n" + b + b"\r\n"

        def arr(*items):
            out = b"*" + str(len(items)).encode() + b"\r\n"
            return out + b"".join(bulk(i) for i in items)

        info = ("# Server\r\nredis_version:5.0.7\r\nos:Linux\r\nredis_mode:standalone\r\n"
                "# Keyspace\r\ndb0:keys=42,expires=0\r\n")
        cfg = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb",
               "requirepass": "", "protected-mode": "no"}

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.settimeout(3.0)
                buf = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                    except OSError:
                        return
                    if not chunk:
                        return
                    buf += chunk
                    # Parse each complete command (array of bulk strings) we have.
                    while True:
                        try:
                            val, n = __import__("recce.redis", fromlist=["_parse"])._parse(buf, 0)
                        except Exception:
                            break
                        buf = buf[n:]
                        args = val if isinstance(val, list) else [val]
                        cmd = (args[0] or "").upper() if args else ""
                        if cmd == "PING":
                            sock.sendall(b"+PONG\r\n")
                        elif cmd == "INFO":
                            sock.sendall(bulk(info))
                        elif cmd == "CONFIG" and len(args) >= 3:
                            sock.sendall(arr(args[2], cfg.get(args[2], "")))
                        else:
                            sock.sendall(b"-ERR unknown\r\n")

        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        cls.srv.daemon_threads = True
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_resp_parse_types(self):
        from recce import redis as R
        self.assertEqual(R._parse(b"+OK\r\n")[0], "OK")
        self.assertEqual(R._parse(b":7\r\n")[0], 7)
        self.assertEqual(R._parse(b"$3\r\nabc\r\n")[0], "abc")
        self.assertEqual(R._parse(b"*2\r\n$1\r\na\r\n$1\r\nb\r\n")[0], ["a", "b"])
        self.assertIsInstance(R._parse(b"-NOAUTH x\r\n")[0], R._Err)
        with self.assertRaises(R._Incomplete):
            R._parse(b"$5\r\nab")

    def test_probe_detects_unauth(self):
        from recce import redis as R
        pr = R.probe("127.0.0.1", self.port, timeout=3.0)
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["version"], "5.0.7")
        self.assertEqual(pr["keys"], 42)
        self.assertEqual(pr["dir"], "/var/lib/redis")

    def test_findings_and_prove(self):
        from recce import redis as R, proofs
        pr = R.probe("127.0.0.1", self.port, timeout=3.0)
        h = Host(ip="10.0.9.9", ports=[Port(portid=6379, service="redis", state="open")])
        fs = R.findings([h], {("10.0.9.9", 6379): pr})
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("Redis exposed without authentication", titles)
        self.assertIn("Redis end-of-life", titles)          # 5.0.7 < 6.0
        h.vulns = R.findings_to_vulns(fs)["10.0.9.9"]
        self.assertIn(proofs.CONFIRMED, [r["verdict"] for r in proofs.verify_host(h)])

    def test_cmd_redis_end_to_end(self):
        from recce import cli, xlsx, redis as R
        from recce.store import Store
        orig = R.is_redis
        R.is_redis = lambda p: p.state == "open" and (p.portid == self.port or orig(p))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=self.port, state="open",
                                                service="redis")]))
                st.close()
                self.assertEqual(cli.main(["redis", "-o", out]), 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("Redis", sheets)
                vtxt = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
                self.assertIn("Redis", vtxt)
        finally:
            R.is_redis = orig




class ElasticsearchTest(unittest.TestCase):
    """Deep Elasticsearch module: a mock HTTP API (/ banner + /_cat/indices), unauth
    detection, findings, prove, `recce elasticsearch`."""

    @classmethod
    def setUpClass(cls):
        import http.server
        import json as _json
        import threading

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, obj):
                body = _json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/":
                    self._send({"name": "es01", "cluster_name": "prod",
                                "version": {"number": "6.8.0", "lucene_version": "7.7.0"},
                                "tagline": "You Know, for Search"})
                elif self.path.startswith("/_cat/indices"):
                    self._send([{"index": "logs-2024", "docs.count": "1500"},
                                {"index": "users", "docs.count": "40"},
                                {"index": ".kibana", "docs.count": "3"}])
                elif self.path.startswith("/_cluster/health"):
                    self._send({"status": "green"})
                else:
                    self._send({})

        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_probe_detects_unauth(self):
        from recce import elasticsearch as E
        pr = E.probe("127.0.0.1", self.port, timeout=3.0)
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["version"], "6.8.0")
        self.assertIn("logs-2024", pr["indices"])
        self.assertEqual(pr["docs"], 1543)
        self.assertEqual(pr["status"], "green")

    def test_findings_and_prove(self):
        from recce import elasticsearch as E, proofs
        pr = E.probe("127.0.0.1", self.port, timeout=3.0)
        h = Host(ip="10.0.9.8", ports=[Port(portid=9200, service="http", state="open")])
        fs = E.findings([h], {("10.0.9.8", 9200): pr})
        titles = " ".join(f["title"] for f in fs)
        self.assertIn("Elasticsearch exposed without authentication", titles)
        self.assertIn("Elasticsearch end-of-life", titles)     # 6.8 < 7
        h.vulns = E.findings_to_vulns(fs)["10.0.9.8"]
        self.assertIn(proofs.CONFIRMED, [r["verdict"] for r in proofs.verify_host(h)])

    def test_cmd_elasticsearch_end_to_end(self):
        from recce import cli, xlsx, elasticsearch as E
        from recce.store import Store
        orig = E.is_elasticsearch
        E.is_elasticsearch = lambda p: (p.state == "open"
                                        and (p.portid == self.port or orig(p)))
        try:
            with tempfile.TemporaryDirectory() as d:
                out = os.path.join(d, "eng")
                os.makedirs(out)
                st = Store(os.path.join(out, "results.sqlite"))
                st.upsert_host(Host(ip="127.0.0.1",
                                    ports=[Port(portid=self.port, state="open",
                                                service="http")]))
                st.close()
                self.assertEqual(cli.main(["elasticsearch", "-o", out]), 0)
                sheets = xlsx.read_sheets(os.path.join(out, "enumeration.xlsx"))
                self.assertIn("Elasticsearch", sheets)
                vtxt = "\n".join(" ".join(map(str, r)) for r in sheets["Vulnerabilities"])
                self.assertIn("Elasticsearch", vtxt)
        finally:
            E.is_elasticsearch = orig
