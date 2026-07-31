"""Live end-to-end smoke test: real localhost services, driven through the recce CLI.

Every other test either mocks the network or replays canned bytes into one function.
This one stands up REAL listening services on 127.0.0.1 and runs the actual `recce`
command line an operator would type, proving the whole
    scan -> parse -> probe -> fold -> report
path holds together against live sockets rather than fixtures.

Two paths are covered:
  * test_sweep_probes_live_services - seed a datastore pointing at live web / mongodb
    / ftp servers, run `recce sweep`, and assert real findings from those live probes
    land in the datastore and the regenerated workbook.
  * test_enum_discovers_live_port - run a REAL nmap-backed `recce enum` against a live
    HTTP server and assert the open port is discovered and stored (skipped when nmap
    is not installed, so the suite still passes on a bare box).
"""
import os
import shutil
import socket
import socketserver
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce import cli
from recce import mongodb as M
from recce.store import Store


# --- live servers ---------------------------------------------------------------

class _WebHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = (b"<html><head><title>Index of /</title></head>"
                b"<body>Directory listing for /</body></html>")
        self.send_response(200)
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Set-Cookie", "SESSIONID=live123; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# Common web ports nmap scans in its default top-ports list, so a fast enum finds
# them without a full -p- sweep. We bind the live web server to the first one free.
_COMMON_WEB_PORTS = (8080, 8000, 8888, 8081, 9090, 8443)


def _start_web():
    """Bind the live web server to a common (nmap-top-ports) port when one is free,
    else fall back to an ephemeral port. Returns (srv, port, is_common)."""
    for p in _COMMON_WEB_PORTS:
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), _WebHandler)
        except OSError:
            continue
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, p, True
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _WebHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1], False


def _start_ftp():
    """A real FTP control channel: 220 greeting, anonymous login, AUTH TLS, SYST."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]
    stop = threading.Event()

    replies = {
        b"FEAT": b"211-Features:\r\n AUTH TLS\r\n211 End\r\n",
        b"USER": b"331 Please specify the password.\r\n",
        b"PASS": b"230 Login successful.\r\n",
        b"SYST": b"215 UNIX Type: L8\r\n",
        b"QUIT": b"221 Goodbye.\r\n",
    }

    def serve():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    def handle(conn):
        try:
            with conn:
                conn.sendall(b"220 ProFTPD 1.3.5 Server ready\r\n")
                buf = b""
                while True:
                    chunk = conn.recv(1024)
                    if not chunk:
                        return
                    buf += chunk
                    while b"\r\n" in buf:
                        line, buf = buf.split(b"\r\n", 1)
                        conn.sendall(replies.get(line[:4].strip(), b"500 ?\r\n"))
                        if line[:4].strip() == b"QUIT":
                            return
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, port, stop


def _start_mongo():
    """A real MongoDB wire server that answers hello / buildInfo / listDatabases
    WITHOUT auth - so mongodb.probe() reports a CONFIRMED unauth exposure."""
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
                       M._e_int32("maxWireVersion", 17), e_double("ok", 1.0))
    build = M.bson_doc(M._e_str("version", "6.0.1"), e_double("ok", 1.0))
    dbs = e_array("databases", [
        M.bson_doc(M._e_str("name", "admin"), e_double("sizeOnDisk", 4096.0)),
        M.bson_doc(M._e_str("name", "loot"), e_double("sizeOnDisk", 9990.0)),
    ])
    listdbs = M.bson_doc(dbs, e_double("totalSize", 14086.0), e_double("ok", 1.0))
    replies = {"hello": hello, "isMaster": hello, "ismaster": hello,
               "buildInfo": build, "listDatabases": listdbs}

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            while True:
                hdr = M._recvn(sock, 16)
                if len(hdr) < 16:
                    return
                length, rid = (struct.unpack("<i", hdr[:4])[0],
                               struct.unpack("<i", hdr[4:8])[0])
                body = M._recvn(sock, length - 16)
                try:
                    doc, _ = M.bson_parse(hdr + body, 16 + 4 + 1)
                except (IndexError, ValueError, struct.error):
                    return
                cmd = next(iter(doc), "")
                reply = replies.get(cmd) or M.bson_doc(
                    M._e_str("errmsg", "no such command"), e_double("ok", 0.0))
                sock.sendall(M.op_msg(rid, reply))

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _nmap_xml(path, web_port, mongo_port, ftp_port):
    """A minimal nmap XML pointing recce at the three live services on 127.0.0.1.
    Service names (not ports) are what the deep modules key off, so ephemeral ports
    are fine."""
    def port_xml(pid, svc, product=""):
        prod = f' product="{product}"' if product else ""
        return (f'<port protocol="tcp" portid="{pid}">'
                f'<state state="open" reason="syn-ack"/>'
                f'<service name="{svc}"{prod}/></port>')
    with open(path, "w") as fh:
        fh.write(
            '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap">\n'
            '<host><status state="up" reason="syn-ack"/>'
            '<address addr="127.0.0.1" addrtype="ipv4"/>'
            '<hostnames><hostname name="live.local" type="PTR"/></hostnames>'
            '<ports>'
            + port_xml(web_port, "http", "nginx")
            + port_xml(mongo_port, "mongodb")
            + port_xml(ftp_port, "ftp", "ProFTPD")
            + '</ports></host></nmaprun>\n')


class LiveSweepSmokeTest(unittest.TestCase):

    def setUp(self):
        self.dir = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), f"recce_live_{os.getpid()}")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        self.web_srv, self.web_port, self.web_common = _start_web()
        self.mongo_srv, self.mongo_port = _start_mongo()
        self.ftp_srv, self.ftp_port, self.ftp_stop = _start_ftp()

    def tearDown(self):
        self.web_srv.shutdown(); self.web_srv.server_close()
        self.mongo_srv.shutdown(); self.mongo_srv.server_close()
        self.ftp_stop.set(); self.ftp_srv.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_sweep_probes_live_services(self):
        xml = os.path.join(self.dir, "seed.xml")
        _nmap_xml(xml, self.web_port, self.mongo_port, self.ftp_port)

        # 1. Seed the datastore through the real CLI.
        rc = cli.main(["import", xml, "-o", self.dir, "--title", "LIVE"])
        self.assertEqual(rc, 0)

        # 2. Run the grouped deep-enum sweep against the LIVE services.
        rc = cli.main(["sweep", "-o", self.dir,
                       "--only-modules", "web", "mongodb", "ftp"])
        self.assertIn(rc, (0, 1))            # 1 only if a module errored

        # 3. The datastore must carry real findings produced by the live probes.
        store = Store(os.path.join(self.dir, "results.sqlite"))
        try:
            host = next(h for h in store.all_hosts() if h.ip == "127.0.0.1")
            vulns = host.vulns
            sources = {v.source for v in vulns}
            titles = " ".join(v.title.lower() for v in vulns)
            blob = store.get_meta("mongodb")
        finally:
            store.close()

        self.assertTrue(vulns, "no findings folded from the live sweep")
        # MongoDB unauth exposure is the headline live-probe result.
        self.assertIn("mongodb", sources)
        self.assertTrue(blob, "mongodb analysis blob not persisted")
        self.assertIn("6.0.1", blob)         # version read off the live wire server
        self.assertIn("unauth", blob.lower())
        # Web probe reached the live server (cookie / dir-listing finding).
        self.assertTrue(any(s in titles for s in ("cookie", "directory listing")),
                        f"expected a web finding, got: {titles}")

        # 4. Reports were regenerated once, and reflect the live findings.
        for name in ("enumeration.xlsx", "enumeration.md", "report.html"):
            self.assertTrue(os.path.getsize(os.path.join(self.dir, name)) > 0)
        with open(os.path.join(self.dir, "enumeration.md")) as fh:
            md = fh.read()
        self.assertIn("127.0.0.1", md)

    @unittest.skipUnless(shutil.which("nmap"), "nmap not installed")
    def test_enum_discovers_live_port(self):
        """Real nmap path: scan the live HTTP server and confirm the open port is
        discovered, parsed and stored. Uses a fast top-ports scan against a common
        web port (skips if every common port was already taken on this box)."""
        if not self.web_common:
            self.skipTest("no common web port was free to bind the live server to")
        d2 = self.dir + "_enum"
        shutil.rmtree(d2, ignore_errors=True)
        try:
            rc = cli.main(["enum", "127.0.0.1", "-o", d2, "--title", "ENUM",
                           "--top-ports", "10000", "--no-os", "--no-udp-fallback"])
            self.assertEqual(rc, 0)
            store = Store(os.path.join(d2, "results.sqlite"))
            try:
                host = next((h for h in store.all_hosts()
                             if h.ip == "127.0.0.1"), None)
                self.assertIsNotNone(host, "nmap enum did not store 127.0.0.1")
                open_ports = {p.portid for p in host.open_ports}
            finally:
                store.close()
            self.assertIn(self.web_port, open_ports,
                          f"live web port {self.web_port} not discovered; "
                          f"found {sorted(open_ports)}")
        finally:
            shutil.rmtree(d2, ignore_errors=True)


class SweepWiringTest(unittest.TestCase):
    """The `sweep` selection logic (--only-modules / --skip) and single report
    rebuild, exercised against the bundled sample scan - no live servers needed."""

    def setUp(self):
        import recce
        self.dir = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), f"recce_sweepwire_{os.getpid()}")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        sample = os.path.join(os.path.dirname(recce.__file__), "sample_scan.xml")
        self.assertTrue(os.path.exists(sample), "bundled sample_scan.xml missing")
        self.assertEqual(cli.main(["import", sample, "-o", self.dir]), 0)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _run_capture(self, argv):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(argv)
        return rc, buf.getvalue()

    def test_only_modules_limits_what_runs(self):
        rc, out = self._run_capture(
            ["sweep", "-o", self.dir, "--no-probe", "--only-modules", "web", "smb"])
        self.assertIn(rc, (0, 1))
        self.assertIn("[SWEEP] web", out)
        self.assertIn("[SWEEP] smb", out)
        self.assertNotIn("[SWEEP] ldap", out)
        self.assertNotIn("[SWEEP] mongodb", out)
        # Exactly one workbook rebuild despite two modules (deferral worked).
        self.assertEqual(out.count("Reports written"), 1)

    def test_skip_excludes_modules(self):
        rc, out = self._run_capture(
            ["sweep", "-o", self.dir, "--no-probe", "--skip", "web", "ldap"])
        self.assertIn(rc, (0, 1))
        self.assertNotIn("[SWEEP] web", out)
        self.assertNotIn("[SWEEP] ldap", out)
        self.assertIn("[SWEEP] smb", out)

    def test_missing_datastore_is_reported(self):
        empty = self.dir + "_empty"
        shutil.rmtree(empty, ignore_errors=True)
        os.makedirs(empty)
        rc, out = self._run_capture(["sweep", "-o", empty])
        self.assertEqual(rc, 1)
        self.assertIn("No datastore", out)
        shutil.rmtree(empty, ignore_errors=True)

    def test_sweep_ignores_passed_credentials(self):
        """Plain `sweep` is the unauthenticated pass: creds are warned about and
        dropped, never fired as a side-effect of the command."""
        rc, out = self._run_capture(
            ["sweep", "-o", self.dir, "--no-probe", "--only-modules", "smb",
             "-u", "admin", "-p", "pw", "-d", "corp.local"])
        self.assertIn(rc, (0, 1))
        self.assertIn("ignoring the credentials", out)
        self.assertIn("[SWEEP] smb", out)

    def test_credsweep_requires_credentials(self):
        rc, out = self._run_capture(["credsweep", "-o", self.dir])
        self.assertEqual(rc, 1)
        self.assertIn("needs credentials", out)

    def test_credsweep_runs_only_authenticated_modules(self):
        """credsweep runs the credentialed table (credenum + auth ldap/smb/mssql/ftp)
        and never the unauth-only modules (web/snmp/mongodb/docker/k8s)."""
        rc, out = self._run_capture(
            ["credsweep", "-o", self.dir, "--no-probe", "-u", "admin", "-p", "pw",
             "-d", "corp.local", "--only-modules", "ldap", "smb"])
        self.assertIn(rc, (0, 1))
        self.assertIn("[CREDSWEEP] ldap", out)
        self.assertIn("[CREDSWEEP] smb", out)
        self.assertNotIn("web", out.split("Credentialed sweep complete")[0]
                         .replace("credenum", ""))   # web is not in the auth table
        self.assertEqual(out.count("Reports written"), 1)

    def test_credsweep_skips_unauth_only_module_names(self):
        """Asking credsweep for an unauth-only module (mongodb) simply runs nothing
        from the auth table matching it - it must not crash."""
        rc, out = self._run_capture(
            ["credsweep", "-o", self.dir, "--no-probe", "-u", "a", "-p", "b",
             "--only-modules", "mongodb"])
        self.assertIn(rc, (0, 1))
        self.assertIn("ran 0 module(s)", out)


if __name__ == "__main__":
    unittest.main()
