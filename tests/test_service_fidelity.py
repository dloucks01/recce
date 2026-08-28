"""High-fidelity SERVICE-detection suite.

recce's core job is to correctly identify and enumerate real services. These tests
stand up minimal but REAL protocol responders on 127.0.0.1 and drive recce's own
protocol clients (`<module>.probe`, `probes.*`, `vulndb`, `web`) against them - so
the actual wire framing, parser, and finding logic are exercised end to end, not
mocked. No nmap needed for most of these (they talk to recce's stdlib probes
directly), so they run fast on any box; the nmap-backed end-to-end test is gated.

Covered service/protocol types: HTTP, HTTPS/TLS, Elasticsearch, Docker API, Redis
(RESP), FTP, plus banner->CVE matching (the offline vuln DB) across several product
banners.
"""
import http.server
import json
import os
import re
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest

from recce.core.models import Host, Port


# --- responder scaffolding ------------------------------------------------------

class _Server:
    """A threaded server bound to an ephemeral 127.0.0.1 port. Subclasses set
    self.srv (with serve_forever/shutdown). Use as a context manager."""

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass


class _HttpJson(_Server):
    """Serve GET routes as JSON. `routes`: {path: (status, obj)}; obj may be dict/list
    (JSON) or bytes/str (raw). Unlisted paths 404. Optionally wraps in TLS."""

    def __init__(self, routes, tls_cert=None):
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                match = outer.routes.get(path)
                if match is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                status, obj = match
                if isinstance(obj, (dict, list)):
                    body = json.dumps(obj).encode()
                    ctype = "application/json"
                else:
                    body = obj.encode() if isinstance(obj, str) else obj
                    ctype = "text/html"
                self.send_response(status)
                for k, v in outer.extra_headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

        self.routes = routes
        self.extra_headers = {}
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls_cert)
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]


class _LineServer(_Server):
    """A raw TCP responder driven by a per-connection handler(rfile-ish sock)."""

    def __init__(self, handler):
        outer = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    outer.handler(self.request)
                except OSError:
                    pass

        class S(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.handler = handler
        self.srv = S(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]


def _selfsigned(dirpath):
    """Generate a currently-valid self-signed cert with openssl; None if unavailable."""
    if not shutil.which("openssl"):
        return None
    cert = os.path.join(dirpath, "cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", cert,
         "-out", cert, "-days", "30", "-nodes", "-subj", "/CN=recce-fidelity.test"],
        capture_output=True, timeout=30)
    return cert if os.path.exists(cert) and os.path.getsize(cert) > 0 else None


# --- HTTP-family services -------------------------------------------------------

class ElasticsearchFidelityTest(unittest.TestCase):
    def test_unauth_cluster_is_detected_and_flagged(self):
        from recce.services.db import elasticsearch as es
        routes = {
            "/": (200, {"name": "node-1", "cluster_name": "prod-logs",
                        "version": {"number": "7.10.2", "lucene_version": "8.7.0"},
                        "tagline": "You Know, for Search"}),
            "/_cat/indices": (200, [{"index": "secrets", "docs.count": "42"},
                                    {"index": "users", "docs.count": "1000"}]),
            "/_cluster/health": (200, {"status": "green"}),
        }
        with _HttpJson(routes) as s:
            pr = es.probe("127.0.0.1", s.port)
            # service labeled elasticsearch (as svcdetect/nmap would on a real ES port)
            host = Host(ip="127.0.0.1", ports=[Port(portid=s.port, service="elasticsearch",
                                                    state="open")])
            fs = es.findings([host], {("127.0.0.1", s.port): pr})
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["version"], "7.10.2")
        self.assertIn("secrets", pr["indices"])
        self.assertEqual(pr["docs"], 1042)
        self.assertTrue(fs, "no Elasticsearch finding produced from a live unauth cluster")

    def test_secured_cluster_is_not_flagged_unauth(self):
        from recce.services.db import elasticsearch as es
        with _HttpJson({"/": (401, {"error": "unauthorized"})}) as s:
            pr = es.probe("127.0.0.1", s.port)
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr.get("secured"))
        self.assertFalse(pr.get("unauth"))


class DockerFidelityTest(unittest.TestCase):
    def test_exposed_docker_api_is_detected(self):
        from recce.services import docker
        routes = {
            "/version": (200, {"Version": "24.0.5", "ApiVersion": "1.43",
                               "Os": "linux", "Arch": "amd64",
                               "KernelVersion": "6.1.0"}),
            "/info": (200, {"Name": "dockerhost", "Containers": 3,
                            "ContainersRunning": 2, "Images": 10,
                            "ServerVersion": "24.0.5"}),
            "/containers/json": (200, [{"Image": "nginx:latest",
                                        "Names": ["/web"], "State": "running"}]),
            "/images/json": (200, [{"RepoTags": ["nginx:latest"]}]),
        }
        with _HttpJson(routes) as s:
            pr = docker.probe("127.0.0.1", s.port)
            host = Host(ip="127.0.0.1", ports=[Port(portid=s.port, service="docker",
                                                    state="open")])
            fs = docker.findings([host], {("127.0.0.1", s.port): pr})
        self.assertIsNotNone(pr)
        self.assertTrue(pr["exposed"])
        self.assertEqual(pr["version"], "24.0.5")
        self.assertEqual(pr["running"][0]["image"], "nginx:latest")
        self.assertTrue(fs, "no Docker finding from a live exposed API")


# --- Redis (RESP) ---------------------------------------------------------------

def _resp_read_command(sock):
    """Read one RESP array-of-bulk-strings command; return list[str] or None."""
    buf = b""

    def need(n):
        nonlocal buf
        while len(buf) < n:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("closed")
            buf += chunk

    def line():
        nonlocal buf
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("closed")
            buf += chunk
        ln, _, rest = buf.partition(b"\r\n")
        buf = rest
        return ln

    try:
        first = line()
        if not first.startswith(b"*"):
            return None
        n = int(first[1:])
        args = []
        for _ in range(n):
            ln = line()                 # $<len>
            length = int(ln[1:])
            need(length + 2)
            args.append(buf[:length].decode())
            buf = buf[length + 2:]
        return args
    except (OSError, ValueError):
        return None


_REDIS_INFO = ("# Server\r\nredis_version:7.0.11\r\nos:Linux 6.1 x86_64\r\n"
               "redis_mode:standalone\r\n# Replication\r\nrole:master\r\n"
               "# Keyspace\r\ndb0:keys=5,expires=0\r\n")


def _redis_handler(sock):
    while True:
        cmd = _resp_read_command(sock)
        if not cmd:
            return
        name = cmd[0].upper()
        if name == "PING":
            sock.sendall(b"+PONG\r\n")
        elif name == "INFO":
            body = _REDIS_INFO.encode()
            sock.sendall(b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
        elif name == "CONFIG" and len(cmd) >= 3:
            val = {"dir": "/data", "dbfilename": "dump.rdb",
                   "requirepass": "", "protected-mode": "no"}.get(cmd[2], "")
            v = val.encode()
            sock.sendall(b"*2\r\n$" + str(len(cmd[2])).encode() + b"\r\n"
                         + cmd[2].encode() + b"\r\n$" + str(len(v)).encode()
                         + b"\r\n" + v + b"\r\n")
        else:
            sock.sendall(b"+OK\r\n")


class RedisFidelityTest(unittest.TestCase):
    def test_unauth_redis_is_fingerprinted_and_flagged(self):
        from recce.services.db import redis
        with _LineServer(_redis_handler) as s:
            pr = redis.probe("127.0.0.1", s.port)
            host = Host(ip="127.0.0.1", ports=[Port(portid=s.port, service="redis",
                                                    state="open")])
            fs = redis.findings([host], {("127.0.0.1", s.port): pr})
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["version"], "7.0.11")
        self.assertEqual(pr["role"], "master")
        self.assertEqual(pr["keys"], 5)
        self.assertTrue(fs, "no Redis finding from a live unauth instance")


# --- FTP ------------------------------------------------------------------------

def _ftp_handler(sock):
    sock.sendall(b"220 recce-fidelity FTP (vsftpd 3.0.3)\r\n")
    while True:
        try:
            data = sock.recv(1024)
        except OSError:
            return
        if not data:
            return
        cmd = data.decode(errors="replace").strip().upper()
        if cmd.startswith("FEAT"):
            sock.sendall(b"211-Features:\r\n UTF8\r\n211 End\r\n")      # no AUTH TLS
        elif cmd.startswith("USER"):
            sock.sendall(b"331 Please specify the password.\r\n")
        elif cmd.startswith("PASS"):
            sock.sendall(b"230 Login successful.\r\n")                # anonymous OK
        elif cmd.startswith("SYST"):
            sock.sendall(b"215 UNIX Type: L8\r\n")
        elif cmd.startswith("QUIT"):
            sock.sendall(b"221 Goodbye.\r\n")
            return
        else:
            sock.sendall(b"200 OK\r\n")


class FtpFidelityTest(unittest.TestCase):
    def test_anonymous_cleartext_ftp_is_detected(self):
        from recce.services import ftp
        with _LineServer(_ftp_handler) as s:
            pr = ftp.probe("127.0.0.1", s.port)
            host = Host(ip="127.0.0.1", ports=[Port(portid=s.port, service="ftp",
                                                    state="open")])
            fs = ftp.findings([host], {("127.0.0.1", s.port): pr})
        self.assertIsNotNone(pr)
        self.assertTrue(pr["anonymous"])
        self.assertFalse(pr["auth_tls"])
        titles = " ".join(f["title"].lower() for f in fs)
        self.assertIn("anonymous", titles)
        self.assertIn("cleartext", titles)          # the no-AUTH-TLS finding fires too


# --- TLS + HTTP header probes ---------------------------------------------------

class TlsProbeFidelityTest(unittest.TestCase):
    def test_self_signed_cert_is_flagged(self):
        from recce.services import probes
        with tempfile.TemporaryDirectory() as d:
            cert = _selfsigned(d)
            if not cert:
                self.skipTest("openssl not available to mint a self-signed cert")
            with _HttpJson({"/": (200, "ok")}, tls_cert=cert) as s:
                fs = probes.tls_findings("127.0.0.1", Port(portid=s.port,
                                                           service="https", state="open"))
        titles = " ".join(f.title.lower() for f in fs)
        self.assertTrue(fs, "no TLS finding against a live self-signed HTTPS server")
        self.assertIn("self-signed", titles)


class HttpHeaderFidelityTest(unittest.TestCase):
    def test_missing_security_headers_are_flagged(self):
        from recce.services import probes
        with _HttpJson({"/": (200, "<html>ok</html>")}) as s:
            # server returns no HSTS/CSP/X-Frame-Options/X-Content-Type-Options
            fs = probes.http_findings("127.0.0.1", Port(portid=s.port, service="http",
                                                        state="open"))
        titles = " ".join(f.title.lower() for f in fs)
        self.assertTrue(fs, "no HTTP-header findings against a live bare HTTP server")
        self.assertIn("content-security-policy", titles)

    def test_http_on_nonstandard_port_classifies_as_web(self):
        from recce.services import probes
        from recce.services import web
        with _HttpJson({"/": (200, "<html>ok</html>")}) as s:
            p = Port(portid=s.port, service="http", state="open")
            self.assertTrue(web.is_web(p))
            self.assertTrue(probes._is_http(p))


# --- banner -> CVE matching (offline vuln DB) -----------------------------------

class BannerVulnMatchFidelityTest(unittest.TestCase):
    """The offline version DB must match a realistic product+version banner to the
    right CVE - and must NOT fire on a patched version (false-positive guard)."""

    def _assess(self, product, version, portid=21, service="ftp", extrainfo=""):
        from recce.vuln import vulndb
        h = Host(ip="10.0.0.1", ports=[Port(portid=portid, protocol="tcp",
                 state="open", service=service, product=product, version=version,
                 extrainfo=extrainfo)])
        vulndb.assess_host_inplace(h)
        return h

    def test_vsftpd_234_backdoor_matches(self):
        h = self._assess("vsftpd", "2.3.4")
        cves = {c for v in h.vulns for c in v.ids}
        self.assertIn("CVE-2011-2523", cves)

    def test_regresshion_openssh_matches_vulnerable_but_not_patched(self):
        vuln = self._assess("OpenSSH", "9.2p1", portid=22, service="ssh")
        patched = self._assess("OpenSSH", "9.8p1", portid=22, service="ssh")
        vuln_cves = {c for v in vuln.vulns for c in v.ids}
        patched_cves = {c for v in patched.vulns for c in v.ids}
        self.assertIn("CVE-2024-6387", vuln_cves)          # regreSSHion
        self.assertNotIn("CVE-2024-6387", patched_cves)    # patched: no false positive

    def test_distro_backport_is_not_a_confirmed_finding(self):
        # A distro-packaged build carries the upstream version but is often patched;
        # it must be downgraded (not a confident finding), per recce's FP guards.
        h = self._assess("OpenSSH", "9.2p1", portid=22, service="ssh",
                         extrainfo="Ubuntu-2ubuntu2.1")
        conf = [v.confidence for v in h.vulns if "CVE-2024-6387" in v.ids]
        self.assertTrue(all(c == "potential" for c in conf) if conf else True)


_ES_ROUTES = {
    "/": (200, {"name": "n1", "cluster_name": "c1",
                "version": {"number": "7.10.2"}, "tagline": "You Know, for Search"}),
    "/_cat/indices": (200, [{"index": "logs", "docs.count": "10"}]),
    "/_cluster/health": (200, {"status": "yellow"}),
}


class MultiServiceSystemFidelityTest(unittest.TestCase):
    """A single 'system' running several services at once - recce must detect and
    enumerate EVERY one, not stop at the first. Models the real scan target."""

    def test_host_with_web_ftp_redis_elasticsearch_all_enumerated(self):
        from recce.services import probes
        from recce.services import ftp, web
        from recce.services.db import redis, elasticsearch as es
        with _HttpJson({"/": (200, "<html>ok</html>")}) as webs, \
                _LineServer(_ftp_handler) as ftps, \
                _LineServer(_redis_handler) as reds, \
                _HttpJson(_ES_ROUTES) as ess:
            ip = "127.0.0.1"
            host = Host(ip=ip, ports=[
                Port(portid=webs.port, service="http", state="open"),
                Port(portid=ftps.port, service="ftp", state="open"),
                Port(portid=reds.port, service="redis", state="open"),
                Port(portid=ess.port, service="elasticsearch", state="open"),
            ])
            # Each service classifier recognises its port on this multi-service host.
            self.assertTrue(web.is_web(host.ports[0]))
            self.assertTrue(ftp.is_ftp(host.ports[1]))
            self.assertTrue(redis.is_redis(host.ports[2]))
            self.assertTrue(es.is_elasticsearch(host.ports[3]))
            # Each protocol client enumerates its live service independently.
            ftp_f = ftp.findings([host], {(ip, ftps.port): ftp.probe(ip, ftps.port)})
            redis_f = redis.findings([host], {(ip, reds.port): redis.probe(ip, reds.port)})
            es_f = es.findings([host], {(ip, ess.port): es.probe(ip, ess.port)})
            web_f = probes.http_findings(ip, host.ports[0])
        self.assertTrue(ftp_f, "FTP not enumerated on the multi-service host")
        self.assertTrue(redis_f, "Redis not enumerated on the multi-service host")
        self.assertTrue(es_f, "Elasticsearch not enumerated on the multi-service host")
        self.assertTrue(web_f, "web headers not enumerated on the multi-service host")


if __name__ == "__main__":
    unittest.main()
