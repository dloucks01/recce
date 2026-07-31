"""Fake-transport probe tests: real socket + real parse, replayed responses.

The pure-decoder tests cover Layer 1. These cover Layer 2 - the probe functions
that open a socket, speak the protocol, and fold the reply into findings. That
round-trip is where integration bugs hide (the end-to-end run found `_is_tls`
mis-routing a plain-HTTP port to the TLS path, which no unit test caught).

SNMP, MongoDB and LDAP already have loopback-server tests in test_pipeline.py.
This file closes the gap for the probes that had none: SMB, FTP, Docker, Kubernetes
and web.scan_endpoint. Each stands up a tiny 127.0.0.1 server that replays a
recorded response, then points the real probe at it - no mocking of the socket or
the parser, so the exact code path a live target drives is exercised.
"""
import json
import socket
import struct
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce import smb
from recce import ftp
from recce import docker
from recce import kubernetes
from recce import web
from recce.models import Port
from tests import wire_vectors as W


# --- tiny loopback servers ------------------------------------------------------

class _TCPReplay:
    """Accept connections on 127.0.0.1:0 and hand each socket to `handler(sock)`."""

    def __init__(self, handler):
        self._handler = handler
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self.port = self._srv.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._run, args=(conn,), daemon=True).start()

    def _run(self, conn):
        try:
            with conn:
                self._handler(conn)
        except OSError:
            pass

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def _recv_smb_pdu(sock):
    """Read one NetBIOS-framed SMB request: 4-byte big-endian length, then body."""
    head = b""
    while len(head) < 4:
        chunk = sock.recv(4 - len(head))
        if not chunk:
            return None
        head += chunk
    n = struct.unpack(">I", head)[0] & 0x00FFFFFF
    body = b""
    while len(body) < n:
        chunk = sock.recv(n - len(body))
        if not chunk:
            break
        body += chunk
    return body


class _JSONHTTP(BaseHTTPRequestHandler):
    routes: dict = {}

    def log_message(self, *a):            # silence the default stderr logging
        pass

    def _respond(self):
        route = self.routes.get(self.path.split("?")[0])
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        status, headers, body = route
        raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _respond
    do_POST = _respond


def _http_server(routes):
    handler = type("H", (_JSONHTTP,), {"routes": routes})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


# --- SMB ------------------------------------------------------------------------

class SmbProbeTransportTest(unittest.TestCase):

    def test_probe_reads_dialect_and_signing(self):
        def handler(sock):
            body = _recv_smb_pdu(sock)               # NetBIOS prefix already stripped
            if body and body[:4] == b"\xfeSMB":
                sock.sendall(W.smb2_negotiate_response())
            elif body and body[:4] == b"\xffSMB":
                sock.sendall(W.smb1_negotiate_response())

        srv = _TCPReplay(handler)
        try:
            out = smb.probe("127.0.0.1", srv.port, timeout=3.0)
        finally:
            srv.close()
        self.assertIsNotNone(out)
        self.assertEqual(out["dialect_name"], "SMB 3.1.1")
        self.assertFalse(out["signing_required"])
        self.assertTrue(out["smbv1"])                 # server answered SMB1 too

    def test_probe_returns_none_when_not_smb(self):
        def handler(sock):
            _recv_smb_pdu(sock)
            sock.sendall(b"\x00\x00\x00\x04GARB")     # non-SMB reply

        srv = _TCPReplay(handler)
        try:
            out = smb.probe("127.0.0.1", srv.port, timeout=3.0)
        finally:
            srv.close()
        self.assertIsNone(out)


# --- FTP ------------------------------------------------------------------------

class FtpProbeTransportTest(unittest.TestCase):

    def test_probe_reads_banner_anon_and_tls(self):
        def handler(sock):
            sock.sendall(b"220-Welcome to the lab\r\n220 ProFTPD 1.3.5 ready\r\n")
            replies = {
                b"FEAT": b"211-Features:\r\n AUTH TLS\r\n211 End\r\n",
                b"USER": b"331 Please specify the password.\r\n",
                b"PASS": b"230 Login successful.\r\n",
                b"SYST": b"215 UNIX Type: L8\r\n",
                b"QUIT": b"221 Goodbye.\r\n",
            }
            buf = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    return
                buf += chunk
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    sock.sendall(replies.get(line[:4].strip(),
                                             b"500 Unknown\r\n"))
                    if line[:4].strip() == b"QUIT":
                        return

        srv = _TCPReplay(handler)
        try:
            out = ftp.probe("127.0.0.1", srv.port, timeout=3.0)
        finally:
            srv.close()
        self.assertIsNotNone(out)
        self.assertIn("ProFTPD 1.3.5", out["banner"])
        self.assertTrue(out["anonymous"])
        self.assertTrue(out["auth_tls"])
        self.assertEqual(out["syst"], "UNIX Type: L8")

    def test_probe_returns_none_on_non_ftp_banner(self):
        def handler(sock):
            sock.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")

        srv = _TCPReplay(handler)
        try:
            out = ftp.probe("127.0.0.1", srv.port, timeout=3.0)
        finally:
            srv.close()
        self.assertIsNone(out)


# --- Docker ---------------------------------------------------------------------

class DockerProbeTransportTest(unittest.TestCase):

    def test_probe_reads_exposed_daemon(self):
        routes = {
            "/version": (200, {"Content-Type": "application/json"},
                         {"Version": "24.0.5", "ApiVersion": "1.43",
                          "Os": "linux", "Arch": "amd64",
                          "KernelVersion": "6.1.0"}),
            "/info": (200, {}, {"Name": "node1", "Containers": 3,
                                "ContainersRunning": 2, "Images": 10,
                                "ServerVersion": "24.0.5"}),
            "/containers/json": (200, {}, [{"Image": "nginx:latest",
                                            "Names": ["/web"],
                                            "Command": "nginx -g daemon off;",
                                            "State": "running"}]),
            "/images/json": (200, {}, [{"RepoTags": ["nginx:latest",
                                                     "<none>:<none>"]}]),
        }
        srv, port = _http_server(routes)
        try:
            out = docker.probe("127.0.0.1", port, timeout=3.0)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIsNotNone(out)
        self.assertTrue(out["exposed"])
        self.assertEqual(out["version"], "24.0.5")
        self.assertEqual(out["name"], "node1")
        self.assertEqual(out["running"][0]["image"], "nginx:latest")
        self.assertEqual(out["running"][0]["names"], ["web"])
        self.assertEqual(out["image_tags"], ["nginx:latest"])   # <none> filtered

    def test_probe_returns_none_when_api_absent(self):
        srv, port = _http_server({"/": (404, {}, "nope")})
        try:
            out = docker.probe("127.0.0.1", port, timeout=3.0)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertIsNone(out)


# --- Kubernetes -----------------------------------------------------------------

class KubernetesProbeTransportTest(unittest.TestCase):

    def test_apiserver_anonymous_list_and_secrets(self):
        routes = {
            "/version": (200, {}, {"gitVersion": "v1.28.2"}),
            "/api/v1/namespaces": (200, {}, {"kind": "NamespaceList",
                                             "items": [{"metadata": {"name": "default"}}]}),
            "/api/v1/secrets": (200, {}, {"kind": "SecretList",
                                          "items": [{"metadata": {"name": "sa-token"}}]}),
        }
        srv, port = _http_server(routes)
        orig = kubernetes.role
        kubernetes.role = lambda p: "apiserver"       # force the apiserver code path
        try:
            out = kubernetes.probe("127.0.0.1", port, timeout=3.0)
        finally:
            kubernetes.role = orig
            srv.shutdown()
            srv.server_close()
        self.assertIsNotNone(out)
        self.assertEqual(out["role"], "apiserver")
        self.assertEqual(out["version"], "v1.28.2")
        self.assertTrue(out["anon_list"])
        self.assertTrue(out["anon_secrets"])


# --- web.scan_endpoint (integration regression guard for _is_tls) ---------------

class WebScanEndpointTransportTest(unittest.TestCase):

    def test_plain_http_endpoint_is_scanned_not_flipped_to_tls(self):
        """The end-to-end run found a plain-HTTP port being scanned as HTTPS, so every
        web finding was missed. This drives the real fetch->fingerprint->findings path
        against a loopback HTTP server and asserts findings actually come back."""
        page = ("<html><head><title>Index of /</title></head>"
                "<body>Directory listing for /</body></html>")
        routes = {
            "/": (200, {"Server": "nginx/1.24.0",
                        "Set-Cookie": "SESSIONID=abc123; Path=/"}, page),
        }
        srv, port = _http_server(routes)
        p = Port(portid=port, protocol="tcp", state="open", service="http")
        try:
            profile, findings = web.scan_endpoint("127.0.0.1", p, active=True)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(profile["scheme"], "http")   # not flipped to https
        self.assertEqual(profile["status"], 200)
        self.assertIn("nginx/1.24.0", profile["server"])
        kinds = {f.script_id for f in findings}
        # A plain-HTTP scan must surface the insecure cookie and/or the dir listing;
        # under the _is_tls bug this list was empty.
        self.assertTrue(findings, "plain-HTTP endpoint yielded no findings")
        self.assertTrue(
            any("cookie" in k or "dirlisting" in k for k in kinds),
            f"expected a cookie/dir-listing finding, got {kinds}")


if __name__ == "__main__":
    unittest.main()
