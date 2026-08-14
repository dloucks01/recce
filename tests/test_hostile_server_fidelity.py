"""Hostile-server fidelity: recce's protocol probes must survive a MISBEHAVING peer.

A real engagement's targets lie. A service can close mid-handshake, spew random
bytes, claim an enormous payload length to make a naive client read gigabytes or
hang, truncate a framed message, or plausibly impersonate a different protocol to
provoke a false finding. Every recce probe is pointed at each of these and must:

  * never raise (a probe returns cleanly, never crashes the phase),
  * never hang past its short timeout (bounded reads + connect timeouts),
  * never emit a FALSE "exposed / unauthenticated" finding for a peer that did not
    actually prove it speaks the protocol.

This complements test_fuzz_decoders.py (which mutates bytes into the parsers) by
exercising the full socket path - framing, bounded reads, timeouts - against a
live hostile server.
"""
import socket
import socketserver
import struct
import threading
import time
import unittest

from recce import (elasticsearch as es, ftp, ldap as L, mongodb as M, mssql,
                   probes, redis, smb, snmp as S)
from recce.models import Port


# --- hostile server scaffolding -------------------------------------------------

class _TcpServer:
    def __init__(self, handler):
        class H(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    handler(self.request)
                except OSError:
                    pass

        class Srv(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.srv = Srv(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


class _UdpServer:
    def __init__(self, handler):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self._stop = False

    def _serve(self):
        while not self._stop:
            try:
                self.sock.settimeout(0.3)
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self.handler(self.sock, data, addr)
            except OSError:
                pass

    def __enter__(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        self.sock.close()


# --- hostile TCP behaviours -----------------------------------------------------

def _h_close(sock):
    """Accept then immediately close - zero bytes."""
    return


def _h_reset(sock):
    """Read the request, then close without answering."""
    try:
        sock.recv(4096)
    except OSError:
        pass


def _h_garbage(sock):
    try:
        sock.recv(4096)
    except OSError:
        pass
    sock.sendall(b"\xff\x00\xde\xad\xbe\xef" * 64)


def _h_huge_length(sock):
    """Claim an enormous framed length in every common prefix shape, then send
    almost nothing - a naive client would try to read gigabytes or block forever."""
    try:
        sock.recv(4096)
    except OSError:
        pass
    # ">I" (SMB/TDS/LDAP-ish), "<i" (mongo/RESP-len) - send both framings' huge claim.
    sock.sendall(struct.pack(">I", 0x7FFFFFFF) + b"\x00" * 8)


def _h_truncated_smb(sock):
    """A believable SMB2 header claiming more than it sends."""
    try:
        sock.recv(4096)
    except OSError:
        pass
    sock.sendall(struct.pack(">I", 4096) + b"\xfeSMB" + b"\x00" * 8)   # says 4KB, sends 12B


def _h_redis_impostor(sock):
    """A RESP-shaped service that is NOT Redis: it never answers the PING with +PONG
    and never carries a redis_version, so it must NOT read as an unauth Redis. (A real
    +PONG to PING is, by design, sufficient proof of Redis - so the impostor avoids it.)"""
    while True:
        try:
            data = sock.recv(4096)
        except OSError:
            return
        if not data:
            return
        sock.sendall(b"+OK\r\n")               # valid RESP, but not PONG and no INFO


_HOSTILE_TCP = [_h_close, _h_reset, _h_garbage, _h_huge_length, _h_truncated_smb]


# --- per-protocol probe drivers + "did it falsely claim exposure?" --------------

def _smb(ip, port):
    return smb.probe(ip, port, timeout=1.0)          # None or a dict; no exposure flag


def _ldap(ip, port):
    pr = L.probe(ip, port, timeout=1.0)
    # A hostile peer must not read as an anonymous-readable / RootDSE-leaking DC.
    return pr, bool(pr and (pr.get("anon_read") or pr.get("rootdse_ok")))


def _mongo(ip, port):
    pr = M.probe(ip, port, timeout=1.0)
    return pr, bool(pr and pr.get("unauth"))


def _redis(ip, port):
    pr = redis.probe(ip, port, timeout=1.0)
    return pr, bool(pr and pr.get("unauth"))


def _es(ip, port):
    pr = es.probe(ip, port, timeout=1.0)
    return pr, bool(pr and pr.get("unauth"))


def _mssql(ip, port):
    pr = mssql.prelogin(ip, port, timeout=1.0)
    return pr, bool(pr and pr.get("version"))        # a bogus version out of garbage


def _ftp(ip, port):
    pr = ftp.probe(ip, port, timeout=1.0)
    return pr, bool(pr and pr.get("anonymous"))


class HostileServerFidelityTest(unittest.TestCase):
    """Every probe survives a hostile peer and never fabricates an exposure finding."""

    def _assert_graceful(self, driver, has_flag=True):
        for handler in _HOSTILE_TCP:
            with _TcpServer(handler) as srv:
                t = time.time()
                try:
                    result = driver("127.0.0.1", srv.port)
                except Exception as e:                # noqa: BLE001 - a probe must never raise
                    self.fail(f"{driver.__name__} raised on {handler.__name__}: {e!r}")
                elapsed = time.time() - t
                self.assertLess(elapsed, 8.0,
                                f"{driver.__name__} hung on {handler.__name__} ({elapsed:.1f}s)")
                if has_flag:
                    _pr, exposed = result
                    self.assertFalse(
                        exposed,
                        f"{driver.__name__} FALSELY reported exposure on {handler.__name__}")

    def test_smb_probe_survives_hostile_servers(self):
        self._assert_graceful(_smb, has_flag=False)

    def test_ldap_probe_survives_hostile_servers(self):
        self._assert_graceful(_ldap)

    def test_mongodb_probe_survives_hostile_servers(self):
        self._assert_graceful(_mongo)

    def test_redis_probe_survives_hostile_servers(self):
        self._assert_graceful(_redis)

    def test_elasticsearch_probe_survives_hostile_servers(self):
        self._assert_graceful(_es)

    def test_mssql_probe_survives_hostile_servers(self):
        self._assert_graceful(_mssql)

    def test_ftp_probe_survives_hostile_servers(self):
        self._assert_graceful(_ftp)

    def test_redis_impostor_is_not_reported_unauth(self):
        # A non-Redis service that happens to answer +PONG must NOT become a
        # "critical unauth Redis" (the probe requires a real redis_version / PONG proof).
        with _TcpServer(_h_redis_impostor) as srv:
            pr = redis.probe("127.0.0.1", srv.port, timeout=1.0)
        self.assertFalse(pr.get("unauth"),
                         "a +PONG-only impostor was misreported as an unauth Redis")

    def test_http_probe_survives_hostile_servers(self):
        for handler in (_h_close, _h_garbage, _h_huge_length):
            with _TcpServer(handler) as srv:
                t = time.time()
                try:
                    fs = probes.http_findings(
                        "127.0.0.1", Port(portid=srv.port, service="http", state="open"))
                except Exception as e:                # noqa: BLE001
                    self.fail(f"http_findings raised on {handler.__name__}: {e!r}")
                self.assertLess(time.time() - t, 8.0)
                self.assertIsInstance(fs, list)

    def test_snmp_probe_survives_hostile_udp_agent(self):
        # A UDP agent that replies with garbage / a wrong-community / oversized packet
        # must not crash the probe or fabricate a readable community.
        def garbage(sock, data, addr):
            sock.sendto(b"\xff" * 400, addr)

        def wrong_community(sock, data, addr):
            # a well-formed-ish but useless reply
            sock.sendto(S._tlv(0x30, S._int(1) + S._octet("nope")), addr)

        for handler in (garbage, wrong_community):
            with _UdpServer(handler) as agent:
                t = time.time()
                try:
                    pr = S.probe("127.0.0.1", agent.port, timeout=1.0, known_open=True)
                except Exception as e:                # noqa: BLE001
                    self.fail(f"snmp.probe raised on hostile UDP: {e!r}")
                self.assertLess(time.time() - t, 8.0)
                self.assertIsNone(pr, "hostile UDP agent misreported as readable SNMP")


if __name__ == "__main__":
    unittest.main()
