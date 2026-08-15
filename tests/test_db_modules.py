"""MySQL + PostgreSQL deep modules, validated against fake servers that speak enough
of each wire protocol to exercise the real probe (not mocks)."""
from __future__ import annotations

import socket
import socketserver
import struct
import threading

from recce import mysql, postgres
from recce.models import Host, Port


def _serve(handler_fn):
    """Start a one-shot threaded TCP server; return (host, port, server)."""
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            handler_fn(self.request)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[0], srv.server_address[1], srv


# ------------------------------- PostgreSQL --------------------------------------

def _pg_msg(type_byte: bytes, body: bytes) -> bytes:
    return type_byte + struct.pack("!I", len(body) + 4) + body


def _pg_server(auth_code=None, error=False):
    def handle(sock):
        sock.recv(4096)                                   # consume StartupMessage
        if error:
            # ErrorResponse fields: S(everity), C(ode), M(essage), each null-terminated.
            sock.sendall(_pg_msg(b"E", b"SFATAL\x00C28000\x00Mno pg_hba.conf entry\x00\x00"))
            return
        sock.sendall(_pg_msg(b"R", struct.pack("!I", auth_code)))
        if auth_code == 0:                                # trust: stream a version + ready
            sock.sendall(_pg_msg(b"S", b"server_version\x0016.2\x00"))
            sock.sendall(_pg_msg(b"Z", b"I"))
    return handle


def test_postgres_trust_auth_is_unauth():
    ip, port, srv = _serve(_pg_server(auth_code=0))
    try:
        pr = postgres.probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert pr["reachable"] and pr["unauth"] and not pr["auth_required"]
    assert pr["version"] == "16.2"


def test_postgres_md5_requires_auth():
    ip, port, srv = _serve(_pg_server(auth_code=5))       # AuthenticationMD5Password
    try:
        pr = postgres.probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert pr["reachable"] and not pr["unauth"] and pr["auth_required"]


def test_postgres_error_response_is_not_unauth():
    ip, port, srv = _serve(_pg_server(error=True))
    try:
        pr = postgres.probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert not pr["unauth"]
    assert "pg_hba" in pr["error"]


def test_postgres_findings_and_fold():
    h = Host(ip="10.0.0.5", ports=[Port(portid=5432, service="postgresql", state="open")])
    probes = {("10.0.0.5", 5432): {"unauth": True, "version": "16.2"}}
    fs = postgres.findings([h], probes)
    assert fs and fs[0]["severity"] == "high" and "trust" in fs[0]["title"].lower()
    by_ip = postgres.findings_to_vulns(fs)
    assert by_ip["10.0.0.5"][0].source == "postgres"


# --------------------------------- MySQL -----------------------------------------

def _my_packet(payload: bytes, seq: int) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


_MY_HANDSHAKE = bytes([10]) + b"8.0.32\x00" + b"\x00" * 20     # proto 10 + version string


def _my_server(login_ok: bool):
    def handle(sock):
        sock.sendall(_my_packet(_MY_HANDSHAKE, 0))
        sock.recv(4096)                                   # consume HandshakeResponse
        if login_ok:
            sock.sendall(_my_packet(b"\x00\x00\x00\x02\x00\x00\x00", 2))   # OK packet
        else:
            # ERR 1045 Access denied
            sock.sendall(_my_packet(b"\xff" + struct.pack("<H", 1045) + b"#28000denied", 2))
    return handle


def test_mysql_empty_password_login_is_unauth():
    ip, port, srv = _serve(_my_server(login_ok=True))
    try:
        pr = mysql.probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert pr["reachable"] and pr["unauth"]
    assert pr["user"] == "root"
    assert pr["version"] == "8.0.32"


def test_mysql_access_denied_requires_auth():
    ip, port, srv = _serve(_my_server(login_ok=False))
    try:
        pr = mysql.probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert pr["reachable"] and not pr["unauth"] and pr["auth_required"]
    assert pr["version"] == "8.0.32"


def test_mysql_findings_and_fold():
    h = Host(ip="10.0.0.6", ports=[Port(portid=3306, service="mysql", state="open")])
    probes = {("10.0.0.6", 3306): {"unauth": True, "user": "root", "version": "8.0.32"}}
    fs = mysql.findings([h], probes)
    assert fs and fs[0]["severity"] == "high" and "empty password" in fs[0]["title"].lower()
    by_ip = mysql.findings_to_vulns(fs)
    assert by_ip["10.0.0.6"][0].source == "mysql"


def test_version_writeback_replaces_open_ended_nmap_banner(tmp_path):
    # a deep module's real version read is adopted onto the port when nmap left an
    # open-ended fingerprint, so the report shows the true build.
    from recce.cli import _fold_service_findings, _open_paths
    from recce.store import Store
    eng = tmp_path / "e"
    st = Store(_open_paths(str(eng))["db"])
    try:
        h = Host(ip="10.0.0.5", up_reason="syn-ack",
                 ports=[Port(portid=5432, service="postgresql", product="PostgreSQL DB",
                             version="9.6.0 or later", state="open")])
        st.upsert_host(h)
        analysis = {
            "findings": [{"title": "PostgreSQL trust authentication (no password required)",
                          "target": "10.0.0.5:5432", "severity": "high", "detail": "trust"}],
            "probes": {"10.0.0.5:5432": {"version": "18.1 (Debian 18.1-2)", "unauth": True}},
            "stats": {}}
        _fold_service_findings(st, [h], analysis, "postgres",
                               postgres.findings_to_vulns, "PostgreSQL")
        p = next(x for x in st.get_host("10.0.0.5").ports if x.portid == 5432)
        assert p.version == "18.1 (Debian 18.1-2)"     # adopted the real version
    finally:
        st.close()


class _FakeSock:
    """A socket that replays scripted bytes - drives the loot result-set parsers."""
    def __init__(self, blob: bytes):
        self.buf = blob
        self.sent: list = []

    def sendall(self, b):
        self.sent.append(b)

    def recv(self, n):
        d, self.buf = self.buf[:n], self.buf[n:]
        return d

    def settimeout(self, *a):
        pass

    def close(self):
        pass


def test_mysql_query_parses_a_result_set():
    from recce import mysql

    def pkt(payload, seq):
        return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload

    def lenstr(s):
        b = s.encode()
        return bytes([len(b)]) + b

    eof = b"\xfe\x00\x00\x02\x00"
    blob = (pkt(b"\x02", 1)                       # 2 columns
            + pkt(b"\x03def", 2) + pkt(b"\x03def", 3)          # column defs (skipped)
            + pkt(eof, 4)                          # EOF after columns
            + pkt(lenstr("root") + lenstr("*ABC123"), 5)       # a row
            + pkt(lenstr("app") + b"\xfb", 6)      # a row with a NULL hash
            + pkt(eof, 7))                         # trailing EOF
    rows = mysql._query(_FakeSock(blob), "SELECT user, authentication_string FROM mysql.user")
    assert rows == [["root", "*ABC123"], ["app", None]]


def test_postgres_simple_query_parses_datarows():
    from recce import postgres

    def msg(t, body):
        return t + struct.pack("!I", len(body) + 4) + body

    def datarow(vals):
        b = struct.pack("!H", len(vals))
        for v in vals:
            if v is None:
                b += struct.pack("!i", -1)
            else:
                bb = v.encode()
                b += struct.pack("!i", len(bb)) + bb
        return msg(b"D", b)

    blob = (datarow(["postgres", "SCRAM-SHA-256$..."])
            + datarow(["app_svc", None])
            + msg(b"C", b"SELECT 2\x00")
            + msg(b"Z", b"I"))                     # ReadyForQuery -> done
    rows = postgres._simple_query(_FakeSock(blob), "SELECT usename, passwd FROM pg_shadow")
    assert rows == [["postgres", "SCRAM-SHA-256$..."], ["app_svc", None]]


def test_is_predicates_respect_open_state():
    assert mysql.is_mysql(Port(portid=3306, service="mysql", state="open"))
    assert not mysql.is_mysql(Port(portid=3306, service="mysql", state="closed"))
    assert postgres.is_postgres(Port(portid=5432, service="postgresql", state="open"))
    assert not postgres.is_postgres(Port(portid=80, service="http", state="open"))
