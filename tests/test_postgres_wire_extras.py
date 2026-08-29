"""Two wire-level PostgreSQL gaps the audit called out:

  * SSLRequest / TLS-mode enumeration (§55.2.10) — a single-byte 'S'/'N'
    reveals whether TLS is offered at all.
  * Replication startup (`replication=true`, §55.4) — a completely separate
    pg_hba surface that admits pg_basebackup and is invisible to the regular
    SQL-only probe.

Tests drive both the wire code (against fake servers speaking enough of each
protocol) and the findings-emit chain (synthetic probe dicts).
"""
from __future__ import annotations

import socketserver
import struct
import threading

from recce.core.models import Host, Port
from recce.services.db import postgres


# ---------- one-shot TCP server harness (mirrors test_db_modules.py) ----------

def _serve(handler_fn):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            handler_fn(self.request)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[0], srv.server_address[1], srv


def _pg_msg(t: bytes, body: bytes) -> bytes:
    return t + struct.pack("!I", len(body) + 4) + body


# =============================== SSLRequest wire ==============================

def _ssl_server(reply_byte: bytes | None):
    """Fake server: expect the exact 8-byte SSLRequest (len=8, code=80877103)
    and reply with `reply_byte` (b'S', b'N', or nothing)."""
    def handle(sock):
        # SSLRequest is fixed 8 bytes: 4-byte length + 4-byte code.
        pkt = sock.recv(8)
        # Sanity-check the shape so a bug in the client (wrong length prefix,
        # wrong code) surfaces here rather than as a silent test pass.
        assert len(pkt) == 8, f"SSLRequest is 8 bytes, got {len(pkt)}"
        ln, code = struct.unpack("!II", pkt)
        assert ln == 8
        assert code == 80877103         # 0x04D2162F per protocol spec
        if reply_byte:
            sock.sendall(reply_byte)
    return handle


def test_probe_ssl_reads_S_reply_as_tls_offered():
    ip, port, srv = _serve(_ssl_server(b"S"))
    try:
        r = postgres.probe_ssl(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["reachable"] and r["tls_offered"] and r["response"] == "S"


def test_probe_ssl_reads_N_reply_as_tls_refused():
    ip, port, srv = _serve(_ssl_server(b"N"))
    try:
        r = postgres.probe_ssl(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["reachable"] and not r["tls_offered"] and r["response"] == "N"


def test_probe_ssl_unreachable_never_raises():
    # 127.0.0.1:1 is virtually always closed / no listener -> connection refused.
    r = postgres.probe_ssl("127.0.0.1", 1, timeout=1)
    assert r["reachable"] is False
    assert r["tls_offered"] is False
    assert r["error"]      # populated with the OS error string


def test_pg_no_tls_finding_fires_on_N():
    """The tls-refused case is the actionable one — a `pg_no_tls` medium
    finding pointing out the whole wire is cleartext."""
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=5432, service="postgresql", state="open")])
    probes = {("10.0.0.5", 5432): {"reachable": True, "auth_required": True,
              "ssl": {"reachable": True, "tls_offered": False,
                      "response": "N", "error": ""}}}
    fs = postgres.findings([h], probes)
    hits = [f for f in fs if f["kind"] == "pg_no_tls"]
    assert len(hits) == 1
    f = hits[0]
    assert f["severity"] == "medium"
    assert "cleartext" in f["detail"].lower()
    assert "CWE-319" in f["cwes"]


def test_pg_no_tls_finding_silent_when_tls_offered():
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=5432, service="postgresql", state="open")])
    probes = {("10.0.0.5", 5432): {"reachable": True, "auth_required": True,
              "ssl": {"reachable": True, "tls_offered": True,
                      "response": "S", "error": ""}}}
    assert not any(f["kind"] == "pg_no_tls" for f in postgres.findings([h], probes))


def test_pg_no_tls_finding_silent_when_probe_unreachable():
    # A connection failure at the SSL probe must NOT invent a cleartext finding.
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=5432, service="postgresql", state="open")])
    probes = {("10.0.0.5", 5432): {"reachable": True, "auth_required": True,
              "ssl": {"reachable": False, "tls_offered": False,
                      "response": "", "error": "Connection refused"}}}
    assert not any(f["kind"] == "pg_no_tls" for f in postgres.findings([h], probes))


# ========================== Replication startup wire ==========================

def _rep_server(auth_code: int | None = None, error: bool = False):
    """Fake server: accept the replication StartupMessage, verify it carries
    `replication=true`, then reply with either AuthenticationOk (0) / any auth
    challenge (5 md5 / 10 SASL / …) / an ErrorResponse."""
    def handle(sock):
        # v3 startup is variable-length; read the 4-byte length first.
        ln_raw = sock.recv(4)
        assert len(ln_raw) == 4
        ln = struct.unpack("!I", ln_raw)[0]
        body = sock.recv(ln - 4)
        # The `replication` parameter is the point of the whole path — assert
        # the client actually sent it, otherwise this test lies.
        assert b"replication\x00true\x00" in body, "must carry replication=true"
        if error:
            sock.sendall(_pg_msg(b"E",
                b"SFATAL\x00C28000\x00Mno pg_hba.conf entry for replication\x00\x00"))
            return
        sock.sendall(_pg_msg(b"R", struct.pack("!I", auth_code)))
        if auth_code == 0:
            sock.sendall(_pg_msg(b"S", b"server_version\x0016.2\x00"))
            sock.sendall(_pg_msg(b"Z", b"I"))
    return handle


def test_probe_replication_trust_reports_unauth():
    ip, port, srv = _serve(_rep_server(auth_code=0))
    try:
        r = postgres.probe_replication(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["reachable"] and r["unauth"] and not r["auth_required"]
    assert r["version"] == "16.2"


def test_probe_replication_md5_reports_auth_required():
    ip, port, srv = _serve(_rep_server(auth_code=5))   # AuthenticationMD5Password
    try:
        r = postgres.probe_replication(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["reachable"] and not r["unauth"] and r["auth_required"]


def test_probe_replication_error_response_captured():
    ip, port, srv = _serve(_rep_server(error=True))
    try:
        r = postgres.probe_replication(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["reachable"] and not r["unauth"]
    assert "replication" in r["error"]


def test_probe_replication_unreachable_never_raises():
    r = postgres.probe_replication("127.0.0.1", 1, timeout=1)
    assert r["reachable"] is False
    assert r["unauth"] is False
    assert r["error"]


def test_pg_replication_trust_finding_fires_critical():
    """When the replication path is trust-open, emit a critical finding — this
    is pg_basebackup-of-the-whole-cluster territory, distinct from any SQL
    trust/cred story on the same port."""
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=5432, service="postgresql", state="open")])
    probes = {("10.0.0.5", 5432): {"reachable": True, "auth_required": True,
              "replication": {"reachable": True, "unauth": True,
                              "auth_required": False,
                              "version": "16.2", "error": ""}}}
    fs = postgres.findings([h], probes)
    hits = [f for f in fs if f["kind"] == "pg_replication_trust"]
    assert len(hits) == 1
    f = hits[0]
    assert f["severity"] == "critical"
    assert "pg_basebackup" in f["command"]
    assert "CWE-306" in f["cwes"]


def test_pg_replication_finding_silent_when_auth_required():
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=5432, service="postgresql", state="open")])
    probes = {("10.0.0.5", 5432): {"reachable": True, "auth_required": True,
              "replication": {"reachable": True, "unauth": False,
                              "auth_required": True, "version": "",
                              "error": ""}}}
    assert not any(f["kind"] == "pg_replication_trust"
                   for f in postgres.findings([h], probes))


def test_startup_replication_encodes_parameter():
    """The parameter block MUST include `replication=true` verbatim — a wire
    regression here silently downgrades the whole probe to a regular startup
    (which still authenticates the SQL surface, so the caller would see
    'unauth' and file the wrong finding)."""
    pkt = postgres._startup_replication("postgres", "postgres")
    assert b"replication\x00true\x00" in pkt
    # length prefix must match the real body size
    ln = struct.unpack("!I", pkt[:4])[0]
    assert ln == len(pkt)
