"""SAFE reachability probe for the PostgreSQL streaming-replication path.

`probe_replication` (already tested elsewhere) only flags the trust case —
AuthenticationOk with no password. That misses the far more common
misconfiguration where `host replication all ... md5` in pg_hba admits a
network but requires a credential the tester can crack or spray. The
`probe_replication_endpoint` capability observes THAT surface without ever
responding to the auth challenge, and the `pg_replication_endpoint` finding
converts the observation into a medium-severity CWE-306 disclosure.

Fixtures are RFC/wire-derived (Postgres v3 §55.2 startup, §55.4 replication,
§55.7 AuthenticationRequest sub-codes). No live network: every server side
is a stdlib socketserver bound to 127.0.0.1:0.
"""
from __future__ import annotations

import socketserver
import struct
import threading

from recce.core.models import Host, Port
from recce.services.db import postgres


# ---------- one-shot TCP server harness ----------

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


def _read_startup(sock) -> bytes:
    """Read exactly one v3 StartupMessage off `sock` and return its body."""
    ln_raw = sock.recv(4)
    assert len(ln_raw) == 4
    ln = struct.unpack("!I", ln_raw)[0]
    body = b""
    while len(body) < ln - 4:
        chunk = sock.recv(ln - 4 - len(body))
        if not chunk:
            break
        body += chunk
    return body


# --- server variants used by the tests ---------------------------------------

def _rep_endpoint_server(auth_code: int, extra_after: bool = False):
    """After startup, reply with a SINGLE AuthenticationRequest of the given
    sub-code. If `extra_after`, also queue a byte the safe probe MUST NOT
    read — the probe must close its socket after the first message."""
    seen: dict = {"read_after_challenge": False}

    def handle(sock):
        body = _read_startup(sock)
        # The `replication` parameter is the whole point of this probe path.
        assert b"replication\x00true\x00" in body, "must carry replication=true"
        sock.sendall(_pg_msg(b"R", struct.pack("!I", auth_code)))
        if extra_after:
            # Wait briefly; if the client is behaving (close-after-first-message)
            # this sendall raises BrokenPipeError we swallow. If the client
            # sends any additional bytes, note it — that would prove the probe
            # is speaking auth material.
            try:
                sock.settimeout(0.5)
                more = sock.recv(1024)
                if more:
                    seen["read_after_challenge"] = True
            except OSError:
                pass
    return handle, seen


def _rep_endpoint_error_server(msg: bytes):
    def handle(sock):
        body = _read_startup(sock)
        assert b"replication\x00true\x00" in body
        # ErrorResponse: series of `field-code + null-terminated str` + final NUL.
        payload = b"SFATAL\x00C28000\x00M" + msg + b"\x00\x00"
        sock.sendall(_pg_msg(b"E", payload))
    return handle


def _rep_endpoint_multi_user_server(behaviors: list):
    """For probes that walk multiple candidate users: `behaviors` is a list of
    per-connection responders (each a callable(sock)-> None) consumed in
    order. Missing entries default to "close immediately"."""
    idx = {"n": 0}
    lock = threading.Lock()

    def handle(sock):
        with lock:
            i = idx["n"]
            idx["n"] += 1
        body = _read_startup(sock)
        assert b"replication\x00true\x00" in body
        if i < len(behaviors):
            behaviors[i](sock)
        # otherwise just close
    return handle, idx


# =============================== wire tests ===================================

def test_endpoint_probe_md5_challenge_marks_endpoint_open():
    """MD5 challenge (sub-code 5) — the vulnerable + patched case's common
    ground: endpoint exists, credentials required."""
    handler, seen = _rep_endpoint_server(auth_code=5, extra_after=True)
    ip, port, srv = _serve(handler)
    try:
        r = postgres.probe_replication_endpoint(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["reachable"] is True
    assert r["endpoint_open"] is True
    assert r["auth_method"] == "md5"
    assert r["auth_code"] == 5
    assert r["user_tried"] == "replication"
    # SAFETY invariant: probe MUST NOT have written back to the server after
    # receiving the challenge.
    assert seen["read_after_challenge"] is False


def test_endpoint_probe_sasl_challenge_captured_as_sasl_method():
    """SASL (sub-code 10 = SCRAM-SHA-256 negotiation start)."""
    handler, _ = _rep_endpoint_server(auth_code=10)
    ip, port, srv = _serve(handler)
    try:
        r = postgres.probe_replication_endpoint(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["endpoint_open"] and r["auth_method"] == "sasl" and r["auth_code"] == 10


def test_endpoint_probe_cleartext_challenge_captured():
    handler, _ = _rep_endpoint_server(auth_code=3)
    ip, port, srv = _serve(handler)
    try:
        r = postgres.probe_replication_endpoint(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["auth_method"] == "cleartext-password"


def test_endpoint_probe_error_mentions_replication_marks_disclosure():
    """`no pg_hba.conf entry for replication` — server tells us the path is
    configured but this user isn't admitted. That is disclosure in its own
    right (CWE-306); the probe records it as endpoint_open + error_mentions.
    """
    ip, port, srv = _serve(_rep_endpoint_error_server(
        b"no pg_hba.conf entry for replication, user \"postgres\""))
    try:
        r = postgres.probe_replication_endpoint(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["endpoint_open"] is True
    assert r["error_mentions_replication"] is True
    assert "replication" in r["error"].lower()
    assert r["auth_method"] == ""       # no R message was sent
    assert r["auth_code"] == -1


def test_endpoint_probe_generic_error_does_not_open_endpoint():
    """Server closes with an unrelated error (e.g. FATAL: too many
    connections). No mention of replication -> no disclosure. Probe walks
    to the next candidate user; if all fail, endpoint_open stays False.
    """
    ip, port, srv = _serve(_rep_endpoint_error_server(b"too many connections"))
    try:
        r = postgres.probe_replication_endpoint(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["reachable"] is True
    assert r["endpoint_open"] is False
    assert r["error_mentions_replication"] is False


def test_endpoint_probe_walks_candidate_users_and_stops_on_first_hit():
    """Multi-candidate walk: the first user gets a generic error, the second
    gets an md5 challenge. Probe should record the second's result and NOT
    open a third connection.
    """
    def first(sock):
        sock.sendall(_pg_msg(b"E",
            b"SFATAL\x00C28000\x00Mrole \"replication\" does not exist\x00\x00"))

    def second(sock):
        sock.sendall(_pg_msg(b"R", struct.pack("!I", 5)))

    handler, idx = _rep_endpoint_multi_user_server([first, second])
    ip, port, srv = _serve(handler)
    try:
        r = postgres.probe_replication_endpoint(ip, port, timeout=3,
                                                users=("replication", "postgres",
                                                       "admin"))
    finally:
        srv.shutdown()
    assert r["endpoint_open"] is True
    assert r["auth_method"] == "md5"
    assert r["user_tried"] == "postgres"
    assert idx["n"] == 2, "must not connect a third time after the hit"


def test_endpoint_probe_unreachable_never_raises_and_absent():
    """Absent case: connection refused. reachable=False, endpoint_open=False,
    error populated. Emitter must stay silent on this shape.
    """
    r = postgres.probe_replication_endpoint("127.0.0.1", 1, timeout=1)
    assert r["reachable"] is False
    assert r["endpoint_open"] is False
    assert r["auth_method"] == ""
    assert r["error"]


def test_endpoint_probe_unknown_auth_code_reports_by_number():
    """Any AuthenticationRequest sub-code we don't know still counts as a
    challenge — record it as ``codeNNN`` so the emitter still fires.
    """
    handler, _ = _rep_endpoint_server(auth_code=99)
    ip, port, srv = _serve(handler)
    try:
        r = postgres.probe_replication_endpoint(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert r["endpoint_open"] is True
    assert r["auth_method"] == "code99"


# ============================== finding-emit chain ============================

def _host():
    return Host(ip="10.0.0.7",
                ports=[Port(portid=5432, service="postgresql", state="open")])


def test_pg_replication_endpoint_finding_fires_on_md5_challenge():
    """Vulnerable-shape probe -> exactly one medium `pg_replication_endpoint`
    finding, CWE-306, depth_tier=t1, stable kind + exploit_note."""
    probes = {("10.0.0.7", 5432): {"reachable": True, "auth_required": True,
              "replication_endpoint": {
                  "reachable": True, "endpoint_open": True,
                  "auth_method": "md5", "auth_code": 5,
                  "error": "", "error_mentions_replication": False,
                  "user_tried": "replication"}}}
    fs = postgres.findings([_host()], probes)
    hits = [f for f in fs if f["kind"] == "pg_replication_endpoint"]
    assert len(hits) == 1
    f = hits[0]
    assert f["severity"] == "medium"
    assert f["depth_tier"] == "t1"
    assert "CWE-306" in f["cwes"]
    assert "md5" in f["detail"]
    assert "pg_basebackup" in f["command"]
    assert f["exploit_note"]                    # non-empty tester next-move


def test_pg_replication_endpoint_finding_fires_on_error_disclosure():
    probes = {("10.0.0.7", 5432): {"reachable": True, "auth_required": True,
              "replication_endpoint": {
                  "reachable": True, "endpoint_open": True,
                  "auth_method": "", "auth_code": -1,
                  "error": "no pg_hba.conf entry for replication, user \"postgres\"",
                  "error_mentions_replication": True,
                  "user_tried": "postgres"}}}
    fs = postgres.findings([_host()], probes)
    hits = [f for f in fs if f["kind"] == "pg_replication_endpoint"]
    assert len(hits) == 1
    assert "no pg_hba.conf entry for replication" in hits[0]["detail"]


def test_pg_replication_endpoint_finding_silent_when_trust_already_fires():
    """The critical `pg_replication_trust` finding covers the trust case;
    emitting a medium finding on top would double-count the same port."""
    probes = {("10.0.0.7", 5432): {"reachable": True, "auth_required": True,
              "replication": {"reachable": True, "unauth": True,
                              "auth_required": False, "version": "16.2",
                              "error": ""},
              "replication_endpoint": {
                  "reachable": True, "endpoint_open": True,
                  "auth_method": "trust", "auth_code": 0,
                  "error": "", "error_mentions_replication": False,
                  "user_tried": "replication"}}}
    fs = postgres.findings([_host()], probes)
    kinds = [f["kind"] for f in fs]
    assert "pg_replication_trust" in kinds       # critical still emitted
    assert "pg_replication_endpoint" not in kinds  # medium suppressed


def test_pg_replication_endpoint_finding_silent_when_endpoint_closed():
    """Patched shape: probe reachable but no auth challenge / no
    replication-mention error -> nothing to disclose, nothing to emit."""
    probes = {("10.0.0.7", 5432): {"reachable": True, "auth_required": True,
              "replication_endpoint": {
                  "reachable": True, "endpoint_open": False,
                  "auth_method": "", "auth_code": -1,
                  "error": "too many connections",
                  "error_mentions_replication": False,
                  "user_tried": ""}}}
    fs = postgres.findings([_host()], probes)
    assert not any(f["kind"] == "pg_replication_endpoint" for f in fs)


def test_pg_replication_endpoint_finding_silent_when_probe_unreachable():
    """Network hiccup at the probe MUST NOT invent a finding."""
    probes = {("10.0.0.7", 5432): {"reachable": True, "auth_required": True,
              "replication_endpoint": {
                  "reachable": False, "endpoint_open": False,
                  "auth_method": "", "auth_code": -1,
                  "error": "Connection refused",
                  "error_mentions_replication": False, "user_tried": ""}}}
    assert not any(f["kind"] == "pg_replication_endpoint"
                   for f in postgres.findings([_host()], probes))


def test_pg_replication_endpoint_finding_silent_when_probe_absent():
    """No probe dict at all (older probes, or the wire probe was skipped)."""
    probes = {("10.0.0.7", 5432): {"reachable": True, "auth_required": True}}
    assert not any(f["kind"] == "pg_replication_endpoint"
                   for f in postgres.findings([_host()], probes))


def test_analyze_pipeline_wires_endpoint_probe_via_monkeypatch(monkeypatch):
    """End-to-end at the analyze() layer: probe_replication_endpoint runs for
    every reachable Postgres port, and its dict lands under
    pr['replication_endpoint'] where the emitter picks it up. Uses monkeypatch
    to stub every network call — no sockets opened."""
    from recce.services.db import postgres as pg_mod
    from recce.services import svcprobe

    calls: dict = {"endpoint": 0, "rep": 0, "ssl": 0}

    def fake_iter_probe(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, {"reachable": True, "auth_required": True,
                       "unauth": False, "version": "", "error": ""}

    monkeypatch.setattr(svcprobe, "iter_probe", fake_iter_probe)
    monkeypatch.setattr(pg_mod, "probe_ssl",
                        lambda ip, port: (calls.__setitem__("ssl", calls["ssl"] + 1)
                                          or {"reachable": True,
                                              "tls_offered": True,
                                              "response": "S", "error": ""}))
    monkeypatch.setattr(pg_mod, "probe_replication",
                        lambda ip, port: (calls.__setitem__("rep", calls["rep"] + 1)
                                           or {"reachable": True, "unauth": False,
                                               "auth_required": True,
                                               "version": "", "error": ""}))
    monkeypatch.setattr(pg_mod, "probe_replication_endpoint",
                        lambda ip, port: (calls.__setitem__(
                            "endpoint", calls["endpoint"] + 1)
                            or {"reachable": True, "endpoint_open": True,
                                "auth_method": "scram-sha-256",  # falls through
                                "auth_code": 10, "error": "",
                                "error_mentions_replication": False,
                                "user_tried": "replication"}))

    h = _host()
    out = pg_mod.analyze([h], creds=None, active=True, datamine_data=False)
    assert calls["endpoint"] == 1, "endpoint probe must run once per reachable port"
    kinds = [f["kind"] for f in out["findings"]]
    assert "pg_replication_endpoint" in kinds


# ------------------------------ safety invariants -----------------------------

def test_startup_replication_still_encodes_replication_true():
    """Regression guard for the shared helper — the endpoint probe reuses
    `_startup_replication`, so silently dropping the parameter would make
    this probe indistinguishable from a plain startup and would falsify
    every finding it emits."""
    pkt = postgres._startup_replication("replication", "postgres")
    assert b"replication\x00true\x00" in pkt
    assert b"user\x00replication\x00" in pkt


def test_role_named_replication_does_not_falsely_disclose_endpoint():
    """SAFETY of the disclosure rule: an error like `role "replication" does
    not exist` mentions the word "replication" only because the tester used
    that name — the replication PATH is not referenced. Endpoint must stay
    closed so we don't emit a phantom finding on a plain missing role."""
    ip, port, srv = _serve(_rep_endpoint_error_server(
        b"role \"replication\" does not exist"))
    try:
        r = postgres.probe_replication_endpoint(ip, port, timeout=3,
                                                users=("replication",))
    finally:
        srv.shutdown()
    assert r["reachable"] is True
    assert r["endpoint_open"] is False
    assert r["error_mentions_replication"] is False
