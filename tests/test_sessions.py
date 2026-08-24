"""End-to-end test of the collaborative shell-session layer, server side.

Stands up the real FastAPI app, opens a listener, connects a fake "target" socket to it,
and drives the whole vertical: catch -> Session -> WebSocket terminal (scrollback, live
output, one-driver input) -> drop -> stale -> reconnect -> REBIND to the same Session.
That last chain is the "deep shell transfer" property: a Session outlives its socket.
"""
from __future__ import annotations

import base64
import importlib.util
import pathlib
import socket
import time

import pytest
from fastapi.testclient import TestClient

REPO = pathlib.Path(__file__).resolve().parent.parent


def _load_mock():
    spec = importlib.util.spec_from_file_location(
        "mock_engagement", REPO / "tools" / "mock_engagement.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    from recce.webui.app import create_app
    eng = tmp_path_factory.mktemp("eng")
    _load_mock().build(str(eng), hosts=4, seed=7)
    app = create_app(str(eng))
    with TestClient(app) as c:          # `with` runs lifespan → binds the session loop
        yield c


def _wait(fn, timeout=5.0, interval=0.05):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(interval)
    return fn()


def _recv_until(ws, kind, timeout=5.0):
    """Drain WS envelopes until one of type `kind` (skipping scrollback/presence/status)."""
    end = time.time() + timeout
    while time.time() < end:
        env = ws.receive_json()
        if env.get("t") == kind:
            return env
    raise AssertionError(f"never saw a {kind!r} frame")


def test_listener_lifecycle(client):
    r = client.post("/api/listeners", json={"port": 0})
    assert r.status_code == 200
    lst = r.json()
    assert lst["kind"] == "tcp" and lst["status"] == "listening" and lst["port"] > 0
    assert any(x["id"] == lst["id"] for x in client.get("/api/listeners").json())
    assert client.delete(f"/api/listeners/{lst['id']}").json()["ok"] is True
    assert client.delete("/api/listeners/nope").status_code == 404


def test_catch_stream_drive_and_rebind(client):
    # open a listener on an ephemeral port
    lst = client.post("/api/listeners", json={"port": 0}).json()
    port = lst["port"]

    # a fake target dials in → recce should catch it as a session
    target = socket.create_connection(("127.0.0.1", port))
    sess = _wait(lambda: (client.get("/api/sessions").json() or [None])[0])
    assert sess and sess["status"] == "live" and sess["kind"] == "reverse-shell"
    sid = sess["id"]

    # attach a browser terminal over the WebSocket
    with client.websocket_connect(f"/api/sessions/{sid}/attach?tester=alice") as ws:
        # target output streams to the terminal (binary-safe, base64 framed)
        target.sendall(b"root@box:~# ")
        out = _recv_until(ws, "out")
        assert base64.b64decode(out["data"]) == b"root@box:~# "

        # the driver's keystrokes reach the target
        ws.send_json({"t": "in", "data": base64.b64encode(b"id\n").decode()})
        target.settimeout(5)
        assert target.recv(1024) == b"id\n"

    # --- the deep part: drop the socket → session goes stale, not gone ----------
    target.close()
    stale = _wait(lambda: next((s for s in client.get("/api/sessions").json()
                                if s["id"] == sid and s["status"] == "stale"), None))
    assert stale, "a dropped shell must leave a stale session, not vanish"

    # a new shell from the same target REBINDS to the same session
    target2 = socket.create_connection(("127.0.0.1", port))
    live_again = _wait(lambda: next((s for s in client.get("/api/sessions").json()
                                     if s["id"] == sid and s["status"] == "live"), None))
    assert live_again, "reconnect must rebind to the SAME session (id preserved)"
    # and it's still one session, not two
    assert sum(1 for s in client.get("/api/sessions").json() if s["id"] == sid) == 1
    target2.close()


def test_auto_pivot_injects_upgrade(client):
    """Auto-pivot: POST /upgrade pushes the reconnecting-PTY stager one-liner into a RAW
    shell so it upgrades itself — verify the command is actually injected into the shell."""
    lst = client.post("/api/listeners", json={"port": 0}).json()
    raw = socket.create_connection(("127.0.0.1", lst["port"]))
    raw.sendall(b"$ ")                                   # raw prompt, no stager marker
    sess = _wait(lambda: next((s for s in client.get("/api/sessions").json()
                               if s["status"] == "live" and not s["pty"]), None))
    assert sess is not None
    sid = sess["id"]
    r = client.post(f"/api/sessions/{sid}/upgrade")
    assert r.status_code == 200 and "callback" in r.json()
    # recce injected the upgrade one-liner into the raw shell's input
    raw.settimeout(5)
    got = b""
    while b"command -v python3" not in got:
        chunk = raw.recv(4096)
        if not chunk:
            break
        got += chunk
    assert b"command -v python3" in got, "the pivot stager must be injected into the shell"
    assert client.post("/api/sessions/nope/upgrade").status_code == 404
    raw.close()


def test_transcript_persists_across_restart(tmp_path):
    """A caught shell's transcript survives a `recce serve` restart, comes back browsable
    as stale, and a reconnect from the same host rebinds and resumes."""
    import asyncio

    from recce.sessions import SessionManager
    from recce.sessions.store import SessionStore
    from recce.sessions.transport import Transport

    db = str(tmp_path / "s.db")

    class FakeTransport(Transport):
        kind = "tcp"

        def __init__(self, chunks, peer=("10.0.0.9", 4444)):
            self._c = list(chunks)
            self._p = peer

        async def read(self):
            await asyncio.sleep(0)
            return self._c.pop(0) if self._c else b""   # b"" == EOF

        async def write(self, d): pass
        async def close(self): pass

        @property
        def peer(self):
            return self._p

    async def run():
        store = SessionStore(db)
        mgr = SessionManager(store=store)
        mgr.bind_loop(asyncio.get_running_loop())
        sess = await mgr.adopt(FakeTransport([b"root@x:~# ", b"whoami\r\nroot\r\n"]))
        sid = sess.id
        await asyncio.sleep(0.2)                      # pump drains -> EOF -> unbind -> flush
        assert mgr.get(sid).status == "stale"
        if mgr._flush_task:
            mgr._flush_task.cancel()
        store.close()

        # --- restart: brand-new manager + store on the same db ------------------
        store2 = SessionStore(db)
        mgr2 = SessionManager(store=store2)
        mgr2.load_persisted()
        got = mgr2.get(sid)
        assert got is not None, "session must survive a restart"
        assert got.status == "stale"
        assert got.scrollback() == b"root@x:~# whoami\r\nroot\r\n", "transcript intact"

        # a reconnect from the same host rebinds to the SAME session and resumes
        mgr2.bind_loop(asyncio.get_running_loop())
        resumed = await mgr2.adopt(FakeTransport([b"back\r\n"], peer=("10.0.0.9", 5555)))
        assert resumed.id == sid and resumed.status == "live", "reconnect resumes the session"
        if mgr2._flush_task:
            mgr2._flush_task.cancel()
        store2.close()

    asyncio.run(run())


def test_stager_handshake_pty_and_token_reconnect(client):
    """A robust-shell stager announces itself with a token → a PTY session that rebinds to
    the SAME session on reconnect (the core of a self-healing shell)."""
    lst = client.post("/api/listeners", json={"port": 0}).json()
    port = lst["port"]
    token = "tok_robust_1"

    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(b"RECCE1 " + token.encode() + b" pty\nrobust@dc01:~# ")
    sess = _wait(lambda: next((x for x in client.get("/api/sessions").json()
                               if x["status"] == "live" and x["pty"]), None))
    assert sess is not None, "stager handshake should create a PTY session"
    sid = sess["id"]
    tr = client.get(f"/api/sessions/{sid}/transcript").json()
    assert b"robust@dc01" in base64.b64decode(tr["data"]), "post-handshake bytes stream through"

    # drop → stale; reconnect WITH THE SAME TOKEN → rebinds the same session (self-healing)
    s.close()
    _wait(lambda: next((x for x in client.get("/api/sessions").json()
                        if x["id"] == sid and x["status"] == "stale"), None))
    s2 = socket.create_connection(("127.0.0.1", port))
    s2.sendall(b"RECCE1 " + token.encode() + b" pty\n")
    live = _wait(lambda: next((x for x in client.get("/api/sessions").json()
                               if x["id"] == sid and x["status"] == "live"), None))
    assert live and live["pty"], "reconnect with the token rebinds the SAME pty session"
    # a raw shell (no marker) is unaffected — still a plain, non-pty session
    raw = socket.create_connection(("127.0.0.1", port))
    raw.sendall(b"$ ")
    plain = _wait(lambda: next((x for x in client.get("/api/sessions").json()
                                if x["status"] == "live" and not x["pty"]), None))
    assert plain is not None, "raw shells still work and are marked non-pty"
    s2.close()
    raw.close()


def test_tls_listener_encrypted_handshake(client):
    """A TLS listener wraps the channel in encryption; a stager handshake over TLS still
    lands as a normal PTY session."""
    import shutil
    import ssl as _ssl
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available to generate a self-signed cert")
    lst = client.post("/api/listeners", json={"port": 0, "tls": True}).json()
    assert lst["kind"] == "tls" and lst["port"] > 0
    raw = socket.create_connection(("127.0.0.1", lst["port"]))
    s = _ssl._create_unverified_context().wrap_socket(raw, server_hostname="127.0.0.1")
    s.sendall(b"RECCE1 tok_tls_1 pty\nencrypted@dc01:~# ")
    sess = _wait(lambda: next((x for x in client.get("/api/sessions").json()
                               if x["status"] == "live" and x["pty"]), None))
    assert sess is not None, "an encrypted stager handshake should create a live PTY session"
    s.close()


def test_loot_cred_transcript_and_host_filter(client):
    lst = client.post("/api/listeners", json={"port": 0}).json()
    target = socket.create_connection(("127.0.0.1", lst["port"]))
    try:
        target.sendall(b"root@x:/# cat /etc/shadow\r\n")
        sess = _wait(lambda: next((s for s in client.get("/api/sessions").json()
                                   if s["status"] == "live"), None))
        sid = sess["id"]

        # host filter returns this host's shells
        assert any(s["id"] == sid for s in client.get("/api/sessions?host=127.0.0.1").json())
        assert client.get("/api/sessions?host=10.99.99.99").json() == []

        # transcript endpoint returns the scrollback (base64); may include rebound history
        tr = client.get(f"/api/sessions/{sid}/transcript").json()
        assert b"cat /etc/shadow" in base64.b64decode(tr["data"])

        # loot a credential from the shell → store, auto-attributed to the host
        r = client.post(f"/api/sessions/{sid}/cred",
                        json={"username": "svc_admin", "secret": "Hunter2", "kind": "password"})
        assert r.status_code == 200 and r.json()["ok"] is True
        creds = client.get("/api/credentials").json()["items"]
        looted = [c for c in creds if c.get("source") == "shell-session"]
        assert looted and looted[0]["origin_ip"] == "127.0.0.1"
        assert looted[0]["username"] == "svc_admin"

        # a cred with neither field is rejected
        assert client.post(f"/api/sessions/{sid}/cred", json={}).status_code == 400
        assert client.post("/api/sessions/nope/cred", json={"username": "x"}).status_code == 404
    finally:
        target.close()


def test_persistence_guards_and_store(client, tmp_path):
    # endpoint guards (fast paths — no shell interaction)
    assert client.post("/api/sessions/nope/persist", json={"mechanism": "cron"}).status_code == 404
    assert client.post("/api/persistence/nope/remove").status_code == 404
    assert isinstance(client.get("/api/persistence").json(), list)
    lst = client.post("/api/listeners", json={"port": 0}).json()
    raw = socket.create_connection(("127.0.0.1", lst["port"]))
    raw.sendall(b"$ ")
    sess = _wait(lambda: next((s for s in client.get("/api/sessions").json()
                               if s["status"] == "live"), None))
    # unsupported mechanism rejected before any target interaction
    assert client.post(f"/api/sessions/{sess['id']}/persist",
                       json={"mechanism": "systemd"}).status_code == 400
    raw.close()

    # store round-trip: install recorded with its remove_cmd, then marked removed
    from recce.sessions.store import SessionStore
    st = SessionStore(str(tmp_path / "p.db"))
    st.add_persistence({"id": "p1", "host_ip": "10.0.0.5", "mechanism": "cron",
                        "artifact_path": "/root/.cache/.rcabc", "remove_cmd": "crontab ...; rm ...",
                        "installed_by": "bob", "installed_at": 1.0, "removed_at": None})
    assert st.list_persistence(active_only=True)[0]["remove_cmd"].startswith("crontab")
    st.mark_persistence_removed("p1", 2.0)
    assert st.list_persistence(active_only=True) == []
    assert st.get_persistence("p1")["removed_at"] == 2.0


def test_file_transfer_and_enum_guards(client):
    # unknown session → 404 on every new endpoint
    assert client.post("/api/sessions/nope/download", json={"path": "/etc/passwd"}).status_code == 404
    assert client.post("/api/sessions/nope/upload", json={"path": "/tmp/x", "data": "QQ=="}).status_code == 404
    assert client.post("/api/sessions/nope/enum").status_code == 404
    # a live session but missing/invalid args → 400
    lst = client.post("/api/listeners", json={"port": 0}).json()
    raw = socket.create_connection(("127.0.0.1", lst["port"]))
    raw.sendall(b"$ ")
    sess = _wait(lambda: next((s for s in client.get("/api/sessions").json()
                               if s["status"] == "live"), None))
    sid = sess["id"]
    assert client.post(f"/api/sessions/{sid}/download", json={}).status_code == 400
    assert client.post(f"/api/sessions/{sid}/upload", json={"path": "/tmp/x"}).status_code == 400
    assert client.post(f"/api/sessions/{sid}/upload",
                       json={"path": "/tmp/x", "data": "not!base64"}).status_code == 400
    raw.close()


def test_input_ignored_from_non_driver(client):
    lst = client.post("/api/listeners", json={"port": 0}).json()
    target = socket.create_connection(("127.0.0.1", lst["port"]))
    try:
        # loopback rebinds prior stale sessions, so just grab the live one
        sess = _wait(lambda: next((s for s in client.get("/api/sessions").json()
                                   if s["status"] == "live"), None))
        sid = sess["id"]
        # alice attaches first → becomes driver; bob attaches → watcher only
        with client.websocket_connect(f"/api/sessions/{sid}/attach?tester=alice") as a, \
             client.websocket_connect(f"/api/sessions/{sid}/attach?tester=bob") as b:
            b.send_json({"t": "in", "data": base64.b64encode(b"rm -rf /\n").decode()})
            target.settimeout(0.5)
            with pytest.raises(socket.timeout):
                target.recv(64)          # bob is not the driver → input dropped
            # bob grabs the wheel, now his input lands
            b.send_json({"t": "wheel"})
            time.sleep(0.2)
            b.send_json({"t": "in", "data": base64.b64encode(b"whoami\n").decode()})
            assert target.recv(64) == b"whoami\n"
    finally:
        target.close()
