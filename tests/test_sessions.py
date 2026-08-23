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
