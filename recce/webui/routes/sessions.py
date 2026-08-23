"""Shell-session routes: listeners, the session list, and the collaborative WebSocket
terminal. This is where the sessions core meets the engagement — the adoption hook links a
caught shell to its host and flips `access_gained`, and the WS carries the multiplayer
terminal (scrollback, live output, one-driver input, presence)."""
from __future__ import annotations

import base64

from fastapi import Body, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect

from ...sessions import tasking


def register_sessions_routes(app: FastAPI, ctx) -> None:
    mgr = ctx.sessions
    db_path = ctx.db_path
    broker = ctx.broker

    # --- engagement hook: caught shell → its host + the activity feed ------------
    def _link_host(session):
        from ...store import Store
        from .. import collab
        st = Store(db_path)
        try:
            host = next((h for h in st.all_hosts() if h.ip == session.host_ip), None)
            label = (host.hostname or session.host_ip) if host is not None else session.host_ip
            if host is not None and not getattr(host, "access_gained", False):
                host.access_gained = True
                st.upsert_host(host)
            collab.add_activity(st, "recce", "session", f"shell caught from {label}")
        except Exception:  # noqa: BLE001 — a hook must never break adoption
            pass
        finally:
            st.close()
        broker.publish({"type": "session", "event": "caught",
                        "ip": session.host_ip, "id": session.id})

    if _link_host not in mgr.hooks:
        mgr.hooks.append(_link_host)

    # --- listeners ---------------------------------------------------------------
    @app.get("/api/listeners")
    def list_listeners():
        return [l.info() for l in mgr.listeners.values()]

    @app.post("/api/listeners")
    async def start_listener(body: dict = Body(default=None)):
        body = body or {}
        try:
            port = int(body.get("port", 0))
        except (TypeError, ValueError):
            raise HTTPException(400, "port must be an integer")
        if not (0 <= port <= 65535):
            raise HTTPException(400, "port out of range")
        tls = bool(body.get("tls", False))
        ssl_ctx = None
        if tls:
            try:
                from ...sessions.tlscert import server_ssl_context
                ssl_ctx = server_ssl_context(ctx.eng_dir)
            except Exception as e:  # noqa: BLE001 — openssl missing / cert failure
                raise HTTPException(500, f"could not set up TLS (is openssl installed?): {e}")
        try:
            lst = await mgr.start_listener(port, host=str(body.get("host", "0.0.0.0")),
                                           tls=tls, ssl_ctx=ssl_ctx)
        except OSError as e:
            raise HTTPException(409, f"could not bind: {e}")
        broker.publish({"type": "session", "event": "listener", "port": lst.port})
        return lst.info()

    @app.delete("/api/listeners/{listener_id}")
    async def stop_listener(listener_id: str):
        if not await mgr.stop_listener(listener_id):
            raise HTTPException(404, "no such listener")
        return {"ok": True}

    # --- sessions ----------------------------------------------------------------
    @app.get("/api/sessions")
    def list_sessions(host: str = ""):
        items = mgr.list()
        if host:                                    # host drawer asks for one host's shells
            items = [s for s in items if s.host_ip == host]
        return [s.info() for s in items]

    @app.get("/api/sessions/{session_id}/transcript")
    def transcript(session_id: str):
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        # the COMPLETE history from disk (not just the live ring) so nothing is ever lost;
        # flush pending first so the very latest bytes are included
        mgr.flush_pending(session_id)
        full = mgr.store.load_transcript(session_id) if mgr.store else b""
        data = full or sess.scrollback()
        return {"id": session_id, "host_ip": sess.host_ip,
                "data": base64.b64encode(data).decode()}

    @app.post("/api/sessions/{session_id}/upgrade")
    async def upgrade(session_id: str):
        """Auto-pivot: push a reconnecting-PTY stager into a RAW shell so it upgrades itself
        into a robust session — no manual stabilize dance ('shell of a shell')."""
        import uuid
        from ...sessions.stagers import upgrade_command
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if sess.pty:
            raise HTTPException(400, "already a robust PTY session")
        if not sess.connected:
            raise HTTPException(409, "shell is not currently connected")
        if not sess.local_addr or not sess.local_addr[1]:
            raise HTTPException(409, "cannot determine a callback address for this shell")
        lhost, port = sess.local_addr            # the exact endpoint the target already reached
        token = "up_" + uuid.uuid4().hex[:12]
        await sess.send(upgrade_command(lhost, port, token).encode() + b"\n")
        broker.publish({"type": "session", "event": "upgrading", "id": sess.id})
        return {"ok": True, "callback": f"{lhost}:{port}"}

    @app.post("/api/sessions/{session_id}/cred")
    def loot_cred(session_id: str, body: dict = Body(...),
                  x_tester: str = Header(default="someone")):
        """Fold a credential found in this shell into the store — auto-attributed to the
        session's host, so it lands in Loot and the spray plan (feeds the Act loop)."""
        from ...models import Credential
        from ...store import Store
        from .. import collab
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        user = str(body.get("username", "")).strip()
        secret = str(body.get("secret", "")).strip()
        if not user and not secret:
            raise HTTPException(400, "a username or secret is required")
        kind = str(body.get("kind", "password"))
        if kind not in ("password", "nthash", "hash", "blank"):
            kind = "password"
        st = Store(db_path)
        try:
            added = st.add_credential(Credential(
                username=user, secret=secret, kind=kind,
                domain=str(body.get("domain", "")), origin_ip=sess.host_ip,
                source="shell-session", notes=f"looted from shell on {sess.host_ip}"))
            collab.add_activity(st, x_tester, "add",
                                f"{x_tester} looted a credential from the shell on {sess.host_ip}")
        finally:
            st.close()
        broker.publish({"type": "add", "what": "credential", "by": x_tester})
        return {"ok": True, "added": added}

    # --- the collaborative terminal (WebSocket) ---------------------------------
    @app.websocket("/api/sessions/{session_id}/attach")
    async def attach(ws: WebSocket, session_id: str):
        await ws.accept()
        sess = mgr.get(session_id)
        if sess is None:
            await ws.send_json({"t": "error", "msg": "no such session"})
            await ws.close()
            return
        tester = ws.query_params.get("tester", "someone")

        q = sess.subscribe()
        sess.attach(tester)
        # replay scrollback, then current presence, then stream live
        await ws.send_json({"t": "scrollback",
                            "data": base64.b64encode(sess.scrollback()).decode()})
        await ws.send_json({"t": "presence", "driver": sess.driver,
                            "attached": sorted(sess.attached)})

        import asyncio

        async def pump_out():
            while True:
                env = await q.get()
                if env["t"] == "out":
                    await ws.send_json({"t": "out",
                                        "data": base64.b64encode(env["data"]).decode()})
                else:
                    await ws.send_json(env)     # status / presence pass through

        out_task = asyncio.ensure_future(pump_out())
        try:
            while True:
                msg = await ws.receive_json()
                t = msg.get("t")
                if t == "in" and sess.driver == tester:
                    data = base64.b64decode(msg.get("data", ""))
                    await tasking.send_input(sess, data)
                elif t == "wheel":
                    sess.take_wheel(tester)
                # "resize" reserved for P1 (window-size propagation)
        except WebSocketDisconnect:
            pass
        finally:
            out_task.cancel()
            sess.unsubscribe(q)
            sess.detach(tester)
