"""SessionManager — the one owner of listeners and sessions, and the single `adopt()`
boundary every shell funnels through.

`adopt(transport)` is the C2-ready seam: reverse-catch produces a transport and calls it;
bind-connect, relay-in, and (later) implants will produce a transport and call the very
same method. Match logic (token → stale-host → new) lives here once, so resilience and
re-adoption are uniform across every acquisition mode.
"""
from __future__ import annotations

import asyncio

from .listener import Listener
from .session import Session
from .transport import Transport


class SessionManager:
    """Registry of listeners + sessions. Single-threaded on the serving asyncio loop."""

    def __init__(self, store=None) -> None:
        self.sessions: dict[str, Session] = {}
        self.listeners: dict[str, Listener] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        # engagement hooks: callables(session) run on adoption (host link, activity, …).
        # Kept as callbacks so this module stays free of webui/store imports.
        self.hooks: list = []
        self.store = store                          # optional SessionStore for durability
        self._pending: dict[str, bytearray] = {}    # per-session transcript, batched
        self._flush_task = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        if self.store is not None and self._flush_task is None:
            self._flush_task = loop.create_task(self._flush_loop())

    def load_persisted(self) -> None:
        """Reload past sessions from the store as stale — call once before serving."""
        if self.store is None:
            return
        for meta, transcript in self.store.load_sessions():
            if meta["id"] not in self.sessions:
                self.sessions[meta["id"]] = Session.restore(meta, transcript)

    # --- transcript persistence (batched so we don't hit sqlite per chunk) -------
    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            self._flush_all()

    def _flush_all(self) -> None:
        if self.store is None:
            return
        for sid, buf in list(self._pending.items()):
            if buf:
                self.store.append(sid, bytes(buf))
                buf.clear()

    def flush_pending(self, session_id: str) -> None:
        """Flush one session's un-persisted transcript bytes to disk right now."""
        if self.store is None:
            return
        buf = self._pending.get(session_id)
        if buf:
            self.store.append(session_id, bytes(buf))
            buf.clear()

    def _record(self, session_id: str, data: bytes) -> None:
        buf = self._pending.setdefault(session_id, bytearray())
        buf.extend(data)
        if len(buf) >= 8192:                        # flush a big burst promptly
            self.store.append(session_id, bytes(buf))
            buf.clear()

    def _save(self, sess: Session) -> None:
        if self.store is not None:
            self.store.save_session(sess)

    # --- listeners ---------------------------------------------------------------
    async def start_listener(self, port: int, host: str = "0.0.0.0",
                             tls: bool = False, ssl_ctx=None) -> Listener:
        lst = Listener(host, port, tls=tls)
        await lst.start(self, ssl_ctx=ssl_ctx)
        self.listeners[lst.id] = lst
        return lst

    async def stop_listener(self, listener_id: str) -> bool:
        lst = self.listeners.pop(listener_id, None)
        if not lst:
            return False
        await lst.stop()
        return True

    # --- adoption: the single boundary ------------------------------------------
    async def adopt(self, transport: Transport, listener_id: str = "",
                    token: str | None = None, initial: bytes = b"",
                    pty: bool = False) -> Session:
        """Bind a freshly-arrived connection to a Session — new, or an existing stale one
        it should resume. Every acquisition mode ends here. A stager presents a `token`
        (reliable NAT-safe re-adoption) and `pty=True`; a raw reverse shell has neither and
        its first bytes arrive as `initial`."""
        ip, port = transport.peer
        sess = self._match(ip, token)
        new = sess is None
        if sess is None:
            sess = Session(host_ip=ip, host_port=port)
            if token:
                sess.token = token          # the stager's embedded token IS the session's,
            self.sessions[sess.id] = sess   # so every reconnect rebinds to this same session
        if pty:
            sess.pty = True
        sess.bind(transport)
        if initial:                          # raw shell's first output / stager leftover
            sess.feed(initial)
            if self.store is not None:
                self._record(sess.id, initial)
        self._save(sess)                     # persist metadata (status → live)
        # pump target → session output in the background
        asyncio.ensure_future(self._pump(sess, transport))
        if new:                              # host-link + "shell caught" only once, not per reconnect
            for hook in list(self.hooks):
                try:
                    hook(sess)
                except Exception:  # noqa: BLE001 — a hook must never kill adoption
                    pass
        return sess

    def _match(self, ip: str, token: str | None) -> Session | None:
        """A tokened stager matches its exact session (NAT-safe) or starts fresh — it never
        grabs an unrelated host's stale session. A raw shell (no token) resumes a stale
        session from the same host."""
        if token:
            for s in self.sessions.values():
                if s.token == token:
                    return s
            return None                           # unknown token → a new agent, not host-fallback
        for s in self.sessions.values():          # raw shell: resume a dropped shell from this host
            if s.host_ip == ip and s.status == "stale":
                return s
        return None

    async def _pump(self, sess: Session, transport: Transport) -> None:
        """Read the target until EOF, feeding output into the session. On close → stale."""
        try:
            while True:
                data = await transport.read()
                if not data:                      # EOF: the shell dropped
                    break
                sess.feed(data)
                if self.store is not None:
                    self._record(sess.id, data)   # persist output (batched)
        except (ConnectionError, OSError):
            pass
        finally:
            if sess._transport is transport:      # only unbind if still the live one
                sess.unbind()
                if self.store is not None:
                    self._flush_all()             # flush remaining transcript
                    self._save(sess)              # persist status → stale

    # --- access ------------------------------------------------------------------
    def get(self, session_id: str) -> Session | None:
        return self.sessions.get(session_id)

    def list(self) -> list[Session]:
        return sorted(self.sessions.values(), key=lambda s: s.created, reverse=True)
