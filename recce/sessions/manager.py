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

    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}
        self.listeners: dict[str, Listener] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        # engagement hooks: callables(session) run on adoption (host link, activity, …).
        # Kept as callbacks so this module stays free of webui/store imports.
        self.hooks: list = []

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    # --- listeners ---------------------------------------------------------------
    async def start_listener(self, port: int, host: str = "0.0.0.0") -> Listener:
        lst = Listener(host, port)
        await lst.start(self)
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
                    token: str | None = None) -> Session:
        """Bind a freshly-arrived connection to a Session — new, or an existing stale one
        it should resume. Every acquisition mode ends here."""
        ip, port = transport.peer
        sess = self._match(ip, token)
        if sess is None:
            sess = Session(host_ip=ip, host_port=port)
            self.sessions[sess.id] = sess
        sess.bind(transport)
        # pump target → session output in the background
        asyncio.ensure_future(self._pump(sess, transport))
        for hook in list(self.hooks):
            try:
                hook(sess)
            except Exception:  # noqa: BLE001 — a hook must never kill adoption
                pass
        return sess

    def _match(self, ip: str, token: str | None) -> Session | None:
        """token (exact, NAT-safe) → a stale session for the same host → None (new)."""
        if token:
            for s in self.sessions.values():
                if s.token == token:
                    return s
        for s in self.sessions.values():          # resume a dropped shell from this host
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
        except (ConnectionError, OSError):
            pass
        finally:
            if sess._transport is transport:      # only unbind if still the live one
                sess.unbind()

    # --- access ------------------------------------------------------------------
    def get(self, session_id: str) -> Session | None:
        return self.sessions.get(session_id)

    def list(self) -> list[Session]:
        return sorted(self.sessions.values(), key=lambda s: s.created, reverse=True)
