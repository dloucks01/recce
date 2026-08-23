"""A Session — the durable engagement object a shell binds to.

The whole "deep shell transfer" idea rests here: a Session outlives any single connection.
A `Transport` binds to it; if that transport dies the Session goes `stale` (transcript,
host link, tags all retained) and a later shell from the same target can rebind to it,
history intact. That is proto-beacon resilience with no implant — and the reason a dropped
shell doesn't mean a lost session.
"""
from __future__ import annotations

import asyncio
import time
import uuid

from .transport import Transport

_BUFFER_CAP = 256 * 1024   # scrollback ring: last ~256 KB of output replayed on attach


class Session:
    """One logical shell on one host. At most one live Transport at a time; survives losing it."""

    def __init__(self, host_ip: str, host_port: int, kind: str = "reverse-shell") -> None:
        self.id = uuid.uuid4().hex[:12]
        self.token = uuid.uuid4().hex[:16]     # for reliable re-adoption (payload can echo it)
        self.host_ip = host_ip
        self.host_port = host_port
        self.kind = kind
        self.created = time.time()
        self.status = "live"                   # live | stale | dead
        self.pty = False
        self.driver: str | None = None         # tester id currently allowed to type
        self.attached: set[str] = set()        # presence — who's watching
        self._transport: Transport | None = None
        self._buffer = bytearray()             # scrollback ring
        self._subs: set[asyncio.Queue] = set() # fan-out to attached WebSockets

    # --- connection binding (the resilience core) --------------------------------
    def bind(self, transport: Transport) -> None:
        """Attach a live connection. Called on first catch and on every re-adoption."""
        self._transport = transport
        self.status = "live"
        self._broadcast({"t": "status", "status": "live"})

    def unbind(self) -> None:
        """The connection died — keep everything, just mark the session stale."""
        self._transport = None
        if self.status != "dead":
            self.status = "stale"
        self._broadcast({"t": "status", "status": self.status})

    @property
    def connected(self) -> bool:
        return self._transport is not None

    async def send(self, data: bytes) -> None:
        """Write to the target (input). No-op if the shell is currently detached."""
        if self._transport is not None:
            await self._transport.write(data)

    # --- output fan-out + scrollback --------------------------------------------
    def feed(self, data: bytes) -> None:
        """Output from the target: append to scrollback and push to every attached UI."""
        self._buffer += data
        if len(self._buffer) > _BUFFER_CAP:
            del self._buffer[:-_BUFFER_CAP]
        self._broadcast({"t": "out", "data": data})

    def scrollback(self) -> bytes:
        return bytes(self._buffer)

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def _broadcast(self, env: dict) -> None:
        for q in list(self._subs):
            q.put_nowait(env)

    # --- presence + driver handoff (collaboration) ------------------------------
    def attach(self, tester: str) -> None:
        self.attached.add(tester)
        if self.driver is None:            # first attacher takes the wheel
            self.driver = tester
        self._presence()

    def detach(self, tester: str) -> None:
        self.attached.discard(tester)
        if self.driver == tester:          # driver left — wheel is free
            self.driver = next(iter(self.attached), None)
        self._presence()

    def take_wheel(self, tester: str) -> None:
        self.driver = tester
        self._presence()

    def _presence(self) -> None:
        self._broadcast({"t": "presence", "driver": self.driver,
                         "attached": sorted(self.attached)})

    # --- serialization for the REST list ----------------------------------------
    def info(self) -> dict:
        return {"id": self.id, "host_ip": self.host_ip, "host_port": self.host_port,
                "kind": self.kind, "status": self.status, "pty": self.pty,
                "driver": self.driver, "attached": sorted(self.attached),
                "created": self.created, "bytes": len(self._buffer)}
