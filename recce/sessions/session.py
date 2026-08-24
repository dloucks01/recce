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
from collections import deque

from .transport import Transport

# Deep scrollback so a tester never worries about losing recent history in the terminal;
# the COMPLETE transcript is always on disk (store) and downloadable — this is just the
# live in-memory window replayed on attach. Held as a deque of chunks so trimming is O(1).
_BUFFER_CAP = 1024 * 1024   # 1 MB of live scrollback


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
        self.label: str = ""                   # user-editable name ("initial foothold", etc.)
        self.driver: str | None = None         # tester id currently allowed to type
        self.attached: set[str] = set()        # presence — who's watching
        self.last_seen = time.time()           # last byte from the target (liveness)
        self.local_addr: tuple[str, int] | None = None  # addr the target reached us on
        self._cap: bytearray | None = None     # capture buffer for run_and_capture()
        self._cap_end: bytes = b""
        self._cap_future: asyncio.Future | None = None
        self._transport: Transport | None = None
        self._chunks: deque[bytes] = deque()   # scrollback ring (O(1) trim)
        self._blen = 0                         # running byte length of the ring
        self._subs: set[asyncio.Queue] = set() # fan-out to attached WebSockets

    @classmethod
    def restore(cls, meta: dict, transcript: bytes) -> "Session":
        """Rebuild a session from persisted state on startup — detached (`stale`) but with
        its id/token/host and full scrollback, so it's browsable and can be rebound."""
        s = cls(host_ip=meta["host_ip"], host_port=meta["host_port"] or 0,
                kind=meta.get("kind", "reverse-shell"))
        s.id = meta["id"]
        s.token = meta["token"]
        s.created = meta.get("opened") or s.created
        s.pty = bool(meta.get("pty"))
        s.label = meta.get("label", "")
        s.status = "stale"
        if transcript:
            tail = transcript[-_BUFFER_CAP:]
            s._chunks.append(tail)
            s._blen = len(tail)
        return s

    # --- connection binding (the resilience core) --------------------------------
    def bind(self, transport: Transport) -> None:
        """Attach a live connection. Called on first catch and on every re-adoption."""
        self._transport = transport
        self.local_addr = getattr(transport, "sockname", None)  # for auto-pivot callback
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
        """Output from the target: append to scrollback (O(1) trim) and fan out to every UI."""
        if data:
            self.last_seen = time.time()
            self._chunks.append(data)
            self._blen += len(data)
            while self._blen > _BUFFER_CAP and len(self._chunks) > 1:
                self._blen -= len(self._chunks.popleft())
            if self._cap is not None:              # a run_and_capture() is collecting
                self._cap += data
                if self._cap_end in self._cap and self._cap_future and not self._cap_future.done():
                    self._cap_future.set_result(True)
        self._broadcast({"t": "out", "data": data})

    async def run_and_capture(self, command: bytes, timeout: float = 30.0) -> bytes:
        """Run a command in the shell and return just its output — used for file transfer and
        running recce's enum through the shell. Markers are printed via a split-string trick
        (`'__RECCE''_S_..'`) so the literal marker only appears in the OUTPUT, never in the
        echoed command line, making extraction robust on an echoing PTY."""
        if not self.connected:
            return b""
        tag = uuid.uuid4().hex[:8].encode()
        start = b"__RECCE_S_" + tag + b"__"
        end = b"__RECCE_E_" + tag + b"__"
        self._cap = bytearray()
        self._cap_end = end
        loop = asyncio.get_event_loop()
        self._cap_future = loop.create_future()
        # split the markers with '' so the echoed command line never contains them contiguously
        wrapped = (b"printf '__RECCE''_S_" + tag + b"__\\n'; " + command
                   + b"; printf '__RECCE''_E_" + tag + b"__\\n'\n")
        try:
            await self.send(wrapped)
            await asyncio.wait_for(self._cap_future, timeout)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        data = bytes(self._cap or b"")
        self._cap = None
        self._cap_end = b""
        self._cap_future = None
        s = data.find(start)
        e = data.find(end, s + len(start)) if s >= 0 else -1
        return data[s + len(start):e] if (s >= 0 and e >= 0) else b""

    def scrollback(self) -> bytes:
        return b"".join(self._chunks)

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
                "label": self.label, "driver": self.driver, "attached": sorted(self.attached),
                "created": self.created, "last_seen": self.last_seen, "bytes": self._blen}
