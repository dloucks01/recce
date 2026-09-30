"""The wire under a session — the one place a live byte-pipe to a caught shell lives.

A `Session` never touches a socket directly; it holds a `Transport`. That indirection is
the C2-ready seam: a reverse-shell `SocketTransport` today, an implant/beacon transport
later, both satisfying the same tiny interface — so nothing above here changes when the
acquisition method grows.
"""
from __future__ import annotations

import abc
import asyncio


class Transport(abc.ABC):
    """One live, binary-safe byte-pipe to a target. `read()` returns b"" on EOF/close."""

    kind = "abstract"

    @abc.abstractmethod
    async def read(self) -> bytes: ...

    @abc.abstractmethod
    async def write(self, data: bytes) -> None: ...

    @abc.abstractmethod
    async def close(self) -> None: ...

    @property
    @abc.abstractmethod
    def peer(self) -> tuple[str, int]:
        """(ip, port) of the remote end — the target, which joins the engagement host."""


class SocketTransport(Transport):
    """A caught reverse shell: an asyncio TCP stream. Binary-safe, chunked reads."""

    kind = "tcp"

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._r = reader
        self._w = writer
        peer = writer.get_extra_info("peername") or ("?", 0)
        self._peer = (str(peer[0]), int(peer[1]))
        # the local end the target actually reached us on — the ideal callback address for
        # an auto-pivot upgrade (guaranteed routable back from the target)
        sn = writer.get_extra_info("sockname") or ("", 0)
        self.sockname = (str(sn[0]), int(sn[1]))
        # TCP keepalive: a half-open connection (target yanked, cable pulled) is detected
        # and torn down instead of lingering as a falsely-"live" shell.
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                import socket as _s
                sock.setsockopt(_s.SOL_SOCKET, _s.SO_KEEPALIVE, 1)
                for opt, val in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
                    if hasattr(_s, opt):
                        sock.setsockopt(_s.IPPROTO_TCP, getattr(_s, opt), val)
            except OSError:
                pass

    async def read(self) -> bytes:
        return await self._r.read(65536)

    async def write(self, data: bytes) -> None:
        self._w.write(data)
        await self._w.drain()

    async def close(self) -> None:
        try:
            self._w.close()
        except Exception:  # noqa: BLE001 — closing a dead socket must never raise
            pass

    @property
    def peer(self) -> tuple[str, int]:
        return self._peer


class BeaconTransport(Transport):
    """An async-beacon session's wire. There is no live socket — a target
    that check-ins via HTTP(S) polls drives this from the outside. The
    transport is a pair of asyncio queues: ``write()`` enqueues bytes into
    the *outbound* deque (drained by the next check-in), ``read()`` blocks
    on the *inbound* queue (fed by /beacon/result POSTs). ``Session`` above
    is oblivious to the difference — same abstract interface.

    Closing marks the beacon as stale; the row and the transcript stay
    behind so operator history is intact.

    Peer is (host_ip, 0) — a beacon has no ephemeral src port; the ip is
    the target the operator registered."""

    kind = "beacon"

    def __init__(self, host_ip: str) -> None:
        # inbound: result payloads arriving via /beacon/result. Small buffer;
        # results are drained by the Session's read loop as they come in.
        self._inbound: asyncio.Queue[bytes] = asyncio.Queue()
        # outbound: bytes destined for the next check-in. Deque so the
        # check-in handler can drain everything queued in one poll (matches
        # the design doc's `dequeue up to N` shape).
        from collections import deque
        self._outbound: deque[bytes] = deque()
        self._closed = False
        self._peer = (str(host_ip or "0.0.0.0"), 0)

    async def read(self) -> bytes:
        """Block until the next inbound payload — or return b"" on close."""
        if self._closed:
            return b""
        return await self._inbound.get()

    async def write(self, data: bytes) -> None:
        """Enqueue for the next check-in. Never blocks — beacon polls drive
        the drain, not this side."""
        if self._closed or not data:
            return
        self._outbound.append(bytes(data))

    async def close(self) -> None:
        """Mark stale + unblock any read() waiter with an EOF sentinel."""
        if self._closed:
            return
        self._closed = True
        # Wake any in-flight read() so the Session's loop exits cleanly.
        try:
            self._inbound.put_nowait(b"")
        except asyncio.QueueFull:  # pragma: no cover — unbounded queue
            pass

    @property
    def peer(self) -> tuple[str, int]:
        return self._peer

    # --- beacon-side plumbing (used by /beacon/checkin and /beacon/result)

    def drain_outbound(self, max_items: int = 32) -> list[bytes]:
        """Called by /beacon/checkin: pop up to N queued payloads FIFO."""
        out: list[bytes] = []
        for _ in range(max_items):
            if not self._outbound:
                break
            out.append(self._outbound.popleft())
        return out

    def feed_inbound(self, data: bytes) -> None:
        """Called by /beacon/result: push a payload for the Session read loop.
        Safe to call from a non-event-loop thread — asyncio.Queue is
        threadsafe via put_nowait when the loop is running on another
        thread."""
        if self._closed:
            return
        # If we're inside the loop, .put_nowait works; if we're outside it,
        # call_soon_threadsafe. The route handlers run inside the loop, so
        # the direct call is the fast path.
        try:
            self._inbound.put_nowait(bytes(data))
        except asyncio.QueueFull:  # pragma: no cover — unbounded queue
            pass

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def outbound_pending(self) -> int:
        return len(self._outbound)
