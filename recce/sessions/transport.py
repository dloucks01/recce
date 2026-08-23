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
