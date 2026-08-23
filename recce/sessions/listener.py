"""Reverse-shell catcher — one adoption mechanism among several (bind-connect, relay-in,
exec-to-callback come later). It does the least it can: accept a TCP connection, wrap it as
a SocketTransport, and hand it to `manager.adopt()`. All the session/resilience logic lives
above it, so adding another acquisition mode is another small file, not a rewrite here.
"""
from __future__ import annotations

import asyncio
import uuid


class Listener:
    """An asyncio TCP listener on the shared server. `kind` is typed so tls/http/dns can
    join later without the concept changing."""

    kind = "tcp"

    def __init__(self, host: str, port: int) -> None:
        self.id = uuid.uuid4().hex[:8]
        self.host = host
        self.port = port                 # 0 = ephemeral; real port filled in after start
        self.status = "starting"
        self._server: asyncio.AbstractServer | None = None
        self._manager = None

    async def start(self, manager) -> None:
        self._manager = manager
        self._server = await asyncio.start_server(self._on_conn, self.host, self.port)
        # reflect the actually-bound port back (matters for port 0 / tests)
        sock = self._server.sockets[0]
        self.port = sock.getsockname()[1]
        self.status = "listening"

    async def _on_conn(self, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
        from .transport import SocketTransport
        transport = SocketTransport(reader, writer)
        await self._manager.adopt(transport, listener_id=self.id)

    async def stop(self) -> None:
        self.status = "stopped"
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    def info(self) -> dict:
        return {"id": self.id, "host": self.host, "port": self.port,
                "kind": self.kind, "status": self.status}
