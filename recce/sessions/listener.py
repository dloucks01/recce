"""Reverse-shell catcher — one adoption mechanism among several (bind-connect, relay-in,
exec-to-callback come later). It does the least it can: accept a TCP connection, wrap it as
a SocketTransport, and hand it to `manager.adopt()`. All the session/resilience logic lives
above it, so adding another acquisition mode is another small file, not a rewrite here.
"""
from __future__ import annotations

import asyncio
import uuid

# A robust-shell stager announces itself with this line so recce can bind it to the right
# session by token (survives NAT + reconnects). A raw reverse shell sends no such line — its
# first bytes are just shell output, which we must not swallow.
_MARKER = b"RECCE1 "


async def _read_handshake(transport):
    """Peek the first bytes: (token, initial_bytes, mode).

    `mode` is one of:
      * "raw" — no handshake line; the bytes we buffered ARE shell output
      * "pty" — reconnecting PTY stager
      * "oob" — dedicated out-of-band control channel (see recce/sessions/oob.py)
      * ""    — legacy bash fallback (has a token but no PTY / no OOB)

    A stager sends `RECCE1 <token> [mode]\\n`; anything else is a raw shell
    whose bytes we hand back untouched."""
    try:
        data = await asyncio.wait_for(transport.read(), timeout=2.0)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return None, b"", "raw"                       # silent raw shell (emits on input)
    if not data.startswith(_MARKER):
        return None, data, "raw"                      # raw shell — data IS shell output
    buf = bytearray(data)                             # stager line may span reads; accumulate
    while b"\n" not in buf and len(buf) < 512:
        try:
            more = await asyncio.wait_for(transport.read(), timeout=2.0)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            break
        if not more:
            break
        buf += more
    line, _, rest = bytes(buf).partition(b"\n")
    parts = line.split()
    token = parts[1].decode("ascii", "replace") if len(parts) >= 2 else None
    mode = ""
    if len(parts) >= 3:
        m = parts[2].decode("ascii", "replace").strip().lower()
        if m in ("pty", "oob"):
            mode = m
    return token, rest, mode


class Listener:
    """An asyncio TCP listener on the shared server. `kind` is typed so tls/http/dns can
    join later without the concept changing."""

    kind = "tcp"

    def __init__(self, host: str, port: int, tls: bool = False) -> None:
        self.id = uuid.uuid4().hex[:8]
        self.host = host
        self.port = port                 # 0 = ephemeral; real port filled in after start
        self.kind = "tls" if tls else "tcp"
        self.tls = tls
        self.status = "starting"
        self._server: asyncio.AbstractServer | None = None
        self._manager = None

    async def start(self, manager, ssl_ctx=None) -> None:
        self._manager = manager
        # ssl_ctx wraps every accepted connection in TLS; the RECCE1 handshake and the whole
        # relay then run over the encrypted stream transparently.
        self._server = await asyncio.start_server(self._on_conn, self.host, self.port,
                                                  ssl=ssl_ctx)
        # reflect the actually-bound port back (matters for port 0 / tests)
        sock = self._server.sockets[0]
        self.port = sock.getsockname()[1]
        self.status = "listening"

    async def _on_conn(self, reader: asyncio.StreamReader,
                       writer: asyncio.StreamWriter) -> None:
        from .transport import SocketTransport
        transport = SocketTransport(reader, writer)
        token, initial, mode = await _read_handshake(transport)
        if mode == "oob":
            # OOB control channel — bind to the parent session by token.
            # Doesn't consume the reader/writer via SocketTransport; the
            # OobChannel wraps them directly so the framed protocol is
            # untouched.
            await self._manager.adopt_oob(reader, writer, token=token)
            return
        await self._manager.adopt(transport, listener_id=self.id,
                                  token=token, initial=initial,
                                  pty=(mode == "pty"))

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
