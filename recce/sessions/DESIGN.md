# Shell sessions — collaborative, engagement-native

Caught reverse shells become first-class, team-shared objects inside the engagement. Shells live next to the findings and creds for the host they came from, driven by the whole team in real time.

Scope: collaboration + engagement interaction. NOT implants, transports, beacons, or evasion — those grow downward from this layer later.

## Module map

    recce/sessions/
      transport.py   Transport ABC + SocketTransport
      session.py     Session: state + output fan-out + scrollback ring
      listener.py    Listener: asyncio TCP accept → Session
      manager.py     SessionManager: registry, listeners, engagement hooks
      tasking.py     Task → session → result
    recce/webui/routes/sessions.py   REST + WS attach
    recce/webui/frontend/src/
      Sessions.tsx   Sessions tab (list, grouped by host)
      Terminal.tsx   xterm.js ↔ WebSocket

Single-threaded asyncio on the `recce serve` event loop. A reverse shell is a live socket; "handoff" is many browsers attaching to the one server.

## C2-ready seams

1. **Transport interface.** Session holds a Transport, not a raw socket. `SocketTransport` today; `ImplantTransport` slots in later with zero changes to Session/Manager/routes.
2. **Task path.** Input goes through `tasking.send_input()` / `Task`. Async beacons reuse the same path.
3. **Session identity.** Id + engagement link outlive any connection; a beacon (no persistent socket) fits the model.
4. **Listener kind.** `tcp` now; `tls`/`http`/`dns` later.

## Session ≠ connection

- **Survive drops.** Transport dies → Session goes `stale` (transcript, host link, tags retained).
- **Re-adopt.** New inbound shell matched to existing Session by host or session token. History intact.
- **Multiple shells per host** group under the host; each is its own Session.
- **Liveness** — heartbeat probing marks dead shells `stale` promptly.
- **Binary-safe** streaming (ANSI/control chars preserved for xterm.js).

`adopt(transport, meta) -> Session`: match token → match host+stale → else new; bind; run engagement hooks.

## Session model

    Session
      id, listener_id, remote_ip, remote_port
      kind          "reverse-shell" (tcp)
      status        live | dead
      pty           bool (stabilized?)
      driver        tester id (soft lock) or None
      attached      set of attached tester ids
      buffer        ring of recent output (scrollback)
      created

## Multiplayer

- One driver, many watchers. Input honored only from current driver; anyone can `take-wheel`.
- Presence per session. Scrollback replay on attach; then live stream.
- Fan-out via asyncio.Queue subscribers per WebSocket.

## Engagement hooks

On session create: match `remote_ip` → engagement host, flip `access_gained`, publish to activity feed. Later: creds fold into store, transcript attaches as finding evidence.

## WebSocket protocol (`WS /api/sessions/{id}/attach`)

    server → browser   {t:"scrollback", data}
                       {t:"out", data}
                       {t:"presence", driver, attached}
    browser → server   {t:"in", data}
                       {t:"wheel"}
                       {t:"resize", cols, rows}

REST: `GET/POST /api/listeners`, `DELETE /api/listeners/{id}`, `GET /api/sessions`.

## Build phases

- **P0** — listener → catch shell → xterm.js over WS. Done.
- **P1** — listener manager, transcript persistence, scrollback, host link. Done.
- **P2** — multi-attach, driver/wheel handoff, presence + activity. Done.
- **Engagement hooks** — creds fold, transcript → writeup. Next.

Deferred: implants, encrypted transports, beacons, evasion.
