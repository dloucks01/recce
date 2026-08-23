# Shell sessions — collaborative, engagement-native

The differentiating layer of recce-as-a-C2: caught reverse shells become **first-class,
team-shared objects inside the engagement**. This is the thing Sliver (and every other C2)
does not do — shells that live next to the findings and creds for the host they came from,
driven by the whole team in real time.

Scope of this build: the **collaboration + engagement-interaction** wedge. NOT implants,
transports, beacons, or evasion — those grow *downward* from this layer later. Every
abstraction here is chosen so that later growth slots in without a rewrite (see "C2-ready").

## Module map

    recce/sessions/
      transport.py   Transport ABC + SocketTransport   ← the C2-ready seam
      session.py     Session: state + output fan-out + scrollback ring
      listener.py    Listener: asyncio TCP accept → Session
      manager.py     SessionManager: registry, listeners, engagement hooks
      tasking.py     Task → session → result            ← C2-ready command path
    recce/webui/routes/sessions.py   REST (listeners, sessions) + WS attach
    recce/webui/frontend/src/
      Sessions.tsx   the Sessions tab (list, grouped by host)
      Terminal.tsx   xterm.js ↔ WebSocket

Everything runs on the one shared `recce serve` event loop (single-threaded asyncio →
no locks). A reverse shell is a live socket owned by that process; "handoff" is many
browsers attaching to the one server, never socket migration.

## The C2-ready seams (cheap now, decisive later)

1. **Transport interface.** A `Session` holds a `Transport` (read/write bytes + `.info`),
   not a raw socket. `SocketTransport` wraps a reverse shell today; an `ImplantTransport`
   slots in beside it later with zero changes to Session/Manager/routes.
2. **task → session → result.** Input goes through `tasking.send_input()` /
   `Task`, not string-append-to-socket. Async beacons reuse the same path later.
3. **Session identity independent of the live socket.** A Session has an id + engagement
   link that outlive any connection; a future beacon (no persistent socket) fits the model.
4. **Listener has a typed `kind`** (`tcp` now; `tls`/`http`/`dns` later).

## Ingestion & adoption — the "deep" part

A shell getting into recce is a first-class subsystem, not "accept a socket." The core
decision: **a Session is decoupled from the connection that carries it.** A `Transport`
is one live byte-pipe (a caught socket); a `Session` is the durable engagement object it
binds to. One Session has at most one *active* Transport at a time, but survives losing it.

Adoption mechanisms (all just produce a Transport that `manager.adopt()` binds to a
Session — so each is small and they share one path):

- **Reverse catch** (`listener.py`) — target dials `recce:port`. The default.
- **Bind connect** (`connector.py`, later) — recce dials OUT to a shell listening on the
  target. For when the target can't reach you but you can reach it.
- **Relay-in** (later) — a `recce relay` shim forwards a shell you caught elsewhere (nc,
  your terminal) into recce over a control channel, without re-throwing on the target.
- **Re-throw helper** — recce hands you the one-liner to spawn a fresh reverse shell from
  an existing foothold into recce's listener (the pragmatic "migrate-in").
- **Exec-to-callback** (later, big) — recce uses *looted engagement creds* (SSH/WinRM/SMB)
  to run a payload that calls back, turning credentialed access into a live session
  automatically. Only recce can do this — it owns the creds. A prime differentiator.

## Resilience — Session ≠ connection

This is what makes it deep rather than a `nc` wrapper:

- **Survive drops.** When a Transport dies, the Session goes `stale` (not deleted) — its
  transcript, host link, tags, and slot are retained.
- **Re-adopt.** A new inbound shell is matched to an existing Session (by host, and by an
  optional **session token** the recce-generated payload echoes on connect — reliable even
  behind NAT). A re-thrown shell rebinds to the *same* Session, history intact. Proto-beacon
  behavior with no implant.
- **Multiple shells per host** group under the host; each is its own Session.
- **Liveness** — heartbeat/keepalive probing marks dead shells `stale` promptly.
- **Binary-safe** streaming (raw bytes, ANSI/control chars preserved) so xterm.js is correct.

`adopt(transport, meta) -> Session`: match token → match host+stale → else new; bind; run
engagement hooks. `unbind()`: mark stale, keep everything. Every adoption mode and (later)
implants funnel through this one method — the C2-ready seam is the *binding boundary*.

## Session model

    Session
      id            short opaque id
      listener_id   which listener caught it
      remote_ip     the target — JOINS the engagement host
      remote_port
      kind          "reverse-shell" (tcp)  [C2-ready: extend]
      status        live | dead
      pty           bool (stabilized?)
      driver        tester id who currently types, or None
      attached      set of attached tester ids (presence)
      buffer        ring of recent output bytes (scrollback for late joiners)
      created

## Multiplayer model (collaboration half)

- Sessions live on the shared server → every tester sees every session.
- **One driver, many watchers.** `driver` is a soft lock: input frames are honored only
  from the current driver; anyone can `take-wheel` (broadcast + logged to activity).
- **Presence:** `attached` set per session → "who's watching/driving".
- **Scrollback:** on attach, replay `buffer`; then stream live. Survives page reload.
- **Fan-out:** each attached WebSocket gets an asyncio.Queue subscriber; socket output is
  appended to `buffer` and pushed to every subscriber.

## Engagement interaction (the other half — what no C2 does)

On session create, `SessionManager` runs the engagement hooks:
- **Host link:** match `remote_ip` → an engagement host; flip `access_gained`; the shell
  shows in that host's drawer.
- **Activity/presence:** publish `"<tester> caught a shell from <ip>"` on the SSE broker.
Later phases: creds pulled during a session fold into the store + spray plan; a transcript
(or a selected span) attaches to a finding as evidence → writeups/report.

## WebSocket protocol  (`WS /api/sessions/{id}/attach`)

JSON envelopes, both directions:

    server → browser   {t:"scrollback", data}      once, on attach
                       {t:"out", data}             live output
                       {t:"presence", driver, attached}
    browser → server   {t:"in", data}              keystrokes (honored iff you're driver)
                       {t:"wheel"}                 take the wheel
                       {t:"resize", cols, rows}

REST: `GET/POST /api/listeners`, `DELETE /api/listeners/{id}`, `GET /api/sessions`.

## Build phases (this wedge)

- **P0** — one listener → catch one shell → xterm.js over one WebSocket, built on the
  seams above. De-risks WS + terminal. (in progress)
- **P1** — listener manager, transcript persistence + scrollback replay, host link.
- **P2** — multi-attach, driver/wheel handoff, presence + activity feed.
- **engagement hooks** — creds fold, transcript → writeup.

Deferred (C2 growth, not this wedge): implants, encrypted transports, beacons, evasion.
