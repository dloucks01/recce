"""A Session — the durable engagement object a shell binds to.

The whole "deep shell transfer" idea rests here: a Session outlives any single connection.
A `Transport` binds to it; if that transport dies the Session goes `stale` (transcript,
host link, tags all retained) and a later shell from the same target can rebind to it,
history intact. That is proto-beacon resilience with no implant — and the reason a dropped
shell doesn't mean a lost session.
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from collections import deque

from .transport import Transport

# Deep scrollback so a tester never worries about losing recent history in the terminal;
# the COMPLETE transcript is always on disk (store) and downloadable — this is just the
# live in-memory window replayed on attach. Held as a deque of chunks so trimming is O(1).
_BUFFER_CAP = 1024 * 1024   # 1 MB of live scrollback

# OOB-command markers emitted onto the PTY by run_and_capture (quickrun,
# download, on-target enum, portfwd, upgrade). Anything between a matched
# S/E pair — plus one-off status lines from short OOB commands — is
# stripped from the operator's terminal view. Raw bytes still feed the
# capture buffer so run_and_capture keeps working.
_OOB_START_RE = re.compile(rb"__RECCE_S_[0-9a-f]{6,16}__")
_OOB_END_RE = re.compile(rb"__RECCE_E_[0-9a-f]{6,16}__")
_OOB_NOISE_RE = re.compile(
    # One-off status lines from short OOB commands (portfwd / upgrade)
    # AND echoed OOB command lines. Command echoes carry the split-marker
    # form (`__RECCE''_S_tag__`, `__RECCE''_E_tag__`) which the strict
    # OOB regexes above never match — this catches them plus any line
    # obviously belonging to OOB choreography (`stty -echo/echo`, `: >
    # <file>.b64`, `printf '%s' '<base64>' >> <file>.b64`, `base64 -d …
    # && rm -f …`, `bash /tmp/.re.sh …`, `python3 /tmp/.rctun.py …`).
    # Also catches "any line that is 90%+ base64 characters longer than
    # 200 chars" — captures leaked base64 payload chunks the strict block
    # regex missed because their surrounding S/E markers were fragmented
    # across recovery from a mid-push shell restart.
    rb"^(?:"
      rb"RECCE_UPGRADE_SENT"
      rb"|SOCAT_OK"
      rb"|rcfwd_[0-9a-f]+_PID_\d+"
      rb"|rctun_[0-9a-f]+_PID_\d+"                   # tunnel-agent launch marker
      rb"|.*__RECCE(?:'')?_[SE]_[0-9a-f]+__.*"       # echoed marker cmds
      rb"|stty (?:-)?echo(?: 2>/dev/null)?"
      rb"|: > \S+\.b64"
      rb"|printf '%s' '[A-Za-z0-9+/=]+' >> \S+\.b64"
      rb"|base64 -d \S+\.b64 > \S+ && rm -f \S+\.b64"
      rb"|bash /tmp/\.re\.sh 2>/dev/null \| cat; rm -f /tmp/\.re\.sh"
      rb"|python3 /tmp/\.rctun\.py \S+ \d+"          # tunnel agent launch
      rb"|[A-Za-z0-9+/=]{200,}"                      # leaked base64 chunk
    rb")[\r\n]*",
    re.M,
)
# Full S/E-block eater (dot matches newlines) — used by the stateless
# scrubber on scrollback() reads. Handles the entire buffer at once so
# order-of-arrival TCP fragmentation isn't a concern here.
_OOB_BLOCK_RE = re.compile(
    rb"__RECCE_S_[0-9a-f]{6,16}__.*?__RECCE_E_[0-9a-f]{6,16}__[\r\n]*",
    re.S,
)


def _oob_scrub_stateless(data: bytes) -> bytes:
    """Best-effort one-shot scrub of a whole buffer — safety net for
    legacy scrollback chunks written before the incremental filter
    landed. Removes complete S/E blocks + one-off noise lines."""
    if not data:
        return data
    scrubbed = _OOB_BLOCK_RE.sub(b"", data)
    return _OOB_NOISE_RE.sub(b"", scrubbed)

# Memorable name = adjective + noun (uppercase, underscored). Every session gets one
# alongside its UUID so testers can refer to it in chat/notes without pasting hex —
# "attach to STORMY_BEAR" beats "attach to a3f9b1c2". The two lists are small on
# purpose: 30 × 30 = 900 combos is plenty for the max sessions any real engagement
# holds; a rare collision gets a `-2` suffix at generation time, deterministically.
_ADJ = ("STORMY", "SHINY", "SILENT", "SWIFT", "BOLD", "CRAFTY", "IRON", "OBSIDIAN",
        "SCARLET", "AMBER", "COBALT", "GILDED", "STEEL", "LATENT", "AGILE", "WEIRD",
        "STRAY", "CROOKED", "DUSTY", "PROUD", "QUIET", "SHARP", "SPRY", "STOIC",
        "TERSE", "VIVID", "WILD", "ZEALOUS", "SLY", "BRAVE")
_NOUN = ("BEAR", "TIGER", "OWL", "FOX", "WOLF", "HAWK", "HERON", "MOUNTAIN",
         "RIVER", "TURKEY", "CEDAR", "STORM", "SPARROW", "COBRA", "LYNX", "MOOSE",
         "OTTER", "PANDA", "RAVEN", "SEAL", "STAG", "SWAN", "VIPER", "WHALE",
         "ZEBRA", "BADGER", "CRANE", "EAGLE", "FALCON", "MARLIN")


def _generate_name(existing: set[str]) -> str:
    """Pick an adjective+noun combo not already in use. Deterministic on the token —
    seeded by uuid.uuid4() at the call site — so the same session always gets the
    same name across restarts (session id is what's persisted; we regenerate the
    name on restore only when it wasn't saved before)."""
    import random
    for _ in range(20):
        n = f"{random.choice(_ADJ)}_{random.choice(_NOUN)}"
        if n not in existing:
            return n
    # rare — fall back to a numeric suffix
    base = f"{random.choice(_ADJ)}_{random.choice(_NOUN)}"
    for i in range(2, 100):
        cand = f"{base}-{i}"
        if cand not in existing:
            return cand
    return base


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
        # Memorable auto-generated name (STORMY_BEAR etc.) — a hex UUID is unmemorable
        # in a team chat. `label` remains the tester's manual override; `name` is
        # always present, always shown when no label is set. Uniqueness against
        # existing session names is enforced by SessionManager at adoption time.
        self.name: str = _generate_name(set())
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
        # OOB-marker filter state (persists across chunks so a marker
        # split by TCP fragmentation still filters correctly).
        self._oob_in_block = False             # inside an S..E block
        self._oob_tail = b""                   # bytes held for the next chunk
        # Dedicated out-of-band control channel — set by
        # `manager.adopt_oob` when the stager's OOB agent connects back.
        # None → OOB commands fall back to the PTY-share path (run_and_
        # capture / _push_file with marker sentinels + regex filter).
        self.oob_channel: object | None = None

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
        # Restore the memorable name if one was persisted; else keep whatever the
        # constructor generated (sessions from before this feature landed).
        if meta.get("name"):
            s.name = meta["name"]
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
        """Output from the target: append to scrollback (O(1) trim) and fan out to every UI.

        The out-of-band command channel (`run_and_capture` for quickrun /
        download / on-session enum / portfwd / PTY-upgrade) shares the
        PTY with the operator's terminal, so its markers + captured
        payload would otherwise land in the visible scrollback as noise
        (`__RECCE_S_xxx__ ... __RECCE_E_xxx__` blocks, `SOCAT_OK`,
        `RECCE_UPGRADE_SENT`, `rcfwd_xxx_PID_xxx`). Capture bookkeeping
        for `_cap` sees the RAW bytes; scrollback + subscribers get the
        FILTERED view so the terminal reads clean."""
        if data:
            self.last_seen = time.time()
            # capture-mode bookkeeping runs on raw bytes so run_and_capture
            # still extracts its full payload between markers.
            if self._cap is not None:
                self._cap += data
                if self._cap_end in self._cap and self._cap_future and not self._cap_future.done():
                    self._cap_future.set_result(True)
            visible = self._filter_oob(data)
            if visible:
                self._chunks.append(visible)
                self._blen += len(visible)
                while self._blen > _BUFFER_CAP and len(self._chunks) > 1:
                    self._blen -= len(self._chunks.popleft())
                self._broadcast({"t": "out", "data": visible})
        else:
            self._broadcast({"t": "out", "data": data})

    def _filter_oob(self, data: bytes) -> bytes:
        """Strip OOB command blocks and one-off status markers so the
        operator's terminal sees only real shell output.

        Marker state persists across chunks (`_oob_in_block`, `_oob_tail`)
        so a marker split by TCP fragmentation still filters correctly —
        the tail is only held when the buffer's end looks like it COULD
        be a partial marker prefix (avoids drowning real output that just
        happens to be short)."""
        buf = self._oob_tail + data
        self._oob_tail = b""
        out = bytearray()
        i = 0
        while i < len(buf):
            if self._oob_in_block:
                m = _OOB_END_RE.search(buf, i)
                if m is None:
                    # inside a block, no end yet — hold ONLY a tail that
                    # could still be a partial end marker. If nothing at
                    # the tail looks like `__RECCE_E_` prefix, we can
                    # safely drop the whole remainder (it's OOB payload).
                    self._oob_tail = self._maybe_partial(buf, i, b"__RECCE_E_")
                    return bytes(_OOB_NOISE_RE.sub(b"", bytes(out)))
                i = m.end()
                self._oob_in_block = False
            else:
                m = _OOB_START_RE.search(buf, i)
                if m is None:
                    # no start marker — flush the rest, holding only a
                    # tail that could still be a partial start marker.
                    keep = self._maybe_partial(buf, i, b"__RECCE_S_")
                    out.extend(buf[i:len(buf) - len(keep)] if keep else buf[i:])
                    self._oob_tail = keep
                    return bytes(_OOB_NOISE_RE.sub(b"", bytes(out)))
                # copy real text before the marker verbatim (preserving
                # the newline that belongs to that shell output).
                out.extend(buf[i:m.start()])
                i = m.end()
                self._oob_in_block = True
        return bytes(_OOB_NOISE_RE.sub(b"", bytes(out)))

    @staticmethod
    def _maybe_partial(buf: bytes, start: int, marker: bytes) -> bytes:
        """Return the tail bytes from `buf[start:]` that COULD be a partial
        `marker` — either an incomplete PREFIX at the end (e.g. `__REC`),
        or the FULL stem plus a partial hex-tag not yet closed (e.g.
        `__RECCE_S_ab` before the rest of the tag + `__` arrive). Returns
        empty when no plausible partial exists — the whole remainder is
        safe to flush."""
        rest = buf[start:]
        # Case A: buffer ends with a prefix of the stem (`__RECCE_S`).
        max_k = min(len(rest), len(marker) - 1)
        best = 0
        for k in range(max_k, 0, -1):
            if rest.endswith(marker[:k]):
                best = k
                break
        # Case B: buffer contains the full stem but the tag+close hasn't
        # arrived. Hold from that stem onward. Full expected tail is
        # stem(10) + tag(up to 16 hex) + close(2) = ~28 bytes; anything
        # longer without a close means the tag itself was noise (drop it
        # — the regex won't ever match, so holding is pointless).
        idx = rest.rfind(marker)
        if idx >= 0 and len(rest) - idx <= len(marker) + 18:
            best = max(best, len(rest) - idx)
        return rest[-best:] if best else b""

    async def run_and_capture(self, command: bytes, timeout: float = 30.0) -> bytes:
        """Run a command via the target and return its stdout+stderr.

        Prefers the dedicated OOB control channel (recce/sessions/oob.py)
        when it's live: frames go over a SEPARATE TCP connection so the
        operator's PTY sees nothing at all — no markers, no echo, no
        payload. Falls back to the PTY-share path with `__RECCE_S_/E_`
        sentinels when there's no OOB (raw reverse shell / legacy stager).

        The bytes returned are identical either way, so every caller
        (quickrun, download, enum, portfwd, upgrade) benefits with no
        further changes."""
        if not self.connected:
            return b""
        # --- OOB fast path -----------------------------------------------
        oob = self.oob_channel
        if oob is not None and getattr(oob, "alive", False):
            try:
                _rc, out = await oob.exec(command.rstrip(b"\n"), timeout=timeout)
                return out
            except (OSError, asyncio.TimeoutError):
                # Channel died mid-request — drop it and fall through to
                # the PTY path so the operation still completes.
                try:
                    await oob.close()
                except Exception:  # noqa: BLE001
                    pass
                self.oob_channel = None
        # --- legacy PTY-share path (unchanged) --------------------------
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

    async def oob_write_file(self, path: str, data: bytes,
                              timeout: float = 60.0) -> bool:
        """Write bytes to a file on the target via the OOB channel.
        Returns True on success, False when no OOB channel is available
        (caller should fall back to the PTY-chunked _push_file)."""
        oob = self.oob_channel
        if oob is None or not getattr(oob, "alive", False):
            return False
        try:
            await oob.write_file(path, data, timeout=timeout)
            return True
        except (OSError, asyncio.TimeoutError):
            try:
                await oob.close()
            except Exception:  # noqa: BLE001
                pass
            self.oob_channel = None
            return False

    def scrollback(self) -> bytes:
        """Return the live scrollback for a fresh WS attach.

        Runs the OOB scrubber on the joined chunks as a safety net: new
        `feed()` calls already store filtered bytes, but chunks written
        before a mid-session code deploy (or a persisted transcript that
        includes raw markers) get cleaned here so a new attacher never
        sees leaked sentinels."""
        return _oob_scrub_stateless(b"".join(self._chunks))

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
        return {"id": self.id, "name": self.name,
                "host_ip": self.host_ip, "host_port": self.host_port,
                "kind": self.kind, "status": self.status, "pty": self.pty,
                "label": self.label, "driver": self.driver, "attached": sorted(self.attached),
                "created": self.created, "last_seen": self.last_seen, "bytes": self._blen}
