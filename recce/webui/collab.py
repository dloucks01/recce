"""Multi-tester collaboration state for the web workbench.

State is stored one row per item in the datastore's `collab_*` tables, each write
atomic under BEGIN IMMEDIATE (see recce/core/store.py) — so two testers acting at
the same moment, even from separate processes, can't clobber each other the way
the previous whole-blob JSON rewrite could. Backward-compatible: an older
engagement's `meta` JSON blobs are migrated into the tables on first open, and a
brand-new engagement simply has empty tables (every getter returns an empty
default). Presence stays in-memory (ephemeral — who's online right now).

These module functions are thin wrappers over the Store methods, kept so the route
layer and tests keep their existing `collab.get_x(st)` / `collab.set_x(st, ...)`
call shape.
"""
from __future__ import annotations

import threading
import time
import uuid

LABELS = ("interesting", "needs-review", "out-of-scope")


# --- assignments --------------------------------------------------------------
def get_assignments(st) -> dict:
    return st.collab_assignments()


def set_assignment(st, ip: str, tester: str) -> dict:
    return st.collab_set_assignment(ip, tester)


# --- triage labels ------------------------------------------------------------
def get_labels(st) -> dict:
    return st.collab_labels()


def set_label(st, ip: str, label: str, on: bool) -> dict:
    return st.collab_set_label(ip, label, on)


# --- per-port tri-state -------------------------------------------------------
def get_port_status(st) -> dict:
    return st.collab_ports()


def set_port_status(st, ip: str, port, status: str) -> dict:
    return st.collab_set_port(f"{ip}:{port}", status)


# --- dismissed (not-a-finding) ------------------------------------------------
def get_dismissed(st) -> dict:
    return st.collab_dismissed()


def set_dismissed(st, key: str, tester: str, on: bool) -> dict:
    return st.collab_set_dismiss(key, tester, on)


# --- activity log -------------------------------------------------------------
def add_activity(st, tester: str, kind: str, text: str) -> dict:
    # UIs render `<tester> <text>` side-by-side; callers historically prefixed
    # the tester name into text too — strip it so the name doesn't double-print.
    t = (tester or "").strip()
    if t and text.startswith(t + " "):
        text = text[len(t) + 1:]
    return st.collab_add_activity(tester, kind, text)


def get_activity(st, limit: int = 100) -> list:
    return st.collab_activity(limit)             # newest first


# --- team chat ----------------------------------------------------------------
def add_chat(st, tester: str, text: str, image: str = "", file: dict | None = None) -> dict:
    """Append a chat message. `image` is a stored media filename (or "" for text-only) -
    rendered as an inline thumbnail. `file` is {"stored", "name", "size"} for a general
    (non-image) attachment - rendered as a download link, never inline (see the app
    layer's forced attachment/octet-stream serving - a stored file is never trusted
    enough to render in-origin). Message metadata lives in the store; bytes live on disk."""
    msg = {"id": uuid.uuid4().hex[:12], "ts": time.time(),
           "tester": tester or "someone", "text": text, "image": image,
           "file": file}
    return st.collab_add_chat(msg)


def get_chat(st, limit: int = 200) -> list:
    return st.collab_chat(limit)                 # oldest -> newest, for a chat transcript


# recognise the common image types a paste can produce (magic bytes -> extension)
def image_ext(raw: bytes) -> str:
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if raw[:3] == b"\xff\xd8\xff":
        return "jpg"
    if raw[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "webp"
    return ""


class Presence:
    """In-memory roster of who's active, pruned by a staleness window. Also tracks
    per-entity focus ("who's editing this host/finding") so operators don't collide —
    ephemeral, never persisted, shorter TTL than the roster."""

    def __init__(self, ttl: float = 45.0, focus_ttl: float = 25.0) -> None:
        self._seen: dict[str, float] = {}
        self._ttl = ttl
        self._focus_ttl = focus_ttl
        # entity key (e.g. "host:10.0.0.5", "finding:<key>") -> {tester: last_seen}
        self._focus: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    def ping(self, tester: str) -> None:
        if tester:
            with self._lock:
                self._seen[tester] = time.time()

    def roster(self) -> list[str]:
        now = time.time()
        with self._lock:
            alive = {t: s for t, s in self._seen.items() if now - s < self._ttl}
            self._seen = alive
        return sorted(alive)

    def set_focus(self, entity: str, tester: str, on: bool = True,
                  editing: bool = False) -> None:
        """Mark (or clear) that `tester` is on `entity`. `editing` is the advisory
        soft-lock: they're actively modifying it (e.g. typing a note), not just
        viewing — surfaced to teammates as "X is editing this" so they don't collide."""
        if not entity or not tester:
            return
        with self._lock:
            m = self._focus.setdefault(entity, {})
            if on:
                m[tester] = (time.time(), bool(editing))
            else:
                m.pop(tester, None)
            if not m:
                self._focus.pop(entity, None)

    def _alive(self, entity: str, now: float) -> dict:
        m = {t: v for t, v in self._focus.get(entity, {}).items()
             if now - v[0] < self._focus_ttl}
        if m:
            self._focus[entity] = m
        else:
            self._focus.pop(entity, None)
        return m

    def focused(self, entity: str) -> list[str]:
        """Everyone currently on `entity` (viewers + editors), stale pruned."""
        if not entity:
            return []
        with self._lock:
            return sorted(self._alive(entity, time.time()))

    def editing(self, entity: str) -> list[str]:
        """Only those with the advisory edit soft-lock on `entity`."""
        if not entity:
            return []
        with self._lock:
            return sorted(t for t, v in self._alive(entity, time.time()).items() if v[1])

    def focus_map(self) -> dict[str, list[str]]:
        """All active focus, entity -> sorted testers (stale pruned)."""
        now = time.time()
        out: dict[str, list[str]] = {}
        with self._lock:
            for e in list(self._focus):
                alive = self._alive(e, now)
                if alive:
                    out[e] = sorted(alive)
        return out
