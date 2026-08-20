"""Multi-tester collaboration state for the web workbench.

Everything here rides in the datastore's `meta` table as small JSON blobs, so it is
100% backward-compatible: an older engagement simply has no collab keys and every
getter returns an empty default. Presence is deliberately in-memory (ephemeral —
who's online right now), tracked per running server.
"""
from __future__ import annotations

import json
import time
import uuid

# meta keys (namespaced so they never collide with engagement metadata)
_ASSIGN = "collab.assignments"      # {ip: tester}
_LABELS = "collab.labels"           # {ip: [label, ...]}
_PORTS = "collab.port_status"       # {"ip:port": "todo"|"wip"|"done"}
_DISMISS = "collab.dismissed"       # {finding_key: tester}
_ACTIVITY = "collab.activity"       # [{ts, tester, kind, text}], newest last
_ACTIVITY_CAP = 300
_CHAT = "collab.chat"               # [{id, ts, tester, text, image}], oldest -> newest
_CHAT_CAP = 500
LABELS = ("interesting", "needs-review", "out-of-scope")


def _load(st, key, default):
    raw = st.get_meta(key)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


def _save(st, key, obj) -> None:
    st.set_meta(key, json.dumps(obj))


# --- assignments --------------------------------------------------------------
def get_assignments(st) -> dict:
    return _load(st, _ASSIGN, {})


def set_assignment(st, ip: str, tester: str) -> dict:
    a = get_assignments(st)
    if tester:
        a[ip] = tester
    else:
        a.pop(ip, None)
    _save(st, _ASSIGN, a)
    return a


# --- triage labels ------------------------------------------------------------
def get_labels(st) -> dict:
    return _load(st, _LABELS, {})


def set_label(st, ip: str, label: str, on: bool) -> dict:
    lab = get_labels(st)
    cur = set(lab.get(ip, []))
    cur.add(label) if on else cur.discard(label)
    if cur:
        lab[ip] = sorted(cur)
    else:
        lab.pop(ip, None)
    _save(st, _LABELS, lab)
    return lab


# --- per-port tri-state -------------------------------------------------------
def get_port_status(st) -> dict:
    return _load(st, _PORTS, {})


def set_port_status(st, ip: str, port, status: str) -> dict:
    ps = get_port_status(st)
    key = f"{ip}:{port}"
    if status in ("todo", "wip", "done"):
        ps[key] = status
    else:
        ps.pop(key, None)          # "" / unknown clears it
    _save(st, _PORTS, ps)
    return ps


# --- dismissed (not-a-finding) ------------------------------------------------
def get_dismissed(st) -> dict:
    return _load(st, _DISMISS, {})


def set_dismissed(st, key: str, tester: str, on: bool) -> dict:
    d = get_dismissed(st)
    if on:
        d[key] = tester
    else:
        d.pop(key, None)
    _save(st, _DISMISS, d)
    return d


# --- activity log -------------------------------------------------------------
def add_activity(st, tester: str, kind: str, text: str) -> dict:
    log = _load(st, _ACTIVITY, [])
    entry = {"ts": time.time(), "tester": tester or "someone", "kind": kind, "text": text}
    log.append(entry)
    _save(st, _ACTIVITY, log[-_ACTIVITY_CAP:])
    return entry


def get_activity(st, limit: int = 100) -> list:
    return list(reversed(_load(st, _ACTIVITY, [])))[:limit]      # newest first


# --- team chat ----------------------------------------------------------------
def add_chat(st, tester: str, text: str, image: str = "") -> dict:
    """Append a chat message. `image` is a stored media filename (or "" for text-only).
    Message metadata lives in meta; the image bytes live on disk (see the app layer)."""
    log = _load(st, _CHAT, [])
    msg = {"id": uuid.uuid4().hex[:12], "ts": time.time(),
           "tester": tester or "someone", "text": text, "image": image}
    log.append(msg)
    _save(st, _CHAT, log[-_CHAT_CAP:])
    return msg


def get_chat(st, limit: int = 200) -> list:
    return _load(st, _CHAT, [])[-limit:]         # oldest -> newest, for a chat transcript


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
    """In-memory roster of who's active, pruned by a staleness window."""

    def __init__(self, ttl: float = 45.0) -> None:
        self._seen: dict[str, float] = {}
        self._ttl = ttl

    def ping(self, tester: str) -> None:
        if tester:
            self._seen[tester] = time.time()

    def roster(self) -> list[str]:
        now = time.time()
        self._seen = {t: s for t, s in self._seen.items() if now - s < self._ttl}
        return sorted(self._seen)
