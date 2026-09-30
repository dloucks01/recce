"""Cross-service "video streams known to this engagement" reader.

Every enumeration path that produces an RTSP video-stream URL — an
RTSP DESCRIBE that returned 200 OK on the root, a vendor path enum
(`/Streaming/Channels/101`, `/axis-media/media.amp`) that answered
200 or 401, a credential-URL scrape (`rtsp://user:pass@host/…`) —
lands the same fact: this URL is a real video stream, here is its
codec and (when the SDP told us) its resolution.

The wanted view is one stream inventory:

  * for THIS host, every distinct stream URL observed (root + each
    vendor path is a separate track — one camera commonly serves
    a main and a substream on different paths)
  * for the WHOLE engagement, the union — grouped by camera IP so an
    operator picks a target camera and gets every stream it exposes
  * an `authless` shortcut for the world-viewable ones (DESCRIBE
    answered 200 without an Authorization header) — that is the
    high-value set an attacker pulls first

Producers WRITE via `record_stream(host, url, ...)`; the reader
never invents streams — the store is the authority. Dedup is
case-insensitive on the URL (RTSP scheme and host are RFC 3986
case-insensitive) with first-seen casing preserved for display,
since path casing on IP cameras is engineer-typed and downstream
tools show what they saw.

References: RFC 2326 (RTSP DESCRIBE), RFC 4566 (SDP), RFC 3986 (URI).
"""
from __future__ import annotations

from typing import Any

from .models import Host


_FIELDS = ("codec", "resolution")


def _norm(v: Any) -> str:
    return str(v or "").strip()


def _url_key(url: str) -> str:
    """Case-insensitive dedup key. RFC 3986 §3.1 / §3.2.2: scheme and
    host are case-insensitive; path is technically case-sensitive but
    RTSP cameras normalise it in practice, and a case-varying reprobe
    of the same path is a duplicate here, not a distinct stream."""
    return _norm(url).lower().rstrip("/")


def record_stream(host: Host, url: str, *, codec: str = "",
                  resolution: str = "", auth_required: bool = False,
                  source: str = "") -> None:
    """Producer entry point. Appends one stream observation onto the
    host, or merges into an existing observation when the URL matches
    (case-insensitively) an earlier one on this same host.

    Merging is field-wise: a later observation fills in fields the
    earlier one left blank, but never overwrites first-seen casing on
    a populated field. `source` is appended to `sources`. `auth_required`
    is AND-folded — it stays True only when EVERY observation reported
    True; a single unauth 200 (past or future) flips it to False, since
    a world-viewable stream does not become unviewable just because a
    later credentialed retry also succeeded.
    """
    url = _norm(url)
    if not url:
        return
    codec = _norm(codec)
    resolution = _norm(resolution)
    src = _norm(source)
    existing = getattr(host, "streams", None)
    if existing is None:
        existing = []
        host.streams = existing  # type: ignore[attr-defined]

    key = _url_key(url)
    for rec in existing:
        if _url_key(rec.get("url", "")) == key:
            for f, v in (("codec", codec), ("resolution", resolution)):
                if v and not rec.get(f):
                    rec[f] = v
            rec["auth_required"] = bool(rec.get("auth_required")) and bool(auth_required)
            srcs = rec.setdefault("sources", [])
            if src and src not in srcs:
                srcs.append(src)
            return

    rec = {"url": url, "codec": codec, "resolution": resolution,
           "auth_required": bool(auth_required), "sources": []}
    if src:
        rec["sources"].append(src)
    existing.append(rec)


def streams_for(host: Host) -> list[dict]:
    """Every stream recorded on this host, insertion order preserved.
    Returned dicts are shallow copies so consumer mutation cannot
    corrupt the store."""
    out: list[dict] = []
    for rec in getattr(host, "streams", None) or []:
        copy = dict(rec)
        copy["sources"] = list(rec.get("sources") or [])
        out.append(copy)
    return out


def known_streams(hosts: list[Host]) -> dict:
    """Engagement-wide video-stream inventory.

    Returns:
      {"streams":   [stream, ...],       # authless first, then rest
       "by_camera": {ip: [stream, ...]},
       "authless":  [stream, ...]}

    `streams` is deduplicated across the engagement by (ip, url_lc) —
    the same URL seen from two probes is one row. First-seen casing
    wins for display; comparison stays case-insensitive.
    """
    streams: list[dict] = []
    by_camera: dict[str, list[dict]] = {}
    seen: dict[tuple[str, str], dict] = {}
    for h in hosts:
        for rec in streams_for(h):
            k = (h.ip, _url_key(rec.get("url", "")))
            entry = seen.get(k)
            if entry is None:
                seen[k] = rec
                streams.append(rec)
                by_camera.setdefault(h.ip, []).append(rec)
                continue
            for f in _FIELDS:
                if rec.get(f) and not entry.get(f):
                    entry[f] = rec[f]
            for s in rec.get("sources") or []:
                if s and s not in entry["sources"]:
                    entry["sources"].append(s)

    # Priority: authless streams first (highest value for attacker),
    # then the rest in first-seen order.
    streams.sort(key=lambda s: (1 if s.get("auth_required") else 0))
    authless = [s for s in streams if not s.get("auth_required")]
    return {"streams": streams, "by_camera": by_camera,
            "authless": authless}
