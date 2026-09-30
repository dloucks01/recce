"""Cross-service "shells/marker files recce uploaded during this engagement".

Producers today:
  * `recce/services/webdav.py` — the anonymous-PUT round-trip and the
    PUT+execute webshell chain each drop one file onto the target and
    IMMEDIATELY try to DELETE it. Recording the (ip, port, path, cleanup)
    tuple here means that even if a DELETE fails (transient 5xx, mount
    turned read-only, race with a WAF), the tester has a clean per-host
    cleanup list at the end of the engagement.

Consumers (this pass ships the reader only):
  * a post-engagement cleanup consumer that emits `curl` commands from
    `cleanup_commands(host)` — recce itself does NOT auto-DELETE anything
    after the initial best-effort in the probe (per user directive: no
    silent scanner-driven writes into a live target after the test window).

`cleanup_verb` defaults to DELETE (RFC 4918 §9.6). We record the verb
rather than hard-coding it because a follow-up producer might drop a
LOCK-only artifact whose cleanup is UNLOCK.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..core.models import Host


def _norm(v: str) -> str:
    return (v or "").strip()


def record_uploaded_shell(host: Host, ip: str, port: int, path: str,
                          cleanup_verb: str = "DELETE",
                          source: str = "webdav",
                          use_tls: bool = False) -> None:
    """Attach one uploaded artifact to `host`. Idempotent per (port, path)
    — a re-run of the same probe records only once. Silently drops empty
    paths."""
    p = _norm(path)
    if host is None or not p:
        return
    existing = getattr(host, "uploaded_shells", None)
    if existing is None:
        existing = []
        host.uploaded_shells = existing  # type: ignore[attr-defined]
    for e in existing:
        if e.get("path") == p and int(e.get("port", 0)) == int(port):
            return
    existing.append({"ip": ip or getattr(host, "ip", "") or "",
                     "port": int(port), "path": p,
                     "cleanup_verb": _norm(cleanup_verb).upper() or "DELETE",
                     "use_tls": bool(use_tls),
                     "source": source or "webdav",
                     "uploaded_at_iso": datetime.now(timezone.utc).isoformat()})


def uploaded_shells_for(host: Host) -> list[dict]:
    """Every uploaded artifact recorded against `host`, insertion order."""
    return [dict(e) for e in (getattr(host, "uploaded_shells", None) or [])]


def cleanup_commands(host: Host) -> list[str]:
    """`curl` invocation per recorded artifact — the operator's post-
    engagement cleanup list. Never fired by recce itself."""
    out: list[str] = []
    for e in uploaded_shells_for(host):
        scheme = "https" if e.get("use_tls") else "http"
        port = int(e.get("port") or 0)
        # RFC 3986 authority: omit :port for scheme-default only when it
        # matches — a mixed http/8080 target still needs the explicit port.
        authority = e["ip"] if port in (80, 443) else f"{e['ip']}:{port}"
        out.append(f"curl -k -X {e['cleanup_verb']} "
                   f"{scheme}://{authority}{e['path']}")
    return out


def known_uploaded_shells(hosts: list[Host]) -> dict:
    """Engagement-wide uploaded-artifact inventory.

    Returns:
      {"shells": [{ip, port, path, cleanup_verb, use_tls, source,
                   uploaded_at_iso}, ...],
       "count":  int}

    Ordering is host-insertion + within-host insertion — the last shell
    dropped is the last row."""
    shells: list[dict] = []
    for h in hosts:
        for e in uploaded_shells_for(h):
            shells.append(e)
    return {"shells": shells, "count": len(shells)}
