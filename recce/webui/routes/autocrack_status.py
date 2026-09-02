"""`/api/autocrack/status` — status snapshot of the auto-crack watcher.

The watcher (recce/creds/crack_watcher.py) runs a background thread while
`recce serve` is up, folding hashcat's OWN cracks back into the credential
store on a 60s tick. This route surfaces its state to the WebUI so the
tester can see at a glance:

  * whether the watcher is running (env-gate or a startup failure could
    have left it off — a silent-off watcher is the failure mode we want
    the UI to make loud)
  * when the last tick ran (empty out_dir vs. dead thread look identical
    without this)
  * how many potfile entries the most recent scan surfaced pre-dedup
    (a "queue_size" proxy: shows work in flight even when everything
    seen is a duplicate)
  * how many cracks have been absorbed since startup
  * a "just cracked X" snippet for the most recent one

The route is read-only, does not open the sqlite store, and consults only
the in-process `watcher_status()` snapshot — so it stays cheap enough to
poll every 30s from the header pill without adding measurable load.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI


def _to_iso(epoch: float | None) -> str:
    """Epoch-seconds → ISO 8601 UTC (empty string when never-run).

    Frontends render the empty string as "—" or "never" without needing
    a separate null-check branch — one less code path in the pill."""
    if not epoch:
        return ""
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()


def register_autocrack_status_routes(app: FastAPI, _ctx) -> None:
    # Import is lazy so a test that never touches this route doesn't drag
    # in the watcher module (which owns threading/module-level state) at
    # app-construction time. The route itself is called only when the UI
    # polls the pill.
    @app.get("/api/autocrack/status")
    def autocrack_status():
        from ...creds.crack_watcher import watcher_status
        s = watcher_status()
        mrc = s.get("most_recent_crack")
        mrc_out = None
        if mrc:
            mrc_out = {
                "username": mrc.get("username", ""),
                "hash_type": mrc.get("hash_type", ""),
                "ts_iso": _to_iso(mrc.get("ts")),
            }
        return {
            "running": bool(s.get("running")),
            "last_tick_iso": _to_iso(s.get("last_run_ts")),
            # Size of the most recent absorb() return pre-dedup — a proxy for
            # "work in the queue" that also stays non-zero when hashcat is
            # producing cracks recce already knows.
            "queue_size": int(s.get("last_scan_size") or 0),
            "cracked_since_start": int(s.get("total_absorbed") or 0),
            "most_recent_crack": mrc_out,
        }
