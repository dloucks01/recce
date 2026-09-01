"""Background watcher that folds hashcat's OWN cracks back into the store.

The tester runs hashcat externally against `<eng>/loot/*.hash` — recce does
NOT drive hashcat itself, because in an air-gapped engagement the operator
already has a wordlist / GPU rig set up and wants to steer the crack. What
was missing: the plaintexts hashcat writes to its potfile had no path back
into recce unless the operator remembered to point `recce creds --potfile`
at the file.

This module periodically calls the (already existing)
`hashloot.absorb_default_potfiles(creds, out_dir)`, which scans hashcat's
default potfile location + any `*.pot` under the engagement out_dir, and
hands the concatenated content to `credentials.parse_potfile`. Anything it
returns is a fresh `Credential(kind="password", source="cracked")` that
matches a hash recce already holds — the watcher then calls
`store.add_credential(c)` for each. The store dedupes on
(domain, user, kind, secret) so a re-scan of the same potfile doesn't
duplicate anything; we treat the store's boolean return as ground truth
for "was this one new".

Thread over asyncio: the FastAPI app hosts this alongside `JobManager`
(also thread-based) and `SessionManager` (loop-bound). Store operations
are synchronous SQLite calls; a threading.Thread with a threading.Event
for stop is simpler than shuttling the sync store between the loop and
a run_in_executor call, and matches the JobManager pattern already used
in `recce/webui/jobs.py`.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any, Optional

from . import hashloot

# Module-level state so start/stop can be called from anywhere (the FastAPI
# lifespan) without wiring a handle through every layer. A single watcher per
# process is the right shape: it reads one engagement's potfiles, and
# `recce serve` is a one-engagement-per-process command.
_state: dict[str, Any] = {
    "thread": None,            # threading.Thread
    "stop_event": None,        # threading.Event
    "started_at": None,        # float | None (epoch seconds)
    "last_run_ts": None,       # float | None (epoch seconds)
    "last_absorbed": 0,        # int — from the most recent tick
    "total_absorbed": 0,       # int — cumulative since start
    "out_dir": None,           # str | None
    "interval": None,          # float | None
}
_lock = threading.Lock()


def watcher_status() -> dict[str, Any]:
    """Snapshot of the watcher for the frontend / a /api/crack_watcher
    endpoint. Cheap to call from a request handler."""
    with _lock:
        thread = _state["thread"]
        return {
            "running": bool(thread is not None and thread.is_alive()),
            "started_at": _state["started_at"],
            "last_run_ts": _state["last_run_ts"],
            "last_absorbed": _state["last_absorbed"],
            "total_absorbed": _state["total_absorbed"],
            "out_dir": _state["out_dir"],
            "interval": _state["interval"],
        }


def start_watcher(store: Any,
                  out_dir: str,
                  interval_seconds: float = 60.0,
                  logger: Optional[logging.Logger] = None) -> threading.Thread:
    """Start the background watcher. Idempotent: a second call while a
    watcher thread is still alive returns the existing handle (no new
    thread). Returns the running Thread handle.

    `store` must expose `all_credentials()` and `add_credential(c) -> bool`
    (bool True = new, False = dupe).
    """
    log = logger or logging.getLogger("recce.creds.crack_watcher")
    with _lock:
        t = _state["thread"]
        if t is not None and t.is_alive():
            return t
        stop = threading.Event()
        thread = threading.Thread(
            target=_loop,
            name="recce-crack-watcher",
            args=(store, out_dir, float(interval_seconds), stop, log),
            daemon=True,
        )
        _state.update({
            "thread": thread,
            "stop_event": stop,
            "started_at": time.time(),
            "last_run_ts": None,
            "last_absorbed": 0,
            "total_absorbed": 0,
            "out_dir": out_dir,
            "interval": float(interval_seconds),
        })
    thread.start()
    return thread


def stop_watcher(timeout: float = 2.0) -> None:
    """Signal the watcher to exit and join it. Safe to call when no
    watcher is running."""
    with _lock:
        thread = _state["thread"]
        stop = _state["stop_event"]
    if stop is not None:
        stop.set()
    if thread is not None:
        thread.join(timeout=timeout)
    with _lock:
        # Only clear if this really is the one we started; a race where
        # start_watcher() ran again during join would have replaced it,
        # but the idempotency guard prevents that (start refuses while
        # the old thread is alive).
        if _state["thread"] is thread:
            _state["thread"] = None
            _state["stop_event"] = None


def _loop(store: Any,
          out_dir: str,
          interval: float,
          stop_event: threading.Event,
          log: logging.Logger) -> None:
    # First tick runs immediately so a crack that landed before startup is
    # picked up without waiting a whole interval.
    while not stop_event.is_set():
        try:
            _tick(store, out_dir, log)
        except OSError as e:
            # A potfile that briefly disappears / becomes unreadable is not
            # a reason to kill the watcher — hashcat may be rotating its
            # own file. Log at debug and keep going.
            log.debug("crack-watcher: OSError during tick (%s); continuing", e)
        except Exception:
            # Any other unexpected error: log with traceback and continue.
            # An unrecoverable error will manifest as repeated failures the
            # operator will see in the log — better than a silent thread
            # death that removes the loop the UI claims is running.
            log.exception("crack-watcher: unexpected error; continuing")
        # wait() returns True if the event was set (stop requested), else
        # False on timeout. Small floor prevents a busy loop if a test
        # passes interval=0.
        if stop_event.wait(timeout=max(0.01, interval)):
            return


def _tick(store: Any, out_dir: str, log: logging.Logger) -> int:
    creds = store.all_credentials()
    new_creds = hashloot.absorb_default_potfiles(creds, out_dir) or []
    added = 0
    for c in new_creds:
        try:
            if store.add_credential(c):
                added += 1
        except Exception:
            log.exception("crack-watcher: add_credential failed for %s",
                          getattr(c, "label", "?"))
    with _lock:
        _state["last_run_ts"] = time.time()
        _state["last_absorbed"] = added
        _state["total_absorbed"] += added
    if added:
        log.info("crack-watcher: %d new crack(s) absorbed", added)
    else:
        log.debug("crack-watcher: no new cracks")
    return added
