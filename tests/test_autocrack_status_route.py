"""`/api/autocrack/status` — route-level test with a fake watcher state.

The route reads only `recce.creds.crack_watcher.watcher_status()`; we patch
that so we don't have to spin up a real background thread just to shape the
snapshot the response is built from. Covers:

  * running=False, never-ticked   → empty last_tick_iso, most_recent_crack null
  * running=True, ticked + crack  → ISO timestamps present, cracked count wired
  * fetch always succeeds (200 JSON) — the route never 500s on a partial state
"""
from __future__ import annotations

import time
from unittest.mock import patch

from fastapi.testclient import TestClient

from recce.webui.app import create_app


def _make_engagement(tmp_path):
    eng = tmp_path / "eng"
    eng.mkdir()
    return str(eng)


def _client(tmp_path, monkeypatch):
    # Keep the real startup hook from also starting a watcher thread —
    # the env gate makes the lifespan a no-op and lets us patch
    # watcher_status() freely without racing an actual tick.
    monkeypatch.setenv("RECCE_DISABLE_CRACK_WATCHER", "1")
    return TestClient(create_app(_make_engagement(tmp_path)))


def test_status_returns_idle_shape_when_watcher_off(tmp_path, monkeypatch):
    fake = {
        "running": False,
        "started_at": None,
        "last_run_ts": None,
        "last_absorbed": 0,
        "total_absorbed": 0,
        "out_dir": None,
        "interval": None,
        "last_scan_size": 0,
        "most_recent_crack": None,
    }
    with _client(tmp_path, monkeypatch) as c, \
            patch("recce.creds.crack_watcher.watcher_status", return_value=fake):
        r = c.get("/api/autocrack/status")
        assert r.status_code == 200
        j = r.json()
        assert j == {
            "running": False,
            "last_tick_iso": "",
            "queue_size": 0,
            "cracked_since_start": 0,
            "most_recent_crack": None,
        }


def test_status_reports_running_with_tick_and_recent_crack(tmp_path, monkeypatch):
    now = time.time()
    fake = {
        "running": True,
        "started_at": now - 120.0,
        "last_run_ts": now - 5.0,
        "last_absorbed": 1,
        "total_absorbed": 7,
        "out_dir": "/tmp/eng",
        "interval": 60.0,
        "last_scan_size": 3,
        "most_recent_crack": {
            "username": "CORP\\alice",
            "hash_type": "password",
            "ts": now - 5.0,
        },
    }
    with _client(tmp_path, monkeypatch) as c, \
            patch("recce.creds.crack_watcher.watcher_status", return_value=fake):
        r = c.get("/api/autocrack/status")
        assert r.status_code == 200
        j = r.json()
        assert j["running"] is True
        assert j["queue_size"] == 3
        assert j["cracked_since_start"] == 7
        # ISO 8601 UTC — must be non-empty and end with '+00:00'
        assert j["last_tick_iso"] and j["last_tick_iso"].endswith("+00:00")
        mrc = j["most_recent_crack"]
        assert mrc is not None
        assert mrc["username"] == "CORP\\alice"
        assert mrc["hash_type"] == "password"
        assert mrc["ts_iso"] and mrc["ts_iso"].endswith("+00:00")


def test_status_tolerates_missing_fields(tmp_path, monkeypatch):
    """Watcher status with just a subset of keys must not 500 — the route
    coerces missing/None safely to defaults."""
    fake = {"running": True}  # anything else absent
    with _client(tmp_path, monkeypatch) as c, \
            patch("recce.creds.crack_watcher.watcher_status", return_value=fake):
        r = c.get("/api/autocrack/status")
        assert r.status_code == 200
        j = r.json()
        assert j["running"] is True
        assert j["last_tick_iso"] == ""
        assert j["queue_size"] == 0
        assert j["cracked_since_start"] == 0
        assert j["most_recent_crack"] is None
