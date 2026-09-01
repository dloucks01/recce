"""Auto-crack watcher (P1-8).

Covers the module-level start/stop/idempotency, the tick loop's dedup via
`store.add_credential`'s boolean return, resilience to a transient OSError
from the potfile scan, and the RECCE_DISABLE_CRACK_WATCHER env gate on the
FastAPI startup hook.

The watcher polls `hashloot.absorb_default_potfiles` on an interval, so we
patch that symbol at its call site (`recce.creds.crack_watcher.hashloot`)
to control what each tick "finds" and to speed the loop up to milliseconds.
"""
from __future__ import annotations

import time
from unittest.mock import patch

from recce.core.models import Credential
from recce.creds import crack_watcher


class _FakeStore:
    """Minimal store that satisfies the watcher's contract.

    `add_credential` mirrors the real Store: True if new (by dedupe key),
    False if a duplicate. The watcher relies on that boolean for its
    "added" count.
    """

    def __init__(self, existing: list[Credential] | None = None):
        self._creds: dict[str, Credential] = {}
        for c in existing or []:
            self._creds[c.dedupe_key()] = c
        self.add_calls: list[Credential] = []

    def all_credentials(self) -> list[Credential]:
        return list(self._creds.values())

    def add_credential(self, cred: Credential) -> bool:
        self.add_calls.append(cred)
        k = cred.dedupe_key()
        if k in self._creds:
            return False
        self._creds[k] = cred
        return True


def _wait_until(predicate, timeout=2.0, poll=0.01):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(poll)
    return False


def teardown_function(_fn):
    # Every test leaves a clean module state so ordering doesn't matter.
    crack_watcher.stop_watcher(timeout=2.0)


def test_watcher_absorbs_new_cracks_and_dedupes_across_ticks(tmp_path):
    """Three ticks: first returns 2 new, second returns 0, third returns
    1 (a NEW one plus one dup). The store must see 3 unique adds and
    the watcher's total_absorbed must be 3."""
    c1 = Credential(username="alice", secret="pw1", kind="password",
                    domain="CORP", source="cracked")
    c2 = Credential(username="bob", secret="pw2", kind="password",
                    domain="CORP", source="cracked")
    c3 = Credential(username="carol", secret="pw3", kind="password",
                    domain="CORP", source="cracked")
    # Third-tick returns carol (new) + alice (dup of first tick).
    scripted = iter([[c1, c2], [], [c3, c1]])

    def fake_absorb(_creds, _out_dir):
        try:
            return next(scripted)
        except StopIteration:
            return []

    store = _FakeStore()
    with patch.object(crack_watcher.hashloot, "absorb_default_potfiles",
                      side_effect=fake_absorb):
        crack_watcher.start_watcher(store, str(tmp_path),
                                    interval_seconds=0.02)
        # Wait until at least 3 ticks have run — the third yields carol.
        assert _wait_until(
            lambda: crack_watcher.watcher_status()["total_absorbed"] >= 3,
            timeout=3.0)
        crack_watcher.stop_watcher(timeout=1.0)

    # Three unique creds in the store; alice re-add returned False so no dup.
    users = sorted(c.username for c in store.all_credentials())
    assert users == ["alice", "bob", "carol"]
    # add_credential was called at least four times (2 + 2 with one dup);
    # the boolean return did the dedup work.
    assert len(store.add_calls) >= 4


def test_stop_watcher_exits_within_one_second(tmp_path):
    with patch.object(crack_watcher.hashloot, "absorb_default_potfiles",
                      return_value=[]):
        t = crack_watcher.start_watcher(_FakeStore(), str(tmp_path),
                                        interval_seconds=5.0)
        assert t.is_alive()
        t0 = time.time()
        crack_watcher.stop_watcher(timeout=1.0)
        elapsed = time.time() - t0
    assert elapsed < 1.0, f"stop_watcher took {elapsed:.2f}s"
    assert not t.is_alive()


def test_start_watcher_is_idempotent(tmp_path):
    with patch.object(crack_watcher.hashloot, "absorb_default_potfiles",
                      return_value=[]):
        t1 = crack_watcher.start_watcher(_FakeStore(), str(tmp_path),
                                         interval_seconds=1.0)
        t2 = crack_watcher.start_watcher(_FakeStore(), str(tmp_path),
                                         interval_seconds=1.0)
    # Same thread handle — second call was a no-op.
    assert t1 is t2
    crack_watcher.stop_watcher(timeout=1.0)


def test_oserror_in_absorb_does_not_kill_the_loop(tmp_path):
    """Alternating OSError and a successful absorb: after several ticks the
    loop is still alive and cracks that came in AFTER the OSError landed
    in the store."""
    c = Credential(username="dora", secret="pw", kind="password",
                   domain="CORP", source="cracked")
    calls = {"n": 0}

    def fake_absorb(_creds, _out_dir):
        calls["n"] += 1
        # Odd calls: raise. Even calls: return a fresh crack (dedup at
        # the store keeps totals honest).
        if calls["n"] % 2 == 1:
            raise OSError("simulated transient IO fault")
        return [c]

    store = _FakeStore()
    with patch.object(crack_watcher.hashloot, "absorb_default_potfiles",
                      side_effect=fake_absorb):
        t = crack_watcher.start_watcher(store, str(tmp_path),
                                        interval_seconds=0.02)
        # Wait for at least one successful add.
        assert _wait_until(
            lambda: crack_watcher.watcher_status()["total_absorbed"] >= 1,
            timeout=3.0)
        # Loop is still alive after having survived an OSError tick.
        assert t.is_alive()
        crack_watcher.stop_watcher(timeout=1.0)


def test_watcher_status_reports_running_state(tmp_path):
    assert crack_watcher.watcher_status()["running"] is False
    with patch.object(crack_watcher.hashloot, "absorb_default_potfiles",
                      return_value=[]):
        crack_watcher.start_watcher(_FakeStore(), str(tmp_path),
                                    interval_seconds=1.0)
        s = crack_watcher.watcher_status()
        assert s["running"] is True
        assert s["out_dir"] == str(tmp_path)
        assert s["interval"] == 1.0
        crack_watcher.stop_watcher(timeout=1.0)
    assert crack_watcher.watcher_status()["running"] is False


# --- FastAPI startup gate --------------------------------------------------
# RECCE_DISABLE_CRACK_WATCHER=1 must skip start_watcher in the lifespan hook.
# We inspect the module state after standing up the app: with the env set,
# the watcher thread must NOT have been started.

def _make_engagement(tmp_path):
    """A minimally-viable engagement dir so create_app() can open it."""
    # create_app calls _open_paths which mkdirs and creates a results.sqlite;
    # no scan data needed for the lifespan smoke test.
    eng = tmp_path / "eng"
    eng.mkdir()
    return str(eng)


def test_env_gate_skips_startup(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from recce.webui.app import create_app
    eng = _make_engagement(tmp_path)
    monkeypatch.setenv("RECCE_DISABLE_CRACK_WATCHER", "1")
    # Belt-and-braces reset in case a prior test in another module left a
    # thread handle (shouldn't happen: teardown_function clears it).
    crack_watcher.stop_watcher(timeout=1.0)

    app = create_app(eng)
    with TestClient(app):
        # Lifespan startup has run under the env gate — no watcher.
        assert crack_watcher.watcher_status()["running"] is False


def test_lifespan_starts_watcher_when_env_unset(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from recce.webui.app import create_app
    eng = _make_engagement(tmp_path)
    monkeypatch.delenv("RECCE_DISABLE_CRACK_WATCHER", raising=False)
    crack_watcher.stop_watcher(timeout=1.0)

    # Patch absorb inside the module the watcher imports it from so the
    # thread doesn't touch a real potfile during the test.
    with patch.object(crack_watcher.hashloot, "absorb_default_potfiles",
                      return_value=[]):
        app = create_app(eng)
        with TestClient(app):
            assert _wait_until(
                lambda: crack_watcher.watcher_status()["running"],
                timeout=2.0)
        # Shutdown hook has run — watcher stopped.
        assert crack_watcher.watcher_status()["running"] is False
