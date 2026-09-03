"""Tests for the JobManager: start, cancel, line cap, and timeout."""
from __future__ import annotations

import sys
import time

import pytest

from recce.webui.jobs import JobManager, TooManyJobs, _MAX_LINES


@pytest.fixture()
def mgr():
    return JobManager()


def test_start_and_done(mgr):
    job = mgr.start([sys.executable, "-c", "print('hello')"])
    for _ in range(50):
        if job.status != "running":
            break
        time.sleep(0.1)
    assert job.status == "done"
    assert "hello" in job.lines


def test_cancel(mgr):
    job = mgr.start([sys.executable, "-c", "import time; time.sleep(60)"])
    time.sleep(0.3)
    assert mgr.cancel(job.id) is True
    for _ in range(50):
        if job.status != "running":
            break
        time.sleep(0.1)
    assert job.status == "cancelled"


def test_cancel_nonexistent(mgr):
    assert mgr.cancel("999") is False


def test_failed_job(mgr):
    job = mgr.start([sys.executable, "-c", "raise SystemExit(1)"])
    for _ in range(50):
        if job.status != "running":
            break
        time.sleep(0.1)
    assert job.status == "failed"
    assert job.returncode == 1


def test_line_cap(mgr):
    n = _MAX_LINES + 500
    job = mgr.start([sys.executable, "-c",
                     f"for i in range({n}): print(f'line {{i}}')"])
    for _ in range(100):
        if job.status != "running":
            break
        time.sleep(0.1)
    assert job.status == "done"
    assert len(job.lines) <= _MAX_LINES


def test_on_done_callback(mgr):
    results = []
    job = mgr.start([sys.executable, "-c", "print('ok')"],
                    on_done=lambda j: results.append(j.status))
    for _ in range(50):
        if job.status != "running":
            break
        time.sleep(0.1)
    assert results == ["done"]


def test_list_and_get(mgr):
    job = mgr.start([sys.executable, "-c", "pass"])
    assert mgr.get(job.id) is job
    assert job in mgr.list()
    assert mgr.get("nonexistent") is None


# ---------------------------------------------------------------------------
# P7-C1: callable jobs — a Python-level fold of the same JobManager contract
# ---------------------------------------------------------------------------

def test_start_callable_captures_return_value(mgr):
    job = mgr.start_callable("compute-thing", lambda: {"answer": 42})
    for _ in range(50):
        if job.status != "running":
            break
        time.sleep(0.02)
    assert job.status == "done"
    assert job.result == {"answer": 42}
    assert job.cmd == "compute-thing"
    assert job.returncode == 0


def test_start_callable_captures_exception_as_failed(mgr):
    def _explode():
        raise RuntimeError("boom")
    job = mgr.start_callable("compute-thing", _explode)
    for _ in range(50):
        if job.status != "running":
            break
        time.sleep(0.02)
    assert job.status == "failed"
    assert job.result == {"error": "boom"}
    assert any("boom" in ln for ln in job.lines)


def test_start_callable_threads_args_and_kwargs(mgr):
    def _add(a, b, mul=1):
        return (a + b) * mul
    job = mgr.start_callable("add", _add, 2, 3, mul=10)
    for _ in range(50):
        if job.status != "running":
            break
        time.sleep(0.02)
    assert job.status == "done"
    assert job.result == 50


# ---------------------------------------------------------------------------
# P7-C5: progress parser — a small, permanent contract with recce's stdout
# ---------------------------------------------------------------------------

def test_progress_parse_authoritative_targets():
    """`[+] masscan found 5 host(s) with open ports; enumerating all 12
    authoritative target(s).` — total=12, phase=enum."""
    from recce.webui.jobs import _apply_progress, Job
    j = Job("1", ["dummy"])
    _apply_progress(
        "[+] masscan found 5 host(s) with open ports; "
        "enumerating all 12 authoritative target(s).", j)
    assert j.progress == {"done": 0, "total": 12, "phase": "enum"}


def test_progress_parse_open_ports_only_falls_back_to_that_total():
    """The bare `masscan found N` line (no authoritative line follows)
    sets total = N. Should NOT overwrite an authoritative total that was
    already recorded, so the setdefault path is exercised."""
    from recce.webui.jobs import _apply_progress, Job
    j = Job("1", ["dummy"])
    _apply_progress(
        "[+] masscan found 7 host(s) with open ports.", j)
    assert j.progress == {"done": 0, "total": 7, "phase": "enum"}
    # Now the authoritative line — total stays at 12 (a set), not 7.
    _apply_progress(
        "[+] masscan found 7 host(s) with open ports; "
        "enumerating all 12 authoritative target(s).", j)
    assert j.progress["total"] == 12


def test_progress_parse_refresh_updates_done():
    """The throttled `~ report refreshed (X host(s) so far).` line — the
    only per-host tick recce enum emits — advances `done`."""
    from recce.webui.jobs import _apply_progress, Job
    j = Job("1", ["dummy"])
    _apply_progress(
        "[+] masscan found 3 host(s) with open ports; "
        "enumerating all 10 authoritative target(s).", j)
    for done in (2, 4, 6, 10):
        _apply_progress(
            f"    ~ report refreshed ({done} host(s) so far).", j)
        assert j.progress["done"] == done
    assert j.progress == {"done": 10, "total": 10, "phase": "enum"}


def test_progress_parse_ignores_unrelated_lines():
    from recce.webui.jobs import _apply_progress, Job
    j = Job("1", ["dummy"])
    for line in ("[*] starting recce",
                 "[+] enum: 10.0.0.5 → 22/ssh, 80/http",
                 "[!] nuclei not installed",
                 ""):
        _apply_progress(line, j)
    assert j.progress is None
