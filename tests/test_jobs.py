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
