"""Background scan jobs for the web workbench.

A scan is just the existing recce CLI run as a subprocess - so the web app reuses
the entire engine (discovery, enum, vulns, AD, reporting) with zero reimplementation,
and a crashing scan can't take the server down. Each job's stdout is captured line by
line and streamed to the browser over SSE; the scan writes to the same SQLite store the
API reads (WAL makes the concurrent read/write safe).
"""
from __future__ import annotations

import itertools
import re
import subprocess
import sys
import threading
import time
from typing import Any, Callable


def recce_argv(*args: str) -> list[str]:
    """Argv to invoke this same recce. In the PyInstaller bundle sys.executable IS the
    frozen recce (dispatch by subcommand); in a dev install, python -m recce."""
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    return [sys.executable, "-m", "recce", *args]


class Job:
    def __init__(self, jid: str, argv: list[str]):
        self.id = jid
        self.cmd = " ".join(argv)
        self.status = "running"           # running | done | failed | cancelled
        self.lines: list[str] = []
        self.returncode: int | None = None
        self.started = time.time()
        self.ended: float | None = None
        self._proc: subprocess.Popen | None = None
        # P7-C5: throttled scan progress parsed from stdout. `done` is the
        # per-host completion counter emitted by recce enum's throttled
        # refresh; `total` is the authoritative-target count masscan logs
        # when it hands off to enum. Neither always known — the frontend
        # renders a bar when total is present, else a "N done" chip.
        self.progress: dict | None = None
        # P7-C1: structured return value for callable-based jobs (spray,
        # act/run). Subprocess jobs leave this None; callers read
        # `job.result` once status is `done` / `failed`. The web API
        # exposes it on GET /api/jobs/{jid}.
        self.result: Any = None


_MAX_JOBS = 60          # cap the in-memory registry; oldest FINISHED jobs are evicted
_MAX_RUNNING = 8        # admission cap: never let more than N scans spawn subprocesses at once
_MAX_LINES = 10_000     # cap per-job stdout buffer; oldest lines dropped when exceeded


# P7-C5 progress parsers — regex + a (done_group, total_group, phase) picker.
# Applied in order; every match updates job.progress in place (partial updates
# are fine — an early match may set total without done, a later one adds done).
# Kept intentionally narrow so a garbled log line doesn't produce a wrong bar.
_PROGRESS_RES: list[tuple[re.Pattern, Callable[[re.Match, dict], None]]] = [
    # `[+] masscan found N host(s) with open ports; enumerating all M
    # authoritative target(s).` — total = M, phase = "enum"
    (re.compile(r"masscan found \d+ host\(s\) with open ports; "
                r"enumerating all (\d+) authoritative target\(s\)"),
     lambda m, p: p.update(total=int(m.group(1)), phase="enum")),
    # `[+] masscan found N host(s) with open ports.` — total = N (weaker
    # signal: recce may then add authoritative targets, but this is a
    # reasonable initial upper bound if the authoritative line never runs).
    # setdefault-style: only take this value if we haven't already learned
    # a better one from the authoritative-target line.
    (re.compile(r"masscan found (\d+) host\(s\) with open ports\."),
     lambda m, p: (p.__setitem__("total", int(m.group(1)))
                   if p.get("total") is None else None,
                   p.__setitem__("phase", "enum"))),
    # `    ~ report refreshed (X host(s) so far).` — done = X
    (re.compile(r"~ report refreshed \((\d+) host\(s\) so far\)"),
     lambda m, p: p.update(done=int(m.group(1)))),
]


def _apply_progress(line: str, job: "Job") -> None:
    """Update job.progress from one stdout line. No-op when nothing matches."""
    for rx, apply in _PROGRESS_RES:
        m = rx.search(line)
        if m is None:
            continue
        if job.progress is None:
            job.progress = {"done": 0, "total": None, "phase": None}
        try:
            apply(m, job.progress)
        except (ValueError, TypeError):
            pass                                # bad capture — silently ignore


class TooManyJobs(Exception):
    """Raised when the concurrent-running-scan cap is hit, so the API can 429 instead
    of letting an unauthenticated caller fork-bomb the box with recce/nmap children."""


class JobManager:
    """In-memory registry of scan jobs (results persist in the store, not here)."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._counter = itertools.count(1)
        self._lock = threading.Lock()

    def start(self, argv: list[str], on_done=None) -> Job:
        with self._lock:
            running = sum(1 for j in self._jobs.values() if j.status == "running")
            if running >= _MAX_RUNNING:
                raise TooManyJobs(f"{running} scans already running (max {_MAX_RUNNING}); "
                                  "wait for one to finish")
            jid = str(next(self._counter))
            job = Job(jid, argv)
            self._jobs[jid] = job
            self._prune()
        threading.Thread(target=self._run, args=(job, argv, on_done), daemon=True).start()
        return job

    def _prune(self) -> None:
        """Keep memory bounded: drop the oldest finished jobs past the cap. A running
        job is never evicted (its SSE stream and buffer are still in use)."""
        if len(self._jobs) <= _MAX_JOBS:
            return
        finished = sorted((j for j in self._jobs.values() if j.status != "running"),
                          key=lambda j: j.started)
        for j in finished[: len(self._jobs) - _MAX_JOBS]:
            self._jobs.pop(j.id, None)

    _JOB_TIMEOUT = 3600

    def _run(self, job: Job, argv: list[str], on_done=None) -> None:
        try:
            import os
            env = {**os.environ, "PYTHONUNBUFFERED": "1"}
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
            job._proc = proc
            assert proc.stdout is not None
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                job.lines.append(stripped)
                if len(job.lines) > _MAX_LINES:
                    job.lines = job.lines[-_MAX_LINES:]
                _apply_progress(stripped, job)
                if time.time() - job.started > self._JOB_TIMEOUT:
                    proc.terminate()
                    job.lines.append(f"[job timeout] killed after {self._JOB_TIMEOUT}s")
                    break
            proc.wait(timeout=10)
            job.returncode = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            job.returncode = -1
            job.lines.append("[job error] process did not exit after terminate")
        except Exception as e:
            job.lines.append(f"[job error] {e}")
            job.returncode = -1
        finally:
            job._proc = None
        job.ended = time.time()
        if job.status == "cancelled":
            pass
        elif job.returncode == 0:
            job.status = "done"
        else:
            job.status = "failed"
        if on_done is not None:
            try:
                on_done(job)
            except Exception:
                import logging
                logging.getLogger("recce.webui").debug("on_done callback failed for job %s", job.id, exc_info=True)

    def start_callable(self, label: str, fn: Callable[..., Any],
                       *args, on_done=None, **kwargs) -> Job:
        """P7-C1: run a Python callable in a background daemon thread as a
        Job. Its return value is captured on `job.result` when it finishes;
        exceptions land on job.result as `{"error": <str>}` with
        status=failed. Cancellation isn't supported for callable jobs —
        they're meant for short (seconds to a few minutes) in-process
        actions like credential spray and act/run. Longer work should
        stay on the subprocess path where `cancel` can SIGTERM the
        child."""
        with self._lock:
            running = sum(1 for j in self._jobs.values() if j.status == "running")
            if running >= _MAX_RUNNING:
                raise TooManyJobs(f"{running} jobs already running (max {_MAX_RUNNING}); "
                                  "wait for one to finish")
            jid = str(next(self._counter))
            # cmd is the display label the sidebar renders. Using a
            # single-token argv keeps `" ".join` output equal to the label.
            job = Job(jid, [label])
            self._jobs[jid] = job
            self._prune()
        threading.Thread(target=self._run_callable,
                         args=(job, fn, args, kwargs, on_done),
                         daemon=True).start()
        return job

    def _run_callable(self, job: Job, fn: Callable[..., Any],
                      args: tuple, kwargs: dict, on_done) -> None:
        try:
            job.result = fn(*args, **kwargs)
            if job.status != "cancelled":
                job.status = "done"
            job.returncode = 0
        except Exception as e:
            job.result = {"error": str(e)}
            job.status = "failed"
            job.returncode = -1
            job.lines.append(f"[job error] {e}")
        job.ended = time.time()
        if on_done is not None:
            try:
                on_done(job)
            except Exception:
                import logging
                logging.getLogger("recce.webui").debug(
                    "on_done callback failed for callable job %s", job.id, exc_info=True)

    def cancel(self, jid: str) -> bool:
        job = self._jobs.get(jid)
        if job is None or job.status != "running":
            return False
        job.status = "cancelled"
        proc = job._proc
        if proc is not None:
            proc.terminate()
        return True

    def get(self, jid: str) -> Job | None:
        return self._jobs.get(jid)

    def list(self) -> list[Job]:
        return sorted(self._jobs.values(), key=lambda j: j.started, reverse=True)
