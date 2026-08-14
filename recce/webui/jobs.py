"""Background scan jobs for the web workbench.

A scan is just the existing recce CLI run as a subprocess - so the web app reuses
the entire engine (discovery, enum, vulns, AD, reporting) with zero reimplementation,
and a crashing scan can't take the server down. Each job's stdout is captured line by
line and streamed to the browser over SSE; the scan writes to the same SQLite store the
API reads (WAL makes the concurrent read/write safe).
"""
from __future__ import annotations

import itertools
import subprocess
import sys
import threading
import time


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
        self.status = "running"           # running | done | failed
        self.lines: list[str] = []
        self.returncode: int | None = None
        self.started = time.time()
        self.ended: float | None = None


class JobManager:
    """In-memory registry of scan jobs (results persist in the store, not here)."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._counter = itertools.count(1)
        self._lock = threading.Lock()

    def start(self, argv: list[str]) -> Job:
        jid = str(next(self._counter))
        job = Job(jid, argv)
        with self._lock:
            self._jobs[jid] = job
        threading.Thread(target=self._run, args=(job, argv), daemon=True).start()
        return job

    def _run(self, job: Job, argv: list[str]) -> None:
        try:
            # PYTHONUNBUFFERED so recce's progress streams live (a piped child otherwise
            # block-buffers its stdout, and the browser sees nothing until it exits).
            import os
            env = {**os.environ, "PYTHONUNBUFFERED": "1"}
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
            assert proc.stdout is not None
            for line in proc.stdout:
                job.lines.append(line.rstrip("\n"))
            proc.wait()
            job.returncode = proc.returncode
        except Exception as e:                            # never let a job kill the server
            job.lines.append(f"[job error] {e}")
            job.returncode = -1
        job.ended = time.time()
        job.status = "done" if job.returncode == 0 else "failed"

    def get(self, jid: str) -> Job | None:
        return self._jobs.get(jid)

    def list(self) -> list[Job]:
        return sorted(self._jobs.values(), key=lambda j: j.started, reverse=True)
