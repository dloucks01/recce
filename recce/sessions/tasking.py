"""The task path — input to a session goes through here, not straight to the socket.

Interactive keystrokes are the ``input`` kind and still bypass the record layer
(one row per keystroke is nonsense). Discrete commands dispatched from the UI —
quickrun, run-and-capture, download, upload, portfwd, upgrade — are ``exec``
tasks with a stable ``task_id``: they land in the shared oplog as ``queued``
the moment they're issued, and get updated in place with ``result_at`` +
``bytes`` when output comes back. That is what makes the team ops-log a
task-tracker rather than a one-line summary log.

Async beacons (P1) plug into the same shape: the Task is enqueued with
``queued``, sits in the store until the next beacon check-in drains it, then
``mark_task_result`` fires when the result POSTs back. Same rows, same UI, same
report — the only difference from interactive is the gap between the two edges.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from .session import Session


def _mint_task_id() -> str:
    """Short, sortable-ish, DB-friendly id for a task row. uuid4 is fine: the
    oplog is small (10 000-row cap) and we're not scanning by id prefix."""
    return uuid.uuid4().hex[:16]


@dataclass
class Task:
    """One dispatched action. ``input`` is raw keystrokes and is not persisted;
    every other kind is a first-class row in the oplog task feed.

    ``id`` is empty for ``input`` (nothing to key on) and always present for
    other kinds. ``command`` is the human-readable form for the UI /
    ATT&CK-tag path; ``data`` is the wire bytes actually sent to the target
    (usually ``command.encode() + b"\n"``, but callers can differ)."""

    kind: str                      # "input" | "exec" | "upload" | "download" | "enum"
    data: bytes = b""
    id: str = ""                   # empty for "input"; minted for the rest
    command: str = ""              # human-readable for the ops-log / attck tag
    issued_by: str = ""            # tester id from x-tester header
    issued_at: float = field(default_factory=time.time)

    @classmethod
    def exec(cls, command: str, *, issued_by: str = "",
             data: bytes | None = None) -> "Task":
        """Convenience constructor for the common case: dispatch a shell command,
        mint a fresh task_id, default the wire bytes to ``command + \\n``."""
        wire = data if data is not None else command.encode() + b"\n"
        return cls(kind="exec", data=wire, id=_mint_task_id(),
                   command=command, issued_by=issued_by,
                   issued_at=time.time())


async def run(session: Session, task: Task) -> None:
    if task.kind == "input":
        await session.send(task.data)
        return
    if task.kind == "exec":
        # For now this just writes to the wire; the record side is on the caller
        # (routes/sessions.py) which has the Store handle. That's a deliberate
        # split — tasking.py stays free of Store/DB knowledge so it can be unit-
        # tested against a fake transport with no engagement dir.
        await session.send(task.data)
        return
    # upload / download / enum land in P0-2; they'll be dispatched here too.


async def send_input(session: Session, data: bytes) -> None:
    """Convenience for the interactive path: a keystroke stream is just an input task."""
    await run(session, Task("input", data))
