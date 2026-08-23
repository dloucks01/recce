"""The task path — input to a session goes through here, not straight to the socket.

Today the only task is "type these bytes." That looks like overkill for a raw shell, and
it is — deliberately. It's the C2-ready seam #2: when async beacons and structured post-ex
(exec / upload / download) arrive, they are new Task kinds routed through this one function,
reusing the queue/result plumbing instead of bypassing it. Cheap now, no rewrite later.
"""
from __future__ import annotations

from dataclasses import dataclass

from .session import Session


@dataclass
class Task:
    kind: str          # "input" now; "exec" / "upload" / "download" / … later
    data: bytes = b""


async def run(session: Session, task: Task) -> None:
    if task.kind == "input":
        await session.send(task.data)
    # future kinds dispatch here


async def send_input(session: Session, data: bytes) -> None:
    """Convenience for the interactive path: a keystroke stream is just an input task."""
    await run(session, Task("input", data))
