"""Durable session state — its own tables in the engagement SQLite (a separate WAL
connection so it never contends with the main store). This is what makes a session
survive a `recce serve` restart: on startup the manager reloads past sessions as `stale`
with their transcripts intact, so history is browsable and a reconnecting shell from the
same host can rebind and resume where it left off.
"""
from __future__ import annotations

import sqlite3
import time

_SCHEMA = """
CREATE TABLE IF NOT EXISTS shell_sessions (
  id TEXT PRIMARY KEY, host_ip TEXT, host_port INTEGER, kind TEXT,
  status TEXT, token TEXT, opened REAL, closed REAL
);
CREATE TABLE IF NOT EXISTS shell_transcript (
  session_id TEXT, seq INTEGER, ts REAL, data BLOB
);
CREATE INDEX IF NOT EXISTS ix_shell_transcript ON shell_transcript(session_id, seq);
"""


class SessionStore:
    """Persists session metadata + the transcript byte-log. Writes are batched by the
    manager, so this stays a thin, synchronous SQLite wrapper."""

    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA busy_timeout=15000")
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._seq: dict[str, int] = {}      # session_id -> next transcript seq

    def save_session(self, s) -> None:
        closed = None if s.status == "live" else time.time()
        self._conn.execute(
            "INSERT INTO shell_sessions(id,host_ip,host_port,kind,status,token,opened,closed) "
            "VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, closed=excluded.closed",
            (s.id, s.host_ip, s.host_port, s.kind, s.status, s.token, s.created, closed))
        self._conn.commit()

    def append(self, session_id: str, data: bytes) -> None:
        if not data:
            return
        seq = self._seq.get(session_id, 0)
        self._conn.execute(
            "INSERT INTO shell_transcript(session_id,seq,ts,data) VALUES(?,?,?,?)",
            (session_id, seq, time.time(), sqlite3.Binary(data)))
        self._seq[session_id] = seq + 1
        self._conn.commit()

    def load_sessions(self) -> list[tuple[dict, bytes]]:
        """Every persisted session with its concatenated transcript, oldest first."""
        rows = self._conn.execute(
            "SELECT id,host_ip,host_port,kind,status,token,opened FROM shell_sessions "
            "ORDER BY opened").fetchall()
        out: list[tuple[dict, bytes]] = []
        for r in rows:
            chunks = self._conn.execute(
                "SELECT seq,data FROM shell_transcript WHERE session_id=? ORDER BY seq",
                (r[0],)).fetchall()
            data = b"".join(bytes(c[1]) for c in chunks)
            self._seq[r[0]] = (chunks[-1][0] + 1) if chunks else 0   # continue the seq
            out.append(({"id": r[0], "host_ip": r[1], "host_port": r[2], "kind": r[3],
                         "token": r[5], "opened": r[6]}, data))
        return out

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
