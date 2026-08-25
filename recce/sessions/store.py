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
  status TEXT, token TEXT, opened REAL, closed REAL, pty INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS shell_transcript (
  session_id TEXT, seq INTEGER, ts REAL, data BLOB
);
CREATE INDEX IF NOT EXISTS ix_shell_transcript ON shell_transcript(session_id, seq);
CREATE TABLE IF NOT EXISTS persistence (
  id TEXT PRIMARY KEY, host_ip TEXT, mechanism TEXT, artifact_path TEXT,
  remove_cmd TEXT, installed_by TEXT, installed_at REAL, removed_at REAL
);
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
        self._migrate()                     # add columns to a pre-existing table (graceful upgrade)
        self._conn.commit()
        self._seq: dict[str, int] = {}      # session_id -> next transcript seq

    def _migrate(self) -> None:
        """CREATE TABLE IF NOT EXISTS won't add a column to a table an older recce already
        made — so ADD COLUMN for anything introduced later, keeping existing engagements safe."""
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(shell_sessions)")}
        if "pty" not in cols:
            self._conn.execute("ALTER TABLE shell_sessions ADD COLUMN pty INTEGER DEFAULT 0")
        if "label" not in cols:
            self._conn.execute("ALTER TABLE shell_sessions ADD COLUMN label TEXT DEFAULT ''")
        if "name" not in cols:
            self._conn.execute("ALTER TABLE shell_sessions ADD COLUMN name TEXT DEFAULT ''")
        if "history" not in cols:
            # Per-session command history so up-arrow after re-attach recalls what
            # was typed against THIS host, not this browser tab. Stored as JSON list.
            self._conn.execute("ALTER TABLE shell_sessions ADD COLUMN history TEXT DEFAULT ''")


    def save_session(self, s) -> None:
        closed = None if s.status == "live" else time.time()
        self._conn.execute(
            "INSERT INTO shell_sessions(id,host_ip,host_port,kind,status,token,opened,closed,pty,label,name) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, closed=excluded.closed, "
            "pty=excluded.pty, label=excluded.label, name=excluded.name",
            (s.id, s.host_ip, s.host_port, s.kind, s.status, s.token, s.created, closed,
             1 if s.pty else 0, s.label, s.name))
        self._conn.commit()

    def save_history(self, session_id: str, entries: list[str]) -> None:
        """Persist a session's command history (bounded list of strings)."""
        import json
        # Cap at 500 entries so a runaway loop can't blow up the row size.
        payload = json.dumps(entries[-500:], ensure_ascii=True)
        self._conn.execute(
            "UPDATE shell_sessions SET history=? WHERE id=?", (payload, session_id))
        self._conn.commit()

    def load_history(self, session_id: str) -> list[str]:
        import json
        row = self._conn.execute(
            "SELECT history FROM shell_sessions WHERE id=?", (session_id,)).fetchone()
        if not row or not row[0]:
            return []
        try:
            v = json.loads(row[0])
            return v if isinstance(v, list) else []
        except (ValueError, TypeError):
            return []

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
            "SELECT id,host_ip,host_port,kind,status,token,opened,pty,label,name FROM shell_sessions "
            "ORDER BY opened").fetchall()
        out: list[tuple[dict, bytes]] = []
        for r in rows:
            chunks = self._conn.execute(
                "SELECT seq,data FROM shell_transcript WHERE session_id=? ORDER BY seq",
                (r[0],)).fetchall()
            data = b"".join(bytes(c[1]) for c in chunks)
            self._seq[r[0]] = (chunks[-1][0] + 1) if chunks else 0   # continue the seq
            out.append(({"id": r[0], "host_ip": r[1], "host_port": r[2], "kind": r[3],
                         "token": r[5], "opened": r[6], "pty": r[7],
                         "label": r[8] or "", "name": r[9] or ""}, data))
        return out

    def load_transcript(self, session_id: str, limit: int = 0) -> bytes:
        """The COMPLETE transcript for one session (optionally just the last `limit` bytes)."""
        chunks = self._conn.execute(
            "SELECT data FROM shell_transcript WHERE session_id=? ORDER BY seq",
            (session_id,)).fetchall()
        data = b"".join(bytes(c[0]) for c in chunks)
        return data[-limit:] if limit else data

    # --- persistence tracking: every backdoor recce drops is recorded so it can be removed
    def add_persistence(self, p: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO persistence"
            "(id,host_ip,mechanism,artifact_path,remove_cmd,installed_by,installed_at,removed_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (p["id"], p["host_ip"], p["mechanism"], p["artifact_path"], p["remove_cmd"],
             p.get("installed_by", ""), p["installed_at"], p.get("removed_at")))
        self._conn.commit()

    def list_persistence(self, host_ip: str = "", active_only: bool = False) -> list[dict]:
        q = "SELECT id,host_ip,mechanism,artifact_path,remove_cmd,installed_by,installed_at,removed_at FROM persistence"
        cond, args = [], []
        if host_ip:
            cond.append("host_ip=?"); args.append(host_ip)
        if active_only:
            cond.append("removed_at IS NULL")
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY installed_at DESC"
        cols = ("id", "host_ip", "mechanism", "artifact_path", "remove_cmd",
                "installed_by", "installed_at", "removed_at")
        return [dict(zip(cols, r)) for r in self._conn.execute(q, args).fetchall()]

    def get_persistence(self, pid: str) -> dict | None:
        rows = self.list_persistence()
        return next((r for r in rows if r["id"] == pid), None)

    def mark_persistence_removed(self, pid: str, ts: float) -> None:
        self._conn.execute("UPDATE persistence SET removed_at=? WHERE id=?", (ts, pid))
        self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
