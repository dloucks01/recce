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
CREATE TABLE IF NOT EXISTS uploads (
  id TEXT PRIMARY KEY, host_ip TEXT, remote_path TEXT, bytes INTEGER,
  uploaded_by TEXT, uploaded_at REAL, cleared_at REAL, note TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_uploads_host ON uploads(host_ip);
-- Beacon registry (async-C2 P1). A beacon IS a session — the id here is the
-- SAME id used in shell_sessions — but instead of a live socket we hold a
-- server-authoritative sleep/jitter policy, the last check-in ts, and the
-- pre-shared key used to HMAC-authenticate the client's polls. HMAC-SHA256
-- verification NEEDS the raw key (a hash-only column can't verify a MAC),
-- so `psk` here is the plaintext PSK — per-beacon, random 32 bytes,
-- shown to the operator once at registration (matches the reverse-shell
-- token pattern). Anyone with DB read can steer that beacon. See the
-- design doc §9 for the trust model this fits.
CREATE TABLE IF NOT EXISTS beacon (
  id           TEXT PRIMARY KEY,     -- == shell_sessions.id
  host_ip      TEXT DEFAULT '',      -- host the beacon runs on (shown in the beacon list)
  transport    TEXT DEFAULT 'http',  -- http | https (future: dns)
  registered   REAL DEFAULT 0,       -- unix ts of first registration
  last_checkin REAL DEFAULT 0,       -- unix ts of most recent check-in
  sleep_s      REAL DEFAULT 30.0,    -- polling interval the client is TOLD to use
  jitter_pct   REAL DEFAULT 20.0,    -- ± jitter around sleep_s (0..100)
  psk          TEXT DEFAULT '',      -- pre-shared key (raw; HMAC key)
  notes        TEXT DEFAULT ''
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
        # Session ergonomics (batch 2): notes let the operator record "how I got in
        # here" per-session (feeds the writeup); pinned floats important sessions to
        # the top of the list; listener_id ties a caught shell back to the listener
        # that received it (traceback surface).
        if "notes" not in cols:
            self._conn.execute("ALTER TABLE shell_sessions ADD COLUMN notes TEXT DEFAULT ''")
        if "pinned" not in cols:
            self._conn.execute("ALTER TABLE shell_sessions ADD COLUMN pinned INTEGER DEFAULT 0")
        if "listener_id" not in cols:
            self._conn.execute("ALTER TABLE shell_sessions ADD COLUMN listener_id TEXT DEFAULT ''")
        # Beacon-table psk column: an early P1-A build named the field
        # `psk_hash` and stored the raw key in it (a hash column can't verify
        # HMAC, so the name was wrong). Rename in place: add `psk`, copy over,
        # leave the old column empty (SQLite lacks a DROP COLUMN pre-3.35, and
        # this schema is only a few days old — nothing else reads psk_hash).
        beacon_cols = {r[1] for r in self._conn.execute("PRAGMA table_info(beacon)")}
        if beacon_cols and "psk" not in beacon_cols:
            self._conn.execute("ALTER TABLE beacon ADD COLUMN psk TEXT DEFAULT ''")
            if "psk_hash" in beacon_cols:
                self._conn.execute("UPDATE beacon SET psk = psk_hash WHERE psk = ''")
        if beacon_cols and "host_ip" not in beacon_cols:
            self._conn.execute("ALTER TABLE beacon ADD COLUMN host_ip TEXT DEFAULT ''")


    def save_session(self, s) -> None:
        closed = None if s.status == "live" else time.time()
        self._conn.execute(
            "INSERT INTO shell_sessions(id,host_ip,host_port,kind,status,token,opened,closed,pty,label,name,"
            "notes,pinned,listener_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status=excluded.status, closed=excluded.closed, "
            "pty=excluded.pty, label=excluded.label, name=excluded.name, "
            "notes=excluded.notes, pinned=excluded.pinned, listener_id=excluded.listener_id",
            (s.id, s.host_ip, s.host_port, s.kind, s.status, s.token, s.created, closed,
             1 if s.pty else 0, s.label, s.name,
             getattr(s, "notes", "") or "", 1 if getattr(s, "pinned", False) else 0,
             getattr(s, "listener_id", "") or ""))
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
        """Every persisted session with its concatenated transcript, oldest first.
        Excludes sessions explicitly marked `dead` (retired beacon / operator-closed
        shell) — without this filter a retired beacon comes back as an orphaned
        stale session after every serve restart, still holding queued tasks that
        can never be delivered because its transport is gone."""
        rows = self._conn.execute(
            "SELECT id,host_ip,host_port,kind,status,token,opened,pty,label,name,"
            "notes,pinned,listener_id "
            "FROM shell_sessions "
            "WHERE status IS NULL OR status != 'dead' "
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
                         "label": r[8] or "", "name": r[9] or "",
                         "notes": r[10] or "", "pinned": bool(r[11]),
                         "listener_id": r[12] or ""}, data))
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

    # --- upload tracking: every file dropped on a target is recorded so a
    # teardown sweep can walk the list and either delete via a live shell or
    # produce a checklist for manual cleanup. Same pattern as persistence.
    def add_upload(self, u: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO uploads"
            "(id,host_ip,remote_path,bytes,uploaded_by,uploaded_at,cleared_at,note) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (u["id"], u["host_ip"], u["remote_path"], int(u.get("bytes", 0)),
             u.get("uploaded_by", ""), u["uploaded_at"], u.get("cleared_at"),
             u.get("note", "")))
        self._conn.commit()

    def list_uploads(self, host_ip: str = "", active_only: bool = False) -> list[dict]:
        q = "SELECT id,host_ip,remote_path,bytes,uploaded_by,uploaded_at,cleared_at,note FROM uploads"
        cond, args = [], []
        if host_ip:
            cond.append("host_ip=?"); args.append(host_ip)
        if active_only:
            cond.append("cleared_at IS NULL")
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY uploaded_at DESC"
        cols = ("id", "host_ip", "remote_path", "bytes", "uploaded_by",
                "uploaded_at", "cleared_at", "note")
        return [dict(zip(cols, r)) for r in self._conn.execute(q, args).fetchall()]

    def mark_upload_cleared(self, uid: str, ts: float) -> bool:
        """Returns True if a row was updated. Callers can 404 on False."""
        cur = self._conn.execute("UPDATE uploads SET cleared_at=? WHERE id=?", (ts, uid))
        self._conn.commit()
        return cur.rowcount > 0

    # --- beacon registry (async-C2 P1) ------------------------------------
    # A row here means the session with this id is beacon-mode. The manager
    # gives it a BeaconTransport rather than a live socket. HTTP(S) polls
    # check in / return results via /beacon/checkin & /beacon/result. `psk`
    # is the raw pre-shared key used to HMAC-authenticate those polls; it
    # is shown to the operator ONCE at registration and stored here for
    # verification (HMAC needs the raw key; a hash column can't verify).
    _BEACON_COLS = ("id", "host_ip", "transport", "registered", "last_checkin",
                    "sleep_s", "jitter_pct", "psk", "notes")

    def add_beacon(self, bid: str, psk: str, *, host_ip: str = "",
                   transport: str = "http",
                   sleep_s: float = 30.0, jitter_pct: float = 20.0,
                   notes: str = "", registered: float | None = None) -> None:
        """Register a beacon. `psk` is the raw pre-shared key — the caller
        (the operator's register-beacon route) has already surfaced it to
        the UI once and won't show it again. `host_ip` is the host the beacon
        runs on, so the beacon list can name its target."""
        import time
        ts = time.time() if registered is None else float(registered)
        self._conn.execute(
            "INSERT OR REPLACE INTO beacon(id,host_ip,transport,registered,last_checkin,"
            "sleep_s,jitter_pct,psk,notes) VALUES(?,?,?,?,?,?,?,?,?)",
            (bid, host_ip or "", transport or "http", ts, 0.0,
             float(sleep_s), max(0.0, min(100.0, float(jitter_pct))),
             psk or "", (notes or "")[:500]))
        self._conn.commit()

    def get_beacon(self, bid: str) -> dict | None:
        r = self._conn.execute(
            "SELECT id,host_ip,transport,registered,last_checkin,sleep_s,jitter_pct,"
            "psk,notes FROM beacon WHERE id=?", (bid,)).fetchone()
        return dict(zip(self._BEACON_COLS, r)) if r else None

    def list_beacons(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id,host_ip,transport,registered,last_checkin,sleep_s,jitter_pct,"
            "psk,notes FROM beacon ORDER BY registered DESC").fetchall()
        return [dict(zip(self._BEACON_COLS, r)) for r in rows]

    def update_beacon_checkin(self, bid: str, ts: float) -> bool:
        cur = self._conn.execute(
            "UPDATE beacon SET last_checkin=? WHERE id=?", (float(ts), bid))
        self._conn.commit()
        return cur.rowcount > 0

    def update_beacon_policy(self, bid: str, *, sleep_s: float | None = None,
                             jitter_pct: float | None = None,
                             notes: str | None = None) -> bool:
        """Operator can retune sleep/jitter or edit notes without re-registering.
        None means "keep current"; server clamps jitter to 0..100."""
        cur = self._conn.execute(
            "SELECT sleep_s, jitter_pct, notes FROM beacon WHERE id=?", (bid,)).fetchone()
        if not cur:
            return False
        new_sleep = float(sleep_s) if sleep_s is not None else float(cur[0])
        new_jit = float(jitter_pct) if jitter_pct is not None else float(cur[1])
        new_jit = max(0.0, min(100.0, new_jit))
        new_notes = (notes if notes is not None else cur[2])[:500]
        self._conn.execute(
            "UPDATE beacon SET sleep_s=?, jitter_pct=?, notes=? WHERE id=?",
            (new_sleep, new_jit, new_notes, bid))
        self._conn.commit()
        return True

    def delete_beacon(self, bid: str) -> bool:
        # Belt + suspenders: also mark the paired shell_sessions row `dead` so
        # a subsequent serve restart never re-hydrates the retired beacon as a
        # stale orphan. (The manager's close_session() usually did this via
        # _save(sess) with status='dead', but a partial teardown or a manager
        # not fully bound would leave a live-looking row behind — this makes
        # retirement atomic at the store layer.)
        import time
        now = time.time()
        cur = self._conn.execute("DELETE FROM beacon WHERE id=?", (bid,))
        self._conn.execute(
            "UPDATE shell_sessions SET status='dead', closed=? "
            "WHERE id=? AND (closed IS NULL OR closed=0)", (now, bid))
        self._conn.commit()
        return cur.rowcount > 0

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
