"""SQLite-backed datastore.

Hosts are stored as JSON blobs keyed by IP so a re-scan simply upserts. This
makes multi-subnet engagements resumable: interrupt at any point, and the next
run merges new findings into the existing store instead of starting over.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import closing, contextmanager

from .models import Credential, Domain, Host


class StoreError(RuntimeError):
    """The datastore file is corrupt/unreadable (e.g. a partial transfer)."""


# Ranked weakest->strongest so a merge never downgrades a host's proof-of-life:
# a real reply outranks the -Pn assume-up ("user-set") which outranks nothing.
_UP_REASON_RANK = {"": 0, "unknown": 0, "no-response": 0, "unknown-response": 0,
                   "user-set": 1}

# The tracking upsert for a review/triage action, shared by set_reviewed and
# bulk_set_tracking so the two can't drift. reviewed_by/reviewed_at are only
# stamped when a real reviewer is supplied (excluded.reviewed_by != ''), so a
# note-only write never clobbers who last reviewed the item.
_TRACKING_REVIEW_UPSERT = (
    "INSERT INTO tracking(key, reviewed, notes, updated, reviewed_by, reviewed_at) "
    "VALUES(?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
    "reviewed=excluded.reviewed, notes=excluded.notes, updated=excluded.updated, "
    "reviewed_by=CASE WHEN excluded.reviewed_by!='' THEN excluded.reviewed_by ELSE tracking.reviewed_by END, "
    "reviewed_at=CASE WHEN excluded.reviewed_by!='' THEN excluded.reviewed_at ELSE tracking.reviewed_at END"
)


def _best_up_reason(old: str, new: str) -> str:
    """Return whichever reason is the stronger proof the host is up. Any concrete
    reply (echo-reply, syn-ack, arp-response, report-listed, ...) ranks above the
    blanket -Pn 'user-set' and above a blank, and never gets overwritten by them."""
    def rank(r: str) -> int:
        return _UP_REASON_RANK.get(r, 2)   # anything not listed is a real reply
    return new if rank(new) > rank(old) else old


def _merge_port_state(old: str, new: str) -> str:
    """Merge two nmap port states without ever downgrading a confirmed 'open'.

    The parser keeps only open / open|filtered, and 'open' is the more certain
    verdict. A later scan that re-sees the same port as 'open|filtered' (UDP flaps
    between the two between runs) must not overwrite a prior 'open' - that, combined
    with open_ports honoring open|filtered, would make a previously-reported port
    disappear on the re-scan. Prefer 'open' whenever either scan saw it."""
    if "open" in (old, new):
        return "open"
    return new or old

_SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip       TEXT PRIMARY KEY,
    subnet   TEXT,
    data     TEXT NOT NULL,
    updated  TEXT
);
CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope (
    subnet TEXT PRIMARY KEY,
    size   INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tracking (
    key         TEXT PRIMARY KEY,
    reviewed    INTEGER DEFAULT 0,
    notes       TEXT DEFAULT '',
    status      TEXT DEFAULT '',
    updated     TEXT DEFAULT '',
    reviewed_by TEXT DEFAULT '',
    reviewed_at TEXT DEFAULT '',
    assignee    TEXT DEFAULT '',
    priority    TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
-- Structured operations log (oplog): one row per post-ex action a team member
-- ran through a session (quick-action, one-shot command). Shared + durable so
-- the whole team sees who did what on which host, and reporting can consume it.
CREATE TABLE IF NOT EXISTS oplog (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT DEFAULT '',
    operator   TEXT DEFAULT '',
    session_id TEXT DEFAULT '',
    host_ip    TEXT DEFAULT '',
    kind       TEXT DEFAULT '',
    command    TEXT DEFAULT '',
    output     TEXT DEFAULT '',
    status     TEXT DEFAULT '',
    attack     TEXT DEFAULT '',
    -- Task-record extension: task_id is a stable uuid the row is keyed by
    -- from the operator UI (so a beacon check-in can update a specific
    -- queued row, not just append). result_at splits issued-vs-completed
    -- for beacon-mode where the two differ by minutes. bytes is the
    -- captured output length (the row keeps a truncated preview, artifact
    -- table holds the full blob when it's larger than a preview).
    task_id    TEXT DEFAULT '',
    result_at  TEXT DEFAULT '',
    bytes      INTEGER DEFAULT 0
);
-- Post-ex artifact index: one row per captured file / oplog output that
-- overflows the inline preview. The blob lives under <eng>/session-loot/;
-- this table indexes it so the UI can browse by host, session, or the
-- finding it proves. Populated by the download endpoint today; async
-- beacon results plug into the same rows in a later phase.
CREATE TABLE IF NOT EXISTS artifact (
    id          TEXT PRIMARY KEY,
    ts          TEXT DEFAULT '',
    task_id     TEXT DEFAULT '',
    session_id  TEXT DEFAULT '',
    host_ip     TEXT DEFAULT '',
    kind        TEXT DEFAULT '',      -- "file" | "output" | "screenshot" | "cred-blob"
    path        TEXT DEFAULT '',      -- on-disk path under <eng>/session-loot/
    sha256      TEXT DEFAULT '',      -- content hash (dedup + integrity)
    bytes       INTEGER DEFAULT 0,
    captured_by TEXT DEFAULT '',      -- tester id who triggered the capture
    finding_id  TEXT DEFAULT '',      -- optional link into engagement findings
    note        TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_artifact_host    ON artifact(host_ip);
CREATE INDEX IF NOT EXISTS ix_artifact_session ON artifact(session_id);
CREATE INDEX IF NOT EXISTS ix_artifact_task    ON artifact(task_id);
CREATE INDEX IF NOT EXISTS ix_artifact_finding ON artifact(finding_id);
-- Out-of-band (OOB) callback catcher — the recce-side interactsh/Burp-
-- Collaborator surrogate. `oob_token` records a per-probe minted token +
-- what it's trying to prove; `oob_hit` records every HTTP hit inbound at
-- /oob/<token> so the operator can see blind exec / SSRF / smuggling
-- proofs land live. First hit on a token that carries a `vuln_key`
-- synthesises a script_id='oob_callback_triggered' finding for the
-- T3 gate at webui/routes/findings.py:1250.
CREATE TABLE IF NOT EXISTS oob_token (
    token       TEXT PRIMARY KEY,
    ts          TEXT DEFAULT '',      -- created_at unix
    kind        TEXT DEFAULT '',      -- 'log4shell' | 'spring4shell' | 'smuggle' | 'ssrf' | 'generic'
    target_ip   TEXT DEFAULT '',
    target_port INTEGER DEFAULT 0,
    target_url  TEXT DEFAULT '',
    vuln_key    TEXT DEFAULT '',      -- optional: back-reference into a Vuln.key
    tester      TEXT DEFAULT '',
    note        TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS oob_hit (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token        TEXT DEFAULT '',
    ts           TEXT DEFAULT '',     -- hit timestamp unix
    src_ip       TEXT DEFAULT '',
    method       TEXT DEFAULT '',
    path         TEXT DEFAULT '',     -- request-target after /oob/<token>/
    headers      TEXT DEFAULT '',     -- JSON dict, truncated
    body_preview TEXT DEFAULT ''       -- first 4KB (utf-8 replace)
);
CREATE INDEX IF NOT EXISTS ix_oob_hit_token ON oob_hit(token);
CREATE INDEX IF NOT EXISTS ix_oob_token_vuln ON oob_token(vuln_key);
CREATE TABLE IF NOT EXISTS credentials (
    ukey TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS issues (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT DEFAULT '',
    ip      TEXT DEFAULT '',
    phase   TEXT DEFAULT '',
    level   TEXT DEFAULT 'warning',
    message TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS testers (
    token      TEXT PRIMARY KEY,
    name       TEXT DEFAULT '',
    first_seen TEXT DEFAULT '',
    last_seen  TEXT DEFAULT ''
);
-- Collaboration state. Previously JSON blobs in `meta` mutated by whole-blob
-- read-modify-write under an in-process lock (clobbers under a second writer).
-- Now one row per item, each write atomic under BEGIN IMMEDIATE, so concurrent
-- testers (even across processes) can't lose each other's updates.
CREATE TABLE IF NOT EXISTS collab_assign (
    ip      TEXT PRIMARY KEY,
    tester  TEXT DEFAULT '',
    updated TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS collab_label (
    ip      TEXT NOT NULL,
    label   TEXT NOT NULL,
    updated TEXT DEFAULT '',
    PRIMARY KEY (ip, label)
);
CREATE TABLE IF NOT EXISTS collab_port (
    endpoint TEXT PRIMARY KEY,   -- "ip:port"
    status   TEXT DEFAULT '',    -- todo | wip | done
    updated  TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS collab_dismiss (
    fkey    TEXT PRIMARY KEY,    -- finding key
    tester  TEXT DEFAULT '',
    updated TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS collab_activity (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     REAL DEFAULT 0,
    tester TEXT DEFAULT '',
    kind   TEXT DEFAULT '',
    text   TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS collab_chat (
    id     TEXT PRIMARY KEY,
    ts     REAL DEFAULT 0,
    tester TEXT DEFAULT '',
    text   TEXT DEFAULT '',
    image  TEXT DEFAULT '',
    file   TEXT DEFAULT ''       -- JSON {stored,name,size} or ''
);
"""

_ACTIVITY_CAP = 300
_CHAT_CAP = 500
_OPLOG_CAP = 10000       # bound oplog growth over a long engagement (reads are capped anyway)

# Bump when _SCHEMA / _migrate change. Gates _migrate so it runs ONCE per version
# rather than on every Store() construction — the webui builds a fresh Store per
# request, and re-running BEGIN IMMEDIATE migration on each would serialise reads
# behind the write lock and defeat WAL's reader/writer concurrency.
_SCHEMA_VERSION = 2


class Store:
    def __init__(self, path: str):
        self.path = path
        # One sqlite3.Connection PER THREAD (see _open_conn). The web workbench
        # shares a single Store across a threadpool; a single shared connection
        # would defeat the BEGIN IMMEDIATE + busy_timeout serialisation (those
        # coordinate *separate* connections - two BEGIN IMMEDIATEs on one shared
        # connection raise "cannot start a transaction within a transaction",
        # which busy_timeout does NOT retry). _all_conns tracks every per-thread
        # connection so close() can shut them all down.
        self._local = threading.local()
        self._all_conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()
        try:
            conn = self._open_conn()       # this thread's connection
            conn.executescript(_SCHEMA)
            # Run the (BEGIN IMMEDIATE) migration only when the stored schema version
            # is behind — once per DB per version, not on every construction.
            if self.get_meta("schema_version") != str(_SCHEMA_VERSION):
                self._migrate()
                self.set_meta("schema_version", str(_SCHEMA_VERSION))
        except sqlite3.Error as e:
            # A corrupt / partially-transferred results.sqlite must fail with a
            # clear, actionable message - not a raw sqlite traceback on the very
            # first command against a carried-over engagement dir. Close any
            # half-open connection first so the handle doesn't leak on this path.
            self.close()
            raise StoreError(
                f"datastore at {path} is corrupt or unreadable ({e}). Delete it "
                "or point -o at a fresh directory, then re-run.") from e

    def _open_conn(self) -> sqlite3.Connection:
        """Open and register a fresh connection for the CURRENT thread. Each thread
        gets its own so BEGIN IMMEDIATE + busy_timeout serialise writers across
        connections as intended. autocommit (isolation_level=None) so we can drive
        `BEGIN IMMEDIATE` explicitly - the sqlite3 legacy mode would auto-begin a
        deferred transaction before any DML, and then our explicit BEGIN would
        raise. check_same_thread=False is belt-and-braces (the object is only
        touched by its owning thread, but close() may run from another)."""
        conn = sqlite3.connect(self.path, isolation_level=None,
                               check_same_thread=False)
        # Ride out a transient lock (operator opened the DB, or a second recce)
        # instead of aborting a scan; WAL lets readers not block the writer.
        conn.execute("PRAGMA busy_timeout=15000")
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass                           # non-fatal (e.g. read-only fs); keep going
        self._local.conn = conn
        with self._conns_lock:
            self._all_conns.append(conn)
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """This thread's connection, opened lazily on first use per thread."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._open_conn()
        return conn

    @contextmanager
    def _write_txn(self):
        """One write transaction: BEGIN IMMEDIATE (take the write lock BEFORE any
        read, so a read-merge-write can't lose an update to a concurrent writer),
        commit on normal exit, roll back on ANY exception - BaseException included,
        so a KeyboardInterrupt mid-write still leaves the store consistent. Replaces
        the BEGIN/try/commit/except-rollback boilerplate that was copied across every
        writer. An early `return` from the body commits (the transaction did its work
        or made no change - either way the lock is released and no partial write is
        left)."""
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    def _migrate(self) -> None:
        """Add columns introduced after a datastore was first created. Fresh stores
        already have these from _SCHEMA; the ALTERs below only upgrade older ones.
        Wrapped in a single BEGIN IMMEDIATE so an interruption mid-migration (esp.
        the multi-step collab move) can't leave a half-migrated store."""
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cols = {r[1] for r in cur.execute("PRAGMA table_info(tracking)").fetchall()}
                if "status" not in cols:
                    cur.execute("ALTER TABLE tracking ADD COLUMN status TEXT DEFAULT ''")
                # Test-management attribution (who actioned a finding's review/triage
                # state, and when), plus per-item ownership + priority. Additive so
                # older engagement stores upgrade in place; all default to ''.
                for col in ("reviewed_by", "reviewed_at", "assignee", "priority"):
                    if col not in cols:
                        cur.execute(f"ALTER TABLE tracking ADD COLUMN {col} TEXT DEFAULT ''")
                # Backfill hosts.updated with a synthetic "an hour ago" timestamp
                # for any host missing one — earlier scan paths never stamped it,
                # which left "Recent changes" saying "0 hosts touched" even on
                # engagements with hundreds of scanned hosts. One-time; safe on
                # empty tables (WHERE updated='' OR updated IS NULL matches none).
                backfill = str(time.time() - 3600)
                cur.execute("UPDATE hosts SET updated=? WHERE updated='' OR updated IS NULL",
                            (backfill,))
                # Task-record columns on oplog (schema v2). Additive so pre-v2
                # engagements upgrade in place — task_id/result_at default '',
                # bytes defaults 0, existing rows keep their empty task_id and
                # simply don't show up under the "tasks" filter (which is the
                # right behaviour: historical rows weren't dispatched as tasks).
                oplog_cols = {r[1] for r in cur.execute(
                    "PRAGMA table_info(oplog)").fetchall()}
                if "task_id" not in oplog_cols:
                    cur.execute("ALTER TABLE oplog ADD COLUMN task_id TEXT DEFAULT ''")
                if "result_at" not in oplog_cols:
                    cur.execute("ALTER TABLE oplog ADD COLUMN result_at TEXT DEFAULT ''")
                if "bytes" not in oplog_cols:
                    cur.execute("ALTER TABLE oplog ADD COLUMN bytes INTEGER DEFAULT 0")
                # One-time purge of stale scan_issue rows from before the
                # dogfood-item-3 fix (commit ec3e856): `udp-basic: skipped
                # (needs root/CAP_NET_RAW ...)` was recorded per-host as a
                # ScanIssue on every unprivileged enum, inflating the
                # `[!] N scan issue(s) logged (0 error, N incomplete)`
                # footer. The condition is a config state, not a scan
                # failure — never should have been persisted. Distinctive
                # message string; false positives impossible.
                cur.execute("DELETE FROM issues WHERE message LIKE "
                            "'udp-basic: skipped (needs root%'")
                self._migrate_collab(cur)

    def _migrate_collab(self, cur) -> None:
        """One-time move of collaboration state from the old `meta` JSON blobs into
        the per-row collab_* tables. Idempotent: each blob's meta key is deleted
        once migrated, so later opens find nothing to do. Runs inside _migrate's
        cursor/commit."""
        def _blob(key):
            row = cur.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            if not row or not row[0]:
                return None
            try:
                return json.loads(row[0])
            except (ValueError, TypeError):
                return None

        now = str(int(time.time()))
        a = _blob("collab.assignments")
        if isinstance(a, dict):
            for ip, tester in a.items():
                if tester:
                    cur.execute("INSERT OR REPLACE INTO collab_assign(ip,tester,updated) "
                                "VALUES(?,?,?)", (ip, tester, now))
            cur.execute("DELETE FROM meta WHERE key='collab.assignments'")
        lab = _blob("collab.labels")
        if isinstance(lab, dict):
            for ip, labels in lab.items():
                for label in (labels or []):
                    cur.execute("INSERT OR IGNORE INTO collab_label(ip,label,updated) "
                                "VALUES(?,?,?)", (ip, label, now))
            cur.execute("DELETE FROM meta WHERE key='collab.labels'")
        ports = _blob("collab.port_status")
        if isinstance(ports, dict):
            for endpoint, status in ports.items():
                if status:
                    cur.execute("INSERT OR REPLACE INTO collab_port(endpoint,status,updated) "
                                "VALUES(?,?,?)", (endpoint, status, now))
            cur.execute("DELETE FROM meta WHERE key='collab.port_status'")
        dis = _blob("collab.dismissed")
        if isinstance(dis, dict):
            for fkey, tester in dis.items():
                cur.execute("INSERT OR REPLACE INTO collab_dismiss(fkey,tester,updated) "
                            "VALUES(?,?,?)", (fkey, tester, now))
            cur.execute("DELETE FROM meta WHERE key='collab.dismissed'")
        act = _blob("collab.activity")
        if isinstance(act, list):
            for e in act:
                cur.execute("INSERT INTO collab_activity(ts,tester,kind,text) VALUES(?,?,?,?)",
                            (e.get("ts", 0), e.get("tester", ""), e.get("kind", ""),
                             e.get("text", "")))
            cur.execute("DELETE FROM meta WHERE key='collab.activity'")
        chat = _blob("collab.chat")
        if isinstance(chat, list):
            for m in chat:
                cur.execute("INSERT OR REPLACE INTO collab_chat(id,ts,tester,text,image,file) "
                            "VALUES(?,?,?,?,?,?)",
                            (m.get("id") or uuid.uuid4().hex[:12], m.get("ts", 0),
                             m.get("tester", ""), m.get("text", ""), m.get("image", ""),
                             json.dumps(m["file"]) if m.get("file") else ""))
            cur.execute("DELETE FROM meta WHERE key='collab.chat'")

    def close(self) -> None:
        with self._conns_lock:
            conns = list(self._all_conns)
            self._all_conns.clear()
        for c in conns:
            try:
                c.close()
            except sqlite3.Error:
                pass
        self._local.conn = None

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- merge semantics --------------------------------------------------------

    def _merge(self, old: Host, new: Host) -> Host:
        """Combine two scans of the same host, preferring the richer data."""
        merged = old
        # Capture pre-merge enumerated states: `merged is old`, so the assignments below
        # mutate old.enumerated before the incomplete_scan logic would read it.
        old_was_enum, new_was_enum = old.enumerated, new.enumerated
        # Ports: index by (proto, portid); newer non-empty fields win.
        port_index = {(p.protocol, p.portid): p for p in old.ports}
        for np in new.ports:
            key = (np.protocol, np.portid)
            if key in port_index:
                op = port_index[key]
                op.state = _merge_port_state(op.state, np.state)
                op.service = np.service or op.service
                op.product = np.product or op.product
                op.version = np.version or op.version
                op.extrainfo = np.extrainfo or op.extrainfo
                op.tunnel = np.tunnel or op.tunnel
                op.cpe = np.cpe or op.cpe
                # Newer non-empty enrichment wins for the remaining fields too - else a
                # later pass (esp. ingest/deploy setting binary/detect_source, or a
                # probe run capturing banner/servicefp) is silently dropped on merge.
                op.reason = np.reason or op.reason
                op.ostype = np.ostype or op.ostype
                op.servicefp = np.servicefp or op.servicefp
                op.detect_source = np.detect_source or op.detect_source
                op.banner = np.banner or op.banner
                op.binary = np.binary or op.binary
                op.vuln_scanned = op.vuln_scanned or np.vuln_scanned
                if np.scripts:
                    seen = {s.id for s in op.scripts}
                    op.scripts.extend(s for s in np.scripts if s.id not in seen)
            else:
                port_index[key] = np
        merged.ports = list(port_index.values())

        # Scalar enrichment: fill blanks, upgrade OS accuracy.
        merged.hostnames = list(dict.fromkeys(old.hostnames + new.hostnames))
        merged.mac = merged.mac or new.mac
        merged.vendor = merged.vendor or new.vendor
        if new.os_accuracy >= old.os_accuracy and new.os_name:
            merged.os_name, merged.os_accuracy, merged.os_family = (
                new.os_name, new.os_accuracy, new.os_family)
        merged.state = new.state or old.state
        # Keep the strongest proof-of-life reason: a real reply (echo-reply/syn-ack/
        # arp-response/report-listed) always outranks the -Pn "user-set" assume-up
        # and a blank, so a later -Pn re-scan can never downgrade a confirmed host.
        merged.up_reason = _best_up_reason(old.up_reason, new.up_reason)
        merged.distance = new.distance or old.distance
        merged.enumerated = old.enumerated or new.enumerated
        # Ports are unioned across scans, so the host is complete if ANY sweep
        # finished; only incomplete when every scan of it was truncated. A record that
        # was NEVER enumerated (a --targets-up seed) contributed no ports, so its
        # default `incomplete_scan=False` must not count as "a scan completed" - that
        # would mark a truncated enum as complete.
        if not old_was_enum:
            merged.incomplete_scan = new.incomplete_scan
        elif not new_was_enum:
            merged.incomplete_scan = old.incomplete_scan
        else:
            merged.incomplete_scan = old.incomplete_scan and new.incomplete_scan
        merged.db_scanned = old.db_scanned or new.db_scanned
        merged.privesc_checked = old.privesc_checked or new.privesc_checked
        merged.cred_enumerated = old.cred_enumerated or new.cred_enumerated
        merged.access_gained = old.access_gained or new.access_gained
        merged.access_detail = new.access_detail or old.access_detail
        merged.last_scanned = new.last_scanned or old.last_scanned
        merged.subnet = new.subnet or old.subnet

        # Host-level scripts: dedup by id.
        hs_seen = {s.id for s in old.host_scripts}
        merged.host_scripts.extend(s for s in new.host_scripts if s.id not in hs_seen)
        # Ingested on-target findings: dedup by (category, vector).
        lf_seen = {(f.get("category"), f.get("vector")) for f in old.local_findings}
        for f in new.local_findings:
            k = (f.get("category"), f.get("vector"))
            if k not in lf_seen:
                lf_seen.add(k)
                merged.local_findings.append(f)
        # Roles / ntlm / signing enrichment.
        merged.roles = sorted(set(old.roles) | set(new.roles))
        # Newer non-empty facts win (consistent with the rest of _merge); a later,
        # richer NTLM capture must not be overwritten by the older scan.
        merged.ntlm = {**old.ntlm, **{k: v for k, v in new.ntlm.items() if v}}
        if new.smb_signing and new.smb_signing != "unknown":
            merged.smb_signing = new.smb_signing
        merged.defenses = list(dict.fromkeys(old.defenses + new.defenses))
        # Observed topology is a fresh snapshot from the latest on-target enum; the
        # newest non-empty one wins (an older capture never overwrites a newer).
        merged.topology = new.topology or old.topology

        # Vulns / exploits / accounts: dedup by natural key, accumulating the
        # seen-set so duplicates WITHIN one scan are collapsed too, not just
        # old-vs-new.
        vseen = {v.key for v in old.vulns}
        for nv in new.vulns:
            if nv.key not in vseen:
                vseen.add(nv.key)
                merged.vulns.append(nv)
        eseen = {e.key for e in old.exploits}
        for ne in new.exploits:
            if ne.key not in eseen:
                eseen.add(ne.key)
                merged.exploits.append(ne)
        aidx = {(a.source, a.kind, a.name, a.domain, a.rid): a for a in old.accounts}
        for a in new.accounts:
            k = (a.source, a.kind, a.name, a.domain, a.rid)
            existing = aidx.get(k)
            if existing is None:
                merged.accounts.append(a)
                aidx[k] = a
            else:
                # Same account seen again: fold in any richer attrs/detail a later pass
                # discovered (admincount, spn, delegation ...) instead of dropping them.
                for ak, av in a.attrs.items():
                    if av and not existing.attrs.get(ak):
                        existing.attrs[ak] = av
                existing.detail = existing.detail or a.detail
        return merged

    def upsert_host(self, host: Host, merge: bool = True) -> None:
        """Persist a host. By default it MERGES with any existing record (union of
        vulns/accounts/exploits by key, so re-scans accumulate). Pass merge=False
        to overwrite the stored record wholesale - used when the caller has already
        loaded the full host and intentionally removed items (e.g. `--replace-ad`),
        which the union-merge would otherwise re-introduce.

        Atomic: the read-merge-write runs under a single `BEGIN IMMEDIATE` transaction,
        so two writers upserting the SAME host can't clobber each other's merge - the
        write lock is taken before the read, so the second writer sees the first's
        committed record instead of a stale one (fixes a lost-update race under the
        concurrent web workbench / multi-worker scans)."""
        with self._write_txn():          # take the write lock before reading
            existing = self.get_host(host.ip)
            if existing and merge:
                host = self._merge(existing, host)
            # Auto-stamp last_scanned on every upsert. Ingestion paths (import
            # tool output, deep-service scans, credential enum) never called
            # `host.last_scanned = str(time.time())` themselves, which meant
            # the Dashboard's "Recent changes" panel stayed at "0 hosts
            # touched" no matter how many scans ran. The parser.py nmap path
            # sets it from the scan `start` attribute; every other path now
            # gets the current wall-clock via this fall-through.
            if not host.last_scanned:
                host.last_scanned = str(time.time())
            with closing(self.conn.cursor()) as cur:
                cur.execute(
                    "INSERT INTO hosts(ip, subnet, data, updated) VALUES(?,?,?,?) "
                    "ON CONFLICT(ip) DO UPDATE SET subnet=excluded.subnet, "
                    "data=excluded.data, updated=excluded.updated",
                    (host.ip, host.subnet, json.dumps(host.to_json()), host.last_scanned),
                )

    def delete_host(self, ip: str) -> bool:
        """Remove a host and its tracking rows. Returns True if the host existed."""
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cur.execute("DELETE FROM hosts WHERE ip=?", (ip,))
                gone = cur.rowcount > 0
                # Tracking keys are namespaced (see core/tracking.py). host:/svc:/
                # web:/vuln: are ip-prefixed; step:{step}:{ip} carries the ip as its
                # last colon-segment. (The old `%@{ip}:%` pattern matched a retired
                # key format and deleted nothing, orphaning every tracking row.)
                cur.execute("DELETE FROM tracking WHERE key=?", (f"host:{ip}",))
                for prefix in ("svc", "web", "vuln"):
                    cur.execute("DELETE FROM tracking WHERE key LIKE ?", (f"{prefix}:{ip}:%",))
                # step: is ip-SUFFIXED, so a LIKE '%' pattern could greedily
                # over-match a host whose ip is a suffix of another's - match the
                # exact trailing segment in Python instead.
                step_rows = cur.execute(
                    "SELECT key FROM tracking WHERE key LIKE 'step:%'").fetchall()
                stale = [(r[0],) for r in step_rows if r[0].rsplit(":", 1)[-1] == ip]
                if stale:
                    cur.executemany("DELETE FROM tracking WHERE key=?", stale)
                cur.execute("DELETE FROM issues WHERE ip=?", (ip,))
        return gone

    def get_host(self, ip: str) -> Host | None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT data FROM hosts WHERE ip=?", (ip,)).fetchone()
        return Host.from_json(json.loads(row[0])) if row else None

    def all_hosts(self) -> list[Host]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT data FROM hosts ORDER BY ip").fetchall()
        return [Host.from_json(json.loads(r[0])) for r in rows]

    # --- domains ----------------------------------------------------------------

    def upsert_domain(self, domain: Domain) -> None:
        """Atomic like upsert_host: merge_domain is a union merge (accumulates
        dc_ips/trusts/sources), so two concurrent writers must not both read the same
        record and clobber each other. BEGIN IMMEDIATE takes the write lock before the
        read."""
        from ..ad import merge_domain
        with self._write_txn():
            existing = self.get_domain(domain.name)
            if existing:
                domain = merge_domain(existing, domain)
            with closing(self.conn.cursor()) as cur:
                cur.execute(
                    "INSERT INTO domains(name, data) VALUES(?,?) "
                    "ON CONFLICT(name) DO UPDATE SET data=excluded.data",
                    (domain.name.lower(), json.dumps(domain.to_json())),
                )

    def get_domain(self, name: str) -> Domain | None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT data FROM domains WHERE name=?",
                              (name.lower(),)).fetchone()
        return Domain.from_json(json.loads(row[0])) if row else None

    def all_domains(self) -> list[Domain]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT data FROM domains ORDER BY name").fetchall()
        return [Domain.from_json(json.loads(r[0])) for r in rows]

    # --- credentials (stacking) -------------------------------------------------

    def add_credential(self, cred: Credential) -> bool:
        """Insert a credential, deduped by (domain, user, kind, secret). Returns
        True if it was new."""
        with closing(self.conn.cursor()) as cur:
            cur.execute("INSERT OR IGNORE INTO credentials(ukey, data) VALUES(?,?)",
                        (cred.dedupe_key(), json.dumps(cred.to_json())))
            added = cur.rowcount > 0
        self.conn.commit()
        return added

    def delete_credential(self, ukey: str) -> bool:
        """Remove a credential by its dedupe key. Returns True if it existed."""
        with closing(self.conn.cursor()) as cur:
            cur.execute("DELETE FROM credentials WHERE ukey=?", (ukey,))
            gone = cur.rowcount > 0
        self.conn.commit()
        return gone

    def all_credentials(self) -> list[Credential]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT data FROM credentials").fetchall()
        return [Credential.from_json(json.loads(r[0])) for r in rows]

    # --- coverage tracking ------------------------------------------------------

    def set_note_cas(self, key: str, notes: str, base: str | None = None) -> tuple[str, str]:
        """Compare-and-swap note write for multi-operator safety. If `base` is given
        and the stored note has since diverged (someone else edited it), write
        nothing and return ("conflict", <current note>); otherwise write and return
        ("ok", notes). The read-check-write runs under one BEGIN IMMEDIATE so two
        testers editing the same note can't silently clobber each other. Preserves
        the reviewed flag and reviewer (who="")."""
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                row = cur.execute("SELECT reviewed, notes FROM tracking WHERE key=?",
                                  (key,)).fetchone()
                reviewed = row[0] if row else 0
                current = (row[1] if row else "") or ""
                if base is not None and current != (base or ""):
                    return ("conflict", current)          # empty txn commits; nothing written
                when = str(int(time.time()))
                cur.execute(_TRACKING_REVIEW_UPSERT,
                            (key, reviewed, notes, when, "", ""))
        return ("ok", notes)

    def set_reviewed(self, key: str, reviewed: bool, notes: str | None = None,
                     when: str = "", who: str = "") -> None:
        # Atomic read-modify-write: the SELECT preserves an existing note when the
        # caller passes notes=None, so a concurrent writer between read and write
        # must not slip in. BEGIN IMMEDIATE takes the write lock before the read.
        #
        # `who` records the operator who took this review action (reviewed_by /
        # reviewed_at). A note-only write passes who="" so it never overwrites the
        # real reviewer — the CASE below only stamps when who is non-empty.
        when = when or str(int(time.time()))
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                row = cur.execute("SELECT notes FROM tracking WHERE key=?", (key,)).fetchone()
                keep_notes = row[0] if (row and notes is None) else (notes or "")
                cur.execute(
                    _TRACKING_REVIEW_UPSERT,
                    (key, 1 if reviewed else 0, keep_notes, when, who, when if who else ""),
                )

    def bulk_set_tracking(self, items: dict[str, tuple], when: str = "",
                          who: str = "") -> int:
        """items: {key: (reviewed_bool, notes)}. Returns number of rows written.
        All rows commit atomically; a mid-loop failure rolls the whole batch back.
        `who` (if given) is stamped as the reviewer on every row in the batch."""
        n = 0
        when = when or str(int(time.time()))
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                for key, (reviewed, notes) in items.items():
                    cur.execute(
                        _TRACKING_REVIEW_UPSERT,
                        (key, 1 if reviewed else 0, notes or "", when, who, when if who else ""),
                    )
                    n += 1
        return n

    # --- scope (every subnet in the engagement, so none is missed) --------------

    def remove_finding(self, ip: str, vuln_key: str) -> bool:
        """Remove a single finding from a host by its canonical `Vuln.key`
        (the "vuln:{ip}:{port}:{script}:{title[:60]}" shape the WebGUI +
        report + tracking-sheet all write out — P7-B5 unified this with
        the model's `.key` property, so there's now one shape to match).
        """
        with self._write_txn():
            host = self.get_host(ip)
            if host is None:
                return False       # empty txn commits (no write); lock released
            before = len(host.vulns)
            host.vulns = [v for v in host.vulns if v.key != vuln_key]
            if len(host.vulns) == before:
                return False       # nothing matched; empty txn, no change
            with closing(self.conn.cursor()) as cur:
                cur.execute(
                    "UPDATE hosts SET data=?, updated=? WHERE ip=?",
                    (json.dumps(host.to_json()), host.last_scanned, ip),
                )
        return True

    def delete_scope(self, subnet: str) -> bool:
        """Remove a subnet from the scope table. Returns True if it existed."""
        with closing(self.conn.cursor()) as cur:
            cur.execute("DELETE FROM scope WHERE subnet=?", (subnet,))
            gone = cur.rowcount > 0
        self.conn.commit()
        return gone

    def set_scope(self, subnet: str, size: int) -> None:
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO scope(subnet, size) VALUES(?,?) "
                "ON CONFLICT(subnet) DO UPDATE SET size=max(scope.size, excluded.size)",
                (subnet, size),
            )
        self.conn.commit()

    def get_scope(self) -> dict[str, int]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT subnet, size FROM scope").fetchall()
        return {r[0]: r[1] for r in rows}

    def delete_tracking(self, key: str) -> None:
        with closing(self.conn.cursor()) as cur:
            cur.execute("DELETE FROM tracking WHERE key=?", (key,))
        self.conn.commit()

    def get_tracking(self) -> dict[str, tuple]:
        """Return {key: (reviewed_bool, notes)}."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT key, reviewed, notes FROM tracking").fetchall()
        return {r[0]: (bool(r[1]), r[2] or "") for r in rows}

    def bulk_set_status(self, items: dict[str, tuple], when: str = "") -> int:
        """items: {key: (status_str, reviewed_bool, notes)}. Persists a per-item
        tri-state status (e.g. a per-port 'in progress') alongside the reviewed
        flag so coverage still works (reviewed True == the port is done). All
        rows commit atomically. Status is a state; who-changed-it is an event
        recorded in the activity feed, so this does not touch reviewed_by."""
        n = 0
        when = when or str(int(time.time()))
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                for key, (status, reviewed, notes) in items.items():
                    cur.execute(
                        "INSERT INTO tracking(key, reviewed, notes, status, updated) "
                        "VALUES(?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
                        "reviewed=excluded.reviewed, notes=excluded.notes, "
                        "status=excluded.status, updated=excluded.updated",
                        (key, 1 if reviewed else 0, notes or "", status or "", when),
                    )
                    n += 1
        return n

    def get_statuses(self) -> dict[str, str]:
        """Return {key: status_str} for rows that carry a non-empty status."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT key, status FROM tracking WHERE status != ''").fetchall()
        return {r[0]: r[1] for r in rows}

    def set_status(self, key: str, status: str, when: str = "") -> None:
        """Set the lifecycle status on one tracking row. Empty status clears it
        (back to the implicit 'new' state — the get_statuses filter drops it).
        Status is a state; who changed it (and when) is an event recorded in the
        activity feed by the route, so this does not touch reviewed_by."""
        when = when or str(int(time.time()))
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO tracking(key, reviewed, notes, status, updated) "
                "VALUES(?, 0, '', ?, ?) ON CONFLICT(key) DO UPDATE SET "
                "status=excluded.status, updated=excluded.updated",
                (key, status or "", when),
            )
        self.conn.commit()

    # --- per-item ownership + priority (test management) ------------------------

    def set_assignment(self, key: str, assignee: str, when: str = "") -> None:
        """Assign a trackable item (any tracking key — vuln:/svc:/host:/...) to a
        tester. Empty assignee clears the claim. Distinct from the host-level
        collab assignments; this is per-finding/per-service ownership."""
        when = when or str(int(time.time()))
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO tracking(key, reviewed, notes, updated, assignee) "
                "VALUES(?, 0, '', ?, ?) ON CONFLICT(key) DO UPDATE SET "
                "assignee=excluded.assignee, updated=excluded.updated",
                (key, when, assignee or ""),
            )
        self.conn.commit()

    def set_priority(self, key: str, priority: str, when: str = "") -> None:
        """Set an operator priority on a trackable item. Empty clears it."""
        when = when or str(int(time.time()))
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO tracking(key, reviewed, notes, updated, priority) "
                "VALUES(?, 0, '', ?, ?) ON CONFLICT(key) DO UPDATE SET "
                "priority=excluded.priority, updated=excluded.updated",
                (key, when, priority or ""),
            )
        self.conn.commit()

    def get_tracking_full(self, keys=None) -> dict[str, dict]:
        """Rich per-item tracking for the web workbench: reviewed flag, notes,
        lifecycle status, and the test-management fields (who/when reviewed,
        assignee, priority). CLI callers keep using the lean get_tracking().

        `keys` (an iterable of tracking keys) restricts the query to just those
        rows — the single-host drawer needs only its host + finding keys, not the
        whole table."""
        with closing(self.conn.cursor()) as cur:
            if keys is not None:
                keys = list(keys)
                if not keys:
                    return {}
                qs = ",".join("?" * len(keys))
                rows = cur.execute(
                    "SELECT key, reviewed, notes, status, reviewed_by, reviewed_at, "
                    f"assignee, priority FROM tracking WHERE key IN ({qs})", keys).fetchall()
            else:
                rows = cur.execute(
                    "SELECT key, reviewed, notes, status, reviewed_by, reviewed_at, "
                    "assignee, priority FROM tracking").fetchall()
        return {r[0]: {"reviewed": bool(r[1]), "notes": r[2] or "",
                       "status": r[3] or "", "reviewed_by": r[4] or "",
                       "reviewed_at": r[5] or "", "assignee": r[6] or "",
                       "priority": r[7] or ""} for r in rows}

    # --- tester roster (light named identity) -----------------------------------

    def touch_tester(self, token: str, name: str) -> None:
        """Register/refresh a tester by their stable client token. The roster is
        durable (survives `recce serve` restart, unlike in-memory presence) and
        lets two testers who picked the same display name stay distinct by token.
        No password — this is attribution, not authentication."""
        if not token:
            return
        now = str(int(time.time()))
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO testers(token, name, first_seen, last_seen) VALUES(?,?,?,?) "
                "ON CONFLICT(token) DO UPDATE SET "
                "name=CASE WHEN excluded.name!='' THEN excluded.name ELSE testers.name END, "
                "last_seen=excluded.last_seen",
                (token, name or "", now, now),
            )
        self.conn.commit()

    def resolve_tester(self, token: str) -> str | None:
        """Return the registered display name for a token, or None if unknown."""
        if not token:
            return None
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT name FROM testers WHERE token=?", (token,)).fetchone()
        return row[0] if row else None

    def get_testers(self) -> list[dict]:
        """The full durable roster: every tester who has ever joined."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT token, name, first_seen, last_seen FROM testers "
                "ORDER BY last_seen DESC").fetchall()
        return [{"token": r[0], "name": r[1] or "", "first_seen": r[2] or "",
                 "last_seen": r[3] or ""} for r in rows]

    # --- operations log (structured post-ex actions, shared + durable) -----------

    _OPLOG_COLS = ("ts", "operator", "session_id", "host_ip", "kind",
                   "command", "output", "status", "attack",
                   "task_id", "result_at", "bytes")

    def add_oplog(self, operator: str, session_id: str, host_ip: str, kind: str,
                  command: str, output: str = "", status: str = "ok",
                  attack: str = "", *, task_id: str = "",
                  result_at: str = "", bytes: int = 0) -> None:
        """Record one post-ex action. Output is truncated (the full stream lives in
        the session transcript); this row is the team-visible, reportable summary.

        For task-record rows (see add_task/mark_task_result), task_id keys the
        row so a follow-up result can update it in place instead of appending.
        result_at is the completion timestamp for beacon-mode where issued vs.
        completed can differ by minutes. bytes is the full captured length even
        when output is truncated, so the UI shows "12 KB, showing preview"."""
        row = (str(int(time.time())), operator or "", session_id or "", host_ip or "",
               kind or "", (command or "")[:8000], (output or "")[:4000],
               status or "", attack or "",
               task_id or "", result_at or "", int(bytes) if bytes else 0)
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cur.execute(
                    "INSERT INTO oplog(ts,operator,session_id,host_ip,kind,command,"
                    "output,status,attack,task_id,result_at,bytes) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", row)
                # Bound growth over a long engagement (like the activity/chat feeds).
                cur.execute("DELETE FROM oplog WHERE id NOT IN "
                            "(SELECT id FROM oplog ORDER BY id DESC LIMIT ?)", (_OPLOG_CAP,))

    def get_oplog(self, limit: int = 200, host_ip: str = "") -> list[dict]:
        """Most-recent-first operations log, optionally scoped to one host."""
        with closing(self.conn.cursor()) as cur:
            if host_ip:
                rows = cur.execute(
                    "SELECT ts,operator,session_id,host_ip,kind,command,output,status,attack,"
                    "task_id,result_at,bytes "
                    "FROM oplog WHERE host_ip=? ORDER BY id DESC LIMIT ?",
                    (host_ip, limit)).fetchall()
            else:
                rows = cur.execute(
                    "SELECT ts,operator,session_id,host_ip,kind,command,output,status,attack,"
                    "task_id,result_at,bytes "
                    "FROM oplog ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(zip(self._OPLOG_COLS, r)) for r in rows]

    # --- task record (oplog rows keyed by a stable task_id) ----------------------
    # add_oplog is the fire-and-forget path (one row = one completed action). The
    # add_task / mark_task_result pair splits that in two: issue the row with
    # status="queued", then update it when the result comes back. For interactive
    # sessions the round-trip is milliseconds; for async beacons (P1) it's the
    # gap between check-ins. Either way the team sees the queued row live via
    # SSE the moment it's issued, not only when it completes.

    def add_task(self, operator: str, session_id: str, host_ip: str,
                 command: str, task_id: str, kind: str = "exec",
                 attack: str = "", status: str = "queued") -> None:
        """Record a dispatched task with an empty result. Call mark_task_result
        with the same task_id when the output comes back."""
        self.add_oplog(operator, session_id, host_ip, kind, command,
                       output="", status=status, attack=attack,
                       task_id=task_id, result_at="", bytes=0)

    def mark_task_result(self, task_id: str, output: str,
                         status: str = "done", bytes: int = 0) -> bool:
        """Fill in the result on a previously-queued task row. Returns True when
        a row was updated (callers can 404 on False). Output is truncated the
        same way add_oplog truncates it — full blob belongs in an artifact row."""
        if not task_id:
            return False
        preview = (output or "")[:4000]
        full_bytes = int(bytes) if bytes else len(output or "")
        now = str(int(time.time()))
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cur = cur.execute(
                    "UPDATE oplog SET output=?, status=?, result_at=?, bytes=? "
                    "WHERE task_id=?",
                    (preview, status or "done", now, full_bytes, task_id))
                return cur.rowcount > 0

    def list_tasks(self, session_id: str = "", host_ip: str = "",
                   status: str = "", since_ts: int = 0,
                   limit: int = 200) -> list[dict]:
        """Task rows (oplog rows with a non-empty task_id) filtered any of the
        three ways. Most-recent-first. `since_ts` returns rows issued at or
        after that unix ts (client polling / SSE catch-up)."""
        conds = ["task_id != ''"]
        args: list = []
        if session_id:
            conds.append("session_id=?"); args.append(session_id)
        if host_ip:
            conds.append("host_ip=?"); args.append(host_ip)
        if status:
            conds.append("status=?"); args.append(status)
        if since_ts:
            conds.append("CAST(ts AS INTEGER) >= ?"); args.append(int(since_ts))
        q = ("SELECT ts,operator,session_id,host_ip,kind,command,output,status,attack,"
             "task_id,result_at,bytes FROM oplog WHERE " + " AND ".join(conds) +
             " ORDER BY id DESC LIMIT ?")
        args.append(int(limit))
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(q, args).fetchall()
        return [dict(zip(self._OPLOG_COLS, r)) for r in rows]

    # --- artifact index (blob path + hash, correlates to task / session / host / finding)

    _ARTIFACT_COLS = ("id", "ts", "task_id", "session_id", "host_ip", "kind",
                      "path", "sha256", "bytes", "captured_by", "finding_id", "note")

    def add_artifact(self, art_id: str, session_id: str, host_ip: str,
                     kind: str, path: str, sha256: str = "",
                     bytes: int = 0, captured_by: str = "",
                     task_id: str = "", finding_id: str = "",
                     note: str = "") -> None:
        """Index one captured artifact. The blob itself already lives on disk
        under <eng>/session-loot/<sid>/; this row just makes it findable and
        (optionally) links it to a task and/or a finding."""
        row = (art_id, str(int(time.time())), task_id or "", session_id or "",
               host_ip or "", kind or "file", path or "", sha256 or "",
               int(bytes) if bytes else 0, captured_by or "",
               finding_id or "", (note or "")[:500])
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cur.execute(
                    "INSERT OR REPLACE INTO artifact"
                    "(id,ts,task_id,session_id,host_ip,kind,path,sha256,bytes,"
                    "captured_by,finding_id,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    row)

    def list_artifacts(self, host_ip: str = "", session_id: str = "",
                       task_id: str = "", finding_id: str = "",
                       limit: int = 500) -> list[dict]:
        conds: list = []
        args: list = []
        if host_ip:
            conds.append("host_ip=?"); args.append(host_ip)
        if session_id:
            conds.append("session_id=?"); args.append(session_id)
        if task_id:
            conds.append("task_id=?"); args.append(task_id)
        if finding_id:
            conds.append("finding_id=?"); args.append(finding_id)
        q = ("SELECT id,ts,task_id,session_id,host_ip,kind,path,sha256,bytes,"
             "captured_by,finding_id,note FROM artifact")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(q, args).fetchall()
        return [dict(zip(self._ARTIFACT_COLS, r)) for r in rows]

    def get_artifact(self, art_id: str) -> dict | None:
        with closing(self.conn.cursor()) as cur:
            r = cur.execute(
                "SELECT id,ts,task_id,session_id,host_ip,kind,path,sha256,bytes,"
                "captured_by,finding_id,note FROM artifact WHERE id=?",
                (art_id,)).fetchone()
        return dict(zip(self._ARTIFACT_COLS, r)) if r else None

    # --- OOB callback catcher (interactsh/Burp-Collaborator surrogate) -----------

    _OOB_TOKEN_COLS = ("token", "ts", "kind", "target_ip", "target_port",
                       "target_url", "vuln_key", "tester", "note")
    _OOB_HIT_COLS = ("id", "token", "ts", "src_ip", "method", "path",
                     "headers", "body_preview")

    def mint_oob_token(self, token: str, kind: str = "generic", *,
                       target_ip: str = "", target_port: int = 0,
                       target_url: str = "", vuln_key: str = "",
                       tester: str = "", note: str = "") -> None:
        """Register a fresh OOB token so subsequent hits at /oob/<token>
        get accepted + attributed to the right probe. Idempotent by
        token — re-minting the SAME token replaces the metadata (a
        rare case, useful when the operator retunes vuln_key mid-run)."""
        row = (token, str(int(time.time())), kind or "generic",
               target_ip or "", int(target_port) or 0, target_url or "",
               vuln_key or "", tester or "", (note or "")[:500])
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cur.execute(
                    "INSERT OR REPLACE INTO oob_token"
                    "(token,ts,kind,target_ip,target_port,target_url,"
                    "vuln_key,tester,note) VALUES(?,?,?,?,?,?,?,?,?)", row)

    def get_oob_token(self, token: str) -> dict | None:
        with closing(self.conn.cursor()) as cur:
            r = cur.execute(
                "SELECT token,ts,kind,target_ip,target_port,target_url,"
                "vuln_key,tester,note FROM oob_token WHERE token=?",
                (token,)).fetchone()
        return dict(zip(self._OOB_TOKEN_COLS, r)) if r else None

    def list_oob_tokens(self, vuln_key: str = "", limit: int = 200) -> list[dict]:
        conds, args = [], []
        if vuln_key:
            conds.append("vuln_key=?"); args.append(vuln_key)
        q = ("SELECT token,ts,kind,target_ip,target_port,target_url,"
             "vuln_key,tester,note FROM oob_token")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY CAST(ts AS INTEGER) DESC LIMIT ?"
        args.append(int(limit))
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(q, args).fetchall()
        return [dict(zip(self._OOB_TOKEN_COLS, r)) for r in rows]

    def record_oob_hit(self, token: str, *, src_ip: str = "",
                       method: str = "", path: str = "",
                       headers: str = "", body_preview: str = "") -> int:
        """Store one inbound HTTP hit. Returns the auto-assigned row id.
        Every field is truncated defensively — a huge body from a
        misbehaving scanner shouldn't run the disk out."""
        row = (token, str(int(time.time())), (src_ip or "")[:64],
               (method or "")[:16], (path or "")[:2048],
               (headers or "")[:8192], (body_preview or "")[:4096])
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cur.execute(
                    "INSERT INTO oob_hit(token,ts,src_ip,method,path,headers,"
                    "body_preview) VALUES(?,?,?,?,?,?,?)", row)
                return int(cur.lastrowid or 0)

    def list_oob_hits(self, token: str = "", limit: int = 500) -> list[dict]:
        conds, args = [], []
        if token:
            conds.append("token=?"); args.append(token)
        q = ("SELECT id,token,ts,src_ip,method,path,headers,body_preview "
             "FROM oob_hit")
        if conds:
            q += " WHERE " + " AND ".join(conds)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(q, args).fetchall()
        return [dict(zip(self._OOB_HIT_COLS, r)) for r in rows]

    def count_oob_hits(self, token: str) -> int:
        with closing(self.conn.cursor()) as cur:
            r = cur.execute("SELECT COUNT(*) FROM oob_hit WHERE token=?",
                            (token,)).fetchone()
        return int(r[0]) if r else 0

    # --- collaboration state (per-row, BEGIN IMMEDIATE — multi-writer safe) ------
    # Each setter takes the write lock before its read, so two testers claiming /
    # labelling / chatting at the same moment (even from separate processes) can
    # never clobber each other the way the old whole-blob rewrite could.

    def collab_assignments(self) -> dict:
        with closing(self.conn.cursor()) as cur:
            return {r[0]: r[1] for r in
                    cur.execute("SELECT ip, tester FROM collab_assign").fetchall()}

    def collab_set_assignment(self, ip: str, tester: str) -> dict:
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                if tester:
                    cur.execute("INSERT INTO collab_assign(ip,tester,updated) VALUES(?,?,?) "
                                "ON CONFLICT(ip) DO UPDATE SET tester=excluded.tester, "
                                "updated=excluded.updated", (ip, tester, str(int(time.time()))))
                else:
                    cur.execute("DELETE FROM collab_assign WHERE ip=?", (ip,))
        return self.collab_assignments()

    def collab_labels(self) -> dict:
        out: dict[str, list] = {}
        with closing(self.conn.cursor()) as cur:
            for ip, label in cur.execute(
                    "SELECT ip, label FROM collab_label ORDER BY ip, label").fetchall():
                out.setdefault(ip, []).append(label)
        return out

    def collab_set_label(self, ip: str, label: str, on: bool) -> dict:
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                if on:
                    cur.execute("INSERT OR IGNORE INTO collab_label(ip,label,updated) "
                                "VALUES(?,?,?)", (ip, label, str(int(time.time()))))
                else:
                    cur.execute("DELETE FROM collab_label WHERE ip=? AND label=?", (ip, label))
        return self.collab_labels()

    def collab_ports(self) -> dict:
        with closing(self.conn.cursor()) as cur:
            return {r[0]: r[1] for r in
                    cur.execute("SELECT endpoint, status FROM collab_port").fetchall()}

    def collab_set_port(self, endpoint: str, status: str) -> dict:
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                if status in ("todo", "wip", "done"):
                    cur.execute("INSERT INTO collab_port(endpoint,status,updated) VALUES(?,?,?) "
                                "ON CONFLICT(endpoint) DO UPDATE SET status=excluded.status, "
                                "updated=excluded.updated", (endpoint, status, str(int(time.time()))))
                else:
                    cur.execute("DELETE FROM collab_port WHERE endpoint=?", (endpoint,))
        return self.collab_ports()

    def collab_dismissed(self) -> dict:
        with closing(self.conn.cursor()) as cur:
            return {r[0]: r[1] for r in
                    cur.execute("SELECT fkey, tester FROM collab_dismiss").fetchall()}

    def collab_set_dismiss(self, fkey: str, tester: str, on: bool) -> dict:
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                if on:
                    cur.execute("INSERT INTO collab_dismiss(fkey,tester,updated) VALUES(?,?,?) "
                                "ON CONFLICT(fkey) DO UPDATE SET tester=excluded.tester, "
                                "updated=excluded.updated", (fkey, tester, str(int(time.time()))))
                else:
                    cur.execute("DELETE FROM collab_dismiss WHERE fkey=?", (fkey,))
        return self.collab_dismissed()

    def collab_add_activity(self, tester: str, kind: str, text: str) -> dict:
        entry = {"ts": time.time(), "tester": tester or "someone", "kind": kind, "text": text}
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cur.execute("INSERT INTO collab_activity(ts,tester,kind,text) VALUES(?,?,?,?)",
                            (entry["ts"], entry["tester"], kind, text))
                # Bound growth: keep only the most recent _ACTIVITY_CAP rows.
                cur.execute("DELETE FROM collab_activity WHERE id NOT IN "
                            "(SELECT id FROM collab_activity ORDER BY id DESC LIMIT ?)",
                            (_ACTIVITY_CAP,))
        return entry

    def collab_activity(self, limit: int = 100) -> list:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT ts, tester, kind, text FROM collab_activity "
                "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"ts": r[0], "tester": r[1], "kind": r[2], "text": r[3]} for r in rows]

    def collab_add_chat(self, msg: dict) -> dict:
        with self._write_txn():
            with closing(self.conn.cursor()) as cur:
                cur.execute("INSERT OR REPLACE INTO collab_chat(id,ts,tester,text,image,file) "
                            "VALUES(?,?,?,?,?,?)",
                            (msg["id"], msg["ts"], msg["tester"], msg.get("text", ""),
                             msg.get("image", ""),
                             json.dumps(msg["file"]) if msg.get("file") else ""))
                cur.execute("DELETE FROM collab_chat WHERE id NOT IN "
                            "(SELECT id FROM collab_chat ORDER BY ts DESC, id DESC LIMIT ?)",
                            (_CHAT_CAP,))
        return msg

    def collab_chat(self, limit: int = 200) -> list:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT id, ts, tester, text, image, file FROM collab_chat "
                "ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in reversed(rows):        # oldest -> newest for the transcript
            file = None
            if r[5]:
                try:
                    file = json.loads(r[5])
                except (ValueError, TypeError):
                    file = None
            out.append({"id": r[0], "ts": r[1], "tester": r[2], "text": r[3],
                        "image": r[4], "file": file})
        return out

    # --- scan issues (errors / incomplete scans, surfaced to the operator) ------

    def add_issue(self, ip: str, phase: str, level: str, message: str,
                  ts: str = "") -> None:
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO issues(ts, ip, phase, level, message) VALUES(?,?,?,?,?)",
                (ts, ip, phase, level, message),
            )
        self.conn.commit()

    def clear_issues(self, ip: str, phase: str) -> None:
        """Drop prior issues for one host+phase so re-running a phase replaces its
        issues instead of appending duplicates (which inflate the Overview count)."""
        with closing(self.conn.cursor()) as cur:
            cur.execute("DELETE FROM issues WHERE ip=? AND phase=?", (ip, phase))
        self.conn.commit()

    def get_issues(self) -> list[dict]:
        """All logged scan issues, newest first."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT ts, ip, phase, level, message FROM issues "
                "ORDER BY id DESC").fetchall()
        return [{"ts": r[0], "ip": r[1], "phase": r[2], "level": r[3],
                 "message": r[4]} for r in rows]

    def count_issues(self) -> dict[str, int]:
        """{'error': n, 'warning': m, 'total': t}."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT level, COUNT(*) FROM issues GROUP BY level").fetchall()
        out = {r[0]: r[1] for r in rows}
        out["total"] = sum(out.values())
        return out

    def set_meta(self, key: str, value: str) -> None:
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
        self.conn.commit()

    def get_meta(self, key: str) -> str | None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None
