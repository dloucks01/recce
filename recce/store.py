"""SQLite-backed datastore.

Hosts are stored as JSON blobs keyed by IP so a re-scan simply upserts. This
makes multi-subnet engagements resumable: interrupt at any point, and the next
run merges new findings into the existing store instead of starting over.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from .models import Credential, Domain, Host


class StoreError(RuntimeError):
    """The datastore file is corrupt/unreadable (e.g. a partial transfer)."""


# Ranked weakest->strongest so a merge never downgrades a host's proof-of-life:
# a real reply outranks the -Pn assume-up ("user-set") which outranks nothing.
_UP_REASON_RANK = {"": 0, "unknown": 0, "no-response": 0, "unknown-response": 0,
                   "user-set": 1}


def _best_up_reason(old: str, new: str) -> str:
    """Return whichever reason is the stronger proof the host is up. Any concrete
    reply (echo-reply, syn-ack, arp-response, report-listed, ...) ranks above the
    blanket -Pn 'user-set' and above a blank, and never gets overwritten by them."""
    def rank(r: str) -> int:
        return _UP_REASON_RANK.get(r, 2)   # anything not listed is a real reply
    return new if rank(new) > rank(old) else old

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
    key      TEXT PRIMARY KEY,
    reviewed INTEGER DEFAULT 0,
    notes    TEXT DEFAULT '',
    status   TEXT DEFAULT '',
    updated  TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
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
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        try:
            self.conn = sqlite3.connect(path)
            # Ride out a transient lock (operator opened the DB, or a second recce)
            # instead of aborting a scan; WAL lets readers not block the writer.
            self.conn.execute("PRAGMA busy_timeout=15000")
            try:
                self.conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.Error:
                pass                       # non-fatal (e.g. read-only fs); keep going
            self.conn.executescript(_SCHEMA)
            self._migrate()
            self.conn.commit()
        except sqlite3.Error as e:
            # A corrupt / partially-transferred results.sqlite must fail with a
            # clear, actionable message - not a raw sqlite traceback on the very
            # first command against a carried-over engagement dir.
            raise StoreError(
                f"datastore at {path} is corrupt or unreadable ({e}). Delete it "
                "or point -o at a fresh directory, then re-run.") from e

    def _migrate(self) -> None:
        """Add columns introduced after a datastore was first created."""
        with closing(self.conn.cursor()) as cur:
            cols = {r[1] for r in cur.execute("PRAGMA table_info(tracking)").fetchall()}
            if "status" not in cols:
                cur.execute("ALTER TABLE tracking ADD COLUMN status TEXT DEFAULT ''")

    def close(self) -> None:
        self.conn.close()

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
                op.state = np.state or op.state
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
        which the union-merge would otherwise re-introduce."""
        existing = self.get_host(host.ip)
        if existing and merge:
            host = self._merge(existing, host)
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO hosts(ip, subnet, data, updated) VALUES(?,?,?,?) "
                "ON CONFLICT(ip) DO UPDATE SET subnet=excluded.subnet, "
                "data=excluded.data, updated=excluded.updated",
                (host.ip, host.subnet, json.dumps(host.to_json()), host.last_scanned),
            )
        self.conn.commit()

    def get_host(self, ip: str) -> Host | None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT data FROM hosts WHERE ip=?", (ip,)).fetchone()
        return Host.from_json(json.loads(row[0])) if row else None

    def all_hosts(self) -> list[Host]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT data FROM hosts ORDER BY ip").fetchall()
        return [Host.from_json(json.loads(r[0])) for r in rows]

    def scanned_ips(self) -> set[str]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT ip FROM hosts").fetchall()
        return {r[0] for r in rows}

    # --- domains ----------------------------------------------------------------

    def upsert_domain(self, domain: Domain) -> None:
        from .ad import merge_domain
        existing = self.get_domain(domain.name)
        if existing:
            domain = merge_domain(existing, domain)
        with closing(self.conn.cursor()) as cur:
            cur.execute(
                "INSERT INTO domains(name, data) VALUES(?,?) "
                "ON CONFLICT(name) DO UPDATE SET data=excluded.data",
                (domain.name.lower(), json.dumps(domain.to_json())),
            )
        self.conn.commit()

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

    def all_credentials(self) -> list[Credential]:
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute("SELECT data FROM credentials").fetchall()
        return [Credential.from_json(json.loads(r[0])) for r in rows]

    # --- coverage tracking ------------------------------------------------------

    def set_reviewed(self, key: str, reviewed: bool, notes: str | None = None,
                     when: str = "") -> None:
        with closing(self.conn.cursor()) as cur:
            row = cur.execute("SELECT notes FROM tracking WHERE key=?", (key,)).fetchone()
            keep_notes = row[0] if (row and notes is None) else (notes or "")
            cur.execute(
                "INSERT INTO tracking(key, reviewed, notes, updated) VALUES(?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET reviewed=excluded.reviewed, "
                "notes=excluded.notes, updated=excluded.updated",
                (key, 1 if reviewed else 0, keep_notes, when),
            )
        self.conn.commit()

    def bulk_set_tracking(self, items: dict[str, tuple], when: str = "") -> int:
        """items: {key: (reviewed_bool, notes)}. Returns number of rows written."""
        n = 0
        with closing(self.conn.cursor()) as cur:
            for key, (reviewed, notes) in items.items():
                cur.execute(
                    "INSERT INTO tracking(key, reviewed, notes, updated) VALUES(?,?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET reviewed=excluded.reviewed, "
                    "notes=excluded.notes, updated=excluded.updated",
                    (key, 1 if reviewed else 0, notes or "", when),
                )
                n += 1
        self.conn.commit()
        return n

    # --- scope (every subnet in the engagement, so none is missed) --------------

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
        flag so coverage still works (reviewed True == the port is done)."""
        n = 0
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
        self.conn.commit()
        return n

    def get_statuses(self) -> dict[str, str]:
        """Return {key: status_str} for rows that carry a non-empty status."""
        with closing(self.conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT key, status FROM tracking WHERE status != ''").fetchall()
        return {r[0]: r[1] for r in rows}

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
