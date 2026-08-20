#!/usr/bin/env python3
"""Seed a demo engagement AND its live web-workbench collaboration layer.

`tools/mock_engagement.py` fills the datastore (hosts, findings, AD accounts, creds).
This wraps it and then seeds the collab meta the `recce serve` UI shows — host
assignments across a few testers, triage labels, per-port status, review ticks, an
activity feed and a team chat — so the workbench opens looking like a live team
engagement, not an empty shell.

    python3 tools/seed_workbench.py demo_engagement --hosts 40
    recce serve -o demo_engagement            # then open the printed URL

Deterministic for a given (hosts, seed).
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recce.store import Store                      # noqa: E402
from recce.webui import collab                     # noqa: E402
from tools.mock_engagement import build            # noqa: E402

# The named archetypes mock_engagement always creates (see its build()).
DC, SQL01, FS01 = "10.20.10.10", "10.20.10.11", "10.20.10.23"
WEB01, WEB02 = "10.20.20.15", "10.20.20.16"
REDIS, MONGO, MYSQL, PG = "10.20.20.30", "10.20.20.31", "10.20.20.32", "10.20.20.33"
NAS, SW = "10.20.20.40", "10.20.30.1"

TESTERS = ["alice", "bob", "carol", "dave"]

# (ip, tester) — who owns what. Leaves the workstation fill unassigned (the "unclaimed" pool).
ASSIGN = [
    (DC, "alice"), (FS01, "alice"), (SQL01, "bob"), (MYSQL, "bob"), (PG, "bob"),
    (WEB01, "carol"), (WEB02, "carol"), (REDIS, "dave"), (MONGO, "dave"), (NAS, "dave"),
]
# (ip, label, on) — triage flags the UI renders as chips.
LABELS = [
    (DC, "interesting"), (FS01, "interesting"), (WEB01, "interesting"), (NAS, "interesting"),
    (WEB02, "needs-review"), (SQL01, "needs-review"), (SW, "out-of-scope"),
]
# (ip, port, status) — per-port tri-state (todo / wip / done).
PORTS = [
    (DC, 88, "done"), (DC, 389, "done"), (DC, 445, "wip"),
    (WEB01, 8080, "done"), (WEB01, 443, "wip"), (WEB02, 443, "wip"),
    (FS01, 445, "todo"), (REDIS, 6379, "done"), (MONGO, 27017, "done"), (MYSQL, 3306, "wip"),
]
REVIEWED = [DC, WEB01, REDIS, MONGO]                # hosts fully signed off
# activity feed — (tester, kind, text); newest last
ACTIVITY = [
    ("alice", "assign", "claimed dc01 (10.20.10.10)"),
    ("alice", "note", "dc01: Zerologon-style netlogon accepted — escalating"),
    ("carol", "assign", "claimed web01 (10.20.20.15)"),
    ("carol", "finding", "web01: confirmed Log4Shell via User-Agent JNDI callback"),
    ("bob", "assign", "claimed sql01 + the DB boxes"),
    ("dave", "port", "redis01: 6379 unauth CONFIG GET dir → RCE, marked done"),
    ("carol", "review", "signed off web01"),
    ("alice", "cred", "added kerberoast cred svc_sql:Summer2023!"),
]
# team chat — (tester, text); oldest first
CHAT = [
    ("alice", "morning all — starting on the DC segment (10.20.10.x)"),
    ("carol", "web01 is a goldmine: exposed .git/.env + Log4Shell. grabbing loot now"),
    ("bob", "I'll take the DB row — mysql root has no password, pulling hashes"),
    ("dave", "redis01 + mongo01 both unauth. redis → RCE. flagged interesting"),
    ("alice", "svc_sql TGS cracked (Summer2023!). trying it against sql01"),
    ("carol", "reminder: core-sw01 is out of scope per the ROE, leave it"),
    ("bob", "nice. pg01 is trust-auth too — postgres with no creds"),
    ("alice", "good progress. let's regroup at 2pm and map the path to DA"),
]


def seed_collab(eng_dir: str) -> dict:
    st = Store(str(Path(eng_dir) / "results.sqlite"))
    try:
        for ip, who in ASSIGN:
            collab.set_assignment(st, ip, who)
        for ip, label in LABELS:
            collab.set_label(st, ip, label, True)
        for ip, port, status in PORTS:
            collab.set_port_status(st, ip, port, status)
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        for ip in REVIEWED:
            st.set_reviewed(f"host:{ip}", True, notes="", when=now)
        for tester, kind, text in ACTIVITY:
            collab.add_activity(st, tester, kind, text)
        for tester, text in CHAT:
            collab.add_chat(st, tester, text)
        return {"assignments": len(ASSIGN), "labels": len(LABELS), "ports": len(PORTS),
                "reviewed": len(REVIEWED), "activity": len(ACTIVITY), "chat": len(CHAT),
                "testers": len(TESTERS)}
    finally:
        st.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed a demo engagement + its live workbench collab layer")
    ap.add_argument("eng_dir", nargs="?", default="demo_engagement",
                    help="engagement directory to create/populate (default: demo_engagement)")
    ap.add_argument("--hosts", type=int, default=40)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    core = build(args.eng_dir, hosts=args.hosts, seed=args.seed)
    collab_stats = seed_collab(args.eng_dir)
    print(f"[+] datastore: {core['hosts']} hosts, {core['findings']} findings, "
          f"{core['credentials']} creds across {core['subnets']} subnets ({core['domain']})")
    print(f"[+] workbench: {collab_stats['assignments']} host assignments across "
          f"{collab_stats['testers']} testers, {collab_stats['labels']} labels, "
          f"{collab_stats['ports']} port statuses, {collab_stats['reviewed']} reviewed, "
          f"{collab_stats['activity']} activity entries, {collab_stats['chat']} chat messages")
    print(f"\n    recce serve -o {args.eng_dir}      # open the printed URL in a browser")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
