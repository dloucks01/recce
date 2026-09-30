"""Offline CVE detail lookup — the runtime side of the optional CVE data pack.

`tools/build_cve_db.py` bakes a compact SQLite (one row per CVE: CVSS, severity,
CWE, year, and a zlib-compressed description) from NVD at build time. This module
reads it on demand, read-only, with nothing but the stdlib (sqlite3 + zlib) — no
external lookup, so it works on an airgapped target.

The full DB is large (~80-120 MB), so it is NOT bundled in the main recce wheel.
It ships as a SEPARATE, optional data pack in recce's "used when present,
graceful-degrade when absent" tradition (like the external tool sidecars): drop
the file in, and recce uses it; leave it out, and every entry point returns None
so recce runs identically. Resolution order (first that exists wins):

  1. $RECCE_CVE_DB                         — explicit path override
  2. an importable `recce_cve_data` package that exposes `DB_PATH`  — pip add-on
  3. recce/data/cve.sqlite                 — drop-in next to the package
  4. ~/.local/share/recce/cve.sqlite       — per-user data dir
"""
from __future__ import annotations

import functools
import os
import pathlib
import sqlite3
import zlib


@functools.lru_cache(maxsize=1)
def db_path() -> pathlib.Path | None:
    """The resolved CVE data-pack path (first location that exists), or None."""
    env = os.environ.get("RECCE_CVE_DB")
    if env and pathlib.Path(env).is_file():
        return pathlib.Path(env)
    try:                                     # optional pip add-on package
        import recce_cve_data                # type: ignore
        p = pathlib.Path(getattr(recce_cve_data, "DB_PATH", ""))
        if p.is_file():
            return p
    except Exception:
        pass
    for cand in (pathlib.Path(__file__).resolve().parent.parent / "data" / "cve.sqlite",
                 pathlib.Path.home() / ".local" / "share" / "recce" / "cve.sqlite"):
        if cand.is_file():
            return cand
    return None


def available() -> bool:
    """True when the optional CVE data pack is installed/discoverable."""
    return db_path() is not None


def _connect() -> sqlite3.Connection | None:
    # A fresh read-only connection per call: sqlite opens are cheap, lookups are
    # rare (a tester clicking a CVE), and per-call connections are trivially
    # thread-safe under the WebUI's handful of concurrent operators.
    p = db_path()
    if p is None:
        return None
    try:
        return sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    except sqlite3.Error:
        return None


def lookup(cve: str) -> dict | None:
    """Detail for one CVE id, or None when absent (no DB, or CVE not in it).

    Returns ``{cvss, severity, cwe: [..], year, desc}``. `desc` is the
    decompressed English description ("" when NVD had none)."""
    cid = (cve or "").strip().upper()
    if not cid.startswith("CVE-"):
        return None
    conn = _connect()
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT cvss, severity, cwe, year, descr FROM cve WHERE id = ?",
            (cid,)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if not row:
        return None
    cvss, severity, cwe, year, descr = row
    desc = ""
    if descr:
        try:
            desc = zlib.decompress(descr).decode("utf-8", "replace")
        except zlib.error:
            desc = ""
    return {
        "cvss": cvss,
        "severity": severity or "",
        "cwe": [c for c in (cwe or "").split(",") if c],
        "year": year or 0,
        "desc": desc,
    }
