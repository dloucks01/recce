#!/usr/bin/env python3
"""Build recce's OPTIONAL offline CVE data pack from the NVD API 2.0.

recce ships airgapped, so per-CVE detail (CVSS, severity, CWE, description) comes
from a compact on-disk SQLite the WebUI queries on demand — no external lookup at
runtime (see recce/vuln/cvedb.py). The full pull is large (NVD holds ~399k CVEs →
~80-120 MB), so it is NOT bundled in the main recce wheel: it's a separate,
optional data pack in recce's "used when present, graceful-degrade when absent"
tradition. This build-time tool generates it; internet needed on the BUILD
machine only; stdlib only.

Storage is kept as small as this coverage allows: one row per CVE, description
(the bulk) stored zlib-compressed.

    NVD_API_KEY=... python3 tools/build_cve_db.py # full pull, ~2 min with a key
    python3 tools/build_cve_db.py                  # no key: rate-limited, ~20 min
    python3 tools/build_cve_db.py --max-pages 2    # quick smoke build for testing
    python3 tools/build_cve_db.py --since 2015     # trim size: only recent CVEs

Get a free NVD API key at https://nvd.nist.gov/developers/request-an-api-key.
By default it writes recce/data/cve.sqlite (a drop-in location recce discovers).
Place it anywhere and point recce at it with $RECCE_CVE_DB, or drop it in
~/.local/share/recce/cve.sqlite. The file is gitignored — it never bloats the
repo, and it is distributed as its own artifact, not inside the main wheel.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import zlib

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_OUT = _ROOT / "recce" / "data" / "cve.sqlite"
_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE = 2000                       # NVD's max resultsPerPage
_UA = {"User-Agent": "recce-build-cve-db/1.0"}


def _get(url: str, timeout: int = 60) -> dict:
    req = urllib.request.Request(url, headers=_UA)
    key = os.environ.get("NVD_API_KEY")
    if key:
        req.add_header("apiKey", key)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _best_cvss(metrics: dict) -> tuple[float | None, str]:
    """Highest-priority CVSS base score + severity: v3.1 > v3.0 > v2."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key, []) or []:
            data = m.get("cvssData", {}) or {}
            score = data.get("baseScore")
            if score is not None:
                return float(score), str(data.get("baseSeverity") or "").lower()
    for m in metrics.get("cvssMetricV2", []) or []:
        data = m.get("cvssData", {}) or {}
        score = data.get("baseScore")
        if score is not None:
            sev = str(m.get("baseSeverity") or "").lower()
            return float(score), sev
    return None, ""


def _cwes(weaknesses: list) -> str:
    out: list[str] = []
    for w in weaknesses or []:
        for d in w.get("description", []) or []:
            v = str(d.get("value") or "")
            if v.startswith("CWE-") and v not in out:
                out.append(v)
    return ",".join(out)


def _english(descriptions: list) -> str:
    for d in descriptions or []:
        if d.get("lang") == "en":
            return str(d.get("value") or "")
    return ""


def _row(cve: dict) -> tuple | None:
    cid = cve.get("id")
    if not cid:
        return None
    score, sev = _best_cvss(cve.get("metrics", {}) or {})
    desc = _english(cve.get("descriptions", []))
    blob = zlib.compress(desc.encode("utf-8"), 9) if desc else None
    year = 0
    pub = str(cve.get("published") or "")
    if len(pub) >= 4 and pub[:4].isdigit():
        year = int(pub[:4])
    return (cid.upper(), score, sev, _cwes(cve.get("weaknesses", [])), year, blob)


def _open_db(path: pathlib.Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute(
        "CREATE TABLE cve (id TEXT PRIMARY KEY, cvss REAL, severity TEXT, "
        "cwe TEXT, year INTEGER, descr BLOB)")
    conn.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT)")
    return conn


def build(out: pathlib.Path, *, max_pages: int | None, since: int | None) -> int:
    conn = _open_db(out)
    delay = 0.6 if os.environ.get("NVD_API_KEY") else 6.5   # respect NVD rate limits
    start, total, pages, written = 0, None, 0, 0
    while True:
        url = f"{_API}?resultsPerPage={_PAGE}&startIndex={start}"
        for attempt in range(5):
            try:
                data = _get(url)
                break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
                wait = delay * (attempt + 2)
                print(f"  retry {attempt+1}/5 after error ({e}); sleeping {wait:.0f}s", file=sys.stderr)
                time.sleep(wait)
        else:
            print("[x] giving up after repeated errors", file=sys.stderr)
            conn.close()
            return 1
        total = data.get("totalResults", total)
        vulns = data.get("vulnerabilities", []) or []
        if not vulns:
            break
        batch = []
        for item in vulns:
            cve = item.get("cve", {}) or {}
            row = _row(cve)
            if row is None:
                continue
            if since and row[4] and row[4] < since:
                continue
            batch.append(row)
        conn.executemany(
            "INSERT OR REPLACE INTO cve (id,cvss,severity,cwe,year,descr) VALUES (?,?,?,?,?,?)",
            batch)
        conn.commit()
        written += len(batch)
        pages += 1
        start += _PAGE
        print(f"  page {pages}: +{len(batch)} rows ({written} total / {total} NVD)", file=sys.stderr)
        if max_pages and pages >= max_pages:
            break
        if total is not None and start >= total:
            break
        time.sleep(delay)
    conn.executemany("INSERT OR REPLACE INTO meta (k,v) VALUES (?,?)", [
        ("source", "NVD API 2.0"),
        ("generated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
        ("count", str(written)),
    ])
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    size_mb = out.stat().st_size / 1e6
    print(f"[+] wrote {written} CVEs to {out} ({size_mb:.1f} MB)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Build recce's offline CVE SQLite from NVD.")
    ap.add_argument("-o", "--out", type=pathlib.Path, default=_OUT, help=f"output db (default {_OUT})")
    ap.add_argument("--max-pages", type=int, default=None, help="stop after N pages (smoke test)")
    ap.add_argument("--since", type=int, default=None, help="only CVEs published in this year or later")
    args = ap.parse_args()
    if not os.environ.get("NVD_API_KEY"):
        print("[!] No NVD_API_KEY set — the full pull is rate-limited to ~5 req/30s "
              "and will take ~15+ min. A free key makes it ~10x faster.", file=sys.stderr)
    return build(args.out, max_pages=args.max_pages, since=args.since)


if __name__ == "__main__":
    raise SystemExit(main())
