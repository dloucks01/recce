#!/usr/bin/env python3
"""Refresh recce's offline prioritization snapshots from the upstream feeds.

recce ships airgapped, so CISA KEV membership and EPSS scores are baked into
recce/kev.py and recce/epss.py as data. This build-time tool refreshes them:

  * KEV  <- CISA Known Exploited Vulnerabilities catalogue (JSON feed)
  * EPSS <- FIRST.org / EPSS daily scores (gzipped CSV feed)

By default it scopes both to the CVEs recce actually references (its vulndb /
verify_rules / exploit tables) so the snapshots stay relevant without bloating to
the full ~1,600-entry KEV / ~200k-row EPSS sets. Pass --full-kev to bake the entire
KEV catalogue instead.

It only rewrites the data between the AUTOGEN markers in each module, leaving the
docstring and functions untouched. Needs internet; stdlib only.

    python3 tools/refresh_intel.py            # scope to recce's CVEs
    python3 tools/refresh_intel.py --full-kev # bake the whole KEV catalogue
"""
from __future__ import annotations

import argparse
import gzip
import io
import pathlib
import re
import sys
import urllib.request

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_RECCE = _ROOT / "recce"
_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_FEED = "https://epss.cyentia.com/epss_scores-current.csv.gz"  # 302 -> dated file
_CVE_RE = re.compile(r"CVE-\d{4}-\d+")
_UA = {"User-Agent": "recce-refresh-intel/1.0"}


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=_UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:   # follows redirects
        return r.read()


def recce_cve_universe() -> set[str]:
    """Every CVE recce references across its modules (minus the two snapshot files,
    so a stale snapshot never keeps itself alive)."""
    universe: set[str] = set()
    for py in sorted(_RECCE.glob("*.py")):
        if py.name in ("kev.py", "epss.py"):
            continue
        universe |= set(_CVE_RE.findall(py.read_text(errors="replace")))
    return universe


def fetch_kev() -> set[str]:
    import json
    data = json.loads(_get(_KEV_FEED))
    return {v["cveID"].upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}


def fetch_epss() -> dict[str, float]:
    raw = gzip.GzipFile(fileobj=io.BytesIO(_get(_EPSS_FEED))).read().decode("utf-8", "replace")
    out: dict[str, float] = {}
    for line in raw.splitlines():
        if not line or line.startswith("#") or line.startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) >= 2 and parts[0].upper().startswith("CVE-"):
            try:
                out[parts[0].upper()] = round(float(parts[1]), 3)
            except ValueError:
                pass
    return out


def _replace_autogen(path: pathlib.Path, body: str) -> None:
    """Replace the text between the AUTOGEN markers in `path` with `body`."""
    text = path.read_text()
    pat = re.compile(r"(# --- AUTOGEN START.*?\n).*?(\n# --- AUTOGEN END ---)", re.S)
    if not pat.search(text):
        sys.exit(f"AUTOGEN markers not found in {path} - add them once, then re-run.")
    path.write_text(pat.sub(lambda m: m.group(1) + body + m.group(2), text))


def _fmt_frozenset(cves: list[str]) -> str:
    lines = ["KEV_CVES: frozenset[str] = frozenset({"]
    row: list[str] = []
    for c in cves:
        row.append(f'"{c}",')
        if len(row) == 4:
            lines.append("    " + " ".join(row))
            row = []
    if row:
        lines.append("    " + " ".join(row))
    lines.append("})")
    return "\n".join(lines)


def _fmt_dict(scores: dict[str, float]) -> str:
    lines = ["EPSS_SCORES: dict[str, float] = {"]
    for c in sorted(scores):
        lines.append(f'    "{c}": {scores[c]},')
    lines.append("}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--full-kev", action="store_true",
                    help="bake the entire KEV catalogue, not just recce's CVEs")
    args = ap.parse_args()

    universe = recce_cve_universe()
    print(f"[*] recce references {len(universe)} distinct CVE(s)")

    print("[*] fetching CISA KEV ...")
    kev = fetch_kev()
    kev_out = sorted(kev if args.full_kev else (kev & universe))
    print(f"    KEV catalogue: {len(kev)} total; baking {len(kev_out)}")
    _replace_autogen(_RECCE / "kev.py", _fmt_frozenset(kev_out))

    print("[*] fetching EPSS ...")
    epss = fetch_epss()
    epss_out = {c: epss[c] for c in sorted(universe & set(epss))}
    print(f"    EPSS feed: {len(epss)} scored; baking {len(epss_out)} for recce's CVEs")
    _replace_autogen(_RECCE / "epss.py", _fmt_dict(epss_out))

    print("[+] refreshed recce/kev.py and recce/epss.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
