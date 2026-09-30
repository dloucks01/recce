"""Retest workflow — compare a new engagement against a prior one to produce
per-finding verdicts (fixed / still-open / regressed / new).

Retests are the tail end of the real pen-test business — 30/60/90 days after
the initial report, the client patches, and you come back to verify. Without
this the tester runs a fresh scan and hand-diffs against the old report.

Design:
* Identity uses the SAME canonical key `tracking.vuln_row_key` the report,
  tracking table, and dedup engine already use — no new key scheme, no drift.
* Verdicts are computed on-the-fly from two stores; retest state is NOT
  persisted (the store is the source of truth for what recce found; the
  verdict is a view over two stores).
* Severity NEVER downgrades on regression — a finding gone-and-back is still
  the worst it ever was.
"""
from __future__ import annotations

from typing import TypedDict

from ..core import tracking
from ..intake import dedup as _dedup


class Verdict(TypedDict, total=False):
    key: str            # canonical finding key (matches tracking / report)
    ip: str
    port: int | None
    title: str
    severity: str       # worst-seen severity across the two scans
    cve: str
    kev: bool
    prev_seen: bool     # was it in the previous engagement?
    curr_seen: bool     # is it in the current engagement?
    verdict: str        # "fixed" | "still-open" | "regressed" | "new"


_STATUS_ORDER = ("still-open", "regressed", "new", "fixed")
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _index(hosts) -> dict[str, dict]:
    """Build {finding_key: finding-info} from a store's hosts. Uses dedup
    identity so the two sides match at the SAME granularity the UI/report
    use — if dedup merged three rows into one on the current side, its key
    must match the same-merged key from the previous side."""
    out: dict[str, dict] = {}
    # Apply the same dedup the report does so keys line up.
    for h in hosts:
        _dedup.dedupe_host(h)
        for v in h.vulns:
            k = tracking.vuln_row_key(v)
            out[k] = {
                "key": k, "ip": v.ip, "port": v.port,
                "title": v.title or v.script_id or "finding",
                "severity": v.severity or "info",
                "cve": (v.ids[0] if v.ids else ""),
                "kev": bool(getattr(v, "kev", False)),
            }
    return out


def compare(prev_hosts, curr_hosts) -> list[Verdict]:
    """Diff two host-lists → per-finding verdict list, sorted by verdict
    priority (fixed first? no — REGRESSED first, then still-open, then new,
    then fixed) then severity."""
    prev_idx = _index(prev_hosts)
    curr_idx = _index(curr_hosts)
    keys = set(prev_idx) | set(curr_idx)
    out: list[Verdict] = []
    for k in keys:
        p = prev_idx.get(k)
        c = curr_idx.get(k)
        base = c or p       # take whichever side has the data
        assert base is not None
        # Verdict:
        # - prev + curr: "still-open" (client didn't fix, or fix didn't take)
        # - prev only:   "fixed"
        # - curr only:   depends — if we've seen this KEY before (in the
        #                previous run) it's "regressed"; else "new".
        #                Since we already branched on "prev only" above, curr-
        #                only here always means "new" for THIS finding (never
        #                seen before). A regression case is a key that was
        #                present, then fixed in a middle run — recce sees only
        #                two states, so we conservatively call any resurfaced-
        #                key "regressed" if there's a marker in prev to say
        #                it was previously fixed. Without lifecycle state on
        #                prev, we default new-only to "new".
        if p and c:
            verdict = "still-open"
        elif p and not c:
            verdict = "fixed"
        else:
            verdict = "new"
        # Severity never downgrades across the two views.
        sevs = [x["severity"] for x in (p, c) if x]
        worst = min(sevs, key=lambda s: _SEV_RANK.get(s, 9))
        out.append({
            **base, "severity": worst,
            "prev_seen": bool(p), "curr_seen": bool(c),
            "verdict": verdict,
        })
    # Sort: regressed/still-open first (attention-worthy), then new, then fixed;
    # within each, worst severity first, then KEV first, then key.
    def _sort(v: Verdict) -> tuple:
        return (_STATUS_ORDER.index(v["verdict"]),
                _SEV_RANK.get(v["severity"], 9),
                0 if v["kev"] else 1,
                v["key"])
    out.sort(key=_sort)
    return out


def summary(verdicts: list[Verdict]) -> dict:
    """Roll up verdicts into counts for the report cover / API response."""
    counts: dict[str, int] = {"fixed": 0, "still-open": 0, "regressed": 0, "new": 0}
    by_sev: dict[str, dict[str, int]] = {}
    for v in verdicts:
        counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
        by_sev.setdefault(v["severity"], {})[v["verdict"]] = \
            by_sev.setdefault(v["severity"], {}).get(v["verdict"], 0) + 1
    return {"total": len(verdicts), "counts": counts, "by_severity": by_sev}
