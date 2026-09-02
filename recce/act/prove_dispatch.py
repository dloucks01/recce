"""Per-finding dispatch to the T2 verification prover.

Both `recce prove` (CLI, in `recce/cli/_act.py`) and the WebUI's
`POST /api/prove/{finding_key}` endpoint run the same recipe for a given
finding — this module is the single dispatch point they share.

The CLI walks every host + vuln via `proofs.verify_hosts(hosts)`; the WebUI
proves ONE finding at a time (the tester clicked a "Prove" button on that
row). This helper resolves a `finding_key` back to the underlying vuln,
runs its recipe from `recce.vuln.proofs`, and returns a verdict record with
the same shape `proofs.verify_host` emits — so any downstream renderer can
consume both.

Returns ``None`` when the finding_key doesn't match any loaded vuln, and
returns a record with ``verdict == INCONCLUSIVE`` when the vuln matches but
carries no proof recipe.
"""
from __future__ import annotations

from typing import Iterable

from ..core.tracking import vuln_row_key
from ..vuln import proofs


def has_prover(vuln) -> bool:
    """True when this vuln has a proof recipe registered — i.e. clicking
    "Prove" on it would produce a real verdict rather than a fallback
    INCONCLUSIVE."""
    return proofs.recipe_for(vuln) is not None


def provable_keys(hosts: Iterable) -> list[str]:
    """Every `vuln_row_key` in `hosts` whose vuln has a proof recipe. The
    WebUI's exploit-surface tab calls this so the "Prove" button renders
    only for the findings that actually have a prover."""
    keys: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        for v in h.vulns:
            if not has_prover(v):
                continue
            k = vuln_row_key(v)
            if k in seen:
                continue
            seen.add(k)
            keys.append(k)
    return keys


def _verdict_for_vuln(host, v) -> dict:
    """Run the matched recipe against a single vuln, mirroring
    `proofs.verify_host`'s per-vuln branch (recipe lookup, port lookup,
    the source='version-db' over-claim guard, verdict shape)."""
    r = proofs.recipe_for(v)
    if r is None:
        # Caller decides whether to expose this; keeping the shape stable
        # lets a "not provable" click still render something legible.
        return {
            "ip": host.ip, "port": v.port, "vuln": "",
            "finding": v.title or v.script_id or "finding",
            "verdict": proofs.INCONCLUSIVE,
            "evidence": ["No proof recipe matches this finding — "
                         "recce doesn't know how to prove this one non-"
                         "intrusively yet."],
            "preconditions": [], "finish": "", "fp": "",
            "key": f"verify:{host.ip}:{v.port or 0}:none",
        }
    port = proofs._port_of(host, v)
    verdict, evidence = r["fn"](host, port, v)
    # Same guard `verify_host` applies: a "we authenticated / read with no
    # credential" phrasing coming out of a version-db banner match gets
    # capped at LIKELY (recce didn't actually probe the live service).
    if verdict == proofs.CONFIRMED and v.source == "version-db" \
            and proofs._LIVE_ACCESS_RE.search(" ".join(evidence)):
        verdict = proofs.LIKELY
        action = list(evidence[1:]) if len(evidence) > 1 else []
        evidence = [
            "Version/advisory match only - recce did NOT authenticate or "
            "read this service live; treat it as a lead to verify, not a "
            "confirmed observation.", *action]
    return {
        "ip": host.ip, "port": v.port, "vuln": r["name"],
        "finding": v.title or v.script_id or r["name"],
        "verdict": verdict, "evidence": evidence,
        "preconditions": r["pre"], "finish": r["finish"], "fp": r["fp"],
        "key": f"verify:{host.ip}:{v.port or 0}:{r['id']}",
    }


def prove_finding_key(hosts: Iterable, finding_key: str) -> dict | None:
    """Locate the vuln whose `vuln_row_key` matches `finding_key` and
    return its verdict record. `None` when no vuln matches."""
    if not finding_key:
        return None
    for h in hosts:
        for v in h.vulns:
            if vuln_row_key(v) != finding_key:
                continue
            return _verdict_for_vuln(h, v)
    return None
