"""`/api/suggest/digest` — the JSON twin of `recce suggest`.

The CLI command in `recce/cli/_suggest.py` prints three sections:

  1. Engagement metrics (host count, credential count, whether the loot
     dir has content).
  2. Cross-service rule outputs — every fired rule from
     `recce.webui.routes.scan._SUGGESTION_RULES`, confidence-sorted.
  3. Proven-exploitable findings — every `Vuln` carrying an `exploit_note`
     or a `depth_tier`, ranked by tier → severity → KEV → EPSS.

This route returns exactly the same three sections as JSON so the
WebUI's Suggest tab can render the same digest the tester sees on the
terminal, without divergence in ordering or field shape.

Read-only: no probes, no state change.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Query


# Section keys returned by /api/suggest/digest. Kept as a module-level
# constant so the parity test in tests/test_suggest_digest.py can assert
# the exposed keys match what `_suggest.py` prints.
DIGEST_SECTION_KEYS = ("metrics", "rules", "exploit_findings")


# Tier and severity ranks — copied from _suggest.py so the JSON ordering
# matches the terminal ordering byte-for-byte.
def _tier_rank(t: str) -> int:
    try:
        from ...core import depth
        return depth.rank(t)
    except Exception:  # noqa: BLE001
        return {"t0": 0, "t1": 1, "t2": 2, "t3": 3, "t4": 4}.get(t, -1)


def _tier_label(t: str) -> str:
    try:
        from ...core import depth
        return depth.label(t)
    except Exception:  # noqa: BLE001
        return {"t0": "enum", "t1": "verify", "t2": "proof",
                "t3": "initial-access", "t4": "chain"}.get(t, t or "-")


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONF_RANK = {"high": 3, "medium": 2, "low": 1}


def _run_rules(hosts, creds, loot_dir) -> list[dict]:
    """Run every `_SUGGESTION_RULES` entry, dedup by rule `key`,
    confidence-sort. Import- and rule-tolerant: a broken rule is
    skipped, never allowed to 500 the digest."""
    try:
        from .scan import _SUGGESTION_RULES
    except Exception:  # noqa: BLE001
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for rule in _SUGGESTION_RULES:
        try:
            for sug in rule(hosts, creds, loot_dir) or []:
                k = sug.get("key") or ""
                if not k or k in seen:
                    continue
                seen.add(k)
                out.append(sug)
        except Exception:  # noqa: BLE001
            continue
    out.sort(key=lambda s: -_CONF_RANK.get(s.get("confidence", ""), 0))
    return out


def _exploit_findings(hosts) -> list[dict]:
    """Every Vuln with an exploit_note OR a depth_tier stamp, ranked
    (tier desc, severity desc, kev, epss). Same shape and ordering
    the CLI prints."""
    rows: list[dict] = []
    for h in hosts:
        for v in (getattr(h, "vulns", None) or []):
            note = getattr(v, "exploit_note", "") or ""
            tier = getattr(v, "depth_tier", "") or ""
            if not note and not tier:
                continue
            rows.append({
                "ip": v.ip,
                "port": v.port,
                "protocol": v.protocol,
                "title": v.title,
                "severity": v.severity,
                "tier": tier,
                "tier_label": _tier_label(tier),
                "kev": bool(getattr(v, "kev", False)),
                "epss": float(getattr(v, "epss", 0.0) or 0.0),
                "exploit_note": note,
                "cves": list(getattr(v, "ids", []) or []),
            })
    rows.sort(key=lambda r: (
        -_tier_rank(r["tier"]),
        -_SEV_RANK.get(r["severity"], 0),
        0 if r["kev"] else 1,
        -r["epss"],
    ))
    return rows


def register_suggest_digest_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path

    @app.get("/api/suggest/digest")
    def suggest_digest(top: int = Query(default=10, ge=1, le=200)):
        """Return the same "recce suggests…" digest the CLI prints.

        Sections (see `DIGEST_SECTION_KEYS`):
          * ``metrics`` — host_count / cred_count / loot_present / eng_dir.
          * ``rules`` — cross-service rule outputs, top `top`, confidence-sorted.
          * ``exploit_findings`` — proven-exploitable Vulns, top `top`, tier-
            → sev → KEV → EPSS-ranked.

        Never 500s on a per-rule / per-finding error: a broken rule
        is skipped so the rest of the digest still renders.
        """
        from ...core.store import Store
        with Store(db_path) as st:
            hosts = list(st.all_hosts() or [])
            try:
                creds = list(st.all_credentials() or [])
            except Exception:  # noqa: BLE001
                creds = []

        loot_dir = os.path.join(eng_dir, "loot")
        loot_present = os.path.isdir(loot_dir) and any(
            True for _ in os.scandir(loot_dir))

        rules_all = _run_rules(hosts, creds, loot_dir)
        findings_all = _exploit_findings(hosts)

        return {
            "metrics": {
                "eng_dir": eng_dir,
                "host_count": len(hosts),
                "cred_count": len(creds),
                "loot_present": bool(loot_present),
                "rules_total": len(rules_all),
                "exploit_findings_total": len(findings_all),
            },
            "rules": rules_all[:top],
            "exploit_findings": findings_all[:top],
            "top": top,
        }
