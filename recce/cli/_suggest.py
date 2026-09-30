"""`recce suggest` — read-only "here's what to run next" advisory.

Pulls entirely from the engagement store and the shared surfaces recce
has already learned about. No probes, no traffic, no state change —
just a ranked terminal-friendly digest of:

  1. `_SUGGESTION_RULES` — the same 10 rules that back the WebUI's
     `/api/scan/suggestions`. Cross-service facts (known_domains ->
     kerberos --domain, known_users admincount -> --user prefill,
     relay_targets -> ntlmrelayx handoff, etc.).
  2. Vulns carrying `exploit_note` at depth_tier t2/t3/t4 — the
     "proven exploitable, here's your next move" set that backs the
     WebUI Exploit Surface tab. Ranked by tier + severity + KEV + EPSS.

Same output the tester sees in the GUI, but on the terminal so a
`recce suggest -o eng` at the top of a hop-into-a-new-engagement
session immediately answers "given what recce already knows, what
should I run right now?".
"""
from __future__ import annotations

import argparse
import os

from .helpers import *  # noqa: F401,F403 — wildcard so _open_paths/_open_store resolve


__all__ = ["cmd_suggest"]


# Tier-to-rank + label helpers mirror recce/core/depth.py so the terminal
# renderer doesn't drift if that module's constants change.
def _tier_rank(t: str) -> int:
    try:
        from ..core import depth
        return depth.rank(t)
    except Exception:  # noqa: BLE001
        return {"t0": 0, "t1": 1, "t2": 2, "t3": 3, "t4": 4}.get(t, -1)


def _tier_label(t: str) -> str:
    try:
        from ..core import depth
        return depth.label(t)
    except Exception:  # noqa: BLE001
        return {"t0": "enum", "t1": "verify", "t2": "proof",
                "t3": "initial-access", "t4": "chain"}.get(t, t or "-")


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _run_rules(hosts, creds, loot_dir):
    """Run every `_SUGGESTION_RULES` entry from the webui routes module.
    Any rule that errors is skipped rather than 500-ing the whole run."""
    try:
        from ..webui.routes.scan import _SUGGESTION_RULES
    except Exception:  # noqa: BLE001 — import env may be minimal
        return []
    out: list[dict] = []
    for rule in _SUGGESTION_RULES:
        try:
            out.extend(rule(hosts, creds, loot_dir) or [])
        except Exception:  # noqa: BLE001
            continue
    return out


def _exploit_findings(hosts) -> list[dict]:
    """Every Vuln with either an exploit_note or a depth_tier stamp.
    Ranked (tier desc, severity desc, kev, epss) so the tester's
    "next 10 moves" set falls out of the top slice."""
    rows: list[dict] = []
    for h in hosts:
        for v in (getattr(h, "vulns", None) or []):
            note = getattr(v, "exploit_note", "") or ""
            tier = getattr(v, "depth_tier", "") or ""
            if not note and not tier:
                continue
            rows.append({
                "ip": v.ip, "port": v.port, "protocol": v.protocol,
                "title": v.title, "severity": v.severity,
                "tier": tier, "tier_label": _tier_label(tier),
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


def _print_top_actions(rules_out: list[dict], top: int) -> None:
    """The "your next N moves" hero block — pulls from cross-service
    rules first (highest signal about what recce is now equipped to
    do next), capped at `top`. Rendered with an ASCII bullet + a
    one-line rationale + the external cmd or field-value hint."""
    if not rules_out:
        print("  (no cross-service intel yet — run `enum` against the "
              "target subnet, then `recce suggest` again.)")
        return
    # Confidence sort: high -> medium -> low (stable within tier).
    conf_rank = {"high": 3, "medium": 2, "low": 1}
    ordered = sorted(rules_out,
                     key=lambda s: -conf_rank.get(s.get("confidence", ""), 0))
    for i, s in enumerate(ordered[:top], 1):
        cmd_or_field = s.get("external_cmd") or (
            f"prefill `{s.get('field')}={s.get('suggested_value')}` on "
            f"`{s.get('command')}`"
            if s.get("command") else "(info)"
        )
        conf = s.get("confidence", "-")
        print(f"  {i}. [{conf:<6}] {s.get('reason','')[:110]}")
        print(f"     -> {cmd_or_field}")


def _print_exploit_findings(findings: list[dict], top: int) -> None:
    """The Exploit Surface digest — one row per proven-exploitable
    finding, showing tier chip + endpoint + title + the exploit_note."""
    if not findings:
        print("  (no findings carry exploit_note or depth_tier yet — "
              "run `vulns` / a per-service deep probe first.)")
        return
    for i, f in enumerate(findings[:top], 1):
        tier = f["tier"] or "-"
        sev = f["severity"]
        kev = " KEV" if f["kev"] else ""
        cves = f" {','.join(f['cves'][:3])}" if f["cves"] else ""
        print(f"  {i}. [{sev:<8}][{tier}:{f['tier_label']:<15}] "
              f"{f['ip']}:{f['port']}  {f['title'][:80]}{kev}{cves}")
        if f["exploit_note"]:
            for line in _wrap_note(f["exploit_note"]).splitlines():
                print(f"       {line}")


def _wrap_note(note: str, width: int = 92) -> str:
    """Naive word-wrap for terminal rendering."""
    words = note.split()
    lines: list[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur.rstrip())
            cur = w + " "
        else:
            cur += w + " "
    if cur.strip():
        lines.append(cur.rstrip())
    return "\n".join(lines)


def cmd_suggest(args: argparse.Namespace) -> int:
    """`recce suggest -o <eng>` — print the ranked "next moves" digest.

    Read-only: opens the datastore, runs every cross-service rule + the
    exploit-note ranker, prints the top hits. Does NOT scan.
    """
    paths = _open_paths(args.output_dir)
    if not os.path.exists(paths["db"]):
        print(f"[x] No datastore at {paths['db']}. Run `enum`/`vulns` first.")
        return 1
    store = _open_store(paths["db"])
    if store is None:
        return 1
    try:
        hosts = list(store.all_hosts() or [])
        creds = list(store.all_credentials() or [])
    finally:
        store.close()

    loot_dir = os.path.join(args.output_dir, "loot")

    print(f"[*] recce suggests — engagement at {args.output_dir}")
    print(f"    ({len(hosts)} host(s), {len(creds)} credential(s), "
          f"loot: {loot_dir if os.path.isdir(loot_dir) else 'empty'})")
    print()

    top = int(getattr(args, "top", 10) or 10)

    print(f"[+] Top {top} cross-service next moves")
    _print_top_actions(_run_rules(hosts, creds, loot_dir), top)
    print()

    print(f"[+] Top {top} proven-exploitable findings (T2/T3/T4)")
    _print_exploit_findings(_exploit_findings(hosts), top)
    print()

    print("[i] Full detail lives in the WebUI: `recce serve -o "
          f"{args.output_dir}` -> Exploit tab + Scan tab suggestions.")
    return 0
