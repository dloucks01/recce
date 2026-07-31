"""Active verification — slice 3a: refute leads an NSE check already disproved.

verify-don't-infer, the safe first slice: ZERO new traffic. recce's vulns phase already
runs non-intrusive vuln DETECTORS (smb-vuln-ms17-010, ssl-heartbleed, ...). When one reports
`NOT VULNERABLE`, that "it's patched" answer is currently thrown away by the parser — so a
version-db LEAD for the same CVE silently survives even though nmap's own check disproved it.

This harvests those already-collected negative results (they're stored in `port.scripts`) and
**refutes** the matching version-inference leads: marks them `qod_type="refuted"`, drops QoD
to 1, and records a negative `Evidence`. Refuted findings are hidden by default in the report
(the one place a hard gate is correct — a check actively disproved it) but are NEVER deleted:
the raw row stays in the datastore and `report --show-refuted` surfaces them.

See docs/ACTIVE-VERIFICATION.md. Later slices (3b/3c) add the registry + opt-in re-checks.
"""

from __future__ import annotations

import re

from .models import Evidence, Host
from .verify_rules import rule_for_cve, script_cves

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# {nse_script_id: [cves]} from the verification registry (verify_rules.py) - the curated
# belt-and-suspenders map for scripts whose NOT-VULNERABLE output doesn't embed the CVE.
_SCRIPT_CVES: dict[str, list[str]] = script_cves()


def _refuted_cves(host: Host) -> set[str]:
    """CVEs an NSE detector actively reported NOT VULNERABLE (patched) on this host.

    'NOT VULNERABLE' is the nmap `vulns` library's verdict string, printed by a single-vuln
    detector as its overall State — so its presence means that check's CVE(s) are patched.
    """
    refuted: set[str] = set()
    scripts = [s for p in host.ports for s in (p.scripts or [])]
    scripts += list(getattr(host, "host_scripts", []) or [])
    for s in scripts:
        out = s.output or ""
        if "NOT VULNERABLE" not in out.upper():
            continue
        cves = {c.upper() for c in _CVE_RE.findall(out)}
        cves |= {c.upper() for c in _SCRIPT_CVES.get(s.id, [])}
        refuted |= cves
    return refuted


def _confirmed_cves(host: Host) -> set[str]:
    """CVEs the host has an actively-CONFIRMED (positive VULNERABLE, NSE/probe) finding for -
    so a contradictory NOT-VULNERABLE never refutes a real, positive result."""
    out: set[str] = set()
    for v in host.vulns:
        if v.source in ("version-db",):        # inference, not a live confirmation
            continue
        state_up = (v.state or "").upper()
        pos_ev = any(getattr(e, "positive", False) and getattr(e, "kind", "") in ("nse", "live-probe")
                     for e in (getattr(v, "evidence", []) or []))
        if ("VULNERABLE" in state_up and "NOT VULNERABLE" not in state_up) or pos_ev:
            out |= {i.upper() for i in (v.ids or [])}
    return out


def apply_refutations(host: Host) -> int:
    """Refute version-inference leads a co-located NSE check disproved. In place; returns
    the number refuted. Conservative: only `version-db` leads, never an actively-confirmed
    finding, and never when the same CVE is confirmed positive elsewhere on the host."""
    refuted = _refuted_cves(host)
    if not refuted:
        return 0
    confirmed = _confirmed_cves(host)
    n = 0
    for v in host.vulns:
        if v.source != "version-db":           # only refute an inference, never a live result
            continue
        vcves = {i.upper() for i in (v.ids or [])}
        hit = vcves & refuted
        if not hit or (vcves & confirmed):     # skip contradictions (a positive wins)
            continue
        v.qod, v.qod_type = 1, "refuted"
        cve = sorted(hit)[0]
        if hasattr(v, "evidence"):
            v.evidence = list(getattr(v, "evidence", []) or []) + [
                Evidence(kind="nse", positive=False,
                         detail=f"an NSE check reported NOT VULNERABLE for {cve} on this host")]
        n += 1
    return n


def is_refuted(v) -> bool:
    return getattr(v, "qod_type", "") == "refuted"


def _ran_scripts(host: Host) -> set[str]:
    ids = {s.id for p in host.ports for s in (p.scripts or [])}
    ids |= {s.id for s in (getattr(host, "host_scripts", []) or [])}
    return ids


def confirm_plan(host: Host) -> list[dict]:
    """For each still-unconfirmed version-inference LEAD that has a registry rule, the exact
    safe check that would settle it — the honesty loop's `to_confirm`, as data. Reports
    whether that check already ran, and the one-line command. No traffic; pure planning.

    Returns [{ip, port, cve, finding, check, tier, command, ran}]. Drives the report's
    'To confirm' guidance now and the opt-in `recce verify --run` (slice 3c) next.
    """
    ran = _ran_scripts(host)
    out: list[dict] = []
    for v in host.vulns:
        if v.source != "version-db" or is_refuted(v):
            continue
        for cve in (i.upper() for i in (v.ids or [])):
            rule = rule_for_cve(cve)
            if not rule:
                continue
            cmd = (rule.get("confirm", "") or "").replace("<ip>", host.ip)
            if v.port:
                cmd = cmd.replace("<port>", str(v.port))
            out.append({"ip": host.ip, "port": v.port, "cve": cve,
                        "finding": v.title or v.script_id, "check": rule.get("nse", ""),
                        "tier": rule.get("tier", "B"), "command": cmd,
                        "ran": rule.get("nse", "") in ran})
            break   # one confirm plan per finding
    return out
