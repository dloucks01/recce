"""Finding deduplication / correlation (SOTA roadmap Stage 2).

The same real issue routinely surfaces several times on one host: a version-db CVE match
AND an NSE script AND a live probe for the SAME CVE on the SAME port. Left alone that
inflates the count and buries the signal — the "hundreds of findings" problem that makes a
report unusable. This collapses TRUE duplicates into one finding (keeping the highest-
confidence one, unioning refs/CWEs/evidence/sources, and never downgrading severity), while
**never merging two DISTINCT findings**.

Guarantees, in order of importance (see docs/design/ARCHITECTURE.md north star):
  * NEVER drop a distinct finding — only fold exact/CVE-identical duplicates.
  * Corroboration RAISES confidence: a version-db lead (QoD 80) + an NSE VULNERABLE
    (QoD 99) for the same CVE merge into one CONFIRMED finding at QoD 99, citing both.
  * Presentation-layer only: applied to the report's throwaway host copies, so the raw
    findings always remain in the datastore untouched.
"""

from __future__ import annotations

import re

from ..core.models import Vuln

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# SMB answers on BOTH 139 (NetBIOS session) and 445 (direct host) for the
# SAME service — a CVE there is one finding, not one-per-port. Collapsing
# these is definitionally safe: 139 and 445 are never two different
# services. HTTP ports (80/8080/…) are deliberately NOT collapsed — a host
# routinely runs DISTINCT web apps on different ports (nginx :80 +
# Tomcat :8080), and merging their findings would hide that the second app
# is also affected. Missed merge (noisier) beats wrong merge (lost finding).
_SMB_FAMILY_PORTS = {139, 445}
_TITLE_CVE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def _cves(v: Vuln) -> list[str]:
    return sorted({i.upper() for i in (v.ids or []) if i})


def _canonical_port(port: int | None) -> int | None:
    """Fold the SMB family (139/445) to one canonical port for correlation
    so a SambaCry-on-139 and SambaCry-on-445 (same SMB service, same CVE)
    collapse to ONE finding. Every other port is itself — HTTP ports are
    left distinct on purpose (see _SMB_FAMILY_PORTS note)."""
    if port in _SMB_FAMILY_PORTS:
        return 139
    return port


def _primary_cve(v: Vuln) -> str:
    """The finding's HEADLINE CVE for correlation. A CVE embedded in the
    title is the headline the detector chose to lead with (my parser now
    formats 'vulners: CVE-2025-10230' / 'Samba smbd: CVE-2025-10230' — the
    same headline CVE from two detectors), so anchor on it. This makes a
    multi-CVE vulners row and a single-CVE version-db row for the same
    headline merge, where anchoring on the sorted-first id would not (a
    vulners row's numerically-first CVE rarely equals the headline). Falls
    back to the numerically-first id when the title carries no CVE."""
    m = _TITLE_CVE.search(v.title or "")
    if m:
        return m.group(0).upper()
    cves = _cves(v)
    return cves[0] if cves else ""


def identity(v: Vuln) -> tuple:
    """The correlation key. Two findings with the same key are the same issue.

    - With a CVE: (ip, canonical_port, proto, headline CVE). Any finding
      citing that headline CVE on that service family is the same issue
      regardless of which detector produced it OR which port of a
      multi-port service family it landed on.
    - Without a CVE: (ip, canonical_port, proto, script_id, title) — so
      ONLY an exact duplicate collapses. Distinct config/advisory findings
      on one port stay separate. Conservative on purpose: a wrong merge
      (losing a distinct finding) is worse than a missed merge.
    """
    port = _canonical_port(v.port)
    cve = _primary_cve(v)
    if cve:
        return (v.ip, port, v.protocol, "cve", cve)
    return (v.ip, port, v.protocol, "id", v.script_id or "", (v.title or "")[:80])


def _qod(v: Vuln) -> int:
    # Use the stored QoD; fall back to the scorer so an un-annotated finding still ranks.
    if getattr(v, "qod", 0):
        return v.qod
    try:
        from ..core import qod as _q
        return _q.qod_of(v)
    except Exception:  # noqa: BLE001 - ranking helper must never break dedup
        return 0


def _merge(group: list[Vuln]) -> Vuln:
    """Fold a group of duplicate findings into one, keeping the best of each axis."""
    # Base = the strongest detection: highest QoD, then worst (most severe) severity,
    # then the richest output. Its wording/remediation is kept.
    base = max(group, key=lambda v: (_qod(v),
                                     -_SEV_RANK.get((v.severity or "info").lower(), 9),
                                     len(v.output or "")))
    import copy
    merged = copy.deepcopy(base)

    # Worst severity across the group never downgrades.
    merged.severity = min((v.severity or "info" for v in group),
                          key=lambda s: _SEV_RANK.get(s.lower(), 9))
    # Best (highest) QoD across the group — corroboration raises confidence.
    best = max(group, key=_qod)
    merged.qod, merged.qod_type = _qod(best), getattr(best, "qod_type", "") or merged.qod_type
    # Strongest confidence wins (confirmed > likely > potential > "").
    _crank = {"confirmed": 0, "likely": 1, "": 2, "potential": 3}
    merged.confidence = min((v.confidence or "" for v in group),
                            key=lambda c: _crank.get(c, 2))
    # Union references / weaknesses / evidence; keep sources for provenance.
    merged.ids = sorted({i for v in group for i in (v.ids or [])})
    merged.cwes = sorted({c for v in group for c in (v.cwes or [])})
    ev = [e for v in group for e in (getattr(v, "evidence", []) or [])]
    if hasattr(merged, "evidence"):
        merged.evidence = ev
    sources = sorted({v.source for v in group if v.source})
    if len(group) > 1 and len(sources) > 1:
        merged.output = (merged.output or "").rstrip() + (
            f"\n\nCorroborated by {len(group)} detections ({', '.join(sources)}).")
    return merged


def dedupe(vulns: list[Vuln]) -> list[Vuln]:
    """Collapse duplicate findings, preserving first-seen order. Distinct findings and
    singletons pass through untouched."""
    groups: dict[tuple, list[Vuln]] = {}
    order: list[tuple] = []
    for v in vulns:
        k = identity(v)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(v)
    out: list[Vuln] = []
    for k in order:
        grp = groups[k]
        out.append(grp[0] if len(grp) == 1 else _merge(grp))
    return out


def dedupe_host(host) -> None:
    """Dedupe a host's findings in place (for the report's throwaway host copies)."""
    host.vulns = dedupe(host.vulns)
