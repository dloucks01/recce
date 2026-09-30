"""As-of dates for the baked offline intel (KEV / EPSS).

Rewritten by tools/refresh_intel.py each time the intel is refreshed, so the
operator can see how fresh the airgapped KEV/EPSS data is (stale intel silently
under-prioritises new exploited CVEs).

Two fields per source:
  * ``*_AS_OF`` — YYYY-MM-DD when this snapshot was baked.
  * ``KEV_CATALOG_VERSION`` — CISA's own ``catalogVersion`` string.
  * ``EPSS_MODEL`` — FIRST's model version stamped in the feed header
    (e.g. ``"v2024.02.29"`` for EPSS v4).

"unknown"/"" means the source predates the stamp — run
tools/refresh_intel.py to update.
"""
from __future__ import annotations

KEV_AS_OF = "unknown"
KEV_CATALOG_VERSION = ""
KEV_RELEASED = ""
EPSS_AS_OF = "unknown"
EPSS_MODEL = ""
EPSS_SCORE_DATE = ""


def _counts() -> tuple[int, int]:
    """(KEV CVEs, EPSS scores) actually baked in. Best-effort — a partial build
    that can't import a snapshot module reports 0 for it, never raises."""
    try:
        from .kev import KEV_CVES
        kev_n = len(KEV_CVES)
    except Exception:  # noqa: BLE001
        kev_n = 0
    try:
        from .epss import EPSS_SCORES
        epss_n = len(EPSS_SCORES)
    except Exception:  # noqa: BLE001
        epss_n = 0
    return kev_n, epss_n


def summary() -> str:
    """One-line freshness summary for `recce doctor` / Overview / reports.

    Leads with what's actually baked in (entry counts) so a present-but-unstamped
    snapshot doesn't read as "missing". The provenance date is appended when it's
    been stamped by tools/refresh_intel.py, or flagged as unstamped otherwise."""
    kev_n, epss_n = _counts()
    if not kev_n and not epss_n:
        return "no offline KEV/EPSS intel baked in — run tools/refresh_intel.py"
    kv = f"v{KEV_CATALOG_VERSION}" if KEV_CATALOG_VERSION else ""
    em = EPSS_MODEL or ""
    kev_part = f"KEV {kev_n} CVEs" + (f" ({kv}, baked {KEV_AS_OF})" if kev_n and KEV_AS_OF != "unknown"
                                      else f" ({kv})" if kv else "")
    epss_part = f"EPSS {epss_n} scores" + (f" ({em}, baked {EPSS_AS_OF})" if epss_n and EPSS_AS_OF != "unknown"
                                           else f" ({em})" if em else "")
    line = f"{kev_part} · {epss_part}"
    if KEV_AS_OF == "unknown" and EPSS_AS_OF == "unknown":
        line += " · snapshot date unstamped"
    return line


def info() -> dict:
    """Structured view for /api/overview / reports. `stamped` is True once the
    snapshot dates have been written by tools/refresh_intel.py; `kev_count` /
    `epss_count` prove the data is present even when the date is unstamped, so
    callers can distinguish 'stale/unstamped' from 'missing'."""
    kev_n, epss_n = _counts()
    return {
        "kev_as_of": KEV_AS_OF,
        "kev_catalog_version": KEV_CATALOG_VERSION,
        "kev_released": KEV_RELEASED,
        "epss_as_of": EPSS_AS_OF,
        "epss_model": EPSS_MODEL,
        "epss_score_date": EPSS_SCORE_DATE,
        "kev_count": kev_n,
        "epss_count": epss_n,
        "stamped": KEV_AS_OF != "unknown" or EPSS_AS_OF != "unknown",
        "present": bool(kev_n or epss_n),
        "summary": summary(),
    }
