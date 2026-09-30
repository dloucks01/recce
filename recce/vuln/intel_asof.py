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


def summary() -> str:
    """One-line freshness summary for `recce doctor` / Overview / reports."""
    kv = f"v{KEV_CATALOG_VERSION}" if KEV_CATALOG_VERSION else "unknown"
    em = EPSS_MODEL or "unknown"
    return f"KEV {kv} baked {KEV_AS_OF} · EPSS {em} baked {EPSS_AS_OF}"


def info() -> dict:
    """Structured view for /api/overview / reports. Empty strings when the
    source hasn't been stamped yet; callers show 'unknown' in that case."""
    return {
        "kev_as_of": KEV_AS_OF,
        "kev_catalog_version": KEV_CATALOG_VERSION,
        "kev_released": KEV_RELEASED,
        "epss_as_of": EPSS_AS_OF,
        "epss_model": EPSS_MODEL,
        "epss_score_date": EPSS_SCORE_DATE,
        "summary": summary(),
    }
