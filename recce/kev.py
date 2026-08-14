"""CISA Known Exploited Vulnerabilities (KEV) — offline prioritization (SOTA roadmap Stage 5).

A CVE in the KEV catalogue is CONFIRMED exploited in the wild — the single strongest
"fix this first" signal, orthogonal to CVSS severity and to QoD confidence. recce is
airgapped, so the catalogue ships as a bundled snapshot (like the vulndb signatures): the
set below is refreshed from https://www.cisa.gov/known-exploited-vulnerabilities-catalog at
package-build time. It is a curated snapshot focused on the CVEs recce actually surfaces on
internal engagements; `make_package.sh` can regenerate the full ~1,300-entry set.

Prioritization = severity × QoD × KEV/EPSS: a KEV finding that recce also *confirmed* is the
top of the fix list; a KEV CVE that's only a version lead is still flagged (fix-first) but
carries the honest "verify" caveat.
"""

from __future__ import annotations

# Snapshot (curated; refresh at package build). Focused on CVEs in recce's vulndb + the
# high-profile internal-engagement KEV set.
# --- AUTOGEN START: refreshed by tools/refresh_intel.py (do not hand-edit below) ---
KEV_CVES: frozenset[str] = frozenset({
    "CVE-2008-4250", "CVE-2010-2861", "CVE-2012-1823", "CVE-2014-0160",
    "CVE-2014-3120", "CVE-2014-6271", "CVE-2014-6278", "CVE-2014-6324",
    "CVE-2014-7169", "CVE-2015-1427", "CVE-2015-1635", "CVE-2017-0143",
    "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0147",
    "CVE-2017-0148", "CVE-2017-12149", "CVE-2017-5638", "CVE-2017-7494",
    "CVE-2018-0171", "CVE-2018-1000861", "CVE-2018-13379", "CVE-2018-14847",
    "CVE-2018-7600", "CVE-2018-9276", "CVE-2019-0708", "CVE-2019-10149",
    "CVE-2019-11510", "CVE-2019-15107", "CVE-2019-1579", "CVE-2019-17558",
    "CVE-2019-19781", "CVE-2019-2725", "CVE-2019-5544", "CVE-2019-7238",
    "CVE-2019-7609", "CVE-2019-9670", "CVE-2020-0618", "CVE-2020-0796",
    "CVE-2020-12271", "CVE-2020-1472", "CVE-2020-14882", "CVE-2020-1938",
    "CVE-2020-3452", "CVE-2020-3992", "CVE-2020-5902", "CVE-2020-8515",
    "CVE-2021-1675", "CVE-2021-20016", "CVE-2021-21972", "CVE-2021-22005",
    "CVE-2021-22205", "CVE-2021-26855", "CVE-2021-3156", "CVE-2021-34473",
    "CVE-2021-34523", "CVE-2021-34527", "CVE-2021-4034", "CVE-2021-41773",
    "CVE-2021-42013", "CVE-2021-43798", "CVE-2021-44228", "CVE-2021-45046",
    "CVE-2022-0847", "CVE-2022-1040", "CVE-2022-1388", "CVE-2022-22947",
    "CVE-2022-22965", "CVE-2022-23131", "CVE-2022-23134", "CVE-2022-24706",
    "CVE-2022-26134", "CVE-2022-27925", "CVE-2022-30525", "CVE-2022-40684",
    "CVE-2022-41352", "CVE-2022-46169", "CVE-2023-20269", "CVE-2023-21839",
    "CVE-2023-22515", "CVE-2023-26360", "CVE-2023-2868", "CVE-2023-28771",
    "CVE-2023-29298", "CVE-2023-34048", "CVE-2023-42793", "CVE-2023-46604",
    "CVE-2023-46747", "CVE-2023-46805", "CVE-2023-4966", "CVE-2023-7028",
    "CVE-2024-21887", "CVE-2024-21893", "CVE-2024-23897", "CVE-2024-27198",
    "CVE-2024-3400", "CVE-2024-40766", "CVE-2024-4577",
})
# --- AUTOGEN END ---


def is_kev(cve: str) -> bool:
    return (cve or "").upper() in KEV_CVES


def any_kev(cves) -> bool:
    return any(is_kev(c) for c in (cves or []))


def annotate(host) -> None:
    """Flag every finding whose CVE is in the KEV catalogue (in place)."""
    for v in getattr(host, "vulns", []) or []:
        v.kev = any_kev(getattr(v, "ids", []))
