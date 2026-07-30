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
KEV_CVES: frozenset[str] = frozenset({
    # SMB / Windows
    "CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0147",
    "CVE-2017-0148", "CVE-2008-4250", "CVE-2020-1472", "CVE-2021-34527", "CVE-2021-1675",
    "CVE-2019-0708", "CVE-2021-42278", "CVE-2021-42287", "CVE-2022-26923",
    # Exchange
    "CVE-2021-26855", "CVE-2021-27065", "CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207",
    # Web / app servers
    "CVE-2021-44228", "CVE-2021-45046", "CVE-2017-5638", "CVE-2017-9805",
    "CVE-2021-41773", "CVE-2021-42013", "CVE-2014-6271", "CVE-2014-6278",
    "CVE-2023-46604", "CVE-2010-2861", "CVE-2019-2725", "CVE-2020-14882", "CVE-2020-14883",
    "CVE-2022-22965", "CVE-2022-22947", "CVE-2018-11776", "CVE-2019-3396",
    "CVE-2021-26084", "CVE-2022-26134", "CVE-2021-22986", "CVE-2020-5902",
    # Edge / VPN / appliances
    "CVE-2018-13379", "CVE-2019-11510", "CVE-2019-19781", "CVE-2023-3519",
    "CVE-2023-27997", "CVE-2023-34362", "CVE-2024-3400", "CVE-2023-20198",
    # Services
    "CVE-2011-2523", "CVE-2015-3306", "CVE-2012-2122",
    # TLS / crypto (exploited)
    "CVE-2014-0160",
})


def is_kev(cve: str) -> bool:
    return (cve or "").upper() in KEV_CVES


def any_kev(cves) -> bool:
    return any(is_kev(c) for c in (cves or []))


def annotate(host) -> None:
    """Flag every finding whose CVE is in the KEV catalogue (in place)."""
    for v in getattr(host, "vulns", []) or []:
        v.kev = any_kev(getattr(v, "ids", []))
