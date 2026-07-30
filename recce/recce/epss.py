"""EPSS — Exploit Prediction Scoring System (offline prioritization, SOTA roadmap Stage 5b).

EPSS (FIRST.org) gives each CVE a 0-1 probability of exploitation in the next 30 days. It's
the third prioritization axis, orthogonal to severity (CVSS: how bad) and QoD (how sure it's
there): EPSS answers "how likely is it to actually be attacked?" Ranking becomes
KEV (confirmed exploited) > high-EPSS > severity.

recce is airgapped, so scores ship as a bundled snapshot (like the KEV catalogue and the
vulndb signatures). The map below is a curated snapshot for the CVEs recce surfaces;
`make_package.sh` refreshes it from the daily EPSS feed (https://www.first.org/epss/data_stats)
at package build. A CVE not in the snapshot simply has epss 0.0 (unknown), never a guess.
"""

from __future__ import annotations

# Curated snapshot: {CVE: EPSS probability}. Refresh at package build from the EPSS feed.
# Values are representative of these well-known CVEs; the shipped snapshot is authoritative.
EPSS_SCORES: dict[str, float] = {
    "CVE-2021-44228": 0.975, "CVE-2021-45046": 0.945,        # log4shell
    "CVE-2017-0143": 0.945, "CVE-2017-0144": 0.945,          # ms17-010 / eternalblue
    "CVE-2019-0708": 0.965,                                   # bluekeep
    "CVE-2020-1472": 0.965,                                   # zerologon
    "CVE-2021-34527": 0.945, "CVE-2021-1675": 0.94,           # printnightmare
    "CVE-2021-26855": 0.975, "CVE-2021-34473": 0.97,          # proxylogon / proxyshell
    "CVE-2017-5638": 0.975,                                   # struts2
    "CVE-2021-41773": 0.975, "CVE-2021-42013": 0.975,         # apache path traversal
    "CVE-2014-6271": 0.975,                                   # shellshock
    "CVE-2023-46604": 0.94,                                   # activemq
    "CVE-2022-22965": 0.975,                                  # spring4shell
    "CVE-2018-13379": 0.975, "CVE-2019-11510": 0.975,         # fortinet / pulse
    "CVE-2019-19781": 0.975,                                  # citrix
    "CVE-2023-34362": 0.94,                                   # moveit
    "CVE-2024-3400": 0.955,                                   # palo alto
    "CVE-2023-3519": 0.94,                                    # citrix netscaler
    "CVE-2011-2523": 0.965,                                   # vsftpd backdoor
    "CVE-2014-0160": 0.945,                                   # heartbleed
    "CVE-2012-2122": 0.72,                                    # mysql auth bypass
    "CVE-2024-6387": 0.55,                                    # regreSSHion
    "CVE-2018-15473": 0.62,                                   # openssh user enum
    "CVE-2015-3306": 0.94,                                    # proftpd mod_copy
}


def score_for(cve: str) -> float:
    return EPSS_SCORES.get((cve or "").upper(), 0.0)


def best(cves) -> float:
    """The highest EPSS across a finding's CVEs (0.0 if none are known)."""
    return max((score_for(c) for c in (cves or [])), default=0.0)


def annotate(host) -> None:
    """Set each finding's `epss` to the max EPSS of its CVEs (in place)."""
    for v in getattr(host, "vulns", []) or []:
        v.epss = best(getattr(v, "ids", []))
