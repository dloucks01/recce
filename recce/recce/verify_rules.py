"""Verification registry (data) — how to CONFIRM or REFUTE a version-inference lead.

Each rule maps a CVE (or set) to the SAFE, non-intrusive check that settles it: the NSE
detector recce already runs, and the exact one-liner an operator (or `recce verify --run`,
a later slice) uses to prove it. Data, not code — Nuclei-template style — so coverage grows
by adding a dict, and the same table drives refutation (3a), the honesty loop's `to_confirm`,
and the opt-in re-check (3c).

Tier is A/B only (see docs/ACTIVE-VERIFICATION.md): read-only / non-intrusive detection.
Weaponizing PoCs are NOT here — they stay operator-gated.
"""

from __future__ import annotations

# tier: "A" read-only, "B" non-intrusive detector (both safe to auto-run).
VERIFY_RULES: list[dict] = [
    {"cves": ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146",
              "CVE-2017-0147", "CVE-2017-0148"], "nse": "smb-vuln-ms17-010", "tier": "B",
     "confirm": "nmap -p445 --script smb-vuln-ms17-010 <ip>"},
    {"cves": ["CVE-2008-4250"], "nse": "smb-vuln-ms08-067", "tier": "B",
     "confirm": "nmap -p445 --script smb-vuln-ms08-067 <ip>"},
    {"cves": ["CVE-2012-0002"], "nse": "rdp-vuln-ms12-020", "tier": "B",
     "confirm": "nmap -p3389 --script rdp-vuln-ms12-020 <ip>"},
    {"cves": ["CVE-2014-0160"], "nse": "ssl-heartbleed", "tier": "B",
     "confirm": "nmap -p<port> --script ssl-heartbleed <ip>"},
    {"cves": ["CVE-2014-3566"], "nse": "ssl-poodle", "tier": "B",
     "confirm": "nmap -p<port> --script ssl-poodle <ip>"},
    {"cves": ["CVE-2014-0224"], "nse": "ssl-ccs-injection", "tier": "B",
     "confirm": "nmap -p<port> --script ssl-ccs-injection <ip>"},
    {"cves": ["CVE-2014-6271", "CVE-2014-6278"], "nse": "http-shellshock", "tier": "B",
     "confirm": "nmap -p<port> --script http-shellshock --script-args uri=/cgi-bin/status <ip>"},
    {"cves": ["CVE-2017-5638"], "nse": "http-vuln-cve2017-5638", "tier": "B",
     "confirm": "nmap -p<port> --script http-vuln-cve2017-5638 <ip>"},
    {"cves": ["CVE-2011-2523"], "nse": "ftp-vsftpd-backdoor", "tier": "B",
     "confirm": "nmap -p21 --script ftp-vsftpd-backdoor <ip>"},
    {"cves": ["CVE-2015-1635"], "nse": "http-vuln-cve2015-1635", "tier": "B",
     "confirm": "nmap -p<port> --script http-vuln-cve2015-1635 <ip>"},
    {"cves": ["CVE-2010-2861"], "nse": "http-vuln-cve2010-2861", "tier": "B",
     "confirm": "nmap -p<port> --script http-vuln-cve2010-2861 <ip>"},
]


def rule_for_cve(cve: str) -> dict | None:
    cve = (cve or "").upper()
    for r in VERIFY_RULES:
        if cve in r["cves"]:
            return r
    return None


def script_cves() -> dict[str, list[str]]:
    """{nse_script_id: [cves]} — the curated map used to attribute a NOT-VULNERABLE result
    to its CVE(s) when the script output doesn't embed them."""
    return {r["nse"]: list(r["cves"]) for r in VERIFY_RULES if r.get("nse")}
