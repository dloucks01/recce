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

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Single-vuln NSE detectors whose CVE set isn't always embedded in the output text, so a
# "NOT VULNERABLE" from them refutes these specific CVEs. (Most vuln scripts DO print their
# IDs, which are picked up directly; this is the belt-and-suspenders map for the rest.)
_SCRIPT_CVES: dict[str, list[str]] = {
    "smb-vuln-ms17-010": ["CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145",
                          "CVE-2017-0146", "CVE-2017-0147", "CVE-2017-0148"],
    "smb-vuln-ms08-067": ["CVE-2008-4250"],
    "rdp-vuln-ms12-020": ["CVE-2012-0002"],
    "ssl-heartbleed": ["CVE-2014-0160"],
    "ssl-poodle": ["CVE-2014-3566"],
    "ssl-ccs-injection": ["CVE-2014-0224"],
    "smb-double-pulsar-backdoor": ["CVE-2017-0143"],
    "http-shellshock": ["CVE-2014-6271", "CVE-2014-6278"],
    "http-vuln-cve2017-5638": ["CVE-2017-5638"],
    "ftp-vsftpd-backdoor": ["CVE-2011-2523"],
}


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
