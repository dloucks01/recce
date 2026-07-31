"""Quality of Detection (QoD) — the single source of truth for detection confidence.

QoD is a 0-100 number describing how RELIABLE a finding's detection method is. It is
deliberately ORTHOGONAL to severity: severity says how bad the issue is if real, QoD
says how likely it is actually there. Modelled on OpenVAS/Greenbone's QoD (see
docs/ARCHITECTURE.md §2.1/§3.1).

The whole point: confidence is computed ONCE here, from the detection method, and every
consumer reads the stored `Vuln.qod` instead of re-deriving "is this real?" from raw
strings in a dozen places (the root cause of recce's recurring false positives).

Two operator-dialable thresholds:
  * MIN_QOD_VISIBLE (70)  - default report inclusion; below this is a lead, hidden until
                            the operator lowers --min-qod. Catches the backport/version-only
                            false-positive class automatically.
  * MIN_QOD_VERIFIED (95) - the bar to be treated as CONFIRMED/exploitable. A banner/version
                            match is shown as a lead but never drives a "confirmed exploit"
                            artifact - which is what resolves recce's two-definitions-of-
                            CONFIRMED contradiction.
"""

from __future__ import annotations

MIN_QOD_VISIBLE = 70
MIN_QOD_VERIFIED = 95

# The tier table (docs/ARCHITECTURE.md §3.1), for reference and reverse lookup.
TIERS: dict[str, int] = {
    "exploit": 100,             # recce actively exploited / got an unauth read
    "active_vuln": 99,          # NSE state:VULNERABLE, or recce negotiated the weak protocol
    "local_authenticated": 97,  # on-target / credentialed / package / registry fact
    "active_app": 95,           # recce's own live probe confirmed the app/config
    "config_observed": 90,      # NSE weak-config observed (anon FTP, weak TLS, risky methods)
    "remote_banner": 80,        # version-db range match on a real banner/version
    "nmap_service": 70,         # -sV-inferred product/version match
    "inferred_port": 50,        # port-number label, no banner
    "banner_unreliable": 30,    # advisory / distro-backport / no patch level in version
    "general_note": 1,          # hygiene note, no vulnerable build confirmed
}


def score(vuln, port=None) -> tuple[int, str]:
    """Return (qod, qod_type) for a finding, from its detection method alone.

    Reads only structured fields: `source`, `confidence`, `state`, and (when the owning
    Port is supplied) `detect_source`. Never inspects free-text output - that scattered
    re-parsing is exactly what QoD replaces.
    """
    src = (getattr(vuln, "source", "") or "").lower()
    conf = (getattr(vuln, "confidence", "") or "").lower()
    state_up = (getattr(vuln, "state", "") or "").upper()
    detect = (getattr(port, "detect_source", "") or "").lower() if port is not None else ""

    # An explicit `potential` from the producer is authoritative: it means "not
    # confirmed" regardless of how it was found (advisory, distro-backport, an NSE
    # script that only hinted), so it caps QoD low and out of the default view.
    if conf == "potential":
        return 30, "banner_unreliable"

    # On-target / credentialed facts read the real system - highest non-exploit trust.
    if src in ("ingest", "service-enum", "local", "cred", "credenum"):
        return 97, "local_authenticated"

    # NSE: a positive VULNERABLE state is an active check that fired. (parser already
    # drops NOT-VULNERABLE, but guard anyway.) Otherwise it's an observed weak-config.
    if src == "nse":
        if "VULNERABLE" in state_up and "NOT VULNERABLE" not in state_up:
            return 99, "active_vuln"
        return 90, "config_observed"

    # recce's own live protocol probe confirmed the app/config.
    if src == "probe":
        return 95, "active_app"

    # Non-NSE observed config/hygiene finding.
    if src == "config":
        return 90, "config_observed"

    # Version-db: a banner/version inference - the low-confidence, backport-prone class.
    if src == "version-db":
        # `potential` already encodes advisory / distro-backport / unreliable (set by
        # vulndb._confidence + the _DISTRO_RE downgrade), so it maps straight to 30.
        if conf == "potential":
            return 30, "banner_unreliable"
        if detect == "inferred":            # port-number guess, no real banner
            return 50, "inferred_port"
        return 80, "remote_banner"          # a concrete version range matched a banner

    # Fallback for any other source: map the coarse confidence tier onto QoD.
    if conf == "confirmed":
        return 95, "active_app"
    if conf == "potential":
        return 30, "banner_unreliable"
    return 70, "nmap_service"               # "" / "likely" -> a visible lead


def qod_of(vuln, port=None) -> int:
    """The finding's stored QoD, or a computed one if it hasn't been annotated yet
    (fail-open: an unscored finding is treated at its method's score, never hidden by a
    missing annotation)."""
    return vuln.qod if getattr(vuln, "qod", 0) else score(vuln, port)[0]


def is_visible(vuln, min_qod: int = MIN_QOD_VISIBLE, port=None) -> bool:
    """Should this finding appear in the default report view?"""
    return qod_of(vuln, port) >= min_qod


def is_verified(vuln, port=None) -> bool:
    """Is this finding actively verified enough to be treated as CONFIRMED / exploitable
    (drive an exploitation plan, a 'proven exploit', a CONFIRMED verdict)? A version/banner
    match is NOT - it is a lead until a live/authenticated check corroborates it."""
    return qod_of(vuln, port) >= MIN_QOD_VERIFIED


def annotate(host) -> None:
    """Stamp qod/qod_type onto every finding on a host, once. Call after findings are
    finalized (post version-db assessment + folding). Idempotent."""
    ports = {(p.protocol, p.portid): p for p in host.ports}
    for v in host.vulns:
        p = ports.get((v.protocol, v.port))
        v.qod, v.qod_type = score(v, p)
