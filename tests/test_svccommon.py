"""svccommon.findings_to_vulns honours per-finding confidence.

A deep-service module can mark a heuristic/observed finding as a lead instead of
every finding being blanket "confirmed" (which pinned it at QoD 95 verified and
attached a bogus live-probe corroboration).
"""
from __future__ import annotations

from recce import qod
from recce.svccommon import findings_to_vulns


def test_per_finding_confidence_and_evidence():
    fs = [
        # default: a live protocol action -> confirmed, carries a live-probe evidence
        {"title": "Anonymous FTP login allowed", "target": "10.0.0.1:21",
         "severity": "medium", "detail": "230 Login successful"},
        # a module marks a banner-only guess as a lead
        {"title": "Banner suggests an old build", "target": "10.0.0.1:21",
         "severity": "info", "detail": "vsftpd 2.x", "confidence": "potential"},
    ]
    vulns = findings_to_vulns(fs, source="ftp", default_port=21)["10.0.0.1"]
    confirmed = next(v for v in vulns if v.title.startswith("Anonymous"))
    lead = next(v for v in vulns if v.title.startswith("Banner"))

    assert confirmed.confidence == "confirmed"
    assert any(e.kind == "live-probe" and e.positive for e in confirmed.evidence)
    assert qod.is_verified(confirmed)                 # live service finding -> 95

    assert lead.confidence == "potential"
    assert lead.evidence == []                        # a guess is not a live corroboration
    assert qod.qod_of(lead) == 30                     # below the visibility floor
    assert not qod.is_visible(lead)
