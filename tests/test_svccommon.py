"""svccommon.findings_to_vulns honours per-finding confidence.

A deep-service module can mark a heuristic/observed finding as a lead instead of
every finding being blanket "confirmed" (which pinned it at QoD 95 verified and
attached a bogus live-probe corroboration).
"""
from __future__ import annotations

from recce import qod
from recce.svccommon import finding_builder, findings_to_vulns


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


def test_finding_builder_shapes_the_dict_and_folds_narrative():
    # every deep-service module now shares this one builder (was 13 identical copies).
    narrative = {"unauth": "an unauthenticated peer can read/modify data"}
    _finding = finding_builder("redis", narrative)
    f = _finding("critical", "Unauthenticated Redis", "10.0.0.5:6379", "INFO answered",
                 "redis-cli", "redis-cli -h 10.0.0.5 INFO", "Require AUTH", ["CWE-306"],
                 kind="unauth")
    assert f["category"] == "redis"
    assert f["narrative"] == "an unauthenticated peer can read/modify data"
    assert f["cwes"] == ["CWE-306"] and f["severity"] == "critical"
    # an unknown kind folds to an empty narrative, never a KeyError
    assert finding_builder("smb", {})("low", "t", "1.2.3.4:445", "d", "x", "c", "r", [])["narrative"] == ""


def test_recvn_two_modes():
    import socket as _s
    from recce.svccommon import recvn
    a, b = _s.socketpair()
    try:
        b.sendall(b"hello world")
        assert recvn(a, 5) == b"hello"                    # no-timeout: exact read
        # timeout mode returns None on an incomplete frame instead of blocking forever
        assert recvn(a, 50, timeout=0.2) is None          # only 6 bytes left ("  world")
    finally:
        a.close(); b.close()
    # no-timeout mode returns the partial buffer at EOF (mongodb/ldap contract)
    c, d = _s.socketpair()
    c.sendall(b"abc"); c.close()
    try:
        assert recvn(d, 10) == b"abc"
    finally:
        d.close()
