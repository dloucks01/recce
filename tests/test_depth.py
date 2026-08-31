"""recce.core.depth: T0-T4 exploit-maturity rubric constants + helpers."""
from __future__ import annotations

from recce.core import depth
from recce.core.models import Vuln


def test_all_tiers_are_ordered_low_to_high():
    """T0 enum -> T4 chain must sort strictly increasing."""
    assert depth.ALL_TIERS == ("t0", "t1", "t2", "t3", "t4")
    for a, b in zip(depth.ALL_TIERS, depth.ALL_TIERS[1:]):
        assert depth.rank(a) < depth.rank(b)


def test_label_returns_human_name():
    assert depth.label("t0") == "enum"
    assert depth.label("t1") == "verify"
    assert depth.label("t2") == "proof"
    assert depth.label("t3") == "initial-access"
    assert depth.label("t4") == "chain"


def test_label_falls_back_to_slug_for_unknown():
    assert depth.label("t9") == "t9"


def test_rank_unknown_sorts_below_t0():
    assert depth.rank("t9") < depth.rank("t0")


def test_valid_recognises_only_the_five_defined_tiers():
    for t in depth.ALL_TIERS:
        assert depth.valid(t)
    assert not depth.valid("")
    assert not depth.valid("t9")
    assert not depth.valid("T2")   # case-sensitive


def test_vuln_carries_exploit_note_and_depth_tier_defaulting_empty():
    """Backward compat: existing findings without the new fields still work."""
    v = Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="smb",
             title="test", severity="high")
    assert v.exploit_note == ""
    assert v.depth_tier == ""


def test_vuln_accepts_exploit_note_and_depth_tier_as_kwargs():
    v = Vuln(ip="10.0.0.1", port=445, protocol="tcp", script_id="smb",
             title="SMB signing not required (NTLM relay target)",
             severity="medium",
             depth_tier=depth.T1_VERIFY,
             exploit_note=("impacket-ntlmrelayx.py -t smb://10.0.0.1 "
                           "-smb2support -socks; then Coercer to trigger "
                           "the auth."))
    assert v.depth_tier == "t1"
    assert "ntlmrelayx" in v.exploit_note
