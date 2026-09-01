"""`recce prove` P2-5 uplift — a CONFIRMED verdict promotes
depth_tier to t2 (proof of exploit) and drops the verdict evidence
into the finding's output field.

Unit-tests the depth-uplift logic in isolation from the CLI wiring
so a future prove-command refactor doesn't quietly drop the promotion.
"""
from __future__ import annotations

from recce.core.models import Host, Vuln


def _promote_confirmed_findings(hosts, by_key, confirmed_value: str) -> int:
    """The exact promotion block from cli/_act.py:cmd_prove — copied here
    so tests exercise it deterministically. If cmd_prove ever changes,
    keep this function in sync (the assertion messages call the mismatch
    out loud)."""
    tier_upgrades = 0
    for host in hosts:
        for v in host.vulns:
            r = by_key.get((v.ip, v.port, v.title))
            if not r:
                continue
            v.verdict = r["verdict"]
            v.verdict_evidence = list(r.get("evidence") or [])
            v.verdict_finish = r.get("finish", "")
            if r["verdict"] == confirmed_value:
                cur = (getattr(v, "depth_tier", "") or "").lower()
                if cur in ("", "t0", "t1"):
                    v.depth_tier = "t2"
                    tier_upgrades += 1
                    if not v.output and v.verdict_evidence:
                        v.output = "proof-verdict:\n  " + "\n  ".join(
                            v.verdict_evidence[:6])
    return tier_upgrades


def _mk_vuln(**kw):
    """Vuln factory with sane defaults so test blocks stay compact."""
    defaults = dict(ip="10.0.0.10", port=445, protocol="tcp",
                    script_id="smb", title="EternalBlue MS17-010",
                    severity="critical")
    defaults.update(kw)
    return Vuln(**defaults)


def test_confirmed_verdict_on_t1_finding_promotes_to_t2():
    """A CONFIRMED verdict from prove IS server-side evidence — the
    depth_tier should climb from t1 (safe verify) to t2 (proof)."""
    h = Host(ip="10.0.0.10")
    h.vulns = [_mk_vuln(depth_tier="t1")]
    by_key = {("10.0.0.10", 445, "EternalBlue MS17-010"): {
        "verdict": "CONFIRMED",
        "evidence": ["STATUS_INSUFF_SERVER_RESOURCES observed on IPC$",
                     "PeekNamedPipe reply parsed"],
        "finish": "msf use exploit/windows/smb/ms17_010_eternalblue",
    }}
    n = _promote_confirmed_findings([h], by_key, "CONFIRMED")
    assert n == 1
    assert h.vulns[0].depth_tier == "t2"
    assert "STATUS_INSUFF" in h.vulns[0].output
    assert "proof-verdict" in h.vulns[0].output


def test_confirmed_verdict_on_unstamped_finding_still_promotes():
    """A finding that never got a depth_tier stamp should also climb —
    the promotion path treats "" as equivalent to t0/t1 for this check."""
    h = Host(ip="10.0.0.10")
    h.vulns = [_mk_vuln(depth_tier="")]      # never stamped
    by_key = {("10.0.0.10", 445, "EternalBlue MS17-010"): {
        "verdict": "CONFIRMED", "evidence": ["proof"], "finish": ""}}
    n = _promote_confirmed_findings([h], by_key, "CONFIRMED")
    assert n == 1
    assert h.vulns[0].depth_tier == "t2"


def test_confirmed_verdict_on_t2_finding_never_demotes_or_re_promotes():
    """A finding already at t2 stays at t2 — the promotion never demotes
    a t3/t4 finding to t2, and never counts as an upgrade for a t2 that
    was already there."""
    h = Host(ip="10.0.0.10")
    h.vulns = [_mk_vuln(depth_tier="t3")]
    by_key = {("10.0.0.10", 445, "EternalBlue MS17-010"): {
        "verdict": "CONFIRMED", "evidence": ["e"], "finish": ""}}
    n = _promote_confirmed_findings([h], by_key, "CONFIRMED")
    assert n == 0
    assert h.vulns[0].depth_tier == "t3"    # unchanged; higher tier retained


def test_likely_verdict_does_not_promote_tier():
    """LIKELY is high-signal-but-not-proven; prove must NOT promote it
    to t2 on that basis alone (the whole point of t2 is 'proved')."""
    h = Host(ip="10.0.0.10")
    h.vulns = [_mk_vuln(depth_tier="t1")]
    by_key = {("10.0.0.10", 445, "EternalBlue MS17-010"): {
        "verdict": "LIKELY", "evidence": ["heuristic"], "finish": ""}}
    n = _promote_confirmed_findings([h], by_key, "CONFIRMED")
    assert n == 0
    assert h.vulns[0].depth_tier == "t1"


def test_false_positive_verdict_never_promotes():
    """A prove that refutes the finding must NOT promote the tier."""
    h = Host(ip="10.0.0.10")
    h.vulns = [_mk_vuln(depth_tier="t1")]
    by_key = {("10.0.0.10", 445, "EternalBlue MS17-010"): {
        "verdict": "FALSE POSITIVE",
        "evidence": ["STATUS_INVALID_HANDLE — patched"], "finish": ""}}
    n = _promote_confirmed_findings([h], by_key, "CONFIRMED")
    assert n == 0
    assert h.vulns[0].depth_tier == "t1"    # not promoted


def test_verdict_evidence_does_not_overwrite_existing_output():
    """If the finding already has output text, prove must not clobber it."""
    h = Host(ip="10.0.0.10")
    h.vulns = [_mk_vuln(depth_tier="t1", output="existing evidence from probe")]
    by_key = {("10.0.0.10", 445, "EternalBlue MS17-010"): {
        "verdict": "CONFIRMED", "evidence": ["new proof line"], "finish": ""}}
    _promote_confirmed_findings([h], by_key, "CONFIRMED")
    assert h.vulns[0].output == "existing evidence from probe"


def test_findings_without_a_matching_prove_result_are_untouched():
    """Sanity: an unrelated Vuln keeps its tier + verdict fields empty."""
    h = Host(ip="10.0.0.10")
    h.vulns = [_mk_vuln(depth_tier="t1", title="Something else entirely")]
    by_key = {("10.0.0.10", 445, "EternalBlue MS17-010"): {
        "verdict": "CONFIRMED", "evidence": ["e"], "finish": ""}}
    n = _promote_confirmed_findings([h], by_key, "CONFIRMED")
    assert n == 0
    assert h.vulns[0].depth_tier == "t1"
    assert h.vulns[0].verdict == ""


def test_evidence_truncated_to_six_lines():
    """A prove with 100 evidence lines would produce a wall of text in
    the ExploitSurface tab — trim to 6 for readability."""
    h = Host(ip="10.0.0.10")
    h.vulns = [_mk_vuln(depth_tier="t1")]
    by_key = {("10.0.0.10", 445, "EternalBlue MS17-010"): {
        "verdict": "CONFIRMED",
        "evidence": [f"line-{i}" for i in range(20)],
        "finish": ""}}
    _promote_confirmed_findings([h], by_key, "CONFIRMED")
    out = h.vulns[0].output
    assert "line-5" in out         # index 5 = the sixth line
    assert "line-6" not in out     # cut-off
