"""T0-T4 exploit-maturity rubric for finding tiering.

Every recce Vuln carries an optional `depth_tier` per this scale so the
WebUI ExploitSurface can rank + group findings by "how close to a real
foothold is this?" rather than only by severity.

  * T0 enum       — fingerprint / version / surface listing. Not evidence
                    of a vuln (e.g. "port 22, OpenSSH_9.6p1").
  * T1 verify     — a probe deterministically confirmed the vuln
                    (e.g. redis INFO answered without AUTH — the anon
                    read primitive is proved).
  * T2 proof      — a controlled payload proved the exploit primitive
                    without full compromise (e.g. MSSQL BULK INSERT
                    reads a canary file the module then reads back).
  * T3 initial    — actual foothold: credentials captured, a session
                    established, meaningful data pulled, a webshell
                    written. Recce does NOT run T3 automatically —
                    tester_next_step in exploit_note tells the operator
                    exactly what to run.
  * T4 chain      — post-foothold follow-on: LSA/DPAPI dumps,
                    secretsdump, ADCS ESC1 request, hash-crack-and-spray
                    loop. Usually surfaces as an attack-path graph edge.

Constants below let modules assert their tier without stringly-typing
the slug at every call site.
"""
from __future__ import annotations

T0_ENUM = "t0"
T1_VERIFY = "t1"
T2_PROOF = "t2"
T3_INITIAL = "t3"
T4_CHAIN = "t4"

ALL_TIERS = (T0_ENUM, T1_VERIFY, T2_PROOF, T3_INITIAL, T4_CHAIN)

_LABEL = {
    T0_ENUM:    "enum",
    T1_VERIFY:  "verify",
    T2_PROOF:   "proof",
    T3_INITIAL: "initial-access",
    T4_CHAIN:   "chain",
}

_RANK = {t: i for i, t in enumerate(ALL_TIERS)}


def label(tier: str) -> str:
    """Human-readable label for a tier slug ('t2' -> 'proof')."""
    return _LABEL.get(tier, tier)


def rank(tier: str) -> int:
    """Sort key — higher tier = higher rank. Unknown tiers sort below T0."""
    return _RANK.get(tier, -1)


def valid(tier: str) -> bool:
    return tier in _RANK
