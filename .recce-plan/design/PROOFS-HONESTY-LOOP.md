# Evaluation & Honesty Loop

Spec for replacing recce's verdict engine. See ARCHITECTURE.md for the QoD model.

## Two failure modes

1. **False negative** — a real finding is hidden or gated away. The tester misses what gets them in. **The worse one.**
2. **False positives at scale** — hundreds of unranked leads. The tester can't find signal in noise and stops trusting the tool.

The old `_v_*` verdict engine leaned toward (2)-avoidance with hard gates that silently dropped findings — risking (1). The honesty loop must beat both.

## Core idea: organize by honest confidence

Never drop a possibly-real finding. Never present noise as equal to signal.

- Every finding is **surfaced**, always
- Each carries an honest realness assessment (confidence + reasoning)
- The report **leads with high-confidence findings**; low-confidence leads are demoted and collapsed (one expand away), never intermixed
- Duplicates merged so the same issue across sources/hosts is ONE finding
- Hard gates fire only for definitive disproofs (NSE NOT VULNERABLE, live re-probe refuses auth)

## Realized through proven SOTA mechanisms

| Goal | Mechanism |
|---|---|
| Hundreds → handful of real issues | Dedup / correlation |
| Evaluate realness, don't guess | Active verification |
| Surface everything, ranked honestly | QoD tiering + EPSS/KEV prioritization |
| Reasoning shown, nothing hidden | Honesty column + tiered/collapsed presentation |

The centerpiece is **active verification** — shifting from inferring to confirming.

## Data model

```python
@dataclass
class Evaluation:
    tier: str            # "confirmed" | "likely" | "lead" | "refuted"
    realness: int        # 0-100
    rationale: str       # one line: why this tier
    supporting: list[str]  # positive evidence
    against: list[str]     # caveats / unmet preconditions
    to_confirm: str        # the cheap next check that would raise to confirmed
```

`realness` starts from QoD, adjusted by evaluators. `tier` derived from final realness, except `refuted` which only a definitive disproof sets. Ranking: `severity × realness`.

## Preconditions become inputs, not gates

The `_v_*` functions encode real precondition knowledge. That knowledge is preserved — but output changes from a hard verdict to an evaluation contribution:

| Situation | Old | New |
|---|---|---|
| ZeroLogon on non-DC | dropped | `tier=lead`, low realness, "host not detected as DC" in against |
| Patched OpenSSH 9.8p1 | dropped | `tier=lead`, "version at/after fixed build" in against |
| NSE NOT VULNERABLE | dropped | `tier=refuted` — hard gate OK here |
| SeImpersonate, remote only | INCONCLUSIVE | `tier=lead`, "not confirmed on-target" |
| NSE ms17-010 VULNERABLE | CONFIRMED | `tier=confirmed`, realness 99 |

Each `_v_*` rewritten as an evaluator returning `{realness_delta, supporting[], against[], definitive_refute}`. Same precondition checks, different output shape.

## Controlling the FP flood without dropping

1. **Merge duplicates** — same CVE across sources/ports/hosts → one finding (biggest reducer)
2. **Tier + collapse** — confirmed/likely prominent; leads collapsed ("N leads to verify"); refuted hidden by default
3. **Rank by severity × realness** — low-realness leads sink
4. **Opt-in filters** (`--min-qod`, `--confirmed-only`) — tester's choice, never default

## End review (holistic pass)

- Cross-finding correlation (affected hosts roll-up, shared root cause)
- Contradiction check (conflicting findings flagged for human review)
- Completeness critic ("what did we NOT verify?" — surfacing `to_confirm` prompts)
- Honesty summary: `N confirmed · N likely · N leads · N refuted`

## Guardrails

- No real finding ever absent from the report (may be a demoted lead, never gone)
- Default view not drowned — confirmed/likely lead, leads collapsed, dupes merged
