# The Evaluation & Honesty Loop (proofs re-plan)

> Spec for replacing recce's verdict engine. Prioritized ahead of the scan-speed stage.
> Read `docs/ARCHITECTURE.md` first for the QoD model and the north star.

## The two failure modes (both make recce useless)

1. **False negative** — a real finding is hidden, dropped, or gated away. The tester
   misses the thing that gets them in. **This is the worse one.**
2. **False positives at scale** — hundreds of unranked leads. The tester can't find the
   signal in the noise, so they stop trusting (and using) the tool.

A design that only avoids (1) produces (2); a design that only avoids (2) causes (1). The
old `_v_*` verdict engine leaned toward (2)-avoidance with **hard gates** that silently
dropped findings — which risks (1). The honesty loop must beat **both at once.**

## The core idea: don't choose hide-vs-show — ORGANIZE by honest confidence

**Never drop a possibly-real finding. Never present noise as equal to signal.** Achieve
both by *ranking and grouping*, not gating:

- Every finding is **surfaced**, always.
- Each carries an **honest realness assessment** (a confidence + the reasoning).
- The report **leads with high-confidence findings**; low-confidence leads are **demoted
  and collapsed** (one expand away), never intermixed as equal rows.
- **Duplicates are merged** so the same issue across ports/sources/hosts is ONE ranked
  finding — this is what turns "hundreds of FPs" back into the handful of real issues.
- A **hard gate fires only for a definitive disproof** (NSE says NOT VULNERABLE; a live
  re-probe refuses auth). Everything else is evaluated and shown.

## Data model

```python
@dataclass
class Evaluation:
    tier: str            # "confirmed" | "likely" | "lead" | "refuted"
    realness: int        # 0-100: how likely the finding is actually real & exploitable
    rationale: str       # one line: why this tier (human-readable, evidence-based)
    supporting: list[str]  # what backs it (positive evidence, an NSE VULNERABLE, a live read)
    against: list[str]     # caveats / unmet preconditions / what argues against it
    to_confirm: str        # the exact cheap next check that would raise it to confirmed
```

`realness` starts from the finding's **QoD** (`recce/qod.py`) and is then adjusted by the
finding's evaluators (below). `tier` is derived from the final realness, except `refuted`
which only a definitive disproof sets. QoD stays orthogonal to **severity** (CVSS) — a
finding is ranked by `severity × realness`, so a critical-severity low-realness lead sorts
*below* a high-realness high-severity confirmed finding, but is still shown.

## Preconditions become inputs, not gates (this is the whole fix)

The `_v_*` functions we almost deleted encode real precondition knowledge (ZeroLogon needs
a DC, BlueKeep needs old Windows, a version must be in range, SeImpersonate needs local
confirmation). **That knowledge is preserved — but its OUTPUT changes** from a hard verdict
to an evaluation contribution:

| Situation | Old (hard gate) | New (honesty loop) |
|---|---|---|
| ZeroLogon on a non-DC | `FALSE_POSITIVE` (dropped) | `tier=lead`, realness low, `against=["host not detected as a DC; ZeroLogon only affects DCs — likely a misfire, but role detection can be wrong"]`, sorted to the bottom of a collapsed leads group. **Shown, not dropped** — so a mis-detected DC isn't a false negative. |
| Patched OpenSSH 9.8p1 flagged regreSSHion | `FALSE_POSITIVE` | `tier=lead`, realness low, `against=["version 9.8p1 is at/after the fixed build"]`, `to_confirm="confirm the distro package build"`. |
| NSE reports NOT VULNERABLE | `FALSE_POSITIVE` | `tier=refuted` — **a hard gate is OK here**: a check actively disproved it. Hidden by default, available with `--show-refuted`. |
| SeImpersonate, remote inference only | `INCONCLUSIVE` | `tier=lead`, `against=["not confirmed on-target"]`, `to_confirm="run recce-enum on the host to read token privileges"`. |
| NSE ms17-010 VULNERABLE | `CONFIRMED` | `tier=confirmed`, realness 99, `supporting=["NSE smb-vuln-ms17-010 reported VULNERABLE"]`. |

Each `_v_*` is rewritten as an **evaluator** `evaluate(host, port, finding) -> EvalDelta`
that returns `{realness_delta, supporting[], against[], definitive_refute: bool}`. It keeps
every precondition check it has today; it just contributes to the assessment instead of
deciding it. Deleting them was the mistake — reusing them as evaluators is the design.

## Controlling the FP flood — without dropping anything

Four levers, in priority order (all preserve every finding):

1. **Merge duplicates (dedup/correlation — Stage 2).** The biggest reducer. The same CVE
   from version-db + NSE + probe, or across ports/hosts, collapses to ONE finding keyed by
   `(issue-identity)`, keeping the highest realness + the union of evidence. "Hundreds" is
   usually duplicates + version-noise; this alone cuts the count by a large factor. **Merge
   must never drop a *distinct* finding** — only fold true duplicates.
2. **Tier + collapse in the report.** Confirmed and Likely are prominent; **Leads render as
   a collapsed group** ("N version-based leads to verify") the tester expands on demand;
   **Refuted is hidden by default** (`--show-refuted`). Signal is never buried under leads.
3. **Rank by `severity × realness`.** Low-realness leads sink to the bottom of their group.
4. **Opt-in filters** (`--min-qod`, a `--leads`/`--confirmed-only` view). The tester's
   choice, never the default — the default shows everything.

Net effect: a scope that produces 300 raw matches shows, by default, (say) 8 confirmed +
15 likely up top and a collapsed "120 leads to verify" the tester opens if they want — no
finding lost, no noise drowning the signal.

## The end review (holistic pass, after per-finding evaluation)

A final pass over the whole result set — this is the "review & evaluation" the tester
asked for, and it's where the completeness-critic / adversarial-verify patterns live:

- **Cross-finding correlation:** same CVE across hosts (an "affected hosts" roll-up);
  shared-root-cause (one OpenSSL/library flaw → one issue, N locations).
- **Contradiction check:** two findings that disagree (e.g. "SMB signing not required" vs
  "required" on one host) get flagged for human review instead of both shown as fact.
- **Completeness critic:** "what did we NOT verify?" — a lead that a single cheap check
  would confirm gets its `to_confirm` surfaced as a prompt, so the tester knows the
  one command that turns 15 leads into confirmed/refuted.
- **Honesty summary:** `N confirmed · N likely · N leads · N refuted`, plus the count of
  findings still unverified — so the tester sees the *shape of the trust* at a glance.

## Report surface: the honesty column

Every verdict row carries its reasoning, so "confirmed" always shows **why** and a lead
states plainly **what's unverified**:

| Finding | Tier | Realness | Why (rationale) | Caveats / against | To confirm |
|---|---|---|---|---|---|

This replaces the current Verification sheet's opaque verdict with a transparent one, and
it's the same data the Exploitation sheet reads to label a non-confirmed action
**candidate — verify** (the fix for the two-definitions-of-CONFIRMED contradiction).

## Migration (safe, incremental, coverage-first)

1. **`evidence[]` foundation** — PR #34 (already open). The evaluators read it.
2. **`Evaluation` model + `evaluate_host()`** alongside the existing `verify_host()`; port
   the `_v_*` bodies to evaluators (reuse their precondition logic; change only the return).
   Keep `verify_host()` working until parity is proven.
3. **Tiering + collapse in the report**; add the honesty column; wire Exploitation labels.
4. **End-review pass** (dedup hooks land with Stage 2; correlation + completeness + summary).
5. **Retire `verify_host()`** once `evaluate_host()` is at parity and the report reads tiers.

**Regression contract:** the current `ProofEngineTest` cases encode the precondition
knowledge (ZeroLogon-on-member, BlueKeep-OS, patched-version, SMB-signing, SeImpersonate-
remote). Under the new model their *verdicts change shape* (member ZeroLogon: `FALSE_POSITIVE`
→ `lead` with a strong `against`), so they get **rebaselined to assert the new tier +
that the finding is still surfaced** — never dropped. `test_qod.py` / `test_fp_sweep.py`
/ `test_false_positives.py` stay green (evidence is additive).

## Guardrail (the acceptance test for this whole design)

Two properties must hold, always:
- **No real finding is ever absent** from the report (it may be a demoted lead, never gone).
- **The default view is not drowned** — confirmed/likely lead; leads are collapsed; dupes
  merged. A tester scanning a /24 sees the real issues first, on one screen.
