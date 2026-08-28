# Operator Workflow

Make the journey smooth, not just the results. The tool should feel like one thing, not 44 subcommands you sequence by hand.

## The problem

- 44 subcommands, no obvious core path
- `scan` only does enum+vuln; everything after is manual
- No ambient "you are here"; inconsistent next-step guidance
- Failures don't offer exact recovery commands
- Every command fully regenerates the report

recce already stores everything this needs (per-host progress, open ports, captured creds, `_DEFER_REPORTS`). This is orchestration over existing state.

## Principles

1. One obvious path; surgical tools remain accessible
2. Adaptive — next phase based on what was found
3. Idempotent + resumable
4. Recovery-first — every failure ends with the exact retry command
5. Ambient guidance — always show location and best next move
6. Safe — active/credentialed/aggressive steps stay opt-in

## Designs

### 1. `recce run` — adaptive orchestrator

One command running the full pipeline via existing phase functions. Declarative phase plan with triggers and done-checks makes `run` idempotent and resumable. Defers report to a single end pass. Per-phase failure isolation: errors logged, run continues, end summary lists failures + retry commands. Opt-in gates: cred phases need creds, active phases honor `--safe`, aggressive behind `--aggressive`.

**As-built:** thin front door over existing `scan --deep` + `_run_sweep`/`credsweep` rather than a new Phase engine.

### 2. Next-best-action engine

Pure function over state returning ranked suggestions:
- No hosts scanned -> `recce run <targets>`
- Open ports not vuln-scanned -> `recce vulns`
- Web ports not screenshotted -> `recce web`
- Creds captured, not sprayed -> `recce credsweep`
- All done -> "review Exploitation/Attack-Path tabs"

Consumed by: end of every major command ("-> Next: ..."), `status`, and `recce next`.

### 3. Recovery-first failures

Shared `fail()` helper: every error prints what happened, why, and the exact recovery command. `run` ends with phases OK / phases failed + retry.

### 4. Progressive disclosure

Help grouped: tiny core path (`run`, `status`, `report`, `next`) shown first; surgical commands below. Bare `recce` opens with a 3-line quickstart.

## Status

| Slice | Status |
|---|---|
| W1 — Next-best-action engine | Shipped |
| W2 — `recce run` | Shipped |
| W3 — Recovery-first failures | Shipped |
| W4 — Progressive disclosure | Shipped |
| W5 — Report smoothness (incremental regen) | Partial (deferred to scan efficiency stage) |
