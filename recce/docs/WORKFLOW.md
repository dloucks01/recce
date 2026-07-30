# Operator Workflow & Experience — design + implementation plan

> Make the *journey* through recce as good as the results. The accuracy work (QoD /
> dedup / verification) makes findings trustworthy; this makes the tool feel like **one
> smooth thing** instead of 44 subcommands you have to sequence by hand. Read
> `docs/ARCHITECTURE.md` (north star) first.

## The problem (from the operator-experience review)

recce today is a set of **sharp, resilient tools** but not yet a smooth **workflow**. The
plumbing is healthy — it rarely crashes, it resumes, it degrades gracefully. The
*connective tissue* is weak:

- **44 subcommands**, no obvious core path — a fresh tester faces a wall and must *know* the
  sequence (`scan` → then `db`? `web`? `credenum`? `mssql`? in what order?).
- **`scan` only does enum+vuln.** Everything after (db, credenum, web, screenshots,
  service-specific enum, privesc) is a separate manual step you have to remember.
- **Next-step guidance is inconsistent and non-adaptive** — some commands suggest a next
  step, most don't, and none compute "the single most valuable thing to do *given what I
  just found*."
- **No ambient "you are here"** — you must run `status` and interpret a progress bar.
- **Recovery isn't offered** — failures rarely dead-end (great), but the tool doesn't end
  with the exact re-run/resume command, so recovery is something you must know.
- **Every command fully regenerates the report** — quick section-commands feel heavy.

The good news: recce already stores everything this needs — per-host progress flags
(`enumerated`, `vuln_scanned`, `db_scanned`, `privesc_checked`, `cred_enumerated`,
`access_gained`), open ports/services, captured creds, and a `_DEFER_REPORTS` toggle. This
is an **orchestration + guidance layer over existing state**, not new machinery.

## Principles

1. **One obvious path; surgical tools remain.** A default command does the right thing; the
   44 stay for precision use.
2. **Adaptive** — recce runs the right next phase based on *what it found* (SMB→credenum,
   web→screenshots, MSSQL→mssql, DC→AD enum).
3. **Idempotent + resumable** — re-run anything; it skips what's done and picks up the rest.
4. **Recovery-first** — no silent dead ends; every failure ends with the exact next command.
5. **Ambient guidance** — always know where you are and the single best next move.
6. **North-star safe** — orchestration surfaces everything; active/credentialed/aggressive
   steps stay opt-in. Never hides a finding, never auto-sends intrusive traffic.

## Acceptance tests (what "smooth" means — the scenarios)

| Scenario | Smooth means | Verified when |
|---|---|---|
| **End-to-end, fresh** | `recce run <targets> -o eng` → a complete engagement + report, no other command needed | one command produces the full deliverable |
| **Come in partway** | `recce status -o eng` states exactly where it stands + the next 1–3 commands | status ends with ranked next actions |
| **A section here/there** | any single command is fast and ends with the next best action | report deferred; every command prints "→ Next" |
| **Failure at the start** | the run continues where it can; every failure ends with the exact recovery command; re-running resumes | `run` re-run skips done work, retries only what failed |

## Designs

### 1. `recce run` — the adaptive orchestrator (the biggest lever)

One command that runs the full adaptive pipeline by **coordinating the existing phase/
command functions** (not rewriting them). A declarative **phase plan**; each phase has a
*trigger* (does the current state call for it?) and a *done-check* (has it already run?),
so `run` is idempotent and resumable.

```python
# recce/workflow.py
@dataclass
class Phase:
    name: str
    run: Callable            # existing _phase_enum / cmd_web / _phase_db / ...
    trigger: Callable        # (hosts, creds) -> bool  : is this phase warranted?
    done: Callable           # (hosts) -> bool         : already complete? (skip)
    needs_creds: bool = False
    active: bool = False     # sends new/heavier traffic -> honor --safe / gates

PLAN = [
  Phase("discover+enum", _phase_enum,  trigger=always,                 done=all_enumerated),
  Phase("vulns",         _phase_vulns, trigger=any_open_ports,         done=all_vuln_scanned),
  Phase("web",           run_web,      trigger=any(is_web),            done=all_web_shot, active=True),
  Phase("mssql",         run_mssql,    trigger=any(port==1433),        done=…),
  Phase("ad+ldap",       run_ad,       trigger=any(role=="DC"),        done=…),
  Phase("credenum",      _phase_cred,  trigger=any(smb/winrm),         done=all_cred_enum, needs_creds=True),
  Phase("db",            _phase_db,    trigger=any(db_port),           done=all_db_scanned),
  Phase("privesc",       _phase_priv,  trigger=any(access_gained|smb), done=all_priv_checked),
  Phase("report",        _final,       trigger=always,                 done=never),
]
```

Behavior:
- Evaluate each phase's trigger against current store state; **skip** anything `done`; run the
  rest in order. Re-running `recce run` after an interrupt just continues.
- **Defer the report** (`_DEFER_REPORTS=True`) through the phases and generate it **once** at
  the end — no O(phases) rebuild. (Already-supported toggle.)
- **Per-phase failure isolation**: a phase that errors is logged as a scan issue and the run
  **continues**; the end-of-run summary lists what failed + the retry command. (Per-host
  isolation already exists; this extends it to phases.)
- **Opt-in gates**: `needs_creds` phases run only when creds are supplied; `active` phases
  honor `--safe`/`--no-active`; aggressive stays behind `--aggressive`. No surprise traffic.
- The 44 subcommands are unchanged — `run` calls them. Low risk, high payoff.

### 2. Next-best-action engine

A pure function over state that returns ranked, actionable suggestions — the ambient
guidance layer.

```python
# recce/workflow.py
@dataclass
class Action:
    priority: int      # lower = more valuable now
    label: str         # "6 web hosts not screenshotted"
    command: str       # "recce web -o eng"
    why: str           # "capture evidence + find login panels"

def next_actions(hosts, creds, tracking, meta) -> list[Action]: ...
```

Rules (data), evaluated against store state, e.g.:
- no hosts scanned → `recce run <targets> -o eng`
- open ports but not vuln-scanned → `recce vulns`
- web ports not screenshotted → `recce web`
- creds captured, not sprayed → `recce credsweep`
- DB ports not `db_scanned` → `recce db`
- foothold gained, not privesc-checked → `recce privesc`
- findings exist, report stale → `recce report`
- all done → "review Exploitation/Attack-Path tabs; `recce writeup <id>`"

Consumed by: the **end of every major command** (echo the top action as "→ Next: …"),
**`status`** (show the ranked list), and a new **`recce next -o eng`** (just prints them).

### 3. Recovery-first failure model

- A shared `fail(command, why, recovery)` helper: every error path prints a one-line *what*,
  a one-line *why* (classified), and the **exact recovery command** — usually
  `recce <cmd> --resume -o eng`. `--resume` becomes the visible recovery verb everywhere.
- `run` ends with a summary: phases OK / phases failed + the one command to retry just the
  failures. Nothing dead-ends silently.
- Ctrl-C already saves partial results; make it also print the resume command.

### 4. Progressive disclosure

- Group the 44 subcommands in `--help`: a tiny **Core path** (`run`, `status`, `report`,
  `next`) shown first; **Surgical** (per-service, ingest, deploy, …) grouped below.
- Bare `recce` / `recce -h` opens with a 3-line quickstart: `run` → `status` → `report`.
- Synergizes with Stage 8's declarative argspec (the command table lives there).

### 5. Report smoothness

- Immediate win: `run` defers the report to the end (above).
- Full fix: incremental/dirty-flag report regen — **shared with Stage 7 (scan efficiency)**;
  cross-referenced, not duplicated.

## Implementation plan (slices, safe/high-value first)

| Slice | Status | Scope | Files | Tests | Risk | Fixes scenario |
|---|---|---|---|---|---|---|
| **W1 — Next-best-action engine** | ✅ **shipped (PR #41)** | `next_actions()` + `Action`; echo top action at end of `enum`/`vulns`/`run`; new `recce next` | `recce/workflow.py`, `cli.py` | `tests/test_next_actions.py` (rules over synthetic state) | low (read-only) | come-in-partway, section |
| **W2 — `recce run`** | ✅ **shipped (PR #41)** | one front door coordinating the existing phases (`scan --deep` + `credsweep`): discover→enum→vulns→deep modules (+ auth when creds) → report; adaptive/resumable; report deferred to the sweep's single pass | `recce/workflow.py`, `cli.py` (new `run` cmd) | orchestration test (deep forced, auth-sweep only with creds) | med (coordination only, no scan logic changed) | end-to-end |
| **W3 — Recovery-first failures** | ◀︎ next | shared `fail()` helper; surface `--resume`; `run` end-of-run retry summary | `cli.py`, phase callers | failure paths end with recovery cmd | low–med | failure-at-start |
| **W4 — Progressive disclosure** | planned | help grouping (core vs surgical); quickstart on bare invocation | `cli.py` argparse / argspec | help lists core path first | low | discoverability |
| **W5 — Report smoothness** | partial | `run` already defers to the sweep's single pass; full incremental regen = Stage 7 (scan efficiency) | — | — | — | section speed |

Each slice ships independently, green, tool usable throughout — same discipline as the
accuracy stages. **W1** (ambient next-best-action) was a large perceived-smoothness win for
near-zero risk; **W2 (`recce run`)** is the headline — recce now feels like one tool.

> **Implementation note (as-built):** W2 was built as a thin front door over the *existing*
> `scan --deep` + `_run_sweep`/`credsweep` machinery (which already does adaptive,
> self-skipping deep modules with a deferred single-pass report and per-module failure
> isolation) rather than a new `Phase`/`PLAN` engine. Same behavior, far less new code and
> risk. A declarative phase plan can still replace the coordinator later if it earns its
> keep, but the front-door + guidance is what the tester feels, and that's shipped.

## Roadmap placement

Slot as a first-class **Workflow / operator-experience** track, ranked **high — alongside
the accuracy work**. Rationale: "do I trust it" (accuracy) and "does it feel good to move
through" (workflow) are the two things that decide whether a tester reaches for recce next
engagement. Suggested interleave: land the current accuracy stack → **W1 + W2** (immediate
felt improvement) → resume accuracy (verification 3c, presentation) → W3/W4 → efficiency
(which subsumes W5).
