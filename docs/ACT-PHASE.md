# The Act phase — "I found things, what do I DO?"

> Design + implementation plan. recce enumerates ("find"); the Act phase turns findings
> into a ranked, guided action plan. Read `docs/ARCHITECTURE.md` (QoD / honesty model)
> first — Act reuses its confidence tiers and the prove/verify loop.

## The idea: "found" is a loop, not a step

```
FIND ──▶ ACT ──▶ YIELD ──▶ (feeds back) ──▶ FIND …
         loot / crack / spray / exploit / escalate / pivot
```

A looted credential opens a new host → enumerate it → new findings → act again. The Act
phase orchestrates that loop honestly: it **auto-runs the read-only / reversible links**
and **guides the intrusive ones** (exact command, never auto-fired).

## Archetypes

Six **atomic** actions. The "chains" (loot→spray, AD→DA, foothold→escalate→pivot) are
leverage relationships *over* the atomics, captured by the `leverage` score factor —
not separate rankable items.

| Archetype | Trigger (finding/state) | Yields | Safety |
|---|---|---|---|
| **loot** | unauth service / exposure (Redis, DB trust/empty-pw, `.git`/`.env`/`.aws`, SMB null-session, NFS export, SNMP public, LDAP anon) | creds / data | read-only → auto |
| **crack** | a captured hash / roast | plaintext cred | offline → auto-queue |
| **spray** | a usable cred + a login surface | new access | reversible → auto-*plan* |
| **exploit** | KEV / high-sev vuln with an exploit | shell | intrusive → guide |
| **escalate** | a foothold (`access_gained`) | SYSTEM / root | on-target → guide |
| **pivot** | access on a multi-segment host | new scope | guide |

## Ranking — two levels, for explainability

The operator has to *trust* the order, so it's a coarse **tier** (what you can do now)
then a **score** within it:

**Tier** (primary sort): `AUTO` (read-only/reversible, ready) → `READY` (preconditions
met, you act now) → `BLOCKED` (needs a downstream yield first — shown as "unlocks
after …") → `LEAD` (confidence below *likely* — verify first).

**Score within a tier** = `impact × confidence × leverage`:
- **impact** (0–100, the yield value): DA 100 · domain-wide 90 · SYSTEM/root 70 ·
  user-shell 55 · plaintext-cred 45 · nthash 40 · hash 30 · sensitive-data 20 · info 5.
  `+15` KEV, `+0–10` scaled by EPSS. (These raise the *score*, not the access-level label.)
- **confidence** (from QoD): confirmed (≥95) 1.0 · likely (≥70) 0.75 · lead 0.4.
- **leverage** (chain multiplier, 1.0–2.0): `1 + min(1, unlocked_hosts/20 +
  unlocked_actions/10)`. A cred that sprays to many hosts, or any action on the path to
  DA, floats up — this is what makes "crack the one service account that's local-admin
  on 30 boxes" outrank a single-host shell.

Loot findings that share a command (`recce web --creds` loots *every* web host at once)
collapse into one card with a host count, so the plan lists **actions**, not duplicates.

## The command

```
recce act [-o ENG] [--host IP] [--only ARCHETYPE] [--top N]
```

Prints the plan grouped by tier: *recce can do these now · do now · unlocks next ·
verify first*. Each card shows the target, the exact command, the expected yield, the
preconditions, a one-line rationale (the ranking factors), and a `prove` line.

## Safety / honesty

Every card carries a safety class. `AUTO` is strictly read-only or reversible-plan
generation. Intrusive actions are **never** auto-fired — they're printed as guided
commands. An unproven action reads "candidate — verify" and points at `recce prove` /
`recce verify` (the existing honesty model).

## Roadmap

- **P1 — model + classifier + `recce act` (guidance-only).** ✅ Shipped. ActionCard,
  the six-archetype classifier, the tier/score ranking, loot aggregation, the
  credential-driven crack/spray/blocked cards, and the grouped CLI output.
- **P2 — auto-run the read-only links + feedback loop.** ✅ Shipped. `recce act --run`
  loots the flagged unauth services (read-only wire-protocol loot for DB trust/empty-pw
  and web `.git`/`.env`/`.aws`), persists new creds, and re-plans in a bounded loop, then
  (re)generates the lockout-safe spray plan from the accumulated cred set — so a looted
  cred surfaces a Spray card automatically. Scoped to hosts already carrying the matching
  loot finding (never a blind re-scan); intrusive actions are still guidance-only.
- **P3 — deepen guided cards + prove integration.** ✅ Shipped. Exploit cards carry the
  concrete PoC command from `exploitplan` (real msf/impacket line + prereq + the
  finding's verified flag) instead of a generic writeup; a synthesized **AD-path-to-DA
  keystone** card (from `attackpath`) leads the plan; unverified leads are flagged
  "candidate — verify". Also fixed classification precedence: a clear exploit (KEV / RCE
  hint) wins over a loot marker, so an *unauthenticated RCE* is an exploit, not a read.
- **P4 — `recce run --act` tail** so a full pipeline ends by auto-looting/spraying and
  printing the guided action plan.
