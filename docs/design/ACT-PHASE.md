# Act Phase

Turns findings into a ranked, guided action plan. Orchestrates the find→act→yield→find loop honestly: auto-runs read-only/reversible links, guides intrusive ones (exact command, never auto-fired).

## Archetypes

Six atomic actions. Chains (loot→spray, AD→DA, foothold→escalate→pivot) are leverage relationships captured by the `leverage` score factor.

| Archetype | Trigger | Yields | Safety |
|---|---|---|---|
| **loot** | unauth service / exposure (Redis, DB trust, `.git`/`.env`, SMB null, NFS, SNMP public) | creds / data | read-only → auto |
| **crack** | captured hash / roast | plaintext cred | offline → auto-queue |
| **spray** | usable cred + login surface | new access | reversible → auto-plan |
| **exploit** | KEV / high-sev vuln with exploit | shell | intrusive → guide |
| **escalate** | foothold (`access_gained`) | SYSTEM / root | on-target → guide |
| **pivot** | access on multi-segment host | new scope | guide |

## Ranking

**Tier** (primary): `AUTO` (read-only, ready) → `READY` (preconditions met) → `BLOCKED` (needs a yield first) → `LEAD` (verify first).

**Score** within tier = `impact × confidence × leverage`:
- **impact** (0–100): DA 100, domain-wide 90, SYSTEM/root 70, user-shell 55, plaintext-cred 45, etc. +15 KEV, +0–10 EPSS.
- **confidence**: confirmed 1.0, likely 0.75, lead 0.4.
- **leverage** (1.0–2.0): `1 + min(1, unlocked_hosts/20 + unlocked_actions/10)`. A cred that sprays to many hosts floats up.

Findings sharing a command collapse into one card with a host count.

## Command

```
recce act [-o ENG] [--host IP] [--only ARCHETYPE] [--top N]
```

Cards grouped by tier, each showing: target, exact command, expected yield, preconditions, rationale, `prove` line.

## Shipped

- **P1** — model + classifier + `recce act` (guidance-only)
- **P2** — `recce act --run` auto-loots read-only services, persists creds, re-plans in bounded loop, generates spray plan
- **P3** — exploit cards carry concrete PoC from `exploitplan`, AD-path-to-DA keystone card, unverified leads flagged "candidate — verify"
- **P4** — `recce run --act` tail: auto-loot, refresh spray plan, print top-3 ranked moves
