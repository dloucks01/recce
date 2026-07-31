# Active Verification — verify, don't infer (SOTA roadmap Stage 3)

> The capability that most improves accuracy and plays to recce's offline edge. Read
> `docs/ARCHITECTURE.md` (QoD model) and `docs/PROOFS-HONESTY-LOOP.md` first.

## Why this is the core capability

Banner/version scanners are inherently high-FP because they **infer** ("the version is in
the affected range, so it's probably vulnerable"). The scanners with the fewest false
positives **confirm** — Nessus authenticated local checks, Nuclei active matchers + OOB
callbacks, OpenVAS `remote_active`. Airgapped recce can't phone home to vulners/NVD, so its
edge *is* verification-by-probe: it re-checks a lead against the live service and reports
**what it actually observed**, not what a version string implies.

Verification does both jobs at once:
- **Confirm** a lead → promote to CONFIRMED with real evidence (QoD → 95–99).
- **Refute** a lead → a check disproved it → mark refuted (drop below the default view).

A finding recce actually re-checked beats any passively-computed rationale.

## The ROE question: what auto-runs vs. what's gated

recce runs against client production. New active traffic must be **deliberate**. Three
tiers:

| Tier | Examples | Default |
|---|---|---|
| **A — safe, read-only** | re-grab a banner; recce's existing service probes (redis `PING`/`INFO`, ftp `USER anonymous`, http `GET`, smb2 NEGOTIATE, snmp GET); nmap `--script safe` detections that only READ (`ssl-cert`, `http-title`) | **auto-run** |
| **B — safe detection, not "safe"-tagged** | the curated non-intrusive vuln DETECTORS recce already runs in the vulns phase (`smb-vuln-ms17-010`, `ssl-heartbleed` detection, `ftp-vsftpd-backdoor` check) — they probe but do not exploit | **auto-run in the vulns phase (already happens); reused for verification** |
| **C — intrusive / weaponizing** | actual exploit, brute force, DoS-risky NSE (`http-slowloris`), the recipe `finish` PoCs | **operator-gated** — only under `--aggressive` / an explicit `recce verify --run`, never automatic |

Guiding rule: **verification never sends traffic more intrusive than the detection that
raised the lead.** Confirming a version-db lead uses a Tier-A/B check, never a Tier-C
exploit. Tier-C stays in the operator's hands (recce already gates it behind `--aggressive`).

## Architecture

Three parts, smallest/safest first:

### 1. Verification registry (data) — lead → its confirming signal
A table mapping a lead (by CVE, else product/rule) to the **safe** check that confirms or
refutes it and how to read the result:

```python
# recce/verify_rules.py  (data, Nuclei-matcher-style)
{"cve": "CVE-2017-0143", "confirm": {"nse": "smb-vuln-ms17-010",
                                     "positive": "VULNERABLE", "negative": "NOT VULNERABLE"}},
{"cve": "CVE-2014-0160", "confirm": {"nse": "ssl-heartbleed",
                                     "positive": "VULNERABLE", "negative": "NOT VULNERABLE"}},
{"product": "redis", "issue": "unauth", "confirm": {"probe": "redis.probe",
                                     "positive": "unauth", "negative": "NOAUTH"}},
```

The registry entries are Tier-A/B only. Each says the exact signal that promotes (positive)
or refutes (negative) — this is the honesty loop's `to_confirm` made executable.

### 2. Correlation-first verification (no NEW traffic) — the safe first slice
Before running anything, **harvest what recce already collected this run**. The vulns phase
already runs the Tier-B detectors; dedup (Stage 2) already merges a same-CVE NSE VULNERABLE
into the lead → CONFIRMED. The missing half is **refutation**: today an NSE `NOT VULNERABLE`
result is *dropped* by the parser, so a lead nmap already disproved silently survives as a
QoD-80 lead.

Slice 3a records the **negative** result as evidence (`Evidence(kind="nse", positive=False)`
— the `evidence[]` foundation, PR #34) and the verifier refutes any lead whose CVE has a
negative check on the same host. **Pure FP removal, zero new traffic** — recce already ran
the check; we just stop ignoring the "it's patched" answer.

### 3. Targeted re-verification (new Tier-A/B traffic) — opt-in
`recce verify [-o eng] [--run]`: for every current lead with a registry entry whose
confirming check did NOT already run, run just that check against just that host/port
(bounded, Tier-A/B), then re-correlate → promote/refute. Explicit command = ROE-deliberate.
`--run` is required for any Tier that sends traffic; without it, `verify` only reports which
leads *could* be confirmed and the exact command (dry-run / the honesty loop's `to_confirm`).

## How results flow

A verification outcome updates the finding's QoD + evidence, then dedup/QoD/presentation do
the rest:
- **positive** → `evidence += Evidence(kind="live-probe"/"nse", positive=True)`; QoD → 95–99;
  tier CONFIRMED.
- **negative** → `evidence += Evidence(..., positive=False)`; tier **refuted** (a *definitive*
  disproof — the one place a hard gate is correct); hidden by default, shown with
  `--show-refuted`, never silently deleted.
- **could-not-run / inconclusive** → lead unchanged (stays a labeled lead). Never invents a
  verdict.

## Composition

- **Stage 2 dedup** already merges a lead + its positive confirmation → this adds the
  negative (refute) half and the on-demand re-check.
- **QoD** consumes the promoted/refuted score; **presentation** (Stage 4) tiers it.
- **Honesty loop**: verification is the mechanism that makes "evaluate realness" real —
  a re-checked finding, not a rationale string.

## Guardrails

- Never send traffic more intrusive than the raising detection (Tier ceiling).
- Bounded: one targeted check per lead, per host, with the existing `--host-timeout`.
- Refute only on a *definitive* negative (an actual check result), never on absence/timeout.
- **Never drop — refute.** A refuted finding is hidden-by-default, not deleted; the raw row
  stays in the datastore and `--show-refuted` surfaces it. (North star: no false negatives.)
- `recce verify` without `--run` sends nothing — it plans.

## Implementation slices (safe-first)

1. **3a — refutation from already-collected results** (needs `evidence[]`, PR #34): parser
   records NSE `NOT VULNERABLE` as negative evidence; verifier refutes same-CVE leads. No new
   traffic. Biggest safe FP win.
2. **3b — verification registry** (`verify_rules.py`) + the confirm/refute correlation over
   existing findings.
3. **3c — `recce verify --run`**: targeted Tier-A/B re-checks for leads not yet confirmed.
4. **3d — report**: verification column (confirmed-by / refuted-by / to-confirm), feeding the
   honesty column.
