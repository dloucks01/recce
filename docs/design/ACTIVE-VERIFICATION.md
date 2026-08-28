# Active Verification (Stage 3)

Verify findings by re-probing the live service instead of inferring from banners. This is recce's core accuracy edge — it can't phone home, so verify-by-probe is how it earns trust.

## Why

Banner/version scanners infer ("version in affected range → probably vulnerable"). Low-FP scanners confirm (Nessus authenticated checks, Nuclei active matchers, OpenVAS `remote_active`). Verification does both jobs: **confirm** a lead (promote to CONFIRMED with real evidence) or **refute** it (mark disproved, hide from default view).

## Traffic tiers

| Tier | Examples | Default |
|---|---|---|
| **A — safe, read-only** | re-grab a banner; existing probes (redis `PING`/`INFO`, ftp `USER anonymous`, http `GET`, smb2 NEGOTIATE) | auto-run |
| **B — safe detection** | curated vuln detectors already in the vulns phase (`smb-vuln-ms17-010`, `ssl-heartbleed`) — probe but don't exploit | auto-run (reused for verification) |
| **C — intrusive** | actual exploit, brute force, DoS-risky NSE | operator-gated (`--aggressive` / explicit `recce verify --run`) |

**Rule: verification never sends traffic more intrusive than the detection that raised the lead.**

## Architecture

### 1. Verification registry (data)

Maps a lead (by CVE or product/rule) to its safe confirming check:

```python
{"cve": "CVE-2017-0143", "confirm": {"nse": "smb-vuln-ms17-010",
                                     "positive": "VULNERABLE", "negative": "NOT VULNERABLE"}},
```

Entries are Tier-A/B only. Each specifies the exact signal that promotes (positive) or refutes (negative).

### 2. Correlation-first verification (no new traffic)

Before running anything, harvest what recce already collected. The vulns phase already runs Tier-B detectors; dedup merges a same-CVE `VULNERABLE` into the lead → CONFIRMED. The missing half: **refutation** — an NSE `NOT VULNERABLE` result was previously dropped. Now it's recorded as negative evidence and refutes same-CVE leads. Pure FP removal, zero new traffic.

### 3. Targeted re-verification (opt-in new traffic)

`recce verify [-o eng] [--run]`: for every lead with a registry entry whose check hasn't run, run just that check against just that host/port (Tier-A/B), then re-correlate. `--run` is required to send traffic; without it, `verify` is a dry-run.

## Result flow

- **positive** → evidence added, QoD → 95–99, tier CONFIRMED
- **negative** → evidence added, tier **refuted** (hidden by default, shown with `--show-refuted`, never deleted)
- **inconclusive** → lead unchanged, no invented verdict

## Guardrails

- Never exceed the raising detection's tier
- One targeted check per lead, per host, bounded by `--host-timeout`
- Refute only on definitive negatives, never on absence/timeout
- Never drop — refute (raw row stays in datastore)
- `recce verify` without `--run` sends nothing

## Implementation slices

1. **3a** — refutation from already-collected results (parse negative NSE, refute same-CVE leads, zero traffic)
2. **3b** — verification registry + confirm/refute correlation
3. **3c** — `recce verify --run` for targeted Tier-A/B re-checks
4. **3d** — verification column in the report (confirmed-by / refuted-by / to-confirm)
