# Architecture & Redesign Plan

> **North star:** built for the tester in the field. Every change is judged by whether it makes the operator faster and more confident, airgapped in a terminal.
>
> **Top principle — a false negative is worse than a false positive.** Never hide a real finding. Confidence work (QoD) must label and sort, never hide by default. When in doubt, surface as a low-confidence lead.

## 1. The problem

No single source of truth for "is this finding real, and how sure are we?" That property is re-derived from raw tool strings in ~20 places. Every FP fix was a different module re-answering from substrings.

- Confidence/severity/verdict computed independently in 30+ modules
- Two contradictory definitions of "CONFIRMED" ship in one workbook (Exploitation says confirmed, Verification says likely — for the same finding)
- `likely` silently collapsed into `confirmed` everywhere except proofs
- proofs has no evidence to reason over — re-greps strings and guesses provenance
- Findings have no stable identity for dedup

The fix: compute confidence **once, at detection, from the detection method**, store as structured data, have every consumer read that one value.

## 2. SOTA models adopted

**OpenVAS QoD** — Quality of Detection (0–100) describing detection reliability, orthogonal to severity. Default `min_qod=70` hides low-confidence detections until the operator dials down.

**Nuclei** — data-driven YAML matchers with `negative: true` matchers. Low FP from compound AND of independent signals.

**Nessus** — KB gating (`script_require_keys`/`_ports`), paranoia dial, authenticated local checks ranked above remote banners.

**Version-range matching** — the backport trap. Distros backport fixes keeping the upstream version. Mark version-only findings as low confidence rather than asserting.

## 3. Target design

### 3.1 QoD confidence model

| QoD | Type | Detection method | Old confidence |
|---:|---|---|---|
| 100 | `exploit` | recce exploited / got unauth read | confirmed |
| 99 | `active_vuln` | NSE VULNERABLE, or recce negotiated the weak protocol | confirmed |
| 97 | `local_authenticated` | on-target ingest, credentialed/package fact | confirmed |
| 95 | `active_app` | live probe confirmed app/config | confirmed |
| 90 | `config_observed` | NSE weak-config observed (anon FTP, weak TLS) | confirmed |
| 80 | `remote_banner` | version-db with patch level, non-distro build | likely |
| 70 | `nmap_service` | -sV product/version match | likely |
| 50 | `inferred_port` | port-number label, no banner | potential |
| 30 | `banner_unreliable` | distro-backport or no patch level | potential |
| 1 | `general_note` | hygiene note | potential |

Two thresholds: `MIN_QOD_VISIBLE=70` (default report inclusion), `MIN_QOD_VERIFIED=95` (confirmed/exploitable bar). Both operator-dialable.

### 3.2 Evidence-carrying findings

```python
@dataclass
class Evidence:
    kind: str       # "nse" | "live-probe" | "version-range" | "on-target" | "config-observed"
    detail: str
    positive: bool  # True supports, False disproves
```

`Vuln` gains `qod`, `qod_type`, `evidence[]`. Dedup keyed on `(ip, port, primary_CVE_or_rule_id)` — multi-source duplicates collapse, keeping highest QoD + merged evidence.

### 3.3 proofs becomes a verifier

Shrinks from string-branching to: **promote** when positive evidence exists, **refute** when negative evidence exists, otherwise leave the detector's QoD and attach the safe finish-command.

### 3.4 Data-driven detection (Stage 6)

Signatures → Nuclei-style YAML matcher rules with negative matchers, each stamping its QoD tier. Detections become reviewable/versionable without touching Python.

## 4. Staged roadmap

| Stage | Win | Status |
|---|---|---|
| **0** | Stop the FP bleeding (tactical sweep) | Done |
| **1 — QoD spine** | Trust the default view; leads labeled, dialable; gates unified | Done |
| **2 — Dedup/correlation** | Hundreds → the handful of real issues | Next |
| **3 — Active verification** | Core low-FP capability; verify-don't-infer | — |
| **4 — Honest tiered presentation** | Signal never buried; honesty column | — |
| **5 — Offline EPSS/KEV** | Priority order, not a flat wall | — |
| **6 — Data-driven detection** | Tune checks without code; enables API-enum | — |
| **7 — Scan efficiency** | ~half scan time, zero coverage loss | — |
| **8 — Structural de-bloat** | Faster iteration; clean library core | — |

**Thesis:** active verification (confirming vs. inferring) + dedup (making results readable) are the priority.

## 5. Stage 1 detail

**1a — QoD foundation (shipped):** `models.Vuln` gains `qod`/`qod_type`. `recce/qod.py` implements the tier table with `score()`, `is_visible()`, `is_verified()`, `annotate()`. Four divergent `confidence != "potential"` gates unified to read the one QoD authority.

**1b — Honesty loop re-plan:** preconditions (ZeroLogon→DC-only, BlueKeep→OS, patched-version→FP) preserved as evaluators that contribute to assessments rather than gate/drop. Hard gates only for definitive disproofs. Honesty column carries confidence + reasoning. Non-verified exploitation actions labeled "candidate — verify".
