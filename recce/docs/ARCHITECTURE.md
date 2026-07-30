# recce architecture & redesign plan

> **North star:** recce is built for the *tester in the field*. Every change is judged
> by whether it makes the operator **faster** and **more confident**, working airgapped
> in a terminal on a client engagement — not by code cleanliness for its own sake. Bloat
> cuts and efficiency work must never cost field capability; they remove friction and
> latency only.
>
> **TOP PRINCIPLE — a false NEGATIVE is worse than a false positive.** Never hide or
> block a real finding. Confidence work (QoD) must **label and sort**, never **hide by
> default**: the report shows everything, and filtering (`--min-qod`) is strictly opt-in.
> When in doubt, surface the finding as a low-confidence lead rather than drop it. This is
> why the aggressive `proofs` rewrite was **dropped** (2026-07-29): deleting the per-type
> precondition gates (ZeroLogon→DC-only, BlueKeep→OS-gated, patched-version→FP, SMB-signing
> -required→FP) would have turned real findings into missed ones. Those gates are accuracy,
> not bloat. The `proofs`/evidence design is to be **re-planned from scratch** under this
> principle before any rewrite — the FP over-claiming it was meant to fix is already handled
> by the QoD gate (PR #31/#32).

This document is the durable plan for the accuracy-first re-architecture. It captures the
root-cause problem, the proven external models we're adopting, the target design, and a
staged roadmap where every stage ships independently with the tool usable throughout.

---

## 1. The problem (why false positives keep recurring)

**There is no single source of truth for "is this finding real, and how sure are we?"**
That property is *re-derived on read* from raw tool strings in ~20 places across the
codebase. Every false positive fixed so far was a *different* module re-answering that
question from substrings.

Concretely (from the lifecycle audit):

- **Confidence/severity/verdict/"proven" are computed independently in 30+ modules.**
  `parser._classify_vuln` decides vuln-or-not from substrings; `vulndb._confidence`
  grades potential/likely from the signature shape; `proofs.py` (1,268 LOC) *re-adjudicates*
  CONFIRMED/LIKELY from the finding's **title text**; `exploitref`/`exploitplan`/
  `report_excel`/`report_docx` each re-gate "proven" with their own predicate.
- **Two contradictory definitions of "CONFIRMED" ship in one workbook.** The Exploitation
  sheet, attack path, PoC, playbook and netmap overlay gate on
  `confidence != "potential"` (`exploitplan.py:119`, `poc.py`, `playbook.py`, `netmap.py`),
  so a *version-db "likely"* match generates a full Metasploit plan — while the
  Verification sheet, driven by the proofs verdict, correctly holds the **same finding** at
  LIKELY ("backport-check first"). The report simultaneously says "confirmed, here's the
  module" and "likely, verify first" for one finding. **This is the #1 FP engine.**
- **`likely` is silently collapsed into `confirmed` everywhere except proofs.** vulndb
  distinguishes potential/likely/confirmed, but every downstream `!= "potential"` gate
  treats likely == confirmed, so an unverified version inference drives exploitation
  artifacts.
- **proofs has no evidence to reason over**, so it re-greps `VULNERABLE`/access phrasing
  from strings and guesses provenance (its only structured signal is `source=="version-db"`).
  A finding never carries *how* it was established.
- **Findings have no stable identity.** `Vuln.key = ip:port:script_id:title[:60]` means the
  same real issue from two sources never dedups (inflated counts) and truncated titles can
  collide distinct issues.

The fix is **not** more string-sniffing. It is to compute confidence **once, at detection,
from the detection method**, store it as structured data, and have every consumer read that
one value.

---

## 2. What state-of-the-art scanners do (the models we adopt)

From the SOTA research (Nuclei, Nessus, OpenVAS/Greenbone, nmap NSE):

### 2.1 OpenVAS QoD — the key model
**Quality of Detection (QoD)** is a **0–100 number describing how reliable the detection
method is**, kept **orthogonal to severity (CVSS)**. Severity = *how bad if real*; QoD =
*how likely it's actually there*. Findings are filtered by a **default `min_qod = 70`** —
lower-confidence detections are recorded but hidden until the operator dials `--min-qod`
down. The `*_unreliable` tiers (e.g. a banner with no patch level, the **distro-backport**
case) sit at QoD 30 and drop out of the default view automatically. This is the proven
answer to recce's exact problem.

### 2.2 Nuclei — data-driven matchers
Detections are **data** (YAML), not code. A check is `matchers` with types
(`word`/`regex`/`status`/`size`/`dsl`), two boolean levels (`condition` within a matcher,
`matchers-condition` across matchers), and — critically — **`negative: true` matchers** that
assert what a real target must *lack* (excludes honeypots/error pages/backported builds).
Low FP comes from **compound AND of independent signals** + negative matchers.

### 2.3 Nessus — KB gating + paranoia
Plugins share a per-host **Knowledge Base**; checks are **gated** on required facts
(`script_require_keys`, `script_require_ports`) so they never fire on the wrong service/OS.
`report_paranoia` (0=avoid FP / 1=normal / 2=paranoid) is a user-facing confidence dial.
**Authenticated/local checks** (read the package DB) are high-confidence; **remote banner**
checks "can lie" (backporting) and rank lower.

### 2.4 Version-range CVE matching — the backport trap
The biggest remote-scan FP source: distros backport fixes keeping the upstream version.
Good tools ask "is the installed *build* the one that fixed this CVE?" (distro VEX/OVAL),
and failing that, **mark version-only findings as low confidence** rather than asserting.
Prioritization layers **EPSS** (30-day exploitation probability) + **CISA KEV** (confirmed
exploited-in-wild) on top of CVSS.

---

## 3. Target design

### 3.1 QoD confidence model (recce's tiers)
Add a numeric `qod` to every finding, **set once from the detection method**, mapped to
recce's existing `source`/`detect_source`/`confidence`/distro fields:

| QoD | `qod_type` | recce detection method | ≈ old `confidence` |
|---:|---|---|---|
| 100 | `exploit` | recce actively exploited / got unauth read (proofs live-access) | confirmed |
| 99 | `active_vuln` | NSE `state: VULNERABLE`, or recce negotiated the weak protocol itself | confirmed |
| 97 | `local_authenticated` | on-target `ingest`/`local_findings`, credentialed/package/registry fact | confirmed |
| 95 | `active_app` | live probe confirmed the app/config (`source=probe`) | confirmed |
| 90 | `config_observed` | NSE weak-config observed (anon FTP, weak TLS, risky methods) | confirmed |
| 80 | `remote_banner` | `source=version-db`, version **with patch level**, non-distro build | likely |
| 70 | `nmap_service` | `-sV`-inferred product/version match (`detect_source=nmap`) | likely |
| 50 | `inferred_port` | `detect_source=inferred` (port-number label, no banner) | potential |
| 30 | `banner_unreliable` | version-db advisory, distro-backport (`_DISTRO_RE`), or no patch level | potential |
| 1 | `general_note` | hygiene note, no vulnerable build confirmed | potential |

**Two thresholds, both operator-dialable:**
- **`MIN_QOD_VISIBLE = 70`** — default report inclusion (OpenVAS's default). `--min-qod N`
  to reveal/hide more.
- **`MIN_QOD_VERIFIED = 95`** — the bar to be treated as **confirmed/exploitable**
  (exploitation plans, "proven exploit", CONFIRMED verdict). A qod-80 banner match is
  *shown* as a lead but never drives a "confirmed exploit" artifact — this is what resolves
  the two-CONFIRMED contradiction.

Severity (CVSS) stays a **separate axis**, exactly as today. Ranking becomes
`severity × qod` (+ EPSS/KEV in Stage 2), so a CVSS-10 banner guess no longer outranks a
verified CVSS-7.

### 3.2 The `Finding` model (evidence-carrying)
Findings gain structured **evidence** so proofs stops guessing provenance:

```python
@dataclass
class Evidence:
    kind: str       # "nse" | "live-probe" | "version-range" | "on-target" | "config-observed"
    detail: str     # what was observed
    positive: bool  # True supports the finding, False disproves it (patched / NOT VULNERABLE / auth-required)
```

`Vuln` gains `qod: int`, `qod_type: str`, `evidence: list[Evidence]` (and later
`epss: float`, `kev: bool`). Identity/dedup moves to a **fingerprint keyed on
`(ip, port, primary_CVE_or_rule_id)`** so multi-source duplicates of one real issue collapse
(keeping the highest QoD + merged evidence) while distinct issues stay separate.

### 3.3 proofs becomes a verifier, not a re-adjudicator
`proofs.verify` shrinks from ~670 lines of string-branching to: **promote** a finding to
`active_*`/`exploit` QoD when positive structured evidence exists, **refute** it (drop below
the filter) when negative evidence exists, otherwise leave the detector's QoD and only
attach the safe finish-command. The `_LIVE_ACCESS_RE` safety net disappears because
`evidence.kind` already distinguishes live from version-range.

### 3.4 Data-driven detection (Stage 4)
`vulndb.SIGNATURES` and the scattered substring checks become **YAML matcher rules** (Nuclei
grammar: `word`/`regex`/`version`/`status`, `matchers-condition`, **`negative`**), each
stamping its QoD tier. Runbooks/narratives move to templates. Detections become
reviewable/versionable and tunable **without touching Python**.

---

## 4. Staged roadmap (SOTA-driven)

Re-sequenced (2026-07-29) around the four mechanisms every state-of-the-art scanner uses to
be low-FP *and* high-signal — **confidence tiering · verify-don't-infer · dedup/correlation ·
exploit-aware prioritization** — plus data-driven detection. The honesty loop's goals are
realized *through* these proven mechanisms, not a bespoke evaluation engine. Accuracy
capabilities come first (the tester's trust); efficiency and bloat follow. Each stage ships
independently (green tests, tool usable).

| Stage | Tester win | Scope |
|---|---|---|
| **0** ✅ | Stop the FP bleeding | Tactical FP sweep (PR #29/#31, merged) |
| **1 — QoD confidence spine** ✅ | Trust the default view; leads labeled (not hidden), dialable | `qod`/`qod_type` + `qod.py` scoring; QoD column + opt-in `--min-qod`; gates unified (PR #32/#33). `evidence[]` foundation = PR #34 (open) |
| **2 — Dedup / correlation** ◀︎ NEXT | **The FP-count killer**: hundreds → the handful of real issues | Merge the same issue across sources/ports/hosts into one finding (identity = primary CVE else normalized rule id), keep top QoD + union of evidence; host roll-up for shared-root-cause. **Never fold two *distinct* findings.** Lowest-risk big win (presentation, not verdicts). |
| **3 — Active verification (verify-don't-infer)** | **The core low-FP capability**; recce's offline edge | Make active confirmation the default posture: for a version/banner *lead*, auto-run the cheap confirm-check the recipe already names (`finish`/`to_confirm`) → promote to CONFIRMED with real evidence, or refute — instead of inferring from a banner. Extends recce's existing live probes (redis/ftp/smb/http…). Bounded, safe-by-default, ROE-aware. |
| **4 — Honest tiered presentation** | Signal never buried; nothing hidden | Tier the report (confirmed/likely up top, **leads collapsed**, refuted hidden-but-available); the honesty column (rationale + caveats + to-confirm); Exploitation labels a non-verified action **candidate — verify**. Keeps `_v_*` precondition knowledge as verification triggers + caveats. Realizes the [honesty loop](PROOFS-HONESTY-LOOP.md) via presentation. |
| **5 — Offline EPSS/KEV prioritization** | A priority order, not a flat wall | Bundle offline EPSS + CISA KEV snapshots; rank = severity × QoD × EPSS/KEV; "fix these first" view. |
| **6 — Data-driven detection** | Tune checks/runbooks without code; enables API-enum | `SIGNATURES`/runbooks → Nuclei-style YAML matcher rules with **negative** matchers; `--validate-rules` lint. Foundation for API enumeration ([[recce-backlog]]). |
| **7 — Scan efficiency** | ~½ the scan time, **zero coverage loss** | Collapse the 4–5 redundant `-sV` passes + merge NSE sets + incremental report regen — **only where coverage is provably preserved** (verify-then-cut). |
| **8 — Structural de-bloat** | Faster/safer iteration; clean library core | `cli.py` 6,018→~2,000 via `phases/` + declarative argspec + service registry; collapse report trio onto one model→renderers; shared `util.run`. ~7,000 LOC out, zero capability loss. |

**One-line thesis:** the capability that makes or breaks a scanner's reputation is **active
verification** — shifting recce from *inferring* findings from banners to *confirming* them —
and **dedup** is what makes the result readable. Those two are the priority.

---

## 5. Stage 1 — detailed spec (in progress)

**Goal:** every finding carries an honest, method-derived `qod`, and every consumer reads
that one number instead of re-deriving confidence. Delivers the trust win and kills the
two-CONFIRMED contradiction.

**1a — QoD foundation (this PR):**
1. `models.Vuln`: add `qod: int = 0`, `qod_type: str = ""` (additive, back-compatible via
   `from_json` field filtering).
2. New `recce/qod.py`: `score(vuln, port) -> (int, str)` implementing §3.1; constants
   `MIN_QOD_VISIBLE = 70`, `MIN_QOD_VERIFIED = 95`; helpers `is_visible(v)`, `is_verified(v)`;
   `annotate(host)` to stamp every finding once. Fully unit-tested against the tier table.
3. Chokepoint: call `qod.annotate(host)` where findings are finalized (after
   `vulndb.assess_host_inplace` + folding in `_enum_worker`, and defensively in the report
   entry so imported/older stores are scored too).

**1a — unify the confidence gates (this PR):** the four divergent
`confidence != "potential"` checks (`exploitplan._confirmed_vulns`, `poc.py`,
`playbook.py`, `netmap.py`) all read the **one** QoD authority (`qod.is_visible`) instead
of the coarse string. Behavior-preserving (potential ⇔ qod < 70) so the suite stays green,
but there is now a single predicate to change — and it already respects `--min-qod`.

**1b — RE-PLAN (superseded): a review & evaluation "honesty loop", not hard gates.**
The first attempt (delete the per-type `_v_*` verdict code, drive everything from
evidence/QoD) was dropped: those functions also encode **precondition gates** that stop
false positives (ZeroLogon→DC-only, BlueKeep→OS, patched-version→FP), and deleting them
would MISS real findings. The replacement direction (user, 2026-07-29):

> Instead of throwing hard gates, have an **end review + evaluation + honesty loop** that
> verifies findings are real. Some gates may be OK.

Design intent for the re-plan (to be specced in full before any code):
- **Surface everything; hide nothing.** No finding is silently dropped. A finding that
  can't be confirmed is shown as a lead with an honest rationale, not deleted.
- **A final evaluation pass per finding** produces `{realness confidence, rationale,
  what-would-confirm-it, what-argues-against-it}` from the structured **evidence** +
  preconditions — a transparent assessment the tester reviews, not a binary verdict.
  Preconditions (DC status, OS, version-in-range) become *inputs that lower/raise the
  realness score and are explained*, not silent drops. (This is where `evidence[]` from
  PR #34 pays off, and it composes with the adversarial-verify / completeness-critic
  patterns — an "is this real, and what did we NOT check?" loop.)
- **Hard gates only for a definitive disproof** — e.g. an NSE check that explicitly reports
  NOT VULNERABLE, or a live re-probe that refuses auth. Everything else is evaluated and
  surfaced, never suppressed.
- **Honesty column in the report**: the verdict carries its confidence AND its reasoning,
  so "confirmed" means recce can show *why*, and a lead says plainly what's unverified.

The two-definitions-of-CONFIRMED fix (label a non-verified exploitation action
**candidate — verify**) still applies and lands with this re-plan.

**Regression contract:** `tests/test_fp_sweep.py` and `tests/test_false_positives.py` encode
the exact version-db-vs-live/EOL/regreSSHion/distro distinctions QoD formalizes — they must
stay green (with only constructor edits), and new `tests/test_qod.py` pins the tier table.
