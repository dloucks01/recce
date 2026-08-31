# Phase A depth audit — T0-T4 scoreboard

Every recce service module scored against the maturity rubric:
- **T0 enum** — fingerprint / version / surface (not evidence of a vuln)
- **T1 safe verify** — probe succeeds only if vuln is present (non-destructive)
- **T2 proof of exploit** — controlled payload proves capability without full compromise
- **T3 initial access** — creds captured, shell, session, meaningful data
- **T4 chain** — follow-on from foothold (LSA/DPAPI/secretsdump/ADCS)

## Coverage

- Services audited: **77**
- Finding kinds scored: **667**
- Per-service JSON: `.recce-plan/depth-audit/<slug>.json`
- Full workflow output: `/tmp/claude-1000/.../tasks/wbbuc862q.output` (~483k chars)

## Current tier distribution

| Tier | Count | % |
|---|---|---|
| T0 enum | 210 | 31% |
| T1 safe verify | 286 | 43% |
| T2 proof of exploit | 122 | 18% |
| T3 initial access | 47 | 7% |
| T4 chain | 2 | ~0% |

Roughly 3/4 of findings are enum-or-verify only — the promotion runway is huge.

## Promotion opportunities

Every finding scored with a realistic `can_promote_to` target and a
`promotion_risk` rating:

| Target tier | Count |
|---|---|
| stay (already at ceiling) | 141 |
| T1 | 68 |
| T2 | 213 |
| T3 | 197 |
| T4 | 48 |

| Risk | Count |
|---|---|
| none | 209 |
| low | 154 |
| medium | 146 |
| high | 85 |
| destructive | 73 |

**118 low-risk promotions available across critical/high findings** —
the sweet spot for Phase B builds.

## Top services by promotion-eligible findings

Where the highest-value depth investments would land:

| Service | Promotable (T0/T1→T2+) | Total findings |
|---|---|---|
| mssql | 16 | 28 |
| ssh | 11 | 13 |
| web (crawl) | 9 | 33 |
| kubernetes | 9 | 10 |
| http | 8 | 17 |
| webdav | 8 | 15 |
| nis_yp | 8 | 10 |
| cups_lpd | 8 | 14 |
| smtp | 7 | 9 |
| enip | 7 | 14 |
| nbd_ndmp | 7 | 12 |
| imap | 6 | 14 |
| jenkins_jnlp | 6 | 9 |
| opcua | 6 | 12 |
| dns | 6 | 8 |

## Top 25 critical/high low-risk promotions (Phase B first-batch candidates)

Critical:
- cloud_metadata `imds_v1_enabled` → T3 (IMDSv1 IAM cred retrieval)
- kubernetes `api_anon_list` → T3 (SA token via anon list)
- mssql `blank_login` → T2 (verify sa-blank + retention of session)
- nomad `nomad_job_spec_secrets` → T3 (env-var + Vault ref extraction)
- opcua `opcua_anonymous_allowed` → T2 (session establishment proof)
- prometheus `prom_federate_open` → T3 (metric-time-series exfil)
- prometheus `prom_pprof_cmdline` → T3 (cmdline arg leak)
- s7 `s7_put_get_enabled` → T2 (PUT/GET semantic probe)
- vault `vault_dev_mode` → T3 (root token retrieval attempt)
- x11 `x11_open` → T2 (screenshot capture with xwd)

High:
- api `api-endpoints-unauth` → T2
- bacnet `bacnet_bbmd_topology_disclosure` → T2
- cloud_metadata `imds_reachable_from_host` → T3
- coap `coap_resource_inventory` → T2
- cups_lpd `lpd_queue_leak` / `lpd_jetdirect_cve` / `ipp_get_jobs` / `cups_admin_open` → T2
- dns `dns_axfr` → T2 (AXFR zone transfer attempt)
- docker `docker_secrets` → T3 (unauth secrets read)
- docker_registry `dockerreg_anonymous_catalog` → T3 (image pull + layer read)
- elasticsearch `es_anonymous` → T2
- enip `enip_io_traffic_exposed` / `enip_unauth_session` / `enip_known_cve` → T2

## What the audit produced beyond tier scores

Every finding got a `tester_next_step` field: **the exact command, PoC
URL, or manual step a pentester should run given this finding.** That's
667 curated advisories ready to thread through to a `Vuln.exploit_note`
field for the GUI to render.

## Phase B plan (informed by this audit)

**B1: `Vuln.exploit_note` field + backfill (mechanical)**
- Add `exploit_note: str` to `recce/core/models.py:Vuln`
- Fan out per-service agents to attach the audit's `tester_next_step`
  text to each finding's `_finding()` / `_mk()` call site
- GUI Findings view + KnownAssets + ExploitSurface all display it
- No new exploit primitives, huge advisory improvement

**B2: 25 low-risk T2 promotions (highest ROI, no auto-exploit)**
- Ship one safe active-verify probe per top-25 target above
- Each stays safe/non-destructive by construction
- Result: every promoted finding graduates from "banner match" to
  "vuln confirmed by probe" — the difference between hacktricks-tier
  and state-of-the-art

**B3: T3-tier promotions gated behind `--exploit` flag**
- Deferred until Phase C GUI can prominently display the "these need
  --exploit to run" callout
- Docker daemon RCE, Redis SSH-key drop, K8s SA-token, cloud_metadata
  IMDSv1 IAM read
