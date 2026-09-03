# Changelog

All notable changes to recce are documented here. This project follows
[semver](https://semver.org): major bumps break API/CLI shape, minor bumps
ship additive capabilities, patches fix regressions without adding surface.

## [0.7.1] — 2026-09-03

Docs-only patch on top of 0.7.0. No code changes.

- **Docs sync to 0.7.0** — a tester opening the repo would have missed
  every headline 0.7.0 addition (web workbench, attack chains, sessions
  with tunnels/port-forwards, ADCS ESC1 auto-request, cross-service
  chain rules, auto-crack loop, OT protocols, BloodHound push). Fixed.
- New user doc `docs/reference/webui.md` (~200 lines) — full tour of the
  web workbench: 11 tabs, sidebar strip, header widgets, attack chains,
  ESC1 flow, every per-session capability, scan-tab suggestions,
  in-browser report generation.
- Refreshed `README.md`, `QUICKSTART.md`, `docs/reference/commands.md`,
  `docs/reference/services.md`, `docs/reference/active-directory.md`,
  `docs/reference/reporting.md`, `docs/reference/privesc.md` to reflect
  0.7.0 features (Act phase, prove engine, suggest digest, OT modules
  s7/bacnet/dnp3/enip/iec104/opcua/modbus, ADCS ESC1 auto-request,
  auto-crack loop, in-browser reporting).
- Moved 6 internal design ADRs `docs/design/*` → `.recce-plan/design/*`
  (they document decisions for shipped subsystems — not user-facing).
- Deleted stale `test_env/TEST_PLAN.md` (297 lines predating the live
  test env; used old flag names). `test_env/README.md` is the single
  source of truth for the lab.

## [0.7.0] — 2026-09-03

The **audit-and-close** release. The 0.6.x cycle shipped a lot of code
without ever cutting a release; this tag folds the whole arc into one
labelled baseline. Every P0 / P1 / P2 / P7 roadmap item is either
shipped ✅ or intentionally deferred ⏸ with clear rationale — see
`.recce-plan/ROADMAP.md`.

### T2 promotions + depth-tier discipline (P0-1)
- **30 T1→T2 label lifts** across ~18 service modules where the module
  already collects concrete server-side content but the depth_tier
  label was stuck at T1. Every promotion documented with the specific
  server-side evidence it captures (protocol reply, enumerated set,
  parsed structure).
- **S7 firmware-band verification** — `_fw_lt(fw_version, cutoff)` +
  `verified` flag; CVE-2020-15782 promotes to T2 only when SZL 0x0011
  reports firmware below the V4.5 mitigation cutoff. 5 new tests lock
  the band comparator.
- Legit-T1 documented: `enip_io_traffic_exposed` (audit's T2 path is
  passive tcpdump, out of scanner scope).

### exploit_note attachment (P0-2)
- Attached `exploit_note` + `depth_tier` to the last 6 medium/low/info
  findings across `ldap` / `nrpe` / `rtsp` (271 of 302 candidates had
  already been done in earlier passes).
- Delivered `.recce-plan/audit/p0_2_missing_capabilities.md` — the
  audit-vs-module gap list (30 kinds the audit expected but the
  module never emits) as a discoverable cherry-pick starting point
  for future capability builds.

### ADCS ESC1 auto-request (P1-7)
- New `recce/ad/adcs_exploit.py` — subprocess wrapper around
  `certipy req` that never raises for a non-zero exit or missing tool;
  redacts `-p` / `-hashes` values from returned argv diagnostics;
  captures PFX bytes as base64 for out-of-band handoff.
- New `POST /api/adcs/esc1/attempt` endpoint with three gating layers:
  - Exact-string `confirm_sentinel` (rejects boolean / case-mismatch /
    trailing whitespace) — no accidental replay
  - Store-lookup credentials — the WebGUI cannot spray arbitrary creds
    through this path; recce looks up the AD principal in its own store
  - Clean-fail on missing certipy — returns 200 + actionable error,
    not a 500
- On success: PFX persisted under `<eng>/session-loot/adcs/`, folded
  into the credential store as `Credential(kind="cert")` so the AD
  chain's `da_path` step naturally advances; audit-trail logged to
  collab activity feed.
- WebGUI: `Esc1RequestModal` on the AD attack-chain's `adcs_esc` step
  when proven — full form (principal picker from store, template / CA /
  DC / UPN inputs) + intrusive warning + inline result rendering.
- 24 tests (16 unit + 8 API) using shell-fixture certipy so no real CA
  needed.

### WebGUI audit close-out (P7)
- **Batch A (quick wins)** — spray-empty 400 guard, `/api/findings?status=`
  filter, `_MODULE_PATH` silent-fallback fix, field-name consistency
- **Batch B (medium UX)** — sidebar CredsSummary rewrite (scope split,
  admin count, paste-to-loot), ScanConsole floating drawer, topology
  empty-state launch hints, engagement switcher header dropdown, unified
  `Vuln.key` shape (drops the `remove_finding` dual-shape fallback)
- **Batch C (large infra)** — async `/api/spray/async` + `/api/act/run/async`
  via new `JobManager.start_callable`; attack-chain DAG viz (`ChainGraph`
  SVG rendering all 3 chains with click-to-scroll); fine-grained live
  events (spray_hit, prove_verdict, session:caught/lost) → toasts;
  delete-host cascade with impact preview + type-to-confirm; long-scan
  progress bars parsed from enum stdout; header JobsPill
- **Batch D (test coverage)** — `tests/test_webui_smoke.py` promotes the
  ad-hoc audit scripts to 39 always-on TestClient assertions covering
  every read-surface endpoint + scan-launcher lifecycle

### Creds UI polish
- Creds tab: added Scope column (🏠 local / 🌐 <domain>) so account
  origin is visible at a glance; added local/domains count tiles;
  pinned actions column tight (was drifting right under wide viewports)
- Sidebar 🔑 tab (`CredsSummary`) rewritten from read-only strip to
  quick-action strip: admin-count chip in header, scope split with
  per-domain chips, kind breakdown, paste-to-loot affordance for
  fire-and-forget loot extraction

### Attack chains
- Cloud pivot chain (`/api/attack-chain/cloud` + `AttackChainCloud.tsx`)
- Web n-day chain (`/api/attack-chain/web` + `AttackChainWeb.tsx`)
- `contributing_hosts` per step surfaced in every chain view
- Chain payload now carries derived `edges[]` from step `depends_on`
  so the DAG visualiser has stable input across all 3 chains

### Scan intelligence
- 18 cross-service chain-correlation rules (AD Kerberos, SMB post-null,
  cloud metadata pivot, web n-day, etc.) as first-class suggestions
- `_rule_t3_capable_findings` — T3 findings + high/critical T2 auto-
  surface with `external_cmd = exploit_note`
- Removed the fragile `*_targets` fallback in `/api/scan/context`;
  canonical `<cmd>_targets` name is required, with 7 short-form modules
  gaining in-module aliases

### Auto-crack loop (P1-8)
- `recce/creds/crack_watcher.py` — polls potfiles, promotes cracks
  to `Credential(kind="password", source="cracked")`
- `AutocrackStatus` header widget + `/api/autocrack/status` for
  visibility into the watcher's queue and recent promotions

### BloodHound push (P2-3)
- `recce/ad/bloodhound_push.py` writes BloodHound-compat JSON so an
  operator can overlay recce's live scan data onto their existing
  BloodHound instance
- CLI: `recce bloodhound-push`; WebGUI: `/api/bloodhound/zip` +
  `/api/bloodhound/status`

### Test environment
- 5 new modern-service canaries: gitlab, ollama, jupyterhub, grafana,
  minio
- Phase 10 batch 2: rdp, sip, ipmi canaries + real RDP probe fix
- Coverage push: ipp, rdp, telnet

### Sessions
- Full session-capability matrix verified against 3 session types
  (raw non-PTY, stager PTY plain, stager PTY TLS): 49 PASS · 0 FAIL
  across list, transcript, history, quick-actions, task, upgrade,
  tunnel, portfwd, pivot-plan, cred, upload, download, teardown,
  label — every session endpoint wired correctly

### Fixes
- `Vuln.cve` AttributeError in `/api/host/{ip}/impact` — was accessing
  a non-existent attr; now reads `Vuln.ids[0]`
- RDP X.224 CR byte count fix
- `cloud_metadata` module missing from `_MODULE_PATH` — now guarded
  with a raise instead of a silent fallback

## [Unreleased]

The 0.7.0 release closed every open roadmap item. Future work is
demand-driven cherry-picking from `.recce-plan/audit/p0_2_missing_
capabilities.md` (30 audit-vs-module gaps) plus the intentionally-
deferred P2-1 / P2-2 pools when a specific engagement calls for the
depth. See `.recce-plan/ROADMAP.md` for the current state.
