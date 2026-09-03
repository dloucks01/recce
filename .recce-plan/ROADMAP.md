# recce roadmap

Durable pickup doc for future sessions. Written after the depth-uplift
sessions that took recce from a hacktricks-style enumerator to a
GUI-driven "here's a proven-exploitable finding, here's your next move"
tool.

## Session-recovery context (read this first)

**Since this roadmap was authored, the following also shipped** (chronological, HEAD-first):
- **P5 honesty-audit close-out (cc304cf, e65e0a5, cb02e00, bd88c33, 9265e16, f23c87e):**
  audit pass triggered by "are we at a good point?" — surfaced real gaps
  by running recce against the live compose test env (172.20.0.10-49,
  31 containers). Fixed everything actionable in one arc:
  * **Untiered kinds:** live scan produced 138/212 (65%) findings with
    empty `depth_tier`. Fan-out tiered 53 kinds in web/checks + http +
    vulndb + parser (bd88c33), then 5 leftover kinds in
    web/discover + probes + parser NSE cases (cb02e00), then the last
    tls-cert/tls-proto in probes.py (e65e0a5). Rate now **0%**
    (only skipped kinds are UDP-only ones that need `sudo` to probe).
  * **SSH test race** (40-60% flake): real bug in the fake server's
    ident-drain — `conn.recv(4096)` pulled ident + KEXINIT + KEXDH_INIT
    into one buffer but split only on \n, discarding the binary tail.
    Rewrote with a shared buffered reader. Now 5/5 pass in 0.26s each.
  * **CWE-214 + CWE-1394 unclassified**: added to _CWE_TYPE + _CWE_NAME
    + core cwe.NAMES fallback (f23c87e).
  * **`_targets` filter brittleness** (backlog item): hoisted
    `_module_scoped_check` with qualname dot-check so class-nested
    `_targets` methods never shadow the real module-scope helper.
  * **GUI parity for CLI-only features (cc304cf, all 5 in one shot):**
    - BloodHound zip download button (routes/bloodhound_export.py +
      ExploitSurface button + status probe)
    - Dedicated Suggest tab (routes/suggest_digest.py +
      views/SuggestDigest.tsx + nav entry)
    - Per-finding Prove button (recce/act/prove_dispatch.py shared by
      CLI+endpoint, routes/prove_endpoint.py, ExploitSurface verdict
      chip + evidence + finish line)
    - Auto-crack watcher status widget (routes/autocrack_status.py +
      components/AutocrackStatus.tsx in top bar)
    - Chain-rules extracted from scan.py to routes/chain_rules.py
      (pure refactor, re-export preserves test imports)
  * Full test suite: **3959 passed, 0 failed, 13 skipped** (32:50).
- **P3-2 batch 2 (4520b7e):** 6 more chain-correlation rules (dns forest
  map, java rmi/jmx deser, snmp write reconfig, sip/rtp eavesdrop, k8s
  token→RBAC privesc, http lfi→rce). Total chain rules now 18.
- **P3-1 (fb3364e):** 12 cross-service chain-correlation rules in
  `/api/scan/suggestions` — AD-Kerberos, cloud IMDS pivot, container
  escape, HashiCorp stack, NTLM harvest, unauth datastore data-mine,
  MSSQL linked-privesc, coerce+relay, printer→domain-creds, OT
  process-impact (safety-first), ESXi/vCenter takeover, +1. Each fires
  on 2+ Vuln.script_id triggers with paste-ready command strings.
- **P2-1 batches 1-3 (6ab76a5, fe43684):** medium-severity gap-fill
  across mongodb/smtp/dns/kerberos/snmp/cassandra. Every other module
  audited (ldap/smb/ntp/ftp/imap/webdav/coap/pop3/elasticsearch/
  prometheus/rtsp/opcua) came back saturated — medium tier of Phase 5a
  audit is now closed for all high-gap services.
- **P2-2 batch 2 (df889e1):** 6 deferred capabilities — mssql
  replication_and_agent_secrets_disclosure, postgres
  replication_startup_leak, k8s admission_webhook_disclosure, vault
  mount_list_leak, redis cluster_topology_disclosure, http
  actuator_env_deep_leak.
- **P0-1 batches 4-5 (7c9dc1a, prior):** additional SAFE T1→T2
  promotions across rdp/winrm/msrpc/oracle/influxdb/docker_registry/
  sip/bgp/stun_turn/minecraft/ipmi/nbd_ndmp and earlier batches.
- **P2-2 batch 1 (15b97fb):** mssql sp_execute_external_script +
  contained_db + DAC 1434, mysql X Protocol, ssh hostkey_reuse.
- **P2-3 / P2-4 / P2-5 / P2-6 (1bbc4cf, 633ce86, 9bb16d4, 74e8828):**
  all shipped (bloodhound push, `recce suggest`, prove uplift,
  shared-surface consumers).

**Still open / externally blocked:**
- P1-1 compose OT profile — Docker Hub is reachable now; the core+db+
  messaging+media profiles are up (31 containers). OT profile
  bring-up (bacnet-sim/enip-sim/opcua-sim/s7 etc.) still deferred —
  they're authored in test_env/docker-compose.yml, just not `up`'d.
- P1-2 Vagrant plane — needs user real-time (~4GB VM downloads).
- P2-2 remainder — Log4Shell OOB, HTTP request smuggling active PoC,
  HTTP/2 rapid-reset, Spring4Shell — all require OOB callback
  infrastructure recce doesn't have.
- P0-1 long tail — ~120+ candidates remain in the audit, but batches
  2-6 confirm the highest-value ones already shipped.

**Audit close-out declared complete as of cc304cf** — everything
actionable in the current environment is done. Next open item is a
scope pivot (new capability class, new attack chain, or the externally-
blocked items above).

---

**What just shipped (last major block):**
- Phase A: 77 services × 667 finding kinds scored against T0-T4
  rubric. Data at `.recce-plan/depth-audit/<slug>.json`.
- Phase B1: 330 exploit_note + depth_tier attachments on critical/high
  emission sites across 73 modules.
- Phase B2: 15 SAFE T1→T2 verification probes (mssql/opcua/s7/x11/api/
  bacnet/coap/cups_lpd/dns/elasticsearch/enip).
- Phase C: `/api/exploit-surface` + `views/ExploitSurface.tsx` (Surface
  tab, default-visible). 8 attack-chain groups + KEV top-10.
- Phase D: `/api/attack-chain/ad` + `views/AttackChain.tsx` (AD Chain
  tab, default-visible). 11-step narrative from `discover_dc` to
  `da_path`.

**Foundational primitives available:**
- `recce/core/depth.py` — T0-T4 constants + `label()` + `rank()`.
- `recce.core.models.Vuln.exploit_note` and `.depth_tier`.
- 16 shared surface readers under `recce/core/known_*.py` and
  `recce/creds/known_*.py`.
- 30 new service modules (Tier 1/2/3) + 34 existing services gap-filled.
- test_env compose plane (46 services, 6 profiles) + Vagrant plane
  (3 VMs) — authored, partially brought up.

**User directive that shapes every item below:**
> "there shouldn't be much automation, but the web GUI should point
> the tester in the right direction"

So: SAFE T1/T2 verify + rich advisory > auto-shell modules. T3+ stays
manual (exploit_note text tells the tester what to run).

**Where to look for prior context:**
- Design docs: `.recce-plan/depth-audit/SUMMARY.md`,
  `.recce-plan/phase9/PLAN.md`, `.recce-plan/phase10/RESULT.md`.
- Punch lists per service: `.recce-plan/tier{1,2,3}/*.json`,
  `.recce-plan/audit/*.json`, `.recce-plan/depth-audit/*.json`.
- Workflow scripts (for iterating on impl agents):
  `~/.claude/projects/-home-kali-Desktop-projects-recce/*/workflows/scripts/`.

---

## Priority tiers

**P0 — high-leverage, low-risk, ship next.**
**P1 — meaningful ambition, needs a design pass or user judgment.**
**P2 — aspirational, cross-cutting, worth tracking.**

---

## P0

### P0-1 — Finish the SAFE T2 promotions (~200 remaining)
**Effort:** L (5-8 fan-out workflows of 10 agents each, ~1 day each)
**Blocks:** Nothing.
**Why:** Every promotion moves a finding from "banner match" to
"proven with server-side evidence" and lights up in the Surface tab
immediately. Same mechanic that shipped 15 already in Phase B2.

**Build plan:**
1. Extract remaining T1→T2 candidates from
   `.recce-plan/depth-audit/*.json` where `can_promote_to == "t2"`,
   `promotion_risk in ("none","low")`, and `finding_kind` is not in
   the Phase B2 already-shipped list (mssql/blank_login, opcua/anon,
   s7/put_get, x11/open, api/endpoints-unauth, bacnet/bbmd,
   coap/inventory, cups_lpd/4-kinds, dns/axfr, elasticsearch/anon,
   enip/3-kinds).
2. Group by service, tranche into batches of ~10 services × ~2-4
   promotions each.
3. Fan out per-service agents using the same prompt shape as Phase B2
   (see `.claude/projects/.../workflows/scripts/phase-b2-t2-*.js`).
4. Per-service agent runs pytest + ruff on its module before returning.
5. Commit per-batch, push, move to next tranche.

**Concrete first-batch candidates (from the audit data):**
- ssh: verify AS-REQ against sshd for pubkey (single request, non-DoS)
- ldap: `ldap_anon_read` T3-adjacent — enumerate SPNs into a
  spn.txt file (read-only, no state change on DC)
- webdav: PROPFIND depth:infinity on `/` returns 207 with URL list
- imap: post-LOGINDISABLED `LOGIN dummy dummy` returns NO — proves
  plaintext auth accepted but keeps single probe
- pop3: USER/APOP disclosure via differential response
- smtp: VRFY / EXPN success on canonical accounts
- iscsi: SendTargets returns non-empty target list
- nfs: showmount -e returns exports (already at T1; T2 adds mount
  attempt on a canary export)
- kafka: MetadataRequest v0 returns broker + topic list
- zookeeper: 4LW `mntr` returns full runtime dump (currently just
  probes it exists)
- prometheus: `/api/v1/query?query=up` returns time series
- vault: `/v1/sys/health` returns cluster metadata
- consul: `/v1/kv/?recurse` returns non-empty tree
- nomad: `/v1/agent/self` returns config with Vault/Consul refs
- jenkins_jnlp: agent-handshake returns protocol version list
- coap: /.well-known/core → GET the first advertised resource
- mqtt: SUBSCRIBE to `#` on anon-connect and capture 1-2 retained msgs
- rtsp: DESCRIBE returns SDP with codec + resolution
- guacamole: `select` opcode returns backend proto list
- mongodb: `hostInfo` command with no auth returns hostname + OS
- redis: `INFO` returns full sections without AUTH
- couchdb: `/_all_dbs` returns DB list (already known; add `/_users`
  read attempt as T2)

**Estimated total:** ~100 wire-ups across ~30 services.
Split into ~4 workflows (12 services each) if the concurrent-agent
cap holds.

### P0-2 — Attach exploit_notes to medium/low severity findings
**Effort:** M (2 fan-out workflows, ~half day each)
**Blocks:** Nothing.
**Why:** Phase B1 stopped at critical/high (330 attachments). The audit
has ~337 more findings at medium/low/info that would light up in the
Surface tab if attached.

**Build plan:**
1. Same fan-out mechanic as Phase B1 (12 tranches of 5-6 services).
2. Prompt agents to attach `exploit_note` + `depth_tier` to
   medium/low/info findings this time.
3. Per-agent verify pytest + ruff.

### P0-3 — Fix the bmc Vagrant canary (UDP)
**Effort:** XS (10 lines)
**Blocks:** Phase 10 Vagrant-lane tests.
**Why:** IPMI 623/udp can't be probed by TCP connect. Currently every
`@needs_vagrant("bmc")` test skips even when the BMC IS up.

**Build plan:**
1. In `tests/conftest.py:_reachable()`, add a `udp: bool` param.
2. When `udp=True`, send an IPMI Get Channel Auth Capabilities packet
   (RMCP class-of-message 0x06, ASF header, IPMI seq 0) and read one
   byte back with a 1s timeout.
3. Update `_VAGRANT_CANARIES["bmc"]` to a tuple that carries the
   UDP flag.
4. Add a small unit test in `tests/test_env_gate_markers.py` that
   asserts an unreachable UDP probe returns False without exception.

### P0-4 — Rename or consolidate the old Exploitation tab
**Effort:** XS (grep + rename)
**Blocks:** Nothing.
**Why:** `exploit` (old attack-plan panel) and `surface` (new
Exploit Surface) confuse in the tab bar.

**Build plan:**
- Option A: rename old `exploit` → `plan` in TabBar + App.tsx + every
  `nav.toAct()` caller. Rename new `surface` → `exploit`. One PR.
- Option B: consolidate old panel INTO the new Surface tab as a
  "Historical action plan" section below the group cards.

User picks A or B; whichever, ~40 lines of changes across 3-5 files.

### P0-5 — ExploitSurfaceCallout empty-flash on fresh load
**Effort:** XS
**Blocks:** Nothing.
**Why:** The callout renders empty for ~500ms while the API round-trip
completes.

**Build plan:**
- Track a `loaded: boolean` state in ExploitSurfaceCallout.
- Render nothing until `loaded && items.length > 0`.
- 5-line change in `views/ExploitSurface.tsx` or wherever the
  callout wrapper lives (agent put it in App.tsx).

---

## P1

### P1-1 — Bring up the compose OT profile + finish Phase 10
**Effort:** M (blocked on Docker Hub reachability)
**Blocks:** Only for tests, not for shipping features.

**Build plan (when Docker Hub is reachable):**
1. `cd test_env && sudo docker compose --profile core --profile ot up -d --wait`
2. First bring-up of `ot` builds 5 simulator images from source
   (~5-8 min).
3. Re-run pytest: `python -m pytest tests/ -k "needs_compose" -q` —
   the 5 currently-skipped compose tests should convert to passes.
4. Run pytest slow lane against the base env:
   `python -m pytest tests/ -m slow -q --ignore=tests/webui` — real
   nmap against the 31 default services + newly-up profiles.
5. Update `.recce-plan/phase10/RESULT.md` with the second-run numbers.

### P1-2 — Bring up the Vagrant plane
**Effort:** L (2-3 hours real time for the AD DC alone + ~1 hour
each for BMC + kernelnet)
**Blocks:** Only for tests.

**Build plan:**
1. `cd test_env/vagrant && vagrant up --provider=virtualbox ad-dc`
   (Windows Server 2022 box download is ~4 GB first time; dcpromo
   dominates second phase).
2. `vagrant up bmc kernelnet` in parallel — much faster.
3. Once all three canaries answer TCP on `172.20.1.10:445`,
   `172.20.1.20:623` (UDP after P0-3 fix), `172.20.1.30:3260`, run
   `python -m pytest tests/ -k "needs_vagrant" -q` — currently 0
   tests use this marker so it's a no-op until an integration test is
   written against the seeded AD accounts.
4. Optional: seed one integration test that hits `svc_backup`'s SPN
   with kerberoast to prove the full chain works.

### P1-3 — Scan-tab intelligence: exploit_note-aware rules
**Effort:** M (extend Phase 8's 9 rules)
**Blocks:** Nothing.
**Why:** Phase 8's `/api/scan/suggestions` recommends next commands
but doesn't yet promote findings whose `depth_tier` is T3-capable to
the "you should look at this now" surface.

**Build plan:**
1. Add rule `_rule_t3_capable_findings` to `webui/routes/scan.py`:
   scans the store for Vuln rows where `depth_tier == "t3"` OR
   `depth_tier == "t2"` AND severity in ("critical", "high"),
   surfaces each as a suggestion with `command=""` (info), `reason=`
   from Vuln.title + Vuln.output, `external_cmd=Vuln.exploit_note`.
2. Cap to top 10 by (depth-rank, severity, kev).
3. Extend `tests/test_webui_suggestions.py` with a seed that produces
   a t3 finding and asserts the suggestion appears.

### P1-4 — Correlate the AD chain to shared surfaces continuously
**Effort:** M (extend `/api/attack-chain/ad`)
**Blocks:** Nothing.
**Why:** The chain reads finding kinds AT REQUEST TIME but doesn't
push updates as new findings land. A finding on host A shouldn't be
invisible to a step that could be satisfied by host B's data.

**Build plan:**
1. Add a `contributing_hosts: [ip]` field per step's evidence — the
   endpoint already collects this data but doesn't surface it.
2. Extend the `AttackChain.tsx` step card to show "Contributing:
   10.0.0.10, 10.0.0.20 (open in HostDrawer)".
3. Test with a seeded engagement where different steps prove against
   different hosts.

### P1-5 — Second attack-chain: Cloud pivot
**Effort:** L
**Blocks:** Nothing.
**Why:** Phase D shipped one chain (AD). Cloud is the second-most-
common enterprise pivot; the ExploitSurface tab already groups
findings by "Cloud + container" so the readers exist.

**Build plan:**
1. Add `/api/attack-chain/cloud` in `routes/findings.py`.
2. Steps: `imds_reachable` → `imds_v1_present` → `iam_role_disclosed`
   → `sts_creds_extracted` (T3, gated) → `s3_buckets_listed` →
   `secrets_manager_read`.
3. Data sources: cloud_metadata module, known_hostkeys (for
   compromised-instance detection), Credential store.
4. `views/AttackChainCloud.tsx` (or generalize the AD component to
   take a chain-config prop and render any 10-step chain).
5. Add `"cloud-chain"` tab.

### P1-6 — Third attack-chain: Web n-day
**Effort:** M
**Blocks:** Nothing.
**Why:** Third narrative most testers care about.

**Build plan:**
- Steps: `web_surface_fingerprinted` → `product+version_pinned` →
  `kev_matched` → `poc_safe_verify_fires` (T2) →
  `oob_callback_triggered` (T3, gated) → `session_established`.
- Data sources: web crawl findings, KEV list already annotated on
  Vuln.kev, exploit_note fields for OOB callback commands.

### P1-7 — ADCS ESC1 auto-request (T3 gated)
**Effort:** M
**Why:** `ad/adcs.py` detects vulnerable templates. The natural next
move — request a cert as `alice` for target `Administrator` — is a
T3 primitive that requires cred_acquired anyway.

**Build plan:**
1. New module `recce/ad/adcs_exploit.py` with an `attempt_esc1(...)`
   helper that wraps certipy.
2. Gated behind `--exploit` CLI flag AND requires a Credential of
   any user for the target domain (checked via known_users).
3. The AD Chain view's `adcs_esc` step gains an "Attempt request as
   alice" button when the step is proven AND cred_acquired is proven.
4. On success, the returned cert lands as a new Credential
   (kind="cert") — that in turn advances `da_path`.

### P1-8 — Auto-crack loop
**Effort:** M
**Why:** Kerberoast/AS-REP/SCRAM hashes recce captures could feed a
scheduled hashcat runbook + watcher that auto-updates the
`cred_acquired` chain step when a crack lands.

**Build plan:**
1. New module `recce/creds/crack_watcher.py`:
   - Periodically (or on-demand via CLI) call
     `hashloot.absorb_default_potfiles(...)` (already exists).
   - When cracks come back, promote the corresponding known_hashes
     entry to a Credential(kind="password", source="cracked").
2. Wire the watcher into `recce serve` as a background task with a
   configurable interval.
3. AD Chain endpoint picks up the new creds naturally on next round-
   trip.

---

## P2

### P2-1 — Deferred capabilities from Phase 5a audit (~370 medium/low)
Each of the 34 existing services had capability gaps identified in
Phase 5a; only critical-tier landed in Phase 5b. The medium/low pool
is in the same audit files' `missing_capabilities` arrays where
`value in ("medium","low")`.

**Effort:** XL (multiple sessions, similar fan-out pattern to 5b).
**Recommendation:** deprioritize unless a specific engagement calls
for depth in a specific protocol.

### P2-2 — Deferred capabilities from Tier 1/2/3 impl agents
Each Tier 1/2/3 service module returned `capabilities_deferred`.
Notable ones:
- SSH: `pubkey_hassig_false_probe` (needs post-NEWKEYS transport
  crypto — non-trivial), `hostkey_reuse_correlation` (needs the new
  known_hostkeys reader — already exists now! could ship).
- MySQL: sha256_password RSA-OAEP + X Protocol.
- HTTP: Log4Shell OOB, request smuggling active PoC, HTTP/2 rapid
  reset, Spring4Shell.
- MSSQL: sp_execute_external_script, ADSI cred capture, contained-DB
  auth, replication secrets, DAC 1434.
- Every other new module has 5-15 deferred items in the same shape.

**Effort:** XL. Each item is a distinct engineering choice.
**Recommendation:** cherry-pick the 2-3 highest-KEV ones per module
in a "T2/T3 hardening" pass rather than tackle wholesale.

### P2-3 — BloodHound push
Read is done; push (write BloodHound-compat JSON so the tester can
overlay live scan data on their BloodHound instance) would close a
loop.

### P2-4 — `--suggest-only` mode
One CLI flag that says "don't scan, tell me what I should run given
what recce already knows" — pulls entirely from shared surfaces +
audit's tester_next_step. GUI-render-only.

**Effort:** S if built as a thin CLI wrapper over
`/api/scan/suggestions` + `/api/exploit-surface`.

### P2-5 — `recce prove` uplift
Wire it to consume `depth_tier` — only try to prove T1s that could
become T2s (audit knows which). It'd auto-promote findings as the
tester runs it.

### P2-6 — Shared-surface consumers noted but not built
- `known_apop_challenges` (POP3 → hashloot categories exist but no
  producer wire)
- `known_ntlm_endpoints` (POP3/IMAP → relay_targets extension)
- `known_uploaded_shells` (WebDAV canary tracking)
- `firmware_versions` (S7 + BACnet + DNP3 unification)
- `known_bacnet_networks` (topology)

Each is a small reader + 1-2 producer wires.

### P2-7 — Skip services from Phase 9 plan
- Real vSphere / vCenter (no viable local repro)
- Real Siemens S7-1200 CPU (snap7-server covers 80%)
- Real BGP peer AS (BIRD covers wire, not propagation)
- Real Hikvision/Dahua RTSP cams (mediamtx covers generic)

These stay documented in `test_env/vagrant/README.md`. Building
integration-only fallback via `RECCE_INT_*` env-var-URL config for
real hardware in specific engagements is a P2 item.

---

## P7 — WebGUI audit close-out (Sept 2026)

Surfaced by an end-to-end tab-by-tab walkthrough against the live
compose test env (44 hosts, 876 findings, 53 credentials). Every item
here was observed in-session; none was hypothetical. Grouped by size
so a limited-token session can pick a self-contained batch.

### Batch A — Quick wins (small, safe, no cross-tab ripple)

#### P7-A1 — `/api/spray` reject empty targets
`/api/spray` with `body.targets == []` currently falls through the
`if tokens:` guard in `routes/act_spray.py`, applies no host filter,
then sprays every stacked cred at every discovered host. One typo away
from a big accidental spray. Should raise HTTPException(400,
"targets required"). Frontend already passes a target — no UI-side
breakage.

#### P7-A2 — `/api/findings?status=X` honored or rejected
Endpoint accepts the query param but ignores it server-side; client
filters locally. Either implement server-side filter (drop the client
`filter(x.status===…)` loop) or reject unknown params with 400. Pick
one contract; document.

#### P7-A3 — Kill the `_MODULE_PATH` silent fallback
`_run_service_scan` in `cli/_service_helpers.py` falls back to
`f"recce.{module}"` when a name isn't in the map. Silent
ModuleNotFoundError at runtime is exactly the bug 687b9f2 fixed for
`cloud_metadata`. Replace with a hard `KeyError` at CLI-parse time
(fail-fast, not fail-at-import). The regression test added in that
commit already asserts every referenced module resolves.

#### P7-A4 — Field-name consistency: `stage` vs `name`
`/api/attackpath.stages[].stage` uses the field name `stage`;
`/api/attack.tactics[].name` uses `name`; frontend has to remember
which is which per surface. Standardise on `name` across every
serialisable "labeled group" shape. Change contained in
`report/attackpath.py` and any test that pins the current key.

### Batch B — Medium UX rework

#### P7-B1 — CredentialsPanel sidebar → compact strip or drop
Right sidebar's 🔑 Creds tab renders the full credential list; the
top-level Credentials tab renders the same thing plus loot-extract +
spray + delete. Same de-dup pattern as the ⚡ Activity + 💬 Chat
buttons removed in eadada1. Either drop the sidebar tab or reduce it
to a compact "N cred(s) captured — last: <username>" strip that
links to the full tab.

#### P7-B2 — ScanConsole → floating drawer
Console currently renders BELOW the workbench body; on a live scan
the Launch button + form scroll off-screen. Refactor into a floating
drawer (bottom-slide, dismissable, minimise-to-pill) so the user can
keep working while a scan runs. Behavior parity: SSE stream + Stop
chain button stay in the drawer header.

#### P7-B3 — Topology empty-state → inline launch hint + button
Reachability (281B) and AD (62B) views currently render a bare
"Nothing to draw" message. Attach a button per view that fires the
scan that would populate it:
  * AD → `recce ldap` + `recce ad` (import BloodHound) — button
    opens the import modal pre-selected.
  * Reachability → `recce enum --all-ports` with a hint about
    routing / overlapping segments.

#### P7-B4 — Engagement switcher header dropdown
`recce serve -o <dir>` serves ONE engagement; switching needs a
kill+relaunch. Add a header dropdown that lists sibling engagement
dirs (peer directories of the currently-served `-o`) with the
current one highlighted. Switch reloads the SPA with `?eng=<slug>`.
Backend gains `/api/engagements` (list) and `/api/engagement/switch`
(POST) endpoints.

#### P7-B5 — Canonicalise `Vuln.key` shape
Two shapes in use today:
  * `models.Vuln.key` (bare `"{ip}:{port}:{script}:{title[:60]}"`)
  * `tracking.vuln_row_key(v)` (`"vuln:…"` prefix)
`store.remove_finding` was fixed in 867aa6b to accept both, but the
dual-shape situation is likely to bite again elsewhere. Audit every
caller, pick ONE shape (the tracking form has a namespace prefix so
it's less collision-prone), migrate the store to write it, and drop
the fallback branch from `remove_finding`.

### Batch C — Large infrastructure

#### P7-C1 — Async `/api/spray` + `/api/act/run`
Both currently block the HTTP request for the full duration. Fold
both through the existing `webui.jobs` spawner so they return
`{id: <jobid>}` immediately and stream progress via
`/api/jobs/{id}/events` — same shape as `/api/scan` uses. The Cancel
button in CollabSidebar's jobs list would then apply.

#### P7-C2 — Attack chain DAG visualization
Chain views render steps as text lists. A dagre-style SVG with
`blocked → pending → proven` colored nodes + `depends_on` edges makes
the compromise story readable at a glance. Server side: extend each
chain's `/api/attack-chain/{ad,cloud,web}` payload with an
`edges[]` array (derived from step.depends_on). Client side: a shared
`ChainGraph.tsx` component that consumes the same shape.

#### P7-C3 — Fine-grained live events → toasts
`/api/events` SSE fires today for engagement mutations, and
`useEngagement.ts` reacts by refetching. Extend the event stream with
per-action events (spray hit, shell caught, chain rule fired, cred
captured, prove verdict landed) that the client surfaces as toasts
without a full refresh. New event kinds: `spray_hit`, `session_new`,
`session_lost`, `chain_rule_fired`, `cred_captured`, `prove_verdict`.

#### P7-C4 — Delete-host cascade with impact preview
`Store.delete_host` removes the host row but doesn't advertise what
goes with it (findings, credentials sourced from the host, tracking
rows, chain-rule facts). Add an `impact_preview(ip) -> {findings, creds,
issues, chain_facts}` method + a WebGUI confirm modal that surfaces
the counts before deletion.

#### P7-C5 — Long-scan progress bar
Nuclei / snmp / sweep / vulns can run 5-45min. Console shows stdout
lines but no "N/M hosts done" progress. Parse the existing
`report refreshed (X host(s) so far)` line already emitted by
`recce enum`, expose it as a `progress: {done, total}` field on
`/api/jobs/{id}` and render a bar next to the running-job chip in
CollabSidebar.

#### P7-C6 — Top-bar jobs pill
AutocrackStatus already sits in the header (self-refreshing widget).
Add a similar `JobsPill` component that shows "N jobs · click to
show console" — no need to open Sessions to see what's running.

### Batch D — Test coverage

#### P7-D1 — Commit WebGUI E2E smoke as CI tests ✅ (2026-09-02, `<pending-hash>`)
Promoted `scratchpad/api_sweep.py` + `scratchpad/scan_smoke.py` (both
built during the P7 audit) to real tests under `tests/test_webui_smoke.py`.
Uses the same `TestClient` + `mock_engagement.build` fixtures as
`tests/test_webui.py` so it's always-on (no live server needed).
39 test cases: 35 parametrized GET sweep + 4 scan-launcher lifecycle.
Confirmed pass under `pytest -n auto` (xdist). Catches the class of bug
that let the `delete-finding` key mismatch + `cloud_metadata`
ModuleNotFoundError + `Vuln.cve` AttributeError ship before we noticed.

---

## Backlog (small fixes, not big enough for their own priority)

- Phase C `ExploitSurfaceCallout` self-hide race (P0-5 above).
- `test_scan_context_reports_qualifying_hosts_per_command` fix filtered
  underscore-prefixed private helpers, but a class-scoped inner class
  named `<Foo>_targets` inside a module could still shadow the module's
  own `<slug>_targets`. Brittle — better to require an
  `is_targets: bool = True` marker on the actual _targets function
  and filter by that.
- test_env compose file still has `version: "3.8"` which docker compose
  v2 warns is obsolete. Remove the line.
- `.recce-plan/tier{1,2,3}/*.json` and `.recce-plan/audit/*.json` are
  untracked. Decide whether to commit them or gitignore.
- Phase B1 skipped some finding kinds in the `attack:*` workflow with
  `reason` strings — worth reviewing whether any of them were skipped
  because the audit was slightly wrong.
- Phase C's `"surface"` tab id vs old `"exploit"` tab (see P0-4).

---

## Not doing (decided against)

- **`--pwn` autonomy mode.** User explicitly said "there shouldn't
  be much automation". T3 primitives stay opt-in per-invocation
  (via `--exploit` when it lands, per P1-7) rather than a global
  autonomy flag.
- **Random-payload fuzzing / IDS-noisy scans.** Recce's value prop is
  "safe intelligence for a tester on an authorized engagement" —
  fuzzing muddies that.
- **Rewriting the frontend.** Existing React + TS + Vite works; the
  visual language is consistent enough that Phase C + D reused the
  Phase B GUI patterns without friction.
- **Replacing hashcat / netexec / impacket.** Recce integrates with
  these; reimplementing them is out of scope.
- **Replacing BloodHound.** Read is fine; write (P2-3) is a stretch
  goal, not a replacement.

---

## Weekly-limit-aware pickup order

Given the limit constraint, next session should probably:
1. **P0-3 (bmc canary UDP fix)** — trivial cleanup, unblocks Vagrant
   test lane.
2. **P0-4 (tab rename)** — trivial UX cleanup so ExploitSurface tab
   isn't confusing.
3. **P0-1 (finish safe T2 promotions)** — the ONE big lift where
   token-per-value is highest. One fan-out workflow of 12 agents
   ships another ~50 promotions.

Everything past that is optional; P1/P2 are deferrable across
several weeks of separate sessions without recce degrading in
between.
