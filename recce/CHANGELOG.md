# Changelog

All notable changes to recce are documented here. Dates are UTC.

## [Unreleased]

### Fixed
- **A host with real open ports could be reported as "0 open ports".** The port sweep
  is completeness-first (retries, congestion-adaptive verify re-scan, truncation flag),
  but its result was only used as the `-p` list handed to the enum phase — the final
  host was then rebuilt *entirely* from the enum re-scan's XML. That enum pass is a much
  heavier `-sV`/`-sC` scan with **none** of the sweep's congestion-adaptive retry, so on
  a lossy/rate-limited network (or under a host-timeout) it under-reported, and any port
  it missed was **silently dropped** — discarding what the sweep had definitively found.
  This was maddening because the verify re-scan would log *"found N ports"* and the host
  would still show 0. Now the sweep's open ports are **folded into the host after enum**,
  so the enum phase can only enrich them, never erase them — it is structurally no longer
  the stage that decides the final port list.
- **`--fast` (masscan) hardened against the same loss without trusting masscan blindly.**
  masscan is stateless and can false-positive, so its ports are kept only if the enum
  re-scan didn't **actively disprove** them (nmap saw the port `closed` via a RST). A
  masscan port nmap simply couldn't reach (`filtered`/no-response = packet loss) is kept
  and tagged `detect_source=masscan` (marked *not confirmed*); a masscan port nmap proved
  closed is pruned. Recovers real ports lost to enum packet loss while still dropping
  masscan's spurious opens. New regression tests in `tests/test_enum_seed.py`.

### Changed
- **The Sköll-Fieldkit integration is now the fieldkit integration.** The companion kit
  was renamed to [**fieldkit**](https://github.com/dloucks01/fieldkit), so the commands
  follow: **`recce fieldkit-export`** / **`recce fieldkit-import`**, writing `eng/fieldkit/`
  with a **`FIELDKIT.md`** plan. `skoll-export` / `skoll-import` still work as hidden
  deprecated aliases (they print a nudge), so existing scripts keep running.
  Imported findings are now tagged source **`fieldkit`** (was `skoll`), and hostname-only
  findings synthesize a `fieldkit:<name>` host key. **Existing engagements need no
  migration** - old `skoll`-tagged vulns still load and render, and re-importing merges
  onto them rather than duplicating (dedup is by title + port, and a synthetic host is
  matched by hostname).
- **`recce ingest` auto-resolves the target host from the enum's own interface IPs.**
  Running `recce ingest enum.txt` with no `--host` now lands the loot on the real
  enumerated host in scope by matching the box's own `NET-IFACE` IP(s) from the ingested
  network block (then by banner hostname, else synthesizing as before). So an on-target
  enum that carries its own topology attaches to the host it came from without the
  operator having to name it — the topology feeds straight into the architecture and
  reachability maps.

## [0.4.0] - 2026-07-27

### Changed
- **Full network map rebuilt as subnet panels + a host grid.** Each network segment is
  now a bordered panel with a header (subnet · host count · per-role summary · owned
  count) and its hosts laid out in a multi-column **grid** instead of one tall column, so
  a large segment no longer scrolls forever (a 400-host estate roughly halved in height)
  and the page reads as a structured map rather than hosts stacked down the page. Added a
  title, an AD-domain strip and a role/severity/owned legend. The >50-host overview
  (per-role counts) is unchanged.
- **Attack path is now a directly-viewable SVG, not Mermaid/Graphviz.** `recce
  attackpath` writes **`attack-path.svg`** (staged left-to-right kill chain — Initial
  Access → Priv-Esc → Credential Access → Lateral Movement → Domain Dominance — with
  stage arrows and dashed same-host continuity), and `report.html` embeds the same
  diagram inline. It opens in any browser with no tools and prints to PDF. The
  `attack_path.mmd`/`.dot` exports and `attackpath.mermaid()`/`.dot()` are removed
  (same airgap reasoning as the network map).
- **Network map is now SVG only, in two forms — full and overview.** Every report writes
  **`network-map-full.svg`** (every host broken out) and **`network-map-overview.svg`**
  (per-subnet role counts); both open in any browser with no tools and print to PDF —
  airgap-native. `netmap.svg` takes an `aggregate` flag (the copy embedded in
  `report.html`/`assets.html` still auto-picks by size, collapsing a >50-host estate for
  readability). Scale-tested at 400 hosts. The Mermaid (`architecture.mmd`) and Graphviz
  (`architecture.dot`) exports are **removed** — they required a renderer recce users on
  an air-gapped box don't have, and the SVG needs none.
- **Role labelling:** a Windows *client* OS (Windows 10/11/7/8/XP/Vista) with SMB open
  is now classed as **Workstation**, not **File/SMB**. 445 is open on every domain-joined
  workstation, so the old rule mislabelled essentially every workstation as a file
  server; File/SMB is now reserved for server OSes.

### Added
- **One-command deep mass scan (`recce scan --deep`).** A single kickoff runs the whole
  credential-free mass surface across every target in one invocation: host discovery →
  port scan → service/version → vuln scan → **every applicable deep module**
  (web/smb/ftp/snmp/db/nfs/rsync/…, each self-skipping where nothing matches). Equivalent
  to `scan` immediately followed by `sweep`; `--skip`/`--only-modules` narrow the deep
  pass. (Companion, Sköll side: `sweep.py plan --oneshot` emits a single runnable
  `mass-scan.sh` that hits the whole scope in one go.)
- **Observed-reachability map from on-target topology (`network-reachability.svg`).** The
  on-target enums (recce's own, and the Sköll linpriv/winpriv enum) now emit a machine
  `NET-IFACE / NET-ROUTE / NET-NEIGH / NET-PEER` block; `recce ingest` folds it onto the
  host (`Host.topology`) and the report draws a **ground-truth** host-to-host map — a
  link only where a foothold actually reached the other end (ARP neighbour = same-segment
  L2 contact; live connection = an established peer). Dual-homed **pivots** that bridge
  segments are flagged. This is the honest counterpart to the tiered map's credentialed
  pivot *surface*: here the edges are observed, not inferred. `ingest` now also accepts a
  topology-only block (no `[!]` findings required). `netmap.adjacency()` exposes the
  edges/pivots.
- **Device icons on the diagrams.** Role-based glyphs — Domain Controller (server tower
  + star), Server (rack), Workstation/host (monitor) — now mark each card on the attack
  path and each chip on the tiered map, with a shared legend. Per-system cards on the
  **full network map** and the **reachability map** now use a shared `host_tile()`: a soft
  role-tinted **header band** (device icon + role), a faintly tinted body with the **IP**,
  a real hostname (an IP-derived name like `10-0-10-10` is suppressed so the IP never
  prints twice) and an OS/note line, an **outline severity chip** (CRIT/HIGH/MED/LOW) and
  an **owned ✓**. The attack path also got a visual pass (stage accent bars, soft shadows,
  device + same-host keys).
  All still pure inline SVG, no tools.
- **Logical architecture view (`network-architecture.svg`).** A real network diagram, not
  a host list: the AD domain over a **routed core**, each segment reached through its
  **gateway** — a router, or a **firewall** for an edge/DMZ segment, with the gateway IP
  when an on-target enum's routes have been ingested — and an **L2 switch**, then the
  segment's role make-up and access/severity, stacked by tier (edge/DMZ → servers →
  workstations). New switch/router/firewall glyphs. Honest: every segment shown was
  reachable from the assessment host, gateway IPs are real, and a switch is the standard
  L2-segment symbol (recce does not fingerprint physical switches). It's the headline of
  the report's Network map, with the per-host segment grid as the drill-down inventory.
  **Topology-driven pass:** once an on-target enum's routes/interfaces are folded in via
  `ingest`, the generic core is replaced by the **real gateway devices** (their IPs from
  `NET-ROUTE default via …`), each segment connects to its actual gateway on the routed
  backbone, and a **dual-homed pivot draws a direct segment-to-segment link** (observed
  ground truth). Segments with no ingested route show "gateway not observed" rather than
  guessing; it gets more accurate the more footholds you feed it.
- **Tiered lateral map (`network-map-tiered.svg`).** A third network-map view that
  groups the estate into trust tiers — **Domain Controllers → servers → workstations &
  hosts** — with the AD domain, per-role counts and access (✓ owned) overlay, upward
  escalation arrows (client → server → DC), and a **credentialed pivot-surface** legend
  (SMB/WinRM/RDP/SSH/MSSQL host counts + footholds held). It answers "how does this look
  from the DC down" and "what can move where laterally" honestly: it is a *logical*
  tiering — recce enumerates hosts independently and does not test host-to-host network
  reachability, so the pivot surface lists services that accept remote auth, not routing.
  Written on every report and embedded in `assets.html`.
- **Sköll-Fieldkit integration (`skoll-export` / `skoll-import`).** recce now
  round-trips with the [Sköll-Fieldkit](https://github.com/dloucks01/skoll-fieldkit)
  exploitation kit, so enumeration seeds exploitation and proven findings flow back
  into the workbook + report. Both directions are file-based and stdlib-only — neither
  tool imports the other, so each runs standalone on an airgapped box and only the
  handoff files travel between them.
  - **`recce skoll-export -o eng`** writes `eng/skoll/`: a severity-ranked **`SKOLL.md`**
    attack plan ("run *this* generator on *that* host, because …"), a rich
    **`recce-bridge.json`** (each host's open ports, service/version, recce's **confirmed**
    findings and the suggested Sköll generator) for `sweep.py triage --recce`, plus a
    synthesized **`ports.gnmap`** and **`smb-null.txt`** for Sköll's unmodified
    `sweep.py triage --nmap/--nxc` path. Respects target selection (IPs / ranges / CIDR /
    `@file`). The plan and bridge also carry **ready-to-paste generator commands** derived
    from what recce enumerated: `gen_exploit.py find --service <p> --version <v>` per
    fingerprinted service (with confirmed CVEs attached), and `gen_shell.py` /
    `gen_spray.py` lines per host from recce's captured credentials and enumerated users —
    exported alongside as **`users.txt`** and **`creds.txt`**.
  - **`recce skoll-import <findings.json> -o eng`** folds a Sköll findings file back in —
    the KB-enriched `recce_findings.json` (from `gen_report.py --export-recce`) or a raw
    `findings.json`. Each proven finding becomes a **confirmed** vulnerability (source
    `skoll`) on its host, landing in the Vulnerabilities sheet, the report and the DOCX
    write-ups; the host is marked *access-gained* (ticks the Checklist **Access** step).
    Idempotent — deduped by title + host, so re-import as you prove each finding.
  - Full round-trip guide in **`INTEGRATION.md`** (now shipped in the burn package).

## [0.3.0] - 2026-07-26

### Added
- **Wall-clock budget + live progress for the deep-service probe loops** (`svcprobe`).
  The credential-free modules probe hosts sequentially on raw sockets; a large target
  list with slow/filtered hosts (a /24 with no SNMP, thousands of AS-REP attempts)
  could run for many minutes with no output — indistinguishable from a hang — and a
  Ctrl-C lost everything probed so far. A shared driver now gives redis / elasticsearch
  / rsync / nfs / mongodb / snmp / kerberos three properties: an optional **`--budget
  SECONDS`** cap (stops early and keeps partial results), **throttled per-target
  progress** (`[i/N] redis 10.0.0.7 …`) so a long run reads as working, and **Ctrl-C
  safety** (a keyboard interrupt stops the loop and the partial results are still folded
  + saved). When a run stops early the CLI says so explicitly, so partial coverage is
  never mistaken for a complete assessment. Behaviour is unchanged when `--budget` is
  omitted. Now applied to **all** the sequential deep modules — smb, ftp, ldap, mssql
  and web included (web cancels pending hosts at the budget and keeps the per-host
  results it already persisted; ldap and mssql run each whole per-target unit — probe +
  paged auth enum / SQL-Browser — under the guard, so a slow authenticated enum can't
  overrun unbounded and a Ctrl-C keeps partial results).

- **Credential-less AD roasting (`recce kerberos` / `asrep`).** A minimal Kerberos
  client — hand-rolled ASN.1 DER over TCP 88, no impacket — that needs **no credential**,
  only a DC and candidate usernames (from the LDAP/SharpHound accounts recce already
  enumerated, or a `--userlist`). For each name it sends a pre-auth-less AS-REQ: an
  **AS-REP back** means the account has pre-auth disabled, and recce captures the
  encrypted part as a crackable `$krb5asrep$` hash (**AS-REP roasting with no
  credential** — CONFIRMED high, critical if privileged); a **KDC_ERR_PREAUTH_REQUIRED**
  confirms a **valid username** (enumeration with no logon → no lockouts), while
  **PRINCIPAL_UNKNOWN** means it doesn't exist. Feeds the totals, a dedicated
  **Kerberos** tab, the prove engine, and `sweep`. Read-only — it only requests tickets.
- **rsync-daemon deep module (`recce rsync`).** Speaks the rsync daemon protocol
  (TCP 873) directly — no rsync binary. Reads the `@RSYNCD` greeting, lists the modules
  with `#list`, then probes each for anonymous access: an `@RSYNCD: OK` module is
  **readable with no credential** (CONFIRMED — unauthenticated read, and often write, of
  every file it exposes), while `@RSYNCD: AUTHREQD` is reported reachable-but-locked. The
  module inventory itself is flagged as an information leak. Read-only — recce reads the
  verdict line and never transfers a file. Feeds the totals, a dedicated **rsync** tab,
  the prove engine, and `sweep`.
- **NFS / mountd deep module (`recce nfs` / `showmount`).** Speaks ONC RPC (Sun RPC)
  directly with stdlib struct/XDR — no rpcinfo/showmount binary. Calls the portmapper
  DUMP (111) for the RPC directory, resolves mountd, and calls `MOUNTPROC_EXPORT` (the
  `showmount -e` equivalent) to read every export and its client ACL. An export shared
  to `*` / everyone (or with no host restriction) is flagged **world-mountable**
  (CONFIRMED — mountable by any host: read, and via `no_root_squash` write, every file).
  A restricted-but-enumerable export list and an open portmapper are lower-severity
  info leaks. Read-only — recce never mounts. Feeds the totals, a dedicated **NFS** tab,
  the prove engine, and `sweep`.
- **Redis deep module (`recce redis`).** Speaks the Redis wire protocol (RESP)
  directly on a raw socket — no redis-py. Sends PING + INFO, and uses INFO-without-auth
  as the discriminator: if the server stats come back with no credential the instance
  is **exposed unauthenticated** (CONFIRMED critical — full read/write plus the CONFIG
  `dir`/`dbfilename` + SAVE file-write → RCE primitive, which recce reads but never
  sets). A `-NOAUTH` reply is reported reachable-but-locked (not a finding). Old/EOL
  builds (< 6.0, pre-ACL) are flagged. Feeds the severity totals, a dedicated **Redis**
  tab, the prove engine, and `sweep`. Read-only.
- **Elasticsearch deep module (`recce elasticsearch` / `es`).** Talks to the ES HTTP
  API (9200/9201) with stdlib `http.client`. Fingerprints via `GET /`, then uses
  `GET /_cat/indices`-without-auth as the discriminator: if the index list comes back
  the cluster is **exposed unauthenticated** (CONFIRMED critical data exposure — every
  document readable/writable), recording index names + total document count. A
  401/security_exception is reported reachable-but-locked. Old/EOL builds (< 7.x, with
  the historical scripting-sandbox RCEs) are flagged. Feeds the severity totals, a
  dedicated **Elasticsearch** tab, the prove engine, and `sweep`. Read-only (GETs only).
- **Access + risk overlay on the AD architecture diagram.** Tier-0 objects recce
  **already holds** (usernames from captured credentials, or an accessed DC) get a
  bold border + ✓; nodes an attacker can **seize directly** get a risk dot (DCSync =
  critical, control ACL = high) — the same grounded overlay language as the network
  map. Legend keys appear only when they apply.
- **Network map enriched from SharpHound + other findings.** The logical map now
  overlays what the engagement actually established: hosts recce **gained access to**
  get a green outline + ✓ badge (and an "N owned" tally per segment), each host card
  carries a **risk dot** for its worst *confirmed* finding (unverified "potential"
  guesses are excluded), and **Domain Controllers are confirmed from the BloodHound
  data** — a DC that only had 445 open is still marked. The text summary gains a
  grounded "Status:" line (how many hosts owned / at critical-high risk) and an
  AD-confirmed-DC line. The same enrichment flows into `architecture.mmd` / `.dot`.
- **AD architecture diagram from the BloodHound / SharpHound collection**
  (`bloodhound.architecture()` + `netmap.ad_svg()`), rendered as an **inline SVG that
  draws directly in the HTML report** (and prints to PDF) — no BloodHound GUI, Neo4j,
  Mermaid or Graphviz needed. It is the **curated tier-0 slice**, not the unreadable
  full graph: the **domain(s)** on top, the **high-value groups** (Domain Admins,
  Administrators, …) and **Domain Controllers** below, and the **privileged members /
  principals that can seize tier-0** at the bottom — with **MemberOf**, **control (ACL /
  DCSync)** and **domain-trust** edges between them. Large graphs are capped for
  legibility (with a truncation note); a standalone `ad-architecture.svg` is also
  written next to the report. Everything is grounded in what SharpHound collected.
- **Architecture / network map from the enumeration** (`netmap.py`), rendered as an
  **inline SVG that draws directly in the HTML report** — no Mermaid/Graphviz tools
  needed, and it prints straight to PDF from the browser. Each **subnet** is a network
  segment, every host a **role-tagged, colour-coded card** (DC / DB / Web / Mail /
  File-SMB / Workstation), with **AD domain** nodes and dashed edges to their DCs; a
  large estate (>50 live hosts) aggregates each subnet to role counts so it stays
  readable. Explicitly a **logical** map, not physical/routing topology — only
  relationships recce actually observed are drawn, nothing inferred. The same map is
  still also written as `architecture.mmd` / `architecture.dot` for those who use them.
- **Users, credentials and key-information inventory in the HTML report.** New sections:
  **Key information** (AD domains, DCs, functional level, machine-account quota,
  password policy), **Users & accounts** (every discovered user with admin /
  kerberoastable / AS-REP / delegation / disabled flags, plus shares), and
  **Credentials captured** (every recovered/stacked credential with type, source and
  origin host). Credential **secrets are masked** in this shareable HTML — the full
  values for spraying stay on the workbook's Credentials tab.

### Fixed
- **Code audit — false-finding and crash fixes.**
  - `parser`: a patched host whose NSE script prints `State: NOT VULNERABLE` no
    longer becomes a false high-severity finding (the substring `VULNERABLE` inside
    `NOT VULNERABLE` was matching); confirmed-vulnerable RCE families (ms17-010,
    ms08-067, …) with no embedded CVSS now rate **critical** instead of a generic high.
  - `vulndb`: the OpenSSH *regreSSHion* (CVE-2024-6387) signature used `eq: 9.8p1` —
    which is the **patched** build — flagging fixed hosts and missing 9.4–9.7; it is
    now a proper `8.5p1 ≤ x < 9.8p1` range. OS-gated signatures (BlueKeep) now resolve
    an NT version from nmap's Windows product-name strings ("Windows 7", "2008 R2"),
    so they actually fire.
  - `web`: default-HTTP-Basic-credential detection no longer treats a 301/302 redirect
    as a confirmed credical — only a 200 counts as proof.
  - `ldap`: `result_code(None)` no longer raises an uncaught `TypeError` (crashing the
    authenticated/pass-the-hash enum) when a server closes the socket or sends a short
    frame.
  - `report_html`: `ssh-key` credentials are now masked in the shareable HTML (they
    previously rendered the full key path/material).
  - `bloodhound`: SharpHound SID case is normalised on graph **edges** as well as
    nodes, so lowercase/hand-built collections no longer produce zero attack paths.
  - `cli`: `review --service IP:PORT` no longer crashes on a missing/non-numeric port
    and now resolves the real protocol (a UDP service tick was silently a no-op).
  - Robustness: `mongodb` reply parsing honours the reply opcode (fingerprints legacy
    OP_REPLY servers) and survives hostile BSON array keys; `snmp` decodes signed
    INTEGERs correctly; `store` keeps the newer NTLM facts on merge.

### Changed
- **Split the HTML report into a findings page and an architecture & assets page.**
  `report.html` now stays focused on the assessment (exec summary, dashboard, scoring
  legend, findings, attack path, coverage checklist), while a new self-contained
  **`assets.html`** holds the reference material: the **network map**, the **AD
  architecture** diagram, **key information**, the **users / accounts** inventory, and
  the **(masked) credentials**. The two pages cross-link in their headers. Both are
  still fully self-contained (no JS, no external assets) and print to PDF.
- **Attack path is now framed honestly as PROJECTED, not a proven kill chain.** recce
  builds the path from confirmed findings (`_confirmed_vulns` excludes "potential"
  version guesses) and observes each step's precondition — but it does **not** execute
  the chain (recce never exploits). The report's Attack-path section now carries a
  "projected" tag and a prominent note: the route is precondition-grounded but has not
  been walked end-to-end, every step gives the command to run + how to validate, and
  lateral-movement steps are options that apply only once you hold a valid credential.
  The workbook's Attack Path tab description says the same. No overclaim that the path
  "works."

### Added
- **Read-only "Assessment coverage" checklist in the HTML report.** A per-host,
  per-subnet progress grid mirroring the workbook Checklist (✓ done · ☐ to-do · —
  not-applicable), so a non-technical stakeholder can see how far the assessment got
  in a browser without opening Excel. It reflects both the tool's auto/derived state
  and the operator's ticks (passed through from the datastore). It is deliberately
  **read-only**: editing still happens in `enumeration.xlsx`, the one place ticks
  persist back into recce's datastore and survive re-scans (a static HTML file can't
  do that offline without a server or a non-authoritative browser-local store).
- **Expanded, grounded executive summary + "How findings are scored" in the HTML
  report.** The exec summary now adds a **Confirmed** tile (and a **Footholds** tile
  when access was gained) and a plain-language **assessment** that separates what recce
  *confirmed by direct observation* from what is **potential** — inferred from a
  service's version/banner and explicitly "flagged for manual verification, not
  presented as fact." A new **How findings are scored** section explains *why* a rating
  is assigned: the **severity** bands (Critical ≥ CVSS 9.0, High 7.0–8.9, Medium
  4.0–6.9, Low < 4.0, plus impact-based for observed misconfigs) and the **confidence**
  labels (Confirmed / Likely / Potential). Every finding now carries a **confidence
  badge** and a one-line **"why this rating"** basis (e.g. "rated High from the
  published CVSS score of CVE-…"), and the findings table gains a Confidence column —
  so nothing in the report reads as fact that recce did not actually observe.
- **Visual "At a glance" dashboard in the HTML report.** `report.html` now opens with
  a graphics band aimed at a non-technical reader: an inline-SVG **severity donut**
  (finding mix at a glance), a **Machines by risk** bar chart (how many live hosts fall
  into each worst-severity bucket), and a **Most-affected systems** bar chart (hosts
  ranked by high + critical findings). All rendered with inline SVG/CSS — no external
  assets, no JavaScript — so the single file still opens offline in any browser and
  prints cleanly. Replaces the old plain severity-bar rollup.
- **Initial-access tracking — the `Access` step is now auto-derived, and a new
  `access` command.** recce marks a host as *access gained* the moment a credentialed
  phase confirms a foothold — a valid credential or local admin from `credenum` /
  `credsweep`, an SSH session, or a working MSSQL login (`Host.access_gained`) — and the
  Checklist **Access** step auto-ticks (green/auto instead of amber/manual, joining
  enum/vuln/web/db/priv-esc). The `access` command reviews footholds per host
  (`recce access`), re-derives them from existing findings, or records one you gained
  another way (`recce access --host IP --note '...'`, `--undo` to clear). `status` now
  shows Access under the auto "Tool progress" block (operator-tick still overrides), and
  the flag round-trips the datastore + survives a re-scan merge. Closes the per-host
  "what's done, what's left" tracking goal for the access phase.
- **`recce sweep` / `recce credsweep` — one command each for the two post-`enum` deep
  passes.** Instead of typing the deep modules by hand after enum, these run them in
  one shot; each module self-skips when the datastore has no matching service, and the
  workbook is rebuilt exactly once at the end (intermediate rebuilds are deferred).
  - **`sweep`** is the **unauthenticated** pass: web/smb/ftp/ldap/snmp/mongodb/docker/
    kubernetes/mssql, using recce's own stdlib probes — no creds needed. `--vulns` also
    runs the nmap NSE scan. Passing creds to `sweep` is refused with a pointer to
    `credsweep` (a credentialed action must be explicit, never a side-effect of a flag).
  - **`credsweep`** is the **authenticated** pass (requires `-u/-p`): the netexec/
    impacket phase (`credenum`) plus the authenticated facets of `ldap` (kerberoast/
    AS-REP/accounts), `smb` (credentialed shares + write proof), `mssql` (access/
    privilege matrix) and `ftp`. The unauth-only modules are intentionally absent —
    you run `sweep` for those.
  - Both take `--skip`/`--only-modules` to narrow the set and `--no-probe` to fold
    passively; a module that errors is isolated (logged, the sweep continues) rather
    than aborting the run.
  - Surfaced everywhere: the `recce` quickstart, `status`'s suggested-next-step (points
    to `sweep` when several deep-dives are pending), the workbook **Start Here** +
    **Runbook** tabs, `README.md`, `QUICKSTART.md`, `CHEATSHEET.html` and `SECURITY.md`
    (which notes `sweep` is credential-free/read-only and `credsweep` is the
    authenticated pass) were all updated to lead with the two grouped commands.
- **Live end-to-end smoke test** (`tests/test_live_smoke.py`). Stands up real localhost
  web / MongoDB-wire / FTP servers and drives the actual `recce` CLI against them —
  `import` → `sweep` folds genuine findings from the live probes (MongoDB unauth
  exposure with the version read off the wire, web cookie/dir-listing, FTP anonymous),
  and a real nmap-backed `recce enum` discovers a live open port — proving the whole
  scan → parse → probe → fold → report path against live sockets, not fixtures. Plus
  `sweep` selection/deferral wiring tests against the bundled sample.
- **Credentialed-path integration tests** (`tests/test_cred_integration.py`). Install a
  fake `nxc` binary on PATH that emits real netexec output, so the credentialed modules
  run their actual `subprocess.run` → stdout-parse → finding-fold → access-derivation
  path (including `recce credenum` end to end) without needing netexec or a live DC —
  previously these were only monkeypatched.
- **Scale test** (`tests/test_scale.py`). Builds a 500-host / 20-subnet datastore and
  rebuilds the workbook + runs `status`/`access` over it, asserting correct output and
  a near-linear time budget so an O(n²) regression in reporting/tracking is caught.
- **`ldap` — deep LDAP / Active Directory directory enumeration (stdlib only).** A
  hand-rolled BER/ASN.1 LDAP client on a raw socket (no python-ldap / ldap3), so it
  runs on a stock airgapped Kali. Credential-free and read-only, against a Directory
  port (389/636/3268/3269) it: attempts an **anonymous simple bind**; reads the
  **RootDSE** (naming contexts, domain/forest DNS names, the DC's dnsHostName, the
  domain/forest **functional level**, supported SASL); tries to **read the naming
  context anonymously** (a real misconfig — the default AD posture denies it); and
  flags **cleartext LDAP** on 389 as a credential-sniff / NTLM-relay surface. LDAPS
  (636/3269) is wrapped in TLS first. Findings fold into the severity totals, the
  Vulnerabilities sheet, the write-ups, a dedicated **LDAP** workbook tab, the prove
  engine (anonymous-bind / anonymous-read / cleartext each adjudicated CONFIRMED —
  recce performed the bind itself), the exploit plan (ldapsearch enumeration,
  ntlmrelayx relay), the `status` service-module coverage, and the Checklist auto-tick.
  - **Authenticated enumeration is now in-house too** (`recce ldap -u U -p P -d DOM`):
    the stdlib client does a UPN simple bind and **paged** subtree searches (walking
    past AD's MaxPageSize via the SimplePagedResults control) for users, computers and
    the domain object, deriving kerberoastable / AS-REP-roastable / unconstrained- &
    constrained-delegation / privileged / disabled from the `userAccountControl` bits
    and attributes. It produces `Account` objects that flow straight into **Users &
    Accounts, AD Quick Wins, Kerberoast and AS-REP** — no hand-off to nxc/bloodhound-
    python — plus module findings for machine-account-quota > 0, a zero lockout
    threshold (spray-friendly), and passwords in `description` fields. An extensible-
    match filter encoder (`userAccountControl:1.2.840.113556.1.4.803:=…`) backs the
    bit tests. LDAPS (636/3269) is TLS-wrapped for the authenticated bind too.
  - **Pass-the-hash** (`recce ldap -u U -d DOM --hash <NT>`): a new stdlib `ntlm`
    module (NTLMSSP Type 1/2/3 with an NTLMv2 response, and a pure-Python MD4 since
    modern OpenSSL drops it) drives an LDAP SASL **GSS-SPNEGO** bind, so the whole
    authenticated enumeration above runs from an NT hash with no plaintext password.
    The NTLMv2 crypto is validated against the MS-NLMP 4.2.4 worked example.
  - **Full NTLM sign+seal on plaintext 389.** When the pass-the-hash bind runs on
    cleartext 389, recce now negotiates SIGN+SEAL with key exchange and wraps every
    post-bind LDAP PDU in an NTLM signature + RC4-sealed payload — so a DC that
    enforces *LDAP signing / channel binding* accepts the enumeration without TLS.
    Adds a pure-stdlib RC4, the MS-NLMP session-key / sign-key / seal-key derivation,
    and a `SecurityContext` that wraps/unwraps the SASL security layer transparently
    (the search code is unchanged). RC4 is checked against known-answer vectors and
    the whole sealed channel is exercised end-to-end against a mock DC that recovers
    the session key from the client's Type 3 and seals its own replies. LDAPS remains
    the path when you'd rather let TLS carry it (no sealing then).
- **`snmp` — deep SNMP enumeration over UDP (stdlib only).** A hand-rolled SNMP v2c
  client on a raw UDP socket (BER/ASN.1 with OID base-128 encoding, GETNEXT walking —
  no pysnmp), so it runs on a stock airgapped Kali. Credential-free and **read-only**:
  recce never sends a SET, so a read-write community is flagged by *name* but never
  exercised. Against a host it **guesses common community strings** (public/private/…),
  reads the **system group** (sysDescr / sysName), and **walks** the Windows LanManager
  user table, running processes, installed software and interfaces. Enumerated local
  accounts become `Account` objects that flow into **Users & Accounts** (a pre-auth
  spray list). Findings (guessable community, exposed user accounts, process/software
  inventory) fold into the severity totals, the Vulnerabilities sheet, the write-ups, a
  dedicated **SNMP** workbook tab, the prove engine (each disclosure adjudicated
  CONFIRMED — recce read the data back itself), the exploit plan (snmpwalk / snmp-check
  → spray), and the `status` service-module coverage. SNMP discovery *is* a GET, so no
  prior UDP scan is required — `recce snmp` probes 161 directly.
- **`mongodb` — deep MongoDB enumeration (stdlib only).** A hand-rolled MongoDB wire-
  protocol client (OP_MSG opcode 2013 with a minimal BSON encoder/decoder — no pymongo).
  Credential-free and read-only: it runs **hello** + **buildInfo** to fingerprint the
  version and replica-set role, then the discriminator — **`listDatabases` without
  authentication**. If the instance returns the database list, it is exposed
  unauthenticated (full read/write to every database) and recce raises a **critical**
  finding; if it errors "not authorized", auth is enforced and recce reports it
  reachable-but-locked (no finding). An end-of-life build raises a medium. Findings fold
  into the severity totals, the Vulnerabilities sheet, the write-ups, a dedicated
  **MongoDB** workbook tab, the prove engine (unauth `listDatabases` CONFIRMED), the
  exploit plan (mongosh / mongodump), and the `status` coverage.
- **Web signatures — Tier 1 niche-app coverage (data-driven, no new module).** Extends
  the existing `web` sweep (`web.py`) rather than adding per-app modules, so each app is
  a fingerprint + a self-proving path, folding into the same **Web** / **Vulnerabilities**
  / **Verification** sheets. Added: **Jenkins** script console reachable unauthenticated
  (critical — Groovy RCE), **Keycloak** admin console reachable, **Grafana** plugin path
  traversal (CVE-2021-43798, reads `/etc/passwd` read-only to confirm), **HashiCorp
  Vault** seal-status/version exposure, **Elasticsearch** unauthenticated index read
  (data exposure), and **Kibana** version disclosure — plus fingerprints for all six.
  A new **form/JSON default-credential probe** (`_form_login_defaults`, opt-in via
  `--creds`, one attempt per documented default, lockout-aware) confirms **Grafana**
  `admin/admin` and **MinIO** `minioadmin/minioadmin`, and HTTP-Basic `guest/guest`
  now covers the **RabbitMQ** management API. Each finding gets a CONFIRMED prove-engine
  verdict with app-specific escalation and an exploit-plan action (Jenkins RCE, Grafana
  file read, Elasticsearch dump, default-cred login).
- **SQL injection detection + form-field fuzzing (`web --crawl`).** The crawler now
  fuzzes **form fields** (POST/GET bodies), not just URL query params — a shared
  injection transport (`_make_sender`) drives both the existing reflection/SSTI canary
  and a new **SQLi engine** against every discovered input. The engine confirms three
  ways, all with **non-destructive payloads** (quote-break + `AND`/sleep inside the
  SELECT/WHERE context — never a stacked `DROP`/`UPDATE`/`DELETE`): **error-based** (a
  DBMS error — MySQL/PostgreSQL/MSSQL/Oracle/SQLite — that appears only after the
  quote-break), **boolean-based blind** (a TRUE payload matches the baseline while a
  FALSE one diverges, re-tested to reproduce, and skipped entirely on highly dynamic
  pages to avoid false positives), and **time-based blind** (opt-in via `--sqli-time`;
  a deliberate DB sleep whose delay scales with the sleep argument). Destructive-looking
  forms (`action` matching delete/remove/logout/…) are never submitted; password and
  anti-CSRF fields are never fuzzed; per-endpoint injection budget is bounded. Findings
  land as `web-sqli` (CWE-89) with a CONFIRMED prove-engine verdict and a pre-filled
  `sqlmap` exploit-plan action.
- **Cookie hardening + open-redirect + path-traversal checks.** `_fetch` now preserves
  every `Set-Cookie` (repeats were being collapsed), and a new per-cookie analysis
  (`_cookie_findings`) flags missing **HttpOnly**/**Secure** (kept), missing **SameSite**
  (or `SameSite=None` without `Secure`), a **session cookie set over cleartext HTTP**
  (token exposed on the wire), a missing **`__Host-`/`__Secure-` prefix**, and an
  **over-broad parent `Domain`** scope (CWE-1004/614/1275/319). Two new active param
  checks join the `--crawl` sweep (GET params **and** form fields, via the shared
  injection transport): **open redirect** (`web-openredirect`, CWE-601 — a parameter
  reflected into a `3xx Location` pointing at an attacker host, read-only, no auto-follow)
  and **generic path traversal / local file read** (`web-lfi`, CWE-22 — `../…/etc/passwd`
  + `....//`, `%2f` and Windows `win.ini` variants, only on file-ish param names to keep
  false positives and request budget down). Both get CONFIRMED prove-engine verdicts;
  path traversal adds a `curl`/`php://filter` exploit-plan action.
- **Discovery hardening — fewer false "host down".** The ping sweep now SYN-pings a
  broader port set that includes the ports firewalled Windows/AD hosts most often still
  answer (88 Kerberos, 389 LDAP, 5985 WinRM, + mail/DB ports) and retries a dropped
  probe once more (`--max-retries` 1 → 2). More importantly, a **partial** sweep no
  longer silently drops the non-responders: recce now **reconfirms** them with a fast
  `-Pn` top-100-ports scan (`scanner.reconfirm_hosts`) — a host that answers on any port
  is definitively up, so a firewalled-but-alive box that blocks ping is recovered into
  the enumeration instead of being written off as down. Bounded (one sweep, `--open`,
  fail-fast, skipped above `reconfirm_cap` = 1024 non-responders), and disableable with
  `--no-reconfirm`. This complements the existing 0-response → auto-`-Pn` fallback, the
  0-port congestion-adaptive re-scan, and the UDP liveness probe.
- **`--targets-up` — authoritative target list (no false "no hosts" from a timeout).**
  Target `@files` now parse `IP hostname` pairs (space / comma / tab / `hosts`-file
  style) — the name flows into the report and the IP stays the scan target. With
  `--targets-up`, recce treats the list as authoritative: it implies `-Pn` and
  **pre-seeds every target into the datastore up front** (with its provided hostname,
  `up_reason` = `target-list`), so a slow, timed-out, crashed or killed scan can never
  make a real host vanish from the report — the host is already there and scanning only
  enriches it. Pre-seeding persists immediately to SQLite, so even a hard-killed run
  keeps every target (rebuildable with `recce report`). Use it when you have a complete
  IP/hostname list you trust.
- **Full-port scan is explicit and partial coverage is flagged.** A full 65535-port TCP
  sweep is already the default (the `standard`/`thorough` profiles), but a reduced scan
  could be mistaken for complete. recce now prints the **port scope** at the start of the
  enum phase — a full sweep is stated plainly, and a top-N scan (`quick` profile /
  `--top-ports` / `--fast`) prints a loud `PARTIAL, NOT a full scan` warning pointing at
  `--all-ports`. The scope is recorded and echoed by `status`; `--all-ports` now
  explicitly overrides the profile (applied last, so it wins over `quick`/`--top-ports`)
  to force a full sweep on demand. Combined with the existing host-timeout truncation
  flagging, a scan is never silently narrower than it looks.

- **Engagement-readiness hardening.**
  - **Basic UDP coverage in the enum phase.** A TCP-only sweep misses UDP services, so
    `enum` now also sweeps a curated set of high-value UDP ports (DNS, DHCP, TFTP, NTP,
    NetBIOS, SNMP, IKE/VPN, syslog, IPMI, MSSQL-browser, SIP, SSDP, mDNS) with service
    detection + the cheap SNMP/DNS/NTP/NBT/IKE scripts, folding any open UDP services
    into the host. On by default (needs root; auto-skips with a warning otherwise);
    `--no-udp` to skip. `--udp-top N` still drives the larger vulns-phase UDP scan.
  - **Exclude IPs from scope, from a file, persistently.** `--exclude` now accepts
    `@file` (one IP/range/CIDR per line, `IP hostname` lines welcome) alongside inline
    tokens, and the exclusion set is **persisted to the engagement** — once an IP is
    excluded it stays out of scope on every later phase/re-run without re-typing.
  - **Fewer form-fuzzing side effects.** The `--crawl` form fuzzer now refuses to submit
    a form whose action or fields signal a real side effect — delete/pay/checkout/
    invite/send/subscribe/upload/… actions, transactional/content fields (amount, card,
    email, message, …), or any file-upload — and **records** the skipped forms as an
    info finding so nothing is silently untested. Login/search/generic forms (where
    injection lives) stay fuzzable. `--fuzz-risky-forms` opts back into submitting
    state-changing forms on a throwaway target (file uploads are never submitted).

### Added (high-fidelity decoder + probe tests)
- **Fuzz-invariant harness for every Layer-1 decoder** (`tests/test_fuzz_decoders.py`).
  Each pure decoder (SNMP `parse_response`, BSON `bson_parse`, LDAP `parse_search_entry`
  / `result_code` / `_op_tag`, NTLM `parse_type2`, SMB2/SMB1 negotiate, `web.fingerprint`,
  `parse_nmap_xml`) is hammered with every truncation, byte-flip, corrupted length field,
  random splice and targeted structural attack (deep nesting, unterminated cstrings) of a
  real message. A SIGALRM watchdog bounds each call so an infinite loop or non-advancing
  offset fails the test instead of hanging the suite; each decoder is checked against its
  *own* allowed-exception set, so any undeclared exception (the class its caller can't
  catch) is flagged.
- **Golden wire-vector tests** (`tests/test_wire_vectors.py`) assert the exact parsed
  output for a real message per protocol — the other half of fidelity, catching a decoder
  that stops mis-reads a field (offset/endianness/sign) even when it never raises.
- **Fake-transport probe tests** (`tests/test_probe_transport.py`) stand up tiny 127.0.0.1
  replay servers and point the real `smb`/`ftp`/`docker`/`kubernetes`/`web.scan_endpoint`
  probes at them — no socket or parser mocking, so the exact socket→parse→findings path a
  live target drives is exercised. Closes the loopback-server gap for the probes that had
  none (SNMP/MongoDB/LDAP already had them); includes an integration-level regression guard
  for the `_is_tls` plain-HTTP bug.
- **Tool-output text-parser fuzzing.** The same harness now mutates a real stdout sample
  of every parser that ingests external-tool output — `mssql.parse_nxc_mssql` / `parse_enum`
  / `parse_dbowner` / `parse_exec` / `parse_datamine` / `parse_permmine` / `parse_write_proof`,
  `credenum.parse_nxc_smb` / `parse_getuserspns` / `parse_getnpusers` / `parse_secretsdump`
  / `parse_ssh_enum`, and `bloodhound.parse_tgs` / `parse_asrep` / `parse_secretsdump` — with
  line truncation, field/sentinel corruption, injected noise lines, ANSI/unicode/NUL and pure
  garbage. Asserts each degrades to an empty/partial result of the right *type* rather than
  crashing the credentialed-enum phase, plus a `dbs`-argument-mismatch case for the db-scoped
  MSSQL parsers. (All 15 held up — the parsers were already defensively written; this locks
  the contract in as a regression guard.)
- Shared fixtures live in `tests/wire_vectors.py`, so the fuzzer and the golden tests
  mutate/parse byte-for-byte the same real message.

### Fixed (high-fidelity test batch)
- **`bson_parse` could crash a MongoDB probe with an unhandled `RecursionError`.** A
  hostile/corrupt daemon sending a deeply nested BSON document (embedded-doc / array types)
  recursed past Python's stack limit; `mongodb.command` catches `struct.error`/`IndexError`/
  `ValueError` but **not** `RecursionError`, so it would escape and kill the enum phase.
  `bson_parse` now caps nesting depth (`_MAX_BSON_DEPTH = 100`; real replies nest a few
  levels) and stops safely. Found on the first run of the new fuzz harness.

### Fixed (audit + end-to-end run)
- **Plain-HTTP services on odd ports were scanned as HTTPS and missed entirely.**
  `_is_tls` substring-matched the *product* name, so any product containing "http"+"s"
  ("SimpleHTTPServer" → "…**https**erver"), "ssl" or "tls" was wrongly treated as TLS —
  a plain-HTTP 8080 got probed over TLS, the handshake failed, and **every** web finding
  (.git/.env/SQLi/etc.) on that port was silently lost. Now only the nmap service +
  tunnel decide TLS; an explicit `http` service is trusted as plaintext. (Found by the
  end-to-end run.)
- **A hostname target or large CIDR could abort the whole scope.** `_expand_token`
  misparsed a hyphenated FQDN (`mail-1.corp.example`) or a typo (`10.0.0.10-`) as a
  numeric range and raised `ValueError`, rejecting *every* target; and it materialised
  an entire CIDR with no cap (an IPv4 `/8` = 16M, an IPv6 `/64` = astronomical) → hang/
  OOM before any scan. Now a range only expands when both sides are numeric, and a
  network above 65 536 addresses is refused with a clear message.
- **`parse_nmap_xml` could raise despite its "never raises" contract** — a well-formed
  XML with an empty/odd numeric attribute (`portid=""`) crashed the run on the main
  thread. Numeric attributes now parse tolerantly.
- **MongoDB BSON parser hung forever on a hostile/corrupt document** (a negative string/
  binary length made the parse offset stand still); the wire reader also had no
  message-length cap. Both are now bounded, so a decoy/misbehaving daemon can't hang or
  OOM the probe.
- **Docker probe crashed on a malformed JSON array**, the LDAP pass-the-hash **sealed
  channel crashed the module on a truncated/tampered frame**, and a **`--targets-up`
  seed marked a truncated enum as complete** on merge — all now degrade cleanly / are
  preserved.
- **Review-coverage could never reach 100%**: unconfirmed `-Pn` phantom hosts were
  counted in the denominator but appear on no sheet. Coverage now counts confirmed-up
  hosts only, matching the Checklist. (Directly relevant to per-host completion tracking.)
- Smaller hardening: `PROFILES` are deep-copied per run (were shared mutable singletons);
  `Host.from_json` tolerates schema drift (unknown keys) on a carried-over datastore;
  `--exclude` persistence and masscan partial-sweep now fail/​warn instead of silently
  losing hosts; HTTP-Basic default-cred probe capped at a real 5 attempts; SNMP replies
  are correlated by request-id (UDP); report generation survives a null severity.

### Fixed (full-codebase audit)
- **`_discover` crashed the caller on invalid targets.** Its error paths returned a
  3-tuple after the callers were updated to unpack 4 values, so a bad CIDR / empty
  scope raised inside `cmd_enum`/`cmd_scan` instead of exiting clean. Return the 4-tuple.
- **`store._merge` silently dropped port enrichment on re-persist.** Six `Port` fields
  (`reason`, `ostype`, `servicefp`, `detect_source`, `banner`, `binary`) were not
  merged, so the on-target `binary`/`detect_source` set by `ingest`/`deploy` never
  survived. Now merged; account `attrs`/`detail` also fold in on a key collision.
- **`_fold_host` dropped `up_reason`/`state`**, hiding an imported port-less host that
  was kept up only by its `report-listed` reason.
- **Docker/Kubernetes truncated large API responses.** A single 256 KB read cut a busy
  node's `/pods` or the apiserver's `/secrets` mid-buffer; JSON parse failed and a
  critical exposure was downgraded to "reachable". Read to EOF (16 MB cap); an
  oversized list body still counts as a real list.
- **SMB2 negotiate trusted an error reply.** Offering a bare 3.1.1 dialect makes strict
  servers return `STATUS_INVALID_PARAMETER`, which was read as dialect-0 /
  signing-not-required and emitted a bogus finding. Validate command/status/
  StructureSize; stop offering 3.1.1 without contexts.
- **FTP write-proof claimed "fully reversible" even when the DELE failed**, leaving the
  marker behind. Track `cleanup_ok`, retry the delete, and soften the finding text.
- **Prove-engine verdicts:** the EOL recipe swallowed legacy-RCE findings ("just
  upgrade"); the null-session verdict false-CONFIRMED a *credentialed* share listing;
  OpenSSH `9.8` (non-portable, fixed) was mislabeled LIKELY; RCE findings (SambaCry,
  Ghostcat, …) got no Verification row at all. Fixed each and added a version-CVE
  catch-all.
- **Overview host-index deep-links** pointed at the wrong Checklist rows for one
  generation after an update added a host to an already-seen subnet (the row
  precompute walked linearly while the writer buckets by group). Bucket identically.
- **Misc:** TLS cert expiry parsed in local time vs a UTC now (`calendar.timegm`); the
  SNMP finding fired on a bare "public"/"private" substring; a masscan intermediate
  temp file was left behind; `cmd_smb`/`cmd_ftp` didn't auto-tick the Checklist when a
  live layer ran under `--no-probe`; `cmd_web` never cleared a stale manual web tick on
  re-run; xlsx dropdown/CF values weren't escaped.

### Changed (audit: performance + cleanup)
- **searchsploit is now cached process-wide** (lock-guarded), so N hosts on the same
  product cost one query instead of one-per-host-thread as the docstring always claimed.
- **Kubernetes** reuses the TLS/plaintext scheme learned from `/version` for its
  follow-up requests; **MSSQL** caches the SQL Browser (UDP 1434) probe per IP — both
  cut redundant connects on large scopes.
- **Privesc** marks its step in the worker and persists once (dropped a second
  full-host pass); `_generate_reports` loads credentials once instead of twice.
- **Dedup:** `svccommon.findings_to_vulns` replaces five near-identical copies; the
  service sheets share one `_write_findings_table`; duplicate severity maps and a
  fragile band-label string hack in the workbook builder removed.

### Added
- **UDP liveness fallback for silent `-Pn` hosts.** Under `-Pn` a host that answers
  nothing on TCP is genuinely ambiguous — dead, or alive behind a default-drop
  firewall. When the TCP sweep (and its verify re-scan) come back with zero ports on
  a host we're scanning on faith, recce now sends a UDP ping to common services
  (DNS/DHCP/NTP/NetBIOS/SNMP/IKE/Syslog/RIP/IPMI/SSDP/mDNS). A service reply *or* an
  ICMP port-unreachable comes back with a real nmap status reason, so the host flips
  from UNKNOWN to **confirmed up** instead of being written off as down. Runs `-sn`
  (not `-Pn`) so nmap's up/down verdict is meaningful again; needs root for raw UDP
  and logs a skip otherwise; `--no-udp-fallback` disables it. The discovery-phase
  reply reason (echo-reply/syn-ack/arp-response) now also propagates into the stored
  host, so a ping-only responder is recorded as proven-up even with no open ports.

### Changed
- **`Host.is_up` no longer counts `enumerated` as proof of life.** The enum phase
  marks every host it *tries* (including a dead `-Pn` IP that answered nothing), so
  liveness now rests only on real evidence: an open port, a finding/script/account,
  a genuine discovery/UDP reply, or DNS/ARP/OS data.
- **Checklist shows only hosts confirmed UP — and never writes a live host off as
  down.** A new one-directional `Host.is_up` gates the Checklist: a host stays on
  the list on *any* concrete proof of life (an open port, enumeration/a finding, a
  real nmap discovery reply, or DNS/ARP/OS evidence), so a live host is never
  dropped; only IPs with zero evidence (e.g. `-Pn` phantoms across a 900-host
  sweep) fall away. The nmap status *reason* is now parsed (`echo-reply`,
  `syn-ack`, `arp-response`, … = a real reply; `user-set` = the `-Pn` blanket
  assume-up, which is **not** proof), and a store merge can never downgrade a
  confirmed reply back to an assume-up. Scanned-but-unconfirmed IPs are tallied
  explicitly on the Overview ("Scanned, not confirmed up — treat as UNKNOWN, not
  down") and in the Markdown/HTML summaries, so nothing is silently lost.
- **Legend line on the Checklist tab itself.** A one-line legend now sits above the
  header (green step headers = auto-ticked by recce, amber = your manual sign-off;
  ☑/☐/— key; and the up-only rule spelled out). The workbook writer, freeze pane,
  auto-filter and every tracking read-back now locate the header row instead of
  assuming row 1, so the shifted header round-trips operator edits intact.

## [0.2.4] - 2026-07-23

## [0.2.4] - 2026-07-23

_Adds four deep offensive service modules (SMB, FTP, Docker, Kubernetes), live AD
Kerberos capture, executed web proofs (PUT / JWT alg:none), and closes the
prove-out audit gaps — every finding is now proven by execution and wired into the
totals, the prove engine, the reports, and its own workbook tab._

### Added
- **`deploy` — credentialed mass local-enum & priv-esc.** Hand recce credentials
  and it runs the read-only on-target enum scripts (`recce-enum.sh`/`.ps1`) across
  every host it can reach, in parallel, and folds the results straight into the
  report — no more per-box copy/run/`ingest` by hand. Transport is auto-selected
  per host from its open ports + OS: **SSH** (script piped over stdin, nothing
  written to disk), **WinRM** (run in-memory via `nxc winrm -X powershell
  -EncodedCommand`), or **SMB** (pushed to `%TEMP%`, run, deleted). Shells out to
  the same `ssh`/`sshpass` and `netexec`/`nxc` `credenum` already uses — and the
  Windows exec is **engine-agnostic**: if `nxc` isn't installed it uses **impacket**
  (`wmiexec`, plus `smbclient` for the push) instead, so it works on a stock Kali
  either way (impacket pairs especially cleanly with `--stager` — wmiexec runs the
  download cradle in memory, no file push at all). Creds:
  `--ssh-user/--ssh-pass/--ssh-key` for Linux, `-u/-p/-d` or `--hash` (pass-the-
  hash) for Windows. `--dry-run` previews the per-host transport plan; per-host
  failures are isolated and logged; loot is saved to `eng/loot/<ip>.txt`. The
  scripts are read-only and run no exploit code / no evasion. (The `ingest`
  folding logic is now shared via `_fold_loot`, so `deploy` and `ingest` fold
  identically.)
  - **nxc credential precheck.** Before running, `deploy` uses netexec to see which
    protocols the given creds actually authenticate to across the targets (SMB
    admin / WinRM / SSH) and picks the transport *proven* to work per host, rather
    than guessing from open ports — so it only runs where it truly can.
    `--no-validate` skips it.
  - **`--stager` (in-memory Windows exec over HTTP).** The 39 KB Windows script is
    too big to inline over SMB and a bloated blob over WinRM; with `--stager`,
    recce stands up a short-lived stdlib HTTP server (random token path, torn down
    after the run) and Windows hosts fetch + run it **in memory** via a one-line
    download cradle — no temp file, no size limit. **Auto-falls-back** to the push
    path if a host can't route back to `--lhost` (autodetected if omitted). SSH is
    unchanged (its stdin-pipe already runs in memory at any size).

### Changed
- **Checklist step headers are colour-coded auto vs manual.** Green headers = steps
  the tool ticks for you (Enumerated, Vuln-scan, Web, DB, Priv-esc); amber headers =
  manual sign-offs only you can confirm (AD, Access, Creds, Lateral). So it's obvious
  at a glance which boxes fill themselves and which are yours. (Also corrects the
  guide, which had listed Priv-esc as manual.)
- **Deep-service capabilities now auto-tick the Checklist as you run them.** Running
  `smb` / `ftp` / `docker` / `kubernetes` marks each port it actually assessed as
  vuln-scanned, and `mssql` also flags the host db-scanned — so the Checklist
  Vuln-scan / DB boxes (and the coverage totals) update automatically, with no manual
  ticking. A host only shows Vuln-scan done once *every* open port has been covered
  (by `vulns` and/or the per-service capabilities), so a partial scan never reads as
  complete.
- **Workbook is far easier on the eyes at scale (900+ hosts).** The big list/finding
  tabs now use Excel's collapsible row grouping so a large scope isn't one endless
  grid:
  - **Checklist** folds by subnet — click the outline [-] to collapse a whole /24 to
    one summary band (`subnet · N hosts · reviewed · high/crit`), expand the one
    you're working. The repeated Subnet column is gone (it's in the band), hosts with
    critical/high findings sort to the top of each subnet, and the # Vulns cell is
    coloured by the worst severity.
  - **Vulnerabilities** and **Verification** fold by host (worst-hosts first), with
    the Hostname column moved into the band.
  - **Services** folds by host too, with Hostname moved into the band.
  Wide text columns (Finding, Details, Remediation, Evidence, Enum command, …) now
  **wrap** so they read DOWN inside their column instead of running off to the right,
  while narrow columns stay single-line — the Details/Evidence are shown in **full**,
  never truncated. Identity columns stay frozen while you scroll, and every sheet
  keeps its autofilter.
- **Distribution is a plain drop-in tarball, not a wheel.** The shipped release
  artifact is the `make_package.sh` burn package — a single `recce-<version>/`
  directory you extract and run with `./bin/recce ...` (or `python3 -m recce`), no
  pip and no wheel, matching the airgapped/stdlib-only design. A pre-built
  `.tar.gz` + `.zip` + `SHA256SUMS` for the release lives in `recce/releases/`.
  (`pyproject.toml` stays so a wheel can still be built on demand, but it is no
  longer the recommended or shipped path.)
- **Workbook reorganised to follow the engagement flow.** The per-service deep-dive
  tabs (Databases, MSSQL, SMB, FTP, Docker, Kubernetes) are now a single grouped band
  right after the findings, the Active Directory cluster (Active Directory, AD Quick
  Wins, AD Findings, AD Attack Paths, Users & Accounts) is kept contiguous instead of
  being split by the service tabs, and Exploitation / Attack Path now come **before**
  Priv-Esc (you exploit → foothold → then escalate). The Overview jump-bar and the
  "Start Here" tab index follow the same order. The Overview also gains a **"Confirmed
  by recce (prove engine)"** total (the count of findings recce actively proved),
  and the CVE-curated tile is relabelled "Findings with a curated exploit" for
  accuracy. The "Start Here" guide and "Runbook" tabs are now fully self-consistent
  with the commands: every tab that's described maps to a listed command, including
  the previously-missing `web`, `exploitplan`, `attackpath` and `creds` (Runbook gains
  a "2b. Web" step and a "6. Act on the findings" phase; Report becomes phase 7).
- **PoCs are stronger, unambiguous proofs with an explicit ROE hand-off.** Each
  generated PoC now states a clear **`PROVEN:`** verdict and marks the single
  **`ACTION (ROE)`** line where the operator substitutes their authorized action:
  the **JWT** PoC forges the `alg:none` token *and replays it*, printing
  accepted-vs-denied so a CONFIRMED is unarguable; **SSTI** declares PROVEN on the
  `7*7→49` evaluation and fingerprints the engine; **PUT** shows the stored file
  then removes it; **git/heapdump/GraphQL/downloads** print a PROVEN line with a
  count of what was recovered. (The word "benign" was dropped from the wording;
  the "no AV/EDR evasion" boundary stays.)

### Added
- **`recce kubernetes` (alias `k8s`) — cluster attack-surface enumeration + tab.**
  Stdlib-only unauthenticated reads of the most dangerous Kubernetes exposures:
  the **kubelet** (10250 — anonymous `/pods` implies the `/exec` RCE-into-pods
  surface; 10255 read-only — pod specs leak env-var secrets), the
  **kube-apiserver** (6443/8443 — whether `system:anonymous` can LIST namespaces,
  and critically **Secrets** = cluster compromise; a 403 downgrades to an
  anonymous-auth-enabled note), and **etcd** (2379 — an unauthenticated key read =
  every Secret in the clear). Each successful read is the proof (recce only READS —
  it never execs into a pod or writes to etcd); findings fold into the main totals /
  Vulnerabilities sheet / write-ups and a new **Kubernetes** tab, and the prove
  engine adjudicates them CONFIRMED (or LIKELY for the anonymous-auth-only case).
  Airgapped-safe, stdlib only.
- **`recce docker` — exposed Docker Engine API detection + tab.** An unauthenticated
  Docker Engine API (TCP 2375, or 2376 without mutual-TLS) is remote **root** RCE on
  the host — anyone who reaches it can run a container that bind-mounts the host root
  as root. recce reads the API unauthenticated with stdlib HTTP (`/version`, `/info`,
  `/containers/json`, `/images/json`) and, if it answers, reports a **CONFIRMED
  critical** exposure plus a container/image-inventory info-leak finding — the
  successful unauthenticated read *is* the proof; recce deliberately does **not**
  create a container. The prove engine adjudicates it CONFIRMED, findings fold into
  the main totals / Vulnerabilities sheet / write-ups, and a new **Docker** tab
  carries the escape command (`docker -H … run -v /:/host … chroot /host sh`).
  Airgapped-safe, stdlib only.
- **`recce ftp` — FTP gets its own deep offensive module + tab.** Credential-free
  stdlib control-channel probe: reads the banner (→ product/version for the offline
  CVE DB and a narrow **known-backdoor map** — vsFTPd 2.3.4 CVE-2011-2523, ProFTPD
  1.3.3c, ProFTPD mod_copy CVE-2015-3306), tries an **anonymous** login, and
  inspects **FEAT** for AUTH TLS/FTPS so it can flag **cleartext** authentication.
  With an anonymous or credentialed session, a reversible **writable-directory
  proof** (`--prove-write`: STOR a marker via stdlib `ftplib`, then DELE it).
  Findings fold into the main totals, the Vulnerabilities sheet and the write-ups,
  and populate a new **FTP** tab; the prove engine adjudicates anonymous-login
  (CONFIRMED from the observed 230) and the backdoor/RCE builds (LIKELY, with the
  exact non-destructive trigger). Airgapped-safe; the write proof degrades cleanly.
- **`recce smb` — SMB / file sharing gets its own deep offensive module + tab.**
  Modelled on `recce mssql`, in two layers. **Credential-free (airgapped, stdlib):**
  recce crafts an SMB2 NEGOTIATE and reads the highest dialect and the *signing
  posture* (required vs merely enabled → the NTLM-relay surface), then an SMBv1
  NEGOTIATE to see whether the legacy protocol is still answered (the MS17-010 /
  EternalBlue surface) — both directly observed, not inferred from a banner, exactly
  like the MSSQL TDS pre-login probe. **With tools / credentials:** null & guest
  session share enumeration via `nxc smb` (reusing the shared parser), and a
  reversible **writable-share proof** (`--prove-write`: drop a marker file via
  `smbclient`, list it, delete it — nothing left behind). Every finding folds into
  the main severity totals, the Vulnerabilities sheet, the write-ups, and a new
  **SMB** workbook tab, each carrying the exact prove/abuse command and a detailed
  narrative of what it enables (relay → act-as-victim, writable share → SCF/LNK
  NetNTLM capture, null session → spray-list recon). The prove engine adjudicates
  the observed states directly: signing-not-required and SMBv1-enabled are
  **CONFIRMED** from the negotiate, signing-required is a **FALSE POSITIVE** for any
  relay finding. `--screenshots` saves terminal-output proof images. Airgapped-safe;
  the live layer degrades cleanly when nxc/smbclient are absent.
- **Findings are proven by execution, not just adjudicated (audit gaps closed).**
  Several checks that used to stop at "advertised / version-matched" now actively
  prove impact and downgrade themselves when the proof fails:
  - **Web `PUT` write primitive.** When `OPTIONS` advertises `PUT` and the scan is
    active, `recce web` PUTs a marker file, GETs it back to confirm the write
    landed, then DELETEs it (reversible). A confirmed round-trip is a **CONFIRMED**
    arbitrary-file-write finding (CWE-434, CWE-650); other advertised methods stay
    a separate *potential* note.
  - **Web JWT `alg:none`.** recce forges an unsigned token (`alg:none`, the
    original claims plus a harmless marker), replays it in the token's real
    location (cookie / `Authorization: Bearer`) against the same path, and compares
    the response to the authenticated and anonymous baselines. Forged-accepted +
    no-token-denied = **CONFIRMED** (signature not verified, tokens forgeable);
    forged-treated-as-no-token downgrades to a *rejected / not-exploitable* note;
    an ungated endpoint is reported inconclusive.
  - **AD live Kerberos capture.** With credentials and `--dc-ip`, the `ad` command
    can now *run* the published impacket tools to capture the real crackable
    material and fold each capture back in as a **proven** finding: `--roast`
    (`GetUserSPNs -request` → live TGS-REP hashes), `--asrep` (`GetNPUsers
    -request` → live AS-REP hashes), and `--dcsync` (`secretsdump -just-dc` →
    replicated NTLM hashes incl. krbtgt for golden-ticket persistence). All three
    are read-only (request tickets / replicate secrets — nothing on the target is
    modified) and only run when explicitly opted in. Captured hashes are written to
    `engagement/loot/` ready for hashcat, and `--screenshots` saves terminal-output
    proof images.
  - **Offline version→CVE matches** now get an honest verdict from the prove
    engine (LIKELY with the "distros backport without bumping the banner" caveat,
    or INCONCLUSIVE when no version was captured), and end-of-life/legacy services
    are CONFIRMED from the version fact itself.
- **Per-web-finding PoC generation.** `exploitplan` now writes a tailored, benign,
  runnable proof for *each* web finding into `exploit-plan/poc/`, with the target
  URL filled in: a **`git-dumper` script** for exposed `.git`, an **HTML page** that
  proves the CORS cross-origin credentialed read, a pure-python **`alg:none` JWT
  forge**, an **SSTI engine-identification script** (then `tplmap` for RCE in ROE),
  a **GraphQL schema dump**, an **actuator heapdump → secrets grep**, a **PUT
  write-primitive** proof, a **JS-secret extractor**, and a read-only fetch for
  exposed `.env`/`.aws`/`.htpasswd`/backups/`server-status`/`metrics`/`phpinfo`.
  Each is a benign proof (marker file / schema dump / redacted read); RCE
  escalations reference the published tool to run within ROE. The generated Python
  and shell are validated (compile / `sh -n`) by tests. Nothing obfuscated or
  AV-evasive.
- **`recce web` — web-facing services get their own category + deep scanning.**
  Every HTTP/HTTPS endpoint recce found (on ANY port, not just 80/443) is
  identified, categorized on a new **Web** workbook tab with its tech stack and
  the exact Kali deep-scan commands (whatweb / nikto / nuclei / gobuster / wpscan /
  sslscan, tailored to the detected stack). `recce web` then runs a stdlib,
  non-intrusive deep scan of each endpoint:
  - **tech fingerprint** (Server / X-Powered-By, framework cookies, CMS body
    signatures, `<title>`, meta generator),
  - **high-signal exposures** — `.git`/`.env`/`.svn`, Apache `server-status`,
    Spring **actuator** (+`/env`), `phpinfo`, readable `web.config`, Swagger,
    Tomcat Manager, WordPress — flagged **only when the response actually matches
    the signature** (the probe fetches it, so it's a real observation),
  - **directory listing**, **dangerous HTTP methods** (PUT/DELETE/TRACE via
    OPTIONS), **weak cookie flags** (HttpOnly/Secure), plus the existing
    security-header + TLS analysis.
  Findings fold into Vulnerabilities and flow through the **same prove + PoC**
  machinery: `recce prove` renders web verdicts (an exposed `.git` the probe
  fetched is CONFIRMED; a PUT advertised in OPTIONS is LIKELY with the curl to
  finish proving), and `exploitplan` writes a benign `recce_poc_web.sh` (curl-based
  proof requests). Airgapped-safe, stdlib only; heavier scanning is bridged to the
  Kali tools. `--no-active` keeps it to passive fingerprint + headers/TLS.
  - **Web scanning now runs automatically in the `vulns` phase** (the deep web
    enum replaced the old headers/TLS-only probe), so `.git`/`.env`/actuator/method
    exposures are found without a separate step; `recce web` re-runs or deep-dives.
    Non-HTTP TLS ports (LDAPS/IMAPS) skip the HTTP path probes but keep TLS checks.
  - **Authenticated web scanning**: `recce web --cookie 'session=…'` and repeatable
    `--header 'Authorization: Bearer …'` run the whole scan as a logged-in user.
  - **Authenticated crawling** (`recce web --crawl`): a same-origin BFS crawler
    (as the logged-in user) discovers pages, forms and params, tests each
    **discovered param** for reflection/SSTI (so the `7*7→49` proof lands on real
    parameters), and flags **password forms over cleartext HTTP** and **POST login
    forms without an anti-CSRF token**. Bounded (≤40 pages, depth 2), stdlib-only.
  - **Per-endpoint screenshots**: `recce web --screenshots` captures each endpoint
    with the headless browser into `engagement/screenshots/`.
  - **Web is now a coverage category.** Every HTTP/HTTPS endpoint counts toward a
    new **Web** line on the Overview / `status` coverage roll-up (ticked per
    endpoint from the Web tab's Status column), so Start-Here progress reflects the
    web surface, not just ports/vulns.
  - **More high-value exposures**: exposed **`.DS_Store`**, permissive
    **`crossdomain.xml`** (wildcard), **Prometheus `/metrics`**, **`.htpasswd`**
    (password hashes), Apache **`/server-info`**, exposed **`.aws/credentials`**,
    **WordPress REST user enumeration**, **GraphQL introspection** (POST probe),
    and **CORS that reflects an arbitrary Origin with credentials** — each flagged
    only on a positive signal and wired into prove + PoC.
  - **Deepened further:**
    - **Full Spring Boot Actuator dive** (self-gated on `/actuator`): `/env`,
      `/configprops`, **downloadable `/heapdump`** (full memory → secrets),
      `/mappings`, `/threaddump`, and **`/gateway/routes`** (Spring Cloud Gateway
      SpEL RCE surface, CVE-2022-22947).
    - **Secret extraction, redacted** — exposed `.env` / `.aws/credentials` /
      `.htpasswd` / actuator `/env` / `/configprops` now show *which* secrets
      leaked as `key=ab…yz` (never the raw value).
    - **Backup / source-file exposure** — `backup.sql`, `db.sql`, `*.zip`,
      `.env.bak`, `wp-config.php.bak`, … confirmed by content signature (SQL dump /
      zip magic / PHP / leaked secrets).
    - **`.git/config`** (remote URL, sometimes embedded creds), in addition to
      `.git/HEAD`.
    - **Product+version fingerprinting** (Jenkins/Confluence/GitLab/WordPress/…)
      enriches the port's product when nmap missed it — and the web scan now runs
      **before** the CVE mapping in `vulns`, so those recovered versions get
      matched to known CVEs.
    - **Opt-in default-credential probe** (`recce web --creds`): a tiny documented
      list against HTTP Basic-auth endpoints, capped at ≤5 tries/endpoint
      (lockout-aware).
    - **JWT weaknesses** — JWTs seen in cookies/headers/body are decoded and
      flagged: **`alg:none`** (forgeable, high), HS* (offline-crackable secret),
      RS*/ES* (algorithm-confusion). Free (reads the root response), so it runs even
      passively.
    - **SSTI / reflected-input quick check** — injects `{{7*7}}` / `${7*7}` /
      `<%=7*7%>` into a throwaway param; **`49` evaluating next to the canary is a
      strong, low-false-positive SSTI hit** (CONFIRMED in `prove`), and an
      unencoded `<i>` reflection is flagged as a reflected-XSS lead. One request,
      non-destructive.
    - **Client-side JS secret scraping** — same-origin `<script src>` files are
      fetched (bounded) and scanned for Google/AWS/Stripe/GitHub/Slack keys,
      private-key blocks and hardcoded `apiKey`s.
    - **WordPress plugin/version enum (wpscan-lite)** — core version (generator /
      `readme.html`), XML-RPC status, and a common-plugin sweep with each plugin's
      version from its `readme.txt` Stable tag.
- **`mssql` — offensive Microsoft SQL Server enumeration + attack chain.** Modelled
  on PowerUpSQL / impacket-mssqlclient / nxc mssql / **MSSQLPwner**:
  - **Credential-free, airgapped (recce's own stdlib probes):** SQL Browser (UDP
    1434) instance/version/port enumeration and a **TDS pre-login** probe for the
    exact server version and whether login encryption is enforced - no creds, no
    external tools. Plus the no-cred access checks (blank `sa`, anonymous, NTLM relay).
  - **With credentials, auto-runs `nxc mssql`** (when installed; falls back to
    commands otherwise): the access + privilege matrix - which servers your creds
    log into and whether the login is effectively **sysadmin** (`Pwn3d!`).
  - **Live deep enumeration via `impacket-mssqlclient`** (auto-run when installed):
    recce connects and runs the enumeration queries, then **detects the actual
    escalation chain on each instance from the live results** - an impersonatable
    sysadmin login (named), a **TRUSTWORTHY** DB owned by a sysadmin (named), a
    reachable **linked server** (named), `xp_cmdshell` already on, and recovered
    `sys.sql_logins` hashes - rendering a grounded *"Live chain: impersonate sa ->
    abuse TRUSTWORTHY payroll -> hop DW01"* plus the exact command per hop. The
    live enumeration (login, sysadmins, TRUSTWORTHY DBs, linked servers,
    impersonatable logins, config, hashes) is shown on the MSSQL sheet.
  - **Server-hardening & permission checks (automatic).** The live enum now also
    flags **mixed-mode authentication** (SQL logins / sprayable `sa`), **dangerous
    server-level permissions** held by the login without the sysadmin role
    (`IMPERSONATE ANY LOGIN`, `ALTER ANY LOGIN`, `CONTROL SERVER`, … - each a privesc
    path), **server permissions over-granted to the public role**, and **startup
    stored procedures** (auto-run as sysadmin = persistence).
  - **Per-database object-permission mining (`--perms`).** For every database:
    whether **`guest` is enabled** (any login gets in) and exactly which objects the
    **public/guest** role can access - read grants on sensitive tables, and
    write/execute grants (INSERT/UPDATE/DELETE/EXECUTE/CONTROL) that any login
    inherits. A `DB_NAME()` guard prevents mis-attribution across a failed `USE`.
  - **Proof screenshots for the technical walkthrough (`--screenshots`).** Executed
    proofs - RCE output, the reversible write-proof, and located sensitive data - are
    rendered as terminal-style PNGs into `engagement/screenshots/` via the headless
    browser, ready to drop into the write-ups.
  - **Database data-mining (`--data`).** Enumerates every database, every table
    (with row counts) and the columns/tables whose names indicate **sensitive data**
    - passwords, tokens, PII (SSN/DOB/email/phone) and financial fields
    (card/CVV/IBAN/salary) - across all databases, and raises a *"Sensitive data
    accessible"* finding naming exactly where the data is (e.g. `payroll ->
    dbo.Employees.ssn, dbo.Employees.email`). A `DB_NAME()` guard means a failed
    `USE` can't mis-attribute tables.
  - **Reversible proof of impact (`--prove-write`).** Demonstrates - non-destructively -
    that the login can **modify data and change security state**: it creates a table,
    writes a row, **MODIFIES the field** (before -> after captured as evidence), drops
    the table, and (as sysadmin) adds a temporary login to a server role, confirms the
    membership, then removes it and drops the login - **undoing every change**. Raises
    a critical *"Proved write + permission-modify capability (reversible)"* finding
    carrying the before/after evidence, so a write/permission vulnerability is
    actually proven, not merely asserted.
  - **Detailed narratives - what each MSSQL issue actually enables.** Every MSSQL
    finding now carries an accurate, capability-focused explanation written for the
    report and write-ups. E.g. the **xp_cmdshell** narrative explains that it runs
    arbitrary OS commands as the SQL Server *service account* (a virtual or domain
    account), giving code execution on the host, local-admin actions, SeImpersonate
    -> SYSTEM, LSASS/credential theft and domain pivoting - and that "disabled" is a
    two-statement speed bump for a sysadmin, not a control. Narratives cover blank
    logins, sysadmin creds, impersonation, TRUSTWORTHY, linked-server reach/sysadmin/
    fixed-login, hashes, stored credentials, NTLM disclosure, unencrypted logins, EOL,
    UNC->relay and confirmed RCE. They render on the MSSQL sheet ("what each issue
    enables") and fold into the finding evidence for the write-ups. A **"How MSSQL is
    tested"** methodology section (discovery -> auth -> privilege -> escalation ->
    effect -> secrets) heads the sheet so a reader understands the approach.
  - **Stored-credential & linked-login secret extraction.** The live enumeration now
    reads `sys.credentials`, SQL Agent proxies (`msdb.dbo.sysproxies`) and the
    linked-login mappings (`sys.linked_logins`) - surfacing the (often privileged)
    accounts SQL Server holds a secret for and every linked server that uses a
    **fixed login mapping** (a stored remote password). A fixed mapping to **`sa`**
    is a **critical** finding. recce shows the identity/mapping and hands off the
    Service-Master-Key decryption to the existing tool
    (`PowerUpSQL Get-SQLServerLinkedServerLogin` / `Get-SQLCredential`) rather than
    shipping a crypto blob. Rendered on the MSSQL sheet (stored credentials, Agent
    proxies, linked logins).
  - **Command execution for effect - `--exec CMD --method {xp,ole,agent,clr}`.**
    Runs an OS command on each reachable instance and **captures the output**:
    **xp_cmdshell** (native), **OLE Automation** (`sp_OACreate WScript.Shell` -> file
    -> `OPENROWSET` read-back), and a **SQL Agent** CmdExec job (create -> run ->
    read -> auto-delete) - the alternatives for when xp_cmdshell is disabled or
    watched. A success is folded into the main totals as a *critical* "Confirmed OS
    command execution via <method>" finding with the captured output. **CLR** is a
    deliberate hand-off to `mssqlpwner custom-asm` / PowerUpSQL (recce does not
    generate or load an assembly).
  - **Auto-verified TRUSTWORTHY chains.** For each TRUSTWORTHY database owned by a
    sysadmin, recce runs a second pass to check whether your login is actually
    **db_owner** there (guarded by `DB_NAME()` so a failed `USE` can't give a false
    positive). A confirmed one becomes a **critical** *"CONFIRMED privesc: db_owner
    on a TRUSTWORTHY db"* finding; a verified-negative is dropped; an unverifiable
    one stays a candidate.
  - **UNC coercion -> NTLM relay with real targets + an executable trigger.** recce
    enumerates concrete relay destinations from the datastore - **LDAP on a DC**
    (RBCD / shadow creds), **another MSSQL** (sysadmin if the service account is
    admin there), and **SMB-signing-not-required hosts** (local admin) - and writes
    the two-step block (start `ntlmrelayx` at a target, then trigger). With
    `--relay --lhost <ip>` recce **executes the trigger** itself
    (`EXEC master..xp_dirtree '\\<lhost>\...'`) so the SQL service account
    authenticates to your listener.
  - **Recursive linked-server graph walk** (the MSSQLPwner move): from the entry
    instance recce follows every linked server, running an identity/privilege query
    **through the chain** with correctly nested `EXEC('...') AT [link]` (single
    quotes doubled per hop), discovering each remote instance's `@@SERVERNAME`,
    your effective login, whether you're **sysadmin there**, and *its* linked
    servers - then recursing. Cycles (bidirectional links), depth (`--link-depth`,
    default 4) and node count are all bounded. Every instance reachable **as
    sysadmin** becomes a critical finding with the full nested chain and a ready
    `xp_cmdshell` RCE command that runs through all the hops; the graph
    (`entry -> DW01 -> DW02  (DW02SRV as sa) [SYSADMIN]`) is drawn on the MSSQL
    sheet. `--no-links` skips the walk.
  - **The MSSQLPwner route** as a pre-filled runbook + attack chain: enumerate
    roles/databases/**TRUSTWORTHY** DBs/**linked servers**/**impersonatable
    logins**/`xp_cmdshell`-OLE-CLR status/`sys.sql_logins` hashes -> escalate
    (impersonation, TRUSTWORTHY+db_owner, linked-server hops, UNC->relay) ->
    **effect** (xp_cmdshell / sp_OACreate / CLR / Agent). Every command is
    pre-filled with your credentials.
  - Findings (blank-password login, xp_cmdshell enabled, pre-auth NTLM disclosure,
    no login encryption, EOL SQL Server, sysadmin credentials) feed the main
    **Overview** severity totals + write-ups, plus a dedicated **MSSQL** sheet with
    the endpoints, findings and runbook. `--local-auth` for SQL logins, `--lhost`
    for the relay commands, `--no-run`/`--no-probe` for airgapped use.
- **`ad` — SharpHound + Certipy (ADCS) import: AD vulns, ESC findings, and paths to
  Domain Admin.** One simple command, credentials-first:
  `recce ad loot.zip certipy.json -u alice -p 'Passw0rd!' -d corp.local -o eng`.
  Pass a SharpHound collection (`.zip` / directory / single `.json`) and/or a
  `certipy find -json` file - any mix; each input is auto-detected. recce parses
  the AD object graph offline (stdlib `json`/`zipfile`, no BloodHound/neo4j needed)
  and turns it into a provable runbook. (`bloodhound` is kept as an alias.)
  - **Credentials-first & copy-paste ready.** Give recce your account with
    `-u/-p/-d` (no NT hash needed) and it (a) starts the attack-path search **from
    your account** by default and (b) **pre-fills every generated command** with
    your username / password / domain / DC IP, so each line in the sheet runs as-is.
  - **ADCS / ESC findings (Certipy).** Every ESC Certipy flags (ESC1-ESC11, ESC13,
    ESC15/EKUwu) becomes a finding with the exact `certipy` command to prove/abuse
    it, the real template/CA name filled in, and *who* can enrol - e.g. ESC1 ->
    `certipy req … -template VulnUser -upn administrator@corp.local && certipy auth
    -pfx administrator.pfx`, ESC8 -> `certipy relay` + coercion.
  - **AD Findings sheet** — every misconfiguration / vulnerability the graph
    reveals, most-severe first, each with the **exact EXISTING-tool command to
    prove or abuse it**: Kerberoastable & AS-REP-roastable accounts (with the
    `GetUserSPNs`/`GetNPUsers` + hashcat lines), **DCSync rights held off tier-0**
    (`secretsdump -just-dc`), unconstrained/constrained delegation & **RBCD**,
    **shadow-credential** (`AddKeyCredentialLink`) edges (`certipy shadow`),
    dangerous ACLs from low-priv principals (`dacledit`/`bloodyAD`), passwords in
    descriptions, `PASSWD_NOTREQD`, and a non-zero **MachineAccountQuota**.
  - **AD Attack Paths sheet** — the **shortest privilege-escalation path from an
    owned / low-priv principal to Domain Admins / the domain object / a DC**
    (`--owned USER` to start from a principal you control; otherwise it shows what
    *any authenticated user* can reach), rendered as an edge chain with the exact
    tool + action to walk each hop.
  - **Kerberos for effect** — with your credential supplied, recce stages the
    actions to run: roast, AS-REP, DCSync, and delegation ticket forging, each
    parametrised with your account (a 32-hex secret is auto-treated as an NT hash
    and rendered as `-hashes`).
  - **Folded into the main findings.** The AD/ESC findings are also attached as
    first-class vulnerabilities on the DC / domain host (keyed by `--dc-ip` so they
    merge onto the scanned DC), so they now feed the **Overview severity totals**,
    the **Vulnerabilities sheet**, and the **per-finding writeups** (DOCX + HTML
    appendix) - each with its CWE, remediation, and the exact prove/abuse command
    as evidence - not just the AD-only sheets. Re-imports accumulate by default;
    `--replace-ad` clears the previously-imported AD/ESC findings on the DC host
    first, so remediated items drop off (scan-sourced vulns on that host are kept).
  - Merges the collected domain facts (functional level, trusts, MachineAccountQuota)
    into the Active Directory sheet even with no network scan. References existing
    published tooling (impacket / certipy / netexec / bloodyAD / Rubeus); generates
    no exploit code.
- **Engagement folder stays operator-accessible after sudo runs.** recce often
  runs under sudo (raw-socket scans, reading protected files), which left the
  output files root-owned and unreadable/uneditable to the normal user afterward.
  recce now chmods the whole engagement folder — every subdirectory and file — to
  **777** on every exit path (success, Ctrl-C, or crash, via a `finally`), and
  relaxes the folder as soon as it's created, so the operator always keeps full
  access to the workbook/reports/loot regardless of how recce was invoked.
  Best-effort: a file owned by another user that can't be chmod'd is skipped, never
  fatal.
- **On-target listener backfill — the binary behind every service.** The read-only
  enum scripts now emit a machine-parseable **listening-service inventory**: for
  each listening socket, `proto/addr/port` + the owning **process**, its **PID**,
  the hosting **Windows service** (svchost-backed ports resolve to the real
  service, e.g. `WinRM`), and — the part a remote scan can never see — the exact
  **backing binary** path (`readlink /proc/<pid>/exe` on Linux, the process
  `.Path` / service `ImagePath` on Windows). `ingest`/`deploy` fold this onto the
  host's ports: an existing scanned port keeps nmap's service name but gains the
  **Backing binary** (new Services-sheet column), and a **loopback-only** listener
  the network scan never reached is added as a fresh port tagged **`ID source =
  local`** so the sheet shows exactly where each fact came from. Purely
  read-only (`readlink` / `command -v` / `Get-*` queries) and degrades gracefully
  on older loot that lacks the section.
- **Richer HTML report — detailed findings appendix.** The shareable one-file HTML
  report now carries a **Finding details** section (below the summary table): one
  card per grounded finding, severity-ranked, with the **vulnerability type**,
  **CWE** and **CVE** references, **security aspect impacted (C/I/A)**, the
  **tools/checks** that found it, the full **affected-systems** list, a
  **Recommendation** block (the finding's remediation), and a trimmed **evidence
  excerpt** — the client-facing detail that previously lived only in the DOCX,
  now travelling in the self-contained HTML. Also embeds the Mermaid attack-path
  graph in the Attack-path section (offline, copyable).
- **Deeper service enum — product/version recovery (feeds CVE mapping).** `svcdetect`
  now mines a concrete **product + version** out of the banner it already holds
  (OpenSSH/dropbear, vsFTPd/ProFTPD/Pure-FTPd, Postfix/Exim/Sendmail,
  MySQL/MariaDB, Dovecot/Courier, Apache/nginx/IIS/Tomcat `Server:` headers, …) —
  so a port nmap named but left version-blank (or one recce banner-grabbed itself)
  gets a version the offline CVE mapper can key on. A no-traffic `enrich_versions`
  pass runs over **every** open port (even nmap-named ones) reading the servicefp
  and captured banner; it only ever *fills* a blank product, never overwrites what
  nmap concretely reported. Runs automatically in the enum path just before the
  version→CVE assessment.
- **Attack-path graph.** `recce attackpath` now also writes the synthesised path
  as a diagram — `attack_path.mmd` (Mermaid: stage subgraphs left-to-right, one
  node per confirmed step `host + finding`, dashed edges tracking a single box
  walked through the stages) and `attack_path.dot` (Graphviz: `dot -Tpng
  attack_path.dot -o attack_path.png`). Both are grounded purely in confirmed
  findings — no new scanning. The Mermaid source is also embedded, copyable, in
  the HTML report's Attack-path section (offline: no external JS), so the graph
  travels with the report and pastes straight into mermaid.live / GitHub.
- **`exploitplan` now emits benign PoC build recipes — the payload source, the
  build command, and the delivery — not just "drop a binary here."** For each
  confirmed finding it writes the standard, documented artifact to
  `exploit-plan/poc/` with the exact `gcc`/`x86_64-w64-mingw32-gcc`/`msfvenom`
  line: the LD_PRELOAD `.so` (SUID env-injection / writable-lib), a root-job shell
  PoC (writable cron/service/PATH-hijack), the `/etc/passwd` UID-0 recipe, a
  Windows service/intercept exe (unquoted-path / writable-binary / autorun), a
  hijack DLL (writable dir / COM), and an AlwaysInstallElevated MSI. Each per-host
  plan script embeds the **build → deliver → proof** block. The payloads are
  deliberately **benign proofs** (run `id`/`whoami` into a marker file, or add a
  clearly-named throwaway `recce_poc` account) — you swap the single ACTION line
  for your ROE command. Nothing is obfuscated or AV-evasive; a control that blocks
  a plain PoC is a scoping/exclusion conversation, which recce still says to have
  rather than engineering evasion. (The emitted `.so` source is covered by a test
  that actually compiles it.)
- **`recce prove` — is this finding real, or a false positive?** A new
  verification engine reasons over the evidence recce already collected (the exact
  version, the port state, the NSE detection result, the on-target privilege
  state) and returns a per-finding verdict for the noisy types testers can never
  easily disposition. Covered: **ActiveMQ (CVE-2023-46604), SMB signing / relay,
  MS17-010, SMBGhost, SeImpersonate/GodPotato, PrintNightmare (CVE-2021-34527/1675),
  BlueKeep (CVE-2019-0708), Heartbleed (CVE-2014-0160), Log4Shell (CVE-2021-44228),
  ZeroLogon (CVE-2020-1472), Kerberoast / AS-REP, null-session, anonymous-FTP,
  default-credentials and weak-TLS** — each with an OS/version/role/state gate so a
  patched build, a non-DC, or a newer OS is called out as a false positive:
  - **CONFIRMED** — the evidence positively proves it (an NSE detection fired,
    signing really is off, the privilege really is *Enabled*, we negotiated the
    weak cipher ourselves).
  - **FALSE POSITIVE** — the evidence disproves it (ActiveMQ build is ≥ the branch
    fix, SMB signing is *required*, the NSE check says NOT VULNERABLE, the OS build
    is outside the SMBGhost window). These are the ones you can safely dismiss.
  - **LIKELY** — preconditions hold but the final proof is the PoC; the exact safe
    command to finish proving is given.
  - **INCONCLUSIVE** — what to collect next (e.g. get the exact version, or run the
    on-target `whoami /priv` to confirm SeImpersonate is Enabled).

  Each verdict lists the evidence it used, the preconditions, the exact
  finish-proving command (within ROE — `nmap --script smb-vuln-ms17-010`,
  `nxc smb … --gen-relay-list`, `GodPotato -cmd whoami`, the msf module) and what a
  false positive looks like. `recce prove --run` additionally re-runs the
  NON-INTRUSIVE SMB detection NSE to move LIKELY verdicts to CONFIRMED / FALSE
  POSITIVE on fresh evidence. Results land on a new **Verification** workbook tab
  (real first, noise last). Nothing here exploits anything — it reasons and tells
  you the safe check to run.
- **Windows privesc: fully-qualified exploits, not just flagged classes.** Where
  the script used to say "unquoted service path" or "DLL hijack," it now computes
  and prints the exact artifact and the precise steps:
  - **Unquoted service paths** are resolved to the exact intercept exe Windows
    would load first (e.g. `C:\Program Files\Sub.exe`), the script checks which
    candidate directory *this* user can actually write, and the finding names the
    plant path, the service, its run-as account, and the `sc stop/start` line.
  - **Writable service binary / registry key** findings carry the exact
    `copy /Y … "<binPath>"` or `reg add … /v ImagePath …` command plus the
    service account.
  - **DLL hijacking** distinguishes writable **SYSTEM PATH** vs user PATH, names
    the writable Program-Files app dirs **and the exe(s) in them**, and flags
    **services whose binary sits in a writable dir** — each with the exact planting
    procedure (ProcMon → `NAME NOT FOUND` → `msfvenom -f dll`).
  - **COM hijack** prints the exact `reg add …\InprocServer32 /ve /d C:\evil.dll`.
  - Deeper Windows credential hunting: profile SSH/PEM keys (triaged), IIS
    `applicationHost.config`, scheduled-task passwords, PS transcripts, RDP files,
    and a profile-wide high-signal secret sweep.
  - All new findings promote to first-class Vulnerabilities and map to
    Exploitation-sheet plays (win-unquoted / win-writable-service / win-dll-hijack).
    Still 100% read-only.
- **On-target scripts now identify the EXACT exploit, not just the vector.** The
  goal is to beat lin/winPEAS at turning a finding into an action:
  - **Embedded GTFOBins-lite engine.** A SUID or NOPASSWD-sudo binary no longer
    says "look it up on gtfobins" — it prints the precise command for *that*
    binary (`find . -exec /bin/sh -p \; -quit`, `sudo vim -c ':!/bin/sh'`,
    `python3 -c 'import os;os.setuid(0);os.system("/bin/sh -p")'`, …), for ~50
    binaries in both SUID and sudo contexts. Capabilities (`cap_setuid`,
    `cap_dac_*`) print their exact commands too.
  - **Deeper analysis of custom SUID binaries.** A non-standard SUID root binary
    is statically analysed (read-only, `strings` only — never executed) to find
    the *actual* vector: which command it shells out to by bare name (**PATH
    hijack**, with the exact planting command), whether it reads `LD_*` (**env
    injection**), and any **writable file/config it opens** — each surfaced as its
    own finding with the concrete exploit.
  - **Serious credential & secret hunting.** SSH/PEM private keys are triaged
    (encrypted → `ssh2john`; unencrypted → ready-to-use, with the matching pubkey/
    host), plus a high-signal sweep for cloud keys (`AKIA…`, `AIza…`), tokens
    (`ghp_…`, `xox…`, GitLab PATs), JWTs, private-key blocks and `password=`/`api_key=`
    assignments across the likely locations, and named credential stores
    (`.git-credentials`, `.netrc`, `.npmrc`, `.aws`, docker/gcloud, mail spools).
    Windows gains the same: profile SSH keys, IIS `applicationHost.config`,
    scheduled-task passwords, PS transcripts, RDP files, and a profile-wide secret
    regex sweep. Everything remains 100% read-only.
- **On-target enum scripts go well beyond privesc: lateral movement, shell
  escape, persistence.** `recce-enum.sh` / `recce-enum.ps1` (run via `deploy` /
  `ingest`) gained whole new read-only sections, and their findings flow through
  the same parse → categorize → promote → playbook pipeline into the workbook:
  - **Lateral movement & pivoting.** Linux: live ssh-agent sockets, SSH trust
    graph (`known_hosts`/`config` ProxyJump), Kubernetes service-account tokens &
    kubeconfigs, config-management inventories (Ansible/Salt/Puppet), dual-homed
    detection, established-connection pivot leads, DB client creds. Windows:
    mapped drives, WinRM/PSRemoting reach + TrustedHosts, and read-only LDAP for
    the classic AD targets — **Kerberoastable** (SPN), **AS-REP roastable**, and
    **unconstrained-delegation** hosts.
  - **Restricted-shell / restricted-environment escape.** Linux: detects
    rbash/lshell/git-shell/`$-` jails and lists candidate escape interpreters.
    Windows: PowerShell **ConstrainedLanguage** mode, JEA session endpoints,
    AppLocker effective policy.
  - **Persistence footholds (read-only detection).** Writable login/boot hooks —
    Linux `.bashrc`/`profile.d`/`update-motd.d`/`authorized_keys`/PAM; Windows
    PowerShell profile, HKCU COM InprocServer32, WMI event subscriptions,
    AppInit_DLLs, accessibility (sethc/utilman) debugger hijacks, netsh helpers.
  - **Current-era kernel privesc.** nf_tables **CVE-2024-1086** range, plus
    `ptrace_scope`, unprivileged-userns and LSM (SELinux/AppArmor) posture.
  - Each new high-value finding is categorized (`lateral` / `escape` /
    `persistence`), the strongest promote to first-class Vulnerabilities, and the
    tailored **How-to-exploit** blocks + Exploitation-sheet plays reference only
    EXISTING public tooling (Rubeus/impacket GetUserSPNs/GetNPUsers, GTFOBins,
    kubectl, public PoCs). Still 100% read-only — no exploit code, no evasion.
- **Better service detection — no more dead "unknown" ports.** nmap's `-sV` is
  still the primary identifier, but the ports it leaves as `unknown`/`tcpwrapped`
  (especially Windows RPC/ephemeral services like **5040 CDPSvc**, 5357 wsdapi,
  47001 winrm-http, dynamic MSRPC) are now recovered by a new `svcdetect` layer,
  airgapped-safe and stdlib-only, in three escalating steps:
  1. **servicefp mining** — nmap already collected the service's raw response but
     couldn't match it; recce now keeps that fingerprint (previously discarded)
     and keyword-matches it itself (SSH/VNC/TLS/RDP/Redis/… signatures). No new
     traffic.
  2. **curated port map** — a well-known port with no name gets an *inferred*
     label from the port number (e.g. 5040 → "Windows CDPSvc"). No new traffic.
  3. **active banner grab** — a timeout-bounded connect-and-read (plus a few
     protocol nudges: HTTP HEAD, Redis PING, RDP X.224) fingerprints what the
     first two missed. Only touches the target; runs on a stock airgapped Kali.
  4. **second-opinion re-probe** — any ports STILL unnamed get one focused nmap
     `-sV --version-all` (intensity 9, every probe) aimed at just those. It's
     cheap because it's a handful of ports, and nmap's answer is authoritative
     (it upgrades our inferred/banner guess and is marked `nmap`). The first enum
     pass spends its version-detection budget across the whole host; this spends a
     fresh one on only the leftovers.

  The Services tab gains an **"ID source"** column (nmap / inferred / banner) so
  you can see *how confident* each label is, and a still-unknown port now shows a
  **suggested identification command** (`nmap -sV --version-all` / `amap`) in its
  Enum-command cell instead of being a dead end. `--no-probes` disables the active
  grab; the free passive layers always run.
- **Domain-qualified usernames are accepted anywhere creds are given.** `-u` now
  takes the credential however AD hands it to you — `CORP\user`,
  `corp.local/user`, or `user@corp.local` — and splits the domain out for you, so
  `-d` becomes optional (an explicit `-d` still wins, keeping e.g. the FQDN form
  over an embedded NetBIOS name). The domain flows through the whole authenticated
  path: nxc (`-d`), impacket (`domain/user`), WinRM and SMB. Applies to every
  credentialed command (`deploy`, `credenum`, `vulns`, `db`, `privesc`) and to the
  privileged `--admin-user` account.

### Changed
- **Priv-Esc tab is real findings now, not boilerplate.** It used to emit the
  generic Windows/Linux privesc *playbook* for every host in the datastore — so a
  host you'd never touched (even a network/broadcast address like `10.200.37.0`
  that slipped into scope) showed ~18 rows of "what to run once you have a shell,"
  making the whole tab read as filler. Fixed three ways:
  - **The tab is driven by the local sweep.** Confirmed escalation paths and
    on-target observations come from `recce deploy` / `ingest` folding the
    read-only `recce-enum.sh/.ps1` output into `local_findings` — that's what the
    Priv-Esc tab shows, plus remotely-observed signals (MS17-010, SMB signing off,
    IIS/MSSQL SeImpersonate, …).
  - **Un-swept hosts get one actionable to-do**, not a checklist: a host with open
    ports but no local sweep shows a single "Local privesc enum not yet run → run
    `recce deploy`" row. A host with no open ports and nothing observed produces
    **no rows at all** (so dead IPs never fabricate entries).
  - **The generic playbook moved to a new `Priv-Esc Playbook` reference sheet**,
    listed once per OS in scope instead of repeated per host.
- **Target hygiene: ranges drop the network / broadcast address.** A full-octet
  range like `10.200.37.0-255` now expands to `.1`–`.254` (it means "the subnet",
  not "scan `.0` and `.255`"), matching how CIDR expansion already behaved. An
  explicitly-typed single `…​.0` is still respected.
- **`deploy` now reports every host's outcome: succeeded / errored / unable.**
  Previously a host with no usable transport (no SSH/WinRM/SMB port, or creds that
  didn't validate) was silently rolled into a single "N skipped" count. Now every
  un-deployable host carries a plain-English reason (`skip_reason()` — e.g. "no
  remote-exec port open", "port open but missing SSH creds", "credentials did not
  authenticate"), and `deploy`: (1) lists both **WILL RUN** and **UNABLE / SKIPPED**
  (with reasons) in `--dry-run`; (2) ends a real run with a three-way
  **`DEPLOY RESULTS: X succeeded · Y errored · Z unable`** summary that lists the
  errored and unable hosts; and (3) writes the unable hosts to the **Overview
  issues tab** too, so the workbook shows what completed and what couldn't — not
  just the successes.
- **`--help` is scannable instead of a flat wall of flags.** Every command's
  options are now sorted into labelled groups — the one or two flags a normal run
  uses (`-o`, `-Pn`, `--fast`, `-u/-p/-d`) stay up top, and the tuning knobs fold
  into clearly-titled *(optional)* sections (`scan tuning`, `output & performance`,
  `privileged & LDAP`, `deploy options`). No flags were added, removed, or renamed
  and every existing invocation is unchanged — `recce <cmd> -h` just reads as
  "here's what you need, advanced stuff is over there." The common runs stay
  short: `recce enum 10.0.0.0/24 -o eng`, `recce vulns -o eng`,
  `recce deploy -u USER -p PASS -o eng`.
- **Port sweep is now completeness-first — it won't silently miss open ports.**
  The sweep is the foundation every later phase keys off, so three ways an open
  port could be silently dropped are closed:
  - **Retries.** `-Pn` used `--max-retries 1` ("fail fast on dead IPs"), so a
    single dropped SYN lost an open port. The sweep now uses `--max-retries 3` by
    default (tunable with `--max-retries`); dead IPs stay bounded by
    `--host-timeout`, not by starving retries.
  - **Verification re-scan.** A host that comes back with **0 open ports** is now
    re-scanned with an independent congestion-adaptive sweep before "no ports" is
    trusted — discovered-live hosts always, `-Pn` hosts with `--verify-all`. If
    the re-scan finds ports, the fast pass under-reported and the re-scan wins.
    `--no-verify` opts out.
  - **Truncation is no longer silent.** A sweep cut short by `--host-timeout`
    returns a *partial* port list; the host is now flagged `incomplete_scan`,
    called out in `status` and marked `⚠ PARTIAL` on the Checklist, so a truncated
    host is never mistaken for a fully-scanned empty one. (Ports union across
    scans, so a later complete sweep clears the flag.)

### Fixed
- **Exploits / exploitation surface was misleading — overhauled.** The
  Vulnerabilities "Proven exploit" column matched a searchsploit hit to a finding
  by **port alone**, so every finding on a port inherited that port's exploit — a
  weak-TLS finding claimed a Heartbleed exploit, "anonymous FTP login" claimed the
  vsftpd backdoor, unrelated Apache advisories all claimed the same path-traversal
  RCE. Now: (1) a searchsploit hit only links to a finding whose **CVEs actually
  match**, and is shown as a labelled **"candidate — verify"**, never as proof;
  (2) the column is renamed **"Exploit"** and only curated, named exploits
  (`proven_exploit_ref`) count as *proven* (and toward the Overview tile);
  (3) config/crypto-hardening findings (weak ciphers, old TLS, missing headers,
  anon login) never carry a proven exploit even if a CVE leaked into their output;
  (4) the **Exploits** sheet gains a **"Corroborates finding?"** column (which
  confirmed finding a candidate's CVEs line up with, else "product/version guess")
  and lists corroborated candidates first — leads to verify, not noise.
- **Truncated sweep no longer counts as fully scanned.** A host with a partial
  (host-timeout) port list is no longer auto-marked Enumerated/Vuln-scanned *done*
  in the Checklist/Overview coverage — it stays outstanding, matching the
  `⚠ PARTIAL` marker (the operator can still tick it).
- **`deploy`: a rejected Windows login is no longer folded as a successful run.**
  `run_winrm`/`run_smb` now require the on-target script's own banner in the output
  before declaring success (as the stager path already did), and the auth-failure
  markers are tightened — recognize nxc's bare `[-]` reject and impacket `STATUS_*`
  codes, and **stop** matching a benign "Proxy Authentication Required" as an auth
  failure (which had suppressed the push fallback). A stager bind failure no longer
  leaks the open datastore.
- **Port sweep missed open ports on rate-limiting / lossy networks.** The sweep
  pinned `nmap --min-rate 1500` (with `--max-retries` 1–2), which prevents nmap's
  congestion control from backing off; on a network that drops probes the SYNs to
  open ports were dropped and never retried, so hosts came back with "no open
  ports" even though a manual nmap (which slows down — "increasing send delay due
  to dropped probes") found them. recce now **detects the drop condition in
  nmap's output and automatically re-scans that host congestion-adaptively** (no
  `--min-rate` floor, `--max-retries 6`, `-T3`), which is what finds the ports.
  The adaptive re-scan stays bounded by the same `--host-timeout` as any host, so
  it returns partial results rather than running for hours (raise `--host-timeout`
  for more completeness, or set a gentle `--min-rate 200` floor to bound it more
  tightly). New `--reliable` flag forces adaptive mode from the first pass for
  networks you already know rate-limit (and avoids the double scan). Clean scans
  are unaffected (no second pass).
- **Browser detection missed installed browsers off PATH.** `doctor` (and the
  auto-screenshot feature) reported "browser not present" when Firefox/Chromium
  were installed but not on the PATH recce sees — common on Kali when scans run
  under `sudo` (which strips PATH to `secure_path`), for snap installs
  (`/snap/bin`), or `/opt` vendor layouts. `screenshot.browser_tool()` now falls
  back to scanning `/usr/bin`, `/usr/local/bin`, `/bin`, `/snap/bin`, `/opt/bin`
  and a shallow `/opt/*/…` glob when nothing is on PATH (the `RECCE_BROWSER`
  override still wins).
- **`doctor` LDAP check was a false negative.** It reported `ldapsearch` missing
  when only the `ldap3` Python package was installed, even though LDAP
  enumeration works fine via ldap3 (the runtime gate `ad.ldap_available()` accepts
  either). The check now mirrors that gate and is labelled `ldap` (shows which
  backend it found — `ldapsearch` or the `ldap3 package`).
- **`doctor` summary contradicted its own tool list.** The "Optional tools
  missing" line recomputed presence with a naive `which()`, so `browser`/`netexec`
  could show `OK` in the detailed list yet still be listed as missing in the
  summary. The summary now reuses the same detection the list prints, and
  `searchsploit` is checked via its runtime gate (`exploits.available()`) too.
  An audit confirmed the remaining checks (nmap, masscan, ssh, impacket,
  openpyxl) already match their runtime gates.

## [0.2.3] - 2026-07-22

### Changed
- **Enum hardened to be robust host-by-host.** A single host that crashes the
  worker, times out, returns hostile data (control chars, huge port counts), or
  fails to persist can no longer abort the run or corrupt the workbook. The
  per-host datastore write is now isolated in every scan phase (enum, vulns, db,
  privesc, credenum) the same way worker failures already were — a persist error
  on one host is recorded as an issue and the phase continues (`_persist_host`).
  Audited and fault-injection-tested end to end: good hosts persist, failures are
  logged, the workbook stays valid (atomic write + illegal-char scrubbing), and
  the final report always runs in `finally` (survives Ctrl-C and locked files).

## [0.2.2] - 2026-07-22

### Fixed
- **Overview phase table now honors operator overrides.** The per-subnet
  "Coverage by subnet" completion cells read only tool auto-progress, so an
  operator who un-ticked a step on the Checklist (e.g. to flag a redo) saw the
  Overview still count that host as done — the two tables could disagree. The
  phase counts now consult the same tracking overrides the Checklist does
  (`report_excel` Overview `phase()`).
- **Accounts differing only by RID no longer collide.** The datastore keeps
  accounts distinct by `(source, kind, name, domain, rid)`, but the workbook/
  coverage key omitted `rid`, so two such accounts collapsed to one Users &
  Accounts row and undercounted. `acct_key` now includes `rid` (appended only
  when present, so existing rid-less keys stay stable).
- **Product-only advisories reported on every affected port.** A product exposed
  on two ports (e.g. Confluence on 8090 and 8091) was deduped by title alone, so
  only the first port was flagged and the write-up's affected-port list was
  short. Dedup is now per `(title, port)` (`vulndb.assess_host`).

## [0.2.1] - 2026-07-22

### Fixed
- **False HIGH on patched MariaDB.** MariaDB 10.x announces itself with a legacy
  MySQL-compat handshake prefix (`5.5.5-10.11.6-MariaDB-…`); the version parser
  read the leading `5.5.5` and flagged a fully-patched MariaDB as end-of-life
  MySQL **and** fabricated a high-severity `CVE-2012-2122` finding. The version
  normalizer now strips the `5.5.5-` prefix, so the real version (10.11.6) is
  compared; genuine old MySQL 5.5.x is still flagged (`vulndb._clean_version`).
- **CVSS vector strings mis-scored.** A `CVSS:3.1/AV:N/…` vector was read as base
  score `3.1`, silently downgrading criticals to "low", and `CVSS Base Score: 7.5`
  wasn't matched at all. The score regex now skips the vector version and
  recognizes the "Base Score" / parenthetical phrasings (`parser._CVSS_RE`).
- **Vulnerability sheet row loss / coverage undercount.** The workbook & coverage
  key truncated the finding title to 40 chars while the datastore dedups on 60,
  so two store-distinct findings (e.g. same title differing only in the CVE id)
  collapsed to one Vulnerabilities row and the coverage total was short by one.
  The keys now use the same 60-char slice (`tracking.vuln_row_key`).

### Changed
- **Docs accuracy pass.** Dropped a non-existent `--subnet` flag from the README
  Speed section (use positional targets); corrected the credentialed-LDAP note to
  say it needs `ldapsearch` (ldap-utils) **or** `ldap3` (not `ldap3` only); added
  the `exploit-plan/` and `creds/` output dirs to the deliverables tables
  (README/QUICKSTART/CHEATSHEET); and fixed stale CLI `--help`/error strings that
  understated `import` (`-oN` is fully supported) and listed only 5 of 19 commands.

## [0.2.0] - 2026-07-22

### Added
- **Stylized tester docs.** `QUICKSTART.md` rewritten as a scannable field guide
  (workflow diagram, command cheat-sheet table, per-step sections, callouts), and
  a new self-contained **`CHEATSHEET.html`** — a printable one-page reference
  matching the report's teal theme (workflow, core commands, targeting, workbook
  legend, deliverables, troubleshooting). Ships in the burn package.
- **Burn-package builder (`make_package.sh`).** Produces a self-contained
  `dist/recce-<version>.tar.gz` (+ `.zip`) with `SHA256SUMS` — copy to a Kali box
  or burn to disk, `tar xzf` and run `./bin/recce doctor`. Runtime stays
  stdlib-only (no pip install). `pyproject` package-data now also ships the
  `scripts/` per-service suite (was only `local/*`).
- **Self-contained HTML report (`report.html`).** Every report run now also writes
  a single shareable `report.html` — inline CSS, **zero external assets**
  (airgapped-safe) — that a client can open in any browser: an executive summary +
  stat tiles, a severity rollup, the findings table, the synthesised attack path,
  and a per-host table (with AV/EDR). Print-friendly. Built from the same data as
  the workbook; stdlib-only.
- **`creds` command — credential stacking + spray planning.** Accumulates every
  credential recce has seen — auto-harvested from AD accounts with a recovered
  secret, default/blank service logins, and autologon/stored creds in ingested
  loot — together with any you captured by hand (`--add 'CORP\alice:Pw!'`, or
  `--user/--pass/--hash/--domain`; a 32-hex secret is auto-detected as an NT
  hash), deduped into one set (a **Credentials** workbook sheet). `--plan` writes
  `creds/users.txt|passwords.txt|nthashes.txt` and prints the exact **netexec /
  impacket** commands to validate and spray the set across the discovered
  SMB/WinRM/LDAP/MSSQL/RDP/SSH surface (pass-the-hash variants where the protocol
  supports it, paired lists to avoid a cartesian brute, and a lockout caution).
  Credentials persist in the datastore (new `credentials` table).
- **`attackpath` command + Attack Path sheet** — chains the **confirmed** findings
  into a prioritised, client-ready attack path: *foothold → privilege escalation →
  credential access → lateral movement → domain dominance*. Grounded entirely in
  what recce found (it reuses the exploitation actions and stages them); every
  step names the specific host and the existing tool, and a one-line narrative
  summarises the likely chain (e.g. *foothold via vsftpd backdoor on X → harvest
  creds → pivot to domain compromise on the DC*). It's the "so what" — how the
  individual findings combine into an attacker's route. Empty until findings are
  confirmed.
- **AV/EDR awareness (detection, not evasion)** — when you `ingest` a
  `recce-enum.ps1` run, recce now captures the host's **AV/EDR product + defensive
  posture** (Defender real-time/tamper state, EDR agents like CrowdStrike/
  SentinelOne, Sysmon logging, LSASS `RunAsPPL`, AppLocker, Credential Guard,
  PowerShell script-block logging) and surfaces it where you decide what to run:
  a new **AV / EDR** column on the Checklist, a **Defenses (host)** column on the
  Exploitation sheet (right next to the GodPotato/PrintSpoofer/msf action), a
  **Hosts with AV/EDR seen** total on the Overview, and a per-host banner in the
  `exploit-plan` scripts. Every surface carries the **legitimate** guidance —
  coordinate a scoped testing exclusion with the blue team (detection of your
  tooling is a finding *for the defender*) or validate in a lab. recce flags what
  is watching a host; **it does not evade AV/EDR**.
- **`exploitplan` command** — turns each **confirmed** finding into a ready-to-run
  artifact that drives an **existing, published** tool/module with the parameters
  recce discovered already filled in: a Metasploit resource (`.rc`) script per
  finding that maps to a module (EternalBlue, vsftpd backdoor, SambaCry, Ghostcat,
  …) with `RHOSTS`/`RPORT`/`PAYLOAD`/`LHOST` set; parameterized impacket/netexec/
  GTFOBins invocations (AS-REP roast, Kerberoast, ntlmrelayx, secretsdump, …) with
  the domain/DC/host filled in; and a per-host `exploit-plan.sh` chaining the
  remote steps plus a post-shell priv-esc reference section. It **selects and
  configures** published exploits against the specific targets — it authors no
  exploit code. Gated to confirmed findings (never "potential" version guesses).
  **Safe by default**: `.rc` launch lines are commented (a non-intrusive `check`
  runs); `--run` arms them, `--lhost/--lport` set the callback. The same actions
  are surfaced **in the workbook** (the *Exploitation* sheet now unifies remote
  exploits + remote tools + post-shell priv-esc) and **in the write-ups** (each
  finding that maps to a module gets a ready-to-run *Exploit with the published
  module* step).
- **`ingest` now also folds in `recce-service.sh` output** — point `ingest` at a
  saved per-service enumeration run and its `[!]` findings land on the
  Vulnerabilities sheet (source `service-enum`) against the right host:port,
  creating a host entry if needed. Observed findings are confirmed; advisory
  "test/verify X" lines are kept low-confidence (`potential`, off the findings
  report by default). Auto-detected — same command as recce-enum loot.
- **Services sheet: an *Enum command* column** — every open-port row now shows the
  exact `recce-service.sh` command to run for that service, so the next step is
  visible where you already track ports.
- **`services` command** — the bridge from recce's findings to the per-service
  suite. `recce services -o eng` prints the exact `recce-service.sh` command to
  run for **every open port** recce found, grouped by host (with roles and a
  one-shot `from-nmap` sweep line); `-a` appends the intrusive flag. Directly
  answers the field complaint "hard to know what command to type" — after `enum`,
  recce now tells you. Mirrors the dispatcher's port/name→script map (new
  `serviceenum` module), including the WinRM-on-5985 fix (nmap labels it `http`).
- **Single-finding write-up** — `recce writeup <selector>` generates one Word
  (.docx) report for a chosen finding, **pre-filled with what's already been
  looted or obtained** on the affected host(s): ingested on-target (recce-enum)
  findings and harvested accounts/credentials go into a new *Obtained Access /
  Looted Evidence* section. Select by F-id (`F-007` / `7`), CVE, IP, `IP:port`,
  or a word from the title; run with no selector to list every finding to pick
  from. Ambiguous selectors list the candidates. F-ids are stable and match the
  bulk write-ups and the combined report.
- **Per-service enumeration suite** (`recce/scripts/`) — Kali-side scripts that
  take a service recce/nmap/masscan found and run the *right* enumeration for it,
  flagging likely vulns and pointing at the existing tool that acts on each.
  Covers 25 services (ftp, ssh, telnet, smtp, dns, finger, http, pop/imap,
  rpc/nfs, msrpc, smb, kerberos, ldap, snmp, mssql, mysql, postgres, rdp, vnc,
  redis, winrm, mongodb, oracle, ajp, elasticsearch). Read-only / safe by
  default (banners, versions, anon/null checks, TLS, NSE `safe`, config
  disclosure); intrusive checks (brute, nikto, dir-bust, user-enum spraying) are
  gated behind `-a`. A `recce-service.sh from-nmap <scan.xml|.gnmap|.nmap>`
  driver sweeps an entire scan — one enumeration per open port — and reads all
  three nmap formats plus masscan/rustscan XML (point it at recce's own
  `raw/*.xml`). Missing tools self-skip; nothing generates exploit code.
- **`import` command** — build (or update) the workbook from **already-completed
  nmap scans** with no scanning. Accepts all three nmap formats — XML (`-oX`),
  grepable (`-oG`), and normal text (`-oN`) — plus nmap-compatible XML from tools
  like masscan; multiple files, directories, and globs at once (a `-oA` set is
  imported once, from the richest file). Folds hosts into the datastore, runs the
  same offline enrichment as `enum` (version→CVE/CWE, AD role/DC ID, SMB signing),
  ticks Enumerated (+ Vuln-scan where the scan ran NSE scripts), and preserves any
  existing ticks/notes. New `parser.parse_gnmap` / `parser.parse_normal` /
  `parser.parse_nmap_file`. Multiple scans across subnets/ranges/IPs **append and
  merge, never duplicate**.
- **Exploitation playbook** — a new **Exploitation** workbook sheet (and an
  *Escalate with existing tooling* step in each write-up) that maps every
  confirmed priv-esc finding to the exact **existing** public tool, the command
  with the finding's own values filled in, prerequisites, and a validation step.
  References vetted tooling (Metasploit, PowerUp, the Potato family, impacket,
  GTFOBins, gpp-decrypt, public PoCs) — it does not generate exploit code. Gated
  to confirmed findings. Expanded the curated proven-exploit + NSE→CVE references
  for Windows (MS08-067, EternalBlue set, SMBGhost, ZeroLogon, MS14-068, …).
- **Runbook** workbook tab — a step-by-step "what to type" for every phase and
  the options that matter, so the workbook is self-serve.
- **`vulns --fast`** — a top-signal detection tier (skips the broad
  `vuln and safe` net and deep enum) with a live per-host **progress % + ETA**,
  making a large `/24` tractable. Unifies with the sweep `--fast`.
- **`ingest <loot>`** — fold on-target `recce-enum.sh` / `recce-enum.ps1` `[!]`
  findings into a host's **Priv-Esc** rows. Parses text recce itself produced
  (no tools, no network), matches the host by name or `--host`, dedupes, and is
  idempotent. High-signal findings (writable `/etc/shadow`, docker socket,
  `SeImpersonate`, NOPASSWD sudo, …) are **promoted to first-class
  Vulnerabilities** so they count toward severity totals and get write-ups.
- **Dual-account credentialed enum** — a normal user does the enumeration; an
  optional privileged account (`--admin-user/--admin-pass/--admin-domain`) runs
  the admin-only power moves, each result labelled by the account that produced
  it. A **credentialed access matrix** on the Overview summarises reach.
- **On-target enum scripts** (`recce/local/recce-enum.sh`, `recce-enum.ps1`) —
  read-only, winPEAS/linPEAS-style deep sweeps with `-t`/`-SelfTest` pre-flight.
  Detection deepened well past the first cut: Linux now flags Dirty COW,
  OverlayFS / GameOver(lay), Looney Tunables, `sudo` CVE-2023-22809, non-standard
  SUID roots, per-binary NOPASSWD→GTFOBins mapping, cron wildcard injection,
  writable `ld.so.preload`, MySQL-as-root / unauth-Redis, and creds on process
  command lines; Windows adds HiveNightmare/SeriousSAM, PrintNightmare surface,
  SeManageVolume / SeCreateToken / SeTcb, and admin-token/UAC state — each with
  the exact discovered artifact. The closing **"how to exploit"** section is now
  a **tailored, per-finding runbook**: it prints only the vectors that actually
  fired on the host, substitutes in the specific file / binary / privilege
  found, and gives prereq → command → how-to-confirm → cleanup for each, pointing
  at existing public tools (GTFOBins, the Potato family, impacket, PwnKit/Dirty
  Pipe PoCs, gpp-decrypt, …) — it does not generate exploit code.
- **Louder failures** — per-phase error summaries, a per-host **auth
  success/fail table** (distinguishing rejected credentials `FAIL` from tool/
  connection errors `ERR`), and explicit missing-tool stops.
- **Packaging** — `pyproject.toml` provides a real `recce` console command and
  a version; still stdlib-only at runtime.
- **Real-nmap integration tests** — the pipeline is now validated against actual
  nmap on localhost (discover → full/enum/vuln incl. `--fast`), not only mocks.
- **Documentation** — a full **TROUBLESHOOTING.md** (symptom → cause → fix per
  phase), a consolidated command/option reference in the README, and an
  in-workbook troubleshooting section on the **Runbook** tab.

### Changed
- **Priv-Esc sheet now verdicts what's *actually* escalatable.** Ingest a
  `recce-enum.sh/.ps1` run and each `[!]` finding is classified with a new **Type**
  column: **Escalation path** (a confirmed on-target finding that maps to a real
  technique — the How-to shows the exact existing tool + command, verdicted with
  the same engine as the Exploitation sheet), **Finding** (an observation with no
  auto-mapped escalation — worth a look, not a confirmed path), or **Checklist**
  (the generic per-OS "what to run once you have a shell" reference). Rows sort
  escalation → finding → checklist and are colour-tinted, so the real paths sit on
  top and the generic checklist no longer reads as findings. Before any local enum
  a host shows only the **Checklist** (clearly labelled); after ingest the checklist
  is tagged "host already swept — see the findings above."
- **Write-ups now cover REAL findings by default.** `recce writeups` generates a
  document only for findings backed by an actual check/observation (an NSE script
  that reported VULNERABLE, a config/probe observation, or an ingested on-target
  finding); low-confidence, version-inferred **"potential"** guesses are skipped
  (and counted in a one-line note). Pass `--include-potential` to write them up
  too. The combined `findings_report.docx` follows the same default.
- **Ping-blocking networks no longer come back empty.** Discovery now auto-falls
  back to `-Pn` (scan every target as up) when **zero** hosts answer the sweep,
  and hints to use `-Pn` when some don't respond. Added a `-Pn` alias for
  `--no-discovery` (matches nmap). This was the #1 real-engagement pain point:
  firewalled / Windows / AD hosts block ping and were being skipped. Under `-Pn`
  the port sweep **fails fast on dead IPs** (`--max-retries 1`) while the per-host
  `--host-timeout` cap and `--min-rate` floor keep the run bounded and moving.
- **Friendlier first run.** Bare `recce` (no subcommand) prints a short quickstart
  instead of an argparse error; `enum`/`vulns` end with an explicit copy-paste
  `Next:` command.

- Deeper scanning by default: a curated `_VULN_DETECT` set (ms17-010, heartbleed,
  vsftpd backdoor, …) always layers into the vuln pass, since the bare
  `vuln and safe` category misses these.
- The `.xlsx` and `.docx` deliverables match the HTML-preview design language
  (teal accent, monospace machine data, zebra banding, collapsible host groups,
  navigation + per-host deep links). Reports are findings-only by default.
- Removed the interactive authorization prompt and the `--yes` flag.

### Fixed
- **Triaged findings now count toward coverage.** The Vulnerabilities sheet keyed
  each row as `vuln:<ip>:<port>:<script_id>:<title>` but coverage counting
  enumerated `vuln:<ip>:<port>:<script_id>` (no title), so the two keys never
  matched and ticking a finding's *Triaged* box was invisible to `compute_coverage`
  — the vulns %, the Overview rollup, and `status` stayed at 0% however many you
  triaged. The key is now defined once in `tracking.vuln_row_key(v)` and used by
  both the sheet writer and the counter.
- **OpenSSH `pN` patch level no longer dropped in version comparison.** The greedy
  `[a-z]*` in `vulndb._ver_tuple` swallowed the `p`, so `9.3p1` and `9.3p2`
  collapsed to the same tuple and the *OpenSSH 8.5–9.3 double-free (< 9.3p2)*
  signature never fired on `9.3p1` (a real false negative). Matching `pN` before
  the trailing letter fixes the ordering (`8.2p1 -> (8,2,1)`, `9.3p1 < 9.3p2`)
  while leaving OpenSSL-style suffixes (`1.0.2k`) unchanged.
- **Checkbox ticks on the Exploitation, Attack Path, and Credentials sheets now
  persist.** Their checkbox columns use the headers *Done* / *Worked*, which the
  workbook read-back didn't recognise (only *Reviewed*/*Checked*/*Triaged*), so an
  operator's ticks on those sheets were silently dropped on the next regenerate.
  Added *Done*/*Worked* to the recognised set, plus a regression test that asserts
  **every** checkbox column across all sheets round-trips.
- **`recce-enum.sh -o` now captures the COMPLETE run.** Previously only lines
  that passed through the emit helper reached the report file; raw command dumps
  (SUID/SGID lists, root processes, sockets, software inventory, interfaces, …)
  were printed to the terminal but omitted from `report.txt`. The whole run is
  now teed to the file, so the report matches the screen exactly. Also fixed the
  bounded secret-grep swallowing its own matches.
- credenum no longer reports a **missing tool** as an auth `FAIL`, and no longer
  runs `secretsdump` where the bind was rejected/errored.
- `ingest --host` records the loot hostname; incoming rows dedupe against each
  other on a brand-new host.
- Re-running a phase replaces its own scan-issue rows instead of appending
  duplicates (which inflated the Overview count).
- `distance` (network hops) is preserved through fold/merge and shown on the
  Checklist.
- Removed dead code and corrected stale return-type annotations.

## [0.1.0]

- Initial release: phased enumeration (discover → full port sweep → service
  enum → vuln scan), an offline version→CVE/CWE vulnerability database, Active
  Directory analysis, an Excel coverage-tracking workbook, per-finding Word
  write-ups, and searchsploit exploit mapping — all stdlib-only for airgapped
  Kali use.
