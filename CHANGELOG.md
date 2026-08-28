# Changelog

All notable changes to recce are documented here. Dates are UTC.

## [Unreleased]

### Added
- **Six new native database engines** wired into `sweep`: `memcached` (unauth stats/key-dump + amplification), `couchdb` (admin-party to RCE chain), `influxdb` (unauth query API + JWT bypass), `cassandra` (CQL AllowAllAuthenticator + UDF RCE), `oracle` (TNS listener + SID/poison surface), `db2` (DRDA identity). Expanded vulndb CVE coverage for all.
- **Credentialed follow-through** for postgres/mongodb/mysql via native SCRAM (RFC 5802) and `mysql_native_password`, so deep enum works against password-protected instances with `-u/-p` or auto-sprayed creds.
- **Data exfiltration (`datamine`)** for postgres/mysql/mongo -- schema-aware secret/PII hunting with redacted row samples and embedded-credential harvesting; MongoDB SCRAM hashes exported as hashcat `-m 24100/24200`.
- **Foothold proof** -- `recce postgres --prove` runs a benign `id` via `COPY FROM PROGRAM` to confirm RCE (opt-in); MySQL FILE-privilege privesc detection; deeper redis/mongodb/mssql RCE-primitive + native NTLM-over-TDS enumeration.
- **Database lateral movement** -- postgres `dblink`/`postgres_fdw` pivot (internal DB targets + foreign-server cred harvest) and MongoDB replica-set-member auto-probe.
- **Web `.git` reconstruction** -- recovers the tracked source tree from an exposed `.git` and mines it for secrets; `.js.map` source-map reconstruction does the same for front-end source.
- **API enumeration (`recce api`)** -- parses OpenAPI/Swagger specs and probes for broken authentication and IDOR/BOLA, harvesting embedded spec credentials.
- **Web injection & auth** -- SSRF (cloud metadata / `file://`), consolidated security-headers audit, and offline JWT HMAC secret crack (weak secret to forge any token).
- **Authenticated crawl (`recce web --autologin`)** -- logs into each site's form with harvested credentials and scans the authenticated surface.
- **Deeper web-app class coverage** -- JWT RS256-to-HS256 algorithm confusion (recovers RSA public key, forges HS256 token, replays in active mode); CSP weakness analysis; subdomain takeover detection; CORS null-Origin acceptance; GraphQL query batching + field-suggestion schema leak; insecure-deserialization markers in cookies/hidden fields; web cache poisoning via unkeyed Host header. Each carries a prove-engine verdict.
- **Two opt-in active web proofs** -- `recce web --upload-shell` finds upload forms and uploads a benign marker payload to confirm upload-to-RCE; `recce web --smuggle` runs CL.TE/TE.CL request-smuggling timing probes (timing only, never a smuggled second request).
- Every new exploitable finding has a prove-engine verdict; `commands.md` documents which capabilities the web workbench exposes vs. CLI-only.

## [0.6.0] - 2026-08-21

### Added
- **Hardened tool-output import** -- encoding detection (UTF-16, BOM, ANSI stripping), correct hash-type labeling (LM:NT split, secretsdump, AS-REP), new format support (nuclei JSON array, testssl pretty-JSON, GVM, Nessus compliance, masscan `-oL`/`-oJ`), dry-run preview, 0-row warnings, host-key validation, body-size guard, and concatenated multi-tool paste detection.
- **Deeper enumeration + vuln coverage** -- web content/directory discovery with curated wordlist and SPA catch-all suppression; virtual-host enumeration via Host-header probing; broader default UDP (17 to 35 ports) with opt-in `--udp-top N`; 11 new version-to-CVE signatures (108 total).
- **Per-CVE PoC dossiers (`recce poc`)** -- assembles offline CVE dossiers with version signatures, KEV/EPSS priority, Exploit-DB entries (`searchsploit`), Metasploit module mapping, build recipes, and a runnable Python harness skeleton targeting affected hosts.
- **Team chat file attachments** -- drag-and-drop and file-picker join clipboard-paste; non-image files show as download cards; all attachments served as `application/octet-stream` with forced `Content-Disposition: attachment` to prevent stored-XSS; 20 MB cap.
- **`recce exploitplan` covers four more headline CVEs** -- Zerologon, Log4Shell, Apache path-normalization RCE, and Struts2 (OGNL) now generate ready-to-run `.rc` files.

### Fixed
- **Findings write-up (`findings_report.docx`) now has an auto-updating TOC** with severity-colored summary counts.
- **27 CWEs with blank weakness names** in the coverage table -- merged the missing entries from the older table.
- **`recce-service.sh` RCE findings classified only medium** -- the severity regex only matched `-> rce`; fixed with a word-boundary match. NFS wildcard export upgraded medium to high.
- **`creds -u/-p` renamed to `--username`/`--password`** for consistency with other subcommands (short flags unchanged).
- **Several file writes assumed platform default encoding** instead of UTF-8 -- fixed across PoC dossier/harness, spray-plan files, exploitation-plan scripts, DCSync/kerberoast loot, and `fieldkit-export`.
- **Seeded demo data fixes** -- subnets read as 0, nonsense RPC service line, and missing Domain summary/Key information section due to wrong account field.

## [0.5.0] - 2026-08-20

### Added
- **Collaborative web workbench** -- `recce serve` now supports claim/assign hosts, triage labels, per-port status, presence roster, activity feed, per-tester progress, deep-links, add-by-hand (findings/creds/hosts/access), dismiss false-positives, and import from ~14 tools with KEV/EPSS ranking.
- **Team chat** -- real-time text and pasted screenshots in the workbench with unread badges, live toasts, persisted history, and a resizable/searchable drawer.
- **Workbench UX pass** -- merged Hosts/Targets into one view, reordered tabs, collapsed scan controls into a Scan popover, added compact-density toggle, sticky headers, keyboard shortcuts, empty state, and branded loading screen.
- **Web workbench (`recce serve`)** -- FastAPI + React app serving the engagement over LAN; run scans with live SSE progress; Dashboard with Next-moves; host detail drawer; tiered Findings; Act tab with ranked action cards and attack-path graph; Loot tab with lockout-safe spray; one-click report export; light/dark mode. Bundled in the airgap package.
- **API enumeration (`recce api`)** -- discovers OpenAPI/Swagger specs, interactive API docs, and GraphQL introspection on web services; read-only; included in `recce run`.
- **Data-driven detection rules** -- `--rules FILE` loads extra version-to-CVE signatures from JSON with negative matchers (`absent`) for false-positive reduction; malformed rules are skipped, never fatal.
- **EPSS exploitation probability** -- each finding now carries its EPSS 30-day exploitation probability, shown in the Fix-first column and folded into the sort alongside KEV and severity.
- **Fix-first prioritization: CISA KEV** -- findings whose CVE is in the Known Exploited Vulnerabilities catalogue sort to the top, above raw severity. Offline snapshot refreshed at package build.
- **Recovery-first interruptions** -- interrupted scans end with the exact command to resume (`--resume` skips finished hosts) or `recce next`.
- **Exploitation actions labeled confirmed vs. candidate** -- the Exploitation sheet gains a Confidence column separating actively-verified findings from version/inference leads.
- **Honest tiered presentation** -- every finding shows a Tier (confirmed/likely/lead) derived from QoD, plus a To-confirm column with the exact safe re-check command.
- **`recce verify`** -- confirms or refutes version-inference leads by running safe NSE checks; dry-run by default, `--run` required to send traffic; only Tier-A/B detection, never weaponizing PoCs.
- **Active refutation** -- when an NSE check already reported NOT VULNERABLE, the matching version-db lead is now refuted (zero new traffic); `report --show-refuted` surfaces them.
- **Duplicate findings collapsed** -- true duplicates (same CVE on same port) fold into one finding, keeping the highest confidence and unioning refs; presentation-only, datastore keeps every raw row.
- **`recce run`** -- one command for the whole engagement: discover to enum to vulns to every deep module to report, resumable; surgical subcommands still exist.
- **`recce next`** -- prints ranked next-best-actions computed from datastore progress; echoed at the end of `enum`/`vulns`/`run`.
- **QoD visible and dialable** -- Vulnerabilities sheet shows a QoD column; `--min-qod N` hides findings below a chosen score across all report formats.
- **Quality of Detection (QoD)** -- every finding gets a 0-100 score from `recce/qod.py` based on detection method (95-100 for active verification, 70-80 for version inference, 30 for advisory/potential); replaces ~20 ad-hoc confidence gates.

### Fixed
- **Concurrent workbench writes no longer clobber each other** -- all mutations serialized by a process-wide lock; concurrency test fires 40 simultaneous writers.
- **Credential-spray targets only enumerated in-scope hosts** -- `_target_expr` was collapsing any same-/24 hosts to a full /24 CIDR, spraying up to 256 addresses including out-of-scope hosts. Fixed for both `creds --run` and `defaultcreds`.
- **Default-credential commands test correct pairs** -- `nxc` pairs lists positionally; the comma-joined, independently-sorted values never matched real defaults. Now aligned, space-separated, shell-quoted.
- **Looted MySQL hashes no longer mislabeled as NT hashes** -- `mysql_native_password` is SHA1 (hashcat `-m 300`), not nthash; was landing in `nthashes.txt` for pass-the-hash spraying.
- **Credentialed SMB write-probe cleanup** -- delete is now retried and flagged per-share if it fails, instead of silently leaving the marker behind.
- **`mysql`/`postgres` `analyze()` no longer discards caller's `creds` argument**.
- **False-positive sweep** -- proofs no longer reports version-db banner matches as "CONFIRMED / directly observed" (capped at LIKELY); vulndb product matching is word-boundary'd; web path checks tightened (Tomcat Manager, `.svn/entries`, Elasticsearch, Kibana, MinIO, SPA backup); SSH access only recorded on a real shell; AD/LDAP substring matching tightened; parser no longer turns "not affected" mentions into findings.
- **False "MSSQL blank password" critical on every instance** -- now requires the `ms-sql-empty-password` script's "Login Success" marker, not just script presence.
- **Plain domain users mislabeled LOCAL ADMIN on DCs** -- admin detection keyed off loose `(admin)` substring instead of netexec's `Pwn3d!` token.
- **Host with real open ports reported as "0 open ports"** -- sweep results were discarded when enum re-scan under-reported; sweep ports now folded in after enum so they can only be enriched, never erased.
- **`--fast` (masscan) hardened** -- masscan ports kept only if not actively disproved by nmap (RST = pruned, filtered/no-response = kept and tagged `detect_source=masscan`).

### Changed
- **Half the vuln-pass NSE work** -- deep service-enum scripts skip when they already ran on that host; still run when enum didn't execute them.
- **`recce -h` leads with the core path** -- `recce run` and the core loop first, ~40 per-service commands grouped below.
- **Fieldkit integration renamed** -- `skoll-export`/`skoll-import` become `fieldkit-export`/`fieldkit-import`; old aliases work with a deprecation nudge; existing engagements need no migration.
- **`recce ingest` auto-resolves target host** from the enum's own interface IPs, so on-target enum attaches to the correct host without `--host`.

## [0.4.0] - 2026-07-27

### Changed
- **Network map rebuilt as subnet panels + host grid** -- bordered panels with headers and multi-column grids instead of one tall column; added title, AD-domain strip, and role/severity/owned legend.
- **Attack path is now a directly-viewable SVG** -- `attack-path.svg` with staged left-to-right kill chain; opens in any browser, prints to PDF. Mermaid/Graphviz exports removed.
- **Network map is SVG only** -- `network-map-full.svg` and `network-map-overview.svg`; Mermaid and Graphviz exports removed (airgap reasoning -- SVG needs no renderer).
- **Role labelling** -- Windows client OS with SMB open classed as Workstation, not File/SMB.

### Added
- **One-command deep mass scan (`recce scan --deep`)** -- host discovery through every applicable deep module in one invocation; `--skip`/`--only-modules` to narrow.
- **Observed-reachability map (`network-reachability.svg`)** -- ground-truth host-to-host map from on-target topology (ARP neighbours, live connections); dual-homed pivots flagged.
- **Device icons on diagrams** -- role-based glyphs (DC, Server, Workstation) on attack path, tiered map, and network map host tiles with severity chips and owned badges.
- **Logical architecture view (`network-architecture.svg`)** -- AD domain over a routed core, segments through gateways/firewalls, stacked by tier; topology-driven pass replaces generic core with real gateway devices when on-target routes are ingested.
- **Tiered lateral map (`network-map-tiered.svg`)** -- groups estate into trust tiers (DC/servers/workstations) with per-role counts, escalation arrows, and credentialed pivot-surface legend.
- **Fieldkit integration (`skoll-export` / `skoll-import`)** -- round-trips with the fieldkit exploitation kit via file-based handoff; export writes a severity-ranked attack plan, bridge JSON, synthesized gnmap, and ready-to-paste generator commands; import folds proven findings back as confirmed vulnerabilities.

## [0.3.0] - 2026-07-26

### Added
- **Wall-clock budget + live progress for deep-service probes** -- `--budget SECONDS` cap, throttled per-target progress output, and Ctrl-C safety (partial results kept). Applied to all sequential deep modules (redis, elasticsearch, rsync, nfs, mongodb, snmp, kerberos, smb, ftp, ldap, mssql, web).
- **Credential-less AD roasting (`recce kerberos` / `asrep`)** -- hand-rolled ASN.1 DER over TCP 88; sends pre-auth-less AS-REQ to capture crackable `$krb5asrep$` hashes (AS-REP roasting with no credential) and enumerate valid usernames with no logons/lockouts.
- **rsync-daemon deep module (`recce rsync`)** -- speaks rsync daemon protocol directly; lists modules, probes for anonymous access; read-only.
- **NFS / mountd deep module (`recce nfs`)** -- speaks ONC RPC directly; calls portmapper DUMP and `MOUNTPROC_EXPORT`; flags world-mountable exports; read-only, no mount.
- **Redis deep module (`recce redis`)** -- speaks RESP protocol directly; PING + INFO without auth as discriminator; flags unauthenticated instances (critical -- full read/write + CONFIG file-write RCE primitive); read-only.
- **Elasticsearch deep module (`recce elasticsearch`)** -- talks ES HTTP API with stdlib; `/_cat/indices` without auth as discriminator; flags unauthenticated clusters (critical data exposure); read-only.
- **Access + risk overlay on AD architecture diagram** -- tier-0 objects already held get a bold border + checkmark; objects seizable directly get a risk dot.
- **Network map enriched from SharpHound** -- hosts with access get green outline + checkmark; host cards carry risk dots for confirmed findings; DCs confirmed from BloodHound data.
- **AD architecture diagram from BloodHound/SharpHound** -- inline SVG in the HTML report (no BloodHound GUI/Neo4j needed); shows curated tier-0 slice: domains, high-value groups, DCs, privileged members, with MemberOf/control/trust edges. Standalone `ad-architecture.svg` also written.
- **Architecture / network map from enumeration** -- inline SVG in the HTML report; each subnet a segment, every host a role-tagged colour-coded card; large estates (>50 hosts) aggregate to role counts. Also written as `architecture.mmd`/`.dot`.
- **Users, credentials, key-information in the HTML report** -- Key information (AD domains, DCs, functional level, password policy), Users & accounts (with admin/kerberoastable/AS-REP/delegation flags), Credentials captured (secrets masked in HTML).

### Fixed
- **parser: `NOT VULNERABLE` no longer false-matches as VULNERABLE** -- the substring `VULNERABLE` inside `NOT VULNERABLE` was matching; confirmed-vulnerable RCE families with no embedded CVSS now rate critical.
- **vulndb: regreSSHion (CVE-2024-6387) signature corrected** -- was `eq: 9.8p1` (the patched build); now `8.5p1 <= x < 9.8p1`. BlueKeep OS-gate now resolves NT version from nmap's Windows product-name strings.
- **web: HTTP-Basic default-cred requires a 200** -- a 301/302 redirect no longer counts as a confirmed credential.
- **ldap: `result_code(None)` no longer raises TypeError** -- crashed the authenticated/pass-the-hash enum when a server closed the socket.
- **report_html: ssh-key credentials now masked** in the shareable HTML.
- **bloodhound: SID case normalized on edges** -- lowercase/hand-built collections no longer produce zero attack paths.
- **cli: `review --service IP:PORT` crash fixed** -- no longer crashes on a missing/non-numeric port; UDP service tick now works.
- **Robustness fixes** -- mongodb reply parsing honours the reply opcode and survives hostile BSON array keys; snmp decodes signed INTEGERs correctly; store keeps the newer NTLM facts on merge.

### Changed
- **Split HTML report into findings page and architecture & assets page** -- `report.html` for the assessment; new `assets.html` for network map, AD architecture, key information, users/accounts, and masked credentials. Both self-contained, cross-linked, print to PDF.
- **Attack path framed as PROJECTED** -- prominent note that the route is precondition-grounded but not walked end-to-end; every step gives the command to run + validation.

### Added
- **Assessment coverage checklist in the HTML report** -- per-host, per-subnet progress grid mirroring the workbook Checklist; read-only (editing stays in `enumeration.xlsx`).
- **Expanded executive summary + "How findings are scored"** -- Confirmed/Footholds tiles, plain-language assessment separating confirmed from potential, severity bands and confidence labels explained, per-finding confidence badge and "why this rating" basis.
- **Visual "At a glance" dashboard** -- inline-SVG severity donut, Machines-by-risk bar chart, Most-affected-systems bar chart; no external assets or JavaScript.
- **Initial-access tracking** -- `Host.access_gained` auto-ticks the Checklist Access step when a credentialed phase confirms a foothold; `recce access` reviews, re-derives, or records footholds.
- **`recce sweep` / `recce credsweep`** -- one command each for the unauthenticated and authenticated post-enum deep passes; each module self-skips when no matching service exists. `--skip`/`--only-modules` to narrow.
- **Live end-to-end smoke test** -- stands up real localhost servers and drives the actual CLI against them, proving the full scan-to-report path against live sockets.
- **Credentialed-path integration tests** -- fake `nxc` binary on PATH emitting real netexec output, so credentialed modules run their actual subprocess-to-finding path without a live DC.
- **Scale test** -- 500-host / 20-subnet datastore rebuild asserting correct output and near-linear time budget.
- **`ldap` deep module** -- hand-rolled BER/ASN.1 LDAP client (no python-ldap); anonymous bind, RootDSE read, anonymous naming-context read, cleartext LDAP flagging, LDAPS support. Authenticated enumeration with paged searches for users/computers/domain objects deriving kerberoastable/AS-REP/delegation/privileged flags. Pass-the-hash via stdlib NTLM module with NTLMv2 + SASL GSS-SPNEGO bind. Full NTLM sign+seal on plaintext 389 for DCs enforcing LDAP signing.
- **`snmp` deep module** -- hand-rolled SNMP v2c client over UDP (no pysnmp); guesses community strings, reads system group, walks user tables/processes/software/interfaces; enumerated accounts flow into Users & Accounts for pre-auth spraying.
- **`mongodb` deep module** -- hand-rolled MongoDB wire-protocol client (no pymongo); `listDatabases` without auth as discriminator; critical finding if unauthenticated; read-only.
- **Web signatures -- Tier 1 niche-app coverage** -- Jenkins script console, Keycloak admin, Grafana path traversal (CVE-2021-43798), HashiCorp Vault exposure, Elasticsearch unauth, Kibana version disclosure. Form/JSON default-credential probe (`--creds`) for Grafana `admin/admin`, MinIO `minioadmin/minioadmin`, RabbitMQ `guest/guest`.
- **SQL injection detection + form-field fuzzing (`web --crawl`)** -- fuzzes form fields and URL params; error-based, boolean-based blind, and opt-in time-based blind SQLi with non-destructive payloads; destructive-looking forms skipped; CSRF/password fields never fuzzed.
- **Cookie hardening + open-redirect + path-traversal checks** -- per-cookie analysis (HttpOnly, Secure, SameSite, cleartext HTTP, over-broad Domain); open-redirect and LFI param checks via shared injection transport.
- **Discovery hardening** -- ping sweep covers more ports (88, 389, 5985); reconfirms non-responders with `-Pn` top-100 scan to recover firewalled-but-alive hosts; `--no-reconfirm` to skip.
- **`--targets-up`** -- treats target list as authoritative with `-Pn`; pre-seeds every target into the datastore so a killed scan can never make a host vanish. Parses `IP hostname` pairs.
- **Full-port scan is explicit and partial coverage flagged** -- port scope printed at enum start; top-N scans get a loud PARTIAL warning; `--all-ports` overrides profiles.
- **Engagement-readiness hardening** -- basic UDP coverage in enum phase (17 high-value ports, on by default, `--no-udp` to skip); `--exclude` accepts `@file` and persists exclusions; form fuzzer refuses destructive-looking forms and records skipped ones.

### Added (high-fidelity decoder + probe tests)
- **Fuzz-invariant harness for every Layer-1 decoder** -- hammers each decoder with truncation, byte-flips, corrupted lengths, random splices; SIGALRM watchdog bounds each call.
- **Golden wire-vector tests** -- asserts exact parsed output for a real message per protocol.
- **Fake-transport probe tests** -- tiny replay servers exercising the real socket-to-parse-to-findings path with no mocking.
- **Tool-output text-parser fuzzing** -- mutates real stdout samples of every external-tool parser; asserts graceful degradation.

### Fixed (high-fidelity test batch)
- **`bson_parse` could crash with unhandled `RecursionError`** on deeply nested BSON documents; now caps nesting depth.

### Fixed (audit + end-to-end run)
- **Plain-HTTP services on odd ports scanned as HTTPS** -- `_is_tls` substring-matched the product name, so "SimpleHTTPServer" was treated as TLS; now only nmap service + tunnel decide TLS.
- **Hostname/large CIDR could abort the whole scope** -- hyphenated FQDNs misparsed as numeric ranges; large CIDRs (/8) caused OOM. Fixed with numeric-only range expansion and a 65K address cap.
- **`parse_nmap_xml` could raise on empty numeric attributes** -- now parses tolerantly.
- **MongoDB BSON parser hung on hostile documents** (negative string length); wire reader had no message-length cap. Both bounded.
- **Docker probe crash on malformed JSON array** -- now degrades cleanly.
- **LDAP sealed channel crash on truncated/tampered frames** -- now degrades cleanly.
- **`--targets-up` seed marked truncated enum as complete on merge** -- now preserved.
- **Review coverage could never reach 100%** -- unconfirmed `-Pn` phantom hosts counted in denominator; now excluded.
- **TLS cert expiry compared in local time vs UTC** -- fixed with `calendar.timegm`.
- **SNMP finding fired on bare "public"/"private" substring** -- tightened.
- **masscan intermediate temp file left behind** -- cleaned up.
- **Checklist auto-tick gaps** -- `cmd_smb`/`cmd_ftp` didn't auto-tick under `--no-probe`; `cmd_web` never cleared a stale manual tick on re-run. Fixed.
- **xlsx dropdown/conditional-formatting values not escaped** -- fixed.

### Fixed (full-codebase audit)
- **`_discover` crashed on invalid targets** -- returned 3-tuple after callers expected 4.
- **`store._merge` silently dropped port enrichment** -- six Port fields not merged; now merged. Account attrs/detail also fold in.
- **`_fold_host` dropped `up_reason`/`state`**.
- **Docker/Kubernetes truncated large API responses** -- single 256 KB read cut mid-buffer; now reads to EOF (16 MB cap).
- **SMB2 negotiate trusted an error reply** -- `STATUS_INVALID_PARAMETER` read as signing-not-required. Now validates command/status/StructureSize.
- **FTP write-proof claimed "fully reversible" even when DELE failed** -- cleanup now retried and tracked.
- **Prove-engine verdict fixes** -- EOL recipe swallowed legacy-RCE findings; null-session verdict false-confirmed credentialed share listing; OpenSSH 9.8 mislabeled; RCE findings got no Verification row. Fixed with a version-CVE catch-all.
- **Overview host-index deep-links** pointed at wrong Checklist rows after host addition; bucket identically.

### Changed (audit: performance + cleanup)
- **searchsploit cached process-wide** -- N hosts on the same product cost one query.
- **Kubernetes/MSSQL reuse connections** -- Kubernetes reuses TLS/plaintext scheme; MSSQL caches SQL Browser probe per IP.
- **Privesc/report generation** -- privesc marks step in worker and persists once; `_generate_reports` loads credentials once.
- **Dedup cleanup** -- `svccommon.findings_to_vulns` replaces five copies; shared `_write_findings_table`; duplicate severity maps removed.

### Added
- **UDP liveness fallback for `-Pn` hosts** -- when TCP sweep returns zero ports, sends UDP ping to common services; a reply confirms the host as up instead of writing it off.

### Changed
- **`Host.is_up` no longer counts `enumerated` as proof of life** -- requires real evidence (open port, finding, discovery reply, DNS/ARP/OS data).
- **Checklist shows only hosts confirmed UP** -- one-directional `Host.is_up` gates the list; nmap status reason parsed; `-Pn` phantoms tallied explicitly as UNKNOWN.
- **Legend line on the Checklist tab** -- one-line legend above the header (green = auto-ticked, amber = manual sign-off); workbook writer locates header row dynamically.

## [0.2.4] - 2026-07-23

### Added
- **`deploy` -- credentialed mass local-enum & priv-esc** -- runs read-only on-target enum scripts across reachable hosts in parallel. Transport auto-selected per host: SSH (script piped over stdin), WinRM (`nxc winrm -X` encoded command), or SMB (push to `%TEMP%`, run, delete). Engine-agnostic: uses nxc or impacket (impacket `wmiexec` pairs cleanly with `--stager` for in-memory exec). `--stager` stands up a short-lived HTTP server for download-cradle execution with no temp file.
  - **Credential precheck** via nxc verifies which protocols authenticate before running; `--dry-run` previews the per-host transport plan; per-host failures isolated and logged.

### Changed
- **Checklist step headers colour-coded** -- green = auto-ticked steps, amber = manual sign-offs.
- **Deep-service capabilities auto-tick the Checklist** -- `smb`/`ftp`/`docker`/`kubernetes`/`mssql` mark assessed ports as vuln-scanned; a host only shows done once every port is covered.
- **Workbook readability at scale (900+ hosts)** -- collapsible row grouping on Checklist (by subnet), Vulnerabilities/Verification/Services (by host); wide text columns wrap; identity columns frozen.
- **Distribution is a plain drop-in tarball** -- `make_package.sh` burn package; extract and run `./bin/recce`; no pip/wheel needed (pyproject.toml retained for optional wheel builds).
- **Workbook reorganised to engagement flow** -- service tabs grouped after findings; AD cluster contiguous; Exploitation/Attack Path before Priv-Esc. Overview gains "Confirmed by recce" total. Start Here/Runbook updated with all commands.
- **PoCs are stronger proofs with explicit ROE hand-off** -- clear PROVEN verdict and marked ACTION (ROE) line; JWT replays the forged token; SSTI declares PROVEN on evaluation; PUT shows then removes the file.

### Added
- **`recce kubernetes` (alias `k8s`)** -- stdlib-only unauthenticated reads of kubelet (anonymous `/pods` implies `/exec` RCE surface), kube-apiserver (anonymous Secrets listing = cluster compromise), and etcd (unauthenticated key read). Read-only.
- **`recce docker`** -- detects exposed Docker Engine API (TCP 2375/2376); unauthenticated read is CONFIRMED critical (remote root RCE); reports container/image inventory. Read-only.
- **`recce ftp`** -- credential-free probe: banner for CVE DB + known-backdoor map (vsFTPd 2.3.4, ProFTPD mod_copy), anonymous login, AUTH TLS/FTPS for cleartext flagging. Reversible writable-directory proof (`--prove-write`).
- **`recce smb`** -- SMB2/SMBv1 NEGOTIATE for signing posture and legacy protocol detection (NTLM relay / EternalBlue surface); null & guest session share enum via nxc; reversible writable-share proof (`--prove-write`).
- **Findings proven by execution, not just adjudicated:**
  - **Web PUT write primitive** -- PUTs a marker file, GETs it back, DELETEs it; round-trip confirmed is CONFIRMED arbitrary-file-write.
  - **Web JWT `alg:none`** -- forges an unsigned token, replays it; accepted + no-token-denied = CONFIRMED signature bypass.
  - **AD live Kerberos capture** -- `--roast` (GetUserSPNs), `--asrep` (GetNPUsers), `--dcsync` (secretsdump); hashes written to `engagement/loot/` for hashcat.
  - **Offline version-to-CVE verdicts** now honestly LIKELY with a "distros backport" caveat; EOL/legacy CONFIRMED from the version fact.
- **Per-web-finding PoC generation** -- `exploitplan` writes tailored benign proofs for each web finding (git-dumper, CORS HTML, JWT forge, SSTI identification, GraphQL dump, heapdump grep, PUT write, JS-secret extractor, exposed-file fetch).
- **`recce web` -- deep web scanning** -- tech fingerprint, high-signal exposures (.git/.env/.svn, server-status, actuator, phpinfo, Swagger, Tomcat Manager, WordPress), directory listing, dangerous HTTP methods, cookie flags, security headers, TLS analysis. Runs automatically in `vulns` phase. Web is now a coverage category.
  - **Authenticated scanning** (`--cookie`/`--header`) and **authenticated crawling** (`--crawl`) with reflection/SSTI testing on discovered params. Per-endpoint screenshots (`--screenshots`).
  - **Full Spring Boot Actuator dive** -- `/env`, `/configprops`, downloadable `/heapdump` (full memory), `/mappings`, `/gateway/routes` (SpEL RCE surface CVE-2022-22947).
  - **Secret extraction (redacted)** -- exposed `.env`/`.aws/credentials`/`.htpasswd`/actuator `/env` show which secrets leaked as `key=ab...yz`, never the raw value.
  - **Backup/source-file exposure** -- `backup.sql`, `db.sql`, `*.zip`, `.env.bak`, `wp-config.php.bak` confirmed by content signature.
  - **Product+version fingerprinting** (Jenkins/Confluence/GitLab/WordPress) enriches ports nmap missed; web scan runs before CVE mapping so recovered versions get matched.
  - **JWT weaknesses** -- `alg:none` (forgeable), HS* (offline-crackable), RS*/ES* (algorithm-confusion) flagged from cookies/headers/body.
  - **SSTI/reflected-input check** -- `{{7*7}}`/`${7*7}`/`<%=7*7%>` canary; `49` evaluation is a strong SSTI hit; unencoded `<i>` reflection flagged as XSS lead.
  - **Client-side JS secret scraping** -- same-origin scripts scanned for Google/AWS/Stripe/GitHub/Slack keys and hardcoded apiKeys.
  - **WordPress plugin/version enum** -- core version, XML-RPC status, common-plugin sweep with versions from `readme.txt`.
  - **Opt-in default-credential probe** (`--creds`) for HTTP Basic endpoints, capped at 5 tries/endpoint.
- **`mssql` -- offensive MSSQL enumeration + attack chain:**
  - **Credential-free** -- SQL Browser (UDP 1434) instance/version/port enumeration; TDS pre-login probe for exact version and login encryption posture.
  - **Credentialed** -- access/privilege matrix via nxc (which servers accept your creds, which are sysadmin); live deep enumeration via impacket detecting the actual escalation chain (impersonatable sysadmin, TRUSTWORTHY, linked servers, xp_cmdshell, `sys.sql_logins` hashes).
  - **Server-hardening checks** -- mixed-mode auth, dangerous server-level permissions, startup stored procedures.
  - **Per-database permission mining (`--perms`)** -- guest enabled, public/guest role grants on sensitive tables, write/execute grants any login inherits.
  - **Database data-mining (`--data`)** -- enumerates every table with row counts; surfaces columns whose names indicate passwords, tokens, PII, financial data.
  - **Reversible proof of impact (`--prove-write`)** -- creates table, writes/modifies a row, drops it; adds/confirms/removes a temporary login to prove permission-modify capability.
  - **Command execution (`--exec`)** -- xp_cmdshell, OLE Automation, SQL Agent CmdExec job, or CLR hand-off; captured output folded as critical finding.
  - **TRUSTWORTHY chains auto-verified** -- checks whether your login is db_owner; confirmed chains become critical findings.
  - **UNC coercion to NTLM relay** -- enumerates concrete relay destinations (LDAP on DC, other MSSQL, SMB-signing-not-required hosts); `--relay --lhost` executes the trigger.
  - **Recursive linked-server graph walk** -- follows linked servers with nested `EXEC AT`, discovering identity/privilege at each hop; sysadmin-reachable instances become critical findings with ready RCE commands. `--link-depth` bounds recursion.
- **`ad` -- SharpHound + Certipy (ADCS) import** -- parses the AD object graph offline (stdlib only, no BloodHound/Neo4j needed); auto-detects SharpHound zip/directory/JSON and Certipy JSON.
  - **Credentials-first** -- `-u/-p/-d` pre-fills every generated command; a 32-hex secret auto-treated as NT hash.
  - **ADCS / ESC findings** -- every ESC Certipy flags (ESC1-ESC11, ESC13, ESC15) becomes a finding with the exact `certipy` command to prove/abuse it.
  - **AD Findings sheet** -- kerberoastable/AS-REP accounts, DCSync rights off tier-0, delegation (unconstrained/constrained/RBCD), shadow credentials, dangerous ACLs, passwords in descriptions, MachineAccountQuota -- each with exact tool command.
  - **AD Attack Paths sheet** -- shortest path from an owned/low-priv principal to DA/domain/DC (`--owned USER` to start from your principal).
  - **Kerberos capture** -- `--roast`, `--asrep`, `--dcsync` run impacket tools and fold hashes back as proven findings.
  - Findings fold into main severity totals, Vulnerabilities sheet, and per-finding write-ups with CWE, remediation, and prove/abuse command.
- **Engagement folder stays operator-accessible** -- chmods to 777 on every exit path (success, Ctrl-C, crash) so sudo runs don't leave root-owned files.
- **On-target listener backfill** -- enum scripts emit listening-service inventory with backing binary path; `ingest`/`deploy` fold onto host ports, adding loopback-only listeners as `ID source = local`.
- **Richer HTML report** -- detailed findings appendix with vulnerability type, CWE/CVE, CIA impact, tools, affected systems, recommendation, and evidence excerpt. Embeds Mermaid attack-path graph.
- **Deeper service enum** -- `svcdetect` mines product+version from banners (OpenSSH, vsFTPd, Postfix, MySQL, Apache, nginx, etc.) for ports nmap left version-blank; no-traffic `enrich_versions` pass runs before CVE mapping.
- **Attack-path graph** -- `attack_path.mmd` (Mermaid) and `attack_path.dot` (Graphviz) diagrams; Mermaid embedded in HTML report.
- **`exploitplan` emits benign PoC build recipes** -- LD_PRELOAD `.so`, root-job shell PoC, `/etc/passwd` UID-0, Windows service/intercept exe, hijack DLL, AlwaysInstallElevated MSI. Deliberately benign proofs with a single ACTION line to swap.
- **`recce prove`** -- per-finding verification engine covering ActiveMQ, SMB signing, MS17-010, SMBGhost, SeImpersonate, PrintNightmare, BlueKeep, Heartbleed, Log4Shell, ZeroLogon, Kerberoast/AS-REP, null-session, anonymous FTP, default creds, weak TLS. Verdicts: CONFIRMED, FALSE POSITIVE, LIKELY (with finish-proving command), INCONCLUSIVE. `--run` re-runs non-intrusive SMB NSE. Results on a Verification workbook tab.
- **Windows privesc: fully-qualified exploits** -- unquoted service paths resolved to the exact intercept exe with a writable-directory check and the `sc stop/start` command; writable service binary/registry key with exact `copy`/`reg add` commands; DLL hijacking distinguished by writable SYSTEM PATH vs user PATH with planting procedure; COM hijack with exact `reg add ... InprocServer32` command. Deeper Windows credential hunting: IIS `applicationHost.config`, scheduled-task passwords, PS transcripts, RDP files, and a profile-wide secret sweep.
- **On-target scripts identify the EXACT exploit** -- embedded GTFOBins-lite engine prints the precise command for ~50 binaries in both SUID and sudo contexts (e.g. `find -exec /bin/sh -p`, `sudo vim -c ':!/bin/sh'`). Capabilities (`cap_setuid`, `cap_dac_*`) print their exact commands too.
  - **Deeper SUID binary analysis** -- non-standard SUID root binaries statically analysed (`strings` only, never executed) for PATH hijack, `LD_*` env injection, and writable files.
  - **Serious credential/secret hunting** -- SSH keys (triaged encrypted vs ready-to-use), cloud keys (`AKIA`, `AIza`), tokens (`ghp_`, `xox`), JWTs, `password=`/`api_key=` assignments, and credential stores (`.git-credentials`, `.netrc`, `.npmrc`, `.aws`, docker/gcloud configs).
- **On-target enum: lateral movement, shell escape, persistence:**
  - **Lateral movement** -- Linux: ssh-agent sockets, SSH trust graph, K8s service-account tokens, config-management inventories (Ansible/Salt/Puppet), dual-homed detection, DB client creds. Windows: mapped drives, WinRM/PSRemoting reach, LDAP for kerberoastable/AS-REP/delegation hosts.
  - **Shell escape detection** -- Linux: rbash/lshell/git-shell jails with candidate escape interpreters. Windows: ConstrainedLanguage mode, JEA, AppLocker.
  - **Persistence foothold detection** -- writable login/boot hooks (Linux: `.bashrc`/`profile.d`/`update-motd.d`/PAM; Windows: PS profile, HKCU COM, WMI subscriptions, AppInit_DLLs, sethc/utilman debugger hijacks).
  - **Current-era kernel privesc** -- nf_tables CVE-2024-1086 range, `ptrace_scope`, unprivileged userns, LSM (SELinux/AppArmor) posture.
- **Better service detection** -- `svcdetect` layer recovers unknown/tcpwrapped ports in four escalating steps: (1) servicefp mining (no new traffic), (2) curated port map (no new traffic), (3) active banner grab with protocol nudges, (4) second-opinion nmap `-sV --version-all` re-probe on remaining unknowns. Services tab gains an ID-source column (nmap/inferred/banner); unknown ports show suggested identification commands.
- **Domain-qualified usernames accepted everywhere** -- `-u` takes `CORP\user`, `corp.local/user`, or `user@corp.local`; domain auto-split, `-d` optional.

### Changed
- **Priv-Esc tab driven by real findings** -- confirmed escalation paths from `deploy`/`ingest`, not generic boilerplate per host; un-swept hosts get one actionable to-do; generic playbook moved to a reference sheet.
- **Target hygiene** -- full-octet ranges drop network/broadcast addresses (`.0` and `.255`).
- **`deploy` reports every host's outcome** -- succeeded/errored/unable with plain-English reasons; `--dry-run` lists both runnable and unable hosts; unable hosts written to Overview issues.
- **`--help` organised into labelled groups** -- common flags up top, tuning knobs in optional sections; no flags added or removed.
- **Port sweep is completeness-first** -- retries increased (`--max-retries 3` default, tunable); zero-port hosts get a verification re-scan before "no ports" is trusted (`--no-verify` opts out); hosts cut short by `--host-timeout` flagged `incomplete_scan` and marked `PARTIAL` on the Checklist so a truncated scan is never mistaken for complete.

### Fixed
- **Exploitation surface overhauled** -- searchsploit hits now linked by CVE match (not port alone), so a weak-TLS finding no longer claims a Heartbleed exploit. Column renamed "Exploit"; config/crypto findings never carry a proven exploit. Exploits sheet gains "Corroborates finding?" column; corroborated candidates sort first.
- **Truncated sweep no longer counts as fully scanned** in the Checklist/Overview.
- **`deploy` rejected Windows login no longer folded as successful** -- requires on-target script banner in output; auth-failure markers tightened.
- **Port sweep missed ports on lossy networks** -- `--min-rate 1500` prevented nmap's congestion control from backing off, so dropped SYNs were never retried. Now detects the drop condition in nmap's output and automatically re-scans congestion-adaptively (no `--min-rate` floor, `--max-retries 6`). `--reliable` forces adaptive mode from the first pass for known rate-limiting networks.
- **Browser detection fixed** -- falls back to scanning common binary paths when browser is off PATH (sudo, snap, /opt).
- **`doctor` LDAP check fixed** -- mirrors the runtime gate accepting either `ldapsearch` or `ldap3`.
- **`doctor` summary fixed** -- reuses the same detection as the detailed list.

## [0.2.3] - 2026-07-22

### Changed
- **Enum hardened host-by-host** -- a single host crash/timeout/hostile data/persist error can no longer abort the run or corrupt the workbook; per-host datastore write isolated in every scan phase; workbook uses atomic write + illegal-char scrubbing; final report runs in `finally`.

## [0.2.2] - 2026-07-22

### Fixed
- **Overview phase table honors operator overrides** -- phase counts now consult the same tracking overrides the Checklist does.
- **Accounts differing only by RID no longer collide** -- `acct_key` now includes `rid`.
- **Product-only advisories reported on every affected port** -- dedup is now per `(title, port)`.

## [0.2.1] - 2026-07-22

### Fixed
- **False HIGH on patched MariaDB** -- strips the `5.5.5-` MySQL-compat prefix so the real version is compared.
- **CVSS vector strings mis-scored** -- `CVSS:3.1/...` was read as base score `3.1`; regex now skips vector version and recognizes "Base Score" phrasings.
- **Vulnerability sheet row loss / coverage undercount** -- workbook key truncated title to 40 chars while datastore used 60; now both use 60.

### Changed
- **Docs accuracy pass** -- dropped non-existent `--subnet` flag, corrected credentialed-LDAP note, added output dirs to deliverables tables, fixed stale CLI help strings.

## [0.2.0] - 2026-07-22

### Added
- **Stylized tester docs** -- `QUICKSTART.md` rewritten as a scannable field guide; new `CHEATSHEET.html` printable one-page reference.
- **Burn-package builder (`make_package.sh`)** -- produces self-contained tarball with SHA256SUMS; stdlib-only runtime, no pip install.
- **Self-contained HTML report (`report.html`)** -- inline CSS, zero external assets; executive summary, severity rollup, findings table, attack path, per-host table. Print-friendly.
- **`creds` command** -- accumulates all credentials (auto-harvested + manual `--add`), deduped on a Credentials sheet. `--plan` writes spray files and prints exact netexec/impacket commands.
- **`attackpath` command + Attack Path sheet** -- chains confirmed findings into a prioritized kill chain (foothold to domain dominance) with specific hosts and tools.
- **AV/EDR awareness** -- captures host defensive posture from `recce-enum.ps1` (Defender, EDR agents, Sysmon, LSASS PPL, AppLocker, Credential Guard); surfaces on Checklist, Exploitation sheet, and exploit-plan scripts. Detection only, no evasion.
- **`exploitplan` command** -- turns confirmed findings into ready-to-run artifacts: Metasploit `.rc` scripts, parameterized impacket/netexec/GTFOBins invocations, per-host `exploit-plan.sh`. Selects and configures published exploits, authors no exploit code. Safe by default (`.rc` launch lines commented; `--run` arms them).
- **`ingest` folds `recce-service.sh` output** -- per-service enumeration findings land on the Vulnerabilities sheet against the right host:port.
- **Services sheet: Enum command column** -- every open-port row shows the exact `recce-service.sh` command to run.
- **`services` command** -- prints exact `recce-service.sh` command for every open port, grouped by host.
- **Single-finding write-up (`recce writeup`)** -- generates one Word report for a chosen finding, pre-filled with looted evidence. Select by F-id, CVE, IP, IP:port, or title keyword.
- **Per-service enumeration suite (`recce/scripts/`)** -- Kali-side scripts covering 25 services; read-only/safe by default, intrusive checks gated behind `-a`; `from-nmap` driver sweeps an entire scan.
- **`import` command** -- builds workbook from existing nmap scans (XML, grepable, normal text, masscan XML); multiple files merge without duplicating.
- **Exploitation playbook** -- workbook sheet mapping confirmed priv-esc findings to exact tool + command + prerequisites + validation step.
- **Runbook workbook tab** -- step-by-step guide for every phase.
- **`vulns --fast`** -- top-signal detection tier with live per-host progress and ETA.
- **`ingest <loot>`** -- folds on-target `recce-enum` findings into Priv-Esc rows; high-signal findings promoted to first-class Vulnerabilities.
- **Dual-account credentialed enum** -- normal user for enumeration, optional privileged account (`--admin-user/--admin-pass`) for admin-only moves; credentialed access matrix on Overview.
- **On-target enum scripts** (`recce-enum.sh`, `recce-enum.ps1`) -- read-only deep sweeps covering Dirty COW, OverlayFS, Looney Tunables, sudo CVEs, non-standard SUID, cron wildcard injection, writable ld.so.preload, MySQL-as-root, unauth Redis, HiveNightmare, PrintNightmare surface, and more. Tailored per-finding runbook pointing at existing public tools.
- **Louder failures** -- per-phase error summaries, per-host auth success/fail table, explicit missing-tool stops.
- **Packaging** -- `pyproject.toml` provides `recce` console command and version.
- **Real-nmap integration tests** -- pipeline validated against actual nmap on localhost.
- **Documentation** -- `TROUBLESHOOTING.md`, consolidated command/option reference, in-workbook troubleshooting section.

### Changed
- **Priv-Esc sheet verdicts what's actually escalatable** -- Type column (Escalation path / Finding / Checklist); rows sorted accordingly; generic checklist clearly labelled.
- **Write-ups cover real findings by default** -- low-confidence version-inferred guesses skipped; `--include-potential` to include them.
- **Ping-blocking networks no longer come back empty** -- auto-fallback to `-Pn` when zero hosts answer; `-Pn` alias for `--no-discovery`.
- **Friendlier first run** -- bare `recce` prints quickstart; `enum`/`vulns` end with explicit Next command.
- Deeper scanning by default with curated `_VULN_DETECT` set (ms17-010, heartbleed, vsftpd backdoor, etc.).
- Workbook and DOCX deliverables match the HTML report design language.
- Removed interactive authorization prompt and `--yes` flag.

### Fixed
- **Triaged findings now count toward coverage** -- key defined once in `tracking.vuln_row_key(v)` and used by both sheet writer and counter.
- **OpenSSH `pN` patch level no longer dropped** in version comparison -- `9.3p1` and `9.3p2` now compare correctly.
- **Checkbox ticks on Exploitation, Attack Path, and Credentials sheets now persist** -- *Done*/*Worked* headers added to recognised set.
- **`recce-enum.sh -o` captures the COMPLETE run** -- whole run teed to file instead of only emit-helper lines.
- credenum no longer reports a missing tool as auth FAIL; no longer runs `secretsdump` where bind was rejected.
- `ingest --host` records the loot hostname; incoming rows dedupe on new hosts.
- Re-running a phase replaces its own scan-issue rows instead of appending duplicates.
- `distance` (network hops) preserved through fold/merge and shown on Checklist.
- Removed dead code and corrected stale return-type annotations.

## [0.1.0]

- Initial release: phased enumeration (discover, full port sweep, service enum, vuln scan), offline version-to-CVE/CWE vulnerability database, Active Directory analysis, Excel coverage-tracking workbook, per-finding Word write-ups, and searchsploit exploit mapping -- all stdlib-only for airgapped Kali use.
