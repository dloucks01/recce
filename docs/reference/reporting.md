# Reporting, write-ups & output files

Per-finding Word write-ups, the fieldkit round-trip, and every file recce writes into the engagement folder.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Finding write-ups (`writeups`)

`recce writeups -o eng` generates **one Word (`.docx`) report per finding**,
matching a walkthrough template. Findings are grouped by title across hosts, so
one issue spanning many systems is a single write-up listing every affected
`IP:port`.

By default it writes up **real findings only** — those confirmed by an actual
check or observation (an NSE script that reported `VULNERABLE`, a config/probe
observation, an ingested on-target finding). Low-confidence, version-inferred
**"potential"** guesses are skipped (with a one-line count); add
`--include-potential` to write them up too.

**One finding at a time.** `recce writeup <selector>` writes up a **single**
finding, **pre-filled with what you've already looted or obtained** on the
affected host(s) — ingested on-target findings and harvested accounts/creds land
in an *Obtained Access / Looted Evidence* section. Pick it by F-id (`F-007`),
CVE, IP, `IP:port`, or a word from the title; run `recce writeup` with no
selector to list every finding. F-ids are stable across the bulk run, the
combined report, and single write-ups.

recce **auto-fills** everything it knows — Finding ID, title, affected systems,
severity, CWE, CVE, tools/techniques used, a drafted vulnerability type and
(CIA) security aspect, recommendations (from the offline KB), a plain-language
narrative draft, and the raw **Evidence**. It also **drafts the technical
walkthrough step-by-step** — the discovery command (`nmap -sV -p …`), a
confirmation step tailored to how it was detected (the NSE script, a `curl -I`
header check, `ssl-enum-ciphers`, `netexec`…), and any mapped searchsploit
exploit (`EDB-…`). The fields only a tester can supply — **Mission Risk &
Impact**, **Level of Difficulty**, and the exploitation *result* + screenshots —
are `[TESTER: …]` placeholders. You open each `.docx` in Word, finish it, and
paste screenshots inline. **recce never overwrites an edited write-up** (re-run
to add docs for new findings; `--overwrite` forces a rebuild).

**Combined report.** Alongside the per-finding docs, `writeups` also produces
`writeups/findings_report.docx` — a single document with a **severity summary
table**, a **findings table** (ID · severity · title · CWE · affected hosts),
and every finding as a section. It's a regenerated rollup (not hand-edited), so
it always reflects the current data; skip it with `--no-combined`.

The whole writer is **pure standard-library** (a `.docx` is a zip of XML, like
the workbook) — no python-docx/Node needed, so it runs on the airgapped box.

**Screenshots (web only).** If a headless browser is present — **Firefox** (the
Kali default) or **Chromium**, whichever is found, or point `RECCE_BROWSER` at a
specific binary — recce screenshots HTTP/HTTPS targets and embeds them under the
walkthrough automatically. Chrome is tried first because it can ignore
self-signed cert warnings; headless Firefox will capture the browser's cert
warning page for a bad-cert HTTPS target (still useful evidence). Non-web
findings are evidenced by their captured tool output. Disable with
`--no-screenshots`; filter with `--min-severity high`.


## fieldkit integration (`fieldkit-export` / `fieldkit-import`)

recce round-trips with the [**fieldkit**](https://github.com/dloucks01/fieldkit)
exploitation kit, so enumeration seeds exploitation and proven findings flow back into the sheet:

```bash
recce fieldkit-export -o eng                     # -> eng/fieldkit/ : an attack plan fieldkit consumes
#   (in the fieldkit checkout)
#   python3 access/network/sweep.py triage --recce eng/fieldkit/recce-bridge.json
#   ... exploit, then write up findings.json and:
#   python3 report/gen_report.py findings.json --export-recce   # -> recce_findings.json
recce fieldkit-import recce_findings.json -o eng  # proven findings -> Vulnerabilities sheet + report
```

`fieldkit-export` writes a severity-ranked `FIELDKIT.md` plan plus machine feeds (`recce-bridge.json`,
`ports.gnmap`, `smb-null.txt`) that name the exact fieldkit generator to run per host, weighting the
hosts recce already confirmed vulnerable. `fieldkit-import` folds fieldkit's proven findings back in as
**confirmed** vulnerabilities (source `fieldkit`) and marks each host *access-gained* — idempotent, so
run it as you go. Both stay stdlib-only / airgap-safe. Full guide: **[INTEGRATION.md](../../INTEGRATION.md)**.


## Output (`<output-dir>/`)

| File | Contents |
|------|----------|
| `enumeration.xlsx` | **Start Here** (self-guide) · **Runbook** (what to type per phase) · **Overview** · **Checklist** (per-IP step tracking) · **Services** (per-port status) · **Web** · **Vulnerabilities** · **Exploits** · **Verification** · **Services by Product/Version** · **Databases** · **Active Directory** · **AD Quick Wins** · **AD Findings** · **AD Attack Paths** (SharpHound + Certipy import) · Users & Accounts · **MSSQL** (offensive SQL Server enum + attack chain) · **SMB** (offensive file-sharing enum + attack surface) · **FTP** (offensive FTP enum + attack surface) · **Docker** (exposed Engine API) · **Kubernetes** (kubelet/API/etcd exposure) · **LDAP** (AD directory enum) · **SNMP** (community walk + users/software) · **MongoDB** (unauthenticated exposure) · **Priv-Esc** · **Exploitation** (confirmed finding → exact existing tool + command + validation) — ordered to follow the engagement flow (orient → track → find → exploit → pivot → AD → post-ex); all with autofilter, freeze panes, and persistent checkbox tracking |
| `enumeration.md`   | Summary + per-host checklist (great for notes / git) |
| `services.csv`     | Flat services table for import/pivot anywhere |
| `report.html`      | Self-contained shareable HTML report (exec summary, severity, findings, attack path, hosts) — no external assets. Links to `assets.html` |
| `assets.html`      | Self-contained **architecture & assets** companion — the network map, the tier-0 AD diagram (from a BloodHound import, when present), key info, users/accounts and masked credentials |
| `network-architecture.svg` | **Headline network diagram** — the AD domain over a routed core, each segment reached through its gateway (router, or firewall for edge/DMZ) and an L2 switch, stacked by tier. **Topology-driven** once on-target routes are ingested (real gateway IPs + dual-homed pivot links). Open in any browser, no tools |
| `network-map-full.svg` / `network-map-overview.svg` / `network-map-tiered.svg` | The host map as standalone SVG — **full** (every host as a role-tinted tile), **overview** (per-subnet role counts, readable at scale), **tiered** (DC → servers → workstations + the credentialed lateral surface) |
| `network-reachability.svg` | **Observed** host-to-host reachability, drawn only after you `ingest` an on-target enum's `NETWORK` block — ARP neighbours + live connections a foothold actually reached, dual-homed pivots flagged. Ground truth, not inferred |
| `attack-path.svg`  | The staged attack path (foothold → priv-esc → creds → lateral → domain) as standalone SVG — after `attackpath`; also embedded in `report.html` |
| `ad-architecture.svg` | The tier-0 AD diagram as a standalone image — after an `ad`/BloodHound import |
| `writeups/*.docx`  | One Word write-up per finding + `findings_report.docx` (combined, with summary tables) — after `writeups` |
| `exploit-plan/*`   | Ready-to-run msf `.rc` + per-host plans — after `exploitplan` |
| `creds/*.txt`      | `users.txt` / `passwords.txt` / `nthashes.txt` for the spray plan — after `creds --plan` |
| `loot/<ip>.txt`    | raw on-target enum output per host — after `deploy` |
| `recce.log`        | Scan errors / timeouts / incomplete hosts (also on the Overview tab) |
| `results.sqlite`   | Normalized datastore (resume + re-report) |
| `raw/*.xml`        | Every raw nmap XML, for auditing / re-parsing |


