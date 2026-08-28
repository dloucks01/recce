# Reporting, write-ups & output files

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Finding write-ups (`writeups`)

`recce writeups -o eng` generates one Word `.docx` per finding, grouped by title across hosts (one issue spanning many systems = one write-up listing every `IP:port`). Real findings only by default; `--include-potential` adds version-inferred guesses.

`recce writeup <selector>` writes up a single finding, pre-filled with looted evidence and harvested creds in an *Obtained Access / Looted Evidence* section. Select by F-id (`F-007`), CVE, IP, `IP:port`, or title keyword; no selector lists all. F-ids are stable across bulk runs, combined reports, and single write-ups.

**Auto-filled:** Finding ID, title, affected systems, severity, CWE/CVE, tools/techniques, vulnerability type, CIA aspect, KB recommendations, narrative draft, raw evidence, and a **technical walkthrough** (discovery command, confirmation step tailored to detection method, mapped searchsploit exploit). Tester-only placeholders: **Mission Risk & Impact**, **Level of Difficulty**, exploitation result + screenshots. Re-run adds new findings; `--overwrite` forces rebuild. **recce never overwrites an edited write-up.**

**Combined report:** `writeups/findings_report.docx` -- severity summary table, findings table (ID/severity/title/CWE/hosts), every finding as a section. Regenerated from current data; skip with `--no-combined`.

**Screenshots (web only).** With a headless browser (**Firefox** or **Chromium**; override via `RECCE_BROWSER`), HTTP/HTTPS targets are auto-screenshotted into the walkthrough. Chrome tried first (ignores self-signed cert warnings); Firefox captures cert warning pages. Disable with `--no-screenshots`; filter with `--min-severity high`.

The writer is **pure stdlib** (`.docx` = zip of XML) -- no python-docx needed, runs airgapped.

## fieldkit integration (`fieldkit-export` / `fieldkit-import`)

Round-trips with [**fieldkit**](https://github.com/dloucks01/fieldkit) -- enumeration seeds exploitation, proven findings flow back:

```bash
recce fieldkit-export -o eng                     # -> eng/fieldkit/ : attack plan fieldkit consumes
recce fieldkit-import recce_findings.json -o eng  # proven findings -> Vulnerabilities sheet + report
```

`fieldkit-export` writes a severity-ranked `FIELDKIT.md` plan plus machine feeds (`recce-bridge.json`, `ports.gnmap`, `smb-null.txt`) naming the exact fieldkit generator per host. `fieldkit-import` folds proven findings back as **confirmed** vulnerabilities (source `fieldkit`), marks hosts *access-gained* -- idempotent. Both stdlib-only / airgap-safe. Full guide: **[INTEGRATION.md](../../INTEGRATION.md)**.

## Output (`<output-dir>/`)

| File | Contents |
|------|----------|
| `enumeration.xlsx` | **Start Here** . **Runbook** . **Overview** . **Checklist** (per-IP tracking) . **Services** (per-port status) . **Web** . **Vulnerabilities** . **Exploits** . **Verification** . **Services by Product/Version** . **Databases** . **AD** . **AD Quick Wins** . **AD Findings** . **AD Attack Paths** (SharpHound + Certipy) . Users & Accounts . **MSSQL** . **SMB** . **FTP** . **Docker** . **Kubernetes** . **LDAP** . **SNMP** . **MongoDB** . **Priv-Esc** . **Exploitation** -- ordered by engagement flow; autofilter, freeze panes, persistent checkbox tracking |
| `enumeration.md`   | Summary + per-host checklist (notes / git) |
| `services.csv`     | Flat services table for import/pivot |
| `report.html`      | Self-contained HTML report (exec summary, severity, findings, attack path, hosts); links to `assets.html` |
| `assets.html`      | Architecture & assets companion -- network map, tier-0 AD diagram (from BloodHound), users/accounts, masked credentials |
| `network-architecture.svg` | AD domain over routed core, segments through gateways, stacked by tier. Topology-driven after on-target route ingestion |
| `network-map-full.svg` / `...-overview.svg` / `...-tiered.svg` | **full** (every host as role-tinted tile), **overview** (per-subnet role counts), **tiered** (DC -> servers -> workstations + lateral surface) |
| `network-reachability.svg` | Observed host-to-host reachability from `ingest` NETWORK block -- ARP neighbours + live connections, dual-homed pivots flagged |
| `attack-path.svg`  | Staged attack path after `attackpath` |
| `ad-architecture.svg` | Tier-0 AD diagram after `ad`/BloodHound import |
| `writeups/*.docx`  | Per-finding write-up + `findings_report.docx` after `writeups` |
| `exploit-plan/*`   | msf `.rc` + per-host plans after `exploitplan` |
| `creds/*.txt`      | `users.txt` / `passwords.txt` / `nthashes.txt` after `creds --plan` |
| `loot/<ip>.txt`    | Raw on-target enum output per host after `deploy` |
| `chat-media/*`     | Team-chat attachments (images inline; others forced download) from `recce serve` |
| `recce.log`        | Scan errors / timeouts / incomplete hosts |
| `results.sqlite`   | Normalized datastore (resume + re-report) |
| `raw/*.xml`        | Raw nmap XML for auditing / re-parsing |


