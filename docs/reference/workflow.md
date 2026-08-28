# Workflow, coverage tracking & speed

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Workflow

Two cheap, resumable commands: `enum` populates the sheet fast, then `vulns` scans for vulnerabilities per open port. Everything after (`db`, `privesc`, `credenum`, `ingest`, `writeups`) is an **optional deeper phase** on any subset, any time. Each phase is separate and re-runnable (never duplicates).

**Already have an nmap scan?** Import it:

```bash
recce import scan.xml -o eng                 # nmap -oX XML (richest)
recce import scan.gnmap -o eng               # nmap -oG grepable
recce import scan.nmap -o eng                # nmap -oN normal text
recce import a.xml b.gnmap c.nmap -o eng     # multiple files, any mix
recce import scans/ -o eng                   # directory or glob
```

All three nmap formats auto-detected by extension or content. Tools emitting nmap-compatible XML (**masscan** `-oX`, rustscan) import too. A `-oA` set imports once from the richest file. Normal/grepable carry hosts + ports + service/version; XML adds NSE scripts and OS detection.

`import` folds hosts into the workbook, runs offline enrichment (version->CVE/CWE, AD role/DC identification, SMB signing), ticks **Enumerated** (and **Vuln-scan** where NSE scripts ran), preserves existing ticks/notes. From there every phase works as if recce scanned it. New hosts append by subnet; duplicates merge (ports unioned, richer data wins).

```bash
python -m recce doctor                        # verify env + tools + localhost self-scan
python -m recce demo -o demo_out              # bundled sample, no network

# Phase 1: fast enumeration
sudo python -m recce enum 10.0.10.0/24 10.0.20.0/24 -o acme --title "ACME internal"
python -m recce status -o acme

# Phase 2: vuln-scan open ports (safe by default)
sudo python -m recce vulns -o acme
sudo python -m recce vulns 10.0.20.0/24 -o acme
sudo python -m recce vulns -o acme --only http smb
sudo python -m recce vulns -o acme --unscanned
sudo python -m recce vulns -o acme --aggressive
sudo python -m recce vulns -o acme --fast

# Phase 3: deep pass -- one command instead of ~9
python -m recce sweep -o acme                 # web/smb/ftp/ldap/snmp/mongodb/redis/
                                              # elasticsearch/rsync/nfs/kerberos/docker/k8s/mssql
python -m recce sweep -o acme --only-modules web smb
python -m recce sweep -o acme --vulns
python -m recce sweep -o acme --skip mssql

# Authenticated counterpart once you have creds
python -m recce credsweep -u alice -p 'Passw0rd!' -d corp.local -o acme

# Databases (safe by default)
sudo python -m recce db -o acme
sudo python -m recce db 10.0.20.6 -o acme --aggressive

# Priv-esc
python -m recce privesc -o acme
sudo python -m recce privesc 10.0.10.0/24 -o acme --scan

# One-shot (enum then vulns):
sudo python -m recce scan 10.0.10.0/24 -o acme

# Regenerate reports from datastore (no re-scan; preserves ticks):
python -m recce report -o acme
```

**Every phase takes targets** -- IP, multiple IPs, ranges (`10.0.0.10-40`), CIDR, or `@file`. `enum`/`scan` take positional scope; `vulns`/`db`/`privesc` restrict to a datastore subset (plus `--only`, `--unscanned`).

### The Checklist tab

One row per IP with a **checkbox per workflow step**:

| Reviewed | IP | OS | Enum | Vuln | Web | AD | DB | Access | Priv-esc | Creds | Lateral | Notes |
|:--:|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|---|
| ☐ | 10.0.10.10 (dc01) | Windows | ✅ | ☐ | — | ☐ | — | ☐ | — | ☐ | ☐ | |
| ☐ | 10.0.20.5 (web01) | Linux | ✅ | ✅ | ✅ | — | ☐ | ☐ | — | ☐ | ☐ | |

Two column types, each showing only where applicable (irrelevant = `--`):

- **Auto surfaces** (tool fills, green when done): **Enumerated** (universal), **Vuln-scan** (open port), **Web** (HTTP/S hosts), **DB** (database hosts), **Access** (auto-ticks on confirmed foothold; also `recce access --host IP --note '...'`), **Priv-esc** (after `privesc`).
- **Manual sign-offs** (start unchecked): **AD** (domain controllers / directory hosts only -- LDAP/Kerberos/GC), **Creds** (harvested secrets), **Lateral** (tried credential reuse / pivot).

The long tail (SMB, SSH/RDP/WinRM/VNC, mail, SNMP, DNS) has no column here -- tracked per-port on the **Services** tab. Tick/untick any box by hand; your choice **persists and overrides** on later refreshes. Re-running an auto phase resets that box; manual boxes stay. Filter `☐` to see what's left. Rows grouped by subnet.

The **Overview** tab accounts for every subnet in scope (including those with no live hosts), with auto-surface completion where denominators count only applicable hosts. **Reviewed** is your per-host sign-off. `status` prints auto progress + manual counts (AD, Access, Priv-esc, Creds, Lateral).

### The Services tab

One row per `IP:port`, grouped by IP, with a **tri-state Status** dropdown:

| Status | IP | Port | Service | Product | Notes |
|---|---|---|---|---|---|
| ☑ Done | 10.0.20.5 | 80 | http | Apache 2.4.41 | creds found |
| ◐ In progress | 10.0.20.5 | 443 | https | | testing TLS |
| ☐ Not started | 10.0.20.5 | 22 | ssh | OpenSSH 8.2 | |

Done = **green**, In-progress = **amber**. Each port has a **Notes** cell. Status + notes **persist** across rescans and rebuilds. Filter `☐ Not started` for untouched ports.

> "Manual wins" records an override only when your box differs from the tool's state. Edit between scans, not during.

## What each phase runs

**`enum`:** 1) **Discovery** -- ping/ARP sweep (`--no-discovery` for `-Pn`). 2) **Port sweep** -- full TCP (`-p-`) or `--top-ports N` (or `--fast` masscan). 3) **Service ID** -- `-sV -sC` (`-O`), safe SMB/LDAP AD facts, deep service-aware NSE set. No vuln scanning. (`quick` profile skips the deep set.)

**`vulns`:** vulnerability + weak-config scripts on open ports, marks each `vuln-scanned`, maps exploits. **Safe by default but deeper than raw `vuln and safe`:** many high-value scripts (`smb-vuln-ms17-010`, `ssl-heartbleed`, `http-shellshock`, `ftp-vsftpd-backdoor`) are `vuln` but not `safe` -- recce layers in a curated non-destructive set. `--aggressive` adds full intrusive `vuln` category. `--udp-top N` for optional UDP.

**`sweep` / `credsweep`:** `sweep` runs every applicable credential-free deep module (`web`/`smb`/`ftp`/`ldap`/`snmp`/`mongodb`/`redis`/`elasticsearch`/`rsync`/`nfs`/`kerberos`/`docker`/`kubernetes`/`mssql`); `credsweep` runs the authenticated ones (`credenum` + authenticated `ldap`/`smb`/`mssql`/`ftp`). Each self-skips when no matching service exists; workbook rebuilds once at end. `sweep` refuses credentials (use `credsweep`); `credsweep` requires `-u/-p`. Both take `--only-modules`/`--skip`.

## Coverage tracking

Check items in Excel or via `review` command -- both write to the persistent datastore. Regenerating reports preserves every check and note (hidden `Key` column ties rows to datastore items). **Overview** (data-bar progress) and `status` give a live picture.

```bash
python -m recce status -o engagement
python -m recce review -o engagement --host 10.0.10.10 --cascade \
       --note "DC enumerated, NTDS dump pending"
python -m recce review -o engagement --service 10.0.20.5:80 10.0.20.5:443
python -m recce review -o engagement --host 10.0.10.25 --undo
python -m recce report -o engagement          # pull Excel edits into datastore + refresh
```

**Access tracked automatically.** recce marks *access gained* when a credentialed phase confirms a foothold (valid creds / local admin via `credenum`/`credsweep`, SSH session, working MSSQL login). Record manual footholds with `access`:

```bash
python -m recce access -o engagement
python -m recce access -o engagement --host 10.0.10.25 --note "SYSTEM via PrintNightmare"
python -m recce access -o engagement --host 10.0.10.25 --undo
```

### How new IPs appear

Scans (or `report`) bring new systems in. The workbook updates **in place**: reviewed rows keep position and checkboxes/notes; new IPs/services append at bottom; Overview/AD tabs recompute. **Track in checkbox and Notes columns only** -- ad-hoc cell coloring or extra columns won't survive re-layout.

**Work the sheet while scans run.** Auto-refresh re-imports saved checkboxes/notes before regenerating, writes atomically. If the workbook is locked, the tool skips and retries. Just **save in Excel** so refresh sees your ticks.

## Resumability

Findings write to SQLite **as each host finishes**. Workbook refreshes **every N hosts or ~20 seconds** (`--refresh-every`). **Ctrl-C** stops cleanly with a final report. A crash loses at most one in-flight host; `report -o <dir>` rebuilds. `--resume` skips already-scanned hosts.

## Speed

- **Two phases** -- `enum` is cheap (sheet usable in minutes); `vulns` runs later on targeted subsets.
- **`--workers N`** -- scan N hosts concurrently (default 6). Biggest win for large scopes.
- **`--fast`** -- network-wide **masscan** (open ports at high packet-rate, then nmap on those pairs; falls back if absent). On vuln pass: **top-signal scripts only**, live **progress % + ETA**. (`--aggressive` for max coverage.)
- **`--refresh-every N`** -- workbook regen every N hosts (default 10). `0` disables.
- **`--profile quick`** for first-pass (top-200 ports, no vuln scripts), then targeted `--profile thorough`.

```bash
sudo python -m recce scan 10.0.0.0/22 --fast --workers 12 --refresh-every 20 -o eng
sudo python -m recce scan 10.0.0.0/22 --fast --workers 12 --resume -o eng
```

## Profiles

| Profile | Ports | OS | Service ID | Host timeout | Notes |
|---------|-------|----|-----------|--------------|-------|
| `quick` | top 200 | no | intensity 6 | 10 min | fast triage |
| `standard` (default) | full TCP | yes | intensity 8 | 20 min | balanced |
| `thorough` | full TCP | yes | `--version-all` | 40 min | + top-100 UDP |

Override with `--all-ports`, `--top-ports`, `--no-ad`, `--no-os`, `--min-rate`, `--udp-top`, `--version-all`/`--version-intensity N`, `--host-timeout N` (minutes).

**Default UDP in `enum`** (needs root): curated high-value set (DNS, DHCP, TFTP, NTP, NetBIOS, SNMP, IKE/VPN, syslog, IPMI, MSSQL-browser, SIP, SSDP, mDNS). `--no-udp` skips; `--udp-top N` runs larger UDP in `vulns`.

**Scope exclusions:** `--exclude` takes IPs/ranges/CIDRs or `@file`, **persisted to the engagement** -- stays out of scope on every later phase.

**Full port scan stated up front.** `standard`/`thorough` sweep all 65535 TCP ports; recce prints port scope at enum start. Reduced scans (`quick`, `--top-ports`, `--fast`) print `PARTIAL, NOT a full scan` warning. `--all-ports` forces full sweep and **overrides the profile**. A host hitting `--host-timeout` is flagged INCOMPLETE rather than trusted as empty.

**Reliability.** Per-host `--host-timeout` ceiling + hard subprocess timeout backstops wedged nmap. Errors/timeouts logged to `recce.log`, listed on **Overview**, summarised by `status` -- never disappears silently. Service detection runs at higher intensity in `enum` (feeds offline vuln DB); `vulns` does a light probe since versions are known.

**No false "host down".** Discovery SYN-pings a broad port set including firewalled Windows/AD ports (88, 389, 5985). Fallbacks: partial sweep **reconfirms** non-responders with `-Pn` top-ports (`--no-reconfirm` to skip); zero-response sweep auto-falls back to `-Pn`; 0-port hosts re-scanned with adaptive timing; `-Pn` hosts silent on TCP get **UDP liveness ping**. A host is shown up only on a **real reply** or open port; silent hosts stay UNKNOWN, never marked down.

**Authoritative target list (`--targets-up`).** Pass `@file` (lines: `IP hostname`, any separator). Implies `-Pn`, **pre-seeds every target** into the report (`up_reason=target-list`), so a slow/crashed/killed scan never loses a host -- already recorded, scanning only enriches.
