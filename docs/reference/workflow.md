# Workflow, coverage tracking & speed

The two-phase engagement model, importing existing scans, what each phase runs, the Checklist/Services tracking tabs, coverage, resumability, speed levers and scan profiles.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Workflow

The core is **two cheap, resumable commands**: `enum` gets the sheet populated
fast, then `vulns` scans for vulnerabilities per open port. Everything after
that — `db`, `privesc`, `credenum`, `ingest`, `writeups` — is an **optional
deeper phase** you run on whatever subset you like, whenever you like. Each phase
is separate and re-runnable (re-running never duplicates anything).

**Already have an nmap scan?** Skip `enum` and `import` it — no scanning needed:

```bash
recce import scan.xml -o eng                 # nmap -oX XML (richest)
recce import scan.gnmap -o eng               # nmap -oG grepable
recce import scan.nmap -o eng                # nmap -oN normal text
recce import a.xml b.gnmap c.nmap -o eng     # multiple files at once (any mix)
recce import scans/ -o eng                   # a whole directory (or a glob)
```

**All three nmap output formats work** — XML (`-oX`), grepable (`-oG`), and normal
(`-oN`) — auto-detected by extension or content, so you can point it at whatever
you have. Tools that emit nmap-compatible XML (**masscan** `-oX`, rustscan, …)
import too. A `-oA` set (`base.xml`/`.gnmap`/`.nmap`) is imported once, from the
richest file. The normal (`-oN`) and grepable formats carry hosts + open ports +
service/version; XML additionally carries NSE scripts and OS detection.

`import` folds the hosts into the workbook, runs the same offline enrichment as
`enum` (version→CVE/CWE database, AD role/DC identification, SMB signing), ticks
**Enumerated** (and **Vuln-scan** where the scan ran NSE scripts), and preserves
any ticks/notes already in the sheet. XML (`-oX`) carries the most (services, NSE
scripts, OS); grepable (`-oG`) gives hosts + open ports + service/version. From
there, every other phase (`vulns`, `db`, `credenum`, `writeups`, …) works exactly
as if recce had done the scan itself.

**Import as many scans as you like** — a single IP, a range, one subnet, or many
— into the same engagement. New hosts are **appended** and grouped by subnet; a
host seen in more than one scan is **merged, never duplicated** (its open ports
are unioned, richer service/version wins). So you can drip-feed scans in as they
finish, or combine per-subnet scans into one workbook.

```bash
# FIRST, on any new box: verify it can run the tool (env + tools + a real
# localhost self-scan). Do this before every engagement.
python -m recce doctor

# See the whole thing with no network (bundled sample):
python -m recce demo -o demo_out

# ── Phase 1: fast enumeration across subnets → populates the sheet ──
#   discovery → port scan → service/version ID only. No vuln scanning yet.
sudo python -m recce enum 10.0.10.0/24 10.0.20.0/24 -o acme \
     --title "ACME internal"

#   ...now open acme/enumeration.xlsx: hosts, ports, services, apps are there.
#   Work the sheet, tick Reviewed as you go. Check where you stand any time:
python -m recce status -o acme

# ── Phase 2: vuln-scan the open ports it found (safe by default) ──
sudo python -m recce vulns -o acme                 # all open ports
sudo python -m recce vulns 10.0.20.0/24 -o acme    # just one subnet
sudo python -m recce vulns 10.0.10.5 -o acme       # just one host
sudo python -m recce vulns -o acme --only http smb # just web + SMB
sudo python -m recce vulns -o acme --unscanned     # only what's left
sudo python -m recce vulns -o acme --aggressive    # intrusive vuln NSE
sudo python -m recce vulns -o acme --fast          # top-signal only + progress/ETA

# ── Phase 3: the deep pass — one command instead of ~9 ──
#   sweep = every applicable credential-free deep module in one shot; each
#   self-skips when the datastore has no matching service, and the workbook is
#   rebuilt once at the end. Run the individual commands only to focus.
python -m recce sweep -o acme                       # web/smb/ftp/ldap/snmp/mongodb/
                                                    # redis/elasticsearch/rsync/nfs/
                                                    # kerberos/docker/k8s/mssql
python -m recce sweep -o acme --only-modules web smb   # narrow to a couple
python -m recce sweep -o acme --vulns               # also run the NSE vuln scan
python -m recce sweep -o acme --skip mssql          # exclude one

#   credsweep = the authenticated counterpart, once you have creds: the
#   netexec/impacket phase (credenum) + authenticated ldap/smb/mssql/ftp.
python -m recce credsweep -u alice -p 'Passw0rd!' -d corp.local -o acme

# ── Databases (per host / subnet / range, safe by default) ──
sudo python -m recce db -o acme                    # all DB services
sudo python -m recce db 10.0.20.6 -o acme --aggressive  # brute/xp_cmdshell

# ── Priv-esc playbook + optional remote checks ──
python -m recce privesc -o acme                    # playbook from data (no scan)
sudo python -m recce privesc 10.0.10.0/24 -o acme --scan  # + smb-vuln-* checks

# One-shot (enum then vulns):
sudo python -m recce scan 10.0.10.0/24 -o acme

# Regenerate reports from the datastore (no re-scan; preserves your ticks):
python -m recce report -o acme
```

**Every phase takes targets** — a single IP, several IPs, ranges
(`10.0.0.10-40`), whole subnets (CIDR), or `@file`. `enum`/`scan` take them as
the positional scope; `vulns`/`db`/`privesc` take them to restrict to a subset of
what's already in the datastore (plus `--only`, `--unscanned`).

### The Checklist tab

The **Checklist** sheet (right after Overview) is the at-a-glance answer to
"which IPs are done and what's left." One row per IP, with a **checkbox for each
workflow step**:

| Reviewed | IP | OS | … | Enum | Vuln | Web | AD | DB | Access | Priv-esc | Creds | Lateral | Notes |
|:--:|---|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|---|
| ☐ | 10.0.10.10 (dc01) | Windows | | ✅ | ☐ | — | ☐ | — | ☐ | — | ☐ | ☐ | |
| ☐ | 10.0.20.5 (web01) | Linux | | ✅ | ✅ | ✅ | — | ☐ | ☐ | — | ☐ | ☐ | |
| ☐ | 10.0.20.9 (smb01) | Windows | | ✅ | ☐ | — | — | — | ☐ | — | ☐ | ☐ | |

The step columns are **two kinds**, and each **only appears where it applies**
(an irrelevant step shows **`—` (N/A)**, so a checked box always means real work):

- **Auto surfaces** — the tool fills these in and they turn green when done:
  - **Enumerated** — universal. **Vuln-scan** — any host with an open port.
  - **Web** — hosts serving HTTP/HTTPS; green once the web ports are scanned.
  - **DB** — hosts running a database; green once `db` runs.
  - **Access** — green once a credentialed step confirms a foothold on the host
    (valid creds / local admin via `credenum`/`credsweep`, an SSH session, or a
    working MSSQL login). You can also record a foothold you got another way with
    `recce access --host IP --note '...'`, and untick to override.
  - **Priv-esc** — appears once the `privesc` phase has run against the host.
- **Manual sign-offs** — operator work the tool can't detect; start unchecked,
  you tick them as you go:
  - **AD** — only on **domain controllers / directory hosts** (LDAP / Kerberos /
    GC, or a discovered DC role). A plain SMB file server is *not* an AD host —
    its SMB surface is tracked per-port on the **Services** tab. Tick AD once
    you've reviewed users/shares/roasting/delegation/ADCS.
  - **Creds** (harvested secrets) → **Lateral** (tried credential reuse / pivot
    from here). These are the kill-chain coverage markers — they answer "did we
    actually try?" per host.
- The long tail of services — **SMB, remote access (SSH/RDP/WinRM/VNC), mail,
  SNMP, DNS, …** — deliberately has **no column here**; each such port is tracked
  with its own tri-state status on the **Services** tab, so the checklist stays
  readable while nothing goes untracked.
- You can **tick or untick any real box by hand**; your choice **persists and
  overrides the tool** on later refreshes. Re-running an auto phase resets that
  box to the tool's state; manual boxes stay exactly as you left them.
- Filter a column to `☐` to see what's left; `—` cells are skipped, so you never
  chase a step that doesn't apply. Rows are **grouped by subnet**.

The **Overview** tab's per-subnet coverage table accounts for **every subnet in
scope** — even ones with no live hosts — showing addresses in range, live hosts
found, and auto-surface completion (Enumerated / Vuln-scanned / Web / DB) where
the denominator counts only hosts that surface applies to. That's your guarantee
no subnet — or surface — is missed.

The **Reviewed** checkbox is your per-host sign-off (on the Checklist row).
`status` prints auto progress *and* your manual sign-off
counts (AD reviewed, Access, Priv-esc, Creds, Lateral) so you can see kill-chain
coverage at a glance.

### The Services tab — per-port status

The Checklist tracks whole hosts; the **Services** tab tracks **each open port**.
One row per `IP:port`, grouped by IP, each with its own **tri-state Status**
dropdown so you can mark exactly where you are on that specific port:

| Status | IP | Port | Service | Product | … | Notes |
|---|---|---|---|---|---|---|
| ☑ Done | 10.0.20.5 | 80 | http | Apache 2.4.41 | | creds found, admin panel |
| ◐ In progress | 10.0.20.5 | 443 | https | | | testing TLS + login |
| ☐ Not started | 10.0.20.5 | 22 | ssh | OpenSSH 8.2 | | |

- Pick **☐ Not started / ◐ In progress / ☑ Done** from the dropdown on each port.
  Done rows turn **green**, In-progress rows **amber**, so a host's remaining work
  is obvious at a glance.
- Every port has its own **Notes** cell for findings, creds, payloads, next steps.
- Your status + notes **persist in the datastore** and survive every rescan and
  report rebuild, exactly like the checklist boxes. Filter `Status = ☐ Not
  started` to see every port nobody has touched yet.

> Because the tool rewrites the sheet, "manual wins" works by recording a step
> override only when your box differs from the tool's current state — so re-tick a
> box to match the tool and it goes back to following the tool automatically.
> Edit step boxes *between* scans (not while a scan of that host is running).


## What each phase runs

**`enum` (light, feeds the sheet):**
1. **Discovery** — ping/ARP sweep (skip with `--no-discovery` for `-Pn`).
2. **Port sweep** — full TCP (`-p-`) or `--top-ports N` (or `--fast` masscan).
3. **Service ID** — `-sV -sC` (+ `-O`), safe SMB/LDAP AD facts, and a **deep
   service-aware enumeration NSE set** (see below). Still no vuln scanning, so it
   stays quick (the `quick` profile skips the deep set).

**`vulns` (targeted, per open port):** for the open ports already in the
datastore, runs the vulnerability + weak-config scripts below, marks each port
`vuln-scanned`, and maps exploits. **Safe by default — but deeper than the raw
`vuln and safe` category:** many high-value detection scripts (`smb-vuln-ms17-010`,
`ssl-heartbleed`, `http-shellshock`, `ftp-vsftpd-backdoor`…) are tagged `vuln` but
*not* `safe`, so the bare category silently misses them — recce always layers in a
curated non-destructive detection set so they run, with nothing extra to remember.
`--aggressive` adds the full intrusive `vuln` category (XSS/SQLi/DoS probes — can
hang printers/OT/old services). Optional top-N UDP with `--udp-top`.

**`sweep` / `credsweep` (the deep pass — one command each):** after `enum`
(+`vulns`), rather than running the deep service modules one at a time, `sweep`
runs every applicable **credential-free** module (`web` / `smb` / `ftp` / `ldap` /
`snmp` / `mongodb` / `redis` / `elasticsearch` / `rsync` / `nfs` / `kerberos` /
`docker` / `kubernetes` / `mssql`) and `credsweep` runs the
**authenticated** ones (`credenum` plus the authenticated facets of `ldap` /
`smb` / `mssql` / `ftp`). Each module self-skips when the datastore has no
matching service, findings fold into the same sheets, and the workbook rebuilds
once at the end. `sweep` refuses credentials (a credentialed action must be
explicit — use `credsweep`); `credsweep` requires `-u/-p`. Both take
`--only-modules` / `--skip` to narrow the set. The per-module commands (below)
still exist for when you want to focus one service or pass module-specific
options.


## Coverage tracking

The goal: know **at any moment** which systems/services you've looked at and
which you haven't — and never lose that as scans grow.

- **Check items off two ways:** tick the `Reviewed`/`Checked`/`Triaged` box in any
  tracked sheet in Excel, **or** use the `review` command. Both write to the
  persistent datastore.
- The datastore is the source of truth. Regenerating reports (`report`, or the
  auto-refresh during a scan) **preserves every check and note**. Each tracked
  sheet carries a hidden `Key` column that ties a row to its datastore item, so
  read-back is exact.
- The **Overview** sheet (data-bar progress per category + per subnet) and the
  `status` command give a live picture.

```bash
# Live coverage in the terminal (also flags unreviewed DCs / high-risk hosts):
python -m recce status -o engagement

# Mark from the CLI: a host and all its services, with a note:
python -m recce review -o engagement --host 10.0.10.10 --cascade \
       --note "DC enumerated, NTDS dump pending"

# Mark specific services / undo:
python -m recce review -o engagement --service 10.0.20.5:80 10.0.20.5:443
python -m recce review -o engagement --host 10.0.10.25 --undo

# Edit checkboxes in Excel, then pull them into the datastore + refresh:
python -m recce report -o engagement
```

**Initial access is tracked automatically.** The `Access` step is no longer a
manual checkbox — recce marks a host as *access gained* whenever a credentialed
phase confirms a foothold (valid creds / local admin via `credenum`/`credsweep`,
an SSH session, or a working MSSQL login), and the Access step auto-ticks. Review
the picture — or record a foothold you gained another way — with the `access`
command:

```bash
python -m recce access -o engagement                       # who do I have a foothold on?
python -m recce access -o engagement --host 10.0.10.25 \
       --note "SYSTEM via PrintNightmare"                  # record a manual foothold
python -m recce access -o engagement --host 10.0.10.25 --undo   # clear it
```

`status` output:

```
  OVERALL      [####----------------]  18%  5/27
  Hosts        [#####---------------]  25%  1/4
  Services     [######--------------]  30%  4/13
  ...
  ! Unreviewed Domain Controllers: 10.0.10.10
```

### How new IPs appear (in-place update)

The spreadsheet is generated from scans — it can't discover IPs on its own, so a
`scan` (or `report`) run is what brings new systems in. When that happens the
workbook is updated **in place**:

- **rows you've already reviewed keep their position and your checkbox/notes**,
- **new IPs/services are appended at the bottom** of each sheet (so nothing you've
  worked through shifts around), and
- the Overview / Active Directory tabs recompute.

Practical rule for a spreadsheet-only workflow: **do your tracking in the
checkbox and `Notes` columns.** The tool re-lays-out the sheets each run, so those
columns survive — but ad-hoc cell coloring or extra columns you add by hand will
not.

**You can keep working in the sheet while a scan runs.** The auto-refresh
re-imports your saved checkboxes/notes *before* regenerating, and writes
atomically — so saved edits are never lost. If the workbook is open and locked
when a refresh fires, the tool skips that write (your edits are already captured)
and retries; it never corrupts the open file. Just **save in Excel** so the
refresh can see your latest ticks.


## Nothing is wasted if a run is slow or crashes

Findings are written to the SQLite datastore **the moment each host finishes** —
not at the end. On top of that:

- The workbook refreshes **after every N hosts *or* every ~20 seconds**, whichever
  comes first (so even slow hosts produce visible progress), controlled by
  `--refresh-every`.
- **Ctrl-C** stops cleanly and still writes a final report from everything done
  so far.
- A hard crash or kill loses at most the one in-flight host; run
  `report -o <dir>` to rebuild the full sheet from the datastore.
- `--resume` skips hosts already scanned, so re-running after an interruption
  picks up where it left off.


## Speed

For a time-boxed engagement, three levers cut wall-clock dramatically:

- **Two phases** — `enum` is cheap, so the sheet is usable in minutes; the
  expensive `vulns` pass runs later and only where you point it (positional
  targets, `--only`, `--unscanned`).
- **`--workers N`** — scan N hosts concurrently (default 6). The single biggest
  win for large scopes.
- **`--fast`** — "go fast" end to end. On the sweep it runs one **network-wide
  masscan** (open ports across the whole scope at high packet-rate, then nmap
  scans *only* those host:port pairs; falls back to nmap if masscan is absent).
  On the vuln pass (`vulns --fast`, or `scan --fast`) it runs **only the curated
  top-signal detection scripts** — no broad `vuln and safe` category, no deep
  service enum — and prints a live **progress % + ETA**, making a big `/24`
  tractable. (`--aggressive` is the opposite end when you want maximum coverage.)
- **`--refresh-every N`** — regenerate the workbook every N hosts (default 10) so
  you can start triaging in Excel while the scan continues. `0` disables.
- **`--profile quick`** for first-pass triage (top-200 ports, no vuln scripts),
  then a targeted `--profile thorough` pass on what matters.

```bash
# Fast full-scope sweep, 12 hosts at a time, report refresh every 20 hosts:
sudo python -m recce scan 10.0.0.0/22 --fast --workers 12 --refresh-every 20 -o eng

# Resume where you left off after a break (skips already-scanned hosts):
sudo python -m recce scan 10.0.0.0/22 --fast --workers 12 --resume -o eng
```


## Profiles

| Profile | Ports | OS | Service ID | Host timeout | Notes |
|---------|-------|----|-----------|--------------|-------|
| `quick` | top 200 | no | intensity 6 | 10 min | fast triage |
| `standard` (default) | full TCP | yes | intensity 8 | 20 min | balanced |
| `thorough` | full TCP | yes | `--version-all` | 40 min | + top-100 UDP, slower/quieter |

Override with `--all-ports`, `--top-ports`, `--no-ad`, `--no-os`, `--min-rate`,
`--udp-top`, `--version-all`/`--version-intensity N` (service detection), and
`--host-timeout N` (minutes). (Vuln scanning is its own `vulns` phase, safe-by-default.)

**Basic UDP is scanned in `enum` by default** (needs root): a curated high-value set —
DNS, DHCP, TFTP, NTP, NetBIOS, SNMP, IKE/VPN, syslog, IPMI, MSSQL-browser, SIP, SSDP,
mDNS — so a TCP-only sweep doesn't silently miss UDP services. `--no-udp` skips it;
`--udp-top N` runs the larger UDP scan in the `vulns` phase.

**Scope exclusions** — `--exclude` takes IPs / ranges / CIDRs **or `@file`**, and the
exclusion set is **persisted to the engagement**: once an IP is excluded it stays out
of scope on every later phase and re-run without re-typing it.

**Full port scan is the default and it's stated up front.** `standard`/`thorough`
sweep all 65535 TCP ports (`-p-`); recce prints the port scope when the enum phase
starts and records it (echoed by `status`). A reduced scan — `quick`, `--top-ports N`,
or `--fast` — prints a loud `PARTIAL, NOT a full scan` warning so it can't be mistaken
for complete. `--all-ports` forces the full sweep and **overrides the profile** (applied
last), so `recce enum --profile quick --all-ports` still scans everything. A host whose
full sweep hits `--host-timeout` is flagged as an INCOMPLETE (partial) port list rather
than trusted as empty.

**Reliability.** Every scan has a per-host time ceiling (`--host-timeout`): nmap
gives up on a stuck host and moves on rather than hanging the run, and a hard
subprocess timeout backstops a truly wedged nmap. Anything that **errors or
doesn't finish** is logged to `engagement/recce.log`, listed at the top of the
**Overview** tab, and summarised by `status` — so a timed-out host or a failed
scan never disappears silently. Service detection runs at higher intensity in
the `enum` phase (it feeds the offline vuln DB); the `vulns` phase only does a
light version probe since enum already has the versions.

**No false "host down" / "no ports open".** The discovery sweep SYN-pings a broad
port set including the ports firewalled Windows/AD hosts still answer (Kerberos 88,
LDAP 389, WinRM 5985) and retries dropped probes. Live hosts that block ping are
still caught four ways: a **partial** sweep **reconfirms** every non-responder with a
fast `-Pn` top-ports scan (any open port = up — recovers firewalled boxes;
`--no-reconfirm` to skip); a **zero-response** sweep auto-falls back to `-Pn` (scan
everything as up); a host that comes back with **0 ports** is re-scanned with
congestion-adaptive timing (no `--min-rate` floor, more retries) before "no ports" is
trusted; and a `-Pn` host still silent on TCP gets a **UDP liveness ping**, so a
firewalled-but-alive box is confirmed up, never ruled dead. A host is only ever shown
as confirmed-up on a **real reply** (or an open port) — a silent host stays UNKNOWN,
never marked down.

**Authoritative target list (`--targets-up`).** When you have a complete IP/hostname
list you trust, pass `--targets-up` with an `@file` (lines may be `IP hostname`, space/
comma/tab-separated). recce treats the list as ground truth: it implies `-Pn` and
**pre-seeds every target into the report up front** (named, `up_reason=target-list`), so
a slow, timed-out, crashed, or even hard-killed scan can **never** make a real host
vanish — the host is already recorded and scanning only enriches it (rebuild anytime
with `recce report`).


