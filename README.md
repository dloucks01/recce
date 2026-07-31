# recce

Multi-subnet enumeration and reporting for penetration-testing engagements.

`recce` orchestrates **nmap** (optionally **masscan**) across many hosts
and subnets, normalizes everything into a resumable datastore, and produces an
**Excel workbook** built for tracking your engagement — plus Markdown and CSV.

It is designed for mixed **Linux + Windows / Active Directory** environments:
full TCP port sweeps, service/version + OS detection, vulnerability
identification (curated detection NSE + a built-in **offline** version→CVE/CWE
database, so it works airgapped), and deep **Active Directory** analysis — DC
identification, NTLM-relay target discovery, credentialed LDAP enumeration of
users, SPNs, roastable accounts, delegation, groups and trusts, and offline
**BloodHound (SharpHound) + Certipy (ADCS/ESC)** import that maps the shortest
paths from your account to Domain Admin.

> 🚀 **New here? Read [QUICKSTART.md](QUICKSTART.md)** — a one-page guide that
> gets you from zero to a filled-in workbook in five commands. Prefer a
> printable one-sheet field reference? Open **[CHEATSHEET.html](CHEATSHEET.html)**
> in a browser. There is also a `./bin/recce` wrapper so you can skip typing
> `python3 -m recce`, and a **Start Here** tab inside every workbook that
> explains each sheet.

> ⚖️ **Authorized use only.** recce is for security work you have written
> permission to perform. Its safety controls, the intrusive actions that are
> opt-in/flag-gated, and your responsibilities as an operator are all documented
> in **[SECURITY.md](SECURITY.md)** — read it before your first engagement.

## Why this over raw nmap / AutoRecon?

Existing tools scan well but leave you with per-host output files. `recce`
adds the layer engagements actually need:

- **Cross-host, checkable deliverable.** Every host, service, vuln and account
  lands in one filterable workbook with `Reviewed`/`Checked`/`Triaged` checkbox
  columns so you can track what's been looked at.
- **Persistent coverage tracking.** Your checkboxes live in the datastore, not
  just the spreadsheet — re-scanning and re-reporting **never wipe your
  progress**. An **Overview** sheet and a `status` command show exactly what's
  left, at any time (see [Coverage tracking](#coverage-tracking)).
- **"Who else runs this?" pivot.** A *Services by Product/Version* sheet groups
  every endpoint by exact product+version — instantly see all systems running
  the same vulnerable service.
- **Built for a tight clock.** Host-level **concurrency** and a **masscan
  fast-path** collapse hours of sequential `-p-` scans; reports refresh
  incrementally so you can start reviewing while the scan is still running (see
  [Speed](#speed)).
- **Resumable across long, multi-subnet scans.** Results are stored in SQLite and
  merged on re-run; interrupt and `--resume` any time.

## Install

**No pip install required.** The tool uses only the Python standard library
(3.9+), so it runs on an **airgapped** box out of the box — including writing and
reading `.xlsx` (a self-contained stdlib writer, no openpyxl). Just copy the
folder over and run **`python3 -m recce ...`** or **`./bin/recce ...`**.

> `pip install .` is **optional** — it only creates a bare `recce` command on
> PATH. recce has zero Python dependencies, so it never fetches anything, but
> pip's default build step pulls `setuptools`/`wheel` from PyPI, so on an
> airgapped box either use `--no-build-isolation` or (simpler) **just skip pip
> and use `./bin/recce`**. `pyproject.toml` is there for staging boxes / an
> internal mirror and for `recce --version`.

It orchestrates these **system tools** if present (all standard on Kali). Only
`nmap` is required; every other tool is optional and its phase degrades cleanly
with a logged note when absent. `recce doctor` reports exactly what's available.

| Tool | Needed for |
|------|-----------|
| `nmap` | **required** — scanning, service/version/OS detection, NSE vuln + AD scripts |
| `masscan` | optional — `--fast` network-wide sweep |
| `searchsploit` (exploitdb) | optional — offline exploit mapping (Exploits sheet) |
| `netexec` / `crackmapexec` | optional — credentialed SMB/AD enum (`credenum`) |
| `impacket` | optional — Kerberoast / AS-REP / secretsdump (`credenum`) |
| `ldapsearch` (ldap-utils) | optional — credentialed AD LDAP enumeration |
| `ssh` (+ `sshpass`) | optional — credentialed Linux local checks (`credenum`) |
| `firefox` / `chromium` | optional — auto web screenshots in write-ups |

Run scans as **root** (SYN scan + OS detection need raw sockets); it falls back
to a TCP connect scan otherwise.

> The `.xlsx` files it writes open in Excel and LibreOffice. If you happen to
> have `openpyxl` on a connected box, the files are fully compatible — but it is
> never required.

### Build the burn package (transfer / airgap)

recce ships as a **plain drop-in tarball** — a single `recce-<version>/` directory
you extract and run, no pip and no wheel. A pre-built one for the current release
lives in **[`recce/releases/`](recce/releases/)** (`.tar.gz` + `.zip` + `SHA256SUMS`);
grab it directly, or build your own:

```bash
./make_package.sh              # -> dist/recce-<version>.tar.gz (+ .zip) + SHA256SUMS
./make_package.sh --verify     # run the test suite first
```

It stages the tool (`recce/` incl. the `local/` and `scripts/` suites), `bin/`,
the tests, and the docs — scrubbing caches, VCS, and any scan/engagement output —
into a single `recce-<version>/` directory, archives it, and writes `SHA256SUMS`
for verifying the transfer. On the target:

```bash
tar xzf recce-<version>.tar.gz && cd recce-<version> && ./bin/recce doctor
```

No network or pip install needed — recce is stdlib-only at runtime.

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

## Enumeration & vulnerability identification

Both `enum` (deep enumeration) and `vulns` run a large, **service-aware** NSE set —
nmap only executes the scripts whose portrule matches each detected service, so
coverage is broad but cheap. Highlights:

- **Web**: `http-enum`, `http-title`, `http-headers`, `http-methods`,
  `http-webdav-scan`, `http-git`, `http-auth`, `http-open-proxy`, `http-ntlm-info`,
  `http-wordpress-enum`, `http-devframework`, `http-config-backup`
- **TLS**: `ssl-cert`, `ssl-enum-ciphers`, `ssl-heartbleed`, `ssl-poodle`,
  `ssl-ccs-injection`, `ssl-dh-params` (weak ciphers/protocols, known TLS CVEs)
- **SSH**: `ssh2-enum-algos`, `ssh-auth-methods`, `ssh-hostkey`
- **SMB/Windows**: `smb-vuln-ms17-010`, `smb-double-pulsar-backdoor`,
  `smb-enum-services`, `smb-system-info`, `smb2-capabilities`
- **FTP/mail**: `ftp-anon`, `ftp-vsftpd-backdoor`, `smtp-open-relay`,
  `smtp-enum-users`, `smtp-vuln-*`, POP3/IMAP caps + NTLM info
- **Databases**: `mysql-info`/`-databases`/`-users`/`-empty-password`, `ms-sql-*`,
  `oracle-tns-version`, `mongodb-info`/`-databases`, `redis-info`, `cassandra-info`
- **SNMP/DNS/misc**: `snmp-info`/`-win32-*`, `dns-zone-transfer`, `nfs-showmount`,
  `rpcinfo`, `vnc-info`, `rdp-ntlm-info`, `ike-version`, `ipmi-version`, `upnp-info`

**Four vulnerability channels feed the Vulnerabilities sheet** (all work
airgapped, none need internet):

1. **NSE `vuln` category** (local) plus **weak-config findings** parsed from the
   enumeration scripts above — anonymous FTP, weak/expired TLS, risky HTTP
   methods, empty DB passwords, cleartext Telnet, SMTP open relay, exposed
   Redis/Mongo, SNMP community strings, DNS zone transfer, etc.
2. **Offline version→CVE engine** (`vulndb.py`) — a curated knowledge base of
   **95+ high-signal signatures** that matches the product+version data `enum`
   already collected against known CVEs, with a description, CWE(s) and
   **remediation**. Covers FTP/SSH/web servers, Samba/SMB, databases, CI/web apps
   (Jenkins, Tomcat, Drupal, Confluence, GitLab, Grafana…), **edge/VPN/firewall
   appliances (Fortinet, Pulse/Ivanti, Citrix, Palo Alto, SonicWall, F5 BIG-IP,
   Cisco ASA/Smart Install, MikroTik, Zyxel, DrayTek, Sophos, Barracuda)**,
   Exchange, **virtualization (vCenter,
   ESXi, Horizon), Java middleware (WebLogic, JBoss, ActiveMQ, ColdFusion, Solr,
   Zimbra, Jetty), dev/CI/infra exposure (Docker API, Kubernetes/kubelet, etcd,
   Nexus, TeamCity, SonarQube), monitoring (Zabbix, Cacti, PRTG, Nagios, CouchDB,
   Kibana, Splunk), OS-gated Windows/AD advisories (SMBGhost, PrintNightmare,
   ZeroLogon, WinRM, MSSQL)**, and default-credential advisories. This is the
   airgapped replacement for nmap's internet-only `vulners` script. Findings are
   tagged `likely` (a concrete version range matched) or `potential` (a
   product-only or OS-gated advisory lead).
3. **Pure-Python enrichment probes** (`probes.py`, stdlib only) — an active
   layer stock Kali needs extra tooling (testssl.sh, nikto, httpx) for:
   **HTTP security-header analysis** (missing HSTS/CSP/X-Frame-Options/
   X-Content-Type-Options, version-disclosing `Server` banners) and **TLS
   certificate & protocol analysis** (expired/self-signed/soon-to-expire certs,
   hostname mismatch, negotiable SSLv3/TLS 1.0/1.1). Disable with `--no-probes`.
   The web sweep (`web.py`) also carries **data-driven application signatures** —
   fingerprint + a self-proving unauthenticated path — for high-value apps:
   **Jenkins** (unauth script-console RCE), **Keycloak** (admin console),
   **Grafana** (CVE-2021-43798 file read), **HashiCorp Vault**, **Elasticsearch**
   (unauth index read), **Kibana**, plus exposed `.git`/`.env`, Spring Actuator
   and Tomcat Manager. With `--creds` it runs a bounded, lockout-aware
   **default-credential** probe (HTTP Basic + form/JSON logins: Grafana
   `admin/admin`, MinIO `minioadmin`, RabbitMQ `guest/guest`). With `--crawl`
   it same-origin crawls each site and fuzzes **discovered GET params and form
   fields** for reflection/SSTI and **SQL injection** — error-based (MySQL/
   PostgreSQL/MSSQL/Oracle/SQLite error signatures), boolean-based blind
   (true≈baseline vs false-diverges, re-tested, skipped on dynamic pages), and
   opt-in time-based blind (`--sqli-time`), plus **open redirect** and generic
   **path traversal / local file read** on the same params/fields. Payloads are
   non-destructive (quote-break + `AND`/sleep, traversal reads only; never
   stacked `DROP`/`UPDATE`/`DELETE`); destructive-looking forms and
   password/anti-CSRF fields are never touched. Every response's **cookies** are
   graded too — missing HttpOnly/Secure/SameSite, `SameSite=None` without Secure,
   a session cookie over cleartext HTTP, a missing `__Host-`/`__Secure-` prefix,
   or an over-broad parent `Domain`.
4. **`searchsploit` (Exploit-DB, offline)** maps every service's product+version
   to known public exploits on a dedicated **Exploits** sheet (EDB-ID, type,
   title, CVEs, local path).

Every finding also carries **CWE** references (in a dedicated column) alongside
its CVEs, so you can group and report weaknesses by class.

> **Airgapped tip:** run with `--offline` to drop the internet-dependent
> `vulners` script; you still get the local `vuln` category, all weak-config
> findings, the offline version→CVE engine, the HTTP/TLS probes, and
> `searchsploit` exploit mapping. Install `exploitdb` for searchsploit
> (`apt install exploitdb`, and it ships on Kali).

Toggles (on `vulns`/`scan`): `--aggressive`, `--offline`, `--no-searchsploit`,
`--no-probes`, `--udp-top N`, plus positional targets, `--only`, `--unscanned`
to target a subset.

## Databases (`db`)

`db` finds database services (MySQL, MSSQL, Oracle, PostgreSQL, MongoDB, Redis,
CouchDB, …) and runs engine-specific NSE. **Safe by default** — version/config
enumeration, database & user listing, empty-password checks. `--aggressive` adds
intrusive checks (brute force, `xp_cmdshell`, hash dumping). Results populate a
**Databases** sheet (engine, version, auth posture, databases, users, findings);
security issues also land in the Vulnerabilities sheet. Credentials via
`--username/--password` are passed to the DB scripts for authenticated checks.

## Priv-Esc (`privesc`)

`privesc` produces a per-host **Priv-Esc** sheet with two parts:

- **Remote findings** we actually observed — missing patches with public
  exploits (MS17-010, ZeroLogon, BlueKeep, PrintNightmare), SMB signing off,
  unauthenticated services, and local/remote exploit candidates from searchsploit.
- **An OS-specific playbook** — the prioritised checks/commands to run once you
  have a foothold. Windows: winPEAS/PowerUp, service perms & unquoted paths,
  `AlwaysInstallElevated`, token privileges (`SeImpersonate`→Potato), stored
  creds, scheduled tasks, DLL hijacking. Linux: linPEAS, `sudo -l`+GTFOBins,
  SUID/SGID, capabilities, cron, writable sensitive files, NFS `no_root_squash`,
  docker/lxd group.

The playbook is generated offline from what `enum` already found (no scanning);
`--scan` additionally runs the remote privesc NSE checks (`--aggressive` includes
intrusive ones like MS08-067 that can crash services).

### On-target enum → `ingest`

recce ships two **read-only** on-target sweeps in `recce/local/` — `recce-enum.sh`
(Linux) and `recce-enum.ps1` (Windows), a linPEAS/winPEAS-style deep dive that
changes nothing on the host. Once you have a shell, run one on the target, save
its output, and fold the `[!]` findings straight into that host's **Priv-Esc**
sheet:

```bash
# on the target:
./recce-enum.sh -o loot.txt                                  # Linux (-t self-tests)
powershell -ep bypass -File recce-enum.ps1 -OutFile loot.txt # Windows (-SelfTest)
# back on Kali:
recce ingest loot.txt -o eng          # auto-resolves the host (see below); --host IP to force
```

**Running the Windows script when `-File` isn't an option.** `recce-enum.ps1` takes
its params and runs its sweep on invocation — there's no separate entry method to
call, so pick the form that fits your channel:

```powershell
# 1) Standard — run the script file directly:
powershell -ep bypass -File .\recce-enum.ps1 -OutFile loot.txt

# 2) Dot-source — load it into an interactive session (its helper functions become
#    available too), then it runs with the params you pass:
. .\recce-enum.ps1 -OutFile loot.txt

# 3) Limited / semi-interactive channel (webshell, no -File) — read the script text
#    and invoke it as a scriptblock, passing params, nothing extra written to disk:
powershell -ep bypass -c "& ([scriptblock]::Create((Get-Content .\recce-enum.ps1 -Raw))) -OutFile loot.txt"
```

`ingest` needs no tools or network — it parses text recce itself produced. Findings
land as rows tagged **on-target finding** at the top of the host's Priv-Esc section.

**Host resolution is automatic.** With no `--host`, `ingest` lands the loot on the
right host by matching the box's own interface IPs from the enum's `NETWORK` block,
then by hostname, else it synthesizes an entry — so `recce ingest loot.txt` usually
needs no flag. The on-target enums (recce's own, and fieldkit's `linpriv`/`winpriv`)
also emit a machine `NET-IFACE / NET-ROUTE / NET-NEIGH / NET-PEER` block; `ingest`
folds that topology onto the host and `report` draws a **ground-truth**
`network-reachability.svg` (and upgrades `network-architecture.svg` to real gateways
+ dual-homed pivots). A topology-only block ingests fine with no `[!]` findings.

### Exploitation playbook (the *Exploitation* sheet)

For every **confirmed** priv-esc finding, recce builds a row on the
**Exploitation** sheet that turns the finding into an actionable next step using
**existing, published tools** — it does not generate exploit code. Each row gives:

- the **exact existing tool** (GodPotato / PrintSpoofer for `SeImpersonate`,
  PowerUp for a writable service, `gpp-decrypt` for a GPP cpassword, `reg save` +
  impacket-secretsdump for `SeBackupPrivilege`, GTFOBins for sudo/SUID,
  `openssl` for a writable `/etc/passwd`, the public PwnKit / Dirty Pipe PoCs, …),
- the **precise command with the finding's own values filled in** (the service
  name, the writable path, the SUID binary),
- the **prerequisite** and a **validation step** to confirm it worked.

Only confirmed findings get an entry — advisories / unconfirmed version matches
never get a "run this" line, matching the proven-exploit gating. The same guidance
appears in each finding's Word write-up as an *Escalate with existing tooling* step.

### Exploitation plan (`exploitplan`)

`recce exploitplan -o eng --lhost <IP>` takes that a step further: for each
**confirmed** finding it writes **ready-to-run artifacts** into `eng/exploit-plan/`,
with the parameters recce discovered already filled in:

- a **Metasploit resource script** (`.rc`) for every finding that maps to a
  published module — `ms17_010_eternalblue`, `vsftpd_234_backdoor`,
  `is_known_pipename` (SambaCry), `tomcat_ghostcat`, … — with `RHOSTS`, `RPORT`,
  `PAYLOAD`, `LHOST`/`LPORT` set. Run it with `msfconsole -q -r <file>`.
- **parameterized invocations of existing tools** — `impacket-GetNPUsers` /
  `GetUserSPNs` (with the domain + DC IP filled in), `ntlmrelayx` for an
  unsigned-SMB relay target, anonymous-FTP mirror, unauth-Redis write, … —
- a per-host **`<ip>.sh`** that chains the remote steps and lists the post-shell
  priv-esc steps (from the playbook) for reference.

It **selects and configures published exploits** against the specific hosts recce
found — **it authors no exploit code**; the exploit logic lives in the referenced
tool/module. It's gated to confirmed findings, and **safe by default**: the
Metasploit *launch* line in each `.rc` is commented out (only a non-intrusive
`check` runs) until you pass `--run`. Everything is to be used strictly within
your rules of engagement.

The same actions are surfaced in the workbook — the **Exploitation** sheet lists
every action (remote msf / remote tool / post-shell, each with the command,
prerequisite, and validation) — and in the Word write-ups, where a finding that
maps to a module gets a ready-to-run *Exploit with the published module* step.

**AV/EDR awareness (detection, not evasion).** When you `ingest` a `recce-enum.ps1`
run, recce records the host's AV/EDR product and defensive posture (Defender
real-time/tamper, EDR agents, Sysmon, LSASS `RunAsPPL`, AppLocker, Credential
Guard) and shows it where it matters: an **AV / EDR** column on the Checklist, a
**Defenses (host)** column on the Exploitation sheet next to each GodPotato/
PrintSpoofer/msf action, a count on the Overview, and a banner in the exploit-plan
scripts. The guidance is the legitimate one — coordinate a scoped testing
exclusion with the blue team (your tooling being caught is a finding *for the
defender*) or validate in a lab. recce flags what's watching a host; **it does not
evade AV/EDR** (the bundled scripts likewise do no AMSI/Defender tampering).

## Credentialed enumeration (`credenum`)

Once you have valid creds, `credenum` runs the *authenticated* checks nmap can't
do on its own. Everything is **optional and tool-gated** — recce shells out to
tools that already ship on Kali and skips (with a logged note) any that are
absent; no Python packages are needed at runtime:

```bash
recce credenum -u alice -p 'Passw0rd!' -d corp.local -o eng          # SMB/AD
recce credenum --ssh-user root --ssh-key id_rsa -o eng               # Linux
recce credenum -u alice -p 'Passw0rd!' -d corp.local --aggressive    # + secretsdump
```

- **netexec / nxc** (or crackmapexec) — authenticated **SMB**: shares & access,
  domain users, sessions, logged-on users, password policy, and crucially
  **local-admin access** (`Pwn3d!` → a high finding). A missing account-lockout
  threshold is flagged as spray-friendly.
- **impacket** — **Kerberoasting** (`GetUserSPNs`) and **AS-REP roasting**
  (`GetNPUsers`) with the actual `$krb5tgs$`/`$krb5asrep$` hashes; `--aggressive`
  adds **secretsdump** (SAM/LSA/NTDS NTLM hashes → a critical finding).
- **ssh** — Linux host-level checks (`id`, `sudo -l`, `uname`, SUID sweep);
  key auth or, for passwords, `sshpass` if present. Flags NOPASSWD sudo and
  unusual SUID binaries.

At the end of the phase `credenum` prints a per-host **authentication
success/fail table** (user account · privileged account · SSH), so you can see
at a glance which creds worked where and which rows to re-check.

Results fold into the normal model: accounts and shares land on **Users &
Accounts**, roasted accounts flow into **AD Quick Wins**, and access/loot/weak-
policy findings become **Vulnerabilities**. It targets each host by surface
(SMB hosts get netexec, DCs get roasting, SSH hosts get local checks), so one
`credenum` run covers a mixed environment. `recce doctor` shows which of these
tools are installed.

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
run it as you go. Both stay stdlib-only / airgap-safe. Full guide: **[INTEGRATION.md](INTEGRATION.md)**.

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

## Active Directory

AD analysis runs in two tiers.

**Tier 1 — credential-free (always on).** Purely from what nmap already collected,
the tool tags roles (**Domain Controller**, Global Catalog, WinRM, RDP, MSSQL…),
determines **SMB signing** posture, and harvests domain/NetBIOS/FQDN facts and
the **password policy** (from `smb-enum-domains`). It then derives target lists:

- **Domain Controllers** — your primary AD targets
- **NTLM relay targets** — hosts where *SMB signing is not required* (feed to `ntlmrelayx`)
- **SMBv1 / MS17-010** candidates

**Tier 2 — credentialed LDAP (`--ldap-enum`, needs `ldapsearch` (ldap-utils) or the `ldap3` package).** Binds to each
discovered DC and enumerates:

- **Users** with UAC flags → **AS-REP roastable** (`DONT_REQ_PREAUTH`) accounts
- **SPNs** → **Kerberoastable** service accounts (krbtgt excluded)
- **Unconstrained / constrained delegation** on users and computers
- **Computers** with OS/build
- **Privileged groups** and their members (Domain/Enterprise Admins, `adminCount=1`)
- **Domain trusts**, functional level, `ms-DS-MachineAccountQuota`, anonymous-bind check

```bash
# Credentialed LDAP enumeration of every discovered DC:
sudo python -m recce scan 10.0.10.0/24 --ldap-enum \
     --username jsmith --password 'P@ss' --domain corp.local

# Point LDAP at a specific DC (skip auto-detect); try anonymous bind:
python -m recce scan 10.0.10.0/24 --ldap-enum --ldap-anon --dc-ip 10.0.10.10

# Credentials are also passed to the SMB/LDAP NSE scripts during the scan so
# authenticated user/share/group enumeration succeeds:
sudo python -m recce scan 10.0.10.0/24 --username jsmith --password 'P@ss' --domain corp.local
```

Everything lands in the **Active Directory** and **AD Quick Wins** sheets (see
below), plus an enriched **Users & Accounts** sheet (roastable/delegation cells
are color-flagged).

**Tier 3 — offline BloodHound + Certipy import (`recce ad`).** Bring back a
**SharpHound** collection and/or a **`certipy find -json`** file and recce parses
the AD object graph offline (stdlib `json`/`zipfile` — no BloodHound/neo4j) into a
provable runbook:

- **AD misconfigurations / vulnerabilities** — Kerberoastable & AS-REP-roastable
  accounts, **DCSync** rights held off tier-0, unconstrained/constrained
  delegation, **RBCD**, **shadow-credential** (`AddKeyCredentialLink`) edges,
  dangerous ACLs from low-priv principals, passwords in descriptions,
  `PASSWD_NOTREQD`, non-zero `MachineAccountQuota`, and **ADCS ESC1–ESC15** from
  Certipy — each with the exact `impacket`/`certipy`/`bloodyAD` command to prove it.
- **Attack paths to Domain Admin** — the shortest path (BFS over the graph) from
  **your account** (or any authenticated user) to Domain Admins / the domain
  object / a DC, rendered as an edge chain with the abuse per hop.
- **Kerberos actions for effect** — roast, AS-REP, DCSync, delegation ticket
  forging, staged with your credential.
- **Live Kerberos capture (opt-in)** — with creds + `--dc-ip`, recce doesn't just
  *stage* the roast, it **runs** the published impacket tools to capture the real
  crackable material and folds each capture in as a **proven** finding:
  `--roast` (`GetUserSPNs -request` → live TGS-REP hashes), `--asrep`
  (`GetNPUsers -request` → AS-REP hashes), `--dcsync` (`secretsdump -just-dc` →
  replicated NTLM hashes incl. **krbtgt**). All three are read-only (request
  tickets / replicate secrets — nothing is modified). Captured hashes land in
  `eng/loot/` ready for `hashcat`; `--screenshots` saves terminal-output proof
  images.

Credentials-first and copy-paste-ready — give it `-u/-p/-d` (no NT hash needed)
and every generated command is pre-filled with your account. Findings feed the
main **Overview** totals, the **Vulnerabilities** sheet, and the write-ups, and
also populate the dedicated **AD Findings** and **AD Attack Paths** sheets.

```bash
# SharpHound + Certipy, credentialed — paths start from your account:
python -m recce ad loot.zip 20260101_Certipy.json \
     -u alice -p 'Passw0rd!' -d corp.local --dc-ip 10.0.10.10 -o eng

# Live capture: roast + AS-REP + DCSync the domain, with proof screenshots:
python -m recce ad loot.zip -u alice -p 'Passw0rd!' -d corp.local \
     --dc-ip 10.0.10.10 --roast --asrep --dcsync --screenshots -o eng

# Re-import after remediating some findings (drop the ones that are now fixed):
python -m recce ad loot.zip -u alice -p 'Passw0rd!' -d corp.local --replace-ad -o eng
```

## MSSQL (`recce mssql`)

Offensive Microsoft SQL Server enumeration modelled on PowerUpSQL / impacket-
mssqlclient / nxc mssql / **MSSQLPwner**:

- **Credential-free (airgapped, recce's own stdlib probes):** SQL Browser (UDP
  1434) instance/version/port enumeration and a **TDS pre-login** probe for the
  exact server version and whether login encryption is enforced — no creds, no
  tools. Plus the no-cred access checks (blank `sa`, anonymous, NTLM relay).
- **With credentials (auto-runs `nxc mssql` when installed):** the access +
  privilege matrix — which servers your creds log into and whether the login is
  effectively **sysadmin** (`Pwn3d!` = xp_cmdshell / RCE).
- **The MSSQLPwner route** (live impacket-mssqlclient enumeration + attack chain):
  recce connects and enumerates server roles, databases, **TRUSTWORTHY** DBs,
  **impersonatable logins**, `xp_cmdshell`/OLE/CLR status, `sys.sql_logins` hashes
  and saved credentials, then **detects the actual escalation chain on each
  instance** and **recursively walks the linked-server graph** (nested `EXEC(...)
  AT [link]`) to every instance reachable **as sysadmin** — each becomes a
  critical finding with the full nested `xp_cmdshell` RCE command. Chains:
  impersonation, TRUSTWORTHY+db_owner, linked-server hops, UNC→relay → **effect**
  (xp_cmdshell / sp_OACreate / CLR / Agent). MSSQL findings feed the main
  **Overview** totals and the write-ups, and populate a dedicated **MSSQL** sheet
  (endpoints, live enumeration, linked-server graph, findings, runbook, chain).

```bash
# No creds — pre-auth recon + the no-cred access commands:
python -m recce mssql -o eng

# Credentialed — access/priv matrix + the full attack chain, commands pre-filled:
python -m recce mssql -u alice -p 'Passw0rd!' -d corp.local --lhost 10.10.14.5 -o eng
python -m recce mssql -u sa -p 'Sql2019!' --local-auth -o eng     # SQL (not domain) auth
```

## SMB (`recce smb`)

Offensive SMB / file-sharing enumeration, in two layers:

- **Credential-free (airgapped, recce's own stdlib probes):** an **SMB2 NEGOTIATE**
  reveals the highest dialect and the **signing posture** — signing *required* vs
  merely *enabled* is the difference between "relay blocked" and the **NTLM-relay
  surface** — and a separate **SMBv1 NEGOTIATE** reveals whether the legacy SMBv1
  protocol is still answered (the **MS17-010 / EternalBlue** surface). Both are
  directly observed, no tools and no credentials.
- **With tools / credentials:** **null & guest** session share enumeration (via
  `nxc smb`), and a reversible **writable-share proof** (`--prove-write`: drop a
  marker file with `smbclient`, list it, delete it — nothing is left behind).

Findings feed the main **Overview** totals, the **Vulnerabilities** sheet and the
write-ups, and populate a dedicated **SMB** tab. The prove engine adjudicates the
observed states directly (signing-not-required and SMBv1-enabled → CONFIRMED;
signing-required → the relay finding is a FALSE POSITIVE).

```bash
# No creds — pre-auth posture (dialect/signing/SMBv1) + anonymous share enum:
python -m recce smb -o eng

# Credentialed — authenticated share enum + prove a writable share (reversible):
python -m recce smb -u alice -p 'Passw0rd!' -d corp.local --prove-write --screenshots -o eng
```

## FTP (`recce ftp`)

Offensive FTP enumeration:

- **Credential-free (airgapped, stdlib):** a control-channel probe reads the
  **banner** (→ product/version for the offline CVE DB and a narrow **known-backdoor
  map**: vsFTPd 2.3.4, ProFTPD 1.3.3c, ProFTPD mod_copy), tries an **anonymous**
  login, and inspects **FEAT** for AUTH TLS/FTPS — so it flags **cleartext**
  authentication.
- **With a session:** a reversible **writable-directory proof** (`--prove-write`:
  STOR a marker via stdlib `ftplib`, then DELE it — nothing left behind).

Findings feed the main totals, the Vulnerabilities sheet and the write-ups, and
populate a dedicated **FTP** tab. The prove engine confirms anonymous login (from
the observed 230) and flags the backdoor/RCE builds with the exact trigger.

```bash
# No creds — banner/anonymous/AUTH-TLS posture + known-backdoor match:
python -m recce ftp -o eng

# Prove a writable directory reversibly (anonymous or with creds):
python -m recce ftp --prove-write -o eng
python -m recce ftp -u bob -p 'hunter2' --prove-write -o eng
```

## Docker (`recce docker`)

An **unauthenticated Docker Engine API** (TCP 2375, or 2376 without mutual-TLS) is
remote **root** RCE on the host: anyone who can reach it can run a container that
bind-mounts the host root (`-v /:/host`) as root. recce reads the API
unauthenticated with **stdlib HTTP** (`/version`, `/info`, `/containers/json`,
`/images/json`) and, if it answers, reports a **CONFIRMED critical** exposure plus a
container/image-inventory info-leak — the successful unauthenticated read *is* the
proof; recce deliberately does **not** create a container. Findings feed the main
totals, the Vulnerabilities sheet and the write-ups, and populate a dedicated
**Docker** tab with the escape command.

```bash
python -m recce docker -o eng                 # read the API; CONFIRM exposure
python -m recce docker --screenshots -o eng   # + a `docker info` proof screenshot
```

## Kubernetes (`recce kubernetes` / `recce k8s`)

Stdlib-only unauthenticated reads of the cluster's most dangerous exposures:

- **kubelet** (10250): an anonymous-auth kubelet answers `/pods` and exposes
  `/exec` — **code execution inside any pod** on the node. The deprecated
  **read-only port** (10255, HTTP) leaks full pod specs (env-var secrets).
- **kube-apiserver** (6443/8443): whether `system:anonymous` can LIST namespaces —
  and, critically, **Secrets** (every service-account token and TLS key = cluster
  compromise). A 403 downgrades to an "anonymous-auth enabled" note.
- **etcd** (2379): an unauthenticated key read = every Secret in the clear.

Each successful read *is* the proof — recce only **reads** (it never execs into a
pod or writes to etcd). Findings feed the main totals, the Vulnerabilities sheet
and the write-ups, and populate a dedicated **Kubernetes** tab.

```bash
python -m recce k8s -o eng          # probe kubelet / apiserver / etcd, CONFIRM exposure
```

## SNMP (`recce snmp`)

A hand-rolled SNMP **v2c** client on a raw UDP socket (BER/ASN.1 with OID base-128
encoding and GETNEXT walking — no pysnmp), so it runs on a stock airgapped Kali. A
read-write community is flagged by *name* (private/write/manager/secret). Safety
posture: see [SECURITY.md](SECURITY.md).

- **Community guessing** — GET `sysDescr` with a list of common community strings
  (public/private/community/…); the first that answers is a readable community.
- **System group** — `sysDescr` / `sysName` identify the host pre-auth.
- **Walks** — the Windows **LanManager user table** (local accounts → a spray list),
  **running processes** and **installed software** (AV/EDR + unpatched builds), and
  interface descriptions.

Enumerated accounts become `Account` rows in **Users & Accounts**. Each read *is* the
proof — findings (guessable community, exposed users, process/software inventory) feed
the main totals, the Vulnerabilities sheet and the write-ups, populate a dedicated
**SNMP** tab, and are adjudicated **CONFIRMED** by the prove engine. SNMP discovery is
itself a GET, so no prior UDP scan is required — recce probes 161 directly.

```bash
python -m recce snmp -o eng          # guess the community, walk users/processes/software
python -m recce snmp --no-probe -o eng   # just write the commands (no live probe)
```

## MongoDB (`recce mongodb` / `recce mongo`)

A hand-rolled MongoDB **wire-protocol** client (OP_MSG opcode 2013 with a minimal
BSON encoder/decoder — no pymongo). Airgapped, stdlib only.

- **hello / buildInfo** — fingerprint the version and replica-set role.
- **`listDatabases` without authentication** — the discriminator. If the instance
  returns the database list, it is exposed unauthenticated (**full read/write to every
  database**) → a **critical** finding. If it errors "not authorized", auth is
  enforced and recce reports it reachable-but-locked (no finding). An end-of-life
  build raises a medium.

The successful unauthenticated `listDatabases` *is* the proof — findings feed the main
totals, the Vulnerabilities sheet and the write-ups, populate a dedicated **MongoDB**
tab, and are adjudicated **CONFIRMED** by the prove engine (with a `mongodump` next
step in the exploit plan).

```bash
python -m recce mongodb -o eng       # fingerprint + CONFIRM unauthenticated listDatabases
```

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

## Command & option reference

Every command takes targets as a single IP, several IPs, a range
(`10.0.0.10-40`), a CIDR, or `@file`. Common options (all scan phases):
`-o DIR` (engagement folder), `--title`, `--profile quick|standard|thorough`,
`--workers N`, `--refresh-every N`, `--host-timeout MIN`.

| Command | What it does | Notable options |
|---|---|---|
| `doctor` | Verify the box (env + tools + real localhost self-scan) | `--no-self-scan` |
| `demo` | Build reports from a bundled sample scan (no network) | — |
| `import <files>` | Import **existing** nmap scans (`-oX`/`-oG`/`-oN`, multiple files/dirs/globs, masscan XML) → workbook, no scanning | `--enum-only`, `--searchsploit` |
| `enum <targets>` | Discover hosts, port sweep, service/OS/AD enum → sheet | `--fast` (masscan), `--all-ports`, `--top-ports N`, `--no-discovery`, `--no-ad`, `--no-os`, `--version-all`, `--version-intensity 0-9`, `--min-rate`, `--exclude`, `--resume` |
| `vulns [targets]` | Vuln-scan open ports (safe detection + offline CVE/CWE DB + probes) | `--fast` (top-signal + progress/ETA), `--aggressive` (full NSE), `--only SVC`, `--unscanned`, `--offline`, `--no-searchsploit`, `--no-probes`, `--udp-top N` |
| `scan <targets>` | `enum` then `vulns` in one shot; `--deep` runs the whole credential-free mass surface (enum → vulns → every applicable deep module) in one kickoff | all of enum + vulns · `--deep` · `--skip MOD...` · `--only-modules MOD...` |
| `db [targets]` | Database enumeration + vuln scan | `--aggressive` (brute/xp_cmdshell/hash), `--no-searchsploit` |
| `privesc [targets]` | Per-host priv-esc playbook | `--scan` (remote NSE checks), `--aggressive` |
| `credenum [targets]` | Authenticated SMB/AD/SSH enum | `-u/-p/-d`, `--admin-user/--admin-pass/--admin-domain`, `--ssh-user/--ssh-pass/--ssh-key`, `--ldap-enum`, `--ldap-anon`, `--ldap-ssl`, `--dc-ip`, `--aggressive` |
| `ingest <loot>` | Fold on-target `recce-enum.sh`/`.ps1` findings into Priv-Esc, **or** `recce-service.sh` output into Vulnerabilities (auto-detected); also folds a `NET-*` topology block for the reachability/architecture maps | `--host IP` (else auto-resolved from the enum's interface IPs / hostname) |
| `writeups [targets]` | One Word write-up per **real** finding + combined report | `--include-potential`, `--min-severity`, `--no-screenshots`, `--no-combined`, `--overwrite` |
| `writeup <selector>` | **One** finding's write-up, pre-filled with looted/obtained evidence (F-id / CVE / IP / title; omit to list) | `--no-screenshots`, `--overwrite` |
| `services [targets]` | Print the per-service enum command (`recce/scripts/`) for every open port found | `-a` (append the intrusive flag) |
| `exploitplan [targets]` | Ready-to-run artifacts (msf `.rc` + tool commands) for **confirmed** findings, params pre-filled | `--lhost`, `--lport`, `--run` |
| `attackpath [targets]` | Chain confirmed findings into a staged attack path (foothold → priv-esc → creds → lateral → domain) | — |
| `creds [targets]` | Stack captured credentials + build a netexec/impacket spray plan | `--add`, `--user/--pass/--hash/--domain`, `--plan` |
| `report` | Rebuild the workbook/reports from the datastore | — |
| `status` | Print live coverage + suggested next command | — |
| `review` | Mark hosts/services/items reviewed from the CLI | `--host`, `--service IP:PORT`, `--key`, `--cascade`, `--note`, `--undo` |

Credentials passed to `enum`/`vulns` (`-u/-p/-d`) also feed the SMB/LDAP NSE
scripts during the scan. Run `recce <command> -h` for the full list.

**Environment:** `RECCE_DEBUG=1` (full tracebacks), `RECCE_BROWSER=/path`
(screenshot browser). **Exit codes:** `0` ok · `1` error · `2` bad args · `130`
interrupted (partial results saved).

## Troubleshooting

Run **`recce doctor`** first — it reports what's missing and self-tests the
pipeline. Most-common issues:

- **`nmap ... not found`** — install nmap (the only hard requirement).
- **weak scan / "Not running as root"** — run with `sudo`; under sudo use
  `sudo ./bin/recce ...` so PATH/PYTHONPATH survive.
- **discovery finds nothing** — a firewall is dropping pings; re-run with
  `--no-discovery` (`-Pn`).
- **too slow** — `--fast`, `--workers N`, `vulns --fast`, `--profile quick`,
  `--top-ports`, `--host-timeout`.
- **crashed / interrupted** — nothing is lost; re-run with `--resume`, or
  `recce report -o DIR`. `RECCE_DEBUG=1` for the traceback.
- **credenum auth table** — `FAIL` = credential rejected (check user/pass/**domain**);
  `ERR` = unreachable/tool error; `-` = not attempted (missing tool never shows FAIL).
- **workbook won't update** — close it in Excel first (an open file is locked).

**Re-running any phase is always safe** — every phase is idempotent and never
duplicates rows. Full guide: **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**.

## Layout

```
bin/recce            convenience wrapper (run: ./bin/recce ...)
pyproject.toml       packaging (pip install . -> `recce` command)
README.md            this file
QUICKSTART.md        one-page user guide
TROUBLESHOOTING.md   symptom -> cause -> fix, per phase
CHANGELOG.md         release notes
recce/               the package (python -m recce)
  cli.py             command-line interface (enum/vulns/db/privesc/... commands)
  targets.py         target parsing / subnet expansion / IP matcher
  scanner.py         nmap / masscan orchestration (discover / enum / vuln / nse)
  parser.py          nmap XML -> normalized model (+ vuln & AD harvesting)
  models.py          Host / Port / Vuln / Exploit / Account / Domain dataclasses
  store.py           SQLite datastore: hosts + domains + tracking, merge-on-rescan
  tracking.py        coverage + per-step keys, progress computation (shared)
  ad.py              AD analysis: roles, signing/relay, LDAP enumeration
  db.py              database detection + engine-specific NSE + inventory
  vulndb.py          offline version->CVE/CWE vulnerability engine (+ remediation)
  exploits.py        offline exploit mapping via searchsploit (Exploit-DB)
  exploitref.py      curated proven-exploit references (walkthroughs + sheet)
  probes.py          stdlib HTTP-header + TLS enrichment probes (airgapped)
  privesc.py         Windows/Linux priv-esc findings + playbook knowledge base
  credenum.py        credentialed enum via netexec / impacket / ssh (tool-gated)
  ingest.py          on-target loot -> Priv-Esc rows + promoted Vulnerabilities
  playbook.py        confirmed finding -> exact existing tool + command + validate
  exploitplan.py     confirmed finding -> runnable msf .rc / tool cmd (existing tools)
  attackpath.py      confirmed findings -> staged attack path (the "so what")
  credentials.py     stack captured creds -> netexec/impacket spray plan
  report_html.py     self-contained shareable HTML report (stdlib, no assets)
  serviceenum.py     open port -> per-service enum command (bridge to scripts/)
  screenshot.py      optional headless-browser web screenshots (tool-gated)
  xlsx.py            standard-library .xlsx writer/reader (no openpyxl)
  docx.py            standard-library .docx writer (no python-docx) + image embed
  report_excel.py    the Excel workbook (Start Here, Runbook, Overview, ...)
  report_docx.py     per-finding Word write-ups from the walkthrough template
  report_markdown.py Markdown + CSV
  sample_scan.xml    bundled sample for `demo`
  local/             on-target read-only enum scripts (recce-enum.sh / .ps1)
```
