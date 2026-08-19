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

## Documentation

New here, start at the top and work down:

| Doc | What it covers |
| --- | --- |
| **[QUICKSTART.md](QUICKSTART.md)** | **Start here** — zero to a filled-in workbook in five commands |
| [CHEATSHEET.html](CHEATSHEET.html) | Printable one-page field reference (open in a browser) |
| [docs/](docs/README.md) | The full reference: per-phase deep dives, the command reference, and design notes |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Symptom → cause → fix, per phase |
| [SECURITY.md](SECURITY.md) | Safety model, authorized-use, and the opt-in intrusive actions |
| [INTEGRATION.md](INTEGRATION.md) | The fieldkit round-trip (enumerate here, exploit there, fold findings back) |

Every workbook also has a **Start Here** tab explaining each sheet, and a
**Runbook** tab with the exact command for each phase.

## Why this over raw nmap / AutoRecon?

Existing tools scan well but leave you with per-host output files. `recce`
adds the layer engagements actually need:

- **Cross-host, checkable deliverable.** Every host, service, vuln and account
  lands in one filterable workbook with `Reviewed`/`Checked`/`Triaged` checkbox
  columns so you can track what's been looked at.
- **Persistent coverage tracking.** Your checkboxes live in the datastore, not
  just the spreadsheet — re-scanning and re-reporting **never wipe your
  progress**. An **Overview** sheet and a `status` command show exactly what's
  left, at any time (see [Coverage tracking](docs/reference/workflow.md#coverage-tracking)).
- **"Who else runs this?" pivot.** A *Services by Product/Version* sheet groups
  every endpoint by exact product+version — instantly see all systems running
  the same vulnerable service.
- **Built for a tight clock.** Host-level **concurrency** and a **masscan
  fast-path** collapse hours of sequential `-p-` scans; reports refresh
  incrementally so you can start reviewing while the scan is still running (see
  [Speed](docs/reference/workflow.md#speed)).
- **Resumable across long, multi-subnet scans.** Results are stored in SQLite and
  merged on re-run; interrupt and `--resume` any time.

## What recce does

One command set takes you from a scope list to a client-ready report. Each phase
is separate, resumable, and safe-by-default; follow the links for the full detail.

- **Scan & enumerate** — full TCP sweeps, service/version + OS detection, and a
  deep service-aware NSE set across many subnets, normalized into a resumable
  SQLite datastore. → [workflow](docs/reference/workflow.md)
- **Identify vulnerabilities (airgapped)** — a curated detection NSE set, an
  offline version→CVE/CWE engine, stdlib HTTP/TLS probes, and searchsploit
  mapping — ranked **fix-first** with CISA KEV + EPSS. → [scanning](docs/reference/scanning.md)
- **Deep per-service modules** — databases, SMB, FTP, Docker, Kubernetes, SNMP,
  MongoDB and MSSQL, each self-proving and airgapped. Run one, or all at once with
  `recce sweep`. → [services](docs/reference/services.md)
- **Active Directory** — DC identification, NTLM-relay targets, credentialed LDAP
  enumeration, and offline **BloodHound + Certipy** import that maps the shortest
  paths to Domain Admin. → [active-directory](docs/reference/active-directory.md)
- **Privilege escalation & exploitation** — a per-host playbook, on-target
  read-only enum you fold back in with `ingest`, and runnable msf/tool artifacts
  for **confirmed** findings. → [privesc](docs/reference/privesc.md)
- **Track & report** — one filterable **Excel workbook** with persistent
  `Reviewed`/`Checked` columns, self-contained HTML reports, network diagrams, and
  per-finding Word write-ups. → [reporting](docs/reference/reporting.md)
- **Drive it from a browser** — `recce serve` hosts the whole engagement as a web
  workbench the team shares over the LAN (see below).

Full **[command & option reference](docs/reference/commands.md)**.

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

### Build a package to carry it over (transfer / airgap)

Build **once on a connected box**, copy the artifact to the target, run it offline.
There are two packages — pick by what the *target* already has:

| Package | Build with | Target needs | Size |
| --- | --- | --- | --- |
| **Source burn package** | `./make_package.sh` | Python 3.9+ and `nmap` | ~1 MB |
| **Self-contained airgap bundle** | `./tools/build_bundle.sh` | **nothing** — no Python, pip, or nmap | ~45 MB |

```bash
# Target already a stock Kali? The tiny source package is enough:
./make_package.sh                     # -> dist/recce-<version>.tar.gz (+ .zip) + SHA256SUMS
#   on the target:
tar xzf recce-<version>.tar.gz && cd recce-<version> && ./bin/recce doctor

# Truly dark box (or you want one artifact that just runs)? Freeze everything:
./tools/build_bundle.sh               # -> dist/recce-airgap-<version>/  (+ .tar.gz)
#   on the target — nothing to install:
tar xzf recce-airgap-<version>.tar.gz && cd recce-airgap-<version> && ./recce doctor
```

The **airgap bundle** freezes the Python runtime + every dependency (impacket,
ldap3, openpyxl, fastapi/uvicorn — so `recce serve` works too) with PyInstaller,
and ships nmap + masscan + ldapsearch as bundled binaries. It builds offline
(reusing on-box deps when PyPI is unreachable), carries a `MANIFEST.txt` of exactly
what's inside, and takes opt-in flags for the heavy extras (`RECCE_WITH_SEARCHSPLOIT=1`
for the 292 MB exploit-db, `RECCE_WITH_SMBCLIENT=1`).

**Full detail, flags and what's in/out: [docs/reference/packaging.md](docs/reference/packaging.md).**

## Web workbench (`recce serve`)

Drive the whole engagement from a browser — no terminal needed, and the whole team
shares one view. One recce instance hosts it; everyone opens the URL over the LAN.

```bash
recce serve -o acme                 # -> http://<this-box>:8008  (share on the LAN)
recce serve -o acme --port 9000     # pick the port; --host to change the bind address
```

It serves the **same datastore** the CLI writes, so terminal and browser stay in
sync. Run `enum`/`vulns`/`run` from the UI with live progress, work the
**Dashboard** (with a *Next moves* panel), **Hosts**, **Findings** (tiered by
confidence), **Act** (ranked action cards + attack-path graph) and **Loot**
(captured creds + a lockout-safe spray) tabs, and export the report in one click.

The web UI needs `fastapi` + `uvicorn` — both are **bundled in the airgap package**.
For a dev install: `pip install 'recce[bundle]'`.

## First run

```bash
./bin/recce doctor                                   # confirm the box can run it
sudo ./bin/recce enum 10.0.10.0/24 -o eng            # ① discover hosts/ports/services
sudo ./bin/recce vulns -o eng                        # ② vuln-scan the open ports (safe)
./bin/recce sweep -o eng                             # ③ deep pass — every applicable module
./bin/recce status -o eng                            # what's left + the next command
```

Open `eng/enumeration.xlsx` and work the **Checklist** tab. Keep `-o eng`
identical across every command — it's the one engagement folder they all share.
The full walkthrough (import, credentialed phases, AD, reporting) is in
**[QUICKSTART.md](QUICKSTART.md)**; the per-phase detail is in **[docs/](docs/README.md)**.

## Layout

```
bin/recce            convenience wrapper (run: ./bin/recce ...)
pyproject.toml       packaging (pip install . -> `recce` command)
README.md            this file — what recce is, install, big picture
QUICKSTART.md        one-page user guide
TROUBLESHOOTING.md   symptom -> cause -> fix, per phase
CHANGELOG.md         release notes
recce/               the package (python -m recce) — see docs/reference/ for the phases
  cli.py             command-line interface (all subcommands)
  scanner.py         nmap / masscan orchestration
  parser.py          nmap XML -> normalized model
  store.py           SQLite datastore (merge-on-rescan, resume)
  vulndb.py          offline version->CVE/CWE engine
  report_excel.py    the Excel workbook  ·  report_html.py  self-contained HTML report
  webui/             the web workbench (`recce serve`)
  local/             on-target read-only enum scripts (recce-enum.sh / .ps1)
  scripts/           per-service enumeration commands
docs/                full reference + design notes (see docs/README.md)
tools/build_bundle.sh  freeze a self-contained binary (+ web UI); offline-capable
```

---

> ⚖️ **Authorized use only.** recce is for security work you have written
> permission to perform. Its safety controls, the opt-in/flag-gated intrusive
> actions, and your responsibilities as an operator are documented in
> **[SECURITY.md](SECURITY.md)** — read it before your first engagement.

Licensed under the [MIT License](LICENSE).
