# Quick Start

Point recce at IPs/subnets, it scans with nmap, fills an Excel workbook, and tracks your progress across re-runs.

## Prerequisites

- Kali (or Linux with Python 3.9+ and `nmap`)
- Written authorization for the target scope

```bash
./bin/recce doctor    # confirms the box can run it
```

> **Airgapped?** `./make_package.sh` builds a ~1 MB source tarball (needs Python + nmap on target). `./tools/build_bundle.sh` builds a ~45 MB self-contained bundle (needs nothing). See [packaging.md](docs/reference/packaging.md).

## Workflow

```
 enum → vulns → sweep → (foothold) → ingest/creds → report
```

Keep **`-o eng`** identical across every command — it's the one engagement folder.

### 1. Enumerate

```bash
sudo ./bin/recce enum 10.0.10.0/24 10.0.20.0/24 -o eng --title "Client X"
```

Or import existing nmap output: `./bin/recce import scan.xml -o eng`

> Hosts showing zero ports? Add **`-Pn`** (skip ping). Still nothing? Add **`--reliable`** (slower, avoids rate-limit drops).

### 2. Vuln-scan

```bash
sudo ./bin/recce vulns -o eng
```

Safe by default — looks, doesn't attack. Add `--fast` for speed, `--only http smb` to focus.

### 3. Deep pass

```bash
./bin/recce sweep -o eng                                          # all unauth modules
./bin/recce credsweep -u alice -p 'Passw0rd!' -d corp.local -o eng  # all auth modules
```

Or run individual services: `web`, `smb`, `ftp`, `ldap`, `snmp`, `mongodb`, `redis`, `mssql`, `docker`, `k8s`, etc.

### 4. Post-exploitation

```bash
# On target: run bundled read-only enum, bring output back
./bin/recce ingest loot.txt -o eng

# Or push enum to every host you have creds for
./bin/recce deploy -u admin -p 'Pw!' -d corp.local -o eng

# Generate artifacts
./bin/recce exploitplan -o eng --lhost 10.10.14.7   # msf .rc files
./bin/recce attackpath  -o eng                       # kill-chain synthesis
./bin/recce poc         -o eng                       # per-CVE dossiers
```

### 5. Report

```bash
./bin/recce writeups -o eng     # Word write-up per finding
./bin/recce status   -o eng     # progress + next command
```

Repeat until `status` says done.

## Command reference

| Command | What it does |
|---|---|
| `enum <targets>` | discover hosts/ports/services |
| `import <file>` | build from existing nmap/tool output |
| `vulns` | NSE + offline CVE/CWE + TLS/HTTP probes |
| `scan --deep <targets>` | enum + vulns + all deep modules in one shot |
| `sweep` | all unauth deep modules |
| `credsweep -u -p -d` | all auth modules |
| `services` | print per-port enum commands |
| `db` | database services |
| `ad loot.zip certipy.json -u -p -d` | BloodHound + Certipy import, paths to DA |
| `credenum -u -p -d` | credentialed SMB/AD/SSH enum |
| `privesc` | per-host escalation playbook |
| `deploy -u -p` | push local-enum to every reachable host |
| `exploitplan --lhost <ip>` | runnable msf `.rc` + tool commands |
| `attackpath` | foothold to domain compromise chain |
| `poc` | per-CVE dossier + harness scaffold |
| `creds --add 'dom\u:p'` | manage creds; `--plan` for spray plan |
| `writeups` | per-finding Word docs |
| `access` | footholds per host |
| `status` | what's left + next command |
| `serve` | web workbench at `http://<box>:8008` |
| `doctor` | self-check |

All commands take `-o <dir>` for the engagement folder.

## Targeting

| Format | Example |
|---|---|
| Single host | `10.0.10.5` |
| Multiple | `10.0.10.5 10.0.10.9` |
| Range | `10.0.10.10-40` |
| Subnet | `10.0.10.0/24` |
| File | `@scope.txt` |

## Workbook tabs

- **Start Here** — explains every tab
- **Checklist** — one row per IP; auto-boxes (Enumerated, Vuln-scan, Web, DB, Access, Priv-esc) turn green when done; manual sign-offs (AD, Creds, Lateral, Reviewed) you tick yourself
- **Services** — one row per open port with status + notes
- **Overview** — per-subnet completion

## Deliverables (in `eng/`)

| File | Purpose |
|---|---|
| `enumeration.xlsx` | tracking workbook |
| `report.html` | client-ready findings report |
| `assets.html` | architecture, network maps, AD diagram, credentials |
| `network-architecture.svg` | headline network diagram |
| `attack-path.svg` | projected attack path |
| `enumeration.md` / `services.csv` | notes-friendly + flat data |
| `writeups/*.docx` | per-finding Word write-ups |
| `exploit-plan/*` | runnable msf `.rc` files |
| `creds/*.txt` | user/password/hash lists for spraying |

## Troubleshooting

Run `recce doctor` first.

| Symptom | Fix |
|---|---|
| `nmap not found` | `sudo apt install nmap` |
| Weak scan / "not root" | Run with `sudo` |
| Zero ports | Add `-Pn`; if still nothing, add `--reliable` |
| Too slow | `--fast`, `--workers N`, `--profile quick` |
| Crashed / interrupted | Re-run with `--resume`; `RECCE_DEBUG=1` for traceback |
| No findings | `--version-all` then `vulns --aggressive` |
| Workbook won't update | Close it in Excel first |

Re-running any command is safe — never duplicates or loses progress.
