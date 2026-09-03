# Quick Start

Point recce at IPs/subnets, it scans with nmap, fills an Excel workbook, and tracks your progress across re-runs. Or drive the whole engagement from a browser via `recce serve`.

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
                              ↑
                       recce serve — driven from a browser
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

Or run individual services: `web`, `smb`, `ftp`, `ldap`, `snmp`, `mongodb`, `redis`, `mssql`, `docker`, `k8s`, `s7`, `opcua`, `bacnet`, `dnp3`, etc.

### 4. Open the web workbench

```bash
./bin/recce serve -o eng --port 8443    # http://<box>:8443
```

Multiple testers open the same URL. The workbench has 11 top-level tabs — the ones you'll live in:

- **Attack** — AD / Cloud / Web attack chains rendered as step timelines with DAG maps; click a step to see contributing hosts + paste-ready next-step
- **Suggest** (Attack > Suggest) — ranked next-move digest from 18 cross-service chain rules ("LDAP anon-read + AS-REP roastable → run kerbrute then GetNPUsers")
- **Sessions** — reverse shells with in-browser xterm, PTY upgrade, SOCKS pivots, port-forwards
- **Findings** — filter/triage; status dropdown drives what lands in the deliverable
- **Creds** — captured credentials with scope (🏠 local / 🌐 domain) + spray + paste-to-loot
- **Scan** — every CLI command in one two-pane workbench

Full tour: [docs/reference/webui.md](docs/reference/webui.md).

### 5. Post-exploitation

```bash
# On target: run bundled read-only enum, bring output back
./bin/recce ingest loot.txt -o eng

# Or push enum to every host you have creds for
./bin/recce deploy -u admin -p 'Pw!' -d corp.local -o eng

# Generate artifacts
./bin/recce act              -o eng --run  # run the auto-safe half of the plan
./bin/recce attackpath       -o eng        # kill-chain synthesis
./bin/recce exploitplan      -o eng --lhost 10.10.14.7   # msf .rc files
./bin/recce prove            -o eng --run  # T2 proof; promotes findings to CONFIRMED
```

### 6. Report

```bash
./bin/recce writeups -o eng     # Word write-up per finding
./bin/recce status   -o eng     # progress + next command
```

Repeat until `status` says done. Or click **Report → Generate** in the workbench.

## Command reference

Every command takes `-o <dir>`. Full catalog: [docs/reference/commands.md](docs/reference/commands.md).

| Command | What it does |
|---|---|
| `enum <targets>` | discover hosts/ports/services |
| `import <file>` | build from existing nmap/tool output |
| `vulns` | NSE + offline CVE/CWE + TLS/HTTP probes |
| `scan <targets>` | enum + vulns in one shot |
| `sweep` | all unauth deep modules |
| `credsweep -u -p -d` | all auth modules |
| `ad loot.zip certipy.json -u -p -d` | BloodHound + Certipy import, paths to DA |
| `credenum -u -p -d` | credentialed SMB/AD/SSH enum |
| `privesc` | per-host escalation playbook |
| `deploy -u -p` | push local-enum to every reachable host |
| `act [--run]` | ranked action plan; `--run` executes the safe / reversible half |
| `prove [--run]` | verdict engine — promotes findings to CONFIRMED on real proof |
| `exploitplan --lhost <ip>` | runnable msf `.rc` + tool commands |
| `attackpath` | foothold to domain compromise chain |
| `poc` | per-CVE dossier + harness scaffold |
| `suggest` | print the ranked next-moves digest (no scan) |
| `creds --add 'dom\u:p'` | manage creds; `--plan` for spray plan |
| `writeups` | per-finding Word docs |
| `bloodhound-push` | write BloodHound-compat JSON for overlay onto an existing BH instance |
| `status` | what's left + next command |
| `serve` | web workbench at `http://<box>:8443` |
| `doctor` | self-check |

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
| `session-loot/adcs/*.pfx` | ESC1 certificates after the web-workbench flow |

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
| ESC1 button greyed out | Install certipy: `pip install certipy-ad` |

Re-running any command is safe — never duplicates or loses progress. Full guide: [TROUBLESHOOTING.md](TROUBLESHOOTING.md).
