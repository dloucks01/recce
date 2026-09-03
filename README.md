# recce

Pentest enumeration, vulnerability triage, exploitation, and reporting — designed for airgapped engagements.

`recce` scans networks, normalises everything into a resumable SQLite datastore, feeds a shared browser workbench, and produces a tracking-ready Excel workbook, HTML report, network diagrams, and per-finding DOCX write-ups. Stdlib-only at runtime — no pip install required.

## What it does

- **Discover & enumerate** — TCP/UDP sweeps, service/version/OS detection, deep NSE across many subnets
- **Prove vulnerabilities** — offline version-to-CVE engine + live probes with server-side evidence + CISA KEV & EPSS prioritisation, then a **verdict engine** (`recce prove`) that promotes findings to `confirmed` on real proof
- **Deep service modules** — native per-service scanners for databases, web, SMB, FTP, Docker, Kubernetes, SNMP, LDAP, and OT/ICS (S7, BACnet, DNP3, ENIP, IEC 104, OPC UA)
- **Active Directory** — DC identification, LDAP enum, BloodHound + Certipy import with shortest-path-to-DA, live Kerberoasting, **ADCS ESC1 auto-request** (strictly gated)
- **Attack chains** — AD, Cloud, and Web narratives rendered as a step-by-step chain from proven evidence, with a DAG view + click-to-jump navigation
- **Cross-service intelligence** — 18 chain-correlation rules surface next moves like "LDAP anon-read + AS-REP roastable → run kerbrute → GetNPUsers → hashcat"; T3-capable findings auto-surface with their next-step command
- **Shell sessions** — built-in reverse-shell listener, browser terminals, PTY upgrade, SOCKS pivots, port-forwards, persistence tracking, team-shared session driver
- **Auto-crack loop** — hashcat potfiles polled continuously; cracks fold back into the credential store as sprayable password credentials
- **Web workbench** — `recce serve` hosts the whole engagement as a shared browser UI with live scan control, findings triage, credential spray, attack-chain navigation, and team coordination
- **Reporting** — Excel with persistent review tracking, HTML, Markdown, CSV, network maps, DOCX write-ups, and a fieldkit round-trip for the past-the-trigger half

## Install

**No pip install required.** Stdlib-only Python (3.9+) — copy the folder and run:

```bash
./bin/recce doctor       # check the box
```

Only `nmap` is required. Optional tools (`masscan`, `searchsploit`, `netexec`, `impacket`, `ldapsearch`, `ssh`/`sshpass`, `certipy`, `hashcat`, `firefox`/`chromium`) are used when present, with clean degradation when absent. `recce doctor` reports what's available.

### Airgap transfer

| Package | Build | Target needs | Size |
| --- | --- | --- | --- |
| Source | `./make_package.sh` | Python 3.9+ and nmap | ~1 MB |
| Self-contained bundle | `./tools/build_bundle.sh` | Nothing | ~45 MB |

The bundle freezes the Python runtime, dependencies, nmap, masscan, and ldapsearch into one artifact. See [packaging.md](docs/reference/packaging.md).

## Quick start

```bash
sudo ./bin/recce enum 10.0.10.0/24 -o eng    # discover hosts/ports/services
sudo ./bin/recce vulns -o eng                 # vuln-scan open ports
./bin/recce sweep -o eng                      # deep pass — every applicable module
./bin/recce serve -o eng                      # open the web workbench (default :8008)
```

Open `eng/enumeration.xlsx` or point a browser at `http://<box>:8008`. Full walkthrough in [QUICKSTART.md](QUICKSTART.md).

## Documentation

| Doc | What it covers |
| --- | --- |
| [QUICKSTART.md](QUICKSTART.md) | Zero to a filled-in workbook in five commands |
| [docs/reference/webui.md](docs/reference/webui.md) | Web workbench: tabs, attack chains, sessions, ESC1 |
| [docs/](docs/README.md) | Full reference: commands, phases, services, AD, packaging |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Symptom → cause → fix, per phase |
| [INTEGRATION.md](INTEGRATION.md) | Fieldkit round-trip (recce ranks, fieldkit proves past the trigger) |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Layout

```
bin/recce               launcher
recce/
  cli/                  command dispatch + per-phase modules
  core/                 models, datastore, scanner engine, targets, shared surfaces
  vuln/                 offline CVE/CWE engine, KEV/EPSS, verify
  services/             per-service scanners (db/, web/, smb, ftp, ldap, s7, opcua, ...)
  ad/                   Active Directory (BloodHound, Kerberos, LDAP/NTLM, ADCS ESC1)
  act/                  ranked action plan + attack-path synthesis + verdict engine
  sessions/             reverse-shell listener, session manager, tunnels, port-forwards
  intake/               parsers for external tool output
  report/               Excel, HTML, Markdown, CSV, DOCX, network maps
  creds/                credential store, spray engine, crack watcher
  webui/                web workbench (FastAPI + React) — routes/ per concern
  data/                 bundled wordlists
  local/                on-target enum scripts (recce-enum.sh/.ps1)
tools/                  build scripts (airgap bundle, wordlists, intel refresh)
docs/                   user reference
tests/                  test suite            (repo only)
test_env/               docker lab            (repo only)
.recce-plan/            internal planning + design ADRs (repo only)
```

`repo only` = development artifacts. They stay here, where CI runs them, and are left out of the airgap burn package built by `make_package.sh`.

---

Licensed under the [MIT License](LICENSE).
