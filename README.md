# recce

Pentest enumeration, vulnerability triage, and reporting — designed for airgapped engagements.

`recce` orchestrates nmap across hosts and subnets, normalizes everything into a resumable SQLite datastore, and produces a tracking-ready Excel workbook, HTML report, network diagrams, and per-finding DOCX write-ups.

## Capabilities

- **Scan & enumerate** — TCP/UDP sweeps, service/version/OS detection, deep NSE across many subnets
- **Vulnerability identification** — offline version-to-CVE/CWE engine, HTTP/TLS probes, web content discovery, CISA KEV + EPSS prioritization
- **Deep service modules** — native per-service scanners (databases, web, SMB, FTP, Docker, Kubernetes, SNMP, LDAP, and more) with credentialed follow-through, data exfiltration proof, and RCE validation
- **Active Directory** — DC identification, NTLM relay targets, LDAP enumeration, BloodHound + Certipy import with shortest-path-to-DA mapping
- **Exploit plans & attack paths** — Metasploit `.rc` files, tool commands, and a prioritized kill-chain grounded in confirmed findings
- **Shell sessions** — built-in reverse-shell listener with browser terminals, PTY upgrade, persistence tracking, and team-shared session management
- **Web workbench** — `recce serve` hosts the engagement as a shared browser UI with live scan control, findings triage, credential spray, and team coordination
- **Reporting** — Excel workbook with persistent review tracking, HTML, Markdown, CSV, network maps, DOCX write-ups

## Install

**No pip install required.** Stdlib-only Python (3.9+) — copy the folder and run:

```bash
./bin/recce doctor       # check the box
```

Only `nmap` is required. Optional tools (`masscan`, `searchsploit`, `netexec`, `impacket`, `ldapsearch`, `ssh`/`sshpass`, `firefox`/`chromium`) are used when present, with clean degradation when absent. `recce doctor` reports what's available.

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
./bin/recce status -o eng                     # what's left
```

Open `eng/enumeration.xlsx` and work the Checklist tab. Full walkthrough in [QUICKSTART.md](QUICKSTART.md).

## Documentation

| Doc | What it covers |
| --- | --- |
| [QUICKSTART.md](QUICKSTART.md) | Zero to a filled-in workbook in five commands |
| [CHEATSHEET.html](CHEATSHEET.html) | Printable one-page field reference |
| [docs/](docs/README.md) | Full reference: commands, phases, services, design |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Symptom, cause, fix — per phase |
| [INTEGRATION.md](INTEGRATION.md) | Fieldkit round-trip (recce ranks, fieldkit proves past the trigger, findings fold back) |

## Layout

```
bin/recce               launcher
recce/
  cli/                  command dispatch + per-phase modules
  core/                 models, datastore, scanner engine, targets
  vuln/                 offline CVE/CWE engine, KEV/EPSS, verify
  services/             per-service scanners (db/, web/, smb, ftp, ldap, ...)
  ad/                   Active Directory (BloodHound, Kerberos, LDAP/NTLM)
  act/                  exploit plan + attack-path synthesis
  sessions/             reverse-shell listener, session manager
  intake/               parsers for external tool output
  report/               Excel, HTML, Markdown, CSV, DOCX, network maps
  creds/                credential store, spray engine
  webui/                web workbench (FastAPI + React)
  data/                 bundled wordlists
  local/                on-target enum scripts (recce-enum.sh/.ps1)
tools/                  build scripts (airgap bundle, wordlists, intel refresh)
docs/                   reference + design notes
tests/                  test suite            (repo only)
test_env/               docker lab            (repo only)
```

`repo only` = development artifacts. They stay here, where CI runs them, and
are left out of the airgap burn package built by `make_package.sh`.

---

Licensed under the [MIT License](LICENSE).
