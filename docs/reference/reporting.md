# Reporting, write-ups & output files

## Finding write-ups (`writeups`)

`recce writeups -o eng` generates one Word `.docx` per finding, grouped by title across hosts. Real findings only by default; `--include-potential` adds version-inferred guesses.

`recce writeup <selector>` writes up a single finding (by F-id, CVE, IP, or title keyword), pre-filled with looted/obtained evidence.

Auto-filled: title, affected systems, severity, CWE/CVE, tools, recommendations, narrative draft, evidence, walkthrough steps. Tester placeholders: mission risk/impact, difficulty, screenshots. recce never overwrites an edited write-up.

**Combined report:** `writeups/findings_report.docx` — severity summary table, findings table, and every finding as a section.

**Screenshots:** if Firefox/Chromium is present, HTTP/HTTPS targets are screenshotted and embedded. `--no-screenshots` disables.

The writer is pure stdlib (a `.docx` is a zip of XML) — runs airgapped.

## Fieldkit integration

```bash
recce fieldkit-export -o eng                    # -> eng/fieldkit/
recce fieldkit-import recce_findings.json -o eng # proven findings back in
```

See [INTEGRATION.md](../../INTEGRATION.md).

## Output files (`<output-dir>/`)

| File | Contents |
|------|----------|
| `enumeration.xlsx` | Start Here, Runbook, Overview, Checklist, Services, Web, Vulnerabilities, Exploits, Verification, Services by Product/Version, Databases, AD, AD Quick Wins, AD Findings, AD Attack Paths, Users & Accounts, MSSQL, SMB, FTP, Docker, Kubernetes, LDAP, SNMP, MongoDB, Priv-Esc, Exploitation |
| `enumeration.md` | Summary + per-host checklist |
| `services.csv` | Flat services table |
| `report.html` | Self-contained HTML report (exec summary, findings, attack path, hosts) |
| `assets.html` | Architecture & assets companion (network map, AD diagram, users/creds) |
| `network-*.svg` | Network diagrams: architecture, full map, overview, tiered, reachability |
| `attack-path.svg` | Staged attack path |
| `writeups/*.docx` | Per-finding write-ups + combined report |
| `exploit-plan/*` | msf `.rc` + per-host plans |
| `creds/*.txt` | users/passwords/nthashes for spray |
| `results.sqlite` | Normalized datastore (resume + re-report) |
| `raw/*.xml` | Raw nmap XML |
| `recce.log` | Scan errors / timeouts |


