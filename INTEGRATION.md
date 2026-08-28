# recce + fieldkit integration

recce handles enumeration and reporting; [fieldkit](https://github.com/dloucks01/fieldkit) handles exploitation. They round-trip offline:

```
recce enum/vulns ──fieldkit-export──> fieldkit sweep + generators ──findings.json──> gen_report
       ^                                                                            |
       └──────────── recce fieldkit-import <── gen_report.py --export-recce ─────────┘
```

| Command | Direction | What it does |
|---|---|---|
| `recce fieldkit-export -o eng` | recce -> fieldkit | Writes `eng/fieldkit/` — a ready attack plan fieldkit consumes |
| `recce fieldkit-import <file> -o eng` | fieldkit -> recce | Folds proven findings back into the workbook + report |

## recce -> fieldkit

```bash
recce fieldkit-export -o eng
```

Produces:
- **`FIELDKIT.md`** — severity-ranked plan: per host, the port-to-generator route, confirmed findings, and ready-to-paste generator commands (version-to-CVE, credential-to-shell, spray)
- **`recce-bridge.json`** — machine-readable feed for `sweep.py triage --recce recce-bridge.json`
- **`users.txt`** / **`creds.txt`** — enumerated usernames and captured credentials
- **`ports.gnmap`** / **`smb-null.txt`** — nmap-greppable + netexec handoff for the classic `sweep.py triage` path

## fieldkit -> recce

```bash
# In the fieldkit checkout:
python3 report/gen_report.py findings.json --export-recce   # -> recce_findings.json

# Fold into engagement:
recce fieldkit-import recce_findings.json -o eng
```

Each proven finding becomes a confirmed vulnerability (source `fieldkit`) in the Vulnerabilities sheet, report, and DOCX write-ups. The host is marked access-gained. Re-importing is idempotent. Raw `findings.json` (without `--export-recce`) also works — the enriched export adds CWE/remediation from fieldkit's knowledge base.

## Host topology

fieldkit's on-target enum scripts emit a `NETWORK` block (interfaces, routes, ARP, live peers). Fold it in:

```bash
recce ingest enum-output.txt -o eng       # host auto-resolved from interface IPs; --host <ip> to force
```

This draws a ground-truth reachability map (`network-reachability.svg`) showing observed host-to-host links and dual-homed pivots.
