# recce ⇄ fieldkit

recce and [**fieldkit**](https://github.com/dloucks01/fieldkit) split one engagement at the
trigger. **recce** is the survey-plan-catch-report platform: it sweeps the network, confirms
and prioritizes vulnerabilities (KEV/EPSS), synthesizes attack paths, catches and holds shells
(C2, SOCKS pivots), and writes the customer report — and by design it stops at the trigger, its
on-target work read-only and non-evasive. **fieldkit** is the half past the trigger: the
autonomous operator that walks recce's ranked plan, fires each move, mutates target state to
**prove** the compromise, prices every step in detection risk, and folds the proven findings
back. They round-trip through a small JSON contract.

```
recce (survey · confirm · rank · catch)  ──scope + ranked findings──▶  fieldkit
        ▲                                              (spray → escalate → prove, detection-priced)
        └────────  recce fieldkit-import  ◀── fieldkit export-recce ──┘
                    (proven findings, KB-enriched, confidence: confirmed)
```

| Command | Direction | What it does |
|---|---|---|
| `recce fieldkit-export -o eng` | recce → fieldkit | Writes `eng/fieldkit/` — scope + ranked findings fieldkit consumes |
| `recce fieldkit-import <file> -o eng` | fieldkit → recce | Folds proven findings back into the workbook + report |

## recce → fieldkit

```bash
recce fieldkit-export -o eng
```

Produces (in `eng/fieldkit/`):

- **`FIELDKIT.md`** — severity-ranked plan: per host, the port-to-generator route, confirmed
  findings, and ready-to-paste commands.
- **`recce-bridge.json`** — machine-readable rich feed: per-host ports/service/version,
  recce's *confirmed* findings, the exact fieldkit generator to run, severity-ranked. This is
  what fieldkit ingests into its exploitability axis so ranking becomes a proper computation
  instead of a heuristic — recce is not handing off "guesses" for fieldkit to re-prove, it's
  handing off a prioritized work-queue.
- **`users.txt`** / **`creds.txt`** — enumerated usernames and captured credentials.
- **`ports.gnmap`** / **`smb-null.txt`** — nmap-greppable + netexec handoff.

## fieldkit → recce

```bash
fieldkit export-recce recce_findings.json   # KB-enriched, confidence: "confirmed"
recce fieldkit-import recce_findings.json -o eng
```

Each proven finding becomes a confirmed vulnerability (source `fieldkit`) in the
Vulnerabilities sheet, report, and DOCX write-ups. The host is marked access-gained.
Re-importing is idempotent. The enriched export adds CWE/remediation from fieldkit's KB.

## The contract

`fieldkit export-recce` emits a self-contained payload where each finding carries a `_recce`
block recce imports directly:

```json
{
  "_recce_import": 1,
  "source": "fieldkit",
  "engagement": { "...": "..." },
  "findings": [
    { "...": "...",
      "_recce": {
        "ip": "10.0.0.7", "hostname": "WS02", "port": 0,
        "severity": "High", "cwe": "CWE-250", "cwes": ["CWE-250"],
        "remediation": "…", "description": "…", "risk": "reversible",
        "confidence": "confirmed", "ids": ["…"]
      } }
  ]
}
```

`confidence` is always **`confirmed`** — fieldkit only exports what it proved. The contract is
pinned by fieldkit's `tests/test_bridge.py`; change the shape only alongside recce's importer.

## Host topology

fieldkit's on-target enum captures a network block (interfaces, routes, ARP, live peers). Fold
it in:

```bash
recce ingest enum-output.txt -o eng       # host auto-resolved from interface IPs; --host <ip> to force
```

This draws a ground-truth reachability map (`network-reachability.svg`) showing observed
host-to-host links and dual-homed pivots.
