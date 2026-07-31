# recce ⇄ fieldkit — feed exploitation, fold findings back in

recce is the **enumeration + reporting** half of an engagement; the
[**fieldkit**](https://github.com/dloucks01/fieldkit) is the **exploitation** half
(initial access → privesc → reporting, generators that *print* the commands you paste). recce
round-trips with it, so you enumerate once and let each side feed the other:

```
recce enum/vulns ──fieldkit-export──▶  fieldkit sweep + generators  ──findings.json──▶ gen_report
       ▲                                                                              │
       └──────────────  recce fieldkit-import  ◀── gen_report.py --export-recce ─────────┘
        (proven findings land back in the recce workbook + report)
```

Both directions are **offline, deterministic, stdlib-only** — same airgap contract as the rest of
recce. Two commands:

| Command | Direction | What it does |
|---|---|---|
| `recce fieldkit-export -o eng` | recce → fieldkit | writes `eng/fieldkit/` — a ready attack plan fieldkit consumes |
| `recce fieldkit-import <file> -o eng` | fieldkit → recce | folds a fieldkit `findings.json` (proven exploitation) back into the workbook + report |

## recce → fieldkit — seed the attack

After `enum`/`vulns`:

```bash
recce fieldkit-export -o eng          # -> eng/fieldkit/{recce-bridge.json, ports.gnmap, smb-null.txt, FIELDKIT.md}
```

- **`FIELDKIT.md`** — a human, severity-ranked "run **this** generator on **that** host, because …"
  plan. Read this first. Per host it lists the port→generator route, recce's confirmed findings, and
  **ready-to-paste generator commands**:
  - **version→CVE**: `gen_exploit.py find --service <p> --version <v>` for each identifiable service
    recce fingerprinted (with any confirmed CVEs attached);
  - **credential→shell / spray**: `gen_shell.py …` for each known credential that applies to the host,
    plus a `gen_spray.py --users users.txt …` line per shell-capable service.
- **`recce-bridge.json`** — the rich machine feed: each host's open ports, service/version, recce's
  **confirmed** findings, the suggested fieldkit generator, and the same `exploit_cmds` / `access_cmds`.
  In the fieldkit checkout: `python3 access/network/sweep.py triage --recce recce-bridge.json` ranks every
  host, floats proven quick-wins to the top, and prints those commands under each host.
- **`users.txt`** / **`creds.txt`** — the usernames recce enumerated (machine accounts dropped) and the
  credentials it captured, in the form `gen_spray.py --users` and `gen_shell.py` expect.
- **`ports.gnmap`** / **`smb-null.txt`** — an nmap-greppable + netexec-style handoff for fieldkit's
  classic `sweep.py triage --nmap … --nxc …` path (works with an unmodified fieldkit).

## fieldkit → recce — fold proven findings back into the sheet + report

When the fieldkit operator has proven findings and written them up, they export the recce feed:

```bash
# (in the fieldkit checkout)
python3 report/gen_report.py findings.json --export-recce   # -> recce_findings.json (KB-enriched)
```

Then fold it into this engagement:

```bash
recce fieldkit-import recce_findings.json -o eng
```

Each proven finding becomes a **confirmed** vulnerability (source `fieldkit`) on its host and shows up in
the **Vulnerabilities** sheet, the report, and the DOCX write-ups; the host is marked *access-gained*
and ticks the Checklist **Access** step. Re-importing is idempotent (deduped by title + host).

recce also imports a **raw** `findings.json` (without the `--export-recce` enrichment) — it uses each
finding's own `severity` and parses the host from `affected_host`; the enriched export just adds the
accurate CWE/remediation from fieldkit's knowledge base.

### Host topology → observed reachability map

fieldkit's on-target triage scripts (`linpriv/enum.sh`, `winpriv/enum.bat`) emit a machine `NETWORK`
block (interfaces, routes, ARP neighbours, live peers). Fold it in with the normal loot path:

```bash
recce ingest enum-output.txt -o eng          # host auto-resolved from the enum's own
                                              # interface IPs; add --host <ip> to force
```

recce stores it on the host and draws a **ground-truth** host-to-host reachability map
(`network-reachability.svg`) — a link only where a foothold actually reached the other end (ARP =
same-segment L2 contact, live connection = an established peer) — and flags dual-homed **pivots**.
Unlike the tiered map's *credentialed pivot surface* (what you could reach with a cred), these edges
are observed. `ingest` accepts a topology-only block, so you can feed it even before any finding.

> One source of truth: recce's workbook now tracks both coverage (what was enumerated) and outcomes
> (what fieldkit proved). See the full round-trip guide in the fieldkit repo's `INTEGRATION.md`.
