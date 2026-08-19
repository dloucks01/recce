# recce documentation

Start with the two guides at the repo root, then dip into the reference below.

- **[QUICKSTART.md](../QUICKSTART.md)** — zero to a filled-in workbook in five commands.
- **[README.md](../README.md)** — what recce is, install, and the big picture.
- **[TROUBLESHOOTING.md](../TROUBLESHOOTING.md)** — symptom → cause → fix, per phase.
- **[SECURITY.md](../SECURITY.md)** — safety model, authorized-use, opt-in intrusive actions.
- **[INTEGRATION.md](../INTEGRATION.md)** — the fieldkit round-trip.

## Reference

Deep-dive docs for each part of the tool. These expand on the README — read them
when you want the full detail on a phase.

| Doc | What it covers |
| --- | --- |
| [reference/workflow.md](reference/workflow.md) | The two-phase model, importing scans, the Checklist/Services tabs, coverage tracking, speed levers, and scan profiles |
| [reference/scanning.md](reference/scanning.md) | The NSE set and the four offline vulnerability channels; the fix-first (KEV/EPSS) ranking |
| [reference/services.md](reference/services.md) | The deep per-service modules — databases, SMB, FTP, Docker, Kubernetes, SNMP, MongoDB, MSSQL |
| [reference/active-directory.md](reference/active-directory.md) | AD analysis (three tiers), credentialed LDAP, BloodHound + Certipy import, `credenum` |
| [reference/privesc.md](reference/privesc.md) | The priv-esc playbook, on-target `ingest`, and the exploitation plan |
| [reference/reporting.md](reference/reporting.md) | Per-finding write-ups, the fieldkit round-trip, and every output file |
| [reference/commands.md](reference/commands.md) | Every subcommand and its notable options |
| [reference/detection-rules.md](reference/detection-rules.md) | The `--rules` JSON format for custom version→CVE detections |

## Design & internals

Developer-facing design notes and roadmap specs — the *why* behind recce's
accuracy and honesty model. Not needed to run the tool.

| Doc | What it covers |
| --- | --- |
| [design/ARCHITECTURE.md](design/ARCHITECTURE.md) | The QoD / honesty model and the staged design (the north star) |
| [design/WORKFLOW.md](design/WORKFLOW.md) | Operator-experience design: making 40+ subcommands feel like one tool |
| [design/ACT-PHASE.md](design/ACT-PHASE.md) | The Act phase — findings → a ranked, guided action plan |
| [design/ACTIVE-VERIFICATION.md](design/ACTIVE-VERIFICATION.md) | Verify, don't infer — the active-verification roadmap |
| [design/PROOFS-HONESTY-LOOP.md](design/PROOFS-HONESTY-LOOP.md) | The evaluation & honesty loop behind recce's verdicts |
| [design/PROXY-PIVOT.md](design/PROXY-PIVOT.md) | Proxy-safe / proxy-honest scanning through a pivot |
