# recce documentation

Start with [QUICKSTART.md](../QUICKSTART.md), then the reference below.

## Reference

| Doc | Covers |
| --- | --- |
| [workflow.md](reference/workflow.md) | Phases, importing scans, coverage tracking, speed, profiles |
| [scanning.md](reference/scanning.md) | NSE set, offline vuln channels, KEV/EPSS ranking |
| [services.md](reference/services.md) | Deep per-service modules (databases, SMB, FTP, Docker, K8s, SNMP, web) |
| [active-directory.md](reference/active-directory.md) | AD analysis, LDAP enum, BloodHound/Certipy, credenum |
| [privesc.md](reference/privesc.md) | Priv-esc playbook, on-target ingest, exploit plans |
| [reporting.md](reference/reporting.md) | Write-ups, fieldkit, output files |
| [commands.md](reference/commands.md) | Every subcommand and its options |
| [detection-rules.md](reference/detection-rules.md) | Custom version-to-CVE rules (JSON) |
| [packaging.md](reference/packaging.md) | Source package vs. airgap bundle |

## Design & internals

| Doc | Covers |
| --- | --- |
| [ARCHITECTURE.md](design/ARCHITECTURE.md) | QoD / honesty model, staged design |
| [WORKFLOW.md](design/WORKFLOW.md) | Operator-experience design |
| [ACT-PHASE.md](design/ACT-PHASE.md) | Findings to ranked action plan |
| [ACTIVE-VERIFICATION.md](design/ACTIVE-VERIFICATION.md) | Active-verification roadmap |
| [PROOFS-HONESTY-LOOP.md](design/PROOFS-HONESTY-LOOP.md) | Evaluation & honesty loop |
| [PROXY-PIVOT.md](design/PROXY-PIVOT.md) | Proxy-safe scanning through a pivot |
