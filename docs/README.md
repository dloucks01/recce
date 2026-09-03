# recce documentation

Start with **[../QUICKSTART.md](../QUICKSTART.md)** for the five-command
walkthrough. This index is the reference — grouped by what you'd want
to do, one hop from any user question.

## Reference

### Running scans
| Doc | Covers |
| --- | --- |
| [reference/workflow.md](reference/workflow.md) | Phases, importing scans, coverage tracking, speed, profiles |
| [reference/scanning.md](reference/scanning.md) | NSE set, offline vuln channels, KEV/EPSS ranking |
| [reference/services.md](reference/services.md) | Deep per-service modules (databases, SMB, FTP, Docker, K8s, SNMP, web, OT) |
| [reference/commands.md](reference/commands.md) | Every subcommand and its options |
| [reference/detection-rules.md](reference/detection-rules.md) | Custom version-to-CVE rules (JSON) |

### Compromise & post-exploitation
| Doc | Covers |
| --- | --- |
| [reference/active-directory.md](reference/active-directory.md) | AD analysis, LDAP enum, BloodHound/Certipy, credenum, ADCS ESC1 auto-request |
| [reference/privesc.md](reference/privesc.md) | Priv-esc playbook, on-target ingest, exploit plans |
| [reference/webui.md](reference/webui.md) | Web workbench — attack chains, sessions, ESC1, team collab |

### Reporting & delivery
| Doc | Covers |
| --- | --- |
| [reference/reporting.md](reference/reporting.md) | Write-ups, fieldkit round-trip, output files |
| [reference/packaging.md](reference/packaging.md) | Source package vs airgap bundle |

## Historical design notes

Internal ADRs for shipped subsystems live in
[`.recce-plan/design/`](../.recce-plan/design/) — decisions and rationale
for QoD confidence model, proof-verdict engine, session architecture,
proxy/pivot semantics, and the Act phase. Kept for future contributors;
not needed to run recce.
