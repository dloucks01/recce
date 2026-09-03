# Command & option reference

Run `recce -h` for the full list, `recce <command> -h` for one command's options. Common options: `-o DIR`, `--title`, `--profile quick|standard|thorough`, `--workers N`, `--host-timeout MIN`.

| Command | What it does | Notable options |
|---|---|---|
| `run [targets]` | One-command flow: enum, vulns, deep sweep, report | all of enum + vulns, `--deep` |
| `doctor` | Verify the box (env + tools + localhost self-scan) | `--no-self-scan` |
| `demo` | Build reports from a bundled sample (no network) | — |
| `import <files>` | Import existing nmap scans (XML/grepable/normal, masscan XML) | `--enum-only`, `--searchsploit` |
| `enum <targets>` | Discover hosts, port sweep, service/OS/AD enum | `--fast`, `--all-ports`, `--top-ports N`, `--resume` |
| `vulns [targets]` | Vuln-scan open ports (safe detection + offline CVE DB) | `--fast`, `--aggressive`, `--only SVC`, `--unscanned` |
| `scan <targets>` | `enum` then `vulns` in one shot | `--deep` runs the full credential-free surface |
| `sweep` | All credential-free deep modules at once | `--skip`, `--only-modules` |
| `credsweep` | All authenticated modules at once | `-u/-p/-d` |
| `db [targets]` | Database enumeration + vuln scan | `--aggressive` |
| `privesc [targets]` | Per-host priv-esc playbook | `--scan`, `--aggressive` |
| `credenum [targets]` | Authenticated SMB/AD/SSH enum | `-u/-p/-d`, `--ssh-user/--ssh-key`, `--ldap-enum`, `--aggressive` |
| `ingest <loot>` | Fold on-target enum output into Priv-Esc / Vulnerabilities | `--host IP` |
| `deploy [targets]` | Run on-target enum on hosts with creds, fold results in | `-u/-p/-d`, `--stager`, `--dry-run` |
| `access` | Show/record footholds per host | `--host IP`, `--note` |
| `writeups` | One Word write-up per finding + combined report | `--include-potential`, `--min-severity` |
| `writeup <sel>` | Single finding write-up, pre-filled with looted evidence | F-id / CVE / IP / title |
| `exploitplan` | Ready-to-run msf `.rc` + tool commands for confirmed findings | `--lhost`, `--lport`, `--run` |
| `poc [CVEs]` | Per-CVE PoC dossier + harness skeleton from offline intel | `--confirmed`, `--with-exploits` |
| `attackpath` | Chain confirmed findings into a staged attack path | — |
| `act` | Ranked action plan; `--run` executes the safe / reversible half | `--host IP`, `--only ARCHETYPE`, `--top N`, `--run` |
| `prove` | Verdict engine — promotes findings to CONFIRMED on real proof + fills evidence | `--run` |
| `suggest` | Print the ranked next-moves digest (no scan) — cross-service chain rules + T3-capable findings | — |
| `verify` | Refresh KEV / EPSS / vulndb snapshots from disk | — |
| `bloodhound-push` | Write BloodHound-compat JSON for overlay onto an existing BloodHound instance | — |
| `creds` | Captured credentials + spray plan | `--add`, `--plan` |
| `serve` | Web workbench (browser UI, multi-tester) — see [webui.md](webui.md) | `--host`, `--port` |
| `report` | Rebuild workbook/reports from datastore | — |
| `status` | Print coverage + suggested next command | — |

Each protocol also has its own deep-enum command: `smb`, `ftp`, `mssql`, `mysql`, `postgres`, `mongodb`, `redis`, `elasticsearch`, `memcached`, `couchdb`, `influxdb`, `cassandra`, `oracle`, `db2`, `snmp`, `ldap`, `nfs`, `rsync`, `kerberos`, `docker`, `k8s`, `web`, `api`, `dns`, `smtp`, plus OT/ICS: `s7`, `bacnet`, `dnp3`, `enip`, `iec104`, `opcua`, `modbus`. See [services.md](services.md).

**Environment:** `RECCE_DEBUG=1` (full tracebacks), `RECCE_BROWSER=/path` (screenshot browser). **Exit codes:** `0` ok, `1` error, `2` bad args, `130` interrupted.
