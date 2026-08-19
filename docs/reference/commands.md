# Command & option reference

Every subcommand and its notable options. Run `recce <command> -h` for the full list.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Command & option reference

Every command takes targets as a single IP, several IPs, a range
(`10.0.0.10-40`), a CIDR, or `@file`. Common options (all scan phases):
`-o DIR` (engagement folder), `--title`, `--profile quick|standard|thorough`,
`--workers N`, `--refresh-every N`, `--host-timeout MIN`.

| Command | What it does | Notable options |
|---|---|---|
| `doctor` | Verify the box (env + tools + real localhost self-scan) | `--no-self-scan` |
| `demo` | Build reports from a bundled sample scan (no network) | — |
| `import <files>` | Import **existing** nmap scans (`-oX`/`-oG`/`-oN`, multiple files/dirs/globs, masscan XML) → workbook, no scanning | `--enum-only`, `--searchsploit` |
| `enum <targets>` | Discover hosts, port sweep, service/OS/AD enum → sheet | `--fast` (masscan), `--all-ports`, `--top-ports N`, `--no-discovery`, `--no-ad`, `--no-os`, `--version-all`, `--version-intensity 0-9`, `--min-rate`, `--exclude`, `--resume` |
| `vulns [targets]` | Vuln-scan open ports (safe detection + offline CVE/CWE DB + probes) | `--fast` (top-signal + progress/ETA), `--aggressive` (full NSE), `--only SVC`, `--unscanned`, `--offline`, `--no-searchsploit`, `--no-probes`, `--udp-top N` |
| `scan <targets>` | `enum` then `vulns` in one shot; `--deep` runs the whole credential-free mass surface (enum → vulns → every applicable deep module) in one kickoff | all of enum + vulns · `--deep` · `--skip MOD...` · `--only-modules MOD...` |
| `db [targets]` | Database enumeration + vuln scan | `--aggressive` (brute/xp_cmdshell/hash), `--no-searchsploit` |
| `privesc [targets]` | Per-host priv-esc playbook | `--scan` (remote NSE checks), `--aggressive` |
| `credenum [targets]` | Authenticated SMB/AD/SSH enum | `-u/-p/-d`, `--admin-user/--admin-pass/--admin-domain`, `--ssh-user/--ssh-pass/--ssh-key`, `--ldap-enum`, `--ldap-anon`, `--ldap-ssl`, `--dc-ip`, `--aggressive` |
| `ingest <loot>` | Fold on-target `recce-enum.sh`/`.ps1` findings into Priv-Esc, **or** `recce-service.sh` output into Vulnerabilities (auto-detected); also folds a `NET-*` topology block for the reachability/architecture maps | `--host IP` (else auto-resolved from the enum's interface IPs / hostname) |
| `writeups [targets]` | One Word write-up per **real** finding + combined report | `--include-potential`, `--min-severity`, `--no-screenshots`, `--no-combined`, `--overwrite` |
| `writeup <selector>` | **One** finding's write-up, pre-filled with looted/obtained evidence (F-id / CVE / IP / title; omit to list) | `--no-screenshots`, `--overwrite` |
| `services [targets]` | Print the per-service enum command (`recce/scripts/`) for every open port found | `-a` (append the intrusive flag) |
| `exploitplan [targets]` | Ready-to-run artifacts (msf `.rc` + tool commands) for **confirmed** findings, params pre-filled | `--lhost`, `--lport`, `--run` |
| `attackpath [targets]` | Chain confirmed findings into a staged attack path (foothold → priv-esc → creds → lateral → domain) | — |
| `creds [targets]` | Stack captured credentials + build a netexec/impacket spray plan | `--add`, `--user/--pass/--hash/--domain`, `--plan` |
| `serve` | Serve the **web workbench** for this engagement (browser UI, multi-tester over the LAN; run scans, Act/Loot, export) | `--host` (bind, default `0.0.0.0`), `--port` (default `8008`) |
| `report` | Rebuild the workbook/reports from the datastore | — |
| `status` | Print live coverage + suggested next command | — |
| `review` | Mark hosts/services/items reviewed from the CLI | `--host`, `--service IP:PORT`, `--key`, `--cascade`, `--note`, `--undo` |

Credentials passed to `enum`/`vulns` (`-u/-p/-d`) also feed the SMB/LDAP NSE
scripts during the scan. Run `recce <command> -h` for the full list.

**Environment:** `RECCE_DEBUG=1` (full tracebacks), `RECCE_BROWSER=/path`
(screenshot browser). **Exit codes:** `0` ok · `1` error · `2` bad args · `130`
interrupted (partial results saved).


