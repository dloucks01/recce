# Workflow, coverage tracking & speed

## Workflow

Two cheap, resumable commands: `enum` populates the sheet fast, then `vulns` scans for vulnerabilities. Everything after (`db`, `privesc`, `credenum`, `sweep`, `writeups`) is an optional deeper phase you run on whatever subset you like.

**Already have scans?** Import them — all three nmap formats (XML, grepable, normal), masscan XML, and directories/globs:

```bash
recce import scan.xml -o eng
recce import a.xml b.gnmap scans/ -o eng    # multiple files, any mix
```

Imported hosts get the same offline enrichment as `enum`. New hosts append; duplicates merge (ports unioned, richer data wins).

```bash
sudo recce enum 10.0.10.0/24 10.0.20.0/24 -o acme --title "ACME internal"
sudo recce vulns -o acme                    # all open ports
sudo recce vulns -o acme --only http smb    # just web + SMB
sudo recce vulns -o acme --unscanned        # only what's left
recce sweep -o acme                         # all credential-free deep modules
recce credsweep -u alice -p 'Passw0rd!' -d corp.local -o acme  # authenticated
recce status -o acme                        # what's left
```

## Checklist tab

One row per IP, a checkbox per workflow step. Auto surfaces (Enum, Vuln, Web, DB, Access, Priv-esc) fill in as phases run. Manual sign-offs (AD, Creds, Lateral) track kill-chain coverage. Irrelevant steps show `—`. Your ticks persist across rescans.

## Services tab

Per-port status tracking: `Not started` / `In progress` / `Done` dropdown on each `IP:port`, with notes. Persists in the datastore.

## What each phase runs

**`enum`:** discovery sweep → full TCP port scan (or `--top-ports`/`--fast`) → service/version/OS ID + deep enumeration NSE set. No vuln scanning.

**`vulns`:** vulnerability + weak-config scripts on open ports, marks each port vuln-scanned, maps exploits. Safe by default; `--aggressive` adds intrusive NSE.

**`sweep`/`credsweep`:** runs every applicable deep module (web/smb/ftp/ldap/snmp/mongodb/redis/elasticsearch/rsync/nfs/kerberos/docker/k8s/mssql) in one shot. `sweep` is credential-free; `credsweep` is authenticated. Each module self-skips when the service isn't present.

## Coverage tracking

- Tick boxes in Excel or via `recce review`. Both write to the persistent datastore.
- Regenerating reports preserves every check and note.
- `status` and the Overview sheet give a live picture.

```bash
recce status -o eng
recce review -o eng --host 10.0.10.10 --cascade --note "DC enumerated"
```

Access is tracked automatically — recce marks a host access-gained when a credentialed phase confirms a foothold.

## Speed

- **`--workers N`** — scan N hosts concurrently (default 6). Biggest win for large scopes.
- **`--fast`** — network-wide masscan sweep + top-signal-only vuln scripts + progress/ETA.
- **`--profile quick`** — top-200 ports, no vuln scripts, for first-pass triage.
- **`--refresh-every N`** — rebuild workbook every N hosts so you can triage while scanning.

```bash
sudo recce scan 10.0.0.0/22 --fast --workers 12 -o eng
sudo recce scan 10.0.0.0/22 --fast --workers 12 --resume -o eng   # pick up where you left off
```

## Profiles

| Profile | Ports | OS | Host timeout |
|---------|-------|----|-------------|
| `quick` | top 200 | no | 10 min |
| `standard` (default) | full TCP | yes | 20 min |
| `thorough` | full TCP + top-100 UDP | yes | 40 min |

Override with `--all-ports`, `--top-ports`, `--no-udp`, `--udp-top N`, `--host-timeout`, `--min-rate`.

## Resumability

Findings are written to SQLite the moment each host finishes. Ctrl-C stops cleanly with a final report. `--resume` skips already-scanned hosts. A crash loses at most one in-flight host; `recce report` rebuilds from the datastore.

## Reliability

- Per-host time ceiling (`--host-timeout`) prevents hangs
- Errors/timeouts logged to `recce.log` and shown on Overview
- Discovery retries and `-Pn` reconfirmation prevent false "host down"
- `--targets-up @file` pre-seeds an authoritative target list so no host can vanish
