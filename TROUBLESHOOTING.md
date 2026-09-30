# Troubleshooting

Run **`recce doctor`** first — it prints what's present/missing and proves the pipeline with a localhost self-scan.

---

## Install / first run

| Symptom | Fix |
|---|---|
| `recce: command not found` | Run `python3 -m recce` or `./bin/recce`. The bare `recce` command only exists after `pip install`. |
| `ModuleNotFoundError: No module named 'recce'` | Use `./bin/recce` (sets PYTHONPATH), or run from the project root. |
| `SyntaxError` / f-string errors | Python < 3.9. Check `python3 --version`. |

## nmap not found

nmap is the only hard requirement. Install it (`apt install nmap`). Every other tool is optional.

## Not running as root

SYN scan, OS detection, and UDP need root. Use **`sudo ./bin/recce ...`** (the wrapper re-adds PYTHONPATH). Alternatively: `sudo env "PATH=$PATH" python3 -m recce ...`.

## Zero hosts / zero ports

The **#1 field issue.** Firewalled hosts block ping and get skipped during discovery.

**Fix:** add **`-Pn`** to scan every target regardless of ping response:
```bash
recce enum 10.0.10.0/24 -Pn -o eng
```

If discovery gets zero responses, recce falls back to `-Pn` automatically.

### Zero ports even with `-Pn` (network rate-limiting)

If manual nmap finds ports but recce doesn't, the network is dropping probes. recce auto-detects this and re-scans adaptively, but you can force it from the start:
```bash
sudo recce enum 10.0.10.0/24 -Pn --reliable -o eng
```

The adaptive scan is bounded by `--host-timeout` (20 min default). Tune:
- **Faster:** lower `--host-timeout`, or `--min-rate 200` instead of `--reliable`
- **More complete:** raise `--host-timeout`, or narrow scope with `--top-ports 1000`

### Partial sweep (`⚠ PARTIAL`)

The `-p-` sweep timed out. Give more time or narrow scope:
```bash
sudo recce enum <ip> -Pn --host-timeout 60 -o eng    # more time
sudo recce enum <ip> -Pn --top-ports 2000 -o eng     # smaller scope
```

Re-scanning unions with stored results — never loses prior ports.

## Scans too slow

In order of impact:
- **`--fast`** — masscan sweep instead of per-host nmap
- **`--workers N`** — scan N hosts concurrently (default 6)
- **`vulns --fast`** — top-signal detection scripts only
- **`--profile quick`** — top-200 ports, no deep enum
- **`--top-ports N`** — cap port sweep
- **`--host-timeout MIN`** — abandon slow hosts after MIN minutes

## Scan hangs

Every tool call has a timeout. Set **`--host-timeout 10`** for a hard ceiling. **Ctrl-C** saves progress; re-run with **`--resume`**.

## Scan crashed / interrupted

Nothing is lost — every host is persisted on completion. Re-run with **`--resume`** to skip finished hosts. Use `RECCE_DEBUG=1` for full tracebacks.

## No open ports match vuln-scan filters

Run `enum` before `vulns`. Check `--only` / `--unscanned` filters aren't excluding everything.

## Vuln-scan finds nothing

Normal on benign hosts. Improve detection: `--version-intensity 9` or `--version-all` on `enum`. Go deeper with `vulns --aggressive` (intrusive NSE — slower, can crash fragile services).

## Credentialed enum (`credenum`)

- Missing credentials → pass `-u USER -p PASS [-d DOMAIN]` and/or `--ssh-user`
- Missing tools → install **netexec** + **impacket**, ensure **ssh** is on PATH
- Auth table key: `OK` = authenticated, `FAIL` = rejected (check domain), `ERR` = unreachable, `-` = not attempted
- Two accounts: `-u/-p/-d` for enumeration, `--admin-user/--admin-pass` for admin-only moves (secretsdump)

## LDAP enumeration fails

- No client → install **ldap-utils** (`ldapsearch`)
- No DCs found → use **`--dc-ip <IP>`**
- Bad bind → check `-d/-u/-p`; try `--ldap-anon` or `--ldap-ssl`

## searchsploit missing

Optional. Install with `apt install exploitdb`, or `--no-searchsploit` to silence.

## Web screenshots missing

Needs a headless browser (firefox or chromium). Install one, or set `RECCE_BROWSER=/path/to/browser`. Use `writeups --no-screenshots` to skip.

## Workbook issues

- **File locked** — close the workbook before running another scan or `report`
- **Corrupt workbook** — regenerate with `recce report -o DIR`
- **Missing info-level findings** — use `writeups --min-severity info`
- **Regenerate anytime** without re-scanning: `recce report -o DIR`

## Ingest (on-target loot)

- Wrong host → pass **`--host <IP>`** explicitly
- Re-ingesting is safe — findings de-duplicate

## On-target scripts

- Pre-flight: **`./recce-enum.sh -t`** or `powershell -ep bypass -File recce-enum.ps1 -SelfTest`
- Windows execution policy: use **`-ep bypass`**
- Scripts are read-only — no exploit code, no obfuscation

## No space left on device

Remove old engagement folders / `raw/` XML and re-run.

---

## Reference

| | |
|---|---|
| `RECCE_DEBUG=1` | Full tracebacks |
| `RECCE_BROWSER=/path` | Override browser for screenshots |
| Exit `0` | Success |
| Exit `1` | Error |
| Exit `2` | Bad arguments |
| Exit `130` | Interrupted (Ctrl-C, partial results saved) |

Every phase is idempotent — re-running never duplicates data. `recce doctor`, `recce <cmd> -h`, and the workbook's Runbook tab cover most questions.
