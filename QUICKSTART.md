# recce — Quick Start

> **Airgapped pentest enumeration → one Excel workbook you check off as you go.**
> Point it at IPs/subnets, it scans with `nmap` and fills the sheet. Your ticks
> are saved — re-scanning never wipes them.

📄 Prefer a printable one-pager? Open **[`CHEATSHEET.html`](CHEATSHEET.html)** in a browser.
📚 Full reference: **[`README.md`](README.md)** · 🧰 Deep troubleshooting: **[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)**

---

## 0 · Before you begin

**What recce does:** you give it the addresses you're authorized to test; it scans
each one, records what it runs and where it's weak, and writes everything into a
single spreadsheet you tick off as you go. After each step, `recce status` prints
the exact next command — you don't have to memorise the flow.

**You need:** Kali (or any Linux with `python3` 3.9+ and `nmap`), the in-scope
addresses from your team, and written authorization. Only point recce at systems
you're allowed to test.

**Conventions in this guide:** lines starting with `#` are notes, not commands;
replace anything in `< >` with your value; `./bin/recce` and `python3 -m recce`
are interchangeable; prefix scans with `sudo` for full detection. Re-running any
command is safe — it never double-counts or loses your ticks. **Keep `-o eng`
identical across every command** — it's the one engagement folder they all share.

---

## 1 · Get it running

Only **`nmap`** is required (Kali has it); every other tool is optional and its
phase is skipped cleanly if absent. From the recce folder, run the self-check:

```bash
cd recce
./bin/recce doctor          # confirms the tool can run here
```

**You'll see:** a list of tools (**OK** = present, `-` = optional and absent), a
short self-scan, and a final **`READY.`** line. If `nmap` shows missing, install
it (`sudo apt install nmap`) and re-run.

> [!TIP]
> `./bin/recce` is a shortcut for `python3 -m recce` — use whichever works. Run
> scans with **`sudo`** for SYN scan + OS detection.

> [!NOTE]
> **Getting it onto Kali** (Windows host → Kali guest): best is `git clone` *inside
> Kali* (preserves LF endings + the executable bit). If you copied it through
> Windows and see *"bad interpreter"* / *"Permission denied"*, run
> `python3 -m recce …` (identical) or `chmod +x bin/recce`.

---

## 2 · The engagement at a glance

```
 enum ─▶ vulns ─▶ services ─▶ (foothold) ─▶ ingest / creds ─▶ writeups
 scan     deep      per-port     exploitplan    attackpath        report
 hosts    NSE+CVE   enum cmds    runnable .rc   the "so what"     deliverables
```

| Phase | Command | What it does |
|---|---|---|
| **Enumerate** | `sudo ./bin/recce enum <targets> -o eng` | discover hosts/ports/services → fills the sheet |
| _(have a scan?)_ | `./bin/recce import scan.xml -o eng` | build the sheet from existing nmap output |
| **Vuln-scan** | `sudo ./bin/recce vulns -o eng` | NSE + offline CVE/CWE engine + TLS/HTTP probes |
| **One-shot deep** | `sudo ./bin/recce scan --deep <targets> -o eng` | the whole credential-free mass surface in one kickoff: enum → vulns → every applicable deep module (`--skip`/`--only-modules` to narrow) |
| **Deep pass (unauth)** | `./bin/recce sweep -o eng` | **all** credential-free deep modules at once (web/smb/ftp/ldap/snmp/mongodb/redis/elasticsearch/rsync/nfs/kerberos/docker/k8s/mssql) — skips services you don't have |
| **Deep pass (auth)** | `./bin/recce credsweep -u U -p P -d dom -o eng` | **all** authenticated modules at once (credenum + authenticated ldap/smb/mssql/ftp) |
| **Per-service** | `./bin/recce services -o eng` | prints the exact enum command for each open port |
| **Databases** | `sudo ./bin/recce db -o eng` | database services |
| **Priv-esc** | `./bin/recce privesc -o eng` | per-host escalation playbook |
| **Credentialed** | `./bin/recce credenum -u U -p P -d dom -o eng` | authed SMB/AD/SSH enum |
| **AD graph** | `./bin/recce ad loot.zip certipy.json -u U -p P -d dom -o eng` | import SharpHound + Certipy → AD vulns, ESC findings, paths to Domain Admin |
| **MSSQL** | `./bin/recce mssql -u U -p P -d dom -o eng` | pre-auth probes + nxc access/priv matrix + MSSQLPwner-style attack chain |
| **SMB** | `./bin/recce smb -o eng` | signing/SMBv1 posture + share enum (add `-u/-p --prove-write`) |
| **FTP** | `./bin/recce ftp -o eng` | anonymous/AUTH-TLS + known backdoors (`--prove-write`) |
| **Docker** | `./bin/recce docker -o eng` | CONFIRM an unauthenticated Engine API (= root RCE) |
| **Kubernetes** | `./bin/recce k8s -o eng` | kubelet / kube-apiserver / etcd unauth exposure |
| **On-target loot** | `./bin/recce ingest loot.txt -o eng` | fold `recce-enum.sh/.ps1` findings in |
| **Mass local-enum** | `./bin/recce deploy -u U -p P -o eng` | run the local-enum + priv-esc scan on every host you have creds for (SSH/WinRM/SMB) |
| **Exploit plan** | `./bin/recce exploitplan -o eng --lhost <ip>` | runnable msf `.rc` + tool commands |
| **Attack path** | `./bin/recce attackpath -o eng` | chains findings → domain compromise |
| **Credentials** | `./bin/recce creds --add 'dom\u:p' -o eng` | stack creds → spray plan (`--plan`) |
| **Write-ups** | `./bin/recce writeups -o eng` | one Word doc per real finding |
| **Access** | `./bin/recce access -o eng` | footholds per host (auto-derived from credentialed enum); record your own with `--host IP --note '...'` |
| **Status** | `./bin/recce status -o eng` | what's left + the next command |
| **→ fieldkit** | `./bin/recce fieldkit-export -o eng` | export an attack plan for the fieldkit exploitation kit ([INTEGRATION.md](INTEGRATION.md)) |
| **← fieldkit** | `./bin/recce fieldkit-import findings.json -o eng` | fold fieldkit's proven findings back into the sheet + report |

> [!IMPORTANT]
> **Keep `-o eng` the same across every command** — it's the one engagement folder
> they all read, update, and write. Different `-o` = a separate engagement.

---

## 3 · Step by step

> The four commands below are the whole loop. Replace `10.0.10.0/24 10.0.20.0/24`
> with **your** scope, and keep **`-o eng`** identical every time.

### ① Enumerate — find the computers and what they run
```bash
sudo ./bin/recce enum 10.0.10.0/24 10.0.20.0/24 -o eng --title "Client X"
```
**You'll see:** a live count of hosts found and, at the end, `Reports written` with
the path to `eng/enumeration.xlsx`. This is the longest step — a `/24` block can take
a few minutes.

> [!WARNING]
> **Hosts showing zero ports?** They're likely hiding from the "are you there?" ping
> (common on Windows / firewalled / AD hosts). Re-run with **`-Pn`** ("assume they're
> up"): `sudo ./bin/recce enum 10.0.10.0/24 -Pn -o eng`. recce also tries this
> automatically when it gets no answers.
>
> Still zero ports under `-Pn`? The network may be **rate-limiting** (slowing scans
> on purpose). Add **`--reliable`** and it scans more patiently.

Already have an nmap scan from someone else? Skip enum and **import** it instead:
```bash
./bin/recce import scan.xml -o eng
```

### ② Open the workbook and look around
Open **`eng/enumeration.xlsx`** in Excel or LibreOffice. Read the **Start Here** tab
(it explains every other tab), then do your tracking on the **Checklist** tab — one
row per computer, a checkbox per step.

### ③ Vuln-scan — check the open services for known weaknesses
```bash
sudo ./bin/recce vulns -o eng
```
**You'll see:** per-host progress, then a summary of findings by severity. This is
**safe by default** (it looks, it doesn't attack). Findings appear on the
**Vulnerabilities** tab.

> [!TIP]
> Handy add-ons: `--fast` (quicker, shows a live **% + ETA**) · `--only http smb`
> (just those services) · `--unscanned` (only what's left).

### ④ Deep pass — dig into each service, in one command
```bash
./bin/recce sweep -o eng
```
**You'll see:** each service type checked in turn (web, SMB, databases, etc.),
skipping any you don't have — one command instead of nine. **Have credentials?**
Run the authenticated pass too:
```bash
./bin/recce credsweep -u alice -p 'Passw0rd!' -d corp.local -o eng
```
> Want to focus a single service instead of the whole sweep? Each has its own
> command — `./bin/recce web -o eng`, `smb`, `ftp`, `ldap`, `snmp`, `mongodb`,
> `redis`, `elasticsearch`, `rsync`, `nfs`, `kerberos` (AS-REP roast, no creds),
> `docker`, `k8s`, `mssql` (see the **Runbook** tab in the workbook).

### ⑤ Post-exploitation
```bash
# Got a shell? Run the bundled read-only sweep, bring the output back, fold it in:
#   target$  ./recce-enum.sh -o loot.txt                                   # Linux (-t self-test)
#   target>  powershell -ep bypass -File recce-enum.ps1 -OutFile loot.txt  # Windows
./bin/recce ingest loot.txt -o eng          # or ingest recce-service.sh output too

# ...or have creds? Run the local-enum + priv-esc scan on EVERY reachable host at once:
./bin/recce deploy --ssh-user root --ssh-key id_rsa -o eng           # all Linux via SSH
./bin/recce deploy -u admin -p 'Pw!' -d corp.local -o eng            # all Windows via WinRM/SMB
./bin/recce deploy -u admin -p 'Pw!' -d corp.local --stager -o eng   # Windows: fetch+run in memory
#   first checks (nxc) which hosts the creds actually work on, then picks SSH/WinRM/SMB per host,
#   runs the read-only script, folds results in. --stager avoids the temp file (auto-falls-back).
#   --dry-run previews the per-host transport plan.

./bin/recce exploitplan -o eng --lhost 10.10.14.7   # runnable msf .rc (--run to arm)
./bin/recce attackpath  -o eng                       # foothold → priv-esc → … → domain
./bin/recce creds --add 'CORP\alice:Pw!' -o eng      # then: creds --plan  (spray plan)
```

> [!NOTE]
> **Credentialed enum** with a normal + privileged account — the user account
> enumerates, the admin one runs admin-only checks; the report labels what each reached:
> ```bash
> ./bin/recce credenum -u alice -p 'Pw!' -d corp.local \
>              --admin-user admin --admin-pass 'AdmPw!' -o eng
> ```

### ⑥ Report & track
```bash
./bin/recce writeups -o eng     # Word write-up per REAL finding (--include-potential for guesses)
./bin/recce writeup  F-007 -o eng   # or ONE finding, pre-filled with what you've looted
./bin/recce status   -o eng     # progress + suggested next command
```

Repeat ③–⑥ until `status` says everything's done.

---

## 4 · 🎯 Targeting (every phase accepts these)

| Scan… | Type |
|---|---|
| one host | `10.0.10.5` |
| several | `10.0.10.5 10.0.10.9` |
| a range | `10.0.10.10-40` |
| a subnet | `10.0.10.0/24` |
| a file list | `@scope.txt` |

`enum`/`scan` take the **scope to scan**. `vulns`/`db`/`privesc` take targets to
work on **just that subset** of what's already enumerated — e.g.
`sudo ./bin/recce vulns 10.0.20.0/24 -o eng`.

---

## 5 · 📗 Using the workbook

- **Start Here** explains every tab; **Runbook** is a "what to type" for each phase.
- **Checklist** — one row per IP, grouped by subnet, with two kinds of box:
  - 🟩 **Auto** (Enumerated / Vuln-scan / Web / DB / **Access** / Priv-esc) turn green
    when recce finishes them — *Access* ticks itself once a credentialed step confirms
    you're in (or record one yourself with `./bin/recce access --host IP --note '...'`).
  - ✍️ **Manual sign-offs** (AD / Creds / Lateral) you tick yourself as you work.
    Tick **Reviewed** when you're done with a host.
- **`—` means the step doesn't apply** (no Web box off a non-web host), so a checked
  box always means real work.
- **Services** — one row per open port with its own **☐ / ◐ / ☑** status + notes.
- **Overview** — every subnet in scope with live-host + per-surface completion.

> [!TIP]
> Filter a step column to **`☐`** (or filter by Subnet) to see what's left. After
> editing in Excel, **save + close**, then `./bin/recce report -o eng` folds your
> edits back in.

---

## 6 · 📦 Deliverables (written into `eng/`)

| File | What it is |
|---|---|
| **`enumeration.xlsx`** | the tracking workbook you work out of |
| **`report.html`** | self-contained client-ready **findings** page — an expanded **exec summary**, an **At a glance** dashboard, a **How findings are scored** legend, findings with confidence + evidence, the attack path, and a **read-only coverage checklist**. Links to the companion `assets.html`. Open it in a browser; use **Print → Save as PDF** for a PDF. |
| **`assets.html`** | self-contained **architecture & assets** companion page — the **Network map**, the **AD architecture** diagram (tier-0 view built from the BloodHound import, when present), **Key information**, **Users & accounts**, and **Credentials** (masked). Links back to `report.html`. Both draw directly and print to PDF. |
| **`network-architecture.svg`** | the **headline** network diagram — AD domain over a routed core, each segment reached through its gateway (router, or firewall for edge/DMZ) + an L2 switch, stacked by tier. Goes **topology-driven** (real gateway IPs + dual-homed pivot links) once you `ingest` on-target routes. Open in a browser, no tools |
| `network-map-full.svg` / `network-map-overview.svg` / `network-map-tiered.svg` | the host map as standalone SVG — **full** (every host), **overview** (per-subnet role counts), and **tiered** (DC → servers → workstations with the credentialed lateral-movement surface). Open any in a browser, no tools; all also render inside `assets.html` |
| `network-reachability.svg` | **observed** host-to-host reachability (only after you `ingest` an on-target enum's `NETWORK` block) — ARP neighbours + live connections a foothold actually reached, with dual-homed pivots flagged. Ground truth, not inferred |
| `attack-path.svg` | the projected attack path (foothold → priv-esc → creds → lateral → domain) as a standalone SVG (written by `recce attackpath`; also embedded in `report.html`) |
| `ad-architecture.svg` | the tier-0 AD diagram as a standalone image you can open directly in a browser (written only after an `ad`/BloodHound import) |
| `enumeration.md` / `services.csv` | notes-friendly + flat pivot data |
| `writeups/*.docx` | per-finding Word write-ups + a combined report (after `writeups`) |
| `exploit-plan/*` | runnable msf `.rc` + per-host plans (after `exploitplan`) |
| `creds/*.txt` | `users` / `passwords` / `nthashes` lists for spraying (after `creds --plan`) |

---

## 7 · 🧰 Troubleshooting (quick hits)

Run **`recce doctor`** first — it self-tests the whole pipeline on this box.

| Symptom | Fix |
|---|---|
| `nmap … not found` | Install nmap — the only hard requirement. |
| weak scan / "not root" | Run with `sudo` (`sudo ./bin/recce …` so PATH survives). |
| **zero ports / few live** | They block ping — add **`-Pn`**. |
| zero ports but manual nmap finds them | Network rate-limiting — add **`--reliable`** (recce also auto-detects dropped probes). |
| too slow | `--fast`, `--workers N`, `--profile quick`, `--host-timeout`. |
| crashed / interrupted | Re-run with `--resume`, or `report -o eng`. `RECCE_DEBUG=1` for the traceback. |
| "No open ports match" | Run `enum` first; `--unscanned` is empty once all is scanned. |
| no findings (expected some) | `--version-all` then `vulns --aggressive`. |
| `credenum: No … tools` | Install netexec + impacket (or ssh). |
| auth `FAIL` / `ERR` | `FAIL` = creds rejected (check **domain**); `ERR` = unreachable/tool error. |
| workbook won't update | Close it in Excel first — an open file is locked. |

> [!NOTE]
> **Re-running any phase is safe** — every phase is idempotent (never duplicates rows).
