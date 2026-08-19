# Privilege escalation & exploitation

The per-host priv-esc playbook, folding on-target enum output back in with `ingest`, and turning confirmed findings into runnable exploitation artifacts.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Priv-Esc (`privesc`)

`privesc` produces a per-host **Priv-Esc** sheet with two parts:

- **Remote findings** we actually observed — missing patches with public
  exploits (MS17-010, ZeroLogon, BlueKeep, PrintNightmare), SMB signing off,
  unauthenticated services, and local/remote exploit candidates from searchsploit.
- **An OS-specific playbook** — the prioritised checks/commands to run once you
  have a foothold. Windows: winPEAS/PowerUp, service perms & unquoted paths,
  `AlwaysInstallElevated`, token privileges (`SeImpersonate`→Potato), stored
  creds, scheduled tasks, DLL hijacking. Linux: linPEAS, `sudo -l`+GTFOBins,
  SUID/SGID, capabilities, cron, writable sensitive files, NFS `no_root_squash`,
  docker/lxd group.

The playbook is generated offline from what `enum` already found (no scanning);
`--scan` additionally runs the remote privesc NSE checks (`--aggressive` includes
intrusive ones like MS08-067 that can crash services).

### On-target enum → `ingest`

recce ships two **read-only** on-target sweeps in `recce/local/` — `recce-enum.sh`
(Linux) and `recce-enum.ps1` (Windows), a linPEAS/winPEAS-style deep dive that
changes nothing on the host. Once you have a shell, run one on the target, save
its output, and fold the `[!]` findings straight into that host's **Priv-Esc**
sheet:

```bash
# on the target:
./recce-enum.sh -o loot.txt                                  # Linux (-t self-tests)
powershell -ep bypass -File recce-enum.ps1 -OutFile loot.txt # Windows (-SelfTest)
# back on Kali:
recce ingest loot.txt -o eng          # auto-resolves the host (see below); --host IP to force
```

**Running the Windows script when `-File` isn't an option.** `recce-enum.ps1` takes
its params and runs its sweep on invocation — there's no separate entry method to
call, so pick the form that fits your channel:

```powershell
# 1) Standard — run the script file directly:
powershell -ep bypass -File .\recce-enum.ps1 -OutFile loot.txt

# 2) Dot-source — load it into an interactive session (its helper functions become
#    available too), then it runs with the params you pass:
. .\recce-enum.ps1 -OutFile loot.txt

# 3) Limited / semi-interactive channel (webshell, no -File) — read the script text
#    and invoke it as a scriptblock, passing params, nothing extra written to disk:
powershell -ep bypass -c "& ([scriptblock]::Create((Get-Content .\recce-enum.ps1 -Raw))) -OutFile loot.txt"
```

`ingest` needs no tools or network — it parses text recce itself produced. Findings
land as rows tagged **on-target finding** at the top of the host's Priv-Esc section.

**Host resolution is automatic.** With no `--host`, `ingest` lands the loot on the
right host by matching the box's own interface IPs from the enum's `NETWORK` block,
then by hostname, else it synthesizes an entry — so `recce ingest loot.txt` usually
needs no flag. The on-target enums (recce's own, and fieldkit's `linpriv`/`winpriv`)
also emit a machine `NET-IFACE / NET-ROUTE / NET-NEIGH / NET-PEER` block; `ingest`
folds that topology onto the host and `report` draws a **ground-truth**
`network-reachability.svg` (and upgrades `network-architecture.svg` to real gateways
+ dual-homed pivots). A topology-only block ingests fine with no `[!]` findings.

### Exploitation playbook (the *Exploitation* sheet)

For every **confirmed** priv-esc finding, recce builds a row on the
**Exploitation** sheet that turns the finding into an actionable next step using
**existing, published tools** — it does not generate exploit code. Each row gives:

- the **exact existing tool** (GodPotato / PrintSpoofer for `SeImpersonate`,
  PowerUp for a writable service, `gpp-decrypt` for a GPP cpassword, `reg save` +
  impacket-secretsdump for `SeBackupPrivilege`, GTFOBins for sudo/SUID,
  `openssl` for a writable `/etc/passwd`, the public PwnKit / Dirty Pipe PoCs, …),
- the **precise command with the finding's own values filled in** (the service
  name, the writable path, the SUID binary),
- the **prerequisite** and a **validation step** to confirm it worked.

Only confirmed findings get an entry — advisories / unconfirmed version matches
never get a "run this" line, matching the proven-exploit gating. The same guidance
appears in each finding's Word write-up as an *Escalate with existing tooling* step.

### Exploitation plan (`exploitplan`)

`recce exploitplan -o eng --lhost <IP>` takes that a step further: for each
**confirmed** finding it writes **ready-to-run artifacts** into `eng/exploit-plan/`,
with the parameters recce discovered already filled in:

- a **Metasploit resource script** (`.rc`) for every finding that maps to a
  published module — `ms17_010_eternalblue`, `vsftpd_234_backdoor`,
  `is_known_pipename` (SambaCry), `tomcat_ghostcat`, … — with `RHOSTS`, `RPORT`,
  `PAYLOAD`, `LHOST`/`LPORT` set. Run it with `msfconsole -q -r <file>`.
- **parameterized invocations of existing tools** — `impacket-GetNPUsers` /
  `GetUserSPNs` (with the domain + DC IP filled in), `ntlmrelayx` for an
  unsigned-SMB relay target, anonymous-FTP mirror, unauth-Redis write, … —
- a per-host **`<ip>.sh`** that chains the remote steps and lists the post-shell
  priv-esc steps (from the playbook) for reference.

It **selects and configures published exploits** against the specific hosts recce
found — **it authors no exploit code**; the exploit logic lives in the referenced
tool/module. It's gated to confirmed findings, and **safe by default**: the
Metasploit *launch* line in each `.rc` is commented out (only a non-intrusive
`check` runs) until you pass `--run`. Everything is to be used strictly within
your rules of engagement.

The same actions are surfaced in the workbook — the **Exploitation** sheet lists
every action (remote msf / remote tool / post-shell, each with the command,
prerequisite, and validation) — and in the Word write-ups, where a finding that
maps to a module gets a ready-to-run *Exploit with the published module* step.

**AV/EDR awareness (detection, not evasion).** When you `ingest` a `recce-enum.ps1`
run, recce records the host's AV/EDR product and defensive posture (Defender
real-time/tamper, EDR agents, Sysmon, LSASS `RunAsPPL`, AppLocker, Credential
Guard) and shows it where it matters: an **AV / EDR** column on the Checklist, a
**Defenses (host)** column on the Exploitation sheet next to each GodPotato/
PrintSpoofer/msf action, a count on the Overview, and a banner in the exploit-plan
scripts. The guidance is the legitimate one — coordinate a scoped testing
exclusion with the blue team (your tooling being caught is a finding *for the
defender*) or validate in a lab. recce flags what's watching a host; **it does not
evade AV/EDR** (the bundled scripts likewise do no AMSI/Defender tampering).


