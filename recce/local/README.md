# recce/local — on-target enumeration scripts

The on-host companions to recce. recce scans and reports from the network side;
these run **on a host you have a shell on** to surface local privilege-escalation
vectors and sensitive exposure — a linPEAS / winPEAS–style deep sweep.

| Script | Target | Run it |
|---|---|---|
| `recce-enum.sh` | Linux / Unix | `./recce-enum.sh [-t] [-q] [-o report.txt]` |
| `recce-enum.ps1` | Windows | `powershell -ep bypass -File .\recce-enum.ps1 [-SelfTest] [-Quiet] [-OutFile report.txt]` |

- `-t` / `-SelfTest` — pre-flight only (see below).
- `-q` / `-Quiet` — print findings only (skip the raw dumps).
- `-o` / `-OutFile` — also write everything to a file.

Lines marked **`[!]`** are worth a closer look. Each run ends with a
**"How to exploit"** reference that maps every vector the script flags to the
concrete escalation commands (GTFOBins/sudo/SUID/caps/cron/kernel on Linux;
Potato/Se-privileges/services/GPP/DLL-hijack on Windows), so a `[!]` finding
above has a matching how-to below.

**Pre-flight it on the first run** — `-t` (Linux) / `-SelfTest` (Windows):
parse-checks the script with the native parser (`bash -n` / the PowerShell
parser), reports the host (shell/PowerShell version, elevation, OS), and lists
which section families will produce data there — flagging any missing commands
(those checks self-skip) — **without running any enumeration**. If the parse is
`[ OK ]`, a real run is safe.

## What they check (deep dive)

**Linux:** kernel + LPE hints (PwnKit CVE-2021-4034, Dirty Pipe CVE-2022-0847,
old-kernel LES), sudo (`-l`, Baron Samedit, `LD_PRELOAD`), SUID/SGID vs GTFOBins,
file capabilities, cron/timers (+ writable scripts), services & root processes
running writable binaries, writable PATH dirs, `/etc/passwd|shadow|sudoers`
state, container escape (docker/lxd group, `docker.sock`, in-container caps),
NFS `no_root_squash`, credential hunting (SSH keys, history, `.env`/app configs,
cloud creds, Kerberos ccache/keytab, GPG), root-process `/proc/*/environ` leaks,
web-app config files, writable shared-library dirs, network, installed software.

**Windows** (modelled on winPEAS / PrivescCheck / Seatbelt / PowerUp):
OS/build + hotfixes (for WES-NG), token privileges → **Potato** recommendations
(SeImpersonate → GodPotato/PrintSpoofer/EfsPotato/JuicyPotatoNG) +
SeBackup/Restore/TakeOwnership/LoadDriver/Debug, integrity level, users/groups/
password policy; services (unquoted paths, writable binaries/registry keys),
scheduled tasks, AlwaysInstallElevated, autoruns + **IFEO/Winlogon** hijacks.
**Credential hunting:** cmdkey, registry autologon, unattend/sysprep, SAM/SYSTEM
backups, PowerShell history, WiFi keys, IIS web.config, registry password search,
**GPP cpassword** (SYSVOL + GPO cache), **DPAPI master keys**, **Kerberos tickets**
(klist), cloud creds (AWS/Azure/GCP/kube), SCCM cache, app stores
(PuTTY/WinSCP/FileZilla/OpenVPN/VNC), **saved RDP**, password-manager DBs, browser
login DBs. **Hardening/defence state:** UAC detail + LocalAccountTokenFilterPolicy,
WDigest, LSA PPL, Credential/Device Guard, **PowerShell logging** (SBL/module/
transcription) + PSv2 downgrade, LAPS, BitLocker, LmCompatibilityLevel/SMB signing,
**WSUS-over-HTTP**, Sysmon, **AV/EDR detection**, AppLocker, language mode.
**Also:** DLL-hijack dirs (PATH/Program Files), named pipes, RDP/NLA config,
installed software, network + firewall + shares, SYSTEM processes, environment.

## Safety & AV

They are **read-only** — they only *read* system state with built-in tools and
change nothing. There is no exploit code, no download, no obfuscation, and no
AMSI/Defender tampering. That transparency is precisely why a plain `Get-*` /
built-in-command script does not match malware signatures. If an EDR still
false-positives, coordinate an allow-list / exclusion rather than trying to
evade it — evasion would defeat the point of a clean, auditable read-only tool.

## Troubleshooting

- **Always self-test first** — `-t` / `-SelfTest`. If the parse says `[ OK ]`, a
  real run is safe; it runs no enumeration.
- **Windows won't run the script** — use `-ep bypass`
  (`powershell -ep bypass -File .\recce-enum.ps1`); the execution policy blocks
  unsigned scripts by default.
- **Sparse output** — many checks self-skip when a command/cmdlet is absent or
  you're not elevated; that's expected (the self-test lists which will run).
- **Bringing findings back** — save with `-o` / `-OutFile`, copy the file to your
  box, then `recce ingest loot.txt -o eng` folds the `[!]` lines into the
  **Priv-Esc** sheet (high-signal ones also become Vulnerabilities).
