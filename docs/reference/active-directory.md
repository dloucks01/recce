# Active Directory & credentialed enumeration

## Active Directory

AD analysis runs in three tiers.

**Tier 1 — credential-free (always on).** From nmap data: tags roles (DC, Global Catalog, WinRM, RDP, MSSQL), determines SMB signing posture, harvests domain/NetBIOS/FQDN and password policy. Derives DC targets, NTLM relay targets (signing not required), and SMBv1/MS17-010 candidates.

**Tier 2 — credentialed LDAP (`--ldap-enum`, needs `ldapsearch` or `ldap3`).** Binds to each DC and enumerates: users with UAC flags (AS-REP roastable), SPNs (Kerberoastable), unconstrained/constrained delegation, computers with OS/build, privileged groups and members, domain trusts, functional level, `MachineAccountQuota`, anonymous-bind check.

```bash
sudo recce scan 10.0.10.0/24 --ldap-enum -u jsmith -p 'P@ss' -d corp.local
recce scan 10.0.10.0/24 --ldap-enum --ldap-anon --dc-ip 10.0.10.10
```

**Tier 3 — offline BloodHound + Certipy import (`recce ad`).** Parses SharpHound collections and `certipy find -json` files offline (stdlib `json`/`zipfile`) into a provable runbook:

- **AD misconfigurations** — Kerberoastable/AS-REP-roastable accounts, DCSync rights, unconstrained/constrained delegation, RBCD, shadow credentials, dangerous ACLs, passwords in descriptions, `PASSWD_NOTREQD`, `MachineAccountQuota`, ADCS ESC1-ESC15 — each with the exact command to prove it
- **Attack paths to DA** — shortest BFS path from your account to Domain Admins / domain object / DC, with abuse per hop
- **Live Kerberos capture (opt-in)** — `--roast` (TGS-REP hashes), `--asrep` (AS-REP hashes), `--dcsync` (NTLM hashes incl. krbtgt). All read-only. Captured hashes land in `eng/loot/`

```bash
recce ad loot.zip certipy.json -u alice -p 'Passw0rd!' -d corp.local --dc-ip 10.0.10.10 -o eng
recce ad loot.zip -u alice -p 'Passw0rd!' -d corp.local --dc-ip 10.0.10.10 \
     --roast --asrep --dcsync --screenshots -o eng
```

## Credentialed enumeration (`credenum`)

Authenticated checks nmap can't do — tool-gated, degrades cleanly when absent:

```bash
recce credenum -u alice -p 'Passw0rd!' -d corp.local -o eng          # SMB/AD
recce credenum --ssh-user root --ssh-key id_rsa -o eng               # Linux
recce credenum -u alice -p 'Passw0rd!' -d corp.local --aggressive -o eng  # + secretsdump
```

- **netexec** — authenticated SMB: shares, users, sessions, password policy, local-admin access (`Pwn3d!`)
- **impacket** — Kerberoasting + AS-REP roasting with real hashes; `--aggressive` adds secretsdump
- **ssh** — host-level checks (`id`, `sudo -l`, SUID sweep); flags NOPASSWD sudo and unusual SUID binaries

Prints a per-host authentication success/fail table at the end. Results fold into Users & Accounts, AD Quick Wins, and Vulnerabilities.
