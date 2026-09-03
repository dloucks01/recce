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

## ADCS ESC1 auto-request (web workbench)

Once `recce ad certipy.json …` has imported an ESC1-vulnerable template AND
the credential store has an AD principal that can enroll on it, the web
workbench's **AD attack chain** gets a 🎯 **Attempt ESC1 request** button
on the `adcs_esc` step. Clicking it opens a form (principal picker from
store, template / CA / DC IP / target UPN inputs), asks for an explicit
"Run certipy req (intrusive)" confirm, and shells out to `certipy req`.

On success the returned PFX lands under `<eng>/session-loot/adcs/` **and**
a new `Credential(kind="cert")` folds into the store — the AD chain's
`da_path` step naturally advances on the next fetch.

Three protections apply at the endpoint (`POST /api/adcs/esc1/attempt`):

1. **Exact-string confirm sentinel** — body must carry the exact string
   `"yes-run-certipy"`, not a boolean. A JS-side `confirm: true` replay
   is refused. The sentinel is discoverable via
   `GET /api/adcs/esc1/available`.
2. **Store-lookup credentials** — the endpoint does NOT accept a password
   in the request body. The WebGUI names the AD principal; recce looks
   the credential up in its own store.
3. **Clean-fail on missing certipy** — returns 200 + `{ok:false,
   error:"certipy not installed — install with pip install certipy-ad"}`
   rather than a 500, so the UI renders the install hint inline.

Requires **certipy** (`pip install certipy-ad`) on the recce host. See
[webui.md](webui.md#adcs-esc1-auto-request-ad-chain) for the full flow.

## Auto-crack loop

Recce ships a **crack watcher** (`recce/creds/crack_watcher.py`) that
polls hashcat's default potfiles in the background — every time you crack
a Kerberos or NTLM hash recce holds, the plaintext folds back into the
credential store as `Credential(kind="password", source="cracked")`.
That lands the cred in the spray plan and advances the AD chain's
`cred_acquired` step naturally.

The header **Autocrack pill** in the web workbench (see
[webui.md](webui.md#header)) shows the watcher's queue and recent
promotions. No CLI required — the watcher runs as a background task
inside `recce serve`.

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
