# Active Directory & credentialed enumeration

Credential-free AD facts, credentialed LDAP enumeration, offline BloodHound + Certipy import to Domain-Admin paths, and the authenticated `credenum` phase.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Active Directory

AD analysis runs in two tiers.

**Tier 1 — credential-free (always on).** Purely from what nmap already collected,
the tool tags roles (**Domain Controller**, Global Catalog, WinRM, RDP, MSSQL…),
determines **SMB signing** posture, and harvests domain/NetBIOS/FQDN facts and
the **password policy** (from `smb-enum-domains`). It then derives target lists:

- **Domain Controllers** — your primary AD targets
- **NTLM relay targets** — hosts where *SMB signing is not required* (feed to `ntlmrelayx`)
- **SMBv1 / MS17-010** candidates

**Tier 2 — credentialed LDAP (`--ldap-enum`, needs `ldapsearch` (ldap-utils) or the `ldap3` package).** Binds to each
discovered DC and enumerates:

- **Users** with UAC flags → **AS-REP roastable** (`DONT_REQ_PREAUTH`) accounts
- **SPNs** → **Kerberoastable** service accounts (krbtgt excluded)
- **Unconstrained / constrained delegation** on users and computers
- **Computers** with OS/build
- **Privileged groups** and their members (Domain/Enterprise Admins, `adminCount=1`)
- **Domain trusts**, functional level, `ms-DS-MachineAccountQuota`, anonymous-bind check

```bash
# Credentialed LDAP enumeration of every discovered DC:
sudo python -m recce scan 10.0.10.0/24 --ldap-enum \
     --username jsmith --password 'P@ss' --domain corp.local

# Point LDAP at a specific DC (skip auto-detect); try anonymous bind:
python -m recce scan 10.0.10.0/24 --ldap-enum --ldap-anon --dc-ip 10.0.10.10

# Credentials are also passed to the SMB/LDAP NSE scripts during the scan so
# authenticated user/share/group enumeration succeeds:
sudo python -m recce scan 10.0.10.0/24 --username jsmith --password 'P@ss' --domain corp.local
```

Everything lands in the **Active Directory** and **AD Quick Wins** sheets (see
below), plus an enriched **Users & Accounts** sheet (roastable/delegation cells
are color-flagged).

**Tier 3 — offline BloodHound + Certipy import (`recce ad`).** Bring back a
**SharpHound** collection and/or a **`certipy find -json`** file and recce parses
the AD object graph offline (stdlib `json`/`zipfile` — no BloodHound/neo4j) into a
provable runbook:

- **AD misconfigurations / vulnerabilities** — Kerberoastable & AS-REP-roastable
  accounts, **DCSync** rights held off tier-0, unconstrained/constrained
  delegation, **RBCD**, **shadow-credential** (`AddKeyCredentialLink`) edges,
  dangerous ACLs from low-priv principals, passwords in descriptions,
  `PASSWD_NOTREQD`, non-zero `MachineAccountQuota`, and **ADCS ESC1–ESC15** from
  Certipy — each with the exact `impacket`/`certipy`/`bloodyAD` command to prove it.
- **Attack paths to Domain Admin** — the shortest path (BFS over the graph) from
  **your account** (or any authenticated user) to Domain Admins / the domain
  object / a DC, rendered as an edge chain with the abuse per hop.
- **Kerberos actions for effect** — roast, AS-REP, DCSync, delegation ticket
  forging, staged with your credential.
- **Live Kerberos capture (opt-in)** — with creds + `--dc-ip`, recce doesn't just
  *stage* the roast, it **runs** the published impacket tools to capture the real
  crackable material and folds each capture in as a **proven** finding:
  `--roast` (`GetUserSPNs -request` → live TGS-REP hashes), `--asrep`
  (`GetNPUsers -request` → AS-REP hashes), `--dcsync` (`secretsdump -just-dc` →
  replicated NTLM hashes incl. **krbtgt**). All three are read-only (request
  tickets / replicate secrets — nothing is modified). Captured hashes land in
  `eng/loot/` ready for `hashcat`; `--screenshots` saves terminal-output proof
  images.

Credentials-first and copy-paste-ready — give it `-u/-p/-d` (no NT hash needed)
and every generated command is pre-filled with your account. Findings feed the
main **Overview** totals, the **Vulnerabilities** sheet, and the write-ups, and
also populate the dedicated **AD Findings** and **AD Attack Paths** sheets.

```bash
# SharpHound + Certipy, credentialed — paths start from your account:
python -m recce ad loot.zip 20260101_Certipy.json \
     -u alice -p 'Passw0rd!' -d corp.local --dc-ip 10.0.10.10 -o eng

# Live capture: roast + AS-REP + DCSync the domain, with proof screenshots:
python -m recce ad loot.zip -u alice -p 'Passw0rd!' -d corp.local \
     --dc-ip 10.0.10.10 --roast --asrep --dcsync --screenshots -o eng

# Re-import after remediating some findings (drop the ones that are now fixed):
python -m recce ad loot.zip -u alice -p 'Passw0rd!' -d corp.local --replace-ad -o eng
```


## Credentialed enumeration (`credenum`)

Once you have valid creds, `credenum` runs the *authenticated* checks nmap can't
do on its own. Everything is **optional and tool-gated** — recce shells out to
tools that already ship on Kali and skips (with a logged note) any that are
absent; no Python packages are needed at runtime:

```bash
recce credenum -u alice -p 'Passw0rd!' -d corp.local -o eng          # SMB/AD
recce credenum --ssh-user root --ssh-key id_rsa -o eng               # Linux
recce credenum -u alice -p 'Passw0rd!' -d corp.local --aggressive    # + secretsdump
```

- **netexec / nxc** (or crackmapexec) — authenticated **SMB**: shares & access,
  domain users, sessions, logged-on users, password policy, and crucially
  **local-admin access** (`Pwn3d!` → a high finding). A missing account-lockout
  threshold is flagged as spray-friendly.
- **impacket** — **Kerberoasting** (`GetUserSPNs`) and **AS-REP roasting**
  (`GetNPUsers`) with the actual `$krb5tgs$`/`$krb5asrep$` hashes; `--aggressive`
  adds **secretsdump** (SAM/LSA/NTDS NTLM hashes → a critical finding).
- **ssh** — Linux host-level checks (`id`, `sudo -l`, `uname`, SUID sweep);
  key auth or, for passwords, `sshpass` if present. Flags NOPASSWD sudo and
  unusual SUID binaries.

At the end of the phase `credenum` prints a per-host **authentication
success/fail table** (user account · privileged account · SSH), so you can see
at a glance which creds worked where and which rows to re-check.

Results fold into the normal model: accounts and shares land on **Users &
Accounts**, roasted accounts flow into **AD Quick Wins**, and access/loot/weak-
policy findings become **Vulnerabilities**. It targets each host by surface
(SMB hosts get netexec, DCs get roasting, SSH hosts get local checks), so one
`credenum` run covers a mixed environment. `recce doctor` shows which of these
tools are installed.


