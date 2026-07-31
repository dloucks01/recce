# recce — Safety, Restrictions & Responsible Use

recce is an **authorized-testing** tool: an airgapped, stdlib-only reconnaissance,
enumeration and vuln-triage assistant for penetration testers and red/blue teams. This
document is the single source of truth for how recce is meant to be used, the safety
controls it enforces, and the restrictions it deliberately keeps. Individual modules no
longer repeat this in full — they point here.

---

## 1. Authorized use only

recce is for security work you are **authorized to perform**:

- You must have **written permission** (a signed engagement / rules-of-engagement, a
  bug-bounty scope, or your own lab) covering every host you point it at.
- Keep scans **inside the agreed scope and time window**. recce accounts for scope by
  subnet so you can show exactly what was in-bounds.
- Respect data-handling rules for anything you enumerate (credentials, PII, secrets):
  store loot only where the engagement allows, and destroy it per the contract.

recce is **not** for scanning systems you do not own or are not contracted to test, for
mass/untargeted internet scanning, or for any activity outside a defined authorization.

---

## 2. Safety design — what recce does by default

recce is built to be **safe to run on a live production estate** during an authorized
test. The following are enforced in the code, not just recommended:

- **Read-only by default.** Enumeration reads; it does not modify targets.
  - **SNMP** guesses community strings and *reads* the MIB — it **never sends a SET**
    (a read-write community is flagged by name only, never exercised).
  - **MongoDB / Redis / Elasticsearch / LDAP / MSSQL / Docker / Kubernetes / SMB /
    FTP / rsync / NFS** deep modules read posture, versions and (where authorized)
    directory/DB/index/share objects. They do not write, drop, exec, or reconfigure —
    e.g. **Redis** reads `CONFIG GET` (never SET/SAVE), **Elasticsearch** issues GETs
    only, **rsync** reads the module list + the OK/AUTHREQD verdict (never transfers a
    file), and **NFS** reads the mountd export list (never mounts).
  - **Kerberos AS-REP roasting** requests tickets with no pre-auth and captures the
    AS-REP hash — it makes **no logon attempt**, so it triggers no account lockouts;
    username enumeration reads the KDC's pre-auth response only.
- **Non-destructive active checks.** Where recce actively confirms a finding, the probe
  is chosen to prove exposure without causing damage:
  - **SQL injection** payloads live in the SELECT/WHERE context (quote-break +
    `AND`/sleep) — **never a stacked `DROP`/`UPDATE`/`DELETE`**.
  - **Path traversal** reads only `/etc/passwd` / `win.ini` to confirm the read
    primitive; it does not exfiltrate arbitrary files automatically.
  - **Open redirect / SSTI / XSS** send a benign canary and inspect the response.
  - **Form fuzzing skips destructive forms** (actions matching
    delete/remove/logout/…) and never fuzzes password or anti-CSRF fields.
- **Reversible proofs.** Any write-impact proof is opt-in and self-undoing — e.g. the
  SMB/FTP writable-share proof drops a marker file, lists it, then **deletes it**, and
  reports whether cleanup succeeded.
- **Bounded and lockout-aware.** Default-credential probes try a tiny documented list,
  capped per endpoint to stay under lockout thresholds. Injection sweeps are budgeted.
- **Airgapped & offline.** Standard library only — no runtime pip dependencies, no
  outbound calls except the tools you explicitly invoke. Runs on a stock Kali with no
  internet.

---

## 3. Intrusive actions are opt-in and flag-gated

Anything with a heavier footprint is **off by default** and requires an explicit flag,
so an operator never trips it by accident:

| Behavior | Gate |
|---|---|
| Time-based (sleep) blind SQLi — deliberately delays the DB | `--sqli-time` |
| Default-credential probes (HTTP Basic + form/JSON logins) | `--creds` |
| Same-origin crawl + input fuzzing (reflection/SSTI/SQLi/redirect/traversal) | `--crawl` |
| Reversible writable-share / writable-dir proof | `--prove-write` |
| Aggressive NSE `vuln` category (XSS/SQLi/DoS probes) | `--aggressive` |
| On-target read-only enumeration script deploy | `deploy` sub-command |
| Pass-the-hash / credentialed enumeration | you supply `-u/-p/--hash` |

The `vulns` phase is **safe-by-default** (non-intrusive detection + the offline CVE DB);
intrusive scripts only run when you ask.

The two grouped deep-pass commands keep this split explicit:

- **`sweep`** is **credential-free and read-only** — it runs only the unauthenticated
  stdlib probes and refuses credentials (it points you at `credsweep` instead), so it
  can never send an auth attempt or write as a side-effect of a flag.
- **`credsweep`** is the **authenticated** pass and requires `-u/-p`: it sends
  credentials over the network (auth attempts) and drives the netexec/impacket tooling.
  It runs the write-impact proofs only if you add `--prove-write` (per the table above).

---

## 4. recce references tools — it does not weaponize

recce **triages and plans**; it hands weaponization to the established, purpose-built
tools an operator already runs under their ROE:

- It maps confirmed findings to the **exact existing tool + command** (e.g. `sqlmap`,
  `impacket-*`, `netexec`, `kubeletctl`, `mongosh`/`mongodump`, `snmpwalk`), with your
  values pre-filled and a validation step — but the Metasploit *launch* line in the
  generated `.rc` files is commented out; recce stages, the operator pulls the trigger.
- Exploitation that belongs to specialist tools — Kerberoasting/AS-REP cracking, secret
  decryption, CLR/agent loading, container escape — is **handed off** (Rubeus,
  impacket, PowerUpSQL, mssqlpwner, docker/kubectl), not reimplemented as an attack
  primitive inside recce.
- On-target scripts deployed by `deploy` are **read-only** local-enumeration helpers,
  torn down when done.

---

## 5. What recce deliberately does NOT do

- No **AV/EDR evasion**, obfuscation, or detection-avoidance tradecraft.
- No **destructive actions** — no data deletion/modification, no DoS, no resource
  exhaustion as an attack.
- No **self-propagation / worming** or lateral movement automation beyond staging
  commands for the operator.
- No **mass or untargeted** scanning; it works from an explicit scope you provide.
- No **credential exfiltration to third parties** — anything captured stays in your
  local engagement datastore.
- No **supply-chain** tampering.

---

## 6. Operator responsibilities

recce is a power tool; you own the outcomes:

- **Confirm authorization and scope** before every run.
- **Understand each flag** — the intrusive gates in §3 change the footprint. `recce
  <command> -h` documents them; the workbook's *Start Here* / *Runbook* tabs explain
  what each phase does.
- **Watch the scan-scope signals** — recce prints the port scope and flags PARTIAL
  (top-N) or INCOMPLETE (host-timeout) sweeps so a narrowed scan is never mistaken for
  complete.
- **Handle findings and loot responsibly** per the engagement's data-handling rules.
- **Validate before acting** — findings are marked CONFIRMED / LIKELY / POTENTIAL;
  confirm a POTENTIAL by hand before you act on it.

---

## 7. Reporting a vulnerability in recce itself

If you find a security issue in recce (not in a target), open an issue describing the
problem and reproduction, or contact the maintainer directly for anything sensitive.
Please do not include real engagement data, credentials, or client-identifying
information in a public report.
