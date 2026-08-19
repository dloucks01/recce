# Deep service modules

The per-service deep enumeration modules — each safe-by-default, airgapped, and self-skipping when the service isn't present. Run them individually, or all at once with `recce sweep`.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Databases (`db`)

`db` finds database services (MySQL, MSSQL, Oracle, PostgreSQL, MongoDB, Redis,
CouchDB, …) and runs engine-specific NSE. **Safe by default** — version/config
enumeration, database & user listing, empty-password checks. `--aggressive` adds
intrusive checks (brute force, `xp_cmdshell`, hash dumping). Results populate a
**Databases** sheet (engine, version, auth posture, databases, users, findings);
security issues also land in the Vulnerabilities sheet. Credentials via
`--username/--password` are passed to the DB scripts for authenticated checks.


## SMB (`recce smb`)

Offensive SMB / file-sharing enumeration, in two layers:

- **Credential-free (airgapped, recce's own stdlib probes):** an **SMB2 NEGOTIATE**
  reveals the highest dialect and the **signing posture** — signing *required* vs
  merely *enabled* is the difference between "relay blocked" and the **NTLM-relay
  surface** — and a separate **SMBv1 NEGOTIATE** reveals whether the legacy SMBv1
  protocol is still answered (the **MS17-010 / EternalBlue** surface). Both are
  directly observed, no tools and no credentials.
- **With tools / credentials:** **null & guest** session share enumeration (via
  `nxc smb`), and a reversible **writable-share proof** (`--prove-write`: drop a
  marker file with `smbclient`, list it, delete it — nothing is left behind).

Findings feed the main **Overview** totals, the **Vulnerabilities** sheet and the
write-ups, and populate a dedicated **SMB** tab. The prove engine adjudicates the
observed states directly (signing-not-required and SMBv1-enabled → CONFIRMED;
signing-required → the relay finding is a FALSE POSITIVE).

```bash
# No creds — pre-auth posture (dialect/signing/SMBv1) + anonymous share enum:
python -m recce smb -o eng

# Credentialed — authenticated share enum + prove a writable share (reversible):
python -m recce smb -u alice -p 'Passw0rd!' -d corp.local --prove-write --screenshots -o eng
```


## FTP (`recce ftp`)

Offensive FTP enumeration:

- **Credential-free (airgapped, stdlib):** a control-channel probe reads the
  **banner** (→ product/version for the offline CVE DB and a narrow **known-backdoor
  map**: vsFTPd 2.3.4, ProFTPD 1.3.3c, ProFTPD mod_copy), tries an **anonymous**
  login, and inspects **FEAT** for AUTH TLS/FTPS — so it flags **cleartext**
  authentication.
- **With a session:** a reversible **writable-directory proof** (`--prove-write`:
  STOR a marker via stdlib `ftplib`, then DELE it — nothing left behind).

Findings feed the main totals, the Vulnerabilities sheet and the write-ups, and
populate a dedicated **FTP** tab. The prove engine confirms anonymous login (from
the observed 230) and flags the backdoor/RCE builds with the exact trigger.

```bash
# No creds — banner/anonymous/AUTH-TLS posture + known-backdoor match:
python -m recce ftp -o eng

# Prove a writable directory reversibly (anonymous or with creds):
python -m recce ftp --prove-write -o eng
python -m recce ftp -u bob -p 'hunter2' --prove-write -o eng
```


## Docker (`recce docker`)

An **unauthenticated Docker Engine API** (TCP 2375, or 2376 without mutual-TLS) is
remote **root** RCE on the host: anyone who can reach it can run a container that
bind-mounts the host root (`-v /:/host`) as root. recce reads the API
unauthenticated with **stdlib HTTP** (`/version`, `/info`, `/containers/json`,
`/images/json`) and, if it answers, reports a **CONFIRMED critical** exposure plus a
container/image-inventory info-leak — the successful unauthenticated read *is* the
proof; recce deliberately does **not** create a container. Findings feed the main
totals, the Vulnerabilities sheet and the write-ups, and populate a dedicated
**Docker** tab with the escape command.

```bash
python -m recce docker -o eng                 # read the API; CONFIRM exposure
python -m recce docker --screenshots -o eng   # + a `docker info` proof screenshot
```


## Kubernetes (`recce kubernetes` / `recce k8s`)

Stdlib-only unauthenticated reads of the cluster's most dangerous exposures:

- **kubelet** (10250): an anonymous-auth kubelet answers `/pods` and exposes
  `/exec` — **code execution inside any pod** on the node. The deprecated
  **read-only port** (10255, HTTP) leaks full pod specs (env-var secrets).
- **kube-apiserver** (6443/8443): whether `system:anonymous` can LIST namespaces —
  and, critically, **Secrets** (every service-account token and TLS key = cluster
  compromise). A 403 downgrades to an "anonymous-auth enabled" note.
- **etcd** (2379): an unauthenticated key read = every Secret in the clear.

Each successful read *is* the proof — recce only **reads** (it never execs into a
pod or writes to etcd). Findings feed the main totals, the Vulnerabilities sheet
and the write-ups, and populate a dedicated **Kubernetes** tab.

```bash
python -m recce k8s -o eng          # probe kubelet / apiserver / etcd, CONFIRM exposure
```


## SNMP (`recce snmp`)

A hand-rolled SNMP **v2c** client on a raw UDP socket (BER/ASN.1 with OID base-128
encoding and GETNEXT walking — no pysnmp), so it runs on a stock airgapped Kali. A
read-write community is flagged by *name* (private/write/manager/secret). Safety
posture: see [SECURITY.md](../../SECURITY.md).

- **Community guessing** — GET `sysDescr` with a list of common community strings
  (public/private/community/…); the first that answers is a readable community.
- **System group** — `sysDescr` / `sysName` identify the host pre-auth.
- **Walks** — the Windows **LanManager user table** (local accounts → a spray list),
  **running processes** and **installed software** (AV/EDR + unpatched builds), and
  interface descriptions.

Enumerated accounts become `Account` rows in **Users & Accounts**. Each read *is* the
proof — findings (guessable community, exposed users, process/software inventory) feed
the main totals, the Vulnerabilities sheet and the write-ups, populate a dedicated
**SNMP** tab, and are adjudicated **CONFIRMED** by the prove engine. SNMP discovery is
itself a GET, so no prior UDP scan is required — recce probes 161 directly.

```bash
python -m recce snmp -o eng          # guess the community, walk users/processes/software
python -m recce snmp --no-probe -o eng   # just write the commands (no live probe)
```


## MongoDB (`recce mongodb` / `recce mongo`)

A hand-rolled MongoDB **wire-protocol** client (OP_MSG opcode 2013 with a minimal
BSON encoder/decoder — no pymongo). Airgapped, stdlib only.

- **hello / buildInfo** — fingerprint the version and replica-set role.
- **`listDatabases` without authentication** — the discriminator. If the instance
  returns the database list, it is exposed unauthenticated (**full read/write to every
  database**) → a **critical** finding. If it errors "not authorized", auth is
  enforced and recce reports it reachable-but-locked (no finding). An end-of-life
  build raises a medium.

The successful unauthenticated `listDatabases` *is* the proof — findings feed the main
totals, the Vulnerabilities sheet and the write-ups, populate a dedicated **MongoDB**
tab, and are adjudicated **CONFIRMED** by the prove engine (with a `mongodump` next
step in the exploit plan).

```bash
python -m recce mongodb -o eng       # fingerprint + CONFIRM unauthenticated listDatabases
```


## MSSQL (`recce mssql`)

Offensive Microsoft SQL Server enumeration modelled on PowerUpSQL / impacket-
mssqlclient / nxc mssql / **MSSQLPwner**:

- **Credential-free (airgapped, recce's own stdlib probes):** SQL Browser (UDP
  1434) instance/version/port enumeration and a **TDS pre-login** probe for the
  exact server version and whether login encryption is enforced — no creds, no
  tools. Plus the no-cred access checks (blank `sa`, anonymous, NTLM relay).
- **With credentials (auto-runs `nxc mssql` when installed):** the access +
  privilege matrix — which servers your creds log into and whether the login is
  effectively **sysadmin** (`Pwn3d!` = xp_cmdshell / RCE).
- **The MSSQLPwner route** (live impacket-mssqlclient enumeration + attack chain):
  recce connects and enumerates server roles, databases, **TRUSTWORTHY** DBs,
  **impersonatable logins**, `xp_cmdshell`/OLE/CLR status, `sys.sql_logins` hashes
  and saved credentials, then **detects the actual escalation chain on each
  instance** and **recursively walks the linked-server graph** (nested `EXEC(...)
  AT [link]`) to every instance reachable **as sysadmin** — each becomes a
  critical finding with the full nested `xp_cmdshell` RCE command. Chains:
  impersonation, TRUSTWORTHY+db_owner, linked-server hops, UNC→relay → **effect**
  (xp_cmdshell / sp_OACreate / CLR / Agent). MSSQL findings feed the main
  **Overview** totals and the write-ups, and populate a dedicated **MSSQL** sheet
  (endpoints, live enumeration, linked-server graph, findings, runbook, chain).

```bash
# No creds — pre-auth recon + the no-cred access commands:
python -m recce mssql -o eng

# Credentialed — access/priv matrix + the full attack chain, commands pre-filled:
python -m recce mssql -u alice -p 'Passw0rd!' -d corp.local --lhost 10.10.14.5 -o eng
python -m recce mssql -u sa -p 'Sql2019!' --local-auth -o eng     # SQL (not domain) auth
```


