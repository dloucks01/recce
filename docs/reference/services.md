# Deep service modules

The per-service deep enumeration modules — each safe-by-default, airgapped, and self-skipping when the service isn't present. Run them individually, or all at once with `recce sweep`.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Databases (`db`)

`db` finds database services and runs engine-specific NSE for the inventory view.
**Safe by default** — version/config enumeration, database & user listing,
empty-password checks. `--aggressive` adds intrusive NSE (brute force, `xp_cmdshell`,
hash dumping). Results populate a **Databases** sheet; security issues also land in
the Vulnerabilities sheet.

Alongside the NSE inventory, recce ships a **native stdlib deep-enum module per
engine** (airgapped, no client library) that you can run individually — these are the
modules that carry the offensive kill-chain below. Engines with a native deep module:

`mssql`, `mysql`, `postgres`, `mongodb`, `redis`, `elasticsearch`, **`memcached`**,
**`couchdb`**, **`influxdb`**, **`cassandra`**, **`oracle`**, **`db2`**.

### Database kill-chain — exfiltration, foothold, priv-esc, lateral

The DB modules go past inventory to the full engagement chain. Every capability is
read-only by default (active proof is opt-in), and every credential recovered is
lifted into the credential store (sprayable) to feed lateral movement.

- **Enumeration (no creds):** each module speaks the real wire protocol to CONFIRM the
  exposure — trust auth (postgres), empty-password (mysql), unauth `listDatabases`
  (mongo), unauth `INFO`/`stats` (redis/memcached), admin-party (couchdb), unauth query
  API + JWT bypass (influxdb), `AllowAllAuthenticator` (cassandra), the TNS listener
  (oracle), the DRDA endpoint (db2), and the exact version → CVE (offline `vulndb`).
- **Credentialed follow-through:** a password-protected instance is retried with the
  engagement's harvested credentials (`recce postgres|mysql|mongodb -u USER -p PASS`,
  or auto-sprayed from the datastore). Postgres/Mongo speak native **SCRAM**, MySQL
  speaks **`mysql_native_password`** — so the deep enum works against real, locked DBs.
- **Data exfiltration (`datamine`):** on any accessible instance recce reads the schema,
  flags columns/fields whose names denote secrets/PII, samples a few **redacted** rows
  to prove the data is real, and **harvests embedded connection strings / credentials**
  out of the data into the store (postgres/mysql/mongo).
- **Loot → crackable creds:** `pg_shadow` (postgres), `mysql.user` (mysql, hashcat
  `-m 300`), and **MongoDB SCRAM** hashes exported as hashcat `-m 24100/24200` lines.
- **Foothold (RCE):** the modules *identify* the RCE path — postgres superuser →
  `COPY … FROM PROGRAM`, MySQL **FILE** privilege → `LOAD_FILE`/`INTO OUTFILE`/UDF,
  redis `CONFIG`+`SAVE`/`MODULE LOAD`/replication, couchdb query-server. `recce
  postgres --prove` runs a **benign `id`** via `COPY … FROM PROGRAM` on a temp table to
  turn "capability" into **"RCE CONFIRMED: uid=…"** (opt-in; default stays read-only).
- **Lateral movement:** postgres **`dblink`/`postgres_fdw`** pivots to internal DB hosts
  and SSRFs `host:port` (+ foreign-server credentials harvested); MongoDB **replica-set
  members** are auto-probed as new targets; every looted cleartext credential sprays
  onward via `credsweep`.

Each finding is adjudicated by the **prove engine** (`recce prove`) with a verdict + the
exact next step, and flows into `attackpath` / `exploitplan` / the write-ups.


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
read-write community is flagged by *name* (private/write/manager/secret).

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




## New database engines (`memcached` · `couchdb` · `influxdb` · `cassandra` · `oracle` · `db2`)

Native stdlib deep modules for the engines recce previously only NSE-scanned — each
speaks the real wire protocol, no client library, airgapped:

- **`memcached`** (11211, text protocol) — reads `version` + `stats`, and samples live
  key names (`stats items`/`cachedump`) to CONFIRM unauthenticated data exposure; flags
  the UDP amplification vector and the pre-1.4.32 SASL-RCE CVEs.
- **`couchdb`** (5984/6984, HTTP) — `GET /_all_dbs` (unauth DB listing) and the
  admin-only `/_node/_local/_config`; a readable config = **admin party** (anyone is
  admin → RCE via the config query-server, or the CVE-2017-12635→12636 chain).
- **`influxdb`** (8086, HTTP) — `/ping` version + `SHOW DATABASES` with no credential
  (auth-off default); `< 1.7.6` also flags the empty-secret **JWT auth bypass**
  (CVE-2019-20933).
- **`cassandra`** (9042, CQL native binary) — a `STARTUP` handshake; a `READY` reply =
  `AllowAllAuthenticator` (no auth), then reads `system.local` (version/cluster/DC).
  Flags the UDF sandbox-escape RCE (CVE-2021-44521) and the JMX vector.
- **`oracle`** (1521, TNS) — builds a TNS `CONNECT` and confirms the listener, best-
  effort leaking the version; surfaces SID-brute / TNS-Poison (CVE-2012-1675) /
  default-credential paths.
- **`db2`** (50000, DRDA/DDM) — an `EXCSAT` exchange confirms the endpoint and reads its
  class name + release level (EBCDIC-aware) — version disclosure + credential-brute
  surface.

```bash
python -m recce sweep -o eng                 # runs all of these (unauth) in one pass
python -m recce couchdb -o eng               # or one engine
python -m recce influxdb -o eng
```


## Web & web-app (`recce web` · `recce api`)

`recce web` deep-enumerates every HTTP/S endpoint (stdlib client, no external tools);
`recce api` focuses the API angle. Both fold into the Vulnerabilities sheet and the
prove engine. Highlights (all read-only unless noted):

- **Recon / fingerprint:** tech stack, headers/TLS, cookies, dangerous methods,
  directory listing, virtual-host discovery, content discovery, WordPress/CMS.
- **Exposure & secret exfiltration:** exposed `.git` is **fully reconstructed** — recce
  parses `.git/index`, inflates the loose objects to recover the **source tree**, and
  mines it for secrets/credentials; exposed **`.js.map` source maps** are reconstructed
  the same way; `.env` / actuator (`/env`, heapdump) / backups / `.htpasswd` are read.
  Every harvested credential lands in the store (sprayable).
- **API surface (`recce api`):** parses the **OpenAPI/Swagger** spec and probes it —
  **broken authentication** (spec-secured endpoints answering 200 with no token) and
  **IDOR/BOLA** (an object-by-id endpoint serving different objects for id=1 vs id=2),
  plus GraphQL introspection and Swagger-UI exposure; embedded spec credentials
  harvested.
- **Injection:** reflected-XSS/SSTI (`7*7→49`), SQLi (error + time-based), path
  traversal / LFI, open redirect, and **SSRF** — a URL-ish parameter pointed at the
  cloud **metadata service** / `file://`; a confirmed metadata/IAM-credential read is
  **critical**.
- **Auth / tokens:** CORS misconfig, a consolidated **security-headers audit**
  (CSP/HSTS/X-Frame-Options/…), default-credential login, JWT `alg:none` forge + replay,
  and an offline **JWT HMAC secret crack** (weak/default secret → forge any token =
  auth bypass / privilege escalation).
- **Authenticated crawl (`--autologin`):** logs into each site's form with the
  engagement's harvested credentials, then scans the **authenticated** surface
  (post-login pages/forms/APIs) — credentialed follow-through for the web.

```bash
python -m recce web -o eng                    # full unauth deep enum (.git dump, SSRF, JWT, …)
python -m recce web --crawl -o eng            # + same-origin crawl: injection on discovered params
python -m recce web --crawl --autologin -o eng  # + auto-login with harvested creds, authenticated scan
python -m recce api -o eng                    # OpenAPI enumeration: broken-auth + IDOR/BOLA
```
