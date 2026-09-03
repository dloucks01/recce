# Deep service modules

Per-service deep enumeration -- safe-by-default, airgapped, self-skipping when the service isn't present. Run individually or all at once with `recce sweep`.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Databases (`db`)

`db` finds database services and runs engine-specific NSE. **Safe by default** -- version/config enum, database & user listing, empty-password checks. `--aggressive` adds intrusive NSE (brute, `xp_cmdshell`, hash dumping). Results populate **Databases**; security issues land in Vulnerabilities.

Native stdlib deep modules (airgapped, no client library): `mssql`, `mysql`, `postgres`, `mongodb`, `redis`, `elasticsearch`, **`memcached`**, **`couchdb`**, **`influxdb`**, **`cassandra`**, **`oracle`**, **`db2`**.

### Database kill-chain

Full engagement chain, read-only by default (active proof opt-in). Every recovered credential feeds the store for lateral movement.

- **Enumeration (no creds):** each module speaks the wire protocol to confirm exposure -- trust auth (postgres), empty-password (mysql), unauth `listDatabases` (mongo), unauth `INFO`/`stats` (redis/memcached), admin-party (couchdb), unauth query API + JWT bypass (influxdb), `AllowAllAuthenticator` (cassandra), TNS listener (oracle), DRDA endpoint (db2), version -> CVE (offline `vulndb`).
- **Credentialed follow-through:** retries with harvested creds (`recce postgres|mysql|mongodb -u USER -p PASS`, or auto-sprayed from datastore). Postgres/Mongo speak native **SCRAM**, MySQL speaks **`mysql_native_password`**.
- **Data exfiltration (`datamine`):** reads schema, flags secret/PII columns, samples **redacted** rows as proof, **harvests embedded connection strings/credentials** into the store.
- **Loot -> crackable creds:** `pg_shadow` (postgres), `mysql.user` (hashcat `-m 300`), MongoDB SCRAM hashes (hashcat `-m 24100/24200`).
- **Foothold (RCE):** identifies the path -- postgres superuser -> `COPY ... FROM PROGRAM`, MySQL FILE -> `LOAD_FILE`/`INTO OUTFILE`/UDF, redis `CONFIG`+`SAVE`/`MODULE LOAD`/replication, couchdb query-server. `recce postgres --prove` runs benign `id` via `COPY ... FROM PROGRAM` -> **"RCE CONFIRMED: uid=..."** (opt-in).
- **Lateral movement:** postgres `dblink`/`postgres_fdw` pivots + SSRF + foreign-server credential harvest; MongoDB replica-set members auto-probed; every cleartext credential sprays via `credsweep`.

Findings adjudicated by the **prove engine** (`recce prove`) with verdict + next step, flowing into `attackpath` / `exploitplan` / write-ups.

## SMB (`recce smb`)

- **Credential-free (stdlib):** **SMB2 NEGOTIATE** reveals highest dialect + **signing posture** (required vs enabled = relay blocked vs **NTLM-relay surface**); **SMBv1 NEGOTIATE** reveals legacy protocol (**MS17-010 / EternalBlue** surface). Both directly observed.
- **With tools/credentials:** null & guest session share enum (`nxc smb`); reversible **writable-share proof** (`--prove-write`: drop marker via `smbclient`, list, delete -- nothing left).

Prove engine adjudicates directly (signing-not-required + SMBv1-enabled -> CONFIRMED; signing-required -> relay = FALSE POSITIVE). Dedicated **SMB** tab.

```bash
python -m recce smb -o eng
python -m recce smb -u alice -p 'Passw0rd!' -d corp.local --prove-write --screenshots -o eng
```

## FTP (`recce ftp`)

- **Credential-free (stdlib):** reads **banner** (-> product/version for CVE DB + **known-backdoor map**: vsFTPd 2.3.4, ProFTPD 1.3.3c, ProFTPD mod_copy), tries **anonymous** login, inspects **FEAT** for AUTH TLS/FTPS -- flags **cleartext** auth.
- **With session:** reversible **writable-directory proof** (`--prove-write`: STOR marker via `ftplib`, DELE -- nothing left).

Prove engine confirms anonymous login (230) and flags backdoor/RCE builds. Dedicated **FTP** tab.

```bash
python -m recce ftp -o eng
python -m recce ftp --prove-write -o eng
python -m recce ftp -u bob -p 'hunter2' --prove-write -o eng
```

## Docker (`recce docker`)

Unauthenticated Docker Engine API (TCP 2375, or 2376 without mutual-TLS) = remote **root** RCE. recce reads with **stdlib HTTP** (`/version`, `/info`, `/containers/json`, `/images/json`); if it answers: **CONFIRMED critical** exposure + container/image inventory. Does **not** create a container. Dedicated **Docker** tab with escape command.

```bash
python -m recce docker -o eng
python -m recce docker --screenshots -o eng
```

## Kubernetes (`recce kubernetes` / `recce k8s`)

Stdlib-only unauthenticated reads of dangerous exposures:

- **kubelet** (10250): anonymous-auth -> `/pods` + `/exec` = **pod code execution**. Read-only port (10255) leaks pod specs (env-var secrets).
- **kube-apiserver** (6443/8443): `system:anonymous` LIST namespaces + **Secrets** (every SA token + TLS key = cluster compromise). 403 -> "anonymous-auth enabled" note.
- **etcd** (2379): unauthenticated key read = every Secret in the clear.

Read-only only (never execs into a pod or writes to etcd). Dedicated **Kubernetes** tab.

```bash
python -m recce k8s -o eng
```

## SNMP (`recce snmp`)

Hand-rolled SNMP **v2c** client on raw UDP socket (BER/ASN.1 + OID base-128 + GETNEXT walking -- no pysnmp). Read-write community flagged by name (private/write/manager/secret).

- **Community guessing** -- GET `sysDescr` with common strings (public/private/community/...).
- **System group** -- `sysDescr`/`sysName` identify the host pre-auth.
- **Walks** -- Windows **LanManager user table** (-> spray list), **running processes** + **installed software** (AV/EDR + unpatched builds), interface descriptions.

Enumerated accounts become `Account` rows in **Users & Accounts**. No prior UDP scan needed -- probes 161 directly. Dedicated **SNMP** tab.

```bash
python -m recce snmp -o eng
python -m recce snmp --no-probe -o eng
```

## MongoDB (`recce mongodb` / `recce mongo`)

Hand-rolled MongoDB **wire-protocol** client (OP_MSG opcode 2013 + minimal BSON encoder/decoder -- no pymongo). Airgapped, stdlib only.

- **hello / buildInfo** -- fingerprint version and replica-set role.
- **`listDatabases` without auth** -- discriminator. Returns DB list = unauthenticated full read/write -> **critical**. "not authorized" error = reachable but locked. EOL build -> medium.

Unauthenticated `listDatabases` *is* the proof. Dedicated **MongoDB** tab; prove engine gives `mongodump` next step.

```bash
python -m recce mongodb -o eng
```

## MSSQL (`recce mssql`)

Offensive SQL Server enumeration (modelled on PowerUpSQL / impacket-mssqlclient / nxc mssql / **MSSQLPwner**):

- **Credential-free (stdlib):** SQL Browser (UDP 1434) instance/version/port enum + **TDS pre-login** for exact version and login encryption status. Plus no-cred access checks (blank `sa`, anonymous, NTLM relay).
- **With credentials:** `nxc mssql` access + privilege matrix -- which servers accept creds, whether login is **sysadmin** (`Pwn3d!` = xp_cmdshell / RCE).
- **MSSQLPwner route** (impacket-mssqlclient): enumerates server roles, databases, **TRUSTWORTHY** DBs, **impersonatable logins**, `xp_cmdshell`/OLE/CLR status, `sys.sql_logins` hashes, saved credentials. **Detects escalation chains** and **recursively walks the linked-server graph** (`EXEC(...) AT [link]`) to every reachable sysadmin instance -- each a critical finding with full nested `xp_cmdshell` RCE command. Chains: impersonation, TRUSTWORTHY+db_owner, linked-server hops, UNC->relay -> effect (xp_cmdshell / sp_OACreate / CLR / Agent). Dedicated **MSSQL** sheet.

```bash
python -m recce mssql -o eng
python -m recce mssql -u alice -p 'Passw0rd!' -d corp.local --lhost 10.10.14.5 -o eng
python -m recce mssql -u sa -p 'Sql2019!' --local-auth -o eng
```

## New database engines (`memcached` / `couchdb` / `influxdb` / `cassandra` / `oracle` / `db2`)

Native stdlib deep modules -- real wire protocol, no client library, airgapped:

- **`memcached`** (11211, text protocol) -- `version` + `stats`, samples live keys (`stats items`/`cachedump`) to CONFIRM unauth data exposure; flags UDP amplification and pre-1.4.32 SASL-RCE CVEs.
- **`couchdb`** (5984/6984, HTTP) -- `GET /_all_dbs` + `/_node/_local/_config`; readable config = **admin party** (-> RCE via config query-server or CVE-2017-12635->12636 chain).
- **`influxdb`** (8086, HTTP) -- `/ping` version + `SHOW DATABASES` (auth-off default); `< 1.7.6` flags empty-secret **JWT auth bypass** (CVE-2019-20933).
- **`cassandra`** (9042, CQL native binary) -- `STARTUP` handshake; `READY` = `AllowAllAuthenticator`, reads `system.local`. Flags UDF sandbox-escape RCE (CVE-2021-44521) and JMX vector.
- **`oracle`** (1521, TNS) -- TNS `CONNECT` confirms listener, leaks version; surfaces SID-brute / TNS-Poison (CVE-2012-1675) / default-credential paths.
- **`db2`** (50000, DRDA/DDM) -- `EXCSAT` exchange confirms endpoint, reads class name + release level (EBCDIC-aware) -- version disclosure + credential-brute surface.

```bash
python -m recce sweep -o eng           # all unauth modules in one pass
python -m recce couchdb -o eng         # or one engine
python -m recce influxdb -o eng
```

## OT / ICS (`s7`, `bacnet`, `dnp3`, `enip`, `iec104`, `opcua`, `modbus`)

Native stdlib deep modules for OT protocols — hand-rolled wire clients, no external ICS libraries needed, airgapped:

- **`s7`** (102/tcp, Siemens ISO-on-TCP) — COTP + S7COMM SetupCommunication + SZL identity read (order code, hardware version, firmware). **CVE fingerprint with firmware-band verification** — CVE-2020-15782 (S7-1200 memory R/W) promotes to T2 only when SZL 0x0011 reports firmware below the V4.5 mitigation cutoff. S7-300/400/1500 CVEs stay at T1 (MLFB family match only).
- **`bacnet`** (47808/udp) — Who-Is / I-Am + Device Object read; enumerates analog values, file objects, firmware revision. Feeds `firmware_versions` shared surface + `known_bacnet_networks` topology.
- **`dnp3`** (20000/tcp) — REQUEST_LINK_STATUS + FC1 Class 0 read; leaks device attribute group (vendor, model, firmware).
- **`enip`** (44818/tcp, Rockwell EtherNet/IP) — List Identity / Services / RegisterSession + follow-on class reads (TCP/IP 0xF5, EthernetLink 0xF6, Identity 0x01). Detects unauth CIP sessions + I/O traffic exposure on UDP/2222.
- **`iec104`** (2404/tcp) — APCI STARTDT + General Interrogation; confirms outstation + reads status objects.
- **`opcua`** (4840/tcp) — GetEndpoints + FindServers + FindServersOnNetwork; enumerates SecurityPolicy=None endpoints + LDS-ME server inventory. Anonymous browse when SecurityMode=None.
- **`modbus`** (502/tcp) — Function-code enumeration + slave-id sweep + coil/register read.

```bash
python -m recce s7 -o eng        # port 102 targets only
python -m recce bacnet -o eng    # UDP 47808 — needs `enum -U` first
python -m recce opcua -o eng
```

## Web & web-app (`recce web` / `recce api`)

`recce web` deep-enumerates every HTTP/S endpoint (stdlib, no external tools); `recce api` focuses the API angle. Both feed Vulnerabilities + prove engine. All read-only unless noted:

- **Recon/fingerprint:** tech stack, headers/TLS, cookies, dangerous methods, directory listing, vhost discovery, content discovery, WordPress/CMS.
- **Exposure & secret exfiltration:** exposed `.git` **fully reconstructed** (parses `.git/index`, inflates loose objects, recovers source tree, mines secrets); **`.js.map` source maps** reconstructed similarly; `.env` / actuator (`/env`, heapdump) / backups / `.htpasswd` read. Every credential -> store (sprayable).
- **API surface (`recce api`):** parses **OpenAPI/Swagger** spec -- **broken authentication** (spec-secured endpoints answering 200 with no token), **IDOR/BOLA** (different objects for id=1 vs id=2), GraphQL introspection, Swagger-UI exposure; spec credentials harvested.
- **Injection:** reflected-XSS/SSTI (`7*7->49`), SQLi (error + time-based), path traversal/LFI, open redirect, **SSRF** (URL param -> cloud metadata/`file://`; confirmed metadata/IAM read = **critical**).
- **Auth/tokens:** CORS misconfig, **security-headers audit** (CSP/HSTS/X-Frame-Options/...), default-credential login, JWT `alg:none` forge + replay, offline **JWT HMAC secret crack** (weak secret -> forge any token = auth bypass / priv-esc).
- **Authenticated crawl (`--autologin`):** logs in with harvested creds, scans the **authenticated** surface (post-login pages/forms/APIs).

```bash
python -m recce web -o eng
python -m recce web --crawl -o eng
python -m recce web --crawl --autologin -o eng
python -m recce api -o eng
```
