# Deep service modules

Per-service deep enumeration — safe-by-default, airgapped, self-skipping when the service isn't present. Run individually or all at once with `recce sweep`.

## Databases (`db`)

Native stdlib deep modules per engine (no client library): `mssql`, `mysql`, `postgres`, `mongodb`, `redis`, `elasticsearch`, `memcached`, `couchdb`, `influxdb`, `cassandra`, `oracle`, `db2`.

**Kill-chain capabilities** (read-only by default, active proof opt-in):

- **Enumeration (no creds):** each module speaks the wire protocol to confirm exposure — trust auth (postgres), empty-password (mysql), unauth `listDatabases` (mongo), unauth INFO (redis/memcached), admin-party (couchdb), JWT bypass (influxdb), AllowAllAuthenticator (cassandra), TNS listener (oracle), DRDA endpoint (db2)
- **Credentialed follow-through:** retries with harvested creds or `-u/-p`. Postgres/Mongo speak SCRAM, MySQL speaks `mysql_native_password`
- **Data exfiltration (`datamine`):** reads schema, flags secret/PII columns, samples redacted rows, harvests embedded connection strings into the credential store
- **Loot:** `pg_shadow`, `mysql.user` hashes, MongoDB SCRAM hashes (hashcat-ready)
- **Foothold (RCE):** identifies the path — postgres `COPY FROM PROGRAM`, MySQL FILE/UDF, Redis CONFIG+SAVE/MODULE, CouchDB query-server. `--prove` runs a benign `id` to confirm (opt-in)
- **Lateral movement:** postgres `dblink`/`postgres_fdw` pivots, MongoDB replica-set auto-probe, credential spray onward

## SMB (`recce smb`)

- **Credential-free:** SMB2 NEGOTIATE for dialect + signing posture (relay surface), SMBv1 NEGOTIATE for EternalBlue surface
- **With tools/creds:** null/guest share enum via `nxc smb`, writable-share proof (`--prove-write`)

## FTP (`recce ftp`)

- **Credential-free:** banner (product/version + known-backdoor map: vsFTPd 2.3.4, ProFTPD 1.3.3c/mod_copy), anonymous login, AUTH TLS check
- **With session:** writable-directory proof (`--prove-write`)

## Docker (`recce docker`)

Unauthenticated Docker Engine API read (`/version`, `/info`, `/containers/json`, `/images/json`). If it answers: confirmed critical RCE exposure. Does not create containers.

## Kubernetes (`recce k8s`)

- **kubelet** (10250): anonymous `/pods` + `/exec` exposure
- **kube-apiserver** (6443): `system:anonymous` namespace/Secret listing
- **etcd** (2379): unauthenticated key read

Read-only probes only.

## SNMP (`recce snmp`)

Hand-rolled SNMPv2c client (raw UDP, BER/ASN.1, no pysnmp). Community guessing, system group, LanManager user table walk, running processes, installed software.

## MSSQL (`recce mssql`)

- **No creds:** SQL Browser instance enum, TDS pre-login version probe, blank `sa` / anonymous / relay checks
- **With creds:** access/privilege matrix via nxc, live impacket enumeration — server roles, TRUSTWORTHY DBs, impersonatable logins, `xp_cmdshell`/OLE/CLR status, `sys.sql_logins` hashes, linked-server graph traversal with nested RCE

## Web (`recce web` / `recce api`)

Stdlib HTTP client, no external tools:

- **Recon:** tech fingerprint, headers/TLS, cookies, directory listing, vhost discovery, content discovery
- **Exposure:** `.git` full reconstruction + secret mining, `.js.map` source maps, `.env`, actuator, backups
- **API (`recce api`):** OpenAPI/Swagger parsing — broken auth, IDOR/BOLA, GraphQL introspection
- **Injection:** reflected XSS/SSTI, SQLi (error + blind + time-based), path traversal/LFI, open redirect, SSRF (metadata service)
- **Auth/tokens:** CORS, security-headers audit, default credentials, JWT `alg:none` + HMAC secret crack
- **Authenticated crawl (`--autologin`):** logs in with harvested creds, scans the authenticated surface

```bash
recce sweep -o eng                              # all modules in one pass
recce web --crawl --autologin -o eng            # web with authenticated crawl
recce mssql -u sa -p 'Sql2019!' --local-auth -o eng
recce postgres --prove -o eng                   # confirm RCE
```
