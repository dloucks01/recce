# Phase 9 — Test Environment Plan

Chosen approach: **hybrid** — Docker Compose for standard services, Vagrant for services needing full OS (AD / IPMI / OT).

## Inventory summary

Total scan-capable services: **~85** across `recce/services/*.py` + Tier 1/2/3.

| Bucket | Count | Coverage today |
|---|---|---|
| Compose (native image, in `test_env/docker-compose.yml`) | 29 | ssh, http, mysql, redis, postgres, smb, ftp, smtp, ldap, snmp, nfs, mongo, es, docker, cassandra, couchdb, ad-dc, zookeeper, kafka, etcd, consul, nomad, prometheus, docker-registry, vnc, modbus, mssql, dvwa, juice-shop |
| Compose (native image, to add) | ~28 | dns, ntp, tftp, memcached, influxdb, oracle-xe, db2, imap/pop3 (dovecot), mqtt, coap, xmpp, vault, jenkins, zabbix, rtsp, sip, ipp/cups_lpd, coturn (stun/turn), guacd, k3s, webdav, rsync, telnet, x11, bird/frr (bgp), cloud_metadata (stub), gitdump (nginx+bare-repo), sqli target |
| Compose (simulator/stub, to author) | ~10 | bacnet, dnp3, enip, iec104, opcua, s7, nis_yp, slp, rservices, nrpe, nbd/ndmp |
| Vagrant VM | 3 | Windows Server 2022 AD DC (real Kerberos/DPAPI/WinRM), OpenBMC/virtualBMC (IPMI), Ubuntu Server (privileged: NFSv4 + LIO iSCSI + NBD) |
| Skip (no credible local reproduction) | 4 | vSphere/vCenter, real Siemens S7 CPU, real BGP peer AS, real IP-camera firmware |

Existing `test_env/` covers ~35% of services. Phase 9 closes the rest.

## Directory layout proposal

```
test_env/
├── compose.yml                      # rename docker-compose.yml, split by profile
├── compose.core.yml                 # profile: default MVP-10
├── compose.databases.yml            # profile: databases (heavy)
├── compose.ot.yml                   # profile: ot
├── compose.web.yml                  # profile: web
├── compose.messaging.yml            # profile: messaging
├── .env.example                     # RECCE_TEST_NET, image tags, weak creds
├── simulators/                      # source for stub images
│   ├── bacnet/  (bacpypes3 server)
│   ├── dnp3/    (pydnp3 outstation)
│   ├── enip/    (cpppo server)
│   ├── iec104/  (lib60870-python)
│   ├── s7/      (snap7-server)
│   ├── nis_yp/
│   ├── slp/
│   ├── nrpe/
│   ├── cloud_metadata/  (Flask IMDSv1/v2 stub)
│   └── rservices/
├── configs/                         # bind-mounts (mosquitto.conf, ejabberd.yml, ...)
├── samples/                         # existing importer fixtures
└── vagrant/
    ├── Vagrantfile
    ├── provision-ad.ps1
    ├── provision-bmc.sh
    └── provision-iscsi.sh
```

## Test-runner integration

Env vars (loaded by `tests/conftest.py`):
```
RECCE_TEST_NET=172.20.0.0/24
RECCE_TEST_TARGET_LINUX=172.20.0.10
RECCE_TEST_AD_DC=172.20.0.30
RECCE_TEST_BMC=172.20.1.20
RECCE_TEST_COMPOSE_PROFILE=core
```

Marker-gated fixtures:
- `@pytest.mark.needs_compose("core")` — auto-skip if compose profile not up
- `@pytest.mark.needs_vagrant("ad-dc")` — auto-skip if VM not reachable

CI two-lane:
- Lane A (fast, every PR): unit + `@needs_compose("core")` — ~3 min
- Lane B (nightly): all profiles + Vagrant lane — ~20 min

Tests expect the env running (not self-starting). A helper `require_compose(profile)` prints the exact `docker compose --profile X up --wait` command to run.

## Scope tiers

**MVP-10 (`--profile core`)** — fits on 4 GB laptop, <60s bring-up:
1. target-linux (ssh)
2. web-target / dvwa (http, sqli)
3. db-mysql
4. db-postgres
5. db-redis
6. mongo-target
7. smb-target
8. ldap-target
9. snmp-target
10. batched core: dns-bind + ntp + cloud-metadata + mqtt + vault + memcached + dovecot

**Tier 2 (`--profile ot --profile messaging --profile web`)** — OT stack, messaging, deliberately-vulnerable web apps.

**Tier 3 (`--profile databases-heavy --profile orchestration --profile monitoring --profile ci`)** — oracle, db2, mssql, k3s, jenkins, zabbix.

**Tier 4 (Vagrant)** — real AD, real IPMI, real iSCSI/NFSv4.

## Known gaps (services we can't credibly reproduce locally)

| Service | Reason | Mock credibility | Path |
|---|---|---|---|
| Real Siemens S7 CPU | Snap7 server mimics wire protocol but not job-catalog quirks | Medium — good for enum, poor for session-write | Ship snap7-server sim; mark firmware-specific tests `xfail` |
| Real IPMI BMC | virtualBMC covers ipmitool but not vendor SDR/OEM | Medium — covers 80% of `ipmi` scan | Vagrant VM with virtualBMC; OEM checks integration-only |
| vSphere/vCenter | Nested ESXi needs paid VMware Workstation + massive disk | None — protocol is proprietary | Skip. Wire tests to `RECCE_INT_VCENTER_URL` env var; skip otherwise |
| Real BGP peer AS | BIRD/FRR gets wire protocol but AS-path/community only means anything against real neighbor | High for probes, low for propagation | Ship BIRD route-server; deep propagation tests integration-only |
| Hikvision/Dahua RTSP cams | Vendor-specific onvif+PSIA quirks | RTSP sim (mediamtx) covers generic only | Ship mediamtx; vendor-quirk tests use captured pcaps |
| Real Cisco/Juniper (telnet/ssh) | Vendor motd/banner cues drive fingerprinting | Substitute with recorded banners | Already how svcprobe tests it — no infra needed |

For every "skip" service, the corresponding test file gets a `@pytest.mark.integration_live_target` marker so recce ships without pretending to test what it can't.

## Deliverable checklist

1. Split existing `test_env/docker-compose.yml` into profile files; retain all 29 current services.
2. Add ~28 native-image services with healthcheck + static IP.
3. Author 10 simulator Dockerfiles under `test_env/simulators/`.
4. Author `test_env/vagrant/Vagrantfile` + 3 provision scripts.
5. Add `tests/conftest.py` fixtures reading `RECCE_TEST_*` env; `@needs_compose` / `@needs_vagrant` skip markers.
6. Add `.github/workflows/testenv.yml` — Lane A (core) + Lane B (nightly full).
7. Rewrite `test_env/README.md` — MVP quick-start, profile matrix, Vagrant instructions.

**Estimated effort: ~2 weeks**
- 9a (MVP + CI wiring): 4 days
- 9b (OT + simulator authoring): 5 days
- 9c (Vagrant + docs): 3 days
