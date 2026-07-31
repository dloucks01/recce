# recce/scripts — per-service enumeration & vuln-ID

Kali-side scripts that take a service recce (or nmap/masscan) found and run the
**right** enumeration for it, flagging likely vulnerabilities and pointing at the
existing tool that exploits each. These complement the two other script sets:

| Where it runs | Scripts | Purpose |
|---|---|---|
| Kali, against a target | **`recce/scripts/`** (this dir) | per-service enum + vuln ID |
| On a shell you already have | `recce/local/` | local priv-esc enumeration |
| Kali, orchestrating | `recce` (the Python tool) | scan → workbook → reports |

## Safe by default

Everything here is **read-only / non-intrusive by default**: banner grabs,
version and capability queries, anonymous / null-session checks, TLS posture,
NSE `safe`-category scripts, and config disclosure. The intrusive checks —
credential brute force, `nikto`, directory busting, user-enum spraying — only
run when you pass **`-a`**. Nothing generates exploit code; findings reference
existing tools (searchsploit, Metasploit modules, impacket, netexec, GTFOBins).

Missing tools self-skip with a note, so a script never dies because one Kali
package isn't installed.

## Usage

```bash
cd recce/scripts

./recce-service.sh list                       # every service script + what it does
./recce-service.sh smb 10.0.10.5              # one service (port defaults per service)
./recce-service.sh http 10.0.10.5 8080        # explicit port
./recce-service.sh auto 10.0.10.5 6379        # pick the script by port number
./recce-service.sh -a http 10.0.10.5          # include intrusive checks (nikto, dirbust)

# Sweep an ENTIRE nmap/masscan scan - runs the matching enum for every open port:
./recce-service.sh from-nmap scan.xml                 # nmap -oX / masscan -oX / rustscan
./recce-service.sh from-nmap scan.gnmap other.nmap    # -oG and -oN too; multiple files
./recce-service.sh from-nmap eng/raw/*.xml            # point it at recce's own raw scans
./recce-service.sh from-nmap -a scan.gnmap            # intrusive sweep
```

Each script is also runnable on its own: `./services/redis.sh 10.0.10.5`.

## Services covered

`ftp ssh telnet smtp dns finger http pop-imap rpc-nfs msrpc smb kerberos ldap
snmp mssql mysql postgres rdp vnc redis winrm mongodb oracle ajp elasticsearch`

Unknown service/port in a scan? `from-nmap` prints the manual `nmap -sV
--script vuln` fallback for it so nothing is silently skipped.

## Output

Consistent with the rest of recce: `[+]` reachable/confirmed, `[!]` a finding
worth attention, `# …` a next-step hint (the tool + command that acts on it).
Redirect to a file to keep it: `./recce-service.sh smb 10.0.10.5 > smb-10.0.10.5.txt`.

## Typical flow

```bash
sudo ./bin/recce enum 10.0.10.0/24 -o eng          # recce finds the hosts/ports
./scripts/recce-service.sh from-nmap eng/raw/*.xml # deep per-service enum on all of them
#   → work the [!] findings; use the # hints for the exploitation step
```
