#!/usr/bin/env bash
# recce-service.sh - per-service enumeration + vuln-ID driver (run from Kali).
#
# recce finds open ports; this drives the RIGHT enumeration for each service and
# flags likely vulnerabilities. Read-only / safe by default; add -a for the
# intrusive checks (brute force, nikto, dir busting, user-enum spraying).
#
# Usage:
#   recce-service.sh list
#   recce-service.sh <service> <target> [port] [-a]     # e.g. smb 10.0.0.5
#   recce-service.sh auto <target> <port> [-a]          # pick by port number
#   recce-service.sh from-nmap [-a] <scan.xml|.gnmap|.nmap> [more...]
#       run the matching enumeration for EVERY open port in an nmap/masscan file
#       (masscan -oX and rustscan produce nmap-compatible XML). Point it straight
#       at recce's own raw/*.xml if you like.
#
# Examples:
#   sudo ./recce-service.sh smb 10.0.10.5
#   ./recce-service.sh from-nmap eng/raw/*.xml
#   ./recce-service.sh from-nmap -a scan.gnmap        # intrusive sweep

set -o pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
SVCDIR="$HERE/services"
. "$HERE/lib.sh"

# --- service-name (nmap) -> script -------------------------------------------
name_to_svc() {
  case "$1" in
    ftp|ftp-data) echo ftp;;
    ssh) echo ssh;;
    telnet) echo telnet;;
    smtp|smtps|submission) echo smtp;;
    domain|dns) echo dns;;
    finger) echo finger;;
    http|http-proxy|http-alt|https|ssl/http|https-alt|http-mgmt) echo http;;
    kerberos|kerberos-sec|kpasswd) echo kerberos;;
    pop3|pop3s|imap|imaps) echo pop-imap;;
    rpcbind|nfs|nfs_acl|mountd) echo rpc-nfs;;
    msrpc|epmap) echo msrpc;;
    netbios-ssn|microsoft-ds|smb) echo smb;;
    ldap|ldaps|globalcatLDAP|globalcatLDAPssl) echo ldap;;
    snmp|snmptrap) echo snmp;;
    ms-sql-s|ms-sql|mssql) echo mssql;;
    mysql|mariadb) echo mysql;;
    postgresql|postgres) echo postgres;;
    ms-wbt-server|rdp|ms-term-serv) echo rdp;;
    vnc|vnc-http) echo vnc;;
    redis) echo redis;;
    wsman|winrm) echo winrm;;
    mongodb|mongod) echo mongodb;;
    oracle|oracle-tns|ncube-lm) echo oracle;;
    ajp13|ajp) echo ajp;;
    elasticsearch|wap-wsp) echo elasticsearch;;
    *) echo "";;
  esac
}

# --- port number -> script (fallback when the service name is unknown) --------
port_to_svc() {
  case "$1" in
    21) echo ftp;; 22) echo ssh;; 23) echo telnet;;
    25|465|587) echo smtp;; 53) echo dns;; 79) echo finger;;
    80|81|8000|8008|8080|8081|8443|8888|443) echo http;;
    88) echo kerberos;;
    110|143|993|995) echo pop-imap;;
    111|2049) echo rpc-nfs;; 135) echo msrpc;;
    139|445) echo smb;;
    389|636|3268|3269) echo ldap;;
    161) echo snmp;;
    1433|1434) echo mssql;; 3306) echo mysql;; 5432) echo postgres;;
    3389) echo rdp;; 5900|5901|5902) echo vnc;;
    6379) echo redis;; 5985|5986) echo winrm;;
    27017|27018) echo mongodb;; 1521|1522) echo oracle;;
    8009) echo ajp;; 9200|9300) echo elasticsearch;;
    *) echo "";;
  esac
}

run_svc() {  # run_svc <script> <target> <port>
  local s="$SVCDIR/$1.sh"
  if [ ! -f "$s" ]; then info "(no enumeration script for '$1' yet)"; return; fi
  AGGR="$AGGR" bash "$s" "$2" "$3"
}

list_services() {
  echo "Available service enumeration scripts (recce/scripts/services/):"
  for f in "$SVCDIR"/*.sh; do
    [ -f "$f" ] || continue
    n=$(basename "$f" .sh)
    d=$(grep -m1 '^# recce-service:' "$f" | sed 's/^# recce-service:[[:space:]]*//')
    printf '  %-14s %s\n' "$n" "$d"
  done
  echo
  echo "Run one:      recce-service.sh <service> <target> [port] [-a]"
  echo "By port:      recce-service.sh auto <target> <port>"
  echo "Whole scan:   recce-service.sh from-nmap <scan.xml|.gnmap|.nmap>"
}

# --- extract "ip port service" from an nmap/masscan output file ---------------
# Portable awk (works with mawk, gawk, and BWK awk - no capture-array extension).
extract_targets() {
  local f="$1"
  case "$f" in
    *.xml)
      awk '
        /<address addr="/ { s=$0; sub(/.*<address addr="/,"",s); sub(/".*/,"",s); if(s ~ /^[0-9.]+$/) ip=s }
        /<port / { s=$0; sub(/.*portid="/,"",s); sub(/".*/,"",s); port=s; svc=""; open=0 }
        /state="open"/ { open=1 }
        /<service name="/ { s=$0; sub(/.*<service name="/,"",s); sub(/".*/,"",s); svc=s }
        /<\/port>/ { if(open && ip && port) print ip, port, (svc?svc:"?") }
      ' "$f" 2>/dev/null ;;
    *.gnmap|*.grep)
      awk -F'\t' '/Host: /{
        split($1,h," "); ip=h[2];
        for(i=1;i<=NF;i++) if($i ~ /Ports:/){
          n=split($i,parts,","); for(j=1;j<=n;j++){split(parts[j],pp,"/");
            gsub(/[^0-9]/,"",pp[1]); if(pp[2]=="open")print ip, pp[1], (pp[5]?pp[5]:"?")}}}' "$f" 2>/dev/null ;;
    *)
      awk '/Nmap scan report for/{ip=$NF; gsub(/[()]/,"",ip)}
           /^[0-9]+\/tcp[ \t]+open/{split($1,pp,"/"); print ip, pp[1], ($3?$3:"?")}' "$f" 2>/dev/null ;;
  esac
}

from_nmap() {
  local total=0 handled=0
  for f in "$@"; do
    [ -f "$f" ] || { echo "skip (not a file): $f"; continue; }
    sec "Parsing $f"
    while read -r ip port svc; do
      [ -z "$ip" ] && continue
      total=$((total+1))
      local script; script=$(name_to_svc "$svc"); [ -z "$script" ] && script=$(port_to_svc "$port")
      case "$port" in 5985|5986) script=winrm;; esac   # nmap labels WinRM as http

      if [ -n "$script" ]; then
        handled=$((handled+1)); run_svc "$script" "$ip" "$port"
      else
        info "no enumeration mapping for $ip:$port ($svc) - run nmap -sV --script vuln -p $port $ip manually"
      fi
    done < <(extract_targets "$f" | sort -u)
  done
  sec "Sweep complete"
  info "$handled of $total open services enumerated."
  [ "$AGGR" = "1" ] || note "safe mode - re-run with -a for brute force / nikto / dir busting"
}

# --- argument handling --------------------------------------------------------
[ $# -eq 0 ] && { list_services; exit 0; }

# pull a global -a out of the args
ARGS=(); for a in "$@"; do [ "$a" = "-a" ] && AGGR=1 || ARGS+=("$a"); done
set -- "${ARGS[@]}"
export AGGR

cmd="$1"; shift || true
case "$cmd" in
  list|help|-h|--help) list_services;;
  from-nmap|nmap) [ $# -eq 0 ] && { echo "usage: recce-service.sh from-nmap <file...>"; exit 1; }; from_nmap "$@";;
  auto)
    [ -z "$2" ] && { echo "usage: recce-service.sh auto <target> <port>"; exit 1; }
    s=$(port_to_svc "$2"); [ -z "$s" ] && { echo "no mapping for port $2"; exit 1; }
    run_svc "$s" "$1" "$2";;
  *)
    # treat cmd as a service name: recce-service.sh <service> <target> [port]
    if [ -f "$SVCDIR/$cmd.sh" ]; then
      [ -z "$1" ] && { echo "usage: recce-service.sh $cmd <target> [port]"; exit 1; }
      bash "$SVCDIR/$cmd.sh" "$@"
    else
      echo "unknown service/command: $cmd"; echo; list_services; exit 1
    fi;;
esac
