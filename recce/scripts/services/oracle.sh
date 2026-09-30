#!/usr/bin/env bash
# recce-service: Oracle TNS (1521) - version, SID enumeration
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-1521}"; [ "$3" = "-a" ] && AGGR=1
svc_start "ORACLE" "$T" "$P"

nse "$T" "$P" "oracle-tns-version,oracle-sid-brute"
note "you need a SID to attack Oracle - the NSE sid-brute above tries common ones"
if have odat; then
  info "odat all (safe checks):"; run odat all -s "$T" -p "$P"
else info "(odat not installed -> 'apt install odat' or use it from the Kali repo for full Oracle testing)"; fi
note "with a SID:  odat sidguesser / passwordguesser -> then utlfile / externaltable / dbmsscheduler for RCE"
note "default accounts to try once you have a SID: scott/tiger, system/manager, sys/change_on_install, dbsnmp/dbsnmp"

if aggr && have odat; then sec "Oracle SID + password guess (intrusive)"; run odat sidguesser -s "$T" -p "$P"
else skip_aggr "odat SID/password guessing"; fi
