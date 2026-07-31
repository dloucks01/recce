#!/usr/bin/env bash
# recce-service: SNMP (161/udp) - community strings, system/route/process walk
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-161}"; [ "$3" = "-a" ] && AGGR=1
svc_header "SNMP" "$T" "$P"
info "SNMP is UDP - a TCP port check doesn't apply; probing communities directly"

COMMUNITIES="public private community manager admin cisco"
FOUND=""
if have snmpget; then
  for c in $COMMUNITIES; do
    R=$(snmpget -v2c -c "$c" -t 2 -r 1 "$T" 1.3.6.1.2.1.1.1.0 2>/dev/null)
    [ -n "$R" ] && { find_ "SNMP community string works: '$c' (v2c)"; FOUND="$c"; break; }
  done
elif have onesixtyone; then
  R=$(printf '%s\n' $COMMUNITIES | onesixtyone -c - "$T" 2>/dev/null | grep -i "\[")
  [ -n "$R" ] && { find_ "onesixtyone found a community:"; printf '%s\n' "$R" | sed 's/^/      /'; FOUND=$(printf '%s' "$R" | grep -oE '\[[^]]+\]' | tr -d '[]' | head -1); }
fi
[ -z "$FOUND" ] && { info "no default community answered (try -a for a bigger community list)"; }

if [ -n "$FOUND" ]; then
  note "guessable community = full read of device config (v1/v2c send it in cleartext)"
  if have snmp-check; then info "snmp-check ($FOUND):"; run snmp-check -c "$FOUND" "$T"
  elif have snmpwalk; then
    info "system:";    run snmpwalk -v2c -c "$FOUND" "$T" 1.3.6.1.2.1.1
    info "processes:"; run snmpwalk -v2c -c "$FOUND" "$T" 1.3.6.1.2.1.25.4.2.1.2
    info "software:";  run snmpwalk -v2c -c "$FOUND" "$T" 1.3.6.1.2.1.25.6.3.1.2
    note "also: users (1.3.6.1.4.1.77.1.2.25), TCP ports, and full config for network gear"
  fi
fi
nse "$T" "$P" "snmp-info,snmp-sysdescr"

if aggr; then sec "Community brute (intrusive)"; need onesixtyone && run onesixtyone -c /usr/share/wordlists/seclists/Discovery/SNMP/common-snmp-community-strings.txt "$T"
else skip_aggr "onesixtyone full community wordlist"; fi
