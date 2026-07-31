#!/usr/bin/env bash
# recce-service: Telnet (23) - banner, encryption, default creds
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-23}"; [ "$3" = "-a" ] && AGGR=1
svc_start "TELNET" "$T" "$P"

find_ "Telnet is cleartext -> credentials and sessions are sniffable on-path"
B=$(banner "$T" "$P" 512); [ -n "$B" ] && { info "banner/prompt:"; printf '%s\n' "$B" | tr -d '\377\375\373\376\374' | sed 's/^/      /'; }
nse "$T" "$P" "telnet-encryption,telnet-ntlm-info,banner"

case "$B" in
  *[Cc]isco*)  note "Cisco device - try default enable / 'cisco'/'cisco'; check for IOS creds";;
  *[Bb]usy[Bb]ox*|*[Dd]link*|*[Nn]etgear*) find_ "Embedded/IoT telnet - very likely default or hardcoded creds (admin/admin, root/<blank>)";;
esac
note "device default creds: check the vendor from the banner against a defaults list"

aggr && { sec "Telnet brute (intrusive)"; need hydra && run hydra -l root -P /usr/share/wordlists/rockyou.txt -f -t 4 "telnet://$T:$P"; } || skip_aggr "hydra credential brute"
