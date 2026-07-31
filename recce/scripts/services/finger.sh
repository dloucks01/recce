#!/usr/bin/env bash
# recce-service: finger (79) - user enumeration
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-79}"; [ "$3" = "-a" ] && AGGR=1
svc_start "FINGER" "$T" "$P"

find_ "finger service exposed -> discloses local usernames, login times, home dirs"
nse "$T" "$P" "finger"
# Query a few common accounts directly over the socket.
for u in root admin user test guest ""; do
  R=$(printf '%s\r\n' "$u" | timeout 6 bash -c "exec 3<>/dev/tcp/$T/$P; cat >&3; head -c 400 <&3" 2>/dev/null | tr -d '\000')
  [ -n "$R" ] && { info "finger '$u':"; printf '%s\n' "$R" | sed 's/^/      /'; }
done
note "user list:  finger-user-enum.pl -U users.txt -t $T   (Kali /usr/share/...)"

if aggr; then sec "finger user brute (intrusive)"; need finger-user-enum && run finger-user-enum.pl -U /usr/share/wordlists/metasploit/unix_users.txt -t "$T"
else skip_aggr "finger-user-enum sweep"; fi
