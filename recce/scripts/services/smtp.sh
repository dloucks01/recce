#!/usr/bin/env bash
# recce-service: SMTP (25/465/587) - relay, VRFY user-enum, STARTTLS
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-25}"; [ "$3" = "-a" ] && AGGR=1
svc_start "SMTP" "$T" "$P"

B=$(banner "$T" "$P" 256 | head -3); [ -n "$B" ] && { info "banner:"; printf '%s\n' "$B" | sed 's/^/      /'; }
nse "$T" "$P" "smtp-commands,smtp-open-relay,smtp-ntlm-info,smtp-strangeport"

# Does it advertise VRFY / EXPN (user enumeration)?
if have nc; then
  CAP=$(printf 'EHLO recce\r\nQUIT\r\n' | timeout 8 nc -w6 "$T" "$P" 2>/dev/null)
  printf '%s\n' "$CAP" | grep -qiE 'STARTTLS' && info "STARTTLS supported"
  printf '%s\n' "$CAP" | grep -qiE 'VRFY'     && find_ "VRFY advertised -> username enumeration (smtp-user-enum -M VRFY)"
  printf '%s\n' "$CAP" | grep -qiE 'EXPN'     && find_ "EXPN advertised -> mailing-list/username disclosure"
  printf '%s\n' "$CAP" | grep -qiE 'AUTH .*(PLAIN|LOGIN)' && ! printf '%s' "$CAP" | grep -qi STARTTLS && find_ "AUTH offered without STARTTLS -> credentials would cross in cleartext"
fi
case "$B" in *Exim\ 4.[0-8]*) find_ "Exim $B -> check CVE-2019-10149 (RCE) and the 4.87-4.91 local-root chain";; esac

if aggr; then
  sec "SMTP user enumeration (intrusive)"
  need smtp-user-enum && run smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t "$T" -p "$P"
else skip_aggr "smtp-user-enum VRFY spraying"; fi
