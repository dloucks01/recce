#!/usr/bin/env bash
# recce-service: POP3/IMAP (110/143/993/995) - capabilities, STARTTLS, auth
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-110}"; [ "$3" = "-a" ] && AGGR=1
svc_start "POP3/IMAP" "$T" "$P"

B=$(banner "$T" "$P" 256 | head -2); [ -n "$B" ] && { info "banner:"; printf '%s\n' "$B" | sed 's/^/      /'; }
case "$P" in
  110|995) KIND=pop3; nse "$T" "$P" "pop3-capabilities,pop3-ntlm-info";;
  143|993) KIND=imap; nse "$T" "$P" "imap-capabilities,imap-ntlm-info";;
  *)       KIND=mail; nse "$T" "$P" "banner";;
esac
case "$P" in 993|995) info "implicit TLS port";; 110|143) info "cleartext port - look for STARTTLS in caps below";; esac

if have nc; then
  if [ "$KIND" = pop3 ]; then C=$(printf 'CAPA\r\nQUIT\r\n' | timeout 8 nc -w6 "$T" "$P" 2>/dev/null)
  else C=$(printf 'a1 CAPABILITY\r\na2 LOGOUT\r\n' | timeout 8 nc -w6 "$T" "$P" 2>/dev/null); fi
  [ -n "$C" ] && { info "capabilities:"; printf '%s\n' "$C" | sed 's/^/      /' | head -12; }
  printf '%s' "$C" | grep -qi STARTTLS || case "$P" in 110|143) find_ "no STARTTLS on a cleartext mail port -> creds sniffable; brute-able (auth)";; esac
  printf '%s' "$C" | grep -qiE 'USER|LOGIN|PLAIN' && info "password auth available"
fi
have searchsploit && [ -n "$B" ] && run searchsploit --disable-colour $(printf '%s' "$B" | grep -oiE 'dovecot|courier|cyrus|exchange' | head -1)

if aggr; then sec "Mailbox brute (intrusive)"; need hydra && run hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f "$([ "$KIND" = pop3 ] && echo pop3 || echo imap)://$T:$P"
else skip_aggr "hydra mailbox brute (needs users.txt)"; fi
