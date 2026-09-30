#!/usr/bin/env bash
# recce-service: SSH (22) - version, algos, auth methods, user-enum CVEs
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-22}"; [ "$3" = "-a" ] && AGGR=1
svc_start "SSH" "$T" "$P"

B=$(banner "$T" "$P" 128 | head -1); [ -n "$B" ] && info "banner: $B"
nse "$T" "$P" "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods,sshv1"

# Auth methods actually offered (password auth => brute/spray surface).
if have ssh; then
  M=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o PreferredAuthentications=none \
        -o ConnectTimeout=6 -p "$P" "invaliduser@$T" 2>&1 | grep -oiE 'password|publickey|keyboard-interactive|gssapi[^ ]*' | sort -u | tr '\n' ' ')
  [ -n "$M" ] && info "auth methods offered: $M"
  printf '%s' "$M" | grep -qi password && { find_ "password authentication enabled -> credential brute/spray possible"; aggr || note "brute with -a (hydra)"; }
fi

# Version -> known issues.
V=$(printf '%s' "$B" | grep -oiE 'OpenSSH[_ ][0-9]+\.[0-9]+([p0-9]*)' | head -1)
maj=$(printf '%s' "$V" | grep -oE '[0-9]+\.[0-9]+' | head -1)
if [ -n "$maj" ]; then
  awk "BEGIN{exit !($maj < 7.7)}" && find_ "OpenSSH $V < 7.7 -> username enumeration CVE-2018-15473 (public PoC)"
  awk "BEGIN{exit !($maj < 8.5)}" && info "OpenSSH $V < 8.5 -> review CVE-2020-14145 (MITM info-leak) and Terrapin CVE-2023-48795 (algo downgrade)"
fi
printf '%s' "$B" | grep -qi 'libssh' && find_ "libssh banner -> if 0.6-0.8.3, auth-bypass CVE-2018-10933 (metasploit auxiliary/scanner/ssh/libssh_auth_bypass)"
have searchsploit && [ -n "$V" ] && run searchsploit --disable-colour "$V"

aggr && { sec "SSH brute (intrusive)"; need hydra && run hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -f -t 4 "ssh://$T:$P"; } || skip_aggr "hydra credential brute"
