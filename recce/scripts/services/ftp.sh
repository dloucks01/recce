#!/usr/bin/env bash
# recce-service: FTP (21) - anon login, bounce, version backdoors
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-21}"; [ "$3" = "-a" ] && AGGR=1
svc_start "FTP" "$T" "$P"

B=$(banner "$T" "$P" 256); [ -n "$B" ] && { info "banner:"; printf '%s\n' "$B" | sed 's/^/      /'; }

# Anonymous access is the #1 FTP win - check it directly and via NSE.
nse "$T" "$P" "ftp-anon,ftp-syst,ftp-bounce"
if have curl; then
  if curl -s --max-time 8 "ftp://$T:$P/" --user 'anonymous:anonymous@recce' -l >/tmp/.ftpanon 2>/dev/null; then
    find_ "Anonymous FTP login accepted -> readable listing:"; sed 's/^/      /' /tmp/.ftpanon; rm -f /tmp/.ftpanon
    note "download all:  wget -m --no-passive ftp://anonymous:anon@$T:$P/"
    aggr && note "test anon UPLOAD (write) with:  curl -T probe.txt ftp://$T:$P/ --user anonymous:anon@x"
  fi
fi

# Version -> known backdoors / CVEs.
case "$B" in
  *vsFTPd\ 2.3.4*) find_ "vsftpd 2.3.4 -> smiley-face backdoor (OSVDB-73573); metasploit exploit/unix/ftp/vsftpd_234_backdoor";;
  *ProFTPD\ 1.3.3c*) find_ "ProFTPD 1.3.3c -> backdoor (compromised source); searchsploit proftpd 1.3.3c";;
  *ProFTPD\ 1.3.[0-5]*) find_ "ProFTPD $B -> check mod_copy RCE CVE-2015-3306 (SITE CPFR/CPTO)";;
  *Pure-FTPd*) info "Pure-FTPd - check CVE-2011-0988 / config for chroot escape";;
esac
have searchsploit && [ -n "$B" ] && { info "exploit search:"; run searchsploit --disable-colour $(printf '%s' "$B" | grep -oiE '[a-z-]*ftpd?[ /][0-9.]+' | head -1); }

aggr && { sec "FTP brute (intrusive)"; need hydra && run hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt -f -t 4 "ftp://$T:$P"; } || skip_aggr "hydra credential brute"
