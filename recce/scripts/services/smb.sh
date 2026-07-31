#!/usr/bin/env bash
# recce-service: SMB (139/445) - shares, null session, signing, EternalBlue et al
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-445}"; [ "$3" = "-a" ] && AGGR=1
svc_start "SMB" "$T" "$P"

nse "$T" "$P" "smb-os-discovery,smb-security-mode,smb2-security-mode,smb-protocols,smb2-time,smb-enum-shares,smb-enum-users"

# Signing (relay precondition) + protocol.
if have nmap; then
  SM=$(nmap -Pn -p "$P" --script smb2-security-mode "$T" 2>/dev/null)
  printf '%s' "$SM" | grep -qi 'signing.*not required\|message signing enabled but not required' && find_ "SMB signing NOT required -> NTLM relay target (ntlmrelayx)"
fi

# Null / guest session -> shares + users.
if have smbclient; then
  info "null-session share list (smbclient -N -L):"
  NL=$(smbclient -N -L "//$T" 2>/dev/null); printf '%s\n' "$NL" | sed 's/^/      /' | head -30
  printf '%s' "$NL" | grep -qiE 'Disk|IPC' && find_ "Null session lists shares -> anonymous SMB access"
fi
if have netexec || have nxc || have crackmapexec; then
  CME=$(command -v netexec || command -v nxc || command -v crackmapexec)
  info "netexec overview:"; run "$CME" smb "$T" --shares -u '' -p ''
  note "as guest:  $CME smb $T -u guest -p '' --shares --users --pass-pol"
fi
if have rpcclient; then
  U=$(rpcclient -U '' -N "$T" -c 'enumdomusers' 2>/dev/null)
  [ -n "$U" ] && { find_ "Anonymous RID/user enumeration via rpcclient:"; printf '%s\n' "$U" | sed 's/^/      /' | head -20; }
fi
have enum4linux-ng && { info "enum4linux-ng (summary):"; run enum4linux-ng -A "$T"; }

# The big SMB vulns.
sec "SMB vulnerability scripts"
nse "$T" "$P" "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2020-0796,smb-vuln-cve2009-3103,smb-vuln-regsvc-dos"
note "ms17-010=EternalBlue (metasploit ms17_010_eternalblue), cve-2020-0796=SMBGhost, ms08-067 legacy"

if aggr; then sec "SMB password spray (intrusive)"; [ -n "$CME" ] && run "$CME" smb "$T" -u users.txt -p passwords.txt --continue-on-success
else skip_aggr "netexec password spray (needs users.txt/passwords.txt)"; fi
