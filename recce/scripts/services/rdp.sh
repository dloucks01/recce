#!/usr/bin/env bash
# recce-service: RDP (3389) - NLA state, BlueKeep, NTLM info
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-3389}"; [ "$3" = "-a" ] && AGGR=1
svc_start "RDP" "$T" "$P"

nse "$T" "$P" "rdp-ntlm-info,rdp-enum-encryption"
note "rdp-ntlm-info leaks the hostname, domain (DNS + NetBIOS) and OS build - use for spraying/relay context"

# NLA off => broader pre-auth surface (and some CVEs).
if have nmap; then
  E=$(nmap -Pn -p "$P" --script rdp-enum-encryption "$T" 2>/dev/null)
  printf '%s' "$E" | grep -qi 'CredSSP (NLA): SUPPORTED' || find_ "NLA does not appear enforced -> pre-auth attack surface (incl. BlueKeep)"
fi
nse "$T" "$P" "rdp-vuln-ms12-020"
find_ "Test BlueKeep CVE-2019-0708 on legacy Windows (7/2008 R2 and older): metasploit auxiliary/scanner/rdp/cve_2019_0708_bluekeep"
note "with creds: xfreerdp /v:$T /u:USER /p:PASS +clipboard   (check for RDP as a login vector after spray)"

if aggr; then sec "RDP brute (intrusive)"; need hydra && run hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f "rdp://$T:$P"
else skip_aggr "hydra rdp brute (lockout risk - needs users.txt)"; fi
