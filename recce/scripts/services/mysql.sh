#!/usr/bin/env bash
# recce-service: MySQL/MariaDB (3306) - version, anon/empty auth, CVEs
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-3306}"; [ "$3" = "-a" ] && AGGR=1
svc_start "MYSQL" "$T" "$P"

B=$(banner "$T" "$P" 128 | tr -cd '[:print:]'); V=$(printf '%s' "$B" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
[ -n "$V" ] && info "server version: $V"
nse "$T" "$P" "mysql-info,mysql-empty-password,mysql-users,mysql-databases,mysql-variables"

if have mysql; then
  info "anonymous / root(blank) login test:"
  for u in root ''; do
    if mysql -h "$T" -P "$P" -u "$u" --connect-timeout=6 -e 'select version(); show databases;' 2>/dev/null | sed 's/^/      /' | grep -q .; then
      find_ "MySQL login with user='${u:-<anon>}' and NO password succeeds"
      mysql -h "$T" -P "$P" -u "$u" -e 'show databases;' 2>/dev/null | sed 's/^/      /'
      note "if FILE priv + secure_file_priv empty: LOAD_FILE('/etc/passwd') / INTO OUTFILE webshell"
      note "if running as root (Linux): lib_mysqludf_sys UDF -> sys_exec() as root"
      break
    fi
  done
fi
[ -n "$V" ] && case "$V" in 5.*) note "MySQL 5.x - check CVE-2012-2122 auth-bypass (repeated login race)";; esac
have searchsploit && [ -n "$V" ] && run searchsploit --disable-colour "mysql $V"

if aggr; then sec "MySQL brute (intrusive)"; need hydra && run hydra -l root -P /usr/share/wordlists/rockyou.txt -f "mysql://$T:$P"
else skip_aggr "hydra mysql brute"; fi
