#!/usr/bin/env bash
# recce-service: MongoDB (27017) - unauth access, DB dump
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-27017}"; [ "$3" = "-a" ] && AGGR=1
svc_start "MONGODB" "$T" "$P"

nse "$T" "$P" "mongodb-info,mongodb-databases"
MSH=$(command -v mongosh || command -v mongo)
if [ -n "$MSH" ]; then
  info "unauthenticated access test:"
  if "$MSH" --host "$T" --port "$P" --quiet --eval 'db.adminCommand({listDatabases:1}).databases.forEach(d=>print(d.name))' 2>/dev/null | grep -q .; then
    find_ "MongoDB allows UNAUTHENTICATED access -> full database read:"
    "$MSH" --host "$T" --port "$P" --quiet --eval 'db.adminCommand({listDatabases:1}).databases.forEach(d=>print("  "+d.name))' 2>/dev/null | sed 's/^/      /'
    note "dump a db:  mongodump --host $T --port $P --db <name> -o loot/"
    note "look for app creds, session tokens, PII in collections"
  else info "auth required (or unreachable)"; fi
else info "(no mongo/mongosh client - nmap NSE results above still apply)"; fi
note "version -> check CVEs (older builds bound to 0.0.0.0 with no auth by default)"
aggr || skip_aggr "(no default brute - Mongo creds are per-db; enumerate then target)"
