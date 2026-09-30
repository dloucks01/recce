#!/usr/bin/env bash
# recce-service: Elasticsearch (9200) - unauth API, index dump
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-9200}"; [ "$3" = "-a" ] && AGGR=1
svc_start "ELASTIC" "$T" "$P"

if have curl; then
  info "cluster banner:"; run curl -sSk -m 8 "http://$T:$P/"
  if curl -sSk -m 8 "http://$T:$P/_cat/indices?v" 2>/dev/null | grep -qiE 'health|open'; then
    find_ "Elasticsearch API is UNAUTHENTICATED -> read every index:"
    run curl -sSk -m 8 "http://$T:$P/_cat/indices?v"
    note "dump an index:  curl -s 'http://$T:$P/<index>/_search?pretty&size=100'"
    note "indices often hold logs, app data, PII, credentials"
  fi
  V=$(curl -sSk -m 8 "http://$T:$P/" 2>/dev/null | grep -oE '"number"[ :]*"[0-9.]+"' | grep -oE '[0-9.]+' | head -1)
  [ -n "$V" ] && case "$V" in 1.*|5.*) find_ "Elasticsearch $V (old) -> Groovy/MVEL sandbox RCE (CVE-2014-3120 / CVE-2015-1427)";; esac
else info "(curl not installed)"; fi
aggr || skip_aggr "(no brute - target the unauth API or a known version CVE)"
