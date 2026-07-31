#!/usr/bin/env bash
# recce-service: DNS (53) - zone transfer, version, recursion
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-53}"; [ "$3" = "-a" ] && AGGR=1
svc_header "DNS" "$T" "$P"
port_open "$T" "$P" || info "TCP $P closed (DNS often UDP-only) - AXFR needs TCP; queries below use UDP"

# version.bind (fingerprint the resolver).
have dig && { info "version.bind:"; run dig +short chaos txt version.bind "@$T"; }

# Zone transfer - the classic DNS jackpot. Needs a domain; derive candidates.
DOMS=""
have dig && DOMS=$(dig +short -x "$T" "@$T" 2>/dev/null | sed 's/\.$//' | sed 's/^[^.]*\.//')
for d in $DOMS $EXTRA_DOMAINS; do
  [ -z "$d" ] && continue
  info "AXFR attempt for $d:"
  if have dig; then
    OUT=$(dig +noall +answer axfr "$d" "@$T" 2>/dev/null)
    if [ -n "$OUT" ]; then find_ "Zone transfer ALLOWED for $d -> full internal DNS:"; printf '%s\n' "$OUT" | sed 's/^/      /' | head -60
    else info "  refused (good)"; fi
  fi
done
[ -z "$DOMS" ] && note "no domain auto-derived - retry with:  EXTRA_DOMAINS='corp.local' $0 $T"

nse "$T" "$P" "dns-nsid,dns-recursion,dns-zone-transfer"
have dig && { R=$(dig +short recursion.test "@$T" 2>/dev/null); info "recursion probe returned: ${R:-<none>}"; note "open recursion -> cache-poisoning / amplification (DDoS) surface"; }

if aggr; then sec "Subdomain brute (intrusive)"; need dnsrecon && run dnsrecon -d "${DOMS%% *}" -n "$T" -t brt
else skip_aggr "dnsrecon subdomain brute"; fi
