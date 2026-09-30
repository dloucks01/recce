#!/usr/bin/env bash
# recce-service: MSRPC endpoint mapper (135) - interface enumeration
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-135}"; [ "$3" = "-a" ] && AGGR=1
svc_start "MSRPC" "$T" "$P"

nse "$T" "$P" "msrpc-enum,rpc-grind"
if have impacket-rpcdump || have rpcdump.py; then
  BIN=$(command -v impacket-rpcdump || command -v rpcdump.py)
  info "RPC endpoint dump:"; run "$BIN" "$T"
  note "look for MS-RPRN (spooler -> PrinterBug), MS-EFSR (PetitPotam), MS-DFSNM -> NTLM relay to AD CS/LDAP"
else info "(impacket rpcdump not found - install impacket for endpoint enumeration)"; fi
note "coerce+relay:  PetitPotam.py / printerbug.py + ntlmrelayx -t ldap://DC --escalate-user (needs a relay target)"
aggr || skip_aggr "(MSRPC coercion is a relay attack - run manually with a target)"
