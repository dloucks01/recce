#!/usr/bin/env bash
# recce-service: LDAP (389/636) - anonymous bind, rootDSE, naming contexts
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-389}"; [ "$3" = "-a" ] && AGGR=1
svc_start "LDAP" "$T" "$P"

PROTO=ldap; [ "$P" = 636 ] || [ "$P" = 3269 ] && PROTO=ldaps
nse "$T" "$P" "ldap-rootdse,ldap-search"

if have ldapsearch; then
  info "rootDSE (anonymous):"
  RD=$(ldapsearch -x -H "$PROTO://$T:$P" -s base -b '' '+' 2>/dev/null)
  printf '%s\n' "$RD" | grep -iE 'namingContexts|defaultNamingContext|dnsHostName|domainFunctionality|supportedLDAPVersion' | sed 's/^/      /'
  BASE=$(printf '%s' "$RD" | grep -i 'defaultNamingContext:' | head -1 | awk '{print $2}')
  [ -z "$BASE" ] && BASE=$(printf '%s' "$RD" | grep -i 'namingContexts:' | head -1 | awk '{print $2}')
  info "base DN: ${BASE:-<none>}"
  if [ -n "$BASE" ]; then
    info "anonymous search under $BASE (first objects):"
    AN=$(ldapsearch -x -H "$PROTO://$T:$P" -b "$BASE" -s sub '(objectClass=*)' dn 2>/dev/null | grep -i '^dn:' | head -20)
    if [ -n "$AN" ]; then find_ "Anonymous LDAP bind returns directory data:"; printf '%s\n' "$AN" | sed 's/^/      /'
      note "dump users:  ldapsearch -x -H $PROTO://$T:$P -b '$BASE' '(objectClass=user)' sAMAccountName description"
      note "creds in description fields are common; also windapsearch / bloodhound-python for full AD map"
    else info "  anonymous bind returned no entries (auth likely required)"; fi
  fi
else info "(ldapsearch not installed - apt install ldap-utils)"; fi
[ "$PROTO" = ldap ] && note "389 is cleartext - binds/creds are sniffable; prefer 636 for real auth"

aggr || skip_aggr "(LDAP has no default brute step - use netexec ldap with creds)"
