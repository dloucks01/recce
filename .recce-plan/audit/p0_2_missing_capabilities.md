# P0-2 audit-vs-implementation gap list

Produced by the P0-2 scanner. These are audit entries (from
`.recce-plan/depth-audit/<svc>.json`) at severity ∈ {medium, low, info}
whose `kind=` string does NOT appear in the current service module.
They are **missing capabilities** — the audit expected the module to
emit them and it does not — which is P2-1 (Phase 5a deferred
capabilities) territory, not exploit_note attachment work.

Kept here as a discoverable checklist so a future capability-build
pass has a concrete starting point rather than re-reading every
audit file to derive it.

**Generated:** 2026-09-03
**Scanner:** `scratchpad/p0_2_scanner.py`

## By service

### api (7 missing kinds)
- `api-spec-creds`
- `api-openapi-spec-exposed`
- `api-graphql-introspection`
- `api-graphql-batch`
- `api-soap-wsdl-exposed`
- `api-grpc-reflection`
- `api-swagger-ui-exposed`

### http (10 missing kinds)
- `http-method-trace`
- `http-method-writable`
- `http-cache-poison`
- `http-webdav`
- `http-open-redirect`
- `http-api-spec`
- `http-directory-listing`
- `http-forms`
- `http-default-creds`
- `http-header-hygiene`

### web (6 missing kinds)
- `web-sourcemap`
- `web-cookie`
- `web-security-headers / web-csp`
- `web-admin-panel`
- `web-vhost`
- `web-csrf / web-form-unfuzzed / web-cleartext-login`

### singletons (7 remaining kinds)
- **cloud_metadata:** `imdsv2_hop_limit_too_high`
- **coap:** `coap_empty_ping`
- **ftp:** `ftp_extra_commands_disclosed`
- **influxdb:** `influxdb_version`
- **mysql:** `mysql_cve_cve_2021_2154`
- **snmp:** `snmp_community`
- **xmpp:** `xmpp_muc_public_rooms`

## Totals

- Audit candidates at medium/low/info: **302**
- Already had exploit_note + depth_tier: **271** (89.7%)
- Missing capabilities in module (this list): **30** (10.0%)
- Attachments actually shipped in P0-2: **6** (0.3%)

## Recommendation

Cherry-pick, don't fan-out. Each entry represents a distinct probe
that has to be designed + implemented + tested — not a mechanical
annotation like P0-2's shipped work. Order by realistic engagement
value:

1. **http-method-trace** — one-line TRACE OPTIONS probe, high XSS-
   chain value → medium effort
2. **web-security-headers / web-csp** — pure header inspection, no
   new tool needed → small effort
3. **api-openapi-spec-exposed** — GET /openapi.json / /swagger.json,
   fingerprint + credential extraction from spec → small effort
4. **api-swagger-ui-exposed** — same shape, small effort
5. **api-graphql-introspection** — POST introspection query → small
6. **snmp_community** — CVE gate on default communities (already
   partially covered by SNMP module) → tiny effort
7. Rest as engagement demand surfaces.
