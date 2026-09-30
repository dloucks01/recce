#!/usr/bin/env bash
# recce-service: AJP (8009) - Tomcat connector, Ghostcat CVE-2020-1938
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-8009}"; [ "$3" = "-a" ] && AGGR=1
svc_start "AJP" "$T" "$P"

find_ "AJP (8009) open -> Tomcat/JBoss connector; test Ghostcat CVE-2020-1938 (file read / RCE)"
nse "$T" "$P" "ajp-methods,ajp-headers"
note "Ghostcat read:   metasploit auxiliary/admin/http/tomcat_ghostcat  (reads WEB-INF/web.xml -> creds)"
note "Ghostcat -> RCE: if the app allows file upload, the read primitive becomes JSP include -> code exec"
note "public PoC:      ajpShooter.py $T $P /  read"
aggr || skip_aggr "(Ghostcat exploitation is manual - confirm the read primitive first)"
