#!/usr/bin/env bash
# recce-service: HTTP/HTTPS (80/443/8080/...) - headers, methods, TLS, tech, paths
. "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
T="$1"; P="${2:-80}"; [ "$3" = "-a" ] && AGGR=1
svc_start "HTTP" "$T" "$P"

# Decide scheme by port / by probing TLS.
SCHEME=http
case "$P" in 443|8443|8843|9443) SCHEME=https;; esac
if [ "$SCHEME" = http ] && have openssl; then
  echo | timeout 5 openssl s_client -connect "$T:$P" >/dev/null 2>&1 && SCHEME=https
fi
URL="$SCHEME://$T:$P/"
info "base URL: $URL"

if have curl; then
  info "response headers:"; run curl -sSk -m 10 -D - -o /dev/null "$URL"
  info "allowed methods (OPTIONS):"; run curl -sSk -m 10 -X OPTIONS -D - -o /dev/null "$URL"
  H=$(curl -sSk -m 10 -D - -o /dev/null "$URL" 2>/dev/null)
  printf '%s' "$H" | grep -qiE '^Server:' && info "$(printf '%s' "$H" | grep -iE '^Server:|^X-Powered-By:')"
  printf '%s' "$H" | grep -qi 'PUT\|DELETE' && find_ "Dangerous HTTP methods may be enabled (PUT/DELETE) -> test webshell upload"
  printf '%s' "$H" | grep -qiE '^WWW-Authenticate: *Basic' && { find_ "HTTP Basic auth -> credentials cross the wire (base64); brute-able"; aggr || note "brute with -a"; }
  # Common quick-win paths.
  info "quick path probe:"
  for path in robots.txt .git/HEAD .env server-status actuator/env phpinfo.php wp-login.php .DS_Store; do
    code=$(curl -sSk -m 8 -o /dev/null -w '%{http_code}' "$URL$path")
    [ "$code" = 200 ] && find_ "200 OK: $URL$path"
    [ "$code" = 401 ] || [ "$code" = 403 ] && info "  $code $path"
  done
fi
have whatweb && { info "tech fingerprint (whatweb):"; run whatweb --color=never -a1 "$URL"; }
nse "$T" "$P" "http-title,http-headers,http-methods,http-enum,http-robots.txt,http-git,http-webdav-scan"

# TLS posture.
if [ "$SCHEME" = https ]; then
  if have sslscan; then info "TLS (sslscan):"; run sslscan --no-colour "$T:$P"
  else nse "$T" "$P" "ssl-enum-ciphers,ssl-cert,ssl-dh-params"; fi
  note "flag: SSLv3/TLS1.0, weak ciphers, expired/self-signed cert, Heartbleed (ssl-heartbleed)"
fi

if aggr; then
  sec "HTTP intrusive (nikto + dir busting)"
  need nikto   && run nikto -host "$URL" -maxtime 120s
  need feroxbuster && run feroxbuster -u "$URL" -w /usr/share/wordlists/dirb/common.txt -q -k --time-limit 120s ||
    { need gobuster && run gobuster dir -u "$URL" -w /usr/share/wordlists/dirb/common.txt -k -q; }
else skip_aggr "nikto + feroxbuster/gobuster dir busting"; fi
