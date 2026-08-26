"""Deep HTTP scanning — path enumeration, framework fingerprinting, response
analysis. `probes.http_findings` calls into here for the checks that go beyond
security-header verification.

Everything here is stdlib-only (http.client, ssl, html.parser, concurrent.futures).
The path wordlist is bundled in this module — no filesystem reads at runtime, no
outbound calls to fetch it, so the airgap story stays intact.

Design constraints:

* One TCP connection per request (http.client, not keep-alive) — servers that
  aggressively drop idle connections shouldn't kill our scan.
* Parallelism capped at 8 workers per host — enough for a 60-path enum in
  ~5s against a snappy server, low enough that we don't DOS a fragile target.
* Every request has an independent short timeout (2s default); a stuck path
  never blocks the whole enum.
* Silent on failure — a timeout or connection error is a "no", not a raise.
  The scan continues; we don't halt-and-catch-fire on one bad path.

Findings emitted here fall into three buckets:

* **Data disclosure** (real bugs): exposed `.git/`, `.env`, backup dumps,
  actuator/env, phpinfo. Severity high-to-critical — these leak secrets or
  source code and are always in-scope.
* **Attack surface** (informational): admin panels, API docs, framework
  fingerprints. Not bugs by themselves, but they tell the tester where to
  focus next.
* **Framework fingerprints** (informational): WordPress/Drupal/Jenkins/etc.
  detected via HTML meta / cookies / body signatures. Feeds later modules
  (default-cred sweep, C5 SQLi) with hints about what to attack.
"""
from __future__ import annotations

import concurrent.futures
import http.client
import re
import ssl
import time
from html.parser import HTMLParser

from ..models import Port, Vuln
from .. import proxy


# ---- request helpers --------------------------------------------------------

_UA = "recce-probe/1.0"
_REQ_TIMEOUT = 2.0                    # per-path GET timeout
_ROOT_TIMEOUT = 4.0                   # a bit more for the root fingerprint fetch
_MAX_WORKERS = 8                      # concurrent paths per host
_MAX_BODY = 65536                     # read-cap per response (fingerprint sample)
_ENUM_BUDGET_S = 45.0                 # hard wall-clock cap on the whole enum


def _connect(ip: str, port: int, use_tls: bool, timeout: float):
    if use_tls:
        ctx = ssl._create_unverified_context()
        return http.client.HTTPSConnection(ip, port, timeout=proxy.scaled(timeout), context=ctx)
    return http.client.HTTPConnection(ip, port, timeout=proxy.scaled(timeout))


def _get(ip: str, port: int, use_tls: bool, path: str, timeout: float = _REQ_TIMEOUT,
         method: str = "GET", extra_headers: dict | None = None,
         read_body: bool = False) -> dict | None:
    """One request. Returns dict {status, headers, body} on success, None on any
    transport-level failure. Never raises."""
    conn = None
    try:
        conn = _connect(ip, port, use_tls, timeout)
        hdrs = {"User-Agent": _UA, "Connection": "close", "Accept": "*/*"}
        if extra_headers:
            hdrs.update(extra_headers)
        conn.request(method, path, headers=hdrs)
        resp = conn.getresponse()
        body = resp.read(_MAX_BODY) if read_body else b""
        # A naive dict-comprehension over getheaders() collapses duplicates,
        # which loses every set-cookie after the first — critical for cookie-
        # based framework fingerprinting where PHPSESSID and the app's own
        # session cookie come through as separate Set-Cookie lines. Join
        # duplicates with "; " so downstream regex still matches each name=.
        hdrs: dict[str, str] = {}
        for k, v in resp.getheaders():
            lk = k.lower()
            if lk in hdrs:
                hdrs[lk] = f"{hdrs[lk]}; {v}"
            else:
                hdrs[lk] = v
        return {"status": resp.status, "headers": hdrs, "body": body}
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


# ---- path wordlist ----------------------------------------------------------

# Each entry: (path, category, severity, cwes, one-line description)
# Categories: disclosure (real bug), surface (attack surface), fingerprint.
#
# Kept lean on purpose — a 200-path enum should complete in ~5s on a snappy
# target. Adding paths that rarely hit anything just wastes time; each entry
# is here because it's caught something in a real engagement.
_PATHS: list[tuple[str, str, str, list[str], str]] = [
    # -- source-code / VCS disclosure (always a real bug) -----------------
    ("/.git/HEAD",           "disclosure", "high",     ["CWE-538"], "Git repository exposed — full source-code history reachable"),
    ("/.git/config",         "disclosure", "high",     ["CWE-538"], "Git repository config exposed"),
    ("/.svn/entries",        "disclosure", "high",     ["CWE-538"], "Subversion repository exposed"),
    ("/.svn/wc.db",          "disclosure", "high",     ["CWE-538"], "Subversion working-copy DB exposed"),
    ("/.hg/store/00manifest.i", "disclosure", "high",  ["CWE-538"], "Mercurial repository exposed"),
    ("/.bzr/README",         "disclosure", "high",     ["CWE-538"], "Bazaar repository exposed"),
    ("/.DS_Store",           "disclosure", "medium",   ["CWE-538"], "macOS .DS_Store discloses directory contents"),

    # -- secrets / config exposure (real bug, severity depends on hit) ----
    ("/.env",                "disclosure", "critical", ["CWE-200","CWE-532"], "Environment file exposed — likely secrets"),
    ("/.env.local",          "disclosure", "critical", ["CWE-200","CWE-532"], "Local environment file exposed"),
    ("/.env.production",     "disclosure", "critical", ["CWE-200","CWE-532"], "Production env file exposed"),
    ("/wp-config.php",       "disclosure", "critical", ["CWE-538"], "WordPress config exposed (should be blocked)"),
    ("/wp-config.php.bak",   "disclosure", "critical", ["CWE-538"], "WordPress config backup exposed"),
    ("/config.php",          "disclosure", "high",     ["CWE-538"], "PHP config file exposed"),
    ("/config.yml",          "disclosure", "high",     ["CWE-538"], "YAML config file exposed"),
    ("/config.yaml",         "disclosure", "high",     ["CWE-538"], "YAML config file exposed"),
    ("/config.json",         "disclosure", "high",     ["CWE-538"], "JSON config file exposed"),
    ("/appsettings.json",    "disclosure", "high",     ["CWE-538"], ".NET appsettings.json exposed"),
    ("/appsettings.Development.json", "disclosure", "high", ["CWE-538"], ".NET dev appsettings.json exposed"),
    ("/web.config",          "disclosure", "high",     ["CWE-538"], "IIS web.config exposed"),
    ("/application.properties", "disclosure", "high",  ["CWE-538"], "Spring application.properties exposed"),
    ("/application.yml",     "disclosure", "high",     ["CWE-538"], "Spring application.yml exposed"),
    ("/settings.py",         "disclosure", "high",     ["CWE-538"], "Django settings.py exposed"),
    ("/database.yml",        "disclosure", "high",     ["CWE-538"], "Rails database.yml exposed"),
    ("/secrets.yml",         "disclosure", "critical", ["CWE-538"], "Rails secrets.yml exposed"),

    # -- backup files (always a real bug) ---------------------------------
    ("/backup.zip",          "disclosure", "high",     ["CWE-538"], "Backup archive exposed"),
    ("/backup.tar",          "disclosure", "high",     ["CWE-538"], "Backup archive exposed"),
    ("/backup.tar.gz",       "disclosure", "high",     ["CWE-538"], "Backup archive exposed"),
    ("/backup.sql",          "disclosure", "critical", ["CWE-538"], "SQL database dump exposed"),
    ("/dump.sql",            "disclosure", "critical", ["CWE-538"], "SQL database dump exposed"),
    ("/db.sql",              "disclosure", "critical", ["CWE-538"], "SQL database dump exposed"),
    ("/database.sql",        "disclosure", "critical", ["CWE-538"], "SQL database dump exposed"),
    ("/site.zip",            "disclosure", "high",     ["CWE-538"], "Site backup archive exposed"),
    ("/www.zip",             "disclosure", "high",     ["CWE-538"], "Site backup archive exposed"),
    ("/htdocs.zip",          "disclosure", "high",     ["CWE-538"], "Site backup archive exposed"),

    # -- debug / info leaks (real bug — often paths to RCE) ---------------
    ("/phpinfo.php",         "disclosure", "high",     ["CWE-200"], "phpinfo() exposed — full server config"),
    ("/info.php",            "disclosure", "high",     ["CWE-200"], "phpinfo() likely exposed"),
    ("/test.php",            "disclosure", "medium",   ["CWE-200"], "Test PHP file exposed"),
    ("/server-status",       "disclosure", "medium",   ["CWE-200"], "Apache mod_status exposed"),
    ("/server-info",         "disclosure", "medium",   ["CWE-200"], "Apache mod_info exposed"),
    ("/nginx_status",        "disclosure", "medium",   ["CWE-200"], "nginx stub_status exposed"),

    # -- Spring Boot actuator (extremely common, often exposed) -----------
    ("/actuator",            "disclosure", "medium",   ["CWE-200"], "Spring Boot Actuator index exposed"),
    ("/actuator/health",     "surface",    "info",     ["CWE-200"], "Actuator health endpoint"),
    ("/actuator/env",        "disclosure", "high",     ["CWE-200","CWE-532"], "Actuator env — leaks all environment variables"),
    ("/actuator/configprops", "disclosure","high",     ["CWE-200"], "Actuator configprops — leaks config"),
    ("/actuator/beans",      "disclosure", "medium",   ["CWE-200"], "Actuator beans — leaks internal wiring"),
    ("/actuator/mappings",   "disclosure", "medium",   ["CWE-200"], "Actuator mappings — enumerates all routes"),
    ("/actuator/heapdump",   "disclosure", "critical", ["CWE-200"], "Actuator heapdump — full memory dump (secrets in cleartext)"),
    ("/actuator/threaddump", "disclosure", "medium",   ["CWE-200"], "Actuator threaddump"),
    ("/actuator/loggers",    "disclosure", "medium",   ["CWE-200"], "Actuator loggers — writable log config"),
    ("/actuator/httptrace",  "disclosure", "high",     ["CWE-200"], "Actuator httptrace — session tokens visible"),
    ("/env",                 "disclosure", "high",     ["CWE-200"], "Legacy Spring env endpoint"),
    ("/trace",               "disclosure", "medium",   ["CWE-200"], "Legacy Spring trace endpoint"),

    # -- API / docs (attack surface — informational) ----------------------
    ("/api",                 "surface",    "info",     [],           "REST API root"),
    ("/api/v1",              "surface",    "info",     [],           "REST API v1"),
    ("/api/v2",              "surface",    "info",     [],           "REST API v2"),
    ("/graphql",             "surface",    "info",     ["CWE-200"],  "GraphQL endpoint — introspection worth checking"),
    ("/graphiql",            "surface",    "medium",   ["CWE-200"],  "GraphiQL UI exposed"),
    ("/swagger",             "surface",    "info",     [],           "Swagger UI"),
    ("/swagger-ui",          "surface",    "info",     [],           "Swagger UI"),
    ("/swagger-ui/",         "surface",    "info",     [],           "Swagger UI"),
    ("/swagger-ui.html",     "surface",    "info",     [],           "Swagger UI (Springfox)"),
    ("/swagger.json",        "disclosure", "info",     [],           "OpenAPI spec — full API surface"),
    ("/openapi.json",        "disclosure", "info",     [],           "OpenAPI spec — full API surface"),
    ("/v2/api-docs",         "disclosure", "info",     [],           "Springfox v2 API docs"),
    ("/v3/api-docs",         "disclosure", "info",     [],           "OpenAPI v3 API docs"),
    ("/api-docs",            "surface",    "info",     [],           "API documentation"),
    ("/docs",                "surface",    "info",     [],           "API documentation"),
    ("/redoc",               "surface",    "info",     [],           "Redoc API viewer"),

    # -- admin / login panels (attack surface — informational) ------------
    ("/admin",               "surface",    "info",     [],           "Admin panel"),
    ("/admin/",              "surface",    "info",     [],           "Admin panel"),
    ("/admin/login",         "surface",    "info",     [],           "Admin login"),
    ("/administrator",       "surface",    "info",     [],           "Joomla admin panel"),
    ("/administrator/",      "surface",    "info",     [],           "Joomla admin panel"),
    ("/wp-admin",            "surface",    "info",     [],           "WordPress admin"),
    ("/wp-admin/",           "surface",    "info",     [],           "WordPress admin"),
    ("/wp-login.php",        "surface",    "info",     [],           "WordPress login"),
    ("/manager/html",        "surface",    "medium",   [],           "Tomcat Manager (default creds: tomcat/tomcat)"),
    ("/host-manager/html",   "surface",    "medium",   [],           "Tomcat Host Manager"),
    ("/manager/status",      "surface",    "info",     [],           "Tomcat Manager status"),
    ("/jenkins",             "surface",    "info",     [],           "Jenkins"),
    ("/jenkins/",            "surface",    "info",     [],           "Jenkins"),
    ("/phpmyadmin",          "surface",    "info",     [],           "phpMyAdmin"),
    ("/phpmyadmin/",         "surface",    "info",     [],           "phpMyAdmin"),
    ("/pma",                 "surface",    "info",     [],           "phpMyAdmin (alt path)"),
    ("/adminer.php",         "surface",    "info",     [],           "Adminer DB tool"),
    ("/grafana",             "surface",    "info",     [],           "Grafana (default admin/admin)"),
    ("/kibana",              "surface",    "info",     [],           "Kibana"),
    ("/rabbitmq",            "surface",    "info",     [],           "RabbitMQ mgmt UI"),
    ("/solr",                "surface",    "info",     [],           "Apache Solr admin"),
    ("/solr/admin",          "surface",    "info",     [],           "Apache Solr admin"),

    # -- info / discovery --------------------------------------------------
    ("/robots.txt",          "surface",    "info",     [],           "robots.txt — often lists sensitive paths"),
    ("/sitemap.xml",         "surface",    "info",     [],           "sitemap.xml"),
    ("/humans.txt",          "surface",    "info",     [],           "humans.txt"),
    ("/security.txt",        "surface",    "info",     [],           "security.txt"),
    ("/.well-known/security.txt", "surface","info",    [],           "security.txt (well-known)"),
    ("/crossdomain.xml",     "surface",    "info",     [],           "Flash cross-domain policy"),
    ("/clientaccesspolicy.xml", "surface", "info",     [],           "Silverlight cross-domain policy"),

    # -- CMS-specific ------------------------------------------------------
    ("/wp-json/wp/v2/users", "disclosure", "medium",   ["CWE-200"],  "WordPress user enumeration via REST API"),
    ("/wp-content/uploads/", "surface",    "info",     [],           "WordPress uploads directory"),
    ("/drupal",              "surface",    "info",     [],           "Drupal"),
    ("/user/login",          "surface",    "info",     [],           "Drupal user login"),
    ("/user/register",       "surface",    "info",     [],           "Drupal user registration"),
    ("/CHANGELOG.txt",       "disclosure", "info",     ["CWE-200"],  "Drupal changelog — exact version disclosed"),

    # -- misc common exposures --------------------------------------------
    ("/uploads",             "surface",    "info",     [],           "Uploads directory"),
    ("/uploads/",            "surface",    "info",     [],           "Uploads directory"),
    ("/files",               "surface",    "info",     [],           "Files directory"),
    ("/logs",                "disclosure", "medium",   ["CWE-200"],  "Logs directory exposed"),
    ("/log",                 "disclosure", "medium",   ["CWE-200"],  "Log directory exposed"),
    ("/tmp",                 "disclosure", "medium",   ["CWE-200"],  "Temp directory exposed"),
    ("/console",             "surface",    "medium",   [],           "Web console (Weblogic/Werkzeug/Jetty)"),
]


# HTTP statuses we treat as "the path exists / is reachable"
_HIT_STATUSES = {200, 201, 202, 203, 204, 206, 301, 302, 401, 403}
# Statuses where 401/403 usually mean "exists but auth required" — worth reporting
# because it enumerates attack surface. 404 => don't report.

# Two synthetic junk paths — an SPA catch-all router (Juice Shop, most React /
# Angular / Vue apps) serves the same index.html for every unknown route, which
# would make our path enum a wall of false positives. We probe these first; any
# real "hit" whose (status, body-length, content-type) matches the canary is
# treated as a catch-all response and dropped. Two paths, so a target that
# returns different-but-still-catch-all bodies (e.g. echoes the path in a 404
# page) still gets classified correctly.
_CANARY_PATHS = ["/recce-canary-Xk9pQ2vL", "/does-not-exist-a72f8b1c/nested"]


# ---- path enum --------------------------------------------------------------

def _catchall_signature(ip: str, port: int, use_tls: bool) -> set[tuple] | None:
    """Fetch two synthetic paths that shouldn't exist. If they both return the
    same 2xx/3xx response, we're behind a catch-all (SPA router, wildcard proxy).
    Return the set of (status, length, content-type) tuples the catch-all
    responds with; caller drops any real hit that matches. Return None if
    neither request succeeded (nothing to compare against)."""
    sigs: set[tuple] = set()
    for path in _CANARY_PATHS:
        r = _get(ip, port, use_tls, path, read_body=True)
        if r is None:
            continue
        # A 404/410 canary is exactly what a well-behaved server does — that
        # means real hits are trustworthy. Only 2xx/3xx canaries signal catch-all.
        if r["status"] in _HIT_STATUSES:
            sigs.add((r["status"], len(r.get("body", b"")),
                      (r["headers"].get("content-type") or "")[:60]))
    return sigs or None


def _probe_one_path(ip: str, port: int, use_tls: bool,
                    entry: tuple, catchall: set[tuple] | None) -> dict | None:
    path, category, sev, cwes, desc = entry
    # Read the body — needed to compare length against the catch-all signature.
    r = _get(ip, port, use_tls, path, read_body=True)
    if r is None or r["status"] not in _HIT_STATUSES:
        return None
    if catchall is not None:
        sig = (r["status"], len(r.get("body", b"")),
               (r["headers"].get("content-type") or "")[:60])
        if sig in catchall:
            return None                        # SPA / wildcard-proxy false positive
    # 401/403 on a "disclosure" path downgrades to "surface" — the file exists
    # but we can't confirm it's readable. Reduce severity so we don't cry wolf.
    effective_sev = sev
    if r["status"] in (401, 403) and category == "disclosure":
        effective_sev = "info"
        desc = f"{desc} (returns {r['status']} — exists but access restricted)"
    return {
        "path": path,
        "status": r["status"],
        "category": category,
        "severity": effective_sev,
        "cwes": cwes,
        "description": desc,
        "length": len(r.get("body", b"")),
    }


def path_enum(ip: str, port: int, use_tls: bool) -> list[dict]:
    """Probe the bundled path list against a single HTTP endpoint. Returns the
    list of hits (paths that responded with any of _HIT_STATUSES), with SPA /
    wildcard-proxy catch-all responses filtered out. Wall-clock capped at
    _ENUM_BUDGET_S."""
    started = time.monotonic()
    catchall = _catchall_signature(ip, port, use_tls)
    hits: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futs = {pool.submit(_probe_one_path, ip, port, use_tls, e, catchall): e
                for e in _PATHS}
        for fut in concurrent.futures.as_completed(futs):
            if time.monotonic() - started > _ENUM_BUDGET_S:
                # cap wall-clock; let outstanding futures die on the pool teardown
                break
            try:
                h = fut.result()
            except Exception:
                continue
            if h:
                hits.append(h)
    return hits


# ---- framework fingerprinting ------------------------------------------------

# Body signatures — regex against the root page HTML. Ordered by specificity:
# more specific patterns (a plugin path, a known error string) beat generic
# ones (jQuery presence).
_BODY_SIGS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"/wp-content/|<meta name=\"generator\" content=\"WordPress", re.I), "WordPress"),
    (re.compile(r"Drupal\.settings|/sites/(all|default)/(modules|themes)", re.I), "Drupal"),
    (re.compile(r"/media/(system|jui)/|/templates/system/", re.I), "Joomla"),
    (re.compile(r"Powered by Django|__debug__", re.I), "Django"),
    (re.compile(r"csrf-param.*authenticity_token|Ruby on Rails", re.I), "Rails"),
    (re.compile(r"laravel_session|Laravel", re.I), "Laravel"),
    (re.compile(r"Symfony_Session|X-Debug-Token", re.I), "Symfony"),
    (re.compile(r"Welcome to Jenkins|X-Jenkins", re.I), "Jenkins"),
    (re.compile(r"Grafana|window\.grafanaBootData", re.I), "Grafana"),
    (re.compile(r"Kibana|window\.__initialState__.*kibana", re.I), "Kibana"),
    (re.compile(r"tomcat.svg|Apache Tomcat/", re.I), "Apache Tomcat"),
    (re.compile(r"<title>Welcome to nginx", re.I), "nginx default page"),
    (re.compile(r"<title>Apache2? .+Default Page|It works!", re.I), "Apache default page"),
    (re.compile(r"phpMyAdmin", re.I), "phpMyAdmin"),
    (re.compile(r"Adminer", re.I), "Adminer"),
    (re.compile(r"__NEXT_DATA__|next\.js", re.I), "Next.js"),
    (re.compile(r"nuxt-|__NUXT__", re.I), "Nuxt.js"),
    (re.compile(r"ng-version=|/angular\.min\.js", re.I), "Angular"),
    (re.compile(r"react-dom|__REACT_DEVTOOLS_GLOBAL_HOOK__", re.I), "React"),
    (re.compile(r"vue(?:\.min)?\.js|__vue_app__|data-v-", re.I), "Vue.js"),
    (re.compile(r"gitea", re.I), "Gitea"),
    (re.compile(r"gitlab", re.I), "GitLab"),
    (re.compile(r"cgit", re.I), "cgit"),
    (re.compile(r"Damn Vulnerable Web|DVWA", re.I), "DVWA"),
    (re.compile(r"OWASP Juice Shop", re.I), "OWASP Juice Shop"),
    (re.compile(r"bWAPP", re.I), "bWAPP"),
    (re.compile(r"WebGoat", re.I), "WebGoat"),
    (re.compile(r"phpBB", re.I), "phpBB"),
    (re.compile(r"MediaWiki", re.I), "MediaWiki"),
    (re.compile(r"Confluence", re.I), "Atlassian Confluence"),
    (re.compile(r"Jira", re.I), "Atlassian Jira"),
    (re.compile(r"Bitbucket", re.I), "Atlassian Bitbucket"),
    (re.compile(r"Nextcloud|ownCloud", re.I), "Nextcloud/ownCloud"),
    (re.compile(r"Prometheus", re.I), "Prometheus"),
    (re.compile(r"MinIO", re.I), "MinIO"),
    (re.compile(r"Vault UI|hashicorp/vault", re.I), "HashiCorp Vault"),
]

# Cookie names -> framework hint
_COOKIE_SIGS: dict[str, str] = {
    "PHPSESSID":        "PHP",
    "JSESSIONID":       "Java (JSP/Servlet)",
    "ASPXAUTH":         "ASP.NET",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session":  "Laravel",
    "django_session":   "Django",
    "sessionid":        "Django",       # Django's default
    "csrftoken":        "Django",
    "_rails_session":   "Rails",
    "connect.sid":      "Express.js",
    "grafana_session":  "Grafana",
    "wordpress_logged_in": "WordPress",
    "wp-settings":      "WordPress",
}


class _MetaTitleParser(HTMLParser):
    """Extract <title> and <meta name="generator" content="..."> — that's all
    we need from the root HTML for fingerprinting."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title: str = ""
        self.generator: str = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "title":
            self._in_title = True
        elif t == "meta":
            d = dict(attrs)
            if (d.get("name") or "").lower() == "generator":
                self.generator = (d.get("content") or "").strip()[:200]

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title and len(self.title) < 200:
            self.title += data.strip()


def fingerprint(ip: str, port: int, use_tls: bool) -> dict:
    """GET / and return whatever we can infer about the stack. Returns
    {title, generator, technologies:[...], cookies:{...}, server:..., status:...}
    or {} on any transport failure. Follows one 301/302 redirect if the root
    replies with one — a lot of apps (DVWA, Grafana, Kibana) redirect / to
    /login and we'd otherwise miss all their fingerprints."""
    r = _get(ip, port, use_tls, "/", timeout=_ROOT_TIMEOUT, read_body=True)
    if r is None:
        return {}
    # Remember cookies from the FIRST response — a lot of apps (PHP-based,
    # ASP.NET) set their session cookie on the redirect itself, and we'd miss
    # the framework hint if we only inspected the followed response.
    pre_cookies = r["headers"].get("set-cookie", "")
    if r["status"] in (301, 302, 303, 307, 308):
        loc = r["headers"].get("location", "")
        # Only follow same-host redirects — absolute URLs to another host are
        # out of scope here. Accept both /login.php (absolute-path) and
        # login.php (relative), rejecting scheme+authority forms.
        if loc and not re.match(r"^[a-z]+://", loc, re.I):
            follow_path = loc if loc.startswith("/") else "/" + loc.lstrip("./")
            r2 = _get(ip, port, use_tls, follow_path, timeout=_ROOT_TIMEOUT, read_body=True)
            if r2 is not None:
                # Preserve pre-redirect cookies by concatenating them into the
                # followed response's set-cookie header.
                merged = r["headers"].copy()
                merged.update(r2["headers"])
                if pre_cookies:
                    merged["set-cookie"] = pre_cookies + "; " + merged.get("set-cookie", "")
                r = {"status": r2["status"], "headers": merged, "body": r2["body"]}
    out: dict = {
        "status": r["status"],
        "server": r["headers"].get("server", ""),
        "powered_by": r["headers"].get("x-powered-by", ""),
        "content_type": r["headers"].get("content-type", ""),
        "title": "",
        "generator": "",
        "technologies": [],
        "cookies": {},
    }
    # Parse Set-Cookie header for framework hints.
    raw_cookies = r["headers"].get("set-cookie", "")
    if raw_cookies:
        for name, product in _COOKIE_SIGS.items():
            if re.search(rf"\b{re.escape(name)}=", raw_cookies):
                out["cookies"][name] = product
    # Parse the HTML if it looks like HTML.
    ctype = out["content_type"].lower()
    body = r.get("body") or b""
    if "html" in ctype or body.lstrip().startswith(b"<"):
        text = body.decode("utf-8", "replace")
        p = _MetaTitleParser()
        try:
            p.feed(text)
        except Exception:
            pass
        out["title"] = p.title.strip()[:200]
        out["generator"] = p.generator
        for rx, product in _BODY_SIGS:
            if rx.search(text):
                if product not in out["technologies"]:
                    out["technologies"].append(product)
    return out


# ---- HTML form discovery (C2) ----------------------------------------------

# Input-name substrings that identify a login form. If two of these appear
# in one <form>, we call it a login form. Case-insensitive.
_LOGIN_USERNAME_HINTS = {"user", "username", "login", "email", "userid", "uid", "acct", "account"}
_LOGIN_PASSWORD_HINTS = {"pass", "passwd", "password", "pwd"}
_CSRF_HINTS = {"csrf", "authenticity_token", "__requestverificationtoken", "_token", "xsrf"}

# CMS/app fingerprints keyed off form action or page URL. If we recognize the
# form's app, we can also flag the common default credentials for it — huge
# signal for the tester's next step.
_DEFAULT_CREDS: dict[str, list[tuple[str, str]]] = {
    "wordpress":    [("admin", "admin"), ("admin", "password")],
    "tomcat":       [("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager")],
    "jenkins":      [("admin", "admin"), ("admin", "password")],
    "grafana":      [("admin", "admin")],
    "phpmyadmin":   [("root", ""), ("root", "root"), ("admin", "admin")],
    "adminer":      [("root", ""), ("root", "root")],
    "solr":         [("solr", "SolrRocks"), ("admin", "admin")],
    "dvwa":         [("admin", "password")],
    "juice-shop":   [("admin@juice-sh.op", "admin123")],
    "airflow":      [("airflow", "airflow"), ("admin", "admin")],
    "kibana":       [("elastic", "changeme"), ("kibana", "changeme")],
    "gitlab":       [("root", "5iveL!fe"), ("root", "password")],
    "rabbitmq":     [("guest", "guest")],
    "consul":       [("", "")],
    "elasticsearch":[("elastic", "changeme")],
    "jira":         [("admin", "admin")],
    "confluence":   [("admin", "admin")],
    "nexus":        [("admin", "admin123")],
}


class _FormParser(HTMLParser):
    """Extract <form> definitions from an HTML page.

    Each form: {action, method, inputs: [{name, type, placeholder}]}. Only
    reads standard <input> / <select> / <textarea> children — enough for 99%
    of authentication surface. Radio/checkbox groups are dedup'd by name."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._cur: dict | None = None
        self._seen_names: set[str] = set()

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        d = dict(attrs)
        if t == "form":
            self._cur = {
                "action": (d.get("action") or "").strip(),
                "method": (d.get("method") or "GET").upper(),
                "id": d.get("id") or "",
                "inputs": [],
            }
            self._seen_names = set()
        elif t in ("input", "select", "textarea") and self._cur is not None:
            name = (d.get("name") or "").strip()
            if not name or name in self._seen_names:
                return
            self._seen_names.add(name)
            self._cur["inputs"].append({
                "name": name,
                "type": (d.get("type") or ("text" if t == "input" else t)).lower(),
                "placeholder": (d.get("placeholder") or "")[:80],
            })

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
            self._seen_names = set()


def _classify_form(form: dict) -> dict:
    """Given a parsed form dict, decide if it's a login form and return
    additional metadata (login=True/False, has_csrf, username_field,
    password_field)."""
    input_names = [i["name"].lower() for i in form["inputs"]]
    input_types = [i["type"].lower() for i in form["inputs"]]
    result = {"login": False, "has_csrf": False, "username_field": "", "password_field": ""}

    # Locate a password field first — a form without a type=password is
    # rarely a login form (and if it is, we can't tell reliably).
    has_pw = False
    for i in form["inputs"]:
        if i["type"] == "password":
            has_pw = True
            result["password_field"] = i["name"]
            break
    if not has_pw:
        # Fallback: field name explicitly says "password".
        for i in form["inputs"]:
            if any(h in i["name"].lower() for h in _LOGIN_PASSWORD_HINTS):
                has_pw = True
                result["password_field"] = i["name"]
                break
    if not has_pw:
        return result

    # A username field is any text/email/name-hinted input.
    for i in form["inputs"]:
        if i["type"] in ("text", "email") or \
                any(h in i["name"].lower() for h in _LOGIN_USERNAME_HINTS):
            result["username_field"] = i["name"]
            break

    result["login"] = True
    result["has_csrf"] = any(any(h in n for h in _CSRF_HINTS) for n in input_names) or \
                        any(t == "hidden" and any(h in input_names[j] for h in _CSRF_HINTS)
                            for j, t in enumerate(input_types))
    return result


def _match_default_creds(fp: dict, form_action: str, page_url: str) -> list[tuple[str, str]]:
    """Return default cred candidates if the form's URL or the page fingerprint
    identifies a known app. Empty list otherwise."""
    blob = f"{page_url} {form_action} {fp.get('title','')} {(fp.get('generator') or '')} " \
           f"{' '.join(fp.get('technologies') or [])}".lower()
    for app, creds in _DEFAULT_CREDS.items():
        if app in blob:
            return creds
    return []


# Pages worth GET'ing for form discovery beyond just /. Same list as
# _PATHS (surface category) plus a few explicit login paths. We DON'T
# probe /wp-admin/… again since path_enum already told us if it exists.
_FORM_DISCOVERY_PATHS = [
    "/", "/login", "/signin", "/sign-in", "/log-in", "/user/login",
    "/admin", "/admin/login", "/wp-login.php", "/administrator",
    "/manager/html", "/actuator/login", "/console",
]


def discover_forms(ip: str, port: int, use_tls: bool,
                   fp: dict | None = None) -> list[dict]:
    """GET the login-adjacent paths and extract forms from each. Returns list
    of dicts: {page, form_action, method, login, has_csrf, username_field,
    password_field, default_creds: [(user, pass)], inputs: [names]}.

    fp is the fingerprint from fingerprint() — reused for default-cred hints
    so we don't refetch /. If None we recompute it (used from tests)."""
    if fp is None:
        fp = fingerprint(ip, port, use_tls)
    out: list[dict] = []
    for path in _FORM_DISCOVERY_PATHS:
        r = _get(ip, port, use_tls, path, timeout=_ROOT_TIMEOUT, read_body=True)
        if r is None or r["status"] not in _HIT_STATUSES:
            continue
        # Follow one same-host redirect (login pages often redirect from /admin).
        if r["status"] in (301, 302, 303, 307, 308):
            loc = r["headers"].get("location", "")
            if loc and not re.match(r"^[a-z]+://", loc, re.I):
                follow = loc if loc.startswith("/") else "/" + loc.lstrip("./")
                r2 = _get(ip, port, use_tls, follow, timeout=_ROOT_TIMEOUT, read_body=True)
                if r2 is not None:
                    r = r2; path = follow
        body = r.get("body") or b""
        if not body or b"<form" not in body.lower():
            continue
        parser = _FormParser()
        try:
            parser.feed(body.decode("utf-8", "replace"))
        except Exception:
            continue
        for form in parser.forms:
            meta = _classify_form(form)
            entry = {
                "page": path,
                "form_action": form["action"] or path,
                "method": form["method"],
                "inputs": [i["name"] for i in form["inputs"]],
                **meta,
            }
            entry["default_creds"] = _match_default_creds(fp, form["action"], path) \
                                     if meta["login"] else []
            out.append(entry)
    return out


# ---- HTTP methods probe (Tier A) -------------------------------------------

# Methods that are notable enough to report if a server actually accepts them.
# GET/HEAD/POST are expected — no news there. We look for the writeable /
# tunneling / debugging ones.
_METHODS_TO_PROBE = ["OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "CONNECT", "PROPFIND"]

# Server responses that mean "yes I speak this method." 405 or 501 means no.
# 200/204/207 → definitely yes. 400 with a meaningful body is ambiguous — treat
# as no. Auth-required (401/403) counts as YES because the method IS routed.
_METHOD_ACCEPTED = {200, 201, 202, 204, 207, 401, 403}
_METHOD_REJECTED = {405, 501}


def methods_probe(ip: str, port: int, use_tls: bool) -> dict:
    """Ask OPTIONS then probe each interesting verb directly. Returns
    {allow_header: str, accepted: [verbs]} — accepted verbs are the ones the
    server actually routed (not 405/501, and not the SPA catch-all that 200s
    every request). A GET-based sanity check on the same root confirms the
    server's baseline; a method that returns the exact same (status, length)
    as GET / on a catch-all target is treated as unrouted."""
    out = {"allow_header": "", "accepted": [], "trace_reflected": False}
    # Baseline: what does a normal GET / return? Then use it as the "SPA
    # catch-all" fingerprint against method responses.
    baseline = _get(ip, port, use_tls, "/", read_body=True)
    baseline_sig = None
    if baseline is not None and baseline["status"] in _HIT_STATUSES:
        baseline_sig = (baseline["status"], len(baseline.get("body") or b""))
    r_opt = _get(ip, port, use_tls, "/", method="OPTIONS", read_body=False)
    if r_opt is not None:
        out["allow_header"] = r_opt["headers"].get("allow", "")
    for m in _METHODS_TO_PROBE:
        r = _get(ip, port, use_tls, "/", method=m, read_body=True)
        if r is None:
            continue
        if r["status"] not in _METHOD_ACCEPTED:
            continue
        # SPA / wildcard-proxy suppression: if the method's response matches
        # the GET-/ baseline exactly, the app didn't actually route the method
        # — it just returned index.html.
        if baseline_sig is not None and \
                (r["status"], len(r.get("body") or b"")) == baseline_sig:
            continue
        out["accepted"].append(m)
        if m == "TRACE":
            body = (r.get("body") or b"").decode("latin-1", "replace")
            if "User-Agent" in body and _UA in body:
                out["trace_reflected"] = True
    return out


# ---- CORS misconfig probe (Tier A) -----------------------------------------

def cors_probe(ip: str, port: int, use_tls: bool) -> dict:
    """Send Origin: https://attacker.example and see if the server reflects it
    into Access-Control-Allow-Origin with Allow-Credentials: true. That
    combination is a real cross-origin exfil bug — any origin can read the
    response with the victim's cookies."""
    origin = "https://attacker.example"
    r = _get(ip, port, use_tls, "/", extra_headers={"Origin": origin})
    if r is None:
        return {}
    aco = r["headers"].get("access-control-allow-origin", "")
    acc = r["headers"].get("access-control-allow-credentials", "").lower() == "true"
    reflects = aco.strip() == origin
    wildcard_with_creds = aco.strip() == "*" and acc
    return {"aco": aco, "credentials": acc, "reflects_origin": reflects,
            "wildcard_with_creds": wildcard_with_creds}


# ---- robots.txt / sitemap.xml free-path enum (Tier A) ----------------------

_ROBOTS_PATH_RE = re.compile(r"^\s*(?:Disallow|Allow):\s*(\S+)", re.M | re.I)
_SITEMAP_LOC_RE = re.compile(r"<loc>([^<]+)</loc>", re.I)


def free_paths_from_index(ip: str, port: int, use_tls: bool) -> list[str]:
    """Pull paths from robots.txt (Disallow/Allow) and sitemap.xml. Servers
    hand these to us for free — every listed path is one the site owner already
    considers interesting. Returns unique same-host paths."""
    paths: list[str] = []
    seen: set[str] = set()

    def _add(p: str) -> None:
        p = p.strip()
        if not p or p in seen:
            return
        # Only same-host relative paths — a sitemap that lists external URLs
        # isn't attack surface here.
        if p.startswith("http"):
            m = re.match(r"^https?://[^/]+(/.*)?$", p)
            if not m:
                return
            p = m.group(1) or "/"
        if not p.startswith("/"):
            p = "/" + p
        # Ignore bare "/" — it's not attack surface, and a "Disallow: /" in a
        # dev-server robots.txt would otherwise flood the finding with
        # useless root entries.
        if p in ("/", ""):
            return
        seen.add(p)
        paths.append(p)

    r = _get(ip, port, use_tls, "/robots.txt", read_body=True)
    if r is not None and r["status"] == 200:
        for m in _ROBOTS_PATH_RE.finditer(r["body"].decode("utf-8", "replace")):
            _add(m.group(1))
    r = _get(ip, port, use_tls, "/sitemap.xml", read_body=True)
    if r is not None and r["status"] == 200:
        for m in _SITEMAP_LOC_RE.finditer(r["body"].decode("utf-8", "replace")):
            _add(m.group(1))
    return paths[:200]                    # cap — a sitemap can list thousands


# ---- OpenAPI / Swagger / GraphQL introspection (Tier A) -------------------

# Paths where API specs commonly live. If we get one, we've got the full
# API surface handed to us — every endpoint, every parameter, every method.
_API_SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/openapi.json",
    "/api/swagger.json", "/api/swagger", "/docs/swagger.json",
]


def api_spec_probe(ip: str, port: int, use_tls: bool) -> dict | None:
    """Return {path, kind, endpoint_count} for the first API spec that hits.
    'kind' is one of openapi/swagger/graphql based on the body. None if none."""
    for path in _API_SPEC_PATHS:
        r = _get(ip, port, use_tls, path, read_body=True)
        if r is None or r["status"] != 200:
            continue
        body = r.get("body") or b""
        if len(body) < 32:
            continue
        text = body.decode("utf-8", "replace")
        # Cheap fingerprint of the body: OpenAPI/Swagger spec bodies mention
        # "openapi" or "swagger" near the top. Reject arbitrary JSON.
        head = text[:400].lower()
        if "openapi" in head:
            kind = "openapi"
        elif "swagger" in head:
            kind = "swagger"
        else:
            continue
        # Path count = number of "paths" keys in the JSON — cheap regex, since
        # the tester just needs a rough sense of API surface size.
        endpoints = len(re.findall(r"\"paths\"\s*:", text)) and \
                    len(re.findall(r'"/[^"\\]{1,200}"\s*:\s*\{', text))
        return {"path": path, "kind": kind, "endpoint_count": endpoints}
    # GraphQL introspection — POST the __schema query.
    try:
        import json as _json
        conn = _connect(ip, port, use_tls, _REQ_TIMEOUT * 2)
        body = _json.dumps({"query": "{__schema{types{name}}}"}).encode()
        conn.request("POST", "/graphql", body=body,
                     headers={"Content-Type": "application/json", "User-Agent": _UA,
                              "Connection": "close"})
        resp = conn.getresponse()
        text = resp.read(_MAX_BODY).decode("utf-8", "replace")
        conn.close()
        if resp.status == 200 and '"__schema"' in text and '"types"' in text:
            type_count = len(re.findall(r'"name"', text))
            return {"path": "/graphql", "kind": "graphql", "endpoint_count": type_count}
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        pass
    return None


# ---- vhost enumeration (Tier A) --------------------------------------------

# Small list of hostname patterns that commonly bind to the same IP as a
# public site. Each is tried as Host: header; a materially different response
# (different size + different title) indicates a virtual host bound to that
# name. The tester now knows there's a second app hiding on the same box.
_VHOST_CANDIDATES = [
    "admin", "dev", "staging", "test", "internal", "intranet", "portal",
    "api", "vpn", "mail", "webmail", "monitor", "grafana", "jenkins",
]


def vhost_probe(ip: str, port: int, use_tls: bool, root_domain: str = "") -> list[dict]:
    """Try each candidate hostname as `Host:` header vs. the ip-only baseline.
    Return list of {hostname, status, length, title} that were materially
    different from the baseline. `root_domain` seeds fully-qualified guesses
    (e.g. 'corp.local' -> admin.corp.local); an empty string uses bare names."""
    r0 = _get(ip, port, use_tls, "/", read_body=True)
    if r0 is None:
        return []
    baseline_len = len(r0.get("body") or b"")
    baseline_status = r0["status"]

    hits: list[dict] = []
    for name in _VHOST_CANDIDATES:
        host_val = f"{name}.{root_domain}" if root_domain else name
        r = _get(ip, port, use_tls, "/", read_body=True,
                 extra_headers={"Host": host_val})
        if r is None:
            continue
        length = len(r.get("body") or b"")
        # Materially different: status differs OR size differs by >=32 bytes.
        # Small differences (dynamic tokens, request IDs) are noise.
        if r["status"] != baseline_status or abs(length - baseline_len) >= 32:
            hits.append({"hostname": host_val, "status": r["status"], "length": length})
    return hits


# ---- Vuln conversion --------------------------------------------------------

def _mk(host_ip: str, port: Port, sid: str, sev: str, title: str,
        cwes: list[str], output: str, remediation: str) -> Vuln:
    return Vuln(
        ip=host_ip, port=port.portid, protocol=port.protocol,
        script_id=sid, state="finding", title=title, output=output,
        severity=sev, cwes=cwes, source="probe", remediation=remediation,
        confidence="confirmed",
    )


def enum_findings(host_ip: str, port: Port) -> list[Vuln]:
    """Run path enum + fingerprint against one HTTP port; produce Vulns.
    Called from `probes.http_findings` alongside the existing header checks."""
    from .. import probes
    use_tls = probes._is_tls(port)

    out: list[Vuln] = []

    # Framework fingerprint — one root fetch, cheap.
    fp = fingerprint(host_ip, port.portid, use_tls)
    if fp:
        techs = list(fp.get("technologies") or [])
        if fp.get("generator"):
            techs.append(f"generator={fp['generator']}")
        for cn, product in (fp.get("cookies") or {}).items():
            techs.append(f"{product} (cookie {cn})")
        if techs:
            out.append(_mk(
                host_ip, port, "http-fingerprint", "info",
                "Web technology fingerprint",
                [],
                (f"root {fp.get('status','?')} · title={fp.get('title','')!r} · "
                 f"server={fp.get('server','')!r} · techs=[{', '.join(techs)}]"),
                "Informational — feeds default-cred and CVE lookup for the detected stack."))

    # Path enum — the meat.
    hits = path_enum(host_ip, port.portid, use_tls)
    for h in hits:
        title = f"Exposed path: {h['path']}"
        output = (f"HTTP {h['status']} · {h['description']} "
                  f"(body {h['length']} bytes)")
        if h["category"] == "disclosure":
            fix = f"Block external access to {h['path']} — return 404 or restrict to internal."
        else:
            fix = f"Confirm {h['path']} is intended to be reachable; if not, block."
        out.append(_mk(
            host_ip, port, "http-path-enum", h["severity"], title,
            h["cwes"], output, fix,
        ))

    # Robots + sitemap — free path list from the server itself. Anything they
    # tell us to disallow is exactly what we want to look at. Emit as info
    # findings so the tester sees the surface without cluttering the report.
    free_paths = free_paths_from_index(host_ip, port.portid, use_tls)
    if free_paths:
        out.append(_mk(
            host_ip, port, "http-robots-sitemap", "info",
            "Paths advertised by robots.txt / sitemap.xml",
            [],
            f"{len(free_paths)} path(s) advertised: " + ", ".join(free_paths[:20])
            + ("…" if len(free_paths) > 20 else ""),
            "Informational — anything a Disallow line names is worth reviewing directly."))

    # OpenAPI / Swagger / GraphQL — full API surface handed to us.
    spec = api_spec_probe(host_ip, port.portid, use_tls)
    if spec:
        out.append(_mk(
            host_ip, port, "http-api-spec", "info",
            f"{spec['kind'].upper()} spec exposed at {spec['path']}",
            ["CWE-200"],
            f"{spec['kind']} spec reachable — approximately {spec['endpoint_count']} "
            f"endpoints/types described",
            f"If the API is internal, block {spec['path']} externally. "
            f"Otherwise, ensure documented endpoints have appropriate authz."))

    # HTTP methods — TRACE with reflection = real XST, PUT/DELETE routed
    # anywhere = worth flagging.
    methods = methods_probe(host_ip, port.portid, use_tls)
    if methods.get("trace_reflected"):
        out.append(_mk(
            host_ip, port, "http-method-trace", "medium",
            "HTTP TRACE method reflects request (XST)",
            ["CWE-693"],
            "TRACE request echoed User-Agent — confirmed Cross-Site Tracing",
            "Disable the TRACE method (e.g. Apache: TraceEnable off; nginx: reject at directive)."))
    dangerous = [m for m in ("PUT", "DELETE", "PATCH", "CONNECT", "PROPFIND")
                 if m in methods.get("accepted", [])]
    if dangerous:
        out.append(_mk(
            host_ip, port, "http-method-writable", "medium",
            "Writable/tunneling HTTP methods accepted",
            ["CWE-650"],
            f"Server routes: {', '.join(dangerous)} (Allow header: {methods.get('allow_header','') or 'none'})",
            "Restrict methods to GET/HEAD/POST for public endpoints; disable PUT/DELETE/PROPFIND unless the app truly needs them."))

    # C2: form / login discovery. Feed fp so default-cred hints reuse it.
    forms = discover_forms(host_ip, port.portid, use_tls, fp=fp if fp else None)
    login_forms = [f for f in forms if f["login"]]
    if forms:
        # Compact summary finding: N forms across M pages.
        pages = sorted({f["page"] for f in forms})
        summary = f"{len(forms)} form(s) across {len(pages)} page(s)"
        detail_lines = []
        for f in forms[:12]:
            tag = "LOGIN" if f["login"] else "form"
            csrf = " +csrf" if f.get("has_csrf") else ""
            detail_lines.append(f"  [{tag}{csrf}] {f['method']} {f['page']} -> "
                                f"{f['form_action']} inputs={f['inputs']}")
        out.append(_mk(
            host_ip, port, "http-forms", "info",
            f"HTML forms discovered: {summary}",
            [],
            summary + "\n" + "\n".join(detail_lines),
            "Informational — feeds credential-spray candidate list and C5 SQLi targeting."))
    # Emit one dedicated finding per login form that has default-cred candidates.
    for f in login_forms:
        if not f.get("default_creds"):
            continue
        creds = ", ".join(f"{u}:{p}" for u, p in f["default_creds"])
        out.append(_mk(
            host_ip, port, "http-default-creds", "medium",
            f"Login form with known default credentials: {f['page']}",
            ["CWE-521", "CWE-1392"],
            f"Login form on {f['page']} appears to belong to a recognized app. "
            f"Default credentials to try: {creds} "
            f"(fields: user={f['username_field']!r}, pass={f['password_field']!r}, "
            f"csrf={'yes' if f['has_csrf'] else 'no'})",
            "Change or disable default credentials. If the app must stay reachable, "
            "restrict it network-adjacent and force password reset on first login."))

    # CORS misconfig — reflect origin + credentials = real cross-origin exfil.
    cors = cors_probe(host_ip, port.portid, use_tls)
    if cors.get("reflects_origin") and cors.get("credentials"):
        out.append(_mk(
            host_ip, port, "http-cors-reflect", "high",
            "CORS reflects any origin with credentials",
            ["CWE-346", "CWE-942"],
            f"Access-Control-Allow-Origin echoes 'https://attacker.example' "
            f"with Allow-Credentials: true — any origin can read authenticated responses",
            "Restrict Access-Control-Allow-Origin to a fixed allowlist. Never combine "
            "wildcard/reflection with Allow-Credentials: true."))
    elif cors.get("wildcard_with_creds"):
        out.append(_mk(
            host_ip, port, "http-cors-wildcard", "medium",
            "CORS wildcard '*' combined with credentials",
            ["CWE-346"],
            "Access-Control-Allow-Origin: * with Allow-Credentials: true — browsers "
            "typically block this combination, but some setups still leak.",
            "Set an explicit origin allowlist instead of '*' when credentials are enabled."))

    return out
