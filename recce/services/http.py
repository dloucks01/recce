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

from ..core.models import Port, Vuln
from ..core import proxy


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
    # /actuator/heapdump is NOT in this static table — it's handled by
    # actuator_probe() which validates the response is a real hprof binary
    # (>100KB, not an SPA catch-all HTML page). See actuator_probe().
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


def _resolve_extra_paths(extra_paths: list[str] | None) -> list[tuple]:
    """Merge caller-supplied paths + `RECCE_HTTP_WORDLIST` env-var paths
    into the tuple shape `_PATHS` uses. Env var is checked every call so a
    user can set/unset it between scans without re-importing.

    External-list entries get medium severity and CWE-538 by default —
    catch-all "the user thinks this is worth probing" — leaving the
    curated bundled list to keep its specific severities/CWEs."""
    from os import environ as _env
    from . import wordlists as _wl
    merged: list[str] = list(extra_paths or [])
    env_path = _env.get("RECCE_HTTP_WORDLIST", "").strip()
    if env_path:
        merged.extend(_wl.load_wordlist(env_path, prefix_slash=True))
    if not merged:
        return []
    seen_paths = {p[0] for p in _PATHS}
    out: list[tuple] = []
    for p in merged:
        if not p.startswith("/"):
            p = "/" + p
        if p in seen_paths:
            continue
        seen_paths.add(p)
        # (path, severity, description, cwes, category)
        out.append((p, "medium", "user-supplied wordlist entry",
                    ["CWE-538"], "disclosure"))
    return out


def path_enum(ip: str, port: int, use_tls: bool,
              extra_paths: list[str] | None = None) -> list[dict]:
    """Probe the bundled path list (+ any user wordlist) against a single
    HTTP endpoint. Returns the list of hits (paths that responded with any
    of _HIT_STATUSES), with SPA / wildcard-proxy catch-all responses
    filtered out. Wall-clock capped at _ENUM_BUDGET_S."""
    started = time.monotonic()
    catchall = _catchall_signature(ip, port, use_tls)
    hits: list[dict] = []
    all_entries = list(_PATHS) + _resolve_extra_paths(extra_paths)
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
        futs = {pool.submit(_probe_one_path, ip, port, use_tls, e, catchall): e
                for e in all_entries}
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
        # Full raw header map — feeds header_hygiene_findings() which does
        # version-disclosure + CSP auditing off the root response.
        "headers": dict(r["headers"]),
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


# ---- JavaScript secret scanning ---------------------------------------------

# Same secret patterns as recce/intake/loot.py, tuned for JS files: API keys,
# tokens, JWTs, DB URLs. High-value hits — a public JS bundle that ships an
# AWS access key or a hard-coded API endpoint URL is a real finding.
_JS_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key",    re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",    re.compile(r"(?i)aws.{0,20}(secret|key).{0,20}['\"][A-Za-z0-9/+=]{40}['\"]")),
    ("github_token",      re.compile(r"gh[oprsu]_[A-Za-z0-9]{36,}")),
    ("gitlab_token",      re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("slack_token",       re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_key",        re.compile(r"sk_(live|test)_[A-Za-z0-9]{20,}")),
    ("jwt",               re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("google_api_key",    re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("firebase_url",      re.compile(r"[a-z0-9-]+\.firebaseio\.com")),
    ("bearer_hardcoded",  re.compile(r"['\"]Bearer\s+[A-Za-z0-9+/=._-]{20,}['\"]")),
]
# API endpoint patterns worth surfacing — often reveals internal URLs the
# tester didn't know existed.
_JS_ENDPOINT_PATTERNS: list[re.Pattern] = [
    re.compile(r"['\"](/(api|v1|v2|v3|graphql|internal|admin)/[A-Za-z0-9._/?-]{2,60})['\"]"),
    re.compile(r"['\"]https?://[a-zA-Z0-9.-]+\.[a-z]{2,10}/[A-Za-z0-9._/?-]{2,60}['\"]"),
]

# JS files this size or larger get skipped to keep the scan bounded.
_JS_MAX_BYTES = 500_000
# Cap total JS files fetched per host so a page with 50 bundles doesn't
# stall the whole scan.
_JS_MAX_FILES = 15


def _extract_js_urls(html: str) -> list[str]:
    """Pull out `src=` attribute values from every <script> tag. Same-origin
    relative and absolute URLs preserved as-is; relative paths handled by the
    fetch step."""
    return re.findall(r'<script[^>]*\bsrc=["\']([^"\'>\s]+)', html, re.I)


def js_secret_scan(ip: str, port: int, use_tls: bool,
                   root_html: str = "") -> list[dict]:
    """GET the root page (or accept a pre-fetched root_html), enumerate
    <script src> URLs, fetch each same-host .js file, and grep for secret
    patterns. Returns list of hits {source, secret_label, snippet}.
    Silently returns [] on any transport failure."""
    if not root_html:
        r = _get(ip, port, use_tls, "/", timeout=_ROOT_TIMEOUT, read_body=True)
        if r is None or not r.get("body"):
            return []
        root_html = (r["body"] or b"").decode("utf-8", "replace")
    urls = _extract_js_urls(root_html)
    # Only same-host + relative paths (external CDNs would leak the target's
    # tokens if any exist there, but they're not attack surface HERE).
    keep: list[str] = []
    seen: set[str] = set()
    for u in urls:
        if u in seen: continue
        seen.add(u)
        if u.startswith("//"):
            continue
        if u.startswith("http://") or u.startswith("https://"):
            # Absolute — must match our host to count.
            m = re.match(r"^https?://([^/]+)(/.*)?$", u)
            if not m: continue
            host_part = m.group(1).split(":")[0]
            if host_part not in (ip, f"{ip}:{port}"):
                continue
            keep.append(m.group(2) or "/")
        elif u.startswith("/"):
            keep.append(u)
        else:
            keep.append("/" + u.lstrip("./"))
    hits: list[dict] = []
    for path in keep[:_JS_MAX_FILES]:
        r = _get(ip, port, use_tls, path, timeout=_ROOT_TIMEOUT, read_body=True)
        if r is None or r.get("status") != 200:
            continue
        body = r.get("body") or b""
        if not body or len(body) > _JS_MAX_BYTES:
            continue
        text = body.decode("utf-8", "replace")
        for label, pat in _JS_SECRET_PATTERNS:
            m = pat.search(text)
            if m:
                hits.append({"source": path, "secret": label,
                             "snippet": m.group(0)[:120]})
        # Endpoint URLs — high signal, we cap at 5 per file so the report
        # stays readable.
        endpoints: set[str] = set()
        for pat in _JS_ENDPOINT_PATTERNS:
            for em in pat.finditer(text):
                url = em.group(1) if em.groups() else em.group(0)
                if len(endpoints) >= 5: break
                endpoints.add(url.strip('"\'').strip())
        if endpoints:
            hits.append({"source": path, "secret": "endpoint_hint",
                         "snippet": ", ".join(sorted(endpoints))[:200]})
    return hits


# ---- Backup-file variants on discovered paths --------------------------------

# When path_enum finds a path like /config.php, try common backup suffixes.
# Backups often contain the same content but bypass application-level access
# controls (they're served as static files).
_BACKUP_SUFFIXES = [".bak", ".old", ".orig", "~", ".swp", ".backup", ".save",
                    ".copy", "1", ".1"]


def backup_variants_of(path: str) -> list[str]:
    """Generate common backup-file variant paths from a discovered path."""
    variants: list[str] = []
    for suf in _BACKUP_SUFFIXES:
        variants.append(path + suf)
    # ~-in-middle variant for editor swap files (config.php~)
    if "." in path.rsplit("/", 1)[-1]:
        base, _, ext = path.rpartition(".")
        variants.append(f"{base}.bak.{ext}")
    return variants


def probe_backup_variants(ip: str, port: int, use_tls: bool,
                          seed_paths: list[str],
                          catchall: set[tuple] | None = None) -> list[dict]:
    """For each seed path (typically the path_enum disclosure hits), probe
    its backup-suffix variants. Returns list of variant hits worth
    reporting. Backup variants of an already-disclosed path are additional
    exposure — often bypassing app auth."""
    hits: list[dict] = []
    for seed in seed_paths[:20]:                # cap seeds to bound the sweep
        for variant in backup_variants_of(seed):
            r = _get(ip, port, use_tls, variant, read_body=True)
            if r is None or r["status"] not in _HIT_STATUSES:
                continue
            # Filter catch-alls same way the main path_enum does.
            if catchall is not None:
                sig = (r["status"], len(r.get("body", b"")),
                       (r["headers"].get("content-type") or "")[:60])
                if sig in catchall:
                    continue
            hits.append({
                "path": variant,
                "status": r["status"],
                "length": len(r.get("body", b"")),
                "seed": seed,
            })
    return hits


# ---- Directory listing detection --------------------------------------------

# Common markers for auto-generated directory listings — Apache, nginx,
# IIS, lighttpd, Node.js serve-index all put distinctive strings in their
# index HTML.
_DIRLIST_MARKERS = [
    re.compile(r"<title>Index of /", re.I),
    re.compile(r"<h1>Index of /", re.I),
    re.compile(r"<pre>[^<]*Directory listing for /", re.I),
    re.compile(r"^\s*\[.+\]\s+Parent Directory", re.M),
    re.compile(r"<h1>Directory listing", re.I),
]


def is_directory_listing(body: bytes) -> bool:
    """Return True if the HTML body looks like an auto-generated directory
    listing (Apache mod_autoindex, nginx autoindex, IIS, Python http.server)."""
    if not body:
        return False
    text = body[:8000].decode("utf-8", "replace")
    return any(pat.search(text) for pat in _DIRLIST_MARKERS)


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
# ---- Deep probes (Actuator / nginx alias / cache poisoning / headers / CSP) --

# Spring Boot Actuator endpoints. `/actuator/env` and `/actuator/heapdump` are
# the crown jewels — env exposes every application property including DB
# credentials and API keys; heapdump gives the raw JVM heap (searchable for
# secrets). `/actuator/mappings` reveals every endpoint. The default context
# path is `/actuator` on Spring Boot 2+, `/` on Spring Boot 1.x.
_ACTUATOR_ENDPOINTS: list[tuple[str, str, str]] = [
    ("env", "medium",
     "Application properties + environment variables (DB passwords, API keys, "
     "AWS creds — anything from application.properties)."),
    ("heapdump", "critical",
     "Raw JVM heap dump. `strings heap.hprof | grep -Ei "
     "'password|secret|key|token'` recovers every credential currently held "
     "in memory. Multi-megabyte download — the size confirms it's the real "
     "thing rather than a routed placeholder."),
    ("configprops", "medium",
     "@ConfigurationProperties beans — often mirrors env with typed schema."),
    ("mappings", "low",
     "Every URL-to-handler mapping the app exposes (attack surface map)."),
    ("beans", "low",
     "Full bean graph — reveals framework versions and injected deps."),
    ("threaddump", "low",
     "Every thread's stack trace — leaks credentials sitting in method args."),
    ("loggers", "medium",
     "Live logger level control. POST to bump root to TRACE and read the "
     "logs from `/actuator/logfile` — real-time credential capture."),
    ("trace", "low",
     "Recent HTTP request/response bodies (Spring Boot 1.x). Cookies + "
     "Authorization headers of live user sessions in the last 100 requests."),
    ("httptrace", "low",
     "Same as `trace` on Spring Boot 2.x."),
]


def actuator_probe(ip: str, port: int, use_tls: bool) -> list[dict]:
    """Enumerate Spring Boot Actuator endpoints under both `/actuator/…` and
    `/…` (Boot 1.x). Returns [{path, endpoint, status, length, severity,
    description}, …] for each responsive endpoint. A 200 with a JSON-shaped
    body (or a large binary for heapdump) confirms exposure; a 401/403 is
    also worth flagging because the endpoint IS there and default creds
    (admin/admin, actuator/actuator) commonly work."""
    hits: list[dict] = []
    for base in ("/actuator", ""):
        for ep, sev, desc in _ACTUATOR_ENDPOINTS:
            path = f"{base}/{ep}" if base else f"/{ep}"
            r = _get(ip, port, use_tls, path, read_body=True)
            if r is None:
                continue
            body = r.get("body") or b""
            blen = len(body)
            status = r.get("status", 0)
            # 200 with a JSON-y body OR the multi-megabyte heapdump payload
            # is a confirmed hit. 401/403 is a partial hit (endpoint exists,
            # default creds might work).
            hit = False
            if status == 200 and blen > 0:
                if ep == "heapdump" and blen > 100_000:      # real hprof, not a stub
                    hit = True
                elif body[:1] in (b"{", b"[") or ep == "heapdump":
                    hit = True
            if status in (401, 403):
                hit = True                                    # partial
            if not hit:
                continue
            hits.append({"path": path, "endpoint": ep, "status": status,
                         "length": blen, "severity": sev, "description": desc})
    return hits


# nginx alias-traversal (CVE-2018-16843 pattern). When a `location /static/`
# maps to `alias /var/www/app/static/;` without a trailing slash on the
# location, `/static../` resolves to `/var/www/app/` — one directory ABOVE
# the intended root. Requesting `/static../etc/passwd` on such a config
# returns the file. The probe is safe: reading /etc/passwd is universally
# non-sensitive and the exact response is diagnostic.
_ALIAS_TRAVERSAL_PROBES: list[tuple[str, list[str]]] = [
    # (marker string that must appear in response, list of paths to try)
    ("root:x:0:0:", ["/static../etc/passwd", "/assets../etc/passwd",
                       "/media../etc/passwd", "/img../etc/passwd",
                       "/js../etc/passwd", "/css../etc/passwd",
                       "/public../etc/passwd", "/uploads../etc/passwd"]),
]


def nginx_alias_traversal_probe(ip: str, port: int, use_tls: bool) -> dict | None:
    """Try each `<mount>../etc/passwd` probe against known common
    static-content mount prefixes. Returns the first hit as
    {path, marker_line} or None."""
    for marker, paths in _ALIAS_TRAVERSAL_PROBES:
        for p in paths:
            r = _get(ip, port, use_tls, p, read_body=True)
            if r is None or r.get("status") != 200:
                continue
            body = r.get("body") or b""
            if marker.encode() in body:
                # Return the actual /etc/passwd root line as proof — cannot
                # be confused with an application 200 that happens to be big.
                line = next((ln for ln in body.split(b"\n")
                             if ln.startswith(b"root:")), b"")
                return {"path": p, "marker": line.decode("utf-8", "replace")}
    return None


# Version-disclosing headers → CVE-hint pairs. `Server` and `X-*-Version`
# families. Ordered by specificity so we surface the strongest signal first.
_VERSION_HEADER_KEYS = ("Server", "X-Powered-By", "X-AspNet-Version",
                          "X-AspNetMvc-Version", "X-Runtime", "X-Generator",
                          "X-Drupal-Cache", "X-Backend-Server", "Via")


def header_hygiene_findings(fp: dict) -> list[dict]:
    """Derive findings from the root response headers already captured by
    fingerprint(). Returns [{severity, title, output, remediation, cwes}, …].
    - Version-disclosing headers = information disclosure (low, but each
      product name/version fed into a CVE lookup is a real recon win).
    - Missing / weak CSP = a whole class of client-side bug. Parse and
      grade what's there rather than only flagging its absence."""
    out: list[dict] = []
    headers = (fp or {}).get("headers") or {}
    # Header keys are case-insensitive; normalise to lower-case lookup.
    hl = {k.lower(): v for k, v in headers.items()}
    disclosures = []
    for key in _VERSION_HEADER_KEYS:
        v = hl.get(key.lower())
        if v and any(ch.isdigit() for ch in v):
            disclosures.append((key, v))
    if disclosures:
        pairs = ", ".join(f"{k}: {v}" for k, v in disclosures[:6])
        out.append({
            "severity": "low",
            "title": "Version-disclosing HTTP headers",
            "output": (f"Response headers reveal product versions: {pairs}. "
                       "Each version string is a direct CVE lookup for the "
                       "attacker — remove or shorten these in production."),
            "cwes": ["CWE-200"],
            "remediation": ("Strip Server / X-Powered-By / X-AspNet-Version "
                            "at the reverse-proxy layer; disable "
                            "`expose_php`, remove ASP.NET version headers "
                            "(<httpProtocol>), set `server_tokens off` in "
                            "nginx, `ServerTokens Prod` in Apache."),
        })
    csp = hl.get("content-security-policy") or hl.get("content-security-policy-report-only")
    if csp:
        weak_directives = []
        low = csp.lower()
        if "'unsafe-inline'" in low:
            weak_directives.append("'unsafe-inline' (defeats XSS defense)")
        if "'unsafe-eval'" in low:
            weak_directives.append("'unsafe-eval' (permits eval/Function/setTimeout(str))")
        if re.search(r"(script-src|default-src)[^;]*\*(?!\.)", low):
            weak_directives.append("wildcard host in script-src/default-src")
        if "data:" in low and re.search(r"script-src[^;]*data:", low):
            weak_directives.append("data: scheme allowed for scripts")
        if "frame-ancestors" not in low:
            weak_directives.append("frame-ancestors missing (clickjacking exposure)")
        if "object-src" not in low:
            weak_directives.append("object-src missing (plugin content unrestricted)")
        if weak_directives:
            out.append({
                "severity": "low",
                "title": "Weak Content-Security-Policy",
                "output": ("The CSP header is present but has weak directives: "
                           + "; ".join(weak_directives) + ".\n\nFull policy: " + csp[:400]
                           + ("…" if len(csp) > 400 else "")),
                "cwes": ["CWE-1021", "CWE-693"],
                "remediation": ("Remove 'unsafe-inline' and 'unsafe-eval'; replace "
                                "wildcard sources with explicit hostnames; add "
                                "`frame-ancestors 'self'` (or `'none'`) and "
                                "`object-src 'none'`."),
            })
    elif fp is not None:                             # explicit absence check
        out.append({
            "severity": "info",
            "title": "No Content-Security-Policy header set",
            "output": "The root response carries no CSP header. Any reflected "
                      "or stored XSS runs freely; no clickjacking or plugin "
                      "restriction.",
            "cwes": ["CWE-1021"],
            "remediation": ("Set a Content-Security-Policy header. Start with "
                            "`default-src 'self'; object-src 'none'; "
                            "frame-ancestors 'none'; base-uri 'self'` and "
                            "widen as needed."),
        })
    return out


# Cache-poisoning primitives — headers that a fronting cache/CDN typically
# forwards but that also influence the application's response body. If the
# app reflects Host or X-Forwarded-Host into an absolute URL (canonical link,
# email link, password-reset), a poisoned cache entry sends every subsequent
# viewer to attacker-controlled content.
_CACHE_POISON_HEADERS = ("X-Forwarded-Host", "X-Original-URL",
                          "X-Rewrite-URL", "X-Forwarded-Scheme",
                          "X-Forwarded-Proto")


def cache_poisoning_probe(ip: str, port: int, use_tls: bool,
                            path: str = "/") -> list[dict]:
    """For each cache-influencing header, request `path` with the header set
    to a syntactically-valid canary host. If the canary appears in the
    response body or in an absolute-URL response header (Location,
    Content-Location, Link), the header is reflected — a poisonable
    surface. Returns [{header, evidence, where}, …]."""
    canary = "recce-canary.invalid"
    hits: list[dict] = []
    for hdr in _CACHE_POISON_HEADERS:
        r = _get(ip, port, use_tls, path, read_body=True,
                 extra_headers={hdr: canary})
        if r is None:
            continue
        body = r.get("body") or b""
        # Direct body reflection (canonical link, email templates, etc.).
        if canary.encode() in body:
            idx = body.find(canary.encode())
            snip = body[max(0, idx-32):idx+len(canary)+32].decode(
                "utf-8", "replace")
            hits.append({"header": hdr, "where": "body",
                          "evidence": snip.strip()})
            continue
        # Reflection into location-family response headers.
        resp_headers = r.get("headers") or {}
        for hk, hv in resp_headers.items():
            if canary in str(hv) and hk.lower() in (
                    "location", "content-location", "link", "refresh"):
                hits.append({"header": hdr, "where": f"response header {hk}",
                              "evidence": str(hv)[:200]})
                break
    return hits


# WebDAV: PROPFIND against discovered directory-ish paths. A 207
# Multi-Status response confirms WebDAV is enabled AND the current tester
# can enumerate the directory tree. Common on IIS misconfigs and
# Apache mod_dav_svn / mod_dav_fs leftovers.
def webdav_probe(ip: str, port: int, use_tls: bool,
                   candidate_paths: list[str] | None = None) -> list[dict]:
    """PROPFIND on each candidate path (defaults to '/' plus a few common
    WebDAV mounts). Returns [{path, status, contains_multistatus, size}, …]
    for each responder — 207 or 200 with a `<multistatus` body is a hit."""
    from urllib.request import Request, urlopen
    import ssl as _ssl
    candidates = candidate_paths or ["/", "/webdav/", "/dav/", "/share/",
                                      "/public/", "/files/", "/uploads/"]
    hits: list[dict] = []
    scheme = "https" if use_tls else "http"
    ctx = _ssl._create_unverified_context() if use_tls else None
    for path in candidates:
        url = f"{scheme}://{ip}:{port}{path}"
        try:
            req = Request(url, method="PROPFIND", headers={
                "Depth": "1",
                "Content-Type": "application/xml",
                "User-Agent": "recce-webdav-probe",
            }, data=b"")
            with urlopen(req, timeout=_REQ_TIMEOUT, context=ctx) as resp:
                body = resp.read(8192)
                status = resp.status
        except Exception as e:
            # urllib raises HTTPError for 4xx/5xx; the object still carries
            # the status. Anything else (timeout, DNS) is genuinely absent.
            from urllib.error import HTTPError
            if isinstance(e, HTTPError):
                body = e.read(8192) if hasattr(e, "read") else b""
                status = e.code
            else:
                continue
        is_multistatus = b"multistatus" in body.lower()
        if status == 207 or (status == 200 and is_multistatus):
            hits.append({"path": path, "status": status,
                          "contains_multistatus": is_multistatus,
                          "size": len(body)})
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


def enum_findings(host_ip: str, port: Port,
                  extra_paths: list[str] | None = None) -> list[Vuln]:
    """Run path enum + fingerprint against one HTTP port; produce Vulns.
    Called from `probes.http_findings` alongside the existing header checks.
    `extra_paths` augments the bundled `_PATHS` list — sourced from either
    a `--wordlist` CLI flag or `RECCE_HTTP_WORDLIST` env var."""
    from . import probes
    use_tls = probes._is_tls(port)

    out: list[Vuln] = []

    # Framework fingerprint — one root fetch, cheap.
    fp = fingerprint(host_ip, port.portid, use_tls)
    # Header-hygiene + CSP audit — derived from `fp['headers']` above, no
    # extra request. Emitted before path-enum so information-disclosure
    # findings sit near the fingerprint section they relate to.
    for f in header_hygiene_findings(fp):
        out.append(_mk(
            host_ip, port, "http-header-hygiene", f["severity"], f["title"],
            f["cwes"], f["output"], f["remediation"]))
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

    # Path enum — the meat. Merges bundled _PATHS with the user's
    # optional wordlist so both fire in one pool.
    hits = path_enum(host_ip, port.portid, use_tls, extra_paths=extra_paths)
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

    # Backup-file variants of every disclosed path — often served as static
    # files that bypass application-level access controls (config.php auth-
    # gated, config.php.bak served as text/plain).
    disclosure_paths = [h["path"] for h in hits
                        if h.get("category") == "disclosure" and h.get("status") == 200]
    if disclosure_paths:
        catchall = _catchall_signature(host_ip, port.portid, use_tls)
        backup_hits = probe_backup_variants(host_ip, port.portid, use_tls,
                                             disclosure_paths, catchall)
        for bh in backup_hits:
            out.append(_mk(
                host_ip, port, "http-backup-variant", "high",
                f"Backup variant exposed: {bh['path']}",
                ["CWE-538"],
                f"HTTP {bh['status']} · derived from disclosed path {bh['seed']} "
                f"(body {bh['length']} bytes). Backup files are commonly served as "
                f"static content, bypassing any application-layer auth on the "
                f"original path.",
                f"Block *.bak, *.old, *.orig, *~, *.swp, *.backup variants at the "
                f"web-server layer; consider a nginx `location ~* \\.(bak|old|~)$ "
                f"{{ deny all; }}` rule."))

    # Directory-listing detection — a 200 on a path with an autoindex response
    # discloses far more than the single-file finding path_enum saw.
    for h in hits[:10]:                            # cap refetch cost
        if h.get("status") != 200 or h.get("category") != "surface":
            continue
        r = _get(host_ip, port.portid, use_tls, h["path"], read_body=True)
        if r is not None and is_directory_listing(r.get("body") or b""):
            out.append(_mk(
                host_ip, port, "http-directory-listing", "medium",
                f"Directory listing enabled: {h['path']}",
                ["CWE-548"],
                f"HTTP 200 for {h['path']} returned an auto-generated directory "
                f"index. Every file in that directory is enumerated; a snapshot "
                f"often reveals dumps, backups, and unlinked test scripts.",
                "Apache: `Options -Indexes` in the vhost or .htaccess. "
                "nginx: remove `autoindex on;` from the location block. "
                "IIS: turn off Directory Browsing in Features View."))

    # JavaScript secret scanning — pull <script src> from the root page,
    # fetch same-host bundles, grep for API keys / tokens / hardcoded URLs.
    # Reuses the fingerprint's root fetch when possible to avoid duplicate work.
    js_hits = js_secret_scan(host_ip, port.portid, use_tls)
    # Aggregate by (source, secret) so a bundle with 5 hardcoded JWTs collapses
    # into one finding rather than five noisy ones.
    by_source: dict[str, list[dict]] = {}
    for jh in js_hits:
        by_source.setdefault(jh["source"], []).append(jh)
    for source, entries in list(by_source.items())[:8]:
        # Bail on endpoint-hint-only sources unless something else fires there
        # too — endpoint URLs alone are informational.
        real_secrets = [e for e in entries if e["secret"] != "endpoint_hint"]
        if not real_secrets and not entries:
            continue
        sev = "critical" if any(e["secret"] in ("aws_secret_key", "stripe_key",
                                                 "github_token", "gitlab_token")
                                for e in real_secrets) else \
              ("high" if real_secrets else "info")
        labels = sorted({e["secret"] for e in entries})
        snippets = "\n".join(f"  [{e['secret']}] {e['snippet']}" for e in entries[:6])
        out.append(_mk(
            host_ip, port, "http-js-secrets", sev,
            f"Secrets/hardcoded endpoints in JS bundle: {source}",
            ["CWE-798", "CWE-200"] if real_secrets else ["CWE-200"],
            f"{source}: {len(entries)} pattern hit(s) — {', '.join(labels)}\n{snippets}",
            "Never commit secrets to client-side JavaScript. Move authentication "
            "to a server-side proxy; rotate any exposed key immediately."))

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

    # Spring Boot Actuator deep-enum. High-value on Java stacks — /env and
    # /heapdump dump every credential the app is holding.
    actuator_hits = actuator_probe(host_ip, port.portid, use_tls)
    for h in actuator_hits:
        sev = h["severity"]
        status_note = "" if h["status"] == 200 else f" (status {h['status']} — endpoint present, auth may be default)"
        out.append(_mk(
            host_ip, port, "http-actuator", sev,
            f"Spring Boot Actuator exposed: {h['path']}",
            ["CWE-200", "CWE-497"] if h["endpoint"] in ("env", "heapdump")
            else ["CWE-200"],
            f"{h['path']} responded with {h['length']} bytes{status_note}. "
            f"{h['description']}",
            f"Disable the {h['endpoint']} Actuator endpoint (management."
            f"endpoints.web.exposure.exclude={h['endpoint']}) or require "
            "authentication for /actuator/*."))

    # Nginx alias-traversal probe (CVE-2018-16843 pattern). One-shot, safe.
    alias = nginx_alias_traversal_probe(host_ip, port.portid, use_tls)
    if alias:
        out.append(_mk(
            host_ip, port, "http-nginx-alias", "critical",
            f"nginx alias-traversal — arbitrary file read via {alias['path']}",
            ["CWE-22"],
            f"GET {alias['path']} returned /etc/passwd. First line: "
            f"{alias['marker']!r}. The nginx `alias` directive is missing a "
            "trailing slash on its `location` block, so `<mount>../` "
            "resolves ABOVE the intended root.",
            "Add a trailing slash to the affected `location` prefix (e.g. "
            "`location /static/ { alias /var/www/static/; }`) OR switch "
            "`alias` to `root`, which is not affected."))

    # Cache-poisoning surface — the reflection is the primitive; the actual
    # cache exploit is fronting-cache dependent, so flag it as medium.
    cp_hits = cache_poisoning_probe(host_ip, port.portid, use_tls)
    if cp_hits:
        seen: set = set()
        for hit in cp_hits:
            key = (hit["header"], hit["where"])
            if key in seen:
                continue
            seen.add(key)
            out.append(_mk(
                host_ip, port, "http-cache-poison", "medium",
                f"Reflected header primitive: {hit['header']} → {hit['where']}",
                ["CWE-444"],
                f"Setting {hit['header']}: <canary> caused the canary to "
                f"appear in the response {hit['where']}. Evidence: "
                f"{hit['evidence']!r}. If a fronting cache/CDN caches the "
                "response, the next viewer of the cached entry receives "
                "attacker-controlled content.",
                f"Do not reflect {hit['header']} into response bodies or "
                "location-family headers; validate against an allowlist of "
                "expected hostnames; ensure cache key includes the "
                "reflected header."))

    # WebDAV method enum — PROPFIND against likely dir paths. A 207 confirms
    # the tree walks. Distinct from the generic methods_probe finding above
    # (which only fires if PROPFIND is listed in OPTIONS).
    dav_hits = webdav_probe(host_ip, port.portid, use_tls)
    if dav_hits:
        for h in dav_hits[:4]:
            out.append(_mk(
                host_ip, port, "http-webdav", "medium",
                f"WebDAV PROPFIND accepted at {h['path']}",
                ["CWE-284"],
                f"PROPFIND {h['path']} returned status {h['status']} "
                f"({h['size']} bytes; multistatus="
                f"{h['contains_multistatus']}). WebDAV is enabled — an "
                "attacker can walk the directory tree and (if PUT is also "
                "routed) upload files.",
                "Disable WebDAV on public endpoints (Apache: `Dav Off`; "
                "IIS: remove WebDAV module; nginx: remove `dav_methods`)."))

    return out
