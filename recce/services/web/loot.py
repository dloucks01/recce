"""Data-leak probes: .git/.env, backups, actuator, sourcemaps, API keys, stack traces.

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


# Shared primitives — every probe fetches through _fetch / _mk / etc.
from .http import *  # noqa: F401,F403
from .crawl import *  # noqa: F401,F403

__all__ = ['_URL_CRED_RE', '_ENV_USER_RE', '_ENV_PASS_RE', '_web_credentials', '_DEBUG_MARKERS', '_scan_debug', '_scan_git_dump', '_ACTUATOR_SUB', '_scan_actuator', '_BACKUPS', '_confirm_backup', '_scan_backups', '_JS_SECRETS', '_SCRIPT_SRC', '_scan_js', '_SOURCEMAP_RE', '_resolve', '_scan_sourcemaps', '_STACK_MARKERS', '_check_error_stack_trace', '_MAX_KEY_FINDINGS', '_extract_api_keys']


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
    from ...models import Credential
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




def _scan_git_dump(ip: str, port: Port, auth: dict | None, findings: list) -> list:
    """Reconstruct an exposed .git over HTTP: recover the tracked source tree, mine the
    recovered files for secrets/credentials, and emit a web-git-dump finding. Returns the
    captured Credential objects (folded into the profile's credential loot)."""
    from .. import gitdump
    from ...models import Credential

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
    from .. import gitdump
    from ...models import Credential
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
            # Cap per-item content: gitdump._mine's secret regex has enough greedy
            # alternation to backtrack heavily on adversarial bytes, and 8MB of
            # attacker-controlled sourcesContent[i] can stall the scanner for tens
            # of seconds. A few hundred KB is enough to recover meaningful secrets.
            if len(content) > 262144:
                content = content[:262144]
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




_STACK_MARKERS = re.compile(
    r"traceback \(most recent call last\)|at\s+[\w.]+\.\w+\([^)]*\.(?:java|kt|scala):\d+\)|"
    r"\bat line \d+|\.php on line \d+|thrown in|"
    r"stack trace:|<b>fatal error</b>", re.I)




def _check_error_stack_trace(ip: str, port: Port, base: str, auth: dict | None) -> list[Vuln]:
    """Stack-trace disclosure via error conditions. Uses tight patterns keyed to
    real framework output (Python traceback header, Java at-line frames, PHP fatal
    error) - a loose match on 'exception' or 'error_code' fires on any properly-
    written error message."""
    probes = [
        ("/?_invalid_param_!@#$%", "PHP/Java/Python stack trace"),
        ("/?action=nonexistent", "action parameter"),
        ("/?id=abc", "type mismatch (string for int)"),
    ]
    for path, desc in probes:
        try:
            r = _fetch(ip, port, path, auth=auth, read=8192)
            if r and r[0] >= 400 and _STACK_MARKERS.search(r[2]):
                return [_mk(ip, port, "web-error-trace", "medium",
                    "Stack trace / Debug info disclosure in error responses", ["CWE-209"],
                    f"Error response included stack trace or debug info: {desc}",
                    "Use generic error messages in production; log details server-side only",
                    confidence="potential")]
        except Exception:
            pass
    return []




_MAX_KEY_FINDINGS = 5




def _extract_api_keys(ip: str, port: Port, body: str) -> list[Vuln]:
    """Scan JavaScript for hardcoded API keys, tokens, secrets. Emission is capped
    (an adversarial body of `apikey=aaaa;apikey=aaaa;...` otherwise produces
    hundreds of critical findings that pollute the store and CSV/XLSX exports).
    Redacted output is stripped of control characters that would corrupt rows."""
    findings = []
    seen: set[str] = set()
    patterns = [
        (r"(?:api[_-]?)?key['\"]?\s*[:=]\s*['\"]([a-z0-9]{20,})['\"]", "API key"),
        (r"authorization['\"]?\s*[:=]\s*['\"]Bearer\s+([a-z0-9\-_.]+)['\"]", "Bearer token"),
        (r"(?:aws|amazon)[_-]?(?:access|secret)[_-]?key['\"]?\s*[:=]\s*['\"]([A-Z0-9]{16,})['\"]", "AWS key"),
        (r"stripe[_-]?(?:public|secret)[_-]?key['\"]?\s*[:=]\s*['\"]([a-z]{2}_[a-z0-9]{24,})['\"]", "Stripe key"),
    ]
    for pattern, key_type in patterns:
        for match in re.finditer(pattern, body, re.I):
            if len(findings) >= _MAX_KEY_FINDINGS:
                return findings
            val = match.group(1)
            if val in seen:
                continue
            seen.add(val)
            core = val[:4] + "*" * min(max(len(val) - 8, 0), 40) + val[-4:] if len(val) > 8 else "***"
            redacted = re.sub(r"[\x00-\x1f\x7f]", "", core)[:80]
            findings.append(_mk(ip, port, "web-hardcoded-secret", "critical",
                f"Hardcoded {key_type} in JavaScript", ["CWE-798"],
                f"Found {key_type} in response: {redacted}",
                "Remove all credentials from client-side code",
                confidence="confirmed"))
    return findings
