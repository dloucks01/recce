"""Login-form / basic-auth / brute / OAuth / session probes.

Extracted from web.py. Every entry is re-exported through
web/__init__.py's wildcard import so `from recce.services.web import X`
keeps working for the split names too."""
from __future__ import annotations

import re
from urllib.parse import quote, urlencode, urljoin, urlparse

from ...core.models import Host, Port, Vuln


# Shared primitives — every probe fetches through _fetch / _mk / etc.
from .http import *  # noqa: F401,F403
from .crawl import *  # noqa: F401,F403

__all__ = ['_find_login_form', '_BASIC_DEFAULTS', '_MAX_BASIC_TRIES', '_basic_auth_defaults', '_APP_LOGINS', '_form_login_defaults', '_VALUE_RE', '_USERFIELD_RE', '_LOGIN_PATHS', '_LOGIN_FAIL', '_form_values', '_login_fields', '_session_cookie', '_looks_logged_out', '_form_login', 'autologin', '_brute_login_form', '_check_oauth_redirect', '_check_session_fixation']




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




def _brute_login_form(ip: str, port: Port, form: dict, base: str, auth: dict | None, creds_to_try: list) -> list[Vuln]:
    """Try common credentials against a login form. Returns a single finding per form."""
    if not form.get("password"):
        return []
    action = urljoin(base + "/", form["action"])
    method = form.get("method", "post")
    for username, password in creds_to_try[:3]:
        try:
            data = {}
            for name in form.get("inputs", []):
                if "pass" in name.lower():
                    data[name] = password
                elif "user" in name.lower() or "login" in name.lower() or "email" in name.lower():
                    data[name] = username
            path = urlparse(action).path or "/"
            r = _fetch(ip, port, path, method=method, body=urlencode(data), auth=auth, read=8192)
            if r and r[0] == 200:
                resp_lower = r[2].lower()
                if "password" not in resp_lower and "login" not in resp_lower and "invalid" not in resp_lower:
                    return [_mk(ip, port, "web-weak-creds", "high",
                        "Default/weak credentials accepted on login form", ["CWE-1391"],
                        f"Login form at {form['action']} accepted {username}:{password}",
                        "Enforce strong password policies; rate-limit logins",
                        confidence="potential")]
        except Exception:
            pass
    return []




def _check_oauth_redirect(ip: str, port: Port, auth: dict | None) -> list[Vuln]:
    """Open-redirect via a well-known redirect parameter. A real bypass 3xx-es to the
    attacker URL (Location header), so check headers - not just the body echo, which
    fires on any error page that reflects the request URL."""
    marker = "recce-redirect-probe.example"
    target = f"http://{marker}/evil"
    for param in ["redirect_uri", "return_url", "callback", "next"]:
        try:
            r = _fetch(ip, port, f"/login?{param}={quote(target)}", auth=auth, read=4096)
            if not r:
                continue
            loc = (r[1].get("location") or r[1].get("Location") or "") if r[1] else ""
            if r[0] in (301, 302, 303, 307, 308) and marker in loc:
                return [_mk(ip, port, "web-oauth-bypass", "high",
                    f"Open redirect via {param}", ["CWE-601"],
                    f"Parameter {param} caused a {r[0]} to attacker-controlled Location: {loc[:120]}",
                    "Validate redirect destinations against allow-list",
                    confidence="confirmed")]
        except Exception:
            pass
    return []




def _check_session_fixation(ip: str, port: Port, auth: dict | None) -> list[Vuln]:
    """Session fixation: test if session ID is reflected."""
    for param in ["sid", "sessionid", "phpsessid"]:
        try:
            test_val = "testsid123"
            r = _fetch(ip, port, f"/?{param}={test_val}", auth=auth, read=2048)
            if r and test_val in r[2]:
                return [_mk(ip, port, "web-session-fixation", "medium",
                    f"Session fixation via {param}", ["CWE-384"],
                    f"Session parameter {param} was reflected in response",
                    "Use random SIDs; don't accept them from user input",
                    confidence="potential")]
        except Exception:
            pass
    return []
