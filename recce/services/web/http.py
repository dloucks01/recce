"""HTTP transport primitives + fingerprinting shared across every probe.

Extracted from web.py. The primitives here are the foundation every
other split file (loot / auth / deserial / probes / crawl / discover)
wildcard-imports."""
from __future__ import annotations

import http.client
import re
import ssl

from ...core.models import Port, Vuln
from .. import probes
from ..svccommon import http_connect


__all__ = ['_TIMEOUT', '_UA', 'is_web', 'scheme_for', 'url_for', '_mk', '_fetch', '_fetch_raw', '_post_multipart', '_TITLE', '_GENERATOR', '_TECH_BODY', '_COOKIE_TECH', 'fingerprint', 'product_version', '_SECRET_RE', '_looks_like_html', '_leaked_secrets', '_resp_same']



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
        remediation: str, confidence: str = "confirmed",
        depth_tier: str = "", exploit_note: str = "") -> Vuln:
    return Vuln(ip=ip, port=port.portid, protocol=port.protocol, script_id=sid,
                state="finding", title=title, output=output, severity=sev,
                cwes=list(cwes), source="web", remediation=remediation,
                confidence=confidence, depth_tier=depth_tier,
                exploit_note=exploit_note)




def _fetch(ip: str, port: Port, path: str = "/", method: str = "GET", read: int = 16384,
           auth: dict | None = None, body: str | None = None):
    """One request. Returns (status, headers_lower, body_text) or None on failure.
    `auth` supplies extra request headers (Cookie / Authorization / custom) so the
    scan can run as an authenticated user; `body` sends a request body (POST)."""
    use_tls = probes._is_tls(port)
    conn = None
    try:
        conn = http_connect(ip, port.portid, use_tls, _TIMEOUT)
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
        conn = http_connect(ip, port.portid, use_tls, _TIMEOUT)
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




def _post_multipart(ip: str, port: Port, path: str, fields: dict, file_field: str,
                    filename: str, content: bytes, ctype: str = "image/jpeg",
                    auth: dict | None = None):
    """POST one multipart/form-data upload. `fields` are extra text parts (hidden form
    values). Returns (status, headers_lower, body_text) or None. Used only under the
    opt-in --upload-shell proof."""
    boundary = "----recce" + "".join(str((i * 7 + 3) % 10) for i in range(16))
    parts = []
    for k, v in (fields or {}).items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'
                     .encode("latin-1", "replace"))
    parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
                  f'filename="{filename}"\r\nContent-Type: {ctype}\r\n\r\n').encode("latin-1"))
    body = b"".join(parts) + content + f"\r\n--{boundary}--\r\n".encode()
    use_tls = probes._is_tls(port)
    conn = None
    try:
        conn = http_connect(ip, port.portid, use_tls, _TIMEOUT)
        hdrs = {"User-Agent": _UA, "Connection": "close", "Accept": "*/*",
                "Content-Type": f"multipart/form-data; boundary={boundary}"}
        if auth:
            hdrs.update({k: v for k, v in auth.items() if k.lower() != "content-type"})
        conn.request("POST", path, body=body, headers=hdrs)
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, \
            resp.read(65536).decode("latin-1", "replace")
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass



_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)


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




def _resp_same(a, b) -> bool:
    """Two HTTP responses look like the same authorization outcome: same status and a
    body length within a small tolerance (page-to-page jitter, not a login redirect)."""
    if a is None or b is None:
        return False
    if a[0] != b[0]:
        return False
    la, lb = len(a[2]), len(b[2])
    return abs(la - lb) <= max(64, int(0.10 * max(la, lb, 1)))
