"""Content/vhost discovery + wordlist bruting.

Extracted from web.py. Every entry is re-exported through
web/__init__.py's wildcard import so `from recce.services.web import X`
keeps working for the split names too."""
from __future__ import annotations

import socket

from ...core.models import Port, Vuln
from .. import probes


# Shared primitives — every probe fetches through _fetch / _mk / etc.
from .http import *  # noqa: F401,F403
from .wordlists import *  # noqa: F401,F403
from .checks import *  # noqa: F401,F403

__all__ = ['_CONTENT_WORDS', '_CONTENT_HIGH', '_baseline_404', '_is_baseline', '_content_discovery', '_cert_names', '_page_shape', '_discover_vhosts', '_brute_wordlist_dirs', '_fuzz_parameters', '_fuzz_headers_wordlist', '_fuzz_cms_if_detected']


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
                            "a 200 an exposed one. Remove what shouldn't be reachable.",
                            depth_tier="t1",
                            exploit_note=(f"curl -sk {base}<path> for each notable listing above; 200 "
                                          "responses are exposed content. Pipe through ffuf -w rockyou-web.txt "
                                          "-u {base}/FUZZ -mc 200,301,302,401,403 to deepen enum.")))
    return findings


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




def _brute_wordlist_dirs(ip: str, port: Port, base: str, auth: dict | None, limit: int = 20) -> list[Vuln]:
    """Brute-force common directories using wordlist. Returns high-value findings only."""
    findings = []
    tested = set()
    # Prioritize by attack surface: admin > config > api > auth
    priority_lists = [
        ("admin", _WORDLIST_ADMIN),
        ("config", _WORDLIST_CONFIG),
        ("api", _WORDLIST_API),
        ("auth", _WORDLIST_AUTH_ENDPOINTS),
    ]

    for category, wordlist in priority_lists:
        for word in wordlist[:limit]:  # Limit per category
            if word in tested:
                continue
            tested.add(word)
            try:
                path = f"/{word}" if not word.startswith("/") else word
                r = _fetch(ip, port, path, auth=auth, read=2048)
                if r and r[0] in (200, 301, 302, 401, 403):
                    # High-value: admin panels, config files, APIs
                    if category in ("admin", "config"):
                        findings.append(_mk(ip, port, f"web-enum-{category}", "medium" if r[0] == 401 else "low",
                            f"{category.title()} path found: {word}", ["CWE-200"],
                            f"GET /{word} -> HTTP {r[0]}. Potential {category} endpoint.",
                            "Restrict access; require authentication", confidence="confirmed",
                            depth_tier="t1" if r[0] in (401, 403) else "t2" if r[0] == 200 else "t1",
                            exploit_note=(
                                f"curl -sk http{'s' if port.portid in (443,8443) else ''}://{ip}:{port.portid}/{word} — "
                                f"if 200, review body for creds/config; if 401, "
                                f"hydra -L users.txt -P passwords.txt http-get://{ip}:{port.portid}/{word} "
                                "or nxc smb/http default-cred spray; if 403, try "
                                "verb-tampering (X-HTTP-Method-Override: PUT), "
                                "path-traversal (/./{word}, /{word}/../{word}), or "
                                "case-swap (/ADMIN, /Admin).")))
            except Exception:
                pass
    return findings[:5]  # Return top 5 to avoid noise




def _fuzz_parameters(ip: str, port: Port, base: str, auth: dict | None, limit: int = 10) -> list[Vuln]:
    """Fuzz common parameters for injection/logic bugs."""
    findings = []
    params = wordlist_get_parameters()[:limit]

    # Test each parameter with simple probes
    for param in params:
        try:
            # Test 1: Boolean-based logic (id=1 vs id=0, id=true vs id=false)
            r1 = _fetch(ip, port, f"/?{param}=1", auth=auth, read=1024)
            r2 = _fetch(ip, port, f"/?{param}=0", auth=auth, read=1024)
            if r1 and r2 and r1[0] == 200 and r2[0] == 200:
                if len(r1[2]) != len(r2[2]):  # Content differs
                    findings.append(_mk(ip, port, "web-param-logic", "low",
                        f"Parameter logic difference: {param}", ["CWE-1025"],
                        f"Parameter {param} affects response size (1 vs 0 differ). May indicate type confusion.",
                        "Verify logic carefully; test with various types", confidence="potential"))
                    break

            # Test 2: Injection character acceptance
            r3 = _fetch(ip, port, f"/?{param}=test'", auth=auth, read=1024)
            if r3 and r3[0] in (500, 400):  # Error on quote = injection possible
                findings.append(_mk(ip, port, "web-param-injection", "medium",
                    f"Parameter {param} triggers error on special chars", ["CWE-89"],
                    f"GET ?{param}=test' -> HTTP {r3[0]}. Possible injection point.",
                    "Use parameterized queries; validate input", confidence="potential"))
                break
        except Exception:
            pass
    return findings




def _fuzz_headers_wordlist(ip: str, port: Port, auth: dict | None, limit: int = 10) -> list[Vuln]:
    """Test common headers for bypass/injection opportunities."""
    findings = []
    headers_to_test = wordlist_get_headers()[:limit]

    for header in headers_to_test:
        if "X-" not in header:  # Skip standard headers, focus on X-* custom
            continue
        try:
            test_value = "test-bypass-value-123"
            hdrs = {**(auth or {}), header: test_value}
            r = _fetch(ip, port, "/", auth=hdrs, read=2048)
            if r and test_value in r[2]:  # Header reflected
                findings.append(_mk(ip, port, "web-header-reflection", "low",
                    f"Custom header {header} reflected in response", ["CWE-79"],
                    f"Header {header} value appears in response body. Potential XSS if unescaped.",
                    "Never reflect user input; use sanitization", confidence="potential"))
        except Exception:
            pass
    return findings[:2]  # Limit to avoid noise




def _fuzz_cms_if_detected(ip: str, port: Port, base: str, fp: dict, auth: dict | None) -> list[Vuln]:
    """If a CMS is detected, test framework-specific paths."""
    findings = []
    if not fp.get("tech"):
        return findings

    tech_lower = [t.lower() for t in fp["tech"]]
    for cms, paths in wordlist_get_cms_paths().items():
        if any(cms in t for t in tech_lower):
            for path in paths[:5]:  # Limit per CMS
                try:
                    r = _fetch(ip, port, f"/{path}", auth=auth, read=2048)
                    if r and r[0] in (200, 301, 302, 401, 403):
                        findings.append(_mk(ip, port, f"web-cms-{cms}", "low",
                            f"{cms.upper()} path discovered: {path}", ["CWE-200"],
                            f"GET /{path} -> HTTP {r[0]}. Confirmed {cms} usage.",
                            "Keep framework updated; harden default paths", confidence="confirmed"))
                except Exception:
                    pass
            break
    return findings
