"""Jupyter Server / JupyterHub (8888, 8000, 8443) — arbitrary Python
execution surface when reachable without auth.

Jupyter Server and JupyterHub both speak the same Tornado-backed HTTP
API. When an instance is reachable without a token or password, the
`/api/kernels` endpoint spawns a full Python kernel — effectively a
remote code-execution primitive that runs as the notebook user. Even
short of that, `/api/contents` walks the notebook tree and lets an
attacker read arbitrary `.ipynb` files (which are the number-one place
data-science teams commit AWS keys, DB connection strings and OAuth
tokens by mistake).

Findings this module can emit:

  * jupyter_reachable (medium, t1) — the Tornado server answered /api
    with a Jupyter version payload. Reachable Jupyter is a spraying and
    token-guessing target even before we can prove unauth.
  * jupyter_version (info, t0) — the running Jupyter version string.
  * jupyter_no_auth_kernel_spawn (critical, t2) — GET /api/kernels
    returned 200 with a JSON list without a token. That means POST
    /api/kernels would spawn a kernel and any /api/kernels/<id>/execute
    call would run attacker Python. WE NEVER SEND POST — the emit is
    proven on the GET response alone (200 + JSON list is the Jupyter
    contract on the no-auth path).
  * jupyter_contents_listable (high, t2) — GET /api/contents returned
    the notebook filesystem tree without a token. Notebook files
    routinely embed cleartext secrets.
  * jupyterhub_present (info, t1) — the /hub/api/info endpoint
    identified this as JupyterHub (multi-tenant) rather than a plain
    single-user Jupyter Server.

Rules honoured (see the workflow contract):
  * SAFE probes only: single-shot, bounded, no writes, no POST/PUT/
    DELETE, no login attempts, no kernel spawning.
  * Fingerprinted via response body/header signatures — never assumed
    from the port number alone.
  * CVE emissions are NOT shipped here — CVE-2022-24737 and
    CVE-2024-22421 are noted in the narrative for the operator but not
    emitted as findings, because the module does not confirm the
    vulnerable configuration in a way that meets the "version-gated,
    never unverified" bar.

Airgap-safe: stdlib http.client + ssl. Bounded (~5 GETs, 3s each).
"""
from __future__ import annotations

import http.client
import json
import re
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 8888
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"

# Ports where a Jupyter/JupyterHub HTTP surface plausibly lives. The port
# filter is intentionally loose — the fingerprint step in probe() is what
# actually decides whether we treat a response as Jupyter.
_HTTP_PORTS = (8888, 8000, 8443)


def is_jupyter_http(port: Port) -> bool:
    """Loose port + service gate. Real filtering happens in probe() via
    the response fingerprint — a random webapp on 8000 will fail the
    fingerprint check and never emit a finding."""
    if port.portid not in _HTTP_PORTS:
        return False
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    # nmap may have left the service as generic 'http', 'unknown', or
    # already tagged 'jupyter'/'tornado' — accept them all; the body
    # fingerprint below is authoritative.
    return ("http" in svc or "http" in prod or "jupyter" in svc
            or "jupyter" in prod or "tornado" in svc or "tornado" in prod
            or svc in ("", "unknown"))


def _http(ip: str, port: int, path: str, timeout: float = _TIMEOUT):
    """One GET. Tries HTTP first, falls back to HTTPS if the first
    handshake fails (8443 is TLS-first). Returns (status, headers, body)
    or None if the target is dead."""
    # 8443 is conventionally TLS; the others are usually plain HTTP.
    schemes = (True, False) if port == 8443 else (False, True)
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


# --- Fingerprint + version parsing ------------------------------------------

_TORNADO_HEADER = re.compile(r"tornadoserver", re.IGNORECASE)
_JUPYTER_BODY = re.compile(rb"jupyter", re.IGNORECASE)
_HUB_BODY = re.compile(rb'"hub"|jupyterhub', re.IGNORECASE)
_VERSION_RE = re.compile(r"(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?")


def _looks_like_jupyter(status: int, hdrs: dict, body: bytes) -> bool:
    """A response is Jupyter/JupyterHub if the Server header names
    TornadoServer OR the body contains 'jupyter'/'hub'. Either signal
    alone is sufficient — reverse proxies routinely strip Server."""
    if _TORNADO_HEADER.search(hdrs.get("server", "")):
        return True
    if body and _JUPYTER_BODY.search(body):
        return True
    if body and _HUB_BODY.search(body):
        return True
    return False


def _parse_version(text: str) -> str:
    """Extract the first 'X.Y[.Z]' triple from a Jupyter /api response.
    Returns '' when nothing parseable is present."""
    if not text:
        return ""
    m = _VERSION_RE.search(text)
    if not m:
        return ""
    parts = [m.group(1), m.group(2)]
    if m.group(3):
        parts.append(m.group(3))
    return ".".join(parts)


# --- Probe --------------------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Return a dict describing what the Jupyter HTTP surface exposes.
    Never raises. Every key is present so callers can index without
    `.get(k, default)` gymnastics."""
    out: dict = {
        "reachable": False,
        "version": "",
        "version_source": "",
        "is_hub": False,               # jupyterhub_present
        "kernels_no_auth": False,      # jupyter_no_auth_kernel_spawn
        "contents_no_auth": False,     # jupyter_contents_listable
        "server_header": "",
    }

    # Step 1 — /api is the Jupyter Server root; it returns {"version": ...}
    # unauthenticated on every current release. The response body is our
    # primary fingerprint carrier.
    r = _http(ip, port, "/api", timeout)
    if r is not None:
        status, hdrs, body = r
        out["server_header"] = str(hdrs.get("server", ""))[:120]
        if _looks_like_jupyter(status, hdrs, body):
            out["reachable"] = True
            if status == 200:
                try:
                    j = json.loads(body.decode("utf-8", "replace"))
                    v = str(j.get("version") or "")
                    parsed = _parse_version(v)
                    if parsed:
                        out["version"] = parsed
                        out["version_source"] = "/api"
                except (ValueError, UnicodeDecodeError):
                    pass

    # Step 2 — fall back to /tree (the HTML file browser) if /api didn't
    # answer as Jupyter — some deployments front /api with an auth
    # middleware but leave /tree open long enough to fingerprint.
    if not out["reachable"]:
        r = _http(ip, port, "/tree", timeout)
        if r is not None and _looks_like_jupyter(r[0], r[1], r[2]):
            out["reachable"] = True
            out["server_header"] = str(r[1].get("server", ""))[:120]

    if not out["reachable"]:
        return out

    # Step 3 — JupyterHub-specific fingerprint. /hub/api/info returns
    # {"version": "...", "python": "..."} when this is JupyterHub (not
    # a bare Jupyter Server).
    r = _http(ip, port, "/hub/api/info", timeout)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            if isinstance(j, dict) and (j.get("version") or j.get("python")):
                out["is_hub"] = True
                if not out["version"]:
                    parsed = _parse_version(str(j.get("version") or ""))
                    if parsed:
                        out["version"] = parsed
                        out["version_source"] = "/hub/api/info"
        except (ValueError, UnicodeDecodeError):
            pass

    # Step 4 — CRITICAL check: /api/kernels. When unauth is granted
    # the endpoint answers 200 with a JSON list (empty [] if no kernel
    # currently exists). A 403 / 401 / redirect means auth is enforced.
    # WE NEVER POST — that would spawn a kernel; the GET response is
    # sufficient proof that a POST would succeed.
    r = _http(ip, port, "/api/kernels", timeout)
    if r is not None and r[0] == 200:
        body = r[2] or b""
        try:
            j = json.loads(body.decode("utf-8", "replace"))
            # Jupyter's /api/kernels always returns a JSON list. Anything
            # else is a fronting proxy's stub page — reject.
            if isinstance(j, list):
                out["kernels_no_auth"] = True
        except (ValueError, UnicodeDecodeError):
            pass

    # Step 5 — HIGH check: /api/contents. When unauth is granted the
    # endpoint answers 200 with a JSON dict describing the notebook
    # directory tree.
    r = _http(ip, port, "/api/contents", timeout)
    if r is not None and r[0] == 200:
        body = r[2] or b""
        try:
            j = json.loads(body.decode("utf-8", "replace"))
            # /api/contents returns a dict with a 'content' key on a
            # directory listing. Guard against a bare 200 HTML stub.
            if isinstance(j, dict) and ("content" in j or "type" in j):
                out["contents_no_auth"] = True
        except (ValueError, UnicodeDecodeError):
            pass

    return out


def jupyterhub_targets(hosts: list[Host]) -> list[dict]:
    """Module-scope function (matches the _module_scoped_check qualname
    rule enforced by the WebUI scanner-picker). Returns [{ip, port,
    version}] for each open port that looks like it could front a
    Jupyter/JupyterHub HTTP surface."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_jupyter_http(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


# --- Findings ---------------------------------------------------------------

_NARRATIVE = {
    "jupyter_reachable": (
        "A Jupyter Server or JupyterHub answered on this HTTP surface. "
        "Jupyter is Python execution as a service — an attacker who "
        "gets a token or catches a session runs arbitrary code as the "
        "notebook user, with access to whatever files, credentials, and "
        "network reachability that user has."),
    "jupyter_version": (
        "Jupyter version disclosure lets an attacker map the exact build "
        "to public CVEs — including CVE-2022-24737 (HistoryManager path "
        "traversal in older Jupyter Notebook / JupyterHub) and "
        "CVE-2024-22421 (LabHub XSS). Verify build against the CVE gates "
        "before claiming exploitability."),
    "jupyter_no_auth_kernel_spawn": (
        "GET /api/kernels returned 200 with a JSON list without a token. "
        "The Jupyter contract is that any client that can enumerate "
        "kernels can also POST /api/kernels to spawn a new one and then "
        "POST /api/kernels/<id>/execute to run arbitrary Python — the "
        "same code path a notebook cell runs. This is remote code "
        "execution as the notebook user."),
    "jupyter_contents_listable": (
        "GET /api/contents returned the notebook filesystem tree "
        "without a token. Notebook files (.ipynb) are JSON documents "
        "that routinely embed cleartext secrets (DB URIs, cloud keys, "
        "OAuth tokens, model API keys) that got pasted into a cell for "
        "a quick experiment and never cleaned up."),
    "jupyterhub_present": (
        "The /hub/api/info endpoint identified this as JupyterHub "
        "(multi-tenant) rather than a plain single-user Jupyter Server. "
        "A successful token/cred against Hub grants a spawned kernel "
        "per user; user-list disclosure and admin-panel routes are "
        "specific to Hub."),
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
            if not is_jupyter_http(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            # CRITICAL — /api/kernels reachable without a token.
            if pr.get("kernels_no_auth"):
                out.append(_finding(
                    "critical",
                    "Jupyter /api/kernels reachable without authentication "
                    "(RCE primitive)",
                    tgt,
                    "GET /api/kernels returned 200 with a JSON kernel list "
                    "without a token or password. The Jupyter contract is "
                    "that any client that can enumerate kernels can also "
                    "POST /api/kernels to spawn a new one and then execute "
                    "arbitrary Python on it via /api/kernels/<id>/execute. "
                    "This probe deliberately DID NOT POST — the 200 GET "
                    "response alone is proof the write path is open. "
                    "Treat this endpoint as remote code execution as the "
                    "notebook process user.",
                    f"curl -sk http://{h.ip}:{p.portid}/api/kernels",
                    "Enforce token authentication (jupyter server "
                    "--ServerApp.token=<random>) or password auth. Bind the "
                    "server to 127.0.0.1 and front with an authenticating "
                    "reverse proxy for shared access. On JupyterHub, "
                    "confirm the Hub authenticator is enforced end-to-end.",
                    ["CWE-306", "CWE-284", "CWE-94"],
                    kind="jupyter_no_auth_kernel_spawn",
                    exploit_note=(
                        "# Confirm reachable (GET only, this probe's step): "
                        "curl -sk http://<ip>:<port>/api/kernels; "
                        "# then spawn a kernel and exec Python (destructive - "
                        "operator-approved only): "
                        "KID=$(curl -sk -X POST http://<ip>:<port>/api/kernels "
                        "| jq -r .id); "
                        "wscat -c ws://<ip>:<port>/api/kernels/$KID/channels"),
                    depth_tier="t2"))

            # HIGH — /api/contents readable without a token.
            if pr.get("contents_no_auth"):
                out.append(_finding(
                    "high",
                    "Jupyter /api/contents readable without authentication",
                    tgt,
                    "GET /api/contents returned the notebook filesystem "
                    "tree without a token. Notebook (.ipynb) files are "
                    "JSON documents that routinely embed cleartext "
                    "secrets — DB connection strings, cloud API keys, "
                    "OAuth tokens — pasted into a cell for a one-off "
                    "experiment and never cleaned up. Enumerate the "
                    "tree, pull each notebook, and grep the cells.",
                    f"curl -sk http://{h.ip}:{p.portid}/api/contents",
                    "Enforce token or password authentication on the "
                    "Jupyter server. Notebook contents should never be "
                    "readable anonymously; audit the ServerApp.token / "
                    "PasswordIdentityProvider configuration.",
                    ["CWE-306", "CWE-200", "CWE-538"],
                    kind="jupyter_contents_listable",
                    exploit_note=(
                        "curl -sk http://<ip>:<port>/api/contents "
                        "| jq -r '.content[] | .path' "
                        "| xargs -I{} curl -sk "
                        "\"http://<ip>:<port>/api/contents/{}\" "
                        "| jq -r '.content.cells[]?.source[]?' "
                        "| grep -aEi 'password|api[_-]?key|AKIA[0-9A-Z]{16}|"
                        "BEGIN [A-Z ]*PRIVATE|xox[abpr]-[0-9A-Za-z-]+'"),
                    depth_tier="t2"))

            # INFO — JupyterHub-specific fingerprint (multi-tenant).
            if pr.get("is_hub"):
                out.append(_finding(
                    "info",
                    "JupyterHub multi-tenant deployment detected",
                    tgt,
                    "/hub/api/info identified this endpoint as "
                    "JupyterHub, not a bare single-user Jupyter Server. "
                    "Hub grants per-user spawned kernels, so a "
                    "recovered credential yields an authenticated "
                    "Python-execution environment.",
                    f"curl -sk http://{h.ip}:{p.portid}/hub/api/info",
                    "Ensure the Hub authenticator matches the "
                    "organization's IdP; require MFA at the reverse "
                    "proxy in front of Hub for external exposure.",
                    ["CWE-284"], kind="jupyterhub_present",
                    exploit_note=(
                        "curl -sk http://<ip>:<port>/hub/api/info; "
                        "# then, with a token: "
                        "curl -sk -H 'Authorization: token <t>' "
                        "http://<ip>:<port>/hub/api/users"),
                    depth_tier="t1"))

            # INFO — version disclosure (lifts to high if a critical
            # unauth-kernel finding was also emitted).
            if pr.get("version"):
                sev = "high" if pr.get("kernels_no_auth") else "info"
                out.append(_finding(
                    sev,
                    f"Jupyter version {pr['version']} disclosed",
                    tgt,
                    f"Version {pr['version']} disclosed via "
                    f"{pr.get('version_source') or '/api'}. Version pins "
                    "the exact CVE set — check CVE-2022-24737 "
                    "(HistoryManager path traversal, older Notebook / "
                    "JupyterHub) and CVE-2024-22421 (LabHub XSS) against "
                    "this build.",
                    f"curl -sk http://{h.ip}:{p.portid}/api",
                    "Strip the version from /api at the reverse proxy, "
                    "and require authentication for /api endpoints.",
                    ["CWE-200"], kind="jupyter_version",
                    exploit_note=(
                        "curl -sk http://<ip>:<port>/api "
                        "# then: searchsploit jupyter <version>"),
                    depth_tier="t0"))

            # MEDIUM — reachable marker (always emit last so a summary
            # includes the target even when nothing worse was found).
            out.append(_finding(
                "medium",
                "Jupyter/JupyterHub HTTP surface reachable",
                tgt,
                (f"Jupyter detected on {tgt}. "
                 f"version={pr.get('version') or '?'}, "
                 f"hub={pr.get('is_hub')}, "
                 f"kernels_no_auth={pr.get('kernels_no_auth')}, "
                 f"contents_no_auth={pr.get('contents_no_auth')}, "
                 f"server='{pr.get('server_header') or '?'}'. "
                 "Reachable Jupyter is a token-guessing / credential "
                 "spraying target even before we can prove unauth."),
                f"curl -sk http://{h.ip}:{p.portid}/api",
                "Restrict Jupyter exposure to VPN or an authenticating "
                "reverse proxy; require a strong token or password.",
                ["CWE-284"], kind="jupyter_reachable",
                exploit_note=(
                    "curl -sk http://<ip>:<port>/api; "
                    "curl -sk http://<ip>:<port>/api/kernels; "
                    "curl -sk http://<ip>:<port>/api/contents"),
                depth_tier="t1"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Fingerprint (Jupyter /api)",
         "cmd": f"curl -sk http://{ip}:{port}/api"},
        {"step": "JupyterHub info",
         "cmd": f"curl -sk http://{ip}:{port}/hub/api/info"},
        {"step": "Kernels (RCE oracle - GET only, do NOT POST here)",
         "cmd": f"curl -sk http://{ip}:{port}/api/kernels"},
        {"step": "Notebook filesystem",
         "cmd": f"curl -sk http://{ip}:{port}/api/contents"},
        {"step": "HTML file browser",
         "cmd": f"curl -sk http://{ip}:{port}/tree"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "jupyterhub", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = jupyterhub_targets(hosts)
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
                t["is_hub"] = pr.get("is_hub", False)
                t["kernels_no_auth"] = pr.get("kernels_no_auth", False)
                t["contents_no_auth"] = pr.get("contents_no_auth", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
