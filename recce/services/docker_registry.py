"""Docker Registry v2 probe.

Distinct from the Docker Engine API (2375/2376) — the registry is a
separate service that hosts image layers. On a default deployment it
runs unauthenticated on port 5000 and answers /v2/_catalog with the
full repository list. Layers can then be pulled with `docker pull`,
extracted, and mined for embedded secrets (env vars set at build
time, credentials committed by mistake, private keys in the layer FS).

Findings:
  * dockerreg_anonymous_catalog (HIGH) — /v2/_catalog returned
    repositories without authentication. Every image on this registry
    is anyone's for pulling.
  * dockerreg_auth_required (info) — /v2/ returned 401 with a
    WWW-Authenticate: Bearer challenge. Any looted registry cred
    targets this endpoint.

Airgap-safe: stdlib http.client + ssl. Bounded — 2 GETs, 3s each.
"""
from __future__ import annotations

import http.client
import json
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 5000
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"


def is_docker_registry(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (5000, 5001, 5002, 443, 5443)
            and ("registry" in svc or "registry" in prod
                 or "docker" in svc or "docker" in prod)
            or port.portid == 5000)


def _http(ip: str, port: int, path: str, timeout: float = _TIMEOUT):
    """One GET. Transparently retries HTTPS if HTTP fails handshake. Returns
    (status, headers, body) or None."""
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request("GET", path,
                         headers={"User-Agent": _UA, "Connection": "close"})
            resp = conn.getresponse()
            body = resp.read(500_000)
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdrs, body
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if not use_tls:
                continue
            return None
        finally:
            if conn is not None:
                try: conn.close()
                except OSError: pass
    return None


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Return {reachable, auth_required, catalog, repositories}."""
    out = {"reachable": False, "auth_required": False,
           "catalog": [], "repositories": 0}
    # /v2/ is the registry API version check per Docker Registry v2 spec.
    # 200 = anon works. 401 with Bearer challenge = auth required.
    r = _http(ip, port, "/v2/", timeout)
    if r is None:
        return out
    status, hdrs, body = r
    # A random HTTP service that isn't a registry will return other codes;
    # Docker-Distribution-Api-Version is the tell.
    ddapi = hdrs.get("docker-distribution-api-version", "").lower()
    www_auth = hdrs.get("www-authenticate", "").lower()
    # Definitive tell: Docker-Distribution-Api-Version header. Fallback:
    # a 401 whose Bearer challenge references a registry realm.
    is_registry = ("registry/2" in ddapi
                   or (status == 401 and "bearer" in www_auth
                       and "registry" in www_auth))
    if not is_registry:
        return out
    out["reachable"] = True
    if status == 401:
        out["auth_required"] = True
        return out
    # Anon /v2/ succeeded — try /v2/_catalog.
    r = _http(ip, port, "/v2/_catalog?n=200", timeout)
    if r is None:
        return out
    if r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            repos = j.get("repositories") or []
            out["catalog"] = repos[:100]
            out["repositories"] = len(repos)
        except (ValueError, UnicodeDecodeError):
            pass
    return out


def docker_registry_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_docker_registry(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "docker", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_docker_registry(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            if pr.get("catalog"):
                repos_txt = ", ".join(pr["catalog"][:15])
                out.append(_finding(
                    "high",
                    "Docker Registry v2 catalog readable without auth", tgt,
                    f"/v2/_catalog returned {pr['repositories']} repositor(y|ies) "
                    f"anonymously: {repos_txt}"
                    + ("… (truncated)" if pr['repositories'] > 15 else "") +
                    ". Any of these images can be pulled with `docker pull`, "
                    "extracted, and mined for secrets baked into layers "
                    "(env variables, config files, private keys committed at "
                    "build time).",
                    "docker",
                    f"curl -sk http://{h.ip}:{p.portid}/v2/_catalog?n=1000; "
                    f"docker pull {h.ip}:{p.portid}/<repo>:latest",
                    "Enable authentication (htpasswd, token, or OAuth2). Bind "
                    "the registry to a private interface. If public registry "
                    "access is required, gate at least the write path.",
                    ["CWE-306", "CWE-284", "CWE-200"],
                    kind="dockerreg_anonymous_catalog",
                    exploit_note=(
                        "curl -sk http://<ip>:5000/v2/_catalog?n=1000; for r in "
                        "<repos>; do docker pull <ip>:5000/$r:latest; docker save "
                        "<ip>:5000/$r:latest | tar -xO | grep -Ei "
                        "'password|api_key|BEGIN.*PRIVATE'; done"),
                    depth_tier="t1"))
            elif pr.get("auth_required"):
                out.append(_finding(
                    "info", "Docker Registry v2 reachable (auth required)", tgt,
                    "Registry answered /v2/ with 401. Any looted registry "
                    "credential targets this endpoint.",
                    "docker",
                    f"docker login {h.ip}:{p.portid}",
                    "Ensure the registry keeps requiring auth on both read and write.",
                    [], kind="dockerreg_authed"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Fingerprint",
         "cmd": f"curl -sk http://{ip}:{port}/v2/"},
        {"step": "List repositories",
         "cmd": f"curl -sk http://{ip}:{port}/v2/_catalog?n=1000"},
        {"step": "Pull an image",
         "cmd": f"docker pull {ip}:{port}/<repo>:latest"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "docker-registry", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = docker_registry_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["repositories"] = pr.get("repositories", 0)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
