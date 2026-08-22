"""API enumeration — discover REST/OpenAPI and GraphQL surface on web services.

recce already fingerprints a lot of web exposures; this focuses the API angle: published
OpenAPI/Swagger specs (which map the whole attack surface), interactive API explorers
(Swagger UI / ReDoc / GraphiQL), and GraphQL introspection. Read-only GETs plus one GraphQL
introspection POST; it reuses web.py's HTTP layer and folds findings through the normal
deep-service path (svccommon -> Vulns -> QoD/dedup/KEV/tiering).

Built on the data-driven detection idea: the path lists below are data; a future slice can
load extra API paths from a rules file (see docs/reference/detection-rules.md).
"""

from __future__ import annotations

import json
import re
import urllib.parse

from . import probes, web

_MAX_ENDPOINT_PROBES = 40                # bounded, read-only GETs against enumerated paths
_ID_PARAM = re.compile(r"\{[^}]*(id|uuid|guid|key|no|num)[^}]*\}", re.I)

# Common locations for a machine-readable API spec.
_SPEC_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs",
               "/api-docs", "/swagger/v1/swagger.json", "/api/swagger.json",
               "/api/openapi.json", "/api/v1/openapi.json", "/openapi.yaml"]
# Interactive API docs UIs.
_UI_PATHS = ["/swagger-ui.html", "/swagger-ui/", "/swagger/index.html", "/api/docs",
             "/redoc", "/graphiql", "/docs"]
# GraphQL endpoints to probe for introspection.
_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
_INTROSPECT = '{"query":"query{__schema{queryType{name}}}"}'


def _base(ip: str, port) -> str:
    return f"{'https' if probes._is_tls(port) else 'http'}://{ip}:{port.portid}"


def _spec_endpoint_count(body: str) -> int | None:
    """Endpoint count if `body` is an OpenAPI/Swagger spec, else None."""
    try:
        d = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(d, dict) or not (d.get("swagger") or d.get("openapi")):
        return None
    paths = d.get("paths")
    if not isinstance(paths, dict):
        return 0
    return sum(len(v) if isinstance(v, dict) else 1 for v in paths.values())


def _parse_spec(body: str) -> dict | None:
    """Parse an OpenAPI/Swagger spec into {v3, base_path, endpoints:[{path,method,
    params,secured}], has_security, secrets}. Returns None if not a spec."""
    try:
        d = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(d, dict) or not (d.get("swagger") or d.get("openapi")):
        return None
    v3 = bool(d.get("openapi"))
    base = ""
    if v3:
        servers = d.get("servers") or []
        if servers and isinstance(servers[0], dict):
            base = urllib.parse.urlparse(servers[0].get("url", "")).path or ""
    else:
        base = d.get("basePath", "") or ""
    base = base.rstrip("/")
    has_security = bool(d.get("securityDefinitions")
                        or (d.get("components", {}) or {}).get("securitySchemes"))
    global_sec = bool(d.get("security"))
    eps = []
    for path, item in (d.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []
        for method, op in item.items():
            if method.lower() not in ("get", "post", "put", "delete", "patch"):
                continue
            if not isinstance(op, dict):
                continue
            sec = op.get("security")
            secured = bool(sec) if sec is not None else global_sec
            eps.append({"path": path, "method": method.lower(),
                        "params": (op.get("parameters") or []) + shared,
                        "secured": secured})
    # embedded example credentials / server creds in the raw spec.
    secrets = []
    for u, pw in re.findall(r"://([^:/@\s]+):([^@/\s]{3,})@", body):
        secrets.append((u, pw))
    return {"v3": v3, "base_path": base, "endpoints": eps,
            "has_security": has_security, "secrets": secrets}


def _concrete(path: str, idval: str = "1") -> str:
    """Substitute {param} placeholders with a benign value so the path is requestable."""
    return re.sub(r"\{[^}]+\}", idval, path)


def _enumerate(ip: str, port, spec: dict) -> tuple[list, list, int]:
    """Probe enumerated GET endpoints (bounded, read-only). Returns
    (unauth_reachable, idor_candidates, probe_count)."""
    base = spec["base_path"]
    unauth: list = []
    idor: list = []
    n = 0
    gets = [e for e in spec["endpoints"] if e["method"] == "get"]
    for e in gets:
        if n >= _MAX_ENDPOINT_PROBES:
            break
        # skip endpoints needing a required query/body param we can't fill (would 400).
        if any(p.get("in") in ("query", "body") and p.get("required")
               for p in e["params"] if isinstance(p, dict)):
            continue
        url = base + _concrete(e["path"], "1")
        r = web._fetch(ip, port, url)
        n += 1
        if not r:
            continue
        st, body = r[0], r[2]
        # A secured endpoint that answers 200 with NO credential = broken auth.
        if st == 200 and e["secured"] and spec["has_security"] and len(body) > 8:
            unauth.append((e["path"], url))
        # IDOR/BOLA: an object-by-id endpoint that serves different objects for
        # different ids (no ownership check) with no credential.
        if st == 200 and _ID_PARAM.search(e["path"]) and len(body) > 20:
            if n >= _MAX_ENDPOINT_PROBES:
                break
            r2 = web._fetch(ip, port, base + _concrete(e["path"], "2"))
            n += 1
            if r2 and r2[0] == 200 and r2[2] != body and len(r2[2]) > 20:
                idor.append((e["path"], url, base + _concrete(e["path"], "2")))
    return unauth, idor, n


def _spec_findings(ip: str, port, base: str, tgt: str, spec: dict) -> list[dict]:
    """From a parsed spec: probe endpoints for broken auth + IDOR, harvest embedded
    creds. Returns finding dicts (creds ride in `_credentials` for the fold step)."""
    out: list[dict] = []
    unauth, idor, _n = _enumerate(ip, port, spec)
    if unauth:
        sample = ", ".join(p for p, _u in unauth[:6])
        out.append({"target": tgt, "severity": "high",
                    "title": "API endpoints reachable without authentication (broken auth)",
                    "detail": f"{len(unauth)} spec-declared-secured endpoint(s) returned 200 "
                              f"with NO credential: {sample}"
                              + (" …" if len(unauth) > 6 else "") + ".",
                    "narrative": "The spec marks these endpoints as requiring auth, but they "
                                 "answer unauthenticated - broken authentication / missing "
                                 "access control on the object/function.",
                    "command": f"curl -s {base}{unauth[0][1]}",
                    "remediation": "Enforce authentication + per-object authorization on every "
                                   "endpoint the spec marks secured.",
                    "cwes": ["CWE-306", "CWE-284"]})
    for path, u1, u2 in idor[:3]:
        out.append({"target": tgt, "severity": "high",
                    "title": f"Potential IDOR / BOLA on {path}",
                    "detail": f"GET {base}{u1} and {base}{u2} both returned 200 with "
                              "DIFFERENT objects and no credential - the id is not "
                              "authorization-checked.",
                    "narrative": "An object-by-id endpoint serves arbitrary records to an "
                                 "unauthenticated caller by changing the id (Broken Object "
                                 "Level Authorization) - enumerate every record.",
                    "command": f"for i in $(seq 1 50); do curl -s {base}"
                               + _concrete(path, "$i") + "; done",
                    "remediation": "Check that the caller owns/may access the requested object "
                                   "server-side; never trust the client-supplied id.",
                    "cwes": ["CWE-639", "CWE-284"]})
    if spec.get("secrets"):
        from .models import Credential
        creds = [Credential(username=u, secret=pw, kind="password", source="api-spec-loot",
                            origin_ip=ip, notes=f"embedded in OpenAPI spec on {tgt} (sprayable)")
                 for u, pw in spec["secrets"][:8]]
        out.append({"target": tgt, "severity": "medium",
                    "title": "Credentials embedded in the API spec",
                    "detail": f"{len(creds)} credential(s) embedded in the published spec "
                              "(example server URLs / default logins) -> credential store.",
                    "narrative": "Published specs frequently embed example or default "
                                 "credentials that are real in the running environment.",
                    "command": "grep -oE '://[^:@/]+:[^@/]+@' spec.json",
                    "remediation": "Never embed credentials in a published spec.",
                    "cwes": ["CWE-798"], "_credentials": creds})
    return out


def _probe_port(ip: str, port) -> list[dict]:
    out: list[dict] = []
    base = _base(ip, port)
    tgt = f"{ip}:{port.portid}"

    for path in _SPEC_PATHS:
        r = web._fetch(ip, port, path)
        if r and r[0] == 200:
            spec = _parse_spec(r[2])
            n = _spec_endpoint_count(r[2])
            if n is not None:
                out.append({"target": tgt, "severity": "medium" if n else "low",
                            "title": "OpenAPI/Swagger spec exposed",
                            "detail": f"GET {base}{path} -> 200; {n} endpoint(s) described.",
                            "narrative": "The API's full surface (paths, methods, params, "
                                         "sometimes example credentials) is published without "
                                         "authentication - a complete map for an attacker.",
                            "command": f"curl -s {base}{path} | jq '.paths | keys'",
                            "remediation": "Restrict the spec to authenticated/internal access.",
                            "cwes": ["CWE-200"]})
                if spec:
                    out.extend(_spec_findings(ip, port, base, tgt, spec))
                break

    for path in _UI_PATHS:
        r = web._fetch(ip, port, path)
        if r and r[0] == 200 and any(k in r[2].lower()
                                     for k in ("swagger", "redoc", "graphiql", "openapi")):
            out.append({"target": tgt, "severity": "low",
                        "title": "Interactive API docs exposed",
                        "detail": f"GET {base}{path} -> 200 (Swagger UI / ReDoc / GraphiQL).",
                        "narrative": "An interactive API explorer is reachable unauthenticated - "
                                     "it lets anyone browse and call the API by hand.",
                        "command": f"xdg-open {base}{path}",
                        "remediation": "Disable the docs UI in production, or gate it behind auth.",
                        "cwes": ["CWE-200"]})
            break

    for path in _GRAPHQL_PATHS:
        r = web._fetch(ip, port, path, method="POST", body=_INTROSPECT)
        if r and r[0] == 200 and "__schema" in (r[2] or "") and "queryType" in r[2]:
            out.append({"target": tgt, "severity": "medium",
                        "title": "GraphQL introspection enabled",
                        "detail": f"POST {base}{path} introspection -> the schema was returned.",
                        "narrative": "Introspection leaks the entire GraphQL schema (types, "
                                     "queries, mutations) - a map of the attack surface.",
                        "command": (f"curl -s {base}{path} -H 'Content-Type: application/json' "
                                    f"-d '{_INTROSPECT}'"),
                        "remediation": "Disable introspection in production.",
                        "cwes": ["CWE-200"]})
            break
    return out


def analyze(hosts, active: bool = True, budget: float | None = None,
            progress=None, **_kw) -> dict:
    """Probe every web port for API surface. Returns the deep-service analysis shape
    ({findings, targets, stats}) so it folds through _fold_service_findings unchanged.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    findings: list[dict] = []
    targets: list[dict] = []
    port_by: dict = {}                    # (ip, portid) -> Port, so the probe keeps the
    for h in hosts:                       # Port object while `targets` stays JSON-clean
        for p in h.open_ports:
            if not web.is_web(p):
                continue
            targets.append({"ip": h.ip, "port": p.portid})
            port_by[(h.ip, p.portid)] = p
    state: dict = {}
    looted: list = []
    if active:
        for t, fs in svcprobe.iter_probe(
                targets, lambda t: _probe_port(t["ip"], port_by[(t["ip"], t["port"])]),
                budget=budget, progress=progress, state=state):
            for f in (fs or []):
                looted.extend(f.pop("_credentials", []))   # lift creds out before serialize
                findings.append(f)
    return {"findings": findings, "targets": targets, "credentials": looted,
            "stats": {"targets": len(targets), "findings": len(findings),
                      "credentials": len(looted), "stopped": state.get("stopped")}}


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, source="api", default_port=80, prefix="api")
