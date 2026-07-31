"""API enumeration — discover REST/OpenAPI and GraphQL surface on web services.

recce already fingerprints a lot of web exposures; this focuses the API angle: published
OpenAPI/Swagger specs (which map the whole attack surface), interactive API explorers
(Swagger UI / ReDoc / GraphiQL), and GraphQL introspection. Read-only GETs plus one GraphQL
introspection POST; it reuses web.py's HTTP layer and folds findings through the normal
deep-service path (svccommon -> Vulns -> QoD/dedup/KEV/tiering).

Built on the data-driven detection idea: the path lists below are data; a future slice can
load extra API paths from a rules file (see docs/DETECTION-RULES.md).
"""

from __future__ import annotations

import json

from . import probes, web

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


def is_api_candidate(port) -> bool:
    return web.is_web(port)


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


def _probe_port(ip: str, port) -> list[dict]:
    out: list[dict] = []
    base = _base(ip, port)
    tgt = f"{ip}:{port.portid}"

    for path in _SPEC_PATHS:
        r = web._fetch(ip, port, path)
        if r and r[0] == 200:
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


def analyze(hosts, active: bool = True, **_kw) -> dict:
    """Probe every web port for API surface. Returns the deep-service analysis shape
    ({findings, targets, stats}) so it folds through _fold_service_findings unchanged."""
    findings: list[dict] = []
    targets: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not web.is_web(p):
                continue
            targets.append({"ip": h.ip, "port": p.portid})
            if active:
                findings.extend(_probe_port(h.ip, p))
    return {"findings": findings, "targets": targets, "stats": {}}


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, source="api", default_port=80, prefix="api")
