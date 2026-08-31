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

from . import web
from . import probes

_MAX_ENDPOINT_PROBES = 40                # bounded, read-only GETs against enumerated paths
_ID_PARAM = re.compile(r"\{[^}]*(id|uuid|guid|key|no|num)[^}]*\}", re.I)

# T2 promotion (api-endpoints-unauth): mine an unauth-200 body for genuine PII /
# secret material. A hit proves the caller actually READ sensitive data from a
# spec-declared-secured endpoint, not just landed on a 200 stub — that's a
# controlled proof-of-read (safe: single GET already made, no extra traffic).
# Regexes are conservative: each fires only on shapes tightly tied to real data.
_PII_EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}")
# JWT: three base64url segments separated by dots. Common enough on real APIs.
_PII_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
# AWS access-key id (AKIA/ASIA) — 20-char uppercase-alphanum after the prefix.
_PII_AWSKEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
# PEM headers — private-key material, not just any base64 blob.
_PII_PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED |)PRIVATE KEY-----")
# US Social Security Number shape (loose — avoids 000-/666- and 000 groups).
_PII_SSN_RE = re.compile(r"\b(?!000|666)[0-8]\d{2}-(?!00)\d{2}-(?!0000)\d{4}\b")
# JSON key names that reliably mark a record as sensitive when present in a body.
_PII_KEYWORD_RE = re.compile(
    r'"(password|passwd|pwd|api[_-]?key|secret|access[_-]?token|'
    r'refresh[_-]?token|ssn|social[_-]?security|credit[_-]?card|cardnumber|'
    r'private[_-]?key|session[_-]?id)"\s*:\s*"[^"]+"',
    re.I)
# Credit-card shape (13-19 digits, optional dashes/spaces). Rough but useful.
_PII_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")


def _mine_pii(body: str) -> list[str]:
    """Scan `body` for PII / secret shapes. Returns short evidence strings
    (kind + redacted sample) — one per distinct hit category. T2 SAFE PROOF:
    the body was already fetched during the T1 probe; this is pure post-hoc
    analysis, no additional network traffic."""
    if not body:
        return []
    ev: list[str] = []
    b = body[:65536]                           # cap; T1 already bounded fetch

    emails = sorted(set(_PII_EMAIL_RE.findall(b)))
    if emails:
        sample = ", ".join(emails[:3]) + ("…" if len(emails) > 3 else "")
        ev.append(f"emails={len(emails)} ({sample})")

    jwts = _PII_JWT_RE.findall(b)
    if jwts:
        # Redact the middle+signature — leak only the header prefix so the
        # tester sees a JWT was captured without publishing it verbatim.
        head = jwts[0].split(".", 1)[0][:24]
        ev.append(f"jwt-tokens={len(jwts)} (header {head}…)")

    aws = sorted(set(_PII_AWSKEY_RE.findall(b)))
    if aws:
        # Mask all but the first 4 chars of each key id.
        redacted = ", ".join(k[:4] + "…" for k in aws[:3])
        ev.append(f"aws-access-key-ids={len(aws)} ({redacted})")

    if _PII_PEM_RE.search(b):
        ev.append("private-key-pem=1 (PEM header captured)")

    ssns = _PII_SSN_RE.findall(b)
    if ssns:
        ev.append(f"ssns={len(ssns)} (last-4 {ssns[0][-4:]})")

    kws = _PII_KEYWORD_RE.findall(b)
    if kws:
        seen = sorted({k.lower() for k in kws})[:5]
        ev.append(f"sensitive-json-keys={len(kws)} ({', '.join(seen)})")

    # CC is noisy — count only, and only if we already saw at least one other hit
    # (to keep false positives off legitimate numeric bodies).
    if ev:
        ccs = _PII_CC_RE.findall(b)
        # Very loose regex: only report if 3+ matches (raises the bar past
        # incidental numeric noise like ids or timestamps).
        if len(ccs) >= 3:
            ev.append(f"credit-card-shape-matches={len(ccs)}")

    return ev

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
# Full introspection — when the compact _INTROSPECT gets a __schema response,
# this second POST pulls every type, every query, every mutation. That IS the
# attack-surface map the tester needs to plan next steps.
_INTROSPECT_FULL = ('{"query":"query{__schema{queryType{name} mutationType{name} '
                    'types{name kind fields{name args{name type{name kind ofType{name}}} '
                    'type{name kind ofType{name}}}}}}"}')

# SOAP / WSDL endpoints commonly seen on .NET and Java stacks.
_SOAP_WSDL_PATHS = ["/service?wsdl", "/services?wsdl", "/Service.svc?wsdl",
                    "/api?wsdl", "/soap?wsdl", "/ws?wsdl"]

# gRPC servers running gRPC-Web often expose a reflection API without auth.
# grpc-web content-type is the reliable signal.
_GRPC_WEB_PATHS = ["/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
                   "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"]


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


_ID_PATTERN = re.compile(r"\{[^}]+\}")

def _concrete(path: str, idval: str = "1") -> str:
    """Substitute {param} placeholders with a benign value so the path is requestable."""
    return _ID_PATTERN.sub(idval, path)


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
            # Keep the body so the T2 mining step can prove data-read without
            # re-fetching (it was already returned by this one bounded GET).
            unauth.append((e["path"], url, body))
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
        sample = ", ".join(p for p, _u, _b in unauth[:6])
        # T2 SAFE PROOF: mine bodies from the unauth-200 endpoints for PII /
        # secret material. Any hit proves the caller READ sensitive data, not
        # just landed on an empty stub — that's a controlled proof-of-read
        # and lifts this finding from T1 (deterministic reachability signal)
        # to T2 (captured data). No extra traffic — bodies were already
        # fetched by _enumerate under the _MAX_ENDPOINT_PROBES cap.
        pii_hits: list[str] = []
        for path, _u, body in unauth:
            hits = _mine_pii(body)
            if hits:
                pii_hits.append(f"{path}: {'; '.join(hits)}")
            if len(pii_hits) >= 6:             # cap the evidence blob
                break
        detail = (f"{len(unauth)} spec-declared-secured endpoint(s) returned 200 "
                  f"with NO credential: {sample}"
                  + (" …" if len(unauth) > 6 else "") + ".")
        f = {"target": tgt, "severity": "high",
             "title": "API endpoints reachable without authentication (broken auth)",
             "detail": detail,
             "narrative": "The spec marks these endpoints as requiring auth, but they "
                          "answer unauthenticated - broken authentication / missing "
                          "access control on the object/function.",
             "command": f"curl -s {base}{unauth[0][1]}",
             "remediation": "Enforce authentication + per-object authorization on every "
                            "endpoint the spec marks secured.",
             "cwes": ["CWE-306", "CWE-284"]}
        if pii_hits:
            f["depth_tier"] = "t2"
            f["detail"] = (detail + " Proof-of-read captured: "
                           + " | ".join(pii_hits) + ".")
        out.append(f)
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
        from ..core.models import Credential
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
            # Full introspection follow-up — pull every type, query, mutation.
            # Cap the response snapshot so a huge schema doesn't blow the finding
            # size, but keep enough for the tester to see the top-level surface.
            full = web._fetch(ip, port, path, method="POST", body=_INTROSPECT_FULL)
            schema_txt = full[2] if (full and full[0] == 200) else r[2]
            query_names = re.findall(r'"queryType":\s*\{\s*"name":\s*"([^"]+)"', schema_txt or "")
            mutation_names = re.findall(r'"mutationType":\s*\{\s*"name":\s*"([^"]+)"', schema_txt or "")
            # Field names inside the schema — a rough surface count.
            type_hits = re.findall(r'"name":\s*"(?!__)([A-Za-z_][A-Za-z0-9_]*)"', schema_txt or "")
            unique_types = sorted(set(type_hits))[:80]
            detail = (f"POST {base}{path} introspection -> full schema returned. "
                      f"Query type={query_names[0] if query_names else '?'}; "
                      f"Mutation type={mutation_names[0] if mutation_names else 'none'}; "
                      f"~{len(unique_types)} type/field name(s) leaked. "
                      f"Sample: {', '.join(unique_types[:15])}"
                      + ("…" if len(unique_types) > 15 else ""))
            out.append({"target": tgt, "severity": "medium",
                        "title": "GraphQL introspection enabled (full schema readable)",
                        "detail": detail,
                        "narrative": "Introspection leaks the entire GraphQL schema (types, "
                                     "queries, mutations) - a map of the attack surface. "
                                     "Every discovered mutation name is a candidate for "
                                     "unauthorized-write testing.",
                        "command": (f"curl -s {base}{path} -H 'Content-Type: application/json' "
                                    f"-d '{_INTROSPECT_FULL}' | jq '.data.__schema.types[] | select(.kind==\"OBJECT\") | .name'"),
                        "remediation": "Disable introspection in production; if introspection "
                                       "is intended for internal API explorers, gate it behind auth.",
                        "cwes": ["CWE-200"]})
            break

    # SOAP / WSDL discovery — .NET WCF, Java Axis. WSDL exposes the full
    # operation surface + type schema, same attack-map value as OpenAPI.
    for path in _SOAP_WSDL_PATHS:
        r = web._fetch(ip, port, path)
        if r and r[0] == 200 and "<wsdl:definitions" in (r[2] or "") \
                or (r and r[0] == 200 and "<definitions" in (r[2] or "")
                    and "http://schemas.xmlsoap.org/wsdl/" in r[2]):
            # Extract operation names from WSDL — regex is good enough here.
            ops = re.findall(r'<(?:wsdl:)?operation\s+name="([^"]+)"', r[2] or "")
            unique_ops = sorted(set(ops))[:40]
            out.append({"target": tgt, "severity": "medium",
                        "title": "SOAP/WSDL exposed",
                        "detail": (f"GET {base}{path} -> WSDL document returned. "
                                   f"{len(unique_ops)} operation(s) described: "
                                   f"{', '.join(unique_ops[:15])}"
                                   + ("…" if len(unique_ops) > 15 else "")),
                        "narrative": "The WSDL describes every SOAP operation, its "
                                     "parameters, and its return types — full attack "
                                     "surface for the service.",
                        "command": f"curl -s {base}{path} | grep -oE '<(wsdl:)?operation name=\"[^\"]+\"'",
                        "remediation": "Restrict WSDL to authenticated/internal access; "
                                       "or gate the SOAP service behind auth entirely.",
                        "cwes": ["CWE-200"]})
            break

    # gRPC ServerReflection — POST returns proto-encoded reflection data with
    # a distinctive 'grpc-web+proto' content-type header even on rejection.
    for path in _GRPC_WEB_PATHS:
        # Just probe — the presence of a grpc-status header (0 = OK, 3 = INVALID)
        # in the response confirms this is a gRPC endpoint speaking reflection.
        r = web._fetch(ip, port, path, method="POST", body="")
        if r and r[0] in (200, 415) and \
                any(h in (r[2] or "").lower() for h in ("grpc-status", "grpc-message")):
            out.append({"target": tgt, "severity": "low",
                        "title": "gRPC ServerReflection endpoint reachable",
                        "detail": f"POST {base}{path} -> gRPC reflection responded.",
                        "narrative": "gRPC ServerReflection lets any client list every "
                                     "service, RPC method, and message type without a .proto. "
                                     "Together with grpcurl, the tester can hand-craft calls.",
                        "command": f"grpcurl -plaintext {ip}:{port.portid} list",
                        "remediation": "Disable reflection in production servers.",
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
