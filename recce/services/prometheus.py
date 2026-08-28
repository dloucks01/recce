"""Prometheus (9090/tcp) — server + admin API probe.

Prometheus commonly runs unauthenticated on 9090 because it was originally
designed for internal-network use. When exposed, its query API leaks all
recorded metrics (host inventory, service topology, disk usage patterns),
and its status API dumps the scrape config — including bearer tokens
embedded for authenticated scrape targets.

Findings:
  * prom_config_readable (HIGH) — /api/v1/status/config returned the
    scrape config. Config often embeds bearer tokens, basic-auth creds,
    and full internal scrape-target URLs (a network map).
  * prom_query_open (MEDIUM) — /api/v1/query works without auth. Metric
    data leaks the deployment topology + baseline behavior.
  * prom_admin_writable (CRITICAL) — /-/reload accepts POST unauth
    (--web.enable-admin-api on the CLI). Attacker can reload with a
    modified config to redirect scrapes / exfil.
  * prom_fingerprint (info) — always emitted for report visibility.

Airgap-safe: stdlib http.client + ssl. Bounded (~5 HTTP requests).
"""
from __future__ import annotations

import http.client
import json
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 9090
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"


def is_prometheus(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (9090, 9091, 9092)
            or "prometheus" in svc or "prometheus" in prod)


def _http(ip: str, port: int, method: str, path: str,
          body: bytes | None = None, timeout: float = _TIMEOUT):
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            hdrs = {"User-Agent": _UA, "Connection": "close"}
            if body is not None:
                hdrs["Content-Length"] = str(len(body))
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, \
                   resp.read(200_000)
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if not use_tls: continue
            return None
        finally:
            if conn is not None:
                try: conn.close()
                except OSError: pass
    return None


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Return {reachable, version, config_readable, query_open, admin_writable,
    build_info, scrape_targets_hint}."""
    out = {"reachable": False, "version": "", "config_readable": False,
           "query_open": False, "admin_writable": False,
           "build_info": {}, "scrape_targets_hint": 0}
    # /-/healthy — Prometheus's canonical reachability endpoint. Answers 200
    # with body "Prometheus Server is Healthy.\n"
    r = _http(ip, port, "GET", "/-/healthy", timeout=timeout)
    if r is None:
        return out
    status, _, body = r
    # "Prometheus" in the body is the fingerprint. Some deployments front it
    # with a reverse-proxy that swallows /-/ paths, so also try /api/v1/status/buildinfo.
    if status != 200 or b"prometheus" not in body.lower():
        r2 = _http(ip, port, "GET", "/api/v1/status/buildinfo", timeout=timeout)
        if r2 is None or r2[0] != 200:
            return out
        try:
            j = json.loads(r2[2].decode("utf-8", "replace"))
            if (j.get("status") == "success" and "version" in (j.get("data") or {})):
                out["build_info"] = j["data"]
                out["version"] = j["data"].get("version", "")
            else:
                return out
        except (ValueError, UnicodeDecodeError):
            return out
    out["reachable"] = True

    # /api/v1/status/config — dumps prometheus.yml. Config typically embeds
    # scrape-target URLs (network map) + credentials for authenticated scrapes.
    r = _http(ip, port, "GET", "/api/v1/status/config", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            if j.get("status") == "success" and "yaml" in (j.get("data") or {}):
                out["config_readable"] = True
                yaml_txt = j["data"]["yaml"]
                # Rough count of scrape targets — one per "- targets:" or "- static_configs:"
                out["scrape_targets_hint"] = yaml_txt.count("- targets:") + \
                                              yaml_txt.count("static_configs:")
        except (ValueError, UnicodeDecodeError):
            pass

    # /api/v1/query — the actual metric-query endpoint. `query=up` returns the
    # scrape health for every target = full topology disclosed.
    r = _http(ip, port, "GET", "/api/v1/query?query=up", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            out["query_open"] = (j.get("status") == "success")
        except (ValueError, UnicodeDecodeError):
            pass

    # /-/reload — only routable when Prometheus was started with
    # --web.enable-admin-api. POST accepted = admin write is on.
    r = _http(ip, port, "POST", "/-/reload", body=b"", timeout=timeout)
    if r is not None and r[0] in (200, 204):
        out["admin_writable"] = True

    return out


def prometheus_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_prometheus(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "curl", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_prometheus(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            if pr.get("admin_writable"):
                out.append(_finding(
                    "critical",
                    "Prometheus admin API accepts unauthenticated writes", tgt,
                    "POST /-/reload returned success without auth. The server was "
                    "started with --web.enable-admin-api; an attacker can overwrite "
                    "the config (via /-/reload after a scrape-target/rule swap) to "
                    "exfiltrate metrics elsewhere or trigger denial-of-service.",
                    f"curl -X POST http://{h.ip}:{p.portid}/-/reload",
                    "Never run Prometheus with --web.enable-admin-api on an exposed "
                    "port. Bind the admin API to loopback / a management-only interface.",
                    ["CWE-306", "CWE-284"], kind="prom_admin_writable"))
            if pr.get("config_readable"):
                out.append(_finding(
                    "high",
                    "Prometheus scrape config readable without auth", tgt,
                    f"/api/v1/status/config returned the full prometheus.yml — approx "
                    f"{pr.get('scrape_targets_hint', '?')} scrape-target block(s). "
                    f"Configs typically embed bearer tokens or basic-auth credentials "
                    f"for authenticated scrape targets (Kubernetes ServiceAccounts, "
                    f"Grafana Cloud, cloud provider metrics). Every internal scrape-"
                    f"target URL is also a network map.",
                    f"curl http://{h.ip}:{p.portid}/api/v1/status/config | jq -r .data.yaml",
                    "Restrict Prometheus's HTTP API behind a reverse-proxy with "
                    "authentication, or bind it to a management-only interface. "
                    "Rotate any embedded scrape credentials.",
                    ["CWE-200", "CWE-306"], kind="prom_config_readable"))
            if pr.get("query_open"):
                out.append(_finding(
                    "medium",
                    "Prometheus query API open (metric-data disclosure)", tgt,
                    "/api/v1/query returned metric data anonymously. `query=up` "
                    "discloses the full scrape topology; other queries reveal "
                    "deployment behavior (traffic patterns, resource usage, "
                    "failure rates) usable to plan targeted attacks.",
                    f"curl http://{h.ip}:{p.portid}/api/v1/query?query=up",
                    "Gate /api/v1/* behind authentication (reverse-proxy or a "
                    "Prometheus-native auth layer like caddy).",
                    ["CWE-200"], kind="prom_query_open"))
            # Fingerprint always for report record.
            ver = pr.get("version") or "?"
            out.append(_finding(
                "info", "Prometheus endpoint reachable", tgt,
                f"Prometheus {ver} — config_readable={pr.get('config_readable')} "
                f"query_open={pr.get('query_open')} admin_writable={pr.get('admin_writable')}",
                f"curl http://{h.ip}:{p.portid}/-/healthy",
                "Restrict to management interface.",
                [], kind="prom_fingerprint"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Version + reachability",
         "cmd": f"curl -sk http://{ip}:{port}/api/v1/status/buildinfo"},
        {"step": "Full scrape config (may contain creds)",
         "cmd": f"curl -sk http://{ip}:{port}/api/v1/status/config | jq -r .data.yaml"},
        {"step": "Scrape topology",
         "cmd": f"curl -sk http://{ip}:{port}/api/v1/query?query=up"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "prometheus", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = prometheus_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["config_readable"] = pr.get("config_readable", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
