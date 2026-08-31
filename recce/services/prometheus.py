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
  * prom_admin_writable (CRITICAL) — /-/reload accepts POST unauth. The
    lifecycle endpoints /-/reload and /-/quit are gated by the CLI flag
    --web.enable-lifecycle (NOT --web.enable-admin-api, which gates the
    separate /api/v1/admin/tsdb/* delete/snapshot surface). Attacker can
    reload with a modified config to redirect scrapes / exfil, or POST
    /-/quit for a monitoring blackout.
  * prom_federate_open (CRITICAL) — /federate returned metric exposition
    text for a permissive matcher. Federation is the bulk-exfil primitive:
    one request dumps the current value of every matched series (labels
    + values), often reachable even when /api/v1/query is fronted by auth.
    Ref: Prometheus federation docs; historically CVE-2019-3826.
  * prom_pprof_cmdline (CRITICAL) — /debug/pprof/cmdline returned the
    NUL-separated process argv. net/http/pprof is registered on the same
    listener by promhttp; argv leaks --web.config.file, --storage.tsdb.
    path, and any secret passed via CLI flag. Ref: pkg net/http/pprof.
  * prom_fingerprint (info) — always emitted for report visibility.

Airgap-safe: stdlib http.client + ssl. Bounded (~7 HTTP requests).
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


def _query_up_topology(ip: str, port: int, timeout: float) -> dict:
    """T2 SAFE proof for prom_query_open.

    Single controlled read of /api/v1/query?query=up. `up` is the synthetic
    metric Prometheus emits for every scrape target (1=healthy, 0=down), so
    a non-empty vector result is REAL server-side evidence: it proves the
    query engine ran and returned the running-service inventory (instance
    labels + job labels + health). Non-destructive, read-only, single-shot,
    bounded by the caller-supplied timeout.

    Returns {"success": bool, "samples": [{"instance","job","up"}, ...],
             "sample_count": int}.
    """
    out = {"success": False, "samples": [], "sample_count": 0}
    r = _http(ip, port, "GET", "/api/v1/query?query=up", timeout=timeout)
    if r is None or r[0] != 200:
        return out
    try:
        j = json.loads(r[2].decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return out
    if j.get("status") != "success":
        return out
    out["success"] = True
    data = j.get("data") or {}
    result = data.get("result") or []
    if not isinstance(result, list):
        return out
    out["sample_count"] = len(result)
    # Capture up to 8 samples as evidence — enough to demonstrate topology
    # without ballooning the finding detail.
    for row in result[:8]:
        if not isinstance(row, dict):
            continue
        metric = row.get("metric") or {}
        val = row.get("value") or []
        up_val = ""
        if isinstance(val, list) and len(val) >= 2:
            up_val = str(val[1])[:8]
        out["samples"].append({
            "instance": str(metric.get("instance", ""))[:120],
            "job": str(metric.get("job", ""))[:60],
            "up": up_val,
        })
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Return {reachable, version, config_readable, query_open, admin_writable,
    federate_open, pprof_cmdline, build_info, scrape_targets_hint,
    federate_series_hint, cmdline_sample, query_topology}."""
    out = {"reachable": False, "version": "", "config_readable": False,
           "query_open": False, "admin_writable": False,
           "federate_open": False, "pprof_cmdline": False,
           "build_info": {}, "scrape_targets_hint": 0,
           "federate_series_hint": 0, "cmdline_sample": "",
           "query_topology": {}}
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
    # scrape health for every target = full topology disclosed. The helper
    # does a SINGLE controlled read and parses the returned vector so that
    # observed instance/job/up samples become the T2 evidence.
    qt = _query_up_topology(ip, port, timeout)
    if qt["success"]:
        out["query_open"] = True
        out["query_topology"] = qt

    # /-/reload — only routable when Prometheus was started with
    # --web.enable-lifecycle. POST accepted = lifecycle write is on
    # (same flag also gates /-/quit for a full shutdown DoS). This is a
    # DIFFERENT flag from --web.enable-admin-api, which gates the
    # /api/v1/admin/tsdb/* delete/snapshot surface.
    r = _http(ip, port, "POST", "/-/reload", body=b"", timeout=timeout)
    if r is not None and r[0] in (200, 204):
        out["admin_writable"] = True

    # /federate — the bulk metric-exposition endpoint. A permissive matcher
    # `{__name__=~".+"}` selects every series; response body is the standard
    # Prometheus text-exposition format (`# HELP` / `# TYPE` comment lines
    # followed by `metric{labels} value timestamp` samples). Prometheus
    # answers with Content-Type: text/plain; charset=utf-8; version=... —
    # a JSON or HTML 200 from a fronting proxy fails the format check so
    # we don't over-claim. Ref: prometheus.io/docs/prometheus/latest/
    # federation/ ; historically CVE-2019-3826.
    r = _http(ip, port, "GET",
              "/federate?match%5B%5D=%7B__name__%3D~%22.%2B%22%7D",
              timeout=timeout)
    if r is not None and r[0] == 200:
        f_status, f_hdrs, f_body = r
        ctype = (f_hdrs.get("content-type") or "").lower()
        # Real federate response is text/plain exposition format. Accept when
        # content-type says text/plain OR body has the exposition markers.
        body_txt = f_body.decode("utf-8", "replace")
        has_expo = ("# TYPE " in body_txt or "# HELP " in body_txt)
        if "text/plain" in ctype or has_expo:
            out["federate_open"] = True
            # Cheap sample-line count: non-comment, non-empty lines are
            # metric samples. Body is capped at 200KB upstream, so this is
            # a floor (a real federation dump is many MB).
            n = 0
            for line in body_txt.splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    n += 1
            out["federate_series_hint"] = n

    # /debug/pprof/cmdline — net/http/pprof is registered by default on the
    # Prometheus web listener. cmdline returns the process argv as
    # NUL-separated bytes (mirrors /proc/self/cmdline). Argv frequently
    # includes --web.config.file, --storage.tsdb.path, and any secret
    # passed via CLI flag. Detect by: 200 status AND (NUL byte in body OR
    # body contains "prometheus") to avoid false positives from generic
    # 200 OK proxies. Ref: pkg.go.dev/net/http/pprof.
    r = _http(ip, port, "GET", "/debug/pprof/cmdline", timeout=timeout)
    if r is not None and r[0] == 200:
        _, _, c_body = r
        has_nul = b"\x00" in c_body
        looks_prom = b"prometheus" in c_body.lower()
        if c_body and (has_nul or looks_prom):
            out["pprof_cmdline"] = True
            # Compact sample: replace NULs with spaces, cap at 300 chars.
            sample = c_body.replace(b"\x00", b" ").decode("utf-8", "replace")
            out["cmdline_sample"] = sample.strip()[:300]

    return out


def prometheus_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_prometheus(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


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
            if not is_prometheus(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            if pr.get("admin_writable"):
                out.append(_finding(
                    "critical",
                    "Prometheus lifecycle API accepts unauthenticated writes", tgt,
                    "POST /-/reload returned success without auth. The server was "
                    "started with --web.enable-lifecycle (this flag gates the "
                    "/-/reload and /-/quit management endpoints; it is a DIFFERENT "
                    "flag from --web.enable-admin-api, which gates /api/v1/admin/"
                    "tsdb/* delete/snapshot). An attacker can overwrite the config "
                    "(via /-/reload after a scrape-target/rule swap) to exfiltrate "
                    "metrics elsewhere, or POST /-/quit for a monitoring blackout.",
                    f"curl -X POST http://{h.ip}:{p.portid}/-/reload",
                    "Do not run Prometheus with --web.enable-lifecycle on an "
                    "exposed port. Bind the management endpoints to loopback / a "
                    "management-only interface, or gate them behind an "
                    "authenticating reverse proxy.",
                    ["CWE-306", "CWE-284"], kind="prom_admin_writable",
                    exploit_note=(
                        "curl -X POST http://<ip>:9090/-/reload; then curl -X POST "
                        "http://<ip>:9090/-/quit for a monitoring blackout PoC "
                        "(destructive). To exfiltrate: swap the config on disk if "
                        "you have write access, then reload."),
                    depth_tier="t1"))
            if pr.get("federate_open"):
                sh = pr.get("federate_series_hint", 0)
                out.append(_finding(
                    "critical",
                    "Prometheus /federate open (bulk metric exfil)", tgt,
                    f"GET /federate with a permissive matcher "
                    f"({{__name__=~\".+\"}}) returned Prometheus text-exposition "
                    f"data anonymously (>= {sh} sample line(s) in the first "
                    f"200KB — a real federation dump is many MB). Federation "
                    f"streams the current value of every matched series in one "
                    f"request; it is a distinct endpoint from /api/v1/query and "
                    f"is frequently reachable even when the query API is fronted "
                    f"by auth. This is the largest single-request metric-exfil "
                    f"primitive on the daemon.",
                    f"curl -sG --data-urlencode 'match[]={{__name__=~\".+\"}}' "
                    f"http://{h.ip}:{p.portid}/federate",
                    "Gate /federate behind authentication (reverse proxy or "
                    "Prometheus's native web.config.file basic_auth_users / "
                    "mTLS). Restrict allowed matchers if federation is required "
                    "for legitimate downstream servers.",
                    ["CWE-200", "CWE-306"], kind="prom_federate_open",
                    exploit_note=(
                        "curl -skG --data-urlencode 'match[]={__name__=~\".+\"}' "
                        "http://<ip>:9090/federate -o federate.txt; grep -aE "
                        "'(token|password|jwt|Bearer|AKIA|-----BEGIN)' federate.txt"),
                    depth_tier="t1"))
            if pr.get("pprof_cmdline"):
                sample = pr.get("cmdline_sample", "")
                short = (sample[:140] + "...") if len(sample) > 140 else sample
                out.append(_finding(
                    "critical",
                    "Prometheus /debug/pprof/cmdline leaks process argv", tgt,
                    f"GET /debug/pprof/cmdline returned the NUL-separated "
                    f"process argv. net/http/pprof is registered on the same "
                    f"listener by promhttp; argv frequently includes "
                    f"--web.config.file, --storage.tsdb.path, --web.listen-"
                    f"address, and any secret passed via CLI flag (auth tokens, "
                    f"DB URIs). Additional pprof endpoints (goroutine, heap, "
                    f"profile) are on the same path and leak internal state / "
                    f"upstream URLs. Observed argv: {short!r}",
                    f"curl http://{h.ip}:{p.portid}/debug/pprof/cmdline",
                    "Disable pprof on the public listener: bind the Prometheus "
                    "web listener to a management-only interface, or front it "
                    "with a proxy that blocks /debug/pprof/*. Never pass "
                    "secrets via CLI flags — use --web.config.file or "
                    "environment variables.",
                    ["CWE-200", "CWE-215"], kind="prom_pprof_cmdline",
                    exploit_note=(
                        "curl http://<ip>:9090/debug/pprof/cmdline | tr '\\0' '\\n'; "
                        "then curl http://<ip>:9090/debug/pprof/heap?debug=1 | "
                        "grep -aiE 'token|password|bearer|aws_|gcp_' — mine for "
                        "in-flight secrets."),
                    depth_tier="t1"))
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
                    ["CWE-200", "CWE-306"], kind="prom_config_readable",
                    exploit_note=(
                        "curl -sk http://<ip>:9090/api/v1/status/config | jq -r "
                        ".data.yaml | grep -E 'bearer_token|username|password|"
                        "http[s]?://' — collect creds + internal URLs, then curl "
                        "each with the disclosed bearer to confirm reuse."),
                    depth_tier="t1"))
            if pr.get("query_open"):
                # T1 baseline: /api/v1/query answered status=success anonymously.
                detail = (
                    "/api/v1/query returned metric data anonymously. `query=up` "
                    "discloses the full scrape topology; other queries reveal "
                    "deployment behavior (traffic patterns, resource usage, "
                    "failure rates) usable to plan targeted attacks.")
                tier = "t1"
                qt = pr.get("query_topology") or {}
                samples = qt.get("samples") or []
                sample_count = qt.get("sample_count", 0)
                if samples:
                    # T2 SAFE proof: the anonymous query engine actually
                    # returned running-service inventory. Render the first
                    # few (instance, job, up) tuples as evidence.
                    tier = "t2"
                    preview = ", ".join(
                        f"{s.get('instance','?')} (job={s.get('job','?')}, "
                        f"up={s.get('up','?')})"
                        for s in samples[:3])
                    more = "" if sample_count <= 3 else f" (+{sample_count - 3} more)"
                    detail += (
                        f" T2 PROOF: anonymous GET /api/v1/query?query=up "
                        f"returned {sample_count} scrape-target sample(s) — "
                        f"the query engine actually ran and disclosed the "
                        f"running-service inventory. Observed: "
                        f"{preview}{more}.")
                out.append(_finding(
                    "medium",
                    "Prometheus query API open (metric-data disclosure)", tgt,
                    detail,
                    f"curl http://{h.ip}:{p.portid}/api/v1/query?query=up",
                    "Gate /api/v1/* behind authentication (reverse-proxy or a "
                    "Prometheus-native auth layer like caddy).",
                    ["CWE-200"], kind="prom_query_open",
                    depth_tier=tier))
            # Fingerprint always for report record.
            ver = pr.get("version") or "?"
            out.append(_finding(
                "info", "Prometheus endpoint reachable", tgt,
                f"Prometheus {ver} — config_readable={pr.get('config_readable')} "
                f"query_open={pr.get('query_open')} admin_writable={pr.get('admin_writable')} "
                f"federate_open={pr.get('federate_open')} "
                f"pprof_cmdline={pr.get('pprof_cmdline')}",
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
        {"step": "Federation bulk-exfil (every series in one request)",
         "cmd": (f"curl -skG --data-urlencode 'match[]={{__name__=~\".+\"}}' "
                 f"http://{ip}:{port}/federate")},
        {"step": "pprof cmdline (argv — often leaks CLI-flag secrets)",
         "cmd": f"curl -sk http://{ip}:{port}/debug/pprof/cmdline"},
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
                t["federate_open"] = pr.get("federate_open", False)
                t["pprof_cmdline"] = pr.get("pprof_cmdline", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
