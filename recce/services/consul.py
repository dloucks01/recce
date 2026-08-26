"""HashiCorp Consul unauthenticated API probe.

Consul (8500/tcp HTTP, 8501/tcp HTTPS) exposes a rich HTTP API for service
discovery, KV store, and ACL management. Default Consul deployments run
without ACLs enabled — anyone who can reach the port reads:

* every registered service (network map handed over)
* the full KV store (credentials, configs, feature flags)
* every node's metadata + tags
* raft peers + cluster config

Findings:
  * consul_unauth_read (CRITICAL) — ACLs are disabled or default-allow;
    the whole cluster state is readable without a token.
  * consul_authed (info) — reachable but requires a token; still worth
    surfacing so any looted token has a known target.

Airgap-safe: stdlib http.client + ssl. Bounded probe (~4 endpoints * 3s).
"""
from __future__ import annotations

import http.client
import json
import ssl

from ..models import Host, Port


_DEFAULT_PORT = 8500
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"


def is_consul(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (8500, 8501)
            or "consul" in svc or "consul" in prod)


def _http(ip: str, port: int, method: str, path: str,
          timeout: float = _TIMEOUT) -> tuple[int, bytes] | None:
    """One request. Transparently retries HTTPS if plain HTTP fails at the
    TLS handshake. Returns (status, body) or None."""
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request(method, path,
                         headers={"User-Agent": _UA, "Connection": "close"})
            resp = conn.getresponse()
            return resp.status, resp.read(200_000)
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if not use_tls:
                continue
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
    return None


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Fingerprint Consul via /v1/status/leader, then probe the readable
    endpoints. Returns {reachable, version, leader, services, nodes, kv_keys}."""
    out = {"reachable": False, "version": "", "leader": "",
           "services": [], "nodes": 0, "kv_keys": 0, "acl_enabled": None}

    # /v1/agent/self returns a huge JSON blob with Consul version + config.
    # If ACLs are enabled AND default-deny is set, this returns 403.
    r = _http(ip, port, "GET", "/v1/agent/self", timeout=timeout)
    if r is None:
        return out
    status, body = r
    if status != 200:
        # Fallback: /v1/status/leader is anonymous even on ACL-strict setups.
        r2 = _http(ip, port, "GET", "/v1/status/leader", timeout=timeout)
        if r2 is None or r2[0] != 200:
            return out
        out["reachable"] = True
        out["leader"] = r2[1].decode("utf-8", "replace").strip().strip('"')[:80]
        out["acl_enabled"] = True                # 403 on /agent/self = ACL enforcing
        return out
    out["reachable"] = True
    try:
        j = json.loads(body.decode("utf-8", "replace"))
        cfg = j.get("Config") or j.get("DebugConfig") or {}
        out["version"] = str(cfg.get("Version", ""))[:60]
        # ACL detection: absence of ACLs in config = disabled; presence with
        # default_policy=allow = disabled-in-practice.
        acl = j.get("DebugConfig", {}).get("ACLDefaultPolicy") \
              or j.get("Config", {}).get("ACL", {}).get("DefaultPolicy") or ""
        out["acl_enabled"] = str(acl).lower() == "deny"
    except (ValueError, UnicodeDecodeError):
        pass

    # /v1/catalog/services — flat map of service name -> tags
    r = _http(ip, port, "GET", "/v1/catalog/services", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            svcs = json.loads(r[1].decode("utf-8", "replace"))
            out["services"] = sorted(svcs.keys())[:50]
        except (ValueError, UnicodeDecodeError):
            pass

    # /v1/catalog/nodes — node inventory
    r = _http(ip, port, "GET", "/v1/catalog/nodes", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            nodes = json.loads(r[1].decode("utf-8", "replace"))
            out["nodes"] = len(nodes) if isinstance(nodes, list) else 0
        except (ValueError, UnicodeDecodeError):
            pass

    # /v1/kv/?recurse — the whole KV store. This is the money endpoint.
    r = _http(ip, port, "GET", "/v1/kv/?recurse", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            kv = json.loads(r[1].decode("utf-8", "replace"))
            out["kv_keys"] = len(kv) if isinstance(kv, list) else 0
        except (ValueError, UnicodeDecodeError):
            pass

    return out


def consul_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_consul(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "consul", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_consul(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            # ACL disabled (or ACL default-allow) with readable services/KV
            # = full cluster state leaked. Emit critical.
            unauth_reads = bool(pr.get("services") or pr.get("nodes") or pr.get("kv_keys"))
            if unauth_reads and not pr.get("acl_enabled"):
                svc_sample = ", ".join(pr.get("services", [])[:8]) or "-"
                out.append(_finding(
                    "critical",
                    "Consul unauthenticated cluster read (ACLs disabled)", tgt,
                    f"Consul {pr.get('version','?')} — ACLs disabled or default-allow. "
                    f"Anonymous reads returned {len(pr.get('services',[]))} service(s), "
                    f"{pr.get('nodes',0)} node(s), and {pr.get('kv_keys',0)} KV key(s). "
                    f"Services: {svc_sample}"
                    + ("… (truncated)" if len(pr.get('services',[])) > 8 else "")
                    + ". KV store may contain credentials, feature flags, service configs.",
                    f"curl http://{h.ip}:{p.portid}/v1/kv/?recurse",
                    "Enable ACLs with default_policy=deny in consul config; issue "
                    "scoped tokens to each service. Bind Consul to a private interface.",
                    ["CWE-306", "CWE-284", "CWE-200"], kind="consul_unauth_read"))
            else:
                out.append(_finding(
                    "info", "Consul endpoint reachable (ACL enforcing)", tgt,
                    f"Consul {pr.get('version','?')} reachable — reads gated by ACL. "
                    f"Leader: {pr.get('leader','?')}. "
                    "Any looted Consul token would target this endpoint.",
                    f"curl http://{h.ip}:{p.portid}/v1/status/leader",
                    "Ensure ACLs stay enforcing; rotate compromised tokens promptly.",
                    [], kind="consul_authed"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Cluster fingerprint",
         "cmd": f"curl -sk http{{,s}}://{ip}:{port}/v1/agent/self | jq .Config.Version"},
        {"step": "List services",
         "cmd": f"curl -sk http://{ip}:{port}/v1/catalog/services"},
        {"step": "Dump KV store",
         "cmd": f"curl -sk http://{ip}:{port}/v1/kv/?recurse"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "consul", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from .. import svcprobe
    targets = consul_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["unauth"] = not pr.get("acl_enabled") and bool(
                    pr.get("services") or pr.get("nodes") or pr.get("kv_keys"))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
