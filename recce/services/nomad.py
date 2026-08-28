"""HashiCorp Nomad unauthenticated API probe.

Nomad (4646/tcp) runs scheduled workloads across a cluster. On a default
deployment without ACLs, the HTTP API reveals every job spec, task
allocation, secret template, and env variable — often including database
passwords, API keys, and TLS material embedded in the job files.

Probe walks:
  * /v1/agent/self       — fingerprint, version, ACL config
  * /v1/jobs             — every registered job (name, type, status)
  * /v1/allocations      — placements (client-node -> job mapping)
  * /v1/nodes            — cluster inventory

Findings:
  * nomad_unauth_read (CRITICAL) — ACL disabled or default-allow; the
    scheduler's entire state is readable, including secret material
    embedded in job specs.
  * nomad_authed (info) — reachable but token-gated; logged so any
    looted Nomad token has a known target endpoint.

Airgap-safe: stdlib http.client + ssl. Bounded (~4 endpoints * 3s).
"""
from __future__ import annotations

import http.client
import json
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 4646
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"


def is_nomad(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (4646, 4647, 4648)
            or "nomad" in svc or "nomad" in prod)


def _http(ip: str, port: int, method: str, path: str,
          timeout: float = _TIMEOUT) -> tuple[int, bytes] | None:
    """One request. Transparently retries HTTPS if plain HTTP is rejected."""
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
            return resp.status, resp.read(500_000)
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
    """Return {reachable, version, acl_enabled, jobs, allocations, nodes}."""
    out = {"reachable": False, "version": "", "acl_enabled": None,
           "jobs": [], "allocations": 0, "nodes": 0, "leader": ""}

    r = _http(ip, port, "GET", "/v1/agent/self", timeout=timeout)
    if r is None:
        return out
    status, body = r
    if status != 200:
        # /v1/status/leader is anonymous even under ACL enforcement
        r2 = _http(ip, port, "GET", "/v1/status/leader", timeout=timeout)
        if r2 is None or r2[0] != 200:
            return out
        out["reachable"] = True
        out["leader"] = r2[1].decode("utf-8", "replace").strip().strip('"')[:80]
        out["acl_enabled"] = True
        return out
    out["reachable"] = True
    try:
        j = json.loads(body.decode("utf-8", "replace"))
        config = j.get("config") or {}
        out["version"] = str(config.get("Version") or j.get("member", {}).get("Tags", {}).get("build") or "")[:60]
        acl = (config.get("ACL") or {}).get("Enabled")
        out["acl_enabled"] = bool(acl)
    except (ValueError, UnicodeDecodeError):
        pass

    r = _http(ip, port, "GET", "/v1/jobs", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            jobs = json.loads(r[1].decode("utf-8", "replace"))
            if isinstance(jobs, list):
                out["jobs"] = [{"name": (j.get("Name") or j.get("ID") or "?"),
                                "type": j.get("Type", ""),
                                "status": j.get("Status", "")}
                               for j in jobs[:50]]
        except (ValueError, UnicodeDecodeError):
            pass

    r = _http(ip, port, "GET", "/v1/allocations", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            allocs = json.loads(r[1].decode("utf-8", "replace"))
            out["allocations"] = len(allocs) if isinstance(allocs, list) else 0
        except (ValueError, UnicodeDecodeError):
            pass

    r = _http(ip, port, "GET", "/v1/nodes", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            nodes = json.loads(r[1].decode("utf-8", "replace"))
            out["nodes"] = len(nodes) if isinstance(nodes, list) else 0
        except (ValueError, UnicodeDecodeError):
            pass

    return out


def nomad_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_nomad(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "nomad", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_nomad(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            unauth = bool(pr.get("jobs") or pr.get("allocations") or pr.get("nodes"))
            if unauth and not pr.get("acl_enabled"):
                job_names = [j["name"] for j in pr.get("jobs", [])]
                jobs_txt = ", ".join(job_names[:8]) or "-"
                out.append(_finding(
                    "critical",
                    "Nomad unauthenticated cluster read (ACLs disabled)", tgt,
                    f"Nomad {pr.get('version','?')} — ACLs disabled or unconfigured. "
                    f"Anonymous reads returned {len(pr.get('jobs',[]))} job(s), "
                    f"{pr.get('allocations',0)} allocation(s), {pr.get('nodes',0)} node(s). "
                    f"Jobs: {jobs_txt}"
                    + ("… (truncated)" if len(job_names) > 8 else "")
                    + ". Job specs commonly embed secret templates, env variables "
                    f"with API keys, and DB connection strings.",
                    f"curl http://{h.ip}:{p.portid}/v1/jobs",
                    "Enable ACLs in the Nomad server config (acl { enabled = true }); "
                    "bind the API to a private interface; require SecretID tokens.",
                    ["CWE-306", "CWE-284", "CWE-200"], kind="nomad_unauth_read"))
            else:
                out.append(_finding(
                    "info", "Nomad endpoint reachable (ACL enforcing)", tgt,
                    f"Nomad {pr.get('version','?')} reachable — reads gated by ACL. "
                    f"Leader: {pr.get('leader','?')}. Any looted Nomad SecretID would "
                    f"target this endpoint.",
                    f"curl http://{h.ip}:{p.portid}/v1/status/leader",
                    "Ensure ACLs stay enforcing; rotate compromised tokens promptly.",
                    [], kind="nomad_authed"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Cluster fingerprint",
         "cmd": f"curl -sk http{{,s}}://{ip}:{port}/v1/agent/self"},
        {"step": "List jobs (contains secrets in specs)",
         "cmd": f"curl -sk http://{ip}:{port}/v1/jobs"},
        {"step": "Dump one job's full spec",
         "cmd": f"curl -sk http://{ip}:{port}/v1/job/<job-id>"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "nomad", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = nomad_targets(hosts)
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
                    pr.get("jobs") or pr.get("allocations") or pr.get("nodes"))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
