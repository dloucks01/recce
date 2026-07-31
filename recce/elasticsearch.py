"""Deep Elasticsearch enumeration (stdlib only).

Talks to the Elasticsearch HTTP API (9200/9201) with http.client - no elasticsearch
client library. Airgapped, stdlib only.

  * **GET /**: name, cluster name, version, lucene version (the fingerprint).
  * **GET /_cat/indices WITHOUT authentication:** the discriminator. If the index
    list comes back, the cluster is exposed unauthenticated - every document is
    readable (and, on a default cluster, writable/deletable): dump PII, secrets,
    logs, or ransom the indices. A 401/security_exception means X-Pack/OpenSearch
    security is enforced (recce reports it reachable-but-locked, not a finding).
  * **GET /_cluster/health, /_nodes/_local (best-effort):** status + node detail.

Positive findings fold into the severity totals, the Vulnerabilities sheet, the
write-ups, a dedicated **Elasticsearch** tab, and the prove engine. Read-only: recce
only issues GETs - it never indexes, updates, or deletes. Safety posture: SECURITY.md.
"""
from __future__ import annotations

import http.client
import json
import ssl

from .models import Host, Port

_PORTS = (9200, 9201)
_DEFAULT_PORT = 9200
_TIMEOUT = 6.0
_MAX_BODY = 8 * 1024 * 1024        # _cat/indices on a big cluster can be large; cap
                                   # high so the index list isn't truncated (which
                                   # would silently drop the unauth finding)


def is_elasticsearch(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    blob = f"{port.service} {port.product}".lower()
    return "elastic" in blob or "elasticsearch" in blob


def _read_capped(resp) -> bytes:
    return resp.read(_MAX_BODY)


def _get(ip: str, port: int, path: str, tls: bool, timeout: float = _TIMEOUT):
    """GET an ES path. Returns (status, parsed_json_or_text) or None on error."""
    conn = None
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", path, headers={"Accept": "application/json",
                                           "User-Agent": "recce-es/1.0"})
        resp = conn.getresponse()
        body = _read_capped(resp).decode("utf-8", "replace")
        try:
            return resp.status, json.loads(body)
        except ValueError:
            return resp.status, body
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


# --- live probe -----------------------------------------------------------------

def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Read-only fingerprint of an Elasticsearch endpoint. Tries plaintext HTTP then
    HTTPS. Returns {reachable, unauth, secured, version, cluster, name, tagline,
    status, indices, docs, tls, error}."""
    out: dict = {"reachable": False, "unauth": False}
    root = None
    tls = False
    for use_tls in (False, True):
        r = _get(ip, port, "/", use_tls, timeout)
        if r is not None:
            root, tls = r, use_tls
            break
    if root is None:
        return {"reachable": False, "error": "no response"}
    status, body = root
    out["reachable"] = True
    out["tls"] = tls
    # A secured cluster answers "/" with 401 (or an authentication/security exception).
    if status in (401, 403):
        out["secured"] = True
        return out
    if isinstance(body, dict):
        # The unauthenticated ES banner: {"name","cluster_name","version":{...},"tagline"}
        ver = (body.get("version") or {})
        out["name"] = body.get("name", "")
        out["cluster"] = body.get("cluster_name", "")
        out["tagline"] = body.get("tagline", "")
        out["version"] = ver.get("number", "") if isinstance(ver, dict) else ""
        out["lucene"] = ver.get("lucene_version", "") if isinstance(ver, dict) else ""
        looks_es = ("You Know, for Search" in str(out["tagline"])
                    or out["version"] or out["cluster"])
        if not looks_es:
            return out
        # Index list = the data-exposure proof (only reachable if unauthenticated).
        cat = _get(ip, port, "/_cat/indices?format=json&bytes=b", tls, timeout)
        if cat and cat[0] == 200 and isinstance(cat[1], list):
            out["unauth"] = True
            out["indices"] = [i.get("index", "") for i in cat[1]
                              if isinstance(i, dict)][:200]
            docs = 0
            for i in cat[1]:
                if isinstance(i, dict):
                    try:
                        docs += int(i.get("docs.count") or 0)
                    except (ValueError, TypeError):
                        pass
            out["docs"] = docs
        elif cat and cat[0] in (401, 403):
            out["secured"] = True
        health = _get(ip, port, "/_cluster/health", tls, timeout)
        if health and health[0] == 200 and isinstance(health[1], dict):
            out["status"] = health[1].get("status", "")
    return out


def es_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_elasticsearch(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "es_unauth": (
        "The Elasticsearch cluster answers the HTTP API with no authentication - recce "
        "listed the indices without a credential. Every document is readable and, on a "
        "default cluster, writable/deletable: dump application logs, PII, credentials "
        "and tokens straight out of the indices, or ransom/wipe them. Enable the "
        "built-in security (xpack.security.enabled: true) with real users/roles, and "
        "bind the HTTP listener to a trusted interface only."),
    "es_version": (
        "The Elasticsearch build is old / end-of-life. Older lines shipped the Groovy / "
        "MVEL scripting sandboxes that were repeatedly bypassed for remote code "
        "execution (e.g. CVE-2015-1427, CVE-2014-3120) and predate the free built-in "
        "security - confirm the running version and upgrade."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Fingerprint (stdlib HTTP)",
     "recce GETs / on the Elasticsearch HTTP API and reads the name, cluster and "
     "version from the JSON banner - no elasticsearch client library."),
    ("2. Unauthenticated access test",
     "It GETs /_cat/indices with no credential. If the index list comes back, the "
     "cluster is exposed unauthenticated (critical data exposure); a 401 / "
     "security_exception means security is enforced (reachable but locked - not a "
     "finding)."),
    ("3. Scope of exposure",
     "On an exposed cluster it records the index names and total document count (via "
     "_cat/indices) and the cluster health - the size of the data at risk. Read-only: "
     "no document is read, written or deleted."),
    ("4. Runbook",
     "The exact follow-on commands (curl _cat/indices, _search dumps, elasticdump, "
     "nmap http-elasticsearch-head) are staged per endpoint."),
]


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "elasticsearch", "severity": sev, "title": title,
            "target": target, "detail": detail, "tool": tool, "command": cmd,
            "remediation": rem, "cwes": list(cwes), "kind": kind,
            "narrative": _NARRATIVE.get(kind, "")}


def _old_version(ver: str) -> bool:
    try:
        return int(ver.split(".")[0]) < 7               # < 7.x is end-of-life
    except (ValueError, IndexError):
        return False


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_elasticsearch(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            if pr.get("unauth"):
                idx = pr.get("indices") or []
                docs = pr.get("docs", 0)
                names = ", ".join(i for i in idx[:12] if not i.startswith("."))
                out.append(_finding(
                    "critical", "Elasticsearch exposed without authentication", tgt,
                    f"recce listed {len(idx)} index/indices with no credential"
                    + (f" (version {ver})" if ver else "")
                    + (f", {docs} document(s) total" if docs else "")
                    + (f": {names}" if names else "")
                    + ". Unauthenticated read (and, by default, write) access to all "
                    "data.",
                    "curl / elasticdump",
                    f"curl -s http://{h.ip}:{p.portid}/_cat/indices ; "
                    f"curl -s http://{h.ip}:{p.portid}/_search?size=100   # then "
                    f"elasticdump --input=http://{h.ip}:{p.portid}/<index> --output=loot/",
                    "Enable the built-in security (xpack.security.enabled: true) with "
                    "users/roles, and bind the HTTP listener to a trusted interface.",
                    ["CWE-306", "CWE-284"], kind="es_unauth"))
            if ver and _old_version(ver):
                out.append(_finding(
                    "medium", "Elasticsearch end-of-life / legacy build", tgt,
                    f"Elasticsearch {ver} is past end-of-life - missing security fixes; "
                    "older lines had scripting-sandbox RCEs (CVE-2015-1427 / "
                    "CVE-2014-3120) and no free built-in security.",
                    "curl",
                    f"curl -s http://{h.ip}:{p.portid}/",
                    "Upgrade to a supported Elasticsearch release.",
                    ["CWE-1104"], kind="es_version"))
    return out


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "curl", f"curl -s http://{ip}:{port}/ ; "
         f"curl -s http://{ip}:{port}/_cluster/health?pretty",
         "Banner + cluster health (confirms unauth)."),
        ("enumerate", "curl", f"curl -s http://{ip}:{port}/_cat/indices?v",
         "List every index without a credential."),
        ("loot", "elasticdump", f"curl -s 'http://{ip}:{port}/<index>/_search?size=100&pretty'"
         f" ; elasticdump --input=http://{ip}:{port}/<index> --output=loot/<index>.json",
         "Dump documents (logs, PII, secrets) for offline analysis."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "elasticsearch", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full Elasticsearch analysis. Returns {targets, findings, runbooks, probes,
    stats}. `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = es_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["unauth"] = pr.get("unauth", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["indices"] = len(pr.get("indices") or [])
                t["secured"] = pr.get("secured", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
