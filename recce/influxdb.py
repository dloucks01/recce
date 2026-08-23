"""Deep InfluxDB enumeration (stdlib only).

InfluxDB 1.x exposes an HTTP API on 8086 and ships with authentication DISABLED by
default, so an exposed instance usually answers queries with no credential. recce
speaks the HTTP API with http.client - no influxdb client - to fingerprint and
confirm the exposure, read-only:

  * **GET /ping**                 - 204 + `X-Influxdb-Version` header = the exact build
                                    (answered even when auth is on: the fingerprint).
  * **GET /query?q=SHOW DATABASES**- the discriminator. A 200 with a results payload and
                                    no credential means the query API is unauthenticated
                                    (auth-enabled=false) - every database is readable. A
                                    401 means auth is enforced (locked - not a finding).
  * version < 1.7.6               - CVE-2019-20933: a JWT signed with an EMPTY shared
                                    secret is accepted, so an attacker forges an admin
                                    token and bypasses auth entirely.

Read-only: recce only runs SHOW DATABASES / SHOW USERS - it never writes a point or
drops a series. Authorized testing only.
"""
from __future__ import annotations

import http.client
import json
import ssl
import urllib.parse

from .models import Host, Port
from .svccommon import finding_builder, make_proof_html_wrapper, make_findings_to_vulns_wrapper

_PORTS = (8086, 8087)
_TLS_PORTS = (8087,)
_DEFAULT_PORT = 8086
_TIMEOUT = 6.0
_MAX_BODY = 1 * 1024 * 1024
_DB_SAMPLE = 25


def is_influxdb(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    return "influx" in f"{port.service} {port.product}".lower()


def influxdb_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_influxdb(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


def _request(ip: str, port: int, path: str, tls: bool, timeout: float = _TIMEOUT):
    """GET a path. Returns (status, headers_dict, parsed_json_or_text) or None."""
    conn = None
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", path, headers={"User-Agent": "recce-influx/1.0"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        body = resp.read(_MAX_BODY).decode("utf-8", "replace")
        try:
            return resp.status, headers, json.loads(body)
        except ValueError:
            return resp.status, headers, body
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _parse_databases(payload) -> list[str]:
    """SHOW DATABASES JSON -> [name, ...]. Shape:
    {"results":[{"series":[{"columns":["name"],"values":[["_internal"],["mydb"]]}]}]}"""
    dbs: list[str] = []
    try:
        for result in payload.get("results", []):
            for series in result.get("series", []):
                for row in series.get("values", []):
                    if row:
                        dbs.append(str(row[0]))
    except (AttributeError, TypeError):
        pass
    return dbs


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Fingerprint via /ping + test the unauthenticated query API. Returns
    {reachable, is_influxdb, version, unauth, dbs, secured, error}."""
    res: dict = {"reachable": False, "is_influxdb": False, "version": "",
                 "unauth": False, "dbs": [], "secured": False, "error": ""}
    tls = port in _TLS_PORTS
    ping = _request(ip, port, "/ping", tls, timeout)
    if ping is None and not tls:
        tls = True
        ping = _request(ip, port, "/ping", tls, timeout)
    if ping is None:
        res["error"] = "no HTTP response"
        return res
    res["reachable"] = True
    status, headers, _ = ping
    ver = headers.get("x-influxdb-version", "")
    if ver:
        res["is_influxdb"] = True
        res["version"] = ver
    # The unauthenticated query test.
    q = "/query?" + urllib.parse.urlencode({"q": "SHOW DATABASES"})
    resp = _request(ip, port, q, tls, timeout)
    if resp is not None:
        st, _h, body = resp
        if st == 200 and isinstance(body, dict) and "results" in body:
            res["is_influxdb"] = True
            res["unauth"] = True
            res["dbs"] = _parse_databases(body)[:_DB_SAMPLE]
        elif st in (401, 403):
            res["secured"] = True
            res["is_influxdb"] = True
    if not res["is_influxdb"]:
        res["error"] = res["error"] or "not an InfluxDB endpoint"
    return res


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "influxdb_unauth": (
        "The InfluxDB HTTP API answered SHOW DATABASES with no credential - "
        "authentication is disabled (auth-enabled=false), InfluxDB's default. Every "
        "database, measurement and point is readable and writable: dump time-series "
        "telemetry (which often carries hostnames, tokens, business metrics), tamper "
        "with monitoring data to hide activity, or DROP series. Enable authentication, "
        "create an admin user, and bind the API to a trusted interface / firewall 8086."),
    "influxdb_jwt_bypass": (
        "This InfluxDB build (< 1.7.6) accepts a JWT signed with an EMPTY shared secret "
        "(CVE-2019-20933). An attacker forges an 'admin' token with any empty-secret JWT "
        "and gains full authenticated access even when auth is enabled - a complete "
        "authentication bypass. Upgrade to 1.7.6+ and set a strong shared secret."),
    "influxdb_version": (
        "The InfluxDB build is old and may carry the JWT auth-bypass (CVE-2019-20933) "
        "and other fixed issues - confirm the version and upgrade."),
}

TESTING_NARRATIVE = [
    ("1. Fingerprint (stdlib HTTP)",
     "recce GETs /ping and reads the X-Influxdb-Version response header - the exact "
     "build, returned even when auth is enabled."),
    ("2. Unauthenticated query test",
     "It runs GET /query?q=SHOW DATABASES. A 200 with a results payload means the query "
     "API is unauthenticated (a confirmed finding); a 401 means auth is enforced."),
    ("3. Version-gated auth bypass",
     "If the version is < 1.7.6 it flags CVE-2019-20933 - the empty-shared-secret JWT "
     "bypass - which defeats auth even on a locked instance."),
    ("4. Runbook",
     "The follow-on influx/curl commands (SHOW DATABASES/USERS, the JWT-forge bypass) "
     "are staged per endpoint."),
]

_finding = finding_builder("influxdb", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_influxdb(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr or not pr.get("is_influxdb"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            scheme = "https" if p.portid in _TLS_PORTS else "http"
            base = f"{scheme}://{h.ip}:{p.portid}"
            if pr.get("unauth"):
                dbs = pr.get("dbs") or []
                user_dbs = [d for d in dbs if d != "_internal"]
                extra = ""
                if dbs:
                    extra = f"; {len(dbs)} database(s)"
                    if user_dbs:
                        extra += " incl. " + ", ".join(user_dbs[:6])
                out.append(_finding(
                    "high", "InfluxDB exposed - unauthenticated query API", tgt,
                    "recce ran SHOW DATABASES with no credential"
                    + (f" (version {ver})" if ver else "") + extra
                    + ". Authentication is disabled - full read/write to all series.",
                    "influx",
                    f"curl -s -G '{base}/query' --data-urlencode 'q=SHOW DATABASES' ; "
                    f"# then SHOW USERS ; SELECT * FROM <db>..<measurement> LIMIT 10",
                    "Set auth-enabled=true, create an admin, firewall 8086.",
                    ["CWE-306", "CWE-287"], kind="influxdb_unauth"))
            if ver and _jwt_bypass(ver):
                out.append(_finding(
                    "high", "InfluxDB < 1.7.6 - JWT auth bypass (CVE-2019-20933)", tgt,
                    f"InfluxDB {ver} accepts a JWT signed with an empty shared secret "
                    "(CVE-2019-20933): an attacker forges an admin token and bypasses "
                    "authentication entirely, even when auth is enabled.",
                    "influx",
                    f"# forge HS256 JWT {{username:admin, exp:...}} with empty secret, then\n"
                    f"curl -s -G '{base}/query' -H 'Authorization: Bearer <jwt>' "
                    f"--data-urlencode 'q=SHOW DATABASES'",
                    "Upgrade to InfluxDB 1.7.6+ and configure a strong shared secret.",
                    ["CWE-287"], kind="influxdb_jwt_bypass"))
    return out


def _jwt_bypass(ver: str) -> bool:
    from . import vulndb
    try:
        return bool(ver) and vulndb._cmp(ver, "1.7.6") < 0
    except Exception:      # noqa: BLE001
        return False


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    scheme = "https" if port in _TLS_PORTS else "http"
    base = f"{scheme}://{ip}:{port}"
    steps = [
        ("recon", "curl", f"curl -sI {base}/ping   # X-Influxdb-Version header",
         "Fingerprint the exact InfluxDB build (works even with auth on)."),
        ("enumerate", "curl",
         f"curl -s -G '{base}/query' --data-urlencode 'q=SHOW DATABASES' ; "
         f"curl -s -G '{base}/query' --data-urlencode 'q=SHOW USERS'",
         "List databases and users with no credential (auth disabled by default)."),
        ("loot", "curl",
         f"curl -s -G '{base}/query' --data-urlencode 'q=SELECT * FROM <db>..<m> LIMIT 20'",
         "Read time-series data (hostnames, tokens, metrics)."),
        ("escalate", "curl",
         f"# CVE-2019-20933 (<1.7.6): forge an empty-secret admin JWT to bypass auth\n"
         f"curl -s -G '{base}/query' -H 'Authorization: Bearer <forged-jwt>' "
         f"--data-urlencode 'q=SHOW DATABASES'",
         "Bypass authentication on a locked <1.7.6 instance via the empty-secret JWT."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


proof_html = make_proof_html_wrapper("$ ")
findings_to_vulns = make_findings_to_vulns_wrapper("influxdb", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full InfluxDB analysis. Returns {targets, findings, runbooks, probes, stats}."""
    from . import svcprobe
    targets = influxdb_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["unauth"] = pr.get("unauth", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
