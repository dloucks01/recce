"""Deep Apache CouchDB enumeration (stdlib only).

CouchDB exposes a pure-HTTP/JSON API on 5984 (6984 for TLS). recce speaks it with
http.client - no couchdb client library - to fingerprint and to CONFIRM the two
classic exposures, read-only:

  * **GET /**                    - the {"couchdb":"Welcome","version":...} banner.
  * **GET /_all_dbs**            - if the database list comes back with no credential,
                                   every database is readable unauthenticated.
  * **GET /_node/_local/_config**- an ADMIN-only endpoint. If it answers 200 with no
    (or /_config on 1.x)          credential the node is in "admin party" (no admins
                                   configured): anyone is a full admin, which is a
                                   direct RCE (the config query-server / OS-daemon
                                   feature, or CVE-2017-12635 -> CVE-2017-12636 on old
                                   builds). A 401 means admins exist (locked - not a
                                   finding).
  * **GET /_membership, /_utils/** - cluster nodes + whether the Fauxton admin UI is up.

Positive findings fold into the severity totals, the Vulnerabilities sheet, the
write-ups and the prove engine. Read-only: recce only issues GETs - it never writes
a document, creates a database or changes config.
"""
from __future__ import annotations

import http.client
import json
import ssl

from ...models import Host, Port
from ...svccommon import finding_builder, make_proof_html_wrapper, make_findings_to_vulns_wrapper

_PORTS = (5984, 6984)
_TLS_PORTS = (6984,)
_DEFAULT_PORT = 5984
_TIMEOUT = 6.0
_MAX_BODY = 2 * 1024 * 1024
_DB_SAMPLE = 25                    # how many database names to surface (not a full dump).


def is_couchdb(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    return "couchdb" in f"{port.service} {port.product}".lower()


def couchdb_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_couchdb(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


def _get(ip: str, port: int, path: str, tls: bool, timeout: float = _TIMEOUT):
    """GET a CouchDB path. Returns (status, parsed_json_or_text) or None on error."""
    conn = None
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", path, headers={"Accept": "application/json",
                                           "User-Agent": "recce-couchdb/1.0"})
        resp = conn.getresponse()
        body = resp.read(_MAX_BODY).decode("utf-8", "replace")
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


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Fingerprint + test unauth /_all_dbs and admin-party /_config. Returns
    {reachable, is_couchdb, version, vendor, unauth_dbs, dbs, admin_party, fauxton,
    secured, error}."""
    res: dict = {"reachable": False, "is_couchdb": False, "version": "", "vendor": "",
                 "unauth_dbs": False, "dbs": [], "admin_party": False, "fauxton": False,
                 "secured": False, "error": ""}
    tls = port in _TLS_PORTS
    root = _get(ip, port, "/", tls, timeout)
    if root is None and not tls:                 # try TLS as a fallback on the plain port
        tls = True
        root = _get(ip, port, "/", tls, timeout)
    if root is None:
        res["error"] = "no HTTP response"
        return res
    res["reachable"] = True
    status, body = root
    if isinstance(body, dict) and str(body.get("couchdb", "")).lower() == "welcome":
        res["is_couchdb"] = True
        res["version"] = str(body.get("version", ""))
        vendor = body.get("vendor")
        if isinstance(vendor, dict):
            res["vendor"] = str(vendor.get("name", ""))
    elif isinstance(body, str) and "couchdb" in body.lower():
        res["is_couchdb"] = True
    if not res["is_couchdb"]:
        res["error"] = "not a CouchDB banner"
        return res

    # Unauthenticated database listing.
    dbs = _get(ip, port, "/_all_dbs", tls, timeout)
    if dbs and dbs[0] == 200 and isinstance(dbs[1], list):
        res["unauth_dbs"] = True
        res["dbs"] = [str(d) for d in dbs[1][:_DB_SAMPLE]]
    elif dbs and dbs[0] in (401, 403):
        res["secured"] = True

    # Admin party: an ADMIN-only config endpoint readable with no credential.
    # 2.x/3.x: /_node/_local/_config ; 1.x: /_config
    for cfg_path in ("/_node/_local/_config", "/_config"):
        cfg = _get(ip, port, cfg_path, tls, timeout)
        if cfg is None:
            continue
        if cfg[0] == 200 and isinstance(cfg[1], dict):
            res["admin_party"] = True
            break
        if cfg[0] in (401, 403):
            res["secured"] = True
            break

    fx = _get(ip, port, "/_utils/", tls, timeout)
    if fx and fx[0] in (200, 301, 302):
        res["fauxton"] = True
    return res


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "couchdb_admin_party": (
        "The CouchDB node is in 'admin party' - NO admin account is configured, so "
        "every anonymous request is treated as a full administrator. recce read an "
        "admin-only config endpoint with no credential to confirm it. That is total "
        "control of the database AND a direct path to remote code execution: an admin "
        "can register a config query-server / OS-daemon that runs arbitrary commands as "
        "the couchdb user (and on old builds the CVE-2017-12635 -> CVE-2017-12636 chain "
        "does the same). Create an admin immediately, bind to localhost, and firewall "
        "5984/6984 plus the Erlang distribution ports."),
    "couchdb_unauth_dbs": (
        "CouchDB served the full database list (/_all_dbs) with no credential - every "
        "database and document behind it is readable (PII, credentials, app state) and, "
        "in admin party, writable/deletable. Require authentication and bind the "
        "listener to a trusted interface."),
    "couchdb_version": (
        "The CouchDB build is old (< 2.1.1). It is affected by the unauthenticated "
        "privilege-escalation-to-RCE chain CVE-2017-12635 (JSON role duplication -> add "
        "an admin) + CVE-2017-12636 (config/query-server command execution). Upgrade."),
}

TESTING_NARRATIVE = [
    ("1. Fingerprint (stdlib HTTP)",
     "recce GETs / and reads the {\"couchdb\":\"Welcome\",\"version\":...} banner to "
     "confirm CouchDB and its exact version - no client library."),
    ("2. Unauthenticated database listing",
     "It GETs /_all_dbs. A 200 with a JSON array means every database is readable "
     "without a credential; a 401 means auth is enforced."),
    ("3. Admin-party test",
     "It GETs the admin-only config (/_node/_local/_config, or /_config on 1.x). A 200 "
     "means no admins exist ('admin party') - anyone is a full admin, an RCE primitive. "
     "A 401/403 means admins are configured (locked - not a finding)."),
    ("4. Runbook",
     "The follow-on curl commands (enumerate DBs, read the admin config, the query-"
     "server / CVE-2017-12635 escalation) are staged per endpoint."),
]

_finding = finding_builder("couchdb", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_couchdb(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr or not pr.get("is_couchdb"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            scheme = "https" if p.portid in _TLS_PORTS else "http"
            base = f"{scheme}://{h.ip}:{p.portid}"
            if pr.get("admin_party"):
                out.append(_finding(
                    "critical", "Apache CouchDB 'admin party' (no admin configured)", tgt,
                    "recce read the admin-only node config with no credential"
                    + (f" (version {ver})" if ver else "")
                    + ". No admins exist, so every anonymous request is a full admin - "
                      "total DB control and RCE via the config query-server / OS-daemon.",
                    "curl",
                    f"curl -s {base}/_node/_local/_config | head ; "
                    f"# then register a query_server / os_daemon to run commands",
                    "Create an admin account (PUT /_node/_local/_config/admins/<user>), "
                    "bind to localhost, firewall 5984/6984 + Erlang ports.",
                    ["CWE-306", "CWE-269"], kind="couchdb_admin_party"))
            if pr.get("unauth_dbs"):
                dbs = pr.get("dbs") or []
                user_dbs = [d for d in dbs if not d.startswith("_")]
                extra = ""
                if dbs:
                    extra = f"; {len(dbs)} database(s) listed"
                    if user_dbs:
                        extra += " incl. " + ", ".join(user_dbs[:6])
                out.append(_finding(
                    "high", "Apache CouchDB exposed - unauthenticated database listing", tgt,
                    "recce read /_all_dbs with no credential" + extra
                    + ". Every database and its documents are readable unauthenticated.",
                    "curl",
                    f"curl -s {base}/_all_dbs ; "
                    f"curl -s {base}/<db>/_all_docs?include_docs=true | head",
                    "Require authentication (create admins), bind to localhost, firewall 5984.",
                    ["CWE-306"], kind="couchdb_unauth_dbs"))
            if ver and _old_version(ver):
                out.append(_finding(
                    "high", "Apache CouchDB < 2.1.1 - unauth privesc -> RCE chain", tgt,
                    f"CouchDB {ver} is affected by CVE-2017-12635 (anonymous role "
                    "duplication -> add an admin) chained with CVE-2017-12636 "
                    "(config/query-server command execution) for unauthenticated RCE.",
                    "curl",
                    f"curl -s {base}/   # confirm version, then the 12635/12636 chain",
                    "Upgrade CouchDB to 2.1.1 / 1.7.0 or later.",
                    ["CWE-269", "CWE-94"], kind="couchdb_version"))
    return out


def _old_version(ver: str) -> bool:
    from ... import vulndb
    try:
        return bool(ver) and vulndb._cmp(ver, "2.1.1") < 0
    except Exception:      # noqa: BLE001 - a weird banner must never crash the scan
        return False


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    scheme = "https" if port in _TLS_PORTS else "http"
    base = f"{scheme}://{ip}:{port}"
    steps = [
        ("recon", "curl", f"curl -s {base}/",
         "Fingerprint CouchDB + version (the Welcome banner)."),
        ("enumerate", "curl", f"curl -s {base}/_all_dbs ; curl -s {base}/_membership",
         "List every database and the cluster nodes - no credential if exposed."),
        ("loot", "curl",
         f"curl -s {base}/_node/_local/_config ; "
         f"curl -s {base}/_users/_all_docs?include_docs=true",
         "Read the node config (secrets / admin hashes) and the user database."),
        ("escalate", "curl",
         f"# admin party or CVE-2017-12635: add an admin, then a query_server -> RCE\n"
         f"# PUT {base}/_node/_local/_config/admins/recce -d '\"pw\"'   (only in scope)",
         "Turn admin access into command execution via the config query-server."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


proof_html = make_proof_html_wrapper("$ ")
findings_to_vulns = make_findings_to_vulns_wrapper("couchdb", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full CouchDB analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from ... import svcprobe
    targets = couchdb_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["admin_party"] = pr.get("admin_party", False)
                t["unauth"] = pr.get("unauth_dbs", False) or pr.get("admin_party", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
