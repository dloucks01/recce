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
only issues GETs - it never indexes, updates, or deletes.
"""
from __future__ import annotations

import base64
import http.client
import json
import ssl

from ...core.models import Host, Port
from ..svccommon import finding_builder

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


def _auth_headers(creds: dict | None) -> dict:
    """Build an `Authorization:` header for Elasticsearch from a creds dict.

    Recognises three shapes documented in the ES Reference (`Basic authentication`
    and `API keys`), in priority order:

      * `{"bearer": "<token>"}`         -> `Authorization: Bearer <token>`
      * `{"api_key": "<id>:<secret>"}`  -> `Authorization: ApiKey <b64(id:secret)>`
        (a bare token that already looks base64 is passed through unchanged)
      * `{"username": "u", "password": "p"}` (also `user`/`pass`)
                                        -> `Authorization: Basic <b64(u:p)>`

    Returns `{}` when creds are missing / unusable so callers get an unauth GET.
    """
    if not isinstance(creds, dict):
        return {}
    tok = creds.get("bearer") or creds.get("token")
    if isinstance(tok, str) and tok:
        return {"Authorization": f"Bearer {tok}"}
    ak = creds.get("api_key") or creds.get("apikey")
    if isinstance(ak, str) and ak:
        # `id:secret` form -> base64 per the ES ApiKey scheme; bare base64 passes through.
        val = ak
        if ":" in ak:
            val = base64.b64encode(ak.encode("utf-8")).decode("ascii")
        return {"Authorization": f"ApiKey {val}"}
    user = creds.get("username") or creds.get("user")
    pw = creds.get("password") or creds.get("pass") or ""
    if isinstance(user, str) and user:
        raw = f"{user}:{pw}".encode("utf-8")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
    return {}


def _get(ip: str, port: int, path: str, tls: bool, timeout: float = _TIMEOUT,
         headers: dict | None = None):
    """GET an ES path. Returns (status, parsed_json_or_text) or None on error.
    `headers` merges over the default Accept/User-Agent (typically an
    `Authorization:` header from `_auth_headers()`)."""
    conn = None
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        h = {"Accept": "application/json", "User-Agent": "recce-es/1.0"}
        if headers:
            h.update(headers)
        conn.request("GET", path, headers=h)
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

def probe(ip: str, port: int, timeout: float = _TIMEOUT,
          headers: dict | None = None) -> dict:
    """Read-only fingerprint of an Elasticsearch endpoint. Tries plaintext HTTP then
    HTTPS. Returns {reachable, unauth, secured, version, cluster, name, tagline,
    status, indices, docs, tls, anonymous, anonymous_username, anonymous_roles,
    snapshot_repo_settings, error}.

    `headers` typically carries an `Authorization:` from `_auth_headers()`; if
    present it is sent on every GET, including the anonymous-authenticate probe
    (which still fires on 401 without creds to catch anonymous-role clusters)."""
    out: dict = {"reachable": False, "unauth": False}
    root = None
    tls = False
    for use_tls in (False, True):
        r = _get(ip, port, "/", use_tls, timeout, headers=headers)
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
        # Anonymous-role clusters answer 401 on / but still grant a role to
        # unauthenticated requests via xpack.security.authc.anonymous.roles.
        # /_security/_authenticate returns 200 with username == "_anonymous"
        # (or authentication_type == "anonymous") for that case even when creds
        # are absent - the definitive anonymous-vs-secured test.
        _check_anonymous(ip, port, tls, timeout, out)
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
        cat = _get(ip, port, "/_cat/indices?format=json&bytes=b", tls, timeout,
                   headers=headers)
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
        health = _get(ip, port, "/_cluster/health", tls, timeout, headers=headers)
        if health and health[0] == 200 and isinstance(health[1], dict):
            out["status"] = health[1].get("status", "")
            out["nodes"] = health[1].get("number_of_nodes", "")
        if out.get("unauth"):
            _deep_es(ip, port, tls, timeout, out, headers=headers)
    return out


def _check_anonymous(ip: str, port: int, tls: bool, timeout: float,
                     out: dict) -> None:
    """Probe /_security/_authenticate WITHOUT credentials. Elasticsearch's built-in
    security supports xpack.security.authc.anonymous.roles - a cluster that answers
    401 on / can still grant a de-facto role to anyone. This endpoint returns 200
    with `{"username": "_anonymous", "authentication_type": "anonymous", "roles":
    [...]}` on such clusters, which is the definitive tell. Populates
    out[anonymous|anonymous_username|anonymous_roles].

    On a positive tell this immediately follows with a safe, read-only T2 proof
    (_probe_anonymous_read) to confirm the granted role actually reads data."""
    who = _get(ip, port, "/_security/_authenticate", tls, timeout, headers=None)
    if not who or who[0] != 200 or not isinstance(who[1], dict):
        return
    body = who[1]
    user = body.get("username") or ""
    at = body.get("authentication_type") or ""
    roles = body.get("roles") if isinstance(body.get("roles"), list) else []
    if user == "_anonymous" or at == "anonymous":
        out["anonymous"] = True
        out["anonymous_username"] = user
        out["anonymous_roles"] = [str(r) for r in roles][:20]
        _probe_anonymous_read(ip, port, tls, timeout, out)


def _probe_anonymous_read(ip: str, port: int, tls: bool, timeout: float,
                          out: dict) -> None:
    """T2 SAFE proof-of-exploit for es_anonymous: after /_security/_authenticate
    reports the request is running as `_anonymous`, GET /_cat/indices with NO
    credentials. A 200 with an index array proves the granted anonymous role
    actually reads cluster metadata - the misconfig is not just theoretical, it
    grants live data access. Read-only (no _search / no doc dump); the raw index
    names + total doc count are the captured evidence.

    Populates out[anonymous_read_ok|anonymous_indices|anonymous_docs]. Silent on
    failure (401/403/timeout) so the T1 anonymous finding still emits."""
    cat = _get(ip, port, "/_cat/indices?format=json&bytes=b", tls, timeout,
               headers=None)
    if not cat or cat[0] != 200 or not isinstance(cat[1], list):
        return
    idx = [i.get("index", "") for i in cat[1]
           if isinstance(i, dict) and i.get("index")]
    if not idx:
        # 200 with an empty list still proves the read primitive worked - the
        # cluster just has no indices yet. Record the ok flag anyway.
        out["anonymous_read_ok"] = True
        out["anonymous_indices"] = []
        out["anonymous_docs"] = 0
        return
    docs = 0
    for i in cat[1]:
        if isinstance(i, dict):
            try:
                docs += int(i.get("docs.count") or 0)
            except (ValueError, TypeError):
                pass
    out["anonymous_read_ok"] = True
    out["anonymous_indices"] = idx[:20]
    out["anonymous_docs"] = docs


def _deep_es(ip: str, port: int, tls: bool, timeout: float, out: dict,
             headers: dict | None = None) -> None:
    """Read-only deep enumeration on an unauthenticated cluster: node OS/JVM (targeting
    for path-traversal / scripting RCE) and snapshot repositories (data-exfil / arbitrary
    read surface). Populates out[os_name|jvm_version|data_paths|snapshot_repos|
    snapshot_repo_settings]."""
    nodes = _get(ip, port, "/_nodes/_local/os,jvm,settings?format=json", tls, timeout,
                 headers=headers)
    if nodes and nodes[0] == 200 and isinstance(nodes[1], dict):
        nd = nodes[1].get("nodes")
        if isinstance(nd, dict):
            for info in nd.values():
                if not isinstance(info, dict):
                    continue
                osd = info.get("os") if isinstance(info.get("os"), dict) else {}
                jvm = info.get("jvm") if isinstance(info.get("jvm"), dict) else {}
                out["os_name"] = osd.get("pretty_name") or osd.get("name", "")
                out["jvm_version"] = jvm.get("version", "")
                break
    snaps = _get(ip, port, "/_snapshot/_all", tls, timeout, headers=headers)
    if snaps and snaps[0] == 200 and isinstance(snaps[1], dict):
        out["snapshot_repos"] = list(snaps[1].keys())[:20]
        # /_snapshot/_all already returns each repo's {type, settings} block
        # inline - no extra round-trip needed. For repository-s3 that yields
        # bucket + endpoint + region + base_path + client; for -gcs the bucket +
        # client; for -azure the container + client; for -fs the on-disk
        # `location` (a.k.a. path.repo entry). These are direct pivots into
        # cloud object stores / file shares. (Ref: ES Reference "Snapshot and
        # Restore" -> repository plugin settings.)
        _INTERESTING = (
            "bucket", "endpoint", "region", "base_path", "client",
            "container", "account", "location", "path", "compress",
            "server_side_encryption", "storage_class", "readonly",
        )
        repo_settings: dict = {}
        for name, spec in list(snaps[1].items())[:20]:
            if not isinstance(name, str) or not isinstance(spec, dict):
                continue
            settings = spec.get("settings") if isinstance(spec.get("settings"),
                                                          dict) else {}
            kept = {k: settings[k] for k in _INTERESTING if k in settings}
            repo_settings[name] = {
                "type": str(spec.get("type") or ""),
                "settings": kept,
            }
        if repo_settings:
            out["snapshot_repo_settings"] = repo_settings


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
    "es_anonymous": (
        "The cluster returns 401 on / but xpack.security.authc.anonymous.roles binds a "
        "de-facto role to every unauthenticated request. /_security/_authenticate "
        "answered 200 with username '_anonymous' - the built-in security is enabled "
        "but a whole role is granted to anyone who can reach the port. Remove the "
        "anonymous role or set xpack.security.authc.anonymous.authz_exception: true "
        "so unauthenticated requests are refused instead of silently authorised."),
}


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


_finding = finding_builder("elasticsearch", _NARRATIVE)


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
                # Deeper: node OS/JVM (targeting) + snapshot repos (exfil surface).
                deep = ""
                if pr.get("os_name") or pr.get("jvm_version"):
                    deep += (f"\n\nNode: {pr.get('os_name', '?')}"
                             + (f", JVM {pr['jvm_version']}" if pr.get("jvm_version") else "")
                             + (f", {pr['nodes']} node(s)" if pr.get("nodes") else "")
                             + " (targets the exact build for scripting-sandbox / "
                               "path-traversal RCE).")
                repos = pr.get("snapshot_repos") or []
                if repos:
                    deep += (f"\n\nSnapshot repositories readable: {', '.join(repos[:8])} "
                             "(data-exfil / restore-tampering surface; arbitrary read on "
                             "old builds).")
                # Per-repo config (bucket/endpoint/region/base_path for s3, container
                # for azure, location for fs, ...) - a direct pivot into cloud object
                # stores or on-disk share mounts.
                rs = pr.get("snapshot_repo_settings") or {}
                if rs:
                    parts = []
                    for name, spec in list(rs.items())[:6]:
                        t = spec.get("type") or "?"
                        st = spec.get("settings") or {}
                        pointer = (st.get("bucket") or st.get("container")
                                   or st.get("location") or st.get("path") or "")
                        endpoint = st.get("endpoint") or ""
                        bp = st.get("base_path") or ""
                        seg = f"{name}[{t}]"
                        if pointer:
                            seg += f" -> {pointer}"
                        if endpoint:
                            seg += f" @ {endpoint}"
                        if bp:
                            seg += f"/{bp}"
                        parts.append(seg)
                    deep += ("\n\nSnapshot repo config (pivot into cloud/fs storage): "
                             + "; ".join(parts) + ".")
                out.append(_finding(
                    "critical", "Elasticsearch exposed without authentication", tgt,
                    f"recce listed {len(idx)} index/indices with no credential"
                    + (f" (version {ver})" if ver else "")
                    + (f", {docs} document(s) total" if docs else "")
                    + (f": {names}" if names else "")
                    + ". Unauthenticated read (and, by default, write) access to all "
                    "data." + deep,
                    "curl / elasticdump",
                    f"curl -s http://{h.ip}:{p.portid}/_cat/indices ; "
                    f"curl -s http://{h.ip}:{p.portid}/_search?size=100   # then "
                    f"elasticdump --input=http://{h.ip}:{p.portid}/<index> --output=loot/",
                    "Enable the built-in security (xpack.security.enabled: true) with "
                    "users/roles, and bind the HTTP listener to a trusted interface.",
                    ["CWE-306", "CWE-284"], kind="es_unauth",
                    exploit_note=(
                        "curl -s 'http://<ip>:<port>/*/_search?size=20&pretty' > "
                        "loot/es.json ; elasticdump --input=http://<ip>:<port>/"
                        "<index> --output=loot/<index>.json ; then map snapshot "
                        "bucket to aws s3 ls s3://<bucket>/<base_path>."),
                    depth_tier="t2"))
            if pr.get("anonymous"):
                roles = pr.get("anonymous_roles") or []
                roles_txt = (", roles: " + ", ".join(roles[:6])) if roles else ""
                # T2 SAFE proof: if the anonymous role actually returned an
                # index list on _cat/indices (no auth), the misconfig is proven
                # live. Fold the captured evidence into the finding detail.
                anon_read = pr.get("anonymous_read_ok")
                anon_idx = pr.get("anonymous_indices") or []
                anon_docs = pr.get("anonymous_docs", 0)
                proof = ""
                if anon_read:
                    names = ", ".join(i for i in anon_idx[:10]
                                      if not i.startswith("."))
                    proof = (
                        "\n\nT2 proof: /_cat/indices returned 200 as _anonymous "
                        f"({len(anon_idx)} index/indices"
                        + (f", {anon_docs} document(s) total" if anon_docs else "")
                        + (f": {names}" if names else "")
                        + ") - the granted role reads live cluster data.")
                tier = "t2" if anon_read else "t1"
                out.append(_finding(
                    "high",
                    "Elasticsearch anonymous role grants unauthenticated access",
                    tgt,
                    "The cluster answered 401 on / (built-in security is enabled) but "
                    "/_security/_authenticate returned 200 with username "
                    f"'{pr.get('anonymous_username', '_anonymous')}'"
                    + roles_txt
                    + " - xpack.security.authc.anonymous.roles is granting a role to "
                    "every request that arrives without credentials, so the '401' on "
                    "/ is misleading and unauthenticated data access is available."
                    + proof,
                    "curl",
                    f"curl -s http://{h.ip}:{p.portid}/_security/_authenticate ; "
                    f"curl -s http://{h.ip}:{p.portid}/_cat/indices",
                    "Remove xpack.security.authc.anonymous.roles or set "
                    "xpack.security.authc.anonymous.authz_exception: true.",
                    ["CWE-284", "CWE-306"], kind="es_anonymous",
                    exploit_note=(
                        "curl -s http://<ip>:<port>/_security/_authenticate ; "
                        "curl -s http://<ip>:<port>/_cat/indices ; "
                        "curl -s 'http://<ip>:<port>/*/_search?size=5&pretty'"),
                    depth_tier=tier))
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
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "elasticsearch", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full Elasticsearch analysis. Returns {targets, findings, runbooks, probes,
    stats}. `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from .. import svcprobe
    targets = es_targets(hosts)
    probes: dict = {}
    state: dict = {}
    hdrs = _auth_headers(creds)
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], headers=hdrs or None),
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
