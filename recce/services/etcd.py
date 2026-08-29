"""etcd unauthenticated API probe.

etcd (2379/tcp) is the canonical key/value store behind Kubernetes and many
other orchestrators. When exposed without auth (the default on many quick-start
and self-hosted deployments) the entire cluster state is readable — including
service-account tokens, TLS keys, and application secrets stored via k8s.

Probe hits both API versions:
  * v2: GET /v2/keys/?recursive=true (deprecated but often still enabled)
  * v3: POST /v3/kv/range with the full-range query {"key":"AA==","range_end":"AA=="}

A response with a `nodes` or `kvs` array means the store is readable.
Version disclosure via GET /version is always attempted.

Airgap-safe: stdlib http.client / ssl. Bounded runtime (~4s per endpoint).
"""
from __future__ import annotations

import base64
import http.client
import json
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 2379
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"

# Seeded credential pairs for /v3/auth/authenticate. Sourced from etcd's own
# Documentation/op-guide/authentication.md (root/root is the historical example)
# and community deploy templates. Not CVE-derived, no vendor-specific creds.
# Order: most common first; the empty-secret case is last because some etcd
# versions reject empty passwords at the validator (400 not 401) before
# reaching the auth check, which is useful info too but not a positive.
_DEFAULT_AUTH_PAIRS = (
    ("root", "root"),
    ("root", "etcd"),
    ("root", "password"),
    ("root", "admin"),
    ("root", ""),
)


def is_etcd(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (2379, 4001, 2380)
            or "etcd" in svc or "etcd" in prod)


def _http(ip: str, port: int, method: str, path: str,
          body: bytes | None = None, timeout: float = _TIMEOUT,
          headers: dict | None = None) -> tuple[int, dict, bytes] | None:
    """Do one HTTP request, transparently retrying with HTTPS if the initial
    HTTP request gets an SSL-looking rejection. Returns (status, headers, body)
    or None on any failure. etcd defaults to HTTP but many deploys front it
    with TLS on the same port; this handles both."""
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            hdrs = {"User-Agent": _UA, "Connection": "close"}
            if headers:
                hdrs.update(headers)
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read(200_000)
            return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if not use_tls:
                # Fall through to retry with TLS
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
    """Return {reachable, version, v2_readable, v3_readable, v2_keys, v3_keys}.
    *_readable flags are True when the corresponding API returned a non-empty
    keys/nodes list without auth."""
    out = {"reachable": False, "version": "", "v2_readable": False,
           "v3_readable": False, "v2_keys": 0, "v3_keys": 0}

    # /version — cheap fingerprint, tells us if this really is etcd.
    r = _http(ip, port, "GET", "/version", timeout=timeout)
    if r is None:
        return out
    status, _, body = r
    if status != 200:
        # /health as a fallback — some deployments block /version but keep
        # /health open for load balancers.
        r = _http(ip, port, "GET", "/health", timeout=timeout)
        if r is None or r[0] != 200:
            return out
    else:
        try:
            j = json.loads(body.decode("utf-8", "replace"))
            out["version"] = str(j.get("etcdserver") or j.get("etcdcluster") or "")[:80]
        except (ValueError, UnicodeDecodeError):
            # Some etcd versions return plain-text — grab the first line.
            out["version"] = body[:120].decode("utf-8", "replace").strip()
    out["reachable"] = True

    # v2 API — GET /v2/keys/?recursive=true. A 200 + non-empty `nodes` = readable.
    r = _http(ip, port, "GET", "/v2/keys/?recursive=true", timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            out["v2_readable"] = True
            # Rough key count — recurse counted by summing "nodes" lists.
            out["v2_keys"] = _count_v2_nodes(j.get("node") or {})
        except (ValueError, UnicodeDecodeError):
            pass

    # v3 API — POST /v3/kv/range with {key: base64(0x00), range_end: base64(0x00)}
    # queries all keys with key >= 0x00 (the whole store).
    v3_query = json.dumps({"key": base64.b64encode(b"\x00").decode(),
                           "range_end": base64.b64encode(b"\x00").decode()}).encode()
    r = _http(ip, port, "POST", "/v3/kv/range", body=v3_query,
              headers={"Content-Type": "application/json"}, timeout=timeout)
    if r is not None and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            kvs = j.get("kvs") or []
            out["v3_readable"] = True
            out["v3_keys"] = len(kvs)
        except (ValueError, UnicodeDecodeError):
            pass

    # v3 Maintenance snapshot — separately-gated permission from kv/range on many
    # deployments; the response is a gRPC-JSON stream of {"result":{"blob":"...",
    # "remaining_bytes":"N"}} frames concatenated. Even one decodable blob frame
    # is proof the server is streaming the bbolt DB to an anonymous caller —
    # we cap the read in _http so a positive here is not a full download.
    snap = _snapshot_probe(ip, port, timeout=timeout)
    out["snapshot_ok"] = snap["ok"]
    out["snapshot_bytes"] = snap["bytes"]

    # Default-credential authenticate — attempted only when unauth v3 read
    # failed (a positive read means auth is off, so credentials are moot).
    # /v3/auth/authenticate returns {"token": "..."} on success.
    if not out["v3_readable"]:
        cred = _default_cred_probe(ip, port, timeout=timeout)
        if cred:
            out["default_cred_user"] = cred[0]
            out["default_cred_pass"] = cred[1]

    return out


def _snapshot_probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """POST /v3/maintenance/snapshot with an empty body. Returns
    {'ok': bool, 'status': int, 'bytes': int}. The bytes count is the sum of
    base64-decoded blob chunks observed in the (capped) response prefix — not a
    complete download."""
    r = _http(ip, port, "POST", "/v3/maintenance/snapshot", body=b"{}",
              headers={"Content-Type": "application/json"}, timeout=timeout)
    if r is None:
        return {"ok": False, "status": 0, "bytes": 0}
    status, _, body = r
    if status != 200 or not body:
        return {"ok": False, "status": status, "bytes": 0}
    # gRPC-JSON streaming: successive JSON objects. The gateway does not
    # newline-delimit reliably; try line-split first, then a naïve split on
    # "}{". A single decodable blob chunk is enough for a positive verdict.
    bytes_dumped = 0
    ok = False
    text = body.decode("utf-8", "replace")
    if '"blob"' not in text and '"result"' not in text:
        return {"ok": False, "status": status, "bytes": 0}
    candidates = text.split("\n") if "\n" in text.strip() else text.replace("}{", "}\x00{").split("\x00")
    for chunk in candidates:
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            obj = json.loads(chunk)
        except ValueError:
            continue
        blob = ((obj.get("result") or {}).get("blob")) or obj.get("blob") or ""
        if blob:
            try:
                bytes_dumped += len(base64.b64decode(blob, validate=False))
                ok = True
            except (ValueError, TypeError):
                pass
    return {"ok": ok, "status": status, "bytes": bytes_dumped}


def _default_cred_probe(ip: str, port: int,
                        timeout: float = _TIMEOUT) -> tuple[str, str] | None:
    """Try seeded (user, password) pairs against POST /v3/auth/authenticate.
    Returns the first pair that yields a bearer token, or None. Bounded by
    len(_DEFAULT_AUTH_PAIRS) requests."""
    for user, pw in _DEFAULT_AUTH_PAIRS:
        body = json.dumps({"name": user, "password": pw}).encode()
        r = _http(ip, port, "POST", "/v3/auth/authenticate", body=body,
                  headers={"Content-Type": "application/json"}, timeout=timeout)
        if r is None:
            # Network error on this attempt — try the next pair; it might
            # transiently succeed against a different TLS path.
            continue
        status, _, resp = r
        if status != 200:
            continue
        try:
            j = json.loads(resp.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            continue
        # etcd returns {"header":{...},"token":"<jwt>"} on success; on failure
        # the gateway returns 200 with {"error":"...","code":3} for older
        # versions and 400/401 for newer — the token key is authoritative.
        token = j.get("token")
        if isinstance(token, str) and token:
            return (user, pw)
    return None


def _count_v2_nodes(node: dict) -> int:
    """Recursively count nodes in an etcd v2 response tree. Bounded by
    the response size we already capped in _http (~200 KB)."""
    n = 1 if node.get("key") else 0
    for child in node.get("nodes", []):
        n += _count_v2_nodes(child)
    return n


def etcd_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_etcd(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "etcdctl", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_etcd(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            if pr.get("v3_readable") or pr.get("v2_readable"):
                api = []
                if pr.get("v3_readable"): api.append(f"v3 ({pr['v3_keys']} keys)")
                if pr.get("v2_readable"): api.append(f"v2 ({pr['v2_keys']} nodes)")
                out.append(_finding(
                    "critical",
                    "etcd unauthenticated key-store read", tgt,
                    f"etcd (version {pr.get('version','?')}) accepts anonymous "
                    f"reads via: {', '.join(api)}. This is the cluster's entire "
                    f"key/value store — for a Kubernetes deployment that means "
                    f"every Secret, ServiceAccount token, TLS key, and ConfigMap "
                    f"is readable without credentials.",
                    f"etcdctl --endpoints http://{h.ip}:{p.portid} get / --prefix --keys-only",
                    "Enable client certificate authentication (--client-cert-auth). "
                    "Bind etcd to a private interface. Never expose 2379 to a "
                    "network shared with untrusted clients.",
                    ["CWE-306", "CWE-284", "CWE-200"], kind="etcd_unauth_read"))
            elif pr.get("default_cred_user"):
                # Unauth reads failed but a seeded credential authenticated.
                # This is critical: the token from /v3/auth/authenticate is
                # usable against every other endpoint, defeating the auth wall.
                u = pr["default_cred_user"]
                pw_disp = pr.get("default_cred_pass") or "<empty>"
                out.append(_finding(
                    "critical",
                    "etcd default-credential authentication", tgt,
                    f"etcd (version {pr.get('version','?')}) authenticated the "
                    f"seeded pair '{u}:{pw_disp}' via POST /v3/auth/authenticate "
                    f"and returned a bearer token. That token authorizes every "
                    f"downstream RPC (kv/range, maintenance/snapshot, "
                    f"cluster/member/list), fully bypassing the auth wall the "
                    f"anonymous v2/v3 range probes hit.",
                    f"curl -sk -X POST http://{h.ip}:{p.portid}/v3/auth/authenticate "
                    f"-d '{{\"name\":\"{u}\",\"password\":\"{pw_disp}\"}}'",
                    "Rotate the etcd root password and every user password. Use "
                    "long random secrets, not deploy-template defaults. Prefer "
                    "--client-cert-auth over password auth for etcd.",
                    ["CWE-798", "CWE-521"], kind="etcd_default_creds"))
            else:
                # Reachable but no unauth read — still worth an info-level
                # finding so the tester knows there's an etcd here to attack
                # with credentials if they get any.
                out.append(_finding(
                    "info", "etcd endpoint reachable", tgt,
                    f"etcd version {pr.get('version','?')} responded, but the "
                    f"unauthenticated v2/v3 range queries were denied — the "
                    f"instance is auth-protected. Any leaked etcd client cert "
                    f"or peer token from other hosts would target this endpoint.",
                    f"curl http://{h.ip}:{p.portid}/version",
                    "Ensure etcd continues to require client-cert or RBAC auth.",
                    [], kind="etcd_authed"))
            # Snapshot download is separately-gated from kv/range on many
            # deployments — emit even when kv/range failed. Independent finding
            # because the primitive (full bbolt dump, including uncompacted
            # historical revisions of deleted Secrets) is distinct from a
            # live-key read: it also recovers keys that were compacted away.
            if pr.get("snapshot_ok"):
                bshown = pr.get("snapshot_bytes") or 0
                out.append(_finding(
                    "critical",
                    "etcd unauthenticated snapshot download", tgt,
                    f"POST /v3/maintenance/snapshot on etcd (version "
                    f"{pr.get('version','?')}) streamed the bbolt database "
                    f"file to an anonymous caller "
                    f"({bshown} bytes decoded from the capped response prefix). "
                    f"A snapshot contains every live key AND uncompacted "
                    f"historical revisions — deleted Kubernetes Secrets can be "
                    f"recovered offline with bbolt walking, regardless of "
                    f"whether current kv/range is denied.",
                    f"curl -sk -X POST http://{h.ip}:{p.portid}/v3/maintenance/snapshot "
                    f"-o etcd-snap.db && etcdctl snapshot status etcd-snap.db",
                    "Restrict /v3/maintenance/* to authenticated maintenance-role "
                    "principals; enable --client-cert-auth. Note that snapshot "
                    "permission is gated separately from kv/range — auditing "
                    "kv/range alone is insufficient.",
                    ["CWE-306", "CWE-200"], kind="etcd_snapshot_download"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Fingerprint version",
         "cmd": f"curl -sk http{{,s}}://{ip}:{port}/version"},
        {"step": "Enumerate all keys (v3)",
         "cmd": f"etcdctl --endpoints http://{ip}:{port} get / --prefix --keys-only"},
        {"step": "Enumerate all keys (v2)",
         "cmd": f"curl -sk 'http://{ip}:{port}/v2/keys/?recursive=true'"},
        {"step": "Download bbolt snapshot (crown-jewel dump)",
         "cmd": f"curl -sk -X POST http://{ip}:{port}/v3/maintenance/snapshot "
                f"-o etcd-snap.db && etcdctl snapshot status etcd-snap.db"},
        {"step": "Try seeded credentials against auth (root/root, root/etcd, ...)",
         "cmd": f"for p in root etcd password admin ''; do curl -sk -X POST "
                f"http://{ip}:{port}/v3/auth/authenticate "
                f"-d \"{{\\\"name\\\":\\\"root\\\",\\\"password\\\":\\\"$p\\\"}}\"; done"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "etcd", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = etcd_targets(hosts)
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
                t["unauth_read"] = pr.get("v3_readable") or pr.get("v2_readable")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
