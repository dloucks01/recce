"""Deep Kubernetes attack-surface enumeration + vulnerability identification.

Stdlib-only HTTP(S) probes of the cluster's most dangerous network exposures:

  * **kubelet** (10250, HTTPS): an anonymous-auth kubelet answers /pods and, worse,
    exposes /exec /run - code execution inside any pod on the node (→ node, often
    cluster, compromise). The deprecated **read-only port** (10255, HTTP) leaks the
    full pod spec (env-var secrets, images) with no auth at all.
  * **kube-apiserver** (6443 / 8443 HTTPS): whether the `system:anonymous` user can
    reach the API and, critically, whether RBAC lets it LIST namespaces / secrets
    (a 200 = cluster-wide read, often game over).
  * **etcd** (2379): the cluster's backing store; unauthenticated read = every Secret
    (all service-account tokens, TLS keys) in plaintext.

Each positive read is the proof, folds into the main severity totals, the
Vulnerabilities sheet and the write-ups, and lands on a dedicated Kubernetes tab.
Airgapped, stdlib only. Safety posture: see SECURITY.md.
"""
from __future__ import annotations

import http.client
import json
import re
import ssl

from .models import Host, Port

_TIMEOUT = 6.0
_KUBELET = 10250
_KUBELET_RO = 10255
# 6443 is the secure apiserver; 8443 is the common alt. The legacy --insecure-port
# (8080) was removed in Kubernetes 1.20, and 8080 is a very common generic-HTTP port,
# so recce only treats it as an apiserver when nmap names the service kube-apiserver
# (handled in is_k8s), never by bare port number.
_API_PORTS = (6443, 8443)
_ETCD = 2379
_K8S_PORTS = (_KUBELET, _KUBELET_RO, 6443, 8443, _ETCD)


def is_k8s(port: Port) -> bool:
    if port.state != "open":
        return False
    if port.portid in _K8S_PORTS:
        return True
    return any(k in f"{port.service} {port.product}".lower()
               for k in ("kubernetes", "kubelet", "kube-apiserver", "etcd", "k8s"))


def role(port: int) -> str:
    if port == _KUBELET:
        return "kubelet"
    if port == _KUBELET_RO:
        return "kubelet-ro"
    if port in _API_PORTS:
        return "apiserver"
    if port == _ETCD:
        return "etcd"
    return "unknown"


_READ_CAP = 16 * 1024 * 1024   # hard ceiling on a single response body (16 MB)


def _read_capped(resp, cap: int = _READ_CAP) -> bytes:
    """Read an HTTP response to EOF, bounded by `cap` (avoids OOM on a hostile body
    while still capturing multi-MB pod/secret lists that a 256 KB read truncated)."""
    chunks, total = [], 0
    while total < cap:
        chunk = resp.read(min(65536, cap - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _req(ip: str, port: int, path: str, tls: bool, method: str = "GET",
         body: str | None = None, timeout: float = _TIMEOUT):
    """Issue one request. Returns (status, parsed_json_or_text) or None."""
    conn = None
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        headers = {"Accept": "application/json", "User-Agent": "recce-k8s/1.0"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        # Read to EOF up to a generous cap. A single small read() truncated a busy
        # node's /pods or the apiserver's /secrets mid-buffer, so json.loads failed
        # and the endpoint was misread as merely "reachable" (a critical exposure
        # downgraded). The str fallback below still flags a >cap body as a real list.
        raw = _read_capped(resp).decode("utf-8", "replace")
        try:
            return resp.status, json.loads(raw)
        except ValueError:
            return resp.status, raw
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _get(ip: str, port: int, path: str, tls: bool, timeout: float = _TIMEOUT):
    """GET a path. Returns (status, parsed_json_or_text) or None."""
    return _req(ip, port, path, tls, "GET", None, timeout)


def _try_get(ip, port, path, timeout):
    """GET trying TLS first then plaintext (kubelet/api are TLS; 8080/10255 plain)."""
    r = _get(ip, port, path, tls=True, timeout=timeout)
    if r is not None:
        return r, True
    r = _get(ip, port, path, tls=False, timeout=timeout)
    return (r, False) if r is not None else (None, None)


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict | None:
    """Role-aware unauthenticated probe. Returns a dict describing what was reachable,
    or None if the port didn't answer."""
    r = role(port)
    out = {"ip": ip, "port": port, "role": r}
    if r == "kubelet":
        pods, tls = _try_get(ip, port, "/pods", timeout)
        if pods is None:
            return None
        out["tls"] = tls
        out["anon_pods"] = pods[0] == 200 and _is_podlist(pods[1])
        out["pod_count"] = _pod_count(pods[1]) if out["anon_pods"] else None
        out["status"] = pods[0]
        return out
    if r == "kubelet-ro":
        pods = _get(ip, port, "/pods", tls=False, timeout=timeout)
        if pods is None:
            pods = _get(ip, port, "/pods", tls=True, timeout=timeout)
        if pods is None:
            return None
        out["anon_pods"] = pods[0] == 200 and _is_podlist(pods[1])
        out["pod_count"] = _pod_count(pods[1]) if out["anon_pods"] else None
        out["status"] = pods[0]
        return out
    if r == "apiserver":
        ver, tls = _try_get(ip, port, "/version", timeout)
        if ver is None:
            return None
        out["tls"] = tls
        out["version"] = (ver[1] or {}).get("gitVersion", "") if isinstance(ver[1], dict) else ""
        # Reuse the scheme /version answered on - re-probing TLS-then-plaintext for
        # every follow-up doubles the connects (and wrong-scheme timeouts) per host.
        # Anonymous authorization: can system:anonymous LIST namespaces?
        ns = _get(ip, port, "/api/v1/namespaces", tls=tls, timeout=timeout)
        out["anon_status"] = ns[0] if ns else None
        out["anon_list"] = bool(ns and ns[0] == 200 and _is_list(ns[1]))
        if out["anon_list"]:
            sec = _get(ip, port, "/api/v1/secrets", tls=tls, timeout=timeout)
            out["anon_secrets"] = bool(sec and sec[0] == 200 and _is_list(sec[1]))
        return out
    if r == "etcd":
        ver, tls = _try_get(ip, port, "/version", timeout)
        if ver is None:
            return None
        out["tls"] = tls
        out["etcd_version"] = _etcd_version(ver[1])
        # v2 keys API (disabled by default since etcd 3.4, but still seen on older
        # clusters). Reuse the scheme /version answered on (etcd serves both over it).
        keys = _get(ip, port, "/v2/keys/?recursive=true", tls=tls, timeout=timeout)
        out["v2_readable"] = bool(keys and keys[0] == 200
                                  and isinstance(keys[1], dict) and "node" in keys[1])
        # v3 gRPC-gateway (what every modern Kubernetes ships): an unauthenticated
        # maintenance/status read = no client-cert-auth = the whole store is readable.
        v3 = _req(ip, port, "/v3/maintenance/status", tls, "POST", "{}", timeout)
        if v3 is None:
            v3 = _req(ip, port, "/v3/maintenance/status", not tls, "POST", "{}", timeout)
        out["v3_readable"] = bool(v3 and v3[0] == 200 and isinstance(v3[1], dict)
                                  and ("version" in v3[1] or "dbSize" in v3[1]
                                       or "header" in v3[1]))
        return out
    return None


def _is_podlist(body) -> bool:
    if isinstance(body, dict):
        return body.get("kind") == "PodList" or isinstance(body.get("items"), list)
    if isinstance(body, str):     # oversized/truncated JSON still proves exposure
        b = body.replace(" ", "")
        return '"kind":"PodList"' in b or '"items"' in b
    return False


def _pod_count(body) -> int | None:
    if isinstance(body, dict) and isinstance(body.get("items"), list):
        return len(body["items"])
    return None


def _is_list(body) -> bool:
    if isinstance(body, dict):
        return (str(body.get("kind", "")).endswith("List")
                or isinstance(body.get("items"), list))
    if isinstance(body, str):     # oversized/truncated JSON still proves exposure
        b = body.replace(" ", "")
        return '"items"' in b or bool(re.search(r'"kind":"\w+List"', b))
    return False


def _etcd_version(body) -> str:
    if isinstance(body, dict):
        return body.get("etcdserver", "") or body.get("etcdcluster", "")
    if isinstance(body, str):
        return body.strip()[:40]
    return ""


def k8s_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_k8s(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "role": role(p.portid), "product": p.product or ""})
    return out


# --- narratives -----------------------------------------------------------------

_NARRATIVE = {
    "kubelet_anon": (
        "The kubelet is the per-node agent that runs containers, and this one answers "
        "unauthenticated. Beyond listing every pod on the node (names, namespaces, "
        "images, and the env-var secrets in the spec), an anonymous kubelet exposes "
        "the /exec, /run and /attach endpoints - remote command execution INSIDE any "
        "container on the node. From a shell in a pod an attacker reads that pod's "
        "mounted service-account token and calls the API server as it; a token with "
        "any meaningful RBAC (or a privileged/hostPath pod on the node) escalates to "
        "the node and frequently the whole cluster. This is one of the highest-impact "
        "Kubernetes misconfigurations."),
    "kubelet_ro": (
        "The kubelet read-only port (10255) serves the full pod spec over plain HTTP "
        "with no authentication. It leaks every pod's images, command lines and - "
        "critically - the environment variables, which routinely hold database "
        "passwords, API keys and cloud credentials. It is pure reconnaissance, but "
        "it habitually hands over the secrets needed for the next hop."),
    "api_anon_list": (
        "The kube-apiserver allows the unauthenticated system:anonymous user to LIST "
        "cluster resources - recce read them with no token. If it can list Secrets, "
        "that is every service-account token and TLS key in the cluster, i.e. full "
        "cluster compromise. Even namespace/pod listing is a serious RBAC failure that "
        "maps the cluster and often exposes a path to a privileged binding."),
    "api_anon_open": (
        "The kube-apiserver accepts anonymous requests (system:anonymous is enabled). "
        "Listing was refused by RBAC here, but anonymous-auth being on is the "
        "precondition for every RBAC-misconfiguration and CVE that grants the "
        "anonymous user access - it should be disabled (--anonymous-auth=false)."),
    "etcd_open": (
        "etcd is the cluster's backing store and it answered unauthenticated. Every "
        "Kubernetes object lives here in the clear, including all Secrets - every "
        "service-account token, kubeconfig and TLS private key in the cluster. Reading "
        "etcd is equivalent to owning the cluster: impersonate any service account, "
        "mint tokens, or decrypt traffic."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Unauthenticated reads (stdlib)",
     "recce issues plain HTTP(S) GETs with no token to each Kubernetes surface: the "
     "kubelet /pods (10250) and read-only /pods (10255), the kube-apiserver /version "
     "and /api/v1/namespaces (anonymous authorization), and etcd /version + /v2/keys."),
    ("2. Vulnerability identification",
     "A kubelet that returns pods anonymously -> exec RCE into pods. The read-only "
     "port -> secret-leaking pod specs. An apiserver that LISTs for system:anonymous "
     "-> RBAC failure (Secrets = cluster compromise). etcd answering -> every secret "
     "in the clear. Each folds into the main totals; the prove engine confirms it."),
    ("3. Proof",
     "recce only READS - it never execs into a pod, writes to etcd, or creates "
     "objects. The successful unauthenticated read is the proof and is captured as "
     "evidence."),
    ("4. Runbook",
     "The exact follow-on (kubeletctl exec, kubectl --insecure anonymous calls, "
     "etcdctl secret dump) is staged, to run within ROE."),
]


# --- findings -------------------------------------------------------------------

def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "kubernetes", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_k8s(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            r = pr.get("role")
            if r == "kubelet" and pr.get("anon_pods"):
                out.append(_finding(
                    "critical", "Kubelet allows anonymous access (exec RCE into pods)",
                    tgt, "The kubelet answered /pods unauthenticated"
                    + (f" ({pr['pod_count']} pod(s))" if pr.get("pod_count") is not None
                       else "")
                    + ".  Anonymous kubelets also expose /exec and /run - remote "
                    "command execution inside any container on the node.",
                    "kubeletctl",
                    "kubeletctl -i --server <ip> pods ; kubeletctl -i --server <ip> "
                    "exec \"id\" -p <pod> -c <container> -n <ns>   # RCE in a pod (ROE)",
                    "Set --anonymous-auth=false and --authorization-mode=Webhook on the "
                    "kubelet; firewall 10250.",
                    ["CWE-306", "CWE-284", "CWE-269"], kind="kubelet_anon"))
            elif r == "kubelet-ro" and pr.get("anon_pods"):
                out.append(_finding(
                    "high", "Kubelet read-only port exposes pod specs (secret leak)",
                    tgt, "The kubelet read-only port served /pods over plain HTTP with "
                    "no authentication"
                    + (f" ({pr['pod_count']} pod(s))" if pr.get("pod_count") is not None
                       else "")
                    + ".  Pod specs leak images, commands and env-var secrets.",
                    "curl",
                    "curl -s http://<ip>:10255/pods | jq '.items[].spec.containers[].env'",
                    "Disable the read-only port (--read-only-port=0).",
                    ["CWE-306", "CWE-200"], kind="kubelet_ro"))
            elif r == "apiserver":
                if pr.get("anon_list"):
                    sec = pr.get("anon_secrets")
                    out.append(_finding(
                        "critical" if sec else "high",
                        "Kubernetes API allows anonymous resource listing"
                        + (" incl. Secrets" if sec else ""),
                        tgt, "The kube-apiserver returned 200 to an unauthenticated "
                        "(system:anonymous) LIST of namespaces"
                        + (" AND secrets - every service-account token and TLS key is "
                           "readable (cluster compromise)" if sec
                           else " - a serious RBAC misconfiguration")
                        + f".  Server: {pr.get('version', '?')}.",
                        "kubectl",
                        "kubectl --server https://<ip>:<port> --insecure-skip-tls-verify "
                        "get secrets -A -o yaml   # dump every secret (ROE)",
                        "Never bind roles to system:anonymous / system:unauthenticated; "
                        "set --anonymous-auth=false.",
                        ["CWE-306", "CWE-284", "CWE-269"] if sec
                        else ["CWE-306", "CWE-284"], kind="api_anon_list"))
                elif pr.get("anon_status") == 403:
                    out.append(_finding(
                        "low", "Kubernetes API accepts anonymous requests", tgt,
                        "The kube-apiserver processes unauthenticated requests "
                        "(system:anonymous is enabled); RBAC refused the list here "
                        f"(403), but anonymous-auth is on.  Server: {pr.get('version', '?')}.",
                        "kubectl",
                        "kubectl --server https://<ip>:<port> --insecure-skip-tls-verify "
                        "auth can-i --list --as=system:anonymous",
                        "Disable anonymous auth (--anonymous-auth=false) unless a health "
                        "endpoint requires it.",
                        ["CWE-306"], kind="api_anon_open"))
            elif r == "etcd" and (pr.get("v2_readable") or pr.get("v3_readable")):
                api = "v2 keys" if pr.get("v2_readable") else "v3 gRPC-gateway"
                out.append(_finding(
                    "critical", "etcd exposed unauthenticated (all cluster secrets)",
                    tgt, f"etcd answered an unauthenticated read via its {api} API. etcd "
                    "holds every Kubernetes object in the clear, including all Secrets "
                    "(service-account tokens, TLS keys).  Version: "
                    f"{pr.get('etcd_version', '?')}.",
                    "etcdctl",
                    "ETCDCTL_API=3 etcdctl --endpoints <ip>:2379 get / --prefix --keys-only "
                    "; ... get /registry/secrets/... (dump secrets - ROE)",
                    "Require client-certificate auth and peer TLS on etcd "
                    "(--client-cert-auth, --peer-client-cert-auth); firewall 2379/2380.",
                    ["CWE-306", "CWE-200", "CWE-284"], kind="etcd_open"))
    return out


# --- runbook --------------------------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    r = role(port)
    if r == "kubelet":
        steps = [("enumerate", "kubeletctl",
                  f"kubeletctl -i --server {ip} pods", "List pods via the kubelet."),
                 ("escalate", "kubeletctl",
                  f"kubeletctl -i --server {ip} exec \"id\" -p <pod> -c <ctr> -n <ns>",
                  "Execute in a pod, read its service-account token, call the API as it.")]
    elif r == "kubelet-ro":
        steps = [("loot", "curl",
                  f"curl -s http://{ip}:{port}/pods | jq '.items[].spec.containers[].env'",
                  "Harvest env-var secrets from every pod spec.")]
    elif r == "apiserver":
        base = f"kubectl --server https://{ip}:{port} --insecure-skip-tls-verify"
        steps = [("enumerate", "kubectl", f"{base} get ns,pods -A",
                  "Enumerate the cluster as system:anonymous."),
                 ("loot", "kubectl", f"{base} get secrets -A -o yaml",
                  "Dump every secret if RBAC allows (cluster compromise).")]
    elif r == "etcd":
        steps = [("loot", "etcdctl",
                  f"ETCDCTL_API=3 etcdctl --endpoints {ip}:{port} get / --prefix --keys-only",
                  "List keys, then read /registry/secrets/* for tokens/keys.")]
    else:
        steps = []
    return [{"phase": ph, "tool": t, "command": c, "why": w} for ph, t, c, w in steps]


# --- proof screenshot -----------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """Kubernetes findings -> {ip: [Vuln]} (source='kubernetes', script_id 'k8s:')."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "kubernetes", _KUBELET, prefix="k8s")


def analyze(hosts: list[Host], active: bool = True) -> dict:
    """Full Kubernetes analysis. Returns {targets, findings, runbooks, stats}."""
    targets = k8s_targets(hosts)
    probes: dict = {}
    if active:
        for t in targets:
            pr = probe(t["ip"], t["port"])
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = True
                for k in ("anon_pods", "anon_list", "anon_secrets", "v2_readable",
                          "v3_readable", "version", "etcd_version", "pod_count",
                          "anon_status"):
                    if k in pr:
                        t[k] = pr[k]
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"], "role": t["role"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs)}}
