"""HashiCorp Consul unauthenticated API probe.

Consul (8500/tcp HTTP, 8501/tcp HTTPS) exposes a rich HTTP API for service
discovery, KV store, and ACL management. Default Consul deployments run
without ACLs enabled — anyone who can reach the port reads:

* every registered service (network map handed over)
* the full KV store (credentials, configs, feature flags)
* every node's metadata + tags
* raft peers + cluster config

Findings:
  * consul_unauth_read (CRITICAL) — ACLs are disabled or default-allow;
    the whole cluster state is readable without a token.
  * consul_authed (info) — reachable but requires a token; still worth
    surfacing so any looted token has a known target.

Airgap-safe: stdlib http.client + ssl. Bounded probe (~4 endpoints * 3s).
"""
from __future__ import annotations

import base64
import http.client
import json
import re
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 8500
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"

_KV_MAX_ENTRIES = 500
_KV_VALUE_MAX = 4096
_KV_SECRET_HITS_MAX = 25
_KV_PREVIEW_LEN = 120

_SECRET_KEY_RE = re.compile(
    r"(?:^|[/_.-])(pass(?:word|wd)?|secret|token|api[_-]?key|apikey|"
    r"auth|creds?|credential|priv(?:ate)?[_-]?key|access[_-]?key|"
    r"aws|gcp|azure|vault|jwt|bearer|session|cookie|sasl|smtp[_-]?pass)"
    r"(?:$|[/_.-])",
    re.IGNORECASE,
)
_SECRET_VALUE_RES = (
    ("aws_access_key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(rb"aws[_-]?secret[_-]?access[_-]?key['\"\s:=]{1,4}[A-Za-z0-9/+=]{40}",
                                  re.IGNORECASE)),
    ("private_key_pem", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt", re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("db_uri", re.compile(rb"\b(?:postgres(?:ql)?|mysql|mongodb|redis|amqp)://"
                          rb"[^\s:@/]+:[^\s@/]+@[^\s/]+", re.IGNORECASE)),
    ("google_api_key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(rb"\bxox[abpr]-[A-Za-z0-9-]{10,}\b")),
    ("ssh_authorized", re.compile(rb"\bssh-(?:rsa|ed25519|dss|ecdsa) [A-Za-z0-9+/=]{40,}")),
)


def _extract_token(creds: dict | None) -> str:
    if not creds:
        return ""
    for key in ("consul_token", "token"):
        v = creds.get(key) if isinstance(creds, dict) else None
        if isinstance(v, str) and v:
            return v
    sub = creds.get("consul") if isinstance(creds, dict) else None
    if isinstance(sub, dict):
        for key in ("token", "secret_id", "SecretID"):
            v = sub.get(key)
            if isinstance(v, str) and v:
                return v
    return ""


def is_consul(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (8500, 8501)
            or "consul" in svc or "consul" in prod)


def _http(ip: str, port: int, method: str, path: str,
          timeout: float = _TIMEOUT, token: str = "",
          max_bytes: int = 200_000) -> tuple[int, bytes] | None:
    """One request. Transparently retries HTTPS if plain HTTP fails at the
    TLS handshake. Returns (status, body) or None."""
    headers = {"User-Agent": _UA, "Connection": "close"}
    if token:
        headers["X-Consul-Token"] = token
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request(method, path, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read(max_bytes)
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if not use_tls:
                continue
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
    return None


def _parse_agent_self(body: bytes, out: dict) -> None:
    try:
        j = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return
    if not isinstance(j, dict):
        return
    cfg = j.get("Config") if isinstance(j.get("Config"), dict) else {}
    dbg = j.get("DebugConfig") if isinstance(j.get("DebugConfig"), dict) else {}
    out["version"] = str(cfg.get("Version", "") or dbg.get("Version", ""))[:60]
    acl = dbg.get("ACLDefaultPolicy") \
          or (cfg.get("ACL", {}) if isinstance(cfg.get("ACL"), dict) else {}).get("DefaultPolicy") \
          or ""
    out["acl_enabled"] = str(acl).lower() == "deny"
    out["datacenter"] = str(cfg.get("Datacenter", "") or dbg.get("Datacenter", ""))[:60]
    server = cfg.get("Server")
    if server is None:
        server = dbg.get("ServerMode")
    if isinstance(server, bool):
        out["server"] = server
    node_name = cfg.get("NodeName") or dbg.get("NodeName")
    if isinstance(node_name, str):
        out["node_name"] = node_name[:80]
    node_id = cfg.get("NodeID") or dbg.get("NodeID")
    if isinstance(node_id, str):
        out["node_id"] = node_id[:80]
    encrypt = dbg.get("EncryptKey")
    enc_present = False
    if isinstance(encrypt, str) and encrypt:
        enc_present = True
    for k in ("SerfLANConfig", "SerfWANConfig"):
        sub = dbg.get(k)
        if isinstance(sub, dict) and sub.get("MemberlistConfig", {}).get("SecretKey"):
            enc_present = True
    if not enc_present:
        keyring = dbg.get("KeyringFile") or cfg.get("EncryptKey")
        if isinstance(keyring, str) and keyring:
            enc_present = True
    out["gossip_encrypted"] = enc_present
    tls_min = dbg.get("TLSMinVersion") or cfg.get("TLSMinVersion") or ""
    if not tls_min and isinstance(cfg.get("TLS"), dict):
        defaults = cfg["TLS"].get("Defaults")
        if isinstance(defaults, dict):
            tls_min = defaults.get("TLSMinVersion", "") or ""
    if isinstance(tls_min, str) and tls_min:
        out["tls_min_version"] = tls_min[:16]
    raft = dbg.get("RaftProtocol") or cfg.get("RaftProtocol")
    if isinstance(raft, int):
        out["raft_protocol"] = raft


def _classify_kv(entries: list) -> tuple[int, list[dict]]:
    total = 0
    hits: list[dict] = []
    for ent in entries:
        if not isinstance(ent, dict):
            continue
        total += 1
        key = str(ent.get("Key", ""))[:200]
        raw_val = ent.get("Value")
        decoded = b""
        if isinstance(raw_val, str) and raw_val:
            try:
                decoded = base64.b64decode(raw_val, validate=False)[:_KV_VALUE_MAX]
            except (ValueError, TypeError, base64.binascii.Error):
                decoded = b""
        matched_key = bool(_SECRET_KEY_RE.search(key))
        val_kinds: list[str] = []
        if decoded:
            for name, rx in _SECRET_VALUE_RES:
                if rx.search(decoded):
                    val_kinds.append(name)
        if matched_key or val_kinds:
            preview = ""
            if decoded:
                try:
                    preview = decoded.decode("utf-8", "replace")[:_KV_PREVIEW_LEN]
                except Exception:
                    preview = ""
            hits.append({
                "key": key,
                "kinds": (["key_name"] if matched_key else []) + val_kinds,
                "size": len(decoded),
                "preview": preview,
            })
            if len(hits) >= _KV_SECRET_HITS_MAX:
                break
    return total, hits


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          token: str = "") -> dict:
    """Fingerprint Consul via /v1/status/leader, then probe the readable
    endpoints. Returns {reachable, version, leader, services, nodes, kv_keys, ...}."""
    out = {"reachable": False, "version": "", "leader": "",
           "services": [], "nodes": 0, "kv_keys": 0, "acl_enabled": None,
           "datacenter": "", "server": None, "node_name": "", "node_id": "",
           "gossip_encrypted": None, "tls_min_version": "", "raft_protocol": None,
           "kv_secrets": [], "authed": bool(token)}

    r = _http(ip, port, "GET", "/v1/agent/self", timeout=timeout, token=token)
    if r is None:
        return out
    status, body = r
    if status != 200:
        r2 = _http(ip, port, "GET", "/v1/status/leader", timeout=timeout, token=token)
        if r2 is None or r2[0] != 200:
            return out
        out["reachable"] = True
        out["leader"] = r2[1].decode("utf-8", "replace").strip().strip('"')[:80]
        out["acl_enabled"] = True
        return out
    out["reachable"] = True
    _parse_agent_self(body, out)

    r = _http(ip, port, "GET", "/v1/catalog/services", timeout=timeout, token=token)
    if r is not None and r[0] == 200:
        try:
            svcs = json.loads(r[1].decode("utf-8", "replace"))
            if isinstance(svcs, dict):
                out["services"] = sorted(svcs.keys())[:50]
        except (ValueError, UnicodeDecodeError):
            pass

    r = _http(ip, port, "GET", "/v1/catalog/nodes", timeout=timeout, token=token)
    if r is not None and r[0] == 200:
        try:
            nodes = json.loads(r[1].decode("utf-8", "replace"))
            out["nodes"] = len(nodes) if isinstance(nodes, list) else 0
        except (ValueError, UnicodeDecodeError):
            pass

    r = _http(ip, port, "GET", "/v1/kv/?recurse", timeout=timeout, token=token,
              max_bytes=2_000_000)
    if r is not None and r[0] == 200:
        try:
            kv = json.loads(r[1].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            kv = None
        if isinstance(kv, list):
            total, hits = _classify_kv(kv[:_KV_MAX_ENTRIES])
            out["kv_keys"] = len(kv)
            out["kv_secrets"] = hits

    return out


def consul_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_consul(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "consul", "command": cmd, "remediation": rem, "cwes": cwes,
            "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_consul(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            # ACL disabled (or ACL default-allow) with readable services/KV
            # = full cluster state leaked. Emit critical.
            unauth_reads = bool(pr.get("services") or pr.get("nodes") or pr.get("kv_keys"))
            if unauth_reads and not pr.get("acl_enabled"):
                svc_sample = ", ".join(pr.get("services", [])[:8]) or "-"
                out.append(_finding(
                    "critical",
                    "Consul unauthenticated cluster read (ACLs disabled)", tgt,
                    f"Consul {pr.get('version','?')} — ACLs disabled or default-allow. "
                    f"Anonymous reads returned {len(pr.get('services',[]))} service(s), "
                    f"{pr.get('nodes',0)} node(s), and {pr.get('kv_keys',0)} KV key(s). "
                    f"Services: {svc_sample}"
                    + ("… (truncated)" if len(pr.get('services',[])) > 8 else "")
                    + ". KV store may contain credentials, feature flags, service configs.",
                    f"curl http://{h.ip}:{p.portid}/v1/kv/?recurse",
                    "Enable ACLs with default_policy=deny in consul config; issue "
                    "scoped tokens to each service. Bind Consul to a private interface.",
                    ["CWE-306", "CWE-284", "CWE-200"], kind="consul_unauth_read",
                    exploit_note=(
                        "curl -s http://<ip>:8500/v1/kv/?recurse | jq -r '.[] | "
                        "\"\\(.Key)=\\(.Value|@base64d)\"'; curl -s "
                        "http://<ip>:8500/v1/snapshot -o consul.snap — then consul "
                        "snapshot inspect."),
                    depth_tier="t1"))
            else:
                out.append(_finding(
                    "info", "Consul endpoint reachable (ACL enforcing)", tgt,
                    f"Consul {pr.get('version','?')} reachable — reads gated by ACL. "
                    f"Leader: {pr.get('leader','?')}. "
                    "Any looted Consul token would target this endpoint.",
                    f"curl http://{h.ip}:{p.portid}/v1/status/leader",
                    "Ensure ACLs stay enforcing; rotate compromised tokens promptly.",
                    [], kind="consul_authed"))

            hits = pr.get("kv_secrets") or []
            if hits:
                kinds = sorted({k for h_ in hits for k in h_.get("kinds", [])})
                sample = ", ".join(h_["key"] for h_ in hits[:5])
                out.append(_finding(
                    "critical",
                    "Consul KV contains suspected secrets", tgt,
                    f"{len(hits)} KV entr{'y' if len(hits)==1 else 'ies'} matched secret "
                    f"patterns ({', '.join(kinds) or 'key_name'}). "
                    f"Sample keys: {sample}"
                    + (" (more redacted)" if len(hits) > 5 else "") + ".",
                    f"curl -s http://{h.ip}:{p.portid}/v1/kv/?recurse "
                    "| jq -r '.[] | \"\\(.Key) \\(.Value|@base64d)\"'",
                    "Remove secrets from Consul KV; store credentials in Vault or a "
                    "secrets manager and reference them via templates with strict ACLs.",
                    ["CWE-200", "CWE-522"], kind="consul_kv_secrets",
                    exploit_note=(
                        "curl -s http://<ip>:8500/v1/kv/?recurse | jq -r '.[] | "
                        "\"\\(.Key)|\\(.Value|@base64d)\"' | grep -Ei "
                        "'BEGIN.*PRIVATE|postgres://|AKIA|xox[abpr]-' — try each "
                        "against its target service."),
                    depth_tier="t3"))

            if pr.get("gossip_encrypted") is False:
                out.append(_finding(
                    "high",
                    "Consul Serf gossip is unencrypted", tgt,
                    f"Consul {pr.get('version','?')} agent config exposes no gossip "
                    f"encryption key (dc={pr.get('datacenter','?')}). Serf traffic on "
                    "8301/8302 is cleartext, enabling cluster-join spoofing and passive "
                    "membership sniffing.",
                    f"curl -sk http://{h.ip}:{p.portid}/v1/agent/self "
                    "| jq .DebugConfig.EncryptKey",
                    "Set an `encrypt` key in every agent config (consul keygen) and "
                    "enable verify_incoming/outgoing for Serf.",
                    ["CWE-319"], kind="consul_gossip_unencrypted",
                    exploit_note=(
                        "tcpdump -i any -w gossip.pcap 'udp port 8301' — snoop "
                        "membership; or use serf agent -join <ip>:8301 with no key "
                        "to attempt cluster join."),
                    depth_tier="t1"))

            tls_min = (pr.get("tls_min_version") or "").upper()
            if tls_min in ("TLSV10", "TLSV1.0", "TLS10", "TLSV11", "TLSV1.1", "TLS11"):
                out.append(_finding(
                    "medium",
                    "Consul accepts obsolete TLS versions", tgt,
                    f"Consul {pr.get('version','?')} reports TLSMinVersion={tls_min}. "
                    "TLS 1.0/1.1 are deprecated (RFC 8996) and vulnerable to downgrade "
                    "and CBC/RC4-family attacks.",
                    f"curl -sk http://{h.ip}:{p.portid}/v1/agent/self "
                    "| jq .DebugConfig.TLSMinVersion",
                    "Set tls.defaults.tls_min_version = tls12 (or tls13) in consul HCL.",
                    ["CWE-327"], kind="consul_weak_tls"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Cluster fingerprint",
         "cmd": f"curl -sk http{{,s}}://{ip}:{port}/v1/agent/self | jq .Config.Version"},
        {"step": "List services",
         "cmd": f"curl -sk http://{ip}:{port}/v1/catalog/services"},
        {"step": "Dump KV store",
         "cmd": f"curl -sk http://{ip}:{port}/v1/kv/?recurse"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "consul", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = consul_targets(hosts)
    probes: dict = {}
    state: dict = {}
    token = _extract_token(creds)
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"], token=token),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["unauth"] = not pr.get("acl_enabled") and bool(
                    pr.get("services") or pr.get("nodes") or pr.get("kv_keys"))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
