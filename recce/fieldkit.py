"""fieldkit bridge — round-trip recce <-> fieldkit.

Two directions, both stdlib-only so this stays airgap-safe like the rest of recce:

  recce -> fieldkit  (seed exploitation from enumeration)
    `fieldkit_export` writes a small handoff folder the fieldkit kit consumes:
      * ports.gnmap      - synthesized nmap-greppable; drops straight into
                           `sweep.py triage --nmap ports.gnmap` with no fieldkit change.
      * smb-null.txt     - netexec-style lines for hosts where recce saw a null
                           session / anonymous SMB (fieldkit's `triage --nxc` bumps them).
      * recce-bridge.json- the RICH feed: per-host ports+service+version, recce's
                           CONFIRMED findings, and the exact fieldkit generator to run,
                           read by `sweep.py triage --recce`.
      * FIELDKIT.md         - a human, severity-ranked "run THIS on THAT host, because ..."
                           plan an operator can work top-down.

  fieldkit -> recce  (fold proven exploitation back into the workbook + report)
    `findings_to_vulns` parses a fieldkit findings.json (raw, or the enriched
    `recce_findings.json` that `gen_report.py --export-recce` emits) into recce
    `Vuln`s (source="fieldkit", confidence="confirmed") so every proven finding lands
    in the Vulnerabilities sheet, the HTML/Markdown report and the DOCX write-ups.

Nothing here scans, connects, or executes; it only transforms data recce already
holds and text a fieldkit operator brings back.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from .models import Host, Port, Vuln

BRIDGE_VERSION = 1

# --------------------------------------------------------------------------------------
# Port -> fieldkit generator map. Mirrors access/network/sweep.py's WINS table so recce's
# suggestions match what fieldkit's own triage would pick; kept here (not imported) so recce
# stays standalone and airgap-safe. (label, "note + generator to run", juiciness 0=best).
# --------------------------------------------------------------------------------------
WINS: dict[int, tuple[str, str, int]] = {
    2375: ("docker-api", "UNAUTH -> root on host: services/gen_container.py docker", 0),
    2376: ("docker-tls", "Docker API (TLS): services/gen_container.py docker", 1),
    6379: ("redis", "often UNAUTH -> RCE: services/gen_db.py --db redis", 0),
    27017: ("mongodb", "often UNAUTH -> data/creds: services/gen_db.py --db mongo", 1),
    9200: ("elastic", "UNAUTH REST -> data (+old RCE): services/gen_db.py --db elastic", 1),
    5984: ("couchdb", "UNAUTH -> add-admin+RCE: services/gen_db.py --db couchdb", 1),
    11211: ("memcached", "UNAUTH -> sessions/creds: services/gen_db.py --db memcached", 2),
    445: ("smb", "null-session/relay/EternalBlue: services/gen_smb + access/gen_relay", 1),
    2049: ("nfs", "exports -> loot/keys: services/gen_nfs.py", 1),
    21: ("ftp", "anon login? services/gen_ftp.py anon", 2),
    161: ("snmp", "community strings: services/gen_snmp.py (UDP - nmap -sU)", 2),
    873: ("rsync", "anon modules: services/gen_remote.py rsync", 2),
    5900: ("vnc", "no-auth/weak: services/gen_remote.py vnc", 2),
    23: ("telnet", "default creds: services/gen_remote.py telnet", 3),
    8080: ("http-alt", "Tomcat/JBoss mgr / web: services/gen_container.py tomcat / web/", 1),
    80: ("http", "web app -> access/web/ (nuclei/ffuf first)", 2),
    443: ("https", "web app -> access/web/", 2),
    8443: ("https-alt", "web app -> access/web/", 2),
    3389: ("rdp", "spray CAREFULLY (lockout): access/gen_spray.py --proto rdp", 3),
    5985: ("winrm", "cred -> shell: access/gen_shell.py --proto winrm", 3),
    5986: ("winrm-tls", "cred -> shell: access/gen_shell.py --proto winrm", 3),
    1433: ("mssql", "SQLi/spray -> xp_cmdshell: access/gen_shell --proto mssql", 2),
    3306: ("mysql", "spray -> UDF/OUTFILE: services/gen_db.py --db mysql", 2),
    5432: ("postgres", "COPY...PROGRAM RCE: services/gen_db.py --db postgres", 2),
    1521: ("oracle", "SID/creds (ODAT): services/gen_db.py --db oracle", 2),
    389: ("ldap", "anon bind? domain enum: access/enum_net --ad", 2),
    88: ("kerberos", "AS-REP roast / kerbrute: access/gen_spray --proto kerberos", 2),
    25: ("smtp", "user-enum/relay: services/gen_remote.py smtp", 3),
}


def fieldkit_module_for_port(port: int) -> tuple[str, str, int] | None:
    """(label, note+generator, juiciness) for a port, or None if recce has no fieldkit route."""
    return WINS.get(port)


# --------------------------------------------------------------------------------------
# recce -> fieldkit : synthesize the handoff artifacts from the host model.
# --------------------------------------------------------------------------------------


def _gnmap_service_field(p: Port) -> str:
    """The `<port>/open/<proto>//<service>/<extra>/` cell nmap greppable uses."""
    svc = (p.service or "").replace("/", "_")
    ver = " ".join(x for x in (p.product, p.version) if x).replace("/", "_")
    return f"{p.portid}/open/{p.protocol or 'tcp'}//{svc}//{ver}/"


def build_gnmap(hosts: list[Host]) -> str:
    """Synthesize an nmap-greppable (`-oG`) scan from recce's host/port model.

    fieldkit's `sweep.py triage --nmap` only needs `Host: <ip> (<name>)  Ports: <p>/open/...`
    lines, so this is a lossless-enough handoff that needs no change on the fieldkit side.
    """
    out: list[str] = ["# recce -> fieldkit handoff (synthesized nmap-greppable). "
                      "Feed: sweep.py triage --nmap ports.gnmap"]
    for h in hosts:
        openp = h.open_ports
        if not openp:
            continue
        name = h.hostname or ""
        ports = ", ".join(_gnmap_service_field(p) for p in openp)
        out.append(f"Host: {h.ip} ({name})\tPorts: {ports}\tIgnored State: closed")
    return "\n".join(out) + "\n"


# recce vuln signals that mean SMB is reachable without creds, so fieldkit should treat
# the host as a null-session / relay candidate. Matched on the SMB null/anon/guest
# wording recce writes (`recce smb` and the credsweep null/guest path) rather than on a
# fixed port, so a finding recorded with port 139/None (or by a different module) still
# counts.
_NULL_TOKENS = ("null", "anonymous", "guest")


def _has_null_smb(h: Host) -> bool:
    for v in h.vulns:
        title = (v.title or "").lower()
        sid = (v.script_id or "").lower()
        smb_ctx = ("smb" in title or "smb" in sid or v.port in (445, 139))
        if smb_ctx and ("session" in title or "share" in title) \
                and any(n in title for n in _NULL_TOKENS):
            return True
    for a in h.accounts:
        if a.kind == "share" and str(a.attrs.get("access", "")).lower() in (
                "read", "read,write", "write", "read/write"):
            return True
    return False


def build_smb_null(hosts: list[Host]) -> str:
    """netexec-style lines for hosts recce saw a null/anonymous SMB session on.

    Matches the loose shape `sweep.py triage --nxc` scrapes (an IP on a line mentioning
    READ/WRITE or 'Enumerated shares'), so those hosts float to the top of fieldkit's board.
    """
    lines: list[str] = ["# recce -> fieldkit: hosts with a null/anonymous SMB session "
                        "(feed: sweep.py triage --nxc smb-null.txt)"]
    any_hit = False
    for h in hosts:
        if _has_null_smb(h):
            any_hit = True
            name = h.hostname or ""
            lines.append(f"SMB   {h.ip}   445   {name}   [+] Enumerated shares "
                         "(null session) READ")
    if not any_hit:
        lines.append("# (recce recorded no null/anonymous SMB sessions in this engagement)")
    return "\n".join(lines) + "\n"


def _confirmed(v: Vuln) -> bool:
    return (v.confidence or "").lower() != "potential"


def _suggest_for_host(h: Host) -> list[dict[str, Any]]:
    """Per-open-port fieldkit routes for a host, best-first (deduped by generator note)."""
    routes: list[dict[str, Any]] = []
    seen: set[str] = set()
    scored = []
    for p in h.open_ports:
        w = fieldkit_module_for_port(p.portid)
        if w:
            scored.append((w[2], p, w))
    for _j, p, (label, note, juic) in sorted(scored, key=lambda t: t[0]):
        if note in seen:
            continue
        seen.add(note)
        routes.append({"port": p.portid, "service": p.service or label, "label": label,
                       "module": note, "juiciness": juic})
    return routes


# Open-port -> the fieldkit credential->shell proto (gen_shell.py --proto). Best-first.
_SHELL_PROTO = [
    (5985, "winrm"), (5986, "winrm"), (1433, "mssql"), (445, "smb"),
    (22, "ssh"), (3389, "rdp"),
]


# Generic vendor/OS/filler words that make a useless `gen_exploit.py find --service`
# search (Windows CVEs come through the confirmed-findings channel instead).
_GENERIC_SVC = {"microsoft", "windows", "ms", "the", "server", "service",
                "services", "linux", "unix", "generic", "unknown", "httpd"}


def _clean_service(product: str, service: str) -> str:
    """The most specific lowercase product token for `gen_exploit.py find --service`
    (e.g. 'Apache httpd' -> 'apache', 'Microsoft Exchange' -> 'exchange'), skipping
    generic vendor/OS words. Falls back to the nmap service name; '' if nothing useful."""
    for tok in re.split(r"[\s/]+", product or ""):
        t = re.sub(r"[^a-z0-9.]", "", tok.lower())
        if t and not t[0].isdigit() and t not in _GENERIC_SVC:
            return t
    svc = (service or "").lower()
    return svc if svc not in _GENERIC_SVC else ""


def _version_like(ver: str) -> bool:
    """True when `ver` looks like a real version (has a digit) rather than a banner
    fragment such as an LDAP 'Domain: corp.local' string."""
    return bool(ver) and any(c.isdigit() for c in ver)


def _exploit_cmds(h: Host) -> list[dict[str, Any]]:
    """Ready `gen_exploit.py find` lines for each distinct product+version recce saw.

    gen_exploit's `find` mode does the CVE lookup itself, so passing recce's exact
    service+version is always valid and never drifts. CVEs recce already confirmed on
    the port are attached so the operator can jump straight to the matching entry.
    """
    cves_by_port: dict[int, list[str]] = {}
    for v in h.vulns:
        if _confirmed(v) and v.port:
            for c in v.ids:
                if c.upper().startswith("CVE") and c not in cves_by_port.setdefault(v.port, []):
                    cves_by_port[v.port].append(c)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for p in h.open_ports:
        # Version-search is only useful with a real version (Windows/MS CVEs already
        # surface through the confirmed-findings channel, not searchsploit-by-version).
        if not _version_like(p.version):
            continue
        svc = _clean_service(p.product, p.service)
        if not svc:
            continue
        key = (svc, p.version)
        if key in seen:
            continue
        seen.add(key)
        cmd = (f'python3 access/network/gen_exploit.py find --service {svc} '
               f'--version "{p.version}"')
        out.append({"port": p.portid, "service": svc, "version": p.version,
                    "cmd": cmd, "cves": cves_by_port.get(p.portid, [])})
    return out


def _cred_applies(cred, h: Host, protos: set[str]) -> bool:
    """Is this credential worth trying against host h? Domain creds are network-wide
    (any Windows/AD shell proto); local creds go to the host they were captured on;
    ssh keys go to hosts with ssh open."""
    if cred.domain and protos & {"smb", "winrm", "mssql", "rdp"}:
        return True
    if cred.origin_ip and cred.origin_ip == h.ip:
        return True
    if cred.kind == "ssh-key" and "ssh" in protos:
        return True
    return False


def _shell_cmd_for(cred, ip: str, proto: str) -> str:
    """One `gen_shell.py` invocation for a credential against ip over proto."""
    parts = [f"python3 access/network/gen_shell.py --target {ip}",
             f"--user {cred.username or '<user>'}"]
    if cred.kind == "nthash":
        parts.append(f"--hash {cred.secret}")
    elif cred.kind == "ssh-key":
        parts.append(f"--pass '<key:{cred.secret}>'")
    else:
        parts.append(f"--pass '{cred.secret}'" if cred.secret else "--pass ''")
    if cred.domain:
        parts.append(f"--domain {cred.domain}")
    parts.append(f"--proto {proto}")
    return " ".join(parts)


def _access_cmds(h: Host, creds: list) -> list[str]:
    """Per-host credential->shell / spray lines. A `gen_shell.py` per applicable known
    credential (capped), plus one `gen_spray.py` against the best shell proto using the
    exported users.txt (spray is useful even before any credential is recovered)."""
    open_ids = {p.portid for p in h.open_ports}
    protos = []
    for pid, proto in _SHELL_PROTO:
        if pid in open_ids and proto not in protos:
            protos.append(proto)
    if not protos:
        return []
    best = protos[0]
    proto_set = set(protos)
    cmds: list[str] = []
    used = set()
    for c in creds:
        if not _cred_applies(c, h, proto_set):
            continue
        key = (c.username.lower(), c.domain.lower(), c.kind)
        if key in used:
            continue
        used.add(key)
        cmds.append(_shell_cmd_for(c, h.ip, best))
        if len(cmds) >= 3:                    # keep the plan readable
            break
    cmds.append(f"python3 access/network/gen_spray.py --proto {best} "
                f"--users users.txt --password '<password>' --target {h.ip}")
    return cmds


def collect_users(hosts: list[Host], creds: list) -> list[str]:
    """Distinct real usernames recce enumerated (host accounts + captured creds), for
    `gen_spray.py --users`. Drops machine accounts ('...$') and blanks."""
    seen: dict[str, str] = {}
    def add(name: str):
        n = (name or "").strip()
        if n and not n.endswith("$") and n.lower() not in seen:
            seen[n.lower()] = n
    for h in hosts:
        for a in h.accounts:
            if a.kind == "user":
                add(a.name)
    for c in creds:
        add(c.username)
    return [seen[k] for k in sorted(seen)]


def collect_creds(creds: list) -> list[str]:
    """Known credentials as impacket/nxc-friendly lines for reference by gen_shell.py."""
    out = []
    for c in creds:
        who = (f"{c.domain}/" if c.domain else "") + (c.username or "")
        if c.kind == "nthash":
            out.append(f"{who}   hash:{c.secret}   (source: {c.source})")
        elif c.kind == "ssh-key":
            out.append(f"{who}   ssh-key:{c.secret}   (source: {c.source})")
        elif c.kind == "blank":
            out.append(f"{who}   (blank password)   (source: {c.source})")
        else:
            out.append(f"{who}:{c.secret}   (source: {c.source})")
    return out


def _host_findings(h: Host) -> list[dict[str, Any]]:
    """recce's CONFIRMED vulns for the bridge, worst-first, with CVE/CWE.

    Deduped by title (the same weakness confirmed on several ports collapses to one
    entry) so the scoreboard/plan stay readable; ports and CVEs are unioned.
    """
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    by_title: dict[str, dict[str, Any]] = {}
    for v in h.vulns:
        if not _confirmed(v):
            continue
        sev = (v.severity or "info").lower()
        cves = [x for x in v.ids if x.upper().startswith("CVE")]
        e = by_title.get(v.title)
        if e is None:
            by_title[v.title] = {
                "title": v.title, "severity": sev,
                "confidence": v.confidence or "confirmed",
                "ports": [v.port] if v.port else [],
                "cves": list(cves), "cwes": list(v.cwes), "source": v.source,
            }
        else:
            if order.get(sev, 5) < order.get(e["severity"], 5):
                e["severity"] = sev
            if v.port and v.port not in e["ports"]:
                e["ports"].append(v.port)
            for c in cves:
                if c not in e["cves"]:
                    e["cves"].append(c)
            for c in v.cwes:
                if c not in e["cwes"]:
                    e["cwes"].append(c)
    return sorted(by_title.values(), key=lambda f: order.get(f["severity"], 5))


def build_bridge(hosts: list[Host], engagement: str = "Recce Engagement",
                 generated: str = "", creds: list | None = None) -> dict[str, Any]:
    """The rich recce -> fieldkit feed consumed by `sweep.py triage --recce`."""
    creds = creds or []
    entries = []
    for h in hosts:
        if not h.is_up:
            continue
        entries.append({
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os_guess,
            "roles": list(h.roles),
            "smb_signing": h.smb_signing,
            "null_smb": _has_null_smb(h),
            "access_gained": h.access_gained,
            "access_detail": h.access_detail,
            "ports": [{"port": p.portid, "service": p.service,
                       "product": p.product, "version": p.version}
                      for p in h.open_ports],
            "findings": _host_findings(h),
            "suggested": _suggest_for_host(h),
            "exploit_cmds": _exploit_cmds(h),
            "access_cmds": _access_cmds(h, creds),
        })
    return {
        "_recce_bridge": BRIDGE_VERSION,
        "engagement": engagement,
        "generated": generated,
        "users": collect_users(hosts, creds),
        "creds_count": len(creds),
        "hosts": entries,
    }


def _host_priority(entry: dict[str, Any]) -> tuple[int, int]:
    """Sort key for the plan: (best juiciness, -confirmed-finding severity). Lower first."""
    juic = min((r["juiciness"] for r in entry["suggested"]), default=9)
    if entry.get("null_smb"):
        juic -= 1
    sevw = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    best_find = min((sevw.get(f["severity"], 5) for f in entry["findings"]), default=9)
    if best_find <= 1:            # a confirmed critical/high floats a host to the top
        juic -= 2
    return (juic, best_find)


def build_plan_md(bridge: dict[str, Any]) -> str:
    """Human, severity-ranked 'run X on host Y, because ...' plan from the bridge."""
    hosts = sorted(bridge.get("hosts", []), key=_host_priority)
    actionable = [h for h in hosts
                  if h["suggested"] or h["findings"] or h.get("exploit_cmds")]
    L: list[str] = []
    L.append(f"# fieldkit attack plan — from recce engagement '{bridge.get('engagement','')}'")
    L.append("")
    L.append(f"Generated by `recce fieldkit-export`{(' · ' + bridge['generated']) if bridge.get('generated') else ''}. "
             f"{len(actionable)} of {len(hosts)} live host(s) have a fieldkit route. Work top-down "
             "(0 = exposed-RCE/unauth quick-win). **Authorized scope only.**")
    L.append("")
    L.append("Feed the machine-readable version straight into fieldkit's mass triage:")
    L.append("")
    L.append("```bash")
    L.append("python3 access/network/sweep.py triage --recce recce-bridge.json")
    L.append("#   (or classic nmap path:  sweep.py triage --nmap ports.gnmap --nxc smb-null.txt)")
    L.append("```")
    L.append("")
    users = bridge.get("users") or []
    if users or bridge.get("creds_count"):
        L.append(f"Spray/auth material also exported: **users.txt** ({len(users)} user(s)) "
                 f"and **creds.txt** ({bridge.get('creds_count', 0)} known credential(s)) — "
                 "referenced by the `gen_spray.py --users` / `gen_shell.py` lines below.")
        L.append("")
    for h in actionable:
        tag = " [NULL-SESSION]" if h.get("null_smb") else ""
        tag += " [ACCESS]" if h.get("access_gained") else ""
        title = f"{h['ip']}" + (f" ({h['hostname']})" if h["hostname"] else "")
        L.append(f"## {title}{tag}")
        meta = []
        if h.get("os"):
            meta.append(h["os"])
        if h.get("roles"):
            meta.append("roles: " + ", ".join(h["roles"]))
        if h.get("smb_signing"):
            meta.append(f"SMB signing: {h['smb_signing']}")
        if meta:
            L.append("*" + " · ".join(meta) + "*")
            L.append("")
        if h["findings"]:
            L.append("**recce confirmed:**")
            for f in h["findings"]:
                cves = (" — " + ", ".join(f["cves"])) if f["cves"] else ""
                L.append(f"- `{f['severity'].upper()}` {f['title']}{cves}")
            L.append("")
        if h["suggested"]:
            L.append("**Run on this host (best-first):**")
            for r in h["suggested"]:
                L.append(f"- `{r['port']}` {r['label']} → {r['module']}")
            L.append("")
        if h.get("exploit_cmds"):
            L.append("**Version→CVE (recce knows the exact version):**")
            for e in h["exploit_cmds"]:
                cve = (" _(recce confirmed " + ", ".join(e["cves"]) + ")_") if e.get("cves") else ""
                L.append(f"- `{e['cmd']}`{cve}")
            L.append("")
        if h.get("access_cmds"):
            L.append("**Credential → shell / spray:**")
            for c in h["access_cmds"]:
                L.append(f"- `{c}`")
            L.append("")
        if h.get("access_detail"):
            L.append(f"> Foothold already recorded by recce: {h['access_detail']}")
            L.append("")
    if not actionable:
        L.append("_(No host exposed a service recce maps to a fieldkit generator. "
                 "Run `recce vulns`/`sweep` for deeper coverage.)_")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------------------
# fieldkit -> recce : fold a fieldkit findings.json back into recce Vulns.
# --------------------------------------------------------------------------------------

_SEV_MAP = {  # fieldkit capitalizes; recce stores lowercase
    "critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info",
}
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def parse_affected_host(s: str) -> tuple[str, str]:
    """Split fieldkit's `affected_host` ('10.0.0.5 (WIN-SQL01)') into (ip, hostname).

    Returns ('', hostname-or-raw) when no IP is present, so a hostname-only finding
    still folds onto a synthesized `fieldkit:<name>` host rather than being dropped.
    """
    s = (s or "").strip()
    ip = ""
    m = _IPV4.search(s)
    if m:
        try:
            ipaddress.ip_address(m.group(1))
            ip = m.group(1)
        except ValueError:
            ip = ""
    name = ""
    pm = re.search(r"\(([^)]*)\)", s)
    if pm:
        name = pm.group(1).split(",")[0].strip()
    elif not ip:
        name = s
    return ip, name


def _proof_blob(f: dict[str, Any]) -> str:
    """Render a finding's evidence + PoC steps into the Vuln.output text kept in recce."""
    parts: list[str] = []
    if f.get("evidence"):
        parts.append(str(f["evidence"]).strip())
    steps = f.get("steps", []) or []
    if steps:
        parts.append("Proof of concept:")
        for s in steps:
            if isinstance(s, str):
                parts.append(f"  $ {s}")
                continue
            cmd = str(s.get("cmd", "")).rstrip()
            outp = str(s.get("output", "")).rstrip()
            if cmd:
                parts.append(f"  $ {cmd}")
            if outp:
                parts.append("    " + outp.replace("\n", "\n    "))
    if f.get("evidence_source"):
        parts.append(f"[evidence: {f['evidence_source']}]")
    return "\n".join(parts).strip()


def finding_to_vuln(f: dict[str, Any]) -> tuple[str, str, Vuln] | None:
    """Map one fieldkit finding -> (ip, hostname, Vuln). None if it has no host at all.

    Uses the enriched `_recce` block (from `gen_report.py --export-recce`) when present
    for accurate severity/CWE/remediation without needing fieldkit's KB here; otherwise
    degrades gracefully to the finding's own fields.
    """
    kb = f.get("_recce") or {}
    ip = kb.get("ip") or ""
    hostname = kb.get("hostname") or ""
    if not ip and not hostname:
        ip, hostname = parse_affected_host(f.get("affected_host", ""))
    if not ip and not hostname:
        return None
    vt = f.get("vector_type") or "finding"
    title = f.get("title") or kb.get("name") or vt
    sev = (f.get("severity") or kb.get("severity") or "medium").lower()
    sev = _SEV_MAP.get(sev, "medium")
    cwes = list(kb.get("cwes") or ([kb["cwe"]] if kb.get("cwe") else []))
    ids = list(kb.get("ids") or [])
    refs = f.get("references")
    if refs:
        ids += [r.strip() for r in re.split(r"[,\s]+", str(refs)) if r.strip()]
    ids = list(dict.fromkeys(ids))                       # dedupe, keep order
    port = kb.get("port")
    remediation = kb.get("remediation") or ""
    output = _proof_blob(f)
    v = Vuln(
        ip=ip or f"fieldkit:{hostname}", port=port, protocol="tcp",
        script_id=f"fieldkit:{vt}", state="finding", title=title,
        severity=sev, source="fieldkit", confidence="confirmed",
        ids=ids, cwes=cwes, remediation=remediation, output=output,
    )
    return ip, hostname, v


def findings_to_hosts(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Group a fieldkit findings.json into {ip: {hostname, vulns[], access_detail}}.

    Accepts both a raw findings.json and the enriched recce_findings.json. Skips the
    advisory `_valid_vector_types` array and any entry with no resolvable host.
    """
    out: dict[str, dict[str, Any]] = {}
    for f in data.get("findings", []):
        if not isinstance(f, dict):
            continue
        res = finding_to_vuln(f)
        if res is None:
            continue
        ip, hostname, v = res
        key = v.ip                                        # real IP, or 'fieldkit:<name>'
        bucket = out.setdefault(key, {"ip": ip, "hostname": hostname,
                                      "vulns": [], "titles": set()})
        if not bucket["hostname"] and hostname:
            bucket["hostname"] = hostname
        if v.title not in bucket["titles"]:               # dedupe by title per host
            bucket["titles"].add(v.title)
            bucket["vulns"].append(v)
    return out
