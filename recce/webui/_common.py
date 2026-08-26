"""Proven, model-correct helpers shared by the webui route modules.

Shared helpers for the web workbench route modules. These live in
`recce/webui/` so their `from .. import ...`
imports of top-level recce modules stay TWO dots.
"""
from __future__ import annotations

import asyncio
import os
import re

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _cmd(label, group, targets="optional", profile=False, creds=False, lhost=False,
         flags=()):
    return {"label": label, "group": group, "targets": targets, "profile": profile,
            "creds": creds, "lhost": lhost, "flags": list(flags)}


def _f(name, flag, label, active=False, *, kind="bool", placeholder=""):
    """Catalog entry for a scan-tab flag.

    kind:
      * "bool"  — checkbox (default). Body sends the name in `flags: []`.
      * "text"  — single string. Body sends `flag_values: {name: "value"}`.
      * "int"   — integer. Same wire shape as "text" (validated server-side).
      * "list"  — whitespace/comma-separated tokens. Splits and passes each
                  as its own argv token after the flag (e.g. `--skip a b c`).
    `active` marks intrusive flags in the UI (renders an "active" pill).
    `placeholder` is UI-only hint text for non-bool inputs.
    """
    return {"name": name, "flag": flag, "label": label, "active": active,
            "kind": kind, "placeholder": placeholder}


# The full command surface the workbench can run. Each entry declares what the UI
# should offer (targets requirement, --profile, credential fields, flags, --lhost) and
# the server builds a safe argv from it - no shell, every value a separate argv token.
_COMMANDS: dict = {
    # --- scan phases ---
    # `no-discovery` (-Pn) is the fix for the classic "host is up but doesn't
    # answer ping" case — a firewall drops ICMP + our discovery probes, so we
    # write the host off. With -Pn every target in scope is scanned regardless.
    # Slower on dead ranges (nothing to prune) so it's opt-in.
    "run": _cmd("Run — guided full flow", "Scan", "required", profile=True,
                # `run` IS the full pipeline — --deep is implicit, and the CLI
                # parser doesn't accept a --deep flag on `run` (it's only valid
                # on `scan`). Listing it in the catalog would translate to argv
                # that the parser rejects with "unrecognized arguments: --deep".
                flags=[_f("no-discovery", "--no-discovery", "no ping (-Pn) — assume every target up"),
                       _f("resume", "--resume", "resume — skip hosts already enumerated"),
                       _f("act", "--act", "run the Act phase after — auto-loot + ranked action plan"),
                       _f("exclude", "--exclude", "exclude IPs / CIDRs", kind="list",
                          placeholder="10.0.0.5, 10.0.0.10/32"),
                       _f("workers", "--workers", "worker threads", kind="int",
                          placeholder="8"),
                       _f("skip", "--skip", "skip deep modules", kind="list",
                          placeholder="mssql docker snmp"),
                       _f("only-modules", "--only-modules", "run ONLY these deep modules", kind="list",
                          placeholder="web ldap smb")]),
    "scan": _cmd("Scan — enum + vulns", "Scan", "required", profile=True,
                 flags=[_f("deep", "--deep", "deep — every credential-free deep module"),
                        _f("fast", "--fast", "fast (masscan port sweep)"),
                        _f("no-discovery", "--no-discovery", "no ping (-Pn) — assume every target up"),
                        _f("resume", "--resume", "resume — skip hosts already enumerated"),
                        _f("all-ports", "--all-ports", "all 65535 TCP ports"),
                        _f("exclude", "--exclude", "exclude IPs / CIDRs", kind="list",
                           placeholder="10.0.0.5, 10.0.0.10/32"),
                        _f("workers", "--workers", "worker threads", kind="int", placeholder="8"),
                        _f("skip", "--skip", "with --deep: skip these modules", kind="list",
                           placeholder="mssql docker snmp"),
                        _f("only-modules", "--only-modules", "with --deep: only these modules", kind="list",
                           placeholder="web ldap smb"),
                        _f("host-timeout", "--host-timeout", "per-host timeout (minutes)", kind="int",
                           placeholder="20"),
                        _f("max-retries", "--max-retries", "nmap retry cap", kind="int", placeholder="6")]),
    "enum": _cmd("Enumerate", "Scan", "required", profile=True,
                 flags=[_f("fast", "--fast", "masscan port sweep"),
                        _f("all-ports", "--all-ports", "all 65535 TCP ports"),
                        _f("no-discovery", "--no-discovery", "no ping (-Pn) — assume every target up"),
                        _f("resume", "--resume", "resume — skip hosts already enumerated"),
                        _f("no-os", "--no-os", "skip OS detection"),
                        _f("no-ad", "--no-ad", "skip SMB / LDAP AD scripts"),
                        _f("no-reconfirm", "--no-reconfirm", "skip -Pn re-probe of missed hosts"),
                        _f("exclude", "--exclude", "exclude IPs / CIDRs", kind="list",
                           placeholder="10.0.0.5, 10.0.0.10/32"),
                        _f("workers", "--workers", "worker threads", kind="int", placeholder="8"),
                        _f("host-timeout", "--host-timeout", "per-host timeout (minutes)", kind="int",
                           placeholder="20")]),
    "vulns": _cmd("Vuln scan", "Scan", "optional",
                  flags=[_f("fast", "--fast", "fast"), _f("aggressive", "--aggressive", "aggressive NSE", True),
                         _f("offline", "--offline", "offline")]),
    "sweep": _cmd("Deep sweep — every credential-free module", "Scan", "optional"),
    "credsweep": _cmd("Credentialed sweep", "Scan", "optional", creds=True),
    "db": _cmd("Database scan (NSE inventory)", "Databases", "optional", creds=True,
               flags=[_f("aggressive", "--aggressive", "aggressive (brute/xp_cmdshell)", True)]),
    # --- databases (native deep modules) ---
    # Postgres depth: weak-default sweep (7 well-known creds) runs
    # automatically when auth is required and no creds supplied; --prove
    # actually executes a benign COPY-FROM-PROGRAM 'id' when superuser.
    # Authed loot pulls replication_roles, RCE capability, pivot ext,
    # pg_shadow hashes automatically — no flag needed.
    "postgres": _cmd("PostgreSQL (deep — weak-default + replication + RCE)", "Databases", "optional", creds=True,
                     flags=[_f("prove", "--prove", "prove RCE with benign id (COPY-FROM-PROGRAM; active)", True)]),
    "mysql": _cmd("MySQL / MariaDB", "Databases", "optional", creds=True),
    "mongodb": _cmd("MongoDB", "Databases", "optional", creds=True),
    # MSSQL depth: native TDS-tunneled TLS SQL-Auth probe. C4 weak-default
    # sweep of 7 sa passwords runs when no creds are supplied; credentialed
    # sweep fires xp_cmdshell / CLR / OLE Automation / linked-server walk
    # via nxc.
    "mssql": _cmd("MSSQL (deep — native TDS + C4 weak-sa sweep + xp_cmdshell)", "Databases", "optional", creds=True),
    "redis": _cmd("Redis", "Databases", "optional"),
    "elasticsearch": _cmd("Elasticsearch", "Databases", "optional"),
    "memcached": _cmd("memcached", "Databases", "optional"),
    "couchdb": _cmd("CouchDB", "Databases", "optional"),
    "influxdb": _cmd("InfluxDB", "Databases", "optional"),
    "cassandra": _cmd("Cassandra", "Databases", "optional"),
    "oracle": _cmd("Oracle TNS", "Databases", "optional"),
    "db2": _cmd("IBM Db2", "Databases", "optional"),
    # --- web / web-app ---
    # The web module folds in every C1/C2/Tier-A HTTP addition automatically
    # via probes.http_findings → services/http.py (path enum against 110-
    # path bundled wordlist, framework fingerprint, form + login discovery,
    # default-cred hints for 18 apps, JS-secret scan, backup-file variants,
    # directory-listing detection, methods/CORS/robots-sitemap/OpenAPI/GraphQL/
    # SOAP-WSDL/vhost). No opt-in needed for those. Flags below toggle the
    # heavier / active checks.
    "web": _cmd("Web deep-enum (path enum + forms + JS secrets + CORS + …)", "Web", "optional",
                flags=[_f("crawl", "--crawl", "crawl + inject (deeper than the standard enum)"),
                       _f("autologin", "--autologin", "auto-login w/ looted creds (active)", True),
                       _f("sqli-time", "--sqli-time", "time-based SQLi on discovered params", True),
                       _f("upload-shell", "--upload-shell",
                          "upload benign webshell to prove RCE (active, writes a file)", True),
                       _f("smuggle", "--smuggle",
                          "CL.TE/TE.CL smuggling probe (active, may disturb proxies)", True)]),
    "api": _cmd("API — OpenAPI/Swagger/GraphQL/SOAP-WSDL/gRPC introspection", "Web", "optional"),
    # --- other services ---
    "smb": _cmd("SMB", "Services", "optional", creds=True),
    "ftp": _cmd("FTP", "Services", "optional", creds=True),
    "snmp": _cmd("SNMP", "Services", "optional"),
    "ldap": _cmd("LDAP", "Services", "optional", creds=True),
    "nfs": _cmd("NFS", "Services", "optional"),
    "rsync": _cmd("rsync", "Services", "optional"),
    "kerberos": _cmd("Kerberos (AS-REP roast)", "Services", "optional"),
    "docker": _cmd("Docker API", "Services", "optional"),
    "kubernetes": _cmd("Kubernetes", "Services", "optional"),
    "dns": _cmd("DNS", "Services", "optional"),
    "smtp": _cmd("SMTP", "Services", "optional"),
    # --- T4 scanner-expansion services (from the "everything else" round) ---
    "zookeeper":       _cmd("Zookeeper 4LW", "Services", "optional"),
    "kafka":           _cmd("Kafka MetadataRequest", "Services", "optional"),
    "etcd":            _cmd("etcd (v2 + v3)", "Services", "optional"),
    "consul":          _cmd("Consul", "Services", "optional"),
    "nomad":           _cmd("Nomad", "Services", "optional"),
    "prometheus":      _cmd("Prometheus", "Services", "optional"),
    "docker-registry": _cmd("Docker Registry v2", "Services", "optional"),
    "vnc":             _cmd("VNC", "Services", "optional"),
    "modbus":          _cmd("Modbus/TCP (OT/ICS)", "Services", "optional"),
    "rdp":             _cmd("RDP (NLA detection)", "Services", "optional"),
    "ipmi":            _cmd("IPMI (cipher-zero + null-user)", "Services", "optional"),
    # --- Loot & Attack tier ---
    # Loot scanner mines <engagement>/evidence/** for cred files, Kerberos
    # tickets, .git dumps, and configs with embedded secrets. Idempotent
    # (dedups on rerun). Standalone from the sweep chain too.
    "loot-scan": _cmd("Loot scan — mine evidence/ for creds, tickets, secrets, .git dumps",
                      "Loot", "none",
                      flags=[_f("dry-run", "--dry-run",
                                "preview candidates without persisting to the store")]),
    # C5 active SQLi tester — GATED. Refuses to run unless the tester sets
    # the active_attacks flag. Discovered forms + URL params get error /
    # boolean-blind / time-based checks; optional sqlmap orchestration.
    "sqli": _cmd("Active SQL injection (GATED — active attack tier)",
                 "Attack", "required",
                 flags=[_f("active-attacks", "--active-attacks",
                           "REQUIRED — acknowledge that recce will send injection "
                           "payloads to targets", True),
                        _f("sqlmap", "--sqlmap",
                           "hand off to sqlmap for deeper testing (needs sqlmap installed)", True)]),
    # --- AD / credentialed ---
    # Credentialed enum accepts AD scoping (--dc-ip / --ldap-*) + a separate
    # admin account for admin-only checks (secretsdump). Surfacing them turns
    # the tab into a real AD enumeration surface without any CLI shell-out.
    "credenum": _cmd("Credentialed enum (SMB/AD/SSH)", "Credentialed", "optional", creds=True,
                     flags=[_f("dc-ip", "--dc-ip", "target DC IP for LDAP (else auto-detect)",
                               kind="text", placeholder="10.0.0.1"),
                            _f("ldap-enum", "--ldap-enum", "credentialed LDAP enum of discovered DCs"),
                            _f("ldap-anon", "--ldap-anon", "attempt anonymous LDAP bind"),
                            _f("ldap-ssl", "--ldap-ssl", "use LDAPS (636)"),
                            _f("admin-user", "--admin-user", "admin username for admin-only checks",
                               kind="text", placeholder="administrator"),
                            _f("admin-pass", "--admin-pass", "admin password", kind="text", placeholder="•••"),
                            _f("admin-domain", "--admin-domain", "admin account domain",
                               kind="text", placeholder="CORP.LOCAL")]),
    "deploy": _cmd("Deploy on-target enum", "Credentialed", "optional", creds=True),
    # `ad` (SharpHound / Certipy) is deliberately NOT in the catalog: it takes a
    # file path (nargs='+'), not a target IP, so it doesn't fit the target-based
    # scan-tab shape. The Add → Import flow (ImportModal) already handles it —
    # drag the .zip, recce folds it into the AD graph. Leaving it out avoids a
    # broken UX where filling the "target" field with an IP wouldn't work.
    "verify": _cmd("Verify version leads (dry-run NSE re-check)", "Reporting", "optional",
                   flags=[_f("run", "--run", "actually execute the check (else dry-run)", active=True)]),
    "showmount": _cmd("NFS showmount (exports)", "Services", "optional"),
    # Active external-tool bridges. recce doesn't reimplement these — it drives
    # them and folds their native output back into the engagement. Missing-tool
    # cases are surfaced as friendly info-level findings, not silent failures.
    "nuclei": _cmd("Nuclei (active web vuln scan)", "Web", "optional"),
    "certipy": _cmd("Certipy — AD-CS enumeration (ESC1..ESC15)", "Credentialed", "none", creds=True,
                    flags=[_f("dc-ip", "--dc-ip", "target DC IP (required)", kind="text",
                              placeholder="10.0.0.1")]),
    "privesc": _cmd("Priv-esc playbook", "Exploitation", "optional",
                    flags=[_f("scan", "--scan", "remote NSE checks")]),
    # --- exploitation / reporting ---
    "exploitplan": _cmd("Exploit plan (msf .rc + commands)", "Exploitation", "optional", lhost=True),
    "poc": _cmd("PoC dossiers (per-CVE)", "Exploitation", "optional"),
    "prove": _cmd("Prove findings (verdicts)", "Exploitation", "none"),
    "attackpath": _cmd("Attack path", "Exploitation", "none"),
    "report": _cmd("Rebuild report", "Reporting", "none"),
    "status": _cmd("Status / coverage", "Reporting", "none"),
    "services": _cmd("Per-service commands", "Reporting", "none"),
    "writeups": _cmd("Word write-ups", "Reporting", "optional"),
}
_PHASES = set(_COMMANDS)      # back-compat: any catalog command is a valid phase
# downloadable deliverables: kind -> (paths-key, download filename, media type)
_REPORTS = {
    "xlsx": ("xlsx", "enumeration.xlsx",
             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "html": ("html", "report.html", "text/html"),
    "docx": ("docx", "findings_report.docx",
             "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "md": ("md", "enumeration.md", "text/markdown"),
    "csv": ("csv", "services.csv", "text/csv"),
}


def _tier(v) -> str:
    # qod_of, not v.qod: findings are persisted BEFORE qod.annotate runs (annotation
    # happens in-memory at report time and isn't written back), so v.qod is often 0 in
    # the store. qod_of fail-open-computes the score from the detection method, so a
    # real confirmed service finding isn't mis-tiered as a hidden "lead".
    from .. import qod
    q = qod.qod_of(v)
    return "confirmed" if q >= 95 else "likely" if q >= 70 else "lead"


def _finding_dict(v, reviewed: bool = False, notes: str = "",
                  status: str = "") -> dict:
    from .. import tracking
    # `sources` = distinct detector names that corroborated this finding after
    # dedup. Populated by _apply_dedup below; a singleton just carries [v.source].
    sources = getattr(v, "_sources", None) or ([v.source] if v.source else [])
    return {
        "key": tracking.vuln_row_key(v),      # same key the Excel sheet + coverage use
        "reviewed": reviewed, "notes": notes,
        "status": status or ("reviewed" if reviewed else ""),
        "severity": v.severity or "info",
        "title": v.title or v.script_id or "finding",
        "ip": v.ip, "port": v.port,
        "cve": (v.ids[0] if v.ids else ""), "cves": list(v.ids or []),
        "kev": bool(getattr(v, "kev", False)),
        "epss": round((getattr(v, "epss", 0.0) or 0.0) * 100),
        "tier": _tier(v), "source": v.source, "confidence": v.confidence,
        "sources": sources,
    }


def _apply_dedup(hosts) -> None:
    """Collapse duplicate findings across each host, in-place, and stamp the
    merged Vuln with a `_sources` attribute listing the detectors that
    corroborated it. The dedup engine (intake.dedup) already handles the
    merge — this helper just captures the pre-merge source list so the API
    can surface it to the UI without changing the Vuln model."""
    from ..intake import dedup as _dd
    for h in hosts:
        pre = h.vulns
        # Bucket by identity BEFORE merge so we know who contributed
        groups: dict = {}
        for v in pre:
            k = _dd.identity(v)
            groups.setdefault(k, []).append(v)
        _dd.dedupe_host(h)
        # After dedupe: for each merged Vuln, look up its identity and attach
        # the pre-merge source list. Singletons get their single source.
        for v in h.vulns:
            grp = groups.get(_dd.identity(v), [v])
            v._sources = sorted({g.source for g in grp if g.source})


def _host_key(ip: str) -> str:
    return f"host:{ip}"


def _host_dict(h, reviewed: bool = False, notes: str = "") -> dict:
    sev: dict[str, int] = {}
    for v in h.vulns:
        sev[v.severity] = sev.get(v.severity, 0) + 1
    return {
        "ip": h.ip, "key": _host_key(h.ip), "hostname": h.hostname or "",
        "os": h.os_name or h.os_family or "", "roles": list(h.roles or []),
        "up": h.is_up,
        "ports": [{"port": p.portid, "proto": p.protocol, "service": p.service,
                   "product": (f"{p.product} {p.version}".strip() or p.service)}
                  for p in h.open_ports],
        "findings": sev,
        # completion signals (what's been looked at) - drive the Targets tracker
        "enumerated": bool(getattr(h, "enumerated", False)),
        "vuln_scanned": any(getattr(p, "vuln_scanned", False) for p in h.ports) or bool(h.vulns),
        "access": bool(getattr(h, "access_gained", False)),
        "db": bool(getattr(h, "db_scanned", False)),
        "privesc": bool(getattr(h, "privesc_checked", False)),
        "credenum": bool(getattr(h, "cred_enumerated", False)),
        "reviewed": reviewed, "notes": notes,
    }


class _Broker:
    """A tiny in-memory pub/sub so every connected browser sees the others' changes
    (a tick, a finished scan) live. Thread-safe publish - the job threads use it too."""

    def __init__(self) -> None:
        self._subs: set = set()
        self._loop = None

    def bind(self, loop) -> None:
        self._loop = loop

    _MAX_SUBS = 128        # bound held-open SSE streams so publish() fan-out can't be abused

    _MAX_QUEUE = 1024

    async def subscribe(self):
        if len(self._subs) >= self._MAX_SUBS:
            return                                # refuse past the cap; stream closes at once
        q: asyncio.Queue = asyncio.Queue(maxsize=self._MAX_QUEUE)
        self._subs.add(q)
        try:
            while True:
                yield await q.get()
        finally:
            self._subs.discard(q)

    def publish(self, event: dict) -> None:
        if self._loop is None:
            return

        def _emit():
            for q in list(self._subs):
                if q.full():
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(event)

        self._loop.call_soon_threadsafe(_emit)


_IMPORT_TOOLS = ("nmap", "nxc", "kerberoast", "asrep", "secretsdump", "loot")


def _import_signatures(content: str, filename: str = "") -> list[str]:
    """Every import format whose signature is present in `content`, most-specific first.
    Returns a list so the endpoint can spot a concatenated multi-tool paste (>1 kind)."""
    from ..importers import detect_scanner
    content = content.lstrip("﻿")
    low = content.lower()
    fn = filename.lower()
    kinds: list[str] = []
    sc = detect_scanner(content)                                       # nessus/openvas/nuclei/testssl
    if sc:
        kinds.append(sc)
    if "<nmaprun" in content[:4000] or "nmap scan report for" in low \
            or re.search(r"^Host:\s+\S+.*\bPorts:", content, re.M) \
            or re.search(r"^(open|closed)\s+(tcp|udp)\s+\d+\s+[0-9a-fA-F:.]+", content, re.M) \
            or (content.lstrip()[:1] == "[" and '"ports"' in content and '"status"' in content):
        kinds.append("nmap")                                          # nmap XML/-oG/-oN + masscan -oL/-oJ
    if "$krb5tgs$" in content:
        kinds.append("kerberoast")
    if "$krb5asrep$" in content:
        kinds.append("asrep")
    if re.search(r"^[^:\s]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::", content, re.I | re.M):
        kinds.append("secretsdump")                                    # user:rid:lm:nt:::
    if re.search(r"^\s*(SMB|LDAP|MSSQL|WINRM|SSH|RDP|FTP|WMI|NFS)\s+\S+\s+\d+\s+\S+\s",
                 content, re.M):
        kinds.append("nxc")                                            # netexec/cme, any protocol
    if ("recce-enum" in low or "recce-service" in low or "net-iface" in low
            or re.search(r"^===[A-Z]", content, re.M)):
        kinds.append("loot")                                           # on-target sweep
    if not kinds and fn.endswith((".gnmap", ".nmap")):                 # extension is the last hint
        kinds.append("nmap")
    # IP1: filename hints for scanners whose export shape overlaps with
    # generic JSON/XML. These only fire when nothing more specific matched.
    if not kinds:
        if "burp" in fn:
            kinds.append("burp")
        elif "zap" in fn or "owasp-zap" in fn:
            kinds.append("zap")
        elif "nikto" in fn:
            kinds.append("nikto")
        elif "wpscan" in fn:
            kinds.append("wpscan")
        elif "sslyze" in fn:
            kinds.append("sslyze")
        elif "enum4linux" in fn or "e4l" in fn:
            kinds.append("enum4linux")
        elif "kerbrute" in fn:
            kinds.append("kerbrute")
        elif "getadusers" in fn:
            kinds.append("impacket-adusers")
        elif "finddelegation" in fn or "delegation" in fn:
            kinds.append("impacket-delegation")
        elif "whatweb" in fn:
            kinds.append("whatweb")
        elif "wafw00f" in fn or "waf00f" in fn:
            kinds.append("wafw00f")
        elif "ffuf" in fn:
            kinds.append("ffuf")
        elif "gobuster" in fn:
            kinds.append("gobuster")
        elif "trivy" in fn:
            kinds.append("trivy")
        elif "grype" in fn:
            kinds.append("grype")
    # Phase 2 — user-declared parsers (JSON in ~/.recce/parsers/). Consulted
    # AFTER built-ins so a user parser only fires when nothing built-in
    # matched. Passes the filename explicitly so filename_glob rules work
    # even when the paste body wouldn't match a content_re.
    if not kinds:
        try:
            from ..intake.parsers_user import detect_user_parser
            hit = detect_user_parser(content, filename)
            if hit:
                kinds.append(hit)
        except ImportError:
            pass
    return kinds


def _detect_import_kind(content: str, filename: str = "") -> str:
    """The single best-guess kind (or 'generic'). 'multiple' means a concatenated paste of
    more than one tool's output — the endpoint asks the user to import them separately.

    Falls back to 'generic' (universal loose parser) when no specific format
    matched — so ad-hoc / custom-script / drifting-tool output still lands
    somewhere the tester can triage, rather than being rejected as unknown.
    """
    kinds = _import_signatures(content, filename)
    if not kinds:
        # Only fall back if the input has ANYTHING worth extracting — an empty
        # paste or a screenshot upload shouldn't emit a phantom "0 findings" row.
        stripped = content.strip() if isinstance(content, str) else ""
        return "generic" if stripped else "unknown"
    if len(set(kinds)) > 1:
        return "multiple"
    return kinds[0]


def _import_preview(kind: str, content: str, raw_bytes: bytes) -> dict:
    """Dry-run: parse `content` WITHOUT committing, so the user sees what an import would
    fold into the shared engagement (and a 0-row warning if the format looks wrong)."""
    from .. import importers
    n = 0
    detail = ""
    sample: list[str] = []
    try:
        # Any kind that's actually registered in SCANNER_PARSERS gets the
        # generic preview shape. Covers built-ins + user parsers (Phase 2)
        # so a new declarative parser previews correctly without a
        # pyproject / route edit.
        if kind in importers.SCANNER_PARSERS:
            vs = importers.SCANNER_PARSERS[kind](content)
            n = len(vs)
            detail = f"{n} finding(s) across {len({v.ip for v in vs})} host(s)"
            sample = [f"{v.severity}: {v.title} @ {v.ip}" for v in vs[:6]]
        elif kind == "nxc":
            lines = importers.strip_ansi(content).splitlines()
            n = sum(1 for ln in lines if re.search(r"\[\+\]", ln))
            detail = f"~{n} validated login line(s)"
        elif kind == "secretsdump":
            from .. import credenum as ce
            rows = ce.parse_secretsdump(content)
            live = [r for r in rows if not r.get("history")]
            n = len(live)
            detail = f"{len(live)} credential(s), {len(rows) - len(live)} history skipped"
            sample = [f"{r['name']} ({r.get('kind')})" for r in live[:6]]
        elif kind in ("kerberoast", "asrep"):
            from .. import credenum as ce
            fn = ce.parse_getuserspns if kind == "kerberoast" else ce.parse_getnpusers
            rows = [r for r in fn(content) if r.get("hash")]
            n = len(rows)
            detail = f"{n} roastable hash(es)"
            sample = [r["name"] for r in rows[:6]]
        elif kind == "creds":
            n = sum(1 for ln in content.splitlines()
                    if ":" in ln and not ln.strip().startswith("#") and ln.strip())
            detail = f"~{n} credential line(s)"
        elif kind == "nmap":
            import tempfile
            from ..parser import parse_nmap_file
            suffix = ".xml" if ("<nmaprun" in content[:4000]
                                or content.lstrip().startswith("<?xml")) else ".gnmap.txt"
            fd, tmp = tempfile.mkstemp(suffix=suffix)
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(content)
                hs = parse_nmap_file(tmp)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
            n = sum(len(h.open_ports) for h in hs)
            detail = f"{len(hs)} host(s), {n} open port(s)"
            sample = [f"{h.ip}: {len(h.open_ports)} port(s)" for h in hs[:6]]
        elif kind == "bloodhound":
            detail = f"SharpHound/Certipy file ({len(raw_bytes)} bytes) — runs the `ad` engine"
            n = 1
        elif kind in ("loot", "fieldkit"):
            detail = f"{kind} file ({len(content.splitlines())} line(s))"
            n = 1
    except Exception:  # noqa: BLE001 — a preview must never 500
        import logging
        logging.getLogger("recce.webui").debug("import preview failed for kind=%s", kind, exc_info=True)
    if n or kind in ("loot", "fieldkit", "bloodhound"):
        warning = ""
    elif kind == "generic":
        warning = ("The universal loose parser found no CVE / IP / severity / "
                   "credential patterns to extract. If this file has content worth "
                   "keeping, attach it as raw evidence to a host instead.")
    else:
        warning = (f"parsed 0 rows — this may not be {kind} output, or it's a variant recce "
                   "can't read yet. Check the tool/format before importing.")
    return {"mode": "preview", "kind": kind, "count": n, "detail": detail,
            "sample": sample, "warning": warning}
