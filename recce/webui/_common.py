"""Proven, model-correct helpers shared by the webui route modules.

Moved VERBATIM from app_legacy.py (the known-good reference). These live in
`recce/webui/` — the same depth as app_legacy — so their `from .. import ...`
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


def _f(name, flag, label, active=False):
    return {"name": name, "flag": flag, "label": label, "active": active}


# The full command surface the workbench can run. Each entry declares what the UI
# should offer (targets requirement, --profile, credential fields, flags, --lhost) and
# the server builds a safe argv from it - no shell, every value a separate argv token.
_COMMANDS: dict = {
    # --- scan phases ---
    "run": _cmd("Run — guided full flow", "Scan", "required", profile=True,
                flags=[_f("deep", "--deep", "deep")]),
    "scan": _cmd("Scan — enum + vulns", "Scan", "required", profile=True,
                 flags=[_f("deep", "--deep", "deep"), _f("fast", "--fast", "fast")]),
    "enum": _cmd("Enumerate", "Scan", "required", profile=True,
                 flags=[_f("fast", "--fast", "masscan"), _f("all-ports", "--all-ports", "all ports")]),
    "vulns": _cmd("Vuln scan", "Scan", "optional",
                  flags=[_f("fast", "--fast", "fast"), _f("aggressive", "--aggressive", "aggressive NSE", True),
                         _f("offline", "--offline", "offline")]),
    "sweep": _cmd("Deep sweep — every credential-free module", "Scan", "optional"),
    "credsweep": _cmd("Credentialed sweep", "Scan", "optional", creds=True),
    "db": _cmd("Database scan (NSE inventory)", "Databases", "optional", creds=True,
               flags=[_f("aggressive", "--aggressive", "aggressive (brute/xp_cmdshell)", True)]),
    # --- databases (native deep modules) ---
    "postgres": _cmd("PostgreSQL", "Databases", "optional", creds=True,
                     flags=[_f("prove", "--prove", "prove RCE (benign id, active)", True)]),
    "mysql": _cmd("MySQL / MariaDB", "Databases", "optional", creds=True),
    "mongodb": _cmd("MongoDB", "Databases", "optional", creds=True),
    "mssql": _cmd("MSSQL", "Databases", "optional", creds=True),
    "redis": _cmd("Redis", "Databases", "optional"),
    "elasticsearch": _cmd("Elasticsearch", "Databases", "optional"),
    "memcached": _cmd("memcached", "Databases", "optional"),
    "couchdb": _cmd("CouchDB", "Databases", "optional"),
    "influxdb": _cmd("InfluxDB", "Databases", "optional"),
    "cassandra": _cmd("Cassandra", "Databases", "optional"),
    "oracle": _cmd("Oracle TNS", "Databases", "optional"),
    "db2": _cmd("IBM Db2", "Databases", "optional"),
    # --- web / web-app ---
    "web": _cmd("Web deep-enum", "Web", "optional",
                flags=[_f("crawl", "--crawl", "crawl + inject"),
                       _f("autologin", "--autologin", "auto-login w/ looted creds (active)", True),
                       _f("sqli-time", "--sqli-time", "time-based SQLi", True),
                       _f("upload-shell", "--upload-shell",
                          "upload benign webshell to prove RCE (active, writes a file)", True),
                       _f("smuggle", "--smuggle",
                          "CL.TE/TE.CL smuggling probe (active, may disturb proxies)", True)]),
    "api": _cmd("API — OpenAPI enum / IDOR / BOLA", "Web", "optional"),
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
    # --- AD / credentialed ---
    "credenum": _cmd("Credentialed enum (SMB/AD/SSH)", "Credentialed", "optional", creds=True),
    "deploy": _cmd("Deploy on-target enum", "Credentialed", "optional", creds=True),
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


def _finding_dict(v, reviewed: bool = False, notes: str = "") -> dict:
    from .. import tracking
    return {
        "key": tracking.vuln_row_key(v),      # same key the Excel sheet + coverage use
        "reviewed": reviewed, "notes": notes,
        "severity": v.severity or "info",
        "title": v.title or v.script_id or "finding",
        "ip": v.ip, "port": v.port,
        "cve": (v.ids[0] if v.ids else ""), "cves": list(v.ids or []),
        "kev": bool(getattr(v, "kev", False)),
        "epss": round((getattr(v, "epss", 0.0) or 0.0) * 100),
        "tier": _tier(v), "source": v.source, "confidence": v.confidence,
    }


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
    return kinds


def _detect_import_kind(content: str, filename: str = "") -> str:
    """The single best-guess kind (or 'unknown'). 'multiple' means a concatenated paste of
    more than one tool's output — the endpoint asks the user to import them separately."""
    kinds = _import_signatures(content, filename)
    if not kinds:
        return "unknown"
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
        if kind in ("nessus", "openvas", "nuclei", "testssl"):
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
    warning = ("" if n or kind in ("loot", "fieldkit", "bloodhound")
               else f"parsed 0 rows — this may not be {kind} output, or it's a variant recce "
               "can't read yet. Check the tool/format before importing.")
    return {"mode": "preview", "kind": kind, "count": n, "detail": detail,
            "sample": sample, "warning": warning}
