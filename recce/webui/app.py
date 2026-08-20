"""The FastAPI application: a JSON API over a recce engagement, background scan jobs
with live SSE progress, and (when built) the React frontend served as static files.

    from recce.webui.app import create_app
    app = create_app("eng")          # engagement dir; `recce serve -o eng` launches it
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time

from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .jobs import JobManager, recce_argv

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_PHASES = {"run", "scan", "enum", "vulns", "sweep"}
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

    async def subscribe(self):
        q: asyncio.Queue = asyncio.Queue()
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
                q.put_nowait(event)

        self._loop.call_soon_threadsafe(_emit)


_IMPORT_TOOLS = ("nmap", "nxc", "kerberoast", "asrep", "secretsdump", "loot")


def _detect_import_kind(content: str, filename: str = "") -> str:
    """Best-effort format sniffing so a teammate can drop ANY tool's output and have
    it routed to the right recce parser. Order matters: the most specific signatures
    (Kerberos hashes, secretsdump rows) are checked before the looser ones."""
    from ..importers import detect_scanner
    scanner = detect_scanner(content)                                  # nessus/openvas/nuclei/testssl
    if scanner:
        return scanner
    low = content.lower()
    fn = filename.lower()
    if "<nmaprun" in content[:4000]:                                   # nmap/masscan XML
        return "nmap"                                                  # require the nmap marker,
    #  don't route arbitrary <?xml (e.g. an unrecognized scanner report) to the nmap parser
    if "$krb5tgs$" in content:
        return "kerberoast"
    if "$krb5asrep$" in content:
        return "asrep"
    if re.search(r"^[^:\s]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::", content, re.I | re.M):
        return "secretsdump"                                           # user:rid:lm:nt:::
    if re.search(r"^\s*SMB\s+\S+\s+\d+\s+\S+\s", content, re.M):        # netexec/cme SMB
        return "nxc"
    if ("nmap scan report for" in low                                  # nmap -oN
            or re.search(r"^Host:\s+\S+.*\bPorts:", content, re.M)      # nmap -oG
            or fn.endswith((".gnmap", ".nmap", ".xml"))):
        return "nmap"
    if ("recce-enum" in low or "recce-service" in low or "net-iface" in low
            or re.search(r"^===[A-Z]", content, re.M) or "[!]" in content):
        return "loot"                                                  # on-target sweep
    return "unknown"


def create_app(eng_dir: str) -> FastAPI:
    from .. import __version__
    from ..cli import _open_paths
    db_path = _open_paths(eng_dir)["db"]

    app = FastAPI(title="recce workbench", version=__version__)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                       allow_headers=["*"])
    jobs = JobManager()
    broker = _Broker()
    from . import collab
    presence = collab.Presence()

    @app.on_event("startup")
    async def _bind():
        broker.bind(asyncio.get_running_loop())

    def _hosts():
        from ..store import Store
        st = Store(db_path)
        try:
            return st.all_hosts(), (st.get_meta("engagement") or "recce engagement")
        finally:
            st.close()

    def _tracking() -> dict:
        from ..store import Store
        st = Store(db_path)
        try:
            return st.get_tracking()          # {key: (reviewed_bool, notes)}
        finally:
            st.close()

    def _scope() -> dict:
        from ..store import Store
        st = Store(db_path)
        try:
            return st.get_scope()             # {subnet: size}
        finally:
            st.close()

    @app.get("/api/engagement")
    def engagement():
        hosts, name = _hosts()
        up = [h for h in hosts if h.is_up]
        vulns = [v for h in up for v in h.vulns]
        by_sev: dict[str, int] = {}
        for v in vulns:
            by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
        checked = sum(1 for h in up if getattr(h, "access_gained", False)
                      or getattr(h, "vuln_scanned", False))
        return {"name": name, "hosts_up": len(up), "hosts_total": len(hosts),
                "services": sum(len(h.open_ports) for h in up),
                "findings_by_severity": by_sev,
                "kev": sum(1 for v in vulns if getattr(v, "kev", False)),
                "checked_pct": round(100 * checked / len(up)) if up else 0}

    @app.get("/api/hosts")
    def hosts():
        hs, _ = _hosts()
        tr = _tracking()
        out = []
        for h in hs:
            if not h.is_up:
                continue
            rev, notes = tr.get(_host_key(h.ip), (False, ""))
            out.append(_host_dict(h, bool(rev), notes))
        return out

    @app.get("/api/host/{ip}")
    def host_detail(ip: str):
        """Everything about one host — services, full findings (with output +
        remediation + QoD), AD accounts, posture — for the drill-down drawer."""
        from .. import qod, tracking
        hs, _ = _hosts()
        h = next((x for x in hs if x.ip == ip), None)
        if h is None:
            raise HTTPException(404, "no such host")
        trk = _tracking()
        hrev, hnotes = trk.get(_host_key(h.ip), (False, ""))
        vulns = []
        for v in h.vulns:
            rev, notes = trk.get(tracking.vuln_row_key(v), (False, ""))
            d = _finding_dict(v, bool(rev), notes)
            qscore, qtype = qod.score(v)
            d.update({
                "output": (v.output or "")[:4000], "remediation": v.remediation or "",
                "cwes": list(v.cwes or []),
                "qod": getattr(v, "qod", 0) or qscore,
                "qod_type": getattr(v, "qod_type", "") or qtype, "state": v.state or "",
            })
            vulns.append(d)
        vulns.sort(key=lambda f: (not f["kev"], _SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        base = _host_dict(h, bool(hrev), hnotes)
        base.update({
            "access_detail": getattr(h, "access_detail", ""),
            "smb_signing": getattr(h, "smb_signing", ""),
            "defenses": list(getattr(h, "defenses", []) or []),
            "ports": [{"port": p.portid, "proto": p.protocol, "state": p.state,
                       "service": p.service, "product": p.product, "version": p.version,
                       "banner": (p.service_banner or p.banner or "")[:200]}
                      for p in h.open_ports],
            "vulns": vulns,
            "accounts": [{"kind": a.kind, "name": a.name, "domain": a.domain,
                          "rid": a.rid, "detail": a.detail,
                          "attrs": {k: a.attrs.get(k) for k in
                                    ("spn", "enabled", "admincount", "memberof",
                                     "asrep_roastable", "delegation") if a.attrs.get(k)}}
                         for a in (getattr(h, "accounts", []) or [])],
        })
        return base

    @app.get("/api/findings")
    def findings():
        from .. import tracking
        hs, _ = _hosts()
        tr = _tracking()
        out = []
        for h in hs:
            if not h.is_up:
                continue
            for v in h.vulns:
                rev, notes = tr.get(tracking.vuln_row_key(v), (False, ""))
                out.append(_finding_dict(v, bool(rev), notes))
        out.sort(key=lambda f: (not f["kev"], _SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        return out

    @app.get("/api/credentials")
    def credentials():
        """The credential store — looted (web/db/share) + captured (kerberoast/gpp/…).
        This is 'what was extracted', which the UI never surfaced before."""
        from ..store import Store
        st = Store(db_path)
        try:
            creds = st.all_credentials()
        finally:
            st.close()
        return [{"username": c.username, "secret": c.secret, "kind": c.kind,
                 "domain": c.domain, "source": c.source, "origin_ip": c.origin_ip,
                 "notes": c.notes, "label": c.label} for c in creds]

    def _card_dict(c):
        return {"archetype": c.archetype, "title": c.title, "target": c.target,
                "command": c.command, "yields": c.yields, "safety": c.safety,
                "tier": c.tier, "score": c.score, "count": c.count,
                "attack_id": c.attack_id, "attack_name": c.attack_name, "cwe": c.cwe,
                "verify_first": c.verify_first, "why": c.why,
                "needs": [d for d, met in c.preconditions if not met]}

    @app.get("/api/act")
    def act_plan():
        """The Act phase: findings -> ranked, guided action plan. 'What do I do now?'."""
        from .. import act
        from ..store import Store
        st = Store(db_path)
        try:
            hosts, creds = st.all_hosts(), st.all_credentials()
        finally:
            st.close()
        cards = act.action_plan(hosts, creds, eng_dir)
        tiers: dict = {}
        for c in cards:
            tiers.setdefault(c.tier, []).append(_card_dict(c))
        return {"top": [_card_dict(c) for c in act.top_moves(cards, 5)],
                "tiers": [{"tier": t, "label": act._TIER_LABEL[t], "cards": tiers[t]}
                          for t in sorted(tiers)]}

    @app.post("/api/act/run")
    def act_run():
        """Execute the AUTO (read-only / reversible) links: loot the flagged unauth
        services, refresh the spray plan, feed yields back. Intrusive actions are never
        run. Returns what was looted so the UI can point the operator at the Loot tab."""
        from .. import act
        from ..store import Store
        st = Store(db_path)
        try:
            summary = act.execute_auto(st, eng_dir)
        finally:
            st.close()
        spray = summary.get("spray") or {}
        broker.publish({"type": "act_run", "looted": len(summary["looted"])})
        return {"looted": len(summary["looted"]),
                "creds": [{"label": c.label, "source": c.source} for c in summary["looted"]],
                "spray_files": sorted((spray.get("files") or {}).keys())}

    @app.post("/api/spray")
    def spray(body: dict = Body(default=None)):
        """Run a lockout-safe spray of the looted/stacked creds across a target scope
        (one IP / range / all), fold the validated logins. safe=false = full user x pass."""
        from .. import credentials as cr
        from ..cli import ip_matcher
        from ..models import Credential
        from ..store import Store
        body = body or {}
        st = Store(db_path)
        try:
            hosts = st.all_hosts()
            sel = (body.get("targets") or "").strip()
            if sel:
                match = ip_matcher(sel.split())
                hosts = [h for h in hosts if match(h.ip)]
            creds = cr.stack(hosts, st.all_credentials())
            res = cr.run_spray(hosts, creds, eng_dir, safe=body.get("safe", True))
            new = 0
            if res.get("ok"):
                for h in res["hits"]:
                    if st.add_credential(Credential(
                            username=h["user"], secret=h["secret"], kind="password",
                            source="spray-validated", origin_ip=h["ip"],
                            notes=f"validated over {h['proto']}"
                                  + (" (local admin)" if h["admin"] else ""))):
                        new += 1
        finally:
            st.close()
        broker.publish({"type": "spray", "hits": len(res.get("hits", []))})
        return {"ok": res.get("ok", False), "error": res.get("error", ""),
                "hits": res.get("hits", []), "new": new}

    @app.post("/api/import")
    def import_output(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """Fold external tool output into the live engagement so the whole team sees it.
        Auto-detects the format (or takes an explicit `kind`) and routes to the same
        parsers the CLI uses: nmap/masscan -> `import`, on-target loot -> `ingest`, and
        netexec / GetUserSPNs / GetNPUsers / secretsdump -> credenum's parsers."""
        import base64
        import tempfile
        from .. import importers
        content_in = str(body.get("content", ""))
        filename = str(body.get("filename", ""))
        kind = str(body.get("kind", "auto")).lower()
        enc = str(body.get("encoding", "")).lower()
        if not content_in.strip():
            raise HTTPException(400, "no content to import")
        # Decode the upload to bytes ONCE. The browser sends base64 (binary-safe) so a
        # UTF-16 / BOM / binary file survives intact; older/plain callers may send raw text.
        try:
            raw_bytes = (base64.b64decode(content_in, validate=False) if enc == "base64"
                         else content_in.encode("utf-8", "replace"))
        except Exception:
            raise HTTPException(400, "could not decode the uploaded file")
        if len(raw_bytes) > 25_000_000:                  # ~25 MB — cap the REAL decoded size
            raise HTTPException(413, "import too large (max ~25 MB)")
        # Text-safe decode (UTF-16 is the default of a PowerShell redirect); bloodhound
        # re-reads raw_bytes below since a SharpHound zip is binary.
        content = importers.decode_bytes(raw_bytes)
        if kind in ("", "auto"):
            kind = _detect_import_kind(content, filename)
        if kind == "unknown":
            raise HTTPException(422, "could not detect the format — pick the tool from "
                                "the dropdown. Supported: nmap/masscan, netexec (nxc smb), "
                                "impacket GetUserSPNs / GetNPUsers / secretsdump, and recce "
                                "on-target loot.")
        # BloodHound (.zip, binary) + Certipy (.json): the SharpHound collection is a
        # zip, so accept a base64 payload, decode, and run it through the `recce ad`
        # engine (works with no creds — findings + graph, just no owned-account paths).
        if kind == "bloodhound":
            raw = raw_bytes                               # already decoded above (binary-safe)
            is_zip = raw[:2] == b"PK" or filename.lower().endswith(".zip")
            fd, tmp = tempfile.mkstemp(prefix="recce-import-",
                                       suffix=".zip" if is_zip else ".json")
            label = f"ad {filename or kind}"

            def _done_ad(job, _tmp=tmp):
                try:
                    os.remove(_tmp)                       # the job has read it; don't leak /tmp
                except OSError:
                    pass
                broker.publish({"type": "scan", "status": job.status,
                                "tester": x_tester, "targets": label})
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(raw)
                job = jobs.start(recce_argv("ad", tmp, "-o", eng_dir), on_done=_done_ad)
            except BaseException:
                try:
                    os.remove(tmp)                        # never leak the temp file on start failure
                except OSError:
                    pass
                raise
            broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
            return {"mode": "job", "id": job.id, "kind": kind}

        # nmap + on-target loot + fieldkit have a real CLI pipeline (host resolution,
        # merge, enrich): run it as a job so the browser streams progress like a scan.
        if kind in ("nmap", "loot", "fieldkit"):
            if kind == "nmap":
                # Choose the suffix from the CONTENT (parse_nmap_file dispatches on extension),
                # so the right parser runs: XML (-oX), grepable (-oG), or normal (-oN). The old
                # "starts with '<'" guess sent a -oN file to the gnmap parser and a BOM'd XML
                # to gnmap too.
                if "<nmaprun" in content[:4000] or content.lstrip().startswith("<?xml"):
                    suffix = ".xml"
                elif re.search(r"^Host:\s+\S+\s+\(", content, re.M):
                    suffix = ".gnmap"
                else:
                    suffix = ".nmap"
                cmd = "import"
            else:
                cmd, suffix = {"loot": ("ingest", ".txt"),
                               "fieldkit": ("fieldkit-import", ".json")}[kind]
            fd, tmp = tempfile.mkstemp(prefix="recce-import-", suffix=suffix)
            label = f"{cmd} {filename or kind}"

            def _done(job, _tmp=tmp):
                try:
                    os.remove(_tmp)                       # the job has read it; don't leak /tmp
                except OSError:
                    pass
                broker.publish({"type": "scan", "status": job.status,
                                "tester": x_tester, "targets": label})
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(content)
                job = jobs.start(recce_argv(cmd, tmp, "-o", eng_dir), on_done=_done)
            except BaseException:
                try:
                    os.remove(tmp)                        # never leak the temp file on start failure
                except OSError:
                    pass
                raise
            broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
            return {"mode": "job", "id": job.id, "kind": kind}

        # Credential-tool output: no CLI import exists, so parse + fold directly.
        from .. import credenum as ce
        from ..models import Credential, Host
        from ..store import Store
        st = Store(db_path)
        added = 0
        summary = ""
        try:
            if kind == "nxc":
                content = importers.strip_ansi(content)      # a piped nxc log carries colour codes
                # SMB gets the full fold (access, shares, users, local-admin finding).
                groups: dict[str, list[str]] = {}
                for raw in content.splitlines():
                    m = ce._NXC_LINE.match(raw)
                    if m and m.group(1).upper() == "SMB":
                        groups.setdefault(m.group(2), []).append(raw)
                hosts_folded = 0
                for ip, lines in groups.items():
                    if not importers.is_ip(ip):              # nxc targeted a hostname, not an IP:
                        continue                             # don't create a hostname-keyed host
                    data = ce.parse_nxc_smb("\n".join(lines))
                    if not (data["auth"] or data["admin"] or data["shares"] or data["users"]):
                        continue
                    host = st.get_host(ip) or Host(ip=ip)
                    host.state = "up"
                    ce._fold_nxc(host, data, label="imported nxc")
                    st.upsert_host(host, merge=True)
                    hosts_folded += 1
                # ANY protocol (smb/ldap/mssql/winrm/ssh/...): a "[+] dom\\user:secret
                # (Pwn3d!)" line is a validated credential — capture it for spraying.
                creds_added = 0
                access: dict[str, str] = {}       # ip -> foothold detail
                cred_re = re.compile(r"\[\+\]\s+(?:([^\\\s]+)\\)?([^\s:]+):(\S+?)(?:\s+\((Pwn3d!)\))?\s*$")
                for raw in content.splitlines():
                    m = ce._NXC_LINE.match(raw)
                    if not m:
                        continue
                    proto, ip, msg = m.group(1).upper(), m.group(2), m.group(5)
                    cm = cred_re.search(msg)
                    if not cm:
                        continue
                    dom, user, secret, pwn = cm.group(1) or "", cm.group(2), cm.group(3), cm.group(4)
                    knd, sec = importers.classify_secret(secret)   # LM:NT -> nthash (spray the NT half)
                    if st.add_credential(Credential(
                            username=user, secret=sec, domain=dom, kind=knd,
                            origin_ip=ip if importers.is_ip(ip) else "", source="nxc-validated",
                            notes=f"validated over {proto}" + (" (local admin)" if pwn else ""))):
                        creds_added += 1
                    # a validated login IS a foothold — record it so Access auto-ticks
                    if importers.is_ip(ip):
                        access.setdefault(ip, f"{proto} login "
                                          f"({'local admin' if pwn else 'valid creds'}) - imported nxc")
                for ip, detail in access.items():
                    host = st.get_host(ip) or Host(ip=ip)
                    host.state = "up"
                    if not getattr(host, "access_gained", False):
                        host.access_gained = True
                        host.access_detail = detail
                    st.upsert_host(host, merge=True)
                added = hosts_folded + creds_added
                summary = (f"folded netexec results: {hosts_folded} SMB host(s), "
                           f"{creds_added} validated credential(s)")
            elif kind == "kerberoast":
                for r in ce.parse_getuserspns(content):
                    if r.get("hash") and st.add_credential(Credential(
                            username=r["name"], secret=r["hash"], kind="hash",
                            source="kerberoast", notes=("SPN " + r.get("spn", "")).strip())):
                        added += 1
                summary = f"stored {added} Kerberoast hash(es)"
            elif kind == "asrep":
                for r in ce.parse_getnpusers(content):
                    if r.get("hash") and st.add_credential(Credential(
                            username=r["name"], secret=r["hash"], kind="hash",
                            source="asrep", notes="AS-REP roastable")):
                        added += 1
                summary = f"stored {added} AS-REP hash(es)"
            elif kind == "secretsdump":
                skipped_hist = 0
                for r in ce.parse_secretsdump(content):
                    if r.get("history"):            # a rotated/old password — never spray as current
                        skipped_hist += 1
                        continue
                    note = ("cleartext (WDigest/LSA)" if r.get("kind") == "password"
                            else ("rid " + r.get("rid", "")).strip())
                    if st.add_credential(Credential(
                            username=r["name"], secret=r.get("secret") or r.get("nt", ""),
                            kind=r.get("kind", "nthash"), source="secretsdump", notes=note)):
                        added += 1
                summary = (f"stored {added} credential(s)"
                           + (f" ({skipped_hist} history entr{'y' if skipped_hist == 1 else 'ies'} "
                              "skipped)" if skipped_hist else ""))
            elif kind == "creds":
                # A plain credential list to stack + spray. Accepts `[domain\]user:secret`
                # (john --show / a spray list), `user:LM:NT` (pass-the-hash — the old
                # count(":")==1 guard silently dropped these), and the hashcat
                # `NThash:plaintext` --show shape (left is the hash, right the cracked pw).
                for raw in content.splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    left, right = line.split(":", 1)
                    if not left or not right:
                        continue
                    if (re.fullmatch(r"[0-9a-fA-F]{32}", left)
                            and not re.fullmatch(r"[0-9a-fA-F]{32}", right)):
                        cred = Credential(username="", secret=right, kind="password",
                                          source="imported",
                                          notes=f"plaintext cracked from NT {left.lower()}")
                    else:
                        dom, user = (left.split("\\", 1) if "\\" in left else ("", left))
                        knd, sec = importers.classify_secret(right)
                        cred = Credential(username=user, secret=sec, domain=dom, kind=knd,
                                          source="imported", notes="imported credential list")
                    if st.add_credential(cred):
                        added += 1
                summary = f"stored {added} credential(s)"
            elif kind in ("nessus", "openvas", "nuclei", "testssl"):
                from .. import epss, kev
                from ..importers import SCANNER_PARSERS
                vulns = SCANNER_PARSERS[kind](content)
                by_ip: dict[str, list] = {}
                for v in vulns:
                    by_ip.setdefault(v.ip, []).append(v)
                skipped_noip = 0
                folded_hosts = 0
                for ip, vs in by_ip.items():
                    if not ip.strip():                 # a finding with no host — don't create ip=""
                        skipped_noip += len(vs)
                        continue
                    host = st.get_host(ip) or Host(ip=ip)
                    host.state = "up"
                    host.vulns.extend(vs)
                    kev.annotate(host)                 # fix-first flags (KEV / EPSS) so
                    epss.annotate(host)                # imported CVEs rank with the rest
                    st.upsert_host(host, merge=True)   # union-merge dedups on re-import
                    added += len(vs)
                    folded_hosts += 1
                summary = (f"folded {added} {kind} finding(s) across {folded_hosts} host(s)"
                           + (f"; {skipped_noip} without a host skipped" if skipped_noip else ""))
            else:
                raise HTTPException(422, f"unsupported import kind {kind!r}")
        finally:
            st.close()
        broker.publish({"type": "import", "kind": kind, "added": added, "tester": x_tester})
        return {"mode": "done", "kind": kind, "added": added, "summary": summary}

    @app.get("/api/attackpath.svg")
    def attackpath_svg():
        """The projected attack-path graph as a standalone SVG, for inline display."""
        from fastapi.responses import Response
        from .. import attackpath
        hs, _ = _hosts()
        steps = attackpath.build(hs)
        if not steps:
            return Response("<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/>",
                            media_type="image/svg+xml")
        svg = attackpath.svg(hs, steps).replace(
            "<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ', 1)
        return Response(svg, media_type="image/svg+xml")

    @app.get("/api/attack")
    def attack_coverage():
        """MITRE ATT&CK coverage: techniques the findings map to, by tactic."""
        from .. import attack
        hs, _ = _hosts()
        cov = attack.coverage(hs)
        return {"technique_count": cov["technique_count"],
                "tactic_count": cov["tactic_count"],
                "tactics": [{"tactic": t, "tactic_id": attack.TACTICS.get(t, ""),
                             "techniques": techs}
                            for t, techs in cov["by_tactic"].items()]}

    @app.get("/api/overview")
    def overview():
        """Everything the dashboard needs in one cheap, live-pollable call."""
        from .. import tracking
        hs, name = _hosts()
        tr = _tracking()
        up = [h for h in hs if h.is_up]
        scope = _scope()
        by_sev: dict[str, int] = {}
        kev_findings, top_hosts = [], []
        reviewed = 0
        total_findings = 0
        enums = accessed = 0
        for h in up:
            hsev: dict[str, int] = {}
            for v in h.vulns:
                total_findings += 1
                by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
                hsev[v.severity] = hsev.get(v.severity, 0) + 1
                if tr.get(tracking.vuln_row_key(v), (False,))[0]:
                    reviewed += 1
                if getattr(v, "kev", False):
                    kev_findings.append({
                        "key": tracking.vuln_row_key(v), "ip": h.ip, "port": v.port,
                        "title": v.title or v.script_id, "severity": v.severity or "info",
                        "cve": (v.ids[0] if v.ids else ""),
                        "epss": round((getattr(v, "epss", 0.0) or 0.0) * 100),
                    })
            if getattr(h, "enumerated", False):
                enums += 1
            if getattr(h, "access_gained", False):
                accessed += 1
            top_hosts.append({
                "ip": h.ip, "hostname": h.hostname or "",
                "os": h.os_name or h.os_family or "", "roles": list(h.roles or []),
                "findings": hsev, "score": sum(
                    hsev.get(s, 0) * w for s, w in
                    (("critical", 1000), ("high", 100), ("medium", 10), ("low", 1)))})
        kev_findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        top_hosts.sort(key=lambda h: -h["score"])
        scope_size = sum(scope.values())
        return {
            "name": name,
            "hosts_up": len(up), "hosts_total": len(hs),
            "scope_subnets": len(scope), "scope_size": scope_size,
            "services": sum(len(h.open_ports) for h in up),
            "by_severity": by_sev, "findings_total": total_findings,
            "kev_total": len(kev_findings), "kev_findings": kev_findings[:12],
            "top_hosts": top_hosts[:8],
            "reviewed": reviewed,
            "enumerated": enums, "accessed": accessed,
        }

    @app.post("/api/note")
    def note(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ..store import Store
        key = str(body.get("key", ""))
        if not key:
            raise HTTPException(400, "no key")
        text = str(body.get("note", ""))
        st = Store(db_path)
        try:
            # preserve the reviewed flag; only the note text changes here
            rev = st.get_tracking().get(key, (False, ""))[0]
            st.set_reviewed(key, bool(rev), notes=text)
        finally:
            st.close()
        broker.publish({"type": "note", "key": key, "note": text, "tester": x_tester})
        return {"ok": True}

    @app.post("/api/tick")
    def tick(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ..store import Store
        key = str(body.get("key", ""))
        if not key:
            raise HTTPException(400, "no key")
        reviewed = bool(body.get("reviewed", True))
        st = Store(db_path)
        try:
            st.set_reviewed(key, reviewed)    # notes=None preserves any existing note
        finally:
            st.close()
        broker.publish({"type": "tick", "key": key, "reviewed": reviewed,
                        "tester": x_tester})
        return {"ok": True}

    # --- multi-tester collaboration ------------------------------------------------

    @app.get("/api/collab")
    def collab_state():
        """Everything the UI overlays on hosts/findings: who owns what, triage labels,
        per-port status, dismissed findings, the activity feed, and who's online."""
        from ..store import Store
        st = Store(db_path)
        try:
            return {"assignments": collab.get_assignments(st),
                    "labels": collab.get_labels(st),
                    "port_status": collab.get_port_status(st),
                    "dismissed": collab.get_dismissed(st),
                    "activity": collab.get_activity(st, 100),
                    "online": presence.roster()}
        finally:
            st.close()

    @app.post("/api/presence")
    def ping_presence(body: dict = Body(default=None), x_tester: str = Header(default="")):
        presence.ping(x_tester or (body or {}).get("tester", ""))
        return {"online": presence.roster()}

    def _mutate(fn, event: dict, activity: tuple | None = None,
                x_tester: str = "someone"):
        """Open the store, run fn(st), persist an activity line, broadcast, close."""
        from ..store import Store
        st = Store(db_path)
        try:
            result = fn(st)
            if activity:
                collab.add_activity(st, x_tester, activity[0], activity[1])
        finally:
            st.close()
        broker.publish(event)
        return result

    @app.post("/api/assign")
    def assign(body: dict = Body(...), x_tester: str = Header(default="someone")):
        ip = str(body.get("ip", ""))
        who = str(body.get("tester", ""))          # "" releases the claim
        if not ip:
            raise HTTPException(400, "no ip")
        verb = ("claimed" if who == x_tester else f"assigned to {who}") if who else "released"
        _mutate(lambda st: collab.set_assignment(st, ip, who),
                {"type": "assign", "ip": ip, "tester": who, "by": x_tester},
                ("assign", f"{x_tester} {verb} {ip}"), x_tester)
        return {"ok": True}

    @app.post("/api/label")
    def label(body: dict = Body(...), x_tester: str = Header(default="someone")):
        ip, lab = str(body.get("ip", "")), str(body.get("label", ""))
        on = bool(body.get("on", True))
        if not ip or lab not in collab.LABELS:
            raise HTTPException(400, f"ip + label required (label in {collab.LABELS})")
        _mutate(lambda st: collab.set_label(st, ip, lab, on),
                {"type": "label", "ip": ip, "label": lab, "on": on, "by": x_tester},
                None, x_tester)
        return {"ok": True}

    @app.post("/api/port_status")
    def port_status(body: dict = Body(...), x_tester: str = Header(default="someone")):
        ip, port = str(body.get("ip", "")), body.get("port")
        status = str(body.get("status", ""))
        if not ip or port is None:
            raise HTTPException(400, "ip + port required")
        _mutate(lambda st: collab.set_port_status(st, ip, port, status),
                {"type": "port_status", "ip": ip, "port": port, "status": status,
                 "by": x_tester}, None, x_tester)
        return {"ok": True}

    @app.post("/api/dismiss")
    def dismiss(body: dict = Body(...), x_tester: str = Header(default="someone")):
        key = str(body.get("key", ""))
        on = bool(body.get("on", True))
        if not key:
            raise HTTPException(400, "no key")
        _mutate(lambda st: collab.set_dismissed(st, key, x_tester, on),
                {"type": "dismiss", "key": key, "on": on, "by": x_tester},
                ("dismiss", f"{x_tester} {'dismissed' if on else 'restored'} a finding"),
                x_tester)
        return {"ok": True}

    @app.post("/api/add/finding")
    def add_finding(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from .. import epss, kev
        from ..models import Host, Vuln
        from ..store import Store
        ip = str(body.get("ip", "")).strip()
        if not ip:
            raise HTTPException(400, "a host IP is required")
        title = str(body.get("title", "")).strip() or "Manual finding"
        sev = str(body.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        port = body.get("port")
        cves = [c.strip().upper() for c in re.findall(r"CVE-\d{4}-\d+",
                str(body.get("cve", "")), re.I)]
        v = Vuln(ip=ip, port=int(port) if str(port).isdigit() else None, protocol="tcp",
                 script_id=f"manual-{int(time.time())}", state="finding", title=title,
                 severity=sev, ids=cves, output=str(body.get("output", ""))[:4000],
                 source="manual", confidence="confirmed")
        st = Store(db_path)
        try:
            host = st.get_host(ip) or Host(ip=ip)
            host.state = "up"
            host.vulns.append(v)
            kev.annotate(host)
            epss.annotate(host)
            st.upsert_host(host, merge=True)
            collab.add_activity(st, x_tester, "add", f"{x_tester} added finding “{title}” on {ip}")
        finally:
            st.close()
        broker.publish({"type": "add", "what": "finding", "ip": ip, "by": x_tester})
        return {"ok": True}

    @app.post("/api/add/credential")
    def add_credential(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ..models import Credential
        from ..store import Store
        user = str(body.get("username", "")).strip()
        secret = str(body.get("secret", "")).strip()
        if not user and not secret:
            raise HTTPException(400, "a username or secret is required")
        kind = str(body.get("kind", "password"))
        if kind not in ("password", "nthash", "hash", "blank"):
            kind = "password"
        st = Store(db_path)
        try:
            added = st.add_credential(Credential(
                username=user, secret=secret, kind=kind,
                domain=str(body.get("domain", "")), origin_ip=str(body.get("origin_ip", "")),
                source="manual", notes=str(body.get("notes", "")) or "added by hand"))
            collab.add_activity(st, x_tester, "add", f"{x_tester} added a credential for {user or '(secret)'}")
        finally:
            st.close()
        broker.publish({"type": "add", "what": "credential", "by": x_tester})
        return {"ok": True, "added": added}

    @app.post("/api/add/host")
    def add_host(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ..models import Host
        from ..store import Store
        from ..targets import load_targets
        tokens = str(body.get("targets", "")).split()
        if not tokens:
            raise HTTPException(400, "give one or more IPs / ranges / CIDRs")
        ips, hostnames, subnets = load_targets(tokens)
        ips = ips[:512]                                       # sanity cap on a big CIDR
        st = Store(db_path)
        try:
            for ip in ips:
                host = st.get_host(ip) or Host(ip=ip)
                host.state = "up"
                host.up_reason = host.up_reason or "manual"
                host.subnet = host.subnet or subnets.get(ip, "")
                if hostnames.get(ip) and hostnames[ip] not in host.hostnames:
                    host.hostnames.append(hostnames[ip])
                st.upsert_host(host, merge=True)
            collab.add_activity(st, x_tester, "add", f"{x_tester} added {len(ips)} host(s) to scope")
        finally:
            st.close()
        broker.publish({"type": "add", "what": "host", "count": len(ips), "by": x_tester})
        return {"ok": True, "added": len(ips)}

    @app.post("/api/add/access")
    def add_access(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ..models import Host
        from ..store import Store
        ip = str(body.get("ip", "")).strip()
        if not ip:
            raise HTTPException(400, "a host IP is required")
        note = str(body.get("note", "")).strip() or "foothold recorded by hand"
        st = Store(db_path)
        try:
            host = st.get_host(ip) or Host(ip=ip)
            host.state = "up"
            host.access_gained = True
            host.access_detail = note
            st.upsert_host(host, merge=True)
            collab.add_activity(st, x_tester, "access", f"{x_tester} recorded access on {ip}: {note}")
        finally:
            st.close()
        broker.publish({"type": "add", "what": "access", "ip": ip, "by": x_tester})
        return {"ok": True}

    # --- team chat ----------------------------------------------------------------
    _CHAT_MAX_BYTES = 8_000_000

    @app.get("/api/chat")
    def chat_history(limit: int = 200):
        from ..store import Store
        st = Store(db_path)
        try:
            return collab.get_chat(st, limit)
        finally:
            st.close()

    @app.post("/api/chat")
    def chat_post(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """A chat message: text and/or a pasted image. The image (base64) is decoded
        and stored on disk under the engagement; the message keeps only its filename."""
        from ..store import Store
        text = str(body.get("text", "")).strip()
        image_b64 = body.get("image") or ""
        image_name = ""
        if image_b64:
            import base64
            try:
                raw = base64.b64decode(image_b64)
            except Exception:
                raise HTTPException(400, "could not decode the image")
            if len(raw) > _CHAT_MAX_BYTES:
                raise HTTPException(413, "image too large (max ~8 MB)")
            ext = collab.image_ext(raw)
            if not ext:
                raise HTTPException(415, "unsupported image type (png/jpg/gif/webp)")
            image_name = f"{time.strftime('%Y%m%d')}-{os.urandom(6).hex()}.{ext}"
            media_dir = os.path.join(eng_dir, "chat-media")
            os.makedirs(media_dir, exist_ok=True)
            with open(os.path.join(media_dir, image_name), "wb") as fh:
                fh.write(raw)
        if not text and not image_name:
            raise HTTPException(400, "empty message")
        st = Store(db_path)
        try:
            msg = collab.add_chat(st, x_tester, text[:4000], image_name)
        finally:
            st.close()
        broker.publish({"type": "chat", "msg": msg})
        return msg

    @app.get("/api/chat/media/{name}")
    def chat_media(name: str):
        if "/" in name or "\\" in name or ".." in name:      # no path traversal
            raise HTTPException(400, "bad name")
        path = os.path.join(eng_dir, "chat-media", name)
        if not os.path.isfile(path):
            raise HTTPException(404, "no such image")
        return FileResponse(path)

    @app.get("/api/report/{kind}")
    def report(kind: str):
        """Regenerate the deliverables from the live datastore and hand back the
        requested file as a download - byte-for-byte what `recce report` produces
        (same builder), so the UI export and the CLI export never diverge."""
        if kind not in _REPORTS:
            raise HTTPException(404, f"unknown report kind {kind!r}")
        from ..store import Store
        from ..cli import _generate_reports, _open_paths
        paths = _open_paths(eng_dir)
        st = Store(db_path)
        try:
            title = st.get_meta("engagement") or "recce engagement"
            _generate_reports(st, paths, title, quiet=True)
        finally:
            st.close()
        pkey, fname, media = _REPORTS[kind]
        path = paths[pkey]
        if not os.path.exists(path):
            raise HTTPException(500, "report generation produced no file")
        return FileResponse(path, media_type=media, filename=fname)

    @app.get("/api/events")
    async def events():
        async def gen():
            yield "retry: 3000\n\n"                    # SSE reconnect hint
            async for ev in broker.subscribe():
                yield f"data: {json.dumps(ev)}\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    # --- scan jobs + live progress ------------------------------------------------

    @app.post("/api/scan")
    def start_scan(body: dict = Body(...), x_tester: str = Header(default="someone")):
        phase = str(body.get("phase", "run"))
        if phase not in _PHASES:
            raise HTTPException(400, f"phase must be one of {sorted(_PHASES)}")
        targets = [t for t in str(body.get("targets", "")).split() if not t.startswith("-")]
        if not targets:
            raise HTTPException(400, "no targets")
        argv = [phase, "-o", eng_dir]
        profile = str(body.get("profile", "")).lower()
        if profile in ("quick", "standard", "thorough"):
            argv += ["--profile", profile]

        def _done(job):
            broker.publish({"type": "scan", "status": job.status, "tester": x_tester,
                            "targets": " ".join(targets)})

        job = jobs.start(recce_argv(*argv, *targets), on_done=_done)
        broker.publish({"type": "scan_started", "tester": x_tester,
                        "targets": " ".join(targets)})
        return {"id": job.id, "status": job.status, "cmd": job.cmd}

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

    # --- the built React frontend (production / airgap bundle) ---------------------
    dist = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(dist):
        app.mount("/assets", StaticFiles(directory=os.path.join(dist, "assets")),
                  name="assets")

        @app.get("/")
        def index():
            return FileResponse(os.path.join(dist, "index.html"))

    return app
