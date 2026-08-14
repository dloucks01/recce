"""The FastAPI application: a JSON API over a recce engagement, background scan jobs
with live SSE progress, and (when built) the React frontend served as static files.

    from recce.webui.app import create_app
    app = create_app("eng")          # engagement dir; `recce serve -o eng` launches it
"""
from __future__ import annotations

import asyncio
import json
import os

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


def create_app(eng_dir: str) -> FastAPI:
    from .. import __version__
    from ..cli import _open_paths
    db_path = _open_paths(eng_dir)["db"]

    app = FastAPI(title="recce workbench", version=__version__)
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                       allow_headers=["*"])
    jobs = JobManager()
    broker = _Broker()

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
