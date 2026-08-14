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


def _tier(v) -> str:
    q = getattr(v, "qod", 0) or 0
    return "confirmed" if q >= 95 else "likely" if q >= 70 else "lead"


def _finding_dict(v, reviewed: bool = False) -> dict:
    from .. import tracking
    return {
        "key": tracking.vuln_row_key(v),      # same key the Excel sheet + coverage use
        "reviewed": reviewed,
        "severity": v.severity or "info",
        "title": v.title or v.script_id or "finding",
        "ip": v.ip, "port": v.port,
        "cve": (v.ids[0] if v.ids else ""), "cves": list(v.ids or []),
        "kev": bool(getattr(v, "kev", False)),
        "epss": round((getattr(v, "epss", 0.0) or 0.0) * 100),
        "tier": _tier(v), "source": v.source, "confidence": v.confidence,
    }


def _host_dict(h) -> dict:
    sev: dict[str, int] = {}
    for v in h.vulns:
        sev[v.severity] = sev.get(v.severity, 0) + 1
    return {
        "ip": h.ip, "hostname": h.hostname or "",
        "os": h.os_name or h.os_family or "", "roles": list(h.roles or []),
        "up": h.is_up,
        "ports": [{"port": p.portid, "proto": p.protocol, "service": p.service,
                   "product": (f"{p.product} {p.version}".strip() or p.service)}
                  for p in h.open_ports],
        "findings": sev,
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
        return [_host_dict(h) for h in hs if h.is_up]

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
                reviewed = bool(tr.get(tracking.vuln_row_key(v), (False, ""))[0])
                out.append(_finding_dict(v, reviewed))
        out.sort(key=lambda f: (not f["kev"], _SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        return out

    @app.post("/api/tick")
    def tick(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ..store import Store
        key = str(body.get("key", ""))
        if not key:
            raise HTTPException(400, "no key")
        reviewed = bool(body.get("reviewed", True))
        st = Store(db_path)
        try:
            st.set_reviewed(key, reviewed, notes=f"web:{x_tester}")
        finally:
            st.close()
        broker.publish({"type": "tick", "key": key, "reviewed": reviewed,
                        "tester": x_tester})
        return {"ok": True}

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
