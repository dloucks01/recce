"""The FastAPI application: a JSON API over a recce engagement, background scan jobs
with live SSE progress, and (when built) the React frontend served as static files.

    from recce.webui.app import create_app
    app = create_app("eng")          # engagement dir; `recce serve -o eng` launches it

This is the modular layout: the proven, model-correct helpers live in `_common.py`
and each handler group lives in a `routes/*.py` module. Behaviour mirrors the
the modular route layout.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from .jobs import JobManager, TooManyJobs
from ._common import _Broker
# Re-exported so `from recce.webui.app import _detect_import_kind` keeps working.
from ._common import _detect_import_kind, _import_preview, _import_signatures  # noqa: F401
from .routes import (
    register_act_spray_routes,
    register_collab_routes,
    register_data_exchange_routes,
    register_engagement_routes,
    register_findings_routes,
    register_manage_routes,
    register_report_routes,
    register_scan_routes,
    register_sessions_routes,
)


def create_app(eng_dir: str) -> FastAPI:
    from .. import __version__
    from ..cli import _open_paths
    db_path = _open_paths(eng_dir)["db"]
    # Phase 2 — tell the user-parser loader where <engagement>/parsers/
    # lives so an engagement can carry its own custom-tool parsers, then
    # refresh the SCANNER_PARSERS registry so those parsers register.
    from ..intake import parsers_user as _up
    from ..intake import importers as _importers
    _up.set_engagement_parser_dir(eng_dir)
    _importers.refresh_user_parsers()

    broker = _Broker()
    from ..sessions import SessionManager
    from ..sessions.store import SessionStore
    session_manager = SessionManager(store=SessionStore(db_path))
    session_manager.load_persisted()          # past sessions come back as stale, browsable

    @asynccontextmanager
    async def _lifespan(_app):
        # Bind the SSE broker + session manager to the serving event loop on startup
        # (replaces the deprecated @app.on_event("startup") hook). The session manager's
        # listeners and adopt() all run on this loop.
        loop = asyncio.get_running_loop()
        broker.bind(loop)
        session_manager.bind_loop(loop)
        # Auto-crack watcher (P1-8): while `recce serve` is up, periodically
        # fold hashcat's OWN cracks (from its default potfile + any *.pot in
        # the engagement out_dir) back into the credential store. Opt out
        # with RECCE_DISABLE_CRACK_WATCHER=1 (matches RECCE_ACTIVE_ATTACKS
        # gate convention). Watcher lives across the whole serve; store is a
        # long-lived instance (Store uses check_same_thread=False).
        _cw_disable = os.environ.get("RECCE_DISABLE_CRACK_WATCHER", "").lower()
        _cw_store = None
        if _cw_disable not in ("1", "true", "yes"):
            try:
                from ..core.store import Store
                from ..creds.crack_watcher import start_watcher
                _cw_store = Store(db_path)
                start_watcher(_cw_store, eng_dir, interval_seconds=60.0)
                logging.getLogger("recce.webui").info(
                    "auto-crack watcher started (interval 60s)")
            except Exception:
                logging.getLogger("recce.webui").exception(
                    "auto-crack watcher failed to start; continuing without it")
        try:
            yield
        finally:
            if _cw_store is not None:
                try:
                    from ..creds.crack_watcher import stop_watcher
                    stop_watcher()
                except Exception:
                    logging.getLogger("recce.webui").debug(
                        "crack-watcher stop failed", exc_info=True)
                try:
                    _cw_store.conn.close()
                except Exception:
                    pass

    app = FastAPI(title="recce workbench", version=__version__, lifespan=_lifespan)
    # No permissive CORS: the SPA is served same-origin (and `npm run dev` proxies /api),
    # so no cross-origin access is needed. A wildcard here would let any web page the
    # tester visits read /api/credentials etc. cross-origin — there is no auth to stop it.

    @app.exception_handler(TooManyJobs)
    async def _too_many_jobs(_request, exc):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": str(exc)}, status_code=429)

    @app.middleware("http")
    async def _limit_body(request, call_next):
        # Reject an oversized upload from its Content-Length before the whole body is
        # buffered into memory (a ~25 MB decoded import is ~34 MB of base64).
        from fastapi.responses import JSONResponse
        cl = request.headers.get("content-length", "")
        if cl.isdigit() and int(cl) > 45_000_000:
            return JSONResponse({"detail": "request too large (max ~45 MB)"}, status_code=413)
        # Require a declared length on the upload endpoint so a chunked / length-omitted
        # body can't stream past the size guard before the handler's decoded-size check.
        if request.url.path == "/api/import" and request.method == "POST" and not cl.isdigit():
            return JSONResponse({"detail": "Content-Length required"}, status_code=411)
        return await call_next(request)

    jobs = JobManager()
    from . import collab
    presence = collab.Presence()

    # Shared context passed to each route group. Route modules build their own tiny
    # _hosts/_tracking/_mutate closures from ctx.db_path.
    ctx = SimpleNamespace(eng_dir=eng_dir, db_path=db_path, jobs=jobs,
                          broker=broker, presence=presence, sessions=session_manager)

    register_engagement_routes(app, ctx)
    register_scan_routes(app, ctx)
    register_collab_routes(app, ctx)
    register_findings_routes(app, ctx)
    register_report_routes(app, ctx)
    register_act_spray_routes(app, ctx)
    register_data_exchange_routes(app, ctx)
    register_sessions_routes(app, ctx)
    register_manage_routes(app, ctx)

    @app.get("/api/events")
    async def events():
        async def gen():
            yield "retry: 3000\n\n"                    # SSE reconnect hint
            async for ev in broker.subscribe():
                yield f"data: {json.dumps(ev)}\n\n"

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
