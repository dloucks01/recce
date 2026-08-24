"""Report download endpoint."""
from __future__ import annotations

import os
import threading

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from .._common import _REPORTS

_report_lock = threading.Lock()


def register_report_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path

    @app.get("/api/report/{kind}")
    def report(kind: str, include: str = ""):
        """Regenerate the deliverables from the live datastore and hand back the
        requested file as a download - byte-for-byte what `recce report` produces
        (same builder), so the UI export and the CLI export never diverge.

        include: same filter as the preview endpoint — comma-separated finding
        keys. Empty = every finding, matching the CLI's default behavior."""
        if kind not in _REPORTS:
            raise HTTPException(404, f"unknown report kind {kind!r}")
        from ...store import Store
        from ...cli import _generate_reports, _open_paths
        include_keys = None
        if include.strip():
            include_keys = {k for k in include.split(",") if k}
        paths = _open_paths(eng_dir)
        with _report_lock, Store(db_path) as st:
            title = st.get_meta("engagement") or "recce engagement"
            _generate_reports(st, paths, title, quiet=True, include_keys=include_keys)
        pkey, fname, media = _REPORTS[kind]
        path = paths[pkey]
        if not os.path.exists(path):
            raise HTTPException(500, "report generation produced no file")
        return FileResponse(path, media_type=media, filename=fname)

    @app.get("/api/report/preview/html")
    def report_preview_html(include: str = ""):
        """Serve the HTML report INLINE (not as a download) so the Report tab
        can render it in an iframe for live preview. Same builder as the
        download endpoint — the tester sees exactly what they will ship.

        include: optional comma-separated finding keys (from Finding.key on
        the frontend). When set, only those findings appear in the preview —
        the Report Studio uses this to reshape the report live as the tester
        selects/deselects rows."""
        from fastapi.responses import Response
        from ...store import Store
        from ...cli import _generate_reports, _open_paths
        include_keys = None
        if include.strip():
            include_keys = {k for k in include.split(",") if k}
        paths = _open_paths(eng_dir)
        with _report_lock, Store(db_path) as st:
            title = st.get_meta("engagement") or "recce engagement"
            _generate_reports(st, paths, title, quiet=True, include_keys=include_keys)
        html_path = paths["html"]
        if not os.path.exists(html_path):
            raise HTTPException(500, "report generation produced no file")
        with open(html_path, "rb") as f:
            data = f.read()
        # X-Frame-Options omitted deliberately so same-origin iframes work.
        return Response(data, media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store"})
