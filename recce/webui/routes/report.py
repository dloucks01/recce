"""Report download endpoint. Ported verbatim from app_legacy."""
from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from .._common import _REPORTS


def register_report_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path

    @app.get("/api/report/{kind}")
    def report(kind: str):
        """Regenerate the deliverables from the live datastore and hand back the
        requested file as a download - byte-for-byte what `recce report` produces
        (same builder), so the UI export and the CLI export never diverge."""
        if kind not in _REPORTS:
            raise HTTPException(404, f"unknown report kind {kind!r}")
        from ...store import Store
        from ...cli import _generate_reports, _open_paths
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
