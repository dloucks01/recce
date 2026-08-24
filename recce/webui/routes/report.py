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

    @app.get("/api/report/writeup/one")
    def report_writeup(include: str = ""):
        """Per-finding walkthrough .docx from report/docx.build_one_writeup.
        Different SHAPE than the combined report: one document focused on
        one finding, with pre-filled [TESTER: ...] placeholders for the
        fields only the operator can supply (mission risk / difficulty /
        step-by-step walkthrough with screenshots).

        include: a single finding key (from Finding.key). Multiple keys
        aren't supported here — use the combined report."""
        from fastapi.responses import FileResponse
        from ...store import Store
        from ...report import docx as _docx
        if not include.strip():
            raise HTTPException(400, "include=<finding_key> required")
        with Store(db_path) as st:
            hosts = st.all_hosts()
        # Frontend key: "vuln:ip:port:script_id:title[:60]" — pass the title
        # tail as selector; if that's ambiguous, fall back to IP:port. The
        # matcher accepts either.
        parts = include.split(":", 4)
        selector = parts[4] if len(parts) == 5 else include
        # Write to the engagement's writeups/ dir directly so the docx
        # persists (matches CLI's `recce writeup` behavior) and there's
        # no tempdir cleanup race with FileResponse.
        eng_out = os.path.join(eng_dir, "writeups")
        os.makedirs(eng_out, exist_ok=True)
        with _report_lock:
            res = _docx.build_one_writeup(hosts, eng_out, selector, overwrite=True)
        matched = res.get("matched", [])
        if len(matched) != 1 or not res.get("written"):
            raise HTTPException(
                404 if not matched else 409,
                f"selector matched {len(matched)} findings — need exactly 1")
        path = res["written"]  # absolute path returned by the builder
        fname = os.path.basename(path)
        return FileResponse(
            path, filename=fname,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

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
