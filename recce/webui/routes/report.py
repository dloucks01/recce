"""Routes: reporting and export."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
import io

router = APIRouter(prefix="/api", tags=["reporting"])


def register_report_routes(app, eng):
    """Register report routes on the app."""

    @router.get("/report/{kind}")
    def get_report(kind: str):
        """Get report in specified format."""
        from fastapi.responses import FileResponse, StreamingResponse

        if kind == "html":
            html = eng.to_html()
            return StreamingResponse(io.BytesIO(html.encode()), media_type="text/html")

        elif kind == "json":
            import json
            data = {
                "hosts": [{"ip": h.ip, "ports": len(h.ports)} for h in eng.hosts],
                "findings": [{"ip": v.ip, "title": v.title, "severity": v.severity} for v in eng.findings],
            }
            return StreamingResponse(
                io.BytesIO(json.dumps(data, indent=2).encode()),
                media_type="application/json",
            )

        elif kind == "csv":
            csv = eng.to_csv()
            return StreamingResponse(
                io.BytesIO(csv.encode()),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=findings.csv"},
            )

        elif kind == "markdown":
            md = eng.to_markdown()
            return StreamingResponse(
                io.BytesIO(md.encode()),
                media_type="text/markdown",
                headers={"Content-Disposition": "attachment; filename=findings.md"},
            )

        elif kind == "xlsx":
            # Word/Excel report generation
            from recce.report_docx import docx_findings
            doc = docx_findings(eng)
            buf = io.BytesIO()
            doc.save(buf)
            buf.seek(0)
            return StreamingResponse(
                buf,
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                headers={"Content-Disposition": "attachment; filename=findings.docx"},
            )

        else:
            raise HTTPException(status_code=400, detail=f"Unknown report format: {kind}")

    app.include_router(router)
