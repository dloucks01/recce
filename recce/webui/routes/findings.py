"""Routes: findings management (add, tick, note)."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from ..schemas import NotePayload, TickPayload
from ..helpers import finding_dict

router = APIRouter(prefix="/api", tags=["findings"])


def register_findings_routes(app, eng):
    """Register findings routes on the app."""

    @router.post("/note")
    def add_note(payload: NotePayload):
        """Add a note to a finding."""
        notes = eng.load_notes()
        notes.setdefault(payload.finding_id, {})["text"] = payload.text
        eng.save_notes(notes)
        return {"status": "ok"}

    @router.post("/tick")
    def tick_finding(payload: TickPayload):
        """Mark a finding as reviewed."""
        notes = eng.load_notes()
        notes.setdefault(payload.finding_id, {})["reviewed"] = True
        eng.save_notes(notes)

        # Add activity log
        eng.log_activity(f"Reviewed finding {payload.finding_id[:40]}")
        return {"status": "ok"}

    @router.post("/add/finding")
    def add_finding(ip: str, port: int, title: str, severity: str, output: str, cwes: list[str] = None):
        """Manually add a finding."""
        from ..models import Vuln, Port

        port_obj = Port(portid=port, protocol="tcp", state="open")
        vuln = Vuln(
            ip=ip,
            port=port_obj,
            protocol="tcp",
            script_id="manual",
            state="finding",
            title=title,
            output=output,
            severity=severity,
            cwes=cwes or [],
            source="manual",
            remediation="",
        )
        eng.findings.append(vuln)
        eng.save()
        return {"status": "ok", "finding_id": f"{ip}:{port}:manual"}

    @router.get("/credentials")
    def get_credentials():
        """Get all looted credentials."""
        return [
            {
                "username": c.username,
                "password": c.password or "",
                "hash": c.hash[:40] if c.hash else "",
                "domain": c.domain or "",
                "source": c.source or "",
            }
            for c in eng.credentials
        ]

    app.include_router(router)
