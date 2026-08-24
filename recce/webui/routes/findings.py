"""Finding tracking (note/tick), manual finding add, and the credential store.

Thin route layer: parse the body, hand off to the service, translate service
exceptions into HTTPException, publish the broker event, return JSON.
"""
from __future__ import annotations

from fastapi import Body, FastAPI, Header, HTTPException, Query

from ..services import credentials as credentials_svc
from ..services import findings as findings_svc


def register_findings_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path
    broker = ctx.broker

    @app.get("/api/credentials")
    def credentials(limit: int = Query(default=0, ge=0),
                    offset: int = Query(default=0, ge=0)):
        """The credential store — looted (web/db/share) + captured (kerberoast/gpp/...).
        This is 'what was extracted', which the UI never surfaced before."""
        return credentials_svc.list_credentials(db_path, limit=limit, offset=offset)

    @app.post("/api/note")
    def note(body: dict = Body(...), x_tester: str = Header(default="someone")):
        key = str(body.get("key", ""))
        text = str(body.get("note", ""))
        try:
            findings_svc.set_note(db_path, key, text)
        except findings_svc.ValidationError as e:
            raise HTTPException(400, str(e))
        broker.publish({"type": "note", "key": key, "note": text, "tester": x_tester})
        return {"ok": True}

    @app.post("/api/tick")
    def tick(body: dict = Body(...), x_tester: str = Header(default="someone")):
        key = str(body.get("key", ""))
        reviewed = bool(body.get("reviewed", True))
        try:
            findings_svc.set_reviewed(db_path, key, reviewed)
        except findings_svc.ValidationError as e:
            raise HTTPException(400, str(e))
        broker.publish({"type": "tick", "key": key, "reviewed": reviewed,
                        "tester": x_tester})
        return {"ok": True}

    @app.post("/api/add/finding")
    def add_finding(body: dict = Body(...), x_tester: str = Header(default="someone")):
        try:
            info = findings_svc.add_manual_finding(
                db_path, tester=x_tester,
                ip=str(body.get("ip", "")),
                title=str(body.get("title", "")),
                severity=str(body.get("severity", "medium")),
                port=body.get("port"),
                cve=str(body.get("cve", "")),
                output=str(body.get("output", "")),
            )
        except findings_svc.ValidationError as e:
            raise HTTPException(400, str(e))
        broker.publish({"type": "add", "what": "finding", "ip": info["ip"], "by": x_tester})
        return {"ok": True}
