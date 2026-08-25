"""Finding tracking (note/tick), manual finding add, and the credential store.

Thin route layer: parse the body, hand off to the service, translate service
exceptions into HTTPException, publish the broker event, return JSON.
"""
from __future__ import annotations

from fastapi import Body, FastAPI, Header, HTTPException, Query

from .. import collab
from ..services import credentials as credentials_svc
from ..services import findings as findings_svc
from ..services import loot as loot_svc


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

    # Finding lifecycle status — beyond reviewed/dismissed. Values are open;
    # the frontend renders the standard set (new / triaged / confirmed /
    # in-report / excluded / retested-fixed / retested-open). Empty status
    # clears back to "new" (which is implicit — no row is stored).
    _STATUSES = {"", "new", "triaged", "confirmed", "in-report", "excluded",
                 "retested-fixed", "retested-open"}

    @app.post("/api/finding/status")
    def set_status(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ...store import Store
        import time
        key = str(body.get("key", "")).strip()
        status = str(body.get("status", "")).strip().lower()
        if not key:
            raise HTTPException(400, "key required")
        if status not in _STATUSES:
            raise HTTPException(400, f"unknown status {status!r}")
        with Store(db_path) as st:
            st.set_status(key, status, when=str(int(time.time())))
        broker.publish({"type": "status", "key": key, "status": status,
                        "tester": x_tester})
        return {"ok": True, "status": status}

    @app.post("/api/loot/extract")
    def loot_extract(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """Auto-loot: scan arbitrary text for credentials (secretsdump rows,
        env-style KEY=VAL, user:pass lines) and add each new one to the
        Credentials store with provenance. Idempotent — dupes are counted
        but not re-added."""
        text = str(body.get("text", ""))
        if not text.strip():
            raise HTTPException(400, "text required")
        origin_ip = str(body.get("origin_ip", "")).strip()
        note = str(body.get("note", "")).strip() or f"pasted by {x_tester}"
        result = loot_svc.extract_and_persist(db_path, text, origin_ip=origin_ip, note=note)
        if result["added"] > 0:
            from ...store import Store
            with Store(db_path) as st:
                collab.add_activity(st, x_tester, "add",
                    f"{x_tester} auto-looted {result['added']} credential(s) from pasted text")
            broker.publish({"type": "add", "what": "credential", "by": x_tester,
                            "count": result["added"]})
        return result

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
