"""Finding tracking (note/tick), manual finding add, and the credential store."""
from __future__ import annotations

import re
import time

from fastapi import Body, FastAPI, Header, HTTPException, Query

from .. import collab


def register_findings_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path
    broker = ctx.broker

    @app.get("/api/credentials")
    def credentials(limit: int = Query(default=0, ge=0),
                    offset: int = Query(default=0, ge=0)):
        """The credential store — looted (web/db/share) + captured (kerberoast/gpp/...).
        This is 'what was extracted', which the UI never surfaced before."""
        from ...store import Store
        with Store(db_path) as st:
            creds = st.all_credentials()
        out = [{"username": c.username, "secret": c.secret, "kind": c.kind,
                "domain": c.domain, "source": c.source, "origin_ip": c.origin_ip,
                "notes": c.notes, "label": c.label} for c in creds]
        total = len(out)
        if limit > 0:
            out = out[offset:offset + limit]
        elif offset > 0:
            out = out[offset:]
        return {"items": out, "total": total, "limit": limit, "offset": offset}

    @app.post("/api/note")
    def note(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ...store import Store
        key = str(body.get("key", ""))
        if not key:
            raise HTTPException(400, "no key")
        text = str(body.get("note", ""))
        with Store(db_path) as st:
            rev = st.get_tracking().get(key, (False, ""))[0]
            st.set_reviewed(key, bool(rev), notes=text)
        broker.publish({"type": "note", "key": key, "note": text, "tester": x_tester})
        return {"ok": True}

    @app.post("/api/tick")
    def tick(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ...store import Store
        key = str(body.get("key", ""))
        if not key:
            raise HTTPException(400, "no key")
        reviewed = bool(body.get("reviewed", True))
        with Store(db_path) as st:
            st.set_reviewed(key, reviewed)
        broker.publish({"type": "tick", "key": key, "reviewed": reviewed,
                        "tester": x_tester})
        return {"ok": True}

    @app.post("/api/add/finding")
    def add_finding(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ... import epss, kev
        from ...models import Host, Vuln
        from ...store import Store
        ip = str(body.get("ip", "")).strip()
        if not ip:
            raise HTTPException(400, "a host IP is required")
        title = str(body.get("title", "")).strip() or "Manual finding"
        sev = str(body.get("severity", "medium")).lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        port = body.get("port")
        cves = [c.strip().upper() for c in re.findall(r"CVE-\d{4}-\d+",
                str(body.get("cve", "")), re.I)]
        port_int = int(port) if str(port).isdigit() else None
        if port_int is not None and not (1 <= port_int <= 65535):
            raise HTTPException(400, "port must be 1–65535")
        v = Vuln(ip=ip, port=port_int, protocol="tcp",
                 script_id=f"manual-{int(time.time())}", state="finding", title=title,
                 severity=sev, ids=cves, output=str(body.get("output", ""))[:4000],
                 source="manual", confidence="confirmed")
        with Store(db_path) as st:
            host = st.get_host(ip) or Host(ip=ip)
            host.state = "up"
            host.vulns.append(v)
            kev.annotate(host)
            epss.annotate(host)
            st.upsert_host(host, merge=True)
            collab.add_activity(st, x_tester, "add", f"{x_tester} added finding “{title}” on {ip}")
        broker.publish({"type": "add", "what": "finding", "ip": ip, "by": x_tester})
        return {"ok": True}
