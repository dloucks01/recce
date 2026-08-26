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

    @app.post("/api/loot/scan-evidence")
    def loot_scan_evidence(x_tester: str = Header(default="someone")):
        """Walk `<engagement>/evidence/**` and produce Vuln findings for
        Kerberos ticket files (.ccache/.kirbi), credential-bearing files
        (.aws/credentials, .netrc, id_rsa, browser saved logins, …), .git
        repository dumps, and configs with embedded secrets (API keys,
        DB URLs, private keys, JWTs, ...).

        Read-only — never mutates the evidence tree. Newly-discovered
        findings persist to the datastore so they show up in the Findings
        tab and roll into the report."""
        from ...intake.loot import scan_evidence
        from ...store import Store
        new_vulns = scan_evidence(ctx.eng_dir)
        if not new_vulns:
            return {"scanned": True, "added": 0}
        with Store(ctx.eng_dir + "/results.sqlite") as st:
            hosts_by_ip = {h.ip: h for h in st.all_hosts()}
            added = 0
            for v in new_vulns:
                h = hosts_by_ip.get(v.ip)
                if not h:
                    continue
                # Dedup: skip if this host already has an identical loot finding.
                if any(x.script_id == v.script_id and x.title == v.title
                       for x in h.vulns):
                    continue
                h.vulns.append(v)
                st.upsert_host(h)
                added += 1
            if added:
                collab.add_activity(st, x_tester, "scan",
                    f"{x_tester} scanned evidence and added {added} loot finding(s)")
        broker.publish({"type": "add", "what": "loot", "by": x_tester, "count": added})
        return {"scanned": True, "added": added, "detected": len(new_vulns)}


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

    @app.post("/api/evidence/upload")
    def upload_evidence(body: dict = Body(...),
                        x_tester: str = Header(default="someone")):
        """Attach an arbitrary file to a host as raw evidence.

        The escape hatch for anything that can't be parsed — screenshots,
        PDFs, packet captures, vendor reports, custom-tool output that
        recce doesn't recognize and even the universal loose parser can't
        get anything out of. Saves the file to <eng>/evidence/<ip>/ and
        creates an info-level finding on the host titled "Manual evidence:
        <filename>" so it shows up in the Findings tab with a link.

        body: {ip: "10.0.0.5", filename: "screenshot.png",
               data: "<base64>", note?: "optional context"}
        """
        import base64
        import os
        import re as _re
        import time
        from ...store import Store
        from ...models import Host, Vuln

        ip = str(body.get("ip", "")).strip()
        filename = str(body.get("filename", "")).strip()
        data_b64 = str(body.get("data", ""))
        note = str(body.get("note", "")).strip()

        if not ip or not filename or not data_b64:
            raise HTTPException(400, "ip, filename, and data (base64) required")
        # Path sanitization — refuse anything that looks like a traversal.
        if _re.search(r"[/\\]|\.\.", filename):
            raise HTTPException(400, "filename must be a bare name (no slashes / '..')")
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (ValueError, TypeError):
            raise HTTPException(400, "data is not valid base64")
        # 25 MB cap — evidence files can be big (captures, PDFs) but we won't
        # let a mistake ballon the engagement dir.
        if len(raw) > 25 * 1024 * 1024:
            raise HTTPException(413, "evidence file too large (max 25 MB)")

        # IP sanity — allow synthetic hosts (container:foo, generic-import,
        # active-directory) so evidence for those "hosts" has a home too.
        safe_ip = _re.sub(r"[^A-Za-z0-9._:-]+", "_", ip)[:80]
        ev_dir = os.path.join(ctx.eng_dir, "evidence", safe_ip)
        os.makedirs(ev_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%S")
        # Prefix filename with timestamp so multiple uploads of the same
        # `screenshot.png` don't clobber each other.
        safe_fn = _re.sub(r"[^A-Za-z0-9._-]+", "_", filename)[:120]
        dest = os.path.join(ev_dir, f"{stamp}_{safe_fn}")
        with open(dest, "wb") as fh:
            fh.write(raw)

        rel_path = os.path.relpath(dest, ctx.eng_dir)

        # Create the info-level tracker finding on the host.
        title = f"Manual evidence: {filename}"
        output = f"Attached by {x_tester} at {stamp}\nFile: {rel_path}\nSize: {len(raw)} bytes"
        if note:
            output += f"\n\nNote:\n{note}"
        with Store(db_path) as st:
            host = st.get_host(ip) or Host(ip=ip)
            if not host.is_up:
                host.state = "up"
            host.vulns.append(Vuln(
                ip=ip, port=None, protocol="tcp",
                script_id=f"evidence-{stamp}",
                state="finding", title=title,
                output=output[:4000], severity="info",
                source="manual-evidence", confidence="confirmed"))
            st.upsert_host(host, merge=True)

        broker.publish({"type": "evidence", "ip": ip, "path": rel_path,
                        "by": x_tester})
        return {"ok": True, "path": rel_path, "bytes": len(raw)}

    @app.get("/api/evidence/{ip}/{name}")
    def download_evidence(ip: str, name: str):
        """Serve back an evidence file the tester uploaded, so the "Manual
        evidence" finding row can link to it."""
        import os
        import re as _re
        from fastapi.responses import FileResponse
        if _re.search(r"[/\\]|\.\.", name):
            raise HTTPException(400, "bad filename")
        safe_ip = _re.sub(r"[^A-Za-z0-9._:-]+", "_", ip)[:80]
        path = os.path.join(ctx.eng_dir, "evidence", safe_ip, name)
        if not os.path.isfile(path):
            raise HTTPException(404, "no such evidence file")
        return FileResponse(path, filename=name)
