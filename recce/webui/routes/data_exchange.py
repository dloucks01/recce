"""Data exchange routes: import external tool output and playbook narrative."""

import base64
import os
import tempfile
import re
from fastapi import APIRouter, Body, Header, HTTPException

router = APIRouter(prefix="/api", tags=["data-exchange"])


def register_data_exchange_routes(app, eng, job_manager=None, broker=None):
    """Register import and playbook routes."""

    @router.post("/import")
    def import_output(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """Fold external tool output into the engagement.
        Auto-detects format: nmap/masscan, loot, netexec, impacket, Nessus, nuclei, BloodHound, etc.
        """
        from .. import importers
        from ..helpers import import_preview, detect_import_kind

        content_in = str(body.get("content", ""))
        filename = str(body.get("filename", ""))
        kind = str(body.get("kind", "auto")).lower()
        enc = str(body.get("encoding", "")).lower()

        if not content_in.strip():
            raise HTTPException(400, "no content to import")

        # Decode upload to bytes ONCE (binary-safe)
        try:
            raw_bytes = (base64.b64decode(content_in, validate=False) if enc == "base64"
                         else content_in.encode("utf-8", "replace"))
        except Exception:
            raise HTTPException(400, "could not decode the uploaded file")

        if len(raw_bytes) > 25_000_000:  # ~25 MB
            raise HTTPException(413, "import too large (max ~25 MB)")

        # Text-safe decode (UTF-16, etc.)
        content = importers.decode_bytes(raw_bytes)
        if not content.strip():
            raise HTTPException(400, "no content to import")

        # Auto-detect format
        if kind in ("", "auto"):
            kind = detect_import_kind(content, filename)

        if kind == "multiple":
            raise HTTPException(422, "multiple tool outputs detected — import one at a time")
        if kind == "unknown":
            raise HTTPException(422, "format not recognized — pick tool from dropdown")

        # Preview mode: show what would import
        if body.get("preview"):
            return import_preview(kind, content, raw_bytes)

        # BloodHound (.zip, binary): run through recce ad engine
        if kind == "bloodhound" and job_manager:
            from ..cli import recce_argv
            raw = raw_bytes
            is_zip = raw[:2] == b"PK" or filename.lower().endswith(".zip")
            fd, tmp = tempfile.mkstemp(prefix="recce-import-",
                                       suffix=".zip" if is_zip else ".json")
            label = f"ad {filename or kind}"

            def _done_ad(job, _tmp=tmp):
                try:
                    os.remove(_tmp)
                except OSError:
                    pass
                if broker:
                    broker.publish({"type": "scan", "status": job.status,
                                    "tester": x_tester, "targets": label})

            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(raw)
                job = job_manager.start(recce_argv("ad", tmp, "-o", eng.dir), on_done=_done_ad)
            except BaseException:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise

            if broker:
                broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
            return {"mode": "job", "id": job.id, "kind": kind}

        # nmap/loot/fieldkit: run as job for progress streaming
        if kind in ("nmap", "loot", "fieldkit") and job_manager:
            from ..cli import recce_argv

            if kind == "nmap":
                # Detect format from content
                if "<nmaprun" in content[:4000] or content.lstrip().startswith("<?xml"):
                    suffix = ".xml"
                elif re.search(r"^Host:\s+\S+\s+\(", content, re.M):
                    suffix = ".gnmap"
                else:
                    suffix = ".scan"
                cmd = "import"
            else:
                cmd, suffix = {"loot": ("ingest", ".txt"),
                               "fieldkit": ("fieldkit-import", ".json")}[kind]

            fd, tmp = tempfile.mkstemp(prefix="recce-import-", suffix=suffix)
            label = f"{cmd} {filename or kind}"

            def _done(job, _tmp=tmp):
                try:
                    os.remove(_tmp)
                except OSError:
                    pass
                if broker:
                    broker.publish({"type": "scan", "status": job.status,
                                    "tester": x_tester, "targets": label})

            try:
                with os.fdopen(fd, "w", encoding="utf-8", errors="replace") as fh:
                    fh.write(content)
                job = job_manager.start(recce_argv(cmd, tmp, "-o", eng.dir), on_done=_done)
            except BaseException:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise

            if broker:
                broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
            return {"mode": "job", "id": job.id, "kind": kind}

        # Inline parsers: nessus, nuclei, testssl, bloodhound json, creds, etc.
        from ..store import Store
        st = Store(eng.db_path)
        try:
            imported = importers.ingest_output(kind, content, raw_bytes, st, eng.dir)
        finally:
            st.close()

        if broker:
            broker.publish({
                "type": "import",
                "kind": kind,
                "count": imported.get("count", 0),
                "tester": x_tester
            })
        return imported

    @router.get("/playbook")
    def playbook():
        """Shared engagement playbook: phase track, live branches, attack-path narrative."""
        from ..store import Store

        _DEEP_SOURCES = {"sweep", "deepdive", "manual_review"}

        st = Store(eng.db_path)
        try:
            hosts = st.all_hosts()
            creds = st.all_credentials()
        finally:
            st.close()

        up = [h for h in hosts if h.is_up]
        findings = sum(len(h.vulns) for h in up)
        kev = sum(1 for h in up for v in h.vulns if getattr(v, "kev", False))
        enum_done = any(getattr(h, "enumerated", False) for h in up)
        vulns_done = findings > 0 or any(p.vuln_scanned for h in up for p in h.open_ports)
        swept = (any(getattr(h, "db_scanned", False) for h in up)
                 or any(v.source in _DEEP_SOURCES for h in up for v in h.vulns))
        access = [h for h in up if getattr(h, "access_gained", False)]

        def _p(key, label, state, detail, cmd=""):
            return {"key": key, "label": label, "state": state, "detail": detail, "cmd": cmd}

        # Linear spine: enum → vulns → sweep → act → report
        phases = [
            _p("enum", "Enumerate", "done" if enum_done else "todo",
               f"{len(up)} host(s) up", f"recce enum <targets> -o {eng.dir}"),
            _p("vulns", "Vuln-scan", "done" if vulns_done else "todo",
               f"{findings} finding(s), {kev} KEV", f"recce vulns -o {eng.dir}"),
            _p("sweep", "Deep sweep", "done" if swept else "todo",
               "confirm exposures across every service", f"recce sweep -o {eng.dir}"),
            _p("act", "Act / prioritise", "ready" if vulns_done else "locked",
               f"{findings} finding(s) to action", f"recce act -o {eng.dir}"),
            _p("creds", "Credentials", "active" if creds else "locked",
               f"{len(creds)} captured — spray them" if creds else "unlocks when login validates",
               f"recce credsweep -u USER -p PASS -o {eng.dir}" if creds else ""),
            _p("foothold", "Foothold", "active" if access else "locked",
               f"{len(access)} host(s) owned — priv-esc" if access else "unlocks on first access",
               f"recce privesc -o {eng.dir}" if access else ""),
            _p("report", "Report", "ready" if findings else "locked",
               f"{findings} finding(s)", f"recce report -o {eng.dir}"),
        ]

        # Current: the first not-done phase of enum/vulns/sweep
        current = None
        for p in phases[:3]:
            if p["state"] == "todo":
                current = p["key"]
                break

        # Narrative chain: what we discovered, what we escalated, what's next
        narrative = []
        if enum_done:
            narrative.append(f"Enumerated {len(up)} hosts")
        if creds:
            narrative.append(f"Found {len(creds)} credential(s)")
        if access:
            narrative.append(f"Gained access on {len(access)} host(s)")
        if findings:
            narrative.append(f"Identified {findings} finding(s)")

        return {
            "phases": phases,
            "current": current,
            "narrative": narrative,
            "stats": {
                "hosts_up": len(up),
                "findings": findings,
                "kev": kev,
                "credentials": len(creds),
                "access": len(access),
            }
        }

    app.include_router(router)
