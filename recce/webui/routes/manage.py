"""Engagement management: verify, delete, metadata, issues, and scope.

These are the operational endpoints that don't fit the scan/review/report
lifecycle — they manage the engagement itself rather than its findings."""
from __future__ import annotations

import ipaddress
import re

from fastapi import Body, FastAPI, Header, HTTPException

from ..jobs import recce_argv


def register_manage_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path
    jobs = ctx.jobs
    broker = ctx.broker

    # --- verify: confirm/refute version-inference leads ----------------------

    @app.get("/api/verify")
    def verify_plan():
        """Dry-run: which version-inference leads can be settled with a safe
        NSE re-check, and which checks already ran."""
        from ... import qod, verify
        from ...store import Store
        with Store(db_path) as st:
            hosts = st.all_hosts()
        for h in hosts:
            qod.annotate(h)
        pending = []
        already = []
        for h in hosts:
            for p in verify.confirm_plan(h):
                item = {"ip": p["ip"], "port": p["port"], "cve": p["cve"],
                        "finding": p["finding"], "tier": p["tier"],
                        "command": p["command"]}
                if p["ran"]:
                    already.append(item)
                else:
                    pending.append(item)
        return {"pending": len(pending), "already_ran": len(already),
                "plan": pending, "completed": already}

    @app.post("/api/verify")
    def verify_run(x_tester: str = Header(default="someone")):
        """Run the safe (Tier-A/B) NSE re-checks to confirm or refute leads.
        Launches as a background job so the browser streams progress."""
        full_argv = recce_argv("verify", "--run", "-o", eng_dir)
        full_cmd = " ".join(full_argv)
        for j in jobs.list():
            if j.status == "running" and j.cmd == full_cmd:
                raise HTTPException(409, "a verify run is already in progress")

        def _done(job):
            broker.publish({"type": "scan", "status": job.status,
                            "tester": x_tester, "targets": "verify"})

        job = jobs.start(full_argv, on_done=_done)
        broker.publish({"type": "scan_started", "tester": x_tester, "targets": "verify"})
        return {"ok": True, "id": job.id, "status": job.status}

    # --- delete operations ---------------------------------------------------

    @app.delete("/api/host/{ip}")
    def delete_host(ip: str, x_tester: str = Header(default="someone")):
        """Remove a host and all its findings/tracking from the engagement."""
        from ...store import Store
        from .. import collab
        with Store(db_path) as st:
            if not st.delete_host(ip):
                raise HTTPException(404, f"no host with IP {ip}")
            collab.add_activity(st, x_tester, "delete",
                                f"{x_tester} removed host {ip}")
        broker.publish({"type": "delete", "what": "host", "ip": ip,
                        "by": x_tester})
        return {"ok": True, "ip": ip}

    @app.post("/api/delete/credential")
    def delete_credential(body: dict = Body(...),
                          x_tester: str = Header(default="someone")):
        """Remove a credential from the store by its dedupe key."""
        from ...models import Credential
        from ...store import Store
        username = str(body.get("username", ""))
        secret = str(body.get("secret", ""))
        kind = str(body.get("kind", "password"))
        domain = str(body.get("domain", ""))
        ukey = Credential(username=username, secret=secret, kind=kind,
                          domain=domain).dedupe_key()
        with Store(db_path) as st:
            if not st.delete_credential(ukey):
                raise HTTPException(404, "credential not found")
        broker.publish({"type": "delete", "what": "credential", "by": x_tester})
        return {"ok": True}

    @app.post("/api/delete/finding")
    def delete_finding(body: dict = Body(...),
                       x_tester: str = Header(default="someone")):
        """Remove a specific finding from a host."""
        from ...store import Store
        from .. import collab
        ip = str(body.get("ip", "")).strip()
        vuln_key = str(body.get("key", "")).strip()
        if not ip or not vuln_key:
            raise HTTPException(400, "ip and key are required")
        with Store(db_path) as st:
            if not st.remove_finding(ip, vuln_key):
                raise HTTPException(404, "finding not found on that host")
            collab.add_activity(st, x_tester, "delete",
                                f"{x_tester} removed finding {vuln_key} from {ip}")
        broker.publish({"type": "delete", "what": "finding", "ip": ip,
                        "by": x_tester})
        return {"ok": True, "ip": ip, "key": vuln_key}

    # --- engagement metadata -------------------------------------------------

    _META_KEYS = ("engagement", "client", "tester", "scope_notes", "notes",
                  "start_date", "end_date")

    @app.get("/api/meta")
    def get_meta():
        """Return all engagement metadata fields."""
        from ...store import Store
        with Store(db_path) as st:
            data = {k: (st.get_meta(k) or "") for k in _META_KEYS}
        return data

    @app.post("/api/meta")
    def set_meta(body: dict = Body(...),
                 x_tester: str = Header(default="someone")):
        """Set one or more engagement metadata fields."""
        from ...store import Store
        from .. import collab
        updated = []
        with Store(db_path) as st:
            for key in _META_KEYS:
                if key in body:
                    val = str(body[key])[:2000]
                    st.set_meta(key, val)
                    updated.append(key)
            if updated:
                collab.add_activity(st, x_tester, "edit",
                                    f"{x_tester} updated {', '.join(updated)}")
        if not updated:
            raise HTTPException(400, f"no recognized fields (use: {', '.join(_META_KEYS)})")
        broker.publish({"type": "meta", "updated": updated, "by": x_tester})
        return {"ok": True, "updated": updated}

    # --- issues log ----------------------------------------------------------

    @app.get("/api/issues")
    def list_issues():
        """Return all scan issues/warnings, newest first."""
        from ...store import Store
        with Store(db_path) as st:
            issues = st.get_issues()
            counts = st.count_issues()
        return {"issues": issues, "counts": counts}

    # --- scope management ----------------------------------------------------

    @app.get("/api/scope")
    def get_scope():
        """Return all scope subnets."""
        from ...store import Store
        with Store(db_path) as st:
            scope = st.get_scope()
        return [{"subnet": s, "size": n} for s, n in sorted(scope.items())]

    @app.post("/api/scope")
    def add_scope(body: dict = Body(...),
                  x_tester: str = Header(default="someone")):
        """Add a subnet to the engagement scope."""
        from ...store import Store
        from .. import collab
        subnet = str(body.get("subnet", "")).strip()
        if not subnet:
            raise HTTPException(400, "subnet is required")
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            size = net.num_addresses
        except ValueError:
            raise HTTPException(400, f"invalid subnet: {subnet!r}")
        with Store(db_path) as st:
            st.set_scope(str(net), size)
            collab.add_activity(st, x_tester, "add",
                                f"{x_tester} added {net} to scope")
        broker.publish({"type": "scope", "action": "add", "subnet": str(net),
                        "by": x_tester})
        return {"ok": True, "subnet": str(net), "size": size}

    @app.delete("/api/scope/{subnet:path}")
    def remove_scope(subnet: str, x_tester: str = Header(default="someone")):
        """Remove a subnet from the engagement scope."""
        from ...store import Store
        from .. import collab
        with Store(db_path) as st:
            if not st.delete_scope(subnet):
                raise HTTPException(404, f"subnet {subnet!r} not in scope")
            collab.add_activity(st, x_tester, "delete",
                                f"{x_tester} removed {subnet} from scope")
        broker.publish({"type": "scope", "action": "remove", "subnet": subnet,
                        "by": x_tester})
        return {"ok": True, "subnet": subnet}

    # --- per-finding writeup -------------------------------------------------

    @app.get("/api/writeups")
    def list_writeup_findings():
        """List all findings available for write-up (id, severity, title, affected)."""
        from ...report_docx import list_findings
        from ...store import Store
        with Store(db_path) as st:
            hosts = st.all_hosts()
        return {"findings": list_findings(hosts, min_severity="info")}

    @app.post("/api/writeup")
    def generate_writeup(body: dict = Body(...)):
        """Generate a single-finding Word write-up. Returns the file as a download."""
        import os
        from fastapi.responses import FileResponse
        from ...report_docx import build_one_writeup
        from ...store import Store
        selector = str(body.get("selector", "")).strip()
        if not selector:
            raise HTTPException(400, "selector required (finding id, CVE, IP, or title substring)")
        with Store(db_path) as st:
            hosts = st.all_hosts()
        out_dir = os.path.join(eng_dir, "writeups")
        result = build_one_writeup(hosts, out_dir, selector, overwrite=True)
        if result["written"]:
            return FileResponse(
                result["written"],
                media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                filename=os.path.basename(result["written"]))
        if result["reason"] == "none":
            raise HTTPException(404, f"no finding matches {selector!r}")
        if result["reason"] == "ambiguous":
            return {"ok": False, "reason": "ambiguous",
                    "matches": result["matched"]}
        raise HTTPException(500, f"writeup failed: {result.get('reason', 'unknown')}")

    # --- network map ---------------------------------------------------------

    @app.get("/api/netmap.svg")
    def netmap_svg():
        """Network/architecture map as a self-contained SVG."""
        from fastapi.responses import Response
        from ... import netmap
        from ...store import Store
        with Store(db_path) as st:
            hosts = st.all_hosts()
            domains = st.all_domains()
        up = [h for h in hosts if h.is_up]
        if not up:
            return Response(
                "<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/>",
                media_type="image/svg+xml")
        out = netmap.svg(up, domains)
        if "<svg " in out and 'xmlns=' not in out:
            out = out.replace("<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ', 1)
        return Response(out, media_type="image/svg+xml")

    # --- doctor (health check) -----------------------------------------------

    @app.post("/api/doctor")
    def run_doctor(x_tester: str = Header(default="someone")):
        """Run the engagement health check as a background job."""
        full_argv = recce_argv("doctor", "-o", eng_dir)
        full_cmd = " ".join(full_argv)
        for j in jobs.list():
            if j.status == "running" and j.cmd == full_cmd:
                raise HTTPException(409, "doctor is already running")

        def _done(job):
            broker.publish({"type": "scan", "status": job.status,
                            "tester": x_tester, "targets": "doctor"})

        job = jobs.start(full_argv, on_done=_done)
        return {"ok": True, "id": job.id, "status": job.status}

    # --- bulk review ---------------------------------------------------------

    @app.post("/api/bulk-review")
    def bulk_review(body: dict = Body(...),
                    x_tester: str = Header(default="someone")):
        """Mark multiple items as reviewed (or unreviewed) in one call.
        Body: {keys: ["key1", "key2", ...], reviewed: true}"""
        from ...store import Store
        from .. import collab
        keys = body.get("keys", [])
        if not isinstance(keys, list) or not keys:
            raise HTTPException(400, "keys must be a non-empty list")
        if len(keys) > 500:
            raise HTTPException(400, "max 500 keys per call")
        reviewed = bool(body.get("reviewed", True))
        with Store(db_path) as st:
            existing = st.get_tracking()
            items = {}
            for k in keys:
                sk = str(k)
                old_notes = existing.get(sk, (False, ""))[1]
                items[sk] = (reviewed, old_notes)
            n = st.bulk_set_tracking(items)
            collab.add_activity(st, x_tester, "review",
                                f"{x_tester} bulk-{'reviewed' if reviewed else 'unreviewed'} "
                                f"{n} item(s)")
        broker.publish({"type": "bulk_review", "count": n, "reviewed": reviewed,
                        "by": x_tester})
        return {"ok": True, "count": n}

    # --- fieldkit export -----------------------------------------------------

    @app.post("/api/fieldkit-export")
    def fieldkit_export():
        """Generate the fieldkit seed folder and return a zip archive."""
        import io
        import json as _json
        import os
        import time
        import zipfile
        from fastapi.responses import Response
        from ... import fieldkit
        from ...store import Store
        with Store(db_path) as st:
            hosts = [h for h in st.all_hosts() if h.is_up]
            if not hosts:
                raise HTTPException(422, "no live hosts to export — run enum/vulns first")
            title = st.get_meta("engagement") or "recce engagement"
            creds = st.all_credentials()
        bridge = fieldkit.build_bridge(hosts, engagement=title,
                                       generated=time.strftime("%Y-%m-%dT%H:%M:%S"),
                                       creds=creds)
        users = fieldkit.collect_users(hosts, creds)
        cred_lines = fieldkit.collect_creds(creds)
        files = {
            "ports.gnmap": fieldkit.build_gnmap(hosts),
            "smb-null.txt": fieldkit.build_smb_null(hosts),
            "recce-bridge.json": _json.dumps(bridge, indent=2) + "\n",
            "FIELDKIT.md": fieldkit.build_plan_md(bridge),
            "users.txt": ("\n".join(users) + "\n") if users
                         else "# (no usernames enumerated yet)\n",
            "creds.txt": ("# known credentials — domain/user:secret\n"
                          + "\n".join(cred_lines) + "\n") if cred_lines
                         else "# (no captured credentials yet)\n",
        }
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(f"fieldkit/{name}", content)
        buf.seek(0)
        return Response(
            buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": "attachment; filename=fieldkit.zip"})

    # --- engagement backup ---------------------------------------------------

    @app.post("/api/backup")
    def engagement_backup():
        """Download the full engagement directory as a zip archive."""
        import io
        import os
        import zipfile
        from fastapi.responses import Response
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, filenames in os.walk(eng_dir):
                for fname in filenames:
                    fpath = os.path.join(root, fname)
                    try:
                        fsize = os.path.getsize(fpath)
                    except OSError:
                        continue
                    if fsize > 100_000_000:
                        continue
                    arcname = os.path.relpath(fpath, os.path.dirname(eng_dir))
                    zf.write(fpath, arcname)
        buf.seek(0)
        basename = os.path.basename(eng_dir) or "engagement"
        return Response(
            buf.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition":
                      f"attachment; filename={basename}-backup.zip"})

    # --- proxy status --------------------------------------------------------

    @app.get("/api/proxy")
    def proxy_status():
        """Return the current proxy configuration (if any). The proxy is
        process-global — set via `recce serve --proxy URL` or by running
        under proxychains. Individual scans inherit it automatically."""
        from ... import proxy as _proxy
        from ...store import Store
        active = _proxy.is_active()
        desc = _proxy.describe() if active else ""
        with Store(db_path) as st:
            stored = st.get_meta("proxy") or ""
        return {"active": active, "description": desc,
                "stored": stored,
                "hint": ("all scan jobs route through the proxy automatically"
                         if active else
                         "start with `recce serve --proxy socks5h://host:port` "
                         "to route scans through a pivot")}
