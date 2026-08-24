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
        st = Store(db_path)
        try:
            hosts = st.all_hosts()
        finally:
            st.close()
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
        st = Store(db_path)
        try:
            if not st.delete_host(ip):
                raise HTTPException(404, f"no host with IP {ip}")
            collab.add_activity(st, x_tester, "delete",
                                f"{x_tester} removed host {ip}")
        finally:
            st.close()
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
        st = Store(db_path)
        try:
            if not st.delete_credential(ukey):
                raise HTTPException(404, "credential not found")
        finally:
            st.close()
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
        st = Store(db_path)
        try:
            if not st.remove_finding(ip, vuln_key):
                raise HTTPException(404, "finding not found on that host")
            collab.add_activity(st, x_tester, "delete",
                                f"{x_tester} removed finding {vuln_key} from {ip}")
        finally:
            st.close()
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
        st = Store(db_path)
        try:
            data = {k: (st.get_meta(k) or "") for k in _META_KEYS}
        finally:
            st.close()
        return data

    @app.post("/api/meta")
    def set_meta(body: dict = Body(...),
                 x_tester: str = Header(default="someone")):
        """Set one or more engagement metadata fields."""
        from ...store import Store
        from .. import collab
        st = Store(db_path)
        updated = []
        try:
            for key in _META_KEYS:
                if key in body:
                    val = str(body[key])[:2000]
                    st.set_meta(key, val)
                    updated.append(key)
            if updated:
                collab.add_activity(st, x_tester, "edit",
                                    f"{x_tester} updated {', '.join(updated)}")
        finally:
            st.close()
        if not updated:
            raise HTTPException(400, f"no recognized fields (use: {', '.join(_META_KEYS)})")
        broker.publish({"type": "meta", "updated": updated, "by": x_tester})
        return {"ok": True, "updated": updated}

    # --- issues log ----------------------------------------------------------

    @app.get("/api/issues")
    def list_issues():
        """Return all scan issues/warnings, newest first."""
        from ...store import Store
        st = Store(db_path)
        try:
            issues = st.get_issues()
            counts = st.count_issues()
        finally:
            st.close()
        return {"issues": issues, "counts": counts}

    # --- scope management ----------------------------------------------------

    @app.get("/api/scope")
    def get_scope():
        """Return all scope subnets."""
        from ...store import Store
        st = Store(db_path)
        try:
            scope = st.get_scope()
        finally:
            st.close()
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
        st = Store(db_path)
        try:
            st.set_scope(str(net), size)
            collab.add_activity(st, x_tester, "add",
                                f"{x_tester} added {net} to scope")
        finally:
            st.close()
        broker.publish({"type": "scope", "action": "add", "subnet": str(net),
                        "by": x_tester})
        return {"ok": True, "subnet": str(net), "size": size}

    @app.delete("/api/scope/{subnet:path}")
    def remove_scope(subnet: str, x_tester: str = Header(default="someone")):
        """Remove a subnet from the engagement scope."""
        from ...store import Store
        from .. import collab
        st = Store(db_path)
        try:
            if not st.delete_scope(subnet):
                raise HTTPException(404, f"subnet {subnet!r} not in scope")
            collab.add_activity(st, x_tester, "delete",
                                f"{x_tester} removed {subnet} from scope")
        finally:
            st.close()
        broker.publish({"type": "scope", "action": "remove", "subnet": subnet,
                        "by": x_tester})
        return {"ok": True, "subnet": subnet}
