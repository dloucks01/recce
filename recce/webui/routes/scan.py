"""Scan jobs + live progress + the command catalog."""
from __future__ import annotations

import asyncio
import json

from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse

from ..jobs import recce_argv
from .._common import _COMMANDS


def register_scan_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    jobs = ctx.jobs
    broker = ctx.broker

    @app.get("/api/commands")
    def list_commands():
        """The command surface the UI renders its runner from (grouped, with the fields/
        flags each command accepts)."""
        return {k: {kk: v[kk] for kk in
                    ("label", "group", "targets", "profile", "creds", "lhost", "flags")}
                for k, v in _COMMANDS.items()}

    @app.post("/api/scan")
    def start_scan(body: dict = Body(...), x_tester: str = Header(default="someone")):
        # `command` (any catalog entry); `phase` kept for older clients.
        command = str(body.get("command") or body.get("phase") or "run")
        spec = _COMMANDS.get(command)
        if spec is None:
            raise HTTPException(400, f"unknown command {command!r}")
        # Targets: whitespace-split, drop any token starting with '-' (no flag injection).
        targets = [t for t in str(body.get("targets", "")).split() if not t.startswith("-")]
        if spec["targets"] == "required" and not targets:
            raise HTTPException(400, "this command needs targets")
        argv = [command, "-o", eng_dir]
        if spec["profile"]:
            profile = str(body.get("profile", "")).lower()
            if profile in ("quick", "standard", "thorough"):
                argv += ["--profile", profile]
        if spec["creds"]:
            user = str(body.get("username", "")).strip()
            if user:
                argv += ["-u", user]
                pw = body.get("password")
                if pw not in (None, ""):
                    argv += ["-p", str(pw)]
                dom = str(body.get("domain", "")).strip()
                if dom:
                    argv += ["-d", dom]
        if spec["lhost"]:
            lh = str(body.get("lhost", "")).strip()
            if lh:
                argv += ["--lhost", lh]
        # Only pass flags this command declares (silently drop anything else).
        allowed = {f["name"]: f["flag"] for f in spec["flags"]}
        for name in (body.get("flags") or []):
            if name in allowed and allowed[name] not in argv:
                argv.append(allowed[name])
        if spec["targets"] != "none":
            argv += targets
        label = f"{command} {' '.join(targets)}".strip()
        full_argv = recce_argv(*argv)
        full_cmd = " ".join(full_argv)
        for j in jobs.list():
            if j.status == "running" and j.cmd == full_cmd:
                raise HTTPException(409, "an identical scan is already running")

        def _done(job):
            broker.publish({"type": "scan", "status": job.status, "tester": x_tester,
                            "targets": label})

        job = jobs.start(full_argv, on_done=_done)
        broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
        return {"id": job.id, "status": job.status, "cmd": job.cmd}

    @app.post("/api/jobs/{jid}/cancel")
    def cancel_job(jid: str):
        if not jobs.cancel(jid):
            raise HTTPException(404, "no running job with that id")
        return {"ok": True}

    @app.get("/api/jobs")
    def list_jobs():
        return [{"id": j.id, "cmd": j.cmd, "status": j.status, "lines": len(j.lines),
                 "started": j.started} for j in jobs.list()]

    @app.get("/api/jobs/{jid}/events")
    async def job_events(jid: str):
        job = jobs.get(jid)
        if job is None:
            raise HTTPException(404, "no such job")

        async def gen():
            i = 0
            while True:
                while i < len(job.lines):
                    yield f"data: {json.dumps({'line': job.lines[i]})}\n\n"
                    i += 1
                if job.status != "running":
                    yield f"data: {json.dumps({'done': True, 'status': job.status})}\n\n"
                    return
                await asyncio.sleep(0.3)

        return StreamingResponse(gen(), media_type="text/event-stream")
