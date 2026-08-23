"""Routes: scan jobs, commands, job streaming."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from ..schemas import ScanPayload, ScanJob

router = APIRouter(prefix="/api", tags=["scanning"])


def register_scan_routes(app, eng, job_manager, COMMANDS):
    """Register scan routes on the app."""

    @router.get("/commands")
    def list_commands():
        """Get all available commands."""
        return {
            cmd_name: {
                "label": cmd.label,
                "group": cmd.group,
                "targets": cmd.targets,
                "profile": cmd.profile,
                "creds": cmd.creds,
                "lhost": cmd.lhost,
                "flags": [f.model_dump() for f in cmd.flags],
            }
            for cmd_name, cmd in COMMANDS.items()
        }

    @router.post("/scan")
    def start_scan(payload: ScanPayload):
        """Start a new scan job."""
        if payload.cmd not in COMMANDS:
            raise HTTPException(status_code=400, detail=f"Unknown command: {payload.cmd}")

        # Build argv from command definition and payload
        argv = ["recce", payload.cmd]

        if payload.targets and payload.targets != "none":
            argv.append(payload.targets)

        if payload.flags:
            argv.extend(payload.flags)

        if payload.creds:
            # Creds passed separately, will be handled by job manager
            pass

        if payload.lhost:
            argv.extend(["-lhost", payload.lhost])

        # Start the job
        job_id = job_manager.add_job(argv, {"creds": payload.creds or {}})
        return {"job_id": job_id, "status": "queued"}

    @router.get("/jobs")
    def list_jobs():
        """Get all jobs (running and completed)."""
        jobs = []
        for jid, job in job_manager.jobs.items():
            jobs.append({
                "id": jid,
                "cmd": " ".join(job["cmd"][:3]),  # First 3 tokens
                "status": job["status"],
                "started": job["started"],
                "ended": job.get("ended"),
                "tester": job.get("tester", ""),
            })
        return jobs

    @router.get("/jobs/{jid}/events")
    def stream_job_events(jid: str):
        """Stream job events via SSE."""
        if jid not in job_manager.jobs:
            raise HTTPException(status_code=404, detail=f"Job not found: {jid}")

        job = job_manager.jobs[jid]

        async def event_generator():
            last_line = 0
            while True:
                current_lines = len(job.get("log", []))
                if current_lines > last_line:
                    for i in range(last_line, current_lines):
                        line = job["log"][i]
                        yield f"data: {line}\n\n"
                    last_line = current_lines

                if job["status"] in ("done", "failed"):
                    yield f"event: done\ndata: {job['status']}\n\n"
                    break

                await asyncio.sleep(0.5)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    app.include_router(router)


import asyncio
