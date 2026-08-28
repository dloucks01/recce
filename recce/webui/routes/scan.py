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

    @app.get("/api/wordlists")
    def list_wordlists(kind: str | None = None):
        """The bundled wordlist catalog. Frontend renders these as a
        dropdown next to the free-text `--wordlist FILE` input. `kind`
        query param filters to a single family (paths / creds / users) so
        the postgres card's dropdown doesn't show HTTP path lists."""
        from ...services.wordlists import list_bundled
        return {"wordlists": list_bundled(kind)}

    @app.post("/api/scan")
    def start_scan(body: dict = Body(...), x_tester: str = Header(default="someone")):
        # `command` (any catalog entry); `phase` kept for older clients.
        command = str(body.get("command") or body.get("phase") or "run")
        spec = _COMMANDS.get(command)
        if spec is None:
            raise HTTPException(400, f"unknown command {command!r}")
        # Targets: split on whitespace OR commas (the field placeholder invites
        # comma lists — "10.0.0.0/24, 10.0.0.5, hostname"). Empty tokens
        # dropped; anything starting with '-' dropped (no flag injection).
        import re as _re
        targets = [t for t in _re.split(r"[\s,]+", str(body.get("targets", "")))
                   if t and not t.startswith("-")]
        if spec["targets"] == "required" and not targets:
            raise HTTPException(400, "this command needs targets")
        argv = [command, "-o", eng_dir]
        if spec["profile"]:
            profile = str(body.get("profile", "")).lower()
            if profile in ("quick", "standard", "thorough", "stealth"):
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
        # Boolean flags: silent-drop anything not in the catalog.
        allowed = {f["name"]: f for f in spec["flags"]}
        for name in (body.get("flags") or []):
            f = allowed.get(name)
            if f and f.get("kind", "bool") == "bool" and f["flag"] not in argv:
                argv.append(f["flag"])
        # Value-carrying flags: `flag_values: {name: value}`. Splits list-kind
        # inputs on whitespace/commas so `--skip mssql,docker` becomes
        # `--skip mssql docker` (nargs='*' on the parser side).
        import re as _re
        used_list_flag = False
        for name, raw in (body.get("flag_values") or {}).items():
            f = allowed.get(name)
            if f is None or f.get("kind", "bool") == "bool":
                continue
            val = str(raw).strip()
            if not val:
                continue
            kind = f.get("kind", "bool")
            if kind == "int":
                try:
                    int(val)
                except ValueError:
                    continue                     # bad int → drop silently
                argv += [f["flag"], val]
            elif kind == "list":
                toks = [t for t in _re.split(r"[\s,]+", val) if t and not t.startswith("-")]
                if toks:
                    argv += [f["flag"], *toks]
                    used_list_flag = True
            elif kind == "wordlist":
                # Same wire shape as "text"; the wordlist loader on the
                # backend resolves `bundled:<name>` to an on-disk path.
                # Refuse dash-leading values (no flag injection) and refuse
                # `bundled:<name>` where the name isn't in the registry —
                # a typo shouldn't silently degrade to "no wordlist".
                if val.startswith("-"):
                    continue
                if val.startswith("bundled:"):
                    from ...services.wordlists import BUNDLED_WORDLISTS
                    name = val[len("bundled:"):].strip()
                    known = {e["name"] for e in BUNDLED_WORDLISTS}
                    if name not in known:
                        continue                # bad bundled name → drop
                argv += [f["flag"], val]
            else:                                # "text"
                if not val.startswith("-"):
                    argv += [f["flag"], val]
        if spec["targets"] != "none":
            # `--` separator when a list-kind flag was used: those flags declare
            # nargs='*' on the parser side, so argparse would otherwise eat the
            # trailing target IP into the list (--skip mssql 10.0.0.1 → skip=
            # [mssql, 10.0.0.1], no target). The explicit terminator forces
            # argparse to stop consuming for the option and treat what follows
            # as positionals.
            if used_list_flag:
                argv.append("--")
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
