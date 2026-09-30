"""The Act phase (ranked action plan), auto-run, and credential spray."""
from __future__ import annotations

from fastapi import Body, FastAPI, Header, HTTPException


def register_act_spray_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path
    broker = ctx.broker
    jobs = ctx.jobs

    def _tool_cmd(c, creds, domain, ports_by_ip):
        """The raw external-tool command a `recce <cmd>` action wraps, filled with
        the engagement's real data (target, that host's open ports, AD realm, and
        a credential ONLY when it's correct for this command+host — see
        toolcmd._pick_credential). Empty when the action's command is already a
        concrete tool invocation (msfconsole/certipy/impacket/…)."""
        from ...services import toolcmd
        cmd = (c.command or "").strip()
        if not cmd.startswith("recce "):
            return ""                       # already a real tool command
        sub = cmd.split()[1] if len(cmd.split()) > 1 else ""
        ip, _, port = (c.target or "").partition(":")
        if ip in ("", "engagement", "active-directory"):
            ip = "<target>"
        return toolcmd.for_command(sub, ip, port, creds=creds, domain=domain,
                                   ports=ports_by_ip.get(ip, ""))

    def _spray_hint(c, tool_cmd, creds):
        """Reuse candidates: a lockout-safe spray of the engagement's found secrets
        against this host's auth service — a password captured elsewhere may be
        reused here, and spraying confirms it. Shown on any per-host auth action
        (a `recce <svc>` wrapper or a raw `nxc <proto>` command) UNLESS a found
        secret is already asserted in the command (a confident credential)."""
        import re
        from ...services import toolcmd
        cmd = c.command or ""
        ip = (c.target or "").partition(":")[0]
        if not ip or ip in ("engagement", "active-directory"):
            return ""
        proto = ""
        if cmd.startswith("recce "):
            parts = cmd.split()
            proto = toolcmd._SPRAY_PROTO.get(parts[1] if len(parts) > 1 else "", "")
        else:
            m = re.search(r"\bnxc\s+(smb|winrm|ldap|mssql|rdp|ssh)\b", cmd)
            proto = m.group(1) if m else ""
        if not proto:
            return ""
        # already using a found secret here? then it's not a blind reuse test.
        secrets = [x.secret for x in toolcmd._usable_creds(creds) if x.secret]
        if any(s in cmd or (tool_cmd and s in tool_cmd) for s in secrets):
            return ""
        return toolcmd.spray_candidates(proto, ip, creds)

    def _card_dict(c, creds=None, domain="", ports_by_ip=None):
        tc = _tool_cmd(c, creds or [], domain, ports_by_ip or {})
        return {"key": c.key, "tool_cmd": tc,
                "spray_hint": _spray_hint(c, tc, creds or []),
                "archetype": c.archetype, "title": c.title, "target": c.target,
                "command": c.command, "yields": c.yields, "safety": c.safety,
                "tier": c.tier, "score": c.score, "count": c.count,
                "attack_id": c.attack_id, "attack_name": c.attack_name, "cwe": c.cwe,
                "verify_first": c.verify_first, "why": c.why,
                "needs": [d for d, met in c.preconditions if not met]}

    @app.get("/api/act")
    def act_plan():
        """The Act phase: findings -> ranked, guided action plan. 'What do I do now?'."""
        from ... import act
        from ...core.store import Store
        from ...services import toolcmd
        with Store(db_path) as st:
            hosts, creds = st.all_hosts(), st.all_credentials()
        domain = toolcmd.discovered_domain(hosts, creds)
        ports_by_ip = {h.ip: ",".join(str(p.portid) for p in sorted(
            h.open_ports, key=lambda p: p.portid)) for h in hosts}
        cards = act.action_plan(hosts, creds, eng_dir)
        tiers: dict = {}
        for c in cards:
            tiers.setdefault(c.tier, []).append(_card_dict(c, creds, domain, ports_by_ip))
        return {"top": [_card_dict(c, creds, domain, ports_by_ip) for c in act.top_moves(cards, 5)],
                "tiers": [{"tier": t, "label": act._TIER_LABEL[t], "cards": tiers[t]}
                          for t in sorted(tiers)]}

    @app.post("/api/act/run")
    def act_run():
        """Execute the AUTO (read-only / reversible) links: loot the flagged unauth
        services, refresh the spray plan, feed yields back. Intrusive actions are never
        run. Returns rich context so the UI can tell the operator EXACTLY what
        happened, not just "0 new" (which reads as "broken" when the store
        already holds the harvest from a previous pass)."""
        from ... import act
        from ...core.store import Store
        with Store(db_path) as st:
            existing_before = len(st.all_credentials())
            summary = act.execute_auto(st, eng_dir)
            existing_after = len(st.all_credentials())
            # Count findings that ALREADY describe credentials so the UI can
            # say "you have N creds already captured from earlier passes"
            # instead of a bare "0 new".
            findings_with_creds = 0
            for h in st.all_hosts():
                for v in h.vulns:
                    if any(k in (v.title or "").lower() for k in (
                            "hash", "credential", "password", "cred", "trust auth",
                            "default cred", "sa password")):
                        findings_with_creds += 1
        spray = summary.get("spray") or {}
        looted = summary.get("looted") or []
        broker.publish({"type": "act_run", "looted": len(looted)})
        # Build a plain-English summary the frontend can render verbatim.
        parts: list[str] = []
        if looted:
            parts.append(f"Collected {len(looted)} new credential(s)")
        elif existing_after > 0:
            parts.append(
                f"Nothing new — {existing_after} credential(s) already in the store"
                f" from earlier passes")
        else:
            parts.append("Nothing looted — no unauth loot surface was reachable")
        if spray.get("files"):
            parts.append(f"Spray plan refreshed ({len(spray['files'])} file(s))")
        if findings_with_creds:
            parts.append(f"{findings_with_creds} finding(s) describe recoverable "
                         "credentials — see Findings")
        return {
            "looted": len(looted),
            "existing_before": existing_before,
            "existing_after": existing_after,
            "findings_with_creds": findings_with_creds,
            "summary": ". ".join(parts) + ".",
            "creds": [{"label": c.label, "source": c.source} for c in looted],
            "spray_files": sorted((spray.get("files") or {}).keys()),
        }

    @app.post("/api/spray")
    def spray(body: dict = Body(default=None)):
        """Run a lockout-safe spray of the looted/stacked creds across a target scope
        (one IP / range / all), fold the validated logins. safe=false = full user x pass."""
        from ...creds import credentials as cr
        from ...cli import ip_matcher
        from ...core.models import Credential
        from ...core.store import Store
        body = body or {}
        # P7-A1: reject empty targets rather than silently spraying every
        # host in scope. Historically a `{"targets": []}` (or missing
        # field, or empty string) fell through the `if tokens:` guard
        # below and applied no host filter — one typo away from a big
        # accidental spray. The frontend always passes a real target; a
        # caller who genuinely wants "everything" can pass an explicit
        # `--all` sentinel (below).
        raw = body.get("targets", "")
        if isinstance(raw, list):
            tokens = [str(t).strip() for t in raw if str(t).strip()]
        else:
            tokens = str(raw).split()
        if not tokens:
            raise HTTPException(
                400, "targets required — pass a CIDR / range / IP / "
                "hostname list. To spray every discovered host on purpose, "
                "pass targets=['--all'] explicitly.")
        # Sentinel: explicit opt-in for "every discovered host". Keeps the
        # capability accessible without making it the default behavior.
        all_hosts = tokens == ["--all"]
        with Store(db_path) as st:
            hosts = st.all_hosts()
            if not all_hosts:
                match = ip_matcher(tokens)
                hosts = [h for h in hosts if match(h.ip)]
            creds = cr.stack(hosts, st.all_credentials())
            res = cr.run_spray(hosts, creds, eng_dir, safe=body.get("safe", True))
            new = 0
            if res.get("ok"):
                for h in res["hits"]:
                    if st.add_credential(Credential(
                            username=h["user"], secret=h["secret"], kind="password",
                            source="spray-validated", origin_ip=h["ip"],
                            notes=f"validated over {h['proto']}"
                                  + (" (local admin)" if h["admin"] else ""))):
                        new += 1
                        # P7-C3: per-hit event so every open tab surfaces a
                        # toast for each fresh credential (`cred_captured`
                        # is the general term; `spray_hit` gives the spray
                        # source so a toast can say "spray hit on host X"
                        # rather than the generic add path).
                        broker.publish({"type": "spray_hit",
                                        "user": h["user"], "ip": h["ip"],
                                        "proto": h["proto"],
                                        "admin": bool(h["admin"])})
            broker.publish({"type": "spray", "hits": len(res.get("hits", []))})
            return {"ok": res.get("ok", False), "error": res.get("error", ""),
                    "hits": res.get("hits", []), "new": new}

    # ----- P7-C1: async variants that return a job id ------------------------
    # /api/spray and /api/act/run above block the HTTP request for the full
    # duration of the underlying work (netexec spray = a few minutes on a big
    # scope; act.execute_auto = ~1 min if it needs to loot several services).
    # These async variants spawn the same work as callable Jobs, return a
    # {id, cmd, status} handle immediately, and let the caller poll via
    # /api/jobs/{jid} or stream stdout via /api/jobs/{jid}/events. Sync
    # variants stay for callers (tests, tiny scopes) that want the rich
    # response inline.

    def _do_act_run():
        from ... import act
        from ...core.store import Store
        with Store(db_path) as st:
            existing_before = len(st.all_credentials())
            summary = act.execute_auto(st, eng_dir)
            existing_after = len(st.all_credentials())
            findings_with_creds = 0
            for h in st.all_hosts():
                for v in h.vulns:
                    if any(k in (v.title or "").lower() for k in (
                            "hash", "credential", "password", "cred",
                            "trust auth", "default cred", "sa password")):
                        findings_with_creds += 1
        spray = summary.get("spray") or {}
        looted = summary.get("looted") or []
        broker.publish({"type": "act_run", "looted": len(looted)})
        parts: list[str] = []
        if looted:
            parts.append(f"Collected {len(looted)} new credential(s)")
        elif existing_after > 0:
            parts.append(
                f"Nothing new — {existing_after} credential(s) already in "
                f"the store from earlier passes")
        else:
            parts.append("Nothing looted — no unauth loot surface was reachable")
        if spray.get("files"):
            parts.append(f"Spray plan refreshed ({len(spray['files'])} file(s))")
        if findings_with_creds:
            parts.append(f"{findings_with_creds} finding(s) describe recoverable "
                         "credentials — see Findings")
        return {
            "looted": len(looted),
            "existing_before": existing_before,
            "existing_after": existing_after,
            "findings_with_creds": findings_with_creds,
            "summary": ". ".join(parts) + ".",
            "creds": [{"label": c.label, "source": c.source} for c in looted],
            "spray_files": sorted((spray.get("files") or {}).keys()),
        }

    @app.post("/api/act/run/async")
    def act_run_async(x_tester: str = Header(default="someone")):
        """P7-C1: non-blocking act/run. Returns {id, cmd, status}; caller
        polls /api/jobs/{jid} to get the same shape /api/act/run returns
        synchronously, once status flips to `done`."""
        from ..jobs import TooManyJobs
        try:
            job = jobs.start_callable("act --run", _do_act_run)
        except TooManyJobs as e:
            raise HTTPException(429, str(e))
        broker.publish({"type": "job_started", "kind": "act_run",
                        "job_id": job.id, "tester": x_tester})
        return {"id": job.id, "status": job.status, "cmd": job.cmd}

    def _do_spray(tokens: list[str], safe: bool, all_hosts: bool):
        from ...creds import credentials as cr
        from ...cli import ip_matcher
        from ...core.models import Credential
        from ...core.store import Store
        with Store(db_path) as st:
            hosts = st.all_hosts()
            if not all_hosts:
                match = ip_matcher(tokens)
                hosts = [h for h in hosts if match(h.ip)]
            creds = cr.stack(hosts, st.all_credentials())
            res = cr.run_spray(hosts, creds, eng_dir, safe=safe)
            new = 0
            if res.get("ok"):
                for h in res["hits"]:
                    if st.add_credential(Credential(
                            username=h["user"], secret=h["secret"], kind="password",
                            source="spray-validated", origin_ip=h["ip"],
                            notes=f"validated over {h['proto']}"
                                  + (" (local admin)" if h["admin"] else ""))):
                        new += 1
                        # P7-C3: per-hit event so every open tab surfaces a
                        # toast for each fresh credential (`cred_captured`
                        # is the general term; `spray_hit` gives the spray
                        # source so a toast can say "spray hit on host X"
                        # rather than the generic add path).
                        broker.publish({"type": "spray_hit",
                                        "user": h["user"], "ip": h["ip"],
                                        "proto": h["proto"],
                                        "admin": bool(h["admin"])})
            broker.publish({"type": "spray", "hits": len(res.get("hits", []))})
            return {"ok": res.get("ok", False), "error": res.get("error", ""),
                    "hits": res.get("hits", []), "new": new}

    @app.post("/api/spray/async")
    def spray_async(body: dict = Body(default=None),
                    x_tester: str = Header(default="someone")):
        """P7-C1: non-blocking spray. Same target-parse + `--all` sentinel
        rules as /api/spray. Returns {id, cmd, status}; caller polls
        /api/jobs/{jid} for the full result."""
        from ..jobs import TooManyJobs
        body = body or {}
        raw = body.get("targets", "")
        if isinstance(raw, list):
            tokens = [str(t).strip() for t in raw if str(t).strip()]
        else:
            tokens = str(raw).split()
        if not tokens:
            raise HTTPException(
                400, "targets required — pass a CIDR / range / IP / "
                "hostname list. To spray every discovered host on purpose, "
                "pass targets=['--all'] explicitly.")
        all_hosts = tokens == ["--all"]
        safe = bool(body.get("safe", True))
        label = ("spray " + ("--all" if all_hosts else " ".join(tokens))
                 + ("" if safe else " (full)"))
        try:
            job = jobs.start_callable(label, _do_spray, tokens, safe, all_hosts)
        except TooManyJobs as e:
            raise HTTPException(429, str(e))
        broker.publish({"type": "job_started", "kind": "spray",
                        "job_id": job.id, "tester": x_tester})
        return {"id": job.id, "status": job.status, "cmd": job.cmd}
