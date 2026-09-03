"""The Act phase (ranked action plan), auto-run, and credential spray."""
from __future__ import annotations

from fastapi import Body, FastAPI, HTTPException


def register_act_spray_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path
    broker = ctx.broker
    jobs = ctx.jobs

    def _card_dict(c):
        return {"archetype": c.archetype, "title": c.title, "target": c.target,
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
        with Store(db_path) as st:
            hosts, creds = st.all_hosts(), st.all_credentials()
        cards = act.action_plan(hosts, creds, eng_dir)
        tiers: dict = {}
        for c in cards:
            tiers.setdefault(c.tier, []).append(_card_dict(c))
        return {"top": [_card_dict(c) for c in act.top_moves(cards, 5)],
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
    def act_run_async():
        """P7-C1: non-blocking act/run. Returns {id, cmd, status}; caller
        polls /api/jobs/{jid} to get the same shape /api/act/run returns
        synchronously, once status flips to `done`."""
        from ..jobs import TooManyJobs
        try:
            job = jobs.start_callable("act --run", _do_act_run)
        except TooManyJobs as e:
            raise HTTPException(429, str(e))
        broker.publish({"type": "job_started", "kind": "act_run",
                        "job_id": job.id})
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
            broker.publish({"type": "spray", "hits": len(res.get("hits", []))})
            return {"ok": res.get("ok", False), "error": res.get("error", ""),
                    "hits": res.get("hits", []), "new": new}

    @app.post("/api/spray/async")
    def spray_async(body: dict = Body(default=None)):
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
                        "job_id": job.id})
        return {"id": job.id, "status": job.status, "cmd": job.cmd}
