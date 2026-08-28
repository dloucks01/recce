"""The Act phase (ranked action plan), auto-run, and credential spray."""
from __future__ import annotations

from fastapi import Body, FastAPI


def register_act_spray_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path
    broker = ctx.broker

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
        with Store(db_path) as st:
            hosts = st.all_hosts()
            # Accept either a whitespace-separated string ("10.0.0.1 10.0.0.2")
            # or a list (["10.0.0.1", "10.0.0.2"]). Both are natural JSON shapes
            # a caller might reach for; the frontend sends string, tests use list.
            raw = body.get("targets") or ""
            if isinstance(raw, list):
                tokens = [str(t) for t in raw if t]
            else:
                tokens = str(raw).split()
            if tokens:
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
