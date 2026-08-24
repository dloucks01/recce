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
        from ...store import Store
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
        run. Returns what was looted so the UI can point the operator at the Loot tab."""
        from ... import act
        from ...store import Store
        with Store(db_path) as st:
            summary = act.execute_auto(st, eng_dir)
        spray = summary.get("spray") or {}
        broker.publish({"type": "act_run", "looted": len(summary["looted"])})
        return {"looted": len(summary["looted"]),
                "creds": [{"label": c.label, "source": c.source} for c in summary["looted"]],
                "spray_files": sorted((spray.get("files") or {}).keys())}

    @app.post("/api/spray")
    def spray(body: dict = Body(default=None)):
        """Run a lockout-safe spray of the looted/stacked creds across a target scope
        (one IP / range / all), fold the validated logins. safe=false = full user x pass."""
        from ... import credentials as cr
        from ...cli import ip_matcher
        from ...models import Credential
        from ...store import Store
        body = body or {}
        with Store(db_path) as st:
            hosts = st.all_hosts()
            sel = (body.get("targets") or "").strip()
            if sel:
                match = ip_matcher(sel.split())
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
