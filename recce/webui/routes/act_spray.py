"""ACT phase + credential spray routes."""

from fastapi import APIRouter, Body, HTTPException

router = APIRouter(prefix="/api", tags=["act-spray"])


def register_act_spray_routes(app, eng, broker=None):
    """Register act and spray routes on the app."""

    @router.get("/act")
    def act_plan():
        """The Act phase: findings → ranked, guided action plan."""
        from .. import act
        from ..store import Store
        db_path = eng.db_path
        eng_dir = eng.dir
        st = Store(db_path)
        try:
            hosts, creds = st.all_hosts(), st.all_credentials()
        finally:
            st.close()
        cards = act.action_plan(hosts, creds, eng_dir)
        tiers = {}
        for c in cards:
            tiers.setdefault(c.tier, []).append(_card_dict(c))
        return {
            "top": [_card_dict(c) for c in act.top_moves(cards, 5)],
            "tiers": [
                {"tier": t, "label": act._TIER_LABEL[t], "cards": tiers[t]}
                for t in sorted(tiers)
            ]
        }

    @router.post("/act/run")
    def act_run():
        """Execute AUTO (read-only/reversible) actions: loot unauth services."""
        from .. import act
        from ..store import Store
        db_path = eng.db_path
        eng_dir = eng.dir
        st = Store(db_path)
        try:
            summary = act.execute_auto(st, eng_dir)
        finally:
            st.close()
        spray = summary.get("spray") or {}
        if broker:
            broker.publish({"type": "act_run", "looted": len(summary["looted"])})
        return {
            "looted": len(summary["looted"]),
            "creds": [{"label": c.label, "source": c.source} for c in summary["looted"]],
            "spray_files": sorted((spray.get("files") or {}).keys())
        }

    @router.post("/spray")
    def spray(body: dict = Body(default=None)):
        """Run lockout-safe spray of looted creds across target scope."""
        from .. import credentials as cr
        from ..cli import ip_matcher
        from ..models import Credential
        from ..store import Store
        db_path = eng.db_path
        eng_dir = eng.dir
        body = body or {}
        st = Store(db_path)
        res = {"ok": False, "error": "spray not initialized", "hits": [], "new": 0}
        try:
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
                res["new"] = new
        finally:
            st.close()
        if broker:
            broker.publish({"type": "spray", "hits": len(res.get("hits", []))})
        return res

    app.include_router(router)


def _card_dict(c):
    """Convert action card to dict."""
    return {
        "tier": c.tier,
        "title": c.title,
        "detail": c.detail,
        "guidance": c.guidance,
        "count": c.count,
        "risky": c.risky,
    }
