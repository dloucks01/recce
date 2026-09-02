"""Route modules for webui API.

Error-shape convention (frontend depends on it):

- ``raise HTTPException(status, detail)`` for genuine 4xx/5xx failures — bad
  input, missing resource, upstream error. The client reads ``.detail``.

- ``return {"ok": True, ...}`` / ``return {"ok": False, "reason": "..."}`` ONLY
  for two-outcome business operations where "didn't work" is a first-class
  result the caller wants to display, not an error to raise. Current uses:
  upgrade (stager might not call back), spawn (target might lack python/bash),
  tunnel / port-forward (bind might fail), persistence removal (might already
  be gone). The client reads ``.ok`` and ``.reason``.

Pick one shape per handler. Do not mix both in the same route.
"""
from .engagement import register_engagement_routes
from .scan import register_scan_routes
from .collab import register_collab_routes
from .findings import register_findings_routes
from .report import register_report_routes
from .act_spray import register_act_spray_routes
from .data_exchange import register_data_exchange_routes
from .sessions import register_sessions_routes
from .manage import register_manage_routes
from .bloodhound_export import register_bloodhound_export_routes
from .suggest_digest import register_suggest_digest_routes
from .autocrack_status import register_autocrack_status_routes

__all__ = [
    "register_engagement_routes",
    "register_scan_routes",
    "register_collab_routes",
    "register_findings_routes",
    "register_report_routes",
    "register_act_spray_routes",
    "register_data_exchange_routes",
    "register_sessions_routes",
    "register_manage_routes",
    "register_bloodhound_export_routes",
    "register_suggest_digest_routes",
    "register_autocrack_status_routes",
]
