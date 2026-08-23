"""Route modules for webui API."""
from .engagement import register_engagement_routes
from .scan import register_scan_routes
from .collab import register_collab_routes
from .findings import register_findings_routes
from .report import register_report_routes

__all__ = [
    "register_engagement_routes",
    "register_scan_routes",
    "register_collab_routes",
    "register_findings_routes",
    "register_report_routes",
]
