"""The FastAPI application: a read-only JSON API over a recce engagement store, plus
(when built) the React frontend served as static files.

    from recce.web.app import create_app
    app = create_app("eng/recce.db")     # uvicorn recce.web.app:... or `recce serve`
"""
from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _tier(v) -> str:
    """Confidence tier from QoD, mirroring the report: confirmed / likely / lead."""
    q = getattr(v, "qod", 0) or 0
    if q >= 95:
        return "confirmed"
    if q >= 70:
        return "likely"
    return "lead"


def _finding_dict(v) -> dict:
    return {
        "severity": v.severity or "info",
        "title": v.title or v.script_id or "finding",
        "ip": v.ip,
        "port": v.port,
        "cve": (v.ids[0] if v.ids else ""),
        "cves": list(v.ids or []),
        "kev": bool(getattr(v, "kev", False)),
        "epss": round((getattr(v, "epss", 0.0) or 0.0) * 100),
        "tier": _tier(v),
        "source": v.source,
        "confidence": v.confidence,
    }


def _host_dict(h) -> dict:
    ports = [{"port": p.portid, "proto": p.protocol, "service": p.service,
              "product": (f"{p.product} {p.version}".strip() or p.service)}
             for p in h.open_ports]
    sev_counts: dict[str, int] = {}
    for v in h.vulns:
        sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1
    return {
        "ip": h.ip,
        "hostname": h.hostname or "",
        "os": h.os_name or h.os_family or "",
        "roles": list(h.roles or []),
        "up": h.is_up,
        "ports": ports,
        "findings": sev_counts,
    }


def _load_hosts(store_path: str):
    from ..store import Store
    st = Store(store_path)
    try:
        return st.all_hosts(), (st.get_meta("engagement") or "recce engagement")
    finally:
        st.close()


def create_app(store_path: str) -> FastAPI:
    from .. import __version__
    app = FastAPI(title="recce workbench", version=__version__)
    # Dev convenience: the Vite dev server runs on another port. Harmless on a LAN tool.
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                       allow_headers=["*"])

    @app.get("/api/engagement")
    def engagement():
        hosts, name = _load_hosts(store_path)
        up = [h for h in hosts if h.is_up]
        vulns = [v for h in up for v in h.vulns]
        by_sev: dict[str, int] = {}
        for v in vulns:
            by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
        checked = sum(1 for h in up if getattr(h, "access_gained", False)
                      or getattr(h, "vuln_scanned", False))
        return {
            "name": name,
            "hosts_up": len(up),
            "hosts_total": len(hosts),
            "services": sum(len(h.open_ports) for h in up),
            "findings_by_severity": by_sev,
            "kev": sum(1 for v in vulns if getattr(v, "kev", False)),
            "checked_pct": round(100 * checked / len(up)) if up else 0,
        }

    @app.get("/api/hosts")
    def hosts():
        hs, _ = _load_hosts(store_path)
        return [_host_dict(h) for h in hs if h.is_up]

    @app.get("/api/findings")
    def findings():
        hs, _ = _load_hosts(store_path)
        out = [_finding_dict(v) for h in hs if h.is_up for v in h.vulns]
        out.sort(key=lambda f: (not f["kev"], _SEV_ORDER.get(f["severity"], 9),
                                -f["epss"]))
        return out

    # Serve the built React frontend if it's present (production/airgap bundle).
    dist = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(dist):
        app.mount("/assets", StaticFiles(directory=os.path.join(dist, "assets")),
                  name="assets")

        @app.get("/")
        def index():
            return FileResponse(os.path.join(dist, "index.html"))

    return app
