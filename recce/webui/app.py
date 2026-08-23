"""FastAPI application - REFACTORED for modularity.

Modular structure:
  - Schemas: type definitions (schemas.py)
  - Helpers: utility functions (helpers.py)
  - Routes: feature modules (routes/)
  - Middleware: error handling, CORS (this file)
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .jobs import JobManager, recce_argv
from .routes import (
    register_engagement_routes,
    register_scan_routes,
    register_collab_routes,
    register_findings_routes,
    register_report_routes,
)
from .helpers import cmd, flag


# ============================================================================
# COMMAND DEFINITIONS (Moved to helpers module as cmd() factory)
# ============================================================================
_COMMANDS = {
    # --- scan phases ---
    "run": cmd("Run — guided full flow", "Scan", "required", profile=True,
               flags=[flag("deep", "--deep", "deep")]),
    "scan": cmd("Scan — enum + vulns", "Scan", "required", profile=True,
                flags=[flag("deep", "--deep", "deep"), flag("fast", "--fast", "fast")]),
    "enum": cmd("Enumerate", "Scan", "required", profile=True,
                flags=[flag("fast", "--fast", "masscan"), flag("all-ports", "--all-ports", "all ports")]),
    "vulns": cmd("Vuln scan", "Scan", "optional",
                 flags=[flag("fast", "--fast", "fast"), flag("aggressive", "--aggressive", "aggressive NSE", True),
                        flag("offline", "--offline", "offline")]),
    "sweep": cmd("Deep sweep — every credential-free module", "Scan", "optional"),
    "credsweep": cmd("Credentialed sweep", "Scan", "optional", creds=True),
    "db": cmd("Database scan (NSE inventory)", "Databases", "optional", creds=True,
              flags=[flag("aggressive", "--aggressive", "aggressive (brute/xp_cmdshell)", True)]),
    # --- databases (native deep modules) ---
    "postgres": cmd("PostgreSQL", "Databases", "optional", creds=True,
                    flags=[flag("prove", "--prove", "prove RCE (benign id, active)", True)]),
    "mysql": cmd("MySQL / MariaDB", "Databases", "optional", creds=True),
    "mongodb": cmd("MongoDB", "Databases", "optional", creds=True),
    "mssql": cmd("MSSQL", "Databases", "optional", creds=True),
    "redis": cmd("Redis", "Databases", "optional"),
    "elasticsearch": cmd("Elasticsearch", "Databases", "optional"),
    "memcached": cmd("memcached", "Databases", "optional"),
    "couchdb": cmd("CouchDB", "Databases", "optional"),
    "influxdb": cmd("InfluxDB", "Databases", "optional"),
    "cassandra": cmd("Cassandra", "Databases", "optional"),
    "oracle": cmd("Oracle TNS", "Databases", "optional"),
    "db2": cmd("IBM Db2", "Databases", "optional"),
    # --- web / web-app ---
    "web": cmd("Web deep-enum", "Web", "optional",
               flags=[flag("crawl", "--crawl", "crawl + inject"),
                      flag("autologin", "--autologin", "auto-login w/ looted creds (active)", True),
                      flag("sqli-time", "--sqli-time", "time-based SQLi", True),
                      flag("upload-shell", "--upload-shell", "upload benign webshell to prove RCE (active, writes a file)", True),
                      flag("smuggle", "--smuggle", "CL.TE/TE.CL smuggling probe (active, may disturb proxies)", True)]),
    "api": cmd("API — OpenAPI enum / IDOR / BOLA", "Web", "optional"),
    # --- other services ---
    "smb": cmd("SMB", "Services", "optional", creds=True),
    "ftp": cmd("FTP", "Services", "optional", creds=True),
    "snmp": cmd("SNMP", "Services", "optional"),
    "ldap": cmd("LDAP", "Services", "optional", creds=True),
    "nfs": cmd("NFS", "Services", "optional"),
    "rsync": cmd("rsync", "Services", "optional"),
    "kerberos": cmd("Kerberos (AS-REP roast)", "Services", "optional"),
    "docker": cmd("Docker API", "Services", "optional"),
    "kubernetes": cmd("Kubernetes", "Services", "optional"),
    "dns": cmd("DNS", "Services", "optional"),
    "smtp": cmd("SMTP", "Services", "optional"),
    # --- AD / credentialed ---
    "credenum": cmd("Credentialed enum (SMB/AD/SSH)", "Credentialed", "optional", creds=True),
    "deploy": cmd("Deploy on-target enum", "Credentialed", "optional", creds=True),
    "privesc": cmd("Priv-esc playbook", "Exploitation", "optional",
                   flags=[flag("scan", "--scan", "remote NSE checks")]),
    # --- exploitation / reporting ---
    "exploitplan": cmd("Exploit plan (msf .rc + commands)", "Exploitation", "optional", lhost=True),
    "poc": cmd("PoC dossiers (per-CVE)", "Exploitation", "optional"),
    "prove": cmd("Prove findings (verdicts)", "Exploitation", "none"),
    "attackpath": cmd("Attack path", "Exploitation", "none"),
    "report": cmd("Rebuild report", "Reporting", "none"),
    "status": cmd("Status / coverage", "Reporting", "none"),
    "services": cmd("Per-service commands", "Reporting", "none"),
    "writeups": cmd("CVE writeups", "Reporting", "optional"),
}


# ============================================================================
# APPLICATION SETUP & MIDDLEWARE
# ============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan hook for startup/shutdown (FastAPI 0.93+)."""
    yield  # Application is running
    # Cleanup on shutdown (if needed)


def create_app(eng_dir: str) -> FastAPI:
    """Create and configure the FastAPI application."""
    from .collab import Collab
    from .jobs import JobManager

    # Load engagement
    from recce.engagement import Engagement
    try:
        eng = Engagement(eng_dir)
    except FileNotFoundError:
        raise RuntimeError(f"Engagement not found: {eng_dir}")

    # Initialize collabor ation & job manager
    collab = Collab()
    job_manager = JobManager(eng)

    # Create FastAPI app
    app = FastAPI(title="recce webui", lifespan=lifespan)

    # ======== MIDDLEWARE ========
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def log_middleware(request, call_next):
        """Log HTTP requests."""
        response = await call_next(request)
        return response

    # ======== REGISTER ROUTE MODULES ========
    register_engagement_routes(app, eng)
    register_scan_routes(app, eng, job_manager, _COMMANDS)
    register_collab_routes(app, collab)
    register_findings_routes(app, eng)
    register_report_routes(app, eng)

    # ======== STATIC FILES & FRONTEND ========
    static_dir = os.path.join(os.path.dirname(__file__), "frontend", "dist")
    if os.path.exists(static_dir):
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="frontend")
    else:
        # Fallback: simple health check
        @app.get("/")
        def health():
            return {"status": "ok", "engine": "recce-webui"}

    return app


if __name__ == "__main__":
    import uvicorn
    app = create_app(".")
    uvicorn.run(app, host="0.0.0.0", port=8080)
