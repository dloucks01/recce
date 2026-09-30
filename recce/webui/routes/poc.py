"""Exploit PoC endpoint — surface recce's proof-of-concept generators to the
WebUI Exploit tab. Read-only: assembles the PoC artifacts in memory (recce/act/
poc_web.py) and hands them back; never writes files. Airgap-safe, no external
calls. Registered additions-only from app.py, like prove_endpoint.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query


def register_poc_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path

    @app.get("/api/poc")
    def poc_scripts(scope: str = Query("engagement"), target: str = Query("")):
        """PoC artifacts for a scope — real proof scripts for CONFIRMED findings
        (web PoCs, build recipes, pwntools skeletons). Each: filename, lang,
        source, what it proves, and build/deliver/proof metadata.

        scope: engagement | host (target=ip) | finding (target=finding_key)."""
        from ...core.store import Store
        from ...act import poc_web
        if scope not in ("engagement", "host", "finding"):
            raise HTTPException(400, "scope must be engagement|host|finding")
        if scope in ("host", "finding") and not target.strip():
            raise HTTPException(400, f"scope={scope} needs a target")
        with Store(db_path) as st:
            hosts = st.all_hosts()
        return poc_web.collect(hosts, scope=scope, target=target)
