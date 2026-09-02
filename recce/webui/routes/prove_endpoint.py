"""Per-finding T2 verification probe — the WebUI twin of `recce prove`.

The Exploit Surface tab lets a tester click "Prove" on a single T1
finding; that click POSTs here and the same recipe the CLI's
`recce prove` would run is executed for that one finding. Nothing here
exploits anything — it re-checks the evidence recce already collected
and returns a verdict + evidence lines.

Two endpoints:

* ``GET  /api/prove/available`` — the set of `finding_key`s whose vuln
  has a proof recipe. The frontend uses this so the "Prove" button
  renders only on rows recce actually knows how to prove.
* ``POST /api/prove/{finding_key}`` — run the recipe for that one
  finding; returns ``{verdict, evidence, finish, ...}``.

Both share ``recce.act.prove_dispatch``, which is also the module the
CLI's `cmd_prove` walks per host via ``proofs.verify_hosts``.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException

from ...act import prove_dispatch
from ...core.store import Store


def register_prove_endpoint_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path

    @app.get("/api/prove/available")
    def prove_available():
        """Every finding_key on this engagement whose vuln has a proof
        recipe. The Exploit Surface tab reads this once on mount so the
        "Prove" button only appears next to rows we can actually prove
        (avoids a click that would 404)."""
        with Store(db_path) as st:
            hosts = st.all_hosts()
        keys = prove_dispatch.provable_keys(hosts)
        return {"keys": keys, "total": len(keys)}

    @app.post("/api/prove/{finding_key:path}")
    def prove_finding(finding_key: str):
        """Run the T2 verification recipe for one finding. Body-less —
        the whole selection is the `finding_key` (a Vulnerabilities-sheet
        row key from ``core.tracking.vuln_row_key``).

        Returns the same verdict record `proofs.verify_host` emits per
        vuln: ``{verdict, evidence, finish, preconditions, fp, ...}``.
        404 when no vuln in the store carries that key."""
        if not (finding_key or "").strip():
            raise HTTPException(400, "finding_key required")
        with Store(db_path) as st:
            hosts = st.all_hosts()
        result = prove_dispatch.prove_finding_key(hosts, finding_key)
        if result is None:
            raise HTTPException(404, f"no finding matches key {finding_key!r}")
        return result
