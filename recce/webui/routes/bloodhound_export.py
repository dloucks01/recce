"""BloodHound export endpoint.

Serves the same zip the CLI command ``recce bloodhound-push`` produces so the
operator can drag-drop recce's scan intel into BloodHound-CE without dropping
back to the terminal. Read-only against the engagement store; the underlying
writer (``recce.ad.bloodhound_push.build_zip``) never mutates it.

Response:
  * 200 + ``application/zip`` + ``Content-Disposition: attachment;
    filename="bloodhound-<engagement>.zip"`` when the store carries any AD
    node (user / computer / group / domain).
  * 404 with ``detail`` when the store is empty of AD data, so the frontend
    can render the button disabled with a "no AD data yet" hint.

The 404 is deliberate: an empty push is a valid file (seven zero-count JSON
files), but downloading it just to open a "there's nothing here" zip is worse
UX than telling the user upfront to run an enum/import first.
"""
from __future__ import annotations

import re
import tempfile

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response


# Filename sanitiser: keep letters/digits/dash/underscore/dot; every other run
# collapses to a single dash. Content-Disposition tolerates more, but a strict
# ASCII filename avoids the RFC-5987 encoding path and works in every browser.
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_engagement_slug(name: str | None) -> str:
    slug = _SAFE_NAME_RE.sub("-", (name or "").strip()).strip("-")
    return slug or "engagement"


def register_bloodhound_export_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path

    @app.get("/api/bloodhound/zip")
    def bloodhound_zip():
        """Stream the BloodHound-CE ingest zip for the current engagement.

        Reads ``Host.accounts`` + ``Credential`` rows from the store, hands
        them to ``bloodhound_push.build_zip`` (the same call the CLI makes),
        and returns the resulting bytes as an attachment. When the store has
        no user/computer/group/domain accounts we return 404 so the frontend
        can present the download as disabled with an explanatory tooltip.
        """
        from ...ad import bloodhound_push as bhp
        from ...core.store import Store

        with Store(db_path) as st:
            hosts = st.all_hosts()
            creds = st.all_credentials()
            eng_name = st.get_meta("engagement") or "engagement"

        # Write the zip into a private tempdir (so a concurrent CLI push
        # doesn't collide on the timestamped filename inside the engagement
        # dir), read the bytes back, and drop the tempdir. The route
        # deliberately does NOT persist a push copy under <eng>/bloodhound/ —
        # the CLI is the writer of the on-disk archive; the WebUI is a
        # download convenience.
        with tempfile.TemporaryDirectory(prefix="recce-bh-push-") as tmp:
            zip_path, summary = bhp.build_zip(hosts, creds, tmp, overwrite=True)
            counts = summary.get("counts", {})
            # "AD data" = at least one node in the four core AD buckets. The
            # other three (gpos/ous/containers) are always empty in a recce
            # push today (recce doesn't collect them), so gating on them would
            # be nonsense.
            if not any(counts.get(k, 0) for k in
                       ("users", "computers", "groups", "domains")):
                raise HTTPException(
                    404,
                    "No AD data in this engagement yet — run `recce ldap` / "
                    "`recce ad` or import a SharpHound zip first.")
            with open(zip_path, "rb") as fh:
                blob = fh.read()

        filename = f"bloodhound-{_safe_engagement_slug(eng_name)}.zip"
        # Manual Response (not FileResponse): the underlying tempdir is gone
        # by the time we return, so we hand back the bytes we've already read.
        return Response(
            content=blob,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/api/bloodhound/status")
    def bloodhound_status():
        """Cheap availability probe for the frontend "Download BloodHound zip"
        button. Returns whether the store currently carries any AD nodes so
        the button can render disabled with an explanatory tooltip instead
        of the user clicking and getting a 404.

        We don't run the full push here — just look at the shape the writer
        would classify: an Account with kind in (user/computer/group/domain).
        """
        from ...core.store import Store

        counts = {"users": 0, "computers": 0, "groups": 0, "domains": 0}
        with Store(db_path) as st:
            for h in st.all_hosts():
                for a in (h.accounts or []):
                    k = (a.kind or "").lower()
                    if k == "user":
                        counts["users"] += 1
                    elif k == "computer":
                        counts["computers"] += 1
                    elif k == "group":
                        counts["groups"] += 1
                    elif k == "domain":
                        counts["domains"] += 1
        available = any(counts.values())
        return {"available": available, "counts": counts}

    # Keep a reference to the engagement dir on the closure so a later
    # refactor that needs to persist pushes has an easy hook.
    _ = eng_dir
