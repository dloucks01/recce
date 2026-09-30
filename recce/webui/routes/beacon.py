"""Beacon routes (async-C2 P1).

Two families of endpoints:

* **Operator-facing** — /api/beacons — register / list / patch / delete a
  beacon. Same auth model as the rest of the workbench (X-Tester bearer).
  A fresh registration returns the raw PSK **once**; the DB keeps the PSK
  so `/beacon/checkin` HMAC verification works but no subsequent read
  returns it.

* **Beacon-client-facing** — /beacon/checkin, /beacon/result — polled by
  the async client living on the target. HMAC-SHA256 (per-beacon key)
  authenticates each request; a stale timestamp is rejected to bound
  replay windows.

Wire protocol matches design doc §4:

  POST /beacon/checkin
    headers: X-Beacon-Id: <bid>, X-Beacon-Ts: <unix>, X-Beacon-Mac: <hex>
    body: {}                    -- (empty; the id is in the header)
    resp: {"tasks": [{task_id, kind, command, data_b64?}], "sleep", "jitter"}

  POST /beacon/result
    headers: X-Beacon-Id / X-Beacon-Ts / X-Beacon-Mac
    body: {"task_id", "status", "output_b64",
           "artifact"?: {"kind", "path", "data_b64"}}
    resp: {"ok": True}

The MAC covers the raw request body plus the id + ts header values, so a
replay across ids or bodies fails. `X-Beacon-Ts` must be within a ±5 min
window of server time. This is enough to keep a random probe off the
port — it is NOT an implant-security story (see the design doc §9)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time

from fastapi import Body, FastAPI, Header, HTTPException, Request


# ± window for accepting X-Beacon-Ts against server time. Tight enough to
# make a replay a race, loose enough to survive clock drift + long RTT.
_TS_WINDOW_S = 300

# Cap the raw HTTP body a beacon client can POST — bounded by design-doc
# §10's "16 KiB inline / rest to disk" cutoff, plus a generous headroom
# for JSON overhead and future kinds. An artifact bigger than this must
# ride in a follow-up call, not one giant checkin/result body.
_MAX_BEACON_BODY = 256 * 1024


def _mint_psk() -> str:
    """32 bytes of urandom, url-safe base64 — 43 chars, printable, easy to
    copy into an operator's stager script."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def _verify_beacon_auth(store, bid: str, ts_hdr: str, mac_hdr: str,
                        raw_body: bytes) -> dict:
    """Return the beacon row or raise HTTPException. Constant-time HMAC
    check + timestamp-window check. No branch leaks which of (unknown id /
    stale ts / bad mac) failed — all 401 with the same detail so a
    scanning attacker can't tell an id apart from a bad key."""
    row = store.get_beacon(bid) if bid else None
    if not row or not row.get("psk"):
        raise HTTPException(401, "beacon auth failed")
    try:
        ts = int(ts_hdr)
    except (TypeError, ValueError):
        raise HTTPException(401, "beacon auth failed")
    if abs(time.time() - ts) > _TS_WINDOW_S:
        raise HTTPException(401, "beacon auth failed")
    key = row["psk"].encode("utf-8")
    # Bind the timestamp + id into the MAC so a replayed body can't be
    # steered to another beacon or another moment.
    msg = f"{bid}:{ts}:".encode("ascii") + raw_body
    expected = hmac.new(key, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, (mac_hdr or "").lower()):
        raise HTTPException(401, "beacon auth failed")
    return row


def register_beacon_routes(app: FastAPI, ctx) -> None:
    mgr = ctx.sessions
    db_path = ctx.db_path
    broker = ctx.broker

    # --- operator-facing --------------------------------------------------

    def _beacon_dict(row: dict) -> dict:
        """The shape returned to the OPERATOR — the PSK is stripped. Any
        listing that leaks the raw key is a bug this helper prevents."""
        return {k: v for k, v in row.items() if k != "psk"}

    @app.post("/api/beacons")
    async def register_beacon(body: dict = Body(default={}),
                              x_tester: str = Header(default="someone")):
        """Register a new beacon session. Response includes the raw PSK
        **once** so the operator can paste it into their stager; the PSK
        never appears in any subsequent response, and no GET returns it."""
        host_ip = str(body.get("host_ip", "")).strip()
        if not host_ip or not re.match(r"^[0-9a-fA-F.:]+$", host_ip):
            raise HTTPException(400, "host_ip is required and must be an IPv4/IPv6")
        try:
            sleep_s = float(body.get("sleep_s", 30.0))
            jitter_pct = float(body.get("jitter_pct", 20.0))
        except (TypeError, ValueError):
            raise HTTPException(400, "sleep_s / jitter_pct must be numbers")
        if sleep_s <= 0 or sleep_s > 3600:
            raise HTTPException(400, "sleep_s must be 0 < x <= 3600")
        transport = str(body.get("transport", "http")).lower()
        if transport not in ("http", "https"):
            raise HTTPException(400, "transport must be http or https")
        notes = str(body.get("notes", ""))[:500]
        psk = _mint_psk()
        sess = await mgr.register_beacon(host_ip, psk, transport=transport,
                                         sleep_s=sleep_s, jitter_pct=jitter_pct,
                                         notes=notes)
        # Ops-log the registration (no PSK in the log line).
        try:
            from ...core.store import Store
            from .. import collab
            with Store(db_path) as st:
                collab.add_activity(st, x_tester, "session",
                                    f"registered beacon on {host_ip} "
                                    f"(sleep {sleep_s}s ±{jitter_pct}%)")
        except Exception:  # noqa: BLE001 — attribution must never fail the register
            pass
        broker.publish({"type": "beacon", "event": "registered",
                        "id": sess.id, "host": host_ip, "by": x_tester})
        return {
            "id": sess.id, "host_ip": host_ip, "transport": transport,
            "sleep_s": sleep_s, "jitter_pct": jitter_pct,
            # SHOWN ONCE — the operator must copy this now. All subsequent
            # GETs redact it.
            "psk": psk,
        }

    @app.get("/api/beacons")
    def list_beacons():
        if not mgr.store:
            return {"beacons": []}
        rows = mgr.store.list_beacons()
        return {"beacons": [_beacon_dict(r) for r in rows]}

    @app.get("/api/beacons/{bid}")
    def get_beacon(bid: str):
        if not mgr.store:
            raise HTTPException(404, "no such beacon")
        row = mgr.store.get_beacon(bid)
        if not row:
            raise HTTPException(404, "no such beacon")
        return _beacon_dict(row)

    @app.patch("/api/beacons/{bid}")
    def patch_beacon(bid: str, body: dict = Body(),
                     x_tester: str = Header(default="someone")):
        """Retune sleep_s / jitter_pct / notes. Any field left out is
        preserved."""
        if not mgr.store:
            raise HTTPException(404, "no such beacon")
        kwargs = {}
        if "sleep_s" in body:
            try:
                s = float(body["sleep_s"])
            except (TypeError, ValueError):
                raise HTTPException(400, "sleep_s must be a number")
            if s <= 0 or s > 3600:
                raise HTTPException(400, "sleep_s must be 0 < x <= 3600")
            kwargs["sleep_s"] = s
        if "jitter_pct" in body:
            try:
                kwargs["jitter_pct"] = float(body["jitter_pct"])
            except (TypeError, ValueError):
                raise HTTPException(400, "jitter_pct must be a number")
        if "notes" in body:
            kwargs["notes"] = str(body["notes"])[:500]
        if not kwargs:
            raise HTTPException(400, "no updatable fields in body")
        if not mgr.store.update_beacon_policy(bid, **kwargs):
            raise HTTPException(404, "no such beacon")
        broker.publish({"type": "beacon", "event": "policy",
                        "id": bid, "by": x_tester})
        return _beacon_dict(mgr.store.get_beacon(bid))

    @app.delete("/api/beacons/{bid}")
    async def delete_beacon(bid: str, x_tester: str = Header(default="someone")):
        """Retire a beacon: mark the session dead (close its transport,
        drop from the registry) and remove the beacon row so no further
        check-in authenticates. The oplog + transcript persist for history."""
        if not mgr.store:
            raise HTTPException(404, "no such beacon")
        row = mgr.store.get_beacon(bid)
        if not row:
            raise HTTPException(404, "no such beacon")
        await mgr.close_session(bid)              # closes BeaconTransport, marks dead
        mgr.store.delete_beacon(bid)
        broker.publish({"type": "beacon", "event": "retired",
                        "id": bid, "by": x_tester})
        return {"ok": True}

    # --- beacon-client-facing --------------------------------------------

    def _tasks_for_beacon(bid: str) -> list[dict]:
        """Drain queued tasks for this beacon from the shared oplog (the
        P0 record layer) — same rows the operator sees under 'queued', now
        translating to a batch of {task_id, kind, command} for the client."""
        from ...core.store import Store
        with Store(db_path) as st:
            rows = st.list_tasks(session_id=bid, status="queued", limit=32)
            # Server-side: mark 'sent' as we hand them off, so operator sees
            # the state advance and a subsequent checkin doesn't re-hand
            # the same task.
            for r in rows:
                st.mark_task_result(r["task_id"], "", status="sent", bytes=0)
        return [{"task_id": r["task_id"], "kind": r["kind"],
                 "command": r["command"]} for r in rows]

    @app.post("/beacon/checkin")
    async def beacon_checkin(request: Request,
                             x_beacon_id: str = Header(default=""),
                             x_beacon_ts: str = Header(default=""),
                             x_beacon_mac: str = Header(default="")):
        raw = await request.body()
        if len(raw) > _MAX_BEACON_BODY:
            raise HTTPException(413, "beacon body too large")
        row = _verify_beacon_auth(mgr.store, x_beacon_id, x_beacon_ts,
                                  x_beacon_mac, raw)
        # Stamp the check-in ts; used by the UI to show 'last seen'.
        mgr.store.update_beacon_checkin(x_beacon_id, time.time())
        tasks = _tasks_for_beacon(x_beacon_id) if row else []
        broker.publish({"type": "beacon", "event": "checkin",
                        "id": x_beacon_id, "tasks_sent": len(tasks)})
        return {"tasks": tasks,
                "sleep": row["sleep_s"],
                "jitter": row["jitter_pct"]}

    @app.post("/beacon/result")
    async def beacon_result(request: Request,
                            x_beacon_id: str = Header(default=""),
                            x_beacon_ts: str = Header(default=""),
                            x_beacon_mac: str = Header(default="")):
        raw = await request.body()
        if len(raw) > _MAX_BEACON_BODY:
            raise HTTPException(413, "beacon body too large")
        _verify_beacon_auth(mgr.store, x_beacon_id, x_beacon_ts,
                            x_beacon_mac, raw)
        import json
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            raise HTTPException(400, "malformed json body")
        if not isinstance(body, dict):
            raise HTTPException(400, "body must be a json object")
        task_id = str(body.get("task_id", "")).strip()
        if not task_id:
            raise HTTPException(400, "task_id required")
        status = str(body.get("status", "done"))
        if status not in ("done", "error"):
            raise HTTPException(400, "status must be 'done' or 'error'")
        # Decode output — b64 for binary-safe transit.
        out_b64 = body.get("output_b64", "")
        try:
            output = base64.b64decode(out_b64) if out_b64 else b""
        except Exception:
            raise HTTPException(400, "output_b64 is not valid base64")
        # Mark the task row; also feed the bytes into the session's
        # transcript via the BeaconTransport (so scrollback shows the
        # result under the operator's terminal view).
        from ...core.store import Store
        with Store(db_path) as st:
            st.mark_task_result(task_id, output.decode("utf-8", "replace"),
                                status=status, bytes=len(output))
        sess = mgr.get(x_beacon_id)
        if sess is not None:
            transport = sess._transport
            if transport is not None and hasattr(transport, "feed_inbound"):
                transport.feed_inbound(output)

        # Optional attached artifact — same shape /download uses.
        art = body.get("artifact")
        art_id = ""
        art_finding = ""
        if isinstance(art, dict):
            art_kind = str(art.get("kind", "file"))
            art_path = str(art.get("path", ""))
            try:
                raw_blob = base64.b64decode(art.get("data_b64", ""))
            except Exception:
                raise HTTPException(400, "artifact.data_b64 is not valid base64")
            if raw_blob:
                ddir = os.path.join(ctx.eng_dir, "session-loot")
                os.makedirs(ddir, exist_ok=True)
                safe_ip = re.sub(r"[^0-9a-fA-F:.]+", "_",
                                 sess.host_ip if sess else x_beacon_id)
                safe_name = os.path.basename(art_path) or f"artifact-{task_id}"
                dest = os.path.join(ddir, f"{safe_ip}_{safe_name}")
                with open(dest, "wb") as f:
                    f.write(raw_blob)
                from ...sessions.tasking import _mint_task_id
                from ...act.artifact_link import link_artifact
                sha256 = hashlib.sha256(raw_blob).hexdigest()
                art_id = _mint_task_id()
                host_ip_for_link = sess.host_ip if sess else ""
                with Store(db_path) as st:
                    # Pull the task command back to feed the linker — the
                    # command is the primary signal ('cat /etc/shadow'
                    # names the story better than the path alone).
                    task_cmd = ""
                    for r in st.list_tasks(session_id=x_beacon_id, limit=1):
                        if r["task_id"] == task_id:
                            task_cmd = r["command"]
                            break
                    art_finding = link_artifact(st, host_ip_for_link,
                                                task_cmd, art_path)
                    st.add_artifact(art_id, x_beacon_id, host_ip_for_link,
                                    art_kind, dest,
                                    sha256=sha256, bytes=len(raw_blob),
                                    task_id=task_id,
                                    finding_id=art_finding,
                                    note=f"from beacon result ({art_path})")
                broker.publish({"type": "artifact", "event": "captured",
                                "id": art_id, "host": host_ip_for_link,
                                "session": x_beacon_id, "bytes": len(raw_blob),
                                "finding_id": art_finding or None})
        broker.publish({"type": "task", "event": "done" if status == "done" else "error",
                        "id": x_beacon_id, "task_id": task_id,
                        "bytes": len(output),
                        "artifact_id": art_id or None,
                        "finding_id": art_finding or None})
        return {"ok": True, "artifact_id": art_id or None,
                "finding_id": art_finding or None}
