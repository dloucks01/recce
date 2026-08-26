"""Multi-tester collaboration, team chat, and manual add endpoints."""
from __future__ import annotations

import os
import re
import time

from fastapi import Body, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse

from .. import collab


def register_collab_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path
    broker = ctx.broker
    presence = ctx.presence

    def _mutate(fn, event: dict, activity: tuple | None = None,
                x_tester: str = "someone"):
        """Open the store, run fn(st), persist an activity line, broadcast, close."""
        from ...store import Store
        with Store(db_path) as st:
            result = fn(st)
            if activity:
                collab.add_activity(st, x_tester, activity[0], activity[1])
        broker.publish(event)
        return result

    # --- multi-tester collaboration ------------------------------------------------

    @app.get("/api/collab")
    def collab_state():
        """Everything the UI overlays on hosts/findings: who owns what, triage labels,
        per-port status, dismissed findings, the activity feed, and who's online."""
        from ...store import Store
        with Store(db_path) as st:
            return {"assignments": collab.get_assignments(st),
                    "labels": collab.get_labels(st),
                    "port_status": collab.get_port_status(st),
                    "dismissed": collab.get_dismissed(st),
                    "activity": collab.get_activity(st, 100),
                    "online": presence.roster()}

    @app.post("/api/presence")
    def ping_presence(body: dict = Body(default=None), x_tester: str = Header(default="")):
        presence.ping(x_tester or (body or {}).get("tester", ""))
        return {"online": presence.roster()}

    @app.post("/api/assign")
    def assign(body: dict = Body(...), x_tester: str = Header(default="someone")):
        ip = str(body.get("ip", ""))
        who = str(body.get("tester", ""))          # "" releases the claim
        if not ip:
            raise HTTPException(400, "no ip")
        verb = ("claimed" if who == x_tester else f"assigned to {who}") if who else "released"
        _mutate(lambda st: collab.set_assignment(st, ip, who),
                {"type": "assign", "ip": ip, "tester": who, "by": x_tester},
                ("assign", f"{x_tester} {verb} {ip}"), x_tester)
        return {"ok": True}

    @app.post("/api/label")
    def label(body: dict = Body(...), x_tester: str = Header(default="someone")):
        ip, lab = str(body.get("ip", "")), str(body.get("label", ""))
        on = bool(body.get("on", True))
        if not ip or lab not in collab.LABELS:
            raise HTTPException(400, f"ip + label required (label in {collab.LABELS})")
        _mutate(lambda st: collab.set_label(st, ip, lab, on),
                {"type": "label", "ip": ip, "label": lab, "on": on, "by": x_tester},
                None, x_tester)
        return {"ok": True}

    @app.post("/api/port_status")
    def port_status(body: dict = Body(...), x_tester: str = Header(default="someone")):
        ip, port = str(body.get("ip", "")), body.get("port")
        status = str(body.get("status", ""))
        if not ip or port is None:
            raise HTTPException(400, "ip + port required")
        _mutate(lambda st: collab.set_port_status(st, ip, port, status),
                {"type": "port_status", "ip": ip, "port": port, "status": status,
                 "by": x_tester}, None, x_tester)
        return {"ok": True}

    @app.post("/api/dismiss")
    def dismiss(body: dict = Body(...), x_tester: str = Header(default="someone")):
        key = str(body.get("key", ""))
        on = bool(body.get("on", True))
        if not key:
            raise HTTPException(400, "no key")
        _mutate(lambda st: collab.set_dismissed(st, key, x_tester, on),
                {"type": "dismiss", "key": key, "on": on, "by": x_tester},
                ("dismiss", f"{x_tester} {'dismissed' if on else 'restored'} a finding"),
                x_tester)
        return {"ok": True}

    @app.post("/api/add/credential")
    def add_credential(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ...models import Credential
        from ...store import Store
        user = str(body.get("username", "")).strip()
        secret = str(body.get("secret", "")).strip()
        if not user and not secret:
            raise HTTPException(400, "a username or secret is required")
        kind = str(body.get("kind", "password"))
        if kind not in ("password", "nthash", "hash", "blank"):
            kind = "password"
        # Preserve caller-supplied `source` (e.g. web-secret, weak-default,
        # anon-share) — losing provenance made it hard to tell paste-imported
        # creds apart from manual entry, and downstream cred-source-aware
        # code (spray planner, exploit-plan lookups) couldn't correlate.
        # Default to "manual" only when the caller didn't specify.
        supplied_source = str(body.get("source", "")).strip() or "manual"
        with Store(db_path) as st:
            added = st.add_credential(Credential(
                username=user, secret=secret, kind=kind,
                domain=str(body.get("domain", "")), origin_ip=str(body.get("origin_ip", "")),
                source=supplied_source,
                notes=str(body.get("notes", "")) or "added by hand"))
            collab.add_activity(st, x_tester, "add", f"{x_tester} added a credential for {user or '(secret)'}")
        broker.publish({"type": "add", "what": "credential", "by": x_tester})
        return {"ok": True, "added": added}

    @app.post("/api/add/host")
    def add_host(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ...models import Host
        from ...store import Store
        from ...targets import load_targets
        tokens = str(body.get("targets", "")).split()
        if not tokens:
            raise HTTPException(400, "give one or more IPs / ranges / CIDRs")
        ips, hostnames, subnets = load_targets(tokens)
        ips = ips[:512]                                       # sanity cap on a big CIDR
        with Store(db_path) as st:
            for ip in ips:
                host = st.get_host(ip) or Host(ip=ip)
                host.state = "up"
                host.up_reason = host.up_reason or "manual"
                host.subnet = host.subnet or subnets.get(ip, "")
                if hostnames.get(ip) and hostnames[ip] not in host.hostnames:
                    host.hostnames.append(hostnames[ip])
                st.upsert_host(host, merge=True)
            collab.add_activity(st, x_tester, "add", f"{x_tester} added {len(ips)} host(s) to scope")
        broker.publish({"type": "add", "what": "host", "count": len(ips), "by": x_tester})
        return {"ok": True, "added": len(ips)}

    @app.post("/api/add/access")
    def add_access(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ...models import Host
        from ...store import Store
        ip = str(body.get("ip", "")).strip()
        if not ip:
            raise HTTPException(400, "a host IP is required")
        note = str(body.get("note", "")).strip() or "foothold recorded by hand"
        with Store(db_path) as st:
            host = st.get_host(ip) or Host(ip=ip)
            host.state = "up"
            host.access_gained = True
            host.access_detail = note
            st.upsert_host(host, merge=True)
            collab.add_activity(st, x_tester, "access", f"{x_tester} recorded access on {ip}: {note}")
        broker.publish({"type": "add", "what": "access", "ip": ip, "by": x_tester})
        return {"ok": True}

    # --- team chat ----------------------------------------------------------------
    _CHAT_MAX_BYTES = 8_000_000          # pasted image (rendered inline)
    _CHAT_FILE_MAX_BYTES = 20_000_000    # general attachment (forced download)
    _SAFE_NAME = re.compile(r"[^A-Za-z0-9 ._-]+")

    def _safe_chat_filename(name: str) -> str:
        """A display/download filename from client-supplied input - never trusted for
        filesystem access (the file is always stored under a random name; this is only
        the Content-Disposition hint and the name shown in the chat log)."""
        base = os.path.basename((name or "").strip().replace("\\", "/"))
        base = _SAFE_NAME.sub("_", base).strip(" ._")[:180]
        return base or "file"

    @app.get("/api/chat")
    def chat_history(limit: int = 200):
        from ...store import Store
        with Store(db_path) as st:
            return collab.get_chat(st, limit)

    @app.post("/api/chat")
    def chat_post(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """A chat message: text, and/or one attachment. A pasted/dropped image is kept
        as `image` (base64) and rendered inline; any other file (or an oversize image)
        is kept as `file` ({data: base64, name}) and offered as a forced download -
        never rendered inline, so an uploaded .html/.svg/etc. can't execute in-origin."""
        from ...store import Store
        import base64
        text = str(body.get("text", "")).strip()
        image_b64 = body.get("image") or ""
        image_name = ""
        if image_b64:
            try:
                raw = base64.b64decode(image_b64)
            except Exception:
                raise HTTPException(400, "could not decode the image")
            if len(raw) > _CHAT_MAX_BYTES:
                raise HTTPException(413, "image too large (max ~8 MB)")
            ext = collab.image_ext(raw)
            if not ext:
                raise HTTPException(415, "unsupported image type (png/jpg/gif/webp)")
            image_name = f"{time.strftime('%Y%m%d')}-{os.urandom(6).hex()}.{ext}"
            media_dir = os.path.join(eng_dir, "chat-media")
            os.makedirs(media_dir, exist_ok=True)
            with open(os.path.join(media_dir, image_name), "wb") as fh:
                fh.write(raw)
        file_meta = None
        file_in = body.get("file")
        if isinstance(file_in, dict) and file_in.get("data"):
            try:
                raw = base64.b64decode(file_in["data"])
            except Exception:
                raise HTTPException(400, "could not decode the file")
            if len(raw) > _CHAT_FILE_MAX_BYTES:
                raise HTTPException(413, "file too large (max ~20 MB)")
            orig = _safe_chat_filename(str(file_in.get("name") or ""))
            ext = os.path.splitext(orig)[1][:12]     # cosmetic only, never trusted
            stored_name = f"{time.strftime('%Y%m%d')}-{os.urandom(8).hex()}{ext}"
            media_dir = os.path.join(eng_dir, "chat-media")
            os.makedirs(media_dir, exist_ok=True)
            with open(os.path.join(media_dir, stored_name), "wb") as fh:
                fh.write(raw)
            file_meta = {"stored": stored_name, "name": orig, "size": len(raw)}
        if not text and not image_name and not file_meta:
            raise HTTPException(400, "empty message")
        with Store(db_path) as st:
            msg = collab.add_chat(st, x_tester, text[:4000], image_name, file_meta)
        broker.publish({"type": "chat", "msg": msg})
        return msg

    @app.get("/api/chat/media/{name}")
    def chat_media(name: str):
        if "/" in name or "\\" in name or ".." in name:      # no path traversal
            raise HTTPException(400, "bad name")
        path = os.path.join(eng_dir, "chat-media", name)
        if not os.path.isfile(path):
            raise HTTPException(404, "no such image")
        return FileResponse(path)

    @app.get("/api/chat/file/{name}")
    def chat_file(name: str, dl: str = Query(default="")):
        """A general chat attachment - ALWAYS served as application/octet-stream with a
        forced Content-Disposition: attachment, regardless of what was uploaded (an
        .html/.svg/.js file must never render in-origin). `name` is the trusted random
        stored filename (path-checked below); `dl` is only a display-filename hint for
        the download, never used for filesystem access."""
        if "/" in name or "\\" in name or ".." in name:      # no path traversal
            raise HTTPException(400, "bad name")
        path = os.path.join(eng_dir, "chat-media", name)
        if not os.path.isfile(path):
            raise HTTPException(404, "no such file")
        return FileResponse(path, media_type="application/octet-stream",
                            filename=_safe_chat_filename(dl) if dl else name)
