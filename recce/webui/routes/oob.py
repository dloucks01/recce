"""OOB callback catcher — recce's interactsh / Burp-Collaborator surrogate.

Unblocks the P2-2 review remainder (Log4Shell, HTTP request smuggling
active PoC, Spring4Shell) by giving the workbench a first-party place to
mint per-probe tokens and catch inbound hits that prove blind execution
/ SSRF / smuggling. The existing T3 chain gate at
``findings.py::_recovery_chain`` already looks for a Vuln whose script_id
matches ``oob_callback_triggered`` / ``interactsh`` / ``collaborator_hit``;
this module produces exactly that finding on the first hit for a
vuln-linked token.

Wire protocol
=============

Operator surface (needs the tester bearer):
  * ``POST /api/oob/mint``       — mint a token for a probe. Body:
      ``{kind, target_ip, target_port, target_url, vuln_key, note}``.
    Response: ``{token, callback_path, callback_url}``. ``callback_url``
    is built from the request's Host header (i.e. the workbench URL the
    operator's browser is talking to) — good enough for same-subnet
    targets. Cross-subnet targets need an operator-configurable
    ``oob_public_host`` meta (falls back to Host header when unset).
  * ``GET  /api/oob/tokens``     — list minted tokens (?vuln_key= filter).
  * ``GET  /api/oob/hits/{tok}`` — poll hits for a token.

Beacon-catcher surface (unauthed by design — the target has to be able
to reach it):
  * ``ANY /oob/{token}[/{...}]`` — any HTTP method + trailing path
    lands the hit. Returns a tiny 200 body regardless (recording that
    the token is unknown would let a scanner enumerate active probes).

Design constraints
==================
* Stdlib-only (asyncio + sqlite + fastapi that's already there).
* The catcher endpoint is single asyncio loop, single process — matches
  recce's per-engagement-6-tester scale.
* Bounded body-preview (first 4KB) + bounded headers (first 8KB) so a
  huge misbehaving scanner can't disk-fill the engagement.
* The first hit for a token that carries a ``vuln_key`` synthesises a
  ``script_id='oob_callback_triggered'`` finding on the target host,
  auto-lighting the T3 chain gate. Later hits on the same token append
  to the row's output rather than duplicating the finding.
"""
from __future__ import annotations

import json
import secrets
import time

from fastapi import FastAPI, Header, HTTPException, Request


def _mint_token() -> str:
    """16 bytes -> 32 hex chars. Plenty of entropy against enumeration;
    fits in a URL path, DNS label, and JNDI payload without escaping."""
    return secrets.token_hex(16)


def _light_t3_finding(store, tok: dict, hit: dict) -> None:
    """First hit on a vuln-linked token synthesises a Vuln with
    script_id='oob_callback_triggered' on the target host, so the T3
    gate at findings.py::_recovery_chain lights up automatically. If a
    matching finding already exists (later hits), append the new hit's
    output to its existing output blob rather than duplicating."""
    from ...core.models import Vuln, Evidence
    vuln_key = tok.get("vuln_key") or ""
    target_ip = tok.get("target_ip") or hit.get("src_ip") or ""
    target_port = int(tok.get("target_port") or 0)
    if not target_ip:
        return
    host = store.get_host(target_ip)
    if host is None:
        return
    # Look for a prior synthetic finding on this host + token to append to.
    marker = f"oob:{tok['token']}"
    existing = next((v for v in host.vulns
                     if v.script_id == "oob_callback_triggered"
                     and marker in (v.output or "")), None)
    hit_summary = (f"[{hit['ts']}] {hit.get('method','?')} {hit.get('path','/')} "
                   f"from {hit.get('src_ip','?')}")
    if existing is not None:
        existing.output = ((existing.output or "") + "\n" + hit_summary)[:6000]
    else:
        title_kind = tok.get("kind") or "generic"
        host.vulns.append(Vuln(
            ip=target_ip, port=target_port, protocol="tcp",
            script_id="oob_callback_triggered",
            state="finding",
            title=f"Out-of-band callback triggered ({title_kind})",
            severity="high", confidence="confirmed",
            source="oob",
            output=(f"OOB proof: recce-hosted /oob/{tok['token']} received an "
                    f"inbound HTTP hit — blind execution / SSRF / smuggling "
                    f"is confirmed against the target.\n"
                    f"{marker}\n{hit_summary}"),
            evidence=[Evidence(kind="oob-callback", positive=True,
                               detail=hit_summary[:200])],
            depth_tier="t3",
            exploit_note=(
                "Callback landed — the vulnerability is real. Escalate: "
                "chain the same primitive to fetch a shell / read secrets, "
                "or move to a proven-CVE PoC once safe-verify is in hand."),
        ))
        if vuln_key:
            # Try to inherit the linked finding's port when we set 0.
            src = next((v for v in host.vulns if getattr(v, "key", "") == vuln_key),
                       None)
            if src and target_port == 0:
                host.vulns[-1].port = src.port
    # merge=False: we've just mutated `existing.output` in place on the
    # loaded host. Store._merge dedups vulns by key and keeps the OLD row,
    # so a plain merge upsert would silently DROP our appended evidence.
    # This host is now the authoritative snapshot; wholesale replace is
    # correct here (concurrent-writer races on the same host are already
    # bounded by _write_txn's BEGIN IMMEDIATE serialisation).
    store.upsert_host(host, merge=False)


def register_oob_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path
    broker = ctx.broker

    @app.post("/api/oob/mint")
    def mint(body: dict = None, request: Request = None,   # type: ignore[assignment]
             x_tester: str = Header(default="someone")):
        body = body or {}
        kind = str(body.get("kind", "generic"))
        if kind not in ("generic", "log4shell", "spring4shell",
                        "smuggle", "ssrf", "xxe", "blind-xss"):
            raise HTTPException(400, "unknown kind")
        try:
            target_port = int(body.get("target_port", 0) or 0)
        except (TypeError, ValueError):
            raise HTTPException(400, "target_port must be an integer")
        target_ip = str(body.get("target_ip", ""))[:64]
        target_url = str(body.get("target_url", ""))[:1024]
        vuln_key = str(body.get("vuln_key", ""))[:512]
        note = str(body.get("note", ""))[:500]
        token = _mint_token()
        from ...core.store import Store
        with Store(db_path) as st:
            st.mint_oob_token(token, kind, target_ip=target_ip,
                              target_port=target_port,
                              target_url=target_url,
                              vuln_key=vuln_key,
                              tester=x_tester, note=note)
        # Build a paste-ready callback URL. Prefer an engagement meta
        # ('oob_public_host') the operator can set when the workbench URL
        # isn't reachable from the target — otherwise fall back to the
        # request's Host header, which works for same-subnet targets.
        public_host = ""
        try:
            with Store(db_path) as st:
                public_host = st.get_meta("oob_public_host") or ""
        except Exception:  # noqa: BLE001 — never let meta lookup break mint
            pass
        if not public_host and request is not None:
            public_host = request.headers.get("host", "")
        callback_path = f"/oob/{token}"
        scheme = "http"
        try:
            if request is not None and request.url.scheme:
                scheme = request.url.scheme
        except Exception:  # noqa: BLE001
            pass
        callback_url = (f"{scheme}://{public_host}{callback_path}"
                        if public_host else callback_path)
        broker.publish({"type": "oob", "event": "minted",
                        "token": token, "kind": kind,
                        "target_ip": target_ip, "by": x_tester})
        return {"token": token, "callback_path": callback_path,
                "callback_url": callback_url, "kind": kind,
                "vuln_key": vuln_key or None}

    @app.get("/api/oob/tokens")
    def list_tokens(vuln_key: str = "", limit: int = 200):
        from ...core.store import Store
        limit = max(1, min(int(limit), 500))
        with Store(db_path) as st:
            toks = st.list_oob_tokens(vuln_key=vuln_key, limit=limit)
            # Add live hit counts so the frontend can render "3 hits" without
            # a follow-up query per token.
            for t in toks:
                t["hits"] = st.count_oob_hits(t["token"])
        return {"tokens": toks}

    @app.get("/api/oob/hits/{token}")
    def hits(token: str, limit: int = 500):
        from ...core.store import Store
        limit = max(1, min(int(limit), 1000))
        with Store(db_path) as st:
            tok = st.get_oob_token(token)
            if not tok:
                raise HTTPException(404, "no such token")
            rows = st.list_oob_hits(token=token, limit=limit)
        return {"token": token, "meta": tok, "hits": rows}

    # --- catcher surface (unauthed by design) ---------------------------

    @app.api_route("/oob/{token}",
                   methods=["GET", "POST", "PUT", "DELETE",
                            "PATCH", "OPTIONS", "HEAD"])
    @app.api_route("/oob/{token}/{tail:path}",
                   methods=["GET", "POST", "PUT", "DELETE",
                            "PATCH", "OPTIONS", "HEAD"])
    async def catch(request: Request, token: str, tail: str = ""):
        """Record any inbound HTTP hit at /oob/<token>. Returns a tiny 200
        regardless of token existence — an unknown token is silently
        dropped rather than returning 404 so a scanner can't enumerate
        active probes just by fuzzing the path."""
        from ...core.store import Store
        # Bounded body read — a scanner reflection could ship megabytes.
        raw = b""
        try:
            raw = await request.body()
        except Exception:  # noqa: BLE001
            pass
        preview = raw[:4096].decode("utf-8", "replace") if raw else ""
        method = request.method
        hdrs = {k.lower(): v[:200] for k, v in list(request.headers.items())[:32]}
        # Client IP: request.client wins; X-Forwarded-For as a fallback for
        # multi-hop test setups (rare on-engagement, cheap to accept).
        src_ip = ""
        try:
            src_ip = (request.client.host if request.client else "") or ""
        except Exception:  # noqa: BLE001
            pass
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            src_ip = xff.split(",", 1)[0].strip() or src_ip
        path = "/" + tail if tail else "/"
        qs = request.url.query
        if qs:
            path = f"{path}?{qs}"

        with Store(db_path) as st:
            tok = st.get_oob_token(token)
            if not tok:
                # Silently 200 for unknown tokens so a scanner can't
                # enumerate live probes. Log to the SSE feed as 'unknown'
                # so the operator sees a stray hit for debugging.
                broker.publish({"type": "oob", "event": "stray",
                                "token": token[:16], "src_ip": src_ip})
                return {"ok": True}
            hid = st.record_oob_hit(token, src_ip=src_ip, method=method,
                                    path=path, headers=json.dumps(hdrs),
                                    body_preview=preview)
            # Light the T3 gate on the first vuln-linked hit; append on
            # subsequent hits so the finding accumulates evidence.
            if tok.get("vuln_key") or tok.get("target_ip"):
                hit = {"ts": str(int(time.time())), "src_ip": src_ip,
                       "method": method, "path": path}
                try:
                    _light_t3_finding(st, tok, hit)
                except Exception:  # noqa: BLE001 — catcher must never 500
                    pass
        broker.publish({"type": "oob", "event": "hit",
                        "token": token, "hit_id": hid,
                        "src_ip": src_ip, "method": method,
                        "path": path, "vuln_key": tok.get("vuln_key") or None})
        return {"ok": True}
