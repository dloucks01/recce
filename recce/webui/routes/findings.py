"""Finding tracking (note/tick), manual finding add, and the credential store.

Thin route layer: parse the body, hand off to the service, translate service
exceptions into HTTPException, publish the broker event, return JSON.
"""
from __future__ import annotations

from fastapi import Body, FastAPI, Header, HTTPException, Query

from .. import collab
from ..services import credentials as credentials_svc
from ..services import findings as findings_svc
from ..services import loot as loot_svc


def register_findings_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path
    broker = ctx.broker

    @app.get("/api/credentials")
    def credentials(limit: int = Query(default=0, ge=0),
                    offset: int = Query(default=0, ge=0)):
        """The credential store — looted (web/db/share) + captured (kerberoast/gpp/...).
        This is 'what was extracted', which the UI never surfaced before."""
        return credentials_svc.list_credentials(db_path, limit=limit, offset=offset)

    @app.post("/api/note")
    def note(body: dict = Body(...), x_tester: str = Header(default="someone")):
        key = str(body.get("key", ""))
        text = str(body.get("note", ""))
        try:
            findings_svc.set_note(db_path, key, text)
        except findings_svc.ValidationError as e:
            raise HTTPException(400, str(e))
        broker.publish({"type": "note", "key": key, "note": text, "tester": x_tester})
        return {"ok": True}

    @app.post("/api/tick")
    def tick(body: dict = Body(...), x_tester: str = Header(default="someone")):
        key = str(body.get("key", ""))
        reviewed = bool(body.get("reviewed", True))
        try:
            findings_svc.set_reviewed(db_path, key, reviewed)
        except findings_svc.ValidationError as e:
            raise HTTPException(400, str(e))
        broker.publish({"type": "tick", "key": key, "reviewed": reviewed,
                        "tester": x_tester})
        return {"ok": True}

    # Finding lifecycle status — beyond reviewed/dismissed. Values are open;
    # the frontend renders the standard set (new / triaged / confirmed /
    # in-report / excluded / retested-fixed / retested-open). Empty status
    # clears back to "new" (which is implicit — no row is stored).
    _STATUSES = {"", "new", "triaged", "confirmed", "in-report", "excluded",
                 "retested-fixed", "retested-open"}

    @app.post("/api/finding/status")
    def set_status(body: dict = Body(...), x_tester: str = Header(default="someone")):
        from ...core.store import Store
        import time
        key = str(body.get("key", "")).strip()
        status = str(body.get("status", "")).strip().lower()
        if not key:
            raise HTTPException(400, "key required")
        if status not in _STATUSES:
            raise HTTPException(400, f"unknown status {status!r}")
        with Store(db_path) as st:
            st.set_status(key, status, when=str(int(time.time())))
        broker.publish({"type": "status", "key": key, "status": status,
                        "tester": x_tester})
        return {"ok": True, "status": status}

    @app.post("/api/sqli/test")
    def sqli_test(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """Active SQL injection test (C5). GATED — the request body MUST set
        `active_attacks: true` (mirroring the module-level opt-in) or the
        request refuses with 403.

        body: {url, method?, inputs?[names], defaults?{}, active_attacks:true}
        Returns {hits:[...], gated_reason?} on success; 403 on missing opt-in.
        """
        from ...services import sqli as sqli_svc
        url = str(body.get("url", "")).strip()
        if not url:
            raise HTTPException(400, "url required")
        active = bool(body.get("active_attacks"))
        if not active:
            raise HTTPException(403, "active SQLi requires 'active_attacks': true "
                                    "in the request body — recce stays passive by default")
        try:
            if body.get("inputs"):
                hits = sqli_svc.test_form(url, str(body.get("method", "POST")),
                                          list(body.get("inputs") or []),
                                          active_attacks=True,
                                          defaults=body.get("defaults") or {})
            else:
                hits = sqli_svc.test_url_param(url, active_attacks=True)
        except sqli_svc.ActiveAttacksDisabled as e:
            raise HTTPException(403, str(e))
        if hits:
            broker.publish({"type": "add", "what": "sqli", "by": x_tester,
                            "count": len(hits), "url": url})
        return {"hits": hits, "url": url, "tester": x_tester}


    @app.post("/api/loot/scan-evidence")
    def loot_scan_evidence(x_tester: str = Header(default="someone")):
        """Walk `<engagement>/evidence/**` and produce Vuln findings for
        Kerberos ticket files (.ccache/.kirbi), credential-bearing files
        (.aws/credentials, .netrc, id_rsa, browser saved logins, …), .git
        repository dumps, and configs with embedded secrets (API keys,
        DB URLs, private keys, JWTs, ...).

        Read-only — never mutates the evidence tree. Newly-discovered
        findings persist to the datastore so they show up in the Findings
        tab and roll into the report."""
        from ...intake.loot import scan_evidence
        from ...core.store import Store
        new_vulns = scan_evidence(ctx.eng_dir)
        if not new_vulns:
            return {"scanned": True, "added": 0}
        with Store(ctx.eng_dir + "/results.sqlite") as st:
            hosts_by_ip = {h.ip: h for h in st.all_hosts()}
            added = 0
            for v in new_vulns:
                h = hosts_by_ip.get(v.ip)
                if not h:
                    continue
                # Dedup: skip if this host already has an identical loot finding.
                if any(x.script_id == v.script_id and x.title == v.title
                       for x in h.vulns):
                    continue
                h.vulns.append(v)
                st.upsert_host(h)
                added += 1
            if added:
                collab.add_activity(st, x_tester, "scan",
                    f"{x_tester} scanned evidence and added {added} loot finding(s)")
        broker.publish({"type": "add", "what": "loot", "by": x_tester, "count": added})
        return {"scanned": True, "added": added, "detected": len(new_vulns)}


    @app.post("/api/loot/extract")
    def loot_extract(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """Auto-loot: scan arbitrary text for credentials (secretsdump rows,
        env-style KEY=VAL, user:pass lines) and add each new one to the
        Credentials store with provenance. Idempotent — dupes are counted
        but not re-added."""
        text = str(body.get("text", ""))
        if not text.strip():
            raise HTTPException(400, "text required")
        origin_ip = str(body.get("origin_ip", "")).strip()
        note = str(body.get("note", "")).strip() or f"pasted by {x_tester}"
        result = loot_svc.extract_and_persist(db_path, text, origin_ip=origin_ip, note=note)
        if result["added"] > 0:
            from ...core.store import Store
            with Store(db_path) as st:
                collab.add_activity(st, x_tester, "add",
                    f"{x_tester} auto-looted {result['added']} credential(s) from pasted text")
            broker.publish({"type": "add", "what": "credential", "by": x_tester,
                            "count": result["added"]})
        return result

    @app.post("/api/add/finding")
    def add_finding(body: dict = Body(...), x_tester: str = Header(default="someone")):
        try:
            info = findings_svc.add_manual_finding(
                db_path, tester=x_tester,
                ip=str(body.get("ip", "")),
                title=str(body.get("title", "")),
                severity=str(body.get("severity", "medium")),
                port=body.get("port"),
                cve=str(body.get("cve", "")),
                output=str(body.get("output", "")),
            )
        except findings_svc.ValidationError as e:
            raise HTTPException(400, str(e))
        broker.publish({"type": "add", "what": "finding", "ip": info["ip"], "by": x_tester})
        return {"ok": True}

    @app.post("/api/evidence/upload")
    def upload_evidence(body: dict = Body(...),
                        x_tester: str = Header(default="someone")):
        """Attach an arbitrary file to a host as raw evidence.

        The escape hatch for anything that can't be parsed — screenshots,
        PDFs, packet captures, vendor reports, custom-tool output that
        recce doesn't recognize and even the universal loose parser can't
        get anything out of. Saves the file to <eng>/evidence/<ip>/ and
        creates an info-level finding on the host titled "Manual evidence:
        <filename>" so it shows up in the Findings tab with a link.

        body: {ip: "10.0.0.5", filename: "screenshot.png",
               data: "<base64>", note?: "optional context"}
        """
        import base64
        import os
        import re as _re
        import time
        from ...core.store import Store
        from ...core.models import Host, Vuln

        ip = str(body.get("ip", "")).strip()
        filename = str(body.get("filename", "")).strip()
        data_b64 = str(body.get("data", ""))
        note = str(body.get("note", "")).strip()

        if not ip or not filename or not data_b64:
            raise HTTPException(400, "ip, filename, and data (base64) required")
        # Path sanitization — refuse anything that looks like a traversal.
        if _re.search(r"[/\\]|\.\.", filename):
            raise HTTPException(400, "filename must be a bare name (no slashes / '..')")
        try:
            raw = base64.b64decode(data_b64, validate=True)
        except (ValueError, TypeError):
            raise HTTPException(400, "data is not valid base64")
        # 25 MB cap — evidence files can be big (captures, PDFs) but we won't
        # let a mistake ballon the engagement dir.
        if len(raw) > 25 * 1024 * 1024:
            raise HTTPException(413, "evidence file too large (max 25 MB)")

        # IP sanity — allow synthetic hosts (container:foo, generic-import,
        # active-directory) so evidence for those "hosts" has a home too.
        safe_ip = _re.sub(r"[^A-Za-z0-9._:-]+", "_", ip)[:80]
        ev_dir = os.path.join(ctx.eng_dir, "evidence", safe_ip)
        os.makedirs(ev_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%dT%H%M%S")
        # Prefix filename with timestamp so multiple uploads of the same
        # `screenshot.png` don't clobber each other.
        safe_fn = _re.sub(r"[^A-Za-z0-9._-]+", "_", filename)[:120]
        dest = os.path.join(ev_dir, f"{stamp}_{safe_fn}")
        with open(dest, "wb") as fh:
            fh.write(raw)

        rel_path = os.path.relpath(dest, ctx.eng_dir)

        # Create the info-level tracker finding on the host.
        title = f"Manual evidence: {filename}"
        output = f"Attached by {x_tester} at {stamp}\nFile: {rel_path}\nSize: {len(raw)} bytes"
        if note:
            output += f"\n\nNote:\n{note}"
        with Store(db_path) as st:
            host = st.get_host(ip) or Host(ip=ip)
            if not host.is_up:
                host.state = "up"
            host.vulns.append(Vuln(
                ip=ip, port=None, protocol="tcp",
                script_id=f"evidence-{stamp}",
                state="finding", title=title,
                output=output[:4000], severity="info",
                source="manual-evidence", confidence="confirmed"))
            st.upsert_host(host, merge=True)

        broker.publish({"type": "evidence", "ip": ip, "path": rel_path,
                        "by": x_tester})
        return {"ok": True, "path": rel_path, "bytes": len(raw)}

    @app.get("/api/evidence/{ip}/{name}")
    def download_evidence(ip: str, name: str):
        """Serve back an evidence file the tester uploaded, so the "Manual
        evidence" finding row can link to it."""
        import os
        import re as _re
        from fastapi.responses import FileResponse
        if _re.search(r"[/\\]|\.\.", name):
            raise HTTPException(400, "bad filename")
        safe_ip = _re.sub(r"[^A-Za-z0-9._:-]+", "_", ip)[:80]
        path = os.path.join(ctx.eng_dir, "evidence", safe_ip, name)
        if not os.path.isfile(path):
            raise HTTPException(404, "no such evidence file")
        return FileResponse(path, filename=name)

    # ---- /api/known/* — shared-surface readers ------------------------------
    # These expose recce's cross-service union views (Phase 7b). Each reader
    # module unions facts learned across every enumeration path into one
    # engagement-wide view, which the KnownAssets tab renders for the operator.
    #
    # Hash-bearing endpoints (known/hashes) MUST NOT return full secret
    # values — mimic CredentialsPanel and truncate the hash preview so a
    # cross-origin read of the API (mis-shared workbench link, cached page)
    # can't lift them wholesale. Kerberos blobs are never previewed at all;
    # only their category counts and per-user attribution.

    def _hosts_only():
        """All hosts (up + down) — the shared-surface readers accept anything
        the store has; keeping down hosts in the union means late enrichment
        (an offline reboot, a DNS PTR added after the fact) isn't silently
        dropped."""
        from ...core.store import Store
        with Store(db_path) as st:
            return st.all_hosts()

    def _creds_only():
        from ...core.store import Store
        with Store(db_path) as st:
            return st.all_credentials()

    def _mask_hash(v: str, keep: int = 12) -> str:
        """Truncate a hash-like secret so a leaked API response can't lift
        the full value. Kerberos blobs (start with `$`) are longer than the
        preview budget; the same rule applies."""
        s = (v or "").strip()
        if len(s) <= keep:
            return s
        return s[:keep] + "…"

    @app.get("/api/known/users")
    def known_users():
        """Prioritized union of user accounts across every host — the same
        list that seeds IPMI RAKP / SSH spray / RID-cycle enrichment.
        `cap=500` because this is the GUI (no spray budget); the returned
        `sources` names every producer that contributed."""
        from ...creds import known_users as ku
        hosts = _hosts_only()
        r = ku.known_users(hosts, cap=500)
        return {"items": [{"name": n} for n in r["users"]],
                "total": r["total_known"],
                "sources": r["sources"],
                "capped": r["capped"]}

    @app.get("/api/known/hashes")
    def known_hashes():
        """Inventory of every crackable secret recce is holding — NT hashes
        from the cred store + hashcat-format loot files. Hash values are
        truncated for GUI display; the raw material stays on disk under
        <eng>/loot/*.hash for hashcat."""
        import os
        from ...creds import known_hashes as kh
        creds = _creds_only()
        loot_dir = os.path.join(ctx.eng_dir, "loot")
        r = kh.known_hashes(creds, loot_dir=loot_dir)
        # Per-user rows — one entry per (user, kind) so the table can list
        # "alice — nthash from cred_store, krb5tgs from loot/kerberoast.hash".
        items = []
        for user_lc, entries in r["by_user"].items():
            for e in entries:
                items.append({
                    "user": user_lc,
                    "domain": e.get("domain", ""),
                    "kind": e.get("kind", ""),
                    "source": e.get("source", ""),
                    "hashcat_mode": e.get("hashcat_mode", 0),
                    "value_preview": _mask_hash(str(e.get("value", ""))),
                })
        items.sort(key=lambda x: (x["user"], x["kind"]))
        return {"items": items,
                "total": r["total"],
                "by_mode": r["by_mode"],
                "categories": r["categories"],
                "unique_users": len(r["by_user"])}

    @app.get("/api/known/domains")
    def known_domains():
        """AD / Kerberos domain view: DNS <-> NetBIOS pairs, primary
        selection, host / cred counts per domain."""
        from ...core import known_domains as kd
        hosts = _hosts_only()
        creds = _creds_only()
        r = kd.known_domains(hosts, creds=creds)
        return {"items": r["domains"],
                "total": r["total_known"],
                "primary_dns": r["primary_dns"],
                "primary_netbios": r["primary_netbios"],
                "operator_domain": r["operator_domain"]}

    @app.get("/api/known/hostnames")
    def known_hostnames():
        """Every DNS / short name recce learned, deduped engagement-wide.
        `by_host` is included so the table can render the per-host name list
        without a second call."""
        from ...core import known_hostnames as kh
        hosts = _hosts_only()
        r = kh.known_hostnames(hosts)
        items = [{"name": n} for n in r["names"]]
        return {"items": items,
                "total": r["total_known"],
                "capped": r["capped"],
                "by_host": r["by_host"]}

    @app.get("/api/known/hostkeys")
    def known_hostkeys():
        """SHA256 host-key fingerprint correlation — a `reused` entry
        (same fingerprint on >=2 distinct IPs) means shared cloning /
        golden image and is the interesting signal."""
        from ...core import known_hostkeys as kh
        hosts = _hosts_only()
        r = kh.known_hostkeys(hosts)
        items = []
        for fp, endpoints in r["by_fingerprint"].items():
            # Pull key_type off the first reused-entry that matches, or
            # walk by_ip. It's simpler to derive from the reused table
            # when present; otherwise leave blank.
            kt = ""
            for reused in r["reused"]:
                if reused["fingerprint"] == fp:
                    kt = reused["key_type"]
                    break
            items.append({
                "fingerprint": fp,
                "key_type": kt,
                "endpoints": endpoints,
                "endpoint_count": len(endpoints),
                "reused": any(ru["fingerprint"] == fp for ru in r["reused"]),
            })
        items.sort(key=lambda x: (not x["reused"], -x["endpoint_count"]))
        return {"items": items,
                "total": len(items),
                "reused": r["reused"]}

    @app.get("/api/known/mail-accounts")
    def known_mail_accounts():
        """SMTP / IMAP / POP3 identity union — a hit on one transport seeds
        the other two, per RFC 8314 (they share one account namespace)."""
        from ...creds import known_mail_accounts as km
        hosts = _hosts_only()
        r = km.known_mail_accounts(hosts)
        return {"items": r["accounts"],
                "total": len(r["accounts"]),
                "by_user": r["by_user"]}

    @app.get("/api/known/ot-assets")
    def known_ot_assets():
        """OT / ICS asset dictionary — vendor / model / serial / firmware
        deduped across every OT probe path (Modbus / EtherNet-IP / etc.).
        `by_firmware` powers a "how many boxes on that firmware rev" view."""
        from ...core import known_ot_assets as ka
        hosts = _hosts_only()
        r = ka.known_ot_assets(hosts)
        # by_firmware keys are tuples — flatten for JSON.
        by_fw = [{"vendor": k[0], "model": k[1], "firmware": k[2], "count": v}
                 for k, v in r.get("by_firmware", {}).items()]
        return {"items": r["assets"],
                "total": len(r["assets"]),
                "by_vendor": {k: len(v) for k, v in r["by_vendor"].items()},
                "by_firmware": by_fw}

    @app.get("/api/known/devices")
    def known_devices():
        """Non-OT device registry — same shape as ot-assets but for IT
        gear (routers, switches, NAS, printers) with per-device CVE
        candidates when a vendor-model-firmware maps to a KEV entry."""
        from ...core import known_devices as kd
        hosts = _hosts_only()
        r = kd.known_devices(hosts)
        return {"items": r["devices"],
                "total": len(r["devices"]),
                "by_vendor": {k: len(v) for k, v in r["by_vendor"].items()},
                "cve_candidates": r.get("cve_candidates", [])}

    @app.get("/api/relay-targets")
    def relay_targets():
        """ntlmrelayx `-tf` target list: hosts where SMB signing is not
        required and the port is open. `include_unknown` / `include_dcs`
        stay at their safe defaults — the GUI shows the same set the
        writer emits by default."""
        from ...core import relay_targets as rt
        hosts = _hosts_only()
        lines = rt.relay_target_lines(hosts)
        items = [{"target": ln} for ln in lines]
        return {"items": items, "total": len(items)}

    @app.get("/api/hashloot/categories")
    def hashloot_categories():
        """The hashcat category table — one row per loot file recce knows
        how to write. Consumed by the KnownAssets 'hashloot' sub-tab as
        the reference the operator maps a hashcat -m number to."""
        from ...creds import hashloot as hl
        items = [{"key": k, "filename": v[0], "mode": v[1], "description": v[2]}
                 for k, v in hl.CATEGORIES.items()]
        items.sort(key=lambda x: x["mode"])
        return {"items": items, "total": len(items)}
