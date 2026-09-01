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


# ---- shared /api/attack-chain/* step assembly -------------------------------
# All three chain endpoints (AD / Cloud / Web) build a raw step tuple list
# and hand it to `_assemble_chain`, which computes proven/blocked/pending,
# the per-step `contributing_hosts` dedup, and the hero summary. Keeps the
# three endpoints from re-implementing the same reduction three ways.
#
# Raw tuple shape:
#   (id, title, proven_bool, evidence_list, deps, next_step_str, surfaces)
def _assemble_chain(raw_steps: list) -> dict:
    step_ids = [s[0] for s in raw_steps]
    proven_flags = [bool(t[2]) for t in raw_steps]
    steps_out: list[dict] = []
    for i, (sid, title, _p, ev, deps, next_step, surfaces) in enumerate(
            raw_steps):
        if proven_flags[i]:
            status = "proven"
        elif any(proven_flags[j] for j in range(i + 1, len(raw_steps))):
            # An upstream / later step already proved — this leg was skipped
            # past. Mark it blocked so the walkthrough highlights the gap.
            status = "blocked"
        else:
            status = "pending"
        # contributing_hosts: dedup IPs across this step's evidence rows,
        # preserving first-seen order. Rows with no ip (union-derived
        # evidence like "known_users") don't contribute.
        seen_hosts: list[str] = []
        for e in ev:
            ip = (e.get("ip") or "").strip()
            if ip and ip not in seen_hosts:
                seen_hosts.append(ip)
        steps_out.append({
            "id": sid,
            "title": title,
            "status": status,
            "evidence": ev,
            "next_step": "" if status == "proven" else next_step,
            "depends_on": list(deps),
            "shared_surfaces_read": list(surfaces),
            "contributing_hosts": seen_hosts,
        })

    proven_n = sum(1 for s in steps_out if s["status"] == "proven")
    pending_n = sum(1 for s in steps_out if s["status"] == "pending")
    blocked_n = sum(1 for s in steps_out if s["status"] == "blocked")
    highest = ""
    for s in steps_out:
        if s["status"] == "proven":
            highest = s["id"]
    # Next action: blocked first (names the skipped-past prereq), then the
    # first pending step in declared order.
    next_action = ""
    for s in steps_out:
        if s["status"] == "blocked":
            next_action = s["next_step"]
            break
    if not next_action:
        for s in steps_out:
            if s["status"] == "pending":
                next_action = s["next_step"]
                break

    return {
        "steps": steps_out,
        "summary": {
            "proven": proven_n,
            "pending": pending_n,
            "blocked": blocked_n,
            "total": len(steps_out),
            "highest_reached": highest,
            "next_action": next_action,
            "step_ids": step_ids,
        },
    }


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

    # ---- /api/exploit-surface — Phase C tester "what's my next move" surface -----
    # Every recce Vuln at critical/high may carry:
    #   * exploit_note  — 1-3 sentences of tester-facing "your next move"
    #   * depth_tier    — T0..T4 rubric slug (see recce.core.depth)
    # This endpoint filters + ranks the annotated set + groups them by attack
    # chain so the WebUI ExploitSurface tab can render "here's what to run
    # next" without any post-processing on the client.
    @app.get("/api/exploit-surface")
    def exploit_surface():
        from ...core import depth as _depth
        from ...core import tracking
        from ...core.store import Store
        from .._common import _SEV_ORDER

        # Attack-chain groups. A finding can belong to more than one group
        # (an SMB Log4Shell relay is both AD chain + Web n-day, etc.).
        SRC_GROUPS = {
            "AD chain": {"smb", "ldap", "kerberos", "winrm", "msrpc"},
            "Web n-day": {"http", "web", "webdav", "api"},
            "Storage exposure": {"nfs", "iscsi", "nbd_ndmp", "mongodb", "redis",
                                 "elasticsearch", "memcached", "couchdb"},
            "OT/ICS": {"modbus", "s7", "bacnet", "opcua", "dnp3", "iec104",
                       "enip", "coap"},
            "Cloud + container": {"docker", "docker_registry", "kubernetes",
                                  "vault", "vcenter", "vsphere", "cloud_metadata",
                                  "consul", "nomad", "etcd"},
            "Mail": {"smtp", "imap", "pop3"},
        }
        # Web n-day extra gate: only tier >= t1 (T1 verify or better).
        WEB_MIN_RANK = _depth.rank(_depth.T1_VERIFY)
        # Kind (script_id) substring markers for the "default creds / spray" bucket.
        SPRAY_MARKERS = ("default_creds", "blank_login", "weak_creds", "anon", "unauth")

        sev_order = _SEV_ORDER
        with Store(db_path) as st:
            hosts = st.all_hosts()

        items: list[dict] = []
        for h in hosts:
            if not h.is_up:
                continue
            host_hint = h.hostname or ""
            for v in h.vulns:
                note = (getattr(v, "exploit_note", "") or "").strip()
                tier = (getattr(v, "depth_tier", "") or "").strip()
                if not note and not tier:
                    continue
                items.append({
                    "key": tracking.vuln_row_key(v),
                    "ip": h.ip,
                    "port": v.port,
                    "protocol": v.protocol or "tcp",
                    "service": v.source or "",
                    "title": v.title or v.script_id or "finding",
                    "severity": v.severity or "info",
                    "depth_tier": tier,
                    "tier_label": _depth.label(tier) if tier else "",
                    "exploit_note": note,
                    "kev": bool(getattr(v, "kev", False)),
                    "cwes": list(getattr(v, "cwes", []) or []),
                    "cves": list(getattr(v, "ids", []) or []),
                    "epss": round((getattr(v, "epss", 0.0) or 0.0) * 100),
                    "script_id": v.script_id or "",
                    "host_hint": host_hint,
                })

        # Rank: depth_tier DESC, severity DESC, kev DESC, epss DESC.
        # Sort ASC on the negated rank so higher tier / more severe / kev / epss
        # bubble up first.
        items.sort(key=lambda it: (
            -_depth.rank(it["depth_tier"]),
            sev_order.get(it["severity"], 9),
            0 if it["kev"] else 1,
            -it["epss"],
        ))

        MAX_ITEMS = 500
        truncated = len(items) > MAX_ITEMS
        items = items[:MAX_ITEMS]

        # Groups: name -> list of finding keys (order preserved from the ranked list).
        groups: dict[str, list[str]] = {}
        for name in list(SRC_GROUPS) + ["Default creds / spray", "KEV top-10"]:
            groups[name] = []
        for it in items:
            svc = (it["service"] or "").lower()
            script = (it["script_id"] or "").lower()
            tier_rank = _depth.rank(it["depth_tier"])
            for gname, srcs in SRC_GROUPS.items():
                if svc in srcs:
                    if gname == "Web n-day" and tier_rank < WEB_MIN_RANK:
                        continue
                    groups[gname].append(it["key"])
            if any(m in script for m in SPRAY_MARKERS):
                groups["Default creds / spray"].append(it["key"])
        # KEV top-10 is its own ranking (epss DESC, severity DESC), capped at 10.
        kev_ranked = sorted(
            [it for it in items if it["kev"]],
            key=lambda it: (-it["epss"], sev_order.get(it["severity"], 9)),
        )[:10]
        groups["KEV top-10"] = [it["key"] for it in kev_ranked]
        # Drop empty buckets so the UI can skip rendering unused tabs.
        groups = {k: v for k, v in groups.items() if v}

        return {"items": items, "total": len(items), "groups": groups,
                "truncated": truncated}

    # ---- /api/attack-chain/ad — Phase D AD attack-chain walkthrough --------------
    # A single narrative that walks a tester through the whole AD compromise
    # story with CURRENT engagement state visible at each step. Every step
    # reads the same shared-surface unions the KnownAssets tab renders,
    # plus per-service finding kinds (null_session, ldap_anon_read,
    # asrep_roast, msrpc_coercion, kerberos_spray_success, adcs-esc*).
    # A step is "proven" when engagement state satisfies its check, "pending"
    # otherwise with a next_step advisory naming the exact command to run.
    @app.get("/api/attack-chain/ad")
    def attack_chain_ad():
        import os
        from ...core import known_domains as _kd
        from ...core import relay_targets as _rt
        from ...core.store import Store
        from ...creds import known_hashes as _kh
        from ...creds import known_users as _ku

        with Store(db_path) as st:
            hosts = st.all_hosts()
            creds = st.all_credentials()

        # Shared-surface reads (mirrors the KnownAssets tab exactly).
        loot_dir = os.path.join(ctx.eng_dir, "loot")
        domains_r = _kd.known_domains(hosts, creds=creds)
        users_r = _ku.known_users(hosts, cap=500)
        hashes_r = _kh.known_hashes(creds, loot_dir=loot_dir)
        relay_lines = _rt.relay_target_lines(hosts)

        # Match on script_id OR title (both are lowercased); `kind` is a
        # tag on the finding dict, and depending on which builder wrote it,
        # it lands on either the script_id or the title — matching both
        # keeps us honest across the whole service surface.
        def _collect(tokens: list[str]) -> list[dict]:
            out: list[dict] = []
            for h in hosts:
                for v in h.vulns:
                    sid = (v.script_id or "").lower()
                    ttl = (v.title or "").lower()
                    if any(t in sid or t in ttl for t in tokens):
                        out.append({
                            "finding_kind": v.script_id or v.title or "finding",
                            "ip": h.ip,
                            "port": v.port,
                            "output_excerpt": (v.output or "")[:240],
                        })
            return out

        # 1. discover_dc — a host with Kerberos 88 + LDAP 389 + SMB 445 open.
        #    Proven when known_domains also names a primary DNS domain, so
        #    "some box has 88 open" doesn't over-claim in the empty case.
        dc_hosts = []
        for h in hosts:
            open_ports = {p.portid for p in h.ports if p.state == "open"}
            if {88, 389, 445}.issubset(open_ports):
                dc_hosts.append(h)
        dc_proven = bool(dc_hosts) and bool(
            domains_r["primary_dns"] or domains_r["total_known"])
        dc_evidence = [{
            "finding_kind": "dc_open_ports",
            "ip": h.ip, "port": 88,
            "output_excerpt": (
                f"Kerberos/LDAP/SMB open — hostname {h.hostname or '(none)'}"
                + (f" — domain {domains_r['primary_dns']}"
                   if domains_r['primary_dns'] else "")),
        } for h in dc_hosts]

        # 2. null_session — SMB null / NTLM info disclosure. Evidence carries
        #    whichever finding hit; the AV pairs land in the vuln.output.
        ns_ev = _collect(["null_session", "null / anonymous session",
                          "smb_ntlm_info_disclosure",
                          "ntlm information disclosure"])

        # 3. anon_ldap_read — recce.services.ldap emits `ldap_anon_read`
        #    (also matches the title "Anonymous LDAP read").
        anon_ev = _collect(["ldap_anon_read", "anonymous ldap read"])

        # 4. user_enum — >=5 unique users unioned across hosts.
        users_total = int(users_r.get("total_known", 0))
        user_enum_proven = users_total >= 5
        user_ev = [{"finding_kind": "known_users", "ip": "",
                    "port": None,
                    "output_excerpt": (
                        f"{users_total} unique user(s) unioned across sources: "
                        + ", ".join(users_r.get("sources") or []))}] \
                  if users_total else []

        # 5. unauth_roast — AS-REP roast finding OR mode 18200 hash present.
        asrep_ev = _collect(["asrep_roast", "as-rep roast"])
        asrep_mode_count = int(hashes_r.get("by_mode", {}).get(18200, 0))
        if asrep_mode_count and not asrep_ev:
            asrep_ev = [{"finding_kind": "asrep_hash", "ip": "",
                         "port": None,
                         "output_excerpt": (
                             f"{asrep_mode_count} AS-REP hash(es) in loot "
                             f"(hashcat -m 18200)")}]

        # 6. cred_acquired — any non-nthash password/nthash from cracked or
        #    spray-validated, or any user with an NT hash in by_user.
        cred_ev: list[dict] = []
        for c in creds:
            src = (c.source or "").lower()
            if c.kind == "password" and ("crack" in src or "spray" in src
                                          or "validated" in src):
                cred_ev.append({
                    "finding_kind": f"credential:{c.kind}", "ip": c.origin_ip,
                    "port": None,
                    "output_excerpt": f"{c.label} — password from {src or 'source'}",
                })
        if hashes_r.get("by_user"):
            # Include the user list so the tester sees who to spray.
            names = sorted(hashes_r["by_user"].keys())[:8]
            cred_ev.append({
                "finding_kind": "nthash_by_user", "ip": "", "port": None,
                "output_excerpt": (f"{len(hashes_r['by_user'])} user(s) with "
                                   f"a captured hash: {', '.join(names)}"),
            })

        # 7. coercion_reachable — MSRPC coercion finding OR any relay target.
        coerce_ev = _collect(["msrpc_coercion", "coercion interfaces"])
        if relay_lines and not coerce_ev:
            coerce_ev = [{"finding_kind": "relay_targets", "ip": "",
                          "port": None,
                          "output_excerpt": (
                              f"{len(relay_lines)} relayable host(s): "
                              + ", ".join(relay_lines[:6]))}]
        elif relay_lines:
            coerce_ev.append({"finding_kind": "relay_targets", "ip": "",
                              "port": None,
                              "output_excerpt": (
                                  f"{len(relay_lines)} relayable host(s) "
                                  "(ntlmrelayx -tf)")})

        # 8. authed_kerberoast — spray-success finding OR any krb5tgs hash.
        kroast_ev = _collect(["kerberos_spray_success", "kerberos spray"])
        krb_tgs_users = [u for u, entries in hashes_r.get("by_user", {}).items()
                         if any(e.get("kind") == "kerberoast" for e in entries)]
        if krb_tgs_users and not kroast_ev:
            kroast_ev = [{"finding_kind": "krb5tgs_hash", "ip": "",
                          "port": None,
                          "output_excerpt": (
                              f"{len(krb_tgs_users)} kerberoast blob(s): "
                              + ", ".join(krb_tgs_users[:6]))}]

        # 9. lsa_or_ntds_dump — any Credential(kind='nthash') exists.
        nthash_creds = [c for c in creds if c.kind == "nthash"]
        nthash_ev = [{"finding_kind": "credential:nthash",
                      "ip": c.origin_ip, "port": None,
                      "output_excerpt": (
                          f"{c.label} — NT hash from {c.source or 'source'}")}
                     for c in nthash_creds[:8]]

        # 10. adcs_esc — any Vuln whose script_id or title flags an ESC.
        adcs_ev = _collect(["adcs-esc", "adcs_esc", "adcs esc"])

        # 11. da_path — a Credential whose account is Domain Admin (via any
        #     Account row with admincount=1) AND recce holds either the
        #     plaintext password or an NT hash.
        da_names: set[str] = set()
        for h in hosts:
            for a in h.accounts or []:
                if str(a.attrs.get("admincount") or "") == "1":
                    da_names.add((a.name or "").lower())
                mo = str(a.attrs.get("memberof") or "").lower()
                if "domain admins" in mo:
                    da_names.add((a.name or "").lower())
        da_ev: list[dict] = []
        for c in creds:
            u = (c.username or "").lower()
            if not u or u not in da_names:
                continue
            if c.kind in ("password", "nthash") and c.secret:
                da_ev.append({
                    "finding_kind": f"da_credential:{c.kind}",
                    "ip": c.origin_ip, "port": None,
                    "output_excerpt": (
                        f"{c.label} (Domain Admin) — {c.kind} from "
                        f"{c.source or 'source'}"),
                })

        # Assemble the ordered step list. Each step's next_step is the
        # "your next move" advisory the tester needs when the step is
        # still pending.
        raw_steps = [
            ("discover_dc", "Discover a Domain Controller", dc_proven,
             dc_evidence, [],
             "Run `recce enum` against the target subnet, focusing on "
             "88/389/445/636/3268.",
             ["known_domains"]),
            ("null_session",
             "Anonymous SMB / NTLM info disclosure",
             bool(ns_ev), ns_ev, ["discover_dc"],
             "nxc smb <dc> -u '' -p '' --shares --users --pass-pol; also "
             "confirm NTLM SSP with `nmap --script smb-security-mode,smb2-security-mode`.",
             ["known_domains"]),
            ("anon_ldap_read",
             "Anonymous LDAP read",
             bool(anon_ev), anon_ev, ["discover_dc"],
             "ldapsearch -x -H ldap://<dc> -b '' -s base '(objectClass=*)' "
             "namingContexts  # then walk defaultNamingContext for users/groups.",
             ["known_domains"]),
            ("user_enum",
             "Enumerate domain users",
             user_enum_proven, user_ev,
             ["null_session", "anon_ldap_read"],
             "kerbrute userenum --dc <dc> -d <domain> users.txt  # seed users.txt "
             "from any anonymous read or SMB SAMR you got.",
             ["known_users"]),
            ("unauth_roast",
             "AS-REP roast (no credential)",
             bool(asrep_ev), asrep_ev, ["user_enum"],
             "impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt "
             "-dc-ip <dc>  # then hashcat -m 18200 asrep.hash rockyou.txt.",
             ["known_users", "known_hashes"]),
            ("cred_acquired",
             "Acquire a domain credential",
             bool(cred_ev), cred_ev,
             ["user_enum", "unauth_roast"],
             "After cracking, validate: nxc smb <dc> -u '<user>' -p '<pass>' "
             "(or -H '<nthash>').",
             ["known_users", "known_hashes"]),
            ("coercion_reachable",
             "Reach a coercion + relay chain",
             bool(coerce_ev), coerce_ev, ["discover_dc"],
             "Confirm SMB signing NOT required on member servers "
             "(relay-targets.txt) + trigger via PetitPotam / PrinterBug / "
             "DFSCoerce; catch with `ntlmrelayx -tf relay-targets.txt "
             "-smb2support`.",
             ["relay_targets"]),
            ("authed_kerberoast",
             "Authenticated Kerberoast",
             bool(kroast_ev), kroast_ev, ["cred_acquired"],
             "impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <dc> "
             "-request  # then hashcat -m 13100 kerberoast.hash rockyou.txt.",
             ["known_hashes"]),
            ("lsa_or_ntds_dump",
             "LSA / NTDS.dit dump",
             bool(nthash_ev), nthash_ev,
             ["cred_acquired"],
             "impacket-secretsdump <domain>/<local-admin>:<pass>@<host>  # or "
             "on a DC: impacket-secretsdump -just-dc <domain>/<user>@<dc>.",
             ["known_hashes"]),
            ("adcs_esc",
             "ADCS ESC1-ESC16",
             bool(adcs_ev), adcs_ev, ["cred_acquired"],
             "certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable  "
             "# then request per the matched ESCn playbook.",
             []),
            ("da_path",
             "Path to Domain Admin",
             bool(da_ev), da_ev,
             ["lsa_or_ntds_dump", "authed_kerberoast", "adcs_esc"],
             "Confirm DA on the DC: nxc smb <dc> -u '<da>' -H '<hash>'; then "
             "impacket-secretsdump -just-dc <domain>/'<da>'@<dc>.",
             ["known_users", "known_hashes"]),
        ]

        return _assemble_chain(raw_steps)

    # ---- /api/attack-chain/cloud — P1-5 cloud pivot chain --------------------
    # Six-step story: IMDS reachable → v1 open → IAM role disclosed → STS
    # creds extracted → object storage listed → secrets manager read.
    # Same step shape as the AD chain; contributing_hosts / next_action /
    # summary are computed by the shared _assemble_chain helper.
    @app.get("/api/attack-chain/cloud")
    def attack_chain_cloud():
        from ...core.store import Store

        with Store(db_path) as st:
            hosts = st.all_hosts()
            creds = st.all_credentials()

        # 1. imds_reachable — a cloud_metadata source finding whose kind
        #    contains "reachable" (e.g. imds_reachable). The name is the
        #    signal — the module writes the finding when the endpoint
        #    responded at least once.
        imds_reach_ev: list[dict] = []
        for h in hosts:
            for v in h.vulns:
                src = (v.source or "").lower()
                sid = (v.script_id or "").lower()
                ttl = (v.title or "").lower()
                if src == "cloud_metadata" and (
                        "reachable" in sid or "reachable" in ttl):
                    imds_reach_ev.append({
                        "finding_kind": v.script_id or v.title or "imds",
                        "ip": h.ip, "port": v.port,
                        "output_excerpt": (v.output or "")[:240],
                    })

        # 2. imds_v1_present — v1 endpoint responds without a token (the
        #    module emits `imds_v1_enabled`).
        imds_v1_ev: list[dict] = []
        for h in hosts:
            for v in h.vulns:
                sid = (v.script_id or "").lower()
                ttl = (v.title or "").lower()
                if "imds_v1_enabled" in sid or "imds v1" in ttl \
                        or "imdsv1" in sid or "imdsv1" in ttl:
                    imds_v1_ev.append({
                        "finding_kind": v.script_id or v.title or "imds_v1",
                        "ip": h.ip, "port": v.port,
                        "output_excerpt": (v.output or "")[:240],
                    })

        # 3. iam_role_disclosed — finding kind, title, or exploit_note names
        #    IAM / STS / a role. Broad match — cloud modules label these many
        #    ways depending on which provider surfaced.
        iam_ev: list[dict] = []
        for h in hosts:
            for v in h.vulns:
                sid = (v.script_id or "").lower()
                ttl = (v.title or "").lower()
                note = (getattr(v, "exploit_note", "") or "").lower()
                text = f" {sid} {ttl} {note} "
                if any(m in text for m in
                       (" iam", "iam_", " sts", "sts_", "assume-role",
                        "assume_role", " role ", "role_")):
                    iam_ev.append({
                        "finding_kind": v.script_id or v.title or "iam",
                        "ip": h.ip, "port": v.port,
                        "output_excerpt": (v.output or "")[:240],
                    })

        # 4. sts_creds_extracted (T3 gate) — a Credential(source='imds') proves
        #    the tester grabbed STS session creds and pulled them into the
        #    engagement store.
        imds_creds = [c for c in creds if (c.source or "").lower() == "imds"]
        sts_ev = [{
            "finding_kind": f"credential:{c.kind}",
            "ip": c.origin_ip, "port": None,
            "output_excerpt": f"{c.label} — {c.kind} from IMDS",
        } for c in imds_creds[:8]]

        # 5. s3_buckets_listed — any finding whose kind/title names S3 / GCS /
        #    Azure blob listing. We match "bucket" or a provider marker plus a
        #    listing verb (list / public / readable / enum).
        buckets_ev: list[dict] = []
        for h in hosts:
            for v in h.vulns:
                sid = (v.script_id or "").lower()
                ttl = (v.title or "").lower()
                text = f" {sid} {ttl} "
                has_target = ("bucket" in text or "s3_" in text
                              or " s3 " in text or "gcs" in text
                              or "gs://" in text or "azure_blob" in text
                              or "azblob" in text)
                has_verb = ("list" in text or "public" in text
                            or "readable" in text or "enum" in text
                            or "world" in text)
                if has_target and has_verb:
                    buckets_ev.append({
                        "finding_kind": v.script_id or v.title or "bucket",
                        "ip": h.ip, "port": v.port,
                        "output_excerpt": (v.output or "")[:240],
                    })

        # 6. secrets_manager_read — Vault or SecretsManager style finding
        #    kinds indicating a secret was pulled from a managed vault.
        secrets_ev: list[dict] = []
        for h in hosts:
            for v in h.vulns:
                sid = (v.script_id or "").lower()
                ttl = (v.title or "").lower()
                text = f" {sid} {ttl} "
                if any(m in text for m in
                       ("vault_read", "vault_secret", "secretsmanager",
                        "secrets_manager", "kv_read", "kv-read",
                        "keyvault", "key_vault")):
                    secrets_ev.append({
                        "finding_kind": v.script_id or v.title or "vault",
                        "ip": h.ip, "port": v.port,
                        "output_excerpt": (v.output or "")[:240],
                    })

        raw_steps = [
            ("imds_reachable", "IMDS endpoint reachable",
             bool(imds_reach_ev), imds_reach_ev, [],
             "curl -s -m 2 http://169.254.169.254/latest/meta-data/  # from a "
             "compromised host or SSRF primitive; GCP uses "
             "metadata.google.internal, Azure 169.254.169.254 with a Metadata "
             "header.",
             []),
            ("imds_v1_present", "IMDSv1 accessible (no token required)",
             bool(imds_v1_ev), imds_v1_ev, ["imds_reachable"],
             "curl -sSf http://169.254.169.254/latest/meta-data/  # if this "
             "returns 200 without an X-aws-ec2-metadata-token header, IMDSv1 "
             "is enabled and SSRF is enough to pivot.",
             []),
            ("iam_role_disclosed", "IAM role attached + name disclosed",
             bool(iam_ev), iam_ev, ["imds_v1_present"],
             "curl -s http://169.254.169.254/latest/meta-data/iam/info | jq  "
             "# then list the role's inline + attached policies with aws iam "
             "list-attached-role-policies / get-role-policy.",
             []),
            ("sts_creds_extracted", "STS session credentials extracted",
             bool(sts_ev), sts_ev, ["iam_role_disclosed"],
             "curl -s http://169.254.169.254/latest/meta-data/iam/"
             "security-credentials/<role>  # export "
             "AccessKeyId/SecretAccessKey/Token and confirm with aws sts "
             "get-caller-identity.",
             []),
            ("s3_buckets_listed", "Cloud object storage enumerated",
             bool(buckets_ev), buckets_ev, ["sts_creds_extracted"],
             "aws s3 ls  # then aws s3api list-objects --bucket <b>. GCP: "
             "gsutil ls gs://; Azure: az storage container list.",
             []),
            ("secrets_manager_read", "Secrets manager / vault read",
             bool(secrets_ev), secrets_ev, ["sts_creds_extracted"],
             "aws secretsmanager list-secrets && aws secretsmanager "
             "get-secret-value --secret-id <arn>  # Vault: vault kv list "
             "secret/; GCP: gcloud secrets versions access latest --secret=<n>.",
             []),
        ]
        return _assemble_chain(raw_steps)

    # ---- /api/attack-chain/web — P1-6 web n-day chain -----------------------
    # Six-step story: fingerprint → pinned versions → KEV match → safe
    # verify (T2) → OOB callback → authenticated session.
    @app.get("/api/attack-chain/web")
    def attack_chain_web():
        from ...core.store import Store

        WEB_SOURCES = {"http", "web", "webdav", "api"}

        with Store(db_path) as st:
            hosts = st.all_hosts()
            creds = st.all_credentials()

        # 1. web_surface_fingerprinted — any open http/web port that has
        #    both product AND version set. Nmap version-scan is what
        #    populates these; a bare "http" service with no product is not
        #    enough.
        fp_ev: list[dict] = []
        for h in hosts:
            for p in h.ports:
                if p.state != "open":
                    continue
                svc = (p.service or "").lower()
                product = getattr(p, "product", "") or ""
                version = getattr(p, "version", "") or ""
                if ("http" in svc or "web" in svc) and product and version:
                    fp_ev.append({
                        "finding_kind": "web_fingerprint",
                        "ip": h.ip, "port": p.portid,
                        "output_excerpt": f"{product} {version}".strip(),
                    })

        # 2. product_version_pinned — >1 distinct (endpoint, banner) pairs.
        #    A single vhost gets you one n-day at best; two or more means
        #    the attack surface is real.
        pinned_uniq = {(e["ip"], e["port"], e["output_excerpt"]) for e in fp_ev}
        pinned_proven = len(pinned_uniq) > 1
        pinned_ev = fp_ev if pinned_proven else []

        # 3. kev_matched — a web-source Vuln flagged kev=True.
        kev_ev: list[dict] = []
        for h in hosts:
            for v in h.vulns:
                src = (v.source or "").lower()
                if src in WEB_SOURCES and bool(getattr(v, "kev", False)):
                    cves = ", ".join(list(getattr(v, "ids", []) or [])[:3])
                    excerpt = (cves + " — " + (v.title or "")).strip(" —")
                    kev_ev.append({
                        "finding_kind": v.script_id or v.title or "kev",
                        "ip": h.ip, "port": v.port,
                        "output_excerpt": excerpt[:240],
                    })

        # 4. poc_safe_verify_fires — T2 proof: any web-source Vuln whose
        #    depth_tier == "t2" (a controlled payload proved the exploit
        #    primitive).
        t2_ev: list[dict] = []
        for h in hosts:
            for v in h.vulns:
                src = (v.source or "").lower()
                tier = (getattr(v, "depth_tier", "") or "").lower()
                if src in WEB_SOURCES and tier == "t2":
                    t2_ev.append({
                        "finding_kind": v.script_id or v.title or "t2_proof",
                        "ip": h.ip, "port": v.port,
                        "output_excerpt": (v.output or "")[:240],
                    })

        # 5. oob_callback_triggered (T3 gate) — a specific OOB-callback
        #    finding kind. This is a manual step in most workflows
        #    (interactsh / Burp collaborator) so the kind is what proves it.
        oob_ev: list[dict] = []
        for h in hosts:
            for v in h.vulns:
                sid = (v.script_id or "").lower()
                ttl = (v.title or "").lower()
                text = f" {sid} {ttl} "
                if any(m in text for m in
                       ("oob_callback", "oob-callback",
                        "out-of-band callback", "dns_callback",
                        "interactsh", "collaborator_hit")):
                    oob_ev.append({
                        "finding_kind": v.script_id or v.title or "oob",
                        "ip": h.ip, "port": v.port,
                        "output_excerpt": (v.output or "")[:240],
                    })

        # 6. session_established — a Credential(source in {cracked,
        #    spray-validated}) proves the tester walked from n-day to an
        #    authenticated primitive. We accept any credential whose source
        #    field carries "crack" / "spray" as the marker.
        sess_ev: list[dict] = []
        for c in creds:
            src = (c.source or "").lower()
            if "crack" in src or "spray" in src or "validated" in src:
                sess_ev.append({
                    "finding_kind": f"credential:{c.kind}",
                    "ip": c.origin_ip, "port": None,
                    "output_excerpt": f"{c.label} — {c.kind} from "
                                      f"{src or 'source'}",
                })

        raw_steps = [
            ("web_surface_fingerprinted",
             "Web surface fingerprinted (product + version)",
             bool(fp_ev), fp_ev, [],
             "whatweb -a3 https://<target>/  # or nmap -sV -p "
             "80,443,8080,8443 <target>; feed the banner into searchsploit "
             "and https://vulners.com/.",
             []),
            ("product_version_pinned",
             "Multiple products / versions pinned to specific endpoints",
             pinned_proven, pinned_ev, ["web_surface_fingerprinted"],
             "For every distinct product+version cluster map to a KEV/EDB "
             "entry (searchsploit <product> <version>; cve.org / "
             "nvd.nist.gov).",
             []),
            ("kev_matched",
             "KEV-listed n-day matches the surface",
             bool(kev_ev), kev_ev, ["product_version_pinned"],
             "Pull the KEV row from CISA + confirm the fingerprint is in the "
             "affected range; queue a T1 safe-verify probe before firing any "
             "PoC.",
             []),
            ("poc_safe_verify_fires",
             "PoC safe-verify probe fires (T2 proof)",
             bool(t2_ev), t2_ev, ["kev_matched"],
             "Run the passive / deterministic verifier per the CVE playbook "
             "(curl-based probe or a nuclei template). Do NOT chain to full "
             "exploit until safe-verify hits.",
             []),
            ("oob_callback_triggered",
             "Out-of-band callback triggered (manual step)",
             bool(oob_ev), oob_ev, ["poc_safe_verify_fires"],
             "Stand up an OOB listener (interactsh-client or a namespaced "
             "Burp collaborator) and fire the marker payload; wait for the "
             "DNS / HTTP callback to prove blind exec.",
             []),
            ("session_established",
             "Authenticated session established",
             bool(sess_ev), sess_ev, ["oob_callback_triggered"],
             "curl -b <cookie> https://<target>/admin/  # or run the "
             "exploit's post-login primitive (RCE / file read / SSRF chain) "
             "via the acquired session.",
             []),
        ]
        return _assemble_chain(raw_steps)

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
