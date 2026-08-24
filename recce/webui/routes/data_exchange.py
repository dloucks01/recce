"""External-tool import, the shared playbook, ATT&CK coverage, and the attack-path
SVG."""
from __future__ import annotations

import os
import re

from fastapi import Body, FastAPI, Header, HTTPException

from ..jobs import recce_argv
from .._common import _detect_import_kind, _import_preview

# Deep-service module source labels — a finding with one of these means `sweep` ran.
_DEEP_SOURCES = {"smb", "ftp", "mssql", "mysql", "postgres", "mongodb", "redis",
                 "elasticsearch", "rsync", "nfs", "kerberos", "snmp", "docker",
                 "kubernetes", "ldap", "web", "api", "dns", "smtp"}


def register_data_exchange_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path
    jobs = ctx.jobs
    broker = ctx.broker

    def _hosts():
        from ...store import Store
        with Store(db_path) as st:
            return st.all_hosts(), (st.get_meta("engagement") or "recce engagement")

    @app.post("/api/import")
    def import_output(body: dict = Body(...), x_tester: str = Header(default="someone")):
        """Fold external tool output into the live engagement so the whole team sees it.
        Auto-detects the format (or takes an explicit `kind`) and routes to the same
        parsers the CLI uses: nmap/masscan -> `import`, on-target loot -> `ingest`, and
        netexec / GetUserSPNs / GetNPUsers / secretsdump -> credenum's parsers."""
        import base64
        import tempfile
        from ... import importers
        content_in = str(body.get("content", ""))
        filename = str(body.get("filename", ""))
        kind = str(body.get("kind", "auto")).lower()
        enc = str(body.get("encoding", "")).lower()
        if not content_in.strip():
            raise HTTPException(400, "no content to import")
        # Decode the upload to bytes ONCE. The browser sends base64 (binary-safe) so a
        # UTF-16 / BOM / binary file survives intact; older/plain callers may send raw text.
        try:
            raw_bytes = (base64.b64decode(content_in, validate=False) if enc == "base64"
                         else content_in.encode("utf-8", "replace"))
        except Exception:
            raise HTTPException(400, "could not decode the uploaded file")
        if len(raw_bytes) > 25_000_000:                  # ~25 MB — cap the REAL decoded size
            raise HTTPException(413, "import too large (max ~25 MB)")
        # Text-safe decode (UTF-16 is the default of a PowerShell redirect); bloodhound
        # re-reads raw_bytes below since a SharpHound zip is binary.
        content = importers.decode_bytes(raw_bytes)
        if not content.strip():                          # empty / whitespace-only decoded upload
            raise HTTPException(400, "no content to import")
        if kind in ("", "auto"):
            kind = _detect_import_kind(content, filename)
        if kind == "multiple":
            raise HTTPException(422, "this looks like more than one tool's output pasted "
                                "together — import them one at a time, or pick the exact "
                                "tool from the dropdown to force a single parser.")
        if kind == "unknown":
            raise HTTPException(422, "could not detect the format — pick the tool from the "
                                "dropdown. Supported: nmap/masscan (XML/-oG/-oN/-oL/-oJ), "
                                "netexec (any protocol), impacket GetUserSPNs / GetNPUsers / "
                                "secretsdump, Nessus/OpenVAS/nuclei/testssl, BloodHound+Certipy, "
                                "a credential list, and recce on-target loot.")
        # Dry-run: show what WOULD import (and a 0-row warning) before committing to the
        # shared engagement. The frontend calls this on file-select.
        if body.get("preview"):
            return _import_preview(kind, content, raw_bytes)
        # BloodHound (.zip, binary) + Certipy (.json): the SharpHound collection is a
        # zip, so accept a base64 payload, decode, and run it through the `recce ad`
        # engine (works with no creds — findings + graph, just no owned-account paths).
        if kind == "bloodhound":
            raw = raw_bytes                               # already decoded above (binary-safe)
            is_zip = raw[:2] == b"PK" or filename.lower().endswith(".zip")
            fd, tmp = tempfile.mkstemp(prefix="recce-import-",
                                       suffix=".zip" if is_zip else ".json")
            label = f"ad {filename or kind}"

            def _done_ad(job, _tmp=tmp):
                try:
                    os.remove(_tmp)                       # the job has read it; don't leak /tmp
                except OSError:
                    pass
                broker.publish({"type": "scan", "status": job.status,
                                "tester": x_tester, "targets": label})
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(raw)
                job = jobs.start(recce_argv("ad", tmp, "-o", eng_dir), on_done=_done_ad)
            except BaseException:
                try:
                    os.remove(tmp)                        # never leak the temp file on start failure
                except OSError:
                    pass
                raise
            broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
            return {"mode": "job", "id": job.id, "kind": kind}

        # nmap + on-target loot + fieldkit have a real CLI pipeline (host resolution,
        # merge, enrich): run it as a job so the browser streams progress like a scan.
        if kind in ("nmap", "loot", "fieldkit"):
            if kind == "nmap":
                # Choose the suffix from the CONTENT (parse_nmap_file dispatches on extension),
                # so the right parser runs: XML (-oX), grepable (-oG), or normal (-oN). The old
                # "starts with '<'" guess sent a -oN file to the gnmap parser and a BOM'd XML
                # to gnmap too.
                if "<nmaprun" in content[:4000] or content.lstrip().startswith("<?xml"):
                    suffix = ".xml"
                elif re.search(r"^Host:\s+\S+\s+\(", content, re.M):
                    suffix = ".gnmap"
                else:
                    # -oN (normal) / masscan -oL / -oJ: a NEUTRAL suffix so parse_nmap_file
                    # content-sniffs the real format (a .nmap suffix would force parse_normal
                    # and misparse a masscan list as zero hosts).
                    suffix = ".scan"
                cmd = "import"
            else:
                cmd, suffix = {"loot": ("ingest", ".txt"),
                               "fieldkit": ("fieldkit-import", ".json")}[kind]
            fd, tmp = tempfile.mkstemp(prefix="recce-import-", suffix=suffix)
            label = f"{cmd} {filename or kind}"

            def _done(job, _tmp=tmp):
                try:
                    os.remove(_tmp)                       # the job has read it; don't leak /tmp
                except OSError:
                    pass
                broker.publish({"type": "scan", "status": job.status,
                                "tester": x_tester, "targets": label})
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(content)
                job = jobs.start(recce_argv(cmd, tmp, "-o", eng_dir), on_done=_done)
            except BaseException:
                try:
                    os.remove(tmp)                        # never leak the temp file on start failure
                except OSError:
                    pass
                raise
            broker.publish({"type": "scan_started", "tester": x_tester, "targets": label})
            return {"mode": "job", "id": job.id, "kind": kind}

        # Credential-tool output: no CLI import exists, so parse + fold directly.
        from ... import credenum as ce
        from ...models import Credential, Host
        from ...store import Store
        added = 0
        summary = ""
        with Store(db_path) as st:
            if kind == "nxc":
                content = importers.strip_ansi(content)      # a piped nxc log carries colour codes
                # SMB gets the full fold (access, shares, users, local-admin finding).
                groups: dict[str, list[str]] = {}
                for raw in content.splitlines():
                    m = ce._NXC_LINE.match(raw)
                    if m and m.group(1).upper() == "SMB":
                        groups.setdefault(m.group(2), []).append(raw)
                hosts_folded = 0
                for ip, lines in groups.items():
                    if not importers.is_ip(ip):              # nxc targeted a hostname, not an IP:
                        continue                             # don't create a hostname-keyed host
                    data = ce.parse_nxc_smb("\n".join(lines))
                    if not (data["auth"] or data["admin"] or data["shares"] or data["users"]):
                        continue
                    host = st.get_host(ip) or Host(ip=ip)
                    host.state = "up"
                    ce._fold_nxc(host, data, label="imported nxc")
                    st.upsert_host(host, merge=True)
                    hosts_folded += 1
                # ANY protocol (smb/ldap/mssql/winrm/ssh/...): a "[+] dom\\user:secret
                # (Pwn3d!)" line is a validated credential — capture it for spraying.
                creds_added = 0
                access: dict[str, str] = {}       # ip -> foothold detail
                cred_re = re.compile(r"\[\+\]\s+(?:([^\\\s]+)\\)?([^\s:]+):(\S+?)(?:\s+\((Pwn3d!)\))?\s*$")
                for raw in content.splitlines():
                    m = ce._NXC_LINE.match(raw)
                    if not m:
                        continue
                    proto, ip, msg = m.group(1).upper(), m.group(2), m.group(5)
                    cm = cred_re.search(msg)
                    if not cm:
                        continue
                    dom, user, secret, pwn = cm.group(1) or "", cm.group(2), cm.group(3), cm.group(4)
                    knd, sec = importers.classify_secret(secret)   # LM:NT -> nthash (spray the NT half)
                    if st.add_credential(Credential(
                            username=user, secret=sec, domain=dom, kind=knd,
                            origin_ip=ip if importers.is_ip(ip) else "", source="nxc-validated",
                            notes=f"validated over {proto}" + (" (local admin)" if pwn else ""))):
                        creds_added += 1
                    # a validated login IS a foothold — record it so Access auto-ticks
                    if importers.is_ip(ip):
                        access.setdefault(ip, f"{proto} login "
                                          f"({'local admin' if pwn else 'valid creds'}) - imported nxc")
                for ip, detail in access.items():
                    host = st.get_host(ip) or Host(ip=ip)
                    host.state = "up"
                    if not getattr(host, "access_gained", False):
                        host.access_gained = True
                        host.access_detail = detail
                    st.upsert_host(host, merge=True)
                added = hosts_folded + creds_added
                summary = (f"folded netexec results: {hosts_folded} SMB host(s), "
                           f"{creds_added} validated credential(s)")
            elif kind == "kerberoast":
                for r in ce.parse_getuserspns(content):
                    if r.get("hash") and st.add_credential(Credential(
                            username=r["name"], secret=r["hash"], kind="hash",
                            source="kerberoast", notes=("SPN " + r.get("spn", "")).strip())):
                        added += 1
                summary = f"stored {added} Kerberoast hash(es)"
            elif kind == "asrep":
                for r in ce.parse_getnpusers(content):
                    if r.get("hash") and st.add_credential(Credential(
                            username=r["name"], secret=r["hash"], kind="hash",
                            source="asrep", notes="AS-REP roastable")):
                        added += 1
                summary = f"stored {added} AS-REP hash(es)"
            elif kind == "secretsdump":
                skipped_hist = 0
                for r in ce.parse_secretsdump(content):
                    if r.get("history"):            # a rotated/old password — never spray as current
                        skipped_hist += 1
                        continue
                    note = ("cleartext (WDigest/LSA)" if r.get("kind") == "password"
                            else ("rid " + r.get("rid", "")).strip())
                    if st.add_credential(Credential(
                            username=r["name"], secret=r.get("secret") or r.get("nt", ""),
                            kind=r.get("kind", "nthash"), source="secretsdump", notes=note)):
                        added += 1
                summary = (f"stored {added} credential(s)"
                           + (f" ({skipped_hist} history entr{'y' if skipped_hist == 1 else 'ies'} "
                              "skipped)" if skipped_hist else ""))
            elif kind == "creds":
                # A plain credential list to stack + spray. Accepts `[domain\]user:secret`
                # (john --show / a spray list), `user:LM:NT` (pass-the-hash — the old
                # count(":")==1 guard silently dropped these), and the hashcat
                # `NThash:plaintext` --show shape (left is the hash, right the cracked pw).
                for raw in content.splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    left, right = line.split(":", 1)
                    if not left or not right:
                        continue
                    if (re.fullmatch(r"[0-9a-fA-F]{32}", left)
                            and not re.fullmatch(r"[0-9a-fA-F]{32}", right)):
                        cred = Credential(username="", secret=right, kind="password",
                                          source="imported",
                                          notes=f"plaintext cracked from NT {left.lower()}")
                    else:
                        dom, user = (left.split("\\", 1) if "\\" in left else ("", left))
                        knd, sec = importers.classify_secret(right)
                        cred = Credential(username=user, secret=sec, domain=dom, kind=knd,
                                          source="imported", notes="imported credential list")
                    if st.add_credential(cred):
                        added += 1
                summary = f"stored {added} credential(s)"
            elif kind in ("nessus", "openvas", "nuclei", "testssl"):
                from ... import epss, kev
                from ...importers import SCANNER_PARSERS
                vulns = SCANNER_PARSERS[kind](content)
                by_ip: dict[str, list] = {}
                for v in vulns:
                    by_ip.setdefault(v.ip, []).append(v)
                skipped_noip = 0
                folded_hosts = 0
                for ip, vs in by_ip.items():
                    if not ip.strip():                 # a finding with no host — don't create ip=""
                        skipped_noip += len(vs)
                        continue
                    host = st.get_host(ip) or Host(ip=ip)
                    host.state = "up"
                    host.vulns.extend(vs)
                    kev.annotate(host)                 # fix-first flags (KEV / EPSS) so
                    epss.annotate(host)                # imported CVEs rank with the rest
                    st.upsert_host(host, merge=True)   # union-merge dedups on re-import
                    added += len(vs)
                    folded_hosts += 1
                summary = (f"folded {added} {kind} finding(s) across {folded_hosts} host(s)"
                           + (f"; {skipped_noip} without a host skipped" if skipped_noip else ""))
            else:
                raise HTTPException(422, f"unsupported import kind {kind!r}")
        if added == 0:                                   # don't let "0 rows" read as success
            summary = (summary + " — " if summary else "") + (
                f"parsed 0 rows; check this is really {kind} output (or a variant recce "
                "can't read yet)")
        broker.publish({"type": "import", "kind": kind, "added": added, "tester": x_tester})
        return {"mode": "done", "kind": kind, "added": added, "summary": summary}

    @app.get("/api/playbook")
    def playbook():
        """The shared engagement playbook: the phase track (where are we), the live
        branches (what's next, from the next-action engine), and the attack-path narrative
        (the chain we're building). All derived from the datastore, so it's the same for
        every tester and updates the instant anyone folds in a result."""
        from ... import attackpath, workflow
        from ...store import Store
        with Store(db_path) as st:
            hosts = st.all_hosts()
            creds = st.all_credentials()
        up = [h for h in hosts if h.is_up]
        findings = sum(len(h.vulns) for h in up)
        kev = sum(1 for h in up for v in h.vulns if getattr(v, "kev", False))
        enum_done = any(getattr(h, "enumerated", False) for h in up)
        vulns_done = findings > 0 or any(p.vuln_scanned for h in up for p in h.open_ports)
        swept = (any(getattr(h, "db_scanned", False) for h in up)
                 or any(v.source in _DEEP_SOURCES for h in up for v in h.vulns))
        access = [h for h in up if getattr(h, "access_gained", False)]
        o = eng_dir

        def _p(key, label, state, detail, cmd=""):
            return {"key": key, "label": label, "state": state, "detail": detail, "cmd": cmd}

        # Linear spine (enum -> vulns -> sweep -> act -> report); the first not-done of
        # enum/vulns/sweep is the "current" credential-free move.
        phases = [
            _p("enum", "Enumerate", "done" if enum_done else "todo",
               f"{len(up)} host(s) up", f"recce enum <targets> -o {o}"),
            _p("vulns", "Vuln-scan", "done" if vulns_done else "todo",
               f"{findings} finding(s), {kev} KEV", f"recce vulns -o {o}"),
            _p("sweep", "Deep sweep", "done" if swept else "todo",
               "confirm exposures across every service", f"recce sweep -o {o}"),
            _p("act", "Act / prioritise", "ready" if vulns_done else "locked",
               f"{findings} finding(s) to action", f"recce act -o {o}"),
            _p("creds", "Credentials", "active" if creds else "locked",
               f"{len(creds)} captured — spray them" if creds
               else "unlocks when a login validates",
               f"recce credsweep -u USER -p PASS -o {o}" if creds else ""),
            _p("foothold", "Foothold", "active" if access else "locked",
               f"{len(access)} host(s) owned — priv-esc" if access
               else "unlocks on first access",
               f"recce privesc -o {o}" if access else ""),
            _p("report", "Report", "ready" if findings else "locked",
               f"{findings} finding(s)", f"recce report -o {o}"),
        ]
        current = None
        for s in phases:
            if s["key"] in ("enum", "vulns", "sweep") and s["state"] == "todo":
                s["state"] = "current"
                current = s
                break

        acts = workflow.next_actions(hosts, creds, o)
        branches = [{"label": a.label, "cmd": a.command, "why": a.why} for a in acts]
        # The header chip's single next move: the current spine step, else the top branch.
        if current:
            next_move = {"label": current["label"], "cmd": current["cmd"]}
        elif branches:
            next_move = {"label": branches[0]["label"], "cmd": branches[0]["cmd"]}
        else:
            next_move = None
        return {"phases": phases, "current": current["key"] if current else None,
                "next": next_move, "branches": branches,
                "path": attackpath.narrative(up)}

    @app.get("/api/attackpath")
    def attackpath_json():
        """Structured attack-path steps grouped by kill-chain stage, plus the
        narrative summary. Frontend renders this as clickable steps on the
        Exploit tab (each step's ip jumps to the host drawer)."""
        from ... import attackpath
        hs, _ = _hosts()
        up = [h for h in hs if h.is_up]
        steps = attackpath.build(up)
        by_stage: dict[str, list] = {}
        for s in steps:
            by_stage.setdefault(s["stage"], []).append(s)
        stages = [{"stage": st, "steps": by_stage[st]}
                  for st in attackpath.STAGE_ORDER if st in by_stage]
        return {"narrative": attackpath.narrative(up, steps),
                "stages": stages, "step_count": len(steps)}

    @app.get("/api/screenshot")
    def host_screenshot(ip: str, port: int, force: bool = False):
        """Capture a headless-browser PNG of the http(s) service on ip:port.
        Caches per (ip, port) under {eng_dir}/screenshots/ so repeat views
        are instant. Returns 404 if headless browser isn't installed or the
        port isn't a web port."""
        import os
        import re
        from fastapi.responses import Response
        from ... import screenshot as shot
        if not shot.available():
            raise HTTPException(503, "no headless browser installed (chromium/firefox)")
        if not (1 <= port <= 65535):
            raise HTTPException(400, "port out of range")
        # Sanitise the filename — belt-and-braces even though ip/port come typed.
        safe_ip = re.sub(r"[^0-9a-fA-F:.]+", "_", str(ip))
        sdir = os.path.join(eng_dir, "screenshots")
        os.makedirs(sdir, exist_ok=True)
        cached = os.path.join(sdir, f"{safe_ip}_{port}.png")
        if os.path.exists(cached) and not force:
            with open(cached, "rb") as f:
                return Response(f.read(), media_type="image/png",
                                headers={"Cache-Control": "private, max-age=3600"})
        # Not cached (or force=1) — capture live. Try https first, then http.
        for scheme in ("https", "http"):
            url = f"{scheme}://{ip}:{port}"
            png = shot.capture(url)
            if png:
                with open(cached, "wb") as f:
                    f.write(png)
                return Response(png, media_type="image/png")
        raise HTTPException(502, f"{ip}:{port} did not render (unreachable, non-web, or slow)")

    @app.get("/api/poc/{cve}")
    def poc_dossier(cve: str):
        """Per-CVE PoC dossier + harness skeleton. Renders on demand so the
        UI can drop a "Generate PoC" button on any KEV/CVE finding without
        the tester leaving the browser for a terminal. Everything is derived
        from what recce already knows (vuln db, KEV/EPSS, exploit refs)."""
        from ...act import pocgen
        if not pocgen.valid_cve(cve):
            raise HTTPException(400, "not a CVE id (expected CVE-YYYY-NNNN)")
        hs, _ = _hosts()
        data = pocgen.gather(cve.upper(), hs)
        return {
            "cve": data["cve"], "title": data["title"], "severity": data["severity"],
            "kev": data["kev"], "epss": data["epss"], "cwe": data["cwe"],
            "affected": data["affected"], "msf": data["msf"], "edb": data["edb"],
            "dossier_md": pocgen.render_dossier(data),
            "harness_py": pocgen.render_harness(data),
        }

    @app.get("/api/attackpath.svg")
    def attackpath_svg():
        """The projected attack-path graph as a standalone SVG, for inline display."""
        from fastapi.responses import Response
        from ... import attackpath
        hs, _ = _hosts()
        steps = attackpath.build(hs)
        if not steps:
            return Response("<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/>",
                            media_type="image/svg+xml")
        svg = attackpath.svg(hs, steps).replace(
            "<svg ", '<svg xmlns="http://www.w3.org/2000/svg" ', 1)
        return Response(svg, media_type="image/svg+xml")

    @app.get("/api/attack")
    def attack_coverage():
        """MITRE ATT&CK coverage: techniques the findings map to, by tactic."""
        from ... import attack
        hs, _ = _hosts()
        cov = attack.coverage(hs)
        return {"technique_count": cov["technique_count"],
                "tactic_count": cov["tactic_count"],
                "tactics": [{"tactic": t, "tactic_id": attack.TACTICS.get(t, ""),
                             "techniques": techs}
                            for t, techs in cov["by_tactic"].items()]}
