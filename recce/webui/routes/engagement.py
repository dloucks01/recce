"""Engagement / hosts / findings / overview read endpoints."""
from __future__ import annotations

import os
import threading

from fastapi import FastAPI, HTTPException, Query

from .._common import (_SEV_ORDER, _finding_dict, _finding_dict_tr, _host_dict,
                       _host_dict_tr, _host_key, _apply_dedup)


def register_engagement_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path

    # Cache the loaded+deduped host set keyed on the datastore's mtime, so the
    # per-read O(hosts×vulns) work (all_hosts JSON parse + KEV annotate + dedup)
    # isn't repaid on every poll of /api/hosts /findings /overview /engagement.
    # Any write bumps results.sqlite / -wal mtime, so the cache self-invalidates.
    _cache: dict = {"sig": None, "hosts": None, "name": None}
    _cache_lock = threading.Lock()
    # Separate cache for the fully-built + sorted findings list. Building it
    # loads the whole tracking table and runs qod_of() per vuln, so repaying
    # that on every /findings poll is the dominant cost at scale. Keyed on the
    # same datastore mtime, so any triage write (which lands in results.sqlite's
    # tracking table) bumps the sig and invalidates it.
    _fcache: dict = {"sig": None, "items": None}
    _fcache_lock = threading.Lock()

    def _db_sig():
        sig = []
        for suffix in ("", "-wal"):
            try:
                sig.append(os.stat(db_path + suffix).st_mtime_ns)
            except OSError:
                sig.append(0)
        return tuple(sig)

    def _hosts():
        """Load hosts + dedup findings in-place (cached per datastore mtime).
        Reads apply the same collapse the report does (intake.dedup) so the WebUI
        and the docx report see the same canonical row count, not a doubled list
        from (say) an nmap NSE + a version-db match for the same CVE."""
        sig = _db_sig()
        with _cache_lock:
            if _cache["sig"] == sig and _cache["hosts"] is not None:
                return _cache["hosts"], _cache["name"]
        from ...core.store import Store
        with Store(db_path) as st:
            hosts = st.all_hosts()
        _apply_dedup(hosts)
        name = _meta_name() or "recce engagement"
        with _cache_lock:
            _cache.update(sig=sig, hosts=hosts, name=name)
        return hosts, name

    def _meta_name():
        from ...core.store import Store
        with Store(db_path) as st:
            return st.get_meta("engagement")

    def _tracking() -> dict:
        from ...core.store import Store
        with Store(db_path) as st:
            return st.get_tracking()

    def _intel_asof() -> dict:
        """Freshness stamp for the baked KEV/EPSS snapshots (see
        recce/vuln/intel_asof.py). Lazy-imported + best-effort so a missing
        stamp module never breaks /api/overview."""
        try:
            from ...vuln import intel_asof
            return intel_asof.info()
        except Exception:  # noqa: BLE001 — the overview must not 500 on a stale build
            return {"summary": "unknown", "kev_as_of": "unknown",
                    "epss_as_of": "unknown"}

    def _tracking_full() -> dict:
        """Rich per-item tracking (reviewed + notes + status + attribution +
        ownership + priority), keyed by tracking key."""
        from ...core.store import Store
        with Store(db_path) as st:
            return st.get_tracking_full()

    def _statuses() -> dict:
        """Lifecycle status per finding key (new/triaged/confirmed/in-report/
        excluded/retested-*). Empty dict when no rows carry a status yet."""
        from ...core.store import Store
        with Store(db_path) as st:
            return st.get_statuses()

    def _scope() -> dict:
        from ...core.store import Store
        with Store(db_path) as st:
            return st.get_scope()

    @app.get("/api/finding/exploit-hint")
    def exploit_hint(key: str = ""):
        """MSF module hint for a KEV / exploitable finding — powers the Sessions
        tab's "🎯 Get shell" one-click launcher. Returns `null` (200) when the
        finding has no mapped published module: not every KEV has a public msf
        module, and recce ships no exploit code — it only names existing ones.
        """
        from ...core import tracking
        from ...act.exploitplan import _msf_for
        if not key.strip():
            raise HTTPException(400, "key=<finding_key> required")
        # Reuse the mtime-keyed _hosts() cache rather than a fresh all_hosts()
        # read: this is a per-row click in the Sessions tab, so an uncached
        # O(hosts×vulns) DB read per call adds up at scale.
        hosts, _ = _hosts()
        for h in hosts:
            for v in h.vulns:
                if tracking.vuln_row_key(v) == key:
                    text = " ".join(str(x) for x in
                                    (v.title, v.script_id, *(v.ids or []),
                                     (v.output or "")[:400]))
                    # Pass the host so _msf_for's SMBv1 gate applies — without it,
                    # an SMBv1-only module (e.g. SambaCry) could be suggested for a
                    # host that never confirmed SMBv1.
                    hint = _msf_for(text, host=h)
                    if hint is None:
                        return {"key": key, "hint": None, "ip": h.ip,
                                "port": v.port, "cve": v.primary_cve()}
                    return {"key": key, "ip": h.ip, "port": v.port,
                            "cve": v.primary_cve(),
                            "hint": {"module": hint["module"],
                                     "payload": hint["payload"] or "",
                                     "note": hint["note"]}}
        raise HTTPException(404, "no such finding")

    @app.get("/api/ref/{ident}")
    def reference(ident: str):
        """Offline reference detail for a CVE or CWE id — airgap-safe, no external
        lookup. CWE → its MITRE weakness name (from the bundled catalogue); CVE →
        CISA-KEV membership (Known Exploited Vulnerabilities — actively exploited
        in the wild) + EPSS exploit-probability. Powers the click-for-more-info on
        a finding's reference chips."""
        ident = (ident or "").strip().upper()
        if ident.startswith("CWE-"):
            from ...core import cwe
            return {"kind": "cwe", "id": ident, "name": cwe.name(ident)}
        if ident.startswith("CVE-"):
            from ...vuln import kev, epss, exploitref, vulndb, cvedb
            info = {"kind": "cve", "id": ident,
                    "kev": kev.is_kev(ident),
                    "epss": round((epss.score_for(ident) or 0.0) * 100),
                    "desc": "", "remediation": "", "severity": "",
                    "cwe": [], "cvss": None, "exploit": "", "source": ""}
            # Published-exploit reference (Metasploit module / well-known PoC),
            # from recce's curated map — the most useful "more info" offline.
            ref = exploitref.proven_exploit_ref([ident])
            if ref:
                info["exploit"] = ref
            # Curated vuln-signature DB first: hand-written desc + remediation for
            # the CVEs recce actually fingerprints (pentest-relevant).
            for sig in getattr(vulndb, "SIGNATURES", []):
                if ident in (sig.get("cves") or []):
                    info.update(desc=sig.get("desc", "") or "",
                                remediation=sig.get("remediation", "") or "",
                                severity=sig.get("severity", "") or "",
                                cwe=list(sig.get("cwe") or []),
                                source="recce vuln DB")
                    break
            # Fall back to the bundled NVD CVE database for the long tail the
            # curated snapshots don't cover (CVSS, description, CWE). Absent DB →
            # nothing filled, still no error and no external lookup.
            nvd = cvedb.lookup(ident)
            if nvd:
                info["cvss"] = nvd.get("cvss")
                info["desc"] = info["desc"] or nvd.get("desc", "")
                info["severity"] = info["severity"] or nvd.get("severity", "")
                info["cwe"] = info["cwe"] or nvd.get("cwe", [])
                info["source"] = info["source"] or "NVD"
            return info
        raise HTTPException(400, "expected a CVE-… or CWE-… id")

    @app.get("/api/self/addresses")
    def self_addresses():
        """Every non-loopback IPv4 the recce host currently holds. The Sessions
        tab's payload catalog uses this to offer LHOST chips — the default
        `location.hostname` is often `127.0.0.1` when the tester opens recce
        locally, and a shell inside a docker container can't dial back to a
        loopback address it doesn't share. Suggesting the LAN/docker-gateway
        IP catches the most common "shell caught nothing" foot-gun.
        Sorted with the most-likely-useful address first (docker gateways,
        then LAN, then anything else)."""
        import socket
        addrs: set[str] = set()
        try:
            # getaddrinfo on the hostname surfaces every configured IPv4.
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                addrs.add(info[4][0])
        except (OSError, socket.gaierror):
            pass
        # Also try the "connect a UDP socket" trick to surface the primary
        # outbound IP (route to 8.8.8.8) — no packet is sent.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 53))
                addrs.add(s.getsockname()[0])
            finally:
                s.close()
        except OSError:
            pass
        # Walk every interface for anything we missed (docker bridges, VPN).
        try:
            import subprocess
            r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=2)
            for a in (r.stdout or "").split():
                if "." in a and not a.startswith("127."):
                    addrs.add(a)
        except (OSError, subprocess.TimeoutExpired):
            pass
        addrs.discard("127.0.0.1")
        addrs.discard("0.0.0.0")
        # Rank: docker-ish (172.16-31, 10.x, 192.168) first, then anything else.
        def _rank(a: str) -> int:
            if a.startswith("172."):
                oct2 = int(a.split(".")[1]) if a.count(".") >= 1 else 0
                if 16 <= oct2 <= 31: return 0  # docker default bridge range
            if a.startswith("10."): return 1
            if a.startswith("192.168."): return 2
            return 3
        return {"addresses": sorted(addrs, key=lambda a: (_rank(a), a))}

    @app.get("/api/engagement")
    def engagement():
        hosts, name = _hosts()
        up = [h for h in hosts if h.is_up]
        vulns = [v for h in up for v in h.vulns]
        by_sev: dict[str, int] = {}
        for v in vulns:
            by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
        checked = sum(1 for h in up if getattr(h, "access_gained", False)
                      or getattr(h, "vuln_scanned", False))
        return {"name": name, "hosts_up": len(up), "hosts_total": len(hosts),
                "services": sum(len(h.open_ports) for h in up),
                "findings_by_severity": by_sev,
                "kev": sum(1 for v in vulns if getattr(v, "kev", False)),
                "checked_pct": round(100 * checked / len(up)) if up else 0}

    def _subnet_resolver():
        """Group hosts by the ACTUAL scope CIDR that contains them — the operator
        may have defined a /16, /28, /30, etc., so a hardcoded /24 mis-buckets. Most
        specific match wins; falls back to the host's stored subnet, then a /24."""
        import ipaddress
        from ...core.store import Store
        from ...core.targets import _subnet_of
        with Store(db_path) as st:
            scope = st.get_scope()
        nets = []
        for cidr in scope:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
        nets.sort(key=lambda n: n.prefixlen, reverse=True)   # most specific first

        def resolve(ip: str, stored: str) -> str:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return stored or "unresolved"
            for n in nets:
                if a in n:
                    return str(n)
            return stored or _subnet_of(ip)
        return resolve

    @app.get("/api/hosts")
    def hosts(limit: int = Query(default=0, ge=0),
              offset: int = Query(default=0, ge=0)):
        hs, _ = _hosts()
        tr = _tracking_full()
        subnet_for = _subnet_resolver()
        out = []
        for h in hs:
            if not h.is_up:
                continue
            row = _host_dict_tr(h, tr.get(_host_key(h.ip)))
            row["subnet"] = subnet_for(h.ip, getattr(h, "subnet", "") or "")
            out.append(row)
        total = len(out)
        if limit > 0:
            out = out[offset:offset + limit]
        elif offset > 0:
            out = out[offset:]
        return {"items": out, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/host/{ip}")
    def host_detail(ip: str):
        """Everything about one host — services, full findings (with output +
        remediation + QoD), AD accounts, posture — for the drill-down drawer."""
        from ...core import qod, tracking
        from ...core.store import Store
        with Store(db_path) as st:
            h = st.get_host(ip)
            if h is None:
                raise HTTPException(404, "no such host")
            _apply_dedup([h])                 # same canonical collapse as the list endpoints
            # fetch only this host's tracking rows, not the whole table (#14)
            keys = {_host_key(h.ip)} | {tracking.vuln_row_key(v) for v in h.vulns}
            trk = st.get_tracking_full(keys)
        vulns = []
        for v in h.vulns:
            d = _finding_dict_tr(v, trk.get(tracking.vuln_row_key(v)))
            qscore, qtype = qod.score(v)
            d.update({
                "output": (v.output or "")[:4000], "remediation": v.remediation or "",
                "cwes": list(v.cwes or []),
                "qod": getattr(v, "qod", 0) or qscore,
                "qod_type": getattr(v, "qod_type", "") or qtype, "state": v.state or "",
            })
            vulns.append(d)
        vulns.sort(key=lambda f: (not f["kev"], _SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        base = _host_dict_tr(h, trk.get(_host_key(h.ip)))
        base.update({
            "access_detail": getattr(h, "access_detail", ""),
            "smb_signing": getattr(h, "smb_signing", ""),
            "defenses": list(getattr(h, "defenses", []) or []),
            "ports": [{"port": p.portid, "proto": p.protocol, "state": p.state,
                       "service": p.service, "product": p.product, "version": p.version,
                       "banner": (p.service_banner or p.banner or "")[:200]}
                      for p in h.open_ports],
            "vulns": vulns,
            "accounts": [{"kind": a.kind, "name": a.name, "domain": a.domain,
                          "rid": a.rid, "detail": a.detail,
                          "attrs": {k: a.attrs.get(k) for k in
                                    ("spn", "enabled", "admincount", "memberof",
                                     "asrep_roastable", "delegation") if a.attrs.get(k)}}
                         for a in (getattr(h, "accounts", []) or [])],
        })
        return base

    # P7-A2: status query param — accepted since the finding-status shape
    # was added, but was ignored server-side (the client had no local
    # filter either, so a caller passing ?status=triaged got every row
    # back). Now honored: unknown values 400 rather than pretend to work.
    _VALID_STATUSES = frozenset({
        "", "new", "triaged", "confirmed", "in-report",
        "excluded", "retested-fixed", "retested-open",
    })

    def _findings_all():
        """The full, sorted findings list (every up host's vulns, folded with
        their tracking rows), cached per datastore mtime. This is where the
        whole-tracking-table load + per-vuln qod_of live, so caching it keeps a
        /findings poll from repaying that each time. Status filter + pagination
        run per-request over the returned list (cheap)."""
        from ...core import tracking
        sig = _db_sig()
        with _fcache_lock:
            if _fcache["sig"] == sig and _fcache["items"] is not None:
                return _fcache["items"]
        hs, _ = _hosts()
        tr = _tracking_full()
        out = []
        for h in hs:
            if not h.is_up:
                continue
            for v in h.vulns:
                out.append(_finding_dict_tr(v, tr.get(tracking.vuln_row_key(v))))
        out.sort(key=lambda f: (not f["kev"], _SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        with _fcache_lock:
            _fcache.update(sig=sig, items=out)
        return out

    @app.get("/api/findings")
    def findings(limit: int = Query(default=0, ge=0),
                 offset: int = Query(default=0, ge=0),
                 status: str = Query(default="")):
        if status and status not in _VALID_STATUSES:
            raise HTTPException(
                400, f"unknown status {status!r}; expected one of "
                f"{sorted(_VALID_STATUSES)}")
        items = _findings_all()
        if status:
            # Server-side filter — empty string means "no filter", any concrete
            # value pins the result set. "new" matches untriaged rows (stored as
            # empty string), so treat both as interchangeable to match the UI's
            # "new" label.
            out = [it for it in items
                   if (status == "new" and (it.get("status") or "") in ("", "new"))
                   or (status != "new" and (it.get("status") or "") == status)]
        else:
            out = list(items)
        total = len(out)
        if limit > 0:
            out = out[offset:offset + limit]
        elif offset > 0:
            out = out[offset:]
        return {"items": out, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/overview")
    def overview():
        """Everything the dashboard needs in one cheap, live-pollable call.

        Counts exclude tier=lead so the Dashboard numbers match the Findings
        tab default view (which also hides leads). `leads_hidden` carries the
        excluded count for the sub-line."""
        from ...core import tracking
        from .._common import _tier
        hs, name = _hosts()
        tr = _tracking()
        up = [h for h in hs if h.is_up]
        scope = _scope()
        by_sev: dict[str, int] = {}
        kev_findings, top_hosts = [], []
        reviewed = 0
        total_findings = 0
        leads_hidden = 0
        enums = accessed = 0
        for h in up:
            hsev: dict[str, int] = {}
            for v in h.vulns:
                if _tier(v) == "lead":
                    leads_hidden += 1
                    continue
                total_findings += 1
                by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
                hsev[v.severity] = hsev.get(v.severity, 0) + 1
                if tr.get(tracking.vuln_row_key(v), (False,))[0]:
                    reviewed += 1
                if getattr(v, "kev", False):
                    kev_findings.append({
                        "key": tracking.vuln_row_key(v), "ip": h.ip, "port": v.port,
                        "title": v.title or v.script_id, "severity": v.severity or "info",
                        "cve": v.primary_cve(),
                        "epss": round((getattr(v, "epss", 0.0) or 0.0) * 100),
                    })
            if getattr(h, "enumerated", False):
                enums += 1
            if getattr(h, "access_gained", False):
                accessed += 1
            top_hosts.append({
                "ip": h.ip, "hostname": h.hostname or "",
                "os": h.os_name or h.os_family or "", "roles": list(h.roles or []),
                "findings": hsev, "score": sum(
                    hsev.get(s, 0) * w for s, w in
                    (("critical", 1000), ("high", 100), ("medium", 10), ("low", 1)))})
        kev_findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        top_hosts.sort(key=lambda h: -h["score"])
        scope_size = sum(scope.values())
        return {
            "name": name,
            "hosts_up": len(up), "hosts_total": len(hs),
            "scope_subnets": len(scope), "scope_size": scope_size,
            "services": sum(len(h.open_ports) for h in up),
            "by_severity": by_sev, "findings_total": total_findings,
            "leads_hidden": leads_hidden,
            "kev_total": len(kev_findings), "kev_findings": kev_findings[:12],
            "top_hosts": top_hosts[:8],
            "reviewed": reviewed,
            "enumerated": enums, "accessed": accessed,
            # Baked-intel freshness — surfaces which KEV catalog / EPSS
            # model produced the KEV+EPSS chips the operator's looking at.
            # Stale intel silently under-prioritises new CVEs, and a
            # bumped-catalog-same-day refresh is invisible without this.
            "intel_asof": _intel_asof(),
        }
