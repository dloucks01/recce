"""Engagement / hosts / findings / overview read endpoints."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query

from .._common import _SEV_ORDER, _finding_dict, _host_dict, _host_key


def register_engagement_routes(app: FastAPI, ctx) -> None:
    db_path = ctx.db_path

    def _hosts():
        from ...store import Store
        with Store(db_path) as st:
            return st.all_hosts(), (st.get_meta("engagement") or "recce engagement")

    def _tracking() -> dict:
        from ...store import Store
        with Store(db_path) as st:
            return st.get_tracking()

    def _scope() -> dict:
        from ...store import Store
        with Store(db_path) as st:
            return st.get_scope()

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

    @app.get("/api/hosts")
    def hosts(limit: int = Query(default=0, ge=0),
              offset: int = Query(default=0, ge=0)):
        hs, _ = _hosts()
        tr = _tracking()
        out = []
        for h in hs:
            if not h.is_up:
                continue
            rev, notes = tr.get(_host_key(h.ip), (False, ""))
            out.append(_host_dict(h, bool(rev), notes))
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
        from ... import qod, tracking
        from ...store import Store
        with Store(db_path) as st:
            h = st.get_host(ip)
            trk = st.get_tracking()
        if h is None:
            raise HTTPException(404, "no such host")
        hrev, hnotes = trk.get(_host_key(h.ip), (False, ""))
        vulns = []
        for v in h.vulns:
            rev, notes = trk.get(tracking.vuln_row_key(v), (False, ""))
            d = _finding_dict(v, bool(rev), notes)
            qscore, qtype = qod.score(v)
            d.update({
                "output": (v.output or "")[:4000], "remediation": v.remediation or "",
                "cwes": list(v.cwes or []),
                "qod": getattr(v, "qod", 0) or qscore,
                "qod_type": getattr(v, "qod_type", "") or qtype, "state": v.state or "",
            })
            vulns.append(d)
        vulns.sort(key=lambda f: (not f["kev"], _SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        base = _host_dict(h, bool(hrev), hnotes)
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

    @app.get("/api/findings")
    def findings(limit: int = Query(default=0, ge=0),
                 offset: int = Query(default=0, ge=0)):
        from ... import tracking
        hs, _ = _hosts()
        tr = _tracking()
        out = []
        for h in hs:
            if not h.is_up:
                continue
            for v in h.vulns:
                rev, notes = tr.get(tracking.vuln_row_key(v), (False, ""))
                out.append(_finding_dict(v, bool(rev), notes))
        out.sort(key=lambda f: (not f["kev"], _SEV_ORDER.get(f["severity"], 9), -f["epss"]))
        total = len(out)
        if limit > 0:
            out = out[offset:offset + limit]
        elif offset > 0:
            out = out[offset:]
        return {"items": out, "total": total, "limit": limit, "offset": offset}

    @app.get("/api/overview")
    def overview():
        """Everything the dashboard needs in one cheap, live-pollable call."""
        from ... import tracking
        hs, name = _hosts()
        tr = _tracking()
        up = [h for h in hs if h.is_up]
        scope = _scope()
        by_sev: dict[str, int] = {}
        kev_findings, top_hosts = [], []
        reviewed = 0
        total_findings = 0
        enums = accessed = 0
        for h in up:
            hsev: dict[str, int] = {}
            for v in h.vulns:
                total_findings += 1
                by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
                hsev[v.severity] = hsev.get(v.severity, 0) + 1
                if tr.get(tracking.vuln_row_key(v), (False,))[0]:
                    reviewed += 1
                if getattr(v, "kev", False):
                    kev_findings.append({
                        "key": tracking.vuln_row_key(v), "ip": h.ip, "port": v.port,
                        "title": v.title or v.script_id, "severity": v.severity or "info",
                        "cve": (v.ids[0] if v.ids else ""),
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
            "kev_total": len(kev_findings), "kev_findings": kev_findings[:12],
            "top_hosts": top_hosts[:8],
            "reviewed": reviewed,
            "enumerated": enums, "accessed": accessed,
        }
