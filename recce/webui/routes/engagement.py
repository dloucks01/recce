"""Routes: engagement metadata, hosts, findings, overview."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from ..helpers import host_dict, finding_dict, tier

router = APIRouter(prefix="/api", tags=["engagement"])


def register_engagement_routes(app, eng):
    """Register engagement routes on the app."""

    @router.get("/engagement")
    def get_engagement():
        """Get engagement metadata."""
        return {
            "name": eng.name,
            "start": eng.scan_start,
            "hosts": len(eng.hosts),
            "services": sum(len(h.ports) for h in eng.hosts),
            "findings": len(eng.findings),
        }

    @router.get("/hosts")
    def get_hosts(reviewed: bool = False):
        """Get all hosts."""
        notes = eng.load_notes()
        return [
            host_dict(h, reviewed=notes.get(h.ip, {}).get("reviewed", False),
                     notes=notes.get(h.ip, {}).get("text", ""))
            for h in sorted(eng.hosts, key=lambda h: h.ip)
        ]

    @router.get("/host/{ip}")
    def get_host(ip: str):
        """Get host details including ports and findings."""
        h = next((h for h in eng.hosts if h.ip == ip), None)
        if not h:
            raise HTTPException(status_code=404, detail=f"Host not found: {ip}")

        notes = eng.load_notes()
        host = host_dict(h, reviewed=notes.get(ip, {}).get("reviewed", False),
                        notes=notes.get(ip, {}).get("text", ""))

        # Add ports
        host["ports_detail"] = [
            {
                "port": p.portid,
                "protocol": p.protocol,
                "state": p.state,
                "service": p.service,
                "product": p.product,
                "version": p.version,
            }
            for p in sorted(h.ports, key=lambda p: p.portid)
        ]

        # Add findings for this host
        host["findings"] = [
            finding_dict(v, reviewed=notes.get(f"{ip}:{v.port}:{v.script_id}", {}).get("reviewed", False),
                        notes=notes.get(f"{ip}:{v.port}:{v.script_id}", {}).get("text", ""))
            for v in eng.findings if v.ip == ip
        ]

        return host

    @router.get("/findings")
    def get_findings(severity: str = "", reviewed: bool = False):
        """Get all findings."""
        notes = eng.load_notes()
        findings = eng.findings

        if severity:
            findings = [v for v in findings if v.severity == severity]

        findings = sorted(findings, key=lambda v: (tier(v.severity), v.title))
        return [
            finding_dict(v, reviewed=notes.get(f"{v.ip}:{v.port}:{v.script_id}", {}).get("reviewed", False),
                        notes=notes.get(f"{v.ip}:{v.port}:{v.script_id}", {}).get("text", ""))
            for v in findings
        ]

    @router.get("/overview")
    def get_overview():
        """Get engagement overview stats."""
        notes = eng.load_notes()
        findings = eng.findings

        severity_counts = {sev: len([v for v in findings if v.severity == sev])
                          for sev in ["critical", "high", "medium", "low", "info"]}
        reviewed_count = sum(1 for v in findings
                            if notes.get(f"{v.ip}:{v.port}:{v.script_id}", {}).get("reviewed", False))

        return {
            "total_hosts": len(eng.hosts),
            "total_findings": len(findings),
            "reviewed_findings": reviewed_count,
            "severity_breakdown": severity_counts,
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
        }

    app.include_router(router)
