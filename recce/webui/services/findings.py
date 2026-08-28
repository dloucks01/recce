"""Findings service — note, tick, and manual add.

Broker publishing stays in the route (infrastructure concern); services just
mutate the datastore and return the values callers need to build the event.
"""
from __future__ import annotations

import re
import time

from ...vuln import epss, kev
from ...core.models import Host, Vuln
from ...core.store import Store
from .. import collab


class ValidationError(ValueError):
    """Raised when input fails a service-level contract. Routes translate this
    into a 400 HTTPException; other callers can catch it."""


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def set_note(db_path: str, key: str, note: str) -> None:
    """Attach a note to a tracking key without changing the reviewed flag."""
    if not key:
        raise ValidationError("no key")
    with Store(db_path) as st:
        rev = st.get_tracking().get(key, (False, ""))[0]
        st.set_reviewed(key, bool(rev), notes=note)


def set_reviewed(db_path: str, key: str, reviewed: bool) -> None:
    """Toggle the reviewed flag on a tracking key."""
    if not key:
        raise ValidationError("no key")
    with Store(db_path) as st:
        st.set_reviewed(key, reviewed)


def add_manual_finding(db_path: str, tester: str, ip: str, title: str,
                        severity: str, port, cve: str, output: str) -> dict:
    """Fold a manually-added finding into a host. Returns the created vuln's
    key so callers (routes) can broadcast it."""
    ip = (ip or "").strip()
    if not ip:
        raise ValidationError("a host IP is required")
    title = (title or "").strip() or "Manual finding"
    sev = (severity or "medium").lower()
    if sev not in _SEVERITIES:
        sev = "medium"
    port_int = int(port) if str(port).isdigit() else None
    if port_int is not None and not (1 <= port_int <= 65535):
        raise ValidationError("port must be 1-65535")
    cves = [c.strip().upper() for c in re.findall(r"CVE-\d{4}-\d+", cve or "", re.I)]
    v = Vuln(
        ip=ip, port=port_int, protocol="tcp",
        script_id=f"manual-{int(time.time())}", state="finding", title=title,
        severity=sev, ids=cves, output=(output or "")[:4000],
        source="manual", confidence="confirmed",
    )
    with Store(db_path) as st:
        host = st.get_host(ip) or Host(ip=ip)
        host.state = "up"
        host.vulns.append(v)
        kev.annotate(host)
        epss.annotate(host)
        st.upsert_host(host, merge=True)
        collab.add_activity(st, tester, "add",
                            f"{tester} added finding “{title}” on {ip}")
    return {"ip": ip, "title": title, "severity": sev}
