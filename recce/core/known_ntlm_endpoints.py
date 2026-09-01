"""Cross-service "NTLM-speaking endpoints" reader.

Every application-protocol listener that advertises NTLM as an auth /
SASL mechanism (SMB, HTTP, POP3, IMAP, SMTP, LDAP, MSSQL, RDP, ...) is a
candidate ntlmrelayx target — the `-t <proto>://ip` sink. The existing
`recce/core/relay_targets.py` catalogs SMB signing posture only; this
reader catalogs the ADDITIONAL relay candidates POP3 / IMAP (and future
protocols) advertise, keyed by (ip, port, protocol).

Producers today:
  * `recce/services/pop3.py`  — CAPA/AUTH advertised `NTLM` mechanism.
  * `recce/services/imap.py`  — CAPABILITY advertised `AUTH=NTLM`.

Consumers (this pass ships the reader only):
  * a future relay-planning consumer that unions SMB-relay + these
    non-SMB endpoints and emits per-target ntlmrelayx invocations.

Deduplication is case-insensitive on protocol (ntlmrelayx accepts
`pop3://`, `imap://`, ... lowercase); first-seen casing wins for display.
"""
from __future__ import annotations

from .models import Host


def _norm(v: str) -> str:
    return (v or "").strip()


def record_ntlm_endpoint(host: Host, ip: str, port: int, protocol: str,
                         source: str = "") -> None:
    """Attach one NTLM-speaking endpoint to `host`. Idempotent per
    (port, protocol_lc) — a re-probe records only once. Silently drops
    empty protocol strings."""
    proto = _norm(protocol).lower()
    if host is None or not proto:
        return
    existing = getattr(host, "ntlm_endpoints", None)
    if existing is None:
        existing = []
        host.ntlm_endpoints = existing  # type: ignore[attr-defined]
    for e in existing:
        if (e.get("protocol", "").lower() == proto
                and int(e.get("port", 0)) == int(port)):
            src = _norm(source)
            srcs = e.setdefault("sources", [])
            if src and src not in srcs:
                srcs.append(src)
            return
    src = _norm(source) or proto
    existing.append({"ip": ip or getattr(host, "ip", "") or "",
                     "port": int(port), "protocol": proto,
                     "sources": [src] if src else []})


def ntlm_endpoints_for(host: Host) -> list[dict]:
    """Every NTLM endpoint recorded against `host`, insertion order."""
    out: list[dict] = []
    for rec in getattr(host, "ntlm_endpoints", None) or []:
        copy = dict(rec)
        copy["sources"] = list(rec.get("sources") or [])
        out.append(copy)
    return out


def known_ntlm_endpoints(hosts: list[Host]) -> dict:
    """Engagement-wide NTLM-speaker inventory.

    Returns:
      {"endpoints":    [{ip, port, protocol, sources}, ...],
       "by_protocol":  {protocol_lc: [{ip, port}, ...]},
       "count":        int}

    `endpoints` is dedup'd across the engagement by (ip, port, protocol_lc)
    — a listener advertising NTLM on both an unencrypted and a TLS port
    reports twice, correctly."""
    endpoints: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    by_protocol: dict[str, list[dict]] = {}
    for h in hosts:
        for rec in ntlm_endpoints_for(h):
            ip = rec.get("ip") or getattr(h, "ip", "") or ""
            port = int(rec.get("port") or 0)
            proto = rec.get("protocol", "").lower()
            key = (ip, port, proto)
            if key in seen:
                continue
            seen.add(key)
            entry = {"ip": ip, "port": port, "protocol": proto,
                     "sources": list(rec.get("sources") or [])}
            endpoints.append(entry)
            by_protocol.setdefault(proto, []).append({"ip": ip, "port": port})
    return {"endpoints": endpoints, "by_protocol": by_protocol,
            "count": len(endpoints)}
