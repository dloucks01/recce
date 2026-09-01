"""Cross-service "APOP challenge tokens observed" reader.

Every POP3 greeting from an APOP-enabled server carries a
`<processid.time@hostname>` token (RFC 1939 §7); a captured or replayed
transcript of that token + a real client's md5(timestamp || password)
response is offline-crackable in hashcat mode 20 (md5($salt.$pass)).

Producers today:
  * `recce/services/pop3.py` — `probe()` captures `apop_timestamp` from
    the greeting; `analyze()` records it here.

Consumers (this pass ships the reader only):
  * creds --plan hash-inventory: an APOP row alongside the existing
    hashloot "pop3-apop" totals so the operator sees the raw challenges
    without opening the .hash file.
  * known_hashes already reads `loot/*.hash` — no changes needed.

The full challenge string is case-SIGNIFICANT (the hostname suffix is a
DNS label, RFC 1035 §2.3.1 case-insensitive, but the process-id/time
prefix is arbitrary bytes) — compare and dedup verbatim per (ip, token).
"""
from __future__ import annotations

from ..core.models import Host


def _norm(v: str) -> str:
    return (v or "").strip()


def record_apop_challenge(host: Host, ip: str, port: int, timestamp: str,
                          source: str = "pop3") -> None:
    """Attach one captured APOP challenge token to `host`. Idempotent per
    (port, timestamp) — a re-probe against the same POP3 listener records
    only once. Silently drops empty tokens."""
    ts = _norm(timestamp)
    if host is None or not ts:
        return
    existing = getattr(host, "apop_challenges", None)
    if existing is None:
        existing = []
        host.apop_challenges = existing  # type: ignore[attr-defined]
    for e in existing:
        if e.get("timestamp") == ts and int(e.get("port", 0)) == int(port):
            return
    existing.append({"ip": ip or getattr(host, "ip", "") or "",
                     "port": int(port), "timestamp": ts,
                     "first_seen_source": source or "pop3"})


def apop_challenges_for(host: Host) -> list[dict]:
    """Every APOP challenge recorded against `host`, first-seen order.
    Returned entries are copies so a consumer mutating them cannot corrupt
    the store."""
    return [dict(e) for e in (getattr(host, "apop_challenges", None) or [])]


def known_apop_challenges(hosts: list[Host]) -> dict:
    """Engagement-wide APOP challenge inventory.

    Returns:
      {"by_ip": {ip: [{timestamp, first_seen_source}, ...]},
       "total": int,
       "ips":   [ip, ...]}

    `total` counts every distinct (ip, timestamp) pair — the same POP3
    listener re-scanned reports one, two POP3 listeners on one host each
    with their own APOP token report two.
    """
    by_ip: dict[str, list[dict]] = {}
    total = 0
    for h in hosts:
        for c in apop_challenges_for(h):
            ip = c.get("ip") or getattr(h, "ip", "") or ""
            entries = by_ip.setdefault(ip, [])
            row = {"timestamp": c.get("timestamp", ""),
                   "first_seen_source": c.get("first_seen_source", "pop3")}
            if row not in entries:
                entries.append(row)
                total += 1
    return {"by_ip": by_ip, "total": total, "ips": sorted(by_ip)}
