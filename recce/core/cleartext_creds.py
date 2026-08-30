"""Cross-service "cleartext-auth exposures known to this engagement" reader.

Every service that carries a login flow in the clear — Telnet (RFC 854, no
transport security at all), FTP USER/PASS (RFC 959), POP3 USER/PASS or AUTH
PLAIN before STLS (RFC 2595), IMAP LOGIN before STARTTLS (RFC 3501), HTTP
Basic over `http://` (RFC 7617 §4 warns "sending the user-id and password in
the clear"), plaintext SMTP AUTH LOGIN/PLAIN (RFC 4954 §13.5) — lets the
tester capture credentials with a passive sniff. RFC 4949 names this class
"cleartext" or "unprotected" authentication and calls it out as one of the
authentication risks a network assessment must surface.

The store is per-host (`Host.cleartext_creds`, populated on demand). Each
producer calls `record_cleartext_auth()` from its `analyze()` when its
probe confirms the port speaks the cleartext-auth protocol; the reader then
gives the engagement view — how many exposures per protocol, which IPs
carry which cleartext-auth ports, and the ordered instance list a report
can render.

Consumers today reach into each service's probe dict; this reader is the
single place a cross-service pass (report totals, risk gate before spraying,
"pick the fastest capture target" prioritizer) asks the same question once.

Dedup is case-insensitive on the identifier tuple `(ip, port, protocol,
auth_type)` — protocol names arrive from banners in mixed casing and DNS-
adjacent tools display what they saw, so first-seen casing wins for the
display fields while comparison stays lower-case.
"""
from __future__ import annotations

from .models import Host


# Severity order for `instances` sorting. Telnet has NO transport crypto at
# all (RFC 854), then FTP; then HTTP Basic on plain HTTP (the Authorization
# header base64 decodes trivially); then the mail protocols whose cleartext
# window is "before the STARTTLS/STLS upgrade" — still cleartext when the
# server exposes the plain socket without requiring the upgrade first, per
# each protocol's security-considerations note. Unknown protocols sort last.
_PROTO_PRIORITY = ("telnet", "ftp", "http-basic", "pop3", "imap", "smtp")


def _lc(v: str) -> str:
    return (v or "").strip().lower()


def _norm(v: str) -> str:
    return (v or "").strip()


def _key(ip: str, port: int, protocol: str, auth_type: str) -> tuple:
    return (_lc(ip), int(port or 0), _lc(protocol), _lc(auth_type))


def record_cleartext_auth(host: Host, port: int, protocol: str,
                          auth_type: str, source: str) -> None:
    """Producer entry point. Attach one cleartext-auth observation to `host`.

    Idempotent per `(ip, port, protocol, auth_type)` — a re-probe of the
    same endpoint appends the new `source` to the existing record's
    `sources` list rather than duplicating. Silently drops observations
    missing the protocol name so callers don't have to guard the "probe
    returned no auth surface" path.
    """
    proto = _norm(protocol)
    if host is None or not proto or not port:
        return
    ip = getattr(host, "ip", "") or ""
    at = _norm(auth_type)
    src = _norm(source)
    existing = getattr(host, "cleartext_creds", None)
    if existing is None:
        existing = []
        # Dataclass without __slots__ — arbitrary attr assignment is fine.
        # Not persisted through to_json/from_json; this is a live in-session
        # correlator, same pattern as known_hostkeys.
        object.__setattr__(host, "cleartext_creds", existing)
    k = _key(ip, int(port), proto, at)
    for rec in existing:
        if _key(rec.get("ip", ""), int(rec.get("port", 0) or 0),
                rec.get("protocol", ""), rec.get("auth_type", "")) == k:
            srcs = rec.setdefault("sources", [])
            if src and src not in srcs:
                srcs.append(src)
            return
    rec = {"ip": ip, "port": int(port), "protocol": proto,
           "auth_type": at, "sources": []}
    if src:
        rec["sources"].append(src)
    existing.append(rec)


def cleartext_creds_for(host: Host) -> list[dict]:
    """Every cleartext-auth observation on this host, first-seen order.

    Returned dicts (and their `sources` list) are shallow copies, so a
    consumer mutating them cannot corrupt the store.
    """
    out: list[dict] = []
    for rec in getattr(host, "cleartext_creds", None) or []:
        copy = dict(rec)
        copy["sources"] = list(rec.get("sources") or [])
        out.append(copy)
    return out


def _priority(proto: str) -> int:
    p = _lc(proto)
    return _PROTO_PRIORITY.index(p) if p in _PROTO_PRIORITY else len(_PROTO_PRIORITY)


def cleartext_credentials_observed(hosts: list[Host]) -> dict:
    """Engagement-wide cleartext-auth exposure view.

    Returns:
      {"instances":   [{"ip","port","protocol","auth_type","sources": [str]},
                       ...],           # deduped, priority-ordered
       "by_protocol": {proto_lc: count},
       "by_ip":       {ip: [{"proto", "port"}, ...]}}

    `instances` is deduplicated across the engagement by
    `(ip, port, protocol, auth_type)` — two producers reporting the same
    exposure yield one row whose `sources` unions both tags. Ordering is
    stable: `_PROTO_PRIORITY` first (most-severe cleartext protocols on
    top), then insertion order as the tiebreaker so a report reads the same
    on every run.
    """
    instances: list[dict] = []
    seen: dict[tuple, dict] = {}
    for h in hosts:
        for rec in cleartext_creds_for(h):
            k = _key(rec.get("ip", ""), int(rec.get("port", 0) or 0),
                     rec.get("protocol", ""), rec.get("auth_type", ""))
            entry = seen.get(k)
            if entry is None:
                seen[k] = rec
                instances.append(rec)
                continue
            for s in rec.get("sources") or []:
                if s and s not in entry["sources"]:
                    entry["sources"].append(s)

    order = list(instances)
    instances = sorted(instances,
                       key=lambda r: (_priority(r.get("protocol", "")),
                                      order.index(r)))

    by_protocol: dict[str, int] = {}
    by_ip: dict[str, list[dict]] = {}
    for r in instances:
        pk = _lc(r.get("protocol", ""))
        if pk:
            by_protocol[pk] = by_protocol.get(pk, 0) + 1
        ip = r.get("ip", "")
        if ip:
            row = {"proto": r.get("protocol", ""), "port": int(r.get("port", 0) or 0)}
            bucket = by_ip.setdefault(ip, [])
            if row not in bucket:
                bucket.append(row)

    return {"instances": instances,
            "by_protocol": by_protocol,
            "by_ip": by_ip}
