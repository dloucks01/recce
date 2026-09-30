"""Cross-service "vendor fingerprints known to this engagement" reader.

Every banner-carrying probe already lands the same class of fact — the
vendor identity of the service or the box behind it — via a wire hint
that varies by protocol but points at the same answer:

  * Telnet: pre-login banner / prompt style (Cisco "User Access
    Verification", "SunOS 5.10", "BusyBox v1.x", "(none) login:")
  * SSH: ident-line softversion + trailing comment (`SSH-2.0-OpenSSH_9.6p1
    Ubuntu-3ubuntu13.4` names Ubuntu after the comma)
  * MQTT: `$SYS/broker/version` topic (`mosquitto version 2.0.15`)
  * RTSP: `Server:` response header on OPTIONS (`Hikvision-Webs/1.0`,
    `AXIS/9.80.1`)
  * Guacamole / Minecraft / redis INFO / ... etc.

Individual finding writers reach into their own probe dict, but the
cross-service view is one vendor inventory keyed by (ip, port, vendor):

  * for THIS host, every distinct vendor observed across all its services
    (a Cisco IOS answering on 22, 23, 80 is one vendor, three sources)
  * for the WHOLE engagement, indexes by vendor (spray Cisco defaults at
    every Cisco-tagged endpoint) and by ip (single-vendor host vs. a
    NAT'd gateway multiplexing several).

Producers WRITE via `record_vendor(host, port, vendor, source,
confidence)`. Confidence tiers are the standard three:

  * high   — banner exactly names the vendor (`SSH-2.0-OpenSSH_9.6p1
             Ubuntu-3`, `$SYS/broker/version = mosquitto 2.0.15`,
             `Server: Hikvision-Webs/1.0`)
  * medium — regex on a distinctive banner string (Cisco IOS login
             prompt, Solaris "SunOS 5.10", NetApp "ONTAP Release")
  * low    — indirect hint (option-set fingerprint, port heuristic)

The reader never invents vendor tags — the store is the authority.
Case-insensitive dedup with first-seen casing preserved for display —
vendor branding on the wire is engineer-typed free text (RTSP header
"HIKVISION-WEBS/1.0" vs Telnet banner "hikvision") and downstream tools
show what they saw.
"""
from __future__ import annotations

from typing import Any

from .models import Host


_CONF_RANK = {"high": 3, "medium": 2, "low": 1, "": 0}


def _norm(v: Any) -> str:
    return str(v or "").strip()


def _lc(v: str) -> str:
    return _norm(v).lower()


def _conf(c: str) -> str:
    """Coerce anything unknown to 'medium' — the caller-friendly default
    that matches record_vendor's signature."""
    c = _norm(c).lower()
    return c if c in _CONF_RANK and c else "medium"


def record_vendor(host: Host, port: int, vendor: str, source: str,
                  confidence: str = "medium") -> None:
    """Producer entry point. Appends one vendor observation onto the host
    at (port, vendor). Idempotent on (port, vendor_lc, source): a re-probe
    against the same endpoint from the same producer records once.

    Merging: a re-record with a HIGHER confidence promotes the entry to
    that confidence (a follow-up cred'd shell replacing a banner guess).
    Never demotes. First-seen casing of the vendor wins for display."""
    v = _norm(vendor)
    if host is None or not v:
        return
    src = _norm(source)
    conf = _conf(confidence)
    existing = getattr(host, "vendors", None)
    if existing is None:
        existing = []
        # Dataclass instance without __slots__ — arbitrary attr assignment
        # is fine. Live in-session correlator, not a persisted fact
        # (won't survive to_json/from_json roundtrip).
        object.__setattr__(host, "vendors", existing)
    key = (int(port), _lc(v), src)
    for rec in existing:
        if (int(rec.get("port", 0)), _lc(rec.get("vendor", "")),
                _norm(rec.get("source", ""))) == key:
            # Promote confidence if the new observation is stronger.
            if _CONF_RANK.get(conf, 0) > _CONF_RANK.get(
                    _conf(rec.get("confidence", "")), 0):
                rec["confidence"] = conf
            return
    existing.append({"ip": getattr(host, "ip", "") or "",
                     "port": int(port), "vendor": v,
                     "source": src, "confidence": conf})


def vendors_for(host: Host) -> list[dict]:
    """Every vendor observation recorded against `host`, insertion order.
    Returned dicts are shallow copies so a consumer mutating them can't
    corrupt the store."""
    return [dict(rec) for rec in (getattr(host, "vendors", None) or [])]


def known_vendors(hosts: list[Host]) -> dict:
    """Engagement-wide vendor inventory.

    Returns:
      {"vendors":   [{vendor, ip, port, source, confidence}, ...],
       "by_vendor": {vendor_lc: [{ip, port, source}, ...]},
       "by_ip":     {ip: [vendor_lc, ...]}}

    `vendors` is priority-ordered — high confidence first, then medium,
    then low — with insertion order preserved within a tier so the caller
    reads the most trustworthy identifications first. Case-insensitive
    dedup; first-seen casing wins for display.
    """
    vendors: list[dict] = []
    for h in hosts:
        for rec in vendors_for(h):
            vendors.append(rec)

    # Stable priority sort: higher confidence first, insertion order kept
    # within a tier (Python's sort is stable).
    vendors.sort(key=lambda r: -_CONF_RANK.get(_conf(r.get("confidence", "")),
                                               0))

    by_vendor: dict[str, list[dict]] = {}
    by_ip: dict[str, list[str]] = {}
    # First-seen display casing per vendor_lc, used only to normalise the
    # dicts stored under by_vendor without touching the flat `vendors`
    # list (whose entries preserve their own casing).
    for rec in vendors:
        vk = _lc(rec.get("vendor", ""))
        if not vk:
            continue
        bucket = by_vendor.setdefault(vk, [])
        entry = {"ip": rec.get("ip", ""),
                 "port": int(rec.get("port", 0)),
                 "source": rec.get("source", "")}
        if entry not in bucket:
            bucket.append(entry)
        ip = rec.get("ip", "")
        if ip:
            iplist = by_ip.setdefault(ip, [])
            if vk not in iplist:
                iplist.append(vk)

    return {"vendors": vendors, "by_vendor": by_vendor, "by_ip": by_ip}
