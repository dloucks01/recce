"""Cross-service "non-OT devices known to this engagement" reader.

Every enumeration path that identifies a non-OT device — an IP camera
model from an RTSP Server header, an IoT device fingerprint from an MQTT
retained-topic convention (shelly/, tasmota/, zigbee2mqtt/), a Minecraft
server brand string, a Telnet banner + auth-prompt vendor, a Guacamole
backend protocol — lands the same fact about the same box: it's a
device, here's its vendor/model/firmware. Consumers today reach into
each service's probe dict directly, but the wanted view is one device
inventory:

  * for THIS host, every distinct device identity observed (an IP camera
    speaking RTSP on 554 and ONVIF on 80 is one device, one row)
  * for the WHOLE engagement, indexes by vendor and a CVE-candidate list
    so a vulndb pass can match against IP-camera / IoT CVE tables
    (Hikvision, Dahua, Axis, Ubiquiti, Shelly firmware families)

Producers WRITE via `record_device(host, source, ...)`; the reader
never invents identity — the store is the authority. Case-insensitive
dedup with first-seen casing preserved for display (vendor and model
names arrive as engineer-typed free text on the wire and downstream
tools show what they saw).
"""
from __future__ import annotations

from typing import Any

from .models import Host


_FIELDS = ("vendor", "model", "firmware", "device_type")


def _norm(v: Any) -> str:
    return str(v or "").strip()


def _lc(v: str) -> str:
    return _norm(v).lower()


def _device_key(vendor: str, model: str, firmware: str) -> tuple[str, str, str]:
    """Correlation key across sources: same (vendor, model, firmware) triplet =
    same device fingerprint. Case-insensitive — vendor branding varies by
    protocol (RTSP header "HIKVISION-WEBS/1.0" vs Telnet banner "hikvision")."""
    return (_lc(vendor), _lc(model), _lc(firmware))


def record_device(host: Host, source: str, *, vendor: str = "",
                  model: str = "", firmware: str = "",
                  device_type: str = "",
                  cves: list[dict] | None = None) -> None:
    """Producer entry point. Appends one device observation onto the host,
    or merges into an existing observation when (vendor, model, firmware)
    matches an earlier one on this same host.

    Merging is field-wise: a later observation fills in fields the earlier
    one left blank, but never overwrites first-seen casing on a populated
    field. `source` is appended to the record's `sources` list; `cves` are
    unioned (each entry deduped by cve id)."""
    vendor = _norm(vendor)
    model = _norm(model)
    firmware = _norm(firmware)
    device_type = _norm(device_type)
    if not (vendor or model or firmware or device_type):
        # Refuse a totally-empty identity — reader would collapse them all
        # into one meaningless bucket.
        return
    src = _norm(source)
    existing = getattr(host, "devices", None)
    if existing is None:
        existing = []
        host.devices = existing  # type: ignore[attr-defined]

    key = _device_key(vendor, model, firmware)
    for rec in existing:
        if _device_key(rec.get("vendor", ""), rec.get("model", ""),
                       rec.get("firmware", "")) == key:
            for f, v in (("vendor", vendor), ("model", model),
                         ("firmware", firmware), ("device_type", device_type)):
                if v and not rec.get(f):
                    rec[f] = v
            srcs = rec.setdefault("sources", [])
            if src and src not in srcs:
                srcs.append(src)
            cve_list = rec.setdefault("cves", [])
            for cve in cves or []:
                cid = cve.get("cve") if isinstance(cve, dict) else str(cve)
                if not cid:
                    continue
                if not any((c.get("cve") if isinstance(c, dict) else c) == cid
                           for c in cve_list):
                    cve_list.append(cve)
            return

    rec = {"ip": host.ip, "vendor": vendor, "model": model,
           "firmware": firmware, "device_type": device_type,
           "sources": [], "cves": list(cves or [])}
    if src:
        rec["sources"].append(src)
    existing.append(rec)


def devices_for(host: Host) -> list[dict]:
    """Every device recorded on this host, insertion order preserved.
    Returned dicts are shallow copies so consumer mutation cannot corrupt
    the store."""
    out: list[dict] = []
    for rec in getattr(host, "devices", None) or []:
        copy = dict(rec)
        copy["sources"] = list(rec.get("sources") or [])
        copy["cves"] = [dict(c) if isinstance(c, dict) else c
                        for c in (rec.get("cves") or [])]
        out.append(copy)
    return out


def known_devices(hosts: list[Host]) -> dict:
    """Engagement-wide non-OT device inventory.

    Returns:
      {"devices":        [device, ...],
       "by_vendor":      {vendor_lc: [device, ...]},
       "cve_candidates": [{"device", "cve", "confidence"}, ...]}

    `devices` is deduplicated across the engagement by (ip, vendor, model,
    firmware) — the same box seen from two probes is one row. First-seen
    casing wins for display; comparison stays case-insensitive."""
    devices: list[dict] = []
    seen: dict[tuple[str, str, str, str], dict] = {}
    for h in hosts:
        for rec in devices_for(h):
            k = (h.ip, _lc(rec.get("vendor", "")),
                 _lc(rec.get("model", "")), _lc(rec.get("firmware", "")))
            entry = seen.get(k)
            if entry is None:
                seen[k] = rec
                devices.append(rec)
                continue
            for f in _FIELDS:
                if rec.get(f) and not entry.get(f):
                    entry[f] = rec[f]
            for s in rec.get("sources") or []:
                if s and s not in entry["sources"]:
                    entry["sources"].append(s)
            entry_cves = entry.setdefault("cves", [])
            for c in rec.get("cves") or []:
                cid = c.get("cve") if isinstance(c, dict) else c
                if not cid:
                    continue
                if not any((x.get("cve") if isinstance(x, dict) else x) == cid
                           for x in entry_cves):
                    entry_cves.append(c)

    by_vendor: dict[str, list[dict]] = {}
    for d in devices:
        vk = _lc(d.get("vendor", ""))
        if vk:
            by_vendor.setdefault(vk, []).append(d)

    cve_candidates: list[dict] = []
    for d in devices:
        for cve in d.get("cves") or []:
            if isinstance(cve, dict):
                cid = cve.get("cve", "")
                # KEV catalogue matches are the highest-confidence class.
                if cve.get("kev"):
                    conf = "high"
                elif cve.get("confidence"):
                    conf = cve["confidence"]
                else:
                    conf = "medium"
            else:
                cid = str(cve)
                conf = "medium"
            if not cid:
                continue
            cve_candidates.append({"device": d, "cve": cid,
                                   "confidence": conf})
    return {"devices": devices, "by_vendor": by_vendor,
            "cve_candidates": cve_candidates}
