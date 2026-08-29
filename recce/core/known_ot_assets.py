"""Cross-service "OT/ICS assets known to this engagement" reader.

Every enumeration path that identifies a PLC / RTU / building controller —
S7 SZL 0x0011 (Siemens order code + firmware), BACnet Read-Property on the
Device Object (vendor / model / firmware), DNP3 device attributes (g0),
IEC-104 station-address ident, EtherNet/IP List Identity (ODVA vendor id,
device type, product code, serial) — lands the same fact about the same
box: it's an OT asset, here's its identity. Consumers today reach into
each service's probe dict directly, but the wanted view is one asset
inventory the engagement can reason about:

  * for THIS host, every distinct OT identity observed (one physical CPU
    can answer S7 on 102 and CIP on 44818 — same vendor/model/serial via
    two protocols)
  * for the WHOLE engagement, an index by vendor and by firmware string
    so a vulndb pass can match against IEC 62443-style asset inventory
    concepts (SR 5.1 / ISA-62443-2-1 §4.2.3)

Producers WRITE via `record_ot_asset(host, protocol, ...)`; the reader
never invents identity — the store is the authority. Case-insensitive
dedup with first-seen casing preserved for display (vendor and model
names are engineer-typed free text on the wire and downstream tools show
what they saw).
"""
from __future__ import annotations

from typing import Any

from .models import Host


_FIELDS = ("vendor", "model", "firmware", "serial", "cpu_family")


def _norm(v: Any) -> str:
    return str(v or "").strip()


def _lc(v: str) -> str:
    return _norm(v).lower()


def _asset_key(vendor: str, model: str, serial: str) -> tuple[str, str, str]:
    """Correlation key across protocols: same (vendor, model, serial) triplet =
    same physical device, regardless of which probe surfaced it. Case-
    insensitive per ODVA CIP §2-4 (vendor names) and ASHRAE 135 (vendor free-
    text). Serial is compared as string — CIP UDINT and DNP3 UINT16 both
    stringify unambiguously."""
    return (_lc(vendor), _lc(model), _lc(serial))


def record_ot_asset(host: Host, protocol: str, *, vendor: str = "",
                    model: str = "", firmware: str = "", serial: str = "",
                    cpu_family: str = "", source: str = "") -> None:
    """Producer entry point. Appends one identity observation onto the host,
    or merges into an existing observation when (vendor, model, serial)
    matches an earlier one on this same host.

    Merging is field-wise: a later observation fills in fields the earlier
    one left blank, but never overwrites first-seen casing on a field that
    was already populated. `source` is appended to the record's `sources`
    list (dedup preserved, insertion-order kept)."""
    proto = _norm(protocol).lower()
    vendor = _norm(vendor)
    model = _norm(model)
    firmware = _norm(firmware)
    serial = _norm(serial)
    cpu_family = _norm(cpu_family)
    if not (vendor or model or firmware or serial or cpu_family):
        # Refuse to record a totally-empty identity — the reader would
        # collapse them all into one meaningless bucket.
        return
    src = _norm(source) or proto
    existing = getattr(host, "ot_assets", None)
    if existing is None:
        existing = []
        host.ot_assets = existing  # type: ignore[attr-defined]

    key = _asset_key(vendor, model, serial)
    for rec in existing:
        if _asset_key(rec.get("vendor", ""), rec.get("model", ""),
                      rec.get("serial", "")) == key:
            for f, v in (("vendor", vendor), ("model", model),
                         ("firmware", firmware), ("serial", serial),
                         ("cpu_family", cpu_family)):
                if v and not rec.get(f):
                    rec[f] = v
            srcs = rec.setdefault("sources", [])
            if src and src not in srcs:
                srcs.append(src)
            if proto and proto not in srcs:
                srcs.append(proto)
            return

    rec = {"ip": host.ip, "protocol": proto,
           "vendor": vendor, "model": model, "firmware": firmware,
           "serial": serial, "cpu_family": cpu_family,
           "sources": []}
    if src:
        rec["sources"].append(src)
    if proto and proto != src:
        rec["sources"].append(proto)
    existing.append(rec)


def assets_for(host: Host) -> list[dict]:
    """Every OT asset recorded on this host, insertion order preserved.
    Returned dicts are shallow copies so consumer mutation cannot corrupt
    the store."""
    out: list[dict] = []
    for rec in getattr(host, "ot_assets", None) or []:
        copy = dict(rec)
        copy["sources"] = list(rec.get("sources") or [])
        out.append(copy)
    return out


def known_ot_assets(hosts: list[Host]) -> dict:
    """Engagement-wide OT asset inventory.

    Returns:
      {"assets":       [asset, ...],
       "by_vendor":    {vendor_lc: [asset, ...]},
       "by_firmware":  {(vendor_lc, model_lc, firmware_lc): count}}

    `assets` is deduplicated across the engagement by (ip, vendor, model,
    serial) — the same physical box seen on two probes is one row. First-
    seen casing wins for display; comparison stays case-insensitive."""
    assets: list[dict] = []
    seen: dict[tuple[str, str, str, str], dict] = {}
    for h in hosts:
        for rec in assets_for(h):
            k = (h.ip, _lc(rec.get("vendor", "")),
                 _lc(rec.get("model", "")), _lc(rec.get("serial", "")))
            entry = seen.get(k)
            if entry is None:
                seen[k] = rec
                assets.append(rec)
                continue
            # Fill blanks; extend sources.
            for f in _FIELDS:
                if rec.get(f) and not entry.get(f):
                    entry[f] = rec[f]
            for s in rec.get("sources") or []:
                if s and s not in entry["sources"]:
                    entry["sources"].append(s)

    by_vendor: dict[str, list[dict]] = {}
    by_firmware: dict[tuple[str, str, str], int] = {}
    for a in assets:
        vk = _lc(a.get("vendor", ""))
        if vk:
            by_vendor.setdefault(vk, []).append(a)
        fw = _lc(a.get("firmware", ""))
        if fw:
            fk = (vk, _lc(a.get("model", "")), fw)
            by_firmware[fk] = by_firmware.get(fk, 0) + 1
    return {"assets": assets, "by_vendor": by_vendor,
            "by_firmware": by_firmware}
