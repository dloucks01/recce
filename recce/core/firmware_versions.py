"""Flat firmware-version view over the OT/ICS asset inventory.

A thin PROJECTION over `known_ot_assets` (no attach-to-host writes of its
own): every OT asset carrying a non-empty `firmware` field surfaces here
as one flat entry keyed on the firmware string itself. The point is the
`by_firmware` index — a future consumer (an offline ICS-CERT / CISA KEV
matcher) needs "how many boxes across the engagement run Siemens 6ES7...
firmware V4.2" as a single-lookup answer, not a hosts-list traversal.

Producers today:
  * `recce/services/s7.py`   — SZL 0x0011 firmware string.
  * `recce/services/enip.py` — CIP List Identity `revision`.
  * `recce/services/bacnet.py` — Device Object `firmware_revision`.
  * `recce/services/dnp3.py` — Group 0 device attribute for firmware.
  * (`recce/services/opcua.py` — no firmware surface; server BuildInfo
    would land here if a future probe pulled it.)

All producers write via `known_ot_assets.record_ot_asset()`; nothing
writes into this reader directly — it iterates `known_ot_assets(hosts)`
and filters. The inverse `by_firmware` count matches
`known_ot_assets.by_firmware` for the same triplet.
"""
from __future__ import annotations

from .known_ot_assets import known_ot_assets
from .models import Host


def firmware_versions(hosts: list[Host]) -> dict:
    """Flat firmware inventory + vendor/(vendor,model,firmware) indexes.

    Returns:
      {"firmware":    [{ip, protocol, vendor, model, firmware,
                        firmware_string, sources}, ...],
       "by_vendor":   {vendor_lc: [entry, ...]},
       "by_firmware": {(vendor_lc, model_lc, firmware_lc): count}}

    Only assets whose `firmware` field is populated appear — a bare
    vendor/model observation (device answered LIST_IDENTITY but firmware
    was blank) belongs in `known_ot_assets` and is filtered out here."""
    inv = known_ot_assets(hosts)
    firmware: list[dict] = []
    by_vendor: dict[str, list[dict]] = {}
    by_firmware: dict[tuple[str, str, str], int] = {}
    for a in inv.get("assets", []):
        fw = (a.get("firmware") or "").strip()
        if not fw:
            continue
        entry = {"ip": a.get("ip", ""),
                 "protocol": a.get("protocol", ""),
                 "vendor": a.get("vendor", ""),
                 "model": a.get("model", ""),
                 "firmware": fw,
                 # `firmware_string` kept as a display alias so a
                 # future template can reference the field by its
                 # obvious name without touching the reader.
                 "firmware_string": fw,
                 "sources": list(a.get("sources") or [])}
        firmware.append(entry)
        vk = (entry["vendor"] or "").lower()
        if vk:
            by_vendor.setdefault(vk, []).append(entry)
        fk = (vk, (entry["model"] or "").lower(), fw.lower())
        by_firmware[fk] = by_firmware.get(fk, 0) + 1
    return {"firmware": firmware, "by_vendor": by_vendor,
            "by_firmware": by_firmware}
