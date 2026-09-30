"""Cross-service "iSCSI block-storage LUNs known to this engagement" reader.

Every enumeration path that identifies an iSCSI LUN — recce's own iSCSI
Login + SendTargets + SCSI INQUIRY probe (RFC 7143 §11 for iSCSI, SPC-4
§6.6 for INQUIRY), an nmap `iscsi-info` NSE run, an on-target
`iscsiadm -m session -P 3` dump, a storage-array management-plane
enumeration — lands the same fact about the same block device: on THIS
portal, under THIS Target IQN, LUN <id> is served by <vendor> /
<product> / <revision>. Consumers today reach into iSCSI's probe dict
directly, but the wanted view is one LUN inventory:

  * for THIS host, every distinct LUN observed (LUN 0 on iqn.A and LUN 0
    on iqn.B are two rows, one per (portal, IQN, LUN id) triplet)
  * for the WHOLE engagement, indexes by IQN (same target advertised on
    multiple portals) and by portal IP (which array holds what)

Producers WRITE via `record_lun(host, iqn, lun_id, ...)`; the reader
never invents identity — the store is the authority. Dedup is
case-insensitive on the identifier triplet (IQN case-folding per
RFC 3721 §1; portal IPs and LUN ids compared lower-case for symmetry)
with first-seen casing preserved for display (vendor/product/revision
land as ASCII off the INQUIRY wire and downstream tools show what they
saw).
"""
from __future__ import annotations

from typing import Any

from .models import Host


_FIELDS = ("vendor", "product", "revision")


def _norm(v: Any) -> str:
    return str(v or "").strip()


def _lc(v: str) -> str:
    return _norm(v).lower()


def _lun_key(portal_ip: str, iqn: str, lun_id: str) -> tuple[str, str, str]:
    """Correlation key across sources: same (portal_ip, iqn, lun_id) triplet =
    same LUN. Case-insensitive — IQNs compare case-insensitively per RFC 3721
    §1 and portal IPs are normalized lower-case for symmetry with IPv6 hex."""
    return (_lc(portal_ip), _lc(iqn), _lc(lun_id))


def record_lun(host: Host, iqn: str, lun_id: str, *,
               portal_ip: str = "", vendor: str = "", product: str = "",
               revision: str = "", source: str = "") -> None:
    """Producer entry point. Appends one LUN observation onto the host, or
    merges into an existing observation when (portal_ip, iqn, lun_id) matches
    an earlier one on this same host.

    `portal_ip` defaults to `host.ip` — the common case where recce probed
    the array directly. Pass an explicit `portal_ip` for a redirected portal
    (Login StatusClass=Redirect) or a portal learned from an on-target
    `iscsiadm` dump against a different array.

    Merging is field-wise: a later observation fills in fields the earlier
    one left blank, but never overwrites first-seen casing on a populated
    field. `source` is appended to the record's `sources` list."""
    iqn = _norm(iqn)
    lun_id = _norm(lun_id)
    if host is None or not iqn:
        # Refuse an empty IQN — an iSCSI LUN is uniquely addressed by its
        # Target IQN, and without one the reader cannot correlate at all.
        return
    vendor = _norm(vendor)
    product = _norm(product)
    revision = _norm(revision)
    portal_ip = _norm(portal_ip) or (host.ip or "")
    src = _norm(source)

    existing = getattr(host, "luns", None)
    if existing is None:
        existing = []
        host.luns = existing  # type: ignore[attr-defined]

    key = _lun_key(portal_ip, iqn, lun_id)
    for rec in existing:
        if _lun_key(rec.get("portal_ip", ""), rec.get("iqn", ""),
                    rec.get("lun_id", "")) == key:
            for f, v in (("vendor", vendor), ("product", product),
                         ("revision", revision)):
                if v and not rec.get(f):
                    rec[f] = v
            srcs = rec.setdefault("sources", [])
            if src and src not in srcs:
                srcs.append(src)
            return

    rec = {"portal_ip": portal_ip, "iqn": iqn, "lun_id": lun_id,
           "vendor": vendor, "product": product, "revision": revision,
           "sources": []}
    if src:
        rec["sources"].append(src)
    existing.append(rec)


def luns_for(host: Host) -> list[dict]:
    """Every LUN recorded on this host, insertion order preserved. Returned
    dicts are shallow copies so consumer mutation cannot corrupt the store."""
    out: list[dict] = []
    for rec in getattr(host, "luns", None) or []:
        copy = dict(rec)
        copy["sources"] = list(rec.get("sources") or [])
        out.append(copy)
    return out


def known_luns(hosts: list[Host]) -> dict:
    """Engagement-wide iSCSI LUN inventory.

    Returns:
      {"luns":      [lun, ...],
       "by_iqn":    {iqn_lc: [lun, ...]},
       "by_portal": {portal_ip: [lun, ...]}}

    `luns` is deduplicated across the engagement by (portal_ip, iqn, lun_id)
    — the same LUN seen from two probes is one row. First-seen casing wins
    for display; comparison stays case-insensitive."""
    luns: list[dict] = []
    seen: dict[tuple[str, str, str], dict] = {}
    for h in hosts:
        for rec in luns_for(h):
            k = _lun_key(rec.get("portal_ip", ""), rec.get("iqn", ""),
                         rec.get("lun_id", ""))
            entry = seen.get(k)
            if entry is None:
                seen[k] = rec
                luns.append(rec)
                continue
            for f in _FIELDS:
                if rec.get(f) and not entry.get(f):
                    entry[f] = rec[f]
            for s in rec.get("sources") or []:
                if s and s not in entry["sources"]:
                    entry["sources"].append(s)

    by_iqn: dict[str, list[dict]] = {}
    by_portal: dict[str, list[dict]] = {}
    for lun in luns:
        ikey = _lc(lun.get("iqn", ""))
        if ikey:
            by_iqn.setdefault(ikey, []).append(lun)
        pkey = _norm(lun.get("portal_ip", ""))
        if pkey:
            by_portal.setdefault(pkey, []).append(lun)
    return {"luns": luns, "by_iqn": by_iqn, "by_portal": by_portal}
