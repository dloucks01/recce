"""core.known_luns: cross-service iSCSI LUN inventory reader.

Fixtures build the SCSI wire directly: a Standard INQUIRY response per
SPC-4 §6.6 (peripheral device type at byte 0, 8-byte vendor ID at
byte 8, 16-byte product ID at byte 16, 4-byte revision level at
byte 32, all ASCII space-padded), and IQN strings per RFC 3721 §1
(iqn.<yyyy-mm>.<reversed-dns>[:<host-tail>]). Nothing here calls a
recce encoder for the reader tests; the producer-wire integration
parses the raw bytes through iscsi._parse_inquiry before handing the
probe-dict shape to iscsi._record_luns.
"""
from __future__ import annotations

from recce.core.known_luns import known_luns, luns_for, record_lun
from recce.core.models import Host
from recce.services import iscsi


# --- wire-derived INQUIRY helper ------------------------------------------

def _wire_inquiry(vendor: str, product: str, revision: str,
                  device_type: int = 0x00) -> bytes:
    """SPC-4 §6.6 Standard INQUIRY data. Vendor: 8 ASCII @ byte 8;
    Product: 16 ASCII @ byte 16; Revision: 4 ASCII @ byte 32. Fields are
    ASCII, space-padded to width. device_type=0 = direct-access block."""
    buf = bytearray(36)
    buf[0] = device_type & 0x1F
    buf[4] = 32                                     # Additional Length (n-4)
    buf[8:16] = vendor.encode("ascii")[:8].ljust(8, b" ")
    buf[16:32] = product.encode("ascii")[:16].ljust(16, b" ")
    buf[32:36] = revision.encode("ascii")[:4].ljust(4, b" ")
    return bytes(buf)


# Two RFC 3721 IQNs on the same reversed-DNS zone; two distinct LUNs.
_IQN_A = "iqn.2001-04.com.example:storage.sql01"
_IQN_B = "iqn.2001-04.com.example:storage.backup"


# --- record_lun -----------------------------------------------------------

def test_record_lun_attaches_to_host_and_luns_for_reads_back():
    h = Host(ip="10.0.0.10")
    record_lun(h, _IQN_A, "0", vendor="NETAPP", product="LUN",
               revision="9.10", source="iscsi:inquiry")
    got = luns_for(h)
    assert len(got) == 1
    r = got[0]
    assert r["iqn"] == _IQN_A
    assert r["lun_id"] == "0"
    assert r["vendor"] == "NETAPP"
    assert r["product"] == "LUN"
    assert r["revision"] == "9.10"
    assert r["portal_ip"] == "10.0.0.10"            # defaults to host.ip
    assert "iscsi:inquiry" in r["sources"]


def test_record_lun_ignores_empty_iqn():
    """An iSCSI LUN is addressed by (portal, IQN, LUN id). No IQN = no
    correlation possible — drop it rather than collapse into a bucket."""
    h = Host(ip="10.0.0.10")
    record_lun(h, "", "0", vendor="NETAPP")
    record_lun(h, "   ", "0", vendor="NETAPP")
    assert luns_for(h) == []


def test_record_lun_dedupes_case_insensitively_and_preserves_first_seen_casing():
    """Second observation on the same (portal_ip, iqn_lc, lun_id) merges
    into the first. IQNs are case-insensitive per RFC 3721 §1; vendor
    strings vary by firmware revision. First-seen display casing wins."""
    h = Host(ip="10.0.0.10")
    record_lun(h, _IQN_A, "0", vendor="NETAPP", product="LUN",
               revision="9.10", source="iscsi:inquiry")
    record_lun(h, _IQN_A.upper(), "0", vendor="netapp", product="lun",
               revision="9.10", source="iscsi:rescan")
    got = luns_for(h)
    assert len(got) == 1
    r = got[0]
    assert r["iqn"] == _IQN_A                       # first-seen casing kept
    assert r["vendor"] == "NETAPP"                  # first-seen casing kept
    assert r["product"] == "LUN"
    assert set(r["sources"]) == {"iscsi:inquiry", "iscsi:rescan"}


def test_record_lun_merges_blank_fields_from_later_observation():
    """Second observation on the same LUN fills in fields the first left
    blank; first-seen casing wins on any field that was already populated."""
    h = Host(ip="10.0.0.10")
    record_lun(h, _IQN_A, "0", vendor="NETAPP", source="iscsi:inquiry")
    record_lun(h, _IQN_A, "0", product="LUN", revision="9.10",
               source="iscsi:rescan")
    r = luns_for(h)[0]
    assert r["vendor"] == "NETAPP"                  # first-pass value survives
    assert r["product"] == "LUN"                    # filled from later probe
    assert r["revision"] == "9.10"
    assert set(r["sources"]) == {"iscsi:inquiry", "iscsi:rescan"}


def test_record_lun_keeps_distinct_luns_when_lun_id_differs():
    """LUN 0 and LUN 1 on the same target = two block devices, two rows."""
    h = Host(ip="10.0.0.10")
    record_lun(h, _IQN_A, "0", vendor="NETAPP", product="LUN")
    record_lun(h, _IQN_A, "1", vendor="NETAPP", product="LUN")
    got = luns_for(h)
    assert len(got) == 2
    assert {r["lun_id"] for r in got} == {"0", "1"}


def test_record_lun_keeps_distinct_luns_when_iqn_differs():
    """LUN 0 on iqn.A and LUN 0 on iqn.B are two different LUNs."""
    h = Host(ip="10.0.0.10")
    record_lun(h, _IQN_A, "0", vendor="NETAPP")
    record_lun(h, _IQN_B, "0", vendor="NETAPP")
    assert len(luns_for(h)) == 2


def test_record_lun_honours_explicit_portal_ip():
    """A redirected portal address (Login StatusClass=Redirect) can carry
    a portal_ip different from host.ip — record where the LUN LIVES so
    by_portal indexes the correct array."""
    h = Host(ip="10.0.0.10")
    record_lun(h, _IQN_A, "0", portal_ip="10.99.0.5",
               vendor="NETAPP", product="LUN")
    r = luns_for(h)[0]
    assert r["portal_ip"] == "10.99.0.5"


def test_record_lun_silently_drops_when_host_is_none():
    """Producers occasionally get a None host (target not in scope) — the
    reader must not raise."""
    record_lun(None, _IQN_A, "0", vendor="NETAPP")    # no exception


# --- known_luns engagement-wide -------------------------------------------

def test_known_luns_indexes_by_iqn_and_portal():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_lun(a, _IQN_A, "0", vendor="NETAPP", product="LUN")
    record_lun(a, _IQN_A, "1", vendor="NETAPP", product="LUN")
    record_lun(b, _IQN_B, "0", vendor="LIO-ORG", product="TCMU")
    inv = known_luns([a, b])
    assert len(inv["luns"]) == 3
    assert len(inv["by_iqn"][_IQN_A.lower()]) == 2
    assert len(inv["by_iqn"][_IQN_B.lower()]) == 1
    assert len(inv["by_portal"]["10.0.0.10"]) == 2
    assert len(inv["by_portal"]["10.0.0.20"]) == 1


def test_known_luns_dedupes_same_lun_seen_from_two_hosts():
    """Same portal + IQN + LUN id observed against two hosts (a shared
    array reachable from two initiator VLANs) collapses to one row; the
    sources list unions."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_lun(a, _IQN_A, "0", portal_ip="10.99.0.5",
               vendor="NETAPP", product="LUN", source="iscsi:inquiry")
    record_lun(b, _IQN_A, "0", portal_ip="10.99.0.5",
               vendor="NETAPP", product="LUN", source="iscsiadm:session")
    inv = known_luns([a, b])
    assert len(inv["luns"]) == 1
    assert set(inv["luns"][0]["sources"]) == {"iscsi:inquiry",
                                              "iscsiadm:session"}


def test_known_luns_ignores_hosts_with_no_recorded_luns():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_lun(a, _IQN_A, "0", vendor="NETAPP", product="LUN")
    inv = known_luns([a, b])
    assert "10.0.0.20" not in inv["by_portal"]
    assert list(inv["by_iqn"].keys()) == [_IQN_A.lower()]


def test_luns_for_returns_copies_so_consumer_mutation_is_safe():
    h = Host(ip="10.0.0.10")
    record_lun(h, _IQN_A, "0", vendor="NETAPP", source="iscsi:inquiry")
    got = luns_for(h)
    got[0]["vendor"] = "TAMPERED"
    got[0]["sources"].append("attacker")
    fresh = luns_for(h)
    assert fresh[0]["vendor"] == "NETAPP"
    assert "attacker" not in fresh[0]["sources"]


# --- wire fixture parses cleanly through iscsi._parse_inquiry --------------

def test_wire_inquiry_parses_to_vendor_product_revision():
    """The SPC-4 §6.6 fixture is the exact shape the wire delivers on a
    successful INQUIRY against LUN 0."""
    raw = _wire_inquiry("NETAPP", "LUN", "9.10")
    parsed = iscsi._parse_inquiry(raw)
    assert parsed["vendor"] == "NETAPP"             # padding stripped
    assert parsed["product"] == "LUN"
    assert parsed["revision"] == "9.10"
    assert parsed["device_type"] == 0               # direct-access block


# --- Producer wire: iscsi._record_luns -> known_luns ----------------------

def test_iscsi_producer_wire_records_lun_from_inquiry():
    """Integration: real INQUIRY bytes parsed through iscsi._parse_inquiry,
    the probe-dict shape iscsi.probe() emits is fed to iscsi._record_luns,
    and known_luns() then sees the LUN with vendor / product / revision +
    portal_ip + IQN."""
    raw = _wire_inquiry("LIO-ORG", "TCMU device", "0002")
    inq = iscsi._parse_inquiry(raw)
    pr = {
        "is_iscsi": True,
        "targets": [{"iqn": _IQN_A,
                     "addresses": [{"ip": "10.0.0.10", "port": 3260,
                                    "portal_group": "1"}]}],
        "inquiry": inq,
        "read_capacity": {"blocks": 2048, "block_size": 512,
                          "capacity_bytes": 1048576},
    }
    h = Host(ip="10.0.0.10")
    iscsi._record_luns([h], "10.0.0.10", pr)

    inv = known_luns([h])
    assert len(inv["luns"]) == 1
    r = inv["luns"][0]
    assert r["portal_ip"] == "10.0.0.10"
    assert r["iqn"] == _IQN_A
    assert r["lun_id"] == "0"
    assert r["vendor"] == "LIO-ORG"
    assert r["product"] == "TCMU device"
    assert r["revision"] == "0002"
    assert "iscsi:inquiry" in r["sources"]
    # by_iqn and by_portal indexes populated
    assert inv["by_iqn"][_IQN_A.lower()][0] is r
    assert inv["by_portal"]["10.0.0.10"][0] is r


def test_iscsi_producer_skips_when_no_inquiry_data():
    """Discovery-only probe (targets known, INQUIRY did not run) — target
    inventory alone isn't a LUN, so the reader stays empty."""
    pr = {"is_iscsi": True,
          "targets": [{"iqn": _IQN_A, "addresses": []}],
          "inquiry": {}, "read_capacity": {}}
    h = Host(ip="10.0.0.10")
    iscsi._record_luns([h], "10.0.0.10", pr)
    assert luns_for(h) == []


def test_iscsi_producer_skips_when_probe_not_iscsi():
    """Port answered but was not iSCSI (e.g. HTTP on 3260 in a lab)."""
    pr = {"is_iscsi": False}
    h = Host(ip="10.0.0.10")
    iscsi._record_luns([h], "10.0.0.10", pr)
    assert luns_for(h) == []


def test_iscsi_producer_skips_when_ip_not_in_hosts():
    """Defensive: probe result addressed to an IP the hosts list doesn't
    carry — no host to attach to, no exception raised."""
    raw = _wire_inquiry("NETAPP", "LUN", "9.10")
    inq = iscsi._parse_inquiry(raw)
    pr = {"is_iscsi": True,
          "targets": [{"iqn": _IQN_A, "addresses": []}],
          "inquiry": inq, "read_capacity": {}}
    h = Host(ip="10.0.0.99")
    iscsi._record_luns([h], "10.0.0.10", pr)
    assert luns_for(h) == []
