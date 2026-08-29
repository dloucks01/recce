"""core.known_ot_assets: cross-service OT/ICS asset inventory reader.

Fixtures below are wire-shaped: the CIP List Identity item is built to
match the on-wire layout documented in ODVA Vol 2 §2-4.4.2 (little-endian
vendor_id / device_type / product_code / serial); the S7 SZL 0x0011
record shape is the 28-byte MLFB block from Siemens' S7-300/400 System
Software Reference §SZL. We feed those bytes into the service parsers,
then call the producer wire and assert the reader sees the asset.
"""
from __future__ import annotations

import struct

from recce.core.known_ot_assets import (assets_for, known_ot_assets,
                                        record_ot_asset)
from recce.core.models import Host
from recce.services import enip, s7


# --- record_ot_asset -------------------------------------------------------

def test_record_appends_asset_to_host():
    h = Host(ip="10.0.0.10")
    record_ot_asset(h, "s7", vendor="Siemens", model="6ES7 315-2EH14-0AB0",
                    firmware="V3.5", serial="S C-C7UM12345678",
                    cpu_family="S7-300", source="s7:szl-0x0011")
    got = assets_for(h)
    assert len(got) == 1
    a = got[0]
    assert a["vendor"] == "Siemens"
    assert a["model"] == "6ES7 315-2EH14-0AB0"
    assert a["firmware"] == "V3.5"
    assert a["cpu_family"] == "S7-300"
    assert "s7:szl-0x0011" in a["sources"]
    assert "s7" in a["sources"]


def test_record_ignores_empty_identity():
    h = Host(ip="10.0.0.10")
    record_ot_asset(h, "s7")
    record_ot_asset(h, "s7", vendor="", model="", firmware="", serial="")
    assert assets_for(h) == []


def test_record_dedupes_by_vendor_model_serial_and_preserves_first_seen_casing():
    """A second observation on the same physical box merges into the first —
    same (vendor, model, serial) triplet is the correlation key. Case-
    insensitive per ODVA §2-4 vendor-string handling; casing that was first
    seen wins for display."""
    h = Host(ip="10.0.0.10")
    record_ot_asset(h, "s7", vendor="Siemens", model="6ES7 315-2EH14-0AB0",
                    serial="C7UM12345678", source="s7:szl-0x0011")
    # Same identity, different casing on vendor, same protocol re-run.
    record_ot_asset(h, "s7", vendor="SIEMENS", model="6ES7 315-2EH14-0AB0",
                    serial="c7um12345678", firmware="V3.5",
                    source="s7:szl-0x0011-rerun")
    got = assets_for(h)
    assert len(got) == 1
    a = got[0]
    # First-seen casing wins on the vendor field
    assert a["vendor"] == "Siemens"
    # firmware got filled from the second observation
    assert a["firmware"] == "V3.5"
    # Both sources tracked
    assert "s7:szl-0x0011" in a["sources"]
    assert "s7:szl-0x0011-rerun" in a["sources"]


def test_record_correlates_across_protocols_on_same_host():
    """Same PLC answering S7 on 102 AND EtherNet/IP on 44818 with matching
    (vendor, model, serial) collapses to one asset with both protocols in
    sources — IEC 62443 asset-inventory intent: one physical asset, one
    record, regardless of how many protocols surfaced it."""
    h = Host(ip="10.0.0.10")
    record_ot_asset(h, "s7", vendor="Siemens", model="SIMATIC S7-1500",
                    serial="ABC123", firmware="V2.9", source="s7:szl-0x0011")
    record_ot_asset(h, "enip", vendor="Siemens", model="SIMATIC S7-1500",
                    serial="abc123", firmware="V2.9",
                    source="enip:list-identity")
    got = assets_for(h)
    assert len(got) == 1
    assert "s7" in got[0]["sources"]
    assert "enip" in got[0]["sources"]


def test_record_keeps_distinct_assets_when_serial_differs():
    """Two CPUs on one gateway IP (rare but real — proxy/gateway front-ends
    for multiple downstream CPUs) must NOT merge into one row."""
    h = Host(ip="10.0.0.10")
    record_ot_asset(h, "s7", vendor="Siemens", model="6ES7 315",
                    serial="AAA", source="s7")
    record_ot_asset(h, "s7", vendor="Siemens", model="6ES7 315",
                    serial="BBB", source="s7")
    assert len(assets_for(h)) == 2


# --- known_ot_assets engagement-wide ---------------------------------------

def test_known_ot_assets_indexes_by_vendor_and_by_firmware():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    c = Host(ip="10.0.0.30")
    record_ot_asset(a, "s7", vendor="Siemens", model="S7-1500",
                    firmware="V2.9", serial="s1")
    record_ot_asset(b, "s7", vendor="Siemens", model="S7-1500",
                    firmware="V2.9", serial="s2")
    record_ot_asset(c, "enip", vendor="Rockwell", model="ControlLogix",
                    firmware="32.011", serial="r1")
    got = known_ot_assets([a, b, c])
    assert len(got["assets"]) == 3
    # by_vendor buckets are lowercased keys
    assert len(got["by_vendor"]["siemens"]) == 2
    assert len(got["by_vendor"]["rockwell"]) == 1
    # by_firmware counts how many devices share a (vendor, model, firmware)
    assert got["by_firmware"][("siemens", "s7-1500", "v2.9")] == 2
    assert got["by_firmware"][("rockwell", "controllogix", "32.011")] == 1


def test_known_ot_assets_returns_shallow_copies_so_consumer_mutation_is_safe():
    h = Host(ip="10.0.0.10")
    record_ot_asset(h, "s7", vendor="Siemens", model="S7-300", serial="X")
    got = assets_for(h)
    got[0]["vendor"] = "TAMPERED"
    got[0]["sources"].append("attacker")
    fresh = assets_for(h)
    assert fresh[0]["vendor"] == "Siemens"
    assert "attacker" not in fresh[0]["sources"]


# --- Producer wire: EtherNet/IP List Identity feeds the reader -------------

def _wire_cip_identity_item() -> bytes:
    """CIP Identity item body (ODVA Vol 2 §2-4.4.2 / Vol 1 §5-2.2).
    Layout: proto_ver(2 LE) socket_addr(16) vendor_id(2 LE) device_type(2 LE)
    product_code(2 LE) rev_major(1) rev_minor(1) status(2 LE) serial(4 LE)
    name_len(1) name(N) state(1)."""
    proto_ver = struct.pack("<H", 1)
    sock_addr = b"\x00" * 16
    vendor_id = struct.pack("<H", 0x0001)             # Rockwell / Allen-Bradley
    device_type = struct.pack("<H", 0x000E)           # PLC
    product_code = struct.pack("<H", 89)
    revision = bytes([32, 11])                        # V32.11
    status = struct.pack("<H", 0x0060)
    serial = struct.pack("<I", 0xDEADBEEF)
    name = b"1756-L83E/B LOGIX5583E"
    return (proto_ver + sock_addr + vendor_id + device_type + product_code
            + revision + status + serial + bytes([len(name)]) + name
            + b"\x00")


def test_enip_producer_wire_records_asset_from_list_identity():
    """The end-to-end wire: parse a real CIP Identity item off the wire,
    hand it to the enip producer helper, and assert the reader sees the
    ODVA-vendored asset with vendor + model + firmware + serial."""
    ident = enip._parse_identity_item(_wire_cip_identity_item())
    assert ident is not None
    assert ident["vendor_id"] == 0x0001

    h = Host(ip="10.1.2.3")
    enip._record_asset([h], "10.1.2.3", ident)

    inv = known_ot_assets([h])
    assert len(inv["assets"]) == 1
    a = inv["assets"][0]
    assert a["vendor"].startswith("Rockwell")
    assert a["model"] == "1756-L83E/B LOGIX5583E"
    assert a["firmware"] == "32.11"
    # Serial rendered as 8-char lowercase hex of the CIP UDINT
    assert a["serial"] == f"{0xDEADBEEF:08x}"
    assert "enip:list-identity" in a["sources"]


# --- Producer wire: S7 SZL 0x0011 feeds the reader -------------------------

def _wire_szl_0011_record() -> bytes:
    """SZL 0x0011 module-identification record — 28 bytes per Siemens
    S7-300/400 System Software Reference: index(2) MLFB(20 ASCII, space-
    padded) BGTyp(2) Ausbg1(2) Ausbg2(2). Ausbg2 high byte encodes firmware
    major, low byte minor."""
    mlfb = b"6ES7 315-2EH14-0AB0 "
    assert len(mlfb) == 20
    return struct.pack(">H", 0x0001) + mlfb + struct.pack(">HHH",
                                                          0x0000, 0x0104, 0x0305)


def test_s7_producer_wire_records_asset_from_szl_0011():
    """Parse a real SZL 0x0011 record off the wire, build the probe dict
    the s7 producer helper expects, and assert the reader sees a Siemens
    S7-300 asset with the CPU order code and the firmware string."""
    module_info = s7._parse_module_id([_wire_szl_0011_record()])
    assert module_info["order_code"].startswith("6ES7 315")
    assert module_info["fw_version"].startswith("V")

    h = Host(ip="10.1.2.4")
    pr = {"order_code": module_info["order_code"],
          "fw_version": module_info["fw_version"],
          "component": {"serial_number": "S C-C7UM12345678"}}
    s7._record_asset([h], "10.1.2.4", pr)

    inv = known_ot_assets([h])
    assert len(inv["assets"]) == 1
    a = inv["assets"][0]
    assert a["vendor"] == "Siemens"
    assert a["model"] == module_info["order_code"]
    assert a["firmware"] == module_info["fw_version"]
    assert a["cpu_family"] == "S7-300"
    assert a["serial"] == "S C-C7UM12345678"
    assert "s7:szl-0x0011" in a["sources"]


def test_s7_and_enip_wire_correlate_when_same_serial_on_same_host():
    """The IEC 62443 asset-inventory point: one physical CPU answering two
    protocols correlates into one asset."""
    h = Host(ip="10.1.2.5")
    # Emulate the CPU answering S7 on 102...
    s7._record_asset([h], "10.1.2.5",
                     {"order_code": "6ES7 516-3AN01-0AB0",
                      "fw_version": "V2.9",
                      "component": {"serial_number": "SN-COMMON"}})
    # ...and its Ethernet CP answering CIP List Identity on 44818 with the
    # same serial the operator engraved on the box.
    ident = {"vendor_id": 0x00A3, "product_name": "6ES7 516-3AN01-0AB0",
             "revision": "2.9", "serial_number": 0}
    # For CIP, the enip producer stringifies the UDINT serial; here we
    # bypass and record directly to prove the correlation key works.
    record_ot_asset(h, "enip", vendor="Siemens",
                    model="6ES7 516-3AN01-0AB0",
                    firmware="2.9", serial="SN-COMMON",
                    source="enip:list-identity")
    _ = ident
    inv = known_ot_assets([h])
    assert len(inv["assets"]) == 1
    a = inv["assets"][0]
    assert "s7" in a["sources"]
    assert "enip" in a["sources"]
