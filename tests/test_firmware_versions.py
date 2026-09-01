"""core.firmware_versions: flat projection over known_ot_assets, keyed on
the firmware string. Producer wires live on the OT service analyze()
paths; the reader itself has no attach-to-host writes to test."""
from __future__ import annotations

from recce.core.firmware_versions import firmware_versions
from recce.core.known_ot_assets import record_ot_asset
from recce.core.models import Host


def test_firmware_versions_filters_out_assets_without_firmware():
    h = Host(ip="10.0.0.10")
    record_ot_asset(h, "enip", vendor="Rockwell", model="1756-L82E",
                    firmware="")  # blank firmware -> filtered out
    record_ot_asset(h, "s7", vendor="Siemens", model="6ES7 315-2AG10-0AB0",
                    firmware="V3.2.6")
    got = firmware_versions([h])
    assert len(got["firmware"]) == 1
    assert got["firmware"][0]["firmware"] == "V3.2.6"
    assert got["firmware"][0]["firmware_string"] == "V3.2.6"


def test_firmware_versions_groups_by_vendor():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_ot_asset(a, "s7", vendor="Siemens", model="315-2AG10",
                    firmware="V3.2.6")
    record_ot_asset(b, "enip", vendor="Rockwell", model="1756-L82E",
                    firmware="33.011")
    got = firmware_versions([a, b])
    assert set(got["by_vendor"].keys()) == {"siemens", "rockwell"}
    assert len(got["by_vendor"]["siemens"]) == 1
    assert got["by_vendor"]["siemens"][0]["ip"] == "10.0.0.10"


def test_firmware_versions_by_firmware_counts_across_engagement():
    """Two boxes on the same firmware = the count the future CVE-match
    consumer needs (blast radius = 2, not 1)."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_ot_asset(a, "s7", vendor="Siemens", model="315",
                    firmware="V3.2.6")
    record_ot_asset(b, "s7", vendor="Siemens", model="315",
                    firmware="V3.2.6")
    got = firmware_versions([a, b])
    assert got["by_firmware"][("siemens", "315", "v3.2.6")] == 2


def test_firmware_versions_case_insensitive_key_display_first_seen():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_ot_asset(a, "s7", vendor="Siemens", model="315",
                    firmware="V3.2.6")
    record_ot_asset(b, "s7", vendor="SIEMENS", model="315",
                    firmware="v3.2.6")
    got = firmware_versions([a, b])
    # Same (vendor_lc, model_lc, firmware_lc) triplet counts as one class.
    assert got["by_firmware"][("siemens", "315", "v3.2.6")] == 2
    # First-seen casing wins on the flat entry from host A.
    a_entry = [e for e in got["firmware"] if e["ip"] == "10.0.0.10"][0]
    assert a_entry["vendor"] == "Siemens"


def test_firmware_versions_empty_when_no_ot_assets():
    h = Host(ip="10.0.0.10")
    got = firmware_versions([h])
    assert got == {"firmware": [], "by_vendor": {}, "by_firmware": {}}


def test_firmware_versions_carries_protocol_and_sources():
    h = Host(ip="10.0.0.10")
    record_ot_asset(h, "bacnet", vendor="Trane", model="SC",
                    firmware="4.30.1052", source="bacnet:read-property")
    got = firmware_versions([h])
    entry = got["firmware"][0]
    assert entry["protocol"] == "bacnet"
    assert "bacnet:read-property" in entry["sources"]
