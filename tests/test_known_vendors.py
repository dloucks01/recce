"""core.known_vendors: cross-service vendor fingerprint reader.

Fixtures below are wire-shaped, not built through a recce encoder:

  * Telnet IAC negotiation stream (RFC 854 IAC=0xFF + WILL/DO option
    bytes) plus a Cisco IOS "User Access Verification" banner
  * MQTT $SYS/broker/version topic payload (`mosquitto version 2.0.15`)
    as landed on the `.version` field of a v3.1.1 CONNACK-completed
    probe dict (MQTT 3.1.1 §3.2)

The reader is driven directly; the integration test drives one producer
(telnet.analyze) through a stubbed iter_probe to prove the wire lands.
"""
from __future__ import annotations

from recce.core.known_vendors import (known_vendors, record_vendor,
                                      vendors_for)
from recce.core.models import Host, Port


# --- record_vendor ---------------------------------------------------------

def test_record_appends_vendor_to_host():
    h = Host(ip="10.0.0.10")
    record_vendor(h, 23, "cisco-ios", source="telnet:banner",
                  confidence="medium")
    got = vendors_for(h)
    assert len(got) == 1
    rec = got[0]
    assert rec["vendor"] == "cisco-ios"
    assert rec["ip"] == "10.0.0.10"
    assert rec["port"] == 23
    assert rec["source"] == "telnet:banner"
    assert rec["confidence"] == "medium"


def test_record_ignores_empty_vendor():
    h = Host(ip="10.0.0.10")
    record_vendor(h, 23, "", source="telnet:banner")
    record_vendor(h, 23, "   ", source="telnet:banner")
    assert vendors_for(h) == []


def test_record_dedupes_case_insensitively_and_preserves_first_seen_casing():
    """A second observation of the same vendor from the same source on
    the same port merges into the first. Vendor branding varies wildly
    in casing between banners of the same product line but the first
    casing seen wins for display."""
    h = Host(ip="10.0.0.10")
    record_vendor(h, 23, "Cisco-IOS", source="telnet:banner")
    record_vendor(h, 23, "CISCO-IOS", source="telnet:banner")
    got = vendors_for(h)
    assert len(got) == 1
    assert got[0]["vendor"] == "Cisco-IOS"


def test_record_keeps_distinct_sources_on_the_same_endpoint():
    """Two producers can observe the same vendor on the same port — the
    banner probe and a later cred'd shell for example. Both rows survive
    because the source is part of the dedup key."""
    h = Host(ip="10.0.0.10")
    record_vendor(h, 22, "openssh-ubuntu", source="ssh:comment")
    record_vendor(h, 22, "openssh-ubuntu", source="ssh:credshell")
    got = vendors_for(h)
    assert len(got) == 2
    assert {r["source"] for r in got} == {"ssh:comment", "ssh:credshell"}


def test_record_promotes_confidence_but_never_demotes():
    """A later observation with a HIGHER confidence promotes the entry
    (a follow-up cred'd shell strengthening a banner guess). A weaker
    later observation is silently dropped so noise cannot degrade a
    strong finding."""
    h = Host(ip="10.0.0.10")
    record_vendor(h, 23, "cisco-ios", source="telnet:banner",
                  confidence="low")
    record_vendor(h, 23, "cisco-ios", source="telnet:banner",
                  confidence="high")
    got = vendors_for(h)
    assert len(got) == 1
    assert got[0]["confidence"] == "high"
    # A weaker follow-up must not demote it.
    record_vendor(h, 23, "cisco-ios", source="telnet:banner",
                  confidence="low")
    assert vendors_for(h)[0]["confidence"] == "high"


def test_record_coerces_unknown_confidence_to_medium():
    h = Host(ip="10.0.0.10")
    record_vendor(h, 23, "cisco-ios", source="telnet:banner",
                  confidence="totally-made-up")
    assert vendors_for(h)[0]["confidence"] == "medium"


def test_vendors_for_returns_copies_so_consumer_cannot_corrupt_store():
    h = Host(ip="10.0.0.10")
    record_vendor(h, 23, "cisco-ios", source="telnet:banner")
    got = vendors_for(h)
    got[0]["vendor"] = "tampered"
    assert vendors_for(h)[0]["vendor"] == "cisco-ios"


# --- known_vendors engagement-wide -----------------------------------------

def test_known_vendors_unions_across_hosts_by_vendor():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_vendor(a, 23, "cisco-ios", source="telnet:banner")
    record_vendor(b, 23, "cisco-ios", source="telnet:banner")
    got = known_vendors([a, b])
    bucket = got["by_vendor"]["cisco-ios"]
    ips = {e["ip"] for e in bucket}
    assert ips == {"10.0.0.10", "10.0.0.20"}


def test_known_vendors_by_ip_lists_every_vendor_seen_on_a_host():
    """A NAT'd gateway can multiplex Cisco (23) and BusyBox (2323) —
    both vendors appear under one IP."""
    h = Host(ip="10.0.0.10")
    record_vendor(h, 23, "cisco-ios", source="telnet:banner")
    record_vendor(h, 2323, "busybox", source="telnet:banner")
    got = known_vendors([h])
    assert set(got["by_ip"]["10.0.0.10"]) == {"cisco-ios", "busybox"}


def test_known_vendors_priority_orders_high_confidence_first():
    """A `$SYS/broker/version` hit (high) precedes a banner-regex hit
    (medium) which precedes an option-set heuristic (low). Within a
    tier, insertion order is preserved (Python's stable sort)."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    c = Host(ip="10.0.0.30")
    record_vendor(a, 23, "cisco-ios", source="telnet:iac-fingerprint",
                  confidence="low")
    record_vendor(b, 1883, "mosquitto", source="mqtt:sys-version",
                  confidence="high")
    record_vendor(c, 23, "solaris", source="telnet:banner",
                  confidence="medium")
    got = known_vendors([a, b, c])
    confs = [r["confidence"] for r in got["vendors"]]
    assert confs == ["high", "medium", "low"]
    assert got["vendors"][0]["vendor"] == "mosquitto"


def test_known_vendors_ignores_hosts_with_no_recorded_vendor():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_vendor(a, 23, "cisco-ios", source="telnet:banner")
    got = known_vendors([a, b])
    assert "10.0.0.20" not in got["by_ip"]
    assert list(got["by_vendor"].keys()) == ["cisco-ios"]


def test_known_vendors_by_vendor_bucket_dedupes_same_endpoint_from_same_source():
    """Two hosts both hitting the same vendor bucket should appear as
    two distinct entries; a duplicate from record_vendor's dedup pass on
    one host should not double the bucket."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_vendor(a, 23, "cisco-ios", source="telnet:banner")
    record_vendor(a, 23, "cisco-ios", source="telnet:banner")   # dup
    record_vendor(b, 23, "cisco-ios", source="telnet:banner")
    bucket = known_vendors([a, b])["by_vendor"]["cisco-ios"]
    assert len(bucket) == 2
    assert {e["ip"] for e in bucket} == {"10.0.0.10", "10.0.0.20"}


# --- producer wire: telnet.analyze() -> record_vendor -----------------------

# A minimal Cisco IOS telnet negotiation captured on the wire:
#   IAC WILL ECHO           (server offers to echo)
#   IAC WILL SUPPRESS-GA    (streaming, no GA)
#   IAC DO   TERMINAL-TYPE  (asks the client for its TTYPE)
# Then a banner and prompt.  IAC=0xFF, WILL=0xFB, DO=0xFD.
_IOS_WIRE = (
    b"\xff\xfb\x01"                        # IAC WILL ECHO
    b"\xff\xfb\x03"                        # IAC WILL SUPPRESS-GA
    b"\xff\xfd\x18"                        # IAC DO   TTYPE
    b"\r\n\r\nUser Access Verification\r\n\r\nUsername: "
)


def test_telnet_analyze_wires_vendor_into_known_vendors(monkeypatch):
    """Integration: telnet.analyze() runs a probe that lands vendor
    ='cisco-ios' from the pre-login banner and feeds it into the
    cross-service correlator.

    We stub the network probe so the test stays offline: return a probe
    dict shaped exactly as telnet.probe() would from the raw wire bytes
    in _IOS_WIRE (banner "User Access Verification" → cisco-ios).
    """
    from recce.services import svcprobe, telnet

    # Sanity: telnet._vendor_from must actually classify this banner
    # as cisco-ios so the wire → vendor mapping is real, not stubbed.
    banner = telnet._clean_banner(telnet._iac_parse(_IOS_WIRE)["text"])
    assert telnet._vendor_from(banner)[0] == "cisco-ios"

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=23, protocol="tcp", state="open",
                    service="telnet")]

    fake_pr = {
        "ip": "10.0.0.10", "port": 23, "banner": banner,
        "options_will": [1, 3], "options_do": [24],
        "options_wont": [], "options_dont": [],
        "encrypt_offered": False, "auth_offered": False,
        "environ_offered": False, "environ_leak": {},
        "vendor": "cisco-ios",
        "vendor_desc": "Cisco IOS (User Access Verification banner)",
        "ntlm": {}, "ayt_ok": False, "tls": False,
        "looks_like_telnet": True,
    }

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)

    telnet.analyze([h], active=True)

    # The host now carries the vendor …
    rows = vendors_for(h)
    assert [r["vendor"] for r in rows] == ["cisco-ios"]
    assert rows[0]["source"] == "telnet:banner"
    assert rows[0]["port"] == 23
    # … and the engagement-wide reader sees it.
    got = known_vendors([h])
    assert got["by_ip"]["10.0.0.10"] == ["cisco-ios"]
    assert {e["ip"] for e in got["by_vendor"]["cisco-ios"]} == {"10.0.0.10"}
