"""core.known_devices: cross-service non-OT device inventory reader.

Fixtures below are wire-shaped: RTSP OPTIONS reply follows RFC 7826 §7
(status line + Server header + CRLF-CRLF); the MQTT probe dict mirrors
the shape mqtt.probe() returns after a v3.1.1 CONNECT + wildcard
subscribe drain (MQTT 3.1.1 spec §3.2, §3.3). We drive the producer
wire directly with those shapes and assert the reader sees the device.
"""
from __future__ import annotations

from recce.core.known_devices import (devices_for, known_devices,
                                      record_device)
from recce.core.models import Host
from recce.services import mqtt, rtsp


# --- record_device ---------------------------------------------------------

def test_record_appends_device_to_host():
    h = Host(ip="10.0.0.10")
    record_device(h, "rtsp:server-header", vendor="hikvision",
                  model="Hikvision-Webs/1.0", firmware="1.0",
                  device_type="ip-camera")
    got = devices_for(h)
    assert len(got) == 1
    d = got[0]
    assert d["vendor"] == "hikvision"
    assert d["model"] == "Hikvision-Webs/1.0"
    assert d["firmware"] == "1.0"
    assert d["device_type"] == "ip-camera"
    assert "rtsp:server-header" in d["sources"]


def test_record_ignores_empty_identity():
    h = Host(ip="10.0.0.10")
    record_device(h, "rtsp")
    record_device(h, "rtsp", vendor="", model="", firmware="", device_type="")
    assert devices_for(h) == []


def test_record_dedupes_case_insensitively_and_preserves_first_seen_casing():
    """A second observation with the same (vendor, model, firmware) merges
    into the first. Case-insensitive comparison — RTSP Server headers vary
    wildly in casing between firmware revisions of the same product line —
    but the display casing that was seen first wins."""
    h = Host(ip="10.0.0.10")
    record_device(h, "rtsp:server-header", vendor="Hikvision",
                  model="Hikvision-Webs/1.0", firmware="1.0",
                  device_type="ip-camera")
    record_device(h, "onvif:probe", vendor="HIKVISION",
                  model="hikvision-webs/1.0", firmware="1.0",
                  device_type="ip-camera")
    got = devices_for(h)
    assert len(got) == 1
    d = got[0]
    assert d["vendor"] == "Hikvision"
    assert d["model"] == "Hikvision-Webs/1.0"
    assert "rtsp:server-header" in d["sources"]
    assert "onvif:probe" in d["sources"]


def test_record_merges_blank_fields_from_later_observation():
    """Second observation on the same (vendor, model, firmware) fills in
    device_type left blank the first time; first-seen casing wins on any
    field that was already populated."""
    h = Host(ip="10.0.0.10")
    record_device(h, "rtsp", vendor="axis", model="M3045-V",
                  firmware="9.80.1")   # device_type blank first pass
    record_device(h, "http", vendor="AXIS", model="M3045-V",
                  firmware="9.80.1", device_type="ip-camera")
    got = devices_for(h)
    assert len(got) == 1
    d = got[0]
    assert d["vendor"] == "axis"                  # first-seen casing wins
    assert d["device_type"] == "ip-camera"        # filled from later probe
    assert set(d["sources"]) == {"rtsp", "http"}


def test_record_keeps_distinct_devices_when_firmware_differs():
    """Two cameras on one gateway (NAT'd behind a single public IP) with
    different firmware must NOT merge."""
    h = Host(ip="10.0.0.10")
    record_device(h, "rtsp", vendor="Hikvision", model="DS-2CD",
                  firmware="5.5.0")
    record_device(h, "rtsp", vendor="Hikvision", model="DS-2CD",
                  firmware="5.7.3")
    assert len(devices_for(h)) == 2


def test_record_unions_cves_across_observations():
    h = Host(ip="10.0.0.10")
    record_device(h, "rtsp", vendor="Hikvision", model="DS-2CD",
                  cves=[{"cve": "CVE-2021-36260", "kev": True}])
    record_device(h, "rtsp", vendor="Hikvision", model="DS-2CD",
                  cves=[{"cve": "CVE-2017-7921", "kev": False},
                        {"cve": "CVE-2021-36260", "kev": True}])
    cves = devices_for(h)[0]["cves"]
    ids = [c["cve"] for c in cves]
    assert "CVE-2021-36260" in ids
    assert "CVE-2017-7921" in ids
    assert len(ids) == 2                          # deduped by cve id


# --- known_devices engagement-wide ----------------------------------------

def test_known_devices_indexes_by_vendor_lowercased():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    c = Host(ip="10.0.0.30")
    record_device(a, "rtsp", vendor="Hikvision", model="DS-2CD",
                  firmware="5.5.0")
    record_device(b, "rtsp", vendor="Hikvision", model="DS-2CD",
                  firmware="5.5.0")
    record_device(c, "mqtt", vendor="mosquitto", firmware="2.0.15",
                  device_type="iot-hub")
    inv = known_devices([a, b, c])
    assert len(inv["devices"]) == 3
    assert len(inv["by_vendor"]["hikvision"]) == 2
    assert len(inv["by_vendor"]["mosquitto"]) == 1


def test_known_devices_yields_cve_candidates_with_kev_confidence():
    a = Host(ip="10.0.0.10")
    record_device(a, "rtsp", vendor="Hikvision", model="DS-2CD",
                  cves=[{"cve": "CVE-2021-36260", "kev": True,
                         "note": "unauth RCE"},
                        {"cve": "CVE-2017-7921", "kev": False}])
    inv = known_devices([a])
    ids = {c["cve"]: c["confidence"] for c in inv["cve_candidates"]}
    assert ids["CVE-2021-36260"] == "high"        # KEV bumps to high
    assert ids["CVE-2017-7921"] == "medium"       # default


def test_known_devices_returns_shallow_copies_so_consumer_mutation_is_safe():
    h = Host(ip="10.0.0.10")
    record_device(h, "rtsp", vendor="Hikvision", model="DS-2CD",
                  cves=[{"cve": "CVE-2021-36260", "kev": True}])
    got = devices_for(h)
    got[0]["vendor"] = "TAMPERED"
    got[0]["sources"].append("attacker")
    got[0]["cves"][0]["cve"] = "CVE-XXXX-XXXX"
    fresh = devices_for(h)
    assert fresh[0]["vendor"] == "Hikvision"
    assert "attacker" not in fresh[0]["sources"]
    assert fresh[0]["cves"][0]["cve"] == "CVE-2021-36260"


# --- Producer wire: RTSP Server header feeds the reader --------------------

def _wire_rtsp_options_reply(server: str) -> bytes:
    """RFC 7826 §7 OPTIONS status-line + headers. Same status line + Server
    header shape that comes back on the wire from a real IP camera."""
    return (
        b"RTSP/1.0 200 OK\r\n"
        b"CSeq: 1\r\n"
        b"Server: " + server.encode("ascii") + b"\r\n"
        b"Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN, GET_PARAMETER\r\n"
        b"\r\n"
    )


def test_rtsp_producer_wire_records_camera_from_server_header():
    """Parse a real RTSP Server header off the wire (RFC 7826 §7), run the
    RTSP CVE matcher, and assert the reader sees an IP-camera device with
    vendor + model + firmware + KEV CVE candidate."""
    reply = _wire_rtsp_options_reply("Hikvision-Webs/2.0")
    m = rtsp._SERVER_RE.search(reply)
    assert m is not None
    server = m.group(1).decode("ascii").strip()
    cve_hits = rtsp.match_cves(server)
    assert any(c["cve"] == "CVE-2021-36260" for c in cve_hits)

    pr = {"reachable": True, "server": server, "cve_hits": cve_hits}
    h = Host(ip="10.1.2.3")
    rtsp._record_device([h], "10.1.2.3", pr)

    inv = known_devices([h])
    assert len(inv["devices"]) == 1
    d = inv["devices"][0]
    assert d["vendor"] == "hikvision"
    assert d["model"] == "Hikvision-Webs/2.0"
    assert d["firmware"] == "2.0"
    assert d["device_type"] == "ip-camera"
    assert "rtsp:server-header" in d["sources"]
    assert any(c["cve"] == "CVE-2021-36260"
               for c in inv["cve_candidates"])


def test_rtsp_producer_skips_unreachable():
    h = Host(ip="10.1.2.3")
    rtsp._record_device([h], "10.1.2.3",
                        {"reachable": False, "server": "Hikvision-Webs/1.0"})
    assert devices_for(h) == []


# --- Producer wire: MQTT retained topic prefix feeds the reader ------------

def test_mqtt_producer_wire_records_iot_hub_from_retained_topics():
    """The MQTT probe dict shape returned by mqtt.probe() after a wildcard
    subscribe drain (§3.3 PUBLISH replays retained). shelly/ / tasmota/ /
    zigbee2mqtt/ retained topics are the vendor-canonical convention that
    identifies the broker as an IoT hub."""
    pr = {
        "reachable": True,
        "version": "mosquitto 2.0.15",
        "retained": [
            {"topic": "shelly/shelly1-abc/status",
             "size": 3, "snippet": b"on", "qos": 0},
            {"topic": "tasmota/plug1/STATE",
             "size": 4, "snippet": b"OFF", "qos": 0},
            {"topic": "zigbee2mqtt/bridge/state",
             "size": 6, "snippet": b"online", "qos": 0},
        ],
        "live": [],
    }
    h = Host(ip="10.1.2.4")
    mqtt._record_device([h], "10.1.2.4", pr)

    inv = known_devices([h])
    assert len(inv["devices"]) == 1
    d = inv["devices"][0]
    assert d["vendor"] == "mosquitto"
    assert d["firmware"] == "2.0.15"
    assert d["device_type"] == "iot-hub"
    assert "mqtt:retained-topic" in d["sources"]


def test_mqtt_producer_records_broker_when_no_iot_topics_seen():
    pr = {"reachable": True, "version": "mosquitto 2.0.15",
          "retained": [], "live": []}
    h = Host(ip="10.1.2.4")
    mqtt._record_device([h], "10.1.2.4", pr)
    d = devices_for(h)[0]
    assert d["device_type"] == "mqtt-broker"
    assert d["vendor"] == "mosquitto"
    assert d["firmware"] == "2.0.15"


def test_mqtt_producer_skips_when_no_version_and_no_iot_topics():
    """Broker refused version disclosure AND no IoT topics — nothing to
    record; the reader stays empty."""
    pr = {"reachable": True, "version": "", "retained": [], "live": []}
    h = Host(ip="10.1.2.4")
    mqtt._record_device([h], "10.1.2.4", pr)
    assert devices_for(h) == []


# --- Cross-service correlation --------------------------------------------

def test_rtsp_and_mqtt_produce_distinct_devices_on_same_host():
    """An IP camera and an MQTT broker on the same host stay as two
    devices — different vendor + model triplets."""
    h = Host(ip="10.1.2.5")
    rtsp._record_device([h], "10.1.2.5",
                        {"reachable": True, "server": "Hikvision-Webs/1.0",
                         "cve_hits": rtsp.match_cves("Hikvision-Webs/1.0")})
    mqtt._record_device([h], "10.1.2.5",
                        {"reachable": True, "version": "mosquitto 2.0.15",
                         "retained": [], "live": []})
    inv = known_devices([h])
    assert len(inv["devices"]) == 2
    vendors = {d["vendor"] for d in inv["devices"]}
    assert vendors == {"hikvision", "mosquitto"}
