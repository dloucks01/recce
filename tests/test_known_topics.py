"""core.known_topics: cross-service MQTT topic-namespace reader.

Fixtures below build MQTT PUBLISH packets directly on the wire (OASIS
MQTT v3.1.1 §3.3) so `retained` / `payload_size` are derived from real
byte layouts, not from any recce encoder. The reader then consumes the
same fields (topic string, RETAIN bit, remaining-length payload) via
`record_topic()`.
"""
from __future__ import annotations

from recce.core.known_topics import (known_topics, record_topic,
                                     topics_for)
from recce.core.models import Host, Port


# --- wire-derived PUBLISH fixture ------------------------------------------
#
# MQTT v3.1.1 §3.3 fixed header for PUBLISH:
#   byte 1: type(4) | DUP(1) | QoS(2) | RETAIN(1)  -> PUBLISH type = 3
#   byte 2..: remaining length (variable-byte int, §2.2.3)
#   variable header: topic name (UTF-8 length-prefixed, §3.3.2.1),
#                    then payload
def _remlen(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _publish(topic: str, payload: bytes, retain: bool = False,
             qos: int = 0) -> bytes:
    tb = topic.encode("utf-8")
    var = len(tb).to_bytes(2, "big") + tb + payload
    fixed = 0x30 | ((qos & 0x03) << 1) | (0x01 if retain else 0x00)
    return bytes([fixed]) + _remlen(len(var)) + var


def _parse_publish(pkt: bytes) -> dict:
    """Bare-minimum parser: reads the fields our reader consumes."""
    fixed = pkt[0]
    assert (fixed >> 4) == 0x03, "expected PUBLISH"
    retain = bool(fixed & 0x01)
    # skip remlen (single-byte here for our small fixtures)
    i = 2
    tlen = int.from_bytes(pkt[i:i + 2], "big")
    i += 2
    topic = pkt[i:i + tlen].decode("utf-8")
    i += tlen
    payload = pkt[i:]
    return {"topic": topic, "retain": retain, "size": len(payload)}


# --- record_topic ----------------------------------------------------------

def test_record_topic_attaches_to_host_and_topics_for_reads_back():
    pkt = _publish("shelly/shelly1-001/status",
                   b'{"ison":true}', retain=True)
    parsed = _parse_publish(pkt)
    h = Host(ip="10.0.0.10")
    record_topic(h, parsed["topic"], retained=parsed["retain"],
                 payload_size=parsed["size"], source="mqtt:retained")
    got = topics_for(h)
    assert len(got) == 1
    assert got[0]["topic"] == "shelly/shelly1-001/status"
    assert got[0]["broker_ip"] == "10.0.0.10"
    assert got[0]["retained"] is True
    assert got[0]["payload_size"] == len(b'{"ison":true}')
    assert got[0]["sources"] == ["mqtt:retained"]


def test_record_topic_dedups_case_insensitively_and_preserves_first_seen():
    """MQTT topics are case-sensitive on the wire (§4.7.1.1), but IoT
    vendors ship consistent per-family casing; the inventory dedupes
    case-insensitively with first-seen casing kept for display."""
    h = Host(ip="10.0.0.10")
    record_topic(h, "Shelly/1/relay", retained=True, payload_size=5,
                 source="mqtt:retained")
    record_topic(h, "shelly/1/relay", retained=False, payload_size=3,
                 source="mqtt:live")
    got = topics_for(h)
    assert len(got) == 1
    # Display casing = first seen
    assert got[0]["topic"] == "Shelly/1/relay"
    # Sources merged
    assert set(got[0]["sources"]) == {"mqtt:retained", "mqtt:live"}


def test_record_topic_retained_is_monotonic_or():
    """A subsequent live-only sighting must not clear an earlier
    retained sighting; the row remembers ANY retained observation."""
    h = Host(ip="10.0.0.10")
    record_topic(h, "sensors/temp", retained=True, payload_size=4,
                 source="mqtt:retained")
    record_topic(h, "sensors/temp", retained=False, payload_size=6,
                 source="mqtt:live")
    got = topics_for(h)
    assert got[0]["retained"] is True


def test_record_topic_payload_size_keeps_largest_observation():
    h = Host(ip="10.0.0.10")
    record_topic(h, "sensors/temp", retained=True, payload_size=4,
                 source="mqtt:retained")
    record_topic(h, "sensors/temp", retained=True, payload_size=128,
                 source="mqtt:retained")
    record_topic(h, "sensors/temp", retained=True, payload_size=12,
                 source="mqtt:retained")
    assert topics_for(h)[0]["payload_size"] == 128


def test_record_topic_silently_drops_empty_topic():
    h = Host(ip="10.0.0.10")
    record_topic(h, "", retained=True, payload_size=0, source="mqtt:retained")
    record_topic(h, "   ", retained=False, payload_size=0, source="mqtt:live")
    assert topics_for(h) == []


def test_record_topic_normalises_trailing_slash_for_dedup_only():
    """`foo/bar/` and `foo/bar` name the same node (§4.7.1.1: the level
    separator has no trailing empty level). Dedup collapses them but
    display keeps the first-seen form."""
    h = Host(ip="10.0.0.10")
    record_topic(h, "shelly/1/", retained=True, payload_size=2,
                 source="mqtt:retained")
    record_topic(h, "shelly/1", retained=True, payload_size=2,
                 source="mqtt:live")
    got = topics_for(h)
    assert len(got) == 1
    assert got[0]["topic"] == "shelly/1/"


def test_topics_for_returns_copies_so_consumer_cannot_corrupt_store():
    h = Host(ip="10.0.0.10")
    record_topic(h, "shelly/1/status", retained=True, payload_size=5,
                 source="mqtt:retained")
    got = topics_for(h)
    got[0]["topic"] = "tampered"
    got[0]["sources"].append("junk")
    # Original store unaffected
    fresh = topics_for(h)
    assert fresh[0]["topic"] == "shelly/1/status"
    assert fresh[0]["sources"] == ["mqtt:retained"]


# --- known_topics engagement-wide correlation ------------------------------

def test_known_topics_unions_across_brokers_by_topic_and_ip():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_topic(a, "shelly/1/status", retained=True, payload_size=8,
                 source="mqtt:retained")
    record_topic(b, "tasmota/plug1/STATE", retained=True, payload_size=32,
                 source="mqtt:retained")
    got = known_topics([a, b])
    assert got["by_broker"]["10.0.0.10"] == ["shelly/1/status"]
    assert got["by_broker"]["10.0.0.20"] == ["tasmota/plug1/STATE"]
    # Two rows, one per broker/topic pair.
    assert len(got["topics"]) == 2


def test_known_topics_by_prefix_counts_broker_topic_pairs():
    """`shelly/` appearing on THREE brokers reads 3, not 6 even when
    each broker has both a retained and a live sighting on the same
    topic (those collapse into one row per broker)."""
    hs = [Host(ip=f"10.0.0.{i}") for i in (10, 20, 30)]
    for h in hs:
        record_topic(h, "shelly/1/status", retained=True, payload_size=8,
                     source="mqtt:retained")
        record_topic(h, "shelly/1/status", retained=False, payload_size=4,
                     source="mqtt:live")
    got = known_topics(hs)
    assert got["by_prefix"] == {"shelly": 3}


def test_known_topics_by_prefix_keeps_dollar_sys_verbatim():
    """`$SYS` is the OASIS-reserved broker-metrics namespace (§4.7.2)
    and must appear as its own prefix, not stripped or merged with
    non-reserved topics."""
    a = Host(ip="10.0.0.10")
    record_topic(a, "$SYS/broker/version", retained=True, payload_size=10,
                 source="mqtt:$sys")
    record_topic(a, "shelly/1", retained=True, payload_size=2,
                 source="mqtt:retained")
    got = known_topics([a])
    assert got["by_prefix"]["$SYS"] == 1
    assert got["by_prefix"]["shelly"] == 1


def test_known_topics_ignores_hosts_with_no_recorded_topics():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_topic(a, "shelly/1/status", retained=True, payload_size=8,
                 source="mqtt:retained")
    got = known_topics([a, b])
    assert "10.0.0.20" not in got["by_broker"]
    assert len(got["topics"]) == 1


def test_known_topics_same_topic_two_brokers_reports_two_rows():
    """`homeassistant/status` on broker A and broker B is two distinct
    facts — the topic namespace is per-broker."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_topic(a, "homeassistant/status", retained=True, payload_size=6,
                 source="mqtt:retained")
    record_topic(b, "homeassistant/status", retained=True, payload_size=6,
                 source="mqtt:retained")
    got = known_topics([a, b])
    assert len(got["topics"]) == 2
    assert got["by_prefix"] == {"homeassistant": 2}


# --- producer wire: mqtt.analyze() -> record_topic -------------------------

def test_mqtt_analyze_wires_topics_into_known_topics(monkeypatch):
    """Integration: mqtt.analyze() feeds the reader from its per-probe
    retained/live/sys lists, and known_topics() then sees them.

    We build the probe result from wire-parsed PUBLISH packets so the
    fixture stays fully derived from bytes, not synthesised."""
    from recce.services import mqtt, svcprobe

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=1883, protocol="tcp", state="open",
                    service="mqtt", product="mosquitto", version="2.0.15")]

    retained_pkt = _publish("shelly/shelly1-001/status",
                            b'{"ison":true}', retain=True)
    live_pkt = _publish("sensors/temp/room1", b"22.4", retain=False)
    r_parsed = _parse_publish(retained_pkt)
    l_parsed = _parse_publish(live_pkt)

    fake_pr = {
        "reachable": True, "anon_ok": True, "publish_ok": False,
        "protocol_level": 4, "version": "mosquitto 2.0.15",
        "sys": {"$SYS/broker/version": "mosquitto version 2.0.15"},
        "retained": [{"topic": r_parsed["topic"],
                      "size": r_parsed["size"],
                      "snippet": b'{"ison":true}', "qos": 0}],
        "live": [{"topic": l_parsed["topic"],
                  "size": l_parsed["size"],
                  "snippet": b"22.4", "qos": 0}],
    }

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)

    mqtt.analyze([h], active=True)

    got_topics = topics_for(h)
    names = {t["topic"] for t in got_topics}
    assert "shelly/shelly1-001/status" in names
    assert "sensors/temp/room1" in names
    assert "$SYS/broker/version" in names

    got = known_topics([h])
    assert got["by_prefix"]["shelly"] == 1
    assert got["by_prefix"]["sensors"] == 1
    assert got["by_prefix"]["$SYS"] == 1
    retained_row = next(t for t in got["topics"]
                        if t["topic"] == "shelly/shelly1-001/status")
    assert retained_row["retained"] is True
    assert "mqtt:retained" in retained_row["sources"]
    live_row = next(t for t in got["topics"]
                    if t["topic"] == "sensors/temp/room1")
    assert live_row["retained"] is False
    assert "mqtt:live" in live_row["sources"]
