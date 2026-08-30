"""core.known_streams: cross-service RTSP video-stream inventory reader.

Fixtures are wire-shaped: an RTSP DESCRIBE 200 reply follows RFC 2326
(status line + headers + CRLF-CRLF + SDP body); the SDP body itself
follows RFC 4566 (v=/o=/s= session lines, m= media, a=rtpmap codec,
a=fmtp with the vendor `framesize`/`x-dimensions` conventions IP
cameras use to expose WxH). Nothing here calls a recce encoder — the
raw bytes go through rtsp.parse_sdp() to prove the producer picks up
what a real camera would send.
"""
from __future__ import annotations

from recce.core.known_streams import (known_streams, record_stream,
                                      streams_for)
from recce.core.models import Host
from recce.services import rtsp


# --- record_stream ---------------------------------------------------------

def test_record_appends_stream_to_host():
    h = Host(ip="10.0.0.10")
    record_stream(h, "rtsp://10.0.0.10:554/Streaming/Channels/101",
                  codec="H264", resolution="1920x1080",
                  auth_required=True, source="rtsp:path-enum")
    got = streams_for(h)
    assert len(got) == 1
    s = got[0]
    assert s["url"] == "rtsp://10.0.0.10:554/Streaming/Channels/101"
    assert s["codec"] == "H264"
    assert s["resolution"] == "1920x1080"
    assert s["auth_required"] is True
    assert "rtsp:path-enum" in s["sources"]


def test_record_ignores_empty_url():
    h = Host(ip="10.0.0.10")
    record_stream(h, "", codec="H264")
    record_stream(h, "   ", codec="H264")
    assert streams_for(h) == []


def test_record_dedupes_case_insensitively_and_preserves_first_seen_casing():
    """RFC 3986 §3.1/§3.2.2: scheme and host are case-insensitive. IP
    cameras also normalise the path in practice — a case-varying reprobe
    of the same path is one stream, and the display casing seen first wins."""
    h = Host(ip="10.0.0.10")
    record_stream(h, "rtsp://10.0.0.10:554/Streaming/Channels/101",
                  codec="H264", source="rtsp:describe")
    record_stream(h, "RTSP://10.0.0.10:554/streaming/channels/101",
                  codec="H264", source="rtsp:path-enum")
    got = streams_for(h)
    assert len(got) == 1
    assert got[0]["url"] == "rtsp://10.0.0.10:554/Streaming/Channels/101"
    assert set(got[0]["sources"]) == {"rtsp:describe", "rtsp:path-enum"}


def test_record_merges_blank_fields_from_later_observation():
    """The path-enum probe learns the URL first with no SDP; the later
    root DESCRIBE fills in codec/resolution from parsed SDP."""
    h = Host(ip="10.0.0.10")
    record_stream(h, "rtsp://10.0.0.10:554/live",
                  source="rtsp:path-enum:dahua")   # codec/res blank
    record_stream(h, "rtsp://10.0.0.10:554/live",
                  codec="H264", resolution="1280x720",
                  source="rtsp:describe")
    got = streams_for(h)
    assert len(got) == 1
    s = got[0]
    assert s["codec"] == "H264"
    assert s["resolution"] == "1280x720"
    assert set(s["sources"]) == {"rtsp:path-enum:dahua", "rtsp:describe"}


def test_record_first_seen_casing_wins_on_populated_field():
    h = Host(ip="10.0.0.10")
    record_stream(h, "rtsp://10.0.0.10:554/live", codec="H264",
                  source="rtsp:describe")
    record_stream(h, "rtsp://10.0.0.10:554/live", codec="h264",
                  source="rtsp:describe-2")
    assert streams_for(h)[0]["codec"] == "H264"


def test_record_auth_required_and_folds_looser_wins():
    """Once ANY probe saw the stream served without auth, that fact
    stays. auth_required is AND-folded: True only when every observation
    reported True."""
    h = Host(ip="10.0.0.10")
    # First: 401 challenge (auth required).
    record_stream(h, "rtsp://10.0.0.10:554/live",
                  auth_required=True, source="rtsp:describe-root")
    # Later: found an alternate path that answered 200 unauth for the
    # SAME URL (e.g. a credentialed retry we later flip on the same rec).
    record_stream(h, "rtsp://10.0.0.10:554/live",
                  auth_required=False, source="rtsp:unauth-retry")
    assert streams_for(h)[0]["auth_required"] is False


def test_record_auth_required_stays_true_when_every_observation_agrees():
    h = Host(ip="10.0.0.10")
    record_stream(h, "rtsp://10.0.0.10:554/live",
                  auth_required=True, source="a")
    record_stream(h, "rtsp://10.0.0.10:554/live",
                  auth_required=True, source="b")
    assert streams_for(h)[0]["auth_required"] is True


def test_record_keeps_distinct_streams_when_paths_differ():
    """One camera commonly exposes main + substream on different paths."""
    h = Host(ip="10.0.0.10")
    record_stream(h, "rtsp://10.0.0.10:554/Streaming/Channels/101",
                  codec="H264", source="rtsp")
    record_stream(h, "rtsp://10.0.0.10:554/Streaming/Channels/102",
                  codec="H264", source="rtsp")
    assert len(streams_for(h)) == 2


def test_streams_for_returns_copies_so_consumer_mutation_is_safe():
    h = Host(ip="10.0.0.10")
    record_stream(h, "rtsp://10.0.0.10:554/live", codec="H264",
                  source="rtsp")
    got = streams_for(h)
    got[0]["codec"] = "TAMPERED"
    got[0]["sources"].append("attacker")
    fresh = streams_for(h)
    assert fresh[0]["codec"] == "H264"
    assert "attacker" not in fresh[0]["sources"]


# --- known_streams engagement-wide -----------------------------------------

def test_known_streams_indexes_by_camera_ip():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_stream(a, "rtsp://10.0.0.10:554/live", codec="H264",
                  auth_required=True, source="rtsp")
    record_stream(a, "rtsp://10.0.0.10:554/live/sub", codec="H264",
                  auth_required=True, source="rtsp")
    record_stream(b, "rtsp://10.0.0.20:554/axis-media/media.amp",
                  codec="H264", auth_required=False, source="rtsp")
    inv = known_streams([a, b])
    assert len(inv["streams"]) == 3
    assert len(inv["by_camera"]["10.0.0.10"]) == 2
    assert len(inv["by_camera"]["10.0.0.20"]) == 1


def test_known_streams_authless_shortcut_is_the_worldviewable_set():
    """auth_required=False = DESCRIBE answered 200 without any
    Authorization header — the world-viewable set an attacker pulls first."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_stream(a, "rtsp://10.0.0.10:554/live", auth_required=True,
                  source="rtsp")
    record_stream(b, "rtsp://10.0.0.20:554/axis-media/media.amp",
                  auth_required=False, source="rtsp")
    inv = known_streams([a, b])
    urls = [s["url"] for s in inv["authless"]]
    assert urls == ["rtsp://10.0.0.20:554/axis-media/media.amp"]


def test_known_streams_priority_orders_authless_before_authgated():
    """Priority ordering: authless streams (highest value) sort ahead
    of auth-gated ones in the flat `streams` list."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_stream(a, "rtsp://10.0.0.10:554/gated", auth_required=True,
                  source="rtsp")
    record_stream(b, "rtsp://10.0.0.20:554/open", auth_required=False,
                  source="rtsp")
    inv = known_streams([a, b])
    assert inv["streams"][0]["auth_required"] is False
    assert inv["streams"][-1]["auth_required"] is True


def test_known_streams_dedupes_across_reprobes_of_same_url():
    """The engagement reader collapses (ip, url_lc) — a rerun of the
    same probe against the same camera does not double-count."""
    h = Host(ip="10.0.0.10")
    record_stream(h, "rtsp://10.0.0.10:554/live", codec="H264",
                  source="rtsp:run1")
    record_stream(h, "RTSP://10.0.0.10:554/LIVE", codec="H264",
                  source="rtsp:run2")
    inv = known_streams([h])
    assert len(inv["streams"]) == 1
    assert set(inv["streams"][0]["sources"]) == {"rtsp:run1", "rtsp:run2"}


# --- Producer wire: RTSP probe result -> known_streams --------------------

# A minimal RFC 2326 DESCRIBE 200 with RFC 4566 SDP. `a=fmtp:96
# framesize:96 1920-1080` is the Hikvision convention for exposing
# resolution outside SPS. `m=video ... 96` + `a=rtpmap:96 H264/90000`
# is the ordinary H.264 media / codec declaration.
_SDP_WIRE = (
    b"v=0\r\n"
    b"o=- 0 0 IN IP4 10.1.2.3\r\n"
    b"s=Media Presentation\r\n"
    b"i=1920x1080\r\n"
    b"c=IN IP4 0.0.0.0\r\n"
    b"t=0 0\r\n"
    b"a=control:*\r\n"
    b"m=video 0 RTP/AVP 96\r\n"
    b"a=rtpmap:96 H264/90000\r\n"
    b"a=fmtp:96 packetization-mode=1; framesize:96 1920-1080; "
    b"profile-level-id=42001F\r\n"
    b"a=control:trackID=1\r\n"
)


def test_resolution_from_sdp_reads_framesize_convention():
    """Hikvision `a=fmtp:96 framesize:96 WxH` is a documented vendor
    convention for exposing resolution outside SPS parsing."""
    sdp = rtsp.parse_sdp(_SDP_WIRE)
    assert rtsp._resolution_from_sdp(sdp) == "1920x1080"


def test_resolution_from_sdp_reads_x_dimensions_convention():
    """Axis / QuickTime convention: `a=fmtp:96 x-dimensions=W,H`."""
    wire = _SDP_WIRE.replace(b"framesize:96 1920-1080",
                             b"x-dimensions=1280,720")
    sdp = rtsp.parse_sdp(wire)
    assert rtsp._resolution_from_sdp(sdp) == "1280x720"


def test_rtsp_producer_wire_records_authless_stream_from_root_describe():
    """Feed the RTSP probe result shape (unauth root DESCRIBE returned
    200 + SDP) into the wire helper, and the reader must see one
    authless stream with codec + resolution from the SDP."""
    sdp = rtsp.parse_sdp(_SDP_WIRE)
    pr = {"reachable": True, "unauth_stream": True, "sdp": sdp,
          "paths": [], "auth": {}, "tls": False}
    h = Host(ip="10.1.2.3")
    rtsp._record_streams([h], "10.1.2.3", 554, pr)

    inv = known_streams([h])
    assert len(inv["streams"]) == 1
    s = inv["streams"][0]
    assert s["url"] == "rtsp://10.1.2.3:554/"
    assert s["codec"] == "H264"
    assert s["resolution"] == "1920x1080"
    assert s["auth_required"] is False
    assert inv["authless"] == [s]
    assert inv["by_camera"]["10.1.2.3"] == [s]


def test_rtsp_producer_wire_records_authgated_stream_from_401_root():
    """No unauth stream, but the 401 challenge on / proves a stream
    lives at the root URL — record it as auth_required."""
    pr = {"reachable": True, "unauth_stream": False, "sdp": None,
          "paths": [], "auth": {"digest": True, "realm": "IPCam",
                                "nonce": "abc"}, "tls": False}
    h = Host(ip="10.1.2.3")
    rtsp._record_streams([h], "10.1.2.3", 554, pr)

    inv = known_streams([h])
    assert len(inv["streams"]) == 1
    s = inv["streams"][0]
    assert s["url"] == "rtsp://10.1.2.3:554/"
    assert s["auth_required"] is True
    assert inv["authless"] == []


def test_rtsp_producer_wire_records_vendor_path_streams():
    """The well-known path enum returned 200 on one path and 401 on
    another — both become stream URLs; the 200 becomes authless, the
    401 becomes auth_required. Codec/resolution attach to the 200 side
    because SDP was served there."""
    sdp = rtsp.parse_sdp(_SDP_WIRE)
    pr = {
        "reachable": True, "unauth_stream": True, "sdp": sdp,
        "paths": [
            {"path": "/Streaming/Channels/101", "vendor": "hikvision",
             "status": 200},
            {"path": "/cam/realmonitor?channel=1&subtype=0",
             "vendor": "dahua", "status": 401},
            {"path": "/junk", "vendor": "generic", "status": 404},
        ],
        "auth": {}, "tls": False,
    }
    h = Host(ip="10.1.2.3")
    rtsp._record_streams([h], "10.1.2.3", 554, pr)

    inv = known_streams([h])
    urls = {s["url"]: s for s in inv["streams"]}
    # Root + hikvision 200 + dahua 401 = 3 streams. /junk (404) is dropped.
    assert set(urls) == {
        "rtsp://10.1.2.3:554/",
        "rtsp://10.1.2.3:554/Streaming/Channels/101",
        "rtsp://10.1.2.3:554/cam/realmonitor?channel=1&subtype=0",
    }
    assert urls["rtsp://10.1.2.3:554/Streaming/Channels/101"]["auth_required"] is False
    assert urls["rtsp://10.1.2.3:554/cam/realmonitor?channel=1&subtype=0"]["auth_required"] is True
    # The 200 path inherits codec from the SDP.
    assert urls["rtsp://10.1.2.3:554/Streaming/Channels/101"]["codec"] == "H264"


def test_rtsp_producer_wire_skips_unreachable():
    h = Host(ip="10.1.2.3")
    rtsp._record_streams([h], "10.1.2.3", 554,
                         {"reachable": False, "unauth_stream": False})
    assert streams_for(h) == []


def test_rtsp_producer_wire_uses_rtsps_scheme_when_tls():
    pr = {"reachable": True, "unauth_stream": True,
          "sdp": rtsp.parse_sdp(_SDP_WIRE), "paths": [], "auth": {},
          "tls": True}
    h = Host(ip="10.1.2.3")
    rtsp._record_streams([h], "10.1.2.3", 322, pr, tls=True)
    s = streams_for(h)[0]
    assert s["url"].startswith("rtsps://")
