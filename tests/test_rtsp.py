"""Tests for recce.services.rtsp.

Fixtures are literal RTSP/1.0 wire bytes derived from RFC 2326 (RTSP), RFC
4566 (SDP), RFC 7616 (Digest) and vendor-shipped Server strings — NOT built
from recce's own encoders. A codec change in recce cannot be masked by a
symmetric bug in the fixture.
"""
from __future__ import annotations

import hashlib
import socket
import threading

from recce.core.models import Host, Port
from recce.services import rtsp


# --- helpers ---------------------------------------------------------------

class _RTSPServer:
    """Serve a scripted sequence of RTSP replies. Each accepted TCP connection
    receives one reply from the queue (in order), then closes."""

    def __init__(self, replies: list[bytes]):
        self._replies = list(replies)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self._sock.settimeout(0.5)
        self.host, self.port = self._sock.getsockname()
        self.requests: list[bytes] = []
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(0.5)
                buf = b""
                while b"\r\n\r\n" not in buf and len(buf) < 8192:
                    try:
                        chunk = conn.recv(4096)
                    except (socket.timeout, OSError):
                        break
                    if not chunk:
                        break
                    buf += chunk
                self.requests.append(buf)
                if self._replies:
                    reply = self._replies.pop(0)
                    try:
                        conn.sendall(reply)
                    except OSError:
                        pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


# Canned wire replies used across tests. Bytes are hand-written, RFC-shaped.

_OPTIONS_200 = (
    b"RTSP/1.0 200 OK\r\n"
    b"CSeq: 1\r\n"
    b"Server: Hipcam RealServer/V1.0\r\n"
    b"Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, GET_PARAMETER\r\n"
    b"\r\n"
)

_OPTIONS_200_NO_GETPARAM = (
    b"RTSP/1.0 200 OK\r\n"
    b"CSeq: 1\r\n"
    b"Server: Dahua Rtsp Server\r\n"
    b"Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n"
    b"\r\n"
)

_SDP_BODY = (
    b"v=0\r\n"
    b"o=- 0 0 IN IP4 127.0.0.1\r\n"
    b"s=HikvisionDS-2CD2032-I\r\n"
    b"i=camera-front-door\r\n"
    b"c=IN IP4 0.0.0.0\r\n"
    b"t=0 0\r\n"
    b"a=tool:LIVE555 Streaming Media v2013.04.30\r\n"
    b"a=control:*\r\n"
    b"m=video 0 RTP/AVP 96\r\n"
    b"a=rtpmap:96 H264/90000\r\n"
    b"a=fmtp:96 packetization-mode=1;profile-level-id=42001F\r\n"
    b"a=control:track1\r\n"
    b"m=audio 0 RTP/AVP 8\r\n"
    b"a=rtpmap:8 PCMA/8000\r\n"
    b"a=control:track2\r\n"
)

_DESCRIBE_200 = (
    b"RTSP/1.0 200 OK\r\n"
    b"CSeq: 3\r\n"
    b"Content-Type: application/sdp\r\n"
    b"Content-Length: " + str(len(_SDP_BODY)).encode() + b"\r\n"
    b"\r\n"
) + _SDP_BODY

_DESCRIBE_401_DIGEST = (
    b"RTSP/1.0 401 Unauthorized\r\n"
    b"CSeq: 3\r\n"
    b'WWW-Authenticate: Digest realm="HikvisionDS", '
    b'nonce="4e6f6e63653132333435", algorithm=MD5, qop="auth"\r\n'
    b"\r\n"
)

_DESCRIBE_401_BASIC_AND_DIGEST = (
    b"RTSP/1.0 401 Unauthorized\r\n"
    b"CSeq: 3\r\n"
    b'WWW-Authenticate: Basic realm="IP Camera"\r\n'
    b'WWW-Authenticate: Digest realm="IP Camera", '
    b'nonce="deadbeefcafe", algorithm=MD5\r\n'
    b"\r\n"
)

_DESCRIBE_404 = (
    b"RTSP/1.0 404 Not Found\r\n"
    b"CSeq: 4\r\n"
    b"\r\n"
)

_GET_PARAMETER_200 = (
    b"RTSP/1.0 200 OK\r\n"
    b"CSeq: 2\r\n"
    b"Session: 12345678\r\n"
    b"\r\n"
)


# --- parser-level unit tests ----------------------------------------------

def test_parse_www_authenticate_digest_only():
    hdr = 'Digest realm="HikvisionDS", nonce="abc", algorithm=MD5, qop="auth"'
    a = rtsp.parse_www_authenticate(hdr)
    assert a["digest"] and not a["basic"]
    assert a["realm"] == "HikvisionDS"
    assert a["nonce"] == "abc"
    assert a["algorithm"] == "MD5"
    assert a["qop"] == "auth"


def test_parse_www_authenticate_basic_and_digest():
    hdr = ('Basic realm="IP Camera", '
           'Digest realm="IP Camera", nonce="xyz", algorithm=MD5')
    a = rtsp.parse_www_authenticate(hdr)
    assert a["basic"] and a["digest"]
    assert a["realm"] == "IP Camera"
    assert a["nonce"] == "xyz"


def test_parse_sdp_captures_session_tool_codecs_and_controls():
    sdp = rtsp.parse_sdp(_SDP_BODY)
    assert sdp["session"] == "HikvisionDS-2CD2032-I"
    assert "LIVE555" in sdp["tool"]
    kinds = [m["kind"] for m in sdp["media"]]
    assert "video" in kinds and "audio" in kinds
    codecs = {c["codec"] for c in sdp["codecs"]}
    assert "H264" in codecs and "PCMA" in codecs
    assert "track1" in sdp["controls"]
    assert any("profile-level-id" in f for f in sdp["fmtp"])


def test_digest_response_matches_rfc7616_reference_vectors():
    # RFC 7616-shaped self-check: computing HA1/HA2/response by hand must
    # match rtsp._digest_response for the same inputs. Fixture derived from
    # the digest algebra, not from rtsp's own helper being called twice.
    user, password, realm = "admin", "12345", "HikvisionDS"
    nonce = "4e6f6e63653132333435"
    method, uri = "DESCRIBE", "rtsp://10.0.0.10:554/"
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    expect_no_qop = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    got = rtsp._digest_response(user, password, realm, nonce, method, uri)
    assert got == expect_no_qop
    # qop=auth path with nc + cnonce.
    nc, cnonce, qop = "00000001", "recce", "auth"
    expect_qop = hashlib.md5(
        f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    got_qop = rtsp._digest_response(user, password, realm, nonce, method, uri,
                                    qop=qop, nc=nc, cnonce=cnonce)
    assert got_qop == expect_qop


def test_hashcat_line_is_mode_11400_shape():
    line = rtsp.hashcat_line_sip(
        realm="HikvisionDS", method="DESCRIBE",
        uri="rtsp://10.0.0.10:554/", nonce="abc123", qop="auth")
    # $sip$* prefix + starred fields + placeholder tokens for the client-
    # side pieces recce cannot know without an intercept.
    assert line.startswith("$sip$*")
    parts = line.split("*")
    # $sip$ / algo / realm / uri / method / nonce / nc / cnonce / qop / response
    assert len(parts) == 10
    assert parts[2] == "HikvisionDS"
    assert parts[4] == "DESCRIBE"
    assert parts[5] == "abc123"
    assert parts[8] == "auth"
    assert "<response>" in line


def test_find_creds_in_text_extracts_inline_credentials():
    text = ("ffplay rtsp://admin:12345@10.0.0.10:554/Streaming/Channels/101 &\n"
            "cat /etc/nvr.conf # rtsps://root:root@cam.example.local/live\n"
            "duplicate: rtsp://admin:12345@10.0.0.10:554/Streaming/Channels/101")
    hits = rtsp.find_creds_in_text(text)
    users = {(h["user"], h["password"], h["host"]) for h in hits}
    assert ("admin", "12345", "10.0.0.10") in users
    assert ("root", "root", "cam.example.local") in users
    # Dedup: three lines but two unique creds.
    assert len(hits) == 2


def test_match_cves_hikvision_kev_hit():
    hits = rtsp.match_cves("Hipcam RealServer/V1.0")
    cves = {h["cve"] for h in hits}
    assert "CVE-2021-36260" in cves
    kev_flags = {h["cve"]: h["kev"] for h in hits}
    assert kev_flags["CVE-2021-36260"] is True


def test_match_cves_no_match_for_generic_server():
    assert rtsp.match_cves("nginx/1.24") == []


def test_is_rtsp_matches_default_and_alt_ports():
    assert rtsp.is_rtsp(Port(portid=554, state="open"))
    assert rtsp.is_rtsp(Port(portid=8554, state="open"))
    assert rtsp.is_rtsp(Port(portid=9999, state="open", service="rtsp"))
    assert not rtsp.is_rtsp(Port(portid=22, state="open", service="ssh"))
    assert not rtsp.is_rtsp(Port(portid=554, state="closed"))


# --- probe() end-to-end tests ---------------------------------------------

def test_probe_options_captures_server_and_public():
    # Sequence probe() issues on a reachable server:
    #   1) OPTIONS
    #   2) GET_PARAMETER (only if Public: contains GET_PARAMETER)
    #   3) DESCRIBE / (root)
    #   4..) per-path DESCRIBE for each well-known path
    #
    # For this test only the OPTIONS + GET_PARAMETER + DESCRIBE matter; a
    # 404 for every well-known path keeps the probe going.
    replies: list[bytes] = [_OPTIONS_200, _GET_PARAMETER_200, _DESCRIBE_401_DIGEST]
    replies += [_DESCRIBE_404] * len(rtsp._WELL_KNOWN_PATHS)
    srv = _RTSPServer(replies)
    try:
        pr = rtsp.probe(srv.host, srv.port, timeout=2.0)
    finally:
        srv.close()
    assert pr["reachable"]
    assert pr["server"] == "Hipcam RealServer/V1.0"
    assert "GET_PARAMETER" in pr["public"]
    assert pr["liveness"] is True
    # Digest challenge captured.
    assert pr["auth"]["digest"] and pr["auth"]["realm"] == "HikvisionDS"
    assert pr["digest_capture"].startswith("$sip$*")
    # Server matched a known-vulnerable Hikvision build.
    assert any(h["cve"] == "CVE-2021-36260" for h in pr["cve_hits"])
    # No unauth stream.
    assert pr["unauth_stream"] is False


def test_probe_unauth_stream_parses_sdp():
    # DESCRIBE returns 200 with SDP -> unauth_stream=True + parsed SDP.
    replies: list[bytes] = [
        _OPTIONS_200_NO_GETPARAM,     # OPTIONS (no GET_PARAMETER in Public)
        _DESCRIBE_200,                # DESCRIBE /  -> 200 + SDP (unauth)
    ]
    # Every well-known path also returns SDP; probe() only sets the first.
    replies += [_DESCRIBE_200] * len(rtsp._WELL_KNOWN_PATHS)
    srv = _RTSPServer(replies)
    try:
        pr = rtsp.probe(srv.host, srv.port, timeout=2.0)
    finally:
        srv.close()
    assert pr["reachable"]
    assert pr["liveness"] is False           # not offered
    assert pr["unauth_stream"] is True
    assert pr["sdp"] is not None
    assert pr["sdp"]["session"] == "HikvisionDS-2CD2032-I"
    assert any(m["kind"] == "video" for m in pr["sdp"]["media"])


def test_probe_path_enum_records_status_per_path():
    # First path in WELL_KNOWN is "/". Give distinct answers: 401 for root,
    # 200 for the Hikvision path, 404 for the rest — validates that
    # probe() records per-path status codes.
    replies: list[bytes] = [
        _OPTIONS_200_NO_GETPARAM,     # OPTIONS
        _DESCRIBE_401_DIGEST,         # DESCRIBE /
    ]
    # Path enum in the order of _WELL_KNOWN_PATHS.
    for path, _ in rtsp._WELL_KNOWN_PATHS:
        if path == "/Streaming/Channels/101":
            replies.append(_DESCRIBE_200)
        elif path == "/":
            replies.append(_DESCRIBE_401_DIGEST)
        else:
            replies.append(_DESCRIBE_404)
    srv = _RTSPServer(replies)
    try:
        pr = rtsp.probe(srv.host, srv.port, timeout=2.0)
    finally:
        srv.close()
    by_path = {p["path"]: p["status"] for p in pr["paths"]}
    assert by_path["/Streaming/Channels/101"] == 200
    assert by_path.get("/videoMain") == 404
    # The Hikvision path returned 200 => unauth_stream latched.
    assert pr["unauth_stream"] is True


def test_probe_basic_and_digest_both_flagged():
    replies: list[bytes] = [_OPTIONS_200_NO_GETPARAM, _DESCRIBE_401_BASIC_AND_DIGEST]
    replies += [_DESCRIBE_404] * len(rtsp._WELL_KNOWN_PATHS)
    srv = _RTSPServer(replies)
    try:
        pr = rtsp.probe(srv.host, srv.port, timeout=2.0)
    finally:
        srv.close()
    assert pr["auth"]["basic"] and pr["auth"]["digest"]
    assert pr["auth"]["realm"] == "IP Camera"


def test_probe_returns_unreachable_when_port_closed():
    # Bind then close — nothing will accept the connection.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    pr = rtsp.probe("127.0.0.1", port, timeout=0.5)
    assert pr["reachable"] is False


# --- default_cred_check ----------------------------------------------------

def test_default_cred_check_accepts_matching_digest():
    realm = "HikvisionDS"
    nonce = "4e6f6e63653132333435"
    algorithm = "MD5"
    qop = "auth"

    accept_user, accept_pass = "admin", "12345"

    # A minimalist RTSP server that:
    #   * demands Digest with the fixed realm+nonce above
    #   * accepts iff response == md5(HA1:nonce:nc:cnonce:qop:HA2)
    class _DigestSrv:
        def __init__(self):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(32)
            self.sock.settimeout(0.5)
            self.host, self.port = self.sock.getsockname()
            self._stop = False
            self.attempts: list[bytes] = []
            threading.Thread(target=self._serve, daemon=True).start()

        def _serve(self):
            while not self._stop:
                try:
                    conn, _ = self.sock.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    conn.settimeout(0.5)
                    buf = b""
                    while b"\r\n\r\n" not in buf and len(buf) < 16384:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                    self.attempts.append(buf)
                    reply = self._answer(buf)
                    try:
                        conn.sendall(reply)
                    except OSError:
                        pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        def _answer(self, req: bytes) -> bytes:
            if b"Authorization: Digest" not in req:
                return (b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n"
                        b'WWW-Authenticate: Digest realm="' + realm.encode()
                        + b'", nonce="' + nonce.encode()
                        + b'", algorithm=MD5, qop="auth"\r\n\r\n')
            # Extract username=, response= and uri= fields.
            import re as _re
            m_user = _re.search(rb'username="([^"]+)"', req)
            m_resp = _re.search(rb'response="([^"]+)"', req)
            m_uri = _re.search(rb'uri="([^"]+)"', req)
            m_nc = _re.search(rb'nc=([0-9a-fA-F]+)', req)
            m_cn = _re.search(rb'cnonce="([^"]+)"', req)
            if not (m_user and m_resp and m_uri):
                return b"RTSP/1.0 400 Bad Request\r\nCSeq: 1\r\n\r\n"
            user = m_user.group(1).decode()
            got = m_resp.group(1).decode()
            uri = m_uri.group(1).decode()
            nc = (m_nc.group(1).decode() if m_nc else "")
            cn = (m_cn.group(1).decode() if m_cn else "")
            ha1 = hashlib.md5(f"{user}:{realm}:{accept_pass}".encode()).hexdigest()
            ha2 = hashlib.md5(f"DESCRIBE:{uri}".encode()).hexdigest()
            expect = hashlib.md5(
                f"{ha1}:{nonce}:{nc}:{cn}:{qop}:{ha2}".encode()).hexdigest()
            if user == accept_user and got == expect:
                return (b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n"
                        b"Content-Type: application/sdp\r\nContent-Length: 5\r\n"
                        b"\r\nv=0\r\n")
            return (b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n"
                    b'WWW-Authenticate: Digest realm="' + realm.encode()
                    + b'", nonce="' + nonce.encode()
                    + b'", algorithm=MD5, qop="auth"\r\n\r\n')

        def close(self):
            self._stop = True
            try:
                self.sock.close()
            except OSError:
                pass

    srv = _DigestSrv()
    try:
        auth = {"digest": True, "basic": False, "realm": realm,
                "nonce": nonce, "algorithm": algorithm, "qop": qop, "opaque": ""}
        # Pin the pair set so the test is deterministic and doesn't try 12.
        pairs = (("admin", "wrong", "wrong"),
                 ("admin", "12345", "Hikvision pre-2015"))
        hits = rtsp.default_cred_check(srv.host, srv.port, auth,
                                       timeout=2.0, pairs=pairs)
    finally:
        srv.close()
    assert hits["tried"] == 2
    assert len(hits["hits"]) == 1
    assert hits["hits"][0]["user"] == "admin"
    assert hits["hits"][0]["password"] == "12345"
    assert hits["hits"][0]["scheme"] == "digest"


def test_default_cred_check_stops_when_no_auth_offered():
    # Server returns 401 with no scheme -> default_cred_check must not try.
    hits = rtsp.default_cred_check(
        "127.0.0.1", 1, {"digest": False, "basic": False}, timeout=0.5)
    assert hits["tried"] == 0
    assert hits["hits"] == []


# --- findings() ------------------------------------------------------------

def _host_with_rtsp(ip="10.0.0.10", port=554):
    return Host(ip=ip, ports=[Port(portid=port, state="open", service="rtsp")])


def test_findings_emit_unauth_stream_critical():
    h = _host_with_rtsp()
    pr = {("10.0.0.10", 554): {
        "reachable": True, "server": "Hipcam", "public": ["OPTIONS"],
        "auth": {}, "unauth_stream": True,
        "sdp": {"session": "cam", "tool": "LIVE555",
                "media": [{"kind": "video", "transport": "RTP/AVP", "payload": 96}],
                "codecs": [{"codec": "H264", "clock": 90000}],
                "controls": [], "fmtp": []},
        "paths": [], "liveness": False, "cve_hits": [], "digest_capture": "",
        "cert_cn": "", "tls": False}}
    fs = rtsp.findings([h], pr)
    kinds = [f["kind"] for f in fs]
    assert "rtsp_unauth_stream" in kinds
    unauth = next(f for f in fs if f["kind"] == "rtsp_unauth_stream")
    assert unauth["severity"] == "critical"


def test_findings_flag_basic_downgrade():
    h = _host_with_rtsp()
    pr = {("10.0.0.10", 554): {
        "reachable": True, "server": "IP Camera",
        "public": [], "allow": [],
        "auth": {"basic": True, "digest": True, "realm": "IPCam",
                 "nonce": "n", "algorithm": "MD5", "qop": ""},
        "unauth_stream": False, "sdp": None,
        "paths": [], "liveness": False, "cve_hits": [],
        "digest_capture": "$sip$**IPCam*rtsp://10.0.0.10:554/*DESCRIBE*n"
                          "*<nc>*<cnonce>**<response>",
        "cert_cn": "", "tls": False}}
    fs = rtsp.findings([h], pr)
    titles = [f["title"] for f in fs]
    assert any("Basic authentication alongside Digest" in t for t in titles)
    assert any("Digest challenge captured" in t for t in titles)


def test_findings_emit_cve_finding_and_mark_kev_critical():
    h = _host_with_rtsp()
    pr = {("10.0.0.10", 554): {
        "reachable": True, "server": "Hipcam RealServer/V1.0",
        "public": [], "allow": [], "auth": {}, "unauth_stream": False,
        "sdp": None, "paths": [], "liveness": False,
        "cve_hits": [{"cve": "CVE-2021-36260", "kev": True,
                      "cwe": ["CWE-78"], "vendor": "hikvision",
                      "note": "unauth RCE via ISAPI (KEV)",
                      "server": "Hipcam RealServer/V1.0"}],
        "digest_capture": "", "cert_cn": "", "tls": False}}
    fs = rtsp.findings([h], pr)
    cve_finding = next(f for f in fs if f["kind"] == "rtsp_known_vuln")
    assert cve_finding["severity"] == "critical"    # KEV -> critical
    assert "CVE-2021-36260" in cve_finding["title"]


def test_findings_default_cred_hit_is_critical():
    h = _host_with_rtsp()
    pr = {("10.0.0.10", 554): {
        "reachable": True, "server": "Hipcam", "public": [], "allow": [],
        "auth": {"digest": True, "realm": "HikvisionDS", "nonce": "n",
                 "algorithm": "MD5", "qop": "auth", "basic": False},
        "unauth_stream": False, "sdp": None, "paths": [], "liveness": False,
        "cve_hits": [], "digest_capture": "", "cert_cn": "", "tls": False}}
    cred_hits = {("10.0.0.10", 554): {"hits": [
        {"user": "admin", "password": "12345",
         "note": "Hikvision pre-2015", "scheme": "digest"}
    ]}}
    fs = rtsp.findings([h], pr, cred_hits=cred_hits)
    dc = next(f for f in fs if f["kind"] == "rtsp_default_cred")
    assert dc["severity"] == "critical"
    assert "admin/12345" in dc["title"]


def test_findings_text_creds_emit_medium():
    text = "vlc rtsp://root:root@cam.local:554/live"
    hits = rtsp.find_creds_in_text(text)
    fs = rtsp.findings([], {}, text_creds=hits)
    assert fs and fs[0]["kind"] == "rtsp_creds_in_url"
    assert fs[0]["severity"] == "medium"


# --- targets / findings_to_vulns -------------------------------------------

def test_rtsp_targets_finds_both_default_ports():
    h = Host(ip="10.0.0.10", ports=[
        Port(portid=554, state="open", service="rtsp"),
        Port(portid=8554, state="open", service="rtsp-alt"),
        Port(portid=22, state="open", service="ssh"),
    ])
    tgts = rtsp.rtsp_targets([h])
    ports = {t["port"] for t in tgts}
    assert ports == {554, 8554}


def test_findings_to_vulns_produces_vuln_objects():
    h = _host_with_rtsp()
    pr = {("10.0.0.10", 554): {
        "reachable": True, "server": "Hipcam", "public": ["OPTIONS"],
        "auth": {}, "unauth_stream": True, "sdp": None, "paths": [],
        "liveness": False, "cve_hits": [], "digest_capture": "", "cert_cn": "",
        "tls": False}}
    fs = rtsp.findings([h], pr)
    v = rtsp.findings_to_vulns(fs)
    assert "10.0.0.10" in v
    assert any(vv.severity == "critical" for vv in v["10.0.0.10"])


def test_http_tunnel_probe_detects_tunnel_content_type():
    reply = (b"HTTP/1.0 200 OK\r\n"
             b"Server: DSS/6.0.3\r\n"
             b"Content-Type: application/x-rtsp-tunnelled\r\n"
             b"\r\n")
    srv = _RTSPServer([reply])
    try:
        out = rtsp._http_tunnel_probe(srv.host, srv.port, timeout=2.0)
    finally:
        srv.close()
    assert out["tunnel"] is True
    assert "DSS" in out["server"]


# --- T2 SAFE PROOF: unauth_setup_probe -------------------------------------
#
# RTSP SETUP (RFC 2326 §11) is how a client asks the server to allocate a
# media transport for one track. A 200 OK with a Session header proves the
# server accepted an anonymous media-session allocation — deterministic T2
# evidence that unauthenticated PLAY would immediately stream RTP. recce
# never issues PLAY; a TEARDOWN with the returned Session id releases the
# allocation, so nothing is recorded off the sensor.

_SETUP_200 = (
    b"RTSP/1.0 200 OK\r\n"
    b"CSeq: 20\r\n"
    b"Session: 47112815;timeout=60\r\n"
    b"Transport: RTP/AVP/TCP;unicast;interleaved=0-1;ssrc=1a2b3c4d\r\n"
    b"\r\n"
)

_SETUP_401 = (
    b"RTSP/1.0 401 Unauthorized\r\n"
    b"CSeq: 20\r\n"
    b'WWW-Authenticate: Digest realm="HikvisionDS", nonce="deadbeef",'
    b" algorithm=MD5\r\n"
    b"\r\n"
)

_SETUP_TEARDOWN_200 = (
    b"RTSP/1.0 200 OK\r\n"
    b"CSeq: 21\r\n"
    b"\r\n"
)


def _parse_sdp_fixture():
    return rtsp.parse_sdp(_SDP_BODY)


def test_unauth_setup_probe_ok_when_setup_returns_200_with_session():
    # Server accepts SETUP + then acknowledges TEARDOWN. The client should
    # only report ok=True when Session is populated, and evidence should
    # carry the reply headers verbatim.
    srv = _RTSPServer([_SETUP_200, _SETUP_TEARDOWN_200])
    try:
        sdp = _parse_sdp_fixture()
        base = f"rtsp://{srv.host}:{srv.port}/"
        out = rtsp.unauth_setup_probe(srv.host, srv.port, timeout=2.0,
                                      tls=False, sdp=sdp, base_uri=base)
    finally:
        srv.close()
    assert out["ok"] is True
    assert out["status"] == 200
    assert out["session"].startswith("47112815")
    assert "interleaved=0-1" in out["transport"]
    # The first non-aggregate control ('*') is 'track1' from the SDP fixture;
    # relative controls resolve against the DESCRIBE base URI.
    assert out["control_uri"].endswith("/track1")
    assert "Session: 47112815" in out["evidence"]


def test_unauth_setup_probe_reports_not_ok_on_401():
    srv = _RTSPServer([_SETUP_401])
    try:
        sdp = _parse_sdp_fixture()
        base = f"rtsp://{srv.host}:{srv.port}/"
        out = rtsp.unauth_setup_probe(srv.host, srv.port, timeout=2.0,
                                      tls=False, sdp=sdp, base_uri=base)
    finally:
        srv.close()
    assert out["ok"] is False
    assert out["status"] == 401
    assert out["session"] == ""


def test_unauth_setup_probe_returns_not_ok_when_port_closed():
    # Bind then immediately close — nothing accepts. Probe must return
    # cleanly (ok=False) rather than raise; bounded timeout enforced.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    sdp = _parse_sdp_fixture()
    out = rtsp.unauth_setup_probe("127.0.0.1", port, timeout=0.5, tls=False,
                                  sdp=sdp, base_uri=f"rtsp://127.0.0.1:{port}/")
    assert out["ok"] is False
    assert out["session"] == ""


def test_unauth_setup_probe_skips_when_no_track_control():
    # sdp with only aggregate '*' control should short-circuit — no network
    # traffic at all.
    sdp = {"session": "x", "tool": "", "media": [], "codecs": [],
           "controls": ["*"], "fmtp": []}
    out = rtsp.unauth_setup_probe("127.0.0.1", 1, timeout=0.1, tls=False,
                                  sdp=sdp, base_uri="rtsp://127.0.0.1:1/")
    assert out["ok"] is False
    assert out["control_uri"] == ""


def test_resolve_control_uri_absolute_and_relative():
    # Absolute wins as-is.
    absu = "rtsp://cam.example.local:554/streaming/track1"
    assert rtsp._resolve_control_uri(absu, "rtsp://10.0.0.10:554/") == absu
    # Relative appends to base, with a single '/' separator either way.
    assert rtsp._resolve_control_uri(
        "track1", "rtsp://10.0.0.10:554/Streaming/Channels/101") \
        == "rtsp://10.0.0.10:554/Streaming/Channels/101/track1"
    assert rtsp._resolve_control_uri(
        "/track1", "rtsp://10.0.0.10:554/") == "rtsp://10.0.0.10:554/track1"


def test_findings_emit_rtsp_setup_unauth_t2_when_setup_ok():
    h = _host_with_rtsp()
    pr = {("10.0.0.10", 554): {
        "reachable": True, "server": "Hipcam", "public": ["OPTIONS"],
        "auth": {}, "unauth_stream": True,
        "sdp": {"session": "cam", "tool": "LIVE555",
                "media": [{"kind": "video", "transport": "RTP/AVP", "payload": 96}],
                "codecs": [{"codec": "H264", "clock": 90000}],
                "controls": ["*", "track1"], "fmtp": []},
        "paths": [], "liveness": False, "cve_hits": [], "digest_capture": "",
        "cert_cn": "", "tls": False,
        "sdp_base_uri": "rtsp://10.0.0.10:554/",
        "setup_probe": {
            "ok": True, "status": 200,
            "session": "47112815;timeout=60",
            "transport": "RTP/AVP/TCP;unicast;interleaved=0-1",
            "control_uri": "rtsp://10.0.0.10:554/track1",
            "evidence": ("RTSP/1.0 200 OK\r\nCSeq: 20\r\n"
                         "Session: 47112815;timeout=60\r\n"
                         "Transport: RTP/AVP/TCP;unicast;interleaved=0-1"),
        }}}
    fs = rtsp.findings([h], pr)
    kinds = [f["kind"] for f in fs]
    assert "rtsp_setup_unauth" in kinds
    setup = next(f for f in fs if f["kind"] == "rtsp_setup_unauth")
    assert setup["severity"] == "critical"
    assert setup["depth_tier"] == "t2"
    # Real server-side evidence carried through into the finding detail.
    assert "Session=47112815" in setup["detail"]
    assert "interleaved=0-1" in setup["detail"]
    assert "track1" in setup["detail"]
    # T1 rtsp_unauth_stream (already t2) still emitted alongside — additions
    # only; no existing finding suppressed.
    assert "rtsp_unauth_stream" in kinds


def test_findings_skip_rtsp_setup_unauth_when_probe_not_ok():
    # setup_probe reported not-ok (server refused or timed out) → no T2
    # setup-unauth finding, but the existing t2 unauth_stream still fires.
    h = _host_with_rtsp()
    pr = {("10.0.0.10", 554): {
        "reachable": True, "server": "Hipcam", "public": ["OPTIONS"],
        "auth": {}, "unauth_stream": True,
        "sdp": {"session": "cam", "tool": "LIVE555",
                "media": [{"kind": "video", "transport": "RTP/AVP", "payload": 96}],
                "codecs": [], "controls": ["*", "track1"], "fmtp": []},
        "paths": [], "liveness": False, "cve_hits": [], "digest_capture": "",
        "cert_cn": "", "tls": False,
        "sdp_base_uri": "rtsp://10.0.0.10:554/",
        "setup_probe": {"ok": False, "status": 401, "session": "",
                         "transport": "", "control_uri": "",
                         "evidence": ""}}}
    fs = rtsp.findings([h], pr)
    kinds = [f["kind"] for f in fs]
    assert "rtsp_setup_unauth" not in kinds
    assert "rtsp_unauth_stream" in kinds


def test_probe_end_to_end_populates_setup_probe_evidence():
    # Full probe(): OPTIONS -> DESCRIBE 200+SDP -> per-path DESCRIBE 404 x N
    # -> SETUP 200 (control from SDP) -> TEARDOWN 200. Verifies the T2
    # promotion field is wired end-to-end from probe() through to findings().
    replies: list[bytes] = [_OPTIONS_200_NO_GETPARAM, _DESCRIBE_200]
    replies += [_DESCRIBE_404] * len(rtsp._WELL_KNOWN_PATHS)
    replies += [_SETUP_200, _SETUP_TEARDOWN_200]
    srv = _RTSPServer(replies)
    try:
        pr = rtsp.probe(srv.host, srv.port, timeout=2.0)
    finally:
        srv.close()
    assert pr["unauth_stream"] is True
    sp = pr["setup_probe"]
    assert sp["ok"] is True
    assert sp["session"].startswith("47112815")
    assert sp["control_uri"].endswith("/track1")


def test_probe_setup_proof_disabled_by_flag():
    # do_setup_proof=False keeps the T1 path unchanged (no SETUP traffic).
    # A single-reply queue is enough — if SETUP fired, the recv would hit
    # a closed connection but the point is: setup_probe stays empty.
    replies: list[bytes] = [_OPTIONS_200_NO_GETPARAM, _DESCRIBE_200]
    replies += [_DESCRIBE_404] * len(rtsp._WELL_KNOWN_PATHS)
    srv = _RTSPServer(replies)
    try:
        pr = rtsp.probe(srv.host, srv.port, timeout=2.0, do_setup_proof=False)
    finally:
        srv.close()
    assert pr["unauth_stream"] is True
    assert pr["setup_probe"] == {}
