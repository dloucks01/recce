"""SIP module — passive header-parsing additions.

Covers three additive capabilities layered onto the existing OPTIONS probe:
  * Full Digest challenge capture (RFC 3261 §22.4 + RFC 8760)
  * Via received= / rport= + Contact internal-IP extraction (RFC 3581, §18.2.1)
  * Vendor + product_version normalisation from Server header (CVE handoff)

Fixtures are wire-derived: byte-for-byte SIP responses recce would receive.
"""
from __future__ import annotations

import socket
import threading

from recce.core.models import Host, Port
from recce.services import sip as S


# ---- vendor normalisation --------------------------------------------------

def test_normalise_vendor_recognises_common_pbxes():
    for banner, expected_vendor, expected_ver in (
            ("Asterisk PBX 13.7.2", "asterisk", "13.7.2"),
            ("Asterisk 18.0.0", "asterisk", "18.0.0"),
            ("FPBX-15.0.16", "freepbx", "15.0.16"),
            ("Kamailio (5.4.4 (x86_64/linux))", "kamailio", "5.4.4"),
            ("OpenSIPS (3.1.2 (x86_64/linux))", "opensips", "3.1.2"),
            ("FreeSWITCH-mod_sofia/1.10.7", "freeswitch", "1.10.7"),
            ("Cisco-CUCM11.5", "cisco-cucm", "11.5"),
    ):
        v, ver = S._normalise_vendor(banner)
        assert (v, ver) == (expected_vendor, expected_ver), banner


def test_normalise_vendor_returns_empty_on_unknown_banner():
    # Must NOT invent a match — a CVE consumer keys on these tuples.
    assert S._normalise_vendor("Weird-PBX/9000") == ("", "")
    assert S._normalise_vendor("") == ("", "")


# ---- Digest challenge parsing ---------------------------------------------

_DIGEST_REPLY_MD5 = (
    b"SIP/2.0 401 Unauthorized\r\n"
    b"Via: SIP/2.0/UDP recce:5060\r\n"
    b"From: <sip:recce@recce.local>;tag=recce\r\n"
    b"To: <sip:10.0.0.10>;tag=srv\r\n"
    b"WWW-Authenticate: Digest realm=\"asterisk\","
    b" nonce=\"1234567890abcdef\", opaque=\"deadbeef\","
    b" algorithm=MD5, qop=\"auth\"\r\n"
    b"Content-Length: 0\r\n\r\n"
)

_DIGEST_REPLY_SHA256 = (
    b"SIP/2.0 401 Unauthorized\r\n"
    b"Via: SIP/2.0/UDP recce:5060\r\n"
    b"WWW-Authenticate: Digest realm=\"kamailio\","
    b" nonce=\"cafef00d\", algorithm=SHA-256, qop=\"auth\"\r\n"
    b"Content-Length: 0\r\n\r\n"
)


def test_parse_digest_challenge_extracts_all_params():
    out = S._parse_digest_challenge(_DIGEST_REPLY_MD5)
    assert out["realm"] == "asterisk"
    assert out["nonce"] == "1234567890abcdef"
    assert out["opaque"] == "deadbeef"
    assert out["algorithm"] == "MD5"
    assert out["qop"] == "auth"


def test_parse_digest_challenge_uppercases_algorithm():
    # RFC 8760 §2.3: algorithm token compared case-insensitively; normalise.
    reply = (b"SIP/2.0 407 Proxy Authentication Required\r\n"
             b"Proxy-Authenticate: Digest realm=\"x\", nonce=\"n\","
             b" algorithm=sha-256\r\n\r\n")
    out = S._parse_digest_challenge(reply)
    assert out["algorithm"] == "SHA-256"
    assert out["realm"] == "x"


def test_parse_digest_challenge_empty_when_no_auth_header():
    assert S._parse_digest_challenge(b"SIP/2.0 200 OK\r\n\r\n") == {}


# ---- Via received= / rport= + Contact internal IP -------------------------

_REPLY_INTERNAL_IP = (
    b"SIP/2.0 200 OK\r\n"
    b"Via: SIP/2.0/UDP recce:5060;branch=z9hG4bK-recce;"
    b"received=192.168.10.5;rport=5060\r\n"
    b"From: <sip:recce@recce.local>;tag=recce\r\n"
    b"To: <sip:10.0.0.10>;tag=srv\r\n"
    b"Contact: <sip:asterisk@10.9.8.7:5060>\r\n"
    b"Server: Asterisk PBX 18.0.0\r\n"
    b"Content-Length: 0\r\n\r\n"
)


def _serve_once(reply: bytes):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def _serve():
        try:
            _, addr = sock.recvfrom(2048)
            sock.sendto(reply, addr)
        except OSError:
            pass

    threading.Thread(target=_serve, daemon=True).start()
    return port, sock


def test_probe_captures_via_received_rport_and_contact_internal_ip():
    port, sock = _serve_once(_REPLY_INTERNAL_IP)
    try:
        pr = S.probe("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert pr["reachable"]
    assert pr["via_received"] == "192.168.10.5"
    assert pr["via_rport"] == 5060
    assert pr["contact_host"] == "10.9.8.7"
    assert pr["contact_internal_ip"] == "10.9.8.7"
    # Vendor normalisation ran on the same reply.
    assert pr["vendor"] == "asterisk"
    assert pr["product_version"] == "18.0.0"


def test_probe_captures_full_digest_challenge():
    port, sock = _serve_once(_DIGEST_REPLY_MD5)
    try:
        pr = S.probe("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert pr["reachable"]
    d = pr["digest"]
    assert d["algorithm"] == "MD5"
    assert d["nonce"] == "1234567890abcdef"
    assert d["opaque"] == "deadbeef"
    assert d["qop"] == "auth"


# ---- findings: internal-IP disclosure -------------------------------------

def test_internal_ip_finding_fires_when_leaked_ip_is_private_and_differs():
    h = Host(ip="203.0.113.10",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("203.0.113.10", 5060): {
        "reachable": True, "transport": "udp", "status": 200,
        "server": "Asterisk PBX 18.0.0",
        "vendor": "asterisk", "product_version": "18.0.0",
        "via_received": "10.1.2.3",
        "contact_internal_ip": "192.168.7.5",
    }}
    fs = S.findings([h], pr)
    f = next(f for f in fs if f["kind"] == "sip_internal_ip_disclosure")
    assert f["severity"] == "medium"
    assert "10.1.2.3" in f["detail"]
    assert "192.168.7.5" in f["detail"]
    assert "CWE-200" in f["cwes"]


def test_internal_ip_finding_does_not_fire_when_reached_ip_matches_leak():
    # No disclosure when the "leak" is just the same address recce called.
    h = Host(ip="10.1.2.3",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("10.1.2.3", 5060): {
        "reachable": True, "transport": "udp", "status": 200,
        "server": "Asterisk PBX 18.0.0",
        "via_received": "10.1.2.3",
        "contact_internal_ip": "10.1.2.3",
    }}
    fs = S.findings([h], pr)
    assert not any(f["kind"] == "sip_internal_ip_disclosure" for f in fs)


def test_internal_ip_finding_ignores_public_via_received():
    h = Host(ip="203.0.113.10",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("203.0.113.10", 5060): {
        "reachable": True, "transport": "udp", "status": 200,
        "server": "Asterisk PBX 18.0.0",
        "via_received": "8.8.8.8",  # routable public IP — not a topology leak
    }}
    fs = S.findings([h], pr)
    assert not any(f["kind"] == "sip_internal_ip_disclosure" for f in fs)


# ---- findings: MD5-only Digest weak-crypto --------------------------------

def test_md5_only_digest_finding_fires_on_md5():
    h = Host(ip="10.0.0.10",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("10.0.0.10", 5060): {
        "reachable": True, "transport": "udp", "status": 401,
        "server": "Asterisk PBX 18.0.0",
        "digest": {"realm": "asterisk", "nonce": "abc",
                   "algorithm": "MD5", "qop": "auth"},
    }}
    fs = S.findings([h], pr)
    f = next(f for f in fs if f["kind"] == "sip_digest_md5_only")
    assert f["severity"] == "low"
    assert "MD5" in f["detail"]
    assert "CWE-327" in f["cwes"]


def test_md5_only_finding_defaults_algorithm_absent_to_md5():
    # RFC 2617 default: algorithm=MD5 when not stated. Recce must still flag it.
    h = Host(ip="10.0.0.10",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("10.0.0.10", 5060): {
        "reachable": True, "transport": "udp", "status": 401,
        "server": "Kamailio 5.4.4",
        "digest": {"realm": "sip", "nonce": "xyz", "qop": "auth"},  # no algorithm=
    }}
    fs = S.findings([h], pr)
    assert any(f["kind"] == "sip_digest_md5_only" for f in fs)


def test_md5_only_finding_suppressed_on_sha256():
    h = Host(ip="10.0.0.10",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("10.0.0.10", 5060): {
        "reachable": True, "transport": "udp", "status": 401,
        "server": "Kamailio 5.4.4",
        "digest": {"realm": "kamailio", "nonce": "n", "algorithm": "SHA-256",
                   "qop": "auth"},
    }}
    fs = S.findings([h], pr)
    assert not any(f["kind"] == "sip_digest_md5_only" for f in fs)


def test_md5_only_finding_suppressed_when_no_nonce_present():
    # No challenge captured -> no finding (guards against false positives from
    # a probe that didn't get a 401 at all).
    h = Host(ip="10.0.0.10",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("10.0.0.10", 5060): {
        "reachable": True, "transport": "udp", "status": 200,
        "server": "Asterisk PBX 18.0.0",
    }}
    fs = S.findings([h], pr)
    assert not any(f["kind"] == "sip_digest_md5_only" for f in fs)


# ---- T2 SAFE evidence: realm-bound Digest challenge capture ---------------
# Promotes sip_fingerprint (a.k.a. sip_realm_disclosure) from T0 -> T2 with a
# single controlled REGISTER for a fixed canary username. The reply is a real
# 401/407 whose WWW-Authenticate binds the disclosed realm to a server-
# generated nonce (RFC 3261 §22.4).

_T2_CHALLENGE_REPLY = (
    b"SIP/2.0 401 Unauthorized\r\n"
    b"Via: SIP/2.0/UDP recce:5060;branch=z9hG4bK-recce-r-recce-canary\r\n"
    b"From: <sip:recce-canary@10.0.0.10>;tag=recce-r-recce-canary\r\n"
    b"To: <sip:recce-canary@10.0.0.10>;tag=srv\r\n"
    b"Call-ID: recce-r-recce-canary@recce\r\n"
    b"CSeq: 1 REGISTER\r\n"
    b"WWW-Authenticate: Digest realm=\"asterisk\","
    b" nonce=\"fe1c9d7a1b2c3d4e5f6a7b8c9d0e1f20\","
    b" opaque=\"cafe\", algorithm=MD5, qop=\"auth\"\r\n"
    b"Content-Length: 0\r\n\r\n"
)

_T2_PROXY_CHALLENGE_REPLY = (
    b"SIP/2.0 407 Proxy Authentication Required\r\n"
    b"Via: SIP/2.0/UDP recce:5060\r\n"
    b"Proxy-Authenticate: Digest realm=\"kamailio\", nonce=\"bb00cc11\","
    b" algorithm=SHA-256, qop=\"auth\"\r\n"
    b"Content-Length: 0\r\n\r\n"
)

_T2_OK_REPLY = (
    b"SIP/2.0 200 OK\r\n"
    b"Via: SIP/2.0/UDP recce:5060\r\n"
    b"Content-Length: 0\r\n\r\n"
)


def test_capture_realm_challenge_evidence_extracts_realm_and_nonce():
    port, sock = _serve_once(_T2_CHALLENGE_REPLY)
    try:
        ev = S.capture_realm_challenge_evidence("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert ev is not None
    assert ev["status"] == 401
    assert ev["realm"] == "asterisk"
    assert ev["nonce"] == "fe1c9d7a1b2c3d4e5f6a7b8c9d0e1f20"
    assert ev["algorithm"] == "MD5"
    assert ev["qop"] == "auth"
    assert ev["canary_user"] == "recce-canary"


def test_capture_realm_challenge_evidence_accepts_proxy_authenticate():
    # A 407 with Proxy-Authenticate is an equally valid Digest challenge for
    # T2 evidence — outbound-proxy SIP endpoints challenge that way.
    port, sock = _serve_once(_T2_PROXY_CHALLENGE_REPLY)
    try:
        ev = S.capture_realm_challenge_evidence("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert ev is not None
    assert ev["status"] == 407
    assert ev["realm"] == "kamailio"
    assert ev["nonce"] == "bb00cc11"
    assert ev["algorithm"] == "SHA-256"


def test_capture_realm_challenge_evidence_returns_none_on_200():
    # A 200 OK on the canary REGISTER means no auth challenge — no T2 evidence
    # to attach. (An unauthenticated-REGISTER 200 is instead the ext_enum
    # seen_ok=True primitive, already handled at T2 by sip_ext_enum.)
    port, sock = _serve_once(_T2_OK_REPLY)
    try:
        ev = S.capture_realm_challenge_evidence("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert ev is None


def test_capture_realm_challenge_evidence_returns_none_on_timeout():
    # Bind a UDP port with no responder -> recvfrom must time out and the
    # function must return None cleanly, never raise.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    try:
        ev = S.capture_realm_challenge_evidence("127.0.0.1", port, timeout=0.3)
    finally:
        sock.close()
    assert ev is None


def test_capture_realm_challenge_evidence_returns_none_when_no_nonce():
    # A challenge missing the nonce (or realm) is not usable evidence — must
    # NOT emit half-parsed output that a downstream hashcat feed would choke on.
    reply = (b"SIP/2.0 401 Unauthorized\r\n"
             b"WWW-Authenticate: Digest realm=\"x\", algorithm=MD5\r\n\r\n")
    port, sock = _serve_once(reply)
    try:
        ev = S.capture_realm_challenge_evidence("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert ev is None


def test_t2_bounded_timeout_clamps_to_range():
    # Bounded 2.0-6.0s so a caller passing a tiny 0.1s or a large 30s still
    # yields a sane per-request budget. proxy.scaled is identity when direct.
    assert S._t2_bounded_timeout(0.1) == 2.0
    assert S._t2_bounded_timeout(30.0) == 6.0
    assert S._t2_bounded_timeout(3.0) == 3.0


def test_fingerprint_finding_stays_t0_without_evidence():
    # Backward-compat: no realm_challenge_evidence in the probe dict ->
    # depth_tier stays t0, detail text unchanged from the T1 path.
    h = Host(ip="203.0.113.10",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("203.0.113.10", 5060): {
        "reachable": True, "transport": "udp", "status": 200,
        "server": "Asterisk PBX 18.0.0", "realm": "asterisk",
    }}
    fs = S.findings([h], pr)
    f = next(f for f in fs if f["kind"] == "sip_fingerprint")
    assert f["depth_tier"] == "t0"
    assert "T2 proof" not in f["detail"]


def test_fingerprint_finding_promoted_to_t2_when_evidence_captured():
    # With realm_challenge_evidence present, the finding upgrades to T2 and
    # emits the captured realm + nonce + canary user in the detail block.
    h = Host(ip="203.0.113.10",
             ports=[Port(portid=5060, protocol="udp", state="open", service="sip")])
    pr = {("203.0.113.10", 5060): {
        "reachable": True, "transport": "udp", "status": 200,
        "server": "Asterisk PBX 18.0.0", "realm": "asterisk",
        "realm_challenge_evidence": {
            "realm": "asterisk",
            "nonce": "fe1c9d7a1b2c3d4e5f6a7b8c9d0e1f20",
            "status": 401, "algorithm": "MD5", "qop": "auth",
            "canary_user": "recce-canary",
        },
    }}
    fs = S.findings([h], pr)
    f = next(f for f in fs if f["kind"] == "sip_fingerprint")
    assert f["depth_tier"] == "t2"
    assert "T2 proof" in f["detail"]
    assert "asterisk" in f["detail"]
    assert "fe1c9d7a1b2c3d4e5f6a7b8c9d0e1f20" in f["detail"]
    assert "recce-canary" in f["detail"]
    assert "MD5" in f["detail"]


def test_probe_captures_realm_challenge_evidence_end_to_end(monkeypatch):
    # End-to-end: probe() sends OPTIONS, then a follow-on canary REGISTER,
    # capturing the challenge into realm_challenge_evidence. The ephemeral
    # server answers both datagrams from the same socket. ext_enum is
    # neutralised so the test isolates the T2 capture from svwar-style probes.
    monkeypatch.setattr(S, "enumerate_extensions",
                        lambda ip, port, extensions=None, timeout=3.0: {})
    options_reply = (
        b"SIP/2.0 200 OK\r\n"
        b"Via: SIP/2.0/UDP recce:5060;branch=z9hG4bK-recce\r\n"
        b"From: <sip:recce@recce.local>;tag=recce\r\n"
        b"To: <sip:127.0.0.1>;tag=srv\r\n"
        b"Server: Asterisk PBX 18.0.0\r\n"
        b"WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"opt-n\","
        b" algorithm=MD5\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def _serve():
        try:
            # First datagram = OPTIONS -> reply with realm.
            _, addr = sock.recvfrom(4096)
            sock.sendto(options_reply, addr)
            # Second datagram = canary REGISTER -> reply with fresh challenge.
            _, addr = sock.recvfrom(4096)
            sock.sendto(_T2_CHALLENGE_REPLY, addr)
        except OSError:
            pass

    threading.Thread(target=_serve, daemon=True).start()
    try:
        pr = S.probe("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert pr["reachable"]
    assert pr.get("realm") == "asterisk"
    ev = pr.get("realm_challenge_evidence")
    assert ev is not None
    assert ev["realm"] == "asterisk"
    assert ev["nonce"] == "fe1c9d7a1b2c3d4e5f6a7b8c9d0e1f20"
    assert ev["canary_user"] == "recce-canary"


def test_probe_skips_realm_challenge_capture_when_no_realm(monkeypatch):
    # When OPTIONS returned no realm= (many PBXes on a plain OPTIONS), the T2
    # capture is skipped entirely — nothing to prove enforced, no wasted
    # packet. Verified by counting REGISTER calls, which must be zero.
    monkeypatch.setattr(S, "enumerate_extensions",
                        lambda ip, port, extensions=None, timeout=3.0: {})
    calls = {"n": 0}

    def _fail_capture(*a, **kw):
        calls["n"] += 1
        return None

    monkeypatch.setattr(S, "capture_realm_challenge_evidence", _fail_capture)
    options_reply = (
        b"SIP/2.0 200 OK\r\n"
        b"Via: SIP/2.0/UDP recce:5060\r\n"
        b"Server: Kamailio 5.4.4\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    port, sock = _serve_once(options_reply)
    try:
        pr = S.probe("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert pr["reachable"]
    assert "realm" not in pr
    assert calls["n"] == 0
    assert "realm_challenge_evidence" not in pr
