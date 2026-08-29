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
