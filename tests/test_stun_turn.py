"""STUN / TURN wire tests.

Every fixture here is built from the RFC wire formats using raw hex / struct —
never from the module's own encoders. A wire built with the codec under test
proves only that the codec is self-consistent; a wrong field offset or a swapped
attribute type would be symmetric and invisible.

RFC 8489 for STUN (§6 Binding, §14.2 XOR-MAPPED-ADDRESS, §14.10 SOFTWARE),
RFC 5769 for canonical STUN vectors, RFC 8656 for TURN (§7 Allocate, §7.2
Allocate error 401 with REALM+NONCE, §9 forbidden peer addresses), RFC 3489
for legacy MAPPED-ADDRESS, RFC 5780 for OTHER-ADDRESS.
"""
from __future__ import annotations

import socket
import struct
import threading
import time

from recce.core.models import Host, Port
from recce.services import stun_turn as st


_MAGIC = bytes.fromhex("2112a442")


# --- raw wire builders --------------------------------------------------------

def _stun_hdr(msg_type: int, txid: bytes, body: bytes) -> bytes:
    return struct.pack("!HH", msg_type, len(body)) + _MAGIC + txid + body


def _tlv(atype: int, val: bytes) -> bytes:
    r = len(val) % 4
    pad = b"\x00" * ((4 - r) % 4)
    return struct.pack("!HH", atype, len(val)) + val + pad


def _xor_mapped_ipv4(ip: str, port: int) -> bytes:
    xp = struct.pack("!H", port ^ 0x2112)
    parts = [int(x) for x in ip.split(".")]
    xa = bytes(b ^ m for b, m in zip(bytes(parts), _MAGIC))
    return b"\x00\x01" + xp + xa


def _plain_ipv4(ip: str, port: int) -> bytes:
    parts = [int(x) for x in ip.split(".")]
    return b"\x00\x01" + struct.pack("!H", port) + bytes(parts)


def _error_code(code: int, reason: str) -> bytes:
    klass, number = divmod(code, 100)
    return b"\x00\x00" + bytes([klass & 0x07, number]) + reason.encode("utf-8")


# --- module-level wire decoding ----------------------------------------------

def test_is_stun_matches_ports_and_service_names():
    assert st.is_stun(Port(portid=3478, protocol="udp", state="open", service="stun"))
    assert st.is_stun(Port(portid=5349, state="open", service="turns"))
    assert st.is_stun(Port(portid=5350, protocol="udp", state="open", service=""))
    assert st.is_stun(Port(portid=12345, state="open", service="turn"))
    assert st.is_stun(Port(portid=99, state="open", service="", product="coturn 4.5"))
    assert not st.is_stun(Port(portid=80, state="open", service="http"))


def test_binding_request_matches_rfc8489_header_layout():
    """20-byte header: type(0x0001), length(0), magic cookie, 12-byte txid."""
    req = st._binding_request(bytes(range(12)))
    assert len(req) == 20
    assert req[:4] == bytes.fromhex("00010000")
    assert req[4:8] == _MAGIC
    assert req[8:20] == bytes(range(12))


def test_allocate_request_carries_requested_transport_udp():
    """RFC 8656 §7.1 Allocate MUST carry REQUESTED-TRANSPORT."""
    req = st._allocate_request(bytes(range(12)))
    # type = 0x0003, length = 8 (one 4-byte attr header + 4-byte value).
    assert req[:2] == b"\x00\x03"
    assert struct.unpack("!H", req[2:4])[0] == 8
    # REQUESTED-TRANSPORT: type 0x0019, length 4, value = 17 (UDP) padded.
    assert req[20:24] == bytes.fromhex("00190004")
    assert req[24:28] == b"\x11\x00\x00\x00"


def test_parse_response_decodes_xor_mapped_address():
    """RFC 5769 §2.2: the XOR obscures the address only from cookie-unaware NATs."""
    txid = bytes(range(12))
    body = _tlv(st._A_XOR_MAPPED_ADDRESS, _xor_mapped_ipv4("192.0.2.1", 32853))
    pkt = _stun_hdr(st._MT_BINDING_SUCCESS, txid, body)
    parsed = st._parse_response(pkt)
    assert parsed["msg_type"] == st._MT_BINDING_SUCCESS
    assert parsed["attrs"]["xor_mapped_address"] == "192.0.2.1:32853"


def test_parse_response_decodes_software_and_other_address():
    txid = bytes(range(12))
    body = (_tlv(st._A_SOFTWARE, b"coturn-4.5.2 'dan Eider'")
            + _tlv(st._A_OTHER_ADDRESS, _plain_ipv4("198.51.100.7", 3479)))
    pkt = _stun_hdr(st._MT_BINDING_SUCCESS, txid, body)
    parsed = st._parse_response(pkt)
    assert parsed["attrs"]["software"].startswith("coturn-4.5.2")
    assert parsed["attrs"]["other_address"] == "198.51.100.7:3479"


def test_parse_response_decodes_turn_error_realm_nonce():
    """RFC 8656 §7.2: unauthenticated Allocate MUST be answered 401 with
    REALM + NONCE. Both are the credentialless identity leak."""
    txid = bytes(range(12))
    body = (_tlv(st._A_ERROR_CODE, _error_code(401, "Unauthorized"))
            + _tlv(st._A_REALM, b"corp.example.com")
            + _tlv(st._A_NONCE, b"abcdef0123456789"))
    pkt = _stun_hdr(st._MT_ALLOCATE_ERROR, txid, body)
    parsed = st._parse_response(pkt)
    assert parsed["msg_type"] == st._MT_ALLOCATE_ERROR
    assert parsed["attrs"]["error_code"] == 401
    assert parsed["attrs"]["realm"] == "corp.example.com"
    assert parsed["attrs"]["nonce"] == "abcdef0123456789"


def test_parse_response_rejects_no_magic_cookie():
    """A packet without the 0x2112A442 magic MUST NOT decode as a
    modern STUN response — that is exactly what makes ClassicSTUN detectable
    as a separate finding."""
    pkt = struct.pack("!HH", st._MT_BINDING_SUCCESS, 0) + b"\xff\xff\xff\xff" + bytes(12)
    assert st._parse_response(pkt) is None


def test_parse_legacy_response_decodes_plain_mapped_address():
    """RFC 3489 responses carry MAPPED-ADDRESS in the clear (no XOR)."""
    body = _tlv(st._A_MAPPED_ADDRESS, _plain_ipv4("203.0.113.9", 4444))
    # no magic cookie in the legacy layout — the first 4 tx bytes are random
    pkt = struct.pack("!HH", st._MT_BINDING_SUCCESS, len(body)) + bytes(16) + body
    parsed = st._parse_legacy_response(pkt)
    assert parsed == {"mapped_address": "203.0.113.9:4444"}


def test_decode_ipv6_xor_address_round_trips():
    """XOR-MAPPED-ADDRESS for IPv6 XORs with (cookie || txid), per §14.2."""
    ip = "2001:db8::1"
    port = 40404
    txid = bytes(range(12))
    raw6 = socket.inet_pton(socket.AF_INET6, ip)
    xaddr = bytes(a ^ b for a, b in zip(raw6, _MAGIC + txid))
    val = b"\x00\x02" + struct.pack("!H", port ^ 0x2112) + xaddr
    out = st._decode_xor_address(val, txid)
    assert out == (ip, port)


def test_parse_software_extracts_product_and_version():
    """coturn / eturnal / pion all self-identify with a vendor+version string."""
    assert st._parse_software("Coturn-4.5.2 'dan Eider'") == ("Coturn", "4.5.2")
    assert st._parse_software("eturnal 1.10.1") == ("eturnal", "1.10.1")
    assert st._parse_software("pion/webrtc-rs v0.9") == ("pion", "")
    assert st._parse_software("random-tool") is None


def test_xor_ipv4_value_matches_hand_computed_xor():
    txid = bytes(range(12))
    val = st._xor_ipv4_value("169.254.169.254", txid)
    assert val[:2] == b"\x00\x01"          # reserved + fam=IPv4
    assert val[2:4] == b"\x00\x00"         # xport=0 (port=0 XOR 0x2112 -> we set 0)
    # xaddress = 169.254.169.254 XOR cookie
    parts = bytes([169, 254, 169, 254])
    assert val[4:8] == bytes(a ^ b for a, b in zip(parts, _MAGIC))


# --- fake UDP server + live probe --------------------------------------------

class _FakeStunTurn(threading.Thread):
    """UDP responder that answers STUN Binding, TURN Allocate, and
    CreatePermission differently — like a real coturn."""
    daemon = True

    def __init__(self, *, software=b"coturn-4.5.2 test", realm=b"corp.example",
                 nonce=b"abcdefabcdef0123", other_address=None,
                 open_relay=False, accept_internal=False,
                 answer_binding=True, answer_allocate=True):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(4)
        self.port = self.sock.getsockname()[1]
        self.software = software
        self.realm = realm
        self.nonce = nonce
        self.other_address = other_address
        self.open_relay = open_relay
        self.accept_internal = accept_internal
        self.answer_binding = answer_binding
        self.answer_allocate = answer_allocate
        self.stop_flag = threading.Event()

    def run(self):
        end = time.time() + 4
        while time.time() < end and not self.stop_flag.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            if not data:
                return
            if len(data) < 20:
                continue
            msg_type = struct.unpack("!H", data[:2])[0]
            # Legacy RFC 3489 has no magic cookie.
            if data[4:8] != _MAGIC:
                # answer with MAPPED-ADDRESS
                body = _tlv(st._A_MAPPED_ADDRESS,
                            _plain_ipv4("198.51.100.42", 9999))
                pkt = struct.pack("!HH", st._MT_BINDING_SUCCESS,
                                  len(body)) + data[4:20] + body
                self.sock.sendto(pkt, addr)
                continue
            txid = data[8:20]
            if msg_type == st._MT_BINDING_REQUEST and self.answer_binding:
                body = _tlv(st._A_XOR_MAPPED_ADDRESS,
                            _xor_mapped_ipv4("203.0.113.9", 55055))
                body += _tlv(st._A_SOFTWARE, self.software)
                if self.other_address:
                    body += _tlv(st._A_OTHER_ADDRESS,
                                 _plain_ipv4(*self.other_address))
                self.sock.sendto(_stun_hdr(st._MT_BINDING_SUCCESS, txid, body),
                                 addr)
            elif msg_type == st._MT_ALLOCATE_REQUEST and self.answer_allocate:
                if self.open_relay:
                    body = _tlv(st._A_XOR_RELAYED_ADDRESS,
                                _xor_mapped_ipv4("198.51.100.77", 49200))
                    body += _tlv(st._A_SOFTWARE, self.software)
                    self.sock.sendto(_stun_hdr(st._MT_ALLOCATE_SUCCESS, txid,
                                               body), addr)
                else:
                    body = (_tlv(st._A_ERROR_CODE,
                                 _error_code(401, "Unauthorized"))
                            + _tlv(st._A_REALM, self.realm)
                            + _tlv(st._A_NONCE, self.nonce)
                            + _tlv(st._A_SOFTWARE, self.software))
                    self.sock.sendto(_stun_hdr(st._MT_ALLOCATE_ERROR, txid,
                                               body), addr)
            elif msg_type == st._MT_CREATE_PERM_REQUEST:
                if self.accept_internal:
                    self.sock.sendto(_stun_hdr(st._MT_CREATE_PERM_SUCCESS,
                                               txid, b""), addr)
                else:
                    body = _tlv(st._A_ERROR_CODE, _error_code(403, "Forbidden"))
                    self.sock.sendto(_stun_hdr(0x0118, txid, body), addr)

    def stop(self):
        self.stop_flag.set()
        try:
            self.sock.close()
        except OSError:
            pass


def _probe(**kw):
    srv = _FakeStunTurn(**kw)
    srv.start()
    time.sleep(0.15)
    try:
        return st.probe("127.0.0.1", srv.port, timeout=1.5)
    finally:
        srv.stop()


def test_probe_decodes_stun_binding_over_udp():
    pr = _probe()
    assert pr["reachable"] is True
    assert pr["external_mapping"] == "203.0.113.9:55055"
    assert pr["software"].startswith("coturn")
    assert pr["product"] == "coturn"
    assert pr["version"] == "4.5.2"
    # Amplification metric present.
    assert pr["request_bytes"] == 20
    assert pr["response_bytes"] > pr["request_bytes"]
    assert pr["amplification"] > 1


def test_probe_captures_turn_401_realm_and_nonce():
    pr = _probe(realm=b"CORP.EXAMPLE.LOCAL",
                nonce=b"deadbeefdeadbeef")
    assert pr["speaks_turn"] is True
    assert pr["turn_realm"] == "CORP.EXAMPLE.LOCAL"
    assert pr["turn_nonce"] == "deadbeefdeadbeef"
    assert pr["turn_error_code"] == 401


def test_probe_flags_open_relay_and_tries_internal_peers():
    pr = _probe(open_relay=True, accept_internal=True)
    assert pr["turn_open_relay"] is True
    # 169.254.169.254 (IMDS) is the canonical SSRF pivot.
    assert "169.254.169.254" in (pr.get("turn_internal_relay") or [])


def test_probe_open_relay_without_internal_permission_does_not_flag_ssrf():
    pr = _probe(open_relay=True, accept_internal=False)
    assert pr["turn_open_relay"] is True
    assert not pr.get("turn_internal_relay")


def test_probe_detects_classic_rfc3489_stun():
    pr = _probe()
    # Fake server also answers the no-magic-cookie request with a MAPPED-ADDRESS
    assert pr.get("classic_stun") is True
    assert pr["classic_mapped_address"] == "198.51.100.42:9999"


def test_probe_captures_other_address_second_listener():
    pr = _probe(other_address=("198.51.100.55", 3478))
    assert pr["other_address"] == "198.51.100.55:3478"


def test_probe_measures_amplification_ratio():
    pr = _probe()
    # A 20-byte binding request draws >20 bytes back → amplification >1.
    # The TURN 401 response is larger still because it also carries REALM +
    # NONCE + SOFTWARE.
    assert pr["turn_amplification"] > pr["amplification"]


def test_unreachable_host_produces_no_findings():
    # send to a closed port — nothing to answer
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    pr = st.probe("127.0.0.1", port, timeout=0.5)
    assert pr["reachable"] is False
    assert st.findings(_hosts(port), {("127.0.0.1", port): pr}) == []


# --- findings ----------------------------------------------------------------

def _hosts(port=3478):
    return [Host(ip="10.0.0.5",
                 ports=[Port(portid=port, protocol="udp", state="open",
                             service="stun")])]


def _f(pr, port=3478):
    return st.findings(_hosts(port), {("10.0.0.5", port): pr})


def test_realm_disclosure_finding_names_the_leaked_namespace():
    fs = _f({"reachable": True, "speaks_turn": True,
             "turn_realm": "corp.example", "turn_nonce": "abc"})
    f = next(x for x in fs if x["kind"] == "turn_realm_disclosure")
    assert f["severity"] == "medium"
    assert "corp.example" in f["detail"]


def test_open_relay_finding_is_critical():
    fs = _f({"reachable": True, "speaks_turn": True, "turn_open_relay": True,
             "turn_relayed_address": "198.51.100.77:49200"})
    f = next(x for x in fs if x["kind"] == "turn_open_relay")
    assert f["severity"] == "critical"
    assert "198.51.100.77:49200" in f["detail"]


def test_internal_relay_finding_names_forbidden_peers():
    fs = _f({"reachable": True, "speaks_turn": True, "turn_open_relay": True,
             "turn_internal_relay": ["169.254.169.254", "127.0.0.1"]})
    f = next(x for x in fs if x["kind"] == "turn_internal_relay")
    assert f["severity"] == "critical"
    assert "169.254.169.254" in f["detail"]
    assert "CWE-918" in f["cwes"]


def test_cleartext_creds_finding_requires_3478_turn_and_no_5349():
    """3478 speaks TURN but no 5349 companion on the same host: creds go
    over cleartext. If 5349 is also listed, the finding must NOT fire."""
    pr_3478 = {"reachable": True, "speaks_turn": True, "turn_realm": "corp"}
    pr_5349 = {"reachable": True, "speaks_turn": True, "turn_realm": "corp"}
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=3478, protocol="udp", state="open", service="stun"),
                    Port(portid=5349, state="open", service="turns")])
    only_3478 = st.findings(_hosts(3478),
                            {("10.0.0.5", 3478): pr_3478})
    with_5349 = st.findings([h],
                            {("10.0.0.5", 3478): pr_3478,
                             ("10.0.0.5", 5349): pr_5349})
    assert any(f["kind"] == "turn_cleartext_creds" for f in only_3478)
    assert not any(f["kind"] == "turn_cleartext_creds" for f in with_5349)


def test_software_fingerprint_finding_shows_product_version():
    fs = _f({"reachable": True, "software": "coturn-4.5.2 test",
             "product": "coturn", "version": "4.5.2"})
    f = next(x for x in fs if x["kind"] == "stun_version_disclosure")
    assert "coturn 4.5.2" in f["title"]
    assert f["severity"] == "low"


def test_classic_stun_finding_is_medium_severity():
    fs = _f({"reachable": True, "classic_stun": True,
             "classic_mapped_address": "203.0.113.9:4444"})
    f = next(x for x in fs if x["kind"] == "stun_legacy_rfc3489")
    assert f["severity"] == "medium"
    assert "203.0.113.9:4444" in f["detail"]


def test_other_address_finding_names_second_listener():
    fs = _f({"reachable": True, "other_address": "198.51.100.55:3478"})
    f = next(x for x in fs if x["kind"] == "stun_second_address_disclosure")
    assert f["severity"] == "low"
    assert "198.51.100.55:3478" in f["detail"]


def test_amplification_finding_fires_only_above_4x():
    fs = _f({"reachable": True, "amplification": 2.0, "request_bytes": 20,
             "response_bytes": 40})
    assert not any(f["kind"] == "stun_amplification" for f in fs)
    fs = _f({"reachable": True, "turn_amplification": 6.0,
             "turn_request_bytes": 28, "turn_response_bytes": 168})
    f = next(x for x in fs if x["kind"] == "stun_amplification")
    assert f["severity"] == "medium"


def test_external_mapping_is_informational_not_alarm():
    fs = _f({"reachable": True, "external_mapping": "203.0.113.9:55055"})
    f = next(x for x in fs if x["kind"] == "stun_external_mapping")
    assert f["severity"] == "info"


def test_turns_tls_weak_finding_fires_on_old_version():
    fs = _f({"reachable": True,
             "tls_meta": {"tls_version": "TLSv1", "cipher": "AES128-SHA",
                          "self_signed": False,
                          "cert_subject": "turn.example",
                          "cert_issuer": "letsencrypt"}}, port=5349)
    f = next(x for x in fs if x["kind"] == "turns_tls_weak")
    assert f["severity"] == "medium"
    assert "TLSv1" in f["detail"]


def test_turns_tls_weak_finding_fires_on_self_signed_cert():
    fs = _f({"reachable": True,
             "tls_meta": {"tls_version": "TLSv1.2", "cipher": "AES256-GCM-SHA384",
                          "self_signed": True,
                          "cert_subject": "turn.corp",
                          "cert_issuer": "turn.corp"}}, port=5349)
    f = next(x for x in fs if x["kind"] == "turns_tls_weak")
    assert "self-signed" in f["detail"]


def test_unreachable_probe_yields_no_findings():
    assert _f({"reachable": False}) == []


# --- plumbing / analyze ------------------------------------------------------

def test_findings_map_to_vulns_on_default_port():
    fs = _f({"reachable": True, "turn_open_relay": True,
             "turn_relayed_address": "198.51.100.77:49200"})
    v = st.findings_to_vulns(fs)
    assert v["10.0.0.5"]
    critical = [x for x in v["10.0.0.5"] if x.severity == "critical"]
    assert critical and critical[0].source == "stun"
    assert critical[0].port == 3478


def test_analyze_returns_standard_service_shape():
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=3478, protocol="udp", state="open", service="stun")])
    res = st.analyze([h], active=False)
    assert set(res) >= {"targets", "findings", "runbooks", "probes", "stats"}
    assert res["stats"]["targets"] == 1
    assert res["runbooks"] and res["runbooks"][0]["credfree"]


def test_runbook_names_the_offensive_paths():
    cmds = " ".join(s["command"] for s in st.runbook("10.0.0.5"))
    assert "stun-info" in cmds
    assert "2112a442" in cmds                 # raw STUN binding one-liner
    assert "s_client" in cmds                 # TURNS cert
    assert "31300" in cmds                    # hashcat handoff mode


def test_stun_targets_infers_tls_from_port():
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=3478, protocol="udp", state="open", service="stun"),
                    Port(portid=5349, state="open", service="turns")])
    targets = st.stun_targets([h])
    assert {t["port"]: t["tls"] for t in targets} == {3478: False, 5349: True}


# --- TLS path monkeypatched (real cert would be a build-env dependency) -----

def test_probe_tls_folds_binding_response_and_tls_meta(monkeypatch):
    """When tls=True, probe drives _tls_exchange and folds the returned
    tls_meta plus any decoded XOR-MAPPED-ADDRESS."""
    txid_holder = {}

    def _fake_tls_exchange(ip, port, payload, timeout):
        # Echo back a well-formed Binding Response for the payload's txid.
        assert payload[:2] == b"\x00\x01"
        txid = payload[8:20]
        txid_holder["v"] = txid
        body = _tlv(st._A_XOR_MAPPED_ADDRESS,
                    _xor_mapped_ipv4("192.0.2.9", 44444))
        pkt = _stun_hdr(st._MT_BINDING_SUCCESS, txid, body)
        return pkt, {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                     "cert_subject": "turn.example", "cert_issuer": "R3",
                     "self_signed": False}

    monkeypatch.setattr(st, "_tls_exchange", _fake_tls_exchange)
    pr = st.probe("127.0.0.1", 5349, tls=True)
    assert pr["reachable"] is True
    assert pr["transport"] == "tls"
    assert pr["external_mapping"] == "192.0.2.9:44444"
    assert pr["tls_meta"]["tls_version"] == "TLSv1.3"


def test_tcp_transport_detected_via_rfc4571_framing():
    """A TCP STUN listener frames the packet with a 2-byte length prefix."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    tcp_port = listener.getsockname()[1]

    stop = threading.Event()

    def _serve():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        conn.settimeout(2)
        try:
            data = conn.recv(4096)
            if len(data) < 2:
                return
            frame_len = struct.unpack("!H", data[:2])[0]
            frame = data[2:2 + frame_len]
            txid = frame[8:20]
            body = _tlv(st._A_XOR_MAPPED_ADDRESS,
                        _xor_mapped_ipv4("192.0.2.4", 12345))
            resp = _stun_hdr(st._MT_BINDING_SUCCESS, txid, body)
            conn.sendall(struct.pack("!H", len(resp)) + resp)
        finally:
            conn.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        reply = st._tcp_exchange("127.0.0.1", tcp_port,
                                 st._binding_request(), timeout=2.0,
                                 framed=True)
        parsed = st._parse_response(reply) if reply else None
        assert parsed is not None
        assert parsed["msg_type"] == st._MT_BINDING_SUCCESS
        assert parsed["attrs"]["xor_mapped_address"] == "192.0.2.4:12345"
    finally:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass
