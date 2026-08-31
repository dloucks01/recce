"""Tests for recce.services.opcua — OPC UA (uacp) probe.

Fixtures are wire-derived: either literal hex byte strings taken from the
IEC 62541 spec (Part 6 message framing) or assembled here with plain
struct.pack calls that MUST NOT call the module's own encoders (otherwise
the test would validate the encoder against itself).
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import opcua
from recce.core.models import Host, Port


# --- raw-hex fixtures ----------------------------------------------------------

# uacp ACK from an open62541-style server (Part 6 §7.1.2.4).
# MessageType 'ACK' (41 43 4B), ChunkType 'F' (46), MessageSize=28 (1C 00 00 00),
# ProtocolVersion=0, ReceiveBufferSize=65536, SendBufferSize=65536,
# MaxMessageSize=4194304, MaxChunkCount=64. All 32-bit LE.
_ACK_FRAME = bytes.fromhex(
    "41434b46"      # 'ACKF'
    "1c000000"      # size 28 (little-endian)
    "00000000"      # ProtocolVersion
    "00000100"      # ReceiveBufferSize (0x00010000 = 65536)
    "00000100"      # SendBufferSize
    "00004000"      # MaxMessageSize (0x00400000 = 4194304)
    "40000000"      # MaxChunkCount = 64
)

# uacp ERR (Part 6 §7.1.2.5): status 0x80AC0000 BadProtocolVersionUnsupported,
# reason "open62541 1.3" (13 bytes).
_ERR_FRAME = bytes.fromhex(
    "45525246"      # 'ERRF'
    "1d000000"      # size 29
    "0000ac80"      # StatusCode 0x80AC0000 (LE)
    "0d000000"      # Reason length 13
    "6f70656e363235343120312e33"    # "open62541 1.3"
)


# --- pure-stdlib assembly helpers (NOT the module's encoders) -----------------


def _le_u32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _le_i32(v: int) -> bytes:
    return struct.pack("<i", v)


def _ua_string(s: str | None) -> bytes:
    if s is None:
        return _le_i32(-1)
    b = s.encode("utf-8")
    return _le_i32(len(b)) + b


def _ua_bytestring(b: bytes | None) -> bytes:
    if b is None:
        return _le_i32(-1)
    return _le_i32(len(b)) + b


def _null_ext_obj() -> bytes:
    return b"\x00\x00\x00"                    # NodeId TwoByte 0 + encoding 0


def _resp_header(request_handle: int = 1, service_result: int = 0) -> bytes:
    return (b"\x00" * 8                       # timestamp
            + _le_u32(request_handle)
            + _le_u32(service_result)
            + b"\x00"                         # diag mask
            + _le_u32(0)                      # stringTable count
            + _null_ext_obj())


def _nodeid_fourbyte(identifier: int) -> bytes:
    return b"\x01\x00" + struct.pack("<H", identifier)


def _frame(mt: bytes, body: bytes) -> bytes:
    return mt + b"F" + _le_u32(8 + len(body)) + body


def _build_opn_response() -> bytes:
    policy = "http://opcfoundation.org/UA/SecurityPolicy#None"
    body = (
        _le_u32(1)                            # SecureChannelId
        + _ua_string(policy)                  # SecurityPolicyUri (echoed)
        + _ua_bytestring(None)                # SenderCertificate
        + _ua_bytestring(None)                # ReceiverCertificateThumbprint
        + _le_u32(1)                          # SequenceNumber
        + _le_u32(1)                          # RequestId
        + _nodeid_fourbyte(449)               # OpenSecureChannelResponse typeId
        + _resp_header()                      # ResponseHeader
        + _le_u32(0)                          # ServerProtocolVersion
        + _le_u32(1)                          # ChannelId (SecurityToken)
        + _le_u32(2)                          # TokenId
        + b"\x00" * 8                         # CreatedAt
        + _le_u32(3600000)                    # RevisedLifetime
        + _ua_bytestring(None)                # ServerNonce
    )
    return _frame(b"OPN", body)


def _endpoint(url: str, security_mode: int, policy_uri: str,
              tokens: list[tuple[int, str]], cert: bytes | None = None,
              product_uri: str = "urn:vendor:product",
              app_name: str = "Vendor Server",
              app_type: int = 0,
              discovery_url: str = "opc.tcp://recce:4840/") -> bytes:
    app_desc = (
        _ua_string(f"urn:recce:{app_type}")   # applicationUri
        + _ua_string(product_uri)             # productUri
        + b"\x02" + _ua_string(app_name)      # LocalizedText mask=text-only
        + _le_u32(app_type)                   # applicationType
        + _ua_string(None)                    # gatewayServerUri
        + _ua_string(None)                    # discoveryProfileUri
        + _le_u32(1) + _ua_string(discovery_url)  # discoveryUrls
    )
    tokens_bytes = _le_u32(len(tokens))
    for token_type, policy_id in tokens:
        tokens_bytes += (
            _ua_string(policy_id)             # policyId
            + _le_u32(token_type)             # tokenType
            + _ua_string(None)                # issuedTokenType
            + _ua_string(None)                # issuerEndpointUrl
            + _ua_string(None)                # securityPolicyUri (empty = inherit)
        )
    return (
        _ua_string(url)                       # endpointUrl
        + app_desc                            # server
        + _ua_bytestring(cert)                # serverCertificate
        + _le_u32(security_mode)              # securityMode
        + _ua_string(policy_uri)              # securityPolicyUri
        + tokens_bytes                        # userIdentityTokens
        + _ua_string("http://opcfoundation.org/UA-Profile/Transport/"
                     "uatcp-uasc-uabinary")   # transportProfileUri
        + b"\x00"                             # securityLevel
    )


def _msg_wrapper(node_id: bytes, service_body: bytes) -> bytes:
    body = (
        _le_u32(1)                            # SecureChannelId
        + _le_u32(2)                          # TokenId
        + _le_u32(2)                          # SequenceNumber
        + _le_u32(2)                          # RequestId
        + node_id
        + service_body
    )
    return _frame(b"MSG", body)


def _build_get_endpoints_response(endpoints_bytes: list[bytes]) -> bytes:
    svc = _resp_header()
    svc += _le_u32(len(endpoints_bytes))
    for ep in endpoints_bytes:
        svc += ep
    return _msg_wrapper(_nodeid_fourbyte(431), svc)


def _build_find_servers_response(app_descs: list[bytes]) -> bytes:
    svc = _resp_header()
    svc += _le_u32(len(app_descs))
    for a in app_descs:
        svc += a
    return _msg_wrapper(_nodeid_fourbyte(425), svc)


def _app_desc(app_uri: str, product_uri: str, name: str,
              app_type: int, discovery_urls: list[str]) -> bytes:
    d = (_ua_string(app_uri)
         + _ua_string(product_uri)
         + b"\x02" + _ua_string(name)
         + _le_u32(app_type)
         + _ua_string(None) + _ua_string(None)
         + _le_u32(len(discovery_urls)))
    for u in discovery_urls:
        d += _ua_string(u)
    return d


def _build_find_servers_on_network_response(servers: list[dict]) -> bytes:
    svc = _resp_header()
    svc += b"\x00" * 8                        # lastCounterResetTime
    svc += _le_u32(len(servers))
    for s in servers:
        svc += _le_u32(s["record_id"])
        svc += _ua_string(s["server_name"])
        svc += _ua_string(s["discovery_url"])
        caps = s.get("capabilities", [])
        svc += _le_u32(len(caps))
        for c in caps:
            svc += _ua_string(c)
    return _msg_wrapper(_nodeid_fourbyte(12211), svc)


def _build_register_server_response(service_result: int = 0) -> bytes:
    svc = _resp_header(service_result=service_result)
    return _msg_wrapper(_nodeid_fourbyte(440), svc)


# --- T2 anon-session fixtures (CreateSession / ActivateSession / Read) --------

# FILETIME (100-ns since 1601-01-01 UTC) for a known instant so a decoded
# value in a probe result is verifiable. 2026-08-30T12:00:00Z:
#   unix = 1_788_091_200
#   filetime = (unix + 11_644_473_600) * 10_000_000 = 134_325_648_000_000_000
_FILETIME_2026_08_30 = 134_325_648_000_000_000


def _build_create_session_response(session_id: int = 1000,
                                   auth_token_id: int = 42) -> bytes:
    """CreateSessionResponse (NodeId 464). SessionId and AuthenticationToken
    are FourByte NodeIds — the module captures the AuthenticationToken raw
    bytes and echoes them into subsequent request headers."""
    svc = _resp_header()
    svc += _nodeid_fourbyte(session_id)            # SessionId
    svc += _nodeid_fourbyte(auth_token_id)         # AuthenticationToken
    svc += struct.pack("<d", 60000.0)              # RevisedSessionTimeout
    svc += _ua_bytestring(bytes(32))               # ServerNonce
    svc += _ua_bytestring(None)                    # ServerCertificate
    svc += _le_u32(0)                              # ServerEndpoints count
    svc += _le_u32(0)                              # ServerSoftwareCertificates
    svc += _ua_string(None)                        # ServerSignature.algorithm
    svc += _ua_bytestring(None)                    # ServerSignature.signature
    svc += _le_u32(0)                              # MaxRequestMessageSize
    return _msg_wrapper(_nodeid_fourbyte(464), svc)


def _build_create_session_response_error(status: int) -> bytes:
    """Server refused CreateSession — ResponseHeader.serviceResult != Good."""
    svc = _resp_header(service_result=status)
    return _msg_wrapper(_nodeid_fourbyte(464), svc)


def _build_activate_session_response(service_result: int = 0) -> bytes:
    """ActivateSessionResponse (NodeId 470)."""
    svc = _resp_header(service_result=service_result)
    svc += _ua_bytestring(None)                    # ServerNonce
    svc += _le_u32(0)                              # Results array count
    svc += _le_u32(0)                              # DiagnosticInfos count
    return _msg_wrapper(_nodeid_fourbyte(470), svc)


def _build_read_response_current_time(filetime: int) -> bytes:
    """ReadResponse (NodeId 634) carrying a single DataValue whose Variant is
    a DateTime (builtin type 13)."""
    svc = _resp_header()
    svc += _le_u32(1)                              # Results count
    # DataValue: mask=0x01 (Value present only)
    svc += b"\x01"
    # Variant: type=13 (DateTime), no array/dim bits
    svc += b"\x0d"
    svc += struct.pack("<q", filetime)             # DateTime int64 LE
    svc += _le_u32(0)                              # DiagnosticInfos count
    return _msg_wrapper(_nodeid_fourbyte(634), svc)


# --- fake TCP server -----------------------------------------------------------


class _OpcuaFakeServer:
    """Serves canned frame responses. `script` is a callable that receives the
    HELLO / OPN / MSG request byte-count so far and returns the next reply."""

    def __init__(self, replies_per_conn):
        self._replies_per_conn = replies_per_conn
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.host, self.port = self._sock.getsockname()
        self._stop = False
        self._conn_index = 0
        self._t = threading.Thread(target=self._serve, daemon=True)
        self._t.start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                replies = (self._replies_per_conn[self._conn_index]
                           if self._conn_index < len(self._replies_per_conn)
                           else [])
                self._conn_index += 1
                conn.settimeout(2.0)
                for reply in replies:
                    hdr = _recvn(conn, 8)
                    if not hdr:
                        break
                    size = struct.unpack("<I", hdr[4:8])[0]
                    remaining = size - 8
                    if remaining > 0:
                        _recvn(conn, remaining)
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


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


# --- decoder unit tests --------------------------------------------------------


class DecoderTest(unittest.TestCase):
    def test_ack_frame_parses(self):
        hdr = opcua._parse_frame_header(_ACK_FRAME)
        self.assertIsNotNone(hdr)
        mt, ct, size = hdr
        self.assertEqual(mt, b"ACK")
        self.assertEqual(ct, b"F")
        self.assertEqual(size, len(_ACK_FRAME))
        parsed = opcua._parse_ack(_ACK_FRAME[8:])
        self.assertEqual(parsed["receive_buffer_size"], 65536)
        self.assertEqual(parsed["max_chunk_count"], 64)

    def test_err_frame_parses(self):
        hdr = opcua._parse_frame_header(_ERR_FRAME)
        self.assertEqual(hdr[0], b"ERR")
        parsed = opcua._parse_err(_ERR_FRAME[8:])
        self.assertEqual(parsed["status_code"], 0x80AC0000)
        self.assertEqual(parsed["reason"], "open62541 1.3")

    def test_endpoint_description_parses_anonymous_and_mode_none(self):
        ep_bytes = _endpoint(
            url="opc.tcp://recce:4840/",
            security_mode=1,
            policy_uri="http://opcfoundation.org/UA/SecurityPolicy#None",
            tokens=[(0, "anonymous"), (1, "username_basic256sha256")],
            cert=None,
        )
        get_ep = _build_get_endpoints_response([ep_bytes])
        inner = opcua._service_body_after_headers(get_ep[8:])
        self.assertIsNotNone(inner)
        parsed = opcua._parse_get_endpoints_response(inner)
        self.assertEqual(len(parsed["endpoints"]), 1)
        ep = parsed["endpoints"][0]
        self.assertEqual(ep["security_mode"], 1)
        self.assertEqual(ep["endpoint_url"], "opc.tcp://recce:4840/")
        types = [t["token_type"] for t in ep["user_identity_tokens"]]
        self.assertIn(0, types)                 # Anonymous
        self.assertIn(1, types)                 # UserName

    def test_deprecated_policy_recognised(self):
        ep_bytes = _endpoint(
            url="opc.tcp://recce:4840/",
            security_mode=2,
            policy_uri="http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
            tokens=[(1, "username")],
        )
        inner = opcua._service_body_after_headers(
            _build_get_endpoints_response([ep_bytes])[8:])
        parsed = opcua._parse_get_endpoints_response(inner)
        self.assertEqual(parsed["endpoints"][0]["security_policy_uri"],
                         "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15")


class CertificateParseTest(unittest.TestCase):
    def test_parse_self_signed_2048(self):
        # A tiny self-signed RSA-2048 cert generated once with
        # `openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=recce-opcua-test/
        #  -addext subjectAltName=URI:urn:recce:opcua:test,DNS:recce.local
        #  -out c.pem -keyout k.pem -days 365 && openssl x509 -in c.pem -outform DER | xxd -p`
        der_b64 = _SELF_SIGNED_CERT_DER
        info = opcua.parse_certificate(der_b64)
        self.assertEqual(info["subject_cn"], "recce-opcua-test")
        self.assertEqual(info["issuer_cn"], "recce-opcua-test")
        self.assertTrue(info["self_signed"])
        self.assertEqual(info["key_algorithm"], "RSA")
        self.assertEqual(info["key_bits"], 2048)
        self.assertIn("recce.local", info["san_dns"])
        self.assertIn("urn:recce:opcua:test", info["san_uri"])
        self.assertEqual(len(info["sha256"]), 64)


# --- probe integration tests ---------------------------------------------------


class ProbeTest(unittest.TestCase):
    def test_full_probe_flags_anonymous_and_none(self):
        ep_bytes = _endpoint(
            url="opc.tcp://recce:4840/",
            security_mode=1,
            policy_uri="http://opcfoundation.org/UA/SecurityPolicy#None",
            tokens=[(0, "anonymous"), (1, "username_none")],
        )
        server_replies = [
            _ACK_FRAME,
            _build_opn_response(),
            _build_get_endpoints_response([ep_bytes]),
            _build_find_servers_response([_app_desc(
                "urn:recce:server", "urn:vendor:product", "Sibling Server", 0,
                ["opc.tcp://internal-plc:4840/"])]),
            _build_find_servers_on_network_response([{
                "record_id": 1, "server_name": "PLC-42",
                "discovery_url": "opc.tcp://plc42.internal:4840/",
                "capabilities": ["LDS", "DA"]}]),
            _build_register_server_response(service_result=0),
        ]
        # Second connection sends HELLO with ProtocolVersion=99, expects ERR.
        srv = _OpcuaFakeServer([server_replies, [_ERR_FRAME]])
        try:
            pr = opcua.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()

        self.assertTrue(pr["reachable"])
        self.assertEqual(len(pr["endpoints"]), 1)
        self.assertEqual(pr["endpoints"][0]["security_mode"], 1)
        types = [t["token_type"]
                 for t in pr["endpoints"][0]["user_identity_tokens"]]
        self.assertIn(0, types)
        self.assertEqual(len(pr["find_servers"]), 1)
        self.assertEqual(len(pr["on_network"]), 1)
        self.assertTrue(pr["register_server"]["accepted"])
        self.assertIsNotNone(pr["err_banner"])
        self.assertEqual(pr["err_banner"]["reason"], "open62541 1.3")

        # findings() sanity: reachable + endpoints + anonymous + mode-none +
        # cleartext-creds + application-id + find_servers + on_network +
        # register_server + err_banner.
        host = Host(ip=srv.host, ports=[Port(portid=srv.port, service="opcua")])
        fs = opcua.findings([host], {(srv.host, srv.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("opcua_reachable", kinds)
        self.assertIn("opcua_endpoints_enumerated", kinds)
        self.assertIn("opcua_anonymous_allowed", kinds)
        self.assertIn("opcua_security_mode_none", kinds)
        self.assertIn("opcua_credentials_in_cleartext", kinds)
        self.assertIn("opcua_application_id", kinds)
        self.assertIn("opcua_find_servers", kinds)
        self.assertIn("opcua_lds_me_inventory", kinds)
        self.assertIn("opcua_open_lds_registration", kinds)
        self.assertIn("opcua_error_banner", kinds)

    def test_probe_with_deprecated_policy(self):
        ep_bytes = _endpoint(
            url="opc.tcp://recce:4840/",
            security_mode=2,
            policy_uri="http://opcfoundation.org/UA/SecurityPolicy#Basic256",
            tokens=[(1, "username")],
        )
        replies = [
            _ACK_FRAME,
            _build_opn_response(),
            _build_get_endpoints_response([ep_bytes]),
            _build_find_servers_response([]),
            _build_find_servers_on_network_response([]),
            _build_register_server_response(service_result=0x80440000),   # refused
        ]
        srv = _OpcuaFakeServer([replies, []])   # no ERR reply on 2nd conn
        try:
            pr = opcua.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()

        host = Host(ip=srv.host, ports=[Port(portid=srv.port, service="opcua")])
        fs = opcua.findings([host], {(srv.host, srv.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("opcua_deprecated_policy", kinds)
        self.assertNotIn("opcua_open_lds_registration", kinds)
        self.assertNotIn("opcua_anonymous_allowed", kinds)

    def test_probe_with_certificate_flags_self_signed(self):
        ep_bytes = _endpoint(
            url="opc.tcp://recce:4840/",
            security_mode=3,
            policy_uri="http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            tokens=[(1, "username")],
            cert=_SELF_SIGNED_CERT_DER,
        )
        replies = [
            _ACK_FRAME, _build_opn_response(),
            _build_get_endpoints_response([ep_bytes]),
            _build_find_servers_response([]),
            _build_find_servers_on_network_response([]),
            _build_register_server_response(service_result=0x80440000),
        ]
        srv = _OpcuaFakeServer([replies, []])
        try:
            pr = opcua.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        host = Host(ip=srv.host, ports=[Port(portid=srv.port, service="opcua")])
        fs = opcua.findings([host], {(srv.host, srv.port): pr})
        cert_findings = [f for f in fs if f["kind"] == "opcua_server_certificate"]
        self.assertEqual(len(cert_findings), 1)
        # 2048-bit key = not weak, but self-signed still bumps severity to medium.
        self.assertEqual(cert_findings[0]["severity"], "medium")
        self.assertIn("recce-opcua-test", cert_findings[0]["detail"])

    def test_probe_on_non_opcua_service(self):
        # Server that just replies with random bytes — probe must not raise or
        # false-flag.
        srv = _OpcuaFakeServer([[b"HTTP/1.1 400 Bad Request\r\n\r\n"], []])
        try:
            pr = opcua.probe(srv.host, srv.port, timeout=1.0)
        finally:
            srv.close()
        self.assertFalse(pr["reachable"])

    def test_probe_on_dead_port(self):
        pr = opcua.probe("127.0.0.1", 1, timeout=0.5)
        self.assertFalse(pr["reachable"])


class AnonymousSessionT2Test(unittest.TestCase):
    """T2 SAFE promotion of opcua_anonymous_allowed:
      CreateSession + ActivateSession(AnonymousIdentityToken) +
      Read(ns=0;i=2258 ServerStatus_CurrentTime).
    A successful Read upgrades the existing critical finding from T1 to T2
    and appends the observed current-time to its detail as evidence."""

    def _anon_ep_bytes(self):
        return _endpoint(
            url="opc.tcp://recce:4840/",
            security_mode=1,
            policy_uri="http://opcfoundation.org/UA/SecurityPolicy#None",
            tokens=[(0, "anonymous")],
        )

    def _base_replies(self, ep_bytes):
        return [
            _ACK_FRAME,
            _build_opn_response(),
            _build_get_endpoints_response([ep_bytes]),
            _build_find_servers_response([]),
            _build_find_servers_on_network_response([]),
            _build_register_server_response(service_result=0x80440000),
        ]

    def test_anonymous_session_promotes_finding_to_t2(self):
        ep_bytes = self._anon_ep_bytes()
        replies = self._base_replies(ep_bytes) + [
            _build_create_session_response(session_id=1000, auth_token_id=42),
            _build_activate_session_response(service_result=0),
            _build_read_response_current_time(_FILETIME_2026_08_30),
        ]
        srv = _OpcuaFakeServer([replies, []])
        try:
            pr = opcua.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()

        self.assertTrue(pr["reachable"])
        sess = pr.get("anonymous_session")
        self.assertIsNotNone(sess)
        self.assertTrue(sess["session_opened"])
        self.assertTrue(sess["activated"])
        self.assertTrue(sess["read_ok"])
        self.assertEqual(sess["current_time"], "2026-08-30T12:00:00Z")

        host = Host(ip=srv.host,
                    ports=[Port(portid=srv.port, service="opcua")])
        fs = opcua.findings([host], {(srv.host, srv.port): pr})
        anon = [f for f in fs if f["kind"] == "opcua_anonymous_allowed"]
        self.assertEqual(len(anon), 1)
        self.assertEqual(anon[0]["depth_tier"], "t2")
        self.assertEqual(anon[0]["severity"], "critical")
        self.assertIn("T2 PROOF", anon[0]["detail"])
        self.assertIn("2026-08-30T12:00:00Z", anon[0]["detail"])

    def test_activate_succeeds_but_read_fails_still_promotes(self):
        """CreateSession + ActivateSession succeed but the Read reply never
        arrives — we still have proof the anon Session is live (Activate=Good)
        so the tier upgrades to T2."""
        ep_bytes = self._anon_ep_bytes()
        replies = self._base_replies(ep_bytes) + [
            _build_create_session_response(),
            _build_activate_session_response(service_result=0),
            # no ReadResponse — connection will close after this
        ]
        srv = _OpcuaFakeServer([replies, []])
        try:
            pr = opcua.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()

        sess = pr.get("anonymous_session")
        self.assertIsNotNone(sess)
        self.assertTrue(sess["activated"])
        self.assertFalse(sess["read_ok"])

        host = Host(ip=srv.host,
                    ports=[Port(portid=srv.port, service="opcua")])
        fs = opcua.findings([host], {(srv.host, srv.port): pr})
        anon = [f for f in fs if f["kind"] == "opcua_anonymous_allowed"][0]
        self.assertEqual(anon["depth_tier"], "t2")
        self.assertIn("T2 PROOF", anon["detail"])

    def test_create_session_rejected_stays_t1(self):
        """Server advertises Anonymous but rejects CreateSession — the T1
        posture finding still emits and stays at T1."""
        ep_bytes = self._anon_ep_bytes()
        replies = self._base_replies(ep_bytes) + [
            _build_create_session_response_error(0x801F0000),  # BadIdentityTokenRejected-ish
        ]
        srv = _OpcuaFakeServer([replies, []])
        try:
            pr = opcua.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()

        sess = pr.get("anonymous_session")
        self.assertIsNotNone(sess)
        self.assertFalse(sess.get("session_opened"))
        self.assertFalse(sess.get("read_ok"))

        host = Host(ip=srv.host,
                    ports=[Port(portid=srv.port, service="opcua")])
        fs = opcua.findings([host], {(srv.host, srv.port): pr})
        anon = [f for f in fs if f["kind"] == "opcua_anonymous_allowed"][0]
        self.assertEqual(anon["depth_tier"], "t1")
        self.assertNotIn("T2 PROOF", anon["detail"])

    def test_no_anonymous_endpoint_skips_session_probe(self):
        """When no endpoint advertises Anonymous, the T2 probe is not even
        attempted — anonymous_session stays None and no anon finding fires."""
        ep_bytes = _endpoint(
            url="opc.tcp://recce:4840/",
            security_mode=2,
            policy_uri="http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
            tokens=[(1, "username_basic256sha256")],
        )
        replies = self._base_replies(ep_bytes)
        srv = _OpcuaFakeServer([replies, []])
        try:
            pr = opcua.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()

        self.assertIsNone(pr.get("anonymous_session"))
        host = Host(ip=srv.host,
                    ports=[Port(portid=srv.port, service="opcua")])
        fs = opcua.findings([host], {(srv.host, srv.port): pr})
        self.assertFalse(any(f["kind"] == "opcua_anonymous_allowed" for f in fs))

    def test_session_probe_on_dead_port_times_out_clean(self):
        """Unreachable target — probe returns cleanly with reachable=False
        and no anonymous_session dict."""
        pr = opcua.probe("127.0.0.1", 1, timeout=0.3,
                         do_anonymous_session=True)
        self.assertFalse(pr["reachable"])
        self.assertIsNone(pr.get("anonymous_session"))


class DecoderT2Test(unittest.TestCase):
    """Unit tests for the T2 decoder helpers, driven off wire-derived bytes."""

    def test_filetime_to_iso_known_value(self):
        self.assertEqual(opcua._filetime_to_iso(_FILETIME_2026_08_30),
                         "2026-08-30T12:00:00Z")

    def test_filetime_to_iso_zero_returns_empty(self):
        self.assertEqual(opcua._filetime_to_iso(0), "")

    def test_filetime_to_iso_out_of_range_returns_empty(self):
        # A value far past year 9999 — must not raise.
        self.assertEqual(opcua._filetime_to_iso(10 ** 19), "")

    def test_read_nodeid_raw_roundtrips_fourbyte(self):
        # FourByte NodeId ns=0, id=42 -> 01 00 2A 00
        buf = bytes.fromhex("01002a00") + b"trailer"
        c = opcua._Cursor(buf)
        raw = opcua._read_nodeid_raw(c)
        self.assertEqual(raw, bytes.fromhex("01002a00"))
        self.assertEqual(c.off, 4)

    def test_parse_create_session_response_captures_auth_token(self):
        frame = _build_create_session_response(session_id=1000,
                                               auth_token_id=42)
        inner = opcua._service_body_after_headers(frame[8:])
        self.assertIsNotNone(inner)
        cs = opcua._parse_create_session_response(inner)
        self.assertEqual(cs["service_result"], 0)
        # AuthenticationToken FourByte NodeId ns=0, id=42 -> 01 00 2A 00
        self.assertEqual(cs["authentication_token"], bytes.fromhex("01002a00"))

    def test_parse_read_response_current_time(self):
        frame = _build_read_response_current_time(_FILETIME_2026_08_30)
        inner = opcua._service_body_after_headers(frame[8:])
        rr = opcua._parse_read_current_time_response(inner)
        self.assertTrue(rr["ok"])
        self.assertEqual(rr["current_time"], "2026-08-30T12:00:00Z")


# --- fixture data --------------------------------------------------------------

# Self-signed RSA-2048 X.509 DER with subject CN=recce-opcua-test, SAN
# URI:urn:recce:opcua:test + DNS:recce.local. Generated once with `openssl req
# -x509 -newkey rsa:2048 -nodes` and pasted here as a hex literal so the test
# has a wire-derived fixture without a runtime openssl dependency.
_SELF_SIGNED_CERT_DER = bytes.fromhex(
    "308203463082022ea00302010202145c2cb9093f553d6b6a67778ce7ed4f10ca634d44"
    "300d06092a864886f70d01010b0500301b3119301706035504030c1072656363652d6f"
    "706375612d74657374301e170d3236303832393035303931335a170d33363038323630"
    "35303931335a301b3119301706035504030c1072656363652d6f706375612d74657374"
    "30820122300d06092a864886f70d01010105000382010f003082010a0282010100e61f"
    "336ad8aeb486c88ac3b7f933fd3ae7ce98103d0b52270dd12062e0980cca504b8cbc7d"
    "e767a5331fb0e35f1f59da4bdddfbd0110941be2d63cb1781601427cd1a5d1b948c564"
    "93f40faeb319ee4355b61fc2b8e050e5e4af343a2ea3eaf3abd49c89c0c78098bda157"
    "65ef8f3ff166c7d9801912902d40423624a72217f666f450cb7ad72b3d982247a43b2d"
    "30139c3f4e5240a1122266566e805710f5d13718ed850bbdf3bec5d8382312c0c819de"
    "abbb17b21083fca937687b2eb10f0c3dcd29549ac2260e466b292e63dd75f546aecf4e"
    "d7d8335f1adcbcf29b96f735b5ed2e3f323a154ebad2e5c1548315d3e2e05d17c48a20"
    "d70f410b4e02e99e5b0203010001a38181307f301d0603551d0e041604148b13936ef2"
    "df53e967235fc895ab00ba479478fe301f0603551d230418301680148b13936ef2df53"
    "e967235fc895ab00ba479478fe300f0603551d130101ff040530030101ff302c060355"
    "1d1104253023861475726e3a72656363653a6f706375613a74657374820b7265636365"
    "2e6c6f63616c300d06092a864886f70d01010b05000382010100d0da862f196fc8aa14"
    "42cd43f17852eb9b7a673891acc918f929887a7b15cdfc466dc816417df22f15ae52a2"
    "38722d0437552decee16b2ffaab5509e19500e93ee04f111d963187af9263f8f849e4e"
    "d6d40cfa9ae93b191c3e1d6a9c48355b1df571a8f3d89f04107362fa80aa093dc64e09"
    "5c8577874058f7c3a83a7149c35cdf894c65cef5e8e981c38ca5ed1fc059060ad72dca"
    "f293287b4d60c0506cc69b7345779d22bcd20d0c858f5da400bd40fabd079134aee015"
    "5377fe0d7a607ecef571d511e31ee32b763081ad5b7894dafa5a45b12cfbffafc5eb40"
    "aac2b55f87eaed9e2b9a9d30fc93238f1d1db80c9210b975e0518287cab86f3f76bbed"
    "ec8a"
)


if __name__ == "__main__":
    unittest.main()
