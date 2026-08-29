"""Tests for recce.services.coap.

Wire fixtures are hand-built against RFC 7252 §3 (message format), RFC 6690
(CoRE Link Format), RFC 7641 (Observe), and RFC 6347 (DTLS 1.2 record layer).
A fake in-process UDP server is scripted with response bytes; no network."""
from __future__ import annotations

import socket
import struct
import threading
import time
import unittest

from recce.services import coap


# --- wire fixture helpers (hand-built from RFC 7252) ----------------------

def _header(ver: int, t: int, tkl: int, code: int, mid: int) -> bytes:
    return bytes([(ver << 6) | (t << 4) | tkl, code,
                  (mid >> 8) & 0xFF, mid & 0xFF])


def _opt_field(v: int) -> tuple[int, bytes]:
    if v < 13:
        return v, b""
    if v < 269:
        return 13, bytes([v - 13])
    return 14, struct.pack(">H", v - 269)


def _opt(prev_num: int, num: int, value: bytes) -> tuple[int, bytes]:
    """Return (num, encoded_option_bytes) for use in building option blocks."""
    delta = num - prev_num
    d_n, d_ext = _opt_field(delta)
    l_n, l_ext = _opt_field(len(value))
    return num, bytes([(d_n << 4) | l_n]) + d_ext + l_ext + value


def _build_reply(t: int, code: int, mid: int, token: bytes,
                 opts: list[tuple[int, bytes]], payload: bytes) -> bytes:
    """Build a CoAP reply from a list of (num, value) options. Order matters."""
    body = _header(1, t, len(token), code, mid) + token
    prev = 0
    for num, value in sorted(opts, key=lambda x: x[0]):
        _, encoded = _opt(prev, num, value)
        body += encoded
        prev = num
    if payload:
        body += bytes([0xFF]) + payload
    return body


# --- Fake CoAP UDP server -------------------------------------------------

class _FakeCoAP:
    """A minimal UDP responder driven by a scripted plan.

    plan keys (all optional):
      - empty_ping_reply: bytes -> reply to an empty-CON (default: RST 0.00)
      - wellknown: bytes payload for /.well-known/core (default: '')
      - wellknown_code: response code byte (default 0x45 = 2.05)
      - wellknown_ct: content-format uint (default 40)
      - resource_replies: dict[path_tuple] -> (code, ct, payload) OR list of
        replies to return in order (block2 support)
      - observe_stream: list[bytes payload] for the observed resource
      - proxy_code: response code for a Proxy-Uri request
      - dtls_reply: raw bytes to return on a DTLS record
      - authgate_wellknown: bool -> reply to wellknown with 4.01
    """

    def __init__(self, plan: dict):
        self.plan = plan
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.settimeout(0.2)
        self.host, self.port = self._srv.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        self.puts_seen: list[tuple[str, bytes]] = []
        self.observe_registered = False

    def close(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass

    def _serve(self):
        while not self._stop:
            try:
                data, addr = self._srv.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            try:
                self._handle(data, addr)
            except Exception:  # noqa: BLE001 - test server: swallow to stay alive
                continue

    def _handle(self, data: bytes, addr):
        try:
            msg = coap._decode_message(data)
        except ValueError:
            return
        # Empty-CON ping -> RST with same MID.
        if msg["code"] == 0x00 and msg["t"] == 0:
            rst = self.plan.get("empty_ping_reply")
            if rst is None:
                rst = _header(1, 3, 0, 0x00, msg["mid"])
            self._srv.sendto(rst, addr)
            return
        # Discover method + Uri-Path.
        method = msg["code"]
        path_segments = tuple(v.decode("utf-8", "replace")
                              for n, v in msg["options"] if n == coap._OPT_URI_PATH)
        path = "/" + "/".join(path_segments) if path_segments else "/"
        proxy_uri = None
        for n, v in msg["options"]:
            if n == coap._OPT_PROXY_URI:
                proxy_uri = v.decode("utf-8", "replace")
        observe_val = None
        for n, v in msg["options"]:
            if n == coap._OPT_OBSERVE:
                observe_val = int.from_bytes(v, "big") if v else 0
        block2_req = None
        for n, v in msg["options"]:
            if n == coap._OPT_BLOCK2:
                num = int.from_bytes(v, "big") if v else 0
                block2_req = (num >> 4, (num >> 3) & 1, num & 7)

        # Proxy-Uri path.
        if proxy_uri is not None:
            code = self.plan.get("proxy_code", 0x45)
            reply = _build_reply(2, code, msg["mid"], msg["token"], [], b"")
            self._srv.sendto(reply, addr)
            return

        # /.well-known/core.
        if path == "/.well-known/core":
            if self.plan.get("authgate_wellknown"):
                reply = _build_reply(2, 0x81, msg["mid"], msg["token"], [], b"")
                self._srv.sendto(reply, addr)
                return
            body = self.plan.get("wellknown", b"")
            code = self.plan.get("wellknown_code", 0x45)
            ct = self.plan.get("wellknown_ct", 40)
            opts = [(coap._OPT_CONTENT_FORMAT, coap._uint_option(ct))]
            # Block2 support: chunk into 32-byte pieces if plan says so.
            block_szx = self.plan.get("wellknown_block_szx")
            if block_szx is not None:
                block_size = 16 << block_szx
                num, _more, szx = block2_req or (0, 0, block_szx)
                start = num * block_size
                end = start + block_size
                chunk = body[start:end]
                more = 1 if end < len(body) else 0
                b2 = (num << 4) | (more << 3) | szx
                opts.append((coap._OPT_BLOCK2, coap._uint_option(b2)))
                reply = _build_reply(2, code, msg["mid"], msg["token"], opts, chunk)
                self._srv.sendto(reply, addr)
                return
            reply = _build_reply(2, code, msg["mid"], msg["token"], opts, body)
            self._srv.sendto(reply, addr)
            return

        # Observe path.
        if observe_val == 0 and path in self.plan.get("observe_paths", ()):
            self.observe_registered = True
            stream = list(self.plan.get("observe_stream", [b"first"]))
            seq = 1
            for payload in stream:
                opts = [(coap._OPT_OBSERVE, coap._uint_option(seq))]
                # Notifications go back as NON, per typical Observe.
                reply = _build_reply(1, 0x45, msg["mid"] + seq,
                                     msg["token"], opts, payload)
                self._srv.sendto(reply, addr)
                seq += 1
                time.sleep(0.02)
            return
        if observe_val == 1:
            reply = _build_reply(2, 0x45, msg["mid"], msg["token"], [], b"")
            self._srv.sendto(reply, addr)
            return

        # Generic resource_replies map (with block2 support).
        replies = self.plan.get("resource_replies", {})
        entry = replies.get(path_segments)
        if entry is not None:
            if method == coap._M_PUT:
                # Record the PUT and reply per plan.
                self.puts_seen.append((path, msg["payload"]))
                code = self.plan.get("put_code", 0x44)          # 2.04 Changed
                reply = _build_reply(2, code, msg["mid"], msg["token"], [], b"")
                self._srv.sendto(reply, addr)
                return
            code, ct, payload = entry
            opts = []
            if ct is not None:
                opts.append((coap._OPT_CONTENT_FORMAT, coap._uint_option(ct)))
            reply = _build_reply(2, code, msg["mid"], msg["token"], opts, payload)
            self._srv.sendto(reply, addr)
            return

        # Fallback: 4.04 Not Found.
        reply = _build_reply(2, 0x84, msg["mid"], msg["token"], [], b"")
        self._srv.sendto(reply, addr)


# --- unit tests: wire codec -----------------------------------------------


class HeaderCodecTest(unittest.TestCase):
    def test_encode_empty_con_matches_rfc_shape(self):
        pkt = coap._encode_message(coap._T_CON, 0x00, 0x1234)
        # Ver=01, T=00, TKL=0 -> 0x40; code 0x00; MID 0x1234
        self.assertEqual(pkt, b"\x40\x00\x12\x34")

    def test_encode_get_with_path(self):
        opts = coap._uri_path_options("/.well-known/core")
        pkt = coap._encode_message(coap._T_CON, coap._M_GET, 0xBEEF,
                                   b"\x01\x02\x03\x04", opts)
        # Header 4 + token 4 + two Uri-Path options.
        # Uri-Path option number 11. First option delta=11 -> nibble 11.
        # ".well-known" length 11 -> nibble 11. Header byte = 0xBB.
        self.assertEqual(pkt[:4], b"\x44\x01\xBE\xEF")
        self.assertEqual(pkt[4:8], b"\x01\x02\x03\x04")
        self.assertEqual(pkt[8], 0xBB)
        self.assertEqual(pkt[9:9 + 11], b".well-known")

    def test_round_trip(self):
        opts = [(coap._OPT_URI_PATH, b"foo"),
                (coap._OPT_URI_PATH, b"bar"),
                (coap._OPT_ACCEPT, coap._uint_option(40))]
        pkt = coap._encode_message(coap._T_CON, coap._M_GET, 0x1000,
                                   b"tk", opts, b"body")
        msg = coap._decode_message(pkt)
        self.assertEqual(msg["ver"], 1)
        self.assertEqual(msg["t"], coap._T_CON)
        self.assertEqual(msg["code"], coap._M_GET)
        self.assertEqual(msg["mid"], 0x1000)
        self.assertEqual(msg["token"], b"tk")
        self.assertEqual(msg["payload"], b"body")
        # Options round-trip in ascending option-number order.
        nums = [n for n, _ in msg["options"]]
        self.assertEqual(nums, sorted(nums))
        vals = {n: [] for n, _ in msg["options"]}
        for n, v in msg["options"]:
            vals[n].append(v)
        self.assertEqual(vals[coap._OPT_URI_PATH], [b"foo", b"bar"])

    def test_decode_extended_delta(self):
        # Option number 269 needs 2-byte extension (14).
        pkt = coap._encode_message(coap._T_CON, coap._M_GET, 1, b"",
                                   [(269, b"x")])
        msg = coap._decode_message(pkt)
        self.assertEqual(msg["options"], [(269, b"x")])

    def test_decode_malformed_raises(self):
        with self.assertRaises(ValueError):
            coap._decode_message(b"\x40")

    def test_uint_option_shortest(self):
        self.assertEqual(coap._uint_option(0), b"")
        self.assertEqual(coap._uint_option(1), b"\x01")
        self.assertEqual(coap._uint_option(255), b"\xff")
        self.assertEqual(coap._uint_option(256), b"\x01\x00")

    def test_code_str(self):
        # 2.05 = 0x45 = (2<<5) | 5
        self.assertEqual(coap._code_str(0x45), "2.05")
        self.assertEqual(coap._code_str(0x84), "4.04")
        self.assertEqual(coap._code_str(0x81), "4.01")


class LinkFormatParseTest(unittest.TestCase):
    """RFC 6690 §2 / §3 examples."""

    def test_rfc6690_example_shape(self):
        body = ('</sensors/temp>;rt="core.s";if="sensor";ct=0,'
                '</actuators/relay>;rt="oic.r.switch.binary";obs,'
                '</config>;rt="mfg.cfg";sz=8192')
        parsed = coap.parse_link_format(body)
        self.assertEqual([p["path"] for p in parsed],
                         ["/sensors/temp", "/actuators/relay", "/config"])
        self.assertEqual(parsed[0]["rt"], "core.s")
        self.assertEqual(parsed[0]["if"], "sensor")
        self.assertEqual(parsed[0]["ct"], "0")
        self.assertTrue(parsed[1]["obs"])
        self.assertEqual(parsed[2]["sz"], "8192")

    def test_comma_inside_quotes_not_split(self):
        body = '</a>;rt="one,two"'
        parsed = coap.parse_link_format(body)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["rt"], "one,two")


# --- integration tests via the fake server --------------------------------


class EmptyPingTest(unittest.TestCase):
    def test_ping_returns_rst(self):
        srv = _FakeCoAP({})
        try:
            r = coap.empty_ping(srv.host, srv.port, timeout=1.0)
        finally:
            srv.close()
        self.assertTrue(r["ok"])
        self.assertEqual(r["reply_type"], coap._T_RST)
        self.assertTrue(r["matching_mid"])

    def test_no_server(self):
        # Send to a closed UDP port; should time out cleanly.
        r = coap.empty_ping("127.0.0.1", 1, timeout=0.3)
        self.assertFalse(r["ok"])


class WellKnownDumpTest(unittest.TestCase):
    def test_dump_and_parse(self):
        body = ('</sensors/temp>;rt="core.s";ct=0,'
                '</actuators/relay>;rt="oic.r.switch.binary";obs')
        srv = _FakeCoAP({"wellknown": body.encode("ascii")})
        try:
            r = coap.get_resource(srv.host, srv.port, "/.well-known/core",
                                  timeout=1.0, accept=40, max_blocks=4)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertEqual(r["code_str"], "2.05")
        self.assertEqual(r["content_format"], 40)
        self.assertIn(b"sensors/temp", r["payload"])

    def test_block2_reassembly(self):
        # 96-byte body chunked into 32-byte blocks (szx=1 -> 32).
        body = b"</a>;rt=\"x\"," * 8  # 96 bytes
        srv = _FakeCoAP({"wellknown": body, "wellknown_block_szx": 1})
        try:
            r = coap.get_resource(srv.host, srv.port, "/.well-known/core",
                                  timeout=1.0, accept=40, max_blocks=8,
                                  block_size_szx=1)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertEqual(r["payload"], body)
        self.assertFalse(r["truncated"])


class ResourceSweepTest(unittest.TestCase):
    def test_sweep_reads_advertised_resources(self):
        replies = {
            ("sensors", "temp"): (0x45, 50, b'{"v":22.4}'),
            ("oic", "d"): (0x45, 50, b'{"mnmn":"AcmeCorp","mnfv":"1.2.3"}'),
        }
        srv = _FakeCoAP({"resource_replies": replies})
        try:
            resources = [
                {"path": "/sensors/temp", "rt": "core.s", "if": "", "ct": "50",
                 "sz": "", "obs": False},
                {"path": "/oic/d", "rt": "oic.wk.d", "if": "", "ct": "50",
                 "sz": "", "obs": False},
            ]
            out = coap.resource_sweep(srv.host, srv.port, resources,
                                      timeout=1.0)
        finally:
            srv.close()
        by_path = {e["path"]: e for e in out}
        self.assertEqual(by_path["/sensors/temp"]["code"], "2.05")
        self.assertIn(b"AcmeCorp", by_path["/oic/d"]["snippet"])
        self.assertEqual(by_path["/oic/d"]["ct"], 50)


class ObserveTest(unittest.TestCase):
    def test_observe_captures_notifications(self):
        srv = _FakeCoAP({
            "observe_paths": ("/sensors/temp",),
            "observe_stream": [b"22.4", b"22.5", b"22.6"],
        })
        try:
            r = coap.observe_resource(srv.host, srv.port, "/sensors/temp",
                                      window=1.0, max_notifications=5,
                                      timeout=1.0)
        finally:
            srv.close()
        self.assertTrue(r["registered"])
        self.assertGreaterEqual(len(r["notifications"]), 1)


class WriteTest(unittest.TestCase):
    def test_put_writable_and_rollback(self):
        replies = {("actuators", "relay"): (0x45, 0, b"off")}
        srv = _FakeCoAP({"resource_replies": replies, "put_code": 0x44})
        try:
            r = coap.write_permission_test(
                srv.host, srv.port, "/actuators/relay",
                pre_value=b"off", pre_content_format=0, timeout=1.0)
        finally:
            srv.close()
        self.assertTrue(r["attempted"])
        self.assertTrue(r["writable"])
        # We should have seen two PUTs: the marker + the rollback.
        self.assertEqual(len(srv.puts_seen), 2)
        first_payload = srv.puts_seen[0][1]
        rollback_payload = srv.puts_seen[1][1]
        self.assertTrue(first_payload.startswith(b"recce-probe-"))
        self.assertEqual(rollback_payload, b"off")
        self.assertTrue(r["rolled_back"])

    def test_put_denied_no_rollback(self):
        # 4.05 Method Not Allowed to any PUT.
        replies = {("actuators", "relay"): (0x45, 0, b"off")}
        srv = _FakeCoAP({"resource_replies": replies, "put_code": 0x85})
        try:
            r = coap.write_permission_test(
                srv.host, srv.port, "/actuators/relay",
                pre_value=b"off", pre_content_format=0, timeout=1.0)
        finally:
            srv.close()
        self.assertTrue(r["attempted"])
        self.assertFalse(r["writable"])
        self.assertEqual(r["code"], "4.05")


class ProxyRelayTest(unittest.TestCase):
    def test_proxy_accepted_flags_as_open_relay(self):
        srv = _FakeCoAP({"proxy_code": 0x45})
        try:
            r = coap.proxy_relay_test(srv.host, srv.port,
                                      "coap://192.0.2.1/x", timeout=1.0)
        finally:
            srv.close()
        self.assertTrue(r["proxied"])
        self.assertEqual(r["code"], "2.05")

    def test_proxy_refused_not_flagged(self):
        srv = _FakeCoAP({"proxy_code": 0xA5})   # 5.05 Proxying Not Supported
        try:
            r = coap.proxy_relay_test(srv.host, srv.port,
                                      "coap://192.0.2.1/x", timeout=1.0)
        finally:
            srv.close()
        self.assertFalse(r["proxied"])
        self.assertEqual(r["code"], "5.05")


class FullProbeTest(unittest.TestCase):
    def test_full_probe_populates_resource_inventory(self):
        wk = ('</sensors/temp>;rt="core.s";ct=0,'
              '</actuators/relay>;rt="oic.r.switch.binary";obs,'
              '</oic/d>;rt="oic.wk.d";ct=50').encode("ascii")
        replies = {
            ("sensors", "temp"): (0x45, 0, b"22.4"),
            ("actuators", "relay"): (0x45, 0, b"off"),
            ("oic", "d"): (0x45, 50, b'{"mnmn":"AcmeCorp","mnfv":"1.0"}'),
        }
        srv = _FakeCoAP({"wellknown": wk, "resource_replies": replies,
                         "observe_paths": ("/actuators/relay",),
                         "observe_stream": [b"off", b"on"],
                         "proxy_code": 0xA5,
                         "put_code": 0x44})
        try:
            pr = coap.probe(srv.host, srv.port, timeout=1.0, active=True,
                            observe_window=0.6, test_write=True)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["wellknown_code"], "2.05")
        self.assertEqual(len(pr["resources"]), 3)
        # Sweep should read every non-well-known resource.
        paths = {e["path"] for e in pr["readable"]}
        self.assertIn("/sensors/temp", paths)
        self.assertIn("/oic/d", paths)
        # Observe should have captured a notification.
        self.assertTrue(pr["observe"])
        # Actuator PUT should have been attempted (and rolled back).
        self.assertTrue(pr["writable"])
        self.assertTrue(pr["writable"][0]["writable"])
        self.assertTrue(pr["writable"][0]["rolled_back"])
        # Proxy refused.
        self.assertFalse(pr["proxy"].get("proxied"))
        # Amplification ratio computed.
        self.assertGreater(pr["amp_ratio"], 0)
        # Product pinned from rt=oic.*
        self.assertEqual(pr["product"], "iotivity")

    def test_authgated_wellknown(self):
        srv = _FakeCoAP({"authgate_wellknown": True})
        try:
            pr = coap.probe(srv.host, srv.port, timeout=1.0, active=True)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["authgated"])
        self.assertEqual(pr["wellknown_code"], "4.01")


# --- DTLS fingerprint (5684) ---------------------------------------------

class DTLSFingerprintTest(unittest.TestCase):
    """DTLS 1.2 ServerHello + ServerKeyExchange fixture, hand-built."""

    def _server_hello(self, cipher: tuple[int, int]) -> bytes:
        # ServerHello body: version(2) random(32) sess_id_len(1) cipher(2) comp(1)
        body = (b"\xfe\xfd"
                + b"\x11" * 32
                + b"\x00"
                + bytes(cipher)
                + b"\x00")
        # Handshake header: type(1) length(3) seq(2) frag_off(3) frag_len(3)
        hs = (bytes([coap._DTLS_HS_SERVER_HELLO])
              + len(body).to_bytes(3, "big")
              + b"\x00\x00"
              + b"\x00\x00\x00"
              + len(body).to_bytes(3, "big")
              + body)
        return hs

    def _server_key_exchange_psk(self, hint: bytes) -> bytes:
        body = struct.pack(">H", len(hint)) + hint
        hs = (bytes([coap._DTLS_HS_SERVER_KEY_EXCHANGE])
              + len(body).to_bytes(3, "big")
              + b"\x00\x01"
              + b"\x00\x00\x00"
              + len(body).to_bytes(3, "big")
              + body)
        return hs

    def _record(self, fragment: bytes) -> bytes:
        return (bytes([coap._DTLS_CONTENT_HANDSHAKE])
                + b"\xfe\xfd"
                + b"\x00\x00"
                + b"\x00\x00\x00\x00\x00\x00"
                + struct.pack(">H", len(fragment)))  + fragment

    def _serve_once(self, reply: bytes):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        host, port = srv.getsockname()

        def _worker():
            srv.settimeout(3.0)
            try:
                _data, addr = srv.recvfrom(65535)
            except (socket.timeout, OSError):
                return
            try:
                srv.sendto(reply, addr)
            except OSError:
                pass
            try:
                srv.close()
            except OSError:
                pass

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return host, port

    def test_psk_hint_disclosed(self):
        cipher = (0xC0, 0xA8)   # TLS_PSK_WITH_AES_128_CCM_8
        hint = b"DeviceSerial-AABBCC"
        sh = self._server_hello(cipher)
        ske = self._server_key_exchange_psk(hint)
        # Two handshakes fit in one record body concatenated.
        reply = self._record(sh + ske)
        host, port = self._serve_once(reply)
        r = coap.dtls_fingerprint(host, port, timeout=2.0)
        self.assertTrue(r["reachable"])
        self.assertEqual(r["server_cipher"], cipher)
        self.assertEqual(r["psk_identity_hint"], "DeviceSerial-AABBCC")
        self.assertFalse(r["weak_cipher"])

    def test_null_cipher_flags_weak(self):
        cipher = (0x00, 0x2C)   # TLS_PSK_WITH_NULL_SHA
        sh = self._server_hello(cipher)
        reply = self._record(sh)
        host, port = self._serve_once(reply)
        r = coap.dtls_fingerprint(host, port, timeout=2.0)
        self.assertTrue(r["reachable"])
        self.assertTrue(r["weak_cipher"])
        self.assertEqual(r["server_cipher"], cipher)


# --- findings / targeting / runbook / vulns -------------------------------


def _hosts(port=5683):
    from recce.core.models import Host, Port
    return [Host(ip="10.0.0.1", ports=[Port(portid=port, service="coap")])]


class FindingsTest(unittest.TestCase):
    def test_inventory_actuator_and_write_emit(self):
        hosts = _hosts()
        pr = {
            "reachable": True,
            "resources": [
                {"path": "/sensors/temp", "rt": "core.s", "if": "", "ct": "0",
                 "sz": "", "obs": False},
                {"path": "/actuators/relay", "rt": "oic.r.switch.binary",
                 "if": "", "ct": "0", "sz": "", "obs": True},
            ],
            "readable": [
                {"path": "/oic/d", "code": "2.05", "code_num": 0x45, "ct": 50,
                 "size": 20, "snippet": b'{"mnmn":"Acme"}'},
            ],
            "writable": [
                {"path": "/actuators/relay", "attempted": True, "writable": True,
                 "code": "2.04", "rolled_back": True},
            ],
            "observe": [
                {"path": "/actuators/relay", "registered": True,
                 "notifications": [{"code": "2.05", "observe": 1, "size": 3,
                                    "snippet": b"off"}],
                 "code": "2.05"},
            ],
            "proxy": {"attempted": True, "proxied": True, "code": "2.05"},
            "amp_ratio": 25.0,
            "authgated": False, "oscore": False,
            "wellknown_code": "2.05", "empty_ping": {},
            "dtls": {}, "product": "iotivity", "version_str": "",
        }
        fs = coap.findings(hosts, {("10.0.0.1", 5683): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("coap_resource_inventory", kinds)
        self.assertIn("coap_actuator_exposed", kinds)
        self.assertIn("coap_device_disclosure", kinds)
        self.assertIn("coap_observe_leak", kinds)
        self.assertIn("coap_open_proxy", kinds)
        self.assertIn("coap_amplifier", kinds)
        self.assertIn("coap_plaintext", kinds)
        # Inventory severity must be critical when actuator-typed resources present.
        inv = next(f for f in fs if f["kind"] == "coap_resource_inventory")
        self.assertEqual(inv["severity"], "critical")
        # Every finding must set kind + severity + target.
        for f in fs:
            self.assertTrue(f["kind"])
            self.assertIn(f["severity"], ("critical", "high", "medium",
                                          "low", "info"))
            self.assertEqual(f["target"], "10.0.0.1:5683")

    def test_authgated_emits_info(self):
        hosts = _hosts()
        pr = {"reachable": True, "authgated": True, "wellknown_code": "4.01",
              "resources": [], "readable": [], "writable": [], "observe": [],
              "proxy": {}, "amp_ratio": 0.0, "oscore": False,
              "empty_ping": {}, "dtls": {}, "product": "", "version_str": ""}
        fs = coap.findings(hosts, {("10.0.0.1", 5683): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("coap_authgated", kinds)
        self.assertIn("coap_plaintext", kinds)
        self.assertNotIn("coap_resource_inventory", kinds)

    def test_dtls_findings_on_5684(self):
        hosts = _hosts(port=5684)
        pr = {"reachable": True,
              "dtls": {"reachable": True, "hello_verify": False,
                       "server_cipher": (0x00, 0x2C),
                       "server_cipher_name": "TLS_PSK_WITH_NULL_SHA",
                       "psk_identity_hint": "DeviceSerial-AABBCC",
                       "weak_cipher": True}}
        fs = coap.findings(hosts, {("10.0.0.1", 5684): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("coap_dtls_psk_hint", kinds)
        self.assertIn("coap_dtls_weak", kinds)
        self.assertIn("coap_dtls_fingerprint", kinds)
        # Plaintext must NOT fire on the DTLS port.
        self.assertNotIn("coap_plaintext", kinds)


class TargetsTest(unittest.TestCase):
    def test_is_coap_by_port_and_service(self):
        from recce.core.models import Port
        self.assertTrue(coap.is_coap(Port(portid=5683)))
        self.assertTrue(coap.is_coap(Port(portid=5684)))
        self.assertTrue(coap.is_coap(Port(portid=9999, service="coap")))
        self.assertFalse(coap.is_coap(Port(portid=9999, service="http")))

    def test_targets_iterates_open_ports(self):
        targets = coap.coap_targets(_hosts())
        self.assertEqual(targets[0]["port"], 5683)


class RunbookTest(unittest.TestCase):
    def test_runbook_has_wellknown(self):
        rb = coap.runbook("10.0.0.1", 5683)
        self.assertTrue(any(".well-known/core" in step["command"] for step in rb))

    def test_dtls_runbook_uses_dtls_client(self):
        rb = coap.runbook("10.0.0.1", 5684)
        self.assertTrue(any("dtls1_2" in step["command"] for step in rb))


class FindingsToVulnsTest(unittest.TestCase):
    def test_conversion_produces_vulns(self):
        fs = [{"severity": "critical",
               "title": "CoAP endpoint accepts anonymous PUT to an actuator",
               "target": "10.0.0.1:5683", "detail": "d", "command": "c",
               "remediation": "r", "cwes": ["CWE-306"],
               "kind": "coap_actuator_exposed"}]
        by_ip = coap.findings_to_vulns(fs)
        self.assertIn("10.0.0.1", by_ip)
        v = by_ip["10.0.0.1"][0]
        self.assertEqual(v.severity, "critical")
        self.assertEqual(v.port, 5683)


if __name__ == "__main__":
    unittest.main()
