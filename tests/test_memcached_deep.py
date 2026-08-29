"""Wire-derived tests for the recently added memcached capabilities:

  * `lru_crawler metadump all`     - full key enumeration on modern servers
  * `get <k1> <k2> ...`            - cached VALUE retrieval (bounded)
  * UDP amplification-vector probe - 8-byte frame header, `stats` datagram
  * key-shape classification       - session / auth / csrf / apikey tags

Every server here speaks the actual memcached wire format from protocol.txt
(text protocol response shapes) so the parser + probe + findings run end to
end - no mocks. Fast (localhost).
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services.db import memcached


def _host(port: int) -> Host:
    return Host(ip="127.0.0.1",
                ports=[Port(portid=port, service="memcached", state="open")])


def _serve_tcp(handler):
    """Start a threaded TCP echo-shape server that hands each connection to
    `handler(conn)`. Returns the bound port."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3)
                try:
                    handler(conn)
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return port


def _serve_udp(handler):
    """Start a UDP echo-shape server; hands each datagram to
    `handler(data) -> reply_bytes`. Returns the bound port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                data, addr = srv.recvfrom(65535)
            except OSError:
                return
            try:
                reply = handler(data)
            except Exception:                  # noqa: BLE001
                reply = None
            if reply is not None:
                try:
                    srv.sendto(reply, addr)
                except OSError:
                    pass

    threading.Thread(target=loop, daemon=True).start()
    return port


class ParseHelpers(unittest.TestCase):
    def test_metadump_parses_and_url_decodes(self):
        # Real memcached metadump line shape: `key=<pct> exp=<n> la=<n> cas=<n> \
        # fetch=<n> cls=<n> size=<n>` terminated by `END`.
        raw = (b"key=session%3Aabc exp=1700000000 la=0 cas=1 fetch=1 cls=1 size=12\r\n"
               b"key=api%5Fkey%2Ex exp=-1 la=0 cas=2 fetch=0 cls=1 size=3\r\n"
               b"key=plain exp=0 la=0 cas=3 fetch=0 cls=1 size=5\r\n"
               b"END\r\n")
        keys = memcached._parse_metadump_keys(raw)
        self.assertEqual(keys, ["session:abc", "api_key.x", "plain"])

    def test_metadump_empty_on_unsupported(self):
        # Old servers return `ERROR` / `CLIENT_ERROR` for `lru_crawler metadump all`.
        self.assertEqual(memcached._parse_metadump_keys(b"ERROR\r\n"), [])
        self.assertEqual(memcached._parse_metadump_keys(b"CLIENT_ERROR bad command\r\n"),
                         [])
        self.assertEqual(memcached._parse_metadump_keys(b""), [])

    def test_metadump_cap(self):
        # Cap keeps a huge cache from filling memory.
        big = b"".join(
            f"key=k{i} exp=0 la=0 cas={i} fetch=0 cls=1 size=1\r\n".encode()
            for i in range(memcached._METADUMP_MAX_KEYS + 50)
        )
        keys = memcached._parse_metadump_keys(big)
        self.assertEqual(len(keys), memcached._METADUMP_MAX_KEYS)

    def test_parse_values_multi_get(self):
        # protocol.txt `get`: VALUE <k> <flags> <bytes>\r\n<data>\r\n...END\r\n
        raw = (b"VALUE session:abc 0 5\r\nhello\r\n"
               b"VALUE api:x 0 3\r\nAAA\r\n"
               b"END\r\n")
        vals = memcached._parse_values(raw)
        self.assertEqual(len(vals), 2)
        self.assertEqual(vals[0], {"key": "session:abc", "bytes": 5,
                                    "preview": "hello", "truncated": False})
        self.assertEqual(vals[1]["key"], "api:x")
        self.assertFalse(vals[1]["truncated"])

    def test_parse_values_binary_with_crlf_inside(self):
        # Values are opaque bytes and CAN contain CR/LF - the length field is
        # authoritative, not a delimiter search.
        raw = b"VALUE k 0 7\r\nab\r\ncde\r\nEND\r\n"
        vals = memcached._parse_values(raw)
        self.assertEqual(len(vals), 1)
        self.assertEqual(vals[0]["bytes"], 7)
        self.assertEqual(vals[0]["preview"], "ab\r\ncde")

    def test_parse_values_truncates_at_preview_cap(self):
        # A value larger than the preview cap is captured only to the cap and
        # flagged truncated - never the whole value.
        big_len = memcached._VALUE_PREVIEW_BYTES + 500
        payload = b"A" * big_len
        raw = f"VALUE big 0 {big_len}\r\n".encode() + payload + b"\r\nEND\r\n"
        vals = memcached._parse_values(raw)
        self.assertEqual(len(vals), 1)
        self.assertTrue(vals[0]["truncated"])
        self.assertEqual(len(vals[0]["preview"]), memcached._VALUE_PREVIEW_BYTES)
        self.assertEqual(vals[0]["bytes"], big_len)

    def test_parse_values_bogus_reply_stops_cleanly(self):
        # An ERROR or malformed reply must not crash the parser.
        self.assertEqual(memcached._parse_values(b"ERROR\r\n"), [])
        self.assertEqual(memcached._parse_values(b"VALUE k 0 notanumber\r\n"), [])
        self.assertEqual(memcached._parse_values(b""), [])

    def test_classify_key_precedence(self):
        # csrf beats auth (both would otherwise match "token" via csrf_token).
        self.assertEqual(memcached._classify_key("csrf_token"), "csrf")
        self.assertEqual(memcached._classify_key("xsrf-cookie"), "csrf")
        self.assertEqual(memcached._classify_key("PHPSESSID_abc"), "session")
        self.assertEqual(memcached._classify_key("django.contrib.sessions.cache.7"),
                         "session")
        self.assertEqual(memcached._classify_key("laravel_session_x"), "session")
        self.assertEqual(memcached._classify_key("api_key:prod"), "apikey")
        self.assertEqual(memcached._classify_key("user_password"), "apikey")
        self.assertEqual(memcached._classify_key("jwt_refresh"), "auth")
        self.assertEqual(memcached._classify_key("oauth_bearer"), "auth")
        self.assertEqual(memcached._classify_key("render_cache:123"), "")


class UdpAmpProbe(unittest.TestCase):
    def test_frame_header_shape(self):
        # 8-byte header: request_id, seq_num=0, num_datagrams=1, reserved=0
        # + payload verbatim.
        f = memcached._udp_frame(b"stats\r\n", request_id=0xBEEF)
        req_id, seq, nd, res = struct.unpack("!HHHH", f[:8])
        self.assertEqual(req_id, 0xBEEF)
        self.assertEqual(seq, 0)
        self.assertEqual(nd, 1)
        self.assertEqual(res, 0)
        self.assertEqual(f[8:], b"stats\r\n")

    def test_udp_amplification_measured(self):
        # Simulate a memcached UDP responder: parses the 8-byte header, echoes
        # request_id in the reply header, num_datagrams=1, then a fat body big
        # enough to trigger amp_ratio >= 2.0.
        body = b"STAT curr_items 10000\r\nSTAT bytes 987654321\r\nEND\r\n" * 6

        def handler(data):
            if len(data) < 8:
                return None
            req_id, _seq, _nd, _res = struct.unpack("!HHHH", data[:8])
            return struct.pack("!HHHH", req_id, 0, 1, 0) + body

        port = _serve_udp(handler)
        r = memcached.udp_stats_probe("127.0.0.1", port, timeout=1.5)
        self.assertTrue(r["responded"])
        self.assertEqual(r["num_datagrams"], 1)
        self.assertEqual(r["response_bytes"], 8 + len(body))
        self.assertGreater(r["amp_ratio"], 2.0)
        self.assertEqual(r["error"], "")

    def test_udp_no_reply_is_not_a_crash(self):
        # A port with nothing listening on UDP: probe returns cleanly with
        # responded=False and an error message. No exception, ever.
        r = memcached.udp_stats_probe("127.0.0.1", 1, timeout=0.3)
        self.assertFalse(r["responded"])
        self.assertEqual(r["response_bytes"], 0)
        self.assertEqual(r["amp_ratio"], 0.0)


class ProbeEndToEnd(unittest.TestCase):
    """A modern memcached simulator: `metadump`, multi-`get`, and UDP `stats`
    all answer per protocol.txt."""

    def setUp(self):
        session_payload = b"user_id=42;role=admin;expires=1700000000"
        api_payload = b"sk-live-XXXX"
        self.session_payload = session_payload
        self.api_payload = api_payload

        def tcp_handle(conn):
            buf = b""
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    cmd = line.decode().strip()
                    if cmd == "version":
                        conn.sendall(b"VERSION 1.6.9\r\n")
                    elif cmd == "stats":
                        conn.sendall(b"STAT version 1.6.9\r\n"
                                     b"STAT curr_items 3\r\n"
                                     b"STAT pointer_size 64\r\n"
                                     b"STAT bytes 128\r\nEND\r\n")
                    elif cmd == "stats items":
                        conn.sendall(b"STAT items:1:number 3\r\nEND\r\n")
                    elif cmd.startswith("stats cachedump"):
                        conn.sendall(b"ITEM PHPSESSID_abc [40 b; 0 s]\r\n"
                                     b"ITEM api_key:live [12 b; 0 s]\r\n"
                                     b"ITEM render_cache:home [1024 b; 0 s]\r\n"
                                     b"END\r\n")
                    elif cmd == "lru_crawler metadump all":
                        # Include one extra key not seen by cachedump - proves
                        # metadump is being merged into sample_keys.
                        conn.sendall(
                            b"key=PHPSESSID_abc exp=1700 la=0 cas=1 fetch=1 "
                            b"cls=1 size=40\r\n"
                            b"key=api_key%3Alive exp=-1 la=0 cas=2 fetch=0 "
                            b"cls=1 size=12\r\n"
                            b"key=render_cache%3Ahome exp=0 la=0 cas=3 fetch=0 "
                            b"cls=1 size=1024\r\n"
                            b"key=jwt_refresh%3Auser42 exp=-1 la=0 cas=4 fetch=0 "
                            b"cls=1 size=180\r\n"
                            b"END\r\n")
                    elif cmd.startswith("get "):
                        picks = cmd[4:].split()
                        parts = []
                        table = {"PHPSESSID_abc": session_payload,
                                 "api_key:live": api_payload,
                                 "jwt_refresh:user42": b"eyJ.abc.def",
                                 "render_cache:home": b"<html>...</html>"}
                        for k in picks:
                            v = table.get(k)
                            if v is not None:
                                parts.append(
                                    f"VALUE {k} 0 {len(v)}\r\n".encode() + v + b"\r\n")
                        parts.append(b"END\r\n")
                        conn.sendall(b"".join(parts))
                    else:
                        conn.sendall(b"ERROR\r\n")

        def udp_handle(data):
            if len(data) < 8:
                return None
            req_id = struct.unpack("!H", data[:2])[0]
            body = b"STAT version 1.6.9\r\nSTAT curr_items 3\r\nEND\r\n" * 4
            return struct.pack("!HHHH", req_id, 0, 1, 0) + body

        self.tcp_port = _serve_tcp(tcp_handle)
        self.udp_port = _serve_udp(udp_handle)

    def test_probe_returns_values_and_metadump_and_udp(self):
        # Use the TCP port for the text probe; independently point the UDP
        # probe at our UDP responder (probe() reuses the same port number,
        # which won't be listening on UDP, so we validate that piece via
        # udp_stats_probe() directly here).
        pr = memcached.probe("127.0.0.1", self.tcp_port, timeout=2.0)
        self.assertTrue(pr["unauth"])
        self.assertEqual(pr["version"], "1.6.9")
        self.assertTrue(pr["metadump_supported"])
        # metadump-only key was merged in
        self.assertIn("jwt_refresh:user42", pr["sample_keys"])
        # value fetch happened and preserved payload
        got = {v["key"]: v["preview"] for v in pr["sample_values"]}
        self.assertIn("PHPSESSID_abc", got)
        self.assertEqual(got["PHPSESSID_abc"], self.session_payload.decode())
        # sensitive-shape classification present
        self.assertEqual(pr["sensitive_key_tags"].get("PHPSESSID_abc"), "session")
        self.assertEqual(pr["sensitive_key_tags"].get("api_key:live"), "apikey")
        self.assertEqual(pr["sensitive_key_tags"].get("jwt_refresh:user42"), "auth")
        # udp field is populated (even if the target UDP port isn't listening
        # under tcp_port, the field shape must be honest, not missing)
        self.assertIn("responded", pr["udp"])

    def test_findings_include_values_readable(self):
        pr = memcached.probe("127.0.0.1", self.tcp_port, timeout=2.0)
        fs = memcached.findings([_host(self.tcp_port)],
                                {("127.0.0.1", self.tcp_port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("memcached_values_readable", kinds)
        crit = [f for f in fs if f["kind"] == "memcached_values_readable"]
        self.assertEqual(crit[0]["severity"], "critical")
        # sensitive tag surfaces in the detail so the report is honest about what leaked
        self.assertIn("session", crit[0]["detail"])
        # findings-to-vulns still round-trips
        self.assertTrue(memcached.findings_to_vulns(fs))

    def test_udp_amplification_finding_only_when_measured(self):
        # Direct UDP probe against our UDP responder - should produce a
        # confirmed amplification finding (amp_ratio >= 2.0).
        udp_result = memcached.udp_stats_probe("127.0.0.1", self.udp_port,
                                               timeout=1.5)
        self.assertTrue(udp_result["responded"])
        pr = {"unauth": True, "version": "1.6.9", "items": 0,
              "sample_keys": [], "sample_values": [],
              "sensitive_key_tags": {}, "udp": udp_result}
        fs = memcached.findings([_host(self.udp_port)],
                                {("127.0.0.1", self.udp_port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("memcached_udp_amplification", kinds)
        # And a probe against a UDP-closed port must NOT emit the finding
        # (measurement-only; no inference).
        pr2 = {"unauth": True, "version": "1.6.9", "items": 0,
               "sample_keys": [], "sample_values": [],
               "sensitive_key_tags": {},
               "udp": {"responded": False, "request_bytes": 15,
                       "response_bytes": 0, "amp_ratio": 0.0,
                       "num_datagrams": 0, "error": "no reply"}}
        fs2 = memcached.findings([_host(self.udp_port)],
                                 {("127.0.0.1", self.udp_port): pr2})
        self.assertNotIn("memcached_udp_amplification",
                         {f["kind"] for f in fs2})


if __name__ == "__main__":
    unittest.main()
