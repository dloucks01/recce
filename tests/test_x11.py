"""Tests for recce.services.x11 — handshake + T2 safe proof-of-exploit.

Every test drives a loopback TCP responder that replays canned X protocol
wire bytes (X §8 setup + §9 GetGeometry). Nothing here calls recce encoders
to build the fixtures — the bytes are hand-constructed from the spec so the
tests break if the parser silently drifts.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import x11


# ---------------------------------------------------------------------------
# Wire fixtures (all multi-byte fields big-endian: client sent 'B').
# ---------------------------------------------------------------------------

# 8-byte Setup Success header: status=1, major=11, minor=0, addl=18 units
# (=> 72 bytes of additional data follow).
_SETUP_SUCCESS_HDR = struct.pack(">BBHHH", 0x01, 0x00, 11, 0, 18)

# 72 bytes of additional data.  vendor_len=0, num_formats=0 means the SCREEN
# starts immediately after the 32-byte fixed prefix.  Root window id is
# 0x0000012A, screen is 1920x1080 at depth 24.
_ROOT_WINDOW = 0x0000012A
_SETUP_SUCCESS_BODY = (
    struct.pack(">IIII", 100, 0, 0, 0)          # release, rid_base, rid_mask, motion_buf
    + struct.pack(">HH", 0, 4096)               # vendor_len, max_req_len
    + bytes([1, 0, 0, 0, 8, 32, 8, 255])        # roots, formats, byteord*2, unit, pad, kc, kc
    + b"\x00" * 4                                # 4 unused bytes -> offset 32
    # SCREEN (40 bytes):
    + struct.pack(">I", _ROOT_WINDOW)           # root
    + struct.pack(">III", 0, 0x00FFFFFF, 0)     # default_cmap, white, black
    + struct.pack(">I", 0)                       # current_input_masks
    + struct.pack(">HHHH", 1920, 1080, 0, 0)    # width_px, height_px, w_mm, h_mm
    + struct.pack(">HH", 0, 0)                  # min_maps, max_maps
    + struct.pack(">I", 0x00000021)             # root_visual
    + bytes([0, 0, 24, 0])                      # backing, save_unders, depth, num_depths
)
assert len(_SETUP_SUCCESS_BODY) == 72

# 32-byte GetGeometry Reply for the root window above.
_GEOM_REPLY = (
    bytes([0x01, 24])                            # Reply, depth=24
    + struct.pack(">H", 1)                       # sequence
    + struct.pack(">I", 0)                       # reply_length (no extra bytes)
    + struct.pack(">I", _ROOT_WINDOW)            # root
    + struct.pack(">hhHHH", 0, 0, 1920, 1080, 0) # x, y, width, height, border
    + b"\x00" * 10                               # unused
)
assert len(_GEOM_REPLY) == 32

# Setup Failed header (status=0), 3-byte reason len ("no").
_SETUP_FAILED = struct.pack(">BBHHH", 0x00, 3, 11, 0, 1) + b"no\x00"


# ---------------------------------------------------------------------------
# Loopback X server (scripted).
# ---------------------------------------------------------------------------

class _XServer:
    """Replays a scripted list of (min_bytes_to_read, bytes_to_send) turns.

    - Reads at least ``min_bytes_to_read`` before sending (0 = send immediately).
    - After the last turn, closes the connection.
    """

    def __init__(self, script: list[tuple[int, bytes]]):
        self._script = script
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(2)
        self.host, self.port = self._sock.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(2.0)
                for need, payload in self._script:
                    got = 0
                    while got < need:
                        try:
                            chunk = conn.recv(need - got)
                        except (socket.timeout, OSError):
                            break
                        if not chunk:
                            break
                        got += len(chunk)
                    if payload:
                        try:
                            conn.sendall(payload)
                        except OSError:
                            break
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


# ---------------------------------------------------------------------------
# Wire / parser
# ---------------------------------------------------------------------------

class SetupInfoParseTest(unittest.TestCase):
    def test_extracts_first_screen_root_and_geometry(self):
        info = x11._parse_setup_success(_SETUP_SUCCESS_BODY)
        self.assertIsNotNone(info)
        self.assertEqual(info["root"], _ROOT_WINDOW)
        self.assertEqual(info["width"], 1920)
        self.assertEqual(info["height"], 1080)
        self.assertEqual(info["depth"], 24)
        self.assertEqual(info["screens"], 1)

    def test_short_body_returns_none(self):
        self.assertIsNone(x11._parse_setup_success(b"\x00" * 16))

    def test_zero_screens_returns_none(self):
        # Same prefix but num_roots byte forced to 0.
        body = bytearray(_SETUP_SUCCESS_BODY)
        body[20] = 0
        self.assertIsNone(x11._parse_setup_success(bytes(body)))


class GetGeometryReplyTest(unittest.TestCase):
    def test_error_reply_is_rejected(self):
        # Type=0 == Error.  A live server saying "no" must NOT count as a T2
        # proof.
        srv_sock, cli_sock = socket.socketpair()
        try:
            # Preload the error reply into the "peer" side of the pair.
            srv_sock.sendall(b"\x00" + b"\x00" * 31)
            self.assertIsNone(x11._get_geometry(cli_sock, _ROOT_WINDOW, 1.0))
        finally:
            srv_sock.close()
            cli_sock.close()

    def test_reply_is_parsed(self):
        srv_sock, cli_sock = socket.socketpair()
        try:
            srv_sock.sendall(_GEOM_REPLY)
            geom = x11._get_geometry(cli_sock, _ROOT_WINDOW, 1.0)
        finally:
            srv_sock.close()
            cli_sock.close()
        self.assertIsNotNone(geom)
        self.assertEqual(geom["root"], _ROOT_WINDOW)
        self.assertEqual(geom["width"], 1920)
        self.assertEqual(geom["height"], 1080)
        self.assertEqual(geom["depth"], 24)


# ---------------------------------------------------------------------------
# Live probe against loopback servers.
# ---------------------------------------------------------------------------

class ProbeTest(unittest.TestCase):
    def test_vulnerable_server_promotes_with_geometry(self):
        # Turn 1: read 12-byte client setup, reply with Success header+body.
        # Turn 2: read 8-byte GetGeometry, reply with 32-byte geometry.
        srv = _XServer([
            (12, _SETUP_SUCCESS_HDR + _SETUP_SUCCESS_BODY),
            (8, _GEOM_REPLY),
        ])
        try:
            pr = x11.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["accepted"])
        geom = pr.get("screen_geometry")
        self.assertIsNotNone(geom)
        self.assertEqual(geom["root"], _ROOT_WINDOW)
        self.assertEqual(geom["width"], 1920)
        self.assertEqual(geom["height"], 1080)
        self.assertEqual(geom["depth"], 24)

    def test_patched_server_stays_t1(self):
        srv = _XServer([(12, _SETUP_FAILED)])
        try:
            pr = x11.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["accepted"])
        # T2 proof requires status=Success; refused handshake must not have it.
        self.assertNotIn("screen_geometry", pr)

    def test_unreachable_stays_quiet(self):
        # Bind then immediately close to guarantee a port with nothing on it.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        _, port = s.getsockname()
        s.close()
        pr = x11.probe("127.0.0.1", port, timeout=1.0)
        self.assertFalse(pr["reachable"])
        self.assertNotIn("screen_geometry", pr)

    def test_accepts_setup_but_no_geometry_reply_stays_t1_shape(self):
        # Server sends the Success handshake but hangs up before answering
        # GetGeometry — probe must degrade gracefully to a T1 shape.
        srv = _XServer([(12, _SETUP_SUCCESS_HDR + _SETUP_SUCCESS_BODY)])
        try:
            pr = x11.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(pr["accepted"])
        self.assertNotIn("screen_geometry", pr)


# ---------------------------------------------------------------------------
# Findings emission — depth_tier promotion is the audit's contract.
# ---------------------------------------------------------------------------

class FindingsTest(unittest.TestCase):
    def _host(self):
        return Host(ip="10.9.8.7",
                    ports=[Port(portid=6000, protocol="tcp", state="open",
                                service="x11")])

    def test_geometry_proof_upgrades_to_t2(self):
        h = self._host()
        probes = {("10.9.8.7", 6000): {
            "reachable": True, "accepted": True,
            "major": 11, "minor": 0,
            "screen_geometry": {"root": _ROOT_WINDOW, "width": 1920,
                                "height": 1080, "depth": 24, "screens": 1},
        }}
        fs = x11.findings([h], probes)
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual(f["kind"], "x11_open")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["depth_tier"], "t2")
        # The proof lands both in detail (for CLI readers) and in output
        # (structured evidence the tester can quote back).
        self.assertIn("GetGeometry", f["detail"])
        self.assertIn("1920", f["output"])
        self.assertIn("1080", f["output"])
        self.assertIn(f"0x{_ROOT_WINDOW:08x}", f["output"])

    def test_no_geometry_keeps_t1(self):
        h = self._host()
        probes = {("10.9.8.7", 6000): {
            "reachable": True, "accepted": True, "major": 11, "minor": 0,
        }}
        fs = x11.findings([h], probes)
        self.assertEqual(fs[0]["depth_tier"], "t1")
        self.assertEqual(fs[0]["output"], "")

    def test_refused_handshake_still_low_present_finding(self):
        h = self._host()
        probes = {("10.9.8.7", 6000): {
            "reachable": True, "accepted": False, "major": 11, "minor": 0,
        }}
        fs = x11.findings([h], probes)
        self.assertEqual(fs[0]["kind"], "x11_present")
        self.assertEqual(fs[0]["severity"], "low")


if __name__ == "__main__":
    unittest.main()
