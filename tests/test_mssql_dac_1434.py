"""SAFE detection of a network-reachable MSSQL Dedicated Admin Connection.

The Dedicated Admin Connection (DAC) is a sysadmin-only diagnostic TDS endpoint
that SQL Server ships loopback-only; making it network-reachable requires
`sp_configure 'remote admin connections', 1`. Two signals reveal it off-box:

  * The SQL Browser (UDP 1434) answers CLNT_UCAST_DAC (MS-SQLR 2.2.1 / 2.2.5)
    with the DAC's dynamic TCP port for the instance. Response frame:
    SVR_RESP=0x05, LE payload size = 3, then protocol version 0x01, then LE
    uint16 port.
  * TCP 1434 (the default-instance DAC port) answers a TDS PRELOGIN.

Both are read-only single round-trips. We NEVER auth to the DAC — a failed
auth there is a very high-signal defender event. All network is faked.
"""

from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

from recce.core import proxy
from recce.services.db import mssql


def _dac_svr_resp(port: int) -> bytes:
    """Wire-derived CLNT_UCAST_DAC response: 0x05 <size_le=3> 0x01 <port_le>."""
    return b"\x05" + struct.pack("<H", 3) + b"\x01" + struct.pack("<H", port)


class BuildAndParseUCastDac(unittest.TestCase):
    """Wire format of the CLNT_UCAST_DAC exchange."""

    def test_request_default_instance(self):
        req = mssql._build_ucast_dac("")
        # 0x0F (message type) + 0x01 (protocol version) + null terminator.
        self.assertEqual(req, b"\x0f\x01\x00")

    def test_request_named_instance(self):
        req = mssql._build_ucast_dac("SQLEXPRESS")
        self.assertTrue(req.startswith(b"\x0f\x01"))
        self.assertTrue(req.endswith(b"\x00"))
        self.assertIn(b"SQLEXPRESS", req)

    def test_parse_valid_dac_port(self):
        self.assertEqual(mssql._parse_ucast_dac(_dac_svr_resp(1434)), 1434)
        self.assertEqual(mssql._parse_ucast_dac(_dac_svr_resp(52913)), 52913)

    def test_parse_rejects_non_svrresp(self):
        # A stray TDS packet (0x04) must not be misread as a DAC advert.
        self.assertEqual(
            mssql._parse_ucast_dac(b"\x04\x03\x00\x01\x9a\x05"), 0)

    def test_parse_rejects_ucast_ex_response(self):
        # The classic CLNT_UCAST_EX answer (long ASCII payload) shares the
        # 0x05 header — refuse to interpret it as a DAC port.
        payload = b"ServerName;WIN\x00"
        wire = b"\x05" + struct.pack("<H", len(payload)) + payload
        self.assertEqual(mssql._parse_ucast_dac(wire), 0)

    def test_parse_rejects_wrong_protocol_version(self):
        wire = b"\x05" + struct.pack("<H", 3) + b"\x02" + struct.pack("<H", 1434)
        self.assertEqual(mssql._parse_ucast_dac(wire), 0)

    def test_parse_rejects_short_buffer(self):
        self.assertEqual(mssql._parse_ucast_dac(b""), 0)
        self.assertEqual(mssql._parse_ucast_dac(b"\x05\x03\x00"), 0)

    def test_parse_rejects_zero_port(self):
        # A zero port means the browser had no DAC info to give.
        self.assertEqual(mssql._parse_ucast_dac(_dac_svr_resp(0)), 0)


class SqlBrowserDacProbe(unittest.TestCase):
    """The UDP probe against 1434: bounded timeout, one datagram in / out,
    proxy-aware. All socket calls faked."""

    def setUp(self):
        proxy.reset()

    def tearDown(self):
        proxy.reset()

    def test_returns_port_when_advertised(self):
        class FakeSock:
            def __init__(self, *a, **kw): self.sent = None
            def settimeout(self, t): self.t = t
            def sendto(self, data, addr):
                self.sent = (data, addr)
            def recvfrom(self, n):
                return _dac_svr_resp(51888), ("10.0.0.1", 1434)
            def close(self): pass
        fake = FakeSock()
        with patch("socket.socket", return_value=fake):
            port = mssql.sql_browser_dac("10.0.0.1", "SQLEXPRESS", timeout=2.0)
        self.assertEqual(port, 51888)
        # One datagram, addressed to UDP 1434, carrying the CLNT_UCAST_DAC
        # request for the named instance.
        self.assertEqual(fake.sent[1], ("10.0.0.1", mssql.SQLBROWSER_PORT))
        self.assertEqual(fake.sent[0], b"\x0f\x01SQLEXPRESS\x00")

    def test_returns_zero_on_socket_error(self):
        class FakeSock:
            def __init__(self, *a, **kw): pass
            def settimeout(self, t): pass
            def sendto(self, *a, **kw): raise OSError("no route to host")
            def recvfrom(self, n): return b"", None
            def close(self): pass
        with patch("socket.socket", return_value=FakeSock()):
            self.assertEqual(mssql.sql_browser_dac("10.0.0.1"), 0)

    def test_returns_zero_when_browser_answers_but_dac_disabled(self):
        # DAC-disabled browser may reply with a size!=3 or 0-port payload.
        class FakeSock:
            def __init__(self, *a, **kw): pass
            def settimeout(self, t): pass
            def sendto(self, *a, **kw): pass
            def recvfrom(self, n):
                return _dac_svr_resp(0), ("x", 0)
            def close(self): pass
        with patch("socket.socket", return_value=FakeSock()):
            self.assertEqual(mssql.sql_browser_dac("10.0.0.1"), 0)

    def test_skipped_when_proxy_active(self):
        proxy.configure("socks5://127.0.0.1:9050")
        called = {"n": 0}
        def fake_socket(*a, **kw):
            called["n"] += 1
            raise AssertionError("must not touch the socket under proxy")
        with patch("socket.socket", side_effect=fake_socket):
            self.assertEqual(mssql.sql_browser_dac("10.0.0.1"), 0)
        self.assertEqual(called["n"], 0)


class DacTcpAnswersPrelogin(unittest.TestCase):
    """The TCP side of the check reuses the existing prelogin() probe."""

    def test_true_when_prelogin_returns_version(self):
        with patch.object(mssql, "prelogin",
                          return_value={"version": "15.0.4335"}):
            self.assertTrue(
                mssql.dac_tcp_answers_prelogin("10.0.0.1"))

    def test_false_when_prelogin_empty(self):
        with patch.object(mssql, "prelogin", return_value={}):
            self.assertFalse(
                mssql.dac_tcp_answers_prelogin("10.0.0.1"))

    def test_targets_tcp_1434_by_default(self):
        calls = []
        def fake_pre(ip, port, timeout=4.0):
            calls.append((ip, port))
            return {}
        with patch.object(mssql, "prelogin", side_effect=fake_pre):
            mssql.dac_tcp_answers_prelogin("10.0.0.1")
        self.assertEqual(calls, [("10.0.0.1", mssql.SQLBROWSER_PORT)])


class ProbeDacExposure(unittest.TestCase):
    """The combined probe: SAFE, no auth, uses both signals."""

    def test_vulnerable_target_reports_both_signals(self):
        # (a) DAC advertised by browser AND TCP 1434 answers TDS PRELOGIN.
        with patch.object(mssql, "sql_browser",
                          return_value=[{"instance": "SQLEXPRESS"}]), \
             patch.object(mssql, "sql_browser_dac", return_value=51888), \
             patch.object(mssql, "dac_tcp_answers_prelogin",
                          return_value=True):
            r = mssql.probe_dac_exposure("10.0.0.1")
        self.assertEqual(r["advertised"],
                         [{"instance": "SQLEXPRESS", "port": 51888}])
        self.assertTrue(r["tcp_1434_tds"])

    def test_absent_target_yields_no_signals(self):
        # (b) Patched / DAC disabled — browser returns 0, TCP 1434 silent.
        with patch.object(mssql, "sql_browser",
                          return_value=[{"instance": "DEFAULT"}]), \
             patch.object(mssql, "sql_browser_dac", return_value=0), \
             patch.object(mssql, "dac_tcp_answers_prelogin",
                          return_value=False):
            r = mssql.probe_dac_exposure("10.0.0.1")
        self.assertEqual(r["advertised"], [])
        self.assertFalse(r["tcp_1434_tds"])

    def test_uses_supplied_instances_without_second_browser_call(self):
        called = {"n": 0}
        def fake_browser(*a, **kw):
            called["n"] += 1
            return []
        with patch.object(mssql, "sql_browser", side_effect=fake_browser), \
             patch.object(mssql, "sql_browser_dac", return_value=0), \
             patch.object(mssql, "dac_tcp_answers_prelogin",
                          return_value=False):
            mssql.probe_dac_exposure(
                "10.0.0.1", instances=[{"instance": "SQLEXPRESS"}])
        self.assertEqual(called["n"], 0)


class DacExposedFinding(unittest.TestCase):
    """The finding: medium, depth_tier=t1, CWE-306, stable kind, never
    suggests an auth attempt against the DAC."""

    def _tgt(self):
        return {"ip": "10.0.0.7", "port": 1433}

    def test_vulnerable_browser_advertisement_emits_finding(self):
        probe = {"advertised": [{"instance": "SQLEXPRESS", "port": 51888}],
                 "tcp_1434_tds": False}
        f = mssql.dac_exposed_finding(self._tgt(), probe)
        self.assertIsNotNone(f)
        self.assertEqual(f["kind"], "mssql_dac_exposed")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f.get("depth_tier"), "t1")
        self.assertIn("CWE-306", f["cwes"])
        self.assertIn("51888", f["detail"])
        self.assertIn("SQLEXPRESS", f["detail"])
        # Narrative wired for the report.
        self.assertIn("dedicated admin connection", f["narrative"].lower())
        # exploit_note must not push an auth attempt on the DAC.
        low = f["exploit_note"].lower()
        for banned in ("impacket-mssqlclient", "login", "sqlcmd",
                       "sp_configure", "xp_cmdshell", "spray"):
            self.assertNotIn(banned, low)

    def test_vulnerable_tcp_1434_only_emits_finding(self):
        # Default-instance DAC on TCP 1434 with no browser advert.
        probe = {"advertised": [], "tcp_1434_tds": True}
        f = mssql.dac_exposed_finding(self._tgt(), probe)
        self.assertIsNotNone(f)
        self.assertIn("1434", f["detail"])

    def test_patched_or_absent_no_finding(self):
        # (b) Neither signal fired -> no finding at all.
        for probe in (
            {"advertised": [], "tcp_1434_tds": False},
            {},
            None,
        ):
            self.assertIsNone(mssql.dac_exposed_finding(self._tgt(), probe),
                              f"unexpected finding for probe={probe!r}")

    def test_target_string_uses_ip_and_port(self):
        probe = {"advertised": [{"instance": "", "port": 1434}],
                 "tcp_1434_tds": True}
        f = mssql.dac_exposed_finding(
            {"ip": "192.0.2.9", "port": 14330}, probe)
        self.assertEqual(f["target"], "192.0.2.9:14330")


if __name__ == "__main__":
    unittest.main()
