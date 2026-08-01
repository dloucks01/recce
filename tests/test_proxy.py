"""Proxy / pivot awareness (P1) — config, proxy-safe scanner profile, UDP honesty.

CRITICAL: proxy state is a process global; every test here MUST reset() it in tearDown,
or a leaked active-proxy state flips the rest of the suite to -sT and breaks it."""

import io
import os
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace

from recce import proxy, scanner
from recce.scanner import ScanProfile


class ProxyBase(unittest.TestCase):
    def tearDown(self):
        proxy.reset()
        os.environ.pop("RECCE_PROXIED", None)


class ParseTest(ProxyBase):
    def test_parse_socks5h_with_creds(self):
        c = proxy.parse("socks5h://bob:s3cr3t@10.0.0.1:1080")
        self.assertEqual((c["scheme"], c["host"], c["port"]), ("socks5h", "10.0.0.1", 1080))
        self.assertEqual((c["user"], c["password"]), ("bob", "s3cr3t"))

    def test_parse_all_supported_schemes(self):
        for url in ("socks5://h:1", "socks5h://h:1", "socks4a://h:1",
                    "socks4://h:1", "http://h:1"):
            self.assertTrue(proxy.parse(url)["host"] == "h")

    def test_bad_scheme_rejected(self):
        with self.assertRaises(proxy.ProxyError):
            proxy.parse("ftp://h:1")

    def test_missing_port_rejected(self):
        with self.assertRaises(proxy.ProxyError):
            proxy.parse("socks5h://h")


class StateTest(ProxyBase):
    def test_direct_by_default(self):
        self.assertFalse(proxy.is_active())
        self.assertEqual(proxy.describe(), "direct (no proxy)")
        self.assertEqual(proxy.banner_line(), "")

    def test_configure_activates(self):
        proxy.configure("socks5h://127.0.0.1:1080")
        self.assertTrue(proxy.is_active())
        self.assertEqual(proxy.describe(), "socks5h://127.0.0.1:1080")
        self.assertIn("connect-scan mode", proxy.banner_line())

    def test_describe_hides_credentials(self):
        proxy.configure("socks5h://bob:s3cr3t@127.0.0.1:1080")
        self.assertNotIn("s3cr3t", proxy.describe())
        self.assertNotIn("s3cr3t", proxy.banner_line())

    def test_detected_mode(self):
        proxy.configure_detected()
        self.assertTrue(proxy.is_active())
        self.assertEqual(proxy.describe(), "proxychains (detected)")

    def test_already_proxied_via_sentinel(self):
        os.environ["RECCE_PROXIED"] = "1"
        self.assertTrue(proxy.already_proxied())

    def test_already_proxied_via_ld_preload(self):
        old = os.environ.get("LD_PRELOAD")
        os.environ["LD_PRELOAD"] = "/usr/lib/libproxychains4.so"
        try:
            self.assertTrue(proxy.already_proxied())
        finally:
            if old is None:
                os.environ.pop("LD_PRELOAD", None)
            else:
                os.environ["LD_PRELOAD"] = old


class ProxychainsConfTest(ProxyBase):
    def test_socks5h_maps_to_socks5(self):
        c = proxy.parse("socks5h://10.0.0.1:1080")
        self.assertEqual(proxy._pc_proxy_line(c), "socks5 10.0.0.1 1080")

    def test_socks4a_maps_to_socks4_and_http_stays(self):
        self.assertTrue(proxy._pc_proxy_line(proxy.parse("socks4a://h:1")).startswith("socks4 "))
        self.assertTrue(proxy._pc_proxy_line(proxy.parse("http://h:8080")).startswith("http "))

    def test_creds_appended(self):
        c = proxy.parse("socks5://h:1080")
        c["user"], c["password"] = "bob", "pw"
        self.assertEqual(proxy._pc_proxy_line(c), "socks5 h 1080 bob pw")

    def test_conf_written(self):
        import tempfile
        c = proxy.parse("socks5h://10.0.0.1:1080")
        with tempfile.TemporaryDirectory() as d:
            path = proxy.write_proxychains_conf(c, os.path.join(d, "pc.conf"))
            text = open(path).read()
        self.assertIn("proxy_dns", text)          # remote DNS (no leak)
        self.assertIn("[ProxyList]", text)
        self.assertIn("socks5 10.0.0.1 1080", text)

    def test_reexec_argv_shape(self):
        import sys
        old = sys.argv
        sys.argv = ["recce", "run", "10.0.0.1", "--proxy", "socks5h://127.0.0.1:1080"]
        try:
            argv = proxy.reexec_argv("/tmp/pc.conf", "/usr/bin/proxychains4")
        finally:
            sys.argv = old
        self.assertEqual(argv[:4], ["/usr/bin/proxychains4", "-f", "/tmp/pc.conf", sys.executable])
        self.assertEqual(argv[4:6], ["-m", "recce"])
        self.assertIn("run", argv)


class ScannerSafetyTest(ProxyBase):
    def test_scan_type_forced_connect_when_proxied(self):
        proxy.configure("socks5h://127.0.0.1:1080")
        self.assertEqual(scanner._scan_type(), "-sT")   # never -sS through a proxy

    def test_scan_type_normal_when_direct(self):
        # direct: whatever root gives us (both are valid; just must not be forced by proxy)
        self.assertIn(scanner._scan_type(), ("-sS", "-sT"))

    def test_harden_disables_raw_and_udp(self):
        proxy.configure("socks5h://127.0.0.1:1080")
        p = ScanProfile(name="standard", scanner="masscan", udp_basic=True, udp_top=100,
                        udp_fallback=True, ping_discovery=True)
        scanner.harden_for_proxy(p)
        self.assertEqual(p.scanner, "nmap")             # masscan can't be proxied
        self.assertFalse(p.udp_basic)
        self.assertEqual(p.udp_top, 0)
        self.assertFalse(p.udp_fallback)
        self.assertFalse(p.ping_discovery)              # ICMP bypasses -> -Pn
        self.assertTrue(p.assume_up)

    def test_harden_is_noop_when_direct(self):
        p = ScanProfile(name="standard", scanner="masscan", udp_basic=True)
        scanner.harden_for_proxy(p)
        self.assertEqual(p.scanner, "masscan")          # untouched without a proxy
        self.assertTrue(p.udp_basic)

    def test_udp_liveness_probe_skipped_when_proxied(self):
        import tempfile
        proxy.configure("socks5h://127.0.0.1:1080")
        with tempfile.TemporaryDirectory() as d:
            _, issue = scanner.udp_liveness_probe("10.0.0.1", os.path.join(d, "u.xml"),
                                                  ScanProfile())
        self.assertIsNotNone(issue)
        self.assertIn("UDP can't traverse the proxy", issue.message)


class HonestyTest(ProxyBase):
    def test_snmp_command_skips_with_honest_message(self):
        from recce import cli
        proxy.configure("socks5h://127.0.0.1:1080")
        args = SimpleNamespace(output_dir="/nonexistent-should-not-be-touched")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.cmd_snmp(args)
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("UDP-only", out)
        self.assertIn("skipped", out)

    def test_mssql_sql_browser_skips_when_proxied(self):
        from recce import mssql
        proxy.configure("socks5h://127.0.0.1:1080")
        # No socket is created; returns [] immediately (TCP 1433 enum still works).
        self.assertEqual(mssql.sql_browser("10.0.0.1"), [])

    def test_markdown_carries_proxy_note(self):
        import tempfile
        from recce.report_markdown import build_markdown
        from recce.models import Host
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.md")
            build_markdown([Host(ip="10.0.0.1")], out, title="T",
                           proxy_note="socks5h://127.0.0.1:1080")
            text = open(out).read()
        self.assertIn("Scanned via proxy", text)
        self.assertIn("socks5h://127.0.0.1:1080", text)


class SetupProxyFlowTest(ProxyBase):
    def _args(self, **kw):
        return SimpleNamespace(proxy=kw.get("proxy"), output_dir=kw.get("output_dir"))

    def test_no_proxy_no_wrap_is_noop(self):
        from recce import cli
        self.assertIsNone(cli._setup_proxy(self._args()))
        self.assertFalse(proxy.is_active())

    def test_bad_url_exits_2(self):
        from recce import cli
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli._setup_proxy(self._args(proxy="ftp://h:1"))
        self.assertEqual(rc, 2)

    def test_detected_wrap_enables_safe_mode(self):
        from recce import cli
        os.environ["RECCE_PROXIED"] = "1"          # pretend we're the re-exec'd child
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli._setup_proxy(self._args())    # no --proxy, but wrapped
        self.assertIsNone(rc)
        self.assertTrue(proxy.is_active())
        self.assertIn("PROXY", buf.getvalue())

    def test_missing_proxychains_exits_2(self):
        from recce import cli
        orig = proxy.proxychains_bin
        proxy.proxychains_bin = lambda: ""          # simulate not installed
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli._setup_proxy(self._args(proxy="socks5h://127.0.0.1:1080"))
        finally:
            proxy.proxychains_bin = orig
        self.assertEqual(rc, 2)
        self.assertIn("proxychains4", buf.getvalue())

    def test_reexec_path_reached_when_ready(self):
        from recce import cli
        import tempfile
        orig_bin, orig_reach, orig_exec = (proxy.proxychains_bin, proxy.reachable,
                                           proxy.reexec_under_proxychains)
        calls = {}
        proxy.proxychains_bin = lambda: "/usr/bin/proxychains4"
        proxy.reachable = lambda cfg, timeout=6.0: True
        proxy.reexec_under_proxychains = lambda conf: calls.__setitem__("conf", conf)
        try:
            with tempfile.TemporaryDirectory() as d:
                buf = io.StringIO()
                with redirect_stdout(buf):
                    cli._setup_proxy(self._args(proxy="socks5h://127.0.0.1:1080",
                                                output_dir=d))
                self.assertIn("conf", calls)               # re-exec was invoked
                self.assertTrue(os.path.exists(calls["conf"]))  # conf was written
        finally:
            proxy.proxychains_bin, proxy.reachable = orig_bin, orig_reach
            proxy.reexec_under_proxychains = orig_exec


if __name__ == "__main__":
    unittest.main()
