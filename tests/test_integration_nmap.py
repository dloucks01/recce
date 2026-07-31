"""Real-nmap integration tests.

Everything else in the suite mocks the nmap seam; these tests run the ACTUAL
scanner commands against a real listener on localhost and parse real nmap XML,
so they catch things mocks can't: command-construction mistakes, nmap flag
drift, and parser regressions against real output.

They are skipped automatically where nmap isn't installed (e.g. CI without it),
so the normal suite stays green everywhere; where nmap IS present they exercise
discover -> full port scan -> enum -> vuln (incl. --fast) end to end.
"""

import http.server
import os
import shutil
import socket
import tempfile
import threading
import unittest

from recce import parser, scanner

_HAS_NMAP = shutil.which("nmap") is not None


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _fast_profile() -> scanner.ScanProfile:
    # Small, quick, deterministic: no OS detection, no AD/deep enum, tight timeout.
    return scanner.ScanProfile(name="itest", all_ports=False, top_ports=100,
                               os_detect=False, ad_enrich=False, deep_enum=False,
                               ping_discovery=True, min_rate=2000, host_timeout=2)


@unittest.skipUnless(_HAS_NMAP, "nmap not installed")
class RealNmapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        handler = http.server.SimpleHTTPRequestHandler
        # Quiet the handler's request logging.
        handler.log_message = lambda *a, **k: None
        cls.httpd = http.server.HTTPServer(("127.0.0.1", cls.port), handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.profile = _fast_profile()
        cls.tmp = tempfile.mkdtemp(prefix="recce-itest-")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _xml(self, name):
        return os.path.join(self.tmp, name)

    def test_discover_localhost_is_up(self):
        out, issue = scanner.discover_hosts(
            self._write_targets("127.0.0.1"), self._xml("disc.xml"))
        self.assertIsNone(issue, f"discovery issue: {issue}")
        hosts = parser.parse_nmap_xml(out)
        self.assertIn("127.0.0.1", [h.ip for h in hosts])

    def test_enum_detects_the_open_http_port(self):
        out, issue = scanner.enum_scan("127.0.0.1", [self.port],
                                       self._xml("enum.xml"), self.profile)
        self.assertIsNone(issue, f"enum issue: {issue}")
        host = self._one_host(out)
        opened = {p.portid: p for p in host.ports if p.state == "open"}
        self.assertIn(self.port, opened, "listener port not detected as open")
        # -sV should fingerprint it as http (SimpleHTTPServer speaks HTTP).
        self.assertIn("http", (opened[self.port].service or "").lower())

    def test_vuln_fast_runs_and_parses(self):
        # The --fast tier must build a valid command and produce parseable XML.
        out, issue = scanner.vuln_scan("127.0.0.1", [self.port],
                                       self._xml("vuln.xml"), self.profile,
                                       fast=True)
        self.assertIsNone(issue, f"vuln issue: {issue}")
        host = self._one_host(out)
        self.assertIn(self.port, [p.portid for p in host.ports])

    def test_full_port_scan_finds_the_listener(self):
        # A real full -p- sweep must discover the ephemeral listener port. (--open
        # means nmap emits the host only once it has an open port to report, so we
        # scan all ports rather than a top-N that wouldn't include an ephemeral.)
        prof = _fast_profile()
        prof.all_ports = True
        out, issue = scanner.full_port_scan("127.0.0.1", self._xml("full.xml"), prof)
        self.assertIsNone(issue, f"full-scan issue: {issue}")
        host = self._one_host(out)
        self.assertIn(self.port, [p.portid for p in host.ports if p.state == "open"])

    # --- helpers ----------------------------------------------------------------
    def _write_targets(self, *ips):
        path = self._xml("targets.txt")
        with open(path, "w") as fh:
            fh.write("\n".join(ips) + "\n")
        return path

    def _one_host(self, xml_path):
        hosts = parser.parse_nmap_xml(xml_path)
        self.assertTrue(hosts, f"no hosts parsed from {xml_path}")
        return next(h for h in hosts if h.ip == "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
