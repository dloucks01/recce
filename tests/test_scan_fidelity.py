"""High-fidelity scan/enumeration fidelity suite.

The recurring real-world failure is "an open port is open but recce doesn't report
it." This module guards the whole port lifecycle against that, at two fidelity
levels:

  * Deterministic (always runs): nmap-shaped XML fixtures + the real Store merge,
    covering the exact bugs behind the symptom - open|filtered ports being dropped,
    a re-scan downgrading a confirmed-open port, and masscan scanning a low port
    range instead of nmap's frequency-ranked top-N.
  * Live (skipUnless nmap): stands up REAL TCP listeners on high / non-standard
    ports and drives the actual scanner -> parse -> store path, asserting EVERY
    listening port survives end to end. This is the test that reproduces the
    field symptom instead of trusting a mock.
"""
import os
import shutil
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from recce import parser
from recce import scanner
from recce.models import Host, Port
from recce.store import Store


# --- deterministic nmap-XML fixtures --------------------------------------------

def _xml(ports_xml: str, ip: str = "10.0.0.1") -> str:
    """Wrap <port> rows in a minimal but valid nmap XML document."""
    return ('<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap" start="1">\n'
            f'<host><status state="up" reason="user-set"/>'
            f'<address addr="{ip}" addrtype="ipv4"/><ports>'
            + ports_xml +
            '</ports></host></nmaprun>\n')


def _port_xml(portid: int, state: str, proto: str = "tcp", service: str = "") -> str:
    svc = f'<service name="{service}"/>' if service else ""
    return (f'<port protocol="{proto}" portid="{portid}">'
            f'<state state="{state}" reason="syn-ack"/>{svc}</port>')


def _parse_xml_str(xml_str: str) -> list:
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml_str)
        path = f.name
    try:
        return parser.parse_nmap_xml(path)
    finally:
        os.unlink(path)


class PortStateFidelityTest(unittest.TestCase):
    """The parser keeps open|filtered; everything downstream must treat it as open."""

    def test_open_filtered_counts_as_open(self):
        hosts = _parse_xml_str(_xml(
            _port_xml(80, "open", service="http")
            + _port_xml(161, "open|filtered", proto="udp", service="snmp")
            + _port_xml(22, "filtered")               # genuinely filtered: dropped
            + _port_xml(23, "closed")))               # closed: dropped
        self.assertEqual(len(hosts), 1)
        h = hosts[0]
        # The parser keeps open + open|filtered, drops closed/filtered.
        self.assertEqual(sorted(p.portid for p in h.ports), [80, 161])
        # open_ports (used by 100+ downstream sites) must include the open|filtered one.
        self.assertEqual(sorted(p.portid for p in h.open_ports), [80, 161])
        snmp = next(p for p in h.open_ports if p.portid == 161)
        self.assertTrue(snmp.is_open)
        self.assertEqual(snmp.state, "open|filtered")

    def test_udp_open_filtered_survives_parse_store_report(self):
        # End-to-end: a UDP open|filtered port must reach the workbook, not vanish.
        from recce import report_excel
        h = _parse_xml_str(_xml(_port_xml(161, "open|filtered", proto="udp",
                                          service="snmp")))[0]
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "r.sqlite"))
            st.upsert_host(h)
            back = st.get_host("10.0.0.1")
            st.close()
            self.assertIn(161, [p.portid for p in back.open_ports])
            xlsx = os.path.join(d, "e.xlsx")
            report_excel.build_workbook(st.all_hosts() if False else [back], xlsx)
            self.assertGreater(os.path.getsize(xlsx), 0)

    def test_is_open_single_source_of_truth(self):
        self.assertTrue(Port(portid=1, state="open").is_open)
        self.assertTrue(Port(portid=1, state="open|filtered").is_open)
        self.assertFalse(Port(portid=1, state="filtered").is_open)
        self.assertFalse(Port(portid=1, state="closed").is_open)


class MergeFidelityTest(unittest.TestCase):
    """A re-scan must never lose or downgrade a port the store already has."""

    def _roundtrip(self, *scans: Host) -> Host:
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "r.sqlite"))
            for h in scans:
                st.upsert_host(h, merge=True)
            back = st.get_host(scans[0].ip)
            st.close()
        return back

    def _host(self, *ports: Port) -> Host:
        return Host(ip="10.0.0.5", state="up", up_reason="syn-ack", ports=list(ports))

    def test_rescan_does_not_downgrade_open_to_open_filtered(self):
        # First scan: 161 open. Second scan (UDP flap): 161 open|filtered. The port
        # must remain open, not disappear from open_ports on the second run.
        merged = self._roundtrip(
            self._host(Port(portid=161, protocol="udp", state="open")),
            self._host(Port(portid=161, protocol="udp", state="open|filtered")))
        p = next(p for p in merged.ports if p.portid == 161)
        self.assertEqual(p.state, "open")
        self.assertIn(161, [p.portid for p in merged.open_ports])

    def test_open_filtered_then_open_upgrades(self):
        merged = self._roundtrip(
            self._host(Port(portid=53, protocol="udp", state="open|filtered")),
            self._host(Port(portid=53, protocol="udp", state="open")))
        self.assertEqual(next(p for p in merged.ports if p.portid == 53).state, "open")

    def test_no_port_lost_across_any_scan_order(self):
        # A realistic multi-phase engagement: sweep, enum re-probe (one port flaps to
        # open|filtered), an ingest-style add, and a lossy re-scan that only re-sees a
        # subset. The union of every open port must always survive, in any order.
        import itertools
        sweep = self._host(Port(portid=22, state="open"), Port(portid=80, state="open"),
                           Port(portid=443, state="open"))
        enum = self._host(Port(portid=80, state="open|filtered"))     # flap
        added = self._host(Port(portid=8443, state="open"))           # new port later
        rescan = self._host(Port(portid=22, state="open"))            # partial re-sight
        expected = {22, 80, 443, 8443}
        for order in itertools.permutations([sweep, enum, added, rescan]):
            merged = self._roundtrip(*order)
            got = {p.portid for p in merged.open_ports}
            self.assertEqual(got, expected, f"lost a port for order {[id(o) for o in order]}")


class MasscanTopPortsFidelityTest(unittest.TestCase):
    """masscan must scan nmap's frequency-ranked top-N, not a literal 0..N range."""

    def test_top_tcp_ports_are_frequency_ranked_not_low_range(self):
        top = scanner._top_tcp_ports(200)
        if not top:
            self.skipTest("nmap-services frequency table not available on this box")
        # RDP (3389) and HTTP-alt (8080) are high-frequency but far above 200 - a
        # 0-200 range would miss them; the real top-200 set must include them.
        self.assertIn(3389, top)
        self.assertIn(8080, top)
        self.assertEqual(len(top), 200)
        self.assertTrue(any(p > 200 for p in top), "top-N wrongly bounded to 0-200")

    def test_masscan_spec_covers_high_ports(self):
        spec = scanner._masscan_port_spec(
            scanner.ScanProfile(all_ports=False, top_ports=200))
        if spec == "0-65535":
            self.skipTest("no nmap-services table; fell back to full range (also safe)")
        got = {int(x) for x in spec.split(",")}
        self.assertIn(3389, got)          # would be missed by the old 0-200 range
        self.assertNotIn(0, got)

    def test_masscan_all_ports_is_full_range(self):
        self.assertEqual(
            scanner._masscan_port_spec(scanner.ScanProfile(all_ports=True)), "0-65535")


class DiscoveryDropFidelityTest(unittest.TestCase):
    """A host that blocks discovery + reconfirm must never silently vanish: a NAMED
    target is force-scanned (-Pn); a CIDR-expanded host is recorded as unscanned.
    Fully mocked - no nmap."""

    @staticmethod
    def _up_xml(ips, path):
        rows = "".join(
            f'<host><status state="up" reason="echo-reply"/>'
            f'<address addr="{ip}" addrtype="ipv4"/></host>' for ip in ips)
        with open(path, "w") as fh:
            fh.write(f'<?xml version="1.0"?><nmaprun start="1">{rows}</nmaprun>')

    def _discover(self, targets, up_ips):
        from unittest import mock
        from types import SimpleNamespace
        from recce import cli

        def fake_discover(targets_file, out_xml):
            self._up_xml(up_ips, out_xml)
            return out_xml, None

        def fake_reconfirm(targets_file, out_xml, profile):
            self._up_xml([], out_xml)                   # reconfirm recovers nothing
            return out_xml, None

        with tempfile.TemporaryDirectory() as d:
            paths = cli._open_paths(d)
            store = Store(paths["db"])
            profile = scanner.ScanProfile(ping_discovery=True)
            args = SimpleNamespace(targets=targets, exclude=[])
            try:
                with mock.patch.object(scanner, "discover_hosts", side_effect=fake_discover), \
                        mock.patch.object(scanner, "reconfirm_hosts", side_effect=fake_reconfirm):
                    _sn, live_ips, _pm, _dr, _hm = cli._discover(args, profile, store, paths)
                issues = store.get_issues()
            finally:
                store.close()
        return live_ips, " ".join(i.get("message", "") for i in issues)

    def test_named_ping_blocker_is_force_scanned(self):
        # The operator NAMED 10.99.0.2; it blocks discovery + reconfirm but must still
        # get a real -Pn port scan (added to live_ips), not be dropped - this is the
        # "firewalled host shows nothing open" fix.
        live_ips, _msgs = self._discover(["10.99.0.1", "10.99.0.2"], ["10.99.0.1"])
        self.assertIn("10.99.0.2", live_ips)

    def test_cidr_host_blocking_discovery_is_recorded_unscanned(self):
        # A host inside a CIDR scope (not individually named) is NOT force-scanned
        # (would explode cost on dead subnets) but must be recorded, not silently lost.
        live_ips, msgs = self._discover(["10.99.0.0/29"], ["10.99.0.1"])
        self.assertNotIn("10.99.0.2", live_ips)
        self.assertIn("10.99.0.2", msgs)
        self.assertIn("-Pn", msgs)


def _ports_xml(ip, ports, path):
    rows = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack"/></port>'
        for p in ports)
    with open(path, "w") as fh:
        fh.write(f'<?xml version="1.0"?><nmaprun start="1"><host>'
                 f'<status state="up" reason="user-set"/>'
                 f'<address addr="{ip}" addrtype="ipv4"/><ports>{rows}</ports>'
                 f'</host></nmaprun>')


class PortSweepRecoveryFidelityTest(unittest.TestCase):
    """The per-host recovery paths in _enum_worker: a lossy PARTIAL sweep is re-verified,
    and a TRUNCATED (slow firewalled) sweep gets a longer retry - both UNION their result
    so ports like 22/80 aren't lost to a lossy or slow scan. Fully mocked - no nmap."""

    def _run_worker(self, ip, fps, verify=None, enum=None, verify_all=False):
        from unittest import mock
        from recce import cli

        def fake_enum(ip_, ports, out_xml, profile, creds=None):
            _ports_xml(ip_, [], out_xml)
            return out_xml, None

        with tempfile.TemporaryDirectory() as d:
            paths = cli._open_paths(d)
            prof = scanner.ScanProfile(ping_discovery=True, udp_basic=False,
                                       ad_enrich=False, os_detect=False,
                                       verify_all=verify_all)
            patches = [mock.patch.object(scanner, "full_port_scan", side_effect=fps),
                       mock.patch.object(scanner, "enum_scan", side_effect=enum or fake_enum)]
            if verify:
                patches.append(mock.patch.object(scanner, "verify_port_scan",
                                                 side_effect=verify))
            for p in patches:
                p.start()
            try:
                host, _iss = cli._enum_worker(ip, prof, paths, None, None,
                                              {ip: "10.0.0.0/24"}, active_probe=False,
                                              disc_reason="syn-ack")
            finally:
                for p in patches:
                    p.stop()
        return host

    def test_partial_lossy_sweep_is_reverified_and_unioned(self):
        # Fast pass drops 2 of 3 open ports (no drop marker); under a thorough sweep
        # (--verify-all here) a congestion-adaptive re-verify fires and the union
        # restores all three. (On a plain discovery scan this stays off for speed.)
        def fps(ip, out_xml, profile):
            _ports_xml(ip, [22], out_xml)                # only 1 of 3 survived the fast pass
            return out_xml, None

        def verify(ip, out_xml, profile):
            _ports_xml(ip, [22, 80, 443], out_xml)
            return out_xml, None

        host = self._run_worker("10.0.0.7", fps, verify=verify, verify_all=True)
        self.assertEqual(sorted(p.portid for p in host.open_ports), [22, 80, 443])

    def test_few_port_host_not_reverified_on_plain_discovery_scan(self):
        # Perf guard: a normal discovery scan of a plain 1-2 service host must NOT
        # trigger the expensive congestion-adaptive re-verify.
        calls = {"verify": 0}

        def fps(ip, out_xml, profile):
            _ports_xml(ip, [80], out_xml)                # one service, cleanly found
            return out_xml, None

        def verify(ip, out_xml, profile):
            calls["verify"] += 1
            _ports_xml(ip, [80], out_xml)
            return out_xml, None

        host = self._run_worker("10.0.0.9", fps, verify=verify)   # verify_all=False
        self.assertEqual(calls["verify"], 0)
        self.assertEqual([p.portid for p in host.open_ports], [80])

    def test_truncated_slow_host_retry_recovers_dropped_common_ports(self):
        # First pass times out (slow firewall) and returns 0 ports - even 22/80 gone.
        # The auto-retry with a longer (capped) host-timeout + adaptive timing recovers
        # them. Default host_timeout is 20m -> the retry is CAPPED at 30m (not 40m).
        seen = {}

        def fps(ip, out_xml, profile):
            if not profile.reliable:                     # first pass: truncated, nothing
                _ports_xml(ip, [], out_xml)
                return out_xml, scanner.ScanIssue("warning", "host timeout",
                                                  kind="host-timeout")
            seen["retry_ht"] = profile.host_timeout      # the retry's (capped) timeout
            _ports_xml(ip, [22, 80], out_xml)            # retry: found the common ports
            return out_xml, None

        host = self._run_worker("10.0.0.8", fps)
        self.assertEqual(sorted(p.portid for p in host.open_ports), [22, 80])
        self.assertFalse(host.incomplete_scan)           # cleared: the retry completed
        self.assertEqual(seen["retry_ht"], 30)           # capped, not 2x (40)


# --- live real-listener integration ---------------------------------------------
# The port SWEEP (full_port_scan) is a pure SYN scan and finishes in well under a
# second on loopback. Version detection (-sV) is what costs seconds, so these tests
# run a bare `nmap -sV` (no --script) directly rather than enum_scan (which forces
# --script default and takes ~1 min), keeping the live suite fast while still real.

def _bind_tcp(port: int):
    """Bind a real listening TCP socket on 127.0.0.1; return (sock, port) or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        s.close()
        return None
    s.listen(16)
    return s, s.getsockname()[1]


def _nmap_sv(ports, out_xml, timeout=45):
    """Fast version detection (no scripts) on specific ports of 127.0.0.1."""
    import subprocess
    subprocess.run(
        ["nmap", "-sV", "-Pn", "-n", "--version-intensity", "3",
         "-p", ",".join(str(p) for p in ports), "127.0.0.1", "-oX", out_xml],
        capture_output=True, timeout=timeout)


class _WebHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html><title>recce-fidelity</title>ok</html>"
        self.send_response(200)
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


# Deliberately high / non-standard ports - exactly the ones a top-N scan or a
# masscan 0-N range would miss (RDP-alt, Elastic, Mongo, WinRM-alt, and higher).
_TEST_PORTS = (18443, 19200, 27017, 15985, 33389, 44444)


@unittest.skipUnless(shutil.which("nmap"), "nmap not installed")
class LiveScanFidelityTest(unittest.TestCase):
    """Real listeners, real nmap: every open port must survive to the store."""

    def setUp(self):
        self.socks = []
        self.ports = []
        for p in _TEST_PORTS:
            got = _bind_tcp(p)
            if got:
                s, port = got
                self.socks.append(s)
                self.ports.append(port)
        self.ports = sorted(self.ports)
        self.dir = tempfile.mkdtemp(prefix="recce-fidelity-")

    def tearDown(self):
        for s in self.socks:
            try:
                s.close()
            except OSError:
                pass
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_all_high_open_ports_found_by_full_sweep(self):
        # The real reproduction of the field symptom: a full sweep must return EVERY
        # open port, including the high / non-standard ones.
        if len(self.ports) < 2:
            self.skipTest("could not bind enough test ports")
        prof = scanner.ScanProfile(all_ports=True, os_detect=False,
                                   host_timeout=3, ad_enrich=False)
        xml = os.path.join(self.dir, "ports.xml")
        _, iss = scanner.full_port_scan("127.0.0.1", xml, prof)
        hosts = [h for h in parser.parse_nmap_xml(xml) if h.ip == "127.0.0.1"]
        self.assertTrue(hosts, f"nmap found no host (issue={iss})")
        found = {p.portid for p in hosts[0].open_ports}
        missing = set(self.ports) - found
        self.assertFalse(missing, f"open ports missing from the sweep: {sorted(missing)}")

    def test_open_ports_survive_version_scan_and_store_merge(self):
        # Sweep, then a -sV re-probe, then merge both into the real Store - no bound
        # port may be lost anywhere along parse -> store -> merge.
        if len(self.ports) < 2:
            self.skipTest("could not bind enough test ports")
        prof = scanner.ScanProfile(all_ports=True, os_detect=False,
                                   host_timeout=3, ad_enrich=False)
        pxml = os.path.join(self.dir, "ports.xml")
        scanner.full_port_scan("127.0.0.1", pxml, prof)
        exml = os.path.join(self.dir, "sv.xml")
        _nmap_sv(self.ports, exml)
        st = Store(os.path.join(self.dir, "r.sqlite"))
        try:
            for path in (pxml, exml):
                for h in parser.parse_nmap_xml(path):
                    st.upsert_host(h, merge=True)
            back = st.get_host("127.0.0.1")
        finally:
            st.close()
        stored = {p.portid for p in back.open_ports}
        missing = set(self.ports) - stored
        self.assertFalse(missing,
                         f"ports lost through version-scan + store merge: {sorted(missing)}")


@unittest.skipUnless(shutil.which("nmap"), "nmap not installed")
class LiveServiceLabelFidelityTest(unittest.TestCase):
    """A real HTTP server on a NON-standard port must be labeled http, not lost as
    'unknown' - the recurring 'silent HTTP on a non-standard port' regression."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="recce-fidelity-svc-")
        self.srv = None
        for p in (18080, 28080, 38080, 48080):
            try:
                self.srv = ThreadingHTTPServer(("127.0.0.1", p), _WebHandler)
                self.port = p
                break
            except OSError:
                continue
        if self.srv:
            threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        if self.srv:
            self.srv.shutdown()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_http_on_nonstandard_port_is_detected(self):
        if not self.srv:
            self.skipTest("no non-standard web port was free")
        exml = os.path.join(self.dir, "sv.xml")
        _nmap_sv([self.port], exml)
        hosts = [h for h in parser.parse_nmap_xml(exml) if h.ip == "127.0.0.1"]
        self.assertTrue(hosts, "nmap -sV returned no host")
        p = next((p for p in hosts[0].open_ports if p.portid == self.port), None)
        self.assertIsNotNone(p, "the live web port was not found open")
        # Either nmap labels it http directly, or recce's svcdetect recovers it.
        from recce import svcdetect
        svcdetect.enrich_host(hosts[0])
        blob = f"{p.service} {p.product} {p.tunnel}".lower()
        self.assertIn("http", blob,
                      f"live HTTP on {self.port} not detected as http: {blob!r}")


if __name__ == "__main__":
    unittest.main()
