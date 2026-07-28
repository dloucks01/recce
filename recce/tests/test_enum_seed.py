"""Regression: the enum phase must never lose a port the sweep authoritatively found.

The port sweep (nmap -sS/-sT --open) is completeness-first and definitive about which
ports are open. The enum phase then re-scans those ports with a much heavier -sV/-sC
pass that has NO congestion-adaptive retry, so on a lossy network (or under a
host-timeout) it can under-report - and because the final host used to be rebuilt
purely from the enum XML, a port the sweep found could silently vanish, leaving a host
with real services reading "0 open ports". These tests pin the fix: swept ports are
folded into the host, so enum can only enrich them, never erase them.
"""

import os
import tempfile
import unittest

from recce import cli, scanner


def _host_xml(ip, ports, closed=()):
    """Minimal nmap XML for one up host.
    ports:  iterable of (portid, service) reported OPEN.
    closed: iterable of portids nmap reports CLOSED (a definitive RST) - kept in the
            XML the way nmap emits them (parse_nmap_xml drops these, but the masscan
            pruning reads them raw)."""
    rows = "".join(
        f'<port protocol="tcp" portid="{pid}">'
        f'<state state="open" reason="syn-ack"/>'
        f'<service name="{svc}"/></port>'
        for pid, svc in ports
    )
    rows += "".join(
        f'<port protocol="tcp" portid="{pid}">'
        f'<state state="closed" reason="reset"/></port>'
        for pid in closed
    )
    return (
        '<?xml version="1.0"?>\n<nmaprun start="1">\n'
        f'<host><status state="up" reason="syn-ack"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f'<ports>{rows}</ports></host>\n</nmaprun>\n'
    )


class EnumSeedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="recce-seed-")
        self.paths = {"raw": self.tmp}
        # No OS/AD/deep-enum/UDP work: keep the worker on the port path only.
        self.profile = scanner.ScanProfile(
            name="t", os_detect=False, ad_enrich=False, deep_enum=False,
            udp_basic=False, udp_fallback=False, verify=True)
        self._orig = {name: getattr(scanner, name) for name in
                      ("full_port_scan", "enum_scan", "verify_port_scan")}

    def tearDown(self):
        for name, fn in self._orig.items():
            setattr(scanner, name, fn)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self):
        # active_probe=False -> no live banner grabs / reprobe; port_map=None -> the
        # authoritative nmap-sweep path (the one the fix guards).
        return cli._enum_worker("10.0.0.5", self.profile, self.paths, None,
                                None, {}, active_probe=False, disc_reason="syn-ack")

    def _run_masscan(self, ports):
        # port_map non-None -> the masscan --fast path.
        return cli._enum_worker("10.0.0.5", self.profile, self.paths, None,
                                {"10.0.0.5": list(ports)}, {},
                                active_probe=False, disc_reason="syn-ack")

    def test_enum_under_report_does_not_lose_swept_ports(self):
        # Sweep finds 22/80/443; the heavier enum pass drops 22 and 443 (lossy net).
        def fake_full(ip, out_xml, profile):
            with open(out_xml, "w") as fh:
                fh.write(_host_xml(ip, [(22, "ssh"), (80, "http"), (443, "https")]))
            return out_xml, None

        def fake_enum(ip, ports, out_xml, profile, creds=None):
            with open(out_xml, "w") as fh:
                fh.write(_host_xml(ip, [(80, "http")]))  # under-reports!
            return out_xml, None

        scanner.full_port_scan = fake_full
        scanner.enum_scan = fake_enum

        host, _ = self._run()
        self.assertEqual({p.portid for p in host.open_ports}, {22, 80, 443},
                         "ports the sweep found were lost when enum under-reported")
        # The port enum DID enrich keeps its service; a recovered one is still open.
        svc = {p.portid: p.service for p in host.open_ports}
        self.assertEqual(svc[80], "http")

    def test_enum_enriches_without_duplicating(self):
        # Sweep and enum agree on the port set; enum adds richer service data. The
        # swept fold must not duplicate the port or clobber the richer enum record.
        def fake_full(ip, out_xml, profile):
            with open(out_xml, "w") as fh:
                fh.write(_host_xml(ip, [(445, "microsoft-ds")]))
            return out_xml, None

        def fake_enum(ip, ports, out_xml, profile, creds=None):
            with open(out_xml, "w") as fh:
                fh.write(_host_xml(ip, [(445, "microsoft-ds")]))
            return out_xml, None

        scanner.full_port_scan = fake_full
        scanner.enum_scan = fake_enum

        host, _ = self._run()
        self.assertEqual([p.portid for p in host.ports], [445],
                         "swept fold duplicated a port enum already reported")

    def test_genuinely_empty_host_stays_empty(self):
        # Sweep finds nothing and the verify re-scan also finds nothing: the host is
        # really empty and must NOT gain phantom ports.
        def fake_full(ip, out_xml, profile):
            with open(out_xml, "w") as fh:
                fh.write('<?xml version="1.0"?><nmaprun start="1"></nmaprun>')
            return out_xml, None

        def fake_verify(ip, out_xml, profile):
            with open(out_xml, "w") as fh:
                fh.write('<?xml version="1.0"?><nmaprun start="1"></nmaprun>')
            return out_xml, None

        def fake_enum(ip, ports, out_xml, profile, creds=None):
            # enum_scan short-circuits to empty XML on no ports; mirror that.
            with open(out_xml, "w") as fh:
                fh.write('<?xml version="1.0"?><nmaprun start="1"></nmaprun>')
            return out_xml, None

        scanner.full_port_scan = fake_full
        scanner.verify_port_scan = fake_verify
        scanner.enum_scan = fake_enum

        host, _ = self._run()
        self.assertEqual(host.open_ports, [])

    # --- masscan (--fast) path --------------------------------------------------

    def test_masscan_port_lost_to_enum_loss_is_recovered(self):
        # masscan saw 22/80/443. enum confirms 80, actively disproves 22 (RST=closed),
        # and never gets a reply for 443 (packet loss). 443 must be recovered (masscan
        # had positive evidence, enum loss doesn't disprove it); 22 must be pruned.
        def fake_enum(ip, ports, out_xml, profile, creds=None):
            with open(out_xml, "w") as fh:
                fh.write(_host_xml(ip, [(80, "http")], closed=[22]))  # 443 absent
            return out_xml, None

        scanner.enum_scan = fake_enum
        host, _ = self._run_masscan([22, 80, 443])
        opened = {p.portid for p in host.open_ports}
        self.assertIn(443, opened, "masscan port lost to enum packet loss not recovered")
        self.assertNotIn(22, opened, "masscan false open disproved by nmap RST was kept")
        self.assertIn(80, opened)
        # The recovered port is marked as masscan-sourced (unconfirmed), for provenance.
        p443 = next(p for p in host.open_ports if p.portid == 443)
        self.assertEqual(p443.detect_source, "masscan")

    def test_masscan_false_open_disproved_by_nmap_is_pruned(self):
        # A spurious masscan open that nmap re-scans and finds closed must NOT survive -
        # keeping it would be a phantom port, the opposite failure that also erodes trust.
        def fake_enum(ip, ports, out_xml, profile, creds=None):
            with open(out_xml, "w") as fh:
                fh.write(_host_xml(ip, [], closed=[31337]))
            return out_xml, None

        scanner.enum_scan = fake_enum
        host, _ = self._run_masscan([31337])
        self.assertEqual(host.open_ports, [])


if __name__ == "__main__":
    unittest.main()
