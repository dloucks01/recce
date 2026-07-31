"""Network map at scale: full (every host) vs aggregated overview, and role labels.

The map has two forms — a full per-host diagram and a subnet→role-count overview — and
both must be produced. These tests build a 400-host estate and assert the full map
stays 1-node-per-host, the overview stays small and bounded, both are written by
`recce report`, and the role classifier labels a Windows client as a Workstation (not a
File/SMB server) even with 445 open. Stdlib only (the map + hand-rolled xlsx writer
need no third-party deps)."""
import contextlib
import io
import os
import shutil
import tempfile
import time
import unittest

from recce import cli
from recce import netmap
from recce.models import Domain, Host, Port
from recce.store import Store

_SUBNETS = 10
_PER = 40
_TOTAL = _SUBNETS * _PER          # 400 hosts


def _host(ip, subnet, os_name, ports, roles=None):
    return Host(ip=ip, subnet=subnet, state="up", up_reason="syn-ack", enumerated=True,
                hostnames=[ip.replace(".", "-")], os_name=os_name,
                ports=[Port(portid=p, state="open", service=s) for p, s in ports],
                roles=roles or [])


def _estate():
    """400 hosts across 10 /24s: a DC, some web + DB servers, the rest Win10 clients."""
    hosts = []
    for s in range(_SUBNETS):
        subnet = f"10.0.{s}.0/24"
        for h in range(_PER):
            ip = f"10.0.{s}.{h + 1}"
            if s == 0 and h == 0:
                hosts.append(_host(ip, subnet, "Windows Server 2019",
                                   [(88, "kerberos-sec"), (389, "ldap"), (445, "microsoft-ds")],
                                   roles=["Domain Controller"]))
            elif h % 20 == 0:
                hosts.append(_host(ip, subnet, "Ubuntu 22.04", [(80, "http"), (443, "https")]))
            elif h % 13 == 0:
                hosts.append(_host(ip, subnet, "Windows Server 2016",
                                   [(445, "microsoft-ds"), (1433, "ms-sql-s")]))
            else:
                hosts.append(_host(ip, subnet, "Windows 10 Pro",
                                   [(445, "microsoft-ds"), (3389, "ms-wbt-server")]))
    return hosts


class RoleLabellingTest(unittest.TestCase):

    def test_windows_client_with_smb_is_a_workstation(self):
        ws = _host("10.0.0.5", "10.0.0.0/24", "Windows 10 Pro",
                   [(445, "microsoft-ds"), (3389, "ms-wbt-server")])
        self.assertEqual(netmap.roles_for(ws), ["Workstation"])
        self.assertEqual(netmap.primary_role(ws), "Workstation")

    def test_server_with_smb_is_file_smb(self):
        srv = _host("10.0.0.6", "10.0.0.0/24", "Windows Server 2019", [(445, "microsoft-ds")])
        self.assertIn("File/SMB", netmap.roles_for(srv))

    def test_server_role_wins_over_smb(self):
        db = _host("10.0.0.7", "10.0.0.0/24", "Windows Server 2016",
                   [(445, "microsoft-ds"), (1433, "ms-sql-s")])
        self.assertIn("DB", netmap.roles_for(db))

    def test_linux_ssh_is_host(self):
        lx = _host("10.0.0.8", "10.0.0.0/24", "Ubuntu 22.04", [(22, "ssh")])
        self.assertEqual(netmap.roles_for(lx), ["Host"])


class MapScaleTest(unittest.TestCase):

    def setUp(self):
        self.hosts = _estate()

    def test_full_svg_draws_every_host_overview_collapses(self):
        full = netmap.svg(self.hosts, aggregate=False)
        over = netmap.svg(self.hosts, aggregate=True)
        # a card (rect) per host in full; a handful of role rows in the overview
        self.assertGreaterEqual(full.count("<rect"), _TOTAL)
        self.assertLess(over.count("<rect"), _TOTAL // 5)
        self.assertGreater(len(full), len(over) * 3)
        # overview role rows are bounded by subnets x roles, never per-host
        self.assertLessEqual(over.count("<rect"), _SUBNETS * len(netmap._ROLE_ORDER) + 4)

    def test_auto_mode_aggregates_a_large_estate(self):
        # default (aggregate=None) auto-collapses >50 hosts
        auto = netmap.svg(self.hosts)
        self.assertLess(auto.count("<rect"), _TOTAL // 5)

    def test_tiered_svg_stays_bounded_at_scale(self):
        import xml.dom.minidom as md
        s = netmap.tiered_svg(self.hosts)
        md.parseString(s)                                            # well-formed
        # role chips are aggregate (bounded by 3 tiers x roles), never per-host
        self.assertLess(s.count("<rect"), 3 * len(netmap._ROLE_ORDER) + 10)
        self.assertIn("Tier 0", s)
        self.assertIn("pivot surface", s.lower())

    def test_both_svg_maps_build_quickly(self):
        t0 = time.monotonic()
        for agg in (False, True, None):
            netmap.svg(self.hosts, aggregate=agg)
        self.assertLess(time.monotonic() - t0, 10.0)                  # generous; guards O(n^2)


class ReportWritesBothMapsTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_report_emits_full_and_overview_maps(self):
        paths = cli._open_paths(self.dir)
        store = Store(paths["db"])
        for h in _estate():
            store.upsert_host(h, merge=False)
        store.upsert_domain(Domain(name="corp.local", dc_ips=["10.0.0.1"]))
        store.close()

        with contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["report", "-o", self.dir])
        self.assertEqual(rc, 0)

        # SVG only — the three maps are written ...
        for name in ("network-map-full.svg", "network-map-overview.svg",
                     "network-map-tiered.svg"):
            self.assertTrue(os.path.exists(os.path.join(self.dir, name)), name)
        # ... and no Mermaid / Graphviz sidecars are produced.
        for name in ("architecture.mmd", "architecture-overview.mmd",
                     "architecture.dot", "architecture-overview.dot"):
            self.assertFalse(os.path.exists(os.path.join(self.dir, name)), name)

        def _read(name):
            with open(os.path.join(self.dir, name)) as fh:
                return fh.read()

        full_svg = _read("network-map-full.svg")
        over_svg = _read("network-map-overview.svg")
        self.assertIn("xmlns", full_svg)                             # standalone-renderable
        self.assertIn("xmlns", over_svg)
        self.assertGreaterEqual(full_svg.count("<rect"), _TOTAL)     # every host drawn
        self.assertGreater(len(full_svg), len(over_svg) * 3)


if __name__ == "__main__":
    unittest.main()
