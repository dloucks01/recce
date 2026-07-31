"""Architecture / network map built from the enumeration."""
import os
import tempfile
import unittest

from recce import netmap
from recce.models import Host, Port
from recce.models import Domain


def _h(ip, subnet="10.0.10.0/24", ports=(), roles=(), os_name="", hostname="",
       access=False, vulns=()):
    from recce.models import Vuln
    return Host(ip=ip, subnet=subnet, state="up", up_reason="syn-ack",
                hostnames=[hostname] if hostname else [], os_name=os_name,
                roles=list(roles), access_gained=access,
                vulns=[Vuln(ip=ip, port=None, protocol="tcp", script_id="v",
                            title="v", severity=sev, source="nse",
                            confidence=conf) for sev, conf in vulns],
                ports=[Port(portid=p, protocol="tcp", state="open", service=s)
                       for p, s in ports])


class RoleTest(unittest.TestCase):

    def test_role_classification(self):
        dc = _h("10.0.10.10", ports=[(389, "ldap"), (445, "microsoft-ds")],
                roles=["Domain Controller"])
        self.assertEqual(netmap.primary_role(dc), "DC")           # DC beats File/SMB
        web = _h("10.0.20.5", ports=[(80, "http"), (443, "https")])
        self.assertEqual(netmap.primary_role(web), "Web")
        dbh = _h("10.0.20.6", ports=[(3306, "mysql")])
        self.assertEqual(netmap.primary_role(dbh), "DB")
        fileh = _h("10.0.10.9", ports=[(445, "microsoft-ds")])
        self.assertEqual(netmap.primary_role(fileh), "File/SMB")
        ws = _h("10.0.10.50", ports=[(3389, "ms-wbt-server")],
                os_name="Microsoft Windows 10 21H2")
        self.assertEqual(netmap.primary_role(ws), "Workstation")
        bare = _h("10.0.10.60", ports=[(23, "telnet")])
        self.assertEqual(netmap.primary_role(bare), "Host")


class MermaidTest(unittest.TestCase):

    def _hosts(self):
        return [
            _h("10.0.10.10", ports=[(389, "ldap"), (445, "microsoft-ds")],
               roles=["Domain Controller"], hostname="dc01", os_name="Windows Server 2019"),
            _h("10.0.20.5", subnet="10.0.20.0/24", ports=[(80, "http")],
               hostname="web01", os_name="Linux 5.4"),
        ]

    def test_empty_is_graceful(self):
        self.assertIn("No hosts", netmap.svg([]))

    def test_svg_renders_directly_and_is_self_contained(self):
        import xml.dom.minidom as md
        doms = [Domain(name="corp.local", dc_ips=["10.0.10.10"])]
        s = netmap.svg(self._hosts(), doms)
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)                              # well-formed XML (renders anywhere)
        self.assertNotIn("xmlns", s)                   # inline, self-contained
        self.assertNotIn("http://", s)
        self.assertIn("#C00000", s)                    # DC role colour
        self.assertIn("<path", s)                      # DC -> domain edge
        self.assertIn("10.0.10.10", s)

    def test_svg_aggregates_large_estate(self):
        many = [_h(f"10.0.0.{i}", ports=[(80, "http")]) for i in range(1, 60)]
        s = netmap.svg(many)
        import xml.dom.minidom as md
        md.parseString(s)
        self.assertIn("×", s)                          # "N× Web" aggregate labels

    def test_summary_is_grounded(self):
        lines = netmap.summary(self._hosts(),
                               [Domain(name="corp.local", dc_ips=["10.0.10.10"])])
        joined = " ".join(lines)
        self.assertIn("2 host(s)", joined)
        self.assertIn("2 network segment(s)", joined)
        self.assertIn("corp.local", joined)

    def test_svg_label_escapes_special_chars(self):
        # Quotes/brackets in a hostname must not break the SVG text.
        import xml.dom.minidom as md
        h = _h("10.0.0.1", hostname='we"ird<name>', ports=[(80, "http")])
        md.parseString(netmap.svg([h]))               # stays well-formed XML


class NetworkMapEnrichmentTest(unittest.TestCase):
    """The network map is enriched from SharpHound + other findings: DCs confirmed
    from AD ground-truth, an access overlay, and a per-host risk dot."""

    def _ad(self):
        return {"architecture": {"nodes": {
            "S-1-5-21-1-1-1-1000": {"type": "Computer", "label": "DC01.CORP.LOCAL",
                                    "dc": True, "hv": True, "tier": 1}},
            "edges": [], "trusts": [], "truncated": False}}

    def test_dc_confirmed_from_sharphound(self):
        # A host with only 445 open and no DC role — SharpHound says it's a DC.
        dc = _h("10.0.10.10", ports=[(445, "microsoft-ds")], hostname="dc01.corp.local")
        self.assertEqual(netmap.primary_role(dc), "File/SMB")     # ports alone
        self.assertEqual(netmap.role_with_ad(dc, netmap.ad_dc_names(self._ad())), "DC")
        s = netmap.svg([dc], None, self._ad())
        import xml.dom.minidom as md
        md.parseString(s)
        self.assertIn("#C00000", s)                               # DC role colour

    def test_access_and_risk_overlay(self):
        owned = _h("10.0.20.6", subnet="10.0.20.0/24", ports=[(21, "ftp")],
                   hostname="web02", access=True, vulns=[("critical", "confirmed")])
        s = netmap.svg([owned])
        import xml.dom.minidom as md
        md.parseString(s)
        self.assertIn("#2E7D32", s)                     # green access outline/badge
        self.assertIn("✓", s)                           # access check mark
        self.assertIn("#C00000", s)                     # critical risk dot
        self.assertIn("access gained", s)               # legend key present

    def test_potential_vuln_not_counted_as_risk(self):
        # An unverified 'potential' finding must NOT light the risk dot.
        h = _h("10.0.0.9", ports=[(80, "http")], vulns=[("high", "potential")])
        self.assertEqual(netmap.worst_severity(h), "")
        s = netmap.svg([h])
        self.assertNotIn("access gained", s)            # no access, no overlay legend

    def test_summary_reports_access_and_confirmed_dc(self):
        hosts = [_h("10.0.10.10", ports=[(445, "microsoft-ds")], hostname="dc01"),
                 _h("10.0.20.6", subnet="10.0.20.0/24", ports=[(21, "ftp")],
                    hostname="web02", access=True, vulns=[("critical", "confirmed")])]
        lines = " ".join(netmap.summary(hosts, None, self._ad()))
        self.assertIn("1 with confirmed access", lines)
        self.assertIn("1 with critical/high findings", lines)
        self.assertIn("AD-confirmed Domain Controller", lines)


class AdArchitectureSvgTest(unittest.TestCase):

    def _arch(self):
        B = "S-1-5-21-9-9-9"
        return {
            "nodes": {
                B: {"type": "Domain", "label": "CORP.LOCAL", "domain": "",
                    "hv": True, "dc": False, "tier": 0},
                "S-1-5-21-7-7-7": {"type": "Domain", "label": "CHILD.CORP.LOCAL",
                                   "domain": "", "hv": True, "dc": False, "tier": 0},
                f"{B}-512": {"type": "Group", "label": "DOMAIN ADMINS", "domain": "CORP.LOCAL",
                             "hv": True, "dc": False, "tier": 1},
                f"{B}-1000": {"type": "Computer", "label": "DC01", "domain": "CORP.LOCAL",
                              "hv": True, "dc": True, "tier": 1},
                f"{B}-1105": {"type": "Group", "label": "HELPDESK", "domain": "CORP.LOCAL",
                              "hv": False, "dc": False, "tier": 2},
                f"{B}-1001": {"type": "User", "label": "BOB", "domain": "CORP.LOCAL",
                              "hv": False, "dc": False, "tier": 2},
            },
            "edges": [[f"{B}-1105", "MemberOf", f"{B}-512"],
                      [f"{B}-1001", "GenericAll", f"{B}-1105"],
                      [f"{B}-1001", "DCSync", B]],
            "trusts": [["CORP.LOCAL", "Bidirectional", "CHILD.CORP.LOCAL"]],
            "truncated": False,
        }

    def test_ad_svg_renders_and_is_self_contained(self):
        import xml.dom.minidom as md
        s = netmap.ad_svg(self._arch())
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)                              # well-formed XML (renders anywhere)
        self.assertNotIn("xmlns", s)                   # inline, self-contained
        self.assertNotIn("http://", s)
        self.assertIn("DOMAIN ADMINS", s)              # a high-value group
        self.assertIn("CORP.LOCAL", s)                 # the domain
        self.assertIn("DC01", s)                       # the Domain Controller
        self.assertIn("#C00000", s)                    # DC / control-edge colour
        self.assertIn("GenericAll", s)                 # a control edge is labelled
        self.assertIn("DCSync", s)
        self.assertIn("trust", s)                      # domain trust edge label
        self.assertIn("<path", s)

    def test_ad_svg_empty_is_graceful(self):
        s = netmap.ad_svg({})
        self.assertIn("No BloodHound", s)
        self.assertTrue(s.startswith("<svg"))

    def test_ad_svg_access_and_risk_overlay(self):
        import xml.dom.minidom as md
        arch = self._arch()
        # We hold ADMINISTRATOR-equivalent principal BOB; a DCSync edge targets the
        # domain (critical) — both overlays should appear, grounded in the data.
        s = netmap.ad_svg(arch, owned_labels={"BOB"})
        md.parseString(s)
        self.assertIn("✓", s)                          # held principal marked
        self.assertIn("already held", s)               # access legend key
        self.assertIn("directly seizable", s)          # risk legend key
        self.assertIn("#C00000", s)                    # critical (DCSync target) dot
        # No owned set → no access legend key (stays honest).
        self.assertNotIn("already held", netmap.ad_svg(arch))

    def test_ad_svg_truncation_note(self):
        arch = self._arch()
        arch["truncated"] = True
        self.assertIn("truncated", netmap.ad_svg(arch).lower())


class ReportEmbedTest(unittest.TestCase):

    def test_network_map_in_assets_page(self):
        from recce import report_html
        hosts = [_h("10.0.10.10", ports=[(445, "microsoft-ds")],
                    roles=["Domain Controller"], hostname="dc01")]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "assets.html")
            report_html.build_assets_html(
                hosts, p, title="Map",
                domains=[Domain(name="corp.local", dc_ips=["10.0.10.10"])])
            with open(p, encoding="utf-8") as fh:
                html = fh.read()
        self.assertIn("Network map", html)
        self.assertIn("<svg", html)                    # renders directly, no tools
        self.assertIn("logical", html)                 # honest caveat
        self.assertNotIn("xmlns", html)                # inline SVG stays self-contained
        for bad in ("src=", "<link", "<script"):
            self.assertNotIn(bad, html)


if __name__ == "__main__":
    unittest.main()


class TieredMapTest(unittest.TestCase):
    """DC → servers → workstations trust-tier view + credentialed pivot surface."""

    def _estate(self):
        return [
            _h("10.0.10.10", ports=[(389, "ldap"), (445, "microsoft-ds")],
               roles=["Domain Controller"], hostname="dc01",
               os_name="Windows Server 2019"),
            _h("10.0.10.20", ports=[(445, "microsoft-ds"), (1433, "ms-sql-s")],
               os_name="Windows Server 2016", hostname="sql01"),
            _h("10.0.10.40", ports=[(80, "http"), (443, "https")],
               os_name="Ubuntu 22.04", hostname="web01"),
            _h("10.0.20.5", ports=[(445, "microsoft-ds"), (3389, "ms-wbt-server")],
               os_name="Windows 10 Pro", hostname="ws01", access=True),
        ]

    def test_reach_counts_are_present_protocols_only(self):
        reach = dict(netmap.reach_counts(self._estate()))
        self.assertEqual(reach["SMB"], 3)          # DC + sql + ws
        self.assertEqual(reach["MSSQL"], 1)
        self.assertEqual(reach["RDP"], 1)
        self.assertNotIn("WinRM", reach)           # none open -> omitted

    def test_tiered_svg_renders_and_is_self_contained(self):
        import xml.dom.minidom as md
        s = netmap.tiered_svg(self._estate(),
                              [Domain(name="corp.local", dc_ips=["10.0.10.10"])])
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)                          # well-formed XML, renders anywhere
        self.assertNotIn("xmlns", s)               # inline / self-contained
        self.assertIn("Tier 0", s)
        self.assertIn("Tier 1", s)
        self.assertIn("Tier 2", s)
        self.assertIn("DC ×1", s)                  # tier-0 chip
        self.assertIn("Workstation ×1", s)         # tier-2 chip
        self.assertIn("AD domain", s)
        self.assertIn("pivot surface", s.lower())
        self.assertIn("1 foothold", s)             # the ws01 access overlay
        # honesty: it must not claim network reachability
        self.assertIn("does not test host-to-host", s)

    def test_tiered_svg_empty_is_graceful(self):
        import xml.dom.minidom as md
        s = netmap.tiered_svg([])
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)
        self.assertIn("No hosts", s)


class RoleGlyphTest(unittest.TestCase):

    def test_role_kind_maps_to_three_device_classes(self):
        self.assertEqual(netmap.role_kind("DC"), "dc")
        for r in ("DB", "Web", "Mail", "File/SMB"):
            self.assertEqual(netmap.role_kind(r), "server")
        for r in ("Workstation", "Host"):
            self.assertEqual(netmap.role_kind(r), "workstation")

    def test_glyphs_are_well_formed_svg_fragments(self):
        import xml.dom.minidom as md
        for kind in ("dc", "server", "workstation"):
            g = netmap.glyph(kind, 10, 10, 18, "#1f4e9c")
            md.parseString(f"<svg xmlns='http://www.w3.org/2000/svg'>{g}</svg>")
        leg = netmap.glyph_legend(0, 0)
        md.parseString(f"<svg xmlns='http://www.w3.org/2000/svg'>{leg}</svg>")
        self.assertIn("Domain Controller", leg)


class ReachabilityTest(unittest.TestCase):
    """Observed host-to-host reachability from on-target topology (ground truth)."""

    def _hosts(self):
        from recce import ingest
        foot = _h("10.0.20.5", subnet="10.0.20.0/24",
                  ports=[(445, "microsoft-ds")], os_name="Windows 10 Pro",
                  hostname="ws01", access=True)
        foot.topology = ingest.parse_topology(
            "==== NETWORK ====\n"
            "NET-IFACE eth0 10.0.20.5/24\nNET-IFACE eth1 10.0.10.9/24\n"
            "NET-NEIGH 10.0.10.10 aa:bb:cc:00:00:10\nNET-NEIGH 127.0.0.1 x\n"
            "NET-PEER 10.0.10.10:445 ESTAB\nNET-PEER 8.8.8.8:443 ESTAB\n")
        dc = _h("10.0.10.10", ports=[(445, "microsoft-ds")],
                roles=["Domain Controller"], hostname="dc01",
                os_name="Windows Server 2019")
        return [foot, dc]

    def test_parse_topology_drops_loopback_and_computes_subnet(self):
        from recce import ingest
        t = ingest.parse_topology("NET-IFACE eth0 10.0.20.5/24\nNET-NEIGH 127.0.0.1 x\n"
                                  "NET-NEIGH 10.0.10.10 aa\nNET-PEER 10.0.10.10:445 E")
        self.assertEqual(t["interfaces"][0]["subnet"], "10.0.20.0/24")
        self.assertEqual(t["neighbors"], ["10.0.10.10"])       # loopback dropped
        self.assertEqual(t["peers"][0]["port"], 445)

    def test_adjacency_edges_and_pivot(self):
        adj = netmap.adjacency(self._hosts())
        self.assertIn("10.0.20.5", adj["footholds"])
        self.assertIn("10.0.20.5", adj["pivots"])              # dual-homed
        self.assertEqual(set(adj["pivots"]["10.0.20.5"]),
                         {"10.0.10.0/24", "10.0.20.0/24"})
        kinds = {(e["dst"], e["kind"]) for e in adj["edges"]}
        self.assertIn(("10.0.10.10", "arp"), kinds)            # ARP neighbour edge
        self.assertIn(("10.0.10.10", "conn"), kinds)           # live connection edge
        ext = [e for e in adj["edges"] if e["dst"] == "8.8.8.8"]
        self.assertTrue(ext and not ext[0]["dst_known"])       # off-scope peer flagged

    def test_reachability_svg_renders_or_placeholder(self):
        import xml.dom.minidom as md
        s = netmap.reachability_svg(self._hosts())
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)
        self.assertIn("PIVOT", s)                              # dual-homed foothold flagged
        self.assertIn("ARP", s)                                # legend
        empty = netmap.reachability_svg([_h("10.0.0.1", ports=[(22, "ssh")])])
        self.assertIn("No on-target topology", empty)          # graceful when none


class HostTileLayoutTest(unittest.TestCase):
    """Full map + reachability draw each system as a vertical tile: icon over IP."""

    def test_full_map_tile_is_identity_rich(self):
        import xml.dom.minidom as md
        dc = _h("10.0.10.10", ports=[(389, "ldap"), (445, "microsoft-ds")],
                roles=["Domain Controller"], hostname="dc01",
                os_name="Windows Server 2019")
        s = netmap.svg([dc], aggregate=False)
        md.parseString(s)
        self.assertIn('text-anchor="middle"', s)          # IP centered under the icon
        self.assertIn("10.0.10.10", s)
        self.assertIn("<g ", s)                            # a device glyph
        self.assertIn("dc01", s)                           # hostname
        self.assertIn("Windows Server 2019", s)            # OS hint

    def test_tile_has_header_wash_and_severity_chip(self):
        # A confirmed critical finding shows the outline CRIT chip; owned shows the checkmark.
        dc = _h("10.0.10.10", ports=[(445, "microsoft-ds")], roles=["Domain Controller"],
                hostname="dc01", os_name="Windows Server 2019", access=True,
                vulns=[("critical", "confirmed")])
        s = netmap.svg([dc], aggregate=False)
        self.assertIn("fill-opacity=\"0.20\"", s)     # role-wash header band
        self.assertIn("CRIT", s)                       # outline severity chip
        self.assertIn("\u2713", s)                        # owned check

    def test_ip_derived_hostname_is_not_shown_twice(self):
        self.assertEqual(netmap.real_hostname(
            _h("10.0.10.10", hostname="10-0-10-10")), "")   # suppressed
        self.assertEqual(netmap.real_hostname(
            _h("10.0.10.10", hostname="dc01")), "dc01")     # real name kept
        s = netmap.svg([_h("10.0.10.10", hostname="10-0-10-10",
                           ports=[(445, "microsoft-ds")])], aggregate=False)
        self.assertEqual(s.count("10.0.10.10"), 1)          # IP printed once
        self.assertNotIn("10-0-10-10", s)


class ArchitectureViewTest(unittest.TestCase):
    """Logical architecture: AD -> core -> gateway(router/firewall) -> switch -> segment."""

    def _hosts(self):
        # no topology -> logical/core mode
        dc = _h("10.0.10.10", ports=[(389, "ldap"), (445, "microsoft-ds")],
                roles=["Domain Controller"], hostname="dc01", access=True,
                vulns=[("critical", "confirmed")])
        web = _h("10.0.40.10", subnet="10.0.40.0/24 (DMZ)", ports=[(80, "http"), (443, "https")],
                 hostname="web01")
        ws = _h("10.0.20.11", subnet="10.0.20.0/24", ports=[(3389, "ms-wbt-server")],
                os_name="Windows 10 Pro")
        return [dc, web, ws]

    def test_net_glyphs_are_well_formed(self):
        import xml.dom.minidom as md
        for kind in ("switch", "router", "firewall"):
            md.parseString(f"<svg xmlns='http://www.w3.org/2000/svg'>"
                           f"{netmap.net_glyph(kind, 4, 4, 22, '#1f4e9c')}</svg>")

    def test_architecture_logical_mode(self):
        import xml.dom.minidom as md
        doms = [Domain(name="corp.local", dc_ips=["10.0.10.10"])]
        s = netmap.architecture_svg(self._hosts(), doms)   # no topology -> core mode
        self.assertTrue(s.startswith("<svg"))
        md.parseString(s)
        self.assertIn("Routed core", s)
        self.assertIn("AD domain", s)
        self.assertIn("firewall", s)                   # the DMZ segment gateway
        self.assertIn("Edge / DMZ", s)                 # tier label
        self.assertIn("a switch = one L2 segment", s)  # honesty note

    def test_architecture_topology_mode_real_gw_and_pivot(self):
        import xml.dom.minidom as md
        # DC with a real gateway; a dual-homed pivot bridging 10.0.10 and 10.0.20
        dc = _h("10.0.10.10", ports=[(445, "microsoft-ds")], roles=["Domain Controller"],
                hostname="dc01", access=True)
        dc.topology = {"interfaces": [{"name": "eth0", "ip": "10.0.10.10", "prefix": 24,
                                       "subnet": "10.0.10.0/24"}],
                       "routes": [{"dest": "default", "gw": "10.0.10.1", "iface": "eth0"}],
                       "neighbors": ["10.0.10.20"], "peers": []}
        piv = _h("10.0.20.11", subnet="10.0.20.0/24", ports=[(3389, "ms-wbt-server")],
                 os_name="Windows 10 Pro", access=True)
        piv.topology = {"interfaces": [
            {"name": "eth0", "ip": "10.0.20.11", "prefix": 24, "subnet": "10.0.20.0/24"},
            {"name": "eth1", "ip": "10.0.10.9", "prefix": 24, "subnet": "10.0.10.0/24"}],
            "routes": [{"dest": "default", "gw": "10.0.20.1", "iface": "eth0"}],
            "neighbors": ["10.0.10.10"], "peers": [{"ip": "10.0.10.10", "port": 445, "state": "E"}]}
        s = netmap.architecture_svg([dc, piv],
                                    [Domain(name="corp.local", dc_ips=["10.0.10.10"])])
        md.parseString(s)
        self.assertIn("topology-driven", s)
        self.assertIn("Routed backbone", s)
        self.assertIn("router 10.0.10.1", s)          # real gateway device + IP
        self.assertIn("pivot · 10.0.20.11", s)        # dual-homed inter-segment link

    def test_architecture_empty_is_graceful(self):
        s = netmap.architecture_svg([])
        self.assertIn("No hosts", s)
