"""Data-quality regression tests for the seeded demo engagement.

tools/mock_engagement.py builds the sample data shown in the workbench, the demo
reports, and README screenshots - so a bug here isn't just a test failure, it's
wrong data every reviewer sees. Guards real bugs found reviewing the generated
reports: every host silently had subnet="" (a real scan/import always sets it); the
fabricated rpcbind/nfs ports duplicated the version string into the product field
("2-4" / "2-4 (RPC #100000)"), rendering nonsense like "2-4 2-4 (RPC #100000)" in
every report format; and the DC's domain-kind Account carried the realm in `.name`
instead of `.domain` (the field ad.derive_domains() actually reads, matching the
real smb-os-discovery parser's shape) - so despite being an obvious AD engagement,
derive_domains() returned [], silently dropping the "Domain contoso.local" line
from the markdown report AND the entire "Key information" section from assets.html.
"""
import tempfile
import unittest

from tools.mock_engagement import build


class MockEngagementDataQualityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from recce.core.store import Store
        cls.dir = tempfile.mkdtemp(prefix="recce-mock-eng-")
        cls.stats = build(cls.dir, hosts=15, seed=1337)
        cls.hosts = Store(f"{cls.dir}/results.sqlite").all_hosts()

    def test_every_host_has_a_subnet(self):
        # A real scan/import always stamps host.subnet; the seeded data must match,
        # or every report's subnet count/grouping silently reads as empty.
        missing = [h.ip for h in self.hosts if not h.subnet]
        self.assertEqual(missing, [], f"host(s) with no subnet: {missing}")

    def test_subnet_count_matches_the_reported_stat(self):
        distinct = {h.subnet for h in self.hosts if h.subnet}
        self.assertEqual(len(distinct), self.stats["subnets"])

    def test_rpc_service_product_and_version_are_not_duplicated(self):
        # product must be the real service name ("rpcbind"/"nfs"), not the version
        # range, and version must not repeat "(RPC #...)" already carried separately.
        for h in self.hosts:
            for p in h.ports:
                if p.portid in (111, 2049):
                    self.assertIn(p.product, ("rpcbind", "nfs"), f"{h.ip}:{p.portid}")
                    self.assertNotIn("(RPC #", p.version, f"{h.ip}:{p.portid}")
                    self.assertNotEqual(p.product, p.version, f"{h.ip}:{p.portid}")

    def test_ad_domain_is_derivable(self):
        # The DC's domain-kind Account must carry .domain, or ad.derive_domains()
        # silently returns [] for an obviously-AD engagement - dropping the domain
        # line from every report that calls it (markdown, assets.html Key info).
        from recce import ad
        doms = ad.derive_domains(self.hosts)
        self.assertEqual([d.name for d in doms], ["contoso.local"])
        dom = doms[0]
        self.assertEqual(dom.netbios, "CONTOSO")
        self.assertIn("10.20.10.10", dom.dc_ips)

    def test_assets_html_renders_key_information(self):
        # End-to-end: build_assets_html's "Key information" section only renders
        # when domains resolve non-empty - assert it actually appears in the page,
        # not just that derive_domains() returns something in isolation.
        import tempfile as _tf
        from recce.report import html as report_html
        out = f"{_tf.mkdtemp()}/assets.html"
        report_html.build_assets_html(self.hosts, out, title="t")
        html = open(out, encoding="utf-8").read()
        self.assertIn("Key information", html)
        self.assertIn("contoso.local", html)


if __name__ == "__main__":
    unittest.main()
