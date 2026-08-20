"""Data-quality regression tests for the seeded demo engagement.

tools/mock_engagement.py builds the sample data shown in the workbench, the demo
reports, and README screenshots - so a bug here isn't just a test failure, it's
wrong data every reviewer sees. Guards two real bugs found reviewing the generated
reports: every host silently had subnet="" (a real scan/import always sets it), and
the fabricated rpcbind/nfs ports duplicated the version string into the product
field ("2-4" / "2-4 (RPC #100000)"), rendering nonsense like "2-4 2-4 (RPC #100000)"
in every report format.
"""
import tempfile
import unittest

from tools.mock_engagement import build


class MockEngagementDataQualityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from recce.store import Store
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


if __name__ == "__main__":
    unittest.main()
