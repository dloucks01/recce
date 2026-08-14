"""Vuln-matcher false-positive fidelity.

The offline version->CVE matcher's worst failure isn't a miss - it's a FALSE POSITIVE:
flagging a PATCHED service as vulnerable, which erodes trust in every finding. This
suite guards that boundary two ways:

  * Data-driven: for EVERY pure version-range signature in the knowledge base, a version
    inside the range flags its CVEs, and the FIX version (the exclusive upper bound)
    does NOT - so the guard auto-scales as signatures are added.
  * Curated: the high-value version-parsing / provenance false positives that have
    actually bitten recce - OpenSSH's pN patch suffix, MariaDB's MySQL-compat version
    prefix, distro-backport downgrades, whole-token product matching, junk banners.

All against recce's real vulndb.assess_host_inplace over a synthetic banner.
"""
import unittest

from recce import vulndb
from recce.models import Host, Port


def _assess(product, version, service="", extra=""):
    svc = service or ((product.split() or ["x"])[0].lower())
    h = Host(ip="10.0.0.1", ports=[Port(
        portid=1234, protocol="tcp", state="open",
        service=svc, product=product, version=version, extrainfo=extra)])
    vulndb.assess_host_inplace(h)
    return h


def _cves(product, version, service="", extra=""):
    return {c for v in _assess(product, version, service, extra).vulns for c in v.ids}


def _conf(product, version, cve, service="", extra=""):
    return [v.confidence for v in _assess(product, version, service, extra).vulns
            if cve in v.ids]


class VulndbBoundaryFidelityTest(unittest.TestCase):
    """Every version-range signature: vulnerable version matches, fix version does not."""

    def test_every_version_range_signature_boundary(self):
        checked = 0
        for sig in vulndb.SIGNATURES:
            # Skip context-gated sigs (OS / DC / negative-matcher) - they need host
            # context a pure version-boundary synthetic banner can't stand in for.
            if any(k in sig for k in ("os", "os_lt", "dc_only", "absent")):
                continue
            cves = set(sig.get("cves") or [])
            if not cves:
                continue                     # hygiene/EOL sigs carry no CVE to bound
            product = sig["product"][0]
            # A version known to be IN range flags the CVEs (any confidence counts).
            in_range = sig.get("ge") or sig.get("eq") or sig.get("le")
            if in_range:
                got = _cves(product, in_range)
                self.assertTrue(
                    cves & got,
                    f"{product} {in_range} should flag {sorted(cves)}, got {sorted(got)}")
                checked += 1
            # The FIX (exclusive upper bound) must NOT flag THIS sig's CVEs (it may
            # still legitimately match a different overlapping sig - that's fine).
            fix = sig.get("lt")
            if fix:
                got = _cves(product, fix)
                self.assertFalse(
                    cves & got,
                    f"{product} {fix} is the fix but still flags {sorted(cves & got)}")
                checked += 1
        # Guard against the loop silently checking nothing (e.g. a schema change).
        self.assertGreaterEqual(checked, 30, f"boundary coverage too low ({checked})")


class VulndbFalsePositiveFidelityTest(unittest.TestCase):
    """Curated version-parsing / provenance false positives that have bitten recce."""

    def test_openssh_regresshion_pN_boundary(self):
        # CVE-2024-6387 (regreSSHion): [8.5p1, 9.8p1). The pN suffix must be parsed so
        # a patched 9.8p1 isn't read as "< 9.8p1".
        self.assertIn("CVE-2024-6387", _cves("OpenSSH", "9.2p1", "ssh"))    # vulnerable
        self.assertNotIn("CVE-2024-6387", _cves("OpenSSH", "9.8p1", "ssh"))  # the fix
        self.assertNotIn("CVE-2024-6387", _cves("OpenSSH", "9.9", "ssh"))    # newer

    def test_openssh_pN_patch_not_collapsed(self):
        # CVE-2023-38408: < 9.3p2. 9.3p1 is vulnerable, 9.3p2 is the fix - a naive
        # parser that drops the pN would treat 9.3p1 == 9.3p2 and mis-classify one.
        self.assertIn("CVE-2023-38408", _cves("OpenSSH", "9.3p1", "ssh"))
        self.assertNotIn("CVE-2023-38408", _cves("OpenSSH", "9.3p2", "ssh"))

    def test_mariadb_version_prefix_not_flagged_as_old_mysql(self):
        # MariaDB announces a legacy MySQL-compat "5.5.5-" prefix; the real version is
        # 10.11.6. It must NOT be read as an EOL/vulnerable MySQL 5.5.
        self.assertFalse(_cves("MariaDB", "5.5.5-10.11.6-MariaDB", "mysql"),
                         "patched MariaDB mis-flagged as old MySQL")
        # A genuine old MySQL 5.5 IS flagged (proves the guard isn't just blanket-silent).
        self.assertIn("CVE-2012-2122", _cves("MySQL", "5.5.40", "mysql"))

    def test_distro_backport_downgraded_to_potential(self):
        # A distro-packaged build carries the upstream version but the fix is often
        # backported without a version bump, so a match is a lead ("potential"), not
        # a confident finding ("likely").
        self.assertEqual(["potential"],
                         _conf("OpenSSH", "9.2p1", "CVE-2024-6387", "ssh",
                               extra="Ubuntu-2ubuntu2.1"))
        self.assertEqual(["likely"],
                         _conf("OpenSSH", "9.2p1", "CVE-2024-6387", "ssh"))

    def test_whole_token_product_match(self):
        # 'rpcbind' must not match an ISC 'bind' signature (whole-token, not substring).
        self.assertFalse(_cves("rpcbind", "1.2.5"), "rpcbind matched a bind signature")

    def test_junk_banners_produce_no_findings(self):
        for product in ("unknown", "tcpwrapped", ""):
            self.assertFalse(_cves(product, "", service="unknown"),
                             f"junk banner {product!r} produced a finding")

    def test_modern_patched_versions_are_clean(self):
        for product, version, service in [
            ("OpenSSH", "9.9", "ssh"),
            ("nginx", "1.27.0", "http"),
            ("Apache httpd", "2.4.62", "http"),
            ("vsftpd", "3.0.5", "ftp"),
            ("ProFTPD", "1.3.8", "ftp"),
            ("Samba", "4.19.0", "netbios-ssn"),
            ("MySQL", "8.0.36", "mysql"),
            ("PostgreSQL", "16.2", "postgresql"),
        ]:
            self.assertFalse(_cves(product, version, service),
                             f"{product} {version} (patched/modern) was flagged")


if __name__ == "__main__":
    unittest.main()
