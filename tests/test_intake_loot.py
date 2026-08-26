"""Tests for recce.intake.loot — evidence-tree loot scanner.

Populates a scratch engagement directory with representative evidence
files (ticket, cred, git dump, secret-bearing config), runs scan_evidence,
and verifies each category produces the expected Vuln findings without
false positives on innocent files.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from recce.intake.loot import scan_evidence


class _Eng:
    """Tiny helper: build an evidence tree under a tempdir."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="recce_loot_test_")

    def add(self, ip: str, path_parts: list[str], content: bytes = b""):
        p = os.path.join(self.dir, "evidence", ip, *path_parts)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(content)
        return p

    def cleanup(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)


class ScanEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.eng = _Eng()

    def tearDown(self):
        self.eng.cleanup()

    def test_kerberos_ticket_detected(self):
        self.eng.add("10.0.0.5", ["administrator.ccache"], b"binary ticket blob")
        self.eng.add("10.0.0.5", ["service.kirbi"], b"binary ticket blob")
        vulns = scan_evidence(self.eng.dir)
        tickets = [v for v in vulns if v.script_id == "loot-kerberos-ticket"]
        self.assertEqual(len(tickets), 2, f"expected 2 tickets, got {[v.title for v in tickets]}")
        self.assertTrue(all(v.severity == "critical" for v in tickets))
        self.assertTrue(all(v.ip == "10.0.0.5" for v in tickets))

    def test_cred_file_detected(self):
        self.eng.add("10.0.0.6", ["id_rsa"], b"-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n")
        self.eng.add("10.0.0.6", [".netrc"], b"machine github.com login x password y\n")
        self.eng.add("10.0.0.6", ["config.pem"], b"key data")
        vulns = scan_evidence(self.eng.dir)
        creds = [v for v in vulns if v.script_id == "loot-cred-file"]
        self.assertGreaterEqual(len(creds), 3)

    def test_git_dump_detected(self):
        self.eng.add("10.0.0.7", [".git", "HEAD"], b"ref: refs/heads/main\n")
        self.eng.add("10.0.0.7", [".git", "config"], b"[core]\n\trepositoryformatversion=0\n")
        vulns = scan_evidence(self.eng.dir)
        git = [v for v in vulns if v.script_id == "loot-git-dump"]
        self.assertGreater(len(git), 0)

    def test_config_secrets_grepped(self):
        env_body = (b"DB_PASSWORD=hunter2\n"
                    b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                    b"# just a comment\n")
        self.eng.add("10.0.0.8", ["app.env"], env_body)
        yaml_body = (b"database:\n"
                     b"  url: postgres://appuser:s3cr3t@dbserver/appdb\n")
        self.eng.add("10.0.0.8", ["config.yaml"], yaml_body)
        vulns = scan_evidence(self.eng.dir)
        secrets = [v for v in vulns if v.script_id == "loot-config-secrets"]
        self.assertEqual(len(secrets), 2, [v.title for v in secrets])
        # AWS + DB URL should push at least one to critical.
        self.assertTrue(any(v.severity == "critical" for v in secrets),
                        f"expected at least one critical, got {[(v.title, v.severity) for v in secrets]}")

    def test_no_findings_on_innocent_files(self):
        self.eng.add("10.0.0.9", ["screenshot.png"], b"\x89PNG\r\n\x1a\n" + b"innocent")
        self.eng.add("10.0.0.9", ["notes.txt"], b"just some text notes here\n")
        vulns = scan_evidence(self.eng.dir)
        self.assertEqual(vulns, [])

    def test_missing_evidence_dir_returns_empty(self):
        # No evidence/ subdir at all
        empty_dir = tempfile.mkdtemp(prefix="recce_loot_empty_")
        try:
            self.assertEqual(scan_evidence(empty_dir), [])
        finally:
            import shutil; shutil.rmtree(empty_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
