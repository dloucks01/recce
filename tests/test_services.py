"""Unit tests for webui/services/ — the thin layer between routes and Store.

Point: services should be exercisable WITHOUT FastAPI. A tempfile db_path is
the only setup needed. If these tests ever need to spin up a TestClient,
something has leaked back into the service layer that belongs in the route.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from recce.core.store import Store
from recce.webui.services import credentials as credentials_svc
from recce.webui.services import findings as findings_svc


class _TmpDbMixin:
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp(prefix="recce-svc-test-")
        self.db_path = os.path.join(self._tmpdir, "engagement.sqlite")
        # Touch the DB so Store() migrates the schema.
        with Store(self.db_path):
            pass

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)


class FindingsServiceTest(_TmpDbMixin, unittest.TestCase):
    def test_set_note_rejects_empty_key(self):
        with self.assertRaises(findings_svc.ValidationError):
            findings_svc.set_note(self.db_path, "", "some note")

    def test_set_reviewed_rejects_empty_key(self):
        with self.assertRaises(findings_svc.ValidationError):
            findings_svc.set_reviewed(self.db_path, "", True)

    def test_note_persists_across_reads(self):
        findings_svc.set_note(self.db_path, "vuln:10.0.0.1:80:test", "look at this")
        with Store(self.db_path) as st:
            tr = st.get_tracking()
        self.assertIn("vuln:10.0.0.1:80:test", tr)
        _rev, note = tr["vuln:10.0.0.1:80:test"]
        self.assertEqual(note, "look at this")

    def test_tick_persists(self):
        findings_svc.set_reviewed(self.db_path, "vuln:10.0.0.1:80:foo", True)
        with Store(self.db_path) as st:
            tr = st.get_tracking()
        self.assertTrue(tr["vuln:10.0.0.1:80:foo"][0])

    def test_add_manual_finding_requires_ip(self):
        with self.assertRaises(findings_svc.ValidationError):
            findings_svc.add_manual_finding(
                self.db_path, tester="alice", ip="", title="",
                severity="high", port=None, cve="", output="")

    def test_add_manual_finding_rejects_bad_port(self):
        with self.assertRaises(findings_svc.ValidationError):
            findings_svc.add_manual_finding(
                self.db_path, tester="alice", ip="10.0.0.1", title="x",
                severity="high", port="99999", cve="", output="")

    def test_add_manual_finding_creates_host_and_vuln(self):
        info = findings_svc.add_manual_finding(
            self.db_path, tester="alice", ip="10.0.0.1", title="RCE via foo",
            severity="critical", port="8080",
            cve="CVE-2024-1234, CVE-2024-5678", output="proof-of-concept output")
        self.assertEqual(info["ip"], "10.0.0.1")
        self.assertEqual(info["severity"], "critical")
        with Store(self.db_path) as st:
            host = st.get_host("10.0.0.1")
        self.assertIsNotNone(host)
        self.assertEqual(host.state, "up")
        vulns = [v for v in host.vulns if v.source == "manual"]
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].title, "RCE via foo")
        self.assertEqual(vulns[0].severity, "critical")
        self.assertEqual(vulns[0].port, 8080)
        # Both CVEs should have been parsed out
        self.assertIn("CVE-2024-1234", vulns[0].ids)
        self.assertIn("CVE-2024-5678", vulns[0].ids)

    def test_add_manual_finding_defaults_severity(self):
        info = findings_svc.add_manual_finding(
            self.db_path, tester="alice", ip="10.0.0.2", title="x",
            severity="not-a-severity", port=None, cve="", output="")
        self.assertEqual(info["severity"], "medium")


class CredentialsServiceTest(_TmpDbMixin, unittest.TestCase):
    def test_list_credentials_empty(self):
        r = credentials_svc.list_credentials(self.db_path)
        self.assertEqual(r["items"], [])
        self.assertEqual(r["total"], 0)

    def test_list_credentials_pagination(self):
        # seed a few creds directly through the store
        from recce.core.models import Credential
        with Store(self.db_path) as st:
            for i in range(5):
                st.add_credential(Credential(
                    username=f"u{i}", secret=f"p{i}", kind="password",
                    domain="", source="test", origin_ip="10.0.0.1", notes=""))
        r = credentials_svc.list_credentials(self.db_path, limit=2, offset=1)
        self.assertEqual(r["total"], 5)
        self.assertEqual(len(r["items"]), 2)
        self.assertEqual(r["limit"], 2)
        self.assertEqual(r["offset"], 1)


class ServiceCliModuleWiringTest(unittest.TestCase):
    """Every `recce <service>` CLI command that invokes `_run_service_scan`
    passes a `module="<name>"` argument. That name must either:
      * appear in `_MODULE_PATH` with a resolvable dotted import path, OR
      * resolve via the `recce.<name>` fallback in `_run_service_scan`.

    Regression: `cmd_cloud_metadata` used to pass `module="cloud_metadata"`
    with no `_MODULE_PATH` entry, so the fallback tried to import
    `recce.cloud_metadata` — which doesn't exist (the real module lives at
    `recce.services.cloud_metadata`). Every `recce cloud_metadata` invocation
    ModuleNotFoundError'd until this test was added. This guard makes sure
    the wiring gap can't reopen for any service."""

    def test_every_cli_module_reference_resolves(self):
        import importlib, pathlib, re
        from recce.cli._service_helpers import _MODULE_PATH

        svc = pathlib.Path(__file__).parent.parent \
            / "recce" / "cli" / "_services.py"
        refs = set(re.findall(r'module=["\']([a-z_][a-z0-9_-]*)["\']',
                              svc.read_text()))
        self.assertTrue(refs, "expected _services.py to hold at least one "
                              "module= call — this test rot-detects if the "
                              "grep pattern goes stale")
        failures: list[str] = []
        for name in sorted(refs):
            path = _MODULE_PATH.get(name, f"recce.{name}")
            try:
                importlib.import_module(path)
            except ImportError as exc:
                failures.append(f"  {name}  →  {path}  ({exc})")
        if failures:
            self.fail(
                "The following CLI command references have no resolvable "
                "module — running `recce <name>` would hit the "
                "`_run_service_scan` import and ModuleNotFoundError:\n"
                + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
