"""Initial-access tracking: auto-derivation, step wiring, and the `access` command.

recce marks a host as 'access gained' when a credentialed phase confirms a foothold
(valid creds / local admin / SSH / MSSQL) or the operator records one; that state
auto-ticks the Checklist Access step. These tests cover the derivation signals, the
step_auto/MANUAL_STEPS wiring, the module hooks that set the flag, datastore
persistence across a merge, and the CLI command.
"""
import os
import shutil
import unittest

from recce import tracking as tr
from recce import credenum
from recce import cli
from recce.models import Host, Port, Vuln
from recce.store import Store


def _host(ip="10.0.0.5", *script_ids, port=445, svc="microsoft-ds"):
    vulns = [Vuln(ip=ip, port=port, protocol="tcp", script_id=s, state="finding",
                  title=s, severity="high", source="cred") for s in script_ids]
    return Host(ip=ip, ports=[Port(portid=port, state="open", service=svc)],
                vulns=vulns)


class AccessDeriveTest(unittest.TestCase):

    def test_stable_signals_are_recognised(self):
        self.assertIn("admin",
                      tr.access_from_findings(_host("10.0.0.5", "cred-smb-admin-alice")).lower())
        self.assertIn("secretsdump",
                      tr.access_from_findings(_host("10.0.0.5", "cred-secretsdump")).lower())
        self.assertIn("ssh",
                      tr.access_from_findings(_host("10.0.0.5", "ssh-sudo")).lower())

    def test_unrelated_findings_do_not_imply_access(self):
        self.assertEqual(tr.access_from_findings(_host("10.0.0.5", "web-dirlisting")), "")
        self.assertEqual(tr.access_from_findings(_host("10.0.0.5")), "")

    def test_access_is_no_longer_a_manual_step(self):
        self.assertNotIn("access", tr.MANUAL_STEPS)

    def test_step_auto_follows_the_flag(self):
        h = _host()
        self.assertFalse(tr.step_auto(h, "access"))
        h.access_gained = True
        self.assertTrue(tr.step_auto(h, "access"))

    def test_step_applies_needs_an_open_port(self):
        self.assertTrue(tr.step_applies(_host(), "access"))
        self.assertFalse(tr.step_applies(Host(ip="10.0.0.9"), "access"))


class AccessModuleHookTest(unittest.TestCase):

    def test_credenum_admin_sets_access(self):
        h = Host(ip="10.0.0.5", ports=[Port(portid=445, state="open")])
        credenum._fold_nxc(h, {"admin": True, "auth": True, "shares": [],
                               "users": [], "loggedon": [], "passpol": {}})
        self.assertTrue(h.access_gained)
        self.assertIn("admin", h.access_detail.lower())

    def test_credenum_auth_without_admin_still_sets_access(self):
        h = Host(ip="10.0.0.6", ports=[Port(portid=445, state="open")])
        credenum._fold_nxc(h, {"admin": False, "auth": True, "shares": [],
                               "users": [], "loggedon": [], "passpol": {}})
        self.assertTrue(h.access_gained)

    def test_failed_auth_does_not_set_access(self):
        h = Host(ip="10.0.0.7", ports=[Port(portid=445, state="open")])
        credenum._fold_nxc(h, {"admin": False, "auth": False, "shares": [],
                               "users": [], "loggedon": [], "passpol": {}})
        self.assertFalse(h.access_gained)

    def test_ssh_fold_sets_access(self):
        h = Host(ip="10.0.0.8", ports=[Port(portid=22, state="open")])
        credenum._fold_ssh(h, {"id": "uid=0(root)", "sudo": [], "suid": [],
                               "kernel": "", "os": ""})
        self.assertTrue(h.access_gained)
        self.assertIn("ssh", h.access_detail.lower())


class AccessPersistenceTest(unittest.TestCase):

    def setUp(self):
        self.path = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                                 f"recce_acc_{os.getpid()}.sqlite")
        if os.path.exists(self.path):
            os.unlink(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.unlink(self.path)

    def test_flag_round_trips_and_survives_merge(self):
        store = Store(self.path)
        h = Host(ip="10.0.0.5", subnet="10.0.0.0/24",
                 ports=[Port(portid=445, state="open")],
                 access_gained=True, access_detail="SMB local admin")
        store.upsert_host(h, merge=False)
        # A later re-scan of the same host (no access info) must not clear it.
        rescan = Host(ip="10.0.0.5", subnet="10.0.0.0/24",
                      ports=[Port(portid=445, state="open")])
        store.upsert_host(rescan, merge=True)
        got = store.get_host("10.0.0.5")
        store.close()
        self.assertTrue(got.access_gained)
        self.assertEqual(got.access_detail, "SMB local admin")


class AccessCommandTest(unittest.TestCase):

    def setUp(self):
        import recce
        self.dir = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                                f"recce_acccmd_{os.getpid()}")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        sample = os.path.join(os.path.dirname(recce.__file__), "sample_scan.xml")
        self.assertEqual(cli.main(["import", sample, "-o", self.dir]), 0)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _host(self, ip):
        store = Store(os.path.join(self.dir, "results.sqlite"))
        try:
            return store.get_host(ip)
        finally:
            store.close()

    def test_manual_record_and_undo(self):
        rc = cli.main(["access", "--host", "10.0.10.10", "--note", "shell via CVE",
                       "-o", self.dir])
        self.assertEqual(rc, 0)
        h = self._host("10.0.10.10")
        self.assertTrue(h.access_gained)
        self.assertEqual(h.access_detail, "shell via CVE")

        rc = cli.main(["access", "--host", "10.0.10.10", "--undo", "-o", self.dir])
        self.assertEqual(rc, 0)
        self.assertFalse(self._host("10.0.10.10").access_gained)

    def test_missing_datastore_reported(self):
        empty = self.dir + "_empty"
        shutil.rmtree(empty, ignore_errors=True)
        os.makedirs(empty)
        rc = cli.main(["access", "-o", empty])
        self.assertEqual(rc, 1)
        shutil.rmtree(empty, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
