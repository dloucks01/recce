"""Credentialed-path integration tests: real subprocess -> parse -> fold -> access.

The unauth probes have live-socket tests; the credentialed modules (credenum / mssql)
were only ever exercised with monkeypatched fakes. These install a fake `nxc` binary
on PATH that emits real netexec output, so recce's actual tool invocation
(subprocess.run), stdout parse, finding fold and access-derivation all run for real -
just without needing netexec or a live DC.
"""
import json
import os
import shutil
import stat
import unittest

from recce import credenum
from recce import mssql
from recce import cli
from recce.models import Host, Port
from recce.store import Store
from tests import wire_vectors as W


def _write_fake_nxc(dir_path):
    """A fake `nxc` that branches on the subcommand and prints the matching real
    netexec output, ignoring the rest of the args (target, creds, flags)."""
    script = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"SMB = {json.dumps(W.NXC_SMB_OUTPUT)}\n"
        f"MSSQL = {json.dumps(W.NXC_MSSQL_OUTPUT)}\n"
        "sub = sys.argv[1] if len(sys.argv) > 1 else ''\n"
        "sys.stdout.write(SMB if sub == 'smb' else MSSQL if sub == 'mssql' else '')\n"
    )
    path = os.path.join(dir_path, "nxc")
    with open(path, "w") as fh:
        fh.write(script)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class _FakeToolMixin(unittest.TestCase):
    def setUp(self):
        self.tooldir = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                                    f"recce_faketool_{os.getpid()}")
        shutil.rmtree(self.tooldir, ignore_errors=True)
        os.makedirs(self.tooldir)
        _write_fake_nxc(self.tooldir)
        self._old_path = os.environ["PATH"]
        os.environ["PATH"] = self.tooldir + os.pathsep + self._old_path

    def tearDown(self):
        os.environ["PATH"] = self._old_path
        shutil.rmtree(self.tooldir, ignore_errors=True)


class NxcSubprocessTest(_FakeToolMixin):

    def test_smb_tool_is_discovered_on_path(self):
        self.assertTrue(credenum.smb_tool(), "fake nxc not found on PATH")

    def test_run_nxc_smb_real_subprocess_parses(self):
        data, err = credenum.run_nxc_smb(
            "10.0.10.10", {"username": "admin", "password": "pw", "domain": "corp.local"})
        self.assertIsNone(err)
        self.assertIsNotNone(data)
        self.assertTrue(data["admin"])                 # (Pwn3d!) in the fixture
        self.assertTrue(any(s["name"] == "ADMIN$" for s in data["shares"]))

    def test_fold_sets_findings_accounts_and_access(self):
        data, _ = credenum.run_nxc_smb(
            "10.0.10.10", {"username": "admin", "password": "pw", "domain": "corp.local"})
        host = Host(ip="10.0.10.10", ports=[Port(portid=445, state="open")])
        credenum._fold_nxc(host, data)
        self.assertTrue(host.access_gained)            # admin -> foothold
        self.assertIn("admin", host.access_detail.lower())
        self.assertTrue(any(v.script_id.startswith("cred-smb-admin") for v in host.vulns))
        self.assertTrue(host.accounts)                 # shares/users folded in

    def test_run_nxc_mssql_real_subprocess_parses(self):
        parsed, err = mssql.run_nxc_mssql(
            "10.0.10.10", {"user": "sa", "secret": "pw", "domain": "corp.local"})
        self.assertIsNone(err)
        self.assertTrue(parsed["access"])
        self.assertTrue(parsed["admin"])               # Pwn3d! in the mssql fixture


class CredenumCliIntegrationTest(_FakeToolMixin):
    """Drive `recce credenum` end to end against the fake nxc: the DC host in the
    bundled sample should gain the credentialed findings + access flag, persisted."""

    def setUp(self):
        super().setUp()
        import recce
        self.dir = os.path.join(os.environ.get("TMPDIR", "/tmp"),
                                f"recce_credcli_{os.getpid()}")
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir)
        sample = os.path.join(os.path.dirname(recce.__file__), "sample_scan.xml")
        self.assertEqual(cli.main(["import", sample, "-o", self.dir]), 0)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)
        super().tearDown()

    @unittest.skipUnless(shutil.which("nmap"), "nmap not installed")
    def test_credenum_folds_nxc_output_and_marks_access(self):
        # The credenum CLI shares recce's environment preflight, which requires nmap
        # on PATH (recce's one hard dependency); skip cleanly where it's absent. The
        # nxc subprocess/parse/fold path itself is covered by NxcSubprocessTest above,
        # which needs no nmap.
        # Scope to the DC only, so no ssh/other tools fire against non-routable IPs.
        rc = cli.main(["credenum", "10.0.10.10", "-u", "alice", "-p", "Passw0rd!",
                       "-d", "corp.local", "-o", self.dir])
        self.assertEqual(rc, 0)
        store = Store(os.path.join(self.dir, "results.sqlite"))
        try:
            host = store.get_host("10.0.10.10")
        finally:
            store.close()
        self.assertTrue(host.access_gained, "credenum did not record access")
        self.assertTrue(any(v.script_id.startswith("cred-smb-admin") for v in host.vulns))
        self.assertTrue(any(a.kind == "share" for a in host.accounts))


if __name__ == "__main__":
    unittest.main()
