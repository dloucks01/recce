"""SAFE metadata-only disclosure of stored replication / SQL Agent secrets.

Reads NAMES from `sys.credentials`, `msdb.dbo.sysproxies`, and the row count
from `msdb.dbo.syscachedcredentials` via the existing impacket-mssqlclient
runner. NEVER touches the encrypted secret bytes (no CONVERT of
credential_identity_secret, no DecryptByKey, no LSA hop). Fixtures are
derived from the sentinel format the module already uses for its batches
(`@@B:name` / `@@E:name`), plus the impacket-mssqlclient tabular chrome
(column header + separator line) so the parser must strip it correctly."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from recce.services.db import mssql


def _fake_replsec(is_sa: str, cred_names: list[str],
                  proxies: list[tuple[int, str]],
                  cached: int) -> str:
    """The bytes impacket-mssqlclient prints for the sentinel-wrapped batch
    (admin marker + creds + proxies + cached count), with the header /
    separator / SQL> chrome the parser must drop."""
    def _wrap(name: str, body_lines: list[str], header: str) -> str:
        return (
            f"SQL> SELECT '@@B:{name}'\n"
            "\n"
            "----\n"
            f"@@B:{name}\n"
            "\n"
            "SQL> ...query...\n"
            "\n"
            f"{header}\n"
            "----\n"
            + "".join(f"{ln}\n" for ln in body_lines)
            + "\n"
            f"SQL> SELECT '@@E:{name}'\n"
            "\n"
            "----\n"
            f"@@E:{name}\n"
        )

    out = _wrap("replsec_admin", [is_sa], "col")
    out += _wrap("replsec_creds", list(cred_names), "name")
    out += _wrap(
        "replsec_proxies",
        [f"{pid}|{pname}" for pid, pname in proxies],
        "col")
    out += _wrap("replsec_cached", [str(cached)], "col")
    return out


class ParseReplicationSecrets(unittest.TestCase):
    """The parser must survive real impacket chrome and only fire when the
    admin sentinel is present. Every branch — vulnerable, empty, non-admin,
    absent — is covered."""

    def test_parses_vulnerable_row(self):
        out = _fake_replsec(
            "1",
            ["BackupSvc", "SSIS_prod", "Repl_Distributor"],
            [(1, "SSIS_proxy"), (2, "Repl_proxy")],
            3)
        r = mssql.parse_replication_secrets(out)
        self.assertTrue(r["ok"])
        self.assertTrue(r["is_sysadmin"])
        self.assertEqual(r["credentials"],
                         ["BackupSvc", "SSIS_prod", "Repl_Distributor"])
        self.assertEqual(r["proxies"],
                         [{"proxy_id": 1, "name": "SSIS_proxy"},
                          {"proxy_id": 2, "name": "Repl_proxy"}])
        self.assertEqual(r["cached_count"], 3)

    def test_parses_patched_row(self):
        # Sysadmin but nothing stored — clean instance.
        out = _fake_replsec("1", [], [], 0)
        r = mssql.parse_replication_secrets(out)
        self.assertTrue(r["ok"])
        self.assertTrue(r["is_sysadmin"])
        self.assertEqual(r["credentials"], [])
        self.assertEqual(r["proxies"], [])
        self.assertEqual(r["cached_count"], 0)

    def test_parses_non_sysadmin_row(self):
        # Login not sysadmin: sys.credentials returns empty by design.
        out = _fake_replsec("0", [], [], 0)
        r = mssql.parse_replication_secrets(out)
        self.assertTrue(r["ok"])
        self.assertFalse(r["is_sysadmin"])

    def test_no_sentinels_returns_not_ok(self):
        self.assertFalse(mssql.parse_replication_secrets("")["ok"])
        self.assertFalse(mssql.parse_replication_secrets("garbage")["ok"])
        self.assertFalse(mssql.parse_replication_secrets(
            "[-] Login failed for user 'u'.\n")["ok"])

    def test_malformed_proxy_row_rejected(self):
        # Proxy row missing the '|' or with a non-numeric id is skipped.
        out = _fake_replsec("1", ["A"],
                            [(9, "good_proxy")], 0)
        # Inject a malformed line into the proxies section by hand.
        out = out.replace("9|good_proxy\n",
                          "9|good_proxy\nbogus_row\nnot_a_pipe\n"
                          "abc|nonnumeric\n")
        r = mssql.parse_replication_secrets(out)
        self.assertTrue(r["ok"])
        self.assertEqual(r["proxies"],
                         [{"proxy_id": 9, "name": "good_proxy"}])


class ProbeReplicationSecrets(unittest.TestCase):
    """probe_replication_secrets drives the impacket-mssqlclient runner
    (mocked here — no live network) but must never read the encrypted
    secret bytes or call DecryptByKey."""

    def test_missing_impacket_short_circuits(self):
        with patch.object(mssql, "_mssqlclient_cmd", return_value=None):
            r = mssql.probe_replication_secrets(
                "10.0.0.1", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("impacket", r["error"])

    def test_runner_error_bubbles_up(self):
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=("", "timed out after 6s")):
            r = mssql.probe_replication_secrets(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("timed out", r["error"])

    def test_vulnerable_target_returns_names_only(self):
        wire = _fake_replsec("1", ["BackupSvc"], [(1, "SSIS_proxy")], 2)
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=(wire, None)) as run:
            r = mssql.probe_replication_secrets(
                "1.2.3.4", {"user": "sa", "secret": "p"})
        self.assertTrue(r["ok"])
        self.assertTrue(r["is_sysadmin"])
        self.assertEqual(r["credentials"], ["BackupSvc"])
        self.assertEqual(r["proxies"],
                         [{"proxy_id": 1, "name": "SSIS_proxy"}])
        self.assertEqual(r["cached_count"], 2)

        # The batch fed to the runner must NEVER read the encrypted secret
        # bytes or invoke DecryptByKey — this is metadata-only.
        script = run.call_args[0][1]
        low = script.lower()
        self.assertNotIn("decryptbykey", low)
        self.assertNotIn("credential_identity_secret", low)
        self.assertNotIn("credential_identity", low)   # name-only, no identity
        self.assertNotIn("password", low)              # no proxy password col
        # And it MUST query exactly the three metadata surfaces.
        self.assertIn("sys.credentials", script)
        self.assertIn("msdb.dbo.sysproxies", script)
        self.assertIn("msdb.dbo.syscachedcredentials", script)
        # Sysadmin gating carried in the batch (existing pattern).
        self.assertIn("IS_SRVROLEMEMBER('sysadmin')", script)
        # Password answered off-argv via stdin (the runner contract).
        _args, kwargs = run.call_args
        self.assertEqual(kwargs.get("password"), "p")

    def test_patched_target_returns_ok_and_empty(self):
        wire = _fake_replsec("1", [], [], 0)
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=(wire, None)):
            r = mssql.probe_replication_secrets(
                "1.2.3.4", {"user": "sa", "secret": "p"})
        self.assertTrue(r["ok"])
        self.assertTrue(r["is_sysadmin"])
        self.assertEqual(r["credentials"], [])
        self.assertEqual(r["proxies"], [])
        self.assertEqual(r["cached_count"], 0)

    def test_unparseable_output_negative(self):
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=("[-] Login failed for user 'u'.\n",
                                        None)):
            r = mssql.probe_replication_secrets(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("no result", r["error"])


class ReplicationSecretsFinding(unittest.TestCase):
    """replication_secrets_finding requires sysadmin AND at least one
    disclosed name (credential / proxy / cached row). Anything less returns
    None. The finding lists names only — never encrypted bytes."""

    def _tgt(self):
        return {"ip": "10.0.0.7", "port": 1433}

    def test_vulnerable_emits_finding(self):
        probe = {"ok": True, "is_sysadmin": True,
                 "credentials": ["BackupSvc", "SSIS_prod"],
                 "proxies": [{"proxy_id": 1, "name": "SSIS_proxy"}],
                 "cached_count": 4}
        f = mssql.replication_secrets_finding(
            self._tgt(), probe, {"user": "sa", "secret": "x"})
        self.assertIsNotNone(f)
        self.assertEqual(f["kind"], "mssql_replication_secrets")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f.get("depth_tier"), "t1")
        self.assertIn("CWE-522", f["cwes"])
        self.assertIn("CWE-257", f["cwes"])
        # Names must appear in the detail; encrypted-bytes language must NOT.
        self.assertIn("BackupSvc", f["detail"])
        self.assertIn("SSIS_prod", f["detail"])
        self.assertIn("SSIS_proxy", f["detail"])
        self.assertIn("4", f["detail"])   # cached count
        self.assertNotIn("DecryptByKey", f["detail"])
        self.assertNotIn("credential_identity_secret", f["detail"])
        # Runbook command must be a metadata read; no DecryptByKey or
        # secret-column selection.
        self.assertNotIn("DecryptByKey", f["command"])
        self.assertNotIn("credential_identity_secret", f["command"])
        self.assertIn("sys.credentials", f["command"])
        self.assertIn("sysproxies", f["command"])
        self.assertIn("syscachedcredentials", f["command"])
        # Narrative wired through _NARRATIVE for the report.
        self.assertIn("Service Master Key", f["narrative"])
        # exploit_note points at PowerUpSQL for the recovery step recce
        # deliberately did NOT take.
        self.assertIn("PowerUpSQL", f["exploit_note"])
        self.assertIn("Get-SQLServerCredential", f["exploit_note"])

    def test_non_sysadmin_no_finding(self):
        # Without sysadmin, sys.credentials is empty by design — no visibility,
        # no finding, no false negative-turned-positive.
        probe = {"ok": True, "is_sysadmin": False,
                 "credentials": [], "proxies": [], "cached_count": 0}
        self.assertIsNone(
            mssql.replication_secrets_finding(
                self._tgt(), probe, {"user": "u", "secret": "p"}))

    def test_absent_no_finding(self):
        # Sysadmin but nothing stored — clean instance, nothing to report.
        for probe in (
            {"ok": True, "is_sysadmin": True,
             "credentials": [], "proxies": [], "cached_count": 0},
            {"ok": False, "error": "impacket-mssqlclient not installed"},
            {"ok": False},
            {},
            None,
        ):
            self.assertIsNone(
                mssql.replication_secrets_finding(
                    self._tgt(), probe, {"user": "u", "secret": "p"}),
                f"unexpected finding for probe={probe!r}")

    def test_cached_only_still_emits(self):
        # A distributor with cached credentials but no server CREDENTIAL
        # objects is still a disclosure worth reporting.
        probe = {"ok": True, "is_sysadmin": True,
                 "credentials": [], "proxies": [], "cached_count": 2}
        f = mssql.replication_secrets_finding(
            self._tgt(), probe, {"user": "sa", "secret": "x"})
        self.assertIsNotNone(f)
        self.assertIn("cached replication credential", f["detail"])

    def test_long_credential_list_is_previewed(self):
        # Ten credentials -> preview 5 + '(+5 more)' — no leak of the
        # encrypted bytes even in the truncated detail.
        names = [f"cred_{i}" for i in range(10)]
        probe = {"ok": True, "is_sysadmin": True,
                 "credentials": names, "proxies": [], "cached_count": 0}
        f = mssql.replication_secrets_finding(
            self._tgt(), probe, {"user": "sa", "secret": "x"})
        self.assertIn("+5 more", f["detail"])
        self.assertIn("cred_0", f["detail"])
        self.assertIn("cred_4", f["detail"])

    def test_target_string_uses_ip_and_port(self):
        probe = {"ok": True, "is_sysadmin": True,
                 "credentials": ["X"], "proxies": [], "cached_count": 0}
        f = mssql.replication_secrets_finding(
            {"ip": "192.0.2.9", "port": 14330}, probe, None)
        self.assertEqual(f["target"], "192.0.2.9:14330")


if __name__ == "__main__":
    unittest.main()
