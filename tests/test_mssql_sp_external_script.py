"""SAFE detection of sp_execute_external_script RCE (Machine Learning
Services). Runs a small read-only batch via the existing impacket-mssqlclient
runner: SERVERPROPERTY('IsPolyBaseInstalled'), the `external scripts enabled`
sp_configure value, and IS_SRVROLEMEMBER('sysadmin'). Never invokes the
procedure itself.

Fixtures are derived from the sentinel format the module already uses for
its enum batches (`@@B:name` / `@@E:name`), plus the impacket-mssqlclient
tabular chrome (column header + separator line) so parse_external_scripts
must strip it correctly."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from recce.services.db import mssql


def _fake_mssqlclient_row(polybase: str, ext: str, is_sa: str) -> str:
    """The bytes impacket-mssqlclient prints for a single-column SELECT that
    concatenates '<polybase>|<external_scripts>|<is_sysadmin>' — sentinel
    wrapped, with the usual header/separator/NULL chrome the parser drops."""
    return (
        "SQL> SELECT '@@B:extscript'\n"
        "\n"
        "----\n"
        "@@B:extscript\n"
        "\n"
        "SQL> ...concat query...\n"
        "\n"
        "----------------------\n"
        f"{polybase}|{ext}|{is_sa}\n"
        "\n"
        "SQL> SELECT '@@E:extscript'\n"
        "\n"
        "----\n"
        "@@E:extscript\n"
    )


class ParseExternalScripts(unittest.TestCase):
    """The sentinel parser must survive real impacket chrome and only
    fire when the sentinels are present and the row has all three fields."""

    def test_parses_vulnerable_row(self):
        r = mssql.parse_external_scripts(_fake_mssqlclient_row("1", "1", "1"))
        self.assertTrue(r["ok"])
        self.assertTrue(r["polybase"])
        self.assertTrue(r["external_scripts"])
        self.assertTrue(r["is_sysadmin"])

    def test_parses_disabled_row(self):
        # Not vulnerable: external scripts off, login is not sysadmin.
        r = mssql.parse_external_scripts(_fake_mssqlclient_row("0", "0", "0"))
        self.assertTrue(r["ok"])
        self.assertFalse(r["external_scripts"])
        self.assertFalse(r["is_sysadmin"])

    def test_parses_partial_configuration(self):
        # Feature enabled but low-priv login — the finding wiring will drop it.
        r = mssql.parse_external_scripts(_fake_mssqlclient_row("0", "1", "0"))
        self.assertTrue(r["ok"])
        self.assertTrue(r["external_scripts"])
        self.assertFalse(r["is_sysadmin"])

    def test_no_sentinels_returns_not_ok(self):
        # Login refused, tool crashed, wrong tool — no sentinel in the output.
        self.assertFalse(mssql.parse_external_scripts("")["ok"])
        self.assertFalse(mssql.parse_external_scripts("some random gibberish")["ok"])

    def test_short_row_rejected(self):
        # Sentinels present but the concat row is malformed (missing columns).
        out = ("@@B:extscript\n"
               "1|1\n"
               "@@E:extscript\n")
        self.assertFalse(mssql.parse_external_scripts(out)["ok"])


class ProbeExternalScripts(unittest.TestCase):
    """probe_external_scripts drives the impacket-mssqlclient runner but must
    never invoke sp_execute_external_script. All network is faked here."""

    def test_missing_impacket_short_circuits(self):
        with patch.object(mssql, "_mssqlclient_cmd", return_value=None):
            r = mssql.probe_external_scripts(
                "10.0.0.1", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("impacket", r["error"])

    def test_runner_error_bubbles_up(self):
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=("", "timed out after 6s")):
            r = mssql.probe_external_scripts(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("timed out", r["error"])

    def test_vulnerable_target_returns_ok_and_flags(self):
        wire = _fake_mssqlclient_row("1", "1", "1")
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=(wire, None)) as run:
            r = mssql.probe_external_scripts(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertTrue(r["ok"])
        self.assertTrue(r["external_scripts"])
        self.assertTrue(r["is_sysadmin"])
        self.assertTrue(r["polybase"])
        # The batch fed to the runner must NEVER call sp_execute_external_script.
        # Verify by inspecting the script that actually went in on stdin.
        _args, kwargs = run.call_args
        script = run.call_args[0][1]        # second positional to _run_stdin
        self.assertNotIn("sp_execute_external_script", script.lower())
        self.assertIn("external scripts enabled", script)
        self.assertIn("IS_SRVROLEMEMBER('sysadmin')", script)
        # Password is answered off-argv via stdin (the runner contract).
        self.assertEqual(kwargs.get("password"), "p")

    def test_patched_target_returns_flags_false(self):
        # Feature turned off + sysadmin — safe (still enumerated).
        wire = _fake_mssqlclient_row("0", "0", "1")
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=(wire, None)):
            r = mssql.probe_external_scripts(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertTrue(r["ok"])
        self.assertFalse(r["external_scripts"])
        self.assertTrue(r["is_sysadmin"])

    def test_unparseable_output_negative(self):
        # Login failed / wrong protocol — no sentinels in the output.
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=("[-] Login failed for user 'u'.\n", None)):
            r = mssql.probe_external_scripts(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("no result", r["error"])


class ExternalScriptRceFinding(unittest.TestCase):
    """external_script_rce_finding requires BOTH: external scripts enabled AND
    the current login is sysadmin. Anything less returns None (no finding)."""

    def _tgt(self):
        return {"ip": "10.0.0.7", "port": 1433}

    def test_vulnerable_emits_finding(self):
        # (a) Vulnerable target -> critical, t2, CWE-77 + CWE-250, stable kind.
        probe = {"ok": True, "polybase": False, "external_scripts": True,
                 "is_sysadmin": True}
        f = mssql.external_script_rce_finding(
            self._tgt(), probe, {"user": "sa", "secret": "x"})
        self.assertIsNotNone(f)
        self.assertEqual(f["kind"], "mssql_external_script_rce")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f.get("depth_tier"), "t2")
        self.assertIn("CWE-77", f["cwes"])
        self.assertIn("CWE-250", f["cwes"])
        # exploit_note must reference sp_execute_external_script (the abuse)
        # but the runbook/command must NOT invoke it — only read-only guidance.
        self.assertIn("sp_execute_external_script", f["exploit_note"])
        self.assertIn("Python", f["exploit_note"])
        # Narrative wired through _NARRATIVE for the report.
        self.assertIn("Launchpad", f["narrative"])

    def test_patched_or_absent_no_finding(self):
        # (b) Patched / absent -> no finding.
        for probe in (
            {"ok": True, "external_scripts": False, "is_sysadmin": True},   # off
            {"ok": True, "external_scripts": True,  "is_sysadmin": False},  # low-priv
            {"ok": True, "external_scripts": False, "is_sysadmin": False},  # both off
            {"ok": False, "error": "impacket-mssqlclient not installed"},
            {"ok": False},
            {},
            None,
        ):
            self.assertIsNone(
                mssql.external_script_rce_finding(
                    self._tgt(), probe, {"user": "u", "secret": "p"}),
                f"unexpected finding for probe={probe!r}")

    def test_polybase_note_appears_when_installed(self):
        probe = {"ok": True, "polybase": True, "external_scripts": True,
                 "is_sysadmin": True}
        f = mssql.external_script_rce_finding(
            self._tgt(), probe, {"user": "sa", "secret": "x"})
        self.assertIn("PolyBase", f["detail"])

    def test_target_string_uses_ip_and_port(self):
        probe = {"ok": True, "external_scripts": True, "is_sysadmin": True}
        f = mssql.external_script_rce_finding(
            {"ip": "192.0.2.9", "port": 14330}, probe, None)
        self.assertEqual(f["target"], "192.0.2.9:14330")


if __name__ == "__main__":
    unittest.main()
