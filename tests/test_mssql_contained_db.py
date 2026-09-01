"""SAFE detection of contained-database authentication users on MSSQL.

Contained databases (sys.databases.containment > 0) hold users whose passwords
live inside the DB (sys.database_principals.authentication_type = 2) and
bypass the server login-policy / audit surface. Detection runs a read-only
enumeration via the existing impacket-mssqlclient runner — no auth attempts,
no spray, no writes.

Fixtures are derived from the sentinel format the module already emits for its
enum batches (`@@B:name` / `@@E:name`), plus the impacket-mssqlclient tabular
chrome (column header + separator line) so the parsers have to strip it."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from recce.services.db import mssql


def _fake_contained_dbs_out(rows: list[tuple[str, str]]) -> str:
    """impacket-mssqlclient output for the contained-DBs listing."""
    body_lines = "\n".join(f"{name}|{desc}" for name, desc in rows)
    return (
        "SQL> SELECT '@@B:contdbs'\n"
        "\n"
        "----\n"
        "@@B:contdbs\n"
        "\n"
        "SQL> SELECT name+'|'+containment_desc FROM sys.databases WHERE containment>0\n"
        "\n"
        "----------------------\n"
        f"{body_lines}\n"
        "\n"
        "SQL> SELECT '@@E:contdbs'\n"
        "\n"
        "----\n"
        "@@E:contdbs\n"
    )


def _fake_contained_users_out(pairs: list[tuple[int, str, int]]) -> str:
    """impacket-mssqlclient output for the per-db user-count batch.
    `pairs` is [(index, db_name, count), ...] in the same order the script
    would have emitted them."""
    chunks = []
    for i, db, count in pairs:
        chunks.append(
            f"SQL> USE [{db}]\n"
            f"SQL> SELECT '@@B:contusers:{i}'\n"
            "\n"
            "----\n"
            f"@@B:contusers:{i}\n"
            "\n"
            "SQL> SELECT DB_NAME()+'|'+CAST(COUNT(*) AS varchar(8)) ...\n"
            "\n"
            "----------------------\n"
            f"{db}|{count}\n"
            "\n"
            f"SQL> SELECT '@@E:contusers:{i}'\n"
            "\n"
            "----\n"
            f"@@E:contusers:{i}\n"
        )
    return "\n".join(chunks)


class ParseContainedDbs(unittest.TestCase):
    """Sentinel-wrapped listing survives impacket chrome and only yields
    real rows."""

    def test_parses_multiple_contained_dbs(self):
        wire = _fake_contained_dbs_out(
            [("PayrollDB", "PARTIAL"), ("HRDb", "PARTIAL")])
        rows = mssql.parse_contained_dbs(wire)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["name"], "PayrollDB")
        self.assertEqual(rows[0]["containment_desc"], "PARTIAL")
        self.assertEqual(rows[1]["name"], "HRDb")

    def test_no_sentinel_returns_empty(self):
        # Login refused / wrong protocol — never yields rows.
        self.assertEqual(mssql.parse_contained_dbs(""), [])
        self.assertEqual(mssql.parse_contained_dbs("random gibberish"), [])

    def test_empty_sentinel_block(self):
        wire = _fake_contained_dbs_out([])
        # Sentinel present but no data rows — nothing to report.
        self.assertEqual(mssql.parse_contained_dbs(wire), [])


class ParseContainedUsers(unittest.TestCase):
    """Per-db user counts round-trip only when DB_NAME() confirms USE landed."""

    def test_parses_counts_when_use_landed(self):
        dbs = ["PayrollDB", "HRDb"]
        wire = _fake_contained_users_out(
            [(0, "PayrollDB", 3), (1, "HRDb", 1)])
        counts = mssql.parse_contained_users(wire, dbs)
        self.assertEqual(counts, {"PayrollDB": 3, "HRDb": 1})

    def test_use_mismatch_drops_entry(self):
        # DB_NAME() came back as master (USE denied) — not the requested DB —
        # so the entry is omitted rather than reported as zero.
        dbs = ["PayrollDB"]
        wire = _fake_contained_users_out([(0, "master", 0)])
        self.assertEqual(mssql.parse_contained_users(wire, dbs), {})

    def test_missing_section_dropped(self):
        # The per-db batch never ran (tool crashed mid-run) — nothing recorded.
        self.assertEqual(
            mssql.parse_contained_users("", ["PayrollDB"]), {})


class ProbeContainedDbAuth(unittest.TestCase):
    """probe_contained_db_auth drives impacket-mssqlclient but never issues
    an auth attempt / spray / write. All network faked."""

    def test_missing_impacket_short_circuits(self):
        with patch.object(mssql, "_mssqlclient_cmd", return_value=None):
            r = mssql.probe_contained_db_auth(
                "10.0.0.1", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("impacket", r["error"])

    def test_runner_error_bubbles_up(self):
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=("", "timed out after 6s")):
            r = mssql.probe_contained_db_auth(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("timed out", r["error"])

    def test_vulnerable_target_reports_contained_dbs_and_users(self):
        # (a) Vulnerable: two contained DBs, one carries users, one doesn't.
        dbs_out = _fake_contained_dbs_out(
            [("PayrollDB", "PARTIAL"), ("Sandbox", "PARTIAL")])
        users_out = _fake_contained_users_out(
            [(0, "PayrollDB", 3), (1, "Sandbox", 0)])
        calls = []
        def _fake_run(cmd, script, timeout=180, password=None):
            calls.append(script)
            return (dbs_out if len(calls) == 1 else users_out), None
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin", side_effect=_fake_run):
            r = mssql.probe_contained_db_auth(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["contained_dbs"]), 2)
        payroll = [d for d in r["contained_dbs"] if d["name"] == "PayrollDB"][0]
        sandbox = [d for d in r["contained_dbs"] if d["name"] == "Sandbox"][0]
        self.assertEqual(payroll["user_count"], 3)
        self.assertEqual(sandbox["user_count"], 0)
        # Both scripts must be read-only — no CREATE/ALTER/DROP/EXEC of
        # authentication-changing statements, no sp_configure, no xp_*, and
        # no attempt at a password spray or ALTER LOGIN.
        for script in calls:
            low = script.lower()
            for banned in ("alter login", "create login", "drop login",
                           "sp_configure", "xp_cmdshell", "alter user",
                           "create user", "drop user"):
                self.assertNotIn(banned, low)
        # The users batch must actually filter on authentication_type=2.
        self.assertIn("authentication_type=2", calls[1])

    def test_patched_target_no_contained_dbs(self):
        # (b) Patched / absent: sentinel present but no rows — ok, no finding
        # material. The per-db batch must NOT be sent (nothing to enumerate).
        dbs_out = _fake_contained_dbs_out([])
        calls = []
        def _fake_run(cmd, script, timeout=180, password=None):
            calls.append(script)
            return dbs_out, None
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin", side_effect=_fake_run):
            r = mssql.probe_contained_db_auth(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["contained_dbs"], [])
        self.assertEqual(len(calls), 1)  # never invoked the per-db batch

    def test_password_answered_off_argv(self):
        # The runner contract: password rides on stdin, not argv.
        dbs_out = _fake_contained_dbs_out([])
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=(dbs_out, None)) as run:
            mssql.probe_contained_db_auth(
                "1.2.3.4", {"user": "u", "secret": "sekrit"})
        _args, kwargs = run.call_args
        self.assertEqual(kwargs.get("password"), "sekrit")

    def test_unparseable_output_negative(self):
        # Login failed — no sentinel present in the output at all.
        with patch.object(mssql, "_mssqlclient_cmd",
                          return_value=["impacket-mssqlclient", "u@1.2.3.4"]), \
             patch.object(mssql, "_run_stdin",
                          return_value=("[-] Login failed for user 'u'.\n",
                                        None)):
            r = mssql.probe_contained_db_auth(
                "1.2.3.4", {"user": "u", "secret": "p"})
        self.assertFalse(r["ok"])
        self.assertIn("no result", r["error"])


class ContainedDbUsersFinding(unittest.TestCase):
    """The finding fires only when at least one contained DB carries at
    least one authentication_type=2 principal; otherwise None."""

    def _tgt(self):
        return {"ip": "10.0.0.7", "port": 1433}

    def test_vulnerable_emits_finding(self):
        # (a) Vulnerable -> medium, t1, CWE-522 + CWE-287, stable kind.
        probe = {"ok": True, "contained_dbs": [
            {"name": "PayrollDB", "containment_desc": "PARTIAL",
             "user_count": 3},
            {"name": "HRDb", "containment_desc": "PARTIAL",
             "user_count": 1}]}
        f = mssql.contained_db_users_finding(
            self._tgt(), probe, {"user": "sa", "secret": "x"})
        self.assertIsNotNone(f)
        self.assertEqual(f["kind"], "mssql_contained_db_users")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f.get("depth_tier"), "t1")
        self.assertIn("CWE-522", f["cwes"])
        self.assertIn("CWE-287", f["cwes"])
        # Detail lists the DBs and total user count.
        self.assertIn("PayrollDB", f["detail"])
        self.assertIn("HRDb", f["detail"])
        self.assertIn("4", f["detail"])   # 3 + 1
        # Narrative wired through _NARRATIVE for the report.
        self.assertIn("contained", f["narrative"].lower())
        # exploit_note refers to sys.database_principals but never suggests
        # an auth spray or a write against the target.
        self.assertIn("sys.database_principals", f["exploit_note"])
        low = f["exploit_note"].lower()
        for banned in ("alter login", "create login", "spray"):
            self.assertNotIn(banned, low)

    def test_contained_dbs_with_zero_users_no_finding(self):
        # A contained DB with no authentication_type=2 principals is harmless
        # on its own — the finding is about the *users*, not the containment.
        probe = {"ok": True, "contained_dbs": [
            {"name": "EmptyContained", "containment_desc": "PARTIAL",
             "user_count": 0}]}
        self.assertIsNone(
            mssql.contained_db_users_finding(
                self._tgt(), probe, {"user": "u", "secret": "p"}))

    def test_patched_or_absent_no_finding(self):
        # (b) Patched / absent -> no finding.
        for probe in (
            {"ok": True, "contained_dbs": []},                # no contained DBs
            {"ok": False, "error": "impacket-mssqlclient not installed"},
            {"ok": False},
            {},
            None,
        ):
            self.assertIsNone(
                mssql.contained_db_users_finding(
                    self._tgt(), probe, {"user": "u", "secret": "p"}),
                f"unexpected finding for probe={probe!r}")

    def test_target_string_uses_ip_and_port(self):
        probe = {"ok": True, "contained_dbs": [
            {"name": "X", "containment_desc": "PARTIAL", "user_count": 1}]}
        f = mssql.contained_db_users_finding(
            {"ip": "192.0.2.9", "port": 14330}, probe, None)
        self.assertEqual(f["target"], "192.0.2.9:14330")


if __name__ == "__main__":
    unittest.main()
