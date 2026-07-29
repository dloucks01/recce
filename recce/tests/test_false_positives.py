"""Regressions for over-eager finding/marker detection that produced false positives.

Two reported classes:
  1. MSSQL "blank password (sysadmin -> RCE)" critical fired on EVERY instance,
     because it keyed off the mere presence of nmap's ms-sql-empty-password script
     (which runs on every 1433 during enum) rather than a positive login result.
  2. Plain domain users were mislabeled LOCAL ADMIN - notably on domain controllers -
     because the netexec parsers matched a loose "(admin)" substring (present in a
     DC's share/session/host-info text) instead of the real "(Pwn3d!)" marker.
"""

import unittest

from recce import credenum, mssql
from recce.models import Host, Port, Script, Vuln


def _mssql_host(script_output=None, vuln_title=None):
    p = Port(portid=1433, protocol="tcp", state="open", service="ms-sql-s")
    if script_output is not None:
        p.scripts.append(Script(id="ms-sql-empty-password", output=script_output))
    h = Host(ip="10.0.0.9", ports=[p])
    if vuln_title:
        h.vulns.append(Vuln(ip="10.0.0.9", port=1433, protocol="tcp",
                            script_id="ms-sql-empty-password", title=vuln_title,
                            severity="high"))
    return h


def _blank_fired(host):
    return any(f.get("kind") == "blank_login" for f in mssql.findings([host]))


class MssqlBlankPasswordTest(unittest.TestCase):
    def test_script_ran_but_found_nothing_is_not_a_finding(self):
        # nmap emitted the script (it always runs on 1433) with empty/negative output.
        for out in ("", "   ", "\n", "No accounts with empty passwords"):
            self.assertFalse(_blank_fired(_mssql_host(script_output=out)),
                             f"blank_login false-fired on negative output {out!r}")

    def test_script_reports_login_success_is_a_finding(self):
        out = ("[DBSERVER01\\SQLEXPRESS]\n"
               "  sa:<empty password> => Login Success")
        self.assertTrue(_blank_fired(_mssql_host(script_output=out)),
                        "blank_login did not fire on a real Login Success")

    def test_parsed_empty_password_vuln_still_fires(self):
        # The vetted vulns path (parser already confirmed the text) must still work.
        h = _mssql_host(vuln_title="Database account with empty password")
        self.assertTrue(_blank_fired(h))


class NxcSmbAdminTest(unittest.TestCase):
    def test_dc_domain_user_is_not_admin(self):
        # A plain domain user against a DC: authenticates, output is share/session/
        # host-info heavy, but NO (Pwn3d!). Must be auth-only, never admin.
        out = "\n".join([
            r"SMB  10.0.0.1  445  DC01  [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)",
            r"SMB  10.0.0.1  445  DC01  [+] corp.local\jdoe:Password1",
            r"SMB  10.0.0.1  445  DC01  [*] Enumerated shares",
            r"SMB  10.0.0.1  445  DC01  Share           Permissions     Remark",
            r"SMB  10.0.0.1  445  DC01  ADMIN$                          Remote Admin",
            r"SMB  10.0.0.1  445  DC01  C$                              Default share",
            r"SMB  10.0.0.1  445  DC01  [+] Enumerated loggedon users",
            r"SMB  10.0.0.1  445  DC01  DC01\Administrator",
        ])
        data = credenum.parse_nxc_smb(out)
        self.assertTrue(data["auth"], "valid domain auth should be detected")
        self.assertFalse(data["admin"], "plain domain user flagged admin on a DC")

    def test_real_pwn3d_is_admin(self):
        out = r"SMB  10.0.0.10  445  DC01  [+] corp.local\admin:Pw (Pwn3d!)"
        data = credenum.parse_nxc_smb(out)
        self.assertTrue(data["admin"])

    def test_literal_admin_substring_does_not_flag(self):
        # A stray "(admin)" in non-auth text must not confer admin.
        out = "\n".join([
            r"SMB  10.0.0.1  445  DC01  [+] corp.local\jdoe:Password1",
            r"SMB  10.0.0.1  445  DC01  [*] Enumerated shares",
            r"SMB  10.0.0.1  445  DC01  admin_backup    READ            (admin) old share",
        ])
        self.assertFalse(credenum.parse_nxc_smb(out)["admin"])


class NxcMssqlAdminTest(unittest.TestCase):
    def test_login_ok_not_admin(self):
        d = mssql.parse_nxc_mssql(r"MSSQL 10.0.0.50 1433 SQL01 [+] CORP\alice:P@ss")
        self.assertTrue(d["access"])
        self.assertFalse(d["admin"])

    def test_pwn3d_is_admin(self):
        d = mssql.parse_nxc_mssql(r"MSSQL 10.0.0.50 1433 SQL01 [+] CORP\alice:P@ss (Pwn3d!)")
        self.assertTrue(d["admin"])


if __name__ == "__main__":
    unittest.main()
