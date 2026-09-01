"""Tests for the BloodHound-CE-compatible push writer.

Every test covers a specific contract: the shape recce writes MUST be
consumable by recce's own reader (bloodhound.load_graph), the Owned mark
follows only from PROVEN credentials (cracked / spray-validated), and every
ADCS ESC finding round-trips as an edge from the abusing user to a CA node.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce.ad import bloodhound as bh
from recce.ad import bloodhound_push as bhp
from recce.core.models import Account, Credential, Host, Vuln


def _read_meta(zip_path: str, kind: str) -> dict:
    with zipfile.ZipFile(zip_path) as zf:
        return json.loads(zf.read(f"{kind}.json").decode("utf-8"))


class BloodHoundPushTest(unittest.TestCase):

    def _hosts_with_accounts(self):
        """Two users + one computer + one domain — the shape recce carries in
        Host.accounts after LDAP/BloodHound enum."""
        h = Host(ip="10.0.0.10", roles=["Domain Controller"])
        h.accounts.append(Account(ip="10.0.0.10", source="ldap", kind="user",
                                  name="alice", domain="CORP.LOCAL",
                                  rid="1105", attrs={"admincount": "1"}))
        h.accounts.append(Account(ip="10.0.0.10", source="ldap", kind="user",
                                  name="bob", domain="CORP.LOCAL",
                                  rid="1106", attrs={"kerberoastable": True,
                                                     "spn": "MSSQL/db"}))
        h.accounts.append(Account(ip="10.0.0.10", source="ldap", kind="computer",
                                  name="DC01$", domain="CORP.LOCAL", rid="1000"))
        h.accounts.append(Account(ip="10.0.0.10", source="ldap", kind="domain",
                                  name="CORP.LOCAL", domain="CORP.LOCAL"))
        return [h]

    def test_empty_engagement_produces_valid_zip(self):
        with tempfile.TemporaryDirectory() as d:
            zp, summary = bhp.build_zip([], [], d, stamp="20260101_000000")
            self.assertTrue(os.path.exists(zp))
            for kind in ("users", "computers", "groups", "domains",
                         "gpos", "ous", "containers"):
                blob = _read_meta(zp, kind)
                self.assertEqual(blob["meta"]["type"], kind)
                self.assertEqual(blob["meta"]["count"], 0)
                self.assertEqual(blob["meta"]["version"], 5)
                self.assertEqual(blob["data"], [])
            self.assertEqual(summary["owned"], 0)
            self.assertEqual(summary["adcs_edges"], 0)

    def test_accounts_land_in_correct_buckets(self):
        with tempfile.TemporaryDirectory() as d:
            hosts = self._hosts_with_accounts()
            zp, summary = bhp.build_zip(hosts, [], d)
            users = _read_meta(zp, "users")
            comps = _read_meta(zp, "computers")
            doms = _read_meta(zp, "domains")
            self.assertEqual(users["meta"]["count"], 2)
            self.assertEqual(comps["meta"]["count"], 1)
            self.assertEqual(doms["meta"]["count"], 1)
            # UPPER@DOMAIN canonicalisation matches BloodHound's convention.
            names = sorted(n["Properties"]["name"] for n in users["data"])
            self.assertEqual(names, ["ALICE@CORP.LOCAL", "BOB@CORP.LOCAL"])
            # Kerberoastable Account.attr → hasspn=True property.
            bob = next(n for n in users["data"]
                       if n["Properties"]["name"] == "BOB@CORP.LOCAL")
            self.assertTrue(bob["Properties"]["hasspn"])
            self.assertEqual(bob["Properties"]["serviceprincipalnames"],
                             ["MSSQL/db"])

    def test_cracked_credential_marks_user_owned(self):
        with tempfile.TemporaryDirectory() as d:
            hosts = self._hosts_with_accounts()
            creds = [Credential(username="alice", secret="Summer2024!",
                                kind="password", domain="CORP.LOCAL",
                                source="cracked")]
            zp, summary = bhp.build_zip(hosts, creds, d)
            users = _read_meta(zp, "users")
            alice = next(n for n in users["data"]
                         if n["Properties"]["name"] == "ALICE@CORP.LOCAL")
            bob = next(n for n in users["data"]
                       if n["Properties"]["name"] == "BOB@CORP.LOCAL")
            self.assertTrue(alice["Properties"].get("Owned"))
            self.assertFalse(bob["Properties"].get("Owned", False))
            self.assertEqual(summary["owned"], 1)

    def test_observed_credential_does_not_mark_owned(self):
        """A `manual`/`autologon`/`gpp` credential is not proof recce cracked
        the account — Owned=True is reserved for cracked / spray-validated."""
        with tempfile.TemporaryDirectory() as d:
            hosts = self._hosts_with_accounts()
            creds = [Credential(username="alice", secret="x", kind="password",
                                domain="CORP.LOCAL", source="manual")]
            zp, summary = bhp.build_zip(hosts, creds, d)
            users = _read_meta(zp, "users")
            alice = next(n for n in users["data"]
                         if n["Properties"]["name"] == "ALICE@CORP.LOCAL")
            self.assertFalse(alice["Properties"].get("Owned", False))
            self.assertEqual(summary["owned"], 0)

    def test_adcs_esc1_vuln_emits_edge_to_ca(self):
        with tempfile.TemporaryDirectory() as d:
            hosts = self._hosts_with_accounts()
            hosts[0].vulns.append(Vuln(
                ip="10.0.0.10", port=None, protocol="tcp",
                # script_id shape produced by bloodhound.findings_to_vulns.
                script_id="ad-adcs-esc1:alice|UserTemplate @ CORP-CA",
                state="finding", title="ADCS ESC1", severity="critical",
                source="adcs", output="ESC1 template abuse"))
            zp, summary = bhp.build_zip(hosts, [], d)
            self.assertEqual(summary["adcs_edges"], 1)
            comps = _read_meta(zp, "computers")
            ca = next(n for n in comps["data"]
                      if n["Properties"].get("isca"))
            self.assertTrue(ca["Aces"])
            ace = ca["Aces"][0]
            self.assertEqual(ace["RightName"], "ADCSESC1")
            # And the abusing principal SID matches ALICE's node SID.
            users = _read_meta(zp, "users")
            alice = next(n for n in users["data"]
                         if n["Properties"]["name"] == "ALICE@CORP.LOCAL")
            self.assertEqual(ace["PrincipalSID"], alice["ObjectIdentifier"])

    def test_writer_output_round_trips_through_reader(self):
        """The whole point of the writer: what recce writes, recce reads."""
        with tempfile.TemporaryDirectory() as d:
            hosts = self._hosts_with_accounts()
            zp, _ = bhp.build_zip(hosts, [], d)
            self.assertTrue(bh.is_sharphound(zp))
            graph = bh.load_graph(zp)
            # ALICE/BOB parsed as User nodes with the same sam@domain identity.
            names = {n["name"] for n in graph["nodes"].values()
                     if n["type"] == "User"}
            self.assertIn("ALICE@CORP.LOCAL", names)
            self.assertIn("BOB@CORP.LOCAL", names)
            # The domain object came through as a Domain-typed node too.
            self.assertTrue(any(n["type"] == "Domain"
                                for n in graph["nodes"].values()))

    def test_collision_appends_suffix_unless_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            stamp = "20260101_000000"
            zp1, _ = bhp.build_zip([], [], d, stamp=stamp)
            zp2, _ = bhp.build_zip([], [], d, stamp=stamp)
            self.assertNotEqual(zp1, zp2)                    # suffixed
            zp3, _ = bhp.build_zip([], [], d, stamp=stamp, overwrite=True)
            self.assertEqual(zp3, zp1)                       # clobbered


if __name__ == "__main__":
    unittest.main()
