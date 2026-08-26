"""Tests for recce.report.enrichment — CVSS auto-calc, SAN extraction,
cred-spray commands, finding correlation."""
from __future__ import annotations

import unittest
from dataclasses import dataclass, field

from recce.report import enrichment as enr


# Lightweight stand-ins so tests don't depend on the full Host/Vuln imports.
@dataclass
class _Port:
    portid: int
    protocol: str = "tcp"

@dataclass
class _Vuln:
    script_id: str
    title: str = ""
    output: str = ""
    severity: str = "info"
    source: str = "probe"

@dataclass
class _Host:
    ip: str
    open_ports: list = field(default_factory=list)
    vulns: list = field(default_factory=list)


@dataclass
class _Cred:
    username: str
    secret: str = ""
    kind: str = "password"
    source: str = "test"


class CvssVectorTest(unittest.TestCase):
    def test_probe_severity_maps(self):
        v = _Vuln(script_id="x", severity="critical", source="probe")
        self.assertIn("AV:N/AC:L/PR:N", enr.cvss_vector(v))
        self.assertIn("C:H", enr.cvss_vector(v))

    def test_loot_uses_local_vector(self):
        v = _Vuln(script_id="x", severity="critical", source="loot")
        self.assertIn("AV:L", enr.cvss_vector(v))

    def test_no_rule_returns_empty(self):
        v = _Vuln(script_id="x", severity="unknown", source="magical")
        self.assertEqual(enr.cvss_vector(v), "")


class SanExtractionTest(unittest.TestCase):
    def test_dns_names_pulled_from_cert_output(self):
        h = _Host(ip="10.0.0.5", vulns=[
            _Vuln(script_id="tls-cert",
                  output="Subject: CN=example.com; SAN: DNS:example.com, DNS:www.example.com, DNS:*.api.example.com"),
        ])
        sans = enr.extract_tls_sans([h])
        self.assertIn("10.0.0.5", sans)
        names = sans["10.0.0.5"]
        self.assertIn("example.com", names)
        self.assertIn("www.example.com", names)
        self.assertIn("api.example.com", names, "wildcard SAN should strip *. prefix")


class CredSprayTest(unittest.TestCase):
    def test_nxc_smb_command_generated_for_password_cred(self):
        h1 = _Host(ip="10.0.0.5", open_ports=[_Port(445)])
        h2 = _Host(ip="10.0.0.6", open_ports=[_Port(445), _Port(22)])
        creds = [_Cred(username="administrator", secret="P@ssw0rd", kind="password", source="looted")]
        cmds = enr.cred_spray_commands([h1, h2], creds)
        smb = [c for c in cmds if c["service"] == "smb"]
        self.assertEqual(len(smb), 1)
        self.assertIn("10.0.0.5", smb[0]["command"])
        self.assertIn("10.0.0.6", smb[0]["command"])
        self.assertIn("-u administrator", smb[0]["command"])
        self.assertIn("-p 'P@ssw0rd'", smb[0]["command"])
        ssh = [c for c in cmds if c["service"] == "ssh"]
        self.assertEqual(len(ssh), 1)
        self.assertIn("10.0.0.6", ssh[0]["command"])

    def test_hash_cred_uses_H_flag(self):
        h = _Host(ip="10.0.0.7", open_ports=[_Port(445)])
        creds = [_Cred(username="administrator",
                       secret="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
                       kind="hash", source="ntds-dump")]
        cmds = enr.cred_spray_commands([h], creds)
        smb = [c for c in cmds if c["service"] == "smb"][0]
        self.assertIn("-H '", smb["command"])
        self.assertNotIn("-p '", smb["command"])

    def test_no_creds_returns_empty(self):
        h = _Host(ip="10.0.0.5", open_ports=[_Port(445)])
        self.assertEqual(enr.cred_spray_commands([h], []), [])


class CorrelateTest(unittest.TestCase):
    def test_git_plus_php_flagged(self):
        h = _Host(ip="10.0.0.5", vulns=[
            _Vuln(script_id="http-path-enum", title="Exposed path: /.git/HEAD"),
            _Vuln(script_id="http-fingerprint", output="techs=[..] cookies=[PHPSESSID]"),
        ])
        corr = enr.correlate([h])
        titles = [c["title"] for c in corr]
        self.assertTrue(any("Git repo + PHP" in t for t in titles), titles)

    def test_no_correlation_when_only_one_side_present(self):
        h = _Host(ip="10.0.0.5", vulns=[
            _Vuln(script_id="http-path-enum", title="Exposed path: /.git/HEAD"),
        ])
        # No PHP fingerprint -> no git+PHP correlation
        corr = enr.correlate([h])
        self.assertFalse(any("Git repo + PHP" in c["title"] for c in corr))


if __name__ == "__main__":
    unittest.main()
