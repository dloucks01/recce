"""fieldkit bridge: export (recce -> fieldkit) and import (fieldkit -> recce).

Covers the round-trip contract: recce synthesizes an nmap-greppable + a rich bridge
JSON + a plan fieldkit consumes, and folds a fieldkit findings.json (raw or the enriched
recce_findings.json) back into confirmed Vulns that reach the workbook + report.
No network, no tools - pure data transforms, so it runs airgapped like the tool.
"""
import json
import os
import re
import shutil
import tempfile
import unittest

from recce import cli
from recce import fieldkit
from recce.models import Account, Credential, Host, Port, Vuln
from recce.store import Store


def _win_host():
    h = Host(ip="10.0.10.10", subnet="10.0.10.0/24", enumerated=True,
             hostnames=["dc01.corp.local"], os_name="Windows Server 2019",
             os_accuracy=96, roles=["Domain Controller"], smb_signing="required")
    h.ports = [Port(portid=445, state="open", service="microsoft-ds",
                    product="Microsoft Windows Server 2019"),
               Port(portid=88, state="open", service="kerberos-sec"),
               Port(portid=3389, state="open", service="ms-wbt-server")]
    h.vulns = [Vuln(ip="10.0.10.10", port=445, protocol="tcp",
                    script_id="smb-vuln-ms17-010", state="finding",
                    title="smb-vuln-ms17-010", severity="critical",
                    confidence="confirmed", source="nse", ids=["CVE-2017-0143"])]
    return h


def _web_host():
    h = Host(ip="10.0.20.5", subnet="10.0.20.0/24", enumerated=True,
             hostnames=["web01"], os_name="Linux 5.4", os_accuracy=94)
    h.ports = [Port(portid=80, state="open", service="http", product="Apache httpd",
                    version="2.4.41"),
               Port(portid=443, state="open", service="https", product="Apache httpd",
                    version="2.4.41")]
    # same weakness confirmed on two ports -> must collapse to one bridge finding
    h.vulns = [Vuln(ip="10.0.20.5", port=80, protocol="tcp", script_id="vulners",
                    state="finding", title="Apache httpd multiple vulns",
                    severity="high", confidence="confirmed", source="version-db",
                    ids=["CVE-2022-22720"]),
               Vuln(ip="10.0.20.5", port=443, protocol="tcp", script_id="vulners",
                    state="finding", title="Apache httpd multiple vulns",
                    severity="high", confidence="confirmed", source="version-db",
                    ids=["CVE-2023-25690"]),
               Vuln(ip="10.0.20.5", port=80, protocol="tcp", script_id="http-methods",
                    state="finding", title="Risky HTTP methods",
                    severity="low", confidence="potential", source="nse")]
    return h


class ExportTest(unittest.TestCase):

    def test_gnmap_is_valid_greppable_sweep_can_parse(self):
        gn = fieldkit.build_gnmap([_win_host(), _web_host()])
        # Re-parse with the exact regexes sweep.py triage uses.
        hosts = {}
        for line in gn.splitlines():
            m = re.search(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
            if not m or "Ports:" not in line:
                continue
            ports = {int(p) for p in re.findall(r"(\d+)/open/", line)}
            hosts[m.group(1)] = (m.group(2), ports)
        self.assertIn("10.0.10.10", hosts)
        self.assertEqual(hosts["10.0.10.10"][0], "dc01.corp.local")
        self.assertEqual(hosts["10.0.10.10"][1], {445, 88, 3389})
        self.assertEqual(hosts["10.0.20.5"][1], {80, 443})

    def test_bridge_has_ports_and_confirmed_findings(self):
        b = fieldkit.build_bridge([_win_host(), _web_host()], engagement="Eng")
        self.assertEqual(b["_recce_bridge"], fieldkit.BRIDGE_VERSION)
        by_ip = {h["ip"]: h for h in b["hosts"]}
        dc = by_ip["10.0.10.10"]
        self.assertEqual(dc["findings"][0]["severity"], "critical")
        self.assertIn("CVE-2017-0143", dc["findings"][0]["cves"])
        # a 445 open port suggests the smb generator
        self.assertTrue(any("gen_smb" in r["module"] for r in dc["suggested"]))

    def test_bridge_collapses_same_finding_across_ports(self):
        b = fieldkit.build_bridge([_web_host()])
        web = b["hosts"][0]
        apache = [f for f in web["findings"] if f["title"] == "Apache httpd multiple vulns"]
        self.assertEqual(len(apache), 1)                       # deduped by title
        self.assertEqual(set(apache[0]["ports"]), {80, 443})   # ports unioned
        self.assertEqual(set(apache[0]["cves"]), {"CVE-2022-22720", "CVE-2023-25690"})
        # the 'potential' finding is excluded (only confirmed reach fieldkit)
        self.assertFalse(any(f["title"] == "Risky HTTP methods" for f in web["findings"]))

    def test_plan_md_ranks_and_names_generators(self):
        b = fieldkit.build_bridge([_win_host(), _web_host()], engagement="Eng")
        md = fieldkit.build_plan_md(b)
        self.assertIn("fieldkit attack plan", md)
        self.assertIn("dc01.corp.local", md)
        self.assertIn("gen_smb", md)
        self.assertIn("CVE-2017-0143", md)


class GeneratorWiringTest(unittest.TestCase):

    def test_exploit_cmds_only_for_real_versions(self):
        h = Host(ip="10.0.20.5", enumerated=True)
        h.ports = [
            Port(portid=22, state="open", service="ssh", product="OpenSSH", version="8.2p1"),
            Port(portid=445, state="open", service="microsoft-ds",
                 product="Microsoft Windows Server 2019", version=""),   # no version
            Port(portid=389, state="open", service="ldap",
                 product="Microsoft Windows Active Directory LDAP",
                 version="Domain: corp.local"),                          # banner, not a version
        ]
        cmds = fieldkit._exploit_cmds(h)
        svcs = {c["service"] for c in cmds}
        self.assertEqual(svcs, {"openssh"})                # only the real-version, non-generic one
        self.assertIn('--service openssh --version "8.2p1"', cmds[0]["cmd"])

    def test_exploit_cmds_attach_confirmed_cves(self):
        h = Host(ip="10.0.20.5", enumerated=True)
        h.ports = [Port(portid=80, state="open", service="http",
                        product="Apache httpd", version="2.4.41")]
        h.vulns = [Vuln(ip="10.0.20.5", port=80, protocol="tcp", script_id="vulners",
                        title="Apache vulns", severity="critical", confidence="confirmed",
                        ids=["CVE-2021-41773"])]
        cmds = fieldkit._exploit_cmds(h)
        self.assertEqual(cmds[0]["service"], "apache")
        self.assertIn("CVE-2021-41773", cmds[0]["cves"])

    def test_collect_users_dedupes_and_drops_machine_accounts(self):
        h = Host(ip="10.0.10.10", enumerated=True)
        h.accounts = [Account(ip="10.0.10.10", source="ldap", kind="user", name="jdoe"),
                      Account(ip="10.0.10.10", source="ldap", kind="user", name="WS01$"),
                      Account(ip="10.0.10.10", source="ldap", kind="group", name="Admins")]
        creds = [Credential(username="JDOE", secret="x"),          # dup (case-insensitive)
                 Credential(username="svc", secret="y", domain="corp.local")]
        users = fieldkit.collect_users([h], creds)
        self.assertIn("jdoe", users)
        self.assertIn("svc", users)
        self.assertNotIn("WS01$", users)                           # machine account dropped
        self.assertEqual(len([u for u in users if u.lower() == "jdoe"]), 1)

    def test_collect_creds_formats_password_and_hash(self):
        lines = fieldkit.collect_creds([
            Credential(username="svc", secret="P@ss", domain="corp.local", source="secretsdump"),
            Credential(username="adm", secret="31d6...", kind="nthash", source="secretsdump"),
        ])
        self.assertTrue(any("corp.local/svc:P@ss" in ln for ln in lines))
        self.assertTrue(any("hash:31d6" in ln for ln in lines))

    def test_access_cmds_domain_cred_yields_shell_and_spray(self):
        h = Host(ip="10.0.10.10", enumerated=True)
        h.ports = [Port(portid=445, state="open", service="microsoft-ds")]
        creds = [Credential(username="svc", secret="P@ss", domain="corp.local")]
        cmds = fieldkit._access_cmds(h, creds)
        self.assertTrue(any("gen_shell.py --target 10.0.10.10 --user svc --pass 'P@ss'"
                            in c and "--proto smb" in c for c in cmds))
        self.assertTrue(any("gen_spray.py --proto smb --users users.txt" in c for c in cmds))

    def test_access_cmds_empty_without_shell_proto(self):
        h = Host(ip="10.0.20.5", enumerated=True)
        h.ports = [Port(portid=80, state="open", service="http")]   # no shell proto
        self.assertEqual(fieldkit._access_cmds(h, [Credential(username="x", secret="y",
                                                           domain="d")]), [])


class ImportTest(unittest.TestCase):

    def test_parse_affected_host(self):
        self.assertEqual(fieldkit.parse_affected_host("10.0.0.5 (WIN-SQL01)"),
                         ("10.0.0.5", "WIN-SQL01"))
        self.assertEqual(fieldkit.parse_affected_host("10.0.0.6 (web01, Ubuntu 22.04)"),
                         ("10.0.0.6", "web01"))
        self.assertEqual(fieldkit.parse_affected_host("justahost")[0], "")

    def test_raw_findings_json_folds_with_fallback_severity(self):
        data = {"findings": [{
            "title": "Passwordless sudo on find", "vector_type": "gtfobins_sudo",
            "affected_host": "10.0.0.6 (web01)", "severity": "High",
            "evidence": "find -exec spawned a root shell",
            "steps": [{"cmd": "sudo -l", "output": "(root) NOPASSWD: /usr/bin/find"}],
            "references": "CVE-2020-0000",
        }]}
        hosts = fieldkit.findings_to_hosts(data)
        self.assertIn("10.0.0.6", hosts)
        v = hosts["10.0.0.6"]["vulns"][0]
        self.assertEqual(v.severity, "high")             # lowercased for recce
        self.assertEqual(v.source, "fieldkit")
        self.assertEqual(v.confidence, "confirmed")
        self.assertIn("CVE-2020-0000", v.ids)
        self.assertIn("sudo -l", v.output)               # PoC step captured

    def test_enriched_recce_block_wins(self):
        data = {"_recce_import": 1, "findings": [{
            "title": "Unquoted service path", "vector_type": "unquoted_service",
            "affected_host": "ignored", "steps": [{"cmd": "sc", "output": "x"}],
            "_recce": {"ip": "10.0.0.5", "hostname": "WIN-SQL01", "port": None,
                       "severity": "high", "cwes": ["CWE-428"],
                       "remediation": "Quote the ImagePath.", "ids": ["CVE-1"]},
        }]}
        hosts = fieldkit.findings_to_hosts(data)
        v = hosts["10.0.0.5"]["vulns"][0]
        self.assertEqual(hosts["10.0.0.5"]["hostname"], "WIN-SQL01")
        self.assertEqual(v.cwes, ["CWE-428"])
        self.assertEqual(v.remediation, "Quote the ImagePath.")


class RoundTripCliTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.eng = os.path.join(self.dir, "eng")
        paths = cli._open_paths(self.eng)
        store = Store(paths["db"])
        store.upsert_host(_win_host())
        store.upsert_host(_web_host())
        store.close()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _args(self, **kw):
        import argparse
        ns = argparse.Namespace(output_dir=self.eng, title="T", targets=[],
                                host=[], subnet=[])
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_export_writes_seed_files(self):
        rc = cli.cmd_fieldkit_export(self._args())
        self.assertEqual(rc, 0)
        sk = os.path.join(self.eng, "fieldkit")
        for name in ("ports.gnmap", "smb-null.txt", "recce-bridge.json", "FIELDKIT.md",
                     "users.txt", "creds.txt"):
            self.assertTrue(os.path.exists(os.path.join(sk, name)), name)
        bridge = json.load(open(os.path.join(sk, "recce-bridge.json")))
        self.assertEqual(len(bridge["hosts"]), 2)

    def test_import_lands_in_store_and_marks_access(self):
        ff = os.path.join(self.dir, "recce_findings.json")
        json.dump({"source": "fieldkit", "findings": [{
            "title": "vsftpd 2.3.4 backdoor", "vector_type": "exposed_service_cve",
            "affected_host": "10.0.20.5 (web01)",
            "steps": [{"cmd": "nc host 21", "output": "230 Login successful"}],
            "_recce": {"ip": "10.0.20.5", "hostname": "web01", "port": 21,
                       "severity": "critical", "cwes": ["CWE-78"],
                       "remediation": "Reinstall vsftpd from a trusted source.",
                       "ids": ["CVE-2011-2523"]},
        }]}, open(ff, "w"))
        rc = cli.cmd_fieldkit_import(self._args(findings=ff))
        self.assertEqual(rc, 0)
        store = Store(cli._open_paths(self.eng)["db"])
        h = store.get_host("10.0.20.5")
        store.close()
        self.assertTrue(h.access_gained)
        fieldkits = [v for v in h.vulns if v.source == "fieldkit"]
        self.assertEqual(len(fieldkits), 1)
        self.assertEqual(fieldkits[0].severity, "critical")
        self.assertEqual(fieldkits[0].port, 21)
        self.assertIn("CVE-2011-2523", fieldkits[0].ids)

    def test_hostname_only_finding_merges_onto_enumerated_host(self):
        # affected_host with no IP ("WIN-SQL01") must fold onto the enumerated host
        # of that name, not fork a synthetic fieldkit:WIN-SQL01 entry.
        store = Store(cli._open_paths(self.eng)["db"])
        store.upsert_host(Host(ip="10.0.10.10", subnet="10.0.10.0/24",
                               enumerated=True, hostnames=["WIN-SQL01"]))
        store.close()
        ff = os.path.join(self.dir, "h.json")
        with open(ff, "w") as fh:
            json.dump({"findings": [{
                "title": "unquoted svc", "vector_type": "unquoted_service",
                "affected_host": "WIN-SQL01",
                "steps": [{"cmd": "sc", "output": "ok"}],
            }]}, fh)
        cli.cmd_fieldkit_import(self._args(findings=ff))
        store = Store(cli._open_paths(self.eng)["db"])
        try:
            self.assertIsNone(store.get_host("fieldkit:WIN-SQL01"))   # no synthetic fork
            h = store.get_host("10.0.10.10")
        finally:
            store.close()
        sk = [v for v in h.vulns if v.source == "fieldkit"]
        self.assertEqual(len(sk), 1)
        self.assertEqual(sk[0].ip, "10.0.10.10")                  # ip realigned
        self.assertTrue(h.access_gained)

    def test_import_is_idempotent(self):
        ff = os.path.join(self.dir, "f.json")
        json.dump({"findings": [{
            "title": "dup", "vector_type": "gtfobins_sudo",
            "affected_host": "10.0.20.5 (web01)",
            "steps": [{"cmd": "sudo -l", "output": "ok"}],
        }]}, open(ff, "w"))
        cli.cmd_fieldkit_import(self._args(findings=ff))
        cli.cmd_fieldkit_import(self._args(findings=ff))
        store = Store(cli._open_paths(self.eng)["db"])
        h = store.get_host("10.0.20.5")
        store.close()
        self.assertEqual(sum(1 for v in h.vulns if v.title == "dup"), 1)


if __name__ == "__main__":
    unittest.main()
