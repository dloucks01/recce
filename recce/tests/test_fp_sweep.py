"""Regression tests for the false-positive sweep (Groups A-F).

Each group corresponds to a class of over-eager detection found in the audit:
  A. proofs.py adjudicated version-db banner matches as CONFIRMED "directly observed".
  B. vulndb.py loose product substrings + version-boundary + distro-backport blindness.
  C. web.py path predicates that treated errors/benign substrings as positives.
  D. credenum.py recorded an SSH foothold on failed auth.
  E. ad/bloodhound/ldap loose substring matches (admin group, DC role, password-in-desc).
  F. parser.py turned a "not affected" CVE mention into a finding.
"""

import unittest

from recce import ad, bloodhound, credenum, ldap, proofs, vulndb, web
from recce.models import Account, Host, Port, Script, Vuln


def _vdb_titles(host):
    return {v.title for v in vulndb.assess_host(host)}


def _vdb(host, want):
    return next((v for v in vulndb.assess_host(host) if want in v.title), None)


def _port(**kw):
    kw.setdefault("state", "open")
    return Port(**kw)


# --- Group A: proofs never CONFIRMS a version-db access-claim ---------------------
class ProofGateTest(unittest.TestCase):
    def _verify_one(self, title, source):
        h = Host(ip="10.0.0.1", ports=[_port(portid=2375, service="docker")])
        h.vulns = [Vuln(ip="10.0.0.1", port=2375, protocol="tcp",
                        script_id="version-db", title=title, source=source,
                        confidence="potential")]
        return proofs.verify_host(h)[0]

    def test_versiondb_access_claim_downgraded(self):
        r = self._verify_one("Docker Engine API exposed unauthenticated", "version-db")
        self.assertEqual(r["verdict"], proofs.LIKELY)
        self.assertTrue(any("did not" in e.lower() or "lead to verify" in e.lower()
                            for e in r["evidence"]))

    def test_live_probe_access_claim_stays_confirmed(self):
        # Same recipe, but the finding came from an actual probe -> CONFIRMED stands.
        r = self._verify_one("Docker Engine API exposed unauthenticated", "probe")
        self.assertEqual(r["verdict"], proofs.CONFIRMED)

    def test_eol_versiondb_stays_confirmed(self):
        # EOL is a version fact, not an access claim -> version-db is fine here.
        h = Host(ip="10.0.0.2", ports=[_port(portid=3306, service="mysql",
                                             product="MySQL", version="5.6.0")])
        h.vulns = [Vuln(ip="10.0.0.2", port=3306, protocol="tcp",
                        script_id="version-db", title="End-of-life MySQL (< 5.7) exposed",
                        source="version-db", confidence="likely")]
        self.assertEqual(proofs.verify_host(h)[0]["verdict"], proofs.CONFIRMED)


# --- Group B: vulndb product tokens, version boundary, distro backports -----------
class VulndbTest(unittest.TestCase):
    def test_rpcbind_not_flagged_as_bind(self):
        h = Host(ip="10.0.0.3", ports=[_port(portid=111, service="rpcbind",
                                              product="rpcbind", version="2-4")])
        self.assertFalse(any("BIND" in t for t in _vdb_titles(h)),
                         "rpcbind matched the ISC BIND signature")

    def test_real_bind_still_flagged(self):
        h = Host(ip="10.0.0.3", ports=[_port(portid=53, service="domain",
                                             product="ISC BIND", version="9.8.0")])
        self.assertTrue(any("BIND" in t for t in _vdb_titles(h)))

    def test_phpmyadmin_not_flagged_as_eol_php(self):
        h = Host(ip="10.0.0.4", ports=[_port(portid=443, service="https",
                                             product="phpMyAdmin", version="5.2.1")])
        self.assertFalse(any("End-of-life PHP" in t for t in _vdb_titles(h)),
                         "phpMyAdmin version matched the PHP interpreter EOL signature")

    def test_openssh_9_8_not_regresshion(self):
        h = Host(ip="10.0.0.5", ports=[_port(portid=22, service="ssh",
                                             product="OpenSSH", version="9.8")])
        self.assertFalse(any("regreSSHion" in t for t in _vdb_titles(h)),
                         "patched OpenSSH 9.8 flagged as regreSSHion (9.8 < 9.8p1)")

    def test_openssh_9_2p1_still_regresshion(self):
        h = Host(ip="10.0.0.5", ports=[_port(portid=22, service="ssh",
                                             product="OpenSSH", version="9.2p1")])
        self.assertTrue(any("regreSSHion" in t for t in _vdb_titles(h)))

    def test_distro_packaged_range_match_is_potential(self):
        h = Host(ip="10.0.0.6", ports=[_port(portid=22, service="ssh", product="OpenSSH",
                                             version="9.2p1", extrainfo="Debian 9+deb12u3")])
        v = _vdb(h, "regreSSHion")
        self.assertIsNotNone(v)
        self.assertEqual(v.confidence, "potential")
        self.assertIn("backport", v.output.lower())


# --- Group C: web.py predicates --------------------------------------------------
def _web_pred(web_id):
    for entry in web._PATHS:
        if entry[2] == web_id:
            return entry[-1]
    raise KeyError(web_id)


class WebPredicateTest(unittest.TestCase):
    def test_tomcat_requires_signature(self):
        pred = _web_pred("web-tomcat-manager")
        self.assertFalse(pred(403, "<html><body>nginx 403 Forbidden</body></html>"))
        self.assertFalse(pred(401, "Site-wide basic auth"))
        self.assertTrue(pred(401, "<h1>401 - Apache Tomcat/9.0.71</h1>"))
        self.assertTrue(pred(200, "Apache Tomcat Manager Application"))

    def test_svn_requires_integer_first_line(self):
        pred = _web_pred("web-svn")
        self.assertFalse(pred(200, '<html lang="en" dir="ltr"><head></head></html>'))
        self.assertTrue(pred(200, "12\n\ndir\n"))

    def test_elasticsearch_needs_index_markers(self):
        pred = _web_pred("web-elastic-open")
        self.assertFalse(pred(200, "[]"))
        self.assertTrue(pred(200, '[{"health":"green","index":"logs"}]'))

    def test_kibana_requires_kibana(self):
        pred = _web_pred("web-kibana")
        self.assertFalse(pred(200, '{"version":{"number":"1.2.3"}}'))
        self.assertTrue(pred(200, '{"version":{"number":"8.1.0"},"name":"kibana"}'))

    def test_backup_rejects_html_index(self):
        self.assertTrue(web._looks_like_html('<!DOCTYPE html><html><head>'))
        self.assertFalse(web._looks_like_html('APP_KEY=base64:abcd\nDB_PASSWORD=hunter2'))
        # A SPA index page carrying a front-end apiKey must not read as an exposed backup.
        self.assertFalse(web._confirm_backup(
            "secret", '<html><body><script>apiKey:"abcd1234efgh"</script></body></html>'))
        self.assertTrue(web._confirm_backup("secret", 'AWS_SECRET_ACCESS_KEY=abcd1234efgh'))


# --- Group D: SSH foothold only on a real shell ----------------------------------
class SshGateTest(unittest.TestCase):
    def setUp(self):
        self._orig = credenum._run

    def tearDown(self):
        credenum._run = self._orig

    def test_failed_auth_is_not_a_foothold(self):
        credenum._run = lambda cmd, timeout=0: ("Permission denied (publickey).", None)
        facts, err = credenum.run_ssh_local("10.0.0.7", {"username": "root", "key": "/k"})
        self.assertIsNone(facts, "failed SSH auth was recorded as a foothold")

    def test_real_shell_is_a_foothold(self):
        credenum._run = lambda cmd, timeout=0: (
            "===ID===\nuid=0(root) gid=0(root)\n===UNAME===\nLinux box 6.1\n", None)
        facts, err = credenum.run_ssh_local("10.0.0.7", {"username": "root", "key": "/k"})
        self.assertIsNotNone(facts)
        self.assertIn("uid=0", facts["id"])


# --- Group E: AD / description substrings -----------------------------------------
class AdSubstringTest(unittest.TestCase):
    def _user(self, memberof):
        return Account(ip="10.0.0.8", source="ldap", kind="user", name="jdoe",
                       attrs={"memberof": memberof})

    def test_helpdesk_admins_not_tier0(self):
        h = Host(ip="10.0.0.8", accounts=[self._user("Helpdesk Administrators; Users")])
        self.assertEqual(ad.privileged_accounts([h]), [])

    def test_domain_admins_is_privileged(self):
        h = Host(ip="10.0.0.8", accounts=[self._user("Domain Admins; Users")])
        self.assertEqual(len(ad.privileged_accounts([h])), 1)

    def test_ldap_server_not_dc_without_marker(self):
        h = Host(ip="10.0.0.9", ports=[_port(portid=389, service="ldap", scripts=[
            Script(id="ldap-rootdse", output="namingContexts: dc=example,dc=com")])])
        ad.identify_roles(h)
        self.assertNotIn("Domain Controller", h.roles)

    def test_ldap_server_is_dc_with_marker(self):
        h = Host(ip="10.0.0.9", ports=[_port(portid=389, service="ldap", scripts=[
            Script(id="ldap-rootdse",
                   output="namingContexts: dc=corp\ndomainControllerFunctionality: 7")])])
        ad.identify_roles(h)
        self.assertIn("Domain Controller", h.roles)

    def test_password_hint_word_boundary(self):
        for benign in ("Encompass integration service", "Account passed review",
                       "Accredited vendor node"):
            self.assertIsNone(bloodhound._PW_DESC_RE.search(benign), benign)
            self.assertIsNone(ldap._PW_DESC_RE.search(benign), benign)
        for hit in ("password: Summer2024", "svc pwd=abc", "stored credential here"):
            self.assertIsNotNone(bloodhound._PW_DESC_RE.search(hit), hit)


# --- Group F: parser negation ----------------------------------------------------
class ParserNegationTest(unittest.TestCase):
    def _classify(self, output):
        from recce.parser import _classify_vuln
        return _classify_vuln("10.0.0.10", None, Script(id="http-vuln-check", output=output))

    def test_not_affected_with_cve_is_not_a_finding(self):
        self.assertIsNone(self._classify(
            "The host is not affected. See CVE-2021-44228 for details."))
        self.assertIsNone(self._classify("Checked: host appears patched (CVE-2017-5638)."))

    def test_real_positive_still_a_finding(self):
        v = self._classify("State: VULNERABLE\nThis host is affected by CVE-2017-5638.")
        self.assertIsNotNone(v)
        self.assertIn("CVE-2017-5638", v.ids)


if __name__ == "__main__":
    unittest.main()
