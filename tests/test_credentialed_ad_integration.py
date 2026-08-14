"""Credentialed Active Directory integration - recce's AUTHENTICATED flows against a
REAL domain controller (a Samba AD DC in Docker).

This is the one tier that cannot be faked in-process: an authenticated SMB session,
Kerberoasting, and secretsdump need a live KDC / SAM / NTDS, not a mock responder. So
it runs against a real DC that CI stands up (tests/integration/docker-compose.ad.yml).

Heavily gated - it runs ONLY when RECCE_AD_IT=1 and the DC env is set and reachable and
the external tools are installed. Everywhere else (the normal suite, any box without
Docker/AD) it skips cleanly and never breaks a run.

Run locally:
    docker compose -f tests/integration/docker-compose.ad.yml up -d
    ./tests/integration/provision-ad.sh
    RECCE_AD_IT=1 RECCE_AD_HOST=127.0.0.1 RECCE_AD_DOMAIN=RECCE.LOCAL \\
      RECCE_AD_ADMIN=Administrator RECCE_AD_PASS='Recce!Passw0rd' \\
      RECCE_AD_SPN_USER=svc_sql RECCE_AD_SPN_PASS='Sql!Passw0rd' \\
      python -m pytest tests/test_credentialed_ad_integration.py -v
"""
import os
import shutil
import socket
import time
import unittest

_ENABLED = os.environ.get("RECCE_AD_IT") == "1"
_HOST = os.environ.get("RECCE_AD_HOST", "127.0.0.1")
_DOMAIN = os.environ.get("RECCE_AD_DOMAIN", "")
_ADMIN = os.environ.get("RECCE_AD_ADMIN", "Administrator")
_PASS = os.environ.get("RECCE_AD_PASS", "")
# A Kerberoastable service account provisioned by provision-ad.sh (an SPN + password).
_SPN_USER = os.environ.get("RECCE_AD_SPN_USER", "svc_sql")


def _reachable(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


@unittest.skipUnless(_ENABLED, "credentialed AD integration disabled (set RECCE_AD_IT=1)")
class CredentialedAdIntegrationTest(unittest.TestCase):
    """recce's authenticated AD flows against a live Samba AD DC."""

    @classmethod
    def setUpClass(cls):
        if not (_DOMAIN and _PASS):
            raise unittest.SkipTest("RECCE_AD_DOMAIN / RECCE_AD_PASS not set")
        # Provisioning + KDC startup is slow; wait for SMB + LDAP + Kerberos.
        deadline = time.time() + 240
        while time.time() < deadline:
            if all(_reachable(_HOST, p) for p in (445, 389, 88)):
                break
            time.sleep(3)
        else:
            raise unittest.SkipTest(f"DC {_HOST} not reachable on 445/389/88")
        cls.creds = {"username": _ADMIN, "password": _PASS, "domain": _DOMAIN}

    def _require(self, tool):
        if not shutil.which(tool):
            self.skipTest(f"{tool} not installed")

    def test_authenticated_smb_enumeration(self):
        # nxc smb with valid domain creds establishes a session and enumerates the DC.
        self._require("nxc")
        from recce import credenum
        data, err = credenum.run_nxc_smb(_HOST, self.creds)
        self.assertIsNone(err, f"nxc smb errored: {err}")
        self.assertIsNotNone(data, "nxc returned no data")
        self.assertTrue(data.get("auth"), "authenticated SMB session was not established")
        # A domain controller exposes standard shares and/or domain user accounts.
        self.assertTrue(data.get("shares") or data.get("users"),
                        "no shares or users enumerated from the DC")

    def test_kerberoast_captures_a_service_ticket(self):
        # GetUserSPNs -request must recover a TGS-REP hash for the provisioned SPN user.
        self._require("impacket-GetUserSPNs")
        from recce import credenum
        spns, err = credenum.run_kerberoast(_HOST, self.creds)
        self.assertIsNone(err, f"kerberoast errored: {err}")
        names = {a.get("name", "").lower() for a in spns}
        self.assertIn(_SPN_USER.lower(), names,
                      f"provisioned SPN user not roasted; got {sorted(names)}")
        self.assertTrue(any(a.get("hash") for a in spns),
                        "no $krb5tgs$ hash captured")

    def test_secretsdump_dumps_domain_hashes(self):
        # As a domain admin, secretsdump -just-dc / SAM+NTDS must return NTLM hashes.
        self._require("impacket-secretsdump")
        from recce import credenum
        dumped, err = credenum.run_secretsdump(_HOST, self.creds)
        self.assertIsNone(err, f"secretsdump errored: {err}")
        self.assertTrue(dumped, "no NTLM hashes dumped")
        self.assertTrue(any(d.get("nt") for d in dumped), "no NT hashes parsed")

    def test_bloodhound_live_kerberoast(self):
        # The bloodhound live-roast path (different creds shape) against the same DC.
        self._require("impacket-GetUserSPNs")
        from recce import bloodhound
        res = bloodhound.live_kerberoast(
            {"domain": _DOMAIN, "user": _ADMIN, "secret": _PASS,
             "dc_ip": _HOST, "is_hash": False})
        self.assertTrue(res.get("ran"), f"live_kerberoast did not run: {res.get('error')}")
        self.assertTrue(res.get("hashes"),
                        f"live_kerberoast captured no hashes: {res.get('error')}")

    def test_ldap_rootdse_identifies_the_domain(self):
        # The unauth LDAP probe reads the DC's RootDSE and identifies the real domain.
        from recce import ldap as L
        pr = L.probe(_HOST, 389, timeout=8.0)
        self.assertIsNotNone(pr, "LDAP probe returned nothing")
        self.assertTrue(pr.get("rootdse_ok"), "RootDSE not read from the live DC")
        self.assertEqual((pr.get("domain") or "").lower(), _DOMAIN.lower())


if __name__ == "__main__":
    unittest.main()
