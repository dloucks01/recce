"""Confidence / honesty fidelity - recce's headline promise end to end.

recce's core claim is that it never presents a version/banner GUESS as if it were
actively confirmed. That honesty runs on the QoD model: a finding's detection method
sets its Quality-of-Detection once, and every consumer reads it instead of re-guessing.
The unit thresholds live in test_qod.py; this suite guards the WHOLE chain -
source -> QoD -> exploit-plan gating/marking -> prove-engine verdict - so a version
inference can never be laundered into a CONFIRMED exploit anywhere downstream.
"""
import unittest

from recce import exploitplan, proofs, qod
from recce.models import Host, Port, Vuln


def _v(port, title, source, **kw):
    return Vuln(ip="10.0.0.1", port=port, protocol="tcp", title=title,
                script_id=kw.pop("script_id", source), source=source,
                severity=kw.pop("severity", "high"), **kw)


def _mixed_host():
    """One host with a finding at each detection tier."""
    h = Host(ip="10.0.0.1", ports=[
        Port(portid=6379, protocol="tcp", state="open", service="redis"),
        Port(portid=445, protocol="tcp", state="open", service="microsoft-ds")])
    h.vulns = [
        # version/banner inference: a visible LEAD, never verified.
        _v(6379, "Redis < 6.0 end-of-life", "version-db", confidence="likely"),
        # distro-backport / advisory: 'potential' -> hidden by default.
        _v(445, "OpenSSH regreSSHion", "version-db", confidence="potential",
           severity="critical", ids=["CVE-2024-6387"]),
        # NSE reported VULNERABLE: an active check fired -> verified.
        _v(445, "smb-vuln-ms17-010", "nse", state="VULNERABLE", severity="critical",
           script_id="smb-vuln-ms17-010", ids=["CVE-2017-0143"]),
        # recce's own live protocol probe read the exposure -> verified.
        _v(6379, "Redis exposed without authentication", "probe",
           confidence="confirmed", severity="critical", script_id="redis-unauth"),
    ]
    qod.annotate(h)
    return h


class QodTieringHonestyTest(unittest.TestCase):
    """A finding's detection source determines whether it's a lead or verified."""

    def test_source_maps_to_visibility_and_verification(self):
        by = {v.title: v for v in _mixed_host().vulns}
        # A version/banner match is a VISIBLE lead but NOT verified.
        eol = by["Redis < 6.0 end-of-life"]
        self.assertTrue(qod.is_visible(eol))
        self.assertFalse(qod.is_verified(eol))
        # A distro-backport / 'potential' match is hidden from the default view.
        self.assertFalse(qod.is_visible(by["OpenSSH regreSSHion"]))
        # An NSE-VULNERABLE result and a live probe are both verified.
        self.assertTrue(qod.is_verified(by["smb-vuln-ms17-010"]))
        self.assertTrue(qod.is_verified(by["Redis exposed without authentication"]))


class ExploitGatingHonestyTest(unittest.TestCase):
    """The exploitation planner respects QoD: no plan for a hidden guess, and every
    plan is marked verified/unverified by whether recce actively confirmed it."""

    def test_visibility_floor_excludes_potential_guesses(self):
        h = _mixed_host()
        titles = [v.title for v in exploitplan._confirmed_vulns(h)]
        # The 'potential' distro-backport guess is below the visibility floor.
        self.assertNotIn("OpenSSH regreSSHion", titles)
        # The visible lead + the actively-confirmed findings are in.
        self.assertIn("Redis < 6.0 end-of-life", titles)
        self.assertIn("smb-vuln-ms17-010", titles)

    def test_plan_marks_version_guess_unverified_vs_active_confirmed(self):
        # Same exploit (EternalBlue), two provenances: a version-db banner match and an
        # NSE VULNERABLE result. Both get a plan, but only the active one is 'verified'.
        h = Host(ip="10.0.0.1", ports=[
            Port(portid=445, protocol="tcp", state="open", service="microsoft-ds")])
        h.vulns = [
            _v(445, "SMB EternalBlue (ms17-010) version-inferred", "version-db",
               confidence="likely", severity="critical", ids=["CVE-2017-0144"]),
            _v(139, "smb-vuln-ms17-010 eternalblue", "nse", state="VULNERABLE",
               severity="critical", script_id="smb-vuln-ms17-010", ids=["CVE-2017-0143"]),
        ]
        qod.annotate(h)
        verified_flags = sorted(a["verified"] for a in exploitplan.actions_for_host(h)
                                if "verified" in a)
        # Exactly one unverified (the version guess) and one verified (the NSE result).
        self.assertEqual(verified_flags, [False, True])


class ProveEngineHonestyTest(unittest.TestCase):
    """The prove engine never returns CONFIRMED for a finding recce only inferred from
    a version/banner - only for something it actively observed."""

    def test_version_only_host_is_never_confirmed(self):
        h = Host(ip="10.0.0.2", ports=[
            Port(portid=22, protocol="tcp", state="open", service="ssh"),
            Port(portid=6379, protocol="tcp", state="open", service="redis")])
        h.vulns = [
            _v(22, "OpenSSH regreSSHion", "version-db", confidence="likely",
               severity="critical", ids=["CVE-2024-6387"]),
            _v(6379, "Redis < 6.0 end-of-life", "version-db", confidence="likely"),
        ]
        qod.annotate(h)
        verdicts = {r["verdict"] for r in proofs.verify_host(h)}
        self.assertNotIn("CONFIRMED", verdicts,
                         f"a version-only host was CONFIRMED: {verdicts}")

    def test_actively_observed_findings_are_confirmed(self):
        h = Host(ip="10.0.0.3", ports=[
            Port(portid=445, protocol="tcp", state="open", service="microsoft-ds"),
            Port(portid=6379, protocol="tcp", state="open", service="redis")])
        h.vulns = [
            _v(445, "smb-vuln-ms17-010 eternalblue", "nse", state="VULNERABLE",
               severity="critical", script_id="smb-vuln-ms17-010", ids=["CVE-2017-0143"]),
            _v(6379, "Redis exposed without authentication", "probe",
               confidence="confirmed", severity="critical", script_id="redis-unauth"),
        ]
        qod.annotate(h)
        verdicts = {r["verdict"] for r in proofs.verify_host(h)}
        self.assertIn("CONFIRMED", verdicts,
                      f"actively-observed findings were not CONFIRMED: {verdicts}")


if __name__ == "__main__":
    unittest.main()
