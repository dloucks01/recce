"""T2 promotion tests for the anonymous-FTP read-foothold snapshot in
``recce/services/ftp.py``.

The T1 anon_ftp finding fires whenever ``probe`` observes a 230 to
``USER anonymous / PASS anonymous@`` (RFC 959 Section 5.4 / RFC 1635 anonymous
FTP convention). :func:`ftp.anon_list_snapshot` then opens ONE fresh, read-only
FTP session and issues a single ``LIST`` (RFC 959 Section 4.1.3, unmarked-path
form) to capture the server-side top-level directory listing as evidence,
lifting the finding to T2. The promotion is additive: any snapshot failure
(TCP refused, 530 login rejected, LIST error, socket timeout) leaves the T1
tier intact and never fabricates evidence.

Fixtures monkeypatch ``ftplib.FTP`` so no live network is needed - the
substitute exposes just the surface :func:`anon_list_snapshot` calls
(``connect``, ``getwelcome``, ``login``, ``retrlines``, ``quit``, ``close``).
"""

from __future__ import annotations

import ftplib
import unittest

from recce.core.models import Host, Port
from recce.services import ftp


# --- ftplib.FTP substitute -----------------------------------------------------

class _FakeFTP:
    """Deterministic stand-in for :class:`ftplib.FTP` shaped by class knobs.

    * ``connect_raises`` -- raise this from ``connect`` (e.g. socket.timeout)
    * ``login_reply``    -- string returned by ``login`` (e.g. ``"230 OK"``)
    * ``login_raises``   -- raise this from ``login`` instead
    * ``list_lines``     -- lines the ``LIST`` callback receives, in order
    * ``list_raises``    -- raise this from ``retrlines`` instead
    * ``welcome``        -- string returned by ``getwelcome``

    Records the last constructed instance on the class as ``last`` so tests can
    assert lifecycle (``quit`` / ``close``) after the call returns.
    """

    connect_raises: BaseException | None = None
    login_reply: str = "230 Login successful."
    login_raises: BaseException | None = None
    list_lines: list[str] = []
    list_raises: BaseException | None = None
    welcome: str = "220 fake-ftp ready"
    last: "_FakeFTP | None" = None

    def __init__(self):
        type(self).last = self
        self.connected_to: tuple[str, int] | None = None
        self.connect_timeout: float | None = None
        self.logged_in_as: tuple[str, str] | None = None
        self.list_commands: list[str] = []
        self.quit_called = False
        self.close_called = False

    def connect(self, host, port=21, timeout=None):
        if type(self).connect_raises is not None:
            raise type(self).connect_raises
        self.connected_to = (host, port)
        self.connect_timeout = timeout
        return f"220 connected {host}:{port}"

    def getwelcome(self):
        return type(self).welcome

    def login(self, user="anonymous", passwd=""):
        if type(self).login_raises is not None:
            raise type(self).login_raises
        self.logged_in_as = (user, passwd)
        return type(self).login_reply

    def retrlines(self, cmd, callback):
        self.list_commands.append(cmd)
        if type(self).list_raises is not None:
            raise type(self).list_raises
        for line in type(self).list_lines:
            callback(line)
        return "226 Transfer complete."

    def quit(self):
        self.quit_called = True
        return "221 Goodbye."

    def close(self):
        self.close_called = True


def _reset_fake():
    _FakeFTP.connect_raises = None
    _FakeFTP.login_reply = "230 Login successful."
    _FakeFTP.login_raises = None
    _FakeFTP.list_lines = []
    _FakeFTP.list_raises = None
    _FakeFTP.welcome = "220 fake-ftp ready"
    _FakeFTP.last = None


# --- snapshot helper tests -----------------------------------------------------

class AnonListSnapshotHelperTest(unittest.TestCase):
    """Direct tests for :func:`ftp.anon_list_snapshot` behaviour."""

    def setUp(self):
        _reset_fake()
        self._orig_ftp = ftplib.FTP
        ftplib.FTP = _FakeFTP

    def tearDown(self):
        ftplib.FTP = self._orig_ftp
        _reset_fake()

    def test_snapshot_captures_listing_and_reports_ok(self):
        # Wire-derived: BSD-style ls output as returned by classic ftpd LIST
        # (RFC 959 Section 4.1.3 - unmarked-path form defaults to CWD).
        _FakeFTP.list_lines = [
            "drwxr-xr-x  2 ftp ftp  4096 Jan 12 09:14 backups",
            "-rw-r--r--  1 ftp ftp  1583 Feb 03 15:44 README.txt",
            "-rw-r--r--  1 ftp ftp   918 Feb 03 15:44 credentials.env",
        ]
        snap = ftp.anon_list_snapshot("10.9.9.9", 21, timeout=2.0, max_lines=20)
        self.assertTrue(snap["ok"])
        self.assertIsNone(snap["error"])
        self.assertEqual(snap["total"], 3)
        self.assertEqual(len(snap["entries"]), 3)
        # A real filename from the fixture must round-trip into evidence -
        # this is what makes the finding a T2 real-evidence promotion.
        self.assertIn("credentials.env", snap["evidence"])
        self.assertIn("LIST", snap["evidence"])

    def test_snapshot_bounds_entries_by_max_lines(self):
        # Guard against blowing out the finding detail on huge directories.
        _FakeFTP.list_lines = [f"file_{i:03d}.bin" for i in range(50)]
        snap = ftp.anon_list_snapshot("10.9.9.9", 21, timeout=2.0, max_lines=5)
        self.assertTrue(snap["ok"])
        self.assertEqual(len(snap["entries"]), 5)
        self.assertEqual(snap["total"], 50)
        self.assertIn("top 5 of 50", snap["evidence"])

    def test_snapshot_issues_exactly_one_list_command(self):
        # T2 must be single-shot: no CWD navigation, no repeated LISTs.
        _FakeFTP.list_lines = ["-rw-r--r-- 1 ftp ftp 0 Jan 1 00:00 pub"]
        ftp.anon_list_snapshot("10.9.9.9", 21, timeout=2.0)
        self.assertIsNotNone(_FakeFTP.last)
        self.assertEqual(_FakeFTP.last.list_commands, ["LIST"])

    def test_snapshot_logs_in_as_anonymous(self):
        # RFC 1635 anonymous convention: USER anonymous / PASS <email>.
        ftp.anon_list_snapshot("10.9.9.9", 21, timeout=2.0)
        self.assertIsNotNone(_FakeFTP.last)
        self.assertEqual(_FakeFTP.last.logged_in_as[0], "anonymous")

    def test_snapshot_closes_session_via_quit(self):
        # Bounded lifecycle: the session must be QUIT even on the happy path.
        ftp.anon_list_snapshot("10.9.9.9", 21, timeout=2.0)
        self.assertIsNotNone(_FakeFTP.last)
        self.assertTrue(_FakeFTP.last.quit_called)

    # --- degradation paths (T1 tier must survive) ------------------------------

    def test_snapshot_returns_not_ok_when_connect_times_out(self):
        # A patched / bounded-timeout server that never answers must degrade
        # cleanly - never raise, never fabricate ok=True.
        _FakeFTP.connect_raises = TimeoutError("connect timed out")
        snap = ftp.anon_list_snapshot("10.9.9.9", 21, timeout=2.0)
        self.assertFalse(snap["ok"])
        self.assertIn("timed out", snap["error"])
        self.assertEqual(snap["entries"], [])

    def test_snapshot_returns_not_ok_when_anonymous_denied(self):
        # A patched server that rejects anonymous with 530 - no T2 evidence.
        _FakeFTP.login_reply = "530 Anonymous access denied."
        snap = ftp.anon_list_snapshot("10.9.9.9", 21, timeout=2.0)
        self.assertFalse(snap["ok"])
        self.assertIn("anonymous login not accepted", snap["error"])

    def test_snapshot_survives_list_error(self):
        # LIST itself may fail (server refuses data channel) - we still return
        # a shape, don't crash, and the T1 path is preserved.
        _FakeFTP.list_raises = ftplib.error_perm("500 LIST not allowed")
        snap = ftp.anon_list_snapshot("10.9.9.9", 21, timeout=2.0)
        self.assertTrue(snap["ok"])   # login succeeded; LIST fault noted
        self.assertEqual(snap["total"], 0)
        self.assertIn("LIST error", snap["evidence"])


# --- findings() tier-promotion tests -------------------------------------------

class FtpAnonFindingTierPromotionTest(unittest.TestCase):
    """The anon_ftp finding must lift its depth_tier to ``t2`` iff evidence is
    present, and must embed the evidence verbatim in the finding's ``detail``."""

    def _findings_for(self, pr: dict) -> list[dict]:
        host = Host(ip="10.0.0.1", ports=[Port(portid=21, service="ftp",
                                                state="open")])
        return ftp.findings([host], {("10.0.0.1", 21): pr})

    def test_anon_without_snapshot_stays_t1(self):
        # No snapshot payload -> the T1 emission path is unchanged.
        pr = {"banner": "vsftpd 3.0.5", "anonymous": True, "auth_tls": True,
              "syst": "UNIX Type: L8"}
        fs = [f for f in self._findings_for(pr) if f["kind"] == "anon_ftp"]
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["depth_tier"], "t1")
        self.assertNotIn("T2 evidence", fs[0]["detail"])

    def test_anon_with_snapshot_promotes_to_t2_and_embeds_evidence(self):
        pr = {
            "banner": "vsftpd 3.0.5",
            "anonymous": True,
            "auth_tls": True,
            "syst": "UNIX Type: L8",
            "anon_list_evidence": (
                "220 fake-ftp ready\n230 Login successful.\n"
                "LIST (3 entries):\n"
                "drwxr-xr-x  2 ftp ftp  4096 Jan 12 09:14 backups\n"
                "-rw-r--r--  1 ftp ftp  1583 Feb 03 15:44 README.txt\n"
                "-rw-r--r--  1 ftp ftp   918 Feb 03 15:44 credentials.env"),
            "anon_list_entries": [
                "drwxr-xr-x  2 ftp ftp  4096 Jan 12 09:14 backups",
                "-rw-r--r--  1 ftp ftp  1583 Feb 03 15:44 README.txt",
                "-rw-r--r--  1 ftp ftp   918 Feb 03 15:44 credentials.env",
            ],
            "anon_list_total": 3,
        }
        fs = [f for f in self._findings_for(pr) if f["kind"] == "anon_ftp"]
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0]["depth_tier"], "t2")
        self.assertIn("T2 evidence", fs[0]["detail"])
        # Real server-side content must appear in the finding detail.
        self.assertIn("credentials.env", fs[0]["detail"])
        # Title, remediation, exploit_note are additive - unchanged from T1.
        self.assertEqual(fs[0]["title"], "Anonymous FTP login allowed")

    def test_no_anon_no_finding(self):
        # anonymous=False -> the anon_ftp finding must not fire regardless of
        # a stale snapshot payload (defensive: never emit without a 230).
        pr = {"banner": "vsftpd 3.0.5", "anonymous": False, "auth_tls": True,
              "anon_list_evidence": "should be ignored", "anon_list_entries": []}
        fs = [f for f in self._findings_for(pr) if f["kind"] == "anon_ftp"]
        self.assertEqual(fs, [])

    def test_promoted_finding_survives_findings_to_vulns(self):
        # depth_tier must flow through findings_to_vulns onto the Vuln.
        pr = {
            "banner": "vsftpd 3.0.5", "anonymous": True, "auth_tls": True,
            "anon_list_evidence": "220 fake-ftp\n230 ok\nLIST (1 entries):\npub",
            "anon_list_entries": ["pub"], "anon_list_total": 1,
        }
        fs = self._findings_for(pr)
        vulns_by_ip = ftp.findings_to_vulns(fs)
        anon_vulns = [v for v in vulns_by_ip.get("10.0.0.1", [])
                      if v.title == "Anonymous FTP login allowed"]
        self.assertEqual(len(anon_vulns), 1)
        self.assertEqual(anon_vulns[0].depth_tier, "t2")


if __name__ == "__main__":
    unittest.main()
