"""Fidelity tests for the FTP active-probe additions in recce/services/ftp.py.

Covers, against live 127.0.0.1 responders whose wire behaviour is drawn from RFC
959 (PASV / HELP / SITE) and RFC 2577 (bounce guard advice):

  * PASV 227-reply IP extraction and the RFC1918-leak finding
    (RFC 959 Sec 4.1.2 / CWE-200).
  * HELP + SITE HELP dangerous-verb fingerprint -- CPFR/CPTO indicates the
    ProFTPD mod_copy primitive behind CVE-2015-3306 / CVE-2019-12815 even when
    the 220 banner has been sanitised.
  * Version-anchored banner-map additions for recent vendor RCEs:
      CrushFTP CVE-2024-4040, Serv-U CVE-2021-35211, WS_FTP CVE-2023-40044,
      ProFTPD 1.3.6/1.3.7 CVE-2019-12815. Patched-version banners MUST NOT
      match (false-positive guard).
"""

import socketserver
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import ftp


# --- minimal FTP responder scaffolding -----------------------------------------

class _LineServer:
    """Threaded TCP responder on 127.0.0.1:<ephemeral>. Handler runs per-connection."""

    def __init__(self, handler):
        outer = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    outer.handler(self.request)
                except OSError:
                    pass

        class S(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.handler = handler
        self.srv = S(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:  # noqa: BLE001
            pass


def _pasv_and_modcopy_handler(sock):
    """FTP server that (a) accepts anonymous, (b) advertises CPFR/CPTO in SITE
    HELP, (c) returns an RFC1918 address in its 227 PASV reply."""
    sock.sendall(b"220 recce-fidelity FTP (ProFTPD 1.3.5 Server) ready.\r\n")
    while True:
        try:
            data = sock.recv(4096)
        except OSError:
            return
        if not data:
            return
        cmd = data.decode(errors="replace").strip().upper()
        if cmd.startswith("FEAT"):
            sock.sendall(b"211-Features:\r\n UTF8\r\n AUTH TLS\r\n211 End\r\n")
        elif cmd.startswith("USER"):
            sock.sendall(b"331 Please specify the password.\r\n")
        elif cmd.startswith("PASS"):
            sock.sendall(b"230 Login successful.\r\n")
        elif cmd.startswith("SYST"):
            sock.sendall(b"215 UNIX Type: L8\r\n")
        elif cmd.startswith("HELP") and not cmd.startswith("HELP SITE"):
            sock.sendall(b"214-The following commands are recognized:\r\n"
                         b" USER PASS QUIT SYST HELP FEAT SITE\r\n"
                         b"214 Help OK.\r\n")
        elif cmd.startswith("SITE"):
            # SITE HELP -- classic mod_copy signature.
            sock.sendall(b"214-The following SITE commands are recognized:\r\n"
                         b" CPFR CPTO CHMOD\r\n"
                         b"214 End.\r\n")
        elif cmd.startswith("PASV"):
            sock.sendall(b"227 Entering Passive Mode (10,0,0,5,196,3).\r\n")
        elif cmd.startswith("QUIT"):
            sock.sendall(b"221 Goodbye.\r\n")
            return
        else:
            sock.sendall(b"500 Unknown command.\r\n")


def _quiet_handler(sock):
    """Baseline: no PASV disclosure, no dangerous SITE verbs, AUTH TLS advertised."""
    sock.sendall(b"220 quiet FTP\r\n")
    while True:
        try:
            data = sock.recv(4096)
        except OSError:
            return
        if not data:
            return
        cmd = data.decode(errors="replace").strip().upper()
        if cmd.startswith("FEAT"):
            sock.sendall(b"211-Features:\r\n UTF8\r\n AUTH TLS\r\n211 End\r\n")
        elif cmd.startswith("USER"):
            sock.sendall(b"530 Anonymous access disabled.\r\n")
        elif cmd.startswith("PASS"):
            sock.sendall(b"530 Login failed.\r\n")
        elif cmd.startswith("SYST"):
            sock.sendall(b"215 UNIX Type: L8\r\n")
        elif cmd.startswith("HELP") and not cmd.startswith("HELP SITE"):
            sock.sendall(b"214-Commands recognized:\r\n USER PASS QUIT\r\n"
                         b"214 End.\r\n")
        elif cmd.startswith("SITE"):
            sock.sendall(b"500 SITE not supported.\r\n")
        elif cmd.startswith("PASV"):
            sock.sendall(b"530 Please login first.\r\n")
        elif cmd.startswith("QUIT"):
            sock.sendall(b"221 Bye.\r\n")
            return
        else:
            sock.sendall(b"500 Unknown command.\r\n")


# --- pure parser tests ---------------------------------------------------------

class FtpPasvParserTest(unittest.TestCase):
    def test_parse_pasv_ip_extracts_octets(self):
        self.assertEqual(
            ftp._parse_pasv_ip("227 Entering Passive Mode (192,168,1,10,196,3).\r\n"),
            "192.168.1.10")

    def test_parse_pasv_ip_rejects_malformed(self):
        self.assertEqual(ftp._parse_pasv_ip(""), "")
        self.assertEqual(ftp._parse_pasv_ip("500 not a PASV reply"), "")
        # Out-of-range octet.
        self.assertEqual(
            ftp._parse_pasv_ip("227 (256,0,0,1,1,2)"), "")

    def test_extract_site_verbs_picks_up_dangerous_verbs(self):
        text = ("214-The following SITE commands are recognized:\r\n"
                " CPFR CPTO CHMOD IDLE\r\n214 End.\r\n")
        verbs = ftp._extract_site_verbs(text)
        self.assertIn("CPFR", verbs)
        self.assertIn("CPTO", verbs)
        self.assertIn("CHMOD", verbs)
        # Not in the dangerous set -- must not appear.
        self.assertNotIn("IDLE", verbs)

    def test_extract_site_verbs_empty_on_benign_help(self):
        self.assertEqual(ftp._extract_site_verbs(""), [])
        self.assertEqual(
            ftp._extract_site_verbs("214-Commands: USER PASS QUIT\r\n214 End."),
            [])


# --- live-probe tests ----------------------------------------------------------

class FtpActiveProbeTest(unittest.TestCase):
    def test_probe_captures_pasv_ip_and_site_verbs(self):
        with _LineServer(_pasv_and_modcopy_handler) as s:
            pr = ftp.probe("127.0.0.1", s.port, timeout=2.0)
        self.assertIsNotNone(pr)
        self.assertEqual(pr.get("pasv_ip"), "10.0.0.5")
        self.assertIn("CPFR", pr.get("site_verbs", []))
        self.assertIn("CPTO", pr.get("site_verbs", []))
        self.assertIn("CHMOD", pr.get("site_verbs", []))

    def test_pasv_leak_and_mod_copy_findings_emitted(self):
        with _LineServer(_pasv_and_modcopy_handler) as s:
            pr = ftp.probe("127.0.0.1", s.port, timeout=2.0)
            host = Host(ip="127.0.0.1", ports=[Port(portid=s.port, service="ftp",
                                                    state="open")])
            fs = ftp.findings([host], {("127.0.0.1", s.port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("ftp_pasv_internal_ip", kinds)
        self.assertIn("ftp_site_copy_exposed", kinds)

    def test_quiet_server_produces_no_new_findings(self):
        with _LineServer(_quiet_handler) as s:
            pr = ftp.probe("127.0.0.1", s.port, timeout=2.0)
            host = Host(ip="127.0.0.1", ports=[Port(portid=s.port, service="ftp",
                                                    state="open")])
            fs = ftp.findings([host], {("127.0.0.1", s.port): pr})
        self.assertEqual(pr.get("pasv_ip"), "")
        self.assertEqual(pr.get("site_verbs"), [])
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("ftp_pasv_internal_ip", kinds)
        self.assertNotIn("ftp_site_copy_exposed", kinds)
        self.assertNotIn("ftp_extra_commands_disclosed", kinds)


# --- banner-map additions (recent vendor CVEs) ---------------------------------

class FtpRecentCveBannerTest(unittest.TestCase):
    """The banner-only backdoor/RCE map must fire on the vulnerable version
    ranges and NOT on the patched ones (false-positive guard)."""

    def _findings_for(self, banner_line):
        host = Host(ip="10.0.0.1", ports=[Port(portid=21, service="ftp",
                                               state="open")])
        probes = {("10.0.0.1", 21): {"banner": banner_line, "anonymous": False,
                                     "auth_tls": True, "syst": ""}}
        return ftp.findings([host], probes)

    # -- CrushFTP CVE-2024-4040 --------------------------------------------------

    def test_crushftp_10_6_matches_2024_4040(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("CrushFTP 10.6.0 Server"))
        self.assertIn("CVE-2024-4040", titles)

    def test_crushftp_11_0_matches_2024_4040(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("CrushFTP 11.0.4 Server"))
        self.assertIn("CVE-2024-4040", titles)

    def test_crushftp_patched_10_7_1_not_matched(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("CrushFTP 10.7.1 Server"))
        self.assertNotIn("CVE-2024-4040", titles)

    def test_crushftp_patched_11_1_0_not_matched(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("CrushFTP 11.1.0 Server"))
        self.assertNotIn("CVE-2024-4040", titles)

    # -- Serv-U CVE-2021-35211 ---------------------------------------------------

    def test_servu_15_2_1_matches_2021_35211(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("Serv-U FTP Server v15.2.1"))
        self.assertIn("CVE-2021-35211", titles)

    def test_servu_14_matches_2021_35211(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("Serv-U FTP Server v14.0.1"))
        self.assertIn("CVE-2021-35211", titles)

    def test_servu_patched_15_2_4_not_matched(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("Serv-U FTP Server v15.2.4"))
        self.assertNotIn("CVE-2021-35211", titles)

    # -- WS_FTP CVE-2023-40044 ---------------------------------------------------

    def test_wsftp_8_6_matches_2023_40044(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("WS_FTP Server 8.6.0"))
        self.assertIn("CVE-2023-40044", titles)

    def test_wsftp_8_7_3_matches_2023_40044(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("WS_FTP Server 8.7.3"))
        self.assertIn("CVE-2023-40044", titles)

    def test_wsftp_patched_8_7_4_not_matched(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("WS_FTP Server 8.7.4"))
        self.assertNotIn("CVE-2023-40044", titles)

    def test_wsftp_patched_8_8_2_not_matched(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("WS_FTP Server 8.8.2"))
        self.assertNotIn("CVE-2023-40044", titles)

    # -- ProFTPD 1.3.6 / 1.3.7 CVE-2019-12815 -----------------------------------

    def test_proftpd_137_matches_2019_12815(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("ProFTPD 1.3.7 Server ready."))
        self.assertIn("CVE-2019-12815", titles)

    def test_proftpd_136_matches_2019_12815(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("ProFTPD 1.3.6 Server ready."))
        self.assertIn("CVE-2019-12815", titles)

    def test_proftpd_138_not_matched_by_2019_12815(self):
        titles = " ".join(f["title"] for f in
                          self._findings_for("ProFTPD 1.3.8 Server ready."))
        self.assertNotIn("CVE-2019-12815", titles)


if __name__ == "__main__":
    unittest.main()
