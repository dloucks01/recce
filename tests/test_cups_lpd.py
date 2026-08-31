"""Tests for recce.services.cups_lpd — LPD queue-list parsing + CUPS extensions.

Every LPD test drives a loopback TCP server that replays canned RFC 1179
response bytes. Every IPP / cups-browsed test uses monkeypatched HTTP or an
in-process UDP+TCP pair. The scanner never touches the real network.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.services import cups_lpd


# --- LPD loopback server ---------------------------------------------------

class _LPDServer:
    """Minimal LPD-style responder: accept one connection, read a request,
    reply with a canned queue-listing payload, close."""

    def __init__(self, response: bytes, hold_open: bool = False):
        self._resp = response
        self._hold = hold_open
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.host, self.port = self._sock.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(1.5)
                try: conn.recv(4096)
                except (socket.timeout, OSError): pass
                try: conn.sendall(self._resp)
                except OSError: pass
            finally:
                try: conn.close()
                except OSError: pass

    def close(self):
        self._stop = True
        try: self._sock.close()
        except OSError: pass


# --- LPD wire ---------------------------------------------------------------

class LPDWireTest(unittest.TestCase):
    def test_short_opcode(self):
        # RFC 1179 sec 3 command 03: single-byte 0x03 + ASCII queue + LF.
        self.assertEqual(cups_lpd._lpd_short("lp"), b"\x03lp\n")

    def test_long_opcode(self):
        self.assertEqual(cups_lpd._lpd_long(""), b"\x04\n")


# --- LPD parsing ------------------------------------------------------------

# Wire-derived: text a BSD lpd emits from `lpq -aP lp` (RFC 1179 sec 5.3).
_SHORT_LISTING = (
    b"Rank   Owner      Job  Files                          Total Size\n"
    b"1st    alice      42   /home/alice/report.pdf           12345 bytes\n"
    b"2nd    bob        43   proposal.docx                   234567 bytes\n"
)

# LPRng-flavoured long listing that carries the daemon fingerprint AND the
# "H" (host of origin) field the punch list flags as recon-grade.
_LONG_LISTING_LPRNG = (
    b"Printer: lp@printsrv-01 'HR color'\n"
    b"Queue: 2 printable jobs\n"
    b" Server: no server active\n"
    b" Status: LPRng-3.8.28 ready\n"
    b"alice: 1st                                [job 042 workstation-42.corp.local]\n"
    b"        /var/spool/lpd/dfA042workstation  1 copies of Q3-forecast.xlsx\n"
    b"        /var/spool/lpd/cfA042workstation\n"
    b"bob:   2nd                                [job 043 laptop-bob.corp.local]\n"
    b"        /var/spool/lpd/dfA043laptop-bob   1 copies of passwords.txt\n"
)

_BSD_EMPTY = b"no entries\n"
_HP_JETDIRECT = b"lp is ready and printing\nno entries\n"
_CUPS_LPD = b"Printer: lp\nprinter status: idle. ipp://cupshost/printers/lp\n"
_WINDOWS = b"Windows LPD Print Service\nOwner    Status    Jobs\nno jobs waiting\n"


class LPDParseTest(unittest.TestCase):
    def test_short_listing_yields_owners_jobs_files(self):
        text = _SHORT_LISTING.decode()
        parsed = cups_lpd._parse_lpd_listing(text)
        owners = parsed["owners"]
        self.assertIn("alice", owners)
        self.assertIn("bob", owners)
        # Filenames are pulled out of the Files column.
        self.assertTrue(any("report.pdf" in f for f in parsed["filenames"]))
        self.assertTrue(any("proposal.docx" in f for f in parsed["filenames"]))
        # Two jobs.
        self.assertEqual(len(parsed["jobs"]), 2)
        job = parsed["jobs"][0]
        self.assertEqual(job["owner"], "alice")
        self.assertEqual(job["size"], 12345)

    def test_long_listing_extracts_host_of_origin(self):
        text = _LONG_LISTING_LPRNG.decode()
        parsed = cups_lpd._parse_lpd_listing(text)
        self.assertIn("alice", parsed["owners"])
        self.assertIn("bob", parsed["owners"])
        # LONG-format 'H' field: host of origin per job.
        self.assertIn("workstation-42.corp.local", parsed["hosts"])
        self.assertIn("laptop-bob.corp.local", parsed["hosts"])
        # Real (non control-file) filenames only.
        files = set(parsed["filenames"])
        self.assertIn("Q3-forecast.xlsx", files)
        self.assertIn("passwords.txt", files)
        # cfA/dfA control-file names must not leak in as job filenames.
        for f in files:
            self.assertFalse(f.startswith("cf") and "042" in f)
            self.assertFalse(f.startswith("df") and "042" in f)


class LPDFingerprintTest(unittest.TestCase):
    def test_lprng_family(self):
        fam, ver = cups_lpd._fingerprint_lpd(_LONG_LISTING_LPRNG.decode())
        self.assertEqual(fam, "lprng")
        # LPRng-3.8.28 -> version hint 3.8.28
        self.assertEqual(ver, "3.8.28")

    def test_bsd_family(self):
        fam, _ = cups_lpd._fingerprint_lpd(_BSD_EMPTY.decode())
        self.assertEqual(fam, "bsd")

    def test_cups_lpd_family(self):
        fam, _ = cups_lpd._fingerprint_lpd(_CUPS_LPD.decode())
        self.assertEqual(fam, "cups-lpd")

    def test_hp_jetdirect_family(self):
        fam, _ = cups_lpd._fingerprint_lpd(_HP_JETDIRECT.decode())
        self.assertEqual(fam, "hp-jetdirect")

    def test_windows_family(self):
        fam, _ = cups_lpd._fingerprint_lpd(_WINDOWS.decode())
        self.assertEqual(fam, "windows")


# --- LPD live probe against loopback ---------------------------------------

class LPDProbeTest(unittest.TestCase):
    def test_probe_lprng_full_capture(self):
        srv = _LPDServer(_LONG_LISTING_LPRNG)
        try:
            pr = cups_lpd.probe_lpd(srv.host, srv.port, timeout=2,
                                    queues=("lp",))
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["family"], "lprng")
        self.assertIn("alice", pr["owners"])
        self.assertIn("workstation-42.corp.local", pr["hosts"])
        self.assertTrue(any("Q3-forecast.xlsx" in f for f in pr["filenames"]))
        # ACL-open signal: recce is an arbitrary peer that got a listing.
        self.assertTrue(pr["acl_open"])

    def test_probe_bsd_empty_queue(self):
        srv = _LPDServer(_BSD_EMPTY)
        try:
            pr = cups_lpd.probe_lpd(srv.host, srv.port, timeout=2,
                                    queues=("lp",))
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["family"], "bsd")
        self.assertFalse(pr["owners"])

    def test_probe_dead_port(self):
        pr = cups_lpd.probe_lpd("127.0.0.1", 1, timeout=1)
        self.assertFalse(pr["reachable"])


# --- LPD findings emission --------------------------------------------------

class LPDFindingsTest(unittest.TestCase):
    def _mkhost(self, ip="10.0.0.5", portid=515):
        from recce.core.models import Host, Port
        return Host(ip=ip, ports=[Port(portid=portid, protocol="tcp",
                                       state="open", service="printer")])

    def test_lprng_finding_cites_the_two_cves(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 515): {
            "reachable": True, "family": "lprng", "version_hint": "3.8.28",
            "listings": [], "owners": ["alice"], "hosts": [], "filenames": [],
            "acl_open": True,
        }}
        fs = cups_lpd.findings([h], lpd_probes=probes)
        titles = [f["title"] for f in fs]
        self.assertTrue(any("LPRng" in t for t in titles))
        lprng = next(f for f in fs if "LPRng" in f["title"])
        self.assertIn("CVE-2000-0917", lprng["title"])
        self.assertIn("CVE-2001-0670", lprng["title"])
        # LPRng CVE finding gets the format-string / injection CWEs.
        self.assertIn("CWE-134", lprng["cwes"])

    def test_hp_jetdirect_finding_flags_cve_2010_4107(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 515): {
            "reachable": True, "family": "hp-jetdirect", "version_hint": "",
            "listings": [], "owners": [], "hosts": [], "filenames": [],
            "acl_open": True,
        }}
        fs = cups_lpd.findings([h], lpd_probes=probes)
        titles = [f["title"] for f in fs]
        self.assertTrue(any("CVE-2010-4107" in t for t in titles))

    def test_windows_lpd_correlates_with_printnightmare(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 515): {
            "reachable": True, "family": "windows", "version_hint": "",
            "listings": [], "owners": [], "hosts": [], "filenames": [],
            "acl_open": True,
        }}
        fs = cups_lpd.findings([h], lpd_probes=probes)
        titles = [f["title"] for f in fs]
        self.assertTrue(any("PrintNightmare" in t for t in titles))

    def test_leak_finding_when_owners_or_hosts_present(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 515): {
            "reachable": True, "family": "bsd", "version_hint": "",
            "listings": [{"queue": "lp", "op": "long", "text": "",
                          "jobs": [{"owner": "alice"}]}],
            "owners": ["alice"], "hosts": ["ws01"], "filenames": ["Q3.xlsx"],
            "acl_open": True,
        }}
        fs = cups_lpd.findings([h], lpd_probes=probes)
        titles = [f["title"] for f in fs]
        self.assertTrue(any("LPD queue leaks" in t for t in titles))
        self.assertTrue(any("accepts queue commands from any peer" in t
                            for t in titles))

    def test_open_queue_but_empty_is_medium_only(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 515): {
            "reachable": True, "family": "bsd", "version_hint": "",
            "listings": [], "owners": [], "hosts": [], "filenames": [],
            "acl_open": True,
        }}
        fs = cups_lpd.findings([h], lpd_probes=probes)
        leaks = [f for f in fs if "leaks" in f["title"]]
        self.assertFalse(leaks)
        opens = [f for f in fs if f["kind"] == "lpd_queue_open"]
        self.assertEqual(len(opens), 1)


# --- IPP Get-Jobs -----------------------------------------------------------

def _ipp_response_get_jobs() -> bytes:
    """A minimally-valid IPP Get-Jobs response body.

    Layout (RFC 8010):
      version(2) status(2) request-id(4)
      operation-attributes-tag (0x01)
        attributes-charset "utf-8"
        attributes-natural-language "en-us"
      job-attributes-tag (0x02)
        job-id 42
        job-name "Q3-forecast.xlsx"
        job-originating-user-name "alice"
        job-originating-host-name "workstation-42.corp.local"
      end-of-attributes (0x03)
    """
    def name_value(tag: int, name: bytes, value: bytes) -> bytes:
        return (bytes([tag]) + struct.pack("!H", len(name)) + name
                + struct.pack("!H", len(value)) + value)

    hdr = struct.pack("!BBHI", 1, 1, 0x0000, 2)
    body = b"\x01"                                          # operation group
    body += name_value(0x47, b"attributes-charset", b"utf-8")
    body += name_value(0x48, b"attributes-natural-language", b"en-us")
    body += b"\x02"                                         # job group
    body += name_value(0x21, b"job-id", struct.pack("!I", 42))       # integer
    body += name_value(0x42, b"job-name", b"Q3-forecast.xlsx")       # nameWithoutLang
    body += name_value(0x42, b"job-originating-user-name", b"alice")
    body += name_value(0x42, b"job-originating-host-name",
                       b"workstation-42.corp.local")
    body += b"\x03"                                         # end-of-attributes
    return hdr + body


class IPPGetJobsTest(unittest.TestCase):
    def test_wire_carries_op_id_000a_and_printer_uri(self):
        wire = cups_lpd._ipp_get_jobs("ipp://10.0.0.5:631/printers/lp")
        # Version 1.1, op 0x000A (Get-Jobs), request-id 2.
        self.assertEqual(wire[:2], b"\x01\x01")
        self.assertEqual(struct.unpack("!H", wire[2:4])[0], 0x000A)
        # printer-uri attribute (tag 0x45) must appear in the operation group.
        self.assertIn(b"printer-uri", wire)
        # Request must end with the end-of-attributes byte 0x03.
        self.assertEqual(wire[-1:], b"\x03")

    def test_parse_response_extracts_user_host_file(self):
        jobs = cups_lpd._parse_ipp_jobs(_ipp_response_get_jobs())
        self.assertEqual(len(jobs), 1)
        j = jobs[0]
        self.assertEqual(j.get("job-originating-user-name"), "alice")
        self.assertEqual(j.get("job-originating-host-name"),
                         "workstation-42.corp.local")
        self.assertEqual(j.get("job-name"), "Q3-forecast.xlsx")

    def test_ipp_get_jobs_calls_post_and_summarises(self, ):
        canned = _ipp_response_get_jobs()

        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            self.assertEqual(ip, "10.0.0.5")
            self.assertEqual(port, 631)
            # Should hit the Get-Jobs op code on the wire we send.
            self.assertEqual(struct.unpack("!H", body[2:4])[0], 0x000A)
            return 200, canned, "CUPS/2.4.7 (Ubuntu)"

        orig = cups_lpd._ipp_post
        cups_lpd._ipp_post = fake_post
        try:
            out = cups_lpd.ipp_get_jobs("10.0.0.5",
                                        "ipp://10.0.0.5:631/printers/lp")
        finally:
            cups_lpd._ipp_post = orig
        self.assertTrue(out["reachable"])
        self.assertIn("alice", out["users"])
        self.assertIn("workstation-42.corp.local", out["hosts"])
        self.assertIn("Q3-forecast.xlsx", out["filenames"])


# --- CUPS version gate ------------------------------------------------------

class CupsVersionGateTest(unittest.TestCase):
    def test_upstream_249_is_fixed(self):
        v, why = cups_lpd.cups_vulnerable("2.4.9")
        self.assertFalse(v)
        self.assertIn("2.4.9", why)

    def test_upstream_247_is_vulnerable_without_distro_marker(self):
        v, why = cups_lpd.cups_vulnerable("2.4.7", "CUPS/2.4.7")
        self.assertTrue(v)

    def test_ubuntu_backport_downgrades(self):
        # Ubuntu SRU suffix in the Server header should downgrade the finding.
        v, why = cups_lpd.cups_vulnerable(
            "2.4.7", "CUPS/2.4.7 (Ubuntu 24.04.1 cups 2.4.7-1.2ubuntu7.1)")
        self.assertFalse(v)
        self.assertIn("distro", why)

    def test_rhel_op_backport_downgrades(self):
        v, why = cups_lpd.cups_vulnerable("2.3.3op2-25")
        self.assertFalse(v)

    def test_unparseable_defaults_vulnerable(self):
        v, why = cups_lpd.cups_vulnerable("weird")
        self.assertTrue(v)


# --- URI harvest ------------------------------------------------------------

class URIHarvestTest(unittest.TestCase):
    def test_extracts_hosts_and_domain_suffixes(self):
        printers = [
            {"printer-uri-supported": "ipp://print01.corp.local:631/printers/HR-Color"},
            {"device-uri": "socket://192.168.7.9:9100"},
            {"printer-more-info": "https://print-portal.hq.corp.local/status"},
        ]
        h = cups_lpd.harvest_uris(printers)
        self.assertIn("print01.corp.local", h["hostnames"])
        self.assertIn("192.168.7.9", h["hostnames"])
        self.assertIn("print-portal.hq.corp.local", h["hostnames"])
        # Suffixes fed to known_domains.
        self.assertIn("corp.local", h["domains"])
        self.assertIn("hq.corp.local", h["domains"])


# --- cups-browsed loopback --------------------------------------------------

class CupsBrowsedTest(unittest.TestCase):
    def test_reachable_signal_when_daemon_dials_back(self):
        # Simulate cups-browsed: bind a UDP receiver; on the packet, dial the
        # advertised URI's host:port back — a TCP connect is the exposure
        # signal the probe watches for.
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(3.0)
        _, port = udp.getsockname()

        def _cups_browsed():
            try:
                data, _addr = udp.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            # Wire the punch list describes: parse the advertised ipp:// URI
            # and TCP-connect to its host:port (the ingress path of
            # CVE-2024-47176).
            text = data.decode("ascii", "replace")
            # ipp://<host>:<port>/...
            import re as _re
            m = _re.search(r"ipp://([^/:\s]+):(\d+)/", text)
            if not m:
                return
            back_host, back_port = m.group(1), int(m.group(2))
            try:
                s = socket.create_connection((back_host, back_port), timeout=2)
                s.close()
            except OSError:
                pass

        t = threading.Thread(target=_cups_browsed, daemon=True)
        t.start()
        try:
            out = cups_lpd.probe_cups_browsed("127.0.0.1", port=port,
                                              listen_timeout=3.0, timeout=2.0)
        finally:
            try: udp.close()
            except OSError: pass
        self.assertTrue(out["sent"])
        self.assertTrue(out["replied"],
                        "listener saw no dial-back — the exposure signal misfires")

    def test_no_reply_leaves_replied_false(self):
        # No UDP listener; probe should still send but see no dial-back.
        out = cups_lpd.probe_cups_browsed("127.0.0.1", port=1,
                                          listen_timeout=1.0, timeout=1.0)
        self.assertFalse(out["replied"])


# --- /admin auth check ------------------------------------------------------

class AdminEndpointTest(unittest.TestCase):
    def test_readable_and_auth_paths_classified(self):
        # Fake HTTP responder: /admin -> 200 (public), /admin/conf -> 401,
        # other paths -> 404. Two endpoints classify as readable / auth_required.
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        host, port = srv.getsockname()
        stop = {"stop": False}

        def _serve():
            srv.settimeout(0.5)
            while not stop["stop"]:
                try:
                    conn, _ = srv.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    conn.settimeout(1.5)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        data += chunk
                        if len(data) > 8192: break
                    req_line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                    parts = req_line.split()
                    path = parts[1] if len(parts) >= 2 else "/"
                    if path == "/admin":
                        body = b"CUPS admin UI"
                        conn.sendall(
                            b"HTTP/1.0 200 OK\r\nContent-Length: "
                            + str(len(body)).encode() + b"\r\n\r\n" + body)
                    elif path == "/admin/conf":
                        conn.sendall(
                            b"HTTP/1.0 401 Unauthorized\r\n"
                            b"WWW-Authenticate: Basic realm=\"CUPS\"\r\n"
                            b"Content-Length: 0\r\n\r\n")
                    else:
                        conn.sendall(b"HTTP/1.0 404 Not Found\r\n"
                                     b"Content-Length: 0\r\n\r\n")
                except OSError:
                    pass
                finally:
                    try: conn.close()
                    except OSError: pass

        th = threading.Thread(target=_serve, daemon=True)
        th.start()
        try:
            out = cups_lpd.probe_admin_endpoints(host, port, timeout=2.0)
        finally:
            stop["stop"] = True
            try: srv.close()
            except OSError: pass
        self.assertIn("/admin", out["readable"])
        self.assertIn("/admin/conf", out["auth_required"])


# --- printer-stack correlation ---------------------------------------------

class CorrelationTest(unittest.TestCase):
    def test_correlation_fires_only_when_all_three_ports_open(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.5", ports=[
            Port(portid=515, protocol="tcp", state="open", service="printer"),
            Port(portid=631, protocol="tcp", state="open", service="ipp"),
            Port(portid=9100, protocol="tcp", state="open", service="jetdirect"),
        ])
        probes = {("10.0.0.5", 515): {
            "reachable": True, "family": "bsd", "version_hint": "",
            "listings": [], "owners": [], "hosts": [], "filenames": [],
            "acl_open": False,
        }}
        fs = cups_lpd.findings([h], lpd_probes=probes)
        self.assertTrue(any(f["kind"] == "printer_stack_correlation" for f in fs))

    def test_correlation_absent_without_9100(self):
        from recce.core.models import Host, Port
        h = Host(ip="10.0.0.5", ports=[
            Port(portid=515, protocol="tcp", state="open", service="printer"),
            Port(portid=631, protocol="tcp", state="open", service="ipp"),
        ])
        probes = {("10.0.0.5", 515): {
            "reachable": True, "family": "bsd", "version_hint": "",
            "listings": [], "owners": [], "hosts": [], "filenames": [],
            "acl_open": False,
        }}
        fs = cups_lpd.findings([h], lpd_probes=probes)
        self.assertFalse(any(f["kind"] == "printer_stack_correlation" for f in fs))


# --- IPP-side findings emission --------------------------------------------

class IPPFindingsTest(unittest.TestCase):
    def _mkhost(self):
        from recce.core.models import Host, Port
        return Host(ip="10.0.0.5", ports=[
            Port(portid=631, protocol="tcp", state="open", service="ipp"),
        ])

    def test_get_jobs_finding_emitted(self):
        h = self._mkhost()
        jobs = {("10.0.0.5", 631): {
            "reachable": True, "jobs": [{}], "users": ["alice"],
            "hosts": ["ws01.corp.local"],
            "filenames": ["Q3-forecast.xlsx"],
        }}
        fs = cups_lpd.findings([h], jobs_probes=jobs)
        self.assertTrue(any(f["kind"] == "ipp_get_jobs" for f in fs))

    def test_admin_readable_high_severity(self):
        h = self._mkhost()
        admin = {("10.0.0.5", 631): {
            "probed": list(cups_lpd._ADMIN_PATHS),
            "results": [],
            "readable": ["/admin/log/error_log"],
            "auth_required": [],
        }}
        fs = cups_lpd.findings([h], admin_probes=admin)
        f = next(x for x in fs if x["kind"] == "cups_admin_open")
        self.assertEqual(f["severity"], "high")

    def test_admin_auth_required_medium_severity(self):
        h = self._mkhost()
        admin = {("10.0.0.5", 631): {
            "probed": list(cups_lpd._ADMIN_PATHS),
            "results": [],
            "readable": [],
            "auth_required": ["/admin"],
        }}
        fs = cups_lpd.findings([h], admin_probes=admin)
        f = next(x for x in fs if x["kind"] == "cups_admin_auth")
        self.assertEqual(f["severity"], "medium")

    def test_browsed_reachable_is_critical(self):
        h = self._mkhost()
        br = {"10.0.0.5": {"sent": True, "replied": True, "remote_port": 44321}}
        fs = cups_lpd.findings([h], browsed_probes=br)
        f = next(x for x in fs if x["kind"] == "cups_browsed_reachable")
        self.assertEqual(f["severity"], "critical")
        self.assertIn("CVE-2024-47176", f["title"])

    def test_version_gate_downgrades_when_patched(self):
        h = self._mkhost()
        vg = {("10.0.0.5", 631): {"version": "2.4.9", "vulnerable": False,
                                  "why": "upstream 2.4.9 >= 2.4.9 (fixed)"}}
        fs = cups_lpd.findings([h], version_gate=vg)
        # Patched -> info-level "past the fixed line" finding, not high.
        f = next(x for x in fs if x["kind"] == "cups_foomatic_patched")
        self.assertEqual(f["severity"], "info")

    def test_version_gate_escalates_when_paired_with_browsed(self):
        h = self._mkhost()
        vg = {("10.0.0.5", 631): {"version": "2.4.7", "vulnerable": True,
                                  "why": "upstream 2.4.7 < 2.4.9"}}
        br = {"10.0.0.5": {"sent": True, "replied": True}}
        fs = cups_lpd.findings([h], version_gate=vg, browsed_probes=br)
        vuln = next(x for x in fs if x["kind"] == "cups_foomatic_vuln")
        self.assertEqual(vuln["severity"], "critical")

    def test_version_gate_high_alone(self):
        h = self._mkhost()
        vg = {("10.0.0.5", 631): {"version": "2.4.7", "vulnerable": True,
                                  "why": "upstream 2.4.7 < 2.4.9"}}
        fs = cups_lpd.findings([h], version_gate=vg)
        vuln = next(x for x in fs if x["kind"] == "cups_foomatic_vuln")
        self.assertEqual(vuln["severity"], "high")

    def test_uri_harvest_finding_emitted(self):
        h = self._mkhost()
        uh = {("10.0.0.5", 631): {"hostnames": ["print01.corp.local"],
                                  "domains": ["corp.local"]}}
        fs = cups_lpd.findings([h], uri_harvest=uh)
        self.assertTrue(any(f["kind"] == "ipp_uri_harvest" for f in fs))


# --- is_lpd / findings_to_vulns --------------------------------------------

class MiscTest(unittest.TestCase):
    def test_is_lpd_matches_by_port_and_service_name(self):
        from recce.core.models import Port
        self.assertTrue(cups_lpd.is_lpd(Port(portid=515, service="printer")))
        self.assertTrue(cups_lpd.is_lpd(Port(portid=9999, service="lpd")))
        self.assertFalse(cups_lpd.is_lpd(Port(portid=80, service="http")))

    def test_findings_to_vulns_returns_by_ip_map(self):
        fs = [cups_lpd._finding("high", "Something", "10.0.0.5:515", "detail",
                                "tool", "cmd", "rem", ["CWE-200"], "kind")]
        vs = cups_lpd.findings_to_vulns(fs)
        self.assertIn("10.0.0.5", vs)
        self.assertEqual(vs["10.0.0.5"][0].port, 515)


# --- T2 promotion: PJL fingerprint on 9100/tcp ------------------------------

# Wire-derived @PJL INFO ID / INFO CONFIG reply from an HP LaserJet — pulled
# from a public HP PJL Technical Reference sample; not fabricated by recce.
_PJL_INFO_REPLY = (
    b"\x1B%-12345X"
    b"@PJL INFO ID\r\n"
    b"\"HP LaserJet 4200\"\r\n"
    b"\x0c"
    b"@PJL INFO CONFIG\r\n"
    b"IN TRAYS [3 ENUMERATED]\r\n"
    b"\tTray 1\r\n"
    b"FIRMWARE DATECODE=20050822\r\n"
    b"\x1B%-12345X"
)


class _PJLServer:
    """Loopback TCP responder that replays a PJL INFO reply."""

    def __init__(self, response: bytes):
        self._resp = response
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self.host, self.port = self._sock.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._sock.settimeout(0.5)
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(1.5)
                try: conn.recv(4096)
                except (socket.timeout, OSError): pass
                try: conn.sendall(self._resp)
                except OSError: pass
            finally:
                try: conn.close()
                except OSError: pass

    def close(self):
        self._stop = True
        try: self._sock.close()
        except OSError: pass


class PJLProbeTest(unittest.TestCase):
    def test_parses_model_and_firmware_from_reply(self):
        srv = _PJLServer(_PJL_INFO_REPLY)
        try:
            pj = cups_lpd.probe_pjl_info(srv.host, port=srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pj["reachable"])
        self.assertEqual(pj["model"], "HP LaserJet 4200")
        self.assertEqual(pj["firmware"], "20050822")

    def test_dead_port_stays_unreachable(self):
        pj = cups_lpd.probe_pjl_info("127.0.0.1", port=1, timeout=1)
        self.assertFalse(pj["reachable"])
        self.assertEqual(pj["model"], "")
        self.assertEqual(pj["firmware"], "")

    def test_empty_reply_stays_unreachable(self):
        srv = _PJLServer(b"")
        try:
            pj = cups_lpd.probe_pjl_info(srv.host, port=srv.port, timeout=2)
        finally:
            srv.close()
        # Nothing came back — probe should NOT upgrade.
        self.assertFalse(pj["reachable"])


class JetDirectT2FindingTest(unittest.TestCase):
    def _mkhost(self):
        from recce.core.models import Host, Port
        return Host(ip="10.0.0.5", ports=[
            Port(portid=515, protocol="tcp", state="open", service="printer"),
        ])

    def _lpd_probes(self):
        return {("10.0.0.5", 515): {
            "reachable": True, "family": "hp-jetdirect", "version_hint": "",
            "listings": [], "owners": [], "hosts": [], "filenames": [],
            "acl_open": False,
        }}

    def test_jetdirect_upgrades_to_t2_when_pjl_probe_hits(self):
        h = self._mkhost()
        pjl = {"10.0.0.5": {"reachable": True, "raw": "",
                             "model": "HP LaserJet 4200",
                             "firmware": "20050822"}}
        fs = cups_lpd.findings([h], lpd_probes=self._lpd_probes(),
                               pjl_probes=pjl)
        jd = next(f for f in fs if f["kind"] == "lpd_jetdirect_cve")
        self.assertEqual(jd["depth_tier"], "t2")
        self.assertIn("HP LaserJet 4200", jd["output"])
        self.assertIn("20050822", jd["output"])
        self.assertIn("T2 proof", jd["detail"])

    def test_jetdirect_stays_t1_without_pjl_probe(self):
        h = self._mkhost()
        # No pjl_probes provided → tier stays T1, output is empty.
        fs = cups_lpd.findings([h], lpd_probes=self._lpd_probes())
        jd = next(f for f in fs if f["kind"] == "lpd_jetdirect_cve")
        self.assertEqual(jd["depth_tier"], "t1")
        self.assertEqual(jd["output"], "")

    def test_jetdirect_stays_t1_when_pjl_probe_unreachable(self):
        # 9100 filtered → PJL probe records reachable=False → tier stays T1.
        h = self._mkhost()
        pjl = {"10.0.0.5": {"reachable": False, "raw": "",
                             "model": "", "firmware": ""}}
        fs = cups_lpd.findings([h], lpd_probes=self._lpd_probes(),
                               pjl_probes=pjl)
        jd = next(f for f in fs if f["kind"] == "lpd_jetdirect_cve")
        self.assertEqual(jd["depth_tier"], "t1")


# --- T2 promotion: CUPS access log body parse -------------------------------

# Two access_log rows from a stock cupsd on 2.4.7 (Ubuntu 24.04): one anon
# request from localhost, one authenticated print job from a workstation.
_CUPS_ACCESS_LOG = (
    "localhost - - [22/Aug/2026:14:33:12 +0000] "
    "\"GET /admin HTTP/1.1\" 200 2340 - -\n"
    "192.168.7.42 - alice [22/Aug/2026:14:33:15 +0000] "
    "\"POST /printers/HR-Color HTTP/1.1\" 200 4711 Print-Job successful-ok\n"
    "192.168.7.99 - bob [22/Aug/2026:14:34:02 +0000] "
    "\"POST /printers/HR-Color HTTP/1.1\" 200 8890 Print-Job successful-ok\n"
)

_CUPS_ERROR_LOG = (
    "E [22/Aug/2026:14:33:12 +0000] [Client 42] Returning IPP "
    "client-error-not-found for Get-Printer-Attributes "
    "(ipp://localhost:631/printers/missing) from 10.9.9.7\n"
)


class CupsLogParseTest(unittest.TestCase):
    def test_access_log_extracts_users_ips_printers(self):
        parsed = cups_lpd.parse_cups_log(_CUPS_ACCESS_LOG)
        self.assertEqual(parsed["entries"], 3)
        self.assertIn("alice", parsed["users"])
        self.assertIn("bob", parsed["users"])
        self.assertNotIn("-", parsed["users"])
        self.assertIn("192.168.7.42", parsed["ips"])
        self.assertIn("192.168.7.99", parsed["ips"])
        # "localhost" is not IPv4, must NOT land in ips.
        self.assertNotIn("localhost", parsed["ips"])
        self.assertIn("/printers/HR-Color", parsed["printers"])

    def test_error_log_extracts_source_ip(self):
        parsed = cups_lpd.parse_cups_log(_CUPS_ERROR_LOG)
        self.assertIn("10.9.9.7", parsed["ips"])

    def test_empty_body_yields_zero_entries(self):
        parsed = cups_lpd.parse_cups_log("")
        self.assertEqual(parsed["entries"], 0)
        self.assertEqual(parsed["users"], [])
        self.assertEqual(parsed["ips"], [])


class AdminOpenT2FindingTest(unittest.TestCase):
    def _mkhost(self):
        from recce.core.models import Host, Port
        return Host(ip="10.0.0.5", ports=[
            Port(portid=631, protocol="tcp", state="open", service="ipp"),
        ])

    def test_admin_upgrades_to_t2_when_log_parsed(self):
        h = self._mkhost()
        admin = {("10.0.0.5", 631): {
            "probed": list(cups_lpd._ADMIN_PATHS),
            "results": [],
            "readable": ["/admin/log/access_log"],
            "auth_required": [],
            "log_parsed": {
                "users": ["alice", "bob"],
                "ips": ["192.168.7.42", "192.168.7.99"],
                "printers": ["/printers/HR-Color"],
                "entries": 3,
            },
        }}
        fs = cups_lpd.findings([h], admin_probes=admin)
        f = next(x for x in fs if x["kind"] == "cups_admin_open")
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("alice", f["output"])
        self.assertIn("192.168.7.42", f["output"])
        self.assertIn("T2 proof", f["detail"])

    def test_admin_stays_t1_when_no_log_body_parsed(self):
        h = self._mkhost()
        admin = {("10.0.0.5", 631): {
            "probed": list(cups_lpd._ADMIN_PATHS),
            "results": [],
            "readable": ["/admin/log/error_log"],
            "auth_required": [],
            # No log_parsed key — body fetch failed or returned nothing.
        }}
        fs = cups_lpd.findings([h], admin_probes=admin)
        f = next(x for x in fs if x["kind"] == "cups_admin_open")
        self.assertEqual(f["depth_tier"], "t1")
        self.assertEqual(f["output"], "")


class FetchAdminLogTest(unittest.TestCase):
    def test_fetches_body_on_200_and_empty_on_401(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        host, port = srv.getsockname()
        stop = {"stop": False}

        def _serve():
            srv.settimeout(0.5)
            while not stop["stop"]:
                try:
                    conn, _ = srv.accept()
                except (socket.timeout, OSError):
                    continue
                try:
                    conn.settimeout(1.5)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk: break
                        data += chunk
                        if len(data) > 8192: break
                    path = data.split(b" ", 2)[1].decode("latin-1", "replace")
                    if path == "/admin/log/access_log":
                        body = _CUPS_ACCESS_LOG.encode()
                        conn.sendall(
                            b"HTTP/1.0 200 OK\r\nContent-Length: "
                            + str(len(body)).encode() + b"\r\n\r\n" + body)
                    else:
                        conn.sendall(
                            b"HTTP/1.0 401 Unauthorized\r\n"
                            b"Content-Length: 0\r\n\r\n")
                except OSError:
                    pass
                finally:
                    try: conn.close()
                    except OSError: pass

        th = threading.Thread(target=_serve, daemon=True)
        th.start()
        try:
            body_ok = cups_lpd.fetch_admin_log(
                host, port, "/admin/log/access_log", timeout=2.0)
            body_bad = cups_lpd.fetch_admin_log(
                host, port, "/admin/conf", timeout=2.0)
        finally:
            stop["stop"] = True
            try: srv.close()
            except OSError: pass
        self.assertIn(b"alice", body_ok)
        self.assertEqual(body_bad, b"")

    def test_dead_port_returns_empty(self):
        body = cups_lpd.fetch_admin_log(
            "127.0.0.1", 1, "/admin/log/access_log", timeout=1.0)
        self.assertEqual(body, b"")


# --- T2 promotion: queue leak + Get-Jobs tier bump --------------------------

class T2TierBumpTest(unittest.TestCase):
    def _mkhost(self, portid, service):
        from recce.core.models import Host, Port
        return Host(ip="10.0.0.5", ports=[Port(
            portid=portid, protocol="tcp", state="open", service=service)])

    def test_lpd_queue_leak_is_t2_when_loot_present(self):
        h = self._mkhost(515, "printer")
        probes = {("10.0.0.5", 515): {
            "reachable": True, "family": "bsd", "version_hint": "",
            "listings": [{"queue": "lp", "op": "long", "text": "",
                          "jobs": [{"owner": "alice"}]}],
            "owners": ["alice"], "hosts": ["ws01"], "filenames": ["Q3.xlsx"],
            "acl_open": True,
        }}
        fs = cups_lpd.findings([h], lpd_probes=probes)
        leak = next(f for f in fs if f["kind"] == "lpd_queue_leak")
        self.assertEqual(leak["depth_tier"], "t2")
        self.assertIn("alice", leak["output"])
        self.assertIn("ws01", leak["output"])
        self.assertIn("Q3.xlsx", leak["output"])

    def test_ipp_get_jobs_is_t2_when_jobs_present(self):
        h = self._mkhost(631, "ipp")
        jobs = {("10.0.0.5", 631): {
            "reachable": True, "jobs": [{"job-id": 42}], "users": ["alice"],
            "hosts": ["ws01.corp.local"],
            "filenames": ["Q3-forecast.xlsx"],
        }}
        fs = cups_lpd.findings([h], jobs_probes=jobs)
        f = next(f for f in fs if f["kind"] == "ipp_get_jobs")
        self.assertEqual(f["depth_tier"], "t2")
        self.assertIn("alice", f["output"])
        self.assertIn("Q3-forecast.xlsx", f["output"])


if __name__ == "__main__":
    unittest.main()
