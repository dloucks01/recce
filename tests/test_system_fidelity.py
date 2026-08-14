"""High-fidelity 'system type' scenarios: several protocols composed on one host, run
through the WHOLE pipeline, not one protocol at a time.

Windows/AD domain controller: a faithful mock DC - a live LDAP RootDSE responder (built
with recce's own BER encoders) and a live SMB2 responder - is driven by recce's REAL
ldap/smb probes; then the real findings, AD role identification, and report generation
run against a host modelling the DC's standard ports. Asserts the whole AD picture
assembles: identified as Domain Controller + Global Catalog, domain read from RootDSE,
and both LDAP and SMB findings reach the rendered report.

No nmap and no real AD needed - the protocol exchanges are real (recce's own wire
encoders build the DC's replies), only the port topology is modelled.
"""
import os
import socketserver
import struct
import tempfile
import threading
import unittest

from recce import ad, ldap as L, smb
from recce.models import Host, Port


# --- faithful mock domain controller --------------------------------------------

def _ldap_dc_reply_script():
    """The per-request LDAP reply sequence a DC gives recce's probe: bind OK, a
    RootDSE searchResEntry (AD-DC markers), then the base naming-context object.
    Built with recce's own BER encoders so it is real wire data."""
    def tlv(tag, val):
        return bytes([tag]) + L._ber_len(len(val)) + val

    def attr(name, vals):
        return tlv(0x30, L._octet(name)
                   + tlv(0x31, b"".join(L._octet(v) for v in vals)))

    def msg(mid, op):
        return tlv(0x30, L._int(mid) + op)

    bind_ok = msg(1, tlv(0x61, L._enum(0) + L._octet("") + L._octet("")))
    rootdse = msg(2, tlv(0x64, L._octet("") + tlv(0x30,
        attr("defaultNamingContext", ["DC=corp,DC=local"])
        + attr("dnsHostName", ["dc01.corp.local"])
        + attr("domainControllerFunctionality", ["7"])   # AD-DC-specific marker
        + attr("forestFunctionality", ["7"])
        + attr("domainFunctionality", ["7"])
        + attr("isGlobalCatalogReady", ["TRUE"])
        + attr("supportedSASLMechanisms", ["GSSAPI", "GSS-SPNEGO"]))))
    done2 = msg(2, tlv(0x65, L._enum(0) + L._octet("") + L._octet("")))
    ncobj = msg(3, tlv(0x64, L._octet("DC=corp,DC=local") + tlv(0x30,
        attr("objectClass", ["top", "domain"])
        + attr("ms-DS-MachineAccountQuota", ["10"]))))
    done3 = msg(3, tlv(0x65, L._enum(0) + L._octet("") + L._octet("")))
    return [bind_ok, rootdse + done2, ncobj + done3]


def _smb2_negotiate_response():
    """SMB 3.1.1 negotiate response with signing ENABLED but NOT required (the NTLM
    relay surface) - built from recce's own SMB2 header helper."""
    hdr = smb._smb2_header(0x0000, flags=0x00000001)
    body = (struct.pack("<H", 65) + struct.pack("<H", 0x01)      # signing enabled only
            + struct.pack("<H", 0x0311) + struct.pack("<H", 0) + b"\x11" * 16
            + struct.pack("<I", 7) + struct.pack("<I", 0x800000) * 3)
    return hdr + body


def _read_framed(sock):
    """Read one length-prefixed (NetBIOS/SMB framed) message."""
    head = sock.recv(4)
    if len(head) < 4:
        return None
    n = struct.unpack(">I", head)[0] & 0x00FFFFFF
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(4096, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return head + buf


class _MockServer:
    """A threaded TCP responder on an ephemeral 127.0.0.1 port (context manager)."""

    def __init__(self, handler_fn):
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    outer.fn(self.request)
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.fn = handler_fn
        self.srv = Server(("127.0.0.1", 0), Handler)
        self.port = self.srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


def _ldap_dc_handler(sock):
    for resp in _ldap_dc_reply_script():
        if L._read_message(sock, 5.0) is None:
            return
        sock.sendall(resp)


def _smb_dc_handler(sock):
    data = _read_framed(sock)
    if not data:
        return
    if data[4:8] == b"\xfeSMB":                  # SMB2 negotiate -> 3.1.1, signing off
        reply = _smb2_negotiate_response()
    else:                                        # SMB1 negotiate -> answer SMB2 = v1 off
        reply = b"\xfeSMB" + b"\x00" * 4
    sock.sendall(struct.pack(">I", len(reply)) + reply)


def _dc_host(ip="127.0.0.1"):
    """A host modelling a domain controller's standard open ports (as a scan finds them)."""
    ports = [("kerberos", 88), ("msrpc", 135), ("netbios-ssn", 139), ("ldap", 389),
             ("microsoft-ds", 445), ("ldaps", 636), ("globalcat", 3268)]
    return Host(ip=ip, os_family="Windows", enumerated=True,
                ports=[Port(portid=n, service=s, state="open") for s, n in ports])


class WindowsADSystemFidelityTest(unittest.TestCase):
    """A composed Windows/AD DC, enumerated end to end through recce's real logic."""

    def test_mock_dc_is_fully_enumerated(self):
        ip = "127.0.0.1"
        with _MockServer(_ldap_dc_handler) as ldap_srv, \
                _MockServer(_smb_dc_handler) as smb_srv:
            host = _dc_host(ip)
            ldap_pr = L.probe(ip, ldap_srv.port)          # real LDAP exchange
            smb_pr = smb.probe(ip, smb_srv.port)          # real SMB2 exchange
            ldap_fs = L.findings([host], {(ip, 389): ldap_pr})
            smb_fs = smb.findings([host], {(ip, 445): smb_pr})
            ad.identify_roles(host)
            ad.parse_signing_and_ntlm(host)

        # 1. LDAP RootDSE read: it IS a DC; domain, DNS name and GC status recovered.
        self.assertIsNotNone(ldap_pr)
        self.assertTrue(ldap_pr["anon_bind"])
        self.assertTrue(ldap_pr["anon_read"])
        self.assertEqual(ldap_pr["domain"], "corp.local")
        self.assertEqual(ldap_pr["dc_dns"], "dc01.corp.local")
        self.assertTrue(ldap_pr["is_gc"])
        # 2. SMB posture: SMB 3.1.1, signing not required, SMBv1 off.
        self.assertIsNotNone(smb_pr)
        self.assertEqual(smb_pr["dialect_name"], "SMB 3.1.1")
        self.assertFalse(smb_pr["signing_required"])
        self.assertFalse(smb_pr["smbv1"])
        # 3. Role identification pulls the ports together into the AD picture.
        self.assertIn("Domain Controller", host.roles)
        self.assertIn("Global Catalog", host.roles)
        self.assertIn("SMB server", host.roles)
        # 4. Findings from BOTH protocols on the one host.
        ldap_titles = " ".join(f["title"].lower() for f in ldap_fs)
        smb_titles = " ".join(f["title"].lower() for f in smb_fs)
        self.assertIn("anonymous", ldap_titles)          # anon read / bind
        self.assertIn("cleartext", ldap_titles)          # LDAP on 389 without TLS
        self.assertIn("signing not required", smb_titles)

    def test_mock_dc_findings_reach_the_report(self):
        # End-to-end: the enumerated DC + BOTH protocols' findings render into reports.
        from recce import report_markdown, report_excel, report_html
        ip = "127.0.0.1"
        with _MockServer(_ldap_dc_handler) as ldap_srv, \
                _MockServer(_smb_dc_handler) as smb_srv:
            host = _dc_host(ip)
            ldap_pr = L.probe(ip, ldap_srv.port)
            smb_pr = smb.probe(ip, smb_srv.port)
            # Fold both protocols' findings into the host's vulns (as the pipeline does).
            for by_ip in (L.findings_to_vulns(L.findings([host], {(ip, 389): ldap_pr})),
                          smb.findings_to_vulns(smb.findings([host], {(ip, 445): smb_pr}))):
                host.vulns.extend(by_ip.get(ip, []))
            ad.identify_roles(host)

        # Both protocols' findings are on the host.
        vuln_titles = " ".join(v.title.lower() for v in host.vulns)
        self.assertTrue(host.vulns, "no vulns folded from the DC enumeration")
        self.assertIn("anonymous", vuln_titles)          # LDAP finding
        self.assertIn("signing not required", vuln_titles)   # SMB finding

        with tempfile.TemporaryDirectory() as d:
            md_path = os.path.join(d, "report.md")
            report_markdown.build_markdown([host], md_path, title="AD Engagement")
            md = open(md_path).read()
            xlsx = os.path.join(d, "report.xlsx")
            report_excel.build_workbook([host], xlsx)
            xlsx_size = os.path.getsize(xlsx)
            html_path = os.path.join(d, "report.html")
            report_html.build_html([host], html_path, title="AD Engagement")
            html = open(html_path).read()

        self.assertGreater(xlsx_size, 0)                 # the workbook rendered
        self.assertIn(ip, md)                            # the DC is in the report
        self.assertIn("ldap", md.lower())
        # The HTML findings table carries EVERY finding, incl. the medium SMB one.
        low = html.lower()
        self.assertIn("signing not required", low)
        self.assertIn("anonymous ldap", low)


if __name__ == "__main__":
    unittest.main()
