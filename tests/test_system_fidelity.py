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
import http.server
import os
import socket
import socketserver
import struct
import tempfile
import threading
import unittest

from recce import ad
from recce.services import ldap as L, nfs as N, rsync as R, smb, snmp as S
from recce.services.db import mongodb as M, mssql, redis
from recce.core.models import Host, Port


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
        from recce.report import markdown as report_markdown, excel as report_excel, html as report_html
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


# --- faithful mock network appliance (router/switch) ----------------------------

def _appliance_mib():
    """A Cisco-style switch MIB: system group + an interface table, but no Windows
    LanManager users / process inventory (an appliance, not a server). Values are the
    already-BER-encoded value bytes, built with recce's own encoder."""
    return {
        "1.3.6.1.2.1.1.1.0": S._octet("Cisco IOS Software, C2960X Software "
            "(C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE"),   # sysDescr
        "1.3.6.1.2.1.1.4.0": S._octet("netops@corp.local"),                    # sysContact
        "1.3.6.1.2.1.1.5.0": S._octet("core-sw01"),                            # sysName
        "1.3.6.1.2.1.1.6.0": S._octet("DC1 Rack 12"),                          # sysLocation
        "1.3.6.1.2.1.2.2.1.2.1": S._octet("GigabitEthernet0/1"),               # ifDescr...
        "1.3.6.1.2.1.2.2.1.2.2": S._octet("GigabitEthernet0/2"),
        "1.3.6.1.2.1.2.2.1.2.3": S._octet("Vlan1"),
    }


class _SnmpAgent:
    """A live SNMPv2c UDP agent that answers a single community, using recce's own
    BER/OID encoders. Serves exact GETs and a numeric GETNEXT walk (context manager)."""

    def __init__(self, mib, community="public"):
        self.mib = mib
        self.community = community
        self._sorted = sorted(mib, key=lambda o: [int(x) for x in o.split(".")])
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def __enter__(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._stop = True
        self.sock.close()

    def _get_response(self, community, rid, oid, value_bytes):
        pdu = S._tlv(0xA2, S._int(rid) + S._int(0) + S._int(0)
                     + S._tlv(0x30, S._tlv(0x30, S.encode_oid(oid) + value_bytes)))
        return S._tlv(0x30, S._int(1) + S._octet(community) + pdu)

    def _parse(self, data):
        _, msg, _ = S._parse_tlv(data, 0)
        _, _ver, i = S._parse_tlv(msg, 0)
        _, comm, i = S._parse_tlv(msg, i)
        tag, pdu, _ = S._parse_tlv(msg, i)
        _, rid_b, j = S._parse_tlv(pdu, 0)
        _, _e, j = S._parse_tlv(pdu, j)
        _, _ei, j = S._parse_tlv(pdu, j)
        _, vbs, _ = S._parse_tlv(pdu, j)
        _, vb, _ = S._parse_tlv(vbs, 0)
        _, oid_b, _ = S._parse_tlv(vb, 0)
        return comm.decode(), int.from_bytes(rid_b, "big"), tag, S.decode_oid(oid_b)

    def _serve(self):
        end_of_mib = b"\x82\x00"

        def tup(o):
            return [int(x) for x in o.split(".")]

        while not self._stop:
            try:
                self.sock.settimeout(0.3)
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                comm, rid, tag, oid = self._parse(data)
                if comm != self.community:
                    continue
                if tag == 0xA0:                          # GetRequest (exact)
                    resp = self._get_response(comm, rid, oid,
                                              self.mib.get(oid) or end_of_mib)
                else:                                    # GetNextRequest (walk)
                    nxt = next((k for k in self._sorted if tup(k) > tup(oid)), None)
                    resp = (self._get_response(comm, rid, nxt, self.mib[nxt]) if nxt
                            else self._get_response(comm, rid, oid, end_of_mib))
                self.sock.sendto(resp, addr)
            except (IndexError, ValueError):
                pass


class _HttpMgmt:
    """A minimal live web-management UI (no security headers), for probes.http_findings."""

    def __init__(self):
        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = b"<html><title>core-sw01 login</title></html>"
                self.send_response(200)
                self.send_header("Server", "GoAhead-Webs")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


def _appliance_host(ip="127.0.0.1"):
    """A host modelling a managed switch's open ports (telnet + web UI + SNMP + HTTPS)."""
    return Host(ip=ip, enumerated=True, ports=[
        Port(portid=23, service="telnet", state="open"),
        Port(portid=80, service="http", state="open"),
        Port(portid=161, protocol="udp", service="snmp", state="open"),
        Port(portid=443, service="https", state="open"),
    ])


class NetworkApplianceSystemFidelityTest(unittest.TestCase):
    """A composed network appliance (managed switch): SNMP + a web management UI, run
    through recce's real probes/findings on one host."""

    def test_snmp_appliance_is_enumerated(self):
        from recce.services import probes
        ip = "127.0.0.1"
        with _SnmpAgent(_appliance_mib()) as agent, _HttpMgmt() as web:
            host = _appliance_host(ip)
            snmp_pr = S.probe(ip, agent.port, timeout=1.0, known_open=True)
            snmp_fs = S.findings([host], {(ip, 161): snmp_pr})
            web_fs = probes.http_findings(
                ip, Port(portid=web.port, service="http", state="open"))

        # SNMP: default community, appliance identity, interface table - and NOT the
        # Windows user/process MIBs (this is a switch, not a server).
        self.assertIsNotNone(snmp_pr)
        self.assertEqual(snmp_pr["community"], "public")
        self.assertIn("Cisco", snmp_pr["sys_descr"])
        self.assertEqual(snmp_pr["sys_name"], "core-sw01")
        self.assertIn("GigabitEthernet0/1", snmp_pr["interfaces"])
        self.assertFalse(snmp_pr["users"])
        snmp_titles = " ".join(f["title"].lower() for f in snmp_fs)
        self.assertIn("guessable community", snmp_titles)
        # Web management UI: missing security headers flagged by the live HTTP probe.
        web_titles = " ".join(f.title.lower() for f in web_fs)
        self.assertIn("content-security-policy", web_titles)

    def test_appliance_findings_reach_the_report(self):
        from recce.report import html as report_html
        ip = "127.0.0.1"
        with _SnmpAgent(_appliance_mib()) as agent:
            host = _appliance_host(ip)
            pr = S.probe(ip, agent.port, timeout=1.0, known_open=True)
            host.vulns.extend(
                S.findings_to_vulns(S.findings([host], {(ip, 161): pr})).get(ip, []))

        self.assertTrue(host.vulns, "no vulns folded from the SNMP enumeration")
        with tempfile.TemporaryDirectory() as d:
            html_path = os.path.join(d, "report.html")
            report_html.build_html([host], html_path, title="Appliance")
            html = open(html_path).read().lower()
        self.assertIn("community", html)                 # the SNMP finding rendered


# --- faithful mock database server ----------------------------------------------

def _tds_prelogin_response(major=15, minor=0, build=2000, encrypt=0):
    """A TDS PRELOGIN response (SQL Server 2019, login encryption OFF) - a 0x04
    packet with VERSION + ENCRYPTION options, mirroring recce's own request format."""
    options = [(0x00, 6), (0x01, 1)]                     # VERSION, ENCRYPTION
    values = {0x00: bytes([major, minor]) + struct.pack(">H", build) + b"\x00\x00",
              0x01: bytes([encrypt])}
    offset = 5 * len(options) + 1
    table = b""
    data = b""
    for tok, ln in options:
        table += struct.pack(">BHH", tok, offset, ln)
        data += values[tok]
        offset += ln
    payload = table + b"\xff" + data
    return struct.pack(">BBHHBB", 0x04, 0x01, 8 + len(payload), 0, 0, 0) + payload


def _mssql_handler(sock):
    sock.recv(4096)                                      # the PRELOGIN request
    sock.sendall(_tds_prelogin_response())


def _resp_read_command(sock):
    """Read one RESP array-of-bulk-strings command; return list[str] or None."""
    buf = b""

    def line():
        nonlocal buf
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("closed")
            buf += chunk
        ln, _, rest = buf.partition(b"\r\n")
        buf = rest
        return ln

    try:
        first = line()
        if not first.startswith(b"*"):
            return None
        args = []
        for _ in range(int(first[1:])):
            length = int(line()[1:])
            while len(buf) < length + 2:
                chunk = sock.recv(4096)
                if not chunk:
                    raise OSError("closed")
                buf += chunk
            args.append(buf[:length].decode())
            buf = buf[length + 2:]
        return args
    except (OSError, ValueError):
        return None


_REDIS_INFO = ("# Server\r\nredis_version:7.0.11\r\nos:Linux\r\nredis_mode:standalone\r\n"
               "# Replication\r\nrole:master\r\n# Keyspace\r\ndb0:keys=12,expires=0\r\n")


def _redis_handler(sock):
    while True:
        cmd = _resp_read_command(sock)
        if not cmd:
            return
        name = cmd[0].upper()
        if name == "PING":
            sock.sendall(b"+PONG\r\n")
        elif name == "INFO":
            body = _REDIS_INFO.encode()
            sock.sendall(b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
        elif name == "CONFIG" and len(cmd) >= 3:
            val = {"dir": "/var/lib/redis", "dbfilename": "dump.rdb",
                   "requirepass": "", "protected-mode": "no"}.get(cmd[2], "")
            v = val.encode()
            sock.sendall(b"*2\r\n$" + str(len(cmd[2])).encode() + b"\r\n" + cmd[2].encode()
                         + b"\r\n$" + str(len(v)).encode() + b"\r\n" + v + b"\r\n")
        else:
            sock.sendall(b"+OK\r\n")


def _mongo_handler(sock):
    """A real MongoDB wire server answering hello / buildInfo / listDatabases WITHOUT
    auth, built with recce's own BSON/OP_MSG encoders -> a CONFIRMED unauth exposure."""
    def e_double(name, v):
        return b"\x01" + M._cstr(name) + struct.pack("<d", v)

    def e_bool(name, v):
        return b"\x08" + M._cstr(name) + bytes([1 if v else 0])

    def e_doc(name, doc):
        return b"\x03" + M._cstr(name) + doc

    def e_array(name, docs):
        inner = M.bson_doc(*[e_doc(str(i), d) for i, d in enumerate(docs)])
        return b"\x04" + M._cstr(name) + inner

    hello = M.bson_doc(e_bool("isWritablePrimary", True),
                       M._e_int32("maxWireVersion", 17), e_double("ok", 1.0))
    build = M.bson_doc(M._e_str("version", "6.0.1"), e_double("ok", 1.0))
    dbs = e_array("databases", [
        M.bson_doc(M._e_str("name", "admin"), e_double("sizeOnDisk", 4096.0)),
        M.bson_doc(M._e_str("name", "customers"), e_double("sizeOnDisk", 99990.0))])
    listdbs = M.bson_doc(dbs, e_double("totalSize", 104086.0), e_double("ok", 1.0))
    replies = {"hello": hello, "isMaster": hello, "ismaster": hello,
               "buildInfo": build, "listDatabases": listdbs}
    while True:
        hdr = M._recvn(sock, 16)
        if len(hdr) < 16:
            return
        length, rid = struct.unpack("<i", hdr[:4])[0], struct.unpack("<i", hdr[4:8])[0]
        body = M._recvn(sock, length - 16)
        try:
            doc, _ = M.bson_parse(hdr + body, 16 + 4 + 1)
        except (IndexError, ValueError, struct.error):
            return
        cmd = next(iter(doc), "")
        reply = replies.get(cmd) or M.bson_doc(
            M._e_str("errmsg", "no such command"), e_double("ok", 0.0))
        sock.sendall(M.op_msg(rid, reply))


class DatabaseServerSystemFidelityTest(unittest.TestCase):
    """A composed database server exposing several unauthenticated data stores -
    MSSQL (TDS), MongoDB (wire) and Redis (RESP) - enumerated on one host."""

    def test_exposed_database_server_is_enumerated(self):
        ip = "127.0.0.1"
        with _MockServer(_mssql_handler) as mssql_srv, \
                _MockServer(_mongo_handler) as mongo_srv, \
                _MockServer(_redis_handler) as redis_srv:
            host = Host(ip=ip, enumerated=True, ports=[
                Port(portid=1433, service="ms-sql-s", state="open"),
                Port(portid=6379, service="redis", state="open"),
                Port(portid=27017, service="mongodb", state="open"),
            ])
            mssql_pr = mssql.probe_target(ip, mssql_srv.port, active=True)
            mongo_pr = M.probe(ip, mongo_srv.port)
            redis_pr = redis.probe(ip, redis_srv.port)
            mssql_fs = mssql.findings([host], {(ip, 1433): mssql_pr})
            mongo_fs = M.findings([host], {(ip, 27017): mongo_pr})
            redis_fs = redis.findings([host], {(ip, 6379): redis_pr})

        # MSSQL: TDS pre-login read - SQL Server 2019, login encryption not enforced.
        self.assertEqual(mssql_pr["prelogin"]["version"], "15.0.2000")
        self.assertIn("off", mssql_pr["prelogin"]["encryption"])
        # MongoDB: unauthenticated - version + database names recovered.
        self.assertIsNotNone(mongo_pr)
        self.assertTrue(mongo_pr["unauth"])
        self.assertEqual(mongo_pr["version"], "6.0.1")
        self.assertIn("customers", [db["name"] for db in mongo_pr["databases"]])
        # Redis: unauthenticated - version + role fingerprinted.
        self.assertTrue(redis_pr["unauth"])
        self.assertEqual(redis_pr["version"], "7.0.11")
        # Every data store produced findings on the one host.
        self.assertTrue(mongo_fs, "MongoDB not enumerated on the DB server")
        self.assertTrue(redis_fs, "Redis not enumerated on the DB server")
        mongo_titles = " ".join(f["title"].lower() for f in mongo_fs)
        self.assertIn("without authentication", mongo_titles)

    def test_database_findings_reach_the_report(self):
        from recce.report import html as report_html
        ip = "127.0.0.1"
        with _MockServer(_mongo_handler) as mongo_srv, \
                _MockServer(_redis_handler) as redis_srv:
            host = Host(ip=ip, enumerated=True, ports=[
                Port(portid=6379, service="redis", state="open"),
                Port(portid=27017, service="mongodb", state="open")])
            for by_ip in (M.findings_to_vulns(M.findings(
                              [host], {(ip, 27017): M.probe(ip, mongo_srv.port)})),
                          redis.findings_to_vulns(redis.findings(
                              [host], {(ip, 6379): redis.probe(ip, redis_srv.port)}))):
                host.vulns.extend(by_ip.get(ip, []))

        self.assertTrue(host.vulns, "no vulns folded from the DB enumeration")
        with tempfile.TemporaryDirectory() as d:
            html_path = os.path.join(d, "report.html")
            report_html.build_html([host], html_path, title="DB Server")
            html = open(html_path).read().lower()
        self.assertIn("mongodb", html)                   # the MongoDB finding rendered


# --- faithful mock Linux file/print server (NFS + rsync + Samba) ----------------

def _nfs_handler(sock):
    """A mock ONC RPC server: portmapper DUMP (mountd on THIS port + nfsd) and mountd
    EXPORT with a world-mountable ('*') share - built with recce's own RPC helpers.
    An accepted socket's local port is the server's own port, so mountd advertises
    itself and the probe's follow-up mountd connection lands back here."""
    def xstr(x):
        b = x.encode()
        return struct.pack(">I", len(b)) + b + b"\x00" * ((4 - len(b) % 4) % 4)

    def reply(xid, results):
        body = (struct.pack(">III", xid, 1, 0) + struct.pack(">II", 0, 0)
                + struct.pack(">I", 0) + results)
        return struct.pack(">I", 0x80000000 | len(body)) + body

    sock.settimeout(3.0)
    myport = sock.getsockname()[1]
    while True:
        rec = N._recv_record(sock, 3.0)
        if rec is None:
            return
        xid, _mt, _rv, prog, _ve, proc = struct.unpack_from(">IIIIII", rec, 0)
        if prog == N._PMAP_PROG and proc == 4:               # portmap DUMP
            res = b""
            for pr, ve, po in ((N._MOUNT_PROG, 3, myport), (N._NFS_PROG, 3, 2049)):
                res += struct.pack(">IIIII", 1, pr, ve, N._IPPROTO_TCP, po)
            sock.sendall(reply(xid, res + struct.pack(">I", 0)))
        elif prog == N._MOUNT_PROG and proc == 5:            # mountd EXPORT
            res = (struct.pack(">I", 1) + xstr("/srv/backups")   # world-mountable ('*')
                   + struct.pack(">I", 1) + xstr("*") + struct.pack(">I", 0)
                   + struct.pack(">I", 1) + xstr("/home")        # host-restricted
                   + struct.pack(">I", 1) + xstr("10.0.0.0/24") + struct.pack(">I", 0)
                   + struct.pack(">I", 0))
            sock.sendall(reply(xid, res))
        else:
            sock.sendall(reply(xid, b""))


def _rsync_handler(sock):
    """A mock rsync daemon: @RSYNCD greeting, #list of modules, and per-module
    OK (anonymous) / AUTHREQD - anonymous access on two modules."""
    sock.settimeout(3.0)
    sock.sendall(b"@RSYNCD: 31.0\n")
    buf = b""
    while buf.count(b"\n") < 2:
        try:
            c = sock.recv(256)
        except OSError:
            return
        if not c:
            return
        buf += c
    req = buf.decode().split("\n")[1]
    if req == "#list":
        sock.sendall(b"backups\tnightly server backups\npublic\tanonymous share\n"
                     b"secret\trestricted\n@RSYNCD: EXIT\n")
    elif req == "secret":
        sock.sendall(b"@RSYNCD: AUTHREQD abcdef\n")
    else:                                                    # backups / public: anon OK
        sock.sendall(b"@RSYNCD: OK\n")


class LinuxFileServerSystemFidelityTest(unittest.TestCase):
    """A composed Linux file/print server exposing NFS, rsync and Samba (SMB), each
    driven by recce's real probes/findings on one host."""

    def test_file_server_shares_are_enumerated(self):
        ip = "127.0.0.1"
        with _MockServer(_nfs_handler) as nfs_srv, \
                _MockServer(_rsync_handler) as rsync_srv, \
                _MockServer(_smb_dc_handler) as smb_srv:
            host = Host(ip=ip, os_family="Linux", enumerated=True, ports=[
                Port(portid=111, service="rpcbind", state="open"),
                Port(portid=139, service="netbios-ssn", state="open"),
                Port(portid=445, service="microsoft-ds", state="open"),
                Port(portid=873, service="rsync", state="open"),
                Port(portid=2049, service="nfs", state="open"),
            ])
            nfs_pr = N.probe(ip, pmport=nfs_srv.port, timeout=3.0)
            smb_pr = smb.probe(ip, smb_srv.port)
            nfs_fs = N.findings([host], {ip: nfs_pr})
            smb_fs = smb.findings([host], {(ip, 445): smb_pr})
            # rsync analyze probes the module list + per-module access against the daemon.
            rhost = Host(ip=ip, ports=[Port(portid=rsync_srv.port, service="rsync",
                                            state="open")])
            rsync_an = R.analyze([rhost], active=True)

        # NFS: world-mountable export enumerated over portmapper + mountd.
        self.assertTrue(nfs_pr["reachable"])
        self.assertTrue(nfs_pr["nfs"])
        self.assertIn("/srv/backups", [e["dir"] for e in nfs_pr["exports"]])
        self.assertIn("world-mountable", " ".join(f["title"].lower() for f in nfs_fs))
        # rsync: modules enumerated + an anonymous-readable module flagged.
        self.assertGreaterEqual(rsync_an["targets"][0].get("modules", 0), 3)
        rsync_titles = " ".join(f["title"].lower() for f in rsync_an["findings"])
        self.assertIn("without authentication", rsync_titles)
        # Samba/SMB: signing not required (relay surface).
        self.assertIsNotNone(smb_pr)
        self.assertIn("signing not required",
                      " ".join(f["title"].lower() for f in smb_fs))

    def test_file_server_findings_reach_the_report(self):
        from recce.report import html as report_html
        ip = "127.0.0.1"
        with _MockServer(_nfs_handler) as nfs_srv, \
                _MockServer(_rsync_handler) as rsync_srv:
            host = Host(ip=ip, os_family="Linux", enumerated=True, ports=[
                Port(portid=873, service="rsync", state="open"),
                Port(portid=2049, service="nfs", state="open")])
            nfs_pr = N.probe(ip, pmport=nfs_srv.port, timeout=3.0)
            host.vulns.extend(N.findings_to_vulns(N.findings([host], {ip: nfs_pr})).get(ip, []))
            rhost = Host(ip=ip, ports=[Port(portid=rsync_srv.port, service="rsync",
                                            state="open")])
            rsync_fs = R.analyze([rhost], active=True)["findings"]
            host.vulns.extend(R.findings_to_vulns(rsync_fs).get(ip, []))

        self.assertTrue(host.vulns, "no vulns folded from the file-server enumeration")
        with tempfile.TemporaryDirectory() as d:
            html_path = os.path.join(d, "report.html")
            report_html.build_html([host], html_path, title="File Server")
            html = open(html_path).read().lower()
        self.assertIn("nfs", html)
        self.assertIn("rsync", html)


if __name__ == "__main__":
    unittest.main()
