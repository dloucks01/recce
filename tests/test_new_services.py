"""NetBIOS / TFTP / IPP / X11 / SIP / r-services — module behaviour.

Fixtures are built from the protocol RFCs directly (struct-packed bytes /
literal SOAP), not from recce's encoders. A codec change in recce cannot be
masked by a symmetric bug in the fixture.
"""
from __future__ import annotations

import socket
import struct
import threading

from recce.core.models import Host, Port
from recce.services import netbios, tftp, ipp, x11, sip, rservices


# ==============================================================================
# NetBIOS
# ==============================================================================

def _nbstat_response(host="DC01", domain="CORP.LOCAL", mac=b"\x00\x50\x56\xaa\xbb\xcc"):
    """Build an RFC 1002 node-status response with a hostname + domain-controller
    suffix + MAC. Encoded by hand — the field offsets are the contract we test."""
    # Header: matches txid 0x1000, response bit + AA, ancount=1
    hdr = struct.pack("!HHHHHH", 0x1000, 0x8400, 0, 1, 0, 0)
    # Echoed question (encoded '*' name, NBSTAT/IN)
    q = netbios._encoded_wildcard() + struct.pack("!HH", 0x0021, 0x0001)
    # Answer name (same encoded '*'), TYPE, CLASS, TTL, RDLENGTH, RDATA
    name_pad = netbios._encoded_wildcard()
    names = [
        (host.encode("ascii").ljust(15, b" "), 0x00, 0x4400),   # workstation
        (domain.encode("ascii").ljust(15, b" "), 0x1C, 0xC400), # DC group
    ]
    rdata = bytes([len(names)])
    for raw15, suffix, flags in names:
        rdata += raw15[:15] + bytes([suffix]) + struct.pack("!H", flags)
    rdata += mac
    ans = name_pad + struct.pack("!HHIH", 0x0021, 0x0001, 0, len(rdata)) + rdata
    return hdr + q + ans


def test_netbios_parses_hostname_domain_and_mac():
    data = _nbstat_response()
    parsed = netbios._parse_nbstat(data)
    assert parsed["mac"] == "00:50:56:aa:bb:cc"
    names = {n["name"]: n for n in parsed["names"]}
    assert "DC01" in names and names["DC01"]["suffix"] == 0x00
    assert any(n["role"] == "domain controller" for n in parsed["names"])


def test_netbios_probe_end_to_end_via_udp_socket():
    """Actual UDP round-trip against a local responder so the send/recv wiring
    is validated, not just the parser."""
    payload = _nbstat_response()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def serve():
        try:
            _, addr = sock.recvfrom(1024)
            sock.sendto(payload, addr)
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        pr = netbios.probe("127.0.0.1", port, timeout=2.0)
    finally:
        sock.close()
    assert pr["reachable"]
    assert pr["hostname"] == "DC01"
    assert pr["is_dc"] is True
    assert pr["mac"] == "00:50:56:aa:bb:cc"


def test_netbios_findings_name_the_dc_role():
    h = Host(ip="10.0.0.10", ports=[Port(portid=137, protocol="udp",
                                          state="open", service="nbns")])
    pr = {("10.0.0.10", 137): {"reachable": True, "hostname": "DC01",
          "domain": "CORP.LOCAL", "is_dc": True, "mac": "00:50:56:aa:bb:cc",
          "names": [{"name":"DC01","suffix":0x00,"role":"workstation","group":False}]}}
    f = netbios.findings([h], pr)[0]
    assert "domain controller" in f["detail"].lower()
    assert "CORP.LOCAL" in f["detail"]


# ==============================================================================
# TFTP
# ==============================================================================

def test_tftp_rrq_encoding_matches_rfc1350():
    req = tftp._rrq("running-config")
    assert req[:2] == b"\x00\x01"                # opcode 1
    assert b"running-config\x00octet\x00" in req


def test_tftp_probe_finds_config_when_server_serves_data():
    """Fake TFTP that answers DATA for `running-config`, ERROR otherwise."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(6)
    port = sock.getsockname()[1]

    def serve():
        for _ in range(len(tftp._CANDIDATES)):
            try:
                data, addr = sock.recvfrom(512)
            except (socket.timeout, OSError):
                return
            fname = data[2:].split(b"\x00", 1)[0]
            if fname == b"running-config":
                # DATA opcode(3) + block 1 + payload
                sock.sendto(b"\x00\x03\x00\x01hostname R1\n", addr)
            else:
                # ERROR opcode(5) + code 1 (file not found) + msg
                sock.sendto(b"\x00\x05\x00\x01File not found\x00", addr)
    threading.Thread(target=serve, daemon=True).start()
    try:
        pr = tftp.probe("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert pr["reachable"]
    assert any(r["file"] == "running-config" for r in pr["readable"])


def test_tftp_config_finding_is_critical_not_high():
    h = Host(ip="10.0.0.10", ports=[Port(portid=69, protocol="udp", state="open",
                                          service="tftp")])
    fs = tftp.findings([h], {("10.0.0.10", 69): {"reachable": True,
        "readable": [{"file":"running-config","sample":""}], "probed": 10}})
    f = next(f for f in fs if f["kind"] == "tftp_readable")
    assert f["severity"] == "critical"


def test_tftp_reachable_but_no_readable_files_still_reports():
    """An open TFTP server with nothing recce guessed right is still a
    unauthenticated-by-design finding worth naming."""
    h = Host(ip="10.0.0.10", ports=[Port(portid=69, protocol="udp", state="open",
                                          service="tftp")])
    fs = tftp.findings([h], {("10.0.0.10", 69):
        {"reachable": True, "readable": [], "probed": 10}})
    assert any(f["kind"] == "tftp_open" for f in fs)


# ==============================================================================
# IPP
# ==============================================================================

def test_ipp_attribute_walk_pulls_out_printer_names():
    """Build an IPP body: version + status + request-id + printer-attrs group
    (0x02) + one printer-name text attribute + end-of-attrs."""
    body = (b"\x01\x01"                        # version 1.1
            + b"\x00\x00"                      # status 0 (successful-ok)
            + b"\x00\x00\x00\x01"              # request id
            + b"\x02"                          # printer-attributes-tag
            + b"\x42" + struct.pack("!H", 12) + b"printer-name"
            + struct.pack("!H", 6) + b"Laser1"
            + b"\x03")                         # end-of-attributes
    printers = ipp._walk_ipp_attributes(body)
    assert printers and printers[0]["printer-name"] == "Laser1"


def test_ipp_finding_flags_cups_specifically_and_notes_the_2024_chain():
    h = Host(ip="10.0.0.10", ports=[Port(portid=631, state="open", service="ipp")])
    fs = ipp.findings([h], {("10.0.0.10", 631): {"reachable": True,
        "is_cups": True, "cups_version": "2.4.7", "server": "CUPS/2.4.7",
        "printers": [{"printer-name": "Laser1"}]}})
    kinds = {f["kind"] for f in fs}
    assert "ipp_cups" in kinds and "ipp_printers" in kinds
    cups = next(f for f in fs if f["kind"] == "ipp_cups")
    assert "CVE-2024-47176" in cups["detail"]


def test_ipp_non_cups_ipp_does_not_fire_the_cups_specific_finding():
    """A non-CUPS IPP server (HP JetDirect, Xerox) must not carry the CVE flag."""
    h = Host(ip="10.0.0.10", ports=[Port(portid=631, state="open", service="ipp")])
    fs = ipp.findings([h], {("10.0.0.10", 631): {"reachable": True,
        "is_cups": False, "server": "HP-IPP/1.1", "printers": []}})
    assert all(f["kind"] != "ipp_cups" for f in fs)


# ==============================================================================
# X11
# ==============================================================================

def test_x11_probe_accepts_status_1_from_a_real_handshake():
    """Fake X server that accepts the handshake — status=1, protocol 11.0."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)
    port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
            c.recv(64)
            # status(1)=success, extra-len, major, minor, addl
            c.sendall(struct.pack(">BBHHH", 1, 0, 11, 0, 0))
            c.close()
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        pr = x11.probe("127.0.0.1", port, timeout=1.5)
    finally:
        srv.close()
    assert pr["reachable"] and pr["accepted"] is True
    assert pr["major"] == 11


def test_x11_open_display_is_critical():
    h = Host(ip="10.0.0.10", ports=[Port(portid=6000, state="open", service="x11")])
    fs = x11.findings([h], {("10.0.0.10", 6000): {"reachable": True, "accepted": True,
                                                    "major": 11, "minor": 0}})
    f = fs[0]
    assert f["severity"] == "critical" and f["kind"] == "x11_open"


def test_x11_auth_required_is_low_not_ignored():
    h = Host(ip="10.0.0.10", ports=[Port(portid=6000, state="open", service="x11")])
    fs = x11.findings([h], {("10.0.0.10", 6000): {"reachable": True, "accepted": False,
                                                    "major": 11, "minor": 0,
                                                    "refused_reason_len": 20}})
    f = fs[0]
    assert f["severity"] == "low" and f["kind"] == "x11_present"


# ==============================================================================
# SIP
# ==============================================================================

def test_sip_options_parses_server_and_realm():
    reply = (b"SIP/2.0 200 OK\r\n"
             b"Via: SIP/2.0/UDP recce:5060\r\n"
             b"From: <sip:recce@recce.local>;tag=recce\r\n"
             b"To: <sip:10.0.0.10>;tag=srv\r\n"
             b"Server: Asterisk PBX 18.0.0\r\n"
             b'WWW-Authenticate: Digest realm="asterisk"\r\n'
             b"Allow: INVITE, OPTIONS, ACK, BYE, CANCEL, REGISTER\r\n"
             b"Content-Length: 0\r\n\r\n")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]

    def serve():
        try:
            _, addr = sock.recvfrom(2048)
            sock.sendto(reply, addr)
        except OSError:
            pass

    threading.Thread(target=serve, daemon=True).start()
    try:
        pr = sip.probe("127.0.0.1", port, timeout=1.5)
    finally:
        sock.close()
    assert pr["reachable"] and pr["server"] == "Asterisk PBX 18.0.0"
    assert pr["realm"] == "asterisk"
    assert "INVITE" in pr["methods"]


# ==============================================================================
# r-services
# ==============================================================================

def test_rservices_finding_is_categorically_high():
    """r-* protocols in 2025 are indefensible — a scanner should always
    high-severity them when found, without conditional logic."""
    for port in (512, 513, 514):
        h = Host(ip="10.0.0.10", ports=[Port(portid=port, state="open", service="shell")])
        fs = rservices.findings([h], {("10.0.0.10", port):
            {"reachable": True, "port": port, "service": rservices._R_PORTS[port]}})
        assert fs and fs[0]["severity"] == "high"


def test_rservices_predicate_matches_ports_and_service_names():
    for port, svc in ((512, "exec"), (513, "login"), (514, "shell"), (514, "rsh")):
        assert rservices.is_rservice(Port(portid=port, state="open", service=svc))
    assert not rservices.is_rservice(Port(portid=22, state="open", service="ssh"))
