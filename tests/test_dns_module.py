"""DNS deep module: zone-transfer (AXFR) detection over the real DNS-over-TCP wire,
validated against a fake DNS server that returns a crafted response header."""
from __future__ import annotations

import socketserver
import struct
import threading

from recce.services import dns
from recce.core.models import Host, Port


def _serve(ancount: int, rcode: int):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request.recv(4096)              # 2-byte len + query
            if not data:
                return
            flags = 0x8000 | (rcode & 0x0F)             # QR=1 + rcode
            hdr = struct.pack("!HHHHHH", 0x1337, flags, 1, ancount, 0, 0)
            body = hdr + b"\x00" * (ancount * 4)         # filler "records"
            self.request.sendall(struct.pack("!H", len(body)) + body)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], srv


def test_axfr_allowed_is_detected():
    port, srv = _serve(ancount=42, rcode=0)             # NOERROR + answers -> leaked
    try:
        r = dns.axfr("127.0.0.1", port, "contoso.local", timeout=3)
    finally:
        srv.shutdown()
    assert r["ok"] is True
    assert r["records"] == 42
    assert r["rcode"] == 0


def test_axfr_refused_is_not_a_finding():
    port, srv = _serve(ancount=0, rcode=5)              # REFUSED
    try:
        r = dns.axfr("127.0.0.1", port, "contoso.local", timeout=3)
    finally:
        srv.shutdown()
    assert r["ok"] is False
    assert r["rcode"] == 5


def test_zones_derived_only_from_known_hostnames():
    hosts = [Host(ip="10.0.0.1", hostnames=["dc01.contoso.local"]),
             Host(ip="10.0.0.2", hostnames=["mail.corp.example.com"]),
             Host(ip="10.0.0.3", hostnames=["singlelabel"])]     # no domain -> ignored
    assert dns._zones_from_hosts(hosts) == ["contoso.local", "corp.example.com"]


def test_findings_from_probe():
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {"axfr_zones": ["contoso.local"],
                                 "records": {"contoso.local": 128}, "version": ""}}
    fs = dns.findings([h], probes)
    assert fs and fs[0]["severity"] == "high" and "zone transfer" in fs[0]["title"].lower()
    assert "128 records" in fs[0]["detail"]
    assert dns.findings_to_vulns(fs)["10.0.0.9"][0].source == "dns"


def test_is_dns_respects_open_state():
    assert dns.is_dns(Port(portid=53, service="domain", state="open"))
    assert not dns.is_dns(Port(portid=53, service="domain", state="closed"))
    assert not dns.is_dns(Port(portid=80, service="http", state="open"))
