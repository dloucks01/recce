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


# --------------------------------------------------------------------------- #
# Wire-format helpers for the AXFR-body-parse and SRV/MX/NS tests.
# All fixtures are hand-built to RFC 1035 §3.2 (RR wire format) / §4 (msg format)
# / RFC 2782 (SRV) — no external DNS library involved.
# --------------------------------------------------------------------------- #
def _enc_name(name: str) -> bytes:
    out = b""
    for lb in name.strip(".").split("."):
        out += bytes([len(lb)]) + lb.encode()
    return out + b"\x00"


def _rr(name: str, rtype: int, rdata: bytes, ttl: int = 60) -> bytes:
    # RFC 1035 §3.2.1: NAME | TYPE(2) | CLASS(2) | TTL(4) | RDLENGTH(2) | RDATA
    return _enc_name(name) + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata


def _msg(qname: str, qtype: int, answers: list[bytes]) -> bytes:
    # QR=1, AA=1, RCODE=NOERROR.
    hdr = struct.pack("!HHHHHH", 0x1337, 0x8400, 1, len(answers), 0, 0)
    q = _enc_name(qname) + struct.pack("!HH", qtype, 1)
    return hdr + q + b"".join(answers)


def _serve_bytes(response: bytes):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            _ = self.request.recv(4096)
            self.request.sendall(struct.pack("!H", len(response)) + response)
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], srv


def test_axfr_body_parse_extracts_a_mx_cname():
    a_rd = bytes([10, 0, 0, 5])                            # 10.0.0.5
    mx_rd = struct.pack("!H", 10) + _enc_name("mail.contoso.local")
    cn_rd = _enc_name("real.contoso.local")
    resp = _msg("contoso.local", dns._QTYPE_AXFR, [
        _rr("dc01.contoso.local", dns._QTYPE_A, a_rd),
        _rr("contoso.local", dns._QTYPE_MX, mx_rd),
        _rr("www.contoso.local", dns._QTYPE_CNAME, cn_rd),
    ])
    port, srv = _serve_bytes(resp)
    try:
        r = dns.axfr("127.0.0.1", port, "contoso.local", timeout=3)
    finally:
        srv.shutdown()
    assert r["ok"] is True and r["records"] == 3
    data = r["data"]
    assert ("dc01.contoso.local", "10.0.0.5") in data["a"]
    assert ("contoso.local", 10, "mail.contoso.local") in data["mx"]
    assert ("www.contoso.local", "real.contoso.local") in data["cname"]
    # Names bucket is deduped & lowercased, in insertion order.
    assert data["names"][0] == "dc01.contoso.local"
    assert "contoso.local" in data["names"]


def test_axfr_body_parse_handles_aaaa_and_ns_and_ptr():
    v6 = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"      # 2001:db8::1
    resp = _msg("contoso.local", dns._QTYPE_AXFR, [
        _rr("ns1.contoso.local", dns._QTYPE_AAAA, v6),
        _rr("contoso.local", dns._QTYPE_NS_, _enc_name("ns1.contoso.local")),
        _rr("5.0.0.10.in-addr.arpa", dns._QTYPE_PTR, _enc_name("dc01.contoso.local")),
    ])
    port, srv = _serve_bytes(resp)
    try:
        r = dns.axfr("127.0.0.1", port, "contoso.local", timeout=3)
    finally:
        srv.shutdown()
    data = r["data"]
    assert ("ns1.contoso.local", "2001:db8::1") in data["aaaa"]
    assert ("contoso.local", "ns1.contoso.local") in data["ns"]
    assert ("5.0.0.10.in-addr.arpa", "dc01.contoso.local") in data["ptr"]


def test_srv_mx_ns_extracts_ad_anchors():
    """RFC 2782 SRV rdata: PRIORITY(2) | WEIGHT(2) | PORT(2) | TARGET.
    Serve a canned SRV answer for every _rr_query call — same body works for
    every question because we ignore qname on this fake server."""
    # SRV rdata: pri=10 wt=100 port=389 target=dc01.contoso.local
    srv_rd = struct.pack("!HHH", 10, 100, 389) + _enc_name("dc01.contoso.local")
    srv_resp = _msg("_ldap._tcp.contoso.local", dns._QTYPE_SRV,
                    [_rr("_ldap._tcp.contoso.local", dns._QTYPE_SRV, srv_rd)])
    port, srv = _serve_bytes(srv_resp)
    try:
        got = dns._rr_query("127.0.0.1", port, "_ldap._tcp.contoso.local",
                            dns._QTYPE_SRV, timeout=3)
    finally:
        srv.shutdown()
    assert len(got) == 1
    assert got[0]["type"] == dns._QTYPE_SRV
    assert got[0]["value"] == (10, 100, 389, "dc01.contoso.local")


def test_ad_anchor_finding_from_probe():
    """When both _ldap._tcp and _kerberos._tcp resolve under a zone, an info
    finding fires naming the zone as AD-integrated."""
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": [], "records": {}, "version": "",
        "service_records": {
            "contoso.local": {
                "srv": {
                    "_ldap._tcp": [(10, 100, 389, "dc01.contoso.local")],
                    "_kerberos._tcp": [(10, 100, 88, "dc01.contoso.local")],
                },
                "mx": [], "ns": [],
            },
        },
    }}
    fs = dns.findings([h], probes)
    ad = [f for f in fs if f.get("kind") == "dns_ad_srv"]
    assert ad and ad[0]["severity"] == "info"
    assert "contoso.local" in ad[0]["title"]
    assert "dc01.contoso.local" in ad[0]["detail"]


def test_axfr_finding_includes_sample_names_when_parsed():
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": ["contoso.local"],
        "records": {"contoso.local": 3},
        "version": "",
        "axfr_data": {"contoso.local": {"names": ["dc01.contoso.local",
                                                  "mail.contoso.local",
                                                  "www.contoso.local"]}},
    }}
    fs = dns.findings([h], probes)
    axfr_f = [f for f in fs if f.get("kind") == "dns_axfr"]
    assert axfr_f and "Sample leaked names" in axfr_f[0]["detail"]
    assert "dc01.contoso.local" in axfr_f[0]["detail"]


def test_parse_rrs_short_buffer_does_not_raise():
    """RR walk stops cleanly when RDLENGTH overshoots the buffer — the module's
    read-only best-effort posture requires it never raise on malformed wire."""
    # Header claims 5 answers, but body is one truncated A record.
    bogus = struct.pack("!HHHHHH", 0, 0x8400, 0, 5, 0, 0) + b"\x00\x00\x01\x00\x01"
    rrs, _ = dns._parse_rrs(bogus, 12, 5)
    assert rrs == []


# --------------------------------------------------------------------------- #
# T2 promotion: dns_axfr
# AXFR is itself the safe read-only proof-of-exploit. When it succeeds AND
# recce parsed real A/AAAA records out of the answer, the finding upgrades
# to depth_tier=t2 with a pivot list captured in `output`. When the AXFR
# probe returned no parseable records, the finding stays at t1.
# --------------------------------------------------------------------------- #
def test_axfr_finding_upgrades_to_t2_when_a_records_parsed():
    """AXFR body carried real A records → finding is depth_tier=t2 and
    pivot list is stapled to `output` and summarized in `detail`."""
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": ["contoso.local"],
        "records": {"contoso.local": 3},
        "version": "",
        "axfr_data": {"contoso.local": {
            "names": ["dc01.contoso.local", "mail.contoso.local"],
            "a": [("dc01.contoso.local", "10.0.0.5"),
                  ("mail.contoso.local", "10.0.0.6"),
                  ("dc01.contoso.local", "10.0.0.5")],   # dup collapses
            "aaaa": [("ns1.contoso.local", "2001:db8::1")],
            "cname": [], "ns": [], "ptr": [], "mx": [], "srv": [],
        }},
    }}
    fs = dns.findings([h], probes)
    axfr_f = [f for f in fs if f.get("kind") == "dns_axfr"]
    assert axfr_f, "AXFR finding must fire"
    f = axfr_f[0]
    assert f["depth_tier"] == "t2"
    # Pivot list captured in the finding's evidence field.
    assert "dc01.contoso.local\t10.0.0.5" in f["output"]
    assert "mail.contoso.local\t10.0.0.6" in f["output"]
    assert "ns1.contoso.local\t2001:db8::1" in f["output"]
    # Dedup — the duplicate (dc01, 10.0.0.5) appears exactly once.
    assert f["output"].count("dc01.contoso.local\t10.0.0.5") == 1
    # Human-readable pivot summary folded into detail.
    assert "Pivot targets" in f["detail"]
    assert "dc01.contoso.local=10.0.0.5" in f["detail"]


def test_axfr_finding_stays_t1_when_no_ip_records_parsed():
    """AXFR succeeded (header ok) but the parsed body carried names only /
    no A or AAAA — no pivot proof, stays at t1."""
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": ["contoso.local"],
        "records": {"contoso.local": 1},
        "version": "",
        "axfr_data": {"contoso.local": {
            "names": ["dc01.contoso.local"],
            "a": [], "aaaa": [], "cname": [], "ns": [],
            "ptr": [], "mx": [], "srv": [],
        }},
    }}
    fs = dns.findings([h], probes)
    axfr_f = [f for f in fs if f.get("kind") == "dns_axfr"]
    assert axfr_f and axfr_f[0]["depth_tier"] == "t1"
    # Still no pivot output when nothing pivotable was captured.
    assert "output" not in axfr_f[0] or not axfr_f[0]["output"]


def test_axfr_pivot_targets_dedup_and_order():
    """Helper: A records come first, AAAA appended after; duplicates collapse."""
    data = {
        "a": [("A.example.", "10.0.0.1"), ("b.example.", "10.0.0.2"),
              ("A.example.", "10.0.0.1")],
        "aaaa": [("b.example.", "2001:db8::2")],
    }
    pivots = dns._axfr_pivot_targets(data)
    assert pivots == [("a.example", "10.0.0.1"), ("b.example", "10.0.0.2"),
                      ("b.example", "2001:db8::2")]


def test_axfr_pivot_targets_empty_on_no_data():
    assert dns._axfr_pivot_targets({}) == []
    assert dns._axfr_pivot_targets({"a": [], "aaaa": []}) == []


# --------------------------------------------------------------------------- #
# BIND version-gated CVE annotation. version-gate, never ship unverified.
# --------------------------------------------------------------------------- #
def test_bind_cves_matches_vulnerable_9_11():
    """BIND 9.11.5 is older than the fixes for all three curated CVEs — every
    one fires. Version string mirrors what version.bind returns on Debian."""
    hits = dns._bind_cves("9.11.5-P4-5.1+deb10u5-Debian")
    ids = {h["cve"] for h in hits}
    assert {"CVE-2020-8617", "CVE-2020-8623", "CVE-2020-8625"} <= ids


def test_bind_cves_silent_on_patched_9_16():
    """9.16.20 is past every 9.16 fix in the table — no CVE emitted."""
    assert dns._bind_cves("9.16.20") == []


def test_bind_cves_silent_on_unparseable():
    """Fingerprint that doesn't look like a BIND version parses to None —
    fail-closed, never ship an unverified CVE."""
    assert dns._bind_cves("") == []
    assert dns._bind_cves("dnsmasq-2.85") == []
    assert dns._bind_cves("MikroTik") == []


def test_parse_bind_version_extracts_minor_patch():
    assert dns._parse_bind_version("BIND 9.16.6") == (16, 6)
    assert dns._parse_bind_version("9.11.5-P4") == (11, 5)
    assert dns._parse_bind_version("nope") is None


def test_axfr_finding_annotates_bind_cve_when_version_vulnerable():
    """AXFR + a co-disclosed vulnerable version.bind → CVE list stapled to
    the finding text; still one finding, still dns_axfr kind."""
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": ["contoso.local"],
        "records": {"contoso.local": 1},
        "version": "9.11.5-P4-5.1+deb10u5-Debian",
        "axfr_data": {"contoso.local": {
            "names": ["dc01.contoso.local"],
            "a": [("dc01.contoso.local", "10.0.0.5")],
            "aaaa": [], "cname": [], "ns": [], "ptr": [], "mx": [], "srv": [],
        }},
    }}
    fs = dns.findings([h], probes)
    axfr_f = [f for f in fs if f.get("kind") == "dns_axfr"]
    assert axfr_f
    detail = axfr_f[0]["detail"]
    assert "CVE-2020-8617" in detail
    assert "9.11.5" in detail


def test_axfr_finding_no_cve_annotation_when_version_patched():
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": ["contoso.local"],
        "records": {"contoso.local": 1},
        "version": "9.16.20",
        "axfr_data": {"contoso.local": {
            "names": ["dc01.contoso.local"],
            "a": [("dc01.contoso.local", "10.0.0.5")],
            "aaaa": [], "cname": [], "ns": [], "ptr": [], "mx": [], "srv": [],
        }},
    }}
    fs = dns.findings([h], probes)
    axfr_f = [f for f in fs if f.get("kind") == "dns_axfr"]
    assert axfr_f
    detail = axfr_f[0]["detail"]
    assert "CVE-" not in detail
    # T2 upgrade still fires purely on the parsed A record.
    assert axfr_f[0]["depth_tier"] == "t2"


def test_axfr_probe_times_out_cleanly_when_target_unreachable():
    """Unreachable target: axfr() returns ok=False without raising. Ensures
    T1 finding path still functions cleanly when the T2 probe cannot connect."""
    # RFC 5737 TEST-NET-1 address — routable-format, guaranteed non-responsive.
    r = dns.axfr("192.0.2.1", 53, "contoso.local", timeout=0.5)
    assert r["ok"] is False
    assert r["records"] == 0
    assert r["rcode"] is None
    assert r["data"] == {"names": [], "a": [], "aaaa": [], "cname": [],
                         "ns": [], "ptr": [], "mx": [], "srv": []}


# --------------------------------------------------------------------------- #
# Open-recursion detection: single recursive query for a name outside any
# authoritative zone. Open resolver = RA=1 AND rcode not in {REFUSED, NOTIMP}.
# --------------------------------------------------------------------------- #
def _serve_recursion(ra: bool, rcode: int):
    """Fake DNS-over-TCP server that always returns a canned header:
    QR=1, RA per parameter, given rcode, no answers/authority/additional."""
    ra_bit = 0x0080 if ra else 0x0000
    flags = 0x8000 | ra_bit | (rcode & 0x0F)

    class H(socketserver.BaseRequestHandler):
        def handle(self):
            data = self.request.recv(4096)
            if not data:
                return
            hdr = struct.pack("!HHHHHH", 0x1337, flags, 1, 0, 0, 0)
            self.request.sendall(struct.pack("!H", len(hdr)) + hdr)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1], srv


def test_open_recursion_detects_open_resolver():
    """RA=1 and rcode=NOERROR (0) → open resolver (server processed the
    recursive query even though .invalid has no upstream answer)."""
    port, srv = _serve_recursion(ra=True, rcode=0)
    try:
        r = dns.open_recursion("127.0.0.1", port, timeout=3)
    finally:
        srv.shutdown()
    assert r["ok"] is True
    assert r["ra"] is True
    assert r["rcode"] == 0


def test_open_recursion_servfail_still_counts_as_open():
    """SERVFAIL (rcode=2) with RA=1 = server accepted the recursion but
    upstream failed — still an open resolver (the exposed primitive is the
    willingness to recurse, not the outcome)."""
    port, srv = _serve_recursion(ra=True, rcode=2)
    try:
        r = dns.open_recursion("127.0.0.1", port, timeout=3)
    finally:
        srv.shutdown()
    assert r["ok"] is True


def test_open_recursion_refused_is_locked_down():
    """REFUSED (rcode=5) = server rejected the recursive query cleanly →
    NOT an open resolver, no finding."""
    port, srv = _serve_recursion(ra=True, rcode=5)
    try:
        r = dns.open_recursion("127.0.0.1", port, timeout=3)
    finally:
        srv.shutdown()
    assert r["ok"] is False
    assert r["rcode"] == 5


def test_open_recursion_notimp_is_locked_down():
    """NOTIMP (rcode=4) = server does not implement recursion → not open."""
    port, srv = _serve_recursion(ra=True, rcode=4)
    try:
        r = dns.open_recursion("127.0.0.1", port, timeout=3)
    finally:
        srv.shutdown()
    assert r["ok"] is False


def test_open_recursion_ra_zero_is_not_open():
    """RA=0 alone is enough to say 'not an open resolver' — an auth-only
    server that answers NXDOMAIN with RA=0 is fine."""
    port, srv = _serve_recursion(ra=False, rcode=0)
    try:
        r = dns.open_recursion("127.0.0.1", port, timeout=3)
    finally:
        srv.shutdown()
    assert r["ok"] is False
    assert r["ra"] is False


def test_open_recursion_unreachable_returns_none_rcode():
    """Unreachable target: probe returns {ok:False, ra:False, rcode:None}
    without raising. Ensures the T1 base findings still fire when the
    open-recursion probe cannot connect."""
    # RFC 5737 TEST-NET-1 — routable-format, non-responsive.
    r = dns.open_recursion("192.0.2.1", 53, timeout=0.5)
    assert r["ok"] is False
    assert r["rcode"] is None


def test_open_recursion_finding_emitted_when_probe_ok():
    """Probe result ok=True → medium-severity dns_open_recursion finding
    with CWE-406 and depth_tier=t1."""
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": [], "records": {}, "version": "",
        "open_recursion": {"ok": True, "ra": True, "rcode": 0},
    }}
    fs = dns.findings([h], probes)
    fr = [f for f in fs if f.get("kind") == "dns_open_recursion"]
    assert fr, "open-recursion finding must fire"
    f = fr[0]
    assert f["severity"] == "medium"
    assert f["depth_tier"] == "t1"
    assert "CWE-406" in f["cwes"]
    assert f["exploit_note"]                            # non-empty
    assert "recursive" in f["detail"].lower()
    assert "amplification" in f["detail"].lower()


def test_open_recursion_no_finding_when_probe_says_locked():
    """Probe result ok=False → no dns_open_recursion finding. Absence is the
    'patched/absent' case."""
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": [], "records": {}, "version": "",
        "open_recursion": {"ok": False, "ra": True, "rcode": 5},
    }}
    fs = dns.findings([h], probes)
    fr = [f for f in fs if f.get("kind") == "dns_open_recursion"]
    assert fr == []


def test_open_recursion_no_finding_when_probe_missing():
    """Legacy probe dicts without an open_recursion key: no finding,
    no KeyError — backward compatible with old scan reports."""
    h = Host(ip="10.0.0.9", ports=[Port(portid=53, service="domain", state="open")])
    probes = {("10.0.0.9", 53): {
        "axfr_zones": [], "records": {}, "version": "",
    }}
    fs = dns.findings([h], probes)
    fr = [f for f in fs if f.get("kind") == "dns_open_recursion"]
    assert fr == []


def test_srv_mx_ns_empty_on_refused():
    """Server that REFUSES every query returns empty srv/mx/ns dicts, and does
    not raise."""
    # RCODE=REFUSED, an=0 — matches the shape _rr_query bails on.
    hdr = struct.pack("!HHHHHH", 0, 0x8005, 0, 0, 0, 0)
    port, srv = _serve_bytes(hdr)
    try:
        got = dns.srv_mx_ns("127.0.0.1", port, "contoso.local", timeout=3)
    finally:
        srv.shutdown()
    assert got == {"srv": {}, "mx": [], "ns": []}
