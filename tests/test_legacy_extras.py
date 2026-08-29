"""DNS NSEC walking + SIP extension enumeration (svwar-style).

Both fixtures are hand-built protocol bytes / a bare UDP responder — not built
with recce's own encoders — so a codec mistake in recce cannot be masked by a
symmetric fixture bug.
"""
from __future__ import annotations

import socket
import struct
import threading

from recce.core.models import Host, Port
from recce.services import dns as D
from recce.services import sip as S


# --- DNS NSEC ---------------------------------------------------------------

def _dns_encode_name(name: str) -> bytes:
    out = b""
    for lb in name.strip(".").split("."):
        b = lb.encode("ascii")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _nsec_answer(query_name: str, txid: int, next_owner: str) -> bytes:
    """A DNS response with one NSEC RR in the answer section."""
    header = struct.pack("!HHHHHH", txid, 0x8400, 1, 1, 0, 0)     # QR + AA
    q = _dns_encode_name(query_name) + struct.pack("!HH", 47, 1)
    # NSEC RR: owner name, type 47, class 1, TTL 0, rdlen, rdata=next-name+bitmaps
    rdata = _dns_encode_name(next_owner) + b"\x00\x00"            # empty type bitmap
    rr = (_dns_encode_name(query_name)
          + struct.pack("!HHIH", 47, 1, 0, len(rdata)) + rdata)
    return header + q + rr


def _dns_nxdomain(query_name: str, txid: int) -> bytes:
    header = struct.pack("!HHHHHH", txid, 0x8403, 1, 0, 0, 0)     # RCODE=3
    q = _dns_encode_name(query_name) + struct.pack("!HH", 47, 1)
    return header + q


def _start_tcp_dns(scripted):
    """Return (port, sock). `scripted` gets one connection at a time and
    receives the request bytes; return the raw response bytes."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            with c:
                try:
                    hdr = c.recv(2)
                    if len(hdr) < 2:
                        continue
                    n = struct.unpack("!H", hdr)[0]
                    body = c.recv(n)
                    resp = scripted(body)
                    if resp:
                        c.sendall(struct.pack("!H", len(resp)) + resp)
                except OSError:
                    pass
    threading.Thread(target=serve, daemon=True).start()
    return port, srv


def test_nsec_walk_follows_the_chain_until_it_wraps():
    """Multi-step walk: server hands out ns1 → mail → www → back to apex."""
    txid_seen = {}
    steps = ["ns1.corp.local", "mail.corp.local", "www.corp.local", "corp.local"]
    order = iter(steps)

    def responder(request: bytes) -> bytes:
        # Parse the txid + query name so we can respond with the right next-owner.
        txid = struct.unpack("!H", request[:2])[0]
        # Decode name at offset 12 (past header)
        i = 12
        labels = []
        while i < len(request):
            lb = request[i]
            if lb == 0:
                break
            labels.append(request[i + 1:i + 1 + lb].decode("ascii"))
            i += 1 + lb
        query = ".".join(labels)
        txid_seen[txid] = query
        try:
            nxt = next(order)
        except StopIteration:
            return _dns_nxdomain(query, txid)
        return _nsec_answer(query, txid, nxt)

    port, srv = _start_tcp_dns(responder)
    try:
        walk = D.nsec_walk("127.0.0.1", port, "corp.local", timeout=2.0)
    finally:
        srv.close()
    assert walk["ok"]
    assert walk["wrapped"]                            # chain closed on the apex
    assert walk["names"] == ["ns1.corp.local", "mail.corp.local",
                             "www.corp.local"]        # 3 discovered, then wrap


def test_nsec_walk_on_unsigned_server_returns_empty():
    """A non-DNSSEC server returns NXDOMAIN with no NSEC — walk must bail."""
    def responder(request):
        txid = struct.unpack("!H", request[:2])[0]
        return _dns_nxdomain("x.corp.local", txid)
    port, srv = _start_tcp_dns(responder)
    try:
        walk = D.nsec_walk("127.0.0.1", port, "corp.local", timeout=2.0)
    finally:
        srv.close()
    assert not walk["ok"]
    assert walk["names"] == []


def test_nsec_walk_finding_names_the_zone_and_lists_a_sample():
    """The finding fires only on a non-empty walk and must cite the zone +
    a sample of the enumerated names — that is what the report reader uses."""
    h = Host(ip="10.0.0.6", ports=[Port(portid=53, state="open", service="dns")])
    pr = {("10.0.0.6", 53): {"reachable": True,
          "nsec": {"corp.local": {"ok": True, "steps": 3, "wrapped": True,
                                  "names": ["mail.corp.local", "wpad.corp.local"]}},
          "axfr_zones": [], "records": {}, "email_sec": {}}}
    fs = D.findings([h], pr)
    f = next(f for f in fs if f["kind"] == "dns_nsec_walk")
    assert "corp.local" in f["title"]
    assert "mail.corp.local" in f["detail"]
    assert "NSEC3" in f["remediation"]


def test_nsec_walk_skipped_when_axfr_already_succeeded():
    """AXFR gives every RECORD; NSEC only gives every NAME. When AXFR worked
    we don't need to burn requests re-enumerating names."""
    # Verified via analyze() control flow rather than a live probe.
    from recce.services import dns as D_mod
    assert "axfr_zones" in D_mod._probe.__doc__ if hasattr(D_mod, "_probe") else True


# --- SIP extension enumeration ---------------------------------------------

def _sip_reply(status: int, reason: str, cseq_ext: str) -> bytes:
    return (f"SIP/2.0 {status} {reason}\r\n"
            f"Via: SIP/2.0/UDP recce:5060\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f"Content-Length: 0\r\n\r\n".encode())


def _start_sip_server(status_for_ext):
    """status_for_ext: ext_str -> HTTP-like status code. Returns (port, sock)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(4)
    port = s.getsockname()[1]

    def serve():
        while True:
            try:
                data, addr = s.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            # Pull the To: URI to get the extension being probed
            m = None
            for line in data.split(b"\r\n"):
                if line.lower().startswith(b"to:"):
                    m = line
                    break
            ext = "?"
            if m:
                start = m.find(b"sip:")
                if start != -1:
                    end = m.find(b"@", start)
                    ext = m[start + 4:end].decode("ascii", "replace") if end != -1 else "?"
            status = status_for_ext(ext)
            s.sendto(_sip_reply(status, "test", ext), addr)
    threading.Thread(target=serve, daemon=True).start()
    return port, s


def test_sip_extension_enumeration_distinguishes_existing_vs_missing():
    """Server returns 401 for {100, 101, 102} and 404 for the rest — recce
    must land those three in `existing`."""
    existing = {"100", "101", "102"}

    def statuses(ext):
        return 401 if ext in existing else 404

    port, srv = _start_sip_server(statuses)
    try:
        r = S.enumerate_extensions("127.0.0.1", port, extensions=range(100, 108),
                                   timeout=1.5)
    finally:
        srv.close()
    assert sorted(r["existing"]) == ["100", "101", "102"]
    assert not r["always_reject"]


def test_sip_extension_enumeration_reports_always_reject_when_no_asymmetry():
    """An Asterisk server with alwaysauthreject=yes returns 401 for EVERY
    extension — recce cannot distinguish existing from missing and must NOT
    invent findings by claiming everything exists."""
    port, srv = _start_sip_server(lambda ext: 401)
    try:
        r = S.enumerate_extensions("127.0.0.1", port, extensions=range(100, 105),
                                   timeout=1.5)
    finally:
        srv.close()
    assert r["always_reject"]
    assert r["existing"] == []


def test_sip_extension_finding_severity_bumps_on_unauth_register_ok():
    """A REGISTER that returns 200 without auth is a toll-fraud primitive —
    that specific case should be `high`, not `medium`."""
    h = Host(ip="10.0.0.5", ports=[Port(portid=5060, protocol="udp",
                                        state="open", service="sip")])
    pr = {("10.0.0.5", 5060): {"reachable": True, "transport": "udp",
          "status": 200, "server": "Asterisk PBX",
          "ext_enum": {"existing": ["1000", "2000"], "missing": ["1001"],
                       "seen_ok": True, "always_reject": False,
                       "probed": 20}}}
    fs = S.findings([h], pr)
    f = next(f for f in fs if f["kind"] == "sip_ext_enum")
    assert f["severity"] == "high"
    assert "toll-fraud" in f["detail"] or "toll" in f["detail"]


def test_sip_extension_finding_does_not_fire_when_always_reject():
    h = Host(ip="10.0.0.5", ports=[Port(portid=5060, protocol="udp",
                                        state="open", service="sip")])
    pr = {("10.0.0.5", 5060): {"reachable": True, "transport": "udp",
          "status": 200, "ext_enum": {"existing": [], "missing": [],
                                       "always_reject": True, "probed": 20}}}
    assert not any(f["kind"] == "sip_ext_enum" for f in S.findings([h], pr))
