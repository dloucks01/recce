"""IPMI RMCP+ RAKP hash extraction — recce sends the exchange, captures the
HMAC the BMC computes with the user password as key, and writes it to
loot/ipmi.hash for hashcat -m 7300.

The critical test cracks the captured HMAC locally by recomputing it with the
right password — proves the captured line is actually feedable to hashcat and
not just plausible-looking bytes."""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import socket
import struct
import threading

from recce.services import ipmi


def _fake_bmc(password: bytes = b"admin", *, refuse: bool = False):
    """A minimal fake BMC that does one RMCP+ Open Session + one RAKP2
    conversation and closes. Returns (port, socket)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(6)
    port = s.getsockname()[1]
    state = {"managed_sid": 0xDEADBEEF, "server_random": b"\x11" * 16,
             "server_guid": b"\x22" * 16}

    def run():
        try:
            # Open Session Request: remote_sid at absolute offset 20
            data, addr = s.recvfrom(4096)
            remote_sid = struct.unpack("<I", data[20:24])[0]
            status = 0x01 if refuse else 0x00
            payload = (bytes([0x00, status, 0x04, 0x00])
                       + struct.pack("<I", remote_sid)
                       + struct.pack("<I", state["managed_sid"])
                       + b"\x00\x00\x00\x08\x01\x00\x00\x00"
                       + b"\x01\x00\x00\x08\x00\x00\x00\x00"
                       + b"\x02\x00\x00\x08\x00\x00\x00\x00")
            resp = (b"\x06\x00\xff\x07\x06\x11"
                    + struct.pack("<I", 0) + struct.pack("<I", 0)
                    + struct.pack("<H", len(payload)) + payload)
            s.sendto(resp, addr)
            if refuse:
                return

            # RAKP1 — payload starts at offset 16
            data, addr = s.recvfrom(4096)
            body = data[16:]
            client_random = body[8:24]
            role = body[24]
            ulen = body[27]
            uname = body[28:28 + ulen]
            msg = (struct.pack("<I", remote_sid)
                   + struct.pack("<I", state["managed_sid"])
                   + client_random + state["server_random"]
                   + state["server_guid"] + bytes([role, ulen]) + uname)
            mac = hmac_mod.new(password, msg, hashlib.sha1).digest()
            payload = (bytes([0x00, 0x00, 0x00, 0x00])
                       + struct.pack("<I", remote_sid)
                       + state["server_random"] + state["server_guid"] + mac)
            resp = (b"\x06\x00\xff\x07\x06\x13"
                    + struct.pack("<I", 0) + struct.pack("<I", 0)
                    + struct.pack("<H", len(payload)) + payload)
            s.sendto(resp, addr)
        except OSError:
            pass

    threading.Thread(target=run, daemon=True).start()
    return port, s


def test_rakp_exchange_captures_a_hashcat_crackable_hmac():
    """The core proof: capture the HMAC, recompute it locally with the right
    password, and confirm they match. If they do, hashcat -m 7300 against the
    captured line would recover the password."""
    port, srv = _fake_bmc(password=b"correcthorse")
    try:
        r = ipmi.rakp_hash("127.0.0.1", port, username="admin", timeout=2.0)
    finally:
        srv.close()
    assert r["reachable"] and not r["error"]
    assert r["hmac_alg"] == "HMAC-SHA1"
    assert r["hashcat_mode"] == 7300
    data_hex, hmac_hex = r["hashcat_line"].split(":")
    recomputed = hmac_mod.new(b"correcthorse", bytes.fromhex(data_hex),
                              hashlib.sha1).hexdigest()
    assert recomputed == hmac_hex, \
        "captured HMAC does not match what the target password produces — " \
        "the line is unusable for hashcat -m 7300"


def test_rakp_reports_the_bmc_refusal_cleanly():
    """A BMC that refuses the Open Session (mismatched auth alg, unsupported
    priv level, or policy) must produce a clean error rather than a
    misleading 'unreachable'."""
    port, srv = _fake_bmc(refuse=True)
    try:
        r = ipmi.rakp_hash("127.0.0.1", port, username="admin", timeout=2.0)
    finally:
        srv.close()
    assert r["reachable"]                           # port answered
    assert r["hashcat_line"] == ""
    assert "refused" in r["error"]


def test_rakp_on_dead_port_returns_unreachable_not_a_traceback():
    """No listener → clean timeout, empty line, no exception."""
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]; s.close()
    r = ipmi.rakp_hash("127.0.0.1", port, username="admin", timeout=1.0)
    assert not r["reachable"]
    assert r["hashcat_line"] == ""


def test_hashcat_line_concatenates_fields_in_the_spec_order():
    """Independent construction: given known random values recompute what the
    line SHOULD contain, and prove _hashcat_rakp_line matches."""
    line = ipmi._hashcat_rakp_line(
        username="admin",
        client_random=b"\xAA" * 16,
        server_random=b"\xBB" * 16,
        server_guid=b"\xCC" * 16,
        remote_sid=0x11111111,
        managed_sid=0x22222222,
        hmac=b"\xDD" * 20,
    )
    data_hex, hmac_hex = line.split(":")
    expected = (
        struct.pack("<I", 0x11111111) + struct.pack("<I", 0x22222222)
        + b"\xAA" * 16 + b"\xBB" * 16 + b"\xCC" * 16
        + bytes([ipmi._ROLE_ADMIN_LOOKUP, 5]) + b"admin")
    assert bytes.fromhex(data_hex) == expected
    assert hmac_hex == "dd" * 20


def test_hashloot_collect_from_probe_routes_ipmi_to_the_right_file():
    """The dispatcher wires IPMI probes → loot/ipmi.hash (mode 7300)."""
    from recce.creds import hashloot
    probe = {"rakp": {"hashcat_line": "abcd:1234", "hashcat_mode": 7300}}
    pairs = hashloot.collect_from_probe(probe, "ipmi")
    assert pairs == [("ipmi", "abcd:1234")]
    # Category must be registered so the writer can name the file + mode
    assert hashloot.CATEGORIES["ipmi"][:2] == ("ipmi.hash", 7300)


def test_hashloot_collect_from_probe_returns_nothing_when_rakp_missing():
    from recce.creds import hashloot
    assert hashloot.collect_from_probe({}, "ipmi") == []
    assert hashloot.collect_from_probe({"rakp": {}}, "ipmi") == []
    assert hashloot.collect_from_probe({"rakp": {"error": "refused"}}, "ipmi") == []


def test_ipmi_finding_fires_only_when_a_hash_was_actually_captured():
    """A failed capture (empty hashcat_line) must not generate the finding —
    otherwise every probe against a BMC that refuses would spam the report."""
    from recce.core.models import Host, Port
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=623, protocol="udp", state="open", service="ipmi")])
    good = {("10.0.0.5", 623): {"reachable": True, "ipmi_version": "2.0",
            "auth_types": ["md5", "hmac-sha1"], "null_user": False,
            "anonymous_login": False, "cipher_zero": False,
            "rakp": {"hashcat_line": "abcd:ef01", "hashcat_mode": 7300,
                     "hmac_alg": "HMAC-SHA1"}}}
    kinds = {f["kind"] for f in ipmi.findings([h], good)}
    assert "ipmi_rakp_hash" in kinds

    bad = {("10.0.0.5", 623): {"reachable": True, "ipmi_version": "2.0",
           "auth_types": ["md5"], "null_user": False, "anonymous_login": False,
           "cipher_zero": False, "rakp": {"hashcat_line": "", "error": "refused"}}}
    kinds2 = {f["kind"] for f in ipmi.findings([h], bad)}
    assert "ipmi_rakp_hash" not in kinds2
