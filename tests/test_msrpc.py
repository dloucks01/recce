"""MSRPC (135/tcp): endpoint mapper + IOXIDResolver.

The DCE/RPC packets here are hand-built from struct so the decoder is validated
against layouts that recce didn't generate — same discipline as the SNMP and NTP
tests. Findings tests drive synthetic probe dicts (no network) so failure modes
are unambiguous.
"""
from __future__ import annotations

import struct
import uuid

from recce.core.models import Host, Port
from recce.services import msrpc


def test_predicate_matches_135_and_svc_names():
    assert msrpc.is_msrpc(Port(portid=135, state="open", service="msrpc"))
    assert msrpc.is_msrpc(Port(portid=135, state="open", service="epmap"))
    assert msrpc.is_msrpc(Port(portid=135, state="open", service=""))
    assert not msrpc.is_msrpc(Port(portid=445, state="open", service="smb"))


def test_utf16_strings_pulls_out_bindings_between_double_nulls():
    """The IOXIDResolver DUALSTRINGARRAY layout is a run of towered addresses
    separated by 0x0000, terminated by a double null. The scan-for-strings
    reader has to survive Windows padding variations."""
    binding = "10.0.0.5".encode("utf-16-le") + b"\x00\x00"
    other = "192.168.1.10".encode("utf-16-le") + b"\x00\x00"
    blob = b"\x00\x00" + binding + b"\x00\x00" + other + b"\x00\x00\x00\x00"
    strings = msrpc._utf16_strings(blob)
    assert "10.0.0.5" in strings
    assert "192.168.1.10" in strings


def test_uuids_in_only_returns_known_interfaces():
    """The EPM response is a tower blob whose NDR layout varies by floor count.
    We scan for the interface UUIDs we can NAME rather than parsing towers, so
    an unknown UUID must not surface as a random hit."""
    known = uuid.UUID("12345678-1234-abcd-ef00-0123456789ab").bytes_le  # spoolss
    unknown = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le
    blob = b"\xff" * 8 + known + b"\x00" * 20 + unknown + b"\xff" * 8
    found = msrpc._uuids_in(blob)
    assert "12345678-1234-abcd-ef00-0123456789ab" in found
    assert "11111111-2222-3333-4444-555555555555" not in found


def test_pdu_header_frames_length_correctly():
    """A bind PDU: 16-byte header, packet length at offset 8, little-endian."""
    body = b"\x00" * 32
    pdu = msrpc._pdu(11, body)
    version, minor, ptype, flags, drep, frag = struct.unpack_from(
        "<BBBB4sH", pdu, 0)
    assert version == 5 and ptype == 11
    assert frag == 16 + len(body)


# --- findings on synthetic probe output --------------------------------------

def _host():
    return Host(ip="10.0.0.10", ports=[Port(portid=135, state="open", service="msrpc")])


def _pr(**kw):
    base = {"reachable": True}
    base.update(kw)
    return {("10.0.0.10", 135): base}


def test_coercion_interfaces_produce_a_high_severity_finding():
    """PetitPotam / PrinterBug / DFSCoerce are the interfaces that convert an
    unauth foothold into a coerced auth to a relay target — the highest-yield
    signal a scanner can produce on 135."""
    fs = msrpc.findings([_host()], _pr(
        interfaces=["c681d488-d850-11d0-8c52-00c04fd90f7e"],  # PetitPotam
        coercion=["c681d488-d850-11d0-8c52-00c04fd90f7e"]))
    f = next(f for f in fs if f["kind"] == "msrpc_coercion")
    assert f["severity"] == "high"
    assert "MS-EFSR" in f["detail"] or "PetitPotam" in f["detail"]


def test_ioxid_names_addresses_outside_the_engagement_scope():
    """A multi-homed host is only interesting when it names networks recce
    hasn't scanned — the point is discovery, not disclosure."""
    fs = msrpc.findings([_host()], _pr(
        addresses=["10.0.0.10", "192.168.99.5", "fe80::abcd"]))
    f = next(f for f in fs if f["kind"] == "msrpc_ioxid")
    assert f["severity"] == "medium"
    assert "192.168.99.5" in f["detail"]

    # All-known addresses drop to low.
    hosts = [Host(ip=ip, ports=[]) for ip in ("10.0.0.10", "192.168.99.5")]
    hosts[0].ports = [Port(portid=135, state="open", service="msrpc")]
    fs2 = msrpc.findings(hosts, _pr(addresses=["10.0.0.10", "192.168.99.5"]))
    f2 = next(f for f in fs2 if f["kind"] == "msrpc_ioxid")
    assert f2["severity"] == "low"


def test_endpoint_mapper_names_the_recognised_interfaces():
    fs = msrpc.findings([_host()], _pr(
        interfaces=["367abb81-9844-35f1-ad32-98f038001003",   # svcctl
                    "8bc3f05e-d86b-11d0-a075-00c04fb68820"],  # WMI
        coercion=[]))
    f = next(f for f in fs if f["kind"] == "msrpc_epm")
    # both interfaces named by their spec, not by raw UUID
    assert "MS-SCMR" in f["detail"] and "MS-WMI" in f["detail"]


def test_unreachable_produces_no_findings():
    assert msrpc.findings([_host()], {("10.0.0.10", 135): {"reachable": False}}) == []


def test_findings_map_to_vulns_on_port_135():
    fs = msrpc.findings([_host()], _pr(
        coercion=["12345678-1234-abcd-ef00-0123456789ab"],
        interfaces=["12345678-1234-abcd-ef00-0123456789ab"]))
    v = msrpc.findings_to_vulns([f for f in fs if f["kind"] == "msrpc_coercion"])
    vuln = v["10.0.0.10"][0]
    assert vuln.source == "msrpc" and vuln.port == 135
    assert vuln.severity == "high"


def test_analyze_shape_matches_the_service_convention():
    res = msrpc.analyze([_host()], active=False)
    assert set(res) >= {"targets", "findings", "runbooks", "probes", "stats"}
    assert res["stats"]["targets"] == 1


# --- new capability: high-value UUIDs (Netlogon, BKRP) recognised ------------

def test_netlogon_uuid_is_recognised_as_a_high_value_interface():
    """MS-NRPC (12345678-1234-abcd-ef00-01234567cffb) is the ZeroLogon dispatch
    precondition (CVE-2020-1472). Without recognition, an EPM dump of a DC
    never flags Netlogon and downstream checks have no dispatch signal."""
    netlogon = "12345678-1234-abcd-ef00-01234567cffb"
    assert netlogon in msrpc._KNOWN
    assert msrpc._KNOWN[netlogon][1] == "MS-NRPC"
    assert netlogon in msrpc._HIGH_VALUE


def test_bkrp_uuid_is_recognised_as_a_high_value_interface():
    """MS-BKRP (3dde7c30-165d-11d1-ab8f-00805f14db40) serves the DPAPI domain
    backup key on a DC — a credentialed follow-up hint."""
    bkrp = "3dde7c30-165d-11d1-ab8f-00805f14db40"
    assert bkrp in msrpc._KNOWN
    assert msrpc._KNOWN[bkrp][1] == "MS-BKRP"
    assert bkrp in msrpc._HIGH_VALUE


def test_uuids_in_finds_netlogon_and_bkrp():
    """Both critical UUIDs must be extracted from a synthetic tower blob so
    the epm_lookup pipeline surfaces them without any code-path change."""
    netlogon = uuid.UUID("12345678-1234-abcd-ef00-01234567cffb").bytes_le
    bkrp = uuid.UUID("3dde7c30-165d-11d1-ab8f-00805f14db40").bytes_le
    blob = b"\xff" * 4 + netlogon + b"\x00" * 8 + bkrp + b"\xff" * 4
    found = msrpc._uuids_in(blob)
    assert "12345678-1234-abcd-ef00-01234567cffb" in found
    assert "3dde7c30-165d-11d1-ab8f-00805f14db40" in found


def test_high_value_interfaces_produce_dedicated_finding():
    """Netlogon and BKRP appear in a distinct msrpc_high_value_iface finding
    at medium severity — no CVE claim, since recce did not probe them."""
    fs = msrpc.findings([_host()], _pr(
        interfaces=["12345678-1234-abcd-ef00-01234567cffb",
                    "3dde7c30-165d-11d1-ab8f-00805f14db40"],
        coercion=[],
        high_value=["12345678-1234-abcd-ef00-01234567cffb",
                    "3dde7c30-165d-11d1-ab8f-00805f14db40"]))
    f = next(f for f in fs if f["kind"] == "msrpc_high_value_iface")
    assert f["severity"] == "medium"
    # named by spec — Netlogon flagged as the ZeroLogon dispatch signal.
    assert "MS-NRPC" in f["detail"] and "MS-BKRP" in f["detail"]
    # no invented CVE ID in the detail body (only advisory-style hardening)
    assert "CVE-2020" not in f["detail"]


# --- new capability: fragment reassembly (PFC_LAST_FRAG) ---------------------

class _FakeSock:
    """Feeds _request pre-canned PDU bytes and records what was sent so the
    reassembly loop can be driven deterministically without a real socket."""

    def __init__(self, chunks: list[bytes]):
        self._buf = b"".join(chunks)
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def settimeout(self, _t):
        pass

    def recv(self, n):
        if not self._buf:
            return b""
        take, self._buf = self._buf[:n], self._buf[n:]
        return take


def _resp_pdu(stub: bytes, flags: int) -> bytes:
    """Build a co-response PDU: 16B CO header + 8B response header + stub."""
    hdr = struct.pack("<BBBB4sHHI",
                      5, 0, 2, flags,          # version 5.0, ptype=response
                      b"\x10\x00\x00\x00",
                      16 + 8 + len(stub), 0, 2)
    # response-header: alloc_hint(4), p_cont_id(2), cancel_count(1), reserved(1)
    resp_hdr = struct.pack("<IHBB", len(stub), 0, 0, 0)
    return hdr + resp_hdr + stub


def test_request_reassembles_multi_fragment_response():
    """C706 §12.6.4.9: PFC_LAST_FRAG (0x02) marks the final fragment. Previously
    _request returned only the first frag — silently truncating any ept_lookup
    response that overflowed max_xmit_frag=5840. The fix concatenates stubs
    across every fragment until PFC_LAST_FRAG is set."""
    # First frag: PFC_FIRST_FRAG only (0x01). Second: PFC_LAST_FRAG only (0x02).
    frag1 = _resp_pdu(b"AAAA", flags=0x01)
    frag2 = _resp_pdu(b"BBBB", flags=0x02)
    frag3 = _resp_pdu(b"CCCC", flags=0x03)   # never reached — sanity
    sock = _FakeSock([frag1, frag2, frag3])
    out = msrpc._request(sock, opnum=2, stub=b"", timeout=1.0)
    assert out == b"AAAABBBB"


def test_request_single_frag_still_works():
    """A single-PDU response has both FIRST+LAST bits set (0x03). The
    reassembly loop must still return the payload after one iteration."""
    sock = _FakeSock([_resp_pdu(b"OK", flags=0x03)])
    out = msrpc._request(sock, opnum=2, stub=b"", timeout=1.0)
    assert out == b"OK"


# --- new capability: tower parse -> dynamic ncacn_ip_tcp port ----------------

def _iface_floor(u: uuid.UUID, ver_maj: int = 1, ver_min: int = 0) -> bytes:
    """C706 §L.1.2.5 interface UUID floor: lhs_len=0x0013, lhs=0x0d+uuid+ver_maj,
    rhs_len=0x0002, rhs=ver_min."""
    lhs = b"\x0d" + u.bytes_le + struct.pack("<H", ver_maj)
    return struct.pack("<H", len(lhs)) + lhs + struct.pack("<HH", 2, ver_min)


def _ncacn_ip_tcp_floor(port: int) -> bytes:
    """ncacn_ip_tcp floor: lhs_len=0x0001, lhs=0x07, rhs_len=0x0002, rhs=port BE."""
    return struct.pack("<H", 1) + b"\x07" + struct.pack("<H", 2) + struct.pack(">H", port)


def test_towers_in_extracts_uuid_and_dynamic_tcp_port():
    """A single tower with an interface floor + an ncacn_ip_tcp floor should
    yield {uuid, ver_major, ver_minor, tcp_port}. Dynamic RPC lives in
    49152-65535; the parser must return the raw port value it sees."""
    drsuapi = uuid.UUID("e3514235-4b06-11d1-ab04-00c04fc2dcd2")
    blob = _iface_floor(drsuapi, 4, 0) + _ncacn_ip_tcp_floor(49669)
    towers = msrpc._towers_in(blob)
    assert len(towers) == 1
    assert towers[0]["uuid"] == "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
    assert towers[0]["ver_major"] == 4
    assert towers[0]["ver_minor"] == 0
    assert towers[0]["tcp_port"] == 49669


def test_towers_in_pairs_multiple_towers_correctly():
    """Two consecutive towers with different dynamic ports: parser must pair
    each UUID with the transport port that follows it, not cross-pair."""
    samr = uuid.UUID("12345778-1234-abcd-ef00-0123456789ac")
    wmi = uuid.UUID("8bc3f05e-d86b-11d0-a075-00c04fb68820")
    blob = (_iface_floor(samr, 1, 0) + _ncacn_ip_tcp_floor(49670)
            + _iface_floor(wmi, 0, 0) + _ncacn_ip_tcp_floor(49671))
    towers = msrpc._towers_in(blob)
    assert len(towers) == 2
    by_uuid = {t["uuid"]: t["tcp_port"] for t in towers}
    assert by_uuid["12345778-1234-abcd-ef00-0123456789ac"] == 49670
    assert by_uuid["8bc3f05e-d86b-11d0-a075-00c04fb68820"] == 49671


def test_towers_in_returns_zero_port_when_no_tcp_floor():
    """A named-pipe-only tower has no ncacn_ip_tcp floor. tcp_port must be 0
    (not None) so the downstream filter in probe() drops it cleanly."""
    lsarpc = uuid.UUID("12345778-1234-abcd-ef00-0123456789ab")
    blob = _iface_floor(lsarpc, 0, 0) + b"\x00" * 10  # trailing padding, no TCP
    towers = msrpc._towers_in(blob)
    assert len(towers) == 1
    assert towers[0]["tcp_port"] == 0


def test_dynport_finding_emits_kind_and_names_ports():
    """The msrpc_dynport_map finding lists each recognised interface's
    resolved dynamic port so downstream services can pivot without a second
    EPM round-trip."""
    fs = msrpc.findings([_host()], _pr(
        interfaces=["e3514235-4b06-11d1-ab04-00c04fc2dcd2"],
        endpoints=[{"uuid": "e3514235-4b06-11d1-ab04-00c04fc2dcd2",
                    "port": 49669, "ver_major": 4, "ver_minor": 0}]))
    f = next(f for f in fs if f["kind"] == "msrpc_dynport_map")
    assert f["severity"] == "low"
    assert "drsuapi=49669" in f["detail"]
