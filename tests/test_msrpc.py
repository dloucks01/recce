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
