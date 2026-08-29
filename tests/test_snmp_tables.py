"""SNMP network tables: ARP cache + routing table.

These turn a read-only community string from an inventory read into network
DISCOVERY - a readable router hands over live neighbours and the routed segments,
including hosts the engagement has never scanned.

The fake agent below is built from raw BER (RFC 1157 / RFC 1213 encodings) rather
than recce's own encoders, so a wrong tag or offset in the decoder cannot be
masked by a symmetric bug in the fixture.
"""
from __future__ import annotations

import socket
import threading
import time

from recce.core.models import Host, Port
from recce.services import snmp

_ARP = "1.3.6.1.2.1.4.22.1.2"       # ipNetToMediaPhysAddress
_NH = "1.3.6.1.2.1.4.21.1.7"        # ipRouteNextHop
_MASK = "1.3.6.1.2.1.4.21.1.11"     # ipRouteMask


# --- hand-rolled BER ----------------------------------------------------------

def _tlv(tag: int, val: bytes) -> bytes:
    if len(val) < 128:
        return bytes([tag, len(val)]) + val
    lb = len(val).to_bytes((len(val).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(lb)]) + lb + val


def _oid(o: str) -> bytes:
    a = [int(x) for x in o.split(".")]
    body = bytes([a[0] * 40 + a[1]])
    for n in a[2:]:
        if n < 128:
            body += bytes([n])
        else:
            s = []
            while n:
                s.insert(0, n & 0x7F)
                n >>= 7
            body += bytes([b | 0x80 for b in s[:-1]] + [s[-1]])
    return _tlv(0x06, body)


def _int(n: int) -> bytes:
    return _tlv(0x02, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big"))


def _ipaddr(dotted: str) -> bytes:
    return _tlv(0x40, bytes(int(x) for x in dotted.split(".")))


def _mib():
    rows = []
    for ifx, ip, mac in [(1, "10.0.10.1", b"\x00\x50\x56\xaa\xbb\xcc"),
                         (1, "10.0.10.77", b"\xde\xad\xbe\xef\x00\x01"),
                         (2, "192.168.99.5", b"\x00\x0c\x29\xff\xee\xdd")]:
        rows.append((f"{_ARP}.{ifx}.{ip}", _tlv(0x04, mac)))
    for dest, nh in [("0.0.0.0", "10.0.10.1"), ("192.168.99.0", "10.0.10.254")]:
        rows.append((f"{_NH}.{dest}", _ipaddr(nh)))
    for dest, mask in [("0.0.0.0", "0.0.0.0"), ("192.168.99.0", "255.255.255.0")]:
        rows.append((f"{_MASK}.{dest}", _ipaddr(mask)))
    rows.append(("1.3.6.1.2.1.1.1.0", _tlv(0x04, b"Cisco IOS Software, C2960")))
    rows.sort(key=lambda kv: [int(a) for a in kv[0].split(".")])
    return rows


class _FakeAgent(threading.Thread):
    """Answers GET and GETNEXT out of an ordered MIB, like a real agent."""
    daemon = True

    def __init__(self):
        super().__init__()
        self.mib = _mib()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]

    @staticmethod
    def _reply(rid, oid, blob):
        vb = _tlv(0x30, _oid(oid) + blob)
        pdu = _tlv(0xA2, _int(rid) + _int(0) + _int(0) + _tlv(0x30, vb))
        return _tlv(0x30, _int(1) + _tlv(0x04, b"public") + pdu)

    def run(self):
        end = time.time() + 5
        while time.time() < end:
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            try:
                _, msg, _ = snmp._parse_tlv(data, 0)
                _, _v, i = snmp._parse_tlv(msg, 0)
                _, _c, i = snmp._parse_tlv(msg, i)
                ptag, pdu, _ = snmp._parse_tlv(msg, i)
                _, rid_b, j = snmp._parse_tlv(pdu, 0)
                rid = int.from_bytes(rid_b, "big")
                _, _e, j = snmp._parse_tlv(pdu, j)
                _, _ei, j = snmp._parse_tlv(pdu, j)
                _, vbs, _ = snmp._parse_tlv(pdu, j)
                _, vb, _ = snmp._parse_tlv(vbs, 0)
                _, ob, _ = snmp._parse_tlv(vb, 0)
                req = snmp.decode_oid(ob)
            except (IndexError, ValueError):
                continue
            key = [int(a) for a in req.split(".")]
            if ptag == 0xA1:
                hit = next((kv for kv in self.mib
                            if [int(a) for a in kv[0].split(".")] > key), None)
            else:
                hit = next((kv for kv in self.mib if kv[0] == req), None)
            if hit:
                self.sock.sendto(self._reply(rid, hit[0], hit[1]), addr)

    def stop(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _agent():
    a = _FakeAgent()
    a.start()
    time.sleep(0.15)
    return a


# --- decoding -----------------------------------------------------------------

def test_arp_walk_decodes_ip_from_oid_and_mac_from_raw_bytes():
    """The IP lives in the OID SUFFIX and the MAC is the value, so a walk that
    discards OIDs loses half of every row."""
    a = _agent()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rows = snmp.read_arp(s, "127.0.0.1", a.port, "public", 1.5)
    finally:
        a.stop()
    by_ip = {r["ip"]: r for r in rows}
    assert set(by_ip) == {"10.0.10.1", "10.0.10.77", "192.168.99.5"}
    assert by_ip["10.0.10.1"]["mac"] == "00:50:56:aa:bb:cc"
    assert by_ip["10.0.10.1"]["ifindex"] == 1
    assert by_ip["192.168.99.5"]["ifindex"] == 2


def test_arp_mac_with_high_bytes_survives():
    """A MAC is binary. The default OCTET STRING decode is utf-8/replace, which
    corrupts any byte over 0x7f - i.e. most real MACs. de:ad:be:ef proves the
    raw path is actually being used."""
    a = _agent()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        rows = snmp.read_arp(s, "127.0.0.1", a.port, "public", 1.5)
    finally:
        a.stop()
    assert any(r["mac"] == "de:ad:be:ef:00:01" for r in rows)
    assert not any("�" in r["mac"] for r in rows)      # no replacement chars


def test_route_walk_pairs_dest_with_next_hop_and_mask():
    a = _agent()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        routes = snmp.read_routes(s, "127.0.0.1", a.port, "public", 1.5)
    finally:
        a.stop()
    by_dest = {r["dest"]: r for r in routes}
    assert by_dest["0.0.0.0"]["next_hop"] == "10.0.10.1"
    assert by_dest["192.168.99.0"]["next_hop"] == "10.0.10.254"
    assert by_dest["192.168.99.0"]["mask"] == "255.255.255.0"


def test_parse_response_raw_preserves_tag_and_bytes():
    """The raw=True path is what keeps binary intact; assert it directly."""
    vb = _tlv(0x30, _oid("1.3.6.1.2.1.4.22.1.2.1.10.0.0.1")
              + _tlv(0x04, b"\xde\xad\xbe\xef\x00\x01"))
    pdu = _tlv(0xA2, _int(9) + _int(0) + _int(0) + _tlv(0x30, vb))
    msg = _tlv(0x30, _int(1) + _tlv(0x04, b"public") + pdu)
    err, rows = snmp.parse_response(msg, raw=True)
    assert err == 0
    _oid_s, (tag, blob) = rows[0]
    assert tag == 0x04 and blob == b"\xde\xad\xbe\xef\x00\x01"
    # and the default path still decodes normally for everything else
    err2, rows2 = snmp.parse_response(msg)
    assert err2 == 0 and isinstance(rows2[0][1], str)


# --- findings -----------------------------------------------------------------

def _findings(pr, known_ips=("10.0.10.1",)):
    hosts = [Host(ip=ip, ports=[Port(portid=161, protocol="udp", state="open",
                                     service="snmp")]) for ip in known_ips]
    base = {"ip": "10.0.10.1", "port": 161, "community": "public",
            "rw_likely": False, "sys_descr": "Cisco IOS", "sys_name": "sw01"}
    return snmp.findings(hosts, {("10.0.10.1", 161): {**base, **pr}})


def test_arp_naming_undiscovered_hosts_is_high_and_lists_them():
    """The pivot value: neighbours recce has never scanned are free discovery."""
    fs = _findings({"arp": [{"ip": "10.0.10.1", "mac": "00:50:56:aa:bb:cc", "ifindex": 1},
                            {"ip": "10.0.10.77", "mac": "de:ad:be:ef:00:01", "ifindex": 1},
                            {"ip": "192.168.99.5", "mac": "00:0c:29:ff:ee:dd", "ifindex": 2}]})
    f = next(f for f in fs if f["kind"] == "snmp_arp")
    assert f["severity"] == "high"
    assert "10.0.10.77" in f["detail"] and "192.168.99.5" in f["detail"]
    assert "NOT in this engagement" in f["detail"]


def test_arp_of_only_known_hosts_is_disclosure_not_discovery():
    fs = _findings({"arp": [{"ip": "10.0.10.1", "mac": "00:50:56:aa:bb:cc", "ifindex": 1}]})
    f = next(f for f in fs if f["kind"] == "snmp_arp")
    assert f["severity"] == "medium"
    assert "already known" in f["detail"]


def test_routing_table_finding_names_the_segments():
    fs = _findings({"routes": [
        {"dest": "0.0.0.0", "next_hop": "10.0.10.1", "mask": "0.0.0.0"},
        {"dest": "192.168.99.0", "next_hop": "10.0.10.254", "mask": "255.255.255.0"}]})
    f = next(f for f in fs if f["kind"] == "snmp_routes")
    assert "192.168.99.0/255.255.255.0" in f["detail"]
    assert "2 gateway(s)" in f["detail"]


def test_no_tables_means_no_table_findings():
    kinds = {f["kind"] for f in _findings({})}
    assert "snmp_arp" not in kinds and "snmp_routes" not in kinds


def test_table_findings_map_to_vulns():
    fs = _findings({"arp": [{"ip": "10.9.9.9", "mac": "00:11:22:33:44:55", "ifindex": 1}]})
    v = snmp.findings_to_vulns([f for f in fs if f["kind"] == "snmp_arp"])
    vuln = v["10.0.10.1"][0]
    assert vuln.source == "snmp" and vuln.port == 161
