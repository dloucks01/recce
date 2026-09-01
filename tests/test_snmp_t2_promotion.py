"""T2 SAFE promotion for snmp_community: single controlled GET on sysObjectID.0.

RFC 1213 §6.4.2 defines sysObjectID as an OBJECT IDENTIFIER identifying the
vendor/model of the SNMP-managed device. Reading it under a discovered
community without credentials proves arbitrary unauth MIB read - not just a
probe-ACK - which is the shape T2 asks for: single controlled read returning
real server-side evidence, non-destructive, bounded timeout, no writes.

Coverage: vulnerable (evidence captured => t2), patched (community fails =>
no evidence, no finding), timeout (community works but sysObjectID read
times out => evidence stays None, finding remains T1).
"""
from __future__ import annotations

import socket
import threading
import time

from recce.core.models import Host, Port
from recce.services import snmp

_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_SYS_OBJECTID = "1.3.6.1.2.1.1.2.0"


# --- BER wire helpers: hand-rolled per RFC 1157/1213, NOT via snmp.py itself,
#     so a decoder bug can't be masked by a symmetric encoder bug in the fixture.

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


class _Agent(threading.Thread):
    """Tiny SNMPv2c agent. `mib` maps requested OID -> (tag, raw value bytes).
    `objectid_delay` sleeps before replying to sysObjectID.0 to force a timeout."""
    daemon = True

    def __init__(self, mib: dict, objectid_delay: float = 0.0,
                 objectid_silent: bool = False):
        super().__init__()
        self.mib = mib
        self.objectid_delay = objectid_delay
        self.objectid_silent = objectid_silent
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(4)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    @staticmethod
    def _reply(rid: int, community: bytes, oid: str, blob: bytes) -> bytes:
        vb = _tlv(0x30, _oid(oid) + blob)
        pdu = _tlv(0xA2, _int(rid) + _int(0) + _int(0) + _tlv(0x30, vb))
        return _tlv(0x30, _int(1) + _tlv(0x04, community) + pdu)

    def run(self) -> None:
        end = time.time() + 4
        while not self._stop and time.time() < end:
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            try:
                _, msg, _ = snmp._parse_tlv(data, 0)
                _, _v, i = snmp._parse_tlv(msg, 0)
                _, comm_b, i = snmp._parse_tlv(msg, i)
                _, pdu, _ = snmp._parse_tlv(msg, i)
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
            if req == _SYS_OBJECTID and self.objectid_silent:
                continue                                  # drop reply -> timeout
            if req == _SYS_OBJECTID and self.objectid_delay:
                time.sleep(self.objectid_delay)
            hit = self.mib.get(req)
            if hit is None:
                continue
            tag, raw = hit
            self.sock.sendto(self._reply(rid, comm_b, req, _tlv(tag, raw)), addr)

    def stop(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def _start(mib, **kw):
    a = _Agent(mib, **kw)
    a.start()
    time.sleep(0.1)
    return a


# --- capture_v2c_read_evidence ------------------------------------------------

def _oid_body(o: str) -> bytes:
    """Raw OID body bytes (no TLV header). _Agent._reply wraps its own TLV,
    so the mib table hands over just the body."""
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
    return body


def test_capture_v2c_evidence_returns_vendor_oid_from_single_get():
    """Vulnerable: agent replies with a real vendor enterprise OID."""
    mib = {_SYS_OBJECTID: (0x06, _oid_body("1.3.6.1.4.1.9.1.516"))}
    a = _start(mib)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ev = snmp.capture_v2c_read_evidence(s, "127.0.0.1", a.port, "public", 1.5)
    finally:
        a.stop()
    assert ev == {"oid": "sysObjectID.0", "value": "1.3.6.1.4.1.9.1.516"}


def test_capture_v2c_evidence_returns_none_on_timeout():
    """Community works elsewhere but sysObjectID.0 stays silent -> None, no crash."""
    mib: dict = {}                                        # nothing to answer
    a = _start(mib, objectid_silent=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ev = snmp.capture_v2c_read_evidence(s, "127.0.0.1", a.port, "public", 0.3)
    finally:
        a.stop()
    assert ev is None


def test_capture_v2c_evidence_rejects_non_oid_value():
    """Defensive: if a non-OID string comes back (broken agent), evidence is None."""
    # STRING tag 0x04 with body 'gibberish' - not an OID.
    mib = {_SYS_OBJECTID: (0x04, b"gibberish")}
    a = _start(mib)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ev = snmp.capture_v2c_read_evidence(s, "127.0.0.1", a.port, "public", 1.5)
    finally:
        a.stop()
    assert ev is None


def test_capture_v2c_evidence_no_community_short_circuits():
    """Empty community can't have been discovered - skip the extra GET."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        assert snmp.capture_v2c_read_evidence(s, "127.0.0.1", 65535, "", 1.5) is None
    finally:
        s.close()


# --- findings() promotion -----------------------------------------------------

def _finding_for(pr_extra, hosts_ips=("10.0.10.1",)):
    hosts = [Host(ip=ip, ports=[Port(portid=161, protocol="udp", state="open",
                                     service="snmp")]) for ip in hosts_ips]
    base = {"ip": "10.0.10.1", "port": 161, "community": "public",
            "rw_likely": False, "sys_descr": "Cisco IOS Software, C2960",
            "sys_name": "sw01"}
    fs = snmp.findings(hosts, {("10.0.10.1", 161): {**base, **pr_extra}})
    return next(f for f in fs if f["kind"] == "snmp_community")


def test_finding_promotes_to_t2_when_evidence_captured():
    f = _finding_for({"v2c_read_evidence":
                      {"oid": "sysObjectID.0", "value": "1.3.6.1.4.1.9.1.516"}})
    assert f["depth_tier"] == "t2"
    assert "T2 proof" in f["detail"]
    assert "1.3.6.1.4.1.9.1.516" in f["detail"]
    assert "sysDescr.0" in f["detail"] and "sysObjectID.0" in f["detail"]
    assert "Cisco IOS" in f["detail"]                     # sysDescr echoed


def test_finding_stays_t1_when_evidence_missing():
    """Timeout on sysObjectID.0 -> no evidence -> depth_tier stays empty (T1)."""
    f = _finding_for({})                                  # no v2c_read_evidence
    assert f["depth_tier"] == ""
    assert "T2 proof" not in f["detail"]


def test_rw_variant_does_not_get_t2_from_read_evidence():
    """A SET-canary would be needed for a genuine T2-for-RW; a read alone
    doesn't upgrade the RW finding. Guards against accidentally overpromising
    on the higher-severity RW branch."""
    hosts = [Host(ip="10.0.10.1", ports=[Port(portid=161, protocol="udp",
                                              state="open", service="snmp")])]
    pr = {"ip": "10.0.10.1", "port": 161, "community": "private",
          "rw_likely": True, "sys_descr": "Cisco IOS", "sys_name": "sw01",
          "v2c_read_evidence": {"oid": "sysObjectID.0",
                                "value": "1.3.6.1.4.1.9.1.516"}}
    fs = snmp.findings(hosts, {("10.0.10.1", 161): pr})
    f = next(f for f in fs if f["kind"] == "snmp_rw")
    assert f["depth_tier"] == "t1"
    assert "T2 proof" not in f["detail"]


# --- integration: probe() attaches evidence when the agent answers ------------

def test_probe_attaches_evidence_when_agent_replies():
    """End-to-end via probe(): community brute finds 'public', follow-on
    sysObjectID.0 GET captures the vendor OID and lands as v2c_read_evidence."""
    mib = {
        _SYS_DESCR: (0x04, b"Cisco IOS Software, C2960"),
        _SYS_OBJECTID: (0x06, _oid_body("1.3.6.1.4.1.9.1.516")),
    }
    a = _start(mib)
    try:
        pr = snmp.probe("127.0.0.1", a.port, timeout=1.0)
    finally:
        a.stop()
    assert pr is not None
    assert pr["community"] == "public"
    assert pr.get("v2c_read_evidence") == {
        "oid": "sysObjectID.0", "value": "1.3.6.1.4.1.9.1.516"}


def test_probe_omits_evidence_when_sysobjectid_times_out():
    """Community brute succeeds on sysDescr, but sysObjectID.0 goes silent.
    probe() must NOT crash and must NOT attach v2c_read_evidence - the T1
    path stays intact and the finding stays at its old tier."""
    mib = {_SYS_DESCR: (0x04, b"Some Router")}            # sysObjectID missing
    a = _start(mib, objectid_silent=True)
    try:
        pr = snmp.probe("127.0.0.1", a.port, timeout=0.3)
    finally:
        a.stop()
    assert pr is not None
    assert pr["community"] == "public"
    assert "v2c_read_evidence" not in pr


# --- promotion sanity: bounded timeout is applied -----------------------------

def test_t2_bounded_timeout_clamps_and_scales(monkeypatch):
    """Bounded [2, 6]s, then proxy-scaled. Guards the RULES contract."""
    # direct mode (no proxy) -> scaled() returns argument unchanged
    monkeypatch.setattr(snmp.proxy, "scaled", lambda s: s)
    assert snmp._t2_bounded_timeout(0.5) == 2.0            # clamped up
    assert snmp._t2_bounded_timeout(10.0) == 6.0           # clamped down
    assert snmp._t2_bounded_timeout(3.0) == 3.0            # inside band
    # proxied -> scaled() applies its multiplier
    monkeypatch.setattr(snmp.proxy, "scaled", lambda s: s * 2.5)
    assert snmp._t2_bounded_timeout(3.0) == 7.5
