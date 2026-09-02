"""hrSWRunParameters credential capture: SNMP walk of process argv turns a
read-only community from generic inventory into a real credential leak.

RFC 2790 §5.3.4 defines hrSWRunParameters (1.3.6.1.2.1.25.4.2.1.5) as the
argv of every running process. Argv is world-readable on the host
(/proc/*/cmdline), so anyone with a working community reads it too. When a
row matches _cmdline_looks_credful() the finding fires - patched hosts
(clean argv) produce no finding.

Coverage:
  (a) vulnerable: process_params contains 'mysql -pSecret123' -> finding
      snmp_cmdline_creds emitted, depth_tier=t2, exploit_note set.
  (b) patched/absent: process_params clean OR missing -> no finding.
  (c) probe() end-to-end via a local fake SNMPv2c agent: hrSWRunParameters
      walked and rows land as pr["process_params"].
"""
from __future__ import annotations

import socket
import threading
import time

from recce.core.models import Host, Port
from recce.services import snmp

_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_HR_SW_RUN_PARAMS = "1.3.6.1.2.1.25.4.2.1.5"


# --- hand-rolled BER (RFC 1157/1213) so a decoder bug can't be masked by a
#     symmetric encoder bug in the fixture --------------------------------------

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


# --- (a)/(b) findings() unit tests: synthesize a probe result -----------------

def _findings(pr_extra):
    hosts = [Host(ip="10.0.10.1", ports=[Port(portid=161, protocol="udp",
                                              state="open", service="snmp")])]
    base = {"ip": "10.0.10.1", "port": 161, "community": "public",
            "rw_likely": False, "sys_descr": "Linux dbhost 5.15",
            "sys_name": "dbhost"}
    return snmp.findings(hosts, {("10.0.10.1", 161): {**base, **pr_extra}})


def test_credful_cmdline_emits_finding_and_is_t2():
    """Vulnerable: argv carries a cleartext secret -> snmp_cmdline_creds fires
    with depth_tier=t2, medium severity, exploit_note from audit. Two of
    three rows match _cmdline_looks_credful() (PGPASSWORD= is a direct
    'password' substring hit; 'curl -u ' is a tool+flag hit)."""
    fs = _findings({"process_params": [
        "/usr/sbin/sshd -D",                                # clean
        "PGPASSWORD=S3cret! psql -h db -U app",             # credful (password=)
        "curl -u admin:hunter2 https://api/int",            # credful (curl -u )
    ]})
    f = next(f for f in fs if f["kind"] == "snmp_cmdline_creds")
    assert f["severity"] == "medium"
    assert f["depth_tier"] == "t2"
    assert "hrSWRunParameters" in f["detail"]
    assert "2 process command line(s)" in f["detail"]
    assert "PGPASSWORD" in f["detail"]                      # sample echoed
    assert "sshd" not in f["detail"]                        # clean row not echoed
    assert "hrSWRunParameters" in f["exploit_note"]
    assert "CWE-214" in f["cwes"]


def test_clean_cmdlines_produce_no_finding():
    """Patched: every argv is benign (no mysql -p, no curl -u, no password=)
    -> _cmdline_looks_credful() rejects them all, no finding is emitted."""
    fs = _findings({"process_params": [
        "/usr/sbin/sshd -D",
        "/usr/bin/python3 /opt/app/server.py --port 8080",
        "nginx: worker process",
        "/bin/bash /etc/init.d/foo start",
    ]})
    kinds = {f["kind"] for f in fs}
    assert "snmp_cmdline_creds" not in kinds


def test_missing_process_params_produces_no_finding():
    """Absent field (older probe result / view restricted) -> no finding."""
    fs = _findings({})                                      # no process_params key
    kinds = {f["kind"] for f in fs}
    assert "snmp_cmdline_creds" not in kinds


def test_empty_process_params_produces_no_finding():
    fs = _findings({"process_params": []})
    kinds = {f["kind"] for f in fs}
    assert "snmp_cmdline_creds" not in kinds


def test_credful_finding_maps_to_vuln():
    """Round-trips through findings_to_vulns() cleanly."""
    fs = _findings({"process_params": ["PGPASSWORD=hunter2 psql -h db -U app"]})
    creds = [f for f in fs if f["kind"] == "snmp_cmdline_creds"]
    v = snmp.findings_to_vulns(creds)
    vuln = v["10.0.10.1"][0]
    assert vuln.source == "snmp"
    assert vuln.port == 161
    assert vuln.severity == "medium"


# --- (c) probe() end-to-end: fake agent answers GETNEXT of hrSWRunParameters --

def _mib_with_params(params: list[str]) -> list[tuple[str, bytes]]:
    """Assemble an ordered MIB: sysDescr + one hrSWRunParameters row per param."""
    rows: list[tuple[str, bytes]] = [
        (_SYS_DESCR, _tlv(0x04, b"Linux dbhost 5.15")),
    ]
    # hrSWRunParameters rows are indexed by PID; use 1000+i so ordering is stable.
    for i, p in enumerate(params):
        rows.append((f"{_HR_SW_RUN_PARAMS}.{1000 + i}", _tlv(0x04, p.encode())))
    rows.sort(key=lambda kv: [int(a) for a in kv[0].split(".")])
    return rows


class _FakeAgent(threading.Thread):
    """Minimal SNMPv2c agent that answers GET (0xA0) and GETNEXT (0xA1)."""
    daemon = True

    def __init__(self, mib):
        super().__init__()
        self.mib = mib
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(20)
        self.port = self.sock.getsockname()[1]

    @staticmethod
    def _reply(rid: int, community: bytes, oid: str, blob: bytes) -> bytes:
        vb = _tlv(0x30, _oid(oid) + blob)
        pdu = _tlv(0xA2, _int(rid) + _int(0) + _int(0) + _tlv(0x30, vb))
        return _tlv(0x30, _int(1) + _tlv(0x04, community) + pdu)

    def run(self) -> None:
        # Full probe() sequence walks users, processes, software, params +
        # sysObjectID GET + v3 discovery + 3 sys_* GETs; missing OIDs each
        # spend up to `timeout` seconds waiting. Give the agent a generous
        # wall so hrSWRunParameters is still reachable at the tail.
        end = time.time() + 20
        while time.time() < end:
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            try:
                _, msg, _ = snmp._parse_tlv(data, 0)
                _, _v, i = snmp._parse_tlv(msg, 0)
                _, comm_b, i = snmp._parse_tlv(msg, i)
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
            if ptag == 0xA1:                                # GETNEXT
                hit = next((kv for kv in self.mib
                            if [int(a) for a in kv[0].split(".")] > key), None)
            else:                                           # GET
                hit = next((kv for kv in self.mib if kv[0] == req), None)
            if hit:
                self.sock.sendto(self._reply(rid, comm_b, hit[0], hit[1]), addr)

    def stop(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def _agent(mib):
    a = _FakeAgent(mib)
    a.start()
    time.sleep(0.15)
    return a


def test_probe_walks_hrswrunparameters_into_process_params():
    """End-to-end: probe() finds community 'public' via sysDescr, then the
    added hrSWRunParameters walk collects argv rows into pr['process_params']."""
    mib = _mib_with_params([
        "/usr/sbin/sshd -D",
        "mysql -uroot -pS3cret! -h db",
        "nginx: worker process",
    ])
    a = _agent(mib)
    try:
        pr = snmp.probe("127.0.0.1", a.port, timeout=1.0)
    finally:
        a.stop()
    assert pr is not None
    assert pr["community"] == "public"
    params = pr.get("process_params") or []
    # All three rows should have been captured; order matches MIB order.
    assert "/usr/sbin/sshd -D" in params
    assert "mysql -uroot -pS3cret! -h db" in params
    assert "nginx: worker process" in params


def test_probe_process_params_empty_when_view_restricted():
    """Patched: agent answers sysDescr but the hrSWRunParameters subtree is
    empty (view restriction). Walk returns [], no finding gets emitted."""
    mib = [(_SYS_DESCR, _tlv(0x04, b"Linux dbhost 5.15"))]
    a = _agent(mib)
    try:
        pr = snmp.probe("127.0.0.1", a.port, timeout=0.5)
    finally:
        a.stop()
    assert pr is not None
    assert pr["community"] == "public"
    assert pr.get("process_params") == []
    # And findings() sees no credful entries -> no snmp_cmdline_creds finding.
    hosts = [Host(ip="127.0.0.1", ports=[Port(portid=161, protocol="udp",
                                              state="open", service="snmp")])]
    pr2 = {**pr, "ip": "127.0.0.1"}
    fs = snmp.findings(hosts, {("127.0.0.1", 161): pr2})
    kinds = {f["kind"] for f in fs}
    assert "snmp_cmdline_creds" not in kinds
