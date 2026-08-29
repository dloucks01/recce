"""NTP (123/udp): monlist, mode-6 disclosure, peer list, Kerberos clock skew.

The fixtures here are built from the WIRE FORMATS (RFC 5905 for the time packet,
RFC 1305 App. B for the mode-6 control header, the ntpd mode-7 private request
layout) using raw struct/bytes — deliberately NOT from recce's own encoders.
A fixture built with the encoder under test can only prove the codec is
self-consistent; a wrong field offset or tag would be symmetric and invisible.
"""
from __future__ import annotations

import socket
import struct
import threading
import time

from recce.core.models import Host, Port
from recce.services import ntp

_NTP_EPOCH_DELTA = 2208988800


def _time_reply(skew: float = 0.0, stratum: int = 3, refid=b"\x0a\x01\x01\x01") -> bytes:
    """RFC 5905 server packet: LI/VN/Mode byte, stratum, refid, transmit stamp."""
    now = time.time() + skew + _NTP_EPOCH_DELTA
    p = bytearray(48)
    p[0] = (0 << 6) | (4 << 3) | 4          # LI=0, VN=4, Mode=4 (server)
    p[1] = stratum
    p[12:16] = refid
    p[40:48] = struct.pack("!II", int(now), int((now % 1) * 2**32))
    return bytes(p)


# A real ntpq readvar response: 12-byte control header then ASCII k=v pairs.
_READVAR = (bytes([(2 << 3) | 6, 0x82]) + struct.pack("!HHHHH", 1, 0, 0, 0, 0x50)
            + b'version="ntpd 4.2.6p5@1.2349-o Fri Jul 22", processor="x86_64", '
              b'system="Linux/3.10.0-1160.el7", leap=0, stratum=3')


def _monlist_reply(seq: int) -> bytes:
    """mode-7 response carrying monitor entries — the payload IS the amplification."""
    hdr = bytes([0x97, 0x00, 0x03, 0x2a, 0x00, 0x06, 0x00, seq])
    return hdr + bytes([10, 0, 0, seq]) * 90


class _FakeNtpd(threading.Thread):
    """A UDP responder that answers each NTP mode differently, like a real ntpd."""
    daemon = True

    def __init__(self, *, skew=0.0, monlist=True, mode6=True, peers=False, stratum=3):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]
        self.skew, self.monlist, self.mode6 = skew, monlist, mode6
        self.peers, self.stratum = peers, stratum

    def run(self):
        end = time.time() + 5
        while time.time() < end:
            try:
                data, addr = self.sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return
            if not data:
                return
            mode = data[0] & 0x07
            if mode == 3:
                self.sock.sendto(_time_reply(self.skew, self.stratum), addr)
            elif mode == 6 and self.mode6:
                self.sock.sendto(_READVAR, addr)
            elif mode == 7:
                req = data[3]
                if req == 42 and self.monlist:
                    for i in range(4):
                        self.sock.sendto(_monlist_reply(i), addr)
                elif req == 0 and self.peers:
                    self.sock.sendto(bytes([0x97, 0, 3, 0]) + b"\x01" * 120, addr)

    def stop(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _probe(**kw):
    srv = _FakeNtpd(**kw)
    srv.start()
    time.sleep(0.15)
    try:
        return ntp.probe("127.0.0.1", srv.port, timeout=1.5)
    finally:
        srv.stop()


def _findings(pr):
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=123, protocol="udp", state="open", service="ntp")])
    return ntp.findings([h], {("10.0.0.5", 123): pr})


# --- detection ----------------------------------------------------------------

def test_is_ntp_matches_port_and_service_without_false_positives():
    assert ntp.is_ntp(Port(portid=123, protocol="udp", state="open", service="ntp"))
    assert ntp.is_ntp(Port(portid=123, protocol="udp", state="open", service=""))
    assert not ntp.is_ntp(Port(portid=80, state="open", service="http"))
    assert not ntp.is_ntp(Port(portid=443, state="open", service="https"))


# --- decoding real wire bytes -------------------------------------------------

def test_probe_decodes_time_packet_fields():
    pr = _probe(stratum=2)
    assert pr["reachable"] is True
    assert pr["stratum"] == 2
    assert pr["mode"] == 4 and pr["version"] == 4
    assert pr["refid"] == "10.1.1.1"
    assert abs(pr["skew"]) < 2          # our own clock, so ~0


def test_probe_reads_mode6_version_and_os():
    pr = _probe()
    assert pr["mode6"] is True
    assert pr["ntpd_version"] == "4.2.6p5"          # parsed out of the version string
    assert pr["sysinfo"]["processor"] == "x86_64"
    assert pr["sysinfo"]["system"] == "Linux/3.10.0-1160.el7"


def test_probe_measures_monlist_amplification():
    pr = _probe()
    assert pr["monlist"] is True
    assert pr["monlist_packets"] >= 2
    # The point of the finding is the ratio, not merely that it answered.
    assert pr["amplification"] > 5


def test_hardened_server_answers_time_only():
    """A patched ntpd still serves time. It must produce no findings at all —
    a false monlist/mode6 positive would put a CVE in a client report."""
    pr = _probe(monlist=False, mode6=False)
    assert pr["reachable"] is True
    assert not pr.get("monlist") and not pr.get("mode6")
    assert _findings(pr) == []


# --- findings -----------------------------------------------------------------

def test_monlist_finding_is_high_and_cites_the_cve():
    fs = _findings({"reachable": True, "monlist": True, "monlist_packets": 6,
                    "monlist_bytes": 5400, "amplification": 112.5})
    f = next(f for f in fs if f["kind"] == "ntp_monlist")
    assert f["severity"] == "high"
    assert "CVE-2013-5211" in f["title"]
    assert "112.5x" in f["detail"] or "112.5" in f["detail"]


def test_mode6_finding_reports_version_and_os():
    fs = _findings({"reachable": True, "mode6": True, "ntpd_version": "4.2.6p5",
                    "sysinfo": {"system": "Linux/3.10.0", "processor": "x86_64"}})
    f = next(f for f in fs if f["kind"] == "ntp_mode6")
    assert "4.2.6p5" in f["detail"] and "Linux/3.10.0" in f["detail"]


def test_clock_skew_beyond_kerberos_tolerance_is_flagged():
    """The engagement-facing finding: a DC outside the 5-minute MS-KILE window
    makes kerberoasting fail in a way that looks like the attack is broken."""
    fs = _findings({"reachable": True, "skew": -671.0})
    f = next(f for f in fs if f["kind"] == "ntp_skew")
    assert f["severity"] == "medium"
    assert "Kerberos" in f["detail"]
    # Inside the window must NOT fire — every host drifts a little.
    assert not [x for x in _findings({"reachable": True, "skew": 42.0})
                if x["kind"] == "ntp_skew"]


def test_peer_list_only_fires_when_monlist_did_not():
    """monlist already dumps far more; a second finding for peers is noise."""
    assert [f for f in _findings({"reachable": True, "peer_list": True})
            if f["kind"] == "ntp_peers"]
    assert not [f for f in _findings({"reachable": True, "peer_list": True,
                                      "monlist": True})
                if f["kind"] == "ntp_peers"]


def test_unreachable_host_produces_nothing():
    assert _findings({"reachable": False}) == []


# --- plumbing -----------------------------------------------------------------

def test_findings_map_to_vulns_on_the_udp_port():
    v = ntp.findings_to_vulns(_findings(
        {"reachable": True, "monlist": True, "monlist_packets": 4,
         "monlist_bytes": 3600, "amplification": 75.0}))
    vuln = v["10.0.0.5"][0]
    assert vuln.source == "ntp" and vuln.port == 123
    assert vuln.severity == "high"


def test_analyze_returns_the_standard_service_shape():
    h = Host(ip="10.0.0.5",
             ports=[Port(portid=123, protocol="udp", state="open", service="ntp")])
    res = ntp.analyze([h], active=False)
    assert set(res) >= {"targets", "findings", "runbooks", "probes", "stats"}
    assert res["stats"]["targets"] == 1
    assert res["runbooks"] and res["runbooks"][0]["credfree"]


def test_runbook_covers_the_offensive_paths():
    cmds = " ".join(s["command"] for s in ntp.runbook("10.0.0.5"))
    assert "monlist" in cmds          # CVE-2013-5211
    assert "readvar" in cmds          # mode-6 disclosure
    assert "ntpdate" in cmds          # sync before Kerberos work


# --- monlist / peer_list wire parsing -----------------------------------------

def _mode7_response(req_code: int, records: list[bytes], seq: int = 0) -> bytes:
    """Build a mode-7 response with N info_* records, matching ntpd's layout.

    Header (8 bytes): 0x97, seq, impl=3, req_code, err|numitems(12b),
    mbz|itemsize(12b). All records must be the same size — that is what
    itemsize is for.
    """
    assert records, "the layout needs at least one record for itemsize"
    itemsize = len(records[0])
    assert all(len(r) == itemsize for r in records), "records must be uniform"
    numitems = len(records)
    # low 12 bits of the u16
    ni_hi, ni_lo = (numitems >> 8) & 0x0f, numitems & 0xff
    is_hi, is_lo = (itemsize >> 8) & 0x0f, itemsize & 0xff
    hdr = bytes([0x97, seq & 0x7f, 0x03, req_code, ni_hi, ni_lo, is_hi, is_lo])
    return hdr + b"".join(records)


def _info_monitor_1(addr: bytes, count: int = 1, v6: bool = False) -> bytes:
    """72-byte info_monitor_1 record: v4 addr at offset 16, v6_flag at 32."""
    rec = bytearray(72)
    struct.pack_into("!I", rec, 12, count)             # count
    if not v6:
        rec[16:20] = addr                              # addr (v4)
    else:
        struct.pack_into("!I", rec, 32, 1)             # v6_flag=1
        rec[40:56] = addr                              # addr6
    return bytes(rec)


def _info_peer_list(addr: bytes, v6: bool = False) -> bytes:
    """32-byte info_peer_list record: v4 addr at offset 0, v6_flag at 8."""
    rec = bytearray(32)
    if not v6:
        rec[0:4] = addr
    else:
        struct.pack_into("!I", rec, 8, 1)
        rec[16:32] = addr
    return bytes(rec)


def test_parse_mon_entries_pulls_client_ipv4s():
    r = _mode7_response(42, [
        _info_monitor_1(bytes([10, 0, 0, 5])),
        _info_monitor_1(bytes([10, 0, 0, 6])),
        _info_monitor_1(bytes([10, 0, 0, 5])),     # dupe
    ])
    assert ntp._parse_mon_entries([r]) == ["10.0.0.5", "10.0.0.6"]


def test_parse_mon_entries_skips_v6_records():
    """v6_flag=1 means the v4 slot is unpopulated — we must not emit 0.0.0.0
    or read a mangled v6 prefix into an IPv4 dotted-quad."""
    r = _mode7_response(42, [
        _info_monitor_1(b"\x20\x01\x0d\xb8" + b"\x00" * 12, v6=True),
        _info_monitor_1(bytes([192, 168, 1, 1])),
    ])
    assert ntp._parse_mon_entries([r]) == ["192.168.1.1"]


def test_parse_mon_entries_ignores_non_mode7_packets():
    # A stray mode-3 reply must not be treated as monitor records.
    assert ntp._parse_mon_entries([_time_reply()]) == []


def test_parse_peer_entries_pulls_upstream_ipv4s():
    r = _mode7_response(0, [
        _info_peer_list(bytes([172, 16, 0, 10])),
        _info_peer_list(bytes([172, 16, 0, 11])),
    ])
    assert ntp._parse_peer_entries([r]) == ["172.16.0.10", "172.16.0.11"]


def test_probe_extracts_mon_clients_from_a_real_wire_response():
    """End-to-end through the socket — the responder speaks a proper
    info_monitor_1 layout and probe() surfaces the extracted client list."""

    class _Responder(_FakeNtpd):
        def run(self):
            end = time.time() + 5
            while time.time() < end:
                try:
                    data, addr = self.sock.recvfrom(4096)
                except (socket.timeout, OSError):
                    return
                if not data:
                    return
                mode = data[0] & 0x07
                if mode == 3:
                    self.sock.sendto(_time_reply(0.0, 3), addr)
                elif mode == 7 and data[3] == 42:
                    self.sock.sendto(_mode7_response(42, [
                        _info_monitor_1(bytes([10, 0, 0, 5]), count=42),
                        _info_monitor_1(bytes([10, 0, 0, 6]), count=17),
                        _info_monitor_1(bytes([10, 0, 0, 7]), count=3),
                    ]), addr)

    srv = _Responder(monlist=True, mode6=False)
    srv.start()
    time.sleep(0.15)
    try:
        pr = ntp.probe("127.0.0.1", srv.port, timeout=1.5)
    finally:
        srv.stop()
    assert pr["monlist"] is True
    assert pr["mon_clients"] == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


def test_monlist_finding_names_disclosed_clients_when_parsed():
    """Report-level: the finding must surface the client IPs so a reader
    doesn't have to open the probe JSON to see what was disclosed."""
    fs = _findings({"reachable": True, "monlist": True, "monlist_packets": 6,
                    "monlist_bytes": 5400, "amplification": 112.5,
                    "mon_clients": ["10.0.0.5", "10.0.0.6", "10.0.0.7"]})
    f = next(f for f in fs if f["kind"] == "ntp_monlist")
    assert "10.0.0.5" in f["detail"]
    assert "10.0.0.7" in f["detail"]
    assert "3" in f["detail"]         # count


def test_monlist_finding_truncates_very_long_client_lists():
    ips = [f"10.0.1.{i}" for i in range(1, 21)]
    fs = _findings({"reachable": True, "monlist": True, "monlist_packets": 6,
                    "monlist_bytes": 5400, "amplification": 112.5,
                    "mon_clients": ips})
    f = next(f for f in fs if f["kind"] == "ntp_monlist")
    # First eight named, and a "+more" hint rather than a wall of IPs.
    assert "10.0.1.1" in f["detail"] and "10.0.1.8" in f["detail"]
    assert "10.0.1.20" not in f["detail"]
    assert "more" in f["detail"]


# --- ntpd version -> CVE cross-check ------------------------------------------

def test_parse_ntpd_version_handles_patchset_suffix():
    assert ntp._parse_ntpd_version("4.2.6p5") == (4, 2, 6, 5)
    assert ntp._parse_ntpd_version("4.2.8") == (4, 2, 8, 0)
    assert ntp._parse_ntpd_version("4.2.8p11") == (4, 2, 8, 11)
    assert ntp._parse_ntpd_version("garbage") is None


def test_cve_gate_flags_legacy_ntpd():
    """4.2.6p5 pre-dates every fix in the table — it must hit the crypto_recv
    RCE-class critical CVE alongside the NAK-bypass and mrulist DoS gates."""
    hits = ntp._ntpd_cve_gate("4.2.6p5")
    ids = [c[0] for c in hits]
    assert "CVE-2014-9295" in ids
    assert "CVE-2015-7871" in ids
    assert "CVE-2016-7431" in ids
    assert "CVE-2018-7182" in ids
    # Severity of the worst hit is critical (crypto_recv stack overflow).
    assert any(sev == "critical" for _, sev, _ in hits)


def test_cve_gate_stays_quiet_on_current_ntpd():
    """A current 4.2.8p17 must NOT fire any of these gates — every entry has
    been fixed by that patchset."""
    assert ntp._ntpd_cve_gate("4.2.8p17") == []


def test_cve_gate_stays_quiet_on_unparseable_version():
    """Refuse to invent a CVE claim when we can't actually decode the banner."""
    assert ntp._ntpd_cve_gate("chrony 4.3") == []
    assert ntp._ntpd_cve_gate("") == []


def test_version_cve_finding_emitted_for_vulnerable_ntpd():
    fs = _findings({"reachable": True, "mode6": True, "ntpd_version": "4.2.6p5",
                    "sysinfo": {}})
    f = next(f for f in fs if f["kind"] == "ntp_version_cve")
    assert f["severity"] == "critical"           # crypto_recv RCE-class
    assert "CVE-2014-9295" in f["detail"]
    assert "CVE-2015-7871" in f["detail"]
    assert "ids" in f and "CVE-2014-9295" in f["ids"]


def test_version_cve_finding_not_emitted_for_current_ntpd():
    fs = _findings({"reachable": True, "mode6": True, "ntpd_version": "4.2.8p17",
                    "sysinfo": {}})
    assert not [f for f in fs if f["kind"] == "ntp_version_cve"]


def test_probe_extracts_peer_ipv4s_from_wire():
    class _Responder(_FakeNtpd):
        def run(self):
            end = time.time() + 5
            while time.time() < end:
                try:
                    data, addr = self.sock.recvfrom(4096)
                except (socket.timeout, OSError):
                    return
                if not data:
                    return
                mode = data[0] & 0x07
                if mode == 3:
                    self.sock.sendto(_time_reply(0.0, 3), addr)
                elif mode == 7 and data[3] == 0:
                    self.sock.sendto(_mode7_response(0, [
                        _info_peer_list(bytes([172, 16, 0, 10])),
                        _info_peer_list(bytes([172, 16, 0, 11])),
                    ]), addr)

    srv = _Responder(mode6=False, monlist=False, peers=True)
    srv.start()
    time.sleep(0.15)
    try:
        pr = ntp.probe("127.0.0.1", srv.port, timeout=1.5)
    finally:
        srv.stop()
    assert pr.get("peer_list") is True
    assert pr.get("peers") == ["172.16.0.10", "172.16.0.11"]
