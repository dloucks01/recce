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
