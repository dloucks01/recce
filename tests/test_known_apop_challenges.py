"""creds.known_apop_challenges: cross-service POP3 APOP challenge reader.

Fixtures build APOP timestamp strings in the exact `<pid.time@host>`
wire format RFC 1939 §7 requires — no imports from pop3.py so the reader
is exercised standalone. One integration test wires
`pop3.analyze()` through a stubbed probe to prove the producer end
records the captured timestamp against the host.
"""
from __future__ import annotations

from recce.core.models import Host, Port
from recce.creds.known_apop_challenges import (apop_challenges_for,
                                               known_apop_challenges,
                                               record_apop_challenge)


_APOP_A = "<1896.697170952@dbc.mtview.ca.us>"
_APOP_B = "<12345.42@mail.corp.local>"


# --- record_apop_challenge --------------------------------------------------

def test_record_attaches_and_reads_back():
    h = Host(ip="10.0.0.10")
    record_apop_challenge(h, "10.0.0.10", 110, _APOP_A, "pop3")
    got = apop_challenges_for(h)
    assert len(got) == 1
    assert got[0]["timestamp"] == _APOP_A
    assert got[0]["ip"] == "10.0.0.10"
    assert got[0]["port"] == 110
    assert got[0]["first_seen_source"] == "pop3"


def test_record_is_idempotent_on_same_port_and_timestamp():
    h = Host(ip="10.0.0.10")
    record_apop_challenge(h, "10.0.0.10", 110, _APOP_A, "pop3")
    record_apop_challenge(h, "10.0.0.10", 110, _APOP_A, "pop3")
    assert len(apop_challenges_for(h)) == 1


def test_record_records_second_endpoint_on_different_port():
    h = Host(ip="10.0.0.10")
    record_apop_challenge(h, "10.0.0.10", 110, _APOP_A, "pop3")
    record_apop_challenge(h, "10.0.0.10", 995, _APOP_A, "pop3")
    ports = sorted(e["port"] for e in apop_challenges_for(h))
    assert ports == [110, 995]


def test_record_silently_drops_empty_timestamp():
    h = Host(ip="10.0.0.10")
    record_apop_challenge(h, "10.0.0.10", 110, "", "pop3")
    record_apop_challenge(h, "10.0.0.10", 110, "   ", "pop3")
    assert apop_challenges_for(h) == []


def test_apop_challenges_for_returns_copies():
    h = Host(ip="10.0.0.10")
    record_apop_challenge(h, "10.0.0.10", 110, _APOP_A, "pop3")
    got = apop_challenges_for(h)
    got[0]["timestamp"] = "<tampered>"
    assert apop_challenges_for(h)[0]["timestamp"] == _APOP_A


# --- engagement-wide reader -------------------------------------------------

def test_known_apop_challenges_unions_across_hosts():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_apop_challenge(a, "10.0.0.10", 110, _APOP_A)
    record_apop_challenge(b, "10.0.0.20", 110, _APOP_B)
    got = known_apop_challenges([a, b])
    assert got["total"] == 2
    assert set(got["ips"]) == {"10.0.0.10", "10.0.0.20"}
    assert got["by_ip"]["10.0.0.10"][0]["timestamp"] == _APOP_A
    assert got["by_ip"]["10.0.0.20"][0]["timestamp"] == _APOP_B


def test_known_apop_challenges_ignores_hosts_with_none_recorded():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_apop_challenge(a, "10.0.0.10", 110, _APOP_A)
    got = known_apop_challenges([a, b])
    assert "10.0.0.20" not in got["by_ip"]
    assert got["total"] == 1


# --- producer wire: pop3.analyze() -----------------------------------------

def test_pop3_analyze_wires_apop_capture_into_known_apop_challenges(monkeypatch):
    from recce.services import pop3, svcprobe

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=110, protocol="tcp", state="open", service="pop3")]

    fake_pr = {"reachable": True, "banner": "+OK POP3 ready",
               "apop_timestamp": _APOP_A, "capa": {}, "sasl": [],
               "stls": False, "plaintext_auth": "unknown"}

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)
    pop3.analyze([h], active=True)

    got = known_apop_challenges([h])
    assert got["total"] == 1
    assert got["by_ip"]["10.0.0.10"][0]["timestamp"] == _APOP_A
