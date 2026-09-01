"""core.known_ntlm_endpoints: catalog of NTLM-speaking non-SMB listeners.

The reader is exercised standalone; two integration tests wire pop3 and
imap analyze() through stubbed probes to prove the producer wires only
fire when NTLM is actually advertised.
"""
from __future__ import annotations

from recce.core.known_ntlm_endpoints import (known_ntlm_endpoints,
                                             ntlm_endpoints_for,
                                             record_ntlm_endpoint)
from recce.core.models import Host, Port


# --- record_ntlm_endpoint ---------------------------------------------------

def test_record_attaches_and_reads_back():
    h = Host(ip="10.0.0.10")
    record_ntlm_endpoint(h, "10.0.0.10", 110, "pop3", source="pop3:capa-sasl")
    got = ntlm_endpoints_for(h)
    assert len(got) == 1
    assert got[0]["port"] == 110
    assert got[0]["protocol"] == "pop3"
    assert got[0]["sources"] == ["pop3:capa-sasl"]


def test_record_normalises_protocol_case():
    h = Host(ip="10.0.0.10")
    record_ntlm_endpoint(h, "10.0.0.10", 143, "IMAP")
    assert ntlm_endpoints_for(h)[0]["protocol"] == "imap"


def test_record_is_idempotent_but_merges_sources():
    h = Host(ip="10.0.0.10")
    record_ntlm_endpoint(h, "10.0.0.10", 143, "imap", source="first")
    record_ntlm_endpoint(h, "10.0.0.10", 143, "imap", source="second")
    got = ntlm_endpoints_for(h)
    assert len(got) == 1
    assert got[0]["sources"] == ["first", "second"]


def test_record_records_second_endpoint_on_different_port():
    h = Host(ip="10.0.0.10")
    record_ntlm_endpoint(h, "10.0.0.10", 110, "pop3")
    record_ntlm_endpoint(h, "10.0.0.10", 995, "pop3")
    ports = sorted(e["port"] for e in ntlm_endpoints_for(h))
    assert ports == [110, 995]


def test_record_silently_drops_empty_protocol():
    h = Host(ip="10.0.0.10")
    record_ntlm_endpoint(h, "10.0.0.10", 110, "")
    record_ntlm_endpoint(h, "10.0.0.10", 110, "   ")
    assert ntlm_endpoints_for(h) == []


# --- engagement-wide reader -------------------------------------------------

def test_known_ntlm_endpoints_unions_and_groups_by_protocol():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_ntlm_endpoint(a, "10.0.0.10", 110, "pop3")
    record_ntlm_endpoint(a, "10.0.0.10", 143, "imap")
    record_ntlm_endpoint(b, "10.0.0.20", 143, "imap")
    got = known_ntlm_endpoints([a, b])
    assert got["count"] == 3
    assert {(e["ip"], e["port"], e["protocol"]) for e in got["endpoints"]} == {
        ("10.0.0.10", 110, "pop3"),
        ("10.0.0.10", 143, "imap"),
        ("10.0.0.20", 143, "imap"),
    }
    assert len(got["by_protocol"]["imap"]) == 2
    assert got["by_protocol"]["pop3"] == [{"ip": "10.0.0.10", "port": 110}]


# --- producer wires ---------------------------------------------------------

def test_pop3_analyze_wires_ntlm_endpoint_when_ntlm_advertised(monkeypatch):
    from recce.services import pop3, svcprobe

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=110, protocol="tcp", state="open", service="pop3")]

    fake_pr = {"reachable": True, "banner": "+OK ready", "apop_timestamp": "",
               "capa": {}, "sasl": ["PLAIN", "NTLM"], "stls": False,
               "plaintext_auth": "unknown"}

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)
    pop3.analyze([h], active=True)
    got = known_ntlm_endpoints([h])
    assert got["count"] == 1
    assert got["endpoints"][0]["protocol"] == "pop3"


def test_pop3_analyze_skips_when_ntlm_not_advertised(monkeypatch):
    from recce.services import pop3, svcprobe

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=110, protocol="tcp", state="open", service="pop3")]

    fake_pr = {"reachable": True, "banner": "+OK ready", "apop_timestamp": "",
               "capa": {}, "sasl": ["PLAIN"], "stls": False,
               "plaintext_auth": "unknown"}

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)
    pop3.analyze([h], active=True)
    assert known_ntlm_endpoints([h])["count"] == 0


def test_imap_analyze_wires_ntlm_endpoint_when_auth_ntlm_advertised(monkeypatch):
    from recce.services import imap, svcprobe

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=143, protocol="tcp", state="open", service="imap")]

    fake_pr = {"reachable": True, "banner": "* OK ready",
               "capabilities": ["IMAP4rev1", "AUTH=NTLM"],
               "starttls": False, "logindisabled": False,
               "sasl": ["NTLM"], "id": {}, "preauth": False,
               "plaintext_login": "unknown", "anonymous": False,
               "starttls_downgrade": False}

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)
    imap.analyze([h], active=True)
    got = known_ntlm_endpoints([h])
    assert got["count"] == 1
    assert got["endpoints"][0]["protocol"] == "imap"
    assert got["endpoints"][0]["port"] == 143
