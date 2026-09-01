"""core.known_bacnet_networks: BBMD topology (Broadcast-Distribution-Table
peer entries) captured from BACnet BVLC Read-BDT (ASHRAE 135 clause J.4)."""
from __future__ import annotations

from recce.core.known_bacnet_networks import (bacnet_networks_for,
                                              known_bacnet_networks,
                                              record_bacnet_network)
from recce.core.models import Host, Port


# --- record_bacnet_network --------------------------------------------------

def test_record_attaches_and_reads_back():
    h = Host(ip="10.0.0.10")
    record_bacnet_network(h, "10.0.0.10", 47808,
                          "10.0.1.5", 47808, mask="255.255.255.255")
    got = bacnet_networks_for(h)
    assert len(got) == 1
    assert got[0]["bdt_peer"] == "10.0.1.5"
    assert got[0]["bdt_port"] == 47808
    assert got[0]["mask"] == "255.255.255.255"
    assert got[0]["source"] == "bacnet:read-bdt"


def test_record_is_idempotent_on_same_peer():
    h = Host(ip="10.0.0.10")
    record_bacnet_network(h, "10.0.0.10", 47808, "10.0.1.5", 47808)
    record_bacnet_network(h, "10.0.0.10", 47808, "10.0.1.5", 47808)
    assert len(bacnet_networks_for(h)) == 1


def test_record_distinct_peers_recorded_separately():
    h = Host(ip="10.0.0.10")
    record_bacnet_network(h, "10.0.0.10", 47808, "10.0.1.5", 47808)
    record_bacnet_network(h, "10.0.0.10", 47808, "10.0.2.5", 47808)
    peers = sorted(e["bdt_peer"] for e in bacnet_networks_for(h))
    assert peers == ["10.0.1.5", "10.0.2.5"]


def test_record_silently_drops_empty_peer():
    h = Host(ip="10.0.0.10")
    record_bacnet_network(h, "10.0.0.10", 47808, "", 47808)
    record_bacnet_network(h, "10.0.0.10", 47808, "  ", 47808)
    assert bacnet_networks_for(h) == []


# --- engagement-wide reader -------------------------------------------------

def test_known_bacnet_networks_groups_by_self_ip():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_bacnet_network(a, "10.0.0.10", 47808, "10.0.1.5", 47808)
    record_bacnet_network(a, "10.0.0.10", 47808, "10.0.2.5", 47808)
    record_bacnet_network(b, "10.0.0.20", 47808, "10.0.3.5", 47808)
    got = known_bacnet_networks([a, b])
    assert len(got["networks"]) == 3
    assert len(got["by_ip"]["10.0.0.10"]) == 2
    assert got["by_ip"]["10.0.0.20"] == [
        {"bdt_peer": "10.0.3.5", "bdt_port": 47808}]
    assert got["ips"] == ["10.0.0.10", "10.0.0.20"]


# --- producer wire: bacnet.analyze() ---------------------------------------

def test_bacnet_analyze_wires_bdt_entries(monkeypatch):
    from recce.services import bacnet, svcprobe

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=47808, protocol="udp", state="open",
                    service="bacnet")]

    fake_pr = {
        "reachable": True, "device_instance": 123, "vendor_id": 42,
        "identity": {"vendor_name": "Trane", "model_name": "SC",
                     "firmware_revision": "4.30.1052"},
        "object_list": [], "bdt": [
            {"ip": "10.0.1.5", "port": 47808, "mask": "255.255.255.255"},
            {"ip": "10.0.2.5", "port": 47808, "mask": "255.255.255.255"},
        ], "fdt": [], "bdt_peers_live": [], "amplification": None,
        "write_dryrun": None, "dcc": None, "reinit": None,
        "atomic_files": [], "foreign_reg": None,
    }

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)
    bacnet.analyze([h], active=True)

    got = known_bacnet_networks([h])
    peers = sorted(e["bdt_peer"] for e in got["networks"])
    assert peers == ["10.0.1.5", "10.0.2.5"]
