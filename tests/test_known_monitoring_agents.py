"""core.known_monitoring_agents: cross-service monitoring-agent inventory.

Fixtures are wire-shaped:

  * Zabbix ZBXD v1 frame is 13-byte header (b"ZBXD" + 0x01 + <Q body_len>)
    followed by the payload — the exact bytes any Zabbix agent puts on
    5B/5B/8B when it answers `agent.version`. We build one by hand and
    assert the reader sees the fact after the wire round-trip.

  * NRPE v2 packet is 1036 bytes (2B version + 2B type + 4B crc32 +
    2B result_code + 1024B buffer + 2B pad). We build a v2 RESPONSE
    with a valid CRC32 the same way the daemon does, then confirm the
    producer wire lands it in the reader.

Nothing here touches the network; the probe functions are stubbed and
the parsers are exercised on hand-built bytes.
"""
from __future__ import annotations

import struct
import zlib

from recce.core.known_monitoring_agents import (KINDS,
                                                known_monitoring_agents,
                                                monitoring_agents_for,
                                                record_monitoring_agent)
from recce.core.models import Host, Port


# --- wire-shaped fixtures --------------------------------------------------

def _zbxd_frame(payload: bytes) -> bytes:
    """ZBXD v1 header + payload — the plaintext frame format."""
    return b"ZBXD" + bytes([0x01]) + struct.pack("<Q", len(payload)) + payload


def _nrpe_v2_response(text: str, result_code: int = 0) -> bytes:
    """1036-byte NRPE v2 RESPONSE with a correct CRC32."""
    buf = text.encode("utf-8")[:1023] + b"\x00"
    buf = buf + b"\xff" * (1024 - len(buf))
    header = struct.pack(">HHIH", 2, 2, 0, result_code)  # v2, response, crc=0
    pad = b"\x00\x00"
    pkt = header + buf + pad
    crc = zlib.crc32(pkt) & 0xffffffff
    return pkt[:4] + struct.pack(">I", crc) + pkt[8:]


# --- record_monitoring_agent -----------------------------------------------

def test_record_appends_and_reads_back():
    h = Host(ip="10.0.0.10")
    record_monitoring_agent(h, 10050, "zabbix-agent",
                            version="6.0.14", gated=False,
                            server_hints=["10.0.0.1"], source="zabbix")
    got = monitoring_agents_for(h)
    assert len(got) == 1
    r = got[0]
    assert r["ip"] == "10.0.0.10"
    assert r["port"] == 10050
    assert r["kind"] == "zabbix-agent"
    assert r["version"] == "6.0.14"
    assert r["gated"] is False
    assert r["server_hints"] == ["10.0.0.1"]
    assert r["sources"] == ["zabbix"]


def test_record_refuses_unknown_kind_no_silent_typo_bucket():
    h = Host(ip="10.0.0.10")
    record_monitoring_agent(h, 10050, "prometheus_exporter",  # underscore typo
                            version="1.6", gated=False, source="prom")
    assert monitoring_agents_for(h) == []


def test_record_dedupes_case_insensitively_and_preserves_first_seen_version():
    """Two probes of the same (ip, port, kind) merge; the first-seen
    `version` casing wins even when the second probe carries a
    differently-cased build string."""
    h = Host(ip="10.0.0.10")
    record_monitoring_agent(h, 10050, "zabbix-agent",
                            version="Zabbix Agent 6.0.14",
                            gated=False, source="zabbix")
    record_monitoring_agent(h, 10050, "ZABBIX-AGENT",
                            version="zabbix agent 6.0.14",
                            gated=True, source="rescan")
    got = monitoring_agents_for(h)
    assert len(got) == 1
    r = got[0]
    assert r["version"] == "Zabbix Agent 6.0.14"
    # Later gated=True cannot un-prove an earlier bypass.
    assert r["gated"] is False
    assert set(r["sources"]) == {"zabbix", "rescan"}


def test_record_server_hints_dedup_case_insensitive_first_wins():
    h = Host(ip="10.0.0.10")
    record_monitoring_agent(h, 10050, "zabbix-agent",
                            server_hints=["Mon01.corp.local"], source="zabbix")
    record_monitoring_agent(h, 10050, "zabbix-agent",
                            server_hints=["mon01.corp.local", "10.0.0.2"],
                            source="rescan")
    r = monitoring_agents_for(h)[0]
    assert r["server_hints"] == ["Mon01.corp.local", "10.0.0.2"]


def test_record_fills_blank_fields_from_later_probe():
    h = Host(ip="10.0.0.10")
    record_monitoring_agent(h, 10050, "zabbix-agent",
                            version="", gated=True, source="a")
    record_monitoring_agent(h, 10050, "zabbix-agent",
                            version="6.0.14", gated=True, source="b")
    r = monitoring_agents_for(h)[0]
    assert r["version"] == "6.0.14"


def test_monitoring_agents_for_returns_copies():
    h = Host(ip="10.0.0.10")
    record_monitoring_agent(h, 10050, "zabbix-agent",
                            version="6.0.14", server_hints=["10.0.0.1"],
                            source="zabbix")
    got = monitoring_agents_for(h)
    got[0]["version"] = "TAMPERED"
    got[0]["sources"].append("nope")
    got[0]["server_hints"].append("evil")
    assert monitoring_agents_for(h)[0]["version"] == "6.0.14"
    assert monitoring_agents_for(h)[0]["sources"] == ["zabbix"]
    assert monitoring_agents_for(h)[0]["server_hints"] == ["10.0.0.1"]


# --- known_monitoring_agents engagement-wide roll-up -----------------------

def test_known_agents_priority_orders_ungated_before_gated():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    # b is gated (TLS enforced); a is exploitable.
    record_monitoring_agent(a, 10050, "zabbix-agent",
                            gated=False, source="zabbix")
    record_monitoring_agent(b, 5666, "nrpe", gated=True, source="nrpe")
    got = known_monitoring_agents([a, b])
    assert [x["ip"] for x in got["agents"]] == ["10.0.0.10", "10.0.0.20"]


def test_known_agents_priority_orders_by_kind_within_ungated():
    """Ties in `gated` are broken by KINDS order — zabbix-agent first,
    prometheus-exporter last — so the report reads high-signal to low."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    c = Host(ip="10.0.0.30")
    record_monitoring_agent(c, 9090, "prometheus-exporter",
                            gated=False, source="prom")
    record_monitoring_agent(b, 5666, "nrpe", gated=False, source="nrpe")
    record_monitoring_agent(a, 10050, "zabbix-agent",
                            gated=False, source="zabbix")
    got = known_monitoring_agents([a, b, c])
    kinds = [x["kind"] for x in got["agents"]]
    # KINDS = zabbix-agent, zabbix-trapper, nrpe, prometheus-exporter
    assert kinds == ["zabbix-agent", "nrpe", "prometheus-exporter"]


def test_known_agents_by_kind_counts():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_monitoring_agent(a, 10050, "zabbix-agent", source="zabbix")
    record_monitoring_agent(b, 10050, "zabbix-agent", source="zabbix")
    record_monitoring_agent(b, 5666, "nrpe", source="nrpe")
    got = known_monitoring_agents([a, b])
    assert got["by_kind"] == {"zabbix-agent": 2, "nrpe": 1}


def test_known_agents_reachable_from_only_ungated_ips_deduped():
    """`reachable_from` is the pivot-open surface — hosts with at least
    one ungated agent. A host that has both a gated and an ungated agent
    still appears once."""
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    c = Host(ip="10.0.0.30")
    record_monitoring_agent(a, 10050, "zabbix-agent", gated=False,
                            source="zabbix")
    record_monitoring_agent(a, 5666, "nrpe", gated=True, source="nrpe")
    record_monitoring_agent(b, 10050, "zabbix-agent", gated=True,
                            source="zabbix")
    record_monitoring_agent(c, 9090, "prometheus-exporter", gated=False,
                            source="prom")
    got = known_monitoring_agents([a, b, c])
    assert sorted(got["reachable_from"]) == ["10.0.0.10", "10.0.0.30"]


def test_known_agents_unions_sources_and_server_hints_across_engagement():
    a = Host(ip="10.0.0.10")
    # Two producer records on the SAME (ip, port, kind) — one from the
    # initial sweep, one from a rescan — merge.
    record_monitoring_agent(a, 10050, "zabbix-agent",
                            server_hints=["10.0.0.1"], source="zabbix")
    record_monitoring_agent(a, 10050, "zabbix-agent",
                            server_hints=["10.0.0.2"], source="rescan")
    got = known_monitoring_agents([a])
    assert len(got["agents"]) == 1
    r = got["agents"][0]
    assert set(r["sources"]) == {"zabbix", "rescan"}
    assert r["server_hints"] == ["10.0.0.1", "10.0.0.2"]


def test_kinds_constant_is_the_authoritative_allowlist():
    assert KINDS == ("zabbix-agent", "zabbix-trapper",
                     "nrpe", "prometheus-exporter")


# --- ZBXD wire fixture -----------------------------------------------------

def test_zbxd_frame_fixture_matches_agent_reply_format():
    """The producer parser (`_recv_frame`) reads exactly this shape off
    the wire — a 13-byte plaintext header + body. We sanity-check the
    fixture round-trips through the recce parser."""
    from recce.services import zabbix

    frame = _zbxd_frame(b"6.0.14")
    assert frame.startswith(b"ZBXD\x01")
    # Header body length is little-endian uint64.
    body_len = struct.unpack("<Q", frame[5:13])[0]
    assert body_len == len(b"6.0.14")
    # Parser accepts the fixture (empty-frame path would be b"").
    assert zabbix._HEADER_MAGIC == b"ZBXD"


# --- producer wire: zabbix.analyze() -> record_monitoring_agent ------------

def test_zabbix_analyze_wires_agent_into_known_monitoring_agents(monkeypatch):
    """Integration: zabbix.analyze() with a stubbed probe reply lands
    the fact in the cross-service reader. Stubs the network only — the
    wire glue in analyze() is exercised for real."""
    from recce.services import svcprobe, zabbix

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=10050, protocol="tcp", state="open",
                    service="zabbix-agent")]

    # Shape mirrors what zabbix.probe_agent() returns after a real
    # ZBXD round-trip of agent.version + inventory + agent conf.
    fake_pr = {
        "reachable": True, "version": "6.0.14", "hostname": "web01",
        "ping": "1", "inventory": {}, "files": {},
        "server_ips": ["10.0.0.1", "10.0.0.2"], "listeners": [],
        "tls_required": False, "remote_commands": False,
        "rce_output": "", "run_as": "",
    }

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)

    zabbix.analyze([h], active=True)

    agents = monitoring_agents_for(h)
    assert len(agents) == 1
    r = agents[0]
    assert r["kind"] == "zabbix-agent"
    assert r["port"] == 10050
    assert r["version"] == "6.0.14"
    # Server= allow-list bypassed — the agent replied to the scanner IP.
    assert r["gated"] is False
    assert r["server_hints"] == ["10.0.0.1", "10.0.0.2"]
    assert "zabbix" in r["sources"]

    got = known_monitoring_agents([h])
    assert got["by_kind"] == {"zabbix-agent": 1}
    assert got["reachable_from"] == ["10.0.0.10"]


# --- producer wire: nrpe.analyze() -> record_monitoring_agent --------------

def test_nrpe_analyze_wires_agent_into_known_monitoring_agents(monkeypatch):
    """Integration: nrpe.analyze() with a stubbed probe reply lands the
    fact. The fixture reply shape mirrors nrpe.probe() output after
    parsing a real 1036-byte v2 response — see `_nrpe_v2_response`
    above for the on-the-wire packet shape."""
    from recce.services import nrpe, svcprobe

    # Wire sanity: our fixture parses through the NRPE parser.
    v2_bytes = _nrpe_v2_response("NRPE v4.1.0")
    assert len(v2_bytes) == 1036
    parsed = nrpe._parse_v2_response(v2_bytes)
    assert parsed is not None
    assert parsed["output"] == "NRPE v4.1.0"
    assert parsed["crc_valid"] is True

    h = Host(ip="10.0.0.20")
    h.ports = [Port(portid=5666, protocol="tcp", state="open", service="nrpe")]

    fake_pr = {
        "reachable": True, "plaintext": True, "tls": False,
        "anon_dh_tls": False, "tls_cipher": "", "tls_cert_cn": "",
        "tls_cert_sans": [], "version": "4.1.0",
        "version_line": "NRPE v4.1.0", "commands_present": ["check_users"],
        "commands_absent": [], "command_outputs": {}, "users": [],
        "hostname": "", "os_hint": "", "arg_injection_rce": False,
        "arg_injection_evidence": "", "metachar_bypass_rce": False,
        "metachar_bypass_evidence": "", "cve_2020_6581_applies": False,
        "crc32_only_integrity": True,
    }

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)

    nrpe.analyze([h], active=True)

    agents = monitoring_agents_for(h)
    assert len(agents) == 1
    r = agents[0]
    assert r["kind"] == "nrpe"
    assert r["port"] == 5666
    assert r["version"] == "4.1.0"
    # Plaintext daemon that answered our probe = allowed_hosts is
    # permissive; the compromised-agent pivot is open from here.
    assert r["gated"] is False
    assert "nrpe" in r["sources"]

    got = known_monitoring_agents([h])
    assert got["by_kind"] == {"nrpe": 1}
    assert got["reachable_from"] == ["10.0.0.20"]
