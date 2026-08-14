"""High-fidelity tests for the web workbench API.

These stand up the real FastAPI app over a *realistic* mock engagement (a Windows
DC + member servers + Linux web/DB boxes + workstations + network gear, built by
tools/mock_engagement.py) and assert the API surfaces the data a tester relies on:
the dashboard aggregates, per-host completion, findings with honest confidence,
collaboration (ticks/notes), and one-click report export.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest
from fastapi.testclient import TestClient

REPO = pathlib.Path(__file__).resolve().parent.parent


def _load_mock():
    spec = importlib.util.spec_from_file_location(
        "mock_engagement", REPO / "tools" / "mock_engagement.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    from recce.webui.app import create_app
    eng = tmp_path_factory.mktemp("eng")
    stats = _load_mock().build(str(eng), hosts=16, seed=99)
    app = create_app(str(eng))
    with TestClient(app) as c:
        c.stats = stats            # type: ignore[attr-defined]
        yield c


def test_overview_reflects_the_engagement(client):
    o = client.get("/api/overview").json()
    assert o["hosts_up"] == 16
    assert o["scope_subnets"] == 3
    assert o["services"] > 0
    # a realistic mix means several severities and some KEV-flagged findings
    assert o["by_severity"].get("critical", 0) >= 2
    assert o["kev_total"] >= 3
    assert o["kev_findings"], "dashboard needs the KEV shortlist populated"
    # top-risk host #1 should be the DC or a member with EternalBlue (highest score)
    assert o["top_hosts"] and o["top_hosts"][0]["score"] > 0
    # completion signals wired through
    assert o["enumerated"] >= 1 and o["accessed"] >= 1


def test_hosts_carry_ad_role_and_completion(client):
    hosts = client.get("/api/hosts").json()
    assert len(hosts) == 16
    by_ip = {h["ip"]: h for h in hosts}
    dc = by_ip["10.20.10.10"]
    assert "Domain Controller" in dc["roles"]
    assert dc["access"] is True          # access_gained flag surfaced
    assert dc["enumerated"] is True
    assert dc["key"] == "host:10.20.10.10"
    # every host exposes the completion flags the Targets tracker needs
    for h in hosts:
        for k in ("enumerated", "vuln_scanned", "access", "reviewed", "notes"):
            assert k in h


def test_findings_are_present_with_honest_confidence(client):
    findings = client.get("/api/findings").json()
    titles = {f["title"] for f in findings}
    # deterministic archetype findings must all be present
    assert any("Zerologon" in t for t in titles)
    assert any("Kerberoastable" in t for t in titles)
    assert any("Log4Shell" in t for t in titles)
    assert any("EternalBlue" in t for t in titles)
    # confidence is expressed as a QoD tier, and KEV/EPSS ride along
    zerologon = next(f for f in findings if "Zerologon" in f["title"])
    assert zerologon["kev"] is True
    assert zerologon["tier"] in ("confirmed", "likely", "lead")
    assert zerologon["epss"] > 0
    # findings are risk-ordered: first row is KEV
    assert findings[0]["kev"] is True


def test_tick_and_note_round_trip(client):
    findings = client.get("/api/findings").json()
    key = findings[0]["key"]
    # tick reviewed
    assert client.post("/api/tick", json={"key": key, "reviewed": True},
                       headers={"X-Tester": "pytest"}).json()["ok"]
    again = client.get("/api/findings").json()
    assert next(f for f in again if f["key"] == key)["reviewed"] is True
    # a note on a host, keyed host:<ip>, survives and does not clobber reviewed
    hkey = "host:10.20.10.10"
    client.post("/api/note", json={"key": hkey, "note": "DC — priority remediation"},
                headers={"X-Tester": "pytest"})
    dc = next(h for h in client.get("/api/hosts").json() if h["key"] == hkey)
    assert dc["notes"] == "DC — priority remediation"


def test_report_export_all_formats(client):
    for kind, magic in (("xlsx", b"PK"), ("csv", None), ("md", None), ("html", b"<")):
        r = client.get(f"/api/report/{kind}")
        assert r.status_code == 200, kind
        assert len(r.content) > 200, kind
        assert "attachment" in r.headers.get("content-disposition", "")
        if magic:
            assert r.content.startswith(magic), kind
    assert client.get("/api/report/pdf").status_code == 404


def test_scan_input_is_allowlisted(client):
    # phase must be on the allowlist (no arbitrary subcommands)
    assert client.post("/api/scan", json={"phase": "rm-rf", "targets": "10.0.0.1"}).status_code == 400
    # flag-shaped tokens are stripped, so an injection attempt leaves no targets -> 400
    assert client.post("/api/scan", json={"phase": "scan", "targets": "--script=vuln"}).status_code == 400
