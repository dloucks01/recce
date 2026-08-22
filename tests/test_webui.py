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
    stats = _load_mock().build(str(eng), hosts=24, seed=99)
    app = create_app(str(eng))
    with TestClient(app) as c:
        c.stats = stats            # type: ignore[attr-defined]
        yield c


def test_overview_reflects_the_engagement(client):
    o = client.get("/api/overview").json()
    assert o["hosts_up"] == 24
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
    assert len(hosts) == 24
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


def test_unannotated_service_finding_is_not_hidden_as_a_lead(tmp_path):
    """Regression: findings are persisted BEFORE qod.annotate runs, so v.qod is 0 in
    the store. The web layer must qod_of-compute the tier, or a real confirmed service
    finding (e.g. MySQL empty-password) is mis-tiered "lead" and hidden by default."""
    from fastapi.testclient import TestClient

    from recce.cli import _open_paths
    from recce.models import Host, Port, Vuln
    from recce.store import Store
    from recce.webui.app import create_app

    eng = tmp_path / "eng_qod"
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "qod regression")
    h = Host(ip="10.9.9.9", up_reason="syn-ack",
             ports=[Port(portid=3306, service="mysql", state="open")])
    h.vulns = [Vuln(ip="10.9.9.9", port=3306, protocol="tcp", script_id="mysql:x",
                    state="finding", title="MySQL 'root' login with empty password",
                    severity="high", source="mysql", confidence="confirmed")]  # qod defaults to 0
    st.upsert_host(h)
    st.close()

    with TestClient(create_app(str(eng))) as c:
        rows = c.get("/api/findings").json()
        assert rows, "the confirmed service finding was hidden entirely"
        assert rows[0]["tier"] == "confirmed", rows[0]
        # and the drawer detail exposes a real QoD, not 0
        d = c.get("/api/host/10.9.9.9").json()
        assert d["vulns"][0]["qod"] >= 95


def test_host_detail_drawer_payload(client):
    d = client.get("/api/host/10.20.10.10").json()
    assert "Domain Controller" in d["roles"]
    assert d["smb_signing"] == "required" and d["access"] is True
    # services carry product/version for the drawer's Services table
    assert any(p["port"] == 445 for p in d["ports"])
    # findings carry the drill-down detail: raw output, remediation, QoD
    zl = next(v for v in d["vulns"] if "Zerologon" in v["title"])
    assert zl["output"] and zl["remediation"] and zl["qod"] >= 95
    assert zl["cwes"]
    # AD accounts surfaced (incl. the kerberoastable service account)
    assert any(a["name"] == "svc_sql" and a["attrs"].get("spn") for a in d["accounts"])
    assert client.get("/api/host/9.9.9.9").status_code == 404


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


def test_command_catalog_exposes_the_full_surface(client):
    cat = client.get("/api/commands").json()
    # every capability is reachable from the browser now
    for cmd in ("postgres", "mongodb", "mysql", "web", "api", "couchdb", "influxdb",
                "cassandra", "oracle", "db2", "credsweep", "exploitplan", "attackpath",
                "prove", "poc", "credenum"):
        assert cmd in cat, f"{cmd} missing from the web command catalog"
    assert cat["postgres"]["creds"] is True
    assert any(f["name"] == "prove" for f in cat["postgres"]["flags"])
    assert any(f["name"] == "autologin" for f in cat["web"]["flags"])
    # the two gated active-proof web flags are reachable from the browser too
    web_flags = {f["name"] for f in cat["web"]["flags"]}
    assert {"upload-shell", "smuggle"} <= web_flags
    assert cat["exploitplan"]["lhost"] is True
    assert cat["attackpath"]["targets"] == "none"


def test_scan_builds_safe_argv_with_creds_and_flags(client):
    # a credentialed DB command with a flag -> the exact argv (no shell; pw is one token)
    r = client.post("/api/scan", json={
        "command": "postgres", "targets": "10.0.0.5",
        "username": "alice", "password": "p@ss w0rd!", "domain": "corp",
        "flags": ["prove"]})
    assert r.status_code == 200
    cmd = r.json()["cmd"]
    assert "postgres" in cmd and "-u alice" in cmd and "-d corp" in cmd
    assert "--prove" in cmd and "10.0.0.5" in cmd
    # web autologin
    r2 = client.post("/api/scan", json={"command": "web", "targets": "10.0.0.5",
                                        "flags": ["autologin", "crawl"]})
    assert "--autologin" in r2.json()["cmd"] and "--crawl" in r2.json()["cmd"]
    # the gated active-proof flags build into a safe argv from the browser
    r3 = client.post("/api/scan", json={"command": "web", "targets": "10.0.0.5",
                                        "flags": ["upload-shell", "smuggle"]})
    assert "--upload-shell" in r3.json()["cmd"] and "--smuggle" in r3.json()["cmd"]


def test_scan_guards(client):
    # unknown command rejected
    assert client.post("/api/scan", json={"command": "rm"}).status_code == 400
    # a targets-required command with none -> 400
    assert client.post("/api/scan", json={"command": "enum"}).status_code == 400
    # a bogus flag is silently dropped (not passed through)
    cmd = client.post("/api/scan", json={"command": "vulns", "targets": "10.0.0.5",
                                         "flags": ["evil"]}).json()["cmd"]
    assert "evil" not in cmd
    # creds are NOT passed to a non-cred command
    cmd2 = client.post("/api/scan", json={"command": "redis", "targets": "10.0.0.5",
                                          "username": "x", "password": "y"}).json()["cmd"]
    assert "-u x" not in cmd2
