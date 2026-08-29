"""Tests for the manage.py route module: verify, delete, metadata, issues,
scope, writeup, netmap, doctor, bulk-review, fieldkit-export, backup, proxy."""
from __future__ import annotations

import importlib.util
import pathlib
import zipfile

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
    _load_mock().build(str(eng), hosts=24, seed=99)
    app = create_app(str(eng))
    with TestClient(app) as c:
        c._eng_dir = str(eng)
        yield c


# --- verify ----------------------------------------------------------------

def test_verify_plan_returns_structure(client):
    r = client.get("/api/verify")
    assert r.status_code == 200
    data = r.json()
    assert "pending" in data and "already_ran" in data
    assert "plan" in data and "completed" in data
    assert isinstance(data["plan"], list)


# --- delete host -----------------------------------------------------------

def test_delete_host_and_404_on_missing(client):
    r = client.get("/api/hosts")
    data = r.json()
    hosts = data["items"]
    assert data["total"] >= 24
    ip = hosts[-1]["ip"]

    r = client.delete(f"/api/host/{ip}", headers={"X-Tester": "pytest"})
    assert r.status_code == 200
    assert r.json()["ok"] is True

    r2 = client.get(f"/api/host/{ip}")
    assert r2.status_code == 404

    r3 = client.delete(f"/api/host/{ip}", headers={"X-Tester": "pytest"})
    assert r3.status_code == 404


# --- delete credential -----------------------------------------------------

def test_delete_credential(client):
    data = client.get("/api/credentials").json()
    creds = data["items"]
    assert len(creds) > 0
    c = creds[0]
    r = client.post("/api/delete/credential", json={
        "username": c["username"], "secret": c["secret"],
        "kind": c["kind"], "domain": c.get("domain", ""),
    }, headers={"X-Tester": "pytest"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_delete_credential_404_on_missing(client):
    r = client.post("/api/delete/credential", json={
        "username": "nonexistent", "secret": "x", "kind": "password",
    }, headers={"X-Tester": "pytest"})
    assert r.status_code == 404


# --- delete finding --------------------------------------------------------

def test_delete_finding(client):
    data = client.get("/api/findings").json()
    findings = data["items"]
    assert len(findings) > 0
    f = findings[-1]
    # The API's "key" is vuln_row_key (prefixed "vuln:"), but remove_finding
    # compares against Vuln.key (no prefix). Strip the prefix.
    vuln_key = f["key"]
    if vuln_key.startswith("vuln:"):
        vuln_key = vuln_key[len("vuln:"):]
    r = client.post("/api/delete/finding", json={
        "ip": f["ip"], "key": vuln_key,
    }, headers={"X-Tester": "pytest"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_delete_finding_requires_fields(client):
    r = client.post("/api/delete/finding", json={}, headers={"X-Tester": "pytest"})
    assert r.status_code == 400


# --- metadata --------------------------------------------------------------

def test_metadata_round_trip(client):
    r = client.post("/api/meta", json={
        "engagement": "Test Engagement",
        "client": "Test Client",
        "tester": "pytest",
    }, headers={"X-Tester": "pytest"})
    assert r.status_code == 200
    assert set(r.json()["updated"]) == {"engagement", "client", "tester"}

    r2 = client.get("/api/meta")
    assert r2.status_code == 200
    data = r2.json()
    assert data["engagement"] == "Test Engagement"
    assert data["client"] == "Test Client"
    assert data["tester"] == "pytest"


def test_metadata_rejects_no_fields(client):
    r = client.post("/api/meta", json={"bogus": "x"}, headers={"X-Tester": "pytest"})
    assert r.status_code == 400


def test_metadata_truncates_long_values(client):
    long_val = "x" * 3000
    r = client.post("/api/meta", json={"notes": long_val},
                    headers={"X-Tester": "pytest"})
    assert r.status_code == 200
    data = client.get("/api/meta").json()
    assert len(data["notes"]) == 2000


# --- issues ----------------------------------------------------------------

def test_issues_returns_structure(client):
    r = client.get("/api/issues")
    assert r.status_code == 200
    data = r.json()
    assert "issues" in data and "counts" in data


# --- scope -----------------------------------------------------------------

def test_scope_crud(client):
    r = client.get("/api/scope")
    assert r.status_code == 200
    initial_count = len(r.json())

    r2 = client.post("/api/scope", json={"subnet": "192.168.99.0/24"},
                     headers={"X-Tester": "pytest"})
    assert r2.status_code == 200
    assert r2.json()["size"] == 256

    r3 = client.get("/api/scope")
    assert len(r3.json()) == initial_count + 1

    r4 = client.delete("/api/scope/192.168.99.0/24",
                       headers={"X-Tester": "pytest"})
    assert r4.status_code == 200

    r5 = client.get("/api/scope")
    assert len(r5.json()) == initial_count


def test_scope_rejects_invalid_subnet(client):
    r = client.post("/api/scope", json={"subnet": "not-a-subnet"},
                    headers={"X-Tester": "pytest"})
    assert r.status_code == 400


def test_scope_delete_404_on_missing(client):
    r = client.delete("/api/scope/99.99.99.0/24",
                      headers={"X-Tester": "pytest"})
    assert r.status_code == 404


# --- writeups --------------------------------------------------------------

def test_writeups_list(client):
    r = client.get("/api/writeups")
    assert r.status_code == 200
    data = r.json()
    assert "findings" in data
    assert len(data["findings"]) > 0


def test_writeup_generate_404_on_no_match(client):
    r = client.post("/api/writeup", json={"selector": "ZZZZZ-nonexistent-ZZZZZ"})
    assert r.status_code == 404


def test_writeup_requires_selector(client):
    r = client.post("/api/writeup", json={})
    assert r.status_code == 400


# --- netmap ----------------------------------------------------------------

def test_netmap_returns_svg(client):
    r = client.get("/api/netmap.svg")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in r.text


def test_netmap_views_lists_every_projection(client):
    """The Topology tab builds its selector from this, so an id added to the
    route without a generator behind it would surface as a dead button."""
    r = client.get("/api/netmap/views")
    assert r.status_code == 200
    body = r.json()
    ids = {v["id"] for v in body["views"]}
    assert ids == {"architecture", "overview", "full", "tiered", "reachability", "ad"}
    assert body["hosts"] > 0
    for v in body["views"]:
        assert v["blurb"] and isinstance(v["available"], bool)


@pytest.mark.parametrize("view", ["architecture", "overview", "full",
                                  "tiered", "reachability"])
def test_netmap_each_view_draws(client, view):
    """Each host-based view must return a real drawable SVG carrying its own
    xmlns - the report embeds these in a page that declares the namespace, but a
    standalone response has to bring it or the browser renders nothing."""
    r = client.get(f"/api/netmap.svg?view={view}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("image/svg+xml")
    assert "<svg" in r.text and "xmlns=" in r.text
    assert len(r.text) > 200, f"{view} returned a blank/placeholder SVG"


def test_netmap_ad_view_is_blank_without_bloodhound(client):
    """`ad` is the one view needing an import rather than just live hosts. With
    no BloodHound blob it must return a valid empty SVG, not 500 - the UI reads
    `available` to grey the button and the short body to show the hint."""
    r = client.get("/api/netmap.svg?view=ad")
    assert r.status_code == 200
    assert "<svg" in r.text
    avail = {v["id"]: v["available"] for v in client.get("/api/netmap/views").json()["views"]}
    assert avail["ad"] is False


def test_netmap_rejects_unknown_view(client):
    r = client.get("/api/netmap.svg?view=../../etc/passwd")
    assert r.status_code == 400


# --- doctor ----------------------------------------------------------------

def test_doctor_launches_job(client):
    r = client.post("/api/doctor", headers={"X-Tester": "pytest"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert "id" in r.json()


# --- bulk review -----------------------------------------------------------

def test_bulk_review(client):
    hosts = client.get("/api/hosts").json()["items"]
    keys = [h["key"] for h in hosts[:5]]
    r = client.post("/api/bulk-review", json={"keys": keys, "reviewed": True},
                    headers={"X-Tester": "pytest"})
    assert r.status_code == 200
    assert r.json()["count"] == 5

    updated = client.get("/api/hosts").json()["items"]
    for h in updated:
        if h["key"] in keys:
            assert h["reviewed"] is True


def test_bulk_review_rejects_empty(client):
    r = client.post("/api/bulk-review", json={"keys": []},
                    headers={"X-Tester": "pytest"})
    assert r.status_code == 400


def test_bulk_review_rejects_over_limit(client):
    r = client.post("/api/bulk-review", json={"keys": ["k"] * 501},
                    headers={"X-Tester": "pytest"})
    assert r.status_code == 400


# --- fieldkit export -------------------------------------------------------

def test_fieldkit_export_returns_zip(client):
    r = client.post("/api/fieldkit-export")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    import io
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert any("ports.gnmap" in n for n in names)
    assert any("recce-bridge.json" in n for n in names)
    assert any("FIELDKIT.md" in n for n in names)


# --- backup ----------------------------------------------------------------

def test_backup_returns_zip_with_db(client):
    r = client.post("/api/backup")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    import io
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert any("results.sqlite" in n for n in names)


# --- proxy -----------------------------------------------------------------

def test_proxy_status(client):
    r = client.get("/api/proxy")
    assert r.status_code == 200
    data = r.json()
    assert "active" in data
    assert "hint" in data
    assert isinstance(data["active"], bool)


# --- pagination ------------------------------------------------------------

def test_hosts_pagination(client):
    full = client.get("/api/hosts").json()
    assert full["total"] >= 20
    assert full["limit"] == 0

    page = client.get("/api/hosts?limit=5&offset=0").json()
    assert len(page["items"]) == 5
    assert page["total"] == full["total"]
    assert page["limit"] == 5
    assert page["offset"] == 0

    page2 = client.get("/api/hosts?limit=5&offset=5").json()
    assert len(page2["items"]) == 5
    assert page2["items"][0]["ip"] != page["items"][0]["ip"]


def test_findings_pagination(client):
    full = client.get("/api/findings").json()
    assert full["total"] > 0

    page = client.get("/api/findings?limit=3&offset=0").json()
    assert len(page["items"]) == 3
    assert page["total"] == full["total"]


def test_credentials_pagination(client):
    full = client.get("/api/credentials").json()
    if full["total"] == 0:
        pytest.skip("no credentials to paginate")

    page = client.get("/api/credentials?limit=2&offset=0").json()
    assert len(page["items"]) <= 2
    assert page["total"] == full["total"]
