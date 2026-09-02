"""Route-level tests for /api/bloodhound/zip.

Contract:
  * 200 + application/zip + Content-Disposition attachment filename=…
    when the store carries AD nodes (users/computers/groups/domains).
  * 404 when the store has none.
  * Companion /api/bloodhound/status reports availability without
    building the full push.
"""
from __future__ import annotations

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from recce.cli import _open_paths
from recce.core.models import Account, Host
from recce.core.store import Store
from recce.webui.app import create_app


def _seed_ad_store(eng_dir: str) -> None:
    db_path = _open_paths(eng_dir)["db"]
    st = Store(db_path)
    st.set_meta("engagement", "acme corp / bh-export test")
    dc = Host(ip="10.0.0.10", roles=["Domain Controller"])
    dc.accounts.append(Account(ip="10.0.0.10", source="ldap", kind="domain",
                               name="CORP.LOCAL", domain="CORP.LOCAL"))
    dc.accounts.append(Account(ip="10.0.0.10", source="ldap", kind="user",
                               name="alice", domain="CORP.LOCAL", rid="1105"))
    dc.accounts.append(Account(ip="10.0.0.10", source="ldap", kind="computer",
                               name="DC01$", domain="CORP.LOCAL", rid="1000"))
    st.upsert_host(dc)
    st.close()


def _seed_empty_store(eng_dir: str) -> None:
    """Just meta — no hosts / accounts. This is what a fresh `recce init` looks
    like before any enum runs."""
    db_path = _open_paths(eng_dir)["db"]
    st = Store(db_path)
    st.set_meta("engagement", "empty engagement")
    st.close()


@pytest.fixture()
def ad_client(tmp_path):
    eng = tmp_path / "eng_ad"
    eng.mkdir()
    _seed_ad_store(str(eng))
    with TestClient(create_app(str(eng))) as c:
        yield c


@pytest.fixture()
def empty_client(tmp_path):
    eng = tmp_path / "eng_empty"
    eng.mkdir()
    _seed_empty_store(str(eng))
    with TestClient(create_app(str(eng))) as c:
        yield c


def test_bloodhound_zip_serves_when_ad_present(ad_client):
    r = ad_client.get("/api/bloodhound/zip")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == "application/zip"
    cd = r.headers.get("content-disposition", "")
    assert cd.startswith("attachment"), cd
    assert 'filename="bloodhound-' in cd
    assert cd.endswith('.zip"')
    # The engagement name's `/`, whitespace, and other unsafe chars must all
    # be sanitised out of the filename.
    assert " " not in cd.split("filename=", 1)[1]
    assert "/" not in cd.split("filename=", 1)[1]

    # Body is a real zip carrying the seven per-kind SharpHound files.
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(zf.namelist())
    assert {"users.json", "computers.json", "groups.json", "domains.json",
            "gpos.json", "ous.json", "containers.json"}.issubset(names)


def test_bloodhound_zip_404_on_empty(empty_client):
    r = empty_client.get("/api/bloodhound/zip")
    assert r.status_code == 404
    assert "AD data" in r.json()["detail"]


def test_bloodhound_status_reports_availability(ad_client, empty_client):
    r = ad_client.get("/api/bloodhound/status")
    assert r.status_code == 200
    j = r.json()
    assert j["available"] is True
    assert j["counts"]["users"] == 1
    assert j["counts"]["computers"] == 1
    assert j["counts"]["domains"] == 1

    r2 = empty_client.get("/api/bloodhound/status")
    assert r2.status_code == 200
    j2 = r2.json()
    assert j2["available"] is False
    assert j2["counts"] == {"users": 0, "computers": 0,
                            "groups": 0, "domains": 0}
