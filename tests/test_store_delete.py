"""Tests for Store delete operations: delete_host, delete_credential,
remove_finding, and delete_scope."""
from __future__ import annotations

import pytest

from recce.core.models import Credential, Host, Port, Vuln
from recce.core.store import Store


@pytest.fixture()
def store(tmp_path):
    st = Store(str(tmp_path / "test.sqlite"))
    yield st
    st.close()


def _host(ip, vulns=None):
    h = Host(ip=ip, up_reason="syn-ack",
             ports=[Port(portid=22, service="ssh", state="open"),
                    Port(portid=80, service="http", state="open")])
    h.vulns = vulns or []
    return h


def _vuln(ip, port, script_id, title="test vuln", severity="high"):
    return Vuln(ip=ip, port=port, protocol="tcp", script_id=script_id,
                state="VULNERABLE", title=title, severity=severity,
                source="test", confidence="confirmed")


# --- delete_host -----------------------------------------------------------

def test_delete_host_removes_host_and_tracking(store):
    h = _host("10.0.0.1")
    store.upsert_host(h)
    store.set_reviewed("host:10.0.0.1", True, notes="keep me")
    store.add_issue("10.0.0.1", "vulns", "warn", "test issue")
    assert store.get_host("10.0.0.1") is not None

    assert store.delete_host("10.0.0.1") is True
    assert store.get_host("10.0.0.1") is None
    tracking = store.get_tracking()
    assert "host:10.0.0.1" not in tracking
    assert len(store.get_issues()) == 0


def test_delete_host_returns_false_for_missing(store):
    assert store.delete_host("9.9.9.9") is False


def test_delete_host_leaves_other_hosts(store):
    store.upsert_host(_host("10.0.0.1"))
    store.upsert_host(_host("10.0.0.2"))
    store.delete_host("10.0.0.1")
    assert store.get_host("10.0.0.2") is not None
    assert len(store.all_hosts()) == 1


# --- delete_credential -----------------------------------------------------

def test_delete_credential_removes_by_key(store):
    c = Credential(username="admin", secret="pass", kind="password")
    store.add_credential(c)
    assert len(store.all_credentials()) == 1

    assert store.delete_credential(c.dedupe_key()) is True
    assert len(store.all_credentials()) == 0


def test_delete_credential_returns_false_for_missing(store):
    assert store.delete_credential("nonexistent-key") is False


def test_delete_credential_leaves_others(store):
    c1 = Credential(username="admin", secret="pass1", kind="password")
    c2 = Credential(username="root", secret="pass2", kind="password")
    store.add_credential(c1)
    store.add_credential(c2)
    store.delete_credential(c1.dedupe_key())
    remaining = store.all_credentials()
    assert len(remaining) == 1
    assert remaining[0].username == "root"


# --- remove_finding --------------------------------------------------------

def test_remove_finding_by_key(store):
    v1 = _vuln("10.0.0.1", 22, "ssh-weak", "Weak SSH key")
    v2 = _vuln("10.0.0.1", 80, "http-vuln", "HTTP vuln")
    store.upsert_host(_host("10.0.0.1", vulns=[v1, v2]))

    assert store.remove_finding("10.0.0.1", v1.key) is True
    h = store.get_host("10.0.0.1")
    assert len(h.vulns) == 1
    assert h.vulns[0].script_id == "http-vuln"


def test_remove_finding_returns_false_for_missing_host(store):
    assert store.remove_finding("9.9.9.9", "any-key") is False


def test_remove_finding_returns_false_for_missing_vuln(store):
    store.upsert_host(_host("10.0.0.1", vulns=[_vuln("10.0.0.1", 22, "ssh-weak")]))
    assert store.remove_finding("10.0.0.1", "nonexistent-key") is False


def test_remove_finding_leaves_host_with_no_vulns(store):
    v = _vuln("10.0.0.1", 22, "ssh-weak")
    store.upsert_host(_host("10.0.0.1", vulns=[v]))
    store.remove_finding("10.0.0.1", v.key)
    h = store.get_host("10.0.0.1")
    assert h is not None
    assert len(h.vulns) == 0


# --- delete_scope ----------------------------------------------------------

def test_delete_scope_removes_subnet(store):
    store.set_scope("10.0.0.0/24", 254)
    assert store.delete_scope("10.0.0.0/24") is True
    assert len(store.get_scope()) == 0


def test_delete_scope_returns_false_for_missing(store):
    assert store.delete_scope("192.168.0.0/16") is False


def test_delete_scope_leaves_others(store):
    store.set_scope("10.0.0.0/24", 254)
    store.set_scope("10.0.1.0/24", 254)
    store.delete_scope("10.0.0.0/24")
    scope = store.get_scope()
    assert len(scope) == 1
    assert "10.0.1.0/24" in scope
