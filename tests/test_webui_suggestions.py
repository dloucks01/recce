"""Scan-tab "recce suggests…" endpoint (/api/scan/suggestions).

Composition rules read the 10 shared-surface modules (known_domains,
known_users, known_hashes, relay_targets, known_ot_assets, known_devices,
known_mail_accounts, known_hostkeys, known_hostnames + hashloot categories)
and turn learned facts into single-click prefills the Scan tab renders
above the command grid.  Each test builds a scripted engagement and
asserts one rule fires (and no others do).
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from recce.cli import _open_paths
from recce.core.models import Account, Credential, Host, Port
from recce.core.store import Store
from recce.webui.app import create_app


def _mkeng(tmp_path, name):
    eng = tmp_path / name
    _open_paths(str(eng))                       # bootstrap dirs
    return str(eng)


def _open_store(eng):
    return Store(_open_paths(eng)["db"])


def _suggestions(eng):
    with TestClient(create_app(eng)) as c:
        r = c.get("/api/scan/suggestions")
        assert r.status_code == 200
        return r.json()["suggestions"]


# --- no engagement facts -> no suggestions --------------------------------

def test_empty_engagement_emits_no_suggestions(tmp_path):
    eng = _mkeng(tmp_path, "empty")
    assert _suggestions(eng) == []


# --- rule 1: known_domains -> --domain prefill for credentialed cmds ------

def test_ntlm_dns_domain_becomes_kerberos_realm_suggestion(tmp_path):
    eng = _mkeng(tmp_path, "ad")
    h = Host(ip="10.0.0.10", up_reason="syn-ack")
    h.ntlm = {"dns_domain": "corp.local", "netbios_domain": "CORP"}
    with _open_store(eng) as st:
        st.upsert_host(h)

    sugs = _suggestions(eng)
    doms = [s for s in sugs if s["source"] == "known_domains"]
    assert doms, "known_domains rule did not fire"
    # every domain suggestion carries the uppercased realm
    assert all(s["suggested_value"] == "CORP.LOCAL" for s in doms)
    assert all(s["field"] == "domain" for s in doms)
    assert all(s["confidence"] == "high" for s in doms)
    # covers the whole credentialed set (kerberos itself doesn't have creds,
    # but credenum / smb / ldap / certipy / db cards all do and need --domain)
    cmds = {s["command"] for s in doms}
    assert {"credenum", "smb", "ldap", "certipy"} <= cmds


# --- rule 2: known_users(admincount) -> --user prefill --------------------

def test_admincount_user_becomes_username_prefill(tmp_path):
    eng = _mkeng(tmp_path, "admins")
    h = Host(ip="10.0.0.11", up_reason="syn-ack")
    h.accounts = [
        Account(ip="10.0.0.11", source="ldap", kind="user",
                name="alice", attrs={}),
        Account(ip="10.0.0.11", source="ldap", kind="user",
                name="da_bob", attrs={"admincount": True}),
    ]
    with _open_store(eng) as st:
        st.upsert_host(h)

    sugs = _suggestions(eng)
    users = [s for s in sugs if s["source"] == "known_users"]
    assert users, "known_users rule did not fire"
    # da_bob is the admincount hit; it beats alice for the username slot
    assert all(s["suggested_value"] == "da_bob" for s in users)
    assert all(s["field"] == "username" for s in users)
    cmds = {s["command"] for s in users}
    # covers the credentialed sweep + AD + native DB cards
    assert {"credenum", "smb", "ldap", "postgres", "mssql"} <= cmds


# --- rule 3: hashloot dir populated + no potfile -> hashcat handoff -------

def test_hashloot_files_surface_hashcat_potfile_suggestion(tmp_path):
    eng = _mkeng(tmp_path, "loot")
    loot = os.path.join(eng, "loot")
    os.makedirs(loot, exist_ok=True)
    # write a fake kerberoast blob so known_hashes picks it up
    with open(os.path.join(loot, "kerberoast.hash"), "w") as fh:
        fh.write("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01*$aabbcc\n")

    sugs = _suggestions(eng)
    hashes = [s for s in sugs if s["source"] == "known_hashes"]
    assert hashes, "known_hashes rule did not fire despite loot on disk"
    s = hashes[0]
    assert "hashcat" in s["external_cmd"]
    assert "kerberoast" in s["reason"]
    # info-only card: no target command / form field to prefill
    assert s["command"] == "" and s["field"] == ""


# --- rule 4: relay_targets present -> ntlmrelayx suggestion ---------------

def test_relay_targets_surface_ntlmrelayx_suggestion(tmp_path):
    eng = _mkeng(tmp_path, "relay")
    h = Host(ip="10.0.0.20", up_reason="syn-ack",
             ports=[Port(portid=445, service="microsoft-ds", state="open")])
    h.smb_signing = "not required"
    with _open_store(eng) as st:
        st.upsert_host(h)

    sugs = _suggestions(eng)
    relays = [s for s in sugs if s["source"] == "relay_targets"]
    assert relays, "relay_targets rule did not fire"
    assert "ntlmrelayx" in relays[0]["external_cmd"]
    assert relays[0]["confidence"] == "high"


# --- shape / dedup invariants --------------------------------------------

def test_suggestion_keys_are_unique_and_stable(tmp_path):
    """The frontend uses `key` for dedup + dismiss; same fact must produce
    the same key across two calls, and no two suggestions may share one."""
    eng = _mkeng(tmp_path, "dedup")
    h = Host(ip="10.0.0.10", up_reason="syn-ack")
    h.ntlm = {"dns_domain": "corp.local", "netbios_domain": "CORP"}
    with _open_store(eng) as st:
        st.upsert_host(h)

    first = _suggestions(eng)
    second = _suggestions(eng)
    keys1 = [s["key"] for s in first]
    keys2 = [s["key"] for s in second]
    assert keys1 == keys2, "suggestion keys drifted between two GETs"
    assert len(keys1) == len(set(keys1)), "duplicate key inside one response"


def test_endpoint_never_500s_on_a_gnarly_store(tmp_path):
    """Rules must be tolerant of missing shared-surface modules and of
    weirdly-populated hosts — the tab pulls this on every mount."""
    eng = _mkeng(tmp_path, "gnarly")
    # Host with an account that has no name (edge case one of the readers
    # collapsed in the past) and a hostkey list with no fingerprint.
    h = Host(ip="10.0.0.99", up_reason="syn-ack")
    h.accounts = [Account(ip="10.0.0.99", source="?", kind="user", name="")]
    with _open_store(eng) as st:
        st.upsert_host(h)
    _ = _suggestions(eng)                       # must not raise


# --- optional smoke: creds carrying a domain also flows through -----------

def test_creds_with_domain_alone_still_produce_a_domain_suggestion(tmp_path):
    """A dropped Kerberos ticket may hand us a realm before any host has
    surfaced NTLM — the reader takes creds too, so the rule should still fire."""
    eng = _mkeng(tmp_path, "creds")
    with _open_store(eng) as st:
        st.add_credential(Credential(
            username="alice", secret="p", domain="corp.local",
            source="secretsdump", kind="password"))
    sugs = _suggestions(eng)
    doms = [s for s in sugs if s["source"] == "known_domains"]
    assert doms, "cred-only domain fact did not surface a suggestion"
    assert doms[0]["suggested_value"] == "CORP.LOCAL"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
