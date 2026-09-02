"""Chain-suggestion rules on /api/scan/suggestions.

Each chain rule fires when a Vuln whose script_id sits in the rule's
trigger set is seeded on any host in the engagement. Every test seeds
exactly one such finding, hits the endpoint, and asserts the rule's
severity and a substring of its suggestion body come back on the card.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from recce.cli import _open_paths
from recce.core.models import Host, Vuln
from recce.core.store import Store
from recce.webui.app import create_app
from recce.webui.routes import scan as scan_mod


def _mkeng(tmp_path, name):
    eng = tmp_path / name
    _open_paths(str(eng))
    return str(eng)


def _open_store(eng):
    return Store(_open_paths(eng)["db"])


def _seed(eng, ip, script_id):
    """Drop one host whose sole vuln has the requested script_id."""
    h = Host(ip=ip, up_reason="syn-ack")
    h.vulns = [Vuln(ip=ip, port=445, protocol="tcp",
                    script_id=script_id, title="seeded",
                    severity="high")]
    with _open_store(eng) as st:
        st.upsert_host(h)


def _suggestions(eng):
    with TestClient(create_app(eng)) as c:
        r = c.get("/api/scan/suggestions")
        assert r.status_code == 200
        return r.json()["suggestions"]


def _one(eng, source):
    hits = [s for s in _suggestions(eng) if s["source"] == source]
    assert hits, f"no suggestion emitted for source={source!r}"
    return hits[0]


# --- individual chain rules ------------------------------------------------

_CASES = [
    # (rule source, sample trigger, expected severity, substring of suggestion)
    ("chain_ad_kerberos", "asrep_roast", "critical", "GetNPUsers.py"),
    ("chain_smb_post_null_loot", "null_session", "high", "enum4linux-ng"),
    ("chain_cloud_metadata_pivot", "imds_iam_credentials_exposed",
     "critical", "169.254.169.254"),
    ("chain_container_orchestrator_escape", "docker_api", "critical",
     "tcp://<host>:2375"),
    ("chain_hashicorp_stack_secrets", "vault_dev_mode", "critical",
     "VAULT_ADDR"),
    ("chain_ntlm_username_harvest", "rdp_ntlm_info", "high", "kerbrute"),
    ("chain_unauth_datastore_datamine", "redis_unauth", "high",
     "loot/datastores/"),
    ("chain_mssql_linked_privesc", "linked_sysadmin", "critical",
     "sp_linkedservers"),
    ("chain_coerce_and_relay", "msrpc_coercion", "critical", "coercer"),
    ("chain_printer_to_domain_creds", "ipp_cups", "high", "ipptool"),
    ("chain_ot_ics_process_impact", "s7_put_get_enabled", "high",
     "snap7-cli"),
    ("chain_esxi_vcenter_takeover", "vsphere_cve_2024_37085", "critical",
     "ESX Admins"),
]


@pytest.mark.parametrize("source,trigger,severity,needle", _CASES)
def test_chain_rule_fires_on_trigger(tmp_path, source, trigger, severity, needle):
    eng = _mkeng(tmp_path, f"chain_{source}")
    _seed(eng, "10.0.0.5", trigger)
    s = _one(eng, source)
    assert s["severity"] == severity, s
    assert needle in s["external_cmd"], (needle, s["external_cmd"][:200])
    # chain rules are info-only handoffs: no form prefill
    assert s["command"] == "" and s["field"] == "" and s["suggested_value"] == ""
    # key must be stable and mention the source
    assert s["key"].startswith(source), s["key"]


# --- rule coverage: every chain in _CHAIN_RULES has a test case -----------

def test_every_chain_rule_has_a_test_case():
    have_source = {c[0] for c in _CASES}
    declared = {r["name"] for r in scan_mod._CHAIN_RULES}
    missing = declared - have_source
    assert not missing, f"chain rules without a fires-on-trigger test: {missing}"


# --- negative: no chain rule fires on an empty store ----------------------

def test_no_chain_rule_fires_on_empty_engagement(tmp_path):
    eng = _mkeng(tmp_path, "empty_chain")
    chain_sources = {r["name"] for r in scan_mod._CHAIN_RULES}
    assert not [s for s in _suggestions(eng) if s["source"] in chain_sources]


# --- dedup: same trigger seeded twice yields one card ---------------------

def test_repeat_trigger_dedups_to_one_suggestion(tmp_path):
    eng = _mkeng(tmp_path, "dedup_chain")
    _seed(eng, "10.0.0.5", "docker_api")
    _seed(eng, "10.0.0.6", "docker_api")
    hits = [s for s in _suggestions(eng)
            if s["source"] == "chain_container_orchestrator_escape"]
    assert len(hits) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
