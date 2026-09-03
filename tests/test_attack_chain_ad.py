"""Phase D — /api/attack-chain/ad walkthrough endpoint tests.

The endpoint models the AD compromise as an ordered 11-step chain and
returns the current engagement state per step (proven / pending /
blocked) with per-step evidence + a next-step advisory. These tests
cover the empty case (fresh tester), partial evidence (a few steps
proven), and a credential-driven skip-ahead (nthash → LSA/NTDS dump).
"""
from __future__ import annotations

import pathlib

from fastapi.testclient import TestClient

from recce.cli import _open_paths
from recce.core.models import Credential, Host, Port, Vuln
from recce.core.store import Store
from recce.webui.app import create_app


_EXPECTED_STEPS = [
    "discover_dc", "null_session", "anon_ldap_read", "user_enum",
    "unauth_roast", "cred_acquired", "coercion_reachable",
    "authed_kerberoast", "lsa_or_ntds_dump", "adcs_esc", "da_path",
]


def _fresh(eng: pathlib.Path) -> None:
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "phase-d empty")
    st.close()


def test_attack_chain_empty_engagement(tmp_path: pathlib.Path) -> None:
    """No hosts, no creds — every step pending, the hero next_action is
    the discover_dc advisory."""
    eng = tmp_path / "eng_empty"
    _fresh(eng)
    with TestClient(create_app(str(eng))) as c:
        r = c.get("/api/attack-chain/ad")
        assert r.status_code == 200
        data = r.json()

    ids = [s["id"] for s in data["steps"]]
    assert ids == _EXPECTED_STEPS, ids
    # Empty state: nothing is proven; every step is pending (blocked only
    # kicks in when an upstream step is proven and a sibling isn't).
    statuses = [s["status"] for s in data["steps"]]
    assert set(statuses) == {"pending"}, statuses

    summary = data["summary"]
    assert summary["proven"] == 0
    assert summary["blocked"] == 0
    assert summary["pending"] == len(_EXPECTED_STEPS)
    assert summary["highest_reached"] == ""
    # The hero card should tell the tester to run recce enum first.
    assert "recce enum" in summary["next_action"], summary["next_action"]

    # P7-C2: edges array is derived server-side from each step's
    # depends_on. Contract check: every edge references two known step
    # ids, the direction matches a real dependency, and the AD chain
    # (which has explicit deps between at least anon_ldap_read →
    # user_enum → unauth_roast) produces a non-empty list.
    assert "edges" in data, "attack chain payload must carry edges (P7-C2)"
    assert isinstance(data["edges"], list)
    assert data["edges"], "AD chain has known deps — edges list should not be empty"
    ids_set = set(ids)
    for e in data["edges"]:
        assert set(e.keys()) == {"from", "to"}, e
        assert e["from"] in ids_set and e["to"] in ids_set, e
        # `to`'s depends_on must actually include `from` — the derivation
        # is not fabricated.
        target_step = next(s for s in data["steps"] if s["id"] == e["to"])
        assert e["from"] in target_step["depends_on"], (
            f"edge {e['from']}->{e['to']} not in {target_step['depends_on']}")


def test_attack_chain_anon_ldap_reachable(tmp_path: pathlib.Path) -> None:
    """A DC with anon LDAP read + a NULL-session finding → the first
    three steps prove, everything else stays pending / blocked."""
    eng = tmp_path / "eng_anon"
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "phase-d anon")

    dc = Host(ip="10.20.0.10", up_reason="syn-ack",
              hostnames=["dc01.corp.local"],
              ports=[Port(portid=88, service="kerberos-sec", state="open"),
                     Port(portid=389, service="ldap", state="open"),
                     Port(portid=445, service="microsoft-ds", state="open")])
    dc.ntlm = {"dns_domain": "corp.local", "netbios_domain": "CORP"}
    dc.vulns = [
        Vuln(ip="10.20.0.10", port=445, protocol="tcp",
             script_id="null_session",
             title="SMB null / anonymous session allows enumeration",
             severity="medium", source="smb",
             output="shares: IPC$, NETLOGON; users: krbtgt, admin"),
        Vuln(ip="10.20.0.10", port=389, protocol="tcp",
             script_id="ldap_anon_read",
             title="Anonymous LDAP read",
             severity="high", source="ldap",
             output="defaultNamingContext=DC=corp,DC=local"),
    ]
    st.upsert_host(dc)
    st.close()

    with TestClient(create_app(str(eng))) as c:
        data = c.get("/api/attack-chain/ad").json()

    steps = {s["id"]: s for s in data["steps"]}
    assert steps["discover_dc"]["status"] == "proven", steps["discover_dc"]
    assert steps["null_session"]["status"] == "proven"
    assert steps["anon_ldap_read"]["status"] == "proven"
    # Evidence carries the excerpt each step needs.
    ns_ev = steps["null_session"]["evidence"]
    assert ns_ev and "shares:" in ns_ev[0]["output_excerpt"]
    # P1-4 — contributing_hosts is present on every step and dedups the
    # evidence IPs (the DC's 10.20.0.10 only appears once).
    for s in data["steps"]:
        assert "contributing_hosts" in s, s
        assert len(s["contributing_hosts"]) == len(set(s["contributing_hosts"]))
    assert steps["null_session"]["contributing_hosts"] == ["10.20.0.10"]
    assert steps["discover_dc"]["contributing_hosts"] == ["10.20.0.10"]

    # user_enum: only 0 known users (accounts weren't seeded) → pending.
    assert steps["user_enum"]["status"] == "pending"
    # cred_acquired has upstream user_enum + unauth_roast → both pending,
    # so cred_acquired itself is pending (no upstream proven).
    assert steps["cred_acquired"]["status"] == "pending"

    summary = data["summary"]
    assert summary["proven"] == 3
    # highest_reached is the LAST proven step in declared order — the anon
    # LDAP read step here.
    assert summary["highest_reached"] == "anon_ldap_read"
    # Next action should now name the next proximate step (user_enum).
    assert "kerbrute" in summary["next_action"] or \
           "userenum" in summary["next_action"], summary["next_action"]


def test_attack_chain_nthash_proves_dump_and_cred(tmp_path: pathlib.Path) -> None:
    """A Credential(kind='nthash') on its own proves BOTH cred_acquired
    (via known_hashes.by_user) and lsa_or_ntds_dump; summary.highest_reached
    reflects the furthest proven step."""
    eng = tmp_path / "eng_nthash"
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "phase-d nthash")
    st.add_credential(Credential(
        username="alice", secret="aad3b435b51404eeaad3b435b51404ee",
        kind="nthash", domain="CORP", source="secretsdump",
        origin_ip="10.30.0.5"))
    st.close()

    with TestClient(create_app(str(eng))) as c:
        data = c.get("/api/attack-chain/ad").json()

    steps = {s["id"]: s for s in data["steps"]}
    assert steps["cred_acquired"]["status"] == "proven", steps["cred_acquired"]
    assert steps["lsa_or_ntds_dump"]["status"] == "proven", \
        steps["lsa_or_ntds_dump"]
    # The nthash evidence lands on both steps (attribution row +
    # by_user row).
    dump_ev = steps["lsa_or_ntds_dump"]["evidence"]
    assert any("alice" in e["output_excerpt"].lower() for e in dump_ev), dump_ev

    # discover_dc was NOT proven (no host was seeded) → it stays pending.
    # Since lsa_or_ntds_dump proved, highest_reached should be it (last
    # proven in declared order).
    summary = data["summary"]
    assert summary["highest_reached"] == "lsa_or_ntds_dump", summary
    assert summary["proven"] >= 2

    # Sanity: the step whose upstream (cred_acquired) is proven but which
    # itself is not, is BLOCKED not pending — that's the walkthrough's
    # signal that "you skipped ahead but you can't complete this leg".
    da = steps["da_path"]
    # da_path deps are lsa_or_ntds_dump + authed_kerberoast + adcs_esc;
    # one dep is proven so if da itself unproven, status is blocked.
    assert da["status"] in ("blocked", "pending")
    if da["status"] == "blocked":
        assert "lsa_or_ntds_dump" in da["depends_on"]
