"""Per-finding T2 prove endpoint tests.

Covers the wire contract the ExploitSurface tab's "Prove" button
depends on:

  * ``GET  /api/prove/available`` returns the set of finding_keys with
    a real proof recipe.
  * ``POST /api/prove/{finding_key}`` returns the recipe's verdict +
    evidence + finish for that one finding.
  * A monkeypatched CONFIRMED prover is dispatched to the right vuln.
  * An unknown key returns 404.

Uses the SMB-signing recipe as the real dispatch happy-path — its
verdict is a pure function of `host.smb_signing`, so no external tool
or nmap output is needed.
"""
from __future__ import annotations

import pathlib

from fastapi.testclient import TestClient

from recce.act import prove_dispatch
from recce.cli import _open_paths
from recce.core.models import Host, Port, Vuln
from recce.core.store import Store
from recce.core.tracking import vuln_row_key
from recce.webui.app import create_app


def _seed(eng_dir: str) -> tuple[str, str]:
    """One host with an SMB-signing finding (has a real recipe) + one
    finding that no recipe matches (banner-only). Returns their keys."""
    st = Store(_open_paths(eng_dir)["db"])
    st.set_meta("engagement", "prove-endpoint test")

    h = Host(ip="10.9.9.9", up_reason="syn-ack",
             ports=[Port(portid=445, service="microsoft-ds", state="open")])
    h.smb_signing = "not required"                # matches _v_smb_signing → CONFIRMED
    vuln_provable = Vuln(
        ip="10.9.9.9", port=445, protocol="tcp",
        script_id="smb2-security-mode",
        state="finding", title="SMB signing not required — NTLM relay to this host works",
        severity="high", source="smb",
        depth_tier="t1",
    )
    vuln_no_recipe = Vuln(
        ip="10.9.9.9", port=22, protocol="tcp",
        script_id="ssh-banner", state="finding",
        title="OpenSSH banner (informational)",
        severity="info", source="ssh", depth_tier="t1",
    )
    h.vulns = [vuln_provable, vuln_no_recipe]
    st.upsert_host(h)
    st.close()

    return vuln_row_key(vuln_provable), vuln_row_key(vuln_no_recipe)


def test_prove_available_lists_only_provable_keys(tmp_path: pathlib.Path) -> None:
    eng = tmp_path / "eng_prove_avail"
    provable_key, no_recipe_key = _seed(str(eng))

    with TestClient(create_app(str(eng))) as c:
        r = c.get("/api/prove/available")
        assert r.status_code == 200
        data = r.json()

    assert provable_key in data["keys"], data["keys"]
    assert no_recipe_key not in data["keys"], data["keys"]
    assert data["total"] == len(data["keys"])


def test_prove_confirmed_verdict_for_real_recipe(tmp_path: pathlib.Path) -> None:
    """SMB signing 'not required' → the real recipe returns CONFIRMED —
    verdict + evidence come straight from `proofs._v_smb_signing`."""
    eng = tmp_path / "eng_prove_confirmed"
    provable_key, _ = _seed(str(eng))

    with TestClient(create_app(str(eng))) as c:
        r = c.post(f"/api/prove/{provable_key}")
        assert r.status_code == 200, r.text
        data = r.json()

    assert data["verdict"] == "CONFIRMED"
    assert data["evidence"], data
    # Recipe wording — pinning the substring keeps this test honest about
    # WHICH recipe fired without going overboard.
    assert any("signing" in e.lower() for e in data["evidence"])
    assert data["ip"] == "10.9.9.9"
    assert data["port"] == 445


def test_prove_confirmed_via_mocked_prover(tmp_path: pathlib.Path,
                                           monkeypatch) -> None:
    """A mocked prover monkeypatched into `prove_dispatch.prove_finding_key`
    must reach the endpoint response byte-for-byte."""
    eng = tmp_path / "eng_prove_mock"
    provable_key, _ = _seed(str(eng))

    fixed = {
        "ip": "10.9.9.9", "port": 445, "vuln": "SMB signing not required",
        "finding": "SMB signing not required — NTLM relay to this host works",
        "verdict": "CONFIRMED",
        "evidence": ["mocked prover fired", "second evidence line"],
        "preconditions": ["signing state observed"],
        "finish": "nxc smb 10.9.9.9 --gen-relay-list relays.txt",
        "fp": "signing is REQUIRED after all",
        "key": "verify:10.9.9.9:445:smb-signing-relay",
    }
    monkeypatch.setattr(prove_dispatch, "prove_finding_key",
                        lambda hosts, key: fixed if key == provable_key else None)

    with TestClient(create_app(str(eng))) as c:
        r = c.post(f"/api/prove/{provable_key}")
        assert r.status_code == 200, r.text
        assert r.json() == fixed


def test_prove_unknown_key_is_404(tmp_path: pathlib.Path) -> None:
    eng = tmp_path / "eng_prove_404"
    _seed(str(eng))
    with TestClient(create_app(str(eng))) as c:
        r = c.post("/api/prove/vuln:10.9.9.9:0:nonesuch:no-title")
        assert r.status_code == 404, r.text
