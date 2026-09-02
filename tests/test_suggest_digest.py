"""Suggest tab — /api/suggest/digest route + CLI/webUI parity.

The route exists so the WebUI's Suggest tab renders exactly what the
`recce suggest` CLI command prints. Two things must not drift:

  1. The three section keys the JSON exposes match the three sections
     `_suggest.py` renders (metrics / rules / exploit_findings).
  2. The exploit-findings ordering and shape mirror the CLI's
     (tier ↓, sev ↓, KEV ↓, EPSS ↓) row-by-row.
"""
from __future__ import annotations

import inspect
import pathlib

from fastapi.testclient import TestClient

from recce.cli import _open_paths, _suggest
from recce.core.models import Host, Port, Vuln
from recce.core.store import Store
from recce.webui.app import create_app
from recce.webui.routes.suggest_digest import DIGEST_SECTION_KEYS


def _seed(eng_dir: str) -> None:
    """Two vulns with exploit_note / depth_tier and one without."""
    st = Store(_open_paths(eng_dir)["db"])
    st.set_meta("engagement", "suggest-digest test")

    h1 = Host(ip="10.9.9.1", up_reason="syn-ack",
              ports=[Port(portid=445, service="microsoft-ds", state="open")])
    h1.vulns = [Vuln(
        ip="10.9.9.1", port=445, protocol="tcp", script_id="smb-eternalblue",
        state="VULNERABLE", title="EternalBlue (MS17-010)",
        severity="critical", source="smb",
        exploit_note="msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue'",
        depth_tier="t3",
        ids=["CVE-2017-0144"], kev=True, epss=0.97,
    )]
    st.upsert_host(h1)

    h2 = Host(ip="10.9.9.2", up_reason="syn-ack",
              ports=[Port(portid=27017, service="mongodb", state="open")])
    h2.vulns = [Vuln(
        ip="10.9.9.2", port=27017, protocol="tcp", script_id="mongodb-unauth",
        state="VULNERABLE", title="MongoDB no-auth listAll",
        severity="high", source="mongodb",
        exploit_note="mongosh mongodb://10.9.9.2:27017 --eval 'db.adminCommand({listDatabases:1})'",
        depth_tier="t2",
        ids=["CVE-2020-9999"], kev=True, epss=0.85,
    )]
    st.upsert_host(h2)

    # Vuln without exploit_note or depth_tier must NOT surface.
    h3 = Host(ip="10.9.9.3", up_reason="syn-ack",
              ports=[Port(portid=22, service="ssh", state="open")])
    h3.vulns = [Vuln(
        ip="10.9.9.3", port=22, protocol="tcp", script_id="ssh-banner",
        state="finding", title="OpenSSH banner",
        severity="info", source="ssh",
    )]
    st.upsert_host(h3)
    st.close()


def test_suggest_digest_returns_all_sections(tmp_path: pathlib.Path) -> None:
    eng = tmp_path / "eng_sd"
    _seed(str(eng))
    with TestClient(create_app(str(eng))) as c:
        r = c.get("/api/suggest/digest")
        assert r.status_code == 200
        data = r.json()

    # Every section key the digest advertises is in the payload.
    for k in DIGEST_SECTION_KEYS:
        assert k in data, k

    m = data["metrics"]
    assert m["host_count"] == 3          # three hosts seeded
    assert m["cred_count"] == 0
    assert m["loot_present"] is False
    assert m["exploit_findings_total"] == 2  # h1 + h2; h3 (no note/tier) dropped

    findings = data["exploit_findings"]
    assert len(findings) == 2
    # Ranking: t3 (EternalBlue) → t2 (Mongo).
    assert findings[0]["tier"] == "t3"
    assert findings[0]["title"].startswith("EternalBlue")
    assert findings[0]["tier_label"] == "initial-access"
    assert findings[0]["kev"] is True
    assert findings[0]["cves"] == ["CVE-2017-0144"]

    assert findings[1]["tier"] == "t2"
    assert findings[1]["title"].startswith("MongoDB")

    # Rules section is a list (may be empty for a bare engagement — the
    # cross-service rules key off shared surfaces we didn't seed).
    assert isinstance(data["rules"], list)


def test_suggest_digest_top_query_bounds(tmp_path: pathlib.Path) -> None:
    """top=1 caps exploit_findings + rules to one row each."""
    eng = tmp_path / "eng_sd_top"
    _seed(str(eng))
    with TestClient(create_app(str(eng))) as c:
        r = c.get("/api/suggest/digest?top=1")
        assert r.status_code == 200
        data = r.json()
    assert data["top"] == 1
    assert len(data["exploit_findings"]) == 1
    assert data["exploit_findings"][0]["tier"] == "t3"  # tier-sorted top pick
    assert len(data["rules"]) <= 1
    # But the totals in `metrics` still reflect the un-capped counts.
    assert data["metrics"]["exploit_findings_total"] == 2


def test_suggest_digest_empty_engagement(tmp_path: pathlib.Path) -> None:
    """Empty engagement: 200 with zeroed metrics and empty lists."""
    eng = tmp_path / "eng_empty"
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "empty")
    st.close()
    with TestClient(create_app(str(eng))) as c:
        r = c.get("/api/suggest/digest")
        assert r.status_code == 200
        data = r.json()
    assert data["metrics"]["host_count"] == 0
    assert data["metrics"]["cred_count"] == 0
    assert data["exploit_findings"] == []
    assert data["rules"] == []


def test_digest_sections_match_cli_output_shape() -> None:
    """Parity: every section the JSON exposes has a matching label the CLI
    prints. Guards against a rename on one side that silently diverges
    from the other."""
    src = inspect.getsource(_suggest)
    # `cmd_suggest` prints these three headers; the JSON sections mirror them.
    assert "engagement at " in src           # metrics section
    assert "cross-service next moves" in src  # rules section
    assert "proven-exploitable findings" in src  # exploit_findings section

    # And the three JSON keys are exactly the sections above.
    assert set(DIGEST_SECTION_KEYS) == {
        "metrics", "rules", "exploit_findings",
    }

    # Every helper the JSON route depends on for parity is present in the
    # CLI module (so a rename there is a compile-time failure here too).
    assert hasattr(_suggest, "_run_rules")
    assert hasattr(_suggest, "_exploit_findings")
    assert hasattr(_suggest, "_tier_rank")
    assert hasattr(_suggest, "_tier_label")
