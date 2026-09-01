"""P1-5 — /api/attack-chain/cloud walkthrough endpoint tests.

Six-step story: IMDS reachable → v1 present → IAM role disclosed →
STS creds extracted → S3 bucket listing → secrets manager read. The
tests cover the empty case, an IMDS-reachable case, and an
IMDS-creds-extracted case that proves the T3 sts_creds_extracted step
via a Credential(source='imds').
"""
from __future__ import annotations

import pathlib

from fastapi.testclient import TestClient

from recce.cli import _open_paths
from recce.core.models import Credential, Host, Port, Vuln
from recce.core.store import Store
from recce.webui.app import create_app


_EXPECTED_STEPS = [
    "imds_reachable", "imds_v1_present", "iam_role_disclosed",
    "sts_creds_extracted", "s3_buckets_listed", "secrets_manager_read",
]


def _fresh(eng: pathlib.Path) -> None:
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "p1-5 empty")
    st.close()


def test_cloud_chain_empty_engagement(tmp_path: pathlib.Path) -> None:
    """No hosts, no creds — every step pending, hero next_action is the
    imds_reachable advisory."""
    eng = tmp_path / "eng_empty"
    _fresh(eng)
    with TestClient(create_app(str(eng))) as c:
        r = c.get("/api/attack-chain/cloud")
        assert r.status_code == 200
        data = r.json()

    ids = [s["id"] for s in data["steps"]]
    assert ids == _EXPECTED_STEPS, ids
    statuses = {s["status"] for s in data["steps"]}
    assert statuses == {"pending"}
    # P1-4 — contributing_hosts on every step (empty here).
    for s in data["steps"]:
        assert s["contributing_hosts"] == []

    summary = data["summary"]
    assert summary["proven"] == 0
    assert summary["blocked"] == 0
    assert summary["pending"] == len(_EXPECTED_STEPS)
    assert "169.254.169.254" in summary["next_action"], summary["next_action"]


def test_cloud_chain_imds_reachable_and_v1(tmp_path: pathlib.Path) -> None:
    """A host with a cloud_metadata 'reachable' finding + imds_v1_enabled
    finding proves the first two steps; the rest stay blocked/pending."""
    eng = tmp_path / "eng_imds"
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "p1-5 imds")

    h = Host(ip="10.42.0.5", up_reason="syn-ack",
             ports=[Port(portid=80, service="http", state="open")])
    h.vulns = [
        Vuln(ip="10.42.0.5", port=80, protocol="tcp",
             script_id="imds_reachable",
             title="AWS IMDS reachable via SSRF",
             severity="high", source="cloud_metadata",
             output="169.254.169.254 responded HTTP 200"),
        Vuln(ip="10.42.0.5", port=80, protocol="tcp",
             script_id="imds_v1_enabled",
             title="IMDSv1 accessible without token",
             severity="high", source="cloud_metadata",
             output="curl without X-aws-ec2-metadata-token succeeded"),
    ]
    st.upsert_host(h)
    st.close()

    with TestClient(create_app(str(eng))) as c:
        data = c.get("/api/attack-chain/cloud").json()

    steps = {s["id"]: s for s in data["steps"]}
    assert steps["imds_reachable"]["status"] == "proven"
    assert steps["imds_v1_present"]["status"] == "proven"
    # contributing_hosts wired.
    assert steps["imds_reachable"]["contributing_hosts"] == ["10.42.0.5"]
    assert steps["imds_v1_present"]["contributing_hosts"] == ["10.42.0.5"]

    # No IAM finding was seeded → iam_role_disclosed is pending (or
    # blocked if a downstream step proved, which it hasn't here).
    assert steps["iam_role_disclosed"]["status"] == "pending"
    assert steps["sts_creds_extracted"]["status"] == "pending"


def test_cloud_chain_imds_creds_prove_sts(tmp_path: pathlib.Path) -> None:
    """A Credential(source='imds') on its own proves the T3
    sts_creds_extracted step; earlier legs stay pending → blocked."""
    eng = tmp_path / "eng_imds_creds"
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "p1-5 imds creds")
    st.add_credential(Credential(
        username="AKIA-test", secret="secret/value/token",
        kind="password", source="imds", origin_ip="10.42.0.5",
        notes="STS session credential from IMDS pivot"))
    st.close()

    with TestClient(create_app(str(eng))) as c:
        data = c.get("/api/attack-chain/cloud").json()

    steps = {s["id"]: s for s in data["steps"]}
    assert steps["sts_creds_extracted"]["status"] == "proven", \
        steps["sts_creds_extracted"]
    # Evidence carries the credential label + IMDS provenance.
    ev = steps["sts_creds_extracted"]["evidence"]
    assert ev and "IMDS" in ev[0]["output_excerpt"], ev
    # Earlier steps have no upstream evidence and a LATER step is proven →
    # they must be blocked, not pending.
    for sid in ("imds_reachable", "imds_v1_present", "iam_role_disclosed"):
        assert steps[sid]["status"] == "blocked", (sid, steps[sid])

    summary = data["summary"]
    assert summary["proven"] >= 1
    # highest_reached is the sts step (the only proven one).
    assert summary["highest_reached"] == "sts_creds_extracted"
