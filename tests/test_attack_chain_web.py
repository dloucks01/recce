"""P1-6 — /api/attack-chain/web walkthrough endpoint tests.

Six-step story: web surface fingerprinted → >1 versions pinned → KEV
match → T2 safe-verify → OOB callback → authenticated session. Tests
cover the empty case, a two-fingerprint case (steps 1+2 prove) with a
KEV n-day (step 3), and a session-credential case (step 6).
"""
from __future__ import annotations

import pathlib

from fastapi.testclient import TestClient

from recce.cli import _open_paths
from recce.core.models import Credential, Host, Port, Vuln
from recce.core.store import Store
from recce.webui.app import create_app


_EXPECTED_STEPS = [
    "web_surface_fingerprinted", "product_version_pinned", "kev_matched",
    "poc_safe_verify_fires", "oob_callback_triggered", "session_established",
]


def _fresh(eng: pathlib.Path) -> None:
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "p1-6 empty")
    st.close()


def test_web_chain_empty_engagement(tmp_path: pathlib.Path) -> None:
    """No hosts, no creds — every step pending; hero next_action is the
    fingerprint advisory."""
    eng = tmp_path / "eng_empty"
    _fresh(eng)
    with TestClient(create_app(str(eng))) as c:
        r = c.get("/api/attack-chain/web")
        assert r.status_code == 200
        data = r.json()

    ids = [s["id"] for s in data["steps"]]
    assert ids == _EXPECTED_STEPS, ids
    assert {s["status"] for s in data["steps"]} == {"pending"}
    for s in data["steps"]:
        assert s["contributing_hosts"] == []

    summary = data["summary"]
    assert summary["proven"] == 0
    assert summary["pending"] == len(_EXPECTED_STEPS)
    assert ("whatweb" in summary["next_action"]
            or "nmap" in summary["next_action"]), summary["next_action"]


def test_web_chain_fingerprint_and_kev(tmp_path: pathlib.Path) -> None:
    """Two distinct web fingerprints + a KEV-flagged web Vuln prove the
    first three steps."""
    eng = tmp_path / "eng_web"
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "p1-6 web")

    h1 = Host(ip="10.55.0.10", up_reason="syn-ack",
              ports=[Port(portid=80, service="http",
                          state="open", product="Apache httpd",
                          version="2.4.49"),
                     Port(portid=443, service="https",
                          state="open", product="nginx", version="1.18.0")])
    h1.vulns = [
        Vuln(ip="10.55.0.10", port=80, protocol="tcp",
             script_id="apache-path-traversal",
             title="Apache 2.4.49 path traversal",
             severity="critical", source="http",
             ids=["CVE-2021-41773"], kev=True,
             output="curl 'http://.../../../../etc/passwd' returned root:x:0..."),
    ]

    # A second host with different fingerprint on port 8080 — proves the
    # product_version_pinned step (>1 distinct product+version).
    h2 = Host(ip="10.55.0.11", up_reason="syn-ack",
              ports=[Port(portid=8080, service="http",
                          state="open", product="Tomcat", version="9.0.30")])
    st.upsert_host(h1)
    st.upsert_host(h2)
    st.close()

    with TestClient(create_app(str(eng))) as c:
        data = c.get("/api/attack-chain/web").json()

    steps = {s["id"]: s for s in data["steps"]}
    assert steps["web_surface_fingerprinted"]["status"] == "proven", \
        steps["web_surface_fingerprinted"]
    assert steps["product_version_pinned"]["status"] == "proven"
    assert steps["kev_matched"]["status"] == "proven"

    # contributing_hosts on the fingerprint step names both hosts.
    fp_hosts = steps["web_surface_fingerprinted"]["contributing_hosts"]
    assert set(fp_hosts) == {"10.55.0.10", "10.55.0.11"}, fp_hosts
    # Dedup — the h1 apache/nginx pair contributes two evidence rows but
    # one IP.
    assert len(fp_hosts) == len(set(fp_hosts))

    kev_ev = steps["kev_matched"]["evidence"]
    assert kev_ev and "CVE-2021-41773" in kev_ev[0]["output_excerpt"], kev_ev

    # Later steps unproven → they're blocked (kev is proven upstream of them
    # only for steps AFTER kev_matched in the chain).
    assert steps["poc_safe_verify_fires"]["status"] == "pending"


def test_web_chain_session_established(tmp_path: pathlib.Path) -> None:
    """A cracked / spray-validated Credential proves session_established
    at the tail of the chain; earlier legs become blocked."""
    eng = tmp_path / "eng_sess"
    st = Store(_open_paths(str(eng))["db"])
    st.set_meta("engagement", "p1-6 session")
    st.add_credential(Credential(
        username="webadmin", secret="hunter2", kind="password",
        source="cracked", origin_ip="10.55.0.10"))
    st.close()

    with TestClient(create_app(str(eng))) as c:
        data = c.get("/api/attack-chain/web").json()

    steps = {s["id"]: s for s in data["steps"]}
    assert steps["session_established"]["status"] == "proven", \
        steps["session_established"]
    # Everything before it must be blocked (later step proved, earlier
    # unproven).
    for sid in ("web_surface_fingerprinted", "product_version_pinned",
                "kev_matched", "poc_safe_verify_fires",
                "oob_callback_triggered"):
        assert steps[sid]["status"] == "blocked", (sid, steps[sid])

    summary = data["summary"]
    assert summary["highest_reached"] == "session_established"
    # Blocked comes first in the next_action ranking — the "your next
    # action" hero should tell the tester to go back and fingerprint.
    assert ("whatweb" in summary["next_action"]
            or "nmap" in summary["next_action"]), summary["next_action"]
