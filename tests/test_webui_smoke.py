"""End-to-end read-surface + scan-launcher smoke for the WebGUI.

Not a targeted unit test — a broad **sweep** over the whole API the SPA
touches on first load, plus a fire-and-cancel over every non-destructive
Scan-tab command against a mock engagement, so a bad rename, a moved
router import, or a regression in the scan spawner blocks the merge
before an operator hits it.

Two suites, both TestClient-based (no live server needed), both always-on:

  * ``ReadSurfaceSweep`` — every GET the frontend hits at load time.
    Each returns 2xx (or one of a small allow-list of "known-empty" 4xx
    responses that the SPA treats as normal), the content-type matches
    what the frontend parses, and where the frontend parses a shape it
    has the fields the frontend reads.

  * ``ScanLauncher`` — /api/commands + /api/scan/context describe the
    Scan tab. For every command whose entry does not require creds or
    an explicit target (i.e. safe to fire "as-is" against a mock),
    POST /api/scan and assert we get back a job id (or, for the small
    subset of always-guarded commands like sqli, an actionable 4xx).
    Then cancel to keep the run bounded.

Promoted from the P7 walkthrough's ad-hoc `api_sweep.py` and
`scan_smoke.py` scratchpad scripts — those needed a live server on
:8443; these run against a TestClient so CI can gate on them.
"""
from __future__ import annotations

import importlib.util
import pathlib
import time

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
    _load_mock().build(str(eng), hosts=16, seed=99)
    app = create_app(str(eng))
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Read-surface sweep
# ---------------------------------------------------------------------------

# (path, allowed_statuses, expected_content_type_fragment_or_None,
#  shape_check: (kind, keys))
#     kind: "dict" — response is a dict, must contain every key in `keys`
#           "list" — response is a list (keys ignored)
#           None   — no shape check, only status/content-type
READ_ENDPOINTS = [
    # --- engagement / hosts / findings ---
    ("/api/engagement",        {200}, "json", ("dict", ("hosts_total",))),
    ("/api/overview",          {200}, "json", ("dict", ("hosts_up", "by_severity"))),
    ("/api/hosts",             {200}, "json", ("dict", ("items",))),
    ("/api/findings",          {200}, "json", ("dict", ("items",))),
    ("/api/meta",              {200}, "json", ("dict", ())),
    ("/api/self/addresses",    {200}, "json", None),
    ("/api/issues",            {200}, "json", None),
    ("/api/scope",             {200}, "json", None),
    ("/api/writeups",          {200}, "json", None),
    # --- scan launcher ---
    ("/api/commands",          {200}, "json", ("dict", ())),
    ("/api/scan/context",      {200}, "json", ("dict", ("commands",))),
    ("/api/scan/suggestions",  {200}, "json", None),
    ("/api/wordlists",         {200}, "json", None),
    # --- reports ---
    ("/api/report/html",         {200}, "html", None),
    ("/api/report/md",           {200}, None,   None),
    ("/api/report/preview/html", {200}, "html", None),
    # --- collab / chat ---
    ("/api/collab",            {200}, "json", None),
    ("/api/chat",              {200}, "json", None),
    # --- sessions ---
    ("/api/listeners",         {200}, "json", None),
    ("/api/sessions",          {200}, "json", None),
    ("/api/sessions/quick-actions", {200}, "json", None),
    ("/api/teardown",          {200}, "json", None),
    # --- attack path / plan ---
    ("/api/playbook",          {200}, "json", None),
    ("/api/attackpath",        {200}, "json", None),
    ("/api/attackpath.svg",    {200}, "svg",  None),
    ("/api/attack",            {200}, "json", None),
    # --- bloodhound / prove / verify / suggest / act ---
    ("/api/bloodhound/status", {200}, "json", None),
    ("/api/prove/available",   {200}, "json", None),
    ("/api/verify",            {200}, "json", None),
    ("/api/suggest/digest",    {200}, "json", None),
    ("/api/act",               {200}, "json", ("dict", ("top", "tiers"))),
    # --- netmap ---
    ("/api/netmap/views",      {200}, "json", None),
    ("/api/netmap.svg",        {200}, "svg",  None),
    # --- jobs / engagements (P7) ---
    ("/api/jobs",              {200}, "json", None),
    ("/api/engagements",       {200}, "json", ("dict", ("current", "engagements"))),
]


@pytest.mark.parametrize(
    "path,allowed,ctype,shape",
    READ_ENDPOINTS,
    ids=[e[0] for e in READ_ENDPOINTS],
)
def test_read_endpoint_shape(client, path, allowed, ctype, shape):
    r = client.get(path)
    assert r.status_code in allowed, (
        f"{path} → {r.status_code} not in {allowed} · body={r.text[:200]!r}")
    if ctype:
        got = r.headers.get("content-type", "")
        assert ctype in got, f"{path} content-type={got!r} missing {ctype!r}"
    if shape:
        kind, keys = shape
        if kind == "dict":
            body = r.json()
            assert isinstance(body, dict), f"{path} not a dict"
            for k in keys:
                assert k in body, f"{path} missing key {k!r}"
        elif kind == "list":
            body = r.json()
            assert isinstance(body, list), f"{path} not a list"


def test_read_surface_covers_every_frontend_route(client):
    """Coverage: every path in READ_ENDPOINTS actually resolves to a route
    (i.e. hasn't been renamed / removed under our feet)."""
    for path, allowed, _ct, _sh in READ_ENDPOINTS:
        r = client.get(path)
        assert r.status_code != 404, f"{path} → 404 (route deleted or renamed?)"


# ---------------------------------------------------------------------------
# Scan launcher smoke
# ---------------------------------------------------------------------------

# Commands blacklisted from the auto-fire smoke — either destructive,
# require creds we don't have on a mock engagement, or are analyzers /
# generators rather than scans.
SKIP_SCAN_CMDS = frozenset({
    "sqli",         # active SQLi
    "credsweep", "spray",
    "attackpath", "exploitplan", "poc", "privesc", "prove",
    "report", "writeups", "status", "verify", "services",
    "loot-scan",    # local FS scan
    "deploy",       # ships on-target scripts
    "run",          # wizard, calls other scans
})


def _pick_scannable_commands(client):
    """Return the subset of catalog commands safe to smoke-fire on a mock."""
    catalog = client.get("/api/commands").json()
    context = client.get("/api/scan/context").json()["commands"]
    picks = []
    for cmd, spec in sorted(catalog.items()):
        if cmd in SKIP_SCAN_CMDS:
            continue
        info = context.get(cmd) or {}
        n = info.get("count", 0)
        sample = info.get("sample") or []
        target_req = spec.get("targets") == "required"
        if n > 0:
            picks.append((cmd, ", ".join(sample[:8])))
        elif not target_req:
            picks.append((cmd, ""))
        # else: needs targets, none discovered — skip (would 400 legitimately)
    return picks


def test_scan_launcher_catalog_is_non_empty(client):
    picks = _pick_scannable_commands(client)
    assert picks, (
        "no scannable commands discovered — either the catalog collapsed or "
        "the mock engagement no longer surfaces any targets")


def test_every_safe_scan_command_accepts_launch(client):
    """POST /api/scan for every safe command. Backend must return a job id
    (or an actionable 4xx we can inspect). We don't wait for output — the
    launcher itself is what's under test; job execution is covered by the
    per-service tests. We cancel each job to keep the run bounded."""
    picks = _pick_scannable_commands(client)
    started, guarded, failed = [], [], []
    for cmd, targets in picks:
        body = {"command": cmd, "targets": targets, "profile": "quick"}
        r = client.post("/api/scan", json=body)
        if 200 <= r.status_code < 300:
            j = r.json()
            jid = j.get("id") or j.get("job_id")
            if jid:
                started.append((cmd, jid))
            else:
                failed.append((cmd, r.status_code, str(j)[:120]))
        elif 400 <= r.status_code < 500:
            # An actionable client-error is a valid "guarded" outcome
            # (e.g. gated behind confirm flag). Backend just told us why.
            guarded.append((cmd, r.status_code, r.text[:120]))
        else:
            failed.append((cmd, r.status_code, r.text[:120]))

    # Cancel every job we started so we don't leave background scans running.
    for _cmd, jid in started:
        client.post(f"/api/jobs/{jid}/cancel")

    # A hard failure is a 5xx (or missing job id from a 2xx) — that's a bug
    # in the launcher. 4xx is fine, that's the launcher telling us "not with
    # these inputs" which is a legitimate answer.
    assert not failed, "\n".join(
        f"  {cmd:<20} http={code} → {msg}" for cmd, code, msg in failed)
    # And we did actually start something — otherwise the smoke isn't smoking.
    assert started, (
        f"no scans accepted for launch (only guarded={len(guarded)}) — "
        f"launcher may be blocking every command")


def test_job_lifecycle_shape(client):
    """A launched scan surfaces in /api/jobs with the fields the frontend
    reads (id, status, cmd, started). Cancel it before returning."""
    # Pick any safe target-optional command.
    picks = _pick_scannable_commands(client)
    cmd, targets = picks[0]
    r = client.post("/api/scan", json={
        "command": cmd, "targets": targets, "profile": "quick"})
    assert r.status_code == 200, r.text[:200]
    jid = r.json().get("id") or r.json().get("job_id")
    assert jid, r.json()

    # Give the spawner a beat to register the job.
    for _ in range(20):
        jobs = client.get("/api/jobs").json()
        if any(j.get("id") == jid for j in jobs):
            break
        time.sleep(0.05)
    matched = [j for j in jobs if j.get("id") == jid]
    assert matched, f"job {jid} not in /api/jobs listing"
    row = matched[0]
    for k in ("id", "status", "cmd"):
        assert k in row, f"job row missing {k!r}: {row!r}"

    client.post(f"/api/jobs/{jid}/cancel")
