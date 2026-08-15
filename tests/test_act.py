"""The Act phase (P1): findings -> classified, ranked action plan.

Pins the archetype classifier, the two-level ranking (tier then
impact×confidence×leverage), loot aggregation, and the credential-driven
crack/spray/blocked cards.
"""
from __future__ import annotations

import http.server
import threading
from pathlib import Path

from recce import act
from recce.cli import _open_paths
from recce.models import Credential, Host, Port, Vuln
from recce.store import Store


def _vuln(ip, port, sid, title, sev, **kw):
    return Vuln(ip=ip, port=port, protocol="tcp", script_id=sid, title=title,
                state="VULNERABLE", severity=sev, **kw)


def _host(ip, ports=(), vulns=(), **kw):
    return Host(ip=ip, ports=[Port(portid=p, service="x", state="open") for p in ports],
                vulns=list(vulns), **kw)


def test_unauth_service_becomes_an_auto_loot_card():
    h = _host("10.0.0.5", ports=[6379],
              vulns=[_vuln("10.0.0.5", 6379, "redis-unauth",
                           "Redis exposed without authentication", "high", qod=95)])
    cards = act.action_plan([h])
    loot = [c for c in cards if c.archetype == "loot"]
    assert loot and loot[0].tier == act.AUTO and loot[0].safety == "read-only"


def test_cred_loot_outranks_data_loot_via_leverage():
    # a .env exposure (yields creds -> feeds spray) must outscore a plain data loot.
    env = _vuln("10.0.0.5", 80, "web-dotenv", "Exposed .env — DB credentials", "high", qod=95)
    snmp = _vuln("10.0.0.6", 161, "snmp-public", "SNMP default community 'public'",
                 "medium", qod=92)
    cards = act.action_plan([_host("10.0.0.5", [80], [env]),
                             _host("10.0.0.6", [161], [snmp])])
    loot = [c for c in cards if c.archetype == "loot"]
    assert loot[0].command.startswith("recce web")        # cred loot is first
    assert "credentials" in loot[0].yields


def test_loot_findings_sharing_a_command_collapse_to_one_card():
    # three web hosts each exposing .git -> ONE `recce web` card (count 3), not three.
    hosts = [_host(f"10.0.0.{i}", [80],
                   [_vuln(f"10.0.0.{i}", 80, "web-gitconfig", "Exposed .git/config",
                          "high", qod=95)]) for i in (5, 6, 7)]
    cards = act.action_plan(hosts)
    web = [c for c in cards if c.command.startswith("recce web")]
    assert len(web) == 1 and web[0].count == 3


def test_dc_rce_is_top_ranked_and_labels_domain_compromise():
    dc = _host("10.0.0.10", [445], roles=["Domain Controller"],
               vulns=[_vuln("10.0.0.10", 445, "smb-vuln-zerologon", "Zerologon",
                            "critical", ids=["CVE-2020-1472"], kev=True, epss=0.94, qod=98)])
    member = _host("10.0.0.23", [445],
                   vulns=[_vuln("10.0.0.23", 445, "smb-vuln-ms17-010", "EternalBlue",
                                "critical", ids=["CVE-2017-0144"], kev=True, epss=0.9, qod=97)])
    cards = act.action_plan([dc, member])
    exploits = [c for c in cards if c.archetype == "exploit"]
    assert exploits[0].target.startswith("10.0.0.10")     # the DC exploit ranks first
    assert exploits[0].yields == "domain compromise"
    assert exploits[0].score > exploits[1].score          # DC leverage wins
    # a member-server RCE is NOT mislabelled domain compromise (EPSS only bumps score)
    assert exploits[1].yields != "domain compromise"


def test_low_qod_exploit_is_a_lead_not_ready():
    h = _host("10.0.0.9", [3389],
              vulns=[_vuln("10.0.0.9", 3389, "rdp-vuln", "BlueKeep candidate", "critical",
                           ids=["CVE-2019-0708"], qod=45)])       # version-inference lead
    card = next(c for c in act.action_plan([h]) if c.archetype == "exploit")
    assert card.tier == act.LEAD


def test_captured_hash_yields_a_crack_card_with_the_right_mode():
    h = _host("10.0.0.5", [445])
    creds = [Credential(username="root", secret="*ABC", kind="nthash",
                        source="mysql-loot", origin_ip="10.0.0.5",
                        notes="mysql.user hash; hashcat -m 300")]
    crack = next(c for c in act.action_plan([h], creds) if c.archetype == "crack")
    assert "-m 300" in crack.command and crack.tier == act.READY


def test_spray_card_appears_with_creds_and_a_surface_and_scales_leverage():
    hosts = [_host(f"10.0.0.{i}", [445]) for i in range(5, 25)]   # 20 SMB hosts
    creds = [Credential(username="svc", secret="P@ss", kind="password", source="loot")]
    spray = next(c for c in act.action_plan(hosts, creds) if c.archetype == "spray")
    assert spray.tier == act.AUTO and spray.leverage > 1.0
    assert "creds --plan" in spray.command


def test_auth_surface_without_creds_is_a_blocked_card():
    hosts = [_host("10.0.0.5", [445])]                    # SMB, but no creds yet
    spray = next(c for c in act.action_plan(hosts, []) if c.archetype == "spray")
    assert spray.tier == act.BLOCKED
    assert any(not met for _d, met in spray.preconditions)


def test_foothold_emits_an_escalate_card():
    h = _host("10.0.0.5", [22], access_gained=True, privesc_checked=False)
    esc = [c for c in act.action_plan([h]) if c.archetype == "escalate"]
    assert esc and esc[0].yields.startswith("SYSTEM")


# ------------------------------ P2: auto-execution -------------------------------

def _serve_http(root: Path):
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(root), **k)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_execute_auto_builds_spray_plan_from_existing_creds(tmp_path):
    st = Store(_open_paths(str(tmp_path / "e"))["db"])
    try:
        st.upsert_host(_host("10.0.0.5", [445]))          # an SMB surface
        st.add_credential(Credential(username="svc", secret="P@ss", kind="password",
                                     source="loot"))
        summary = act.execute_auto(st, str(tmp_path / "e"))
        assert summary["looted"] == []                    # nothing to loot
        assert "passwords.txt" in summary["spray"]["files"]
        assert "P@ss" in Path(summary["spray"]["files"]["passwords.txt"]).read_text()
    finally:
        st.close()


def test_execute_auto_loots_web_env_then_spray_carries_the_password(tmp_path):
    # The full P2 loop: a flagged .env exposure -> auto-loot the cleartext DB cred ->
    # persist it -> the spray plan is (re)built carrying that looted password.
    root = tmp_path / "web"
    root.mkdir()
    (root / ".env").write_text("DB_USER=webapp\nDB_PASSWORD=Pa55w0rd-Prod\n")
    srv = _serve_http(root)
    port = srv.server_address[1]
    st = Store(_open_paths(str(tmp_path / "eng"))["db"])
    try:
        h = Host(ip="127.0.0.1",
                 ports=[Port(portid=port, service="http", state="open"),
                        Port(portid=22, service="ssh", state="open")],   # spray surface
                 vulns=[Vuln(ip="127.0.0.1", port=port, protocol="tcp",
                             script_id="web-dotenv", title="Exposed .env", state="VULNERABLE",
                             severity="high", qod=95)])
        st.upsert_host(h)
        summary = act.execute_auto(st, str(tmp_path / "eng"))
    finally:
        srv.shutdown()
    try:
        assert any(c.secret == "Pa55w0rd-Prod" for c in summary["looted"])
        assert any(c.secret == "Pa55w0rd-Prod" for c in st.all_credentials())
        pw = Path(summary["spray"]["files"]["passwords.txt"]).read_text()
        assert "Pa55w0rd-Prod" in pw                       # loot -> store -> spray plan
    finally:
        st.close()


def test_execute_auto_is_bounded_and_idempotent(tmp_path):
    # No loot opportunities -> exactly one pass, no crash, empty loot.
    st = Store(_open_paths(str(tmp_path / "e"))["db"])
    try:
        st.upsert_host(_host("10.0.0.9", [80]))            # web host, but NO loot finding
        summary = act.execute_auto(st, str(tmp_path / "e"))
        assert summary["passes"] == 1 and summary["looted"] == []
    finally:
        st.close()


def test_plan_is_ordered_auto_then_ready_then_blocked():
    # tiers must come out grouped/ordered regardless of insertion order.
    dc = _host("10.0.0.10", [445], roles=["Domain Controller"],
               vulns=[_vuln("10.0.0.10", 445, "zerologon", "Zerologon", "critical",
                            ids=["CVE-2020-1472"], kev=True, qod=98)])
    redis = _host("10.0.0.5", [6379],
                  vulns=[_vuln("10.0.0.5", 6379, "redis-unauth", "Redis unauth", "high", qod=95)])
    tiers = [c.tier for c in act.action_plan([dc, redis])]
    assert tiers == sorted(tiers)                         # non-decreasing tier order
