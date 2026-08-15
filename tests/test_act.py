"""The Act phase (P1): findings -> classified, ranked action plan.

Pins the archetype classifier, the two-level ranking (tier then
impact×confidence×leverage), loot aggregation, and the credential-driven
crack/spray/blocked cards.
"""
from __future__ import annotations

from recce import act
from recce.models import Credential, Host, Port, Vuln


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


def test_plan_is_ordered_auto_then_ready_then_blocked():
    # tiers must come out grouped/ordered regardless of insertion order.
    dc = _host("10.0.0.10", [445], roles=["Domain Controller"],
               vulns=[_vuln("10.0.0.10", 445, "zerologon", "Zerologon", "critical",
                            ids=["CVE-2020-1472"], kev=True, qod=98)])
    redis = _host("10.0.0.5", [6379],
                  vulns=[_vuln("10.0.0.5", 6379, "redis-unauth", "Redis unauth", "high", qod=95)])
    tiers = [c.tier for c in act.action_plan([dc, redis])]
    assert tiers == sorted(tiers)                         # non-decreasing tier order
