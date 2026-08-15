"""MITRE ATT&CK technique mapping: findings -> techniques, coverage, Act tagging."""
from __future__ import annotations

from recce import act, attack
from recce.models import Host, Port, Vuln


def _v(sid, title, sev="high", **kw):
    return Vuln(ip="10.0.0.1", port=1, protocol="tcp", script_id=sid, title=title,
                state="VULNERABLE", severity=sev, **kw)


def test_specific_technique_mappings():
    cases = {
        ("krb5-enum-spn", "Kerberoastable service account"): ("T1558.003", "Credential Access"),
        ("asrep", "AS-REP roastable user"): ("T1558.004", "Credential Access"),
        ("smb-vuln-zerologon", "Zerologon — Netlogon privilege escalation"): ("T1068", "Privilege Escalation"),
        ("smb-vuln-ms17-010", "EternalBlue — remote code execution"): ("T1210", "Lateral Movement"),
        ("web-log4shell", "Log4Shell — JNDI RCE"): ("T1190", "Initial Access"),
        ("web-gitconfig", "Exposed .git/config"): ("T1552.001", "Credential Access"),
        ("web-dotenv", "Exposed .env"): ("T1552.001", "Credential Access"),
        ("postgres-trust-auth", "PostgreSQL trust authentication"): ("T1078", "Initial Access"),
        ("snmp-public", "SNMP default community 'public'"): ("T1078.001", "Initial Access"),
        ("smb-security-mode", "SMB signing not required"): ("T1557.001", "Credential Access"),
        ("smb-null-session-shares", "SMB shares over a null session"): ("T1135", "Discovery"),
        ("ldap-anon-bind", "LDAP allows anonymous bind"): ("T1087.002", "Discovery"),
    }
    for (sid, title), (tid, tactic) in cases.items():
        tech = attack.technique_for(_v(sid, title))
        assert tech is not None, f"{sid} unmapped"
        assert tech.id == tid and tech.tactic == tactic, f"{sid} -> {tech.id}/{tech.tactic}"


def test_unmappable_finding_is_none_not_a_wrong_code():
    assert attack.technique_for(_v("http-robots", "robots.txt discloses paths")) is None


def test_technique_url_and_tactic_id():
    tech = attack.technique_for(_v("krb5", "Kerberoasting"))
    assert tech.url == "https://attack.mitre.org/techniques/T1558/003/"
    assert tech.tactic_id == "TA0006"


def test_coverage_groups_by_tactic_and_counts_hosts():
    h1 = Host(ip="10.0.0.10", ports=[Port(portid=445, state="open")],
              vulns=[_v("smb-vuln-zerologon", "Zerologon", "critical"),
                     _v("krb5", "Kerberoastable svc_sql")])
    h2 = Host(ip="10.0.0.11", ports=[Port(portid=445, state="open")],
              vulns=[_v("smb-vuln-zerologon", "Zerologon", "critical")])
    cov = attack.coverage([h1, h2])
    assert cov["technique_count"] == 2                 # T1068 + T1558.003
    assert "Privilege Escalation" in cov["by_tactic"]
    pe = cov["by_tactic"]["Privilege Escalation"][0]
    assert pe["id"] == "T1068" and pe["hosts"] == ["10.0.0.10", "10.0.0.11"]


def test_act_cards_are_tagged_with_attack_techniques():
    h = Host(ip="10.0.0.5", ports=[Port(portid=6379, service="redis", state="open")],
             vulns=[_v("redis-unauth", "Redis exposed without authentication")])
    cards = act.action_plan([h])
    loot = next(c for c in cards if c.archetype == "loot")
    assert loot.attack_id                              # tagged
    # a spray card (archetype default) picks up the spraying technique
    h2 = Host(ip="10.0.0.6", ports=[Port(portid=445, state="open")])
    from recce.models import Credential
    cards2 = act.action_plan([h2], [Credential(username="u", secret="p", kind="password")])
    spray = next(c for c in cards2 if c.archetype == "spray")
    assert spray.attack_id == "T1110.003"
