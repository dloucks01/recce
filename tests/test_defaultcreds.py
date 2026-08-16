"""Default-credential knowledge base + the Act default-cred cards."""
from __future__ import annotations

from recce import act, defaultcreds
from recce.models import Host, Port


def _p(portid, service=""):
    return Port(portid=portid, service=service, state="open")


def test_service_key_by_name_then_port():
    assert defaultcreds.service_key(_p(22, "ssh")) == "ssh"
    assert defaultcreds.service_key(_p(445, "microsoft-ds")) == "smb"
    assert defaultcreds.service_key(_p(1433, "")) == "mssql"          # by port number
    assert defaultcreds.service_key(_p(9999, "")) is None


def test_creds_for_known_services():
    assert ("root", "root", "") in defaultcreds.creds_for(_p(22, "ssh"))
    assert any(u == "sa" for u, _p_, _n in defaultcreds.creds_for(_p(1433, "ms-sql")))
    assert defaultcreds.creds_for(_p(80, "http"))


def test_test_command_shapes():
    # nxc for ssh
    assert defaultcreds.test_command("ssh", ["10.0.0.5"]).startswith("nxc ssh")
    # snmp -> onesixtyone with community strings
    assert "onesixtyone" in defaultcreds.test_command("snmp", ["10.0.0.6"])
    # redis -> unauth check, no creds
    assert "unauth" in defaultcreds.test_command("redis", ["10.0.0.7"])
    # http -> hydra fallback (nxc has no http module)
    assert "hydra" in defaultcreds.test_command("http", ["10.0.0.8"])
    # targets are the discovered in-scope IPs only - never widened to a /24
    cmd = defaultcreds.test_command("ssh", ["10.0.0.5", "10.0.0.6"])
    assert "10.0.0.5 10.0.0.6" in cmd
    assert "/24" not in cmd
    # default pairs are aligned positionally for --no-bruteforce (root/root, pi/raspberry)
    assert "--no-bruteforce" in cmd
    assert "-u root root admin pi ubnt vagrant admin" in cmd
    assert "-p root toor admin raspberry ubnt vagrant password" in cmd


def test_act_emits_aggregated_default_cred_cards_tagged_t1078():
    hosts = [Host(ip=f"10.0.0.{i}", ports=[_p(22, "ssh")]) for i in (5, 6, 7)]
    cards = [c for c in act.action_plan(hosts) if c.archetype == "default-cred"]
    assert len(cards) == 1                          # one SSH card, aggregated
    c = cards[0]
    assert c.count == 3 and c.safety == "intrusive"
    assert c.attack_id == "T1078.001"
    assert "nxc ssh" in c.command


def test_default_cred_card_is_lockout_aware():
    h = Host(ip="10.0.0.5", ports=[_p(3389, "ms-wbt-server")])
    card = next(c for c in act.action_plan([h]) if c.archetype == "default-cred")
    assert any("lockout" in d.lower() for d, _met in card.preconditions)
