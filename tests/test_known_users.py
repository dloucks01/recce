"""creds.known_users: cross-service "users known to this engagement" set.

Consumers today: IPMI RAKP sweep. Structured so SSH spray, SMB user-enum
against unknown DCs, and SNMPv3 engineID discovery can consume the same
prioritized list without each rebuilding it.
"""
from __future__ import annotations

from recce.core.models import Account, Host
from recce.creds.known_users import (collect_user_accounts, known_users,
                                     _priority)


def _host_with(accs):
    h = Host(ip="10.0.0.1")
    h.accounts = accs
    return h


def test_priority_puts_admins_first_service_second_others_last():
    """The whole point of the prioritization: on a capped sweep, admins are
    the accounts most likely to have BMC access, then service accounts."""
    assert _priority("Administrator", {}) == 0
    assert _priority("root", {}) == 0
    assert _priority("alice", {"admincount": "1"}) == 0
    assert _priority("bob", {"memberof": "cn=Domain Admins,dc=corp"}) == 0
    assert _priority("svc_sccm", {}) == 1
    assert _priority("iis_appool", {}) == 1
    assert _priority("regular.user", {}) == 2


def test_collect_dedupes_case_insensitively_but_keeps_first_seen_casing():
    """SAMR gives Windows accounts as 'ADMIN', BloodHound as 'admin',
    LDAP as 'Admin' — all one account. First-seen casing wins."""
    hosts = [_host_with([
        Account(ip="1.1.1.1", source="ldap", kind="user", name="Admin"),
        Account(ip="1.1.1.1", source="bloodhound", kind="user", name="admin"),
        Account(ip="1.1.1.1", source="snmp", kind="user", name="ADMIN"),
    ])]
    accts = collect_user_accounts(hosts)
    assert len(accts) == 1
    assert accts[0]["name"] == "Admin"
    assert set(accts[0]["sources"]) == {"ldap", "bloodhound", "snmp"}


def test_collect_strips_domain_prefix_from_samr_style_names():
    """SAMR returns DOMAIN\\name; BMC sweeps want the leading component only."""
    hosts = [_host_with([
        Account(ip="1.1.1.1", source="netexec", kind="user", name="CORP\\alice"),
    ])]
    accts = collect_user_accounts(hosts)
    assert accts[0]["name"] == "alice"


def test_collect_skips_non_user_kinds():
    """Only kind=user is spray-relevant here (computers/groups/shares are noise
    for a BMC probe)."""
    hosts = [_host_with([
        Account(ip="1", source="ldap", kind="user", name="alice"),
        Account(ip="1", source="ldap", kind="group", name="Domain Admins"),
        Account(ip="1", source="ldap", kind="computer", name="WKS01$"),
        Account(ip="1", source="ldap", kind="share", name="C$"),
    ])]
    assert [a["name"] for a in collect_user_accounts(hosts)] == ["alice"]


def test_known_users_extras_prepended_verbatim_and_cap_only_applies_to_added():
    """Extras (the vendor defaults for IPMI, or an operator-supplied list)
    always fit — the cap bounds only what recce adds from the store."""
    hosts = [_host_with([
        Account(ip="1.1.1.1", source="ldap", kind="user", name=f"user{i}")
        for i in range(50)
    ])]
    picked = known_users(hosts, cap=5, extras=["root", "admin", "ADMIN"])
    assert picked["users"][:3] == ["root", "admin", "ADMIN"]
    # Cap 5 → 5 more from the store on top of extras = 8 total
    assert len(picked["users"]) == 3 + 5
    assert picked["total_known"] == 50
    assert picked["capped"] is True


def test_known_users_reports_not_capped_when_cap_exceeds_available():
    hosts = [_host_with([
        Account(ip="1.1.1.1", source="ldap", kind="user", name="alice"),
        Account(ip="1.1.1.1", source="ldap", kind="user", name="bob"),
    ])]
    picked = known_users(hosts, cap=25, extras=["root"])
    assert picked["capped"] is False
    assert picked["total_known"] == 2
    assert set(picked["users"]) == {"root", "alice", "bob"}


def test_known_users_prioritizes_admins_when_the_cap_bites():
    """On a cap-limited sweep, admin accounts must land in the picked list
    before ordinary users — otherwise the highest-value target is skipped."""
    hosts = [_host_with([
        Account(ip="1", source="ldap", kind="user", name=f"user{i}")
        for i in range(20)
    ] + [
        Account(ip="1", source="ldap", kind="user", name="svc_sql"),   # priority 1
        Account(ip="1", source="ldap", kind="user", name="Administrator"),
        Account(ip="1", source="ldap", kind="user", name="bob",
                attrs={"admincount": "1"}),                            # priority 0
    ])]
    picked = known_users(hosts, cap=3)
    # Top 3 by priority: 2 admins (Administrator, bob) + 1 service (svc_sql)
    got = set(picked["users"])
    assert "Administrator" in got and "bob" in got and "svc_sql" in got
    assert not (got & {f"user{i}" for i in range(20)})


# --- IPMI RAKP integration --------------------------------------------------

def test_ipmi_analyze_pulls_known_users_from_the_engagement():
    """The wire: analyze() calls known_users(hosts) and hands the resulting
    list to each RAKP sweep. Without an operator override, that list should
    include AD-enum users on top of the vendor defaults."""
    from recce.services import ipmi
    from recce.core.models import Port
    dc = Host(ip="10.0.0.10")
    dc.accounts = [
        Account(ip="10.0.0.10", source="bloodhound", kind="user", name="alice"),
        Account(ip="10.0.0.10", source="ldap", kind="user", name="svc_sccm"),
    ]
    bmc = Host(ip="10.0.0.20",
               ports=[Port(portid=623, protocol="udp", state="open", service="ipmi")])
    result = ipmi.analyze([dc, bmc], active=False)
    assert "rakp" in result
    users = result["rakp"]["users"]
    # Vendor defaults present
    assert "root" in users and "admin" in users and "USERID" in users
    # AD-enum users appended after
    assert "alice" in users and "svc_sccm" in users
    # Sources signal what fed the list
    assert set(result["rakp"]["known"]["sources"]) == {"bloodhound", "ldap"}


def test_ipmi_analyze_honours_operator_rakp_users_override():
    from recce.services import ipmi
    from recce.core.models import Port
    dc = Host(ip="10.0.0.10")
    dc.accounts = [Account(ip="10.0.0.10", source="ldap", kind="user", name="alice")]
    bmc = Host(ip="10.0.0.20",
               ports=[Port(portid=623, protocol="udp", state="open", service="ipmi")])
    result = ipmi.analyze([dc, bmc], active=False, rakp_users=["bob", "carol"])
    # Operator override REPLACES the auto-union: alice is NOT probed
    assert result["rakp"]["users"] == ["bob", "carol"]
    assert result["rakp"]["known"]["sources"] == ["operator-supplied"]


def test_bloodhound_extract_lands_user_and_computer_accounts_on_the_dc():
    """The other half of the wire: BloodHound → host.accounts, so IPMI can
    see AD users without a second import step."""
    from recce.ad import bloodhound as bh
    graph = {"nodes": {
        "S-1-5-21-A": {"type": "User", "name": "ALICE@CORP.LOCAL",
                       "domain": "CORP.LOCAL",
                       "props": {"enabled": True, "admincount": True}},
        "S-1-5-21-B": {"type": "User", "name": "DISABLED@CORP.LOCAL",
                       "domain": "CORP.LOCAL",
                       "props": {"enabled": False}},                # skipped
        "S-1-5-21-C": {"type": "Computer", "name": "DC01$@CORP.LOCAL",
                       "domain": "CORP.LOCAL", "props": {"enabled": True}},
        "S-1-5-21-D": {"type": "Group", "name": "Domain Admins",    # skipped
                       "domain": "CORP.LOCAL", "props": {}},
    }}
    accts = bh.analysis_to_accounts(graph, dc_ip="10.0.0.10")
    by_name = {a.name: a for a in accts}
    assert set(by_name) == {"ALICE", "DC01$"}
    assert by_name["ALICE"].kind == "user"
    assert by_name["ALICE"].attrs.get("admincount") == "1"
    assert by_name["DC01$"].kind == "computer"
