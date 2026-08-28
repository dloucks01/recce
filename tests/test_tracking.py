"""Tests for recce/tracking.py — coverage-tracking primitives."""
from __future__ import annotations

import pytest

from recce.core.models import Account, Exploit, Host, Port, Vuln
from recce.core import tracking


# --- helpers: build hosts quickly -------------------------------------------

def _host(ip="10.0.0.1", ports=None, vulns=None, roles=None, **kw):
    return Host(ip=ip, state="up", up_reason="syn-ack",
                ports=ports or [], vulns=vulns or [], roles=roles or [], **kw)


def _port(portid=80, proto="tcp", service="http", state="open", **kw):
    return Port(portid=portid, protocol=proto, service=service, state=state, **kw)


def _vuln(ip="10.0.0.1", port=80, script_id="test", title="Test Vuln", **kw):
    return Vuln(ip=ip, port=port, protocol="tcp", script_id=script_id, title=title, **kw)


# --- key generation ---------------------------------------------------------

def test_host_key():
    assert tracking.host_key("10.0.0.1") == "host:10.0.0.1"


def test_svc_key():
    assert tracking.svc_key("10.0.0.1", "tcp", 80) == "svc:10.0.0.1:tcp:80"


def test_web_key():
    assert tracking.web_key("10.0.0.1", 443) == "web:10.0.0.1:443"


def test_vuln_key():
    assert tracking.vuln_key("10.0.0.1", 80, "ssl-heartbleed") == "vuln:10.0.0.1:80:ssl-heartbleed"


def test_vuln_key_none_port():
    assert tracking.vuln_key("10.0.0.1", None, "test") == "vuln:10.0.0.1:0:test"


def test_vuln_row_key_tcp():
    v = _vuln(ip="10.0.0.1", port=445, script_id="smb-vuln", title="EternalBlue")
    key = tracking.vuln_row_key(v)
    assert key == "vuln:10.0.0.1:445:smb-vuln:EternalBlue"
    assert ":udp" not in key


def test_vuln_row_key_udp():
    v = Vuln(ip="10.0.0.1", port=161, protocol="udp", script_id="snmp-brute",
             title="SNMP community string")
    key = tracking.vuln_row_key(v)
    assert key.endswith(":udp")


def test_vuln_row_key_title_truncated():
    long_title = "A" * 60 + "BBBBB"
    v = _vuln(title=long_title)
    key = tracking.vuln_row_key(v)
    assert long_title[:60] in key
    assert "BBBBB" not in key


def test_exploit_key():
    assert tracking.exploit_key("10.0.0.1", 80, "12345") == "exploit:10.0.0.1:80:12345"


def test_acct_key_without_rid():
    assert tracking.acct_key("ldap", "user", "corp", "admin") == "acct:ldap:user:corp:admin"


def test_acct_key_with_rid():
    k = tracking.acct_key("smb-enum-users", "user", "corp", "admin", "500")
    assert k == "acct:smb-enum-users:user:corp:admin:500"


def test_prod_key():
    assert tracking.prod_key("Apache|2.4.49") == "prod:Apache|2.4.49"


def test_subnet_key():
    assert tracking.subnet_key("10.0.0.0/24") == "subnet:10.0.0.0/24"


def test_step_key():
    assert tracking.step_key("enum", "10.0.0.1") == "step:enum:10.0.0.1"


# --- access_from_findings ---------------------------------------------------

def test_access_from_findings_smb_admin():
    h = _host(vulns=[_vuln(script_id="cred-smb-admin-local")])
    assert "SMB local admin" in tracking.access_from_findings(h)


def test_access_from_findings_secretsdump():
    h = _host(vulns=[_vuln(script_id="cred-secretsdump")])
    assert "secretsdump" in tracking.access_from_findings(h)


def test_access_from_findings_ssh():
    h = _host(vulns=[_vuln(script_id="ssh-sudo")])
    assert "SSH" in tracking.access_from_findings(h)


def test_access_from_findings_ssh_suid():
    h = _host(vulns=[_vuln(script_id="ssh-suid")])
    assert "SSH" in tracking.access_from_findings(h)


def test_access_from_findings_none():
    h = _host(vulns=[_vuln(script_id="http-vuln-cve2021-41773")])
    assert tracking.access_from_findings(h) == ""


def test_access_from_findings_empty():
    h = _host()
    assert tracking.access_from_findings(h) == ""


# --- step_applies -----------------------------------------------------------

def test_step_applies_enum_always():
    h = _host()
    assert tracking.step_applies(h, "enum") is True


def test_step_applies_vuln_needs_ports():
    h = _host(ports=[_port()])
    assert tracking.step_applies(h, "vuln") is True
    h_no_ports = _host()
    assert tracking.step_applies(h_no_ports, "vuln") is False


def test_step_applies_web_needs_web_port():
    h = _host(ports=[_port(portid=80, service="http")])
    assert tracking.step_applies(h, "web") is True
    h_no_web = _host(ports=[_port(portid=22, service="ssh")])
    assert tracking.step_applies(h_no_web, "web") is False


def test_step_applies_web_nonstandard_port_with_http_service():
    h = _host(ports=[_port(portid=9999, service="http-proxy")])
    assert tracking.step_applies(h, "web") is True


def test_step_applies_ad_with_dc_role():
    h = _host(roles=["Domain Controller"])
    assert tracking.step_applies(h, "ad") is True


def test_step_applies_ad_with_ldap_port():
    h = _host(ports=[_port(portid=389, service="ldap")])
    assert tracking.step_applies(h, "ad") is True


def test_step_applies_ad_no_ad_surface():
    h = _host(ports=[_port(portid=80)])
    assert tracking.step_applies(h, "ad") is False


def test_step_applies_db_with_mysql():
    h = _host(ports=[_port(portid=3306, service="mysql")])
    assert tracking.step_applies(h, "db") is True


def test_step_applies_db_no_db():
    h = _host(ports=[_port(portid=80)])
    assert tracking.step_applies(h, "db") is False


def test_step_applies_privesc():
    h = _host(privesc_checked=True)
    assert tracking.step_applies(h, "privesc") is True
    h2 = _host(privesc_checked=False)
    assert tracking.step_applies(h2, "privesc") is False


# --- step_auto --------------------------------------------------------------

def test_step_auto_enum_done():
    h = _host(enumerated=True)
    assert tracking.step_auto(h, "enum") is True


def test_step_auto_enum_incomplete():
    h = _host(enumerated=True, incomplete_scan=True)
    assert tracking.step_auto(h, "enum") is False


def test_step_auto_enum_not_run():
    h = _host(enumerated=False)
    assert tracking.step_auto(h, "enum") is False


def test_step_auto_vuln():
    h = _host(enumerated=True,
              ports=[_port(portid=80, vuln_scanned=True),
                     _port(portid=443, vuln_scanned=True)])
    assert tracking.step_auto(h, "vuln") is True


def test_step_auto_vuln_partial():
    h = _host(enumerated=True,
              ports=[_port(portid=80, vuln_scanned=True),
                     _port(portid=443, vuln_scanned=False)])
    assert tracking.step_auto(h, "vuln") is False


def test_step_auto_access():
    h = _host(access_gained=True)
    assert tracking.step_auto(h, "access") is True
    h2 = _host(access_gained=False)
    assert tracking.step_auto(h2, "access") is False


def test_step_auto_manual_steps_always_false():
    h = _host(enumerated=True, access_gained=True,
              ports=[_port(portid=80, vuln_scanned=True)])
    for step in ("ad", "creds", "lateral"):
        assert tracking.step_auto(h, step) is False


# --- item_keys --------------------------------------------------------------

def test_item_keys_basic():
    h = _host(ip="10.0.0.1", subnet="10.0.0.0/24",
              ports=[_port(portid=80, service="http")],
              vulns=[_vuln(ip="10.0.0.1", port=80)])
    keys = tracking.item_keys([h])
    assert "host:10.0.0.1" in keys["hosts"]
    assert "svc:10.0.0.1:tcp:80" in keys["services"]
    assert "web:10.0.0.1:80" in keys["web"]
    assert len(keys["vulns"]) == 1


def test_item_keys_skips_down_host_for_host_key():
    h = Host(ip="10.0.0.2", state="down", ports=[], vulns=[], roles=[])
    keys = tracking.item_keys([h])
    assert keys["hosts"] == []


def test_item_keys_includes_exploits():
    e = Exploit(ip="10.0.0.1", port=80, edb_id="99999", title="Test Exploit")
    h = _host(ip="10.0.0.1", ports=[_port(portid=80)])
    h.exploits = [e]
    keys = tracking.item_keys([h])
    assert "exploit:10.0.0.1:80:99999" in keys["exploits"]


def test_item_keys_includes_accounts():
    a = Account(ip="10.0.0.1", source="smb-enum-users", kind="user",
                name="admin", domain="corp", rid="500")
    h = _host(ip="10.0.0.1")
    h.accounts = [a]
    keys = tracking.item_keys([h])
    assert "acct:smb-enum-users:user:corp:admin:500" in keys["accounts"]


def test_item_keys_deduplicates():
    v1 = _vuln(ip="10.0.0.1", port=80, script_id="x", title="T")
    v2 = _vuln(ip="10.0.0.1", port=80, script_id="x", title="T")
    h = _host(ip="10.0.0.1", vulns=[v1, v2], ports=[_port(portid=80)])
    keys = tracking.item_keys([h])
    assert len(keys["vulns"]) == 1


# --- compute_coverage -------------------------------------------------------

def test_compute_coverage_empty():
    cov = tracking.compute_coverage([], {})
    assert cov["overall"]["total"] == 0
    assert cov["overall"]["pct"] == 100  # 0/0 → 100%


def test_compute_coverage_partial():
    h = _host(ip="10.0.0.1",
              ports=[_port(portid=80)],
              vulns=[_vuln(ip="10.0.0.1", port=80, script_id="a", title="A"),
                     _vuln(ip="10.0.0.1", port=80, script_id="b", title="B")])
    keys = tracking.item_keys([h])
    vk = keys["vulns"][0]
    trk = {vk: (True, "")}
    cov = tracking.compute_coverage([h], trk)
    assert cov["vulns"]["total"] == 2
    assert cov["vulns"]["done"] == 1
    assert cov["vulns"]["pct"] == 50


def test_compute_coverage_all_reviewed():
    h = _host(ip="10.0.0.1", ports=[_port(portid=22, service="ssh")])
    keys = tracking.item_keys([h])
    trk = {k: (True, "") for cat in keys.values() for k in cat}
    cov = tracking.compute_coverage([h], trk)
    assert cov["overall"]["pct"] == 100


# --- subnet_coverage --------------------------------------------------------

def test_subnet_coverage_basic():
    h1 = _host(ip="10.0.0.1", subnet="10.0.0.0/24")
    h2 = _host(ip="10.0.0.2", subnet="10.0.0.0/24")
    trk = {"host:10.0.0.1": (True, "")}
    sc = tracking.subnet_coverage([h1, h2], trk)
    assert sc["10.0.0.0/24"]["total"] == 2
    assert sc["10.0.0.0/24"]["done"] == 1
    assert sc["10.0.0.0/24"]["pct"] == 50


def test_subnet_coverage_skips_down():
    h1 = _host(ip="10.0.0.1", subnet="10.0.0.0/24")
    h2 = Host(ip="10.0.0.2", state="down", subnet="10.0.0.0/24")
    sc = tracking.subnet_coverage([h1, h2], {})
    assert sc["10.0.0.0/24"]["total"] == 1


def test_subnet_coverage_unknown_subnet():
    h = _host(ip="10.0.0.1", subnet="")
    sc = tracking.subnet_coverage([h], {})
    assert "unknown" in sc
    assert sc["unknown"]["total"] == 1
