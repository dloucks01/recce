"""CWE naming, inference, coverage, and the report/Act integration."""
from __future__ import annotations

from recce import act, cwe
from recce.models import Host, Port, Vuln


def _v(sid, title, cwes=None):
    return Vuln(ip="10.0.0.1", port=1, protocol="tcp", script_id=sid, title=title,
                state="VULNERABLE", severity="high", cwes=cwes or [])


def test_name_and_label_and_url():
    assert cwe.name("CWE-306") == "Missing Authentication for Critical Function"
    assert cwe.label("CWE-89") == "CWE-89 (SQL Injection)"
    assert cwe.label("CWE-99999") == "CWE-99999"          # unknown -> bare id
    assert cwe.url("CWE-22") == "https://cwe.mitre.org/data/definitions/22.html"


def test_infer_from_finding_vocabulary():
    cases = {
        ("krb5", "Kerberoastable svc_sql"): "CWE-522",
        ("postgres-trust-auth", "PostgreSQL trust authentication"): "CWE-306",
        ("snmp-public", "SNMP default community 'public'"): "CWE-1392",
        ("web-gitconfig", "Exposed .git/config"): "CWE-527",
        ("web-dotenv", "Exposed .env"): "CWE-526",
        ("nfs", "NFS export no_root_squash"): "CWE-732",
        ("web-sqli", "SQL injection in id"): "CWE-89",
        ("smb-security-mode", "SMB signing not required"): "CWE-287",
    }
    for (sid, title), want in cases.items():
        assert want in cwe.for_text(f"{sid} {title}"), f"{sid} -> {cwe.for_text(title)}"


def test_infer_prefers_existing_cwes():
    v = _v("x", "custom finding", cwes=["CWE-611"])
    assert cwe.infer(v) == ["CWE-611"]                    # keeps the hand-assigned one
    v2 = _v("postgres-trust-auth", "trust authentication")
    assert cwe.infer(v2) == ["CWE-306"]                   # infers when none


def test_coverage_groups_and_counts():
    h1 = Host(ip="10.0.0.5", vulns=[_v("redis-unauth", "Redis without authentication"),
                                    _v("snmp-public", "SNMP public community")])
    h2 = Host(ip="10.0.0.6", vulns=[_v("redis-unauth", "Redis without authentication")])
    cov = cwe.coverage([h1, h2])
    ids = {w["id"] for w in cov["weaknesses"]}
    assert "CWE-306" in ids and "CWE-1392" in ids
    top = cov["weaknesses"][0]                            # most-common first
    assert top["id"] == "CWE-306" and top["hosts"] == ["10.0.0.5", "10.0.0.6"]
    assert top["name"] == "Missing Authentication for Critical Function"


def test_report_docx_cwe_label_falls_back_to_fuller_table():
    from recce.report_docx import cwe_label
    # CWE-1392 isn't in report_docx's own table but is in recce.cwe -> resolves to a name
    assert cwe_label("CWE-1392") == "CWE-1392 (Use of Default Credentials)"


def test_names_table_covers_every_report_docx_cwe():
    # cwe.NAMES is the fuller, first-class table (its own docstring's claim) that
    # markdown/HTML's coverage() draws on - unlike report_docx.cwe_label(), it has no
    # fallback, so any CWE missing here renders with a blank "-" weakness name in
    # those reports' CWE coverage table. Regression: CWE-917 and 26 others were
    # missing, so a real finding's CWE row would render nameless.
    from recce.report_docx import _CWE_NAME
    missing = sorted(set(_CWE_NAME) - set(cwe.NAMES))
    assert missing == [], f"CWE(s) missing from cwe.NAMES: {missing}"


def test_act_cards_are_tagged_with_cwe():
    h = Host(ip="10.0.0.5", ports=[Port(portid=6379, service="redis", state="open")],
             vulns=[_v("redis-unauth", "Redis exposed without authentication")])
    loot = next(c for c in act.action_plan([h]) if c.archetype == "loot")
    assert loot.cwe == "CWE-306"
