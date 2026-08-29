"""core.known_domains: cross-service AD/Kerberos domain reader.

Fixtures use wire-format AD strings — LDAP defaultNamingContext DNs from
RFC 4514, NTLM Type 2 AV pair keys from MS-NLMP §2.2.2.1 — not any
recce encoder.
"""
from __future__ import annotations

from recce.core.known_domains import (_dns_from_dn, domain_for,
                                      kerberos_realm, known_domains)
from recce.core.models import Account, Credential, Host


def _dc(ip="10.0.0.10", *, dns="", nb="", tree="", dnc=""):
    h = Host(ip=ip)
    h.ntlm = {}
    if dns:
        h.ntlm["dns_domain"] = dns
    if nb:
        h.ntlm["netbios_domain"] = nb
    if tree:
        h.ntlm["dns_tree"] = tree
    if dnc:
        h.ntlm["default_naming_context"] = dnc
    return h


# --- RFC 4514 DN -> dotted DNS conversion ---------------------------------

def test_dn_to_dns_handles_multi_component_dc():
    assert _dns_from_dn("dc=corp,dc=local") == "corp.local"
    assert _dns_from_dn("DC=Corp,DC=local,DC=UK") == "Corp.local.UK"


def test_dn_to_dns_ignores_non_dc_rdns():
    # RFC 4514: DN can have CN=, OU=, etc. ahead of the DC= tail
    assert _dns_from_dn("CN=Configuration,DC=corp,DC=local") == "corp.local"


def test_dn_to_dns_empty_when_no_dc():
    assert _dns_from_dn("cn=Users") == ""
    assert _dns_from_dn("") == ""


# --- NTLM Type 2 AV-pair harvest -----------------------------------------
# NTLM AV pair keys used here match Microsoft's [MS-NLMP] §2.2.2.1:
#   MsvAvNbDomainName = 0x0002 -> netbios_domain
#   MsvAvDnsDomainName = 0x0004 -> dns_domain
#   MsvAvDnsTreeName = 0x0005 -> dns_tree (forest root)

def test_known_domains_reads_ntlm_pair_from_a_host():
    h = _dc(dns="corp.local", nb="CORP")
    kd = known_domains([h])
    assert kd["primary_dns"] == "corp.local"
    assert kd["primary_netbios"] == "CORP"
    # Same-exchange NTLM pair maps DNS<->NetBIOS
    entry = kd["domains"][0]
    assert entry["dns"] == "corp.local" and entry["netbios"] == "CORP"
    assert "ntlm" in entry["sources"]


def test_known_domains_records_forest_root_from_dns_tree():
    """MsvAvDnsTreeName is the forest ROOT domain — record it as an
    unmatched-DNS entry (not paired with netbios), which is correct
    behaviour: forest root usually differs from the joined domain."""
    h = _dc(dns="child.corp.local", nb="CHILD", tree="corp.local")
    kd = known_domains([h])
    dns_seen = {e["dns"] for e in kd["domains"]}
    assert "child.corp.local" in dns_seen
    assert "corp.local" in dns_seen


def test_known_domains_reads_ldap_default_naming_context():
    h = _dc(dnc="dc=corp,dc=local")
    kd = known_domains([h])
    assert kd["primary_dns"] == "corp.local"
    # Source label reflects producer (ldap vs ntlm)
    assert "ldap" in kd["domains"][0]["sources"]


# --- Case + normalization -----------------------------------------------

def test_known_domains_normalizes_dns_lowercase_and_netbios_upper():
    """DNS names are case-insensitive (RFC 4343); we lowercase for
    comparison. NetBIOS convention is UPPERCASE — reports read wrong
    otherwise."""
    h = _dc(dns="CORP.LOCAL", nb="corp")
    kd = known_domains([h])
    assert kd["primary_dns"] == "corp.local"
    assert kd["primary_netbios"] == "CORP"


# --- Multi-host union ---------------------------------------------------

def test_known_domains_unions_across_hosts_and_counts_frequency():
    h1 = _dc(ip="10.0.0.10", dns="corp.local", nb="CORP")
    h2 = _dc(ip="10.0.0.11", dns="corp.local", nb="CORP")
    h3 = _dc(ip="10.0.0.99", dns="other.local", nb="OTHER")
    kd = known_domains([h1, h2, h3])
    # corp.local seen on 2 hosts, other.local on 1 — corp.local wins primary
    assert kd["primary_dns"] == "corp.local"
    corp = next(e for e in kd["domains"] if e["dns"] == "corp.local")
    other = next(e for e in kd["domains"] if e["dns"] == "other.local")
    assert corp["host_count"] == 2
    assert other["host_count"] == 1
    assert corp["is_primary"] is True and other["is_primary"] is False


def test_known_domains_by_ip_maps_each_host_to_its_domain():
    h1 = _dc(ip="10.0.0.10", dns="corp.local", nb="CORP")
    h2 = _dc(ip="10.0.0.99", dns="other.local", nb="OTHER")
    kd = known_domains([h1, h2])
    assert kd["by_ip"]["10.0.0.10"] == {"dns": "corp.local", "netbios": "CORP"}
    assert kd["by_ip"]["10.0.0.99"] == {"dns": "other.local", "netbios": "OTHER"}


# --- Account / cred domain producers ------------------------------------

def test_known_domains_picks_up_account_domain_when_no_ntlm():
    """A BloodHound import lands users with .domain — the reader must
    surface it even when no NTLM handshake happened."""
    h = Host(ip="10.0.0.10")
    h.accounts = [Account(ip="10.0.0.10", source="bloodhound", kind="user",
                          name="alice", domain="corp.local")]
    kd = known_domains([h])
    assert kd["primary_dns"] == "corp.local"


def test_known_domains_counts_creds_carrying_a_domain():
    h = _dc(dns="corp.local", nb="CORP")
    creds = [
        Credential(username="alice", secret="x", kind="password",
                   domain="CORP"),
        Credential(username="bob", secret="y", kind="password",
                   domain="CORP"),
    ]
    kd = known_domains([h], creds=creds)
    corp = next(e for e in kd["domains"] if e["dns"] == "corp.local")
    assert corp["cred_count"] == 2


# --- Operator override --------------------------------------------------

def test_operator_domain_beats_enumeration_frequency_when_matches_known():
    h1 = _dc(ip="10.0.0.10", dns="corp.local", nb="CORP")
    h2 = _dc(ip="10.0.0.20", dns="other.local", nb="OTHER")
    # `other.local` has 1 host, `corp.local` has 1 — operator picks other
    kd = known_domains([h1, h2], operator_domain="OTHER.LOCAL")
    assert kd["primary_dns"] == "other.local"
    other = next(e for e in kd["domains"] if e["dns"] == "other.local")
    assert other["is_primary"] is True


def test_operator_domain_becomes_primary_when_not_yet_enumerated():
    """Fresh scan: operator passes --domain, nothing else has enumerated
    yet. The operator name IS the primary."""
    kd = known_domains([], operator_domain="CORP.LOCAL")
    assert kd["primary_dns"] == "corp.local"


# --- Kerberos realm helper ----------------------------------------------

def test_kerberos_realm_uppercases_dns_domain():
    """Kerberos realm convention: uppercased DNS form (RFC 4120 §7.1)."""
    h = _dc(dns="corp.local", nb="CORP")
    assert kerberos_realm([h]) == "CORP.LOCAL"


def test_kerberos_realm_prefers_operator_supplied_realm():
    h = _dc(dns="corp.local", nb="CORP")
    assert kerberos_realm([h], operator_domain="OTHER.LOCAL") == "OTHER.LOCAL"


def test_kerberos_realm_returns_empty_when_nothing_learned():
    assert kerberos_realm([]) == ""


# --- domain_for(host): single-host lookup with engagement fallback ------

def test_domain_for_host_reads_hosts_own_ntlm():
    h = _dc(dns="corp.local", nb="CORP")
    assert domain_for(h) == {"dns": "corp.local", "netbios": "CORP"}


def test_domain_for_host_falls_back_to_engagement_primary():
    """A member server may not surface domain via NTLM (no signed
    session), but its DC did. domain_for(host, all_hosts=…) should
    fall back to the engagement primary."""
    member = Host(ip="10.0.0.50")             # no NTLM info
    dc = _dc(ip="10.0.0.10", dns="corp.local", nb="CORP")
    got = domain_for(member, all_hosts=[dc, member])
    assert got == {"dns": "corp.local", "netbios": "CORP"}


# --- Kerberos analyze() integration -------------------------------------

def test_kerberos_analyze_falls_back_to_known_domains_realm(monkeypatch):
    """analyze(realm="") used to only call ad.derive_domains (NSE + NTLM).
    Wired to known_domains, it now also picks up LDAP defaultNamingContext
    and BloodHound-derived domains."""
    from recce.ad import kerberos as krb
    # Host with a Kerberos DC port + a BloodHound-supplied domain (no NTLM).
    from recce.core.models import Port
    dc = Host(ip="10.0.0.10",
              ports=[Port(portid=88, protocol="tcp", state="open",
                          service="kerberos-sec")])
    dc.accounts = [Account(ip="10.0.0.10", source="bloodhound",
                           kind="user", name="alice", domain="corp.local")]
    # Stub out the actual AS-REQ so no packets fly.
    monkeypatch.setattr(krb, "roast_user", lambda *a, **k: {"state": "err"})
    monkeypatch.setattr(krb, "candidate_users", lambda hosts: ["alice"])
    result = krb.analyze([dc], active=False)
    # analyze() should have auto-picked corp.local -> CORP.LOCAL as realm
    assert result["realm"] == "CORP.LOCAL"
