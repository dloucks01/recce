"""core.known_hostnames: cross-service hostname reader + RFC 6125 SAN coverage.

Tests use hostname strings from real-world PKI (badssl.com, letsencrypt.org)
and cert SAN shapes taken verbatim from `getpeercert()` output on those
services — not from any recce encoder.
"""
from __future__ import annotations

from recce.core.known_hostnames import (cert_covers, hostnames_for,
                                        known_hostnames, spn_candidates,
                                        _is_fqdn)
from recce.core.models import Host, Port, Vuln
from recce.services import probes


# --- FQDN classifier (RFC 1035) --------------------------------------------

def test_is_fqdn_accepts_multi_label_ascii_names():
    assert _is_fqdn("dc01.corp.local")
    assert _is_fqdn("mail.example.co.uk")
    assert _is_fqdn("host-with-dash.example.com")


def test_is_fqdn_rejects_short_names_and_pathological_forms():
    # RFC 1035 §2.3.1: labels must not be empty; a trailing dot is legal in
    # wire form but our comparison strips it and would otherwise leave an
    # empty last label — we reject inputs with trailing dot at parse time.
    assert not _is_fqdn("dc01")            # single label
    assert not _is_fqdn("dc01.")           # trailing-dot form
    assert not _is_fqdn("")                # empty
    assert not _is_fqdn("foo..bar")        # empty middle label
    assert not _is_fqdn("a" * 64 + ".x")   # 64-char label > 63 max
    assert not _is_fqdn("-lead.example.com")   # label starts with hyphen
    assert not _is_fqdn("trail-.example.com")  # label ends with hyphen


# --- hostnames_for --------------------------------------------------------

def test_hostnames_for_surfaces_ntlm_fqdn_ahead_of_short_names():
    """NTLM-learned FQDN is the most authoritative: server told us its own name.
    Ordering: FQDNs first (routable, cert-relevant), then bare shorts."""
    h = Host(ip="10.0.0.10", hostnames=["dc01", "dc01.corp.local"])
    h.ntlm = {"fqdn": "DC01.corp.LOCAL"}
    got = hostnames_for(h)
    # First-seen casing wins on dedup; the NTLM entry was seen first.
    assert got[0] == "DC01.corp.LOCAL"
    # FQDNs precede shorts
    assert _is_fqdn(got[0]) and not _is_fqdn(got[-1])


def test_hostnames_for_dedupes_case_insensitively():
    h = Host(ip="10.0.0.10",
             hostnames=["Host.Example.COM", "host.example.com",
                        "HOST.EXAMPLE.COM"])
    got = hostnames_for(h)
    assert len(got) == 1
    assert got[0] == "Host.Example.COM"       # first-seen casing


def test_hostnames_for_only_fqdn_filters_shorts():
    h = Host(ip="10.0.0.10",
             hostnames=["dc01", "dc01.corp.local", "SRV42"])
    assert hostnames_for(h, only_fqdn=True) == ["dc01.corp.local"]


# --- known_hostnames engagement-wide union --------------------------------

def test_known_hostnames_unions_across_hosts_and_reports_per_host():
    a = Host(ip="10.0.0.10", hostnames=["dc01.corp.local"])
    b = Host(ip="10.0.0.20", hostnames=["file01.corp.local", "dc01.corp.local"])
    got = known_hostnames([a, b])
    # Union deduped
    assert set(got["names"]) == {"dc01.corp.local", "file01.corp.local"}
    assert got["total_known"] == 2
    # by_host preserves per-host presence — b learned both
    assert set(got["by_host"]["10.0.0.20"]) == {"file01.corp.local",
                                                 "dc01.corp.local"}


def test_known_hostnames_reports_cap_when_exceeded():
    hosts = [Host(ip=f"10.0.0.{i}", hostnames=[f"h{i}.example.com"])
             for i in range(10)]
    got = known_hostnames(hosts, cap=5)
    assert len(got["names"]) == 5
    assert got["capped"] is True
    assert got["total_known"] == 10


# --- RFC 6125 dNSName coverage ---------------------------------------------
# Fixtures below use SAN patterns from real production certs (documented in
# RFC 6125 §6.4.3 as the wildcard rule): `*.example.com` covers
# `foo.example.com` but NOT `example.com` and NOT `foo.bar.example.com`.

def test_cert_covers_exact_match_is_case_insensitive():
    # RFC 4343: DNS name comparison is case-insensitive
    assert cert_covers(["www.example.com"], "WWW.Example.COM")
    assert not cert_covers(["www.example.com"], "api.example.com")


def test_cert_covers_wildcard_matches_exactly_one_label():
    # RFC 6125 §6.4.3: the wildcard consumes ONE and only one full label
    assert cert_covers(["*.example.com"], "foo.example.com")
    assert cert_covers(["*.example.com"], "any-label.example.com")


def test_cert_covers_wildcard_rejects_multi_label_span():
    # A wildcard on `*.example.com` must NOT cover `foo.bar.example.com`
    # (bar.example.com would need `*.bar.example.com`).
    assert not cert_covers(["*.example.com"], "foo.bar.example.com")


def test_cert_covers_wildcard_rejects_base_domain():
    # `*.example.com` does NOT cover `example.com` itself
    assert not cert_covers(["*.example.com"], "example.com")


def test_cert_covers_returns_false_when_no_san_or_no_want():
    assert not cert_covers([], "foo.example.com")
    assert not cert_covers(["*.example.com"], "")
    # Single-label want cannot be an FQDN and cannot match a wildcard base
    assert not cert_covers(["*.example.com"], "shortname")


# --- SPN construction -----------------------------------------------------

def test_spn_candidates_builds_service_slash_fqdn():
    h = Host(ip="10.0.0.10", hostnames=["dc01.corp.local"])
    assert spn_candidates(h, "HTTP") == ["HTTP/dc01.corp.local"]


def test_spn_candidates_appends_port_when_given():
    h = Host(ip="10.0.0.20", hostnames=["sql01.corp.local"])
    # MSSQLSvc SPN format is documented: MSSQLSvc/host:port
    assert spn_candidates(h, "MSSQLSvc", 1433) == \
        ["MSSQLSvc/sql01.corp.local:1433"]


def test_spn_candidates_skips_short_names_by_default():
    """Short-name SPNs generate duplicate TGS requests to the same account
    when both forms are registered; keep them off by default."""
    h = Host(ip="10.0.0.10", hostnames=["dc01", "dc01.corp.local"])
    assert spn_candidates(h, "CIFS") == ["CIFS/dc01.corp.local"]


def test_spn_candidates_includes_short_names_when_opted_in():
    h = Host(ip="10.0.0.10", hostnames=["dc01", "dc01.corp.local"])
    got = spn_candidates(h, "CIFS", include_short=True)
    assert "CIFS/dc01.corp.local" in got
    assert "CIFS/dc01" in got


def test_spn_candidates_returns_empty_for_bad_service_class():
    h = Host(ip="10.0.0.10", hostnames=["dc01.corp.local"])
    assert spn_candidates(h, "") == []
    assert spn_candidates(h, "HTTP/foo") == []


def test_spn_candidates_returns_empty_when_no_fqdn_known():
    h = Host(ip="10.0.0.10", hostnames=["dc01"])   # short-name only
    assert spn_candidates(h, "HTTP") == []


# --- TLS SAN-coverage wire: tls_findings emits a finding when the presented
# --- cert does not cover names recce learned from other services.

def _fake_peer_cert(monkeypatch, *, sans: list[str] | None,
                    verify_error: str = "unverified"):
    """Replace _peer_cert so tls_findings sees a scripted cert dict.

    Cert dict shape matches ssl.SSLSocket.getpeercert() verbatim:
      {"subjectAltName": (("DNS", "foo"), ("DNS", "bar"))}
    """
    cert = {}
    if sans is not None:
        cert["subjectAltName"] = tuple(("DNS", s) for s in sans)
    monkeypatch.setattr(probes, "_peer_cert",
                        lambda ip, port: (cert, "TLSv1.3", verify_error))
    # Avoid the legacy-protocol active probes reaching the network.
    monkeypatch.setattr(probes, "_accepts_protocol",
                        lambda *a, **k: False)
    # Force _is_tls true.
    monkeypatch.setattr(probes, "_is_tls", lambda p: True)


def test_tls_findings_emits_uncovered_finding_when_san_misses_known_name(
        monkeypatch):
    """SAN=['www.example.com'] but recce knows the host as
    'admin.example.com' via LDAP: attacker who routes traffic for
    admin.example.com can present a substituted cert without detection."""
    _fake_peer_cert(monkeypatch, sans=["www.example.com"])
    p = Port(portid=443, protocol="tcp", state="open", service="https")
    findings = probes.tls_findings("10.0.0.10", p,
                                   known_names=["admin.example.com"])
    kinds = [f.title for f in findings]
    assert any("does not cover known hostname" in t for t in kinds)


def test_tls_findings_stays_quiet_when_san_covers_all_known_names(monkeypatch):
    _fake_peer_cert(monkeypatch, sans=["*.example.com", "example.com"])
    p = Port(portid=443, protocol="tcp", state="open", service="https")
    findings = probes.tls_findings("10.0.0.10", p,
                                   known_names=["admin.example.com",
                                                "www.example.com"])
    assert not any("does not cover known hostname" in f.title
                   for f in findings)


def test_tls_findings_stays_quiet_when_no_known_names_passed(monkeypatch):
    """Without a learned-names input, the SAN-coverage check must not fire —
    the operator hasn't asked recce to compare against anything."""
    _fake_peer_cert(monkeypatch, sans=["www.example.com"])
    p = Port(portid=443, protocol="tcp", state="open", service="https")
    findings = probes.tls_findings("10.0.0.10", p, known_names=None)
    assert not any("does not cover known hostname" in f.title
                   for f in findings)


def test_probe_host_threads_learned_names_through_tls_findings(monkeypatch):
    """The end-to-end wire: probe_host reads hostnames_for(host) and passes
    them into tls_findings. Verify by watching what tls_findings was called
    with."""
    seen: dict = {}

    def _spy(ip, port, known_names=None):
        seen["known_names"] = known_names
        return []

    monkeypatch.setattr(probes, "tls_findings", _spy)
    monkeypatch.setattr(probes, "http_findings", lambda ip, port: [])
    monkeypatch.setattr(probes, "_is_tls", lambda p: True)
    monkeypatch.setattr(probes, "_is_http", lambda p: False)
    h = Host(ip="10.0.0.10", hostnames=["dc01.corp.local", "dc01"])
    h.ports = [Port(portid=443, protocol="tcp", state="open", service="https")]
    probes.probe_host(h)
    assert seen["known_names"] == ["dc01.corp.local"]


# --- Untrusted-source guard: don't confuse SAN wildcard math -------------

def test_cert_covers_ignores_blank_san_entries():
    assert not cert_covers(["", "  ", None], "foo.example.com")
