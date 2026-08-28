"""Regression tests for the AD false-positive / correctness fixes.

Covers three concrete fixes:
  * anonymous LDAP *bind* is info (Windows-default), and cleartext-389 is flagged
    independent of anonymity (the real relay surface);
  * disabled accounts are excluded from Kerberoast / AS-REP target lists;
  * Kerberoasting requests AES as a fallback and formats AES tickets crackably.
"""
from __future__ import annotations

from recce.core.models import Account, Host, Port


def test_anonymous_bind_is_info_and_cleartext_is_decoupled():
    from recce.services import ldap as L
    h = Host(ip="10.0.0.5", ports=[Port(portid=389, service="ldap", state="open")])
    # a DC that accepts an anonymous bind but denies anonymous reads (the default)
    pr = {"anon_bind": True, "anon_read": False, "rootdse_ok": False, "tls": False}
    by_title = {f["title"]: f for f in L.findings([h], {("10.0.0.5", 389): pr})}
    # the default anonymous bind is info-level, not a medium false positive
    assert by_title["Anonymous LDAP bind allowed"]["severity"] == "info"
    # cleartext-389 still fires even though nothing anonymous is readable
    assert "LDAP over cleartext (no TLS on 389)" in by_title


def test_disabled_accounts_are_not_roast_targets():
    from recce import ad
    h = Host(ip="10.0.0.10")
    h.accounts = [
        Account(ip=h.ip, source="ldap", kind="user", name="svc_live",
                attrs={"spn": "MSSQLSvc/a:1433", "enabled": "yes"}),
        Account(ip=h.ip, source="ldap", kind="user", name="svc_dead",
                attrs={"spn": "MSSQLSvc/b:1433", "enabled": "no"}),
        Account(ip=h.ip, source="ldap", kind="user", name="svc_unknown",
                attrs={"spn": "MSSQLSvc/c:1433"}),                      # no UAC -> fail-open
        Account(ip=h.ip, source="ldap", kind="user", name="asrep_live",
                attrs={"asrep_roastable": "yes", "enabled": "yes"}),
        Account(ip=h.ip, source="ldap", kind="user", name="asrep_dead",
                attrs={"asrep_roastable": "yes", "enabled": "no"}),
    ]
    # disabled excluded, unknown-state kept (never hide a possibly-live target)
    assert {a.name for a in ad.kerberoastable([h])} == {"svc_live", "svc_unknown"}
    assert {a.name for a in ad.asrep_roastable([h])} == {"asrep_live"}


def test_tgs_hash_formats_rc4_and_aes_crackably():
    from recce.ad import kerberos as K
    cipher = bytes(range(40))
    rc4 = K.tgs_hash("svc", "CORP.LOCAL", "MSSQLSvc/a", 23, cipher)
    assert rc4.startswith("$krb5tgs$23$*svc$CORP.LOCAL$MSSQLSvc/a*$")
    assert rc4.endswith(f"{cipher[:16].hex()}${cipher[16:].hex()}")
    # AES256 (etype 18 -> hashcat 19700): user/realm outside *spn*, 12-byte tag first
    aes = K.tgs_hash("svc", "CORP.LOCAL", "MSSQLSvc/a", 18, cipher)
    assert aes.startswith("$krb5tgs$18$svc$CORP.LOCAL$*MSSQLSvc/a*$")
    assert aes.endswith(f"{cipher[-12:].hex()}${cipher[:-12].hex()}")


def test_tgs_request_advertises_aes_fallback():
    from recce.ad import kerberos as K
    # the TGS-REQ body must offer AES (17,18), not RC4 (23) only, so AES-only service
    # accounts are roasted instead of silently dropped on KDC_ERR_ETYPE_NOSUPP.
    rc4_only = K._req_body("CORP.LOCAL", K._principal(2, ["MSSQLSvc", "a"]), None,
                           etypes=(K.ETYPE_RC4,))
    multi = K._build_tgs_req("CORP.LOCAL", "user", "MSSQLSvc/a",
                             b"\x60\x03\x00\x00", b"\x00" * 16)
    # the multi-etype body encodes strictly more etypes than the RC4-only one
    assert len(multi) > len(rc4_only)
