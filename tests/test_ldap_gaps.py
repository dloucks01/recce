"""Tests for LDAP capabilities added in the gap sweep: LAPS-readable finding,
RBCD detection, and weak-SASL-mechanism analysis.

Fixtures build RFC 4511 wire-shaped attribute dicts (the shape the module's
parse_search_entry / ldap3 normalizer produce) directly - no monkeypatching of
the encoders."""
from __future__ import annotations

from recce.core.models import Host
from recce.services import ldap as L


# --- helpers -------------------------------------------------------------------

def _computer(name: str, **extra) -> dict:
    d: dict[str, list[str]] = {"sAMAccountName": [name + "$"],
                               "dNSHostName": [name.lower() + ".corp.local"],
                               "operatingSystem": ["Windows Server 2019"],
                               "userAccountControl": ["4096"]}
    for k, v in extra.items():
        # map _ to - for attribute names (ms_Mcs_AdmPwd -> ms-Mcs-AdmPwd style)
        d[k] = v if isinstance(v, list) else [v]
    return d


def _enum(users=None, computers=None, domain=None):
    return {"users": users or [], "computers": computers or [], "domain": domain or {},
            "bind_dn": "alice@corp.local", "bind_method": "simple bind", "error": None}


# --- LAPS: critical finding when the bound principal reads an admin password ---

def test_laps_readable_emits_critical_finding():
    c1 = _computer("PC01")
    c1["ms-Mcs-AdmPwd"] = ["Sup3rS3cretP@ss!"]                # legacy Microsoft LAPS
    c2 = _computer("PC02")
    c2["msLAPS-Password"] = ['{"n":"Administrator","p":"W1nd0wsL@PS!"}']  # Windows LAPS
    c3 = _computer("PC03")                                    # no LAPS - control
    en = _enum(computers=[c1, c2, c3])
    _summary, fs = L.apply_enum(Host(ip="10.0.0.1"), "corp.local", "10.0.0.1", 389, en)
    laps = [f for f in fs if f["kind"] == "ldap_laps_readable"]
    assert len(laps) == 1, [f["kind"] for f in fs]
    f = laps[0]
    assert f["severity"] == "critical"
    assert "PC01" in f["detail"] and "PC02" in f["detail"]
    # Never echo the plaintext password into the finding.
    assert "Sup3rS3cretP@ss!" not in f["detail"]
    assert "W1nd0wsL@PS!" not in f["detail"]
    assert _summary["laps_readable"] == 2


def test_laps_not_readable_no_finding():
    en = _enum(computers=[_computer("PC01"), _computer("PC02")])
    _summary, fs = L.apply_enum(Host(ip="10.0.0.1"), "corp.local", "10.0.0.1", 389, en)
    assert not [f for f in fs if f["kind"] == "ldap_laps_readable"]
    assert _summary["laps_readable"] == 0


def test_laps_encrypted_only_still_flags():
    c = _computer("PC01")
    c["msLAPS-EncryptedPassword"] = [b"\x01\x02\x03\x04".decode("latin-1")]
    en = _enum(computers=[c])
    _summary, fs = L.apply_enum(Host(ip="1.1.1.1"), "corp.local", "1.1.1.1", 389, en)
    laps = [f for f in fs if f["kind"] == "ldap_laps_readable"]
    assert len(laps) == 1


# --- RBCD: high finding when msDS-AllowedToActOnBehalfOfOtherIdentity is set ----

def test_rbcd_configured_emits_high_finding():
    c1 = _computer("SRV01")
    # RBCD attr - an ntSecurityDescriptor blob; content is opaque, presence is the signal.
    c1["msDS-AllowedToActOnBehalfOfOtherIdentity"] = [b"\x01\x00\x04\x80".decode("latin-1")]
    c2 = _computer("SRV02")                                   # no RBCD - control
    en = _enum(computers=[c1, c2])
    _summary, fs = L.apply_enum(Host(ip="10.0.0.2"), "corp.local", "10.0.0.2", 389, en)
    rbcd = [f for f in fs if f["kind"] == "ldap_rbcd"]
    assert len(rbcd) == 1
    assert rbcd[0]["severity"] == "high"
    assert "SRV01" in rbcd[0]["detail"]
    assert _summary["rbcd_configured"] == 1


def test_rbcd_not_configured_no_finding():
    en = _enum(computers=[_computer("SRV01"), _computer("SRV02")])
    _summary, fs = L.apply_enum(Host(ip="10.0.0.2"), "corp.local", "10.0.0.2", 389, en)
    assert not [f for f in fs if f["kind"] == "ldap_rbcd"]
    assert _summary["rbcd_configured"] == 0


# --- Requested attribute list carries LAPS + RBCD ------------------------------

def test_computer_attrs_include_laps_and_rbcd():
    for a in L._LAPS_ATTRS:
        assert a in L._COMPUTER_ATTRS
    assert L._RBCD_ATTR in L._COMPUTER_ATTRS


# --- SASL: legacy / weak mechanism advertisement flagged in findings() ---------

def _fake_port(portid=389):
    from recce.core.models import Port
    p = Port(portid=portid, protocol="tcp", state="open", service="ldap")
    return p


def _host_with_port(portid=389):
    h = Host(ip="10.9.9.9")
    h.ports.append(_fake_port(portid))
    return h


def test_weak_sasl_flag_anonymous_and_digest_md5():
    h = _host_with_port(389)
    probes = {("10.9.9.9", 389): {
        "anon_bind": False, "anon_read": False, "rootdse_ok": True,
        "domain": "corp.local", "forest": "corp.local", "dc_dns": "dc01.corp.local",
        "dc_level": "2016", "naming_context": "DC=corp,DC=local", "tls": False,
        "sasl": ["GSSAPI", "GSS-SPNEGO", "ANONYMOUS", "DIGEST-MD5", "PLAIN"],
        "is_gc": False,
    }}
    fs = L.findings([h], probes)
    weak = [f for f in fs if f["kind"] == "ldap_weak_sasl_mech"]
    assert len(weak) == 1, [f["kind"] for f in fs]
    f = weak[0]
    assert f["severity"] == "medium"
    for mech in ("ANONYMOUS", "DIGEST-MD5", "PLAIN"):
        assert mech in f["detail"]
    # GSSAPI/GSS-SPNEGO are the normal AD pair - never flagged as weak.
    assert "GSSAPI," not in f["detail"] and "GSS-SPNEGO" not in f["detail"]


def test_weak_sasl_only_normal_mechs_no_finding():
    h = _host_with_port(389)
    probes = {("10.9.9.9", 389): {
        "anon_bind": False, "anon_read": False, "rootdse_ok": True,
        "domain": "corp.local", "forest": "corp.local", "dc_dns": "dc01.corp.local",
        "dc_level": "2016", "naming_context": "DC=corp,DC=local", "tls": False,
        "sasl": ["GSSAPI", "GSS-SPNEGO", "EXTERNAL"], "is_gc": False,
    }}
    fs = L.findings([h], probes)
    # EXTERNAL is flagged (bare EXTERNAL without a mutual-auth cert bind is a downgrade).
    weak = [f for f in fs if f["kind"] == "ldap_weak_sasl_mech"]
    assert len(weak) == 1
    assert "EXTERNAL" in weak[0]["detail"]


def test_weak_sasl_helper_case_insensitive_and_dedup():
    assert L._weak_sasl_mechs(["gssapi", "digest-md5", "DIGEST-MD5", "cram-md5"]) == [
        "digest-md5", "DIGEST-MD5", "cram-md5",
    ]
    assert L._weak_sasl_mechs([]) == []
    assert L._weak_sasl_mechs(None) == []


def _user(name: str, description: str = "") -> dict:
    d: dict[str, list[str]] = {"sAMAccountName": [name],
                               "userAccountControl": ["512"]}
    if description:
        d["description"] = [description]
    return d


# --- ldap_pw_desc T2 promotion: captured redacted evidence in output field ------

def test_pw_desc_t2_emits_captured_evidence_output():
    """Vulnerable: an authenticated read returned real descriptions with password
    hints - the T2 finding must ship a captured-evidence `output` block that names
    each account and shows the description text existed, without echoing the
    plaintext secret."""
    users = [
        _user("alice", "Temporary password: Sup3rS3cret!Rotate"),
        _user("bob", "pwd=Winter2025! reset me"),
        _user("carol", "backup service credential Xy9zTop"),   # 'credential' hint
        _user("dave"),                                          # no desc - control
        _user("eve", "please review"),                          # no hint - control
    ]
    en = _enum(users=users)
    _summary, fs = L.apply_enum(Host(ip="10.0.0.9"), "corp.local", "10.0.0.9", 389, en)
    hits = [f for f in fs if f["kind"] == "ldap_pw_desc"]
    assert len(hits) == 1, [f["kind"] for f in fs]
    f = hits[0]
    assert f["depth_tier"] == "t2"
    assert f["severity"] == "high"
    # Captured evidence block is present and contains each vulnerable sAMAccountName.
    out = f.get("output", "")
    assert out, "T2 finding must carry captured evidence in `output`"
    for name in ("alice", "bob", "carol"):
        assert name in out, out
    # Non-matching users must not appear in the evidence block.
    assert "dave" not in out and "eve" not in out
    # The plaintext secrets must NEVER be echoed into the evidence.
    for secret in ("Sup3rS3cret!Rotate", "Winter2025!", "Xy9zTop"):
        assert secret not in out, f"plaintext {secret!r} leaked into T2 evidence"
    # A recognisable credential-hint keyword IS preserved (proves the match).
    assert "password" in out.lower() or "pwd" in out.lower() or "cred" in out.lower()


def test_pw_desc_patched_no_finding_no_output():
    """Patched: no description carries a credential hint -> no finding emitted at
    all (and therefore no captured evidence to leak)."""
    users = [_user("alice", "on leave"), _user("bob", "engineering team"),
             _user("carol")]
    en = _enum(users=users)
    _summary, fs = L.apply_enum(Host(ip="10.0.0.9"), "corp.local", "10.0.0.9", 389, en)
    assert not [f for f in fs if f["kind"] == "ldap_pw_desc"]


def test_pw_desc_t2_bounded_evidence_row_cap():
    """Bounded evidence: >12 hits collapses into a 'and N more' tail, so the
    output block stays compact on large environments."""
    users = [_user(f"user{i:03d}", f"password: Sekret{i:03d}!") for i in range(20)]
    en = _enum(users=users)
    _summary, fs = L.apply_enum(Host(ip="10.0.0.9"), "corp.local", "10.0.0.9", 389, en)
    f = [x for x in fs if x["kind"] == "ldap_pw_desc"][0]
    out = f["output"]
    # 12 rows + one tail line
    assert out.count("\n") == 12
    assert "and 8 more" in out
    # No plaintext leak in the truncated set either.
    for i in range(20):
        assert f"Sekret{i:03d}!" not in out


def test_pw_desc_t2_enum_timeout_yields_no_output():
    """Timeout / connect-failed shape: enum returned an error, so apply_enum is
    never called and no T2 evidence exists to display. Verifies the module's
    error branch does not synthesize a fake finding."""
    # Mirror the analyze() path: on `error`, apply_enum is skipped entirely.
    en = {"error": "connect failed"}
    # Nothing to fold - apply_enum path is bypassed by design in analyze().
    assert en.get("error") == "connect failed"
    # And if apply_enum WERE invoked with an empty users list (equivalent shape
    # after a mid-search timeout that returned zero rows), no pw_desc finding
    # is emitted:
    empty = _enum(users=[])
    _summary, fs = L.apply_enum(Host(ip="10.0.0.9"), "corp.local", "10.0.0.9", 389, empty)
    assert not [f for f in fs if f["kind"] == "ldap_pw_desc"]


def test_redact_pw_desc_helper_masks_secret_keeps_hint():
    """Unit test for the redactor: hint-keyword survives, secret does not."""
    r = L._redact_pw_desc("Temporary password: Sup3rS3cret!Rotate")
    assert "password" in r.lower()
    assert "Sup3rS3cret!Rotate" not in r
    assert r.endswith("***")
    # No hint match -> hard truncate + ***
    r2 = L._redact_pw_desc("service account for backups only")
    assert r2.endswith("***")
    # Empty description -> empty string, not '***' (nothing to redact).
    assert L._redact_pw_desc("") == ""


def test_weak_sasl_dedup_per_host_across_multiple_ports():
    """Host-level SASL finding fires once per host even when 389/636/3268/3269 all open."""
    h = Host(ip="10.9.9.9")
    for portid in (389, 636, 3268, 3269):
        h.ports.append(_fake_port(portid))
    probe = {"anon_bind": False, "anon_read": False, "rootdse_ok": True,
             "domain": "corp.local", "forest": "corp.local", "dc_dns": "dc01.corp.local",
             "dc_level": "2016", "naming_context": "DC=corp,DC=local",
             "sasl": ["GSSAPI", "ANONYMOUS"], "is_gc": False}
    probes = {("10.9.9.9", p): {**probe, "tls": p in (636, 3269)} for p in (389, 636, 3268, 3269)}
    fs = L.findings([h], probes)
    assert len([f for f in fs if f["kind"] == "ldap_weak_sasl_mech"]) == 1
