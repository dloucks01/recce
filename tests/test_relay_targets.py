"""core.relay_targets: SMB relay candidate filter + ntlmrelayx target file.

Signing-value strings come from what recce's SMB probes record; those are
sourced from the SMB security-mode field defined in MS-CIFS §2.2.4.5.1
(SecurityMode bits 0x01 SIGN_ENABLED / 0x02 SIGN_REQUIRED) — the two
posture values the reader distinguishes are exactly what an ntlmrelayx
relay session would succeed vs fail against.
"""
from __future__ import annotations

import os
import stat

from recce.core.models import Host, Port
from recce.core.relay_targets import (relay_target_lines,
                                      smb_relay_candidates,
                                      write_relay_targets)


def _host(ip, *, signing="not required", ports=(445,), roles=()):
    h = Host(ip=ip)
    h.smb_signing = signing
    h.roles = list(roles)
    h.ports = [Port(portid=p, protocol="tcp", state="open", service="smb")
               for p in ports]
    return h


# --- SMB relay filter -----------------------------------------------------

def test_smb_relay_candidates_matches_signing_not_required_with_smb_open():
    h = _host("10.0.0.10")
    assert [c.ip for c in smb_relay_candidates([h])] == ["10.0.0.10"]


def test_smb_relay_candidates_excludes_hosts_with_signing_required():
    """SMB SecurityMode 0x02 (SIGN_REQUIRED) blocks relay of a coerced
    NTLM authentication at the server."""
    h = _host("10.0.0.10", signing="required")
    assert smb_relay_candidates([h]) == []


def test_smb_relay_candidates_excludes_hosts_with_signing_unknown():
    """Signing==unknown => the SMB probe couldn't tell; excluded by
    default because an "unknown" host inflates the target list with
    false positives that waste the operator's session slots."""
    h = _host("10.0.0.10", signing="unknown")
    assert smb_relay_candidates([h]) == []


def test_smb_relay_candidates_excludes_domain_controllers():
    """A DC that reports "not required" is almost always enforced-by-GPO
    in practice; relaying to a DC that then rejects the session wastes
    a coercion. Exclude DCs by default."""
    h = _host("10.0.0.10", roles=["Domain Controller"])
    assert smb_relay_candidates([h]) == []


def test_smb_relay_candidates_requires_smb_port_open():
    h = _host("10.0.0.10", ports=(3389,))  # RDP only, no SMB
    assert smb_relay_candidates([h]) == []


def test_smb_relay_candidates_accepts_port_139_as_well_as_445():
    """MS-CIFS §2.2 SMB can ride 139 (NetBIOS session service) too — a
    legacy-only host that still exposes 139 is a relay target."""
    h = _host("10.0.0.10", ports=(139,))
    assert [c.ip for c in smb_relay_candidates([h])] == ["10.0.0.10"]


# --- ntlmrelayx target-file format ---------------------------------------

def test_relay_target_lines_prefixes_smb_scheme_per_ntlmrelayx_docs():
    """impacket's ntlmrelayx `-tf` file accepts `smb://ip` — the reader
    emits that form so a single file could drive other relay protocols
    (mssql://, ldap://) with only a scheme swap."""
    h = _host("10.0.0.10")
    assert relay_target_lines([h]) == ["smb://10.0.0.10"]


def test_relay_target_lines_respects_include_unknown_opt_in():
    h = _host("10.0.0.10", signing="unknown")
    assert relay_target_lines([h]) == []
    assert relay_target_lines([h], include_unknown=True) == ["smb://10.0.0.10"]


def test_relay_target_lines_respects_include_dcs_opt_in():
    h = _host("10.0.0.10", roles=["Domain Controller"])
    assert relay_target_lines([h]) == []
    assert relay_target_lines([h], include_dcs=True) == ["smb://10.0.0.10"]


def test_relay_target_lines_supports_alternate_protocol_scheme():
    h = _host("10.0.0.10")
    # ntlmrelayx also supports mssql://, http://, ldap://, ldaps://
    assert relay_target_lines([h], protocol="mssql") == ["mssql://10.0.0.10"]


# --- write_relay_targets file-emission wire ------------------------------

def test_write_relay_targets_writes_one_line_per_candidate(tmp_path):
    hosts = [
        _host("10.0.0.10"),
        _host("10.0.0.11"),
        _host("10.0.0.20", signing="required"),         # excluded
        _host("10.0.0.30", roles=["Domain Controller"]),  # excluded
    ]
    out = tmp_path / "relay-targets.txt"
    r = write_relay_targets(hosts, str(out))
    assert r["count"] == 2
    assert r["skipped_dcs"] == 1
    assert r["skipped_signed"] == 1
    lines = out.read_text().splitlines()
    assert set(lines) == {"smb://10.0.0.10", "smb://10.0.0.11"}


def test_write_relay_targets_creates_file_with_0o600_permissions(tmp_path):
    """The target list is a live attack payload — keep it non-world-readable."""
    out = tmp_path / "relay-targets.txt"
    write_relay_targets([_host("10.0.0.10")], str(out))
    mode = stat.S_IMODE(os.stat(out).st_mode)
    assert mode == 0o600


def test_write_relay_targets_returns_absolute_path_for_cli_message(tmp_path):
    out = tmp_path / "relay-targets.txt"
    r = write_relay_targets([_host("10.0.0.10")], str(out))
    assert os.path.isabs(r["path"])
    assert r["path"] == str(out)     # tmp_path IS absolute


def test_write_relay_targets_skips_file_when_no_candidates(tmp_path):
    out = tmp_path / "relay-targets.txt"
    r = write_relay_targets([_host("10.0.0.10", signing="required")], str(out))
    assert r["count"] == 0
    assert not out.exists()          # nothing to write, no empty file
    # But the caller still gets a stable path back for its message
    assert r["path"] == str(out)


def test_write_relay_targets_counts_skipped_unknown_when_default(tmp_path):
    """The skipped-unknown counter lets the CLI say "3 hosts had unknown
    signing posture — pass --include-unknown to include them"."""
    hosts = [
        _host("10.0.0.10"),
        _host("10.0.0.20", signing="unknown"),
        _host("10.0.0.21", signing="unknown"),
    ]
    r = write_relay_targets(hosts, str(tmp_path / "t.txt"))
    assert r["count"] == 1
    assert r["skipped_unknown"] == 2
    # With opt-in, the unknowns are folded in and no longer "skipped"
    r2 = write_relay_targets(hosts, str(tmp_path / "t2.txt"),
                             include_unknown=True)
    assert r2["count"] == 3
    assert r2["skipped_unknown"] == 0
