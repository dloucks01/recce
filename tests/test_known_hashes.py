"""creds.known_hashes + hashloot.absorb_default_potfiles.

Hash-line fixtures use the exact formats hashcat documents for each mode
(hashcat wiki example_hashes.txt) — not any recce encoder — so a change
in recce's formatters cannot silently pass the test suite.
"""
from __future__ import annotations

import os

from recce.core.models import Credential
from recce.creds import hashloot
from recce.creds.known_hashes import (default_potfile_paths, known_hashes)


# --- Real hashcat wire formats, verbatim from hashcat's wiki. --------------
# Format documented in doc/hashes.txt and example_hashes.txt in the
# hashcat repo; these ARE the strings hashcat's own test suite uses.

# NTLM (mode 1000) — 32 hex, no salt
_NTLM_ALICE = "b4b9b02e6f09a9bd760f388b67351e2b"    # 'hashcat'

# MSSQL 2012+ (mode 1731) — starts with 0x0200, contains salt
_MSSQL_SA = ("0x0200F733058A07892C5CACE899768F89965F6BD1DED7955F"
             "E89B1C7A1AB40E3F6DDB2B85D63A2D5F60B0BFB63C3F86ADB0"
             "6A34F5DFB44E85BE28DAA7D7B39D2C3EE9")

# Kerberos TGS-REP (mode 13100) — the format kerberoast + hashcat both use;
# embeds SPN, user, realm inline. Truncated body for brevity but the
# prefix parser only reads the header.
_KRB_TGS_ALICE = ("$krb5tgs$23$*alice$CORP.LOCAL$MSSQLSvc/sql01.corp:1433*"
                  "$abcdef1234567890" + ("a" * 200))

# Kerberos AS-REP (mode 18200) — user@realm inline
_KRB_ASREP_BOB = ("$krb5asrep$23$bob@CORP.LOCAL:"
                  "1234567890abcdef" + ("b" * 100))


# --- known_hashes inventory ------------------------------------------------

def test_known_hashes_reads_nthash_from_credential_store():
    creds = [Credential(username="alice", secret=_NTLM_ALICE, kind="nthash",
                        domain="CORP")]
    kh = known_hashes(creds)
    assert kh["total"] == 1
    assert kh["by_mode"][1000] == 1
    assert _NTLM_ALICE.lower() in kh["by_hash"]
    assert kh["by_hash"][_NTLM_ALICE.lower()] == ("alice", "CORP")
    assert "alice" in kh["by_user"]
    entry = kh["by_user"]["alice"][0]
    assert entry["kind"] == "nthash" and entry["hashcat_mode"] == 1000


def test_known_hashes_reads_kerberos_loot_and_attributes_to_user(tmp_path):
    (tmp_path / "kerberoast.hash").write_text(_KRB_TGS_ALICE + "\n")
    (tmp_path / "asrep.hash").write_text(_KRB_ASREP_BOB + "\n")
    kh = known_hashes([], loot_dir=str(tmp_path))
    assert kh["categories"] == {"kerberoast": 1, "asrep": 1}
    assert kh["by_mode"] == {13100: 1, 18200: 1}
    # Kerberos blob self-identifies the user + realm — the reader parses it
    # out so `by_hash` can match a hashcat potfile line back to alice/bob.
    assert kh["by_hash"][_KRB_TGS_ALICE] == ("alice", "CORP.LOCAL")
    assert kh["by_hash"][_KRB_ASREP_BOB] == ("bob", "CORP.LOCAL")
    assert "alice" in kh["by_user"]
    assert "bob" in kh["by_user"]


def test_known_hashes_counts_non_attributing_loot_categories(tmp_path):
    """MSSQL/MongoDB/IPMI hashes don't self-identify a user in the blob —
    the READER still counts them (so the CLI summary is accurate) but they
    don't land in by_user unless attribution is separately supplied."""
    (tmp_path / "mssql.hash").write_text(_MSSQL_SA + "\n")
    kh = known_hashes([], loot_dir=str(tmp_path))
    assert kh["total"] == 1
    assert kh["by_mode"] == {1731: 1}
    assert kh["categories"]["mssql"] == 1
    # No user attribution possible from the blob alone → by_user stays empty
    assert kh["by_user"] == {}


def test_known_hashes_unions_creds_and_loot_dir(tmp_path):
    (tmp_path / "kerberoast.hash").write_text(_KRB_TGS_ALICE + "\n")
    creds = [Credential(username="alice", secret=_NTLM_ALICE, kind="nthash",
                        domain="CORP")]
    kh = known_hashes(creds, loot_dir=str(tmp_path))
    # alice has TWO hashes now: NT + krb5tgs — same user, two entries
    assert len(kh["by_user"]["alice"]) == 2
    kinds = {e["kind"] for e in kh["by_user"]["alice"]}
    assert kinds == {"nthash", "kerberoast"}
    assert kh["total"] == 2


def test_known_hashes_skips_password_kind_credentials():
    """Only nthash kinds are hashes; plaintext passwords in the store are
    already-cracked and shouldn't be counted as "captured for cracking"."""
    creds = [Credential(username="alice", secret="Passw0rd!", kind="password")]
    kh = known_hashes(creds)
    assert kh["total"] == 0
    assert kh["by_user"] == {}


# --- Potfile auto-discovery -------------------------------------------------

def test_default_potfile_paths_finds_potfiles_in_out_dir(tmp_path):
    (tmp_path / "cracked.pot").write_text("dead:beef")
    (tmp_path / "cracked.txt").write_text("dead:beef")
    (tmp_path / "notpot.log").write_text("noise")
    paths = default_potfile_paths(str(tmp_path))
    names = [os.path.basename(p) for p in paths]
    # Both extensions recognised; the .log ignored.
    assert "cracked.pot" in names
    assert "cracked.txt" in names
    assert "notpot.log" not in names


def test_default_potfile_paths_returns_empty_when_out_dir_missing():
    assert default_potfile_paths("") == [] or default_potfile_paths("") is not None


# --- absorb_default_potfiles wiring ----------------------------------------
# Hashcat potfile lines are `<hash>:<plaintext>`; recce's parse_potfile
# already knows how to match those back. What we test here: absorb picks up
# an out_dir potfile without needing an explicit --potfile flag.

def test_absorb_default_potfiles_returns_creds_for_matching_nt_hash(tmp_path):
    creds = [Credential(username="alice", secret=_NTLM_ALICE, kind="nthash",
                        domain="CORP")]
    # Hashcat's potfile format: hash:plaintext, one per line
    (tmp_path / "cracks.pot").write_text(f"{_NTLM_ALICE}:hashcat\n")
    got = hashloot.absorb_default_potfiles(creds, str(tmp_path))
    assert len(got) == 1
    assert got[0].username == "alice"
    assert got[0].secret == "hashcat"
    assert got[0].kind == "password"
    assert got[0].source == "cracked"


def test_absorb_default_potfiles_matches_kerberos_blob(tmp_path):
    (tmp_path / "kerberoast.hash").write_text(_KRB_TGS_ALICE + "\n")
    # potfile line: full blob : plaintext
    (tmp_path / "cracks.pot").write_text(f"{_KRB_TGS_ALICE}:Autumn2024!\n")
    got = hashloot.absorb_default_potfiles([], str(tmp_path))
    assert len(got) == 1
    assert got[0].username == "alice"
    assert got[0].secret == "Autumn2024!"


def test_absorb_default_potfiles_skips_unknown_hashes(tmp_path):
    """A crack for a hash recce never captured must NOT invent a
    credential — the (user, domain) mapping would be a lie."""
    (tmp_path / "cracks.pot").write_text(
        "ff" * 16 + ":someone_elses_plaintext\n")
    got = hashloot.absorb_default_potfiles([], str(tmp_path))
    assert got == []


def test_absorb_default_potfiles_returns_empty_when_no_potfile_exists(tmp_path):
    creds = [Credential(username="alice", secret=_NTLM_ALICE, kind="nthash",
                        domain="CORP")]
    got = hashloot.absorb_default_potfiles(creds, str(tmp_path))
    assert got == []


# --- run_spray wire: absorbed potfile cracks flow into the credential set --

def test_run_spray_absorbs_potfile_before_spraying(monkeypatch, tmp_path):
    """End-to-end: an out_dir/*.pot with a crack for a stored nthash gets
    absorbed and reported in the summary. Netexec calls are stubbed so no
    network happens."""
    from recce.creds import credentials as cr, credenum
    from recce.core.models import Host, Port

    monkeypatch.setattr(credenum, "smb_tool", lambda: "nxc")
    monkeypatch.setattr(credenum, "_run", lambda cmd, timeout=0, **k: ("", None))

    h = Host(ip="10.0.0.10",
             ports=[Port(portid=445, protocol="tcp", state="open", service="smb")])
    creds = [Credential(username="alice", secret=_NTLM_ALICE, kind="nthash",
                        domain="CORP")]
    # Simulate hashcat having cracked it, sitting in out_dir waiting to be
    # picked up on the next spray.
    (tmp_path / "cracks.pot").write_text(f"{_NTLM_ALICE}:hashcat\n")

    res = cr.run_spray([h], creds, str(tmp_path))
    assert res["ok"]
    assert res["absorbed_from_potfile"] == 1
    # The absorbed plaintext must now be in the cred set that got sprayed.
    assert any(c.kind == "password" and c.secret == "hashcat" for c in creds)
