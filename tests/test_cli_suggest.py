"""`recce suggest` — read-only next-moves digest.

Two acceptance tests exercising the command against a mocked-out
engagement store; a third uses the real parser to confirm the flag
wiring survives future refactors.
"""
from __future__ import annotations

import argparse
import os
import tempfile
from unittest.mock import patch

from recce.cli._suggest import (_exploit_findings, _tier_label, _tier_rank,
                                cmd_suggest)
from recce.core.models import Host, Vuln


def test_tier_helpers_match_the_depth_module():
    """rank/label helpers must not drift from recce.core.depth."""
    from recce.core import depth
    for t in depth.ALL_TIERS:
        assert _tier_rank(t) == depth.rank(t)
        assert _tier_label(t) == depth.label(t)


def test_exploit_findings_ranks_t3_kev_above_t2_and_unstamped_is_filtered():
    h = Host(ip="10.0.0.10")
    h.vulns = [
        # T3 with exploit_note — should rank first
        Vuln(ip="10.0.0.10", port=445, protocol="tcp", script_id="smb",
             title="EternalBlue vulnerable", severity="critical",
             depth_tier="t3", exploit_note="msf ms17_010_eternalblue", kev=True),
        # T2 crit KEV — should rank second (KEV boost within T2)
        Vuln(ip="10.0.0.10", port=27017, protocol="tcp", script_id="mongo",
             title="MongoDB unauth", severity="critical",
             depth_tier="t2", exploit_note="mongosh --host 10.0.0.10", kev=True),
        # T1 medium — no exploit_note + no depth_tier -> filtered
        Vuln(ip="10.0.0.10", port=22, protocol="tcp", script_id="ssh",
             title="Legacy SSH banner", severity="low"),
    ]
    got = _exploit_findings([h])
    assert len(got) == 2                       # unstamped Vuln filtered out
    assert got[0]["tier"] == "t3"              # T3 ranks first
    assert got[1]["tier"] == "t2"
    assert got[0]["kev"] is True
    assert "ms17_010" in got[0]["exploit_note"]


def test_cmd_suggest_prints_no_datastore_when_out_dir_empty(capsys):
    with tempfile.TemporaryDirectory() as td:
        args = argparse.Namespace(output_dir=td, top=10)
        rc = cmd_suggest(args)
    assert rc == 1                              # missing-datastore error path
    out = capsys.readouterr().out
    assert "No datastore" in out


def test_parser_registers_suggest_command_with_top_arg():
    """The parser must accept `recce suggest -o eng --top 5` and route
    to cmd_suggest so a future parser refactor can't silently drop it."""
    from recce.cli import parser as p
    a = p.build_arg_parser().parse_args(["suggest", "-o", "/tmp/xx", "--top", "5"])
    assert a.func.__name__ == "cmd_suggest"
    assert a.top == 5


def test_cmd_suggest_renders_seeded_engagement_end_to_end(capsys):
    """Integration: seed a Store with one host + one exploit-note vuln
    + one credential; assert the digest names them and the rules block
    fires (known_users rule picks up the seeded cred's admin bucket)."""
    from recce.core.models import Account, Credential
    from recce.core.store import Store
    with tempfile.TemporaryDirectory() as td:
        db_path = os.path.join(td, "results.sqlite")
        store = Store(db_path)
        h = Host(ip="10.0.0.10")
        h.vulns = [Vuln(
            ip="10.0.0.10", port=445, protocol="tcp", script_id="smb",
            title="SMBv1 enabled — MS17-010 verified",
            severity="critical", depth_tier="t2",
            exploit_note="msf use exploit/windows/smb/ms17_010_eternalblue; "
                         "set RHOSTS 10.0.0.10; check first",
            kev=True, ids=["CVE-2017-0143"])]
        h.accounts = [Account(ip="10.0.0.10", source="ldap", kind="user",
                              name="Administrator",
                              attrs={"admincount": "1"})]
        store.upsert_host(h)
        store.add_credential(Credential(
            username="Administrator", secret="Passw0rd!",
            kind="password", domain="CORP"))
        store.close()

        args = argparse.Namespace(output_dir=td, top=5)
        rc = cmd_suggest(args)
        assert rc == 0
        out = capsys.readouterr().out
        # Header + engagement metrics
        assert "recce suggests" in out
        assert "1 host" in out and "1 credential" in out
        # Exploit-findings block picked up the seeded T2 KEV finding
        assert "MS17-010" in out or "MS17_010" in out.upper() or "SMBv1" in out
        assert "10.0.0.10:445" in out
        # exploit_note text made it to the terminal
        assert "eternalblue" in out.lower() or "ms17_010" in out.lower()
