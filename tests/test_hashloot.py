"""hashloot: per-DB hashcat-format loot files, deduped + append-safe + 0600.

The DB modules extract hashes and put the hashcat mode number in each finding's
text. The operator needed the FILE to feed hashcat next to the command; before
this module they were grepping the report to reconstruct it.
"""
from __future__ import annotations

import os

import pytest

from recce.creds import hashloot


def test_mssql_probe_yields_the_pipe_delimited_line(tmp_path):
    """MSSQL stores hashes as (str,) tuples: 'user|0x0200<hex>'. The whole
    line goes into loot/mssql.hash — hashcat -m 1731 accepts the hex blob,
    and the user prefix makes the crack attributable to the account."""
    pairs = hashloot.collect_from_db_probe(
        {"hashes": [("sa|0x0200aa",), ("app|0x0200bb",)]}, "mssql")
    assert pairs == [("mssql", "sa|0x0200aa"), ("mssql", "app|0x0200bb")]


def test_mysql_probe_prefixes_star_when_missing(tmp_path):
    """mysql.user Password digests either arrive with or without the leading
    '*'; hashcat -m 300 wants the star, so we normalise before writing."""
    pairs = hashloot.collect_from_db_probe({"hashes": [
        {"user": "root", "host": "%", "hash": "*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B"},
        {"user": "svc",  "host": "%", "hash": "010203"},        # no star
    ]}, "mysql")
    assert pairs[0] == ("mysql", "root:*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B")
    assert pairs[1] == ("mysql", "svc:*010203")


def test_mongo_splits_scram_sha1_and_sha256_by_mechanism(tmp_path):
    """Mongo emits both mechanisms in one probe; each goes to its own file so
    hashcat -m 24100 vs -m 24200 can be run separately."""
    pairs = hashloot.collect_from_db_probe({"hashes": [
        {"user": "r", "mechanism": "SCRAM-SHA-1",
         "hashcat": "$mongodb-scram$*0*a*10*b*c"},
        {"user": "a", "mechanism": "SCRAM-SHA-256",
         "hashcat": "$mongodb-scram$*1*a*15*b*c"},
    ]}, "mongodb")
    cats = [c for c, _ in pairs]
    assert cats == ["mongo-scram", "mongo-scram256"]


def test_probe_with_no_hashes_yields_nothing(tmp_path):
    assert hashloot.collect_from_db_probe({}, "mssql") == []
    assert hashloot.collect_from_db_probe({"hashes": []}, "mysql") == []
    # a service with no extractor mapped returns [] rather than raising
    assert hashloot.collect_from_db_probe({"hashes": [{"x": 1}]}, "unknown") == []


def test_write_creates_the_file_with_0600(tmp_path):
    n = hashloot.write_hashcat_file(str(tmp_path), "mssql",
                                    ["sa|0x0200aa", "app|0x0200bb"])
    assert n == 2
    path = tmp_path / "mssql.hash"
    assert path.exists()
    mode = oct(path.stat().st_mode)[-3:]
    assert mode == "600", f"expected 0600, got 0{mode}"
    body = path.read_text().splitlines()
    assert body == ["sa|0x0200aa", "app|0x0200bb"]


def test_write_appends_and_dedups_across_runs(tmp_path):
    """Re-running a scan mid-engagement adds NEW hashes, keeps the file
    monotonically growing, and never duplicates a line already present.
    Otherwise the tester's incremental crack progress is lost or corrupted."""
    hashloot.write_hashcat_file(str(tmp_path), "mysql",
                                ["root:*AAA", "svc:*BBB"])
    # second run: one repeated, one new
    n = hashloot.write_hashcat_file(str(tmp_path), "mysql",
                                    ["root:*AAA", "new:*CCC"])
    assert n == 1
    body = (tmp_path / "mysql.hash").read_text().splitlines()
    assert body == ["root:*AAA", "svc:*BBB", "new:*CCC"]


def test_empty_input_writes_nothing(tmp_path):
    n = hashloot.write_hashcat_file(str(tmp_path), "mssql", [])
    assert n == 0
    assert not (tmp_path / "mssql.hash").exists()


def test_unknown_category_raises(tmp_path):
    with pytest.raises(ValueError):
        hashloot.write_hashcat_file(str(tmp_path), "not_a_category", ["x"])


def test_kerberos_categories_are_registered_so_potfile_matcher_recognises_them():
    """The existing kerberoast + asrep loot files were written by
    cli/_service_helpers.py before this module existed. Registering them in
    CATEGORIES with their real modes lets the potfile importer + any future
    reader look them up by the same name."""
    assert hashloot.CATEGORIES["kerberoast"][:2] == ("kerberoast.hash", 13100)
    assert hashloot.CATEGORIES["asrep"][:2] == ("asrep.hash", 18200)


def test_creds_to_hashcat_lines_labels_nt_hashes_with_user(tmp_path):
    """passwords.txt / nthashes.txt are bare-line files that spraying tools
    consume. The labeled form makes the crack attributable after hashcat writes
    its potfile — user:hash is what mode 1000 expects too."""
    from recce.core.models import Credential
    lines = hashloot.creds_to_hashcat_lines([
        Credential(username="alice", secret="8846F7EAEE8FB117AD06BDD830B7586C",
                   kind="nthash", domain="CORP"),
        Credential(username="", secret="deadbeef", kind="nthash"),   # skipped: no user
        Credential(username="bob", secret="p4ss", kind="password"),  # skipped: not nthash
    ])
    assert lines == ["alice:8846F7EAEE8FB117AD06BDD830B7586C"]
