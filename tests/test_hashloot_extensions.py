"""hashloot: new category coverage for the challenge/response services.

pop3-apop, imap-cram, imap-digest and iscsi-chap were added so the SASL/CHAP
challenge that pop3/imap/iscsi capture on the wire gets a loot file (rather
than only appearing in a finding-text template the operator has to grep out).
Only the server half is captured — the loot line carries a stable placeholder
for the operator to drop the on-path client response into.
"""
from __future__ import annotations

import pytest

from recce.creds import hashloot
from recce.creds import known_hashes


# --- categories registered --------------------------------------------------

def test_new_categories_carry_the_documented_hashcat_modes():
    """Modes are load-bearing: they show up in the CLI 'hashcat -m N' hint
    printed after the loot file is written, and in the potfile matcher's
    by_mode index. Pinning them here catches an accidental mode edit."""
    assert hashloot.CATEGORIES["pop3-apop"][:2]   == ("pop3-apop.hash",   20)
    assert hashloot.CATEGORIES["imap-cram"][:2]   == ("imap-cram.hash",   10200)
    assert hashloot.CATEGORIES["imap-digest"][:2] == ("imap-digest.hash", 11500)
    assert hashloot.CATEGORIES["iscsi-chap"][:2]  == ("iscsi-chap.hash",  4800)


def test_known_hashes_reader_recognises_new_categories(tmp_path):
    """known_hashes reads its category table off hashloot.CATEGORIES, so a
    file dropped into loot/<new>.hash by write_hashcat_file() gets counted
    into by_mode and categories without a second registration step."""
    hashloot.write_hashcat_file(str(tmp_path), "iscsi-chap",
                                ["<CLIENT-RESPONSE>:0123abcd:7"])
    inv = known_hashes.known_hashes([], loot_dir=str(tmp_path))
    assert inv["categories"].get("iscsi-chap") == 1
    assert inv["by_mode"].get(4800) == 1


# --- write_hashcat_file dedup + append across the new categories -----------

@pytest.mark.parametrize("category,first,repeat,new", [
    ("pop3-apop",
     "<CLIENT-RESPONSE>:<1896.697170952@dbc.mtview.ca.us>",
     "<CLIENT-RESPONSE>:<1896.697170952@dbc.mtview.ca.us>",
     "<CLIENT-RESPONSE>:<9999.111@other.example>"),
    ("imap-cram",
     "$cram_md5$PDE4OTYuNjk3MTcwOTUyQGRiYy5tdHZpZXcuY2EudXM+$<CLIENT-RESPONSE>",
     "$cram_md5$PDE4OTYuNjk3MTcwOTUyQGRiYy5tdHZpZXcuY2EudXM+$<CLIENT-RESPONSE>",
     "$cram_md5$YWJjZGVm$<CLIENT-RESPONSE>"),
    ("imap-digest",
     "realm=\"corp\",nonce=\"AAAAAA==\",qop=\"auth\":<CLIENT-RESPONSE>",
     "realm=\"corp\",nonce=\"AAAAAA==\",qop=\"auth\":<CLIENT-RESPONSE>",
     "realm=\"corp\",nonce=\"BBBBBB==\",qop=\"auth\":<CLIENT-RESPONSE>"),
    ("iscsi-chap",
     "<CLIENT-RESPONSE>:0x1a2b3c4d5e6f:23",
     "<CLIENT-RESPONSE>:0x1a2b3c4d5e6f:23",
     "<CLIENT-RESPONSE>:0xdeadbeef:42"),
])
def test_write_dedups_per_new_category(tmp_path, category, first, repeat, new):
    """Re-scanning a service twice must not duplicate a challenge already
    on disk, but a genuinely-new challenge must land. This is the same
    invariant the existing mssql/mysql tests cover, restated per new file
    so a category-specific writer bug can't slip in."""
    n1 = hashloot.write_hashcat_file(str(tmp_path), category, [first])
    assert n1 == 1
    n2 = hashloot.write_hashcat_file(str(tmp_path), category, [repeat, new])
    assert n2 == 1
    fname = hashloot.CATEGORIES[category][0]
    body = (tmp_path / fname).read_text().splitlines()
    assert body == [first, new]


# --- collect_from_probe: producer wire-up ----------------------------------

def test_pop3_probe_yields_apop_line_when_timestamp_captured():
    """RFC 1939 §7 APOP challenge is the server greeting suffix. The
    reference example from RFC 1939 uses '<1896.697170952@dbc.mtview.ca.us>'
    as the challenge; the finished hash format is 'md5(challenge.password)'
    (mode 20 = md5($salt.$pass)), so the line the loot file carries is
    '<hex>:<challenge>' with the hex half a placeholder until the operator
    captures a real client's APOP response line."""
    probe = {"apop_timestamp": "<1896.697170952@dbc.mtview.ca.us>",
             "sasl_challenges": {}}
    pairs = hashloot.collect_from_probe(probe, "pop3")
    assert pairs == [
        ("pop3-apop", "<CLIENT-RESPONSE>:<1896.697170952@dbc.mtview.ca.us>")]


def test_pop3_probe_also_covers_cram_and_digest_challenges():
    """POP3 stores SASL challenges under sasl_challenges — the same
    hashcat modes (10200 / 11500) as IMAP, so the loot categories are
    shared."""
    probe = {"apop_timestamp": "",
             "sasl_challenges": {"cram_md5": "PGFAYj4=",
                                 "digest_md5": "realm=\"x\",nonce=\"y\""}}
    pairs = hashloot.collect_from_probe(probe, "pop3")
    cats = [c for c, _ in pairs]
    assert cats == ["imap-cram", "imap-digest"]
    assert pairs[0][1] == "$cram_md5$PGFAYj4=$<CLIENT-RESPONSE>"
    assert pairs[1][1] == "realm=\"x\",nonce=\"y\":<CLIENT-RESPONSE>"


def test_imap_probe_yields_cram_and_digest_when_both_captured():
    """The IMAP prober kicks off AUTHENTICATE CRAM-MD5 / DIGEST-MD5 and
    aborts with '*' after capturing the server's continuation challenge
    (RFC 3501 §6.2.2). Both challenges landing in the same probe should
    produce two loot lines, one per mode."""
    probe = {"cram_md5_challenge": "PDE4OTYuNjk3MTcwOTUyQGRiYy5tdHZpZXcuY2EudXM+",
             "digest_md5_challenge": "cmVhbG09XCJ4XCIsbm9uY2U9XCJ5XCI="}
    pairs = hashloot.collect_from_probe(probe, "imap")
    assert pairs == [
        ("imap-cram",
         "$cram_md5$PDE4OTYuNjk3MTcwOTUyQGRiYy5tdHZpZXcuY2EudXM+$<CLIENT-RESPONSE>"),
        ("imap-digest",
         "cmVhbG09XCJ4XCIsbm9uY2U9XCJ5XCI=:<CLIENT-RESPONSE>"),
    ]


def test_iscsi_probe_yields_chap_line_when_id_and_challenge_present():
    """RFC 3720 §11.1 CHAP negotiation: target picks CHAP_A, sends CHAP_I
    (identifier) + CHAP_C (challenge). Hashcat -m 4800 wants
    'chap_r:chap_c:chap_i'; recce never sends CHAP_R itself (conservative
    capture) so the response half is the placeholder."""
    probe = {"chap": {"algorithm": "5", "id": "23",
                      "challenge": "0x1a2b3c4d5e6f", "hashcat_mode": 4800}}
    assert hashloot.collect_from_probe(probe, "iscsi") == [
        ("iscsi-chap", "<CLIENT-RESPONSE>:0x1a2b3c4d5e6f:23")]


def test_iscsi_probe_without_full_chap_yields_nothing():
    """A CHAP dict missing either half is not usable — recce should not
    write a half-line the operator can't complete."""
    assert hashloot.collect_from_probe({"chap": {}}, "iscsi") == []
    assert hashloot.collect_from_probe(
        {"chap": {"id": "23"}}, "iscsi") == []
    assert hashloot.collect_from_probe(
        {"chap": {"challenge": "0xdead"}}, "iscsi") == []


def test_empty_probes_yield_nothing_for_the_new_services():
    """Missing / empty fields must not produce a loot line — otherwise the
    file fills with placeholder-only rows and the dedup set drifts. Nothing
    to record is the right answer."""
    assert hashloot.collect_from_probe({}, "pop3") == []
    assert hashloot.collect_from_probe({}, "imap") == []
    assert hashloot.collect_from_probe({}, "iscsi") == []
    assert hashloot.collect_from_probe(
        {"apop_timestamp": "", "sasl_challenges": {}}, "pop3") == []
    assert hashloot.collect_from_probe(
        {"cram_md5_challenge": "", "digest_md5_challenge": ""}, "imap") == []


# --- end-to-end wire: probe -> collect -> write --------------------------

def test_probe_to_disk_flows_all_new_services(tmp_path):
    """Integration: the shape each service actually stores lands in the
    matching loot file with the mode the CLI announces. Mirrors what
    _service_helpers.py does after each per-service analyze() call."""
    scenarios = [
        ("pop3", {"apop_timestamp": "<x@y>", "sasl_challenges": {}}),
        ("imap", {"cram_md5_challenge": "PGE+"}),
        ("iscsi", {"chap": {"id": "1", "challenge": "0xab"}}),
    ]
    total = 0
    for service, probe in scenarios:
        for cat, line in hashloot.collect_from_probe(probe, service):
            total += hashloot.write_hashcat_file(str(tmp_path), cat, [line])
    assert total == 3
    assert (tmp_path / "pop3-apop.hash").exists()
    assert (tmp_path / "imap-cram.hash").exists()
    assert (tmp_path / "iscsi-chap.hash").exists()
    # A repeat pass adds nothing.
    total2 = 0
    for service, probe in scenarios:
        for cat, line in hashloot.collect_from_probe(probe, service):
            total2 += hashloot.write_hashcat_file(str(tmp_path), cat, [line])
    assert total2 == 0
