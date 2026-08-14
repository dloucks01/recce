"""The default port sweep must be at least as reliable as a plain `nmap -p-`.

recce used to force --max-retries 3 (HALF of nmap's -T4 default of 6) and a
--min-rate floor, so it dropped SYNs to open ports that a manual `nmap -p-` at the
same -T level would have found - the "recce misses ports vs manual nmap" bug.
"""
from __future__ import annotations

from recce import scanner


def test_nmap_default_retries_table():
    assert scanner._nmap_default_retries(4) == 6      # -T4
    assert scanner._nmap_default_retries(5) == 2      # -T5
    assert scanner._nmap_default_retries(3) == 10     # -T3 / slower
    assert scanner._nmap_default_retries(2) == 10


def _sweep(profile):
    cmd, _ = scanner._portscan_cmd("10.0.0.5", "/tmp/x.xml", profile, reliable=False)
    return cmd


def test_no_profile_retries_below_nmaps_own_default():
    # every profile's sweep must retry >= nmap's own default for its -T level
    for name, prof in scanner.PROFILES.items():
        cmd = _sweep(prof)
        retries = int(cmd[cmd.index("--max-retries") + 1])
        timing = int(next(a for a in cmd if a.startswith("-T"))[2:])
        assert retries >= scanner._nmap_default_retries(timing), (name, retries, timing)


def test_standard_default_has_no_min_rate_floor():
    # the default is adaptive like manual nmap: no --min-rate floor to overspeed +
    # drop SYNs to open ports; and it retries at nmap's -T4 default (6), not 3.
    cmd = _sweep(scanner.PROFILES["standard"])
    assert "--min-rate" not in cmd
    assert cmd[cmd.index("--max-retries") + 1] == "6"


def test_quick_keeps_a_floor_for_triage_but_still_retries_enough():
    # quick trades some completeness for speed (a rate floor), but must still retry
    # >= nmap's default so it doesn't silently lose ports either.
    cmd = _sweep(scanner.PROFILES["quick"])
    assert "--min-rate" in cmd
    assert int(cmd[cmd.index("--max-retries") + 1]) >= 6
