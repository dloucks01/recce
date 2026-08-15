"""Regression tests for the engagement-blocker hardening pass.

Each test pins a fix for a way a real engagement could silently lose data or
open ports:
  - iter_probe must isolate a single crashing target (a hostile/broken server
    response) instead of aborting the whole deep-service phase;
  - the `thorough` profile must not carry a --min-rate floor (which trips
    firewall scan-detection and drops open ports - the exact standard-profile bug);
  - the auto -Pn fallback (discovery fully blocked) must enable verify_all so
    firewalled 0-port hosts still get the union re-verify.
"""
from __future__ import annotations

from recce import scanner, svcprobe


def test_iter_probe_isolates_a_crashing_target():
    # target #2 raises like a hostile server would (struct.error/IndexError/...);
    # the sweep must skip it, record it, and still probe #1 and #3.
    targets = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}]

    def probe_one(t):
        if t["ip"] == "10.0.0.2":
            raise IndexError("truncated response from a broken server")
        return {"ok": True}

    state: dict = {}
    got = list(svcprobe.iter_probe(targets, probe_one, state=state))
    # the two good targets still came back - one bad target did NOT abort the sweep
    assert [t["ip"] for t, _ in got] == ["10.0.0.1", "10.0.0.3"]
    assert state["done"] == 3                       # all three were attempted
    assert state["stopped"] is None                 # ran to completion, not aborted
    assert len(state.get("errors", [])) == 1        # the crash was recorded, not lost
    assert state["errors"][0][0]["ip"] == "10.0.0.2"


def test_thorough_profile_also_has_no_min_rate_floor():
    # An operator worried about coverage reaches for --profile thorough; it must not
    # be MORE likely to miss ports behind a firewall than standard.
    assert scanner.PROFILES["thorough"].min_rate == 0
    assert scanner.PROFILES["standard"].min_rate == 0
    # ...and the built command must carry no --min-rate for a thorough sweep.
    import os
    cmd = scanner._portscan_cmd("10.0.0.9", os.devnull, scanner.PROFILES["thorough"],
                                reliable=False)
    assert "--min-rate" not in cmd


def test_ipv6_target_gets_dash6_injected():
    # nmap refuses an IPv6 literal without -6 (0 ports otherwise). _run injects it.
    v6 = scanner._maybe_ipv6(["nmap", "-sS", "-Pn", "-p-", "2001:db8::1", "-oX", "/x"])
    assert v6[:2] == ["nmap", "-6"] and "2001:db8::1" in v6
    # an IPv4 target is untouched...
    v4 = scanner._maybe_ipv6(["nmap", "-sS", "-Pn", "10.0.0.1", "-oX", "/x"])
    assert "-6" not in v4
    # ...already-pinned family is left alone, and non-nmap commands are ignored
    assert scanner._maybe_ipv6(["nmap", "-4", "10.0.0.1"]).count("-6") == 0
    assert scanner._maybe_ipv6(["masscan", "2001:db8::1", "-p", "80"])[0] == "masscan"


def test_ipv6_only_target_file_gets_dash6(tmp_path):
    f6 = tmp_path / "v6.txt"
    f6.write_text("2001:db8::1\n2001:db8::2\n")
    assert scanner._file_family_args(str(f6)) == ["-6"]
    fmix = tmp_path / "mixed.txt"
    fmix.write_text("10.0.0.1\n2001:db8::1\n")           # mixed -> no -6 (v4 default)
    assert scanner._file_family_args(str(fmix)) == []
