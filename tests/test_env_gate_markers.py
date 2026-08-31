"""Phase 9a env-gate marker smoke tests.

Confirms the `@needs_compose` and `@needs_vagrant` markers registered by
conftest.py behave correctly — SKIP (not FAIL) when the test_env plane
isn't reachable, and pass through when it is (spot-checked here with a
canary that's always unreachable so we exercise the skip path).
"""
from __future__ import annotations

import pytest


def test_needs_compose_marker_is_registered(pytestconfig):
    """The marker must show up in `pytest --markers` so users see the docs."""
    markers = pytestconfig.getini("markers")
    assert any("needs_compose" in m for m in markers), \
        "needs_compose marker not registered; check conftest.pytest_configure"


def test_needs_vagrant_marker_is_registered(pytestconfig):
    markers = pytestconfig.getini("markers")
    assert any("needs_vagrant" in m for m in markers), \
        "needs_vagrant marker not registered; check conftest.pytest_configure"


# The following test uses the marker with a profile whose canary lives at
# 172.20.0.50:143 — Phase 9a's dovecot. On any dev box where the test_env
# core profile is not up (i.e. every CI runner today) this MUST skip, not
# fail, not error. If the core profile IS up this passes trivially.
@pytest.mark.needs_compose("core")
def test_dovecot_canary_reachable_when_core_is_up():
    """Trivial pass — proves the skip machinery lets a test through when
    the env IS actually reachable. Skipped otherwise."""
    import socket
    with socket.create_connection(("172.20.0.50", 143), timeout=2):
        pass


# An unknown-profile marker should skip with a helpful message rather
# than fail the collection.
@pytest.mark.needs_compose("this-profile-does-not-exist")
def test_unknown_profile_skips_cleanly():
    """Should never execute — skipped by pytest_runtest_setup with a
    'unknown compose profile' message."""
    raise AssertionError("this test should have been skipped")


@pytest.mark.needs_vagrant("this-vm-does-not-exist")
def test_unknown_vagrant_skips_cleanly():
    raise AssertionError("this test should have been skipped")


# The bmc canary uses ipmi-udp probing (IPMI is 623/udp only, so the
# default TCP-connect canary always reports the BMC down). Confirm the
# UDP probe returns False cleanly when nothing is listening — the failure
# mode we care about is "hangs the test suite" or "raises OSError".
def test_ipmi_udp_probe_returns_false_when_nothing_listens():
    from tests.conftest import _ipmi_udp_reachable
    # 0-port is guaranteed to have nothing listening; timeout keeps the
    # test snappy even when the loopback stack accepts the datagram and
    # produces no reply.
    assert _ipmi_udp_reachable("127.0.0.1", 0, timeout=0.5) is False


def test_bmc_canary_is_registered_with_ipmi_udp_kind():
    """Regression: the bmc canary must carry the ipmi-udp kind so
    `@pytest.mark.needs_vagrant("bmc")` actually probes the BMC and
    doesn't always skip through the TCP path."""
    from tests.conftest import _VAGRANT_CANARIES
    canary = _VAGRANT_CANARIES.get("bmc")
    assert canary is not None
    assert len(canary) == 3
    assert canary[2] == "ipmi-udp"
