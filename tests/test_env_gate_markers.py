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
