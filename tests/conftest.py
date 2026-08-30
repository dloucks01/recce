"""Shared pytest config: auto-mark the slow, real-nmap integration suites.

Most of the suite is fast pure-logic tests. A minority stand up real listeners and
drive REAL nmap / real network probes (or generate large scale datasets) - these
dominate wall-clock and don't need to run on every push. They're auto-marked `slow`
here so CI (and local dev) can split them:

    pytest -m "not slow"    # fast feedback - every PR/push
    pytest -m slow          # the real-nmap integration suite - master / nightly

Marking lives here (one place, keyed by module name) rather than editing each file.

Phase 9a additions — env-gated markers for the test_env/ compose plane:

    @pytest.mark.needs_compose("core")    # skip unless test_env core profile is up
    @pytest.mark.needs_vagrant("ad-dc")   # skip unless the AD-DC VM is reachable

The helper reads RECCE_TEST_NET (default 172.20.0.0/24) and probes a
per-profile canary IP. Tests SKIP (never fail) when the env isn't up so
CI runners without the plane still pass the fast lane.
"""
import os
import socket

import pytest

_SLOW_MODULES = {
    "test_scan_fidelity",           # real nmap: port-state fidelity
    "test_service_fidelity",        # real nmap: service detection
    "test_system_fidelity",         # real nmap: system-type scenarios
    "test_hostile_server_fidelity", # real nmap vs slow/hostile listeners
    "test_integration_nmap",        # real nmap end-to-end
    "test_live_smoke",              # real nmap smoke (slowest file)
    "test_scan_efficiency",         # real nmap timing/efficiency
    "test_cred_integration",        # real nmap + credentialed flow
    "test_probe_transport",         # real TLS/socket transport probes
    "test_scale",                   # large-scope scale generation
    "test_netmap_scale",            # large-scope map rendering
    "test_workflow",                # real nmap: end-to-end workflow/usability
    "test_credentialed_ad_integration",  # real Samba DC (also env-gated)
    "test_db_integration",               # real PostgreSQL + MariaDB servers
}


def pytest_collection_modifyitems(config, items):
    slow = pytest.mark.slow
    for item in items:
        module = getattr(item, "module", None)
        name = getattr(module, "__name__", "").rsplit(".", 1)[-1]
        if name in _SLOW_MODULES:
            item.add_marker(slow)


# ─── Phase 9a: test_env/ compose + vagrant env-gate markers ────────────────

# A canary IP per profile — a TCP connect to (canary_ip, canary_port) with a
# ≤1 s timeout classifies whether the profile is reachable. Chosen so a
# probe-and-skip round-trip stays under ~1 s per test even when nothing is up.
_COMPOSE_CANARIES = {
    # Base env services always ship — canary is the SSH target.
    "base":       ("172.20.0.10", 22),
    # Phase 9a `core` profile: dovecot always comes up in core.
    "core":       ("172.20.0.50", 143),
    "mail":       ("172.20.0.50", 143),
    "databases":  ("172.20.0.53", 11211),
    "messaging":  ("172.20.0.54", 1883),
    "media":      ("172.20.0.58", 8554),
}

_VAGRANT_CANARIES = {
    "ad-dc":     ("172.20.1.10", 445),      # Windows AD DC (planned Phase 9c)
    "bmc":       ("172.20.1.20", 623),
    "kernelnet": ("172.20.1.30", 3260),
}


def _reachable(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def pytest_configure(config):
    """Register the compose/vagrant env markers so pytest doesn't warn."""
    config.addinivalue_line(
        "markers",
        "needs_compose(profile): skip unless the named test_env/ compose "
        "profile is reachable (default 172.20.0.0/24; override with "
        "RECCE_TEST_NET). Profiles: base, core, mail, databases, messaging, media.")
    config.addinivalue_line(
        "markers",
        "needs_vagrant(vm): skip unless the named Vagrant VM is reachable "
        "(planned Phase 9c). VMs: ad-dc, bmc, kernelnet.")


@pytest.fixture(scope="session")
def _env_reachable() -> dict:
    """Session-scoped cache: {(kind, key): bool}. Computed once per pytest run
    so 200 `@needs_compose` tests don't all pay the connect cost."""
    return {}


def pytest_runtest_setup(item):
    """Skip a test whose @needs_compose / @needs_vagrant marker names an
    unreachable env slice. The reachability probe is cached per session via
    the module-level `_ENV_REACHED` dict so we only pay the TCP-connect once
    per profile even when many tests reference the same one."""
    for mark in item.iter_markers(name="needs_compose"):
        profile = (mark.args[0] if mark.args else "base")
        canary = _COMPOSE_CANARIES.get(profile)
        if canary is None:
            pytest.skip(f"unknown compose profile {profile!r} — "
                        f"expected one of {sorted(_COMPOSE_CANARIES)}")
        if not _env_reached(("compose", profile), canary):
            pytest.skip(f"test_env compose profile {profile!r} not up "
                        f"(canary {canary[0]}:{canary[1]} unreachable) — "
                        f"run `docker compose --profile {profile} up --wait` "
                        f"in test_env/")
    for mark in item.iter_markers(name="needs_vagrant"):
        vm = (mark.args[0] if mark.args else "ad-dc")
        canary = _VAGRANT_CANARIES.get(vm)
        if canary is None:
            pytest.skip(f"unknown vagrant VM {vm!r} — "
                        f"expected one of {sorted(_VAGRANT_CANARIES)}")
        if not _env_reached(("vagrant", vm), canary):
            pytest.skip(f"vagrant VM {vm!r} not up (canary "
                        f"{canary[0]}:{canary[1]} unreachable) — "
                        f"run `vagrant up {vm}` in test_env/vagrant/ "
                        f"(Phase 9c)")


# Module-level cache — one connect per (kind, key) per pytest run.
_ENV_REACHED: dict = {}


def _env_reached(cache_key: tuple, canary: tuple) -> bool:
    if cache_key not in _ENV_REACHED:
        # Env override lets a CI runner override the subnet base
        # (`RECCE_TEST_NET=10.0.0.0/24` -> flip 172.20.x.y -> 10.0.x.y).
        ip, port = canary
        override = os.environ.get("RECCE_TEST_NET_BASE")
        if override:
            octets = ip.split(".")
            base = override.split(".")
            ip = ".".join(base[:2] + octets[2:])
        _ENV_REACHED[cache_key] = _reachable(ip, port)
    return _ENV_REACHED[cache_key]
