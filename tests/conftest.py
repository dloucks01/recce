"""Shared pytest config: auto-mark the slow, real-nmap integration suites.

Most of the suite is fast pure-logic tests. A minority stand up real listeners and
drive REAL nmap / real network probes (or generate large scale datasets) - these
dominate wall-clock and don't need to run on every push. They're auto-marked `slow`
here so CI (and local dev) can split them:

    pytest -m "not slow"    # fast feedback - every PR/push
    pytest -m slow          # the real-nmap integration suite - master / nightly

Marking lives here (one place, keyed by module name) rather than editing each file.
"""
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
}


def pytest_collection_modifyitems(config, items):
    slow = pytest.mark.slow
    for item in items:
        module = getattr(item, "module", None)
        name = getattr(module, "__name__", "").rsplit(".", 1)[-1]
        if name in _SLOW_MODULES:
            item.add_marker(slow)
