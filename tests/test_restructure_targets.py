"""Safety-net smoke tests for the seven modules the planned restructure touches.

Purpose: the restructure will rename or move public entry points. Integration
tests reach these modules through orchestration paths and can pass even when a
function has been silently renamed or a contract broken. These tests explicitly
import each target and exercise its public API with a valid input plus a
malformed input, so any regression during a subpackage move (report/, ad/,
services/, services/db/, vuln/, act/, creds/, intake/, core/) surfaces here.

Each test intentionally uses the CURRENT import path (`from recce.services.web import …`)
so that a move to `from recce.services.web import …` breaks the import and
forces the restructure PR to also update this file. That's the point.

Keep these tests fast — they must run in the default (non-slow) suite.
"""
from __future__ import annotations

import pytest

from recce.core.models import Host, Port


# --- web.py -------------------------------------------------------------------

class TestWebModule:
    def test_imports(self):
        from recce.services import web  # noqa: F401

    def test_is_web_positive_and_negative(self):
        from recce.services.web import is_web
        assert is_web(Port(portid=80, service="http")) is True
        assert is_web(Port(portid=443, service="https")) is True
        assert is_web(Port(portid=22, service="ssh")) is False

    def test_wordlist_returns_list(self):
        from recce.services.web import wordlist_for_gobuster, wordlist_for_domain_enum
        gob = wordlist_for_gobuster()
        assert isinstance(gob, list) and len(gob) > 0
        dom = wordlist_for_domain_enum()
        assert isinstance(dom, list)

    def test_is_web_malformed(self):
        from recce.services.web import is_web
        # empty service string + non-standard port: must not crash
        assert isinstance(is_web(Port(portid=0, service="")), bool)


# --- bloodhound.py ------------------------------------------------------------

class TestBloodhoundModule:
    def test_imports(self):
        from recce.ad import bloodhound  # noqa: F401

    def test_public_fns_exist(self):
        from recce.ad.bloodhound import (
            is_sharphound, load_graph, high_value_targets,
            attack_paths, findings, is_dc,
        )
        # non-existent path must not raise, just return falsy
        assert is_sharphound("/nonexistent/path/that/does/not/exist") is False

    def test_high_value_targets_empty_graph(self):
        from recce.ad.bloodhound import high_value_targets, findings
        # bloodhound expects the parsed BloodHound JSON shape: {nodes, edges}.
        # An empty-but-well-formed graph must yield empty results, not crash.
        # bloodhound.load_graph returns {nodes, edges, adj, domains}.
        empty = {"nodes": {}, "edges": [], "adj": {}, "domains": {}}
        assert isinstance(high_value_targets(empty), dict)
        assert isinstance(findings(empty), list)

    def test_attack_paths_empty_graph(self):
        from recce.ad.bloodhound import attack_paths
        # bloodhound.load_graph returns {nodes, edges, adj, domains}.
        empty = {"nodes": {}, "edges": [], "adj": {}, "domains": {}}
        result = attack_paths(empty, owned=set())
        assert result is not None


# --- ad.py --------------------------------------------------------------------

class TestAdModule:
    def test_imports(self):
        from recce import ad  # noqa: F401

    def test_empty_host_list_returns_empty(self):
        from recce.ad import (
            analyze_hosts, domain_controllers, relay_targets,
            smbv1_hosts, kerberoastable, asrep_roastable,
            delegation_accounts, quick_wins, privileged_accounts,
        )
        # analyze_hosts mutates in place; calling with [] must not crash
        analyze_hosts([])
        # every "give me matching hosts/accounts" helper returns [] for empty input
        for fn in (domain_controllers, relay_targets, smbv1_hosts,
                   kerberoastable, asrep_roastable, delegation_accounts,
                   quick_wins, privileged_accounts):
            assert list(fn([])) == []

    def test_identify_roles_bare_host(self):
        from recce.ad import identify_roles
        # a bare Host with no scripts / ports must not blow up
        h = Host(ip="10.0.0.1")
        identify_roles(h)  # in-place; contract is "does not raise"
        assert isinstance(h.roles, list)


# --- kerberos.py --------------------------------------------------------------

class TestKerberosModule:
    def test_imports(self):
        from recce.ad import kerberos  # noqa: F401

    def test_is_kerberos(self):
        from recce.ad.kerberos import is_kerberos
        # Recognises the main KDC port (88), plus service/product string hints.
        # 464 (kpasswd) is intentionally NOT recognised — see kerberos.is_kerberos.
        assert is_kerberos(Port(portid=88)) is True
        assert is_kerberos(Port(portid=88, service="kerberos-sec")) is True
        assert is_kerberos(Port(portid=22)) is False

    def test_client_key_derives_bytes(self):
        from recce.ad.kerberos import client_key
        # password-based derivation must return bytes of a plausible key length
        key = client_key(password="Passw0rd!")
        assert isinstance(key, bytes) and len(key) in (16, 32)  # RC4 or AES

    def test_parse_response_malformed(self):
        from recce.ad.kerberos import parse_response
        # short/garbage KRB response must not crash — should return dict or raise
        # a specific caught exception, not propagate an unexpected one
        try:
            parse_response(b"\x00\x01\x02\x03")
        except (ValueError, IndexError, KeyError):
            pass  # expected classes for malformed ASN.1


# --- scanner.py ---------------------------------------------------------------

class TestScannerModule:
    def test_imports(self):
        from recce.core import scanner  # noqa: F401

    def test_scan_profile_defaults(self):
        from recce.core.scanner import ScanProfile
        p = ScanProfile()
        assert p.name == "standard"
        assert p.top_ports > 0

    def test_harden_for_proxy_returns_profile(self):
        from recce.core.scanner import ScanProfile, harden_for_proxy
        p = harden_for_proxy(ScanProfile())
        # returns a (potentially adjusted) ScanProfile — must not be None
        assert p is not None
        assert hasattr(p, "top_ports")

    def test_check_environment_returns_list(self):
        from recce.core.scanner import ScanProfile, check_environment
        issues = check_environment(ScanProfile())
        assert isinstance(issues, list)


# --- sessions/tunnel.py -------------------------------------------------------

class TestTunnelModule:
    def test_imports(self):
        from recce.sessions import tunnel  # noqa: F401

    def test_public_classes_exist(self):
        from recce.sessions.tunnel import TunnelState, TunnelMux, get_tunnel
        # class-level sanity: they should be instantiable/queryable
        assert callable(TunnelState)
        assert callable(TunnelMux)
        assert callable(get_tunnel)

    def test_get_tunnel_missing_id(self):
        from recce.sessions.tunnel import get_tunnel
        # asking for a session id that doesn't exist must return None, not crash
        assert get_tunnel("no-such-session-id-12345") is None


# --- scram.py -----------------------------------------------------------------

class TestScramModule:
    def test_imports(self):
        from recce.ad import scram  # noqa: F401

    def test_mongo_sha1_secret_shape(self):
        from recce.ad.scram import mongo_sha1_secret
        # MongoDB SCRAM-SHA-1 secret is md5(user + ":mongo:" + password), hex string
        h = mongo_sha1_secret("alice", "hunter2")
        assert isinstance(h, str)
        assert len(h) == 32 and all(c in "0123456789abcdef" for c in h)

    def test_mongo_sha1_secret_deterministic(self):
        from recce.ad.scram import mongo_sha1_secret
        # same input → same output (it's a hash)
        a = mongo_sha1_secret("bob", "swordfish")
        b = mongo_sha1_secret("bob", "swordfish")
        assert a == b

    def test_mongo_sha1_secret_empty(self):
        from recce.ad.scram import mongo_sha1_secret
        # empty inputs should still produce a valid hex digest, not crash
        assert len(mongo_sha1_secret("", "")) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
