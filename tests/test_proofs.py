"""Tests for the proof-of-vulnerability engine (recce.proofs)."""
from __future__ import annotations

import pytest

from recce.core.models import Host, Port, Vuln
from recce.vuln.proofs import (
    CONFIRMED, FALSE_POSITIVE, INCONCLUSIVE, LIKELY,
    _is_dc, _local, _nse_vulnerable, _os_blob, _port_of, _port_open, _pv,
    _v_activemq, _v_eol, _v_kerberoast, _v_log4shell, _v_ms17,
    _v_potato, _v_smb_signing, _v_version_cve, _v_zerologon,
    recipe_for, summary, verify_host, verify_hosts,
)


# ---------------------------------------------------------------------------
# fixture helpers
# ---------------------------------------------------------------------------

def _host(ip="10.0.0.1", ports=None, vulns=None, **kw):
    h = Host(ip=ip, ports=ports or [], vulns=vulns or [])
    for k, v in kw.items():
        setattr(h, k, v)
    return h


def _port(portid, service="", product="", version="", state="open"):
    return Port(portid=portid, service=service, product=product,
                version=version, state=state)


def _vuln(ip="10.0.0.1", port=445, script_id="test", title="",
          source="nse", state="", output="", ids=None):
    return Vuln(ip=ip, port=port, protocol="tcp", script_id=script_id,
                title=title, source=source, state=state, output=output,
                ids=ids or [])


# ===========================================================================
# Helper functions
# ===========================================================================

class TestPortOf:
    def test_match(self):
        h = _host(ports=[_port(445), _port(80)])
        v = _vuln(port=445)
        assert _port_of(h, v).portid == 445

    def test_no_match(self):
        h = _host(ports=[_port(80)])
        v = _vuln(port=445)
        assert _port_of(h, v) is None


class TestPv:
    def test_returns_product_version(self):
        h = _host(ports=[_port(445, product="Samba", version="4.15.2")])
        v = _vuln(port=445)
        assert _pv(h, v) == ("Samba", "4.15.2")

    def test_no_port_returns_empty(self):
        h = _host(ports=[])
        v = _vuln(port=445)
        assert _pv(h, v) == ("", "")


class TestPortOpen:
    def test_open(self):
        h = _host(ports=[_port(22), _port(80)])
        assert _port_open(h, 22) is True

    def test_not_open(self):
        h = _host(ports=[_port(22)])
        assert _port_open(h, 80) is False


class TestNseVulnerable:
    def test_vulnerable_state(self):
        v = _vuln(state="VULNERABLE")
        assert _nse_vulnerable(v) is True

    def test_nse_source_vulnerable_output(self):
        v = _vuln(source="nse", state="", output="State: VULNERABLE")
        assert _nse_vulnerable(v) is True

    def test_not_vulnerable(self):
        v = _vuln(state="NOT VULNERABLE")
        assert _nse_vulnerable(v) is False

    def test_unrelated(self):
        v = _vuln(source="version-db", state="", output="some output")
        assert _nse_vulnerable(v) is None


class TestLocal:
    def test_match(self):
        h = _host(local_findings=[{"vector": "SeImpersonatePrivilege Enabled"}])
        assert _local(h, r"seimpersonate") is not None

    def test_no_match(self):
        h = _host(local_findings=[{"vector": "nothing relevant"}])
        assert _local(h, r"seimpersonate") is None

    def test_empty(self):
        h = _host(local_findings=[])
        assert _local(h, r"anything") is None


class TestOsBlob:
    def test_combines_name_and_family(self):
        h = _host(os_name="Windows 10", os_family="Windows")
        assert "windows 10" in _os_blob(h)
        assert "windows" in _os_blob(h)


class TestIsDc:
    def test_by_role(self):
        h = _host(roles=["Domain Controller"])
        assert _is_dc(h) is True

    def test_by_ports(self):
        h = _host(ports=[_port(88), _port(389)])
        assert _is_dc(h) is True

    def test_not_dc(self):
        h = _host(ports=[_port(80), _port(443)])
        assert _is_dc(h) is False


# ===========================================================================
# Verdict functions
# ===========================================================================

class TestSmbSigning:
    def test_not_required_is_confirmed(self):
        h = _host(smb_signing="not required")
        verdict, ev = _v_smb_signing(h, None, _vuln())
        assert verdict == CONFIRMED

    def test_required_is_fp(self):
        h = _host(smb_signing="required")
        verdict, ev = _v_smb_signing(h, None, _vuln())
        assert verdict == FALSE_POSITIVE

    def test_unknown_is_inconclusive(self):
        h = _host(smb_signing="")
        verdict, ev = _v_smb_signing(h, None, _vuln())
        assert verdict == INCONCLUSIVE


class TestMs17:
    def test_nse_vulnerable(self):
        v = _vuln(state="VULNERABLE", source="nse")
        verdict, _ = _v_ms17(_host(), None, v)
        assert verdict == CONFIRMED

    def test_nse_not_vulnerable(self):
        v = _vuln(state="NOT VULNERABLE")
        verdict, _ = _v_ms17(_host(), None, v)
        assert verdict == FALSE_POSITIVE

    def test_version_inference_is_likely(self):
        v = _vuln(source="version-db", state="")
        verdict, _ = _v_ms17(_host(), None, v)
        assert verdict == LIKELY


class TestActivemq:
    def test_no_version_is_inconclusive(self):
        h = _host(ports=[_port(8161, product="", version="")])
        v = _vuln(port=8161, title="ActiveMQ CVE-2023-46604")
        verdict, _ = _v_activemq(h, _port_of(h, v), v)
        assert verdict == INCONCLUSIVE

    def test_patched_is_fp(self):
        h = _host(ports=[_port(8161, product="ActiveMQ", version="5.15.16")])
        v = _vuln(port=8161, title="ActiveMQ CVE-2023-46604")
        verdict, _ = _v_activemq(h, _port_of(h, v), v)
        assert verdict == FALSE_POSITIVE

    def test_vulnerable_with_openwire_is_likely(self):
        h = _host(ports=[_port(8161, product="ActiveMQ", version="5.15.10"),
                         _port(61616)])
        v = _vuln(port=8161, title="ActiveMQ CVE-2023-46604")
        verdict, ev = _v_activemq(h, _port_of(h, v), v)
        assert verdict == LIKELY
        assert any("OPEN" in e for e in ev)

    def test_vulnerable_without_openwire_still_likely(self):
        h = _host(ports=[_port(8161, product="ActiveMQ", version="5.15.10")])
        v = _vuln(port=8161, title="ActiveMQ CVE-2023-46604")
        verdict, _ = _v_activemq(h, _port_of(h, v), v)
        assert verdict == LIKELY


class TestPotato:
    def test_enabled_is_confirmed(self):
        h = _host(local_findings=[{"vector": "SeImpersonatePrivilege Enabled"}])
        v = _vuln(title="SeImpersonate potato")
        verdict, _ = _v_potato(h, None, v)
        assert verdict == CONFIRMED

    def test_disabled_is_likely(self):
        h = _host(local_findings=[{"vector": "SeImpersonatePrivilege Disabled"}])
        v = _vuln(title="SeImpersonate potato")
        verdict, _ = _v_potato(h, None, v)
        assert verdict == LIKELY

    def test_no_local_is_inconclusive(self):
        h = _host(local_findings=[])
        v = _vuln(title="SeImpersonate potato")
        verdict, _ = _v_potato(h, None, v)
        assert verdict == INCONCLUSIVE


class TestLog4shell:
    def test_always_likely(self):
        v = _vuln(title="Log4Shell CVE-2021-44228")
        verdict, _ = _v_log4shell(_host(), None, v)
        assert verdict == LIKELY


class TestZerologon:
    def test_dc_is_likely(self):
        h = _host(roles=["Domain Controller"],
                  ports=[_port(88), _port(389), _port(445)])
        v = _vuln(title="ZeroLogon CVE-2020-1472")
        verdict, _ = _v_zerologon(h, None, v)
        assert verdict == LIKELY

    def test_non_dc_is_fp(self):
        h = _host(ports=[_port(80)])
        v = _vuln(title="ZeroLogon CVE-2020-1472")
        verdict, _ = _v_zerologon(h, None, v)
        assert verdict == FALSE_POSITIVE


class TestKerberoast:
    def test_always_confirmed(self):
        v = _vuln(title="Kerberoastable SPN")
        verdict, _ = _v_kerberoast(_host(), None, v)
        assert verdict == CONFIRMED


class TestVersionCve:
    def test_with_version_is_likely(self):
        h = _host(ports=[_port(22, product="OpenSSH", version="7.6p1")])
        v = _vuln(port=22, title="CVE-2023-XXXXX")
        verdict, _ = _v_version_cve(h, _port_of(h, v), v)
        assert verdict == LIKELY

    def test_no_version_is_inconclusive(self):
        h = _host(ports=[_port(22, product="", version="")])
        v = _vuln(port=22, title="CVE-2023-XXXXX")
        verdict, _ = _v_version_cve(h, _port_of(h, v), v)
        assert verdict == INCONCLUSIVE


class TestEol:
    def test_with_version_is_confirmed(self):
        h = _host(ports=[_port(3306, product="MySQL", version="5.5.62")])
        v = _vuln(port=3306, title="End of Life MySQL")
        verdict, _ = _v_eol(h, _port_of(h, v), v)
        assert verdict == CONFIRMED

    def test_no_version_is_likely(self):
        h = _host(ports=[_port(3306, product="MySQL", version="")])
        v = _vuln(port=3306, title="End of Life MySQL")
        verdict, _ = _v_eol(h, _port_of(h, v), v)
        assert verdict == LIKELY


# ===========================================================================
# Public API
# ===========================================================================

class TestRecipeFor:
    def test_finds_smb_signing(self):
        v = _vuln(title="SMB signing not required", script_id="smb2-security-mode")
        r = recipe_for(v)
        assert r is not None
        assert r["id"] == "smb-signing-relay"

    def test_finds_eternalblue(self):
        v = _vuln(title="EternalBlue MS17-010", ids=["CVE-2017-0143"])
        r = recipe_for(v)
        assert r is not None
        assert r["id"] == "ms17-010"

    def test_no_match(self):
        v = _vuln(title="Something completely unrelated to any recipe")
        assert recipe_for(v) is None


class TestVerifyHost:
    def test_produces_verdicts(self):
        h = _host(
            smb_signing="not required",
            ports=[_port(445, service="microsoft-ds")],
            vulns=[_vuln(title="SMB signing not required",
                         script_id="smb2-security-mode")]
        )
        results = verify_host(h)
        assert len(results) >= 1
        assert results[0]["verdict"] == CONFIRMED
        assert results[0]["ip"] == "10.0.0.1"
        assert "key" in results[0]

    def test_deduplicates(self):
        v1 = _vuln(title="SMB signing not required", script_id="smb2-security-mode", port=445)
        v2 = _vuln(title="SMB message signing not required", script_id="smb-mode", port=445)
        h = _host(smb_signing="not required",
                  ports=[_port(445)],
                  vulns=[v1, v2])
        results = verify_host(h)
        ids = [r["vuln"] for r in results]
        assert ids.count("SMB signing not required (NTLM relay)") == 1

    def test_order_confirmed_first(self):
        h = _host(
            smb_signing="not required",
            ports=[_port(445), _port(8161, product="ActiveMQ", version="5.15.10")],
            vulns=[
                _vuln(title="ActiveMQ CVE-2023-46604", port=8161),
                _vuln(title="SMB signing not required", script_id="smb2-security-mode",
                      port=445),
            ]
        )
        results = verify_host(h)
        assert results[0]["verdict"] == CONFIRMED

    def test_empty_host(self):
        h = _host(vulns=[])
        assert verify_host(h) == []


class TestVerifyHosts:
    def test_aggregates(self):
        h1 = _host(ip="10.0.0.1", smb_signing="not required",
                    ports=[_port(445)],
                    vulns=[_vuln(ip="10.0.0.1", title="SMB signing not required",
                                script_id="smb2-security-mode")])
        h2 = _host(ip="10.0.0.2", smb_signing="required",
                    ports=[_port(445)],
                    vulns=[_vuln(ip="10.0.0.2", title="SMB signing not required",
                                script_id="smb2-security-mode")])
        results = verify_hosts([h1, h2])
        assert len(results) == 2
        verdicts = {r["ip"]: r["verdict"] for r in results}
        assert verdicts["10.0.0.1"] == CONFIRMED
        assert verdicts["10.0.0.2"] == FALSE_POSITIVE


class TestSummary:
    def test_counts(self):
        results = [
            {"verdict": CONFIRMED},
            {"verdict": CONFIRMED},
            {"verdict": LIKELY},
            {"verdict": FALSE_POSITIVE},
        ]
        s = summary(results)
        assert s[CONFIRMED] == 2
        assert s[LIKELY] == 1
        assert s[FALSE_POSITIVE] == 1
        assert s[INCONCLUSIVE] == 0


# ===========================================================================
# Version-db safety cap
# ===========================================================================

class TestVersionDbSafetyCap:
    def test_version_db_with_live_access_language_capped_to_likely(self):
        """When source='version-db' and evidence uses live-access language,
        CONFIRMED should be capped to LIKELY."""
        h = _host(ports=[_port(6379, product="Redis", version="5.0.2")])
        v = _vuln(
            port=6379,
            title="Redis unauthenticated access",
            script_id="redis-info",
            source="version-db",
        )
        results = verify_host(h)
        redis_results = [r for r in results if "redis" in r["vuln"].lower()
                         or "redis" in r["finding"].lower()]
        for r in redis_results:
            if any("with no credential" in e or "no authentication and the server returned" in e
                   for e in r["evidence"]):
                assert r["verdict"] != CONFIRMED, \
                    "version-db source with live-access language must be capped to LIKELY"

    def test_nse_source_not_capped(self):
        """When source='nse' (a real probe), CONFIRMED should stay CONFIRMED."""
        h = _host(smb_signing="not required",
                  ports=[_port(445)],
                  vulns=[_vuln(title="SMB signing not required",
                               script_id="smb2-security-mode",
                               source="nse")])
        results = verify_host(h)
        assert results[0]["verdict"] == CONFIRMED
