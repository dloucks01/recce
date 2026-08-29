"""Tests for recce.services.slp — the SLPv2 427/udp+tcp probe.

Fixtures are RFC 2608-derived hex wire bytes hand-assembled per §8 header
and §10 message layouts, NOT calls to slp._build_* — the parser must survive
against wire the code did not encode itself.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest
from unittest import mock

from recce.core.models import Host, Port
from recce.services import slp


# --- hand-assembled wire fixtures (RFC 2608) --------------------------------

def _hdr(fid: int, body: bytes, xid: int = 0x1234, flags: int = 0,
         lang: bytes = b"en") -> bytes:
    """SLPv2 header per RFC 2608 §8, built without calling into slp._slp_header."""
    total = 14 + len(lang) + len(body)
    return (bytes([2, fid, (total >> 16) & 0xff])
            + struct.pack("!H", total & 0xffff)
            + struct.pack("!H", flags)
            + bytes([0]) + struct.pack("!H", 0)   # next-ext-offset (3 bytes)
            + struct.pack("!H", xid)
            + struct.pack("!H", len(lang)) + lang
            + body)


def _lstr(s: str | bytes) -> bytes:
    b = s.encode("utf-8") if isinstance(s, str) else s
    return struct.pack("!H", len(b)) + b


def _url_entry(url: str, lifetime: int = 3600, auth_blocks: int = 0) -> bytes:
    b = url.encode("utf-8")
    return (bytes([0])
            + struct.pack("!H", lifetime)
            + struct.pack("!H", len(b))
            + b
            + bytes([auth_blocks]))


def _srvtyperply_wire(types: list[str], error: int = 0) -> bytes:
    types_str = ",".join(types).encode("utf-8")
    body = struct.pack("!H", error) + struct.pack("!H", len(types_str)) + types_str
    return _hdr(slp._FID_SRVTYPERPLY, body)


def _srvrply_wire(urls: list[str], error: int = 0) -> bytes:
    body = struct.pack("!H", error) + struct.pack("!H", len(urls))
    for u in urls:
        body += _url_entry(u)
    return _hdr(slp._FID_SRVRPLY, body)


def _attrrply_wire(attrs_raw: str, error: int = 0, auth_blocks: int = 0) -> bytes:
    body = (struct.pack("!H", error)
            + _lstr(attrs_raw)
            + bytes([auth_blocks]))
    return _hdr(slp._FID_ATTRRPLY, body)


def _daadvert_wire(url: str, scope: str, attrs: str = "", boot: int = 100,
                   error: int = 0) -> bytes:
    body = (struct.pack("!H", error) + struct.pack("!I", boot)
            + _lstr(url) + _lstr(scope) + _lstr(attrs)
            + _lstr("")           # SPI list
            + bytes([0]))         # auth blocks
    return _hdr(slp._FID_DAADVERT, body)


# --- header build+parse ----------------------------------------------------

class HeaderTest(unittest.TestCase):
    def test_header_version_and_fid_and_length(self):
        pkt = slp._slp_header(slp._FID_SRVTYPERQST, body_len=0, xid=0xbeef)
        self.assertEqual(pkt[0], 2)
        self.assertEqual(pkt[1], slp._FID_SRVTYPERQST)
        length = (pkt[2] << 16) | struct.unpack_from("!H", pkt, 3)[0]
        self.assertEqual(length, len(pkt))
        # XID at offset 10
        self.assertEqual(struct.unpack_from("!H", pkt, 10)[0], 0xbeef)

    def test_parse_header_rejects_wrong_version(self):
        junk = bytes([1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        self.assertIsNone(slp._parse_header(junk))

    def test_parse_header_recovers_xid_and_lang(self):
        pkt = _hdr(slp._FID_SRVRPLY, b"\x00\x00\x00\x00", xid=0x4242,
                   lang=b"fr")
        h = slp._parse_header(pkt)
        self.assertIsNotNone(h)
        self.assertEqual(h["fid"], slp._FID_SRVRPLY)
        self.assertEqual(h["xid"], 0x4242)
        self.assertEqual(h["lang"], "fr")


# --- request wire encodings match RFC 2608 layout --------------------------

class BuildRequestsTest(unittest.TestCase):
    def test_srvtyperqst_uses_ffff_for_all_naming_authorities(self):
        pkt = slp._build_srvtyperqst(xid=1, scope="DEFAULT",
                                     naming_authority=None)
        # After the 14-byte header + 2-byte lang "en" = 16 bytes, body starts
        # with 2-byte PRList length (0), then 0xFFFF (naming authority = all).
        body = pkt[16:]
        self.assertEqual(body[:2], b"\x00\x00")     # empty PRList
        self.assertEqual(body[2:4], b"\xff\xff")    # "all" marker
        # Then scope length + scope
        self.assertEqual(body[4:6], struct.pack("!H", len("DEFAULT")))
        self.assertEqual(body[6:6 + len("DEFAULT")], b"DEFAULT")

    def test_srvrqst_multicast_sets_r_flag(self):
        pkt = slp._build_srvrqst(xid=2, service_type="service:printer",
                                 multicast=True)
        flags = struct.unpack_from("!H", pkt, 5)[0]
        self.assertTrue(flags & slp._FLAG_MCAST)

    def test_attrrqst_encodes_url_in_body(self):
        url = "service:VMwareInfrastructure:https://10.0.0.5"
        pkt = slp._build_attrrqst(xid=3, url=url)
        body = pkt[16:]
        # PRList (0-len) then URL length + URL
        self.assertEqual(body[:2], b"\x00\x00")
        self.assertEqual(body[2:4], struct.pack("!H", len(url)))
        self.assertEqual(body[4:4 + len(url)].decode(), url)


# --- reply parsing ---------------------------------------------------------

class ParseRepliesTest(unittest.TestCase):
    def test_srvtyperply_parses_types_list(self):
        wire = _srvtyperply_wire(["service:vmware-infrastructure",
                                  "service:printer",
                                  "service:directory-agent"])
        parsed = slp._parse_srvtyperply(wire)
        self.assertEqual(parsed["error"], 0)
        self.assertEqual(parsed["types"],
                         ["service:vmware-infrastructure",
                          "service:printer",
                          "service:directory-agent"])

    def test_srvtyperply_error_short_circuits(self):
        wire = _srvtyperply_wire([], error=1)
        parsed = slp._parse_srvtyperply(wire)
        self.assertEqual(parsed["error"], 1)
        self.assertEqual(parsed["types"], [])

    def test_srvrply_extracts_multiple_urls(self):
        wire = _srvrply_wire(["service:cifs://fs01/",
                              "service:cifs://fs02/",
                              "service:nfs://fs03/export"])
        parsed = slp._parse_srvrply(wire)
        self.assertEqual(parsed["error"], 0)
        self.assertEqual([u["url"] for u in parsed["urls"]],
                         ["service:cifs://fs01/",
                          "service:cifs://fs02/",
                          "service:nfs://fs03/export"])

    def test_url_entry_with_auth_blocks_advances_past_them(self):
        # One URL entry with one auth block of length 12 (BSD 2 + BlockLen 2 +
        # 8 bytes payload) — the parser must skip it and stop cleanly.
        url = "service:cifs://fs01/"
        b = url.encode()
        body = (struct.pack("!H", 0)                       # error
                + struct.pack("!H", 1)                     # count
                + bytes([0])                               # reserved
                + struct.pack("!H", 3600)                  # lifetime
                + struct.pack("!H", len(b)) + b            # url
                + bytes([1])                               # 1 auth block
                + struct.pack("!H", 2)                     # BSD
                + struct.pack("!H", 12)                    # block len (total)
                + b"\x00" * 8)                             # payload
        wire = _hdr(slp._FID_SRVRPLY, body)
        parsed = slp._parse_srvrply(wire)
        self.assertEqual(len(parsed["urls"]), 1)
        self.assertEqual(parsed["urls"][0]["url"], url)
        self.assertEqual(parsed["urls"][0]["auth_blocks"], 1)

    def test_attrrply_parses_paren_tuples(self):
        raw = ("(product=VMware ESXi),(version=7.0.0),"
               "(build-20328353),(uuid=abc-123)")
        wire = _attrrply_wire(raw)
        parsed = slp._parse_attrrply(wire)
        self.assertEqual(parsed["error"], 0)
        self.assertEqual(parsed["attrs_raw"], raw)
        self.assertEqual(parsed["attrs"]["product"], "VMware ESXi")
        self.assertEqual(parsed["attrs"]["version"], "7.0.0")

    def test_daadvert_parses_url_and_scope(self):
        wire = _daadvert_wire("service:directory-agent://10.0.0.1",
                              scope="PROD,STAGING", attrs="(pri=1)")
        parsed = slp._parse_daadvert(wire)
        self.assertEqual(parsed["error"], 0)
        self.assertEqual(parsed["url"], "service:directory-agent://10.0.0.1")
        self.assertEqual(parsed["scope"], "PROD,STAGING")
        self.assertEqual(parsed["attrs_raw"], "(pri=1)")


# --- attr-list parsing ------------------------------------------------------

class AttrListTest(unittest.TestCase):
    def test_paren_tuple_with_and_without_value(self):
        # "(build-20328353)" is a keyword — the parser drops it (no =); the
        # keyed tuples come through.
        d = slp._parse_attr_list("(product=VMware ESXi),(build-20328353),"
                                 "(managementserver=vcenter.corp.local)")
        self.assertEqual(d.get("product"), "VMware ESXi")
        self.assertEqual(d.get("managementserver"), "vcenter.corp.local")

    def test_multivalue_first_taken(self):
        d = slp._parse_attr_list("(scope=prod,staging,dev)")
        # value is the raw between = and ), split downstream by consumer.
        self.assertEqual(d["scope"], "prod,staging,dev")


# --- ESXi build gating -----------------------------------------------------

class EsxiGateTest(unittest.TestCase):
    def test_esxi_7_pre_fix_flagged(self):
        r = slp._esxi_vulnerable("VMware ESXi", "7.0.0 build-15843807")
        self.assertIsNotNone(r)
        vulnerable, series, build, fix = r
        self.assertTrue(vulnerable)
        self.assertEqual(series, "7.0")
        self.assertEqual(build, 15843807)
        self.assertEqual(fix, slp._ESXI_FIX_BUILDS["7.0"])

    def test_esxi_7_at_fix_line_not_flagged(self):
        r = slp._esxi_vulnerable(
            "VMware ESXi", f"7.0.1 build-{slp._ESXI_FIX_BUILDS['7.0']}")
        self.assertIsNotNone(r)
        vulnerable, *_ = r
        self.assertFalse(vulnerable)

    def test_esxi_65_pre_fix_flagged(self):
        r = slp._esxi_vulnerable("VMware ESXi", "6.5.0 build-17097218")
        self.assertIsNotNone(r)
        vulnerable, series, *_ = r
        self.assertTrue(vulnerable)
        self.assertEqual(series, "6.5")

    def test_missing_build_returns_none(self):
        # No parseable build → we must NOT emit a CVE
        self.assertIsNone(slp._esxi_vulnerable("VMware ESXi", "7.0.0"))

    def test_non_esxi_returns_none(self):
        self.assertIsNone(slp._esxi_vulnerable("CUPS", "2.4.7"))

    def test_unknown_series_returns_none(self):
        # ESXi 8.0 is not in the fix table -> no CVE
        self.assertIsNone(
            slp._esxi_vulnerable("VMware ESXi", "8.0.0 build-20000000"))


# --- UDP loopback probe end-to-end -----------------------------------------

class _UDPResponder:
    """One UDP socket that replies to a sequence of requests with a canned
    per-function-id response map. Any request whose function-id has no
    canned reply is answered with an empty packet (equivalent to silence
    at this level — the parser will reject it)."""
    def __init__(self, replies: dict[int, bytes]):
        self._replies = replies
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.host, self.port = self._sock.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                data, addr = self._sock.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            if len(data) < 2 or data[0] != 2:
                continue
            fid = data[1]
            resp = self._replies.get(fid)
            if resp is None:
                continue
            try:
                self._sock.sendto(resp, addr)
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


class ProbeTest(unittest.TestCase):
    def test_probe_walks_srvtypes_then_urls_then_attrs(self):
        srvtypes = _srvtyperply_wire(["service:VMwareInfrastructure"])
        srvrply = _srvrply_wire(
            ["service:VMwareInfrastructure:https://10.0.0.5"])
        attrrply = _attrrply_wire(
            "(product=VMware ESXi),(version=7.0.0),(build-15843807),"
            "(managementserver=vcenter.corp.local)")
        srv = _UDPResponder({
            slp._FID_SRVTYPERQST: srvtypes,
            slp._FID_SRVRQST: srvrply,
            slp._FID_ATTRRQST: attrrply,
        })
        try:
            pr = slp.probe(srv.host, srv.port, timeout=2)
        finally:
            srv.close()
        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["version"], "2")
        self.assertIn("service:VMwareInfrastructure", pr["types"])
        self.assertTrue(pr["urls"])
        self.assertEqual(
            pr["urls"][0]["url"],
            "service:VMwareInfrastructure:https://10.0.0.5")
        self.assertTrue(pr["esxi"])
        self.assertTrue(pr["esxi"]["vulnerable"])
        self.assertEqual(pr["esxi"]["series"], "7.0")

    def test_probe_dead_port_returns_unreachable(self):
        # Bind a socket to grab a free port, then close so nothing is listening.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        _, dead_port = s.getsockname()
        s.close()
        pr = slp.probe("127.0.0.1", dead_port, timeout=1)
        self.assertFalse(pr["reachable"])
        self.assertEqual(pr["types"], [])
        self.assertEqual(pr["urls"], [])


# --- findings emit the right kinds ------------------------------------------

def _fake_probe_result(**overrides) -> dict:
    base = {
        "reachable": True, "version": "2",
        "types": ["service:VMwareInfrastructure", "service:cifs"],
        "urls": [{"url": "service:VMwareInfrastructure:https://10.0.0.5",
                  "service_type": "service:VMwareInfrastructure",
                  "lifetime": 3600, "auth_blocks": 0}],
        "attrs": {"service:VMwareInfrastructure:https://10.0.0.5":
                  {"product": "VMware ESXi", "version": "7.0.0",
                   "managementserver": "vcenter.corp.local"}},
        "attrs_raw": {}, "openslp": False,
        "auth_blocks_seen": False, "esxi": None, "used_tcp": False,
        "scopes": [],
    }
    base.update(overrides)
    return base


def _mkhost(protocol: str = "udp") -> Host:
    h = Host(ip="10.0.0.5")
    h.ports.append(Port(portid=427, protocol=protocol, state="open",
                        service="slp"))
    return h


class FindingsTest(unittest.TestCase):
    def test_esxi_vulnerable_emits_critical_cve(self):
        h = _mkhost("tcp")
        pr = _fake_probe_result(esxi={
            "product": "VMware ESXi", "version": "7.0.0 build-15843807",
            "series": "7.0", "build": 15843807,
            "fix_build": slp._ESXI_FIX_BUILDS["7.0"], "vulnerable": True})
        fs = slp.findings([h], {(h.ip, 427): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("slp_esxi_openslp_rce", kinds)
        crit = [f for f in fs if f["kind"] == "slp_esxi_openslp_rce"][0]
        self.assertEqual(crit["severity"], "critical")
        self.assertIn("CVE-2021-21974", crit["cves"])
        self.assertIn("CVE-2019-5544", crit["cves"])
        self.assertIn("CVE-2020-3992", crit["cves"])

    def test_patched_esxi_no_cve_flag(self):
        h = _mkhost("tcp")
        pr = _fake_probe_result(esxi={
            "product": "VMware ESXi", "version": "7.0.3",
            "series": "7.0", "build": 22000000,
            "fix_build": slp._ESXI_FIX_BUILDS["7.0"], "vulnerable": False})
        fs = slp.findings([h], {(h.ip, 427): pr})
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("slp_esxi_openslp_rce", kinds)
        self.assertIn("slp_esxi_patched", kinds)

    def test_esxi_url_no_build_emits_cwe_only(self):
        h = _mkhost("tcp")
        pr = _fake_probe_result(esxi=None)  # product visible but no build parse
        fs = slp.findings([h], {(h.ip, 427): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("slp_esxi_unknown_build", kinds)
        cwe_only = [f for f in fs if f["kind"] == "slp_esxi_unknown_build"][0]
        # CWE only — never assert an unverified CVE
        self.assertNotIn("cves", cwe_only)
        self.assertIn("CWE-787", cwe_only["cwes"])

    def test_udp_responder_flagged_as_amplifier(self):
        h = _mkhost("udp")
        fs = slp.findings([h], {(h.ip, 427): _fake_probe_result()})
        kinds = {f["kind"] for f in fs}
        self.assertIn("slp_amplifier", kinds)
        amp = [f for f in fs if f["kind"] == "slp_amplifier"][0]
        self.assertEqual(amp["severity"], "high")
        self.assertIn("CVE-2023-29552", amp["cves"])

    def test_tcp_responder_not_flagged_as_amplifier(self):
        h = _mkhost("tcp")
        fs = slp.findings([h], {(h.ip, 427): _fake_probe_result()})
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("slp_amplifier", kinds)

    def test_service_catalogue_and_url_findings(self):
        h = _mkhost("udp")
        fs = slp.findings([h], {(h.ip, 427): _fake_probe_result()})
        kinds = {f["kind"] for f in fs}
        self.assertIn("slp_service_catalogue", kinds)
        self.assertIn("slp_url_disclosure", kinds)
        self.assertIn("slp_attribute_disclosure", kinds)

    def test_directory_agent_finding(self):
        h = _mkhost("tcp")
        pr = _fake_probe_result(urls=[{
            "url": "service:directory-agent://10.0.0.1",
            "service_type": "service:directory-agent",
            "lifetime": 3600, "auth_blocks": 0}])
        fs = slp.findings([h], {(h.ip, 427): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("slp_directory_agent", kinds)

    def test_openslp_fingerprint_finding(self):
        h = _mkhost("tcp")
        fs = slp.findings([h], {(h.ip, 427): _fake_probe_result(openslp=True)})
        kinds = {f["kind"] for f in fs}
        self.assertIn("slp_openslp_fingerprint", kinds)

    def test_auth_blocks_present_and_absent(self):
        h = _mkhost("tcp")
        fs = slp.findings([h], {(h.ip, 427):
                                _fake_probe_result(auth_blocks_seen=True)})
        kinds = {f["kind"] for f in fs}
        self.assertIn("slp_auth_present", kinds)
        self.assertNotIn("slp_no_auth", kinds)

        fs2 = slp.findings([h], {(h.ip, 427):
                                 _fake_probe_result(auth_blocks_seen=False)})
        kinds2 = {f["kind"] for f in fs2}
        self.assertIn("slp_no_auth", kinds2)
        self.assertNotIn("slp_auth_present", kinds2)

    def test_scope_disclosure_emitted(self):
        h = _mkhost("tcp")
        pr = _fake_probe_result(scopes=["PROD-VMOTION", "BLDG12-PRINT"])
        fs = slp.findings([h], {(h.ip, 427): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("slp_scope_disclosure", kinds)

    def test_unreachable_probe_yields_nothing(self):
        h = _mkhost("udp")
        fs = slp.findings([h], {(h.ip, 427): {"reachable": False}})
        self.assertEqual(fs, [])


# --- targets / is_slp ------------------------------------------------------

class TargetsTest(unittest.TestCase):
    def test_is_slp_by_port(self):
        self.assertTrue(slp.is_slp(Port(portid=427, service="")))
        self.assertFalse(slp.is_slp(Port(portid=80, service="http")))

    def test_is_slp_by_service_name(self):
        self.assertTrue(slp.is_slp(Port(portid=1234, service="slp")))
        self.assertTrue(slp.is_slp(Port(portid=1234, service="svrloc")))

    def test_slp_targets_lists_open_ports(self):
        h = Host(ip="1.2.3.4")
        h.ports.append(Port(portid=427, protocol="udp", state="open",
                            service="slp"))
        h.ports.append(Port(portid=80, protocol="tcp", state="open",
                            service="http"))
        ts = slp.slp_targets([h])
        self.assertEqual(len(ts), 1)
        self.assertEqual(ts[0]["ip"], "1.2.3.4")
        self.assertEqual(ts[0]["port"], 427)


# --- runbook / findings_to_vulns / analyze plumbing ------------------------

class PlumbingTest(unittest.TestCase):
    def test_runbook_has_slptool_and_nmap_steps(self):
        rb = slp.runbook("10.0.0.5")
        tools = {r["tool"] for r in rb}
        self.assertIn("slptool", tools)
        self.assertIn("nmap", tools)

    def test_findings_to_vulns_produces_vuln_objects(self):
        h = _mkhost("udp")
        fs = slp.findings([h], {(h.ip, 427): _fake_probe_result()})
        by_ip = slp.findings_to_vulns(fs)
        self.assertIn("10.0.0.5", by_ip)
        self.assertTrue(by_ip["10.0.0.5"])
        v = by_ip["10.0.0.5"][0]
        self.assertEqual(v.source, "slp")

    def test_analyze_active_false_skips_probe(self):
        h = _mkhost("udp")
        with mock.patch.object(slp, "probe",
                               side_effect=AssertionError("should not run")):
            out = slp.analyze([h], active=False)
        self.assertEqual(out["stats"]["targets"], 1)
        self.assertEqual(out["findings"], [])

    def test_analyze_active_true_calls_probe(self):
        h = _mkhost("udp")
        with mock.patch.object(slp, "probe",
                               return_value=_fake_probe_result()) as m:
            out = slp.analyze([h], active=True)
        self.assertEqual(m.call_count, 1)
        self.assertTrue(out["findings"])
        self.assertIn("stats", out)


if __name__ == "__main__":
    unittest.main()
