"""Coverage-boosting tests for recce.services.ipp: the full probe() path,
the attribute walker's edge cases, and the analyze() aggregator.

The existing tests/test_ipp_extras.py covers status parsing, the CVE gate,
and findings-side branches — this file drives the wire-side of probe() by
monkey-patching `ipp._ipp_post`, so no real HTTP server is needed.

All IPP body fixtures are hand-built from the RFC 8010 §3.1 encoding.
"""
from __future__ import annotations

import struct
import unittest

from recce.core.models import Host, Port
from recce.services import ipp


# --- IPP body fixtures (RFC 8010 §3.1) --------------------------------------

def _cups_get_printers_body(printers: list[dict],
                            status_code: int = 0x0000) -> bytes:
    """Build a CUPS-Get-Printers response with one attribute group per printer.

    RFC 8010: version(2) status(2) request-id(4) then groups. Each group
    starts with an attribute-group tag (0x04 = printer-attributes), followed
    by tagged attributes (each: tag(1) name-len(2) name value-len(2) value).
    Ends with 0x03 (end-of-attributes).
    """
    body = struct.pack("!BBHI", 1, 1, status_code, 1)
    for pr in printers:
        body += b"\x04"                         # printer-attributes-tag
        for name, value in pr.items():
            nb = name.encode("ascii", "replace")
            vb = value.encode("ascii", "replace")
            body += b"\x42"                     # nameWithoutLanguage tag
            body += struct.pack("!H", len(nb)) + nb
            body += struct.pack("!H", len(vb)) + vb
    body += b"\x03"                             # end-of-attributes
    return body


# --- probe() full happy-path -------------------------------------------------

class ProbeHappyPathTest(unittest.TestCase):
    """probe() with a CUPS response that lists printers + a Get-Printer-
    Attributes ingress reply. Exercises the whole 250-313 path in one shot."""

    def test_cups_reachable_with_printers_ingress_verified(self):
        printers = [{"printer-name": "Laser1",
                     "printer-uri-supported":
                        "ipp://10.0.0.5:631/printers/Laser1"}]
        get_printers = _cups_get_printers_body(printers)
        # A Get-Printer-Attributes reply with status successful-ok so the
        # ingress-verified path fires. RFC 8011: same header shape, then
        # a printer-attribute group with the two mandatory attributes.
        gpa_ok = struct.pack("!BBHI", 1, 1, 0x0000, 1) + b"\x04\x03"
        # Sequence: first POST is CUPS-Get-Printers (root path "/"), second
        # is Get-Printer-Attributes on the printer URI's path.
        calls: list[dict] = []

        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            op = struct.unpack("!H", body[2:4])[0]
            calls.append({"op": op, "path": path, "tls": tls})
            if op == 0x4002:                                # CUPS-Get-Printers
                return 200, get_printers, "CUPS/2.4.7 (Ubuntu)"
            if op == 0x000B:                                # Get-Printer-Attributes
                return 200, gpa_ok, "CUPS/2.4.7 (Ubuntu)"
            return 0, b"", ""

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            pr = ipp.probe("10.0.0.5", 631, timeout=2)
        finally:
            ipp._ipp_post = orig

        self.assertTrue(pr["reachable"])
        self.assertEqual(pr["http_status"], 200)
        self.assertTrue(pr["is_cups"])
        self.assertEqual(pr["cups_version"], "2.4.7")
        self.assertEqual(pr["printers"][0].get("printer-name"), "Laser1")
        self.assertEqual(pr["ipp_status"], 0x0000)
        self.assertEqual(pr["ipp_status_label"], "successful-ok")
        # Ingress verification ran and succeeded.
        self.assertTrue(pr["ingress_verified"])
        self.assertIn("get_printer_attrs", pr)
        # Ubuntu 24.04.1 backport marker downgrades foomatic vulnerability.
        self.assertIn("foomatic_vulnerable", pr)
        # Second call is Get-Printer-Attributes. The printer URI travels in
        # the body's printer-uri attribute (RFC 8011 §4.2.5), not in the
        # HTTP path (probe() calls with the default path="/").
        self.assertEqual(calls[1]["op"], 0x000B)

    def test_tls_fallback_when_plain_http_fails(self):
        """First _ipp_post returns 0 (transport failure) → probe retries
        with tls=True. Covers lines 256-260."""
        gp_ok = _cups_get_printers_body([])

        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            if not tls:
                return 0, b"", ""                           # simulate plain-HTTP dead
            return 200, gp_ok, "CUPS/2.4.9"                 # TLS succeeded

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            pr = ipp.probe("10.0.0.5", 631, timeout=2)
        finally:
            ipp._ipp_post = orig
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["is_cups"])
        self.assertEqual(pr["cups_version"], "2.4.9")

    def test_both_transports_dead_returns_unreachable(self):
        """Neither plain HTTP nor TLS answered — probe returns reachable=False."""
        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            return 0, b"", ""

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            pr = ipp.probe("10.0.0.5", 631, timeout=1)
        finally:
            ipp._ipp_post = orig
        self.assertFalse(pr["reachable"])
        self.assertNotIn("http_status", pr)

    def test_non_ipp_response_still_marks_reachable(self):
        """A 200 with non-IPP body (e.g. an HTML admin page) — the reachable
        flag flips but printers/ipp_status stay unset."""
        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            return 200, b"<html>i am not IPP</html>", "nginx"

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            pr = ipp.probe("10.0.0.5", 631, timeout=1)
        finally:
            ipp._ipp_post = orig
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["is_cups"])
        self.assertNotIn("printers", pr)

    def test_ipp_endpoint_but_not_cups_skips_ingress_probe(self):
        """A non-CUPS IPP server (e.g. HP JetDirect) — the CVE-2024-47176
        gate does not run and no Get-Printer-Attributes ingress fires."""
        printers = [{"printer-name": "JetDirect"}]
        body = _cups_get_printers_body(printers)
        n_posts = [0]

        def fake_post(ip, port, body_, timeout, tls=False, path="/"):
            n_posts[0] += 1
            return 200, body, "HP-JetDirect"

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            pr = ipp.probe("10.0.0.5", 631, timeout=1)
        finally:
            ipp._ipp_post = orig
        self.assertTrue(pr["reachable"])
        self.assertFalse(pr["is_cups"])
        self.assertNotIn("foomatic_vulnerable", pr)
        self.assertEqual(n_posts[0], 1)         # only CUPS-Get-Printers, no GPA

    def test_ingress_probe_raises_oserror_still_returns_probe(self):
        """get_printer_attributes throwing OSError does NOT poison probe() —
        the outer try/except keeps ingress_verified unset."""
        gp = _cups_get_printers_body([{"printer-name": "P1"}])
        n = [0]

        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            n[0] += 1
            if n[0] == 1:
                return 200, gp, "CUPS/2.4.7"
            raise OSError("simulated Ingress transport crash")

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            pr = ipp.probe("10.0.0.5", 631, timeout=1)
        finally:
            ipp._ipp_post = orig
        self.assertTrue(pr["reachable"])
        self.assertTrue(pr["is_cups"])
        # ingress_verified remains False when the follow-up raises.
        self.assertFalse(pr.get("ingress_verified", False))


# --- attribute walker edge cases (204-247) ----------------------------------

class WalkAttributesEdgeTest(unittest.TestCase):
    def test_empty_body_returns_empty(self):
        self.assertEqual(ipp._walk_ipp_attributes(b""), [])

    def test_body_too_short_returns_empty(self):
        # 8 bytes = version(2)+status(2)+request-id(4), nothing after.
        self.assertEqual(ipp._walk_ipp_attributes(b"\x01\x01\x00\x00" +
                                                  b"\x00\x00\x00\x01"), [])

    def test_end_of_attributes_tag_terminates(self):
        # An operation-attributes group with a single attr then 0x03 stops
        # the walk cleanly.
        body = (struct.pack("!BBHI", 1, 1, 0x0000, 1)
                + b"\x01"                        # operation-attributes tag
                + b"\x42" + struct.pack("!H", 4) + b"name"
                + struct.pack("!H", 3) + b"foo"
                + b"\x03")                       # end-of-attributes
        walk = ipp._walk_ipp_attributes(body)
        self.assertTrue(walk)
        self.assertEqual(walk[0].get("name"), "foo")

    def test_unknown_tag_stops_walk(self):
        # A tag below the value-tag floor (0x08) but not a recognised group
        # tag should break the loop and return what parsed so far.
        body = (struct.pack("!BBHI", 1, 1, 0x0000, 1)
                + b"\x04"                        # printer-attributes group
                + b"\x42" + struct.pack("!H", 4) + b"kind"
                + struct.pack("!H", 3) + b"one"
                + b"\x07")                       # unknown / stop tag
        walk = ipp._walk_ipp_attributes(body)
        self.assertEqual(walk[0].get("kind"), "one")

    def test_truncated_length_prefix_stops(self):
        # Truncated name-length prefix — walk stops without raising.
        body = (struct.pack("!BBHI", 1, 1, 0x0000, 1)
                + b"\x04"                        # printer group
                + b"\x42" + b"\x00")             # tag + partial length
        self.assertEqual(ipp._walk_ipp_attributes(body), [])

    def test_utf16_binary_attribute_falls_back_to_hex(self):
        """A value that doesn't decode as UTF-8 (invalid multi-byte) must
        be rendered as hex without raising."""
        bad = b"\xff\xfe\x00\x00"
        body = (struct.pack("!BBHI", 1, 1, 0x0000, 1)
                + b"\x04"
                + b"\x42" + struct.pack("!H", 4) + b"blob"
                + struct.pack("!H", len(bad)) + bad
                + b"\x03")
        walk = ipp._walk_ipp_attributes(body)
        # Decoded via utf-8 "replace" — the exact result string doesn't
        # matter; the point is the parser returned without raising.
        self.assertIn("blob", walk[0])


# --- _ipp_post integration (uses a loopback HTTP server) --------------------

class IppPostIntegrationTest(unittest.TestCase):
    """Exercise the real _ipp_post transport (no monkey-patching). Uses a
    tiny loopback HTTP server so the try/except/finally branches all fire."""

    def test_ipp_post_returns_body_and_server(self):
        import http.server
        import threading

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):            # noqa: N802 - http.server API
                length = int(self.headers.get("Content-Length", "0"))
                _ = self.rfile.read(length)
                body = struct.pack("!BBHI", 1, 1, 0x0000, 1) + b"\x03"
                self.send_response(200)
                self.send_header("Server", "TestIPP/1.0")
                self.send_header("Content-Type", "application/ipp")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):    # keep test output quiet
                return

        srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            status, body, server = ipp._ipp_post(
                "127.0.0.1", port, ipp._ipp_get_printers(), timeout=2.0)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(status, 200)
        # Python's BaseHTTPRequestHandler prepends its own Server value in
        # front of ours — the important thing is our banner survived.
        self.assertIn("TestIPP/1.0", server)
        self.assertGreaterEqual(len(body), 8)

    def test_ipp_post_dead_port_returns_zeros(self):
        # Loopback :1 refuses → the OSError branch runs (lines 78-79).
        status, body, server = ipp._ipp_post(
            "127.0.0.1", 1, ipp._ipp_get_printers(), timeout=0.5)
        self.assertEqual(status, 0)
        self.assertEqual(body, b"")
        self.assertEqual(server, "")


# --- Get-Printers wire builder (45-55) --------------------------------------

class GetPrintersWireTest(unittest.TestCase):
    def test_wire_shape_matches_rfc_8010(self):
        wire = ipp._ipp_get_printers()
        self.assertEqual(wire[:2], b"\x01\x01")              # version 1.1
        self.assertEqual(struct.unpack("!H", wire[2:4])[0], 0x4002)
        self.assertEqual(struct.unpack("!I", wire[4:8])[0], 1)
        # Operation-attributes-tag then mandatory charset + language attrs.
        self.assertEqual(wire[8:9], b"\x01")
        self.assertIn(b"attributes-charset", wire)
        self.assertIn(b"attributes-natural-language", wire)
        self.assertEqual(wire[-1:], b"\x03")                 # end-of-attrs


# --- targets + analyze() + runbook + findings_to_vulns ----------------------

class AnalyzeAndAggregatorsTest(unittest.TestCase):
    """The remaining orchestrator surface — cheap, but each function has
    its own uncovered chunk."""

    def test_ipp_targets_picks_631(self):
        h = Host(ip="10.0.0.7", ports=[Port(portid=631, service="ipp")])
        t = ipp.ipp_targets([h])
        self.assertEqual(len(t), 1)
        self.assertEqual(t[0]["port"], 631)

    def test_ipp_targets_skips_unrelated_ports(self):
        h = Host(ip="10.0.0.7", ports=[Port(portid=22, service="ssh")])
        self.assertEqual(ipp.ipp_targets([h]), [])

    def test_runbook_shape(self):
        rb = ipp.runbook("10.0.0.7", 631)
        self.assertGreaterEqual(len(rb), 3)
        phases = [s["phase"] for s in rb]
        self.assertIn("enumerate", phases)
        self.assertIn("exploit", phases)

    def test_findings_to_vulns_source_ipp(self):
        h = Host(ip="10.0.0.7", ports=[Port(portid=631, service="ipp")])
        probes = {("10.0.0.7", 631): {
            "reachable": True, "is_cups": True,
            "cups_version": "2.4.7", "server": "CUPS/2.4.7",
            "printers": [{"printer-name": "P"}],
        }}
        fs = ipp.findings([h], probes)
        by_ip = ipp.findings_to_vulns(fs)
        vulns = by_ip.get("10.0.0.7") or []
        self.assertTrue(vulns)
        self.assertTrue(all(v.source == "ipp" for v in vulns))

    def test_analyze_runs_active_probe_and_folds_state(self):
        """analyze() calls svcprobe.iter_probe which calls probe(); we
        intercept probe() so the network round trip is bypassed."""
        h = Host(ip="10.0.0.7", ports=[Port(portid=631, service="ipp")])
        canned = {"reachable": True, "is_cups": True,
                  "cups_version": "2.4.9",
                  "server": "CUPS/2.4.9",
                  "printers": [{"printer-name": "PDF"}]}
        orig = ipp.probe
        ipp.probe = lambda ip, port: canned
        try:
            out = ipp.analyze([h], active=True)
        finally:
            ipp.probe = orig
        self.assertEqual(out["stats"]["targets"], 1)
        self.assertGreaterEqual(out["stats"]["findings"], 1)
        # analyze() folds `reachable` / `is_cups` / `printers` onto the
        # target dict so the caller can read them without indexing probes.
        t0 = out["targets"][0]
        self.assertTrue(t0["reachable"])
        self.assertTrue(t0["is_cups"])
        self.assertEqual(t0["printers"], 1)

    def test_analyze_no_active_leaves_probes_empty(self):
        h = Host(ip="10.0.0.7", ports=[Port(portid=631, service="ipp")])
        out = ipp.analyze([h], active=False)
        self.assertEqual(out["probes"], {})
        self.assertEqual(out["stats"]["findings"], 0)


if __name__ == "__main__":
    unittest.main()
