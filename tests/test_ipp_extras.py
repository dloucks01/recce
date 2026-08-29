"""Tests for the P1/P2/P3 additions to recce.services.ipp.

Covers, in order of severity:
  * IPP status-code parsing (RFC 8011 §5.1 — offset 2-3 of every response).
  * Get-Printer-Attributes wire (op 0x000B, RFC 8011 §4.2.5) and probe helper.
  * CUPS version gate for the CVE-2024-47176 chain (upstream + distro backport).
  * The findings() version-gate behaviour: patched builds emit an info-level
    `ipp_cups_patched` entry instead of the high-severity `ipp_cups` finding,
    while vulnerable / unknown-version hosts still fire `ipp_cups` unchanged.

All fixtures are constructed from the RFC 8010 encoding rules (§3.1) — no
network calls, no external tools.
"""
from __future__ import annotations

import struct
import unittest

from recce.core.models import Host, Port
from recce.services import ipp


# --- IPP status-code parser (RFC 8011 §5.1) --------------------------------

def _ipp_response(status_code: int, extra_body: bytes = b"\x03") -> bytes:
    """Minimal valid IPP response: version(2) status(2) request-id(4) + trailer."""
    return struct.pack("!BBHI", 1, 1, status_code, 1) + extra_body


class IPPStatusCodeTest(unittest.TestCase):
    def test_extracts_successful_ok(self):
        self.assertEqual(ipp._ipp_status_code(_ipp_response(0x0000)), 0x0000)

    def test_extracts_client_error_not_authenticated(self):
        # RFC 8011 §5.1: 0x0401 client-error-not-authenticated.
        self.assertEqual(ipp._ipp_status_code(_ipp_response(0x0401)), 0x0401)

    def test_extracts_server_error(self):
        self.assertEqual(ipp._ipp_status_code(_ipp_response(0x0500)), 0x0500)

    def test_none_on_short_body(self):
        self.assertIsNone(ipp._ipp_status_code(b""))
        self.assertIsNone(ipp._ipp_status_code(b"\x01\x01\x00"))

    def test_none_on_empty(self):
        self.assertIsNone(ipp._ipp_status_code(None or b""))

    def test_label_families(self):
        self.assertEqual(ipp._ipp_status_label(0x0000), "successful-ok")
        self.assertEqual(ipp._ipp_status_label(0x0401),
                         "client-error-not-authenticated")
        self.assertEqual(ipp._ipp_status_label(0x0403),
                         "client-error-forbidden")
        self.assertIn("client-error", ipp._ipp_status_label(0x0402))
        self.assertIn("server-error", ipp._ipp_status_label(0x0501))
        self.assertIn("successful", ipp._ipp_status_label(0x0001))
        self.assertEqual(ipp._ipp_status_label(None), "no-status")


# --- Get-Printer-Attributes wire (op 0x000B, RFC 8011 §4.2.5) ---------------

class GetPrinterAttrsWireTest(unittest.TestCase):
    def test_wire_carries_op_000b_and_printer_uri(self):
        wire = ipp._ipp_get_printer_attributes("ipp://10.0.0.5:631/printers/lp")
        # Version 1.1.
        self.assertEqual(wire[:2], b"\x01\x01")
        # Op code 0x000B (Get-Printer-Attributes).
        self.assertEqual(struct.unpack("!H", wire[2:4])[0], 0x000B)
        # Must include a printer-uri attribute (tag 0x45) in the operation
        # group; RFC 8011 §4.2.5 requires it.
        self.assertIn(b"printer-uri", wire)
        self.assertIn(b"\x45", wire)
        # attributes-charset + attributes-natural-language MUST be present.
        self.assertIn(b"attributes-charset", wire)
        self.assertIn(b"attributes-natural-language", wire)
        # Ends with the end-of-attributes tag 0x03.
        self.assertEqual(wire[-1:], b"\x03")


class GetPrinterAttrsProbeTest(unittest.TestCase):
    def test_ingress_verified_when_ipp_status_ok(self):
        # Response with an operation-attributes-tag then end-of-attributes so
        # the walker returns [] but the status-code parse still succeeds.
        canned = _ipp_response(0x0000, extra_body=b"\x01\x03")

        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            # Verify the request carries op 0x000B and hits the requested path.
            self.assertEqual(struct.unpack("!H", body[2:4])[0], 0x000B)
            self.assertEqual(path, "/printers/lp")
            return 200, canned, "CUPS/2.4.7"

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            out = ipp.get_printer_attributes(
                "10.0.0.5", 631, "ipp://10.0.0.5:631/printers/lp",
                path="/printers/lp")
        finally:
            ipp._ipp_post = orig
        self.assertEqual(out["http_status"], 200)
        self.assertEqual(out["ipp_status"], 0x0000)
        self.assertEqual(out["ipp_status_label"], "successful-ok")
        self.assertTrue(out["ingress_verified"])

    def test_ingress_not_verified_when_auth_required(self):
        canned = _ipp_response(0x0401, extra_body=b"\x03")

        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            return 200, canned, "CUPS/2.4.7"

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            out = ipp.get_printer_attributes(
                "10.0.0.5", 631, "ipp://10.0.0.5:631/printers/lp")
        finally:
            ipp._ipp_post = orig
        self.assertEqual(out["ipp_status"], 0x0401)
        self.assertEqual(out["ipp_status_label"],
                         "client-error-not-authenticated")
        self.assertFalse(out["ingress_verified"])

    def test_probe_no_reply_leaves_ingress_false(self):
        def fake_post(ip, port, body, timeout, tls=False, path="/"):
            return 0, b"", ""

        orig = ipp._ipp_post
        ipp._ipp_post = fake_post
        try:
            out = ipp.get_printer_attributes(
                "10.0.0.5", 631, "ipp://10.0.0.5:631/printers/lp")
        finally:
            ipp._ipp_post = orig
        self.assertEqual(out["http_status"], 0)
        self.assertIsNone(out["ipp_status"])
        self.assertFalse(out["ingress_verified"])
        self.assertEqual(out["attrs"], [])


# --- CUPS version gate ------------------------------------------------------

class CupsVersionGateTest(unittest.TestCase):
    def test_upstream_249_is_fixed(self):
        v, why = ipp._cups_version_vulnerable("2.4.9")
        self.assertFalse(v)
        self.assertIn("2.4.9", why)

    def test_upstream_2410_is_fixed(self):
        v, _ = ipp._cups_version_vulnerable("2.4.10")
        self.assertFalse(v)

    def test_upstream_247_is_vulnerable_without_distro_marker(self):
        v, _ = ipp._cups_version_vulnerable("2.4.7", "CUPS/2.4.7")
        self.assertTrue(v)

    def test_ubuntu_backport_downgrades(self):
        v, why = ipp._cups_version_vulnerable(
            "2.4.7", "CUPS/2.4.7 (Ubuntu 24.04.1 cups 2.4.7-1.2ubuntu7.1)")
        self.assertFalse(v)
        self.assertIn("distro", why)

    def test_rhel_op_backport_downgrades(self):
        # RHEL op-suffix in the raw version string (no server header path).
        v, _ = ipp._cups_version_vulnerable("2.3.3op2-25")
        self.assertFalse(v)

    def test_debian_security_update_downgrades(self):
        v, _ = ipp._cups_version_vulnerable("2.4.2", "CUPS/2.4.2 (Debian deb12u3)")
        self.assertFalse(v)

    def test_empty_defaults_vulnerable(self):
        v, why = ipp._cups_version_vulnerable("")
        self.assertTrue(v)
        self.assertIn("no version", why)

    def test_unparseable_defaults_vulnerable(self):
        v, why = ipp._cups_version_vulnerable("weird")
        self.assertTrue(v)
        self.assertIn("unparseable", why)


# --- findings() with the version gate ---------------------------------------

class FindingsGateTest(unittest.TestCase):
    def _mkhost(self):
        return Host(ip="10.0.0.5",
                    ports=[Port(portid=631, state="open", service="ipp")])

    def test_patched_cups_emits_info_ipp_cups_patched(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 631): {
            "reachable": True, "is_cups": True,
            "cups_version": "2.4.9", "server": "CUPS/2.4.9",
            "printers": [],
        }}
        fs = ipp.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("ipp_cups_patched", kinds)
        self.assertNotIn("ipp_cups", kinds)
        patched = next(f for f in fs if f["kind"] == "ipp_cups_patched")
        self.assertEqual(patched["severity"], "info")

    def test_ubuntu_backport_emits_patched_finding(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 631): {
            "reachable": True, "is_cups": True,
            "cups_version": "2.4.7",
            "server": "CUPS/2.4.7 (Ubuntu 24.04.1 cups 2.4.7-1.2ubuntu7.1)",
            "printers": [],
        }}
        fs = ipp.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("ipp_cups_patched", kinds)
        self.assertNotIn("ipp_cups", kinds)

    def test_vulnerable_still_emits_ipp_cups_high(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 631): {
            "reachable": True, "is_cups": True,
            "cups_version": "2.4.7", "server": "CUPS/2.4.7",
            "printers": [{"printer-name": "Laser1"}],
        }}
        fs = ipp.findings([h], probes)
        f = next(x for x in fs if x["kind"] == "ipp_cups")
        self.assertEqual(f["severity"], "high")
        self.assertIn("CVE-2024-47176", f["detail"])

    def test_ingress_verified_flag_annotates_detail(self):
        h = self._mkhost()
        probes = {("10.0.0.5", 631): {
            "reachable": True, "is_cups": True,
            "cups_version": "2.4.7", "server": "CUPS/2.4.7",
            "printers": [{"printer-name": "Laser1"}],
            "ingress_verified": True,
        }}
        fs = ipp.findings([h], probes)
        f = next(x for x in fs if x["kind"] == "ipp_cups")
        # Detail must reflect the verified ingress path (not the old
        # "recce did NOT invoke that path" wording, which is only correct
        # when ingress was NOT verified).
        self.assertIn("ingress path verified", f["detail"])

    def test_unknown_version_still_emits_high_ipp_cups(self):
        # Backward compat: probe dicts without foomatic_vulnerable/no version
        # (older callers) must still fire the high finding — a scanner never
        # silently patches away a real exposure just because parsing failed.
        h = self._mkhost()
        probes = {("10.0.0.5", 631): {
            "reachable": True, "is_cups": True, "server": "CUPS/",
            "printers": [],
        }}
        fs = ipp.findings([h], probes)
        kinds = {f["kind"] for f in fs}
        self.assertIn("ipp_cups", kinds)
        self.assertNotIn("ipp_cups_patched", kinds)


if __name__ == "__main__":
    unittest.main()
