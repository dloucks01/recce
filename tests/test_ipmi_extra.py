"""Wire-fixture tests for the IPMI additions:

  * Get Device ID (App/0x01)             — vendor + firmware fingerprint
  * Get Channel Cipher Suites (App/0x54) — direct cipher-0 confirmation
  * Auth Status bits 3/4/5 surfaced      — per-msg/user-level auth,  KG

Fixtures are hand-assembled from the IPMI 2.0 spec (§20.1, §22.15, §22.13) so
they exercise the wire-level parser rather than round-tripping through the
module's own encoder.
"""
from __future__ import annotations

import socket
import threading
import unittest

from recce.core.models import Host, Port
from recce.services import ipmi


# ---------------------------------------------------------------------------
# Shared UDP responder that hands out different canned replies per received
# IPMI command. Fake_bmc understands: Get Device ID (0x01), Get Channel
# Cipher Suites (0x54), Get Channel Auth Capabilities (0x38). Anything else
# gets no reply (client-side timeout).
# ---------------------------------------------------------------------------
class _MultiBMC:
    def __init__(self, replies: dict[int, bytes]):
        self._replies = replies                # cmd_byte -> full RMCP+IPMI reply
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.host, self.port = self._sock.getsockname()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _cmd(self, pkt: bytes) -> int | None:
        # Session-less IPMI 1.5 request has cmd at offset 14 + 5 = 19.
        return pkt[19] if len(pkt) >= 20 else None

    def _serve(self):
        while not self._stop:
            try:
                self._sock.settimeout(0.5)
                data, addr = self._sock.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            cmd = self._cmd(data)
            reply = self._replies.get(cmd) if cmd is not None else None
            if reply:
                self._sock.sendto(reply, addr)

    def close(self):
        self._stop = True
        try: self._sock.close()
        except OSError: pass


def _ipmi15_reply(cmd: int, data: bytes) -> bytes:
    """Assemble an IPMI 1.5 session-less response for `cmd` with `data` as
    the payload (after completion code 0x00). The two checksums are
    2's-complement per IPMI §13.8."""
    rq_addr = 0x81            # remote console echoed as rq in response
    netfn_resp = (0x07 << 2)  # App response (netFn 7)
    csum1 = (-(rq_addr + netfn_resp)) & 0xff
    rs_addr = 0x20
    rs_seq = 0x00
    body = bytes([rs_addr, rs_seq, cmd, 0x00]) + data   # 0x00 = comp code
    csum2 = (-sum(body)) & 0xff
    msg = bytes([rq_addr, netfn_resp, csum1]) + body + bytes([csum2])
    rmcp = b"\x06\x00\xff\x07"
    sess = b"\x00" + b"\x00" * 4 + b"\x00" * 4
    return rmcp + sess + bytes([len(msg)]) + msg


def _gdi_reply(mfg_id: int, prod_id: int,
               fw_major: int = 2, fw_minor: int = 0x30,
               ipmi_ver_byte: int = 0x02) -> bytes:
    """Build a Get Device ID response for the given manufacturer/product/fw.
    See IPMI 2.0 §20.1 Table 20-2 for the field layout."""
    data = bytes([
        0x20,                                  # device_id
        0x01,                                  # device_revision
        fw_major & 0x7f,                       # fw_maj (bit7 = avail masked off)
        fw_minor,                              # fw_min
        ipmi_ver_byte,                         # IPMI version (BCD, digits swapped)
        0xbf,                                  # additional device support
        mfg_id & 0xff, (mfg_id >> 8) & 0xff, (mfg_id >> 16) & 0xff,
        prod_id & 0xff, (prod_id >> 8) & 0xff,
        0x00, 0x00, 0x00, 0x00,                # aux fw rev (optional)
    ])
    return _ipmi15_reply(0x01, data)


def _cipher_suites_reply(record_data: bytes, channel: int = 0x0e) -> bytes:
    """Build a Get Channel Cipher Suites response with `record_data` as the
    raw cipher-suite-record bytes."""
    return _ipmi15_reply(0x54, bytes([channel]) + record_data)


# ---------------------------------------------------------------------------
# Get Device ID
# ---------------------------------------------------------------------------
class GetDeviceIDTest(unittest.TestCase):
    def test_dell_idrac_manufacturer_id_maps_to_vendor(self):
        # Dell IANA private enterprise number = 674 (0x2a2). Product 0x0003
        # is chosen just to prove the LE decode works — not a claim about
        # any specific iDRAC generation.
        srv = _MultiBMC({0x01: _gdi_reply(mfg_id=674, prod_id=0x0003,
                                          fw_major=2, fw_minor=0x30)})
        try:
            d = ipmi.get_device_id(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(d["reachable"])
        self.assertEqual(d["manufacturer_id"], 674)
        self.assertEqual(d["vendor"], "Dell")
        self.assertEqual(d["product_id"], 3)
        self.assertEqual(d["firmware_major"], 2)
        self.assertEqual(d["firmware_minor"], 0x30)
        self.assertEqual(d["ipmi_version"], "2.0")

    def test_unknown_manufacturer_id_leaves_vendor_blank(self):
        # A fabricated OEM (999) is still valid to decode — vendor label
        # falls back to "" rather than an invented name.
        srv = _MultiBMC({0x01: _gdi_reply(mfg_id=999, prod_id=0x1234)})
        try:
            d = ipmi.get_device_id(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(d["reachable"])
        self.assertEqual(d["manufacturer_id"], 999)
        self.assertEqual(d["vendor"], "")
        self.assertEqual(d["product_id"], 0x1234)

    def test_no_reply_returns_unreachable(self):
        # Bind and close so port is closed → recvfrom will time out.
        s = socket.socket(); s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]; s.close()
        d = ipmi.get_device_id("127.0.0.1", port, timeout=0.4)
        self.assertFalse(d["reachable"])
        self.assertEqual(d["vendor"], "")

    def test_wrong_cmd_echoed_is_not_mis_parsed(self):
        # A BMC that answers our device-id request with something else
        # (e.g. still sending GCAC) must not be mis-parsed.
        srv = _MultiBMC({0x01: _gdi_reply(mfg_id=11, prod_id=1)})
        # But respond to cmd 0x01 with a payload whose echoed cmd is 0x38 —
        # simulate by swapping the reply.
        wrong = _ipmi15_reply(0x38, b"\x00" * 16)
        srv._replies[0x01] = wrong
        try:
            d = ipmi.get_device_id(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertFalse(d["reachable"])


# ---------------------------------------------------------------------------
# Get Channel Cipher Suites — record parser
# ---------------------------------------------------------------------------
class CipherSuitesTest(unittest.TestCase):
    def test_cipher_zero_confirmed_when_record_has_auth_alg_zero(self):
        # 0xC0 = start-of-record, suite_id=0x00, auth alg tag 0x00 = auth_alg 0,
        # integrity tag 0x40 = alg 0, confidentiality tag 0x80 = alg 0.
        record = bytes.fromhex("c000004080")
        srv = _MultiBMC({0x54: _cipher_suites_reply(record)})
        try:
            r = ipmi.get_channel_cipher_suites(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertIn(0, r["cipher_suite_ids"])
        self.assertEqual(r["auth_algs"][0], 0)
        self.assertTrue(r["cipher_zero"])

    def test_no_cipher_zero_when_only_strong_suites(self):
        # Suite 3: RAKP-HMAC-SHA1(0x01) + HMAC-SHA1-96(int 0x41) + AES-128(conf 0x81)
        record = bytes.fromhex("c003014181")
        srv = _MultiBMC({0x54: _cipher_suites_reply(record)})
        try:
            r = ipmi.get_channel_cipher_suites(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(r["reachable"])
        self.assertEqual(r["cipher_suite_ids"], [3])
        self.assertEqual(r["auth_algs"][3], 1)
        self.assertFalse(r["cipher_zero"])

    def test_multiple_records_parsed_back_to_back(self):
        # Suite 0 (cipher-zero) then suite 3 (SHA1+AES) — the parser must
        # split at 0xC0 boundaries and detect the cipher-0 record.
        record = bytes.fromhex("c000004080" "c003014181")
        suites, auth = ipmi._parse_cipher_records(record)
        self.assertEqual(suites, [0, 3])
        self.assertEqual(auth, {0: 0, 3: 1})

    def test_oem_record_variant_parses_suite_id(self):
        # 0xC1 <iana3> <suite_id> <tagged algs> — OEM record framing.
        # IANA bytes are arbitrary here; suite_id is 0x21.
        record = bytes.fromhex("c1" "aa" "bb" "cc" "21" "02" "42" "82")
        suites, auth = ipmi._parse_cipher_records(record)
        self.assertEqual(suites, [0x21])
        self.assertEqual(auth[0x21], 2)

    def test_truncated_record_stops_cleanly(self):
        # Tag says start-of-record but only one byte follows — parser must
        # not raise. Yield nothing.
        suites, auth = ipmi._parse_cipher_records(b"\xc0")
        self.assertEqual(suites, [])
        self.assertEqual(auth, {})


# ---------------------------------------------------------------------------
# Auth Status bits 3/4/5 (surfaced in probe output + findings)
# ---------------------------------------------------------------------------
def _build_gcac_response(auth_types: int, auth_status: int,
                        ext_caps: int) -> bytes:
    """Copy of test_ipmi's GCAC-response builder — inlined so this test
    module does not import from a peer test file."""
    hdr = bytes([0x06, 0x00, 0xff, 0x07])
    sess = bytes([0x00]) + b"\x00" * 4 + b"\x00" * 4
    msg = bytes([
        0x81, 0x1c, 0x63, 0x20, 0x00, 0x38,
        0x00, 0x01,
        auth_types & 0xff, auth_status & 0xff, ext_caps & 0xff,
        0x00, 0x00, 0x00,
    ])
    return hdr + sess + bytes([len(msg)]) + msg


class AuthStatusBitsTest(unittest.TestCase):
    def test_per_message_auth_disabled_bit_surfaced_and_reported(self):
        # auth_status bit 4 (0x10) = per-msg auth disabled.
        srv = _MultiBMC({
            0x38: _build_gcac_response(auth_types=0x10, auth_status=0x10,
                                       ext_caps=0x00),
            # No 0x01 / 0x54 answers — probe should degrade cleanly.
        })
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=0.6)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertTrue(p["per_msg_auth_disabled"])
        self.assertFalse(p["user_level_auth_disabled"])
        self.assertFalse(p["kg_set"])

        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=623, protocol="udp", state="open",
                             service="ipmi")])
        kinds = {f["kind"] for f in ipmi.findings([h], {("10.0.0.5", 623): p})}
        self.assertIn("ipmi_per_msg_auth_disabled", kinds)
        self.assertNotIn("ipmi_userlevel_auth_disabled", kinds)

    def test_user_level_auth_disabled_bit_surfaced_and_reported(self):
        # auth_status bit 3 (0x08).
        srv = _MultiBMC({
            0x38: _build_gcac_response(auth_types=0x10, auth_status=0x08,
                                       ext_caps=0x00),
        })
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=0.6)
        finally:
            srv.close()
        self.assertTrue(p["user_level_auth_disabled"])
        self.assertFalse(p["per_msg_auth_disabled"])
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=623, protocol="udp", state="open",
                             service="ipmi")])
        kinds = {f["kind"] for f in ipmi.findings([h], {("10.0.0.5", 623): p})}
        self.assertIn("ipmi_userlevel_auth_disabled", kinds)

    def test_kg_not_set_emits_info_finding(self):
        # KG bit CLEAR (0x00) — the default posture. The finding is info,
        # not high, because on its own it isn't exploitable.
        srv = _MultiBMC({
            0x38: _build_gcac_response(auth_types=0x10, auth_status=0x00,
                                       ext_caps=0x00),
        })
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=0.6)
        finally:
            srv.close()
        self.assertFalse(p["kg_set"])
        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=623, protocol="udp", state="open",
                             service="ipmi")])
        fs = ipmi.findings([h], {("10.0.0.5", 623): p})
        kg = [f for f in fs if f["kind"] == "ipmi_kg_key_status"]
        self.assertEqual(len(kg), 1)
        self.assertEqual(kg[0]["severity"], "info")


# ---------------------------------------------------------------------------
# End-to-end: probe() rolls all three additions together
# ---------------------------------------------------------------------------
class ProbeRollupTest(unittest.TestCase):
    def test_probe_populates_vendor_and_confirmed_cipher_zero(self):
        # GCAC advertises none+password on IPMI 2.0 (heuristic cipher-0),
        # Device ID reports HP (IANA 11), Cipher Suites confirms cipher-0.
        # Result: probe() carries vendor="HP/HPE", cipher_zero_confirmed=True,
        # findings emit ipmi_cipher_zero_confirmed and ipmi_device_id.
        gcac = _build_gcac_response(auth_types=0x11, auth_status=0x00,
                                    ext_caps=0x01)
        gdi = _gdi_reply(mfg_id=11, prod_id=0x0100, fw_major=2, fw_minor=0x53)
        cs = _cipher_suites_reply(bytes.fromhex("c000004080"))
        srv = _MultiBMC({0x38: gcac, 0x01: gdi, 0x54: cs})
        try:
            p = ipmi.probe(srv.host, srv.port, timeout=2.0)
        finally:
            srv.close()
        self.assertTrue(p["reachable"])
        self.assertEqual(p["vendor"], "HP/HPE")
        self.assertEqual(p["manufacturer_id"], 11)
        self.assertEqual(p["firmware_version"], "2.53")
        self.assertTrue(p["cipher_zero"])
        self.assertTrue(p["cipher_zero_confirmed"])
        self.assertIn(0, p["cipher_suite_ids"])

        h = Host(ip="10.0.0.5",
                 ports=[Port(portid=623, protocol="udp", state="open",
                             service="ipmi")])
        kinds = {f["kind"] for f in ipmi.findings([h], {("10.0.0.5", 623): p})}
        self.assertIn("ipmi_cipher_zero_confirmed", kinds)
        self.assertNotIn("ipmi_cipher_zero", kinds)      # heuristic replaced
        self.assertIn("ipmi_device_id", kinds)


if __name__ == "__main__":
    unittest.main()
