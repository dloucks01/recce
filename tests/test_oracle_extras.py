"""Tests for the additive Oracle deep-probe capabilities:

  * (COMMAND=services)/(COMMAND=status) listener dump -> SIDs / service names /
    instances / machine hostname parsed out of the DATA payload;
  * REDIRECT (packet type 5) payload parsed for the internal cluster HOST/PORT
    a SCAN/RAC listener leaks;
  * offline version -> CVE mapping (CVE-2012-1675 TNS Poison, CVE-2012-3137
    o5logon), with the corresponding finding kind emitted.

Every test drives a real in-process fake TNS listener over TCP - no mocks - so
the wire format, the probe helper, the parser, and the finding builders all run
end-to-end.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services.db import oracle


def _tcp_serve(handler):
    """Spawn a daemon-thread TCP acceptor bound to 127.0.0.1:0; each accepted
    connection is handed to `handler(conn)`. Returns the bound port."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                conn.settimeout(3)
                try:
                    handler(conn)
                except OSError:
                    pass
    threading.Thread(target=loop, daemon=True).start()
    return port


def _tns_packet(ptype: int, payload: bytes) -> bytes:
    """Assemble a minimal TNS packet with the given type-byte and payload."""
    pkt = bytearray(b"\x00\x00\x00\x00" + bytes([ptype]) + b"\x00\x00\x00")
    pkt += payload
    struct.pack_into(">H", pkt, 0, len(pkt))
    return bytes(pkt)


def _host_one(port: int) -> Host:
    return Host(ip="127.0.0.1",
                ports=[Port(portid=port, service="oracle-tns", state="open")])


class VersionCveMapping(unittest.TestCase):
    """Purely offline: version string -> known-CVE list."""

    def test_11_2_0_1_hits_both_2012_cves(self):
        cves = {c["id"] for c in oracle._known_cves("11.2.0.1.0")}
        self.assertIn("CVE-2012-1675", cves)
        self.assertIn("CVE-2012-3137", cves)

    def test_11_2_0_3_still_o5logon_and_poison(self):
        cves = {c["id"] for c in oracle._known_cves("11.2.0.3")}
        self.assertEqual({"CVE-2012-1675", "CVE-2012-3137"}, cves)

    def test_11_2_0_4_no_longer_vulnerable(self):
        # 11.2.0.4 is the patched line for TNS Poison and above the o5logon range.
        self.assertEqual(oracle._known_cves("11.2.0.4.0"), [])

    def test_19c_clean(self):
        self.assertEqual(oracle._known_cves("19.3.0.0.0"), [])

    def test_empty_and_junk_versions(self):
        self.assertEqual(oracle._known_cves(""), [])
        self.assertEqual(oracle._known_cves("not-a-version"), [])

    def test_version_tuple_pads_short_versions(self):
        self.assertEqual(oracle._version_tuple("11.2"), (11, 2, 0, 0))
        self.assertEqual(oracle._version_tuple("11.2.0.3.7"), (11, 2, 0, 3))
        self.assertEqual(oracle._version_tuple(""), ())


class RedirectParsing(unittest.TestCase):
    """The (ADDRESS=(HOST=..)(PORT=..)) payload is extracted from REDIRECT (type 5)
    and ONLY from REDIRECT — a REFUSE that happens to carry HOST= must not
    match."""

    def test_redirect_extracts_internal_endpoint(self):
        r = oracle._parse_redirect(_tns_packet(
            5, b"(ADDRESS=(PROTOCOL=TCP)(HOST=10.10.5.42)(PORT=1522))"))
        self.assertEqual(r, {"host": "10.10.5.42", "port": 1522})

    def test_non_redirect_reply_returns_empty(self):
        # Same HOST=..., but this is a REFUSE (type 4). Must NOT parse.
        self.assertEqual(oracle._parse_redirect(_tns_packet(
            4, b"HOST=1.2.3.4")), {})

    def test_redirect_without_host_returns_empty(self):
        self.assertEqual(oracle._parse_redirect(_tns_packet(5, b"(NO=ADDRESS)")), {})

    def test_probe_captures_redirect_from_version_response(self):
        def handle(conn):
            conn.recv(4096)
            conn.sendall(_tns_packet(
                5,
                b"(ADDRESS=(PROTOCOL=TCP)(HOST=rac-node-2.internal)(PORT=1521))"))
        port = _tcp_serve(handle)
        pr = oracle.probe("127.0.0.1", port)
        self.assertTrue(pr["is_oracle"])
        self.assertEqual(pr["tns_type"], "REDIRECT")
        self.assertEqual(pr["redirect"],
                         {"host": "rac-node-2.internal", "port": 1521})
        fs = oracle.findings([_host_one(port)],
                             {("127.0.0.1", port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("oracle_rac_internal_endpoint_leak", kinds)
        rac = [f for f in fs if f["kind"] == "oracle_rac_internal_endpoint_leak"][0]
        self.assertEqual(rac["severity"], "medium")
        self.assertIn("rac-node-2.internal", rac["detail"])


class ListenerStatusDump(unittest.TestCase):
    """A legacy listener answers (COMMAND=services|status) with a text DATA blob
    whose SERVICE_NAME / SID_NAME / INSTANCE_NAME / MACHINE keys expose the
    database SIDs and machine hostname."""

    def _stub(self):
        # Answer the initial (COMMAND=version) with a version REFUSE, and the
        # follow-on services/status queries with a DATA blob carrying SIDs and a
        # machine name — three separate connections, all one handler.
        services_blob = (
            b"(DESCRIPTION=(TMP=)(VSNNUM=186647040)(ERR=0)(ALIAS=LISTENER)"
            b"(SECURITY=OFF)(VERSION=TNSLSNR for Linux: Version 11.2.0.1.0)"
            b"(SERVICE=(SERVICE_NAME=orcl.corp.local)"
            b"(INSTANCE=(INSTANCE_NAME=orcl)(NUM=1)"
            b"(MACHINE=prod-db01.corp.local))))"
        )
        status_blob = (
            b"(DESCRIPTION=(TMP=)(ALIAS=LISTENER)(SECURITY=OFF)"
            b"(SID_LIST=(SID=(SID_NAME=XE))(SID=(SID_NAME=XEPDB1))))"
        )

        def handle(conn):
            data = conn.recv(4096)
            if b"COMMAND=services" in data:
                conn.sendall(_tns_packet(6, services_blob))
            elif b"COMMAND=status" in data:
                conn.sendall(_tns_packet(6, status_blob))
            else:
                conn.sendall(_tns_packet(
                    4, b" TNSLSNR for Linux: Version 11.2.0.1.0 - Production"))
        return _tcp_serve(handle)

    def test_probe_aggregates_services_status_and_maps_cves(self):
        port = self._stub()
        pr = oracle.probe("127.0.0.1", port)
        self.assertTrue(pr["is_oracle"])
        self.assertEqual(pr["version"], "11.2.0.1.0")
        # SIDs from status; SERVICE_NAME + INSTANCE_NAME from services.
        self.assertEqual(set(pr["sids"]), {"XE", "XEPDB1"})
        self.assertIn("orcl.corp.local", pr["service_names"])
        self.assertIn("orcl", pr["instances"])
        self.assertEqual(pr["machine"], "prod-db01.corp.local")
        cve_ids = {c["id"] for c in pr["known_cves"]}
        self.assertEqual(cve_ids, {"CVE-2012-1675", "CVE-2012-3137"})

    def test_findings_include_status_leak_and_known_cves(self):
        port = self._stub()
        pr = oracle.probe("127.0.0.1", port)
        fs = oracle.findings([_host_one(port)],
                             {("127.0.0.1", port): pr})
        kinds = {f["kind"] for f in fs}
        # Existing kinds preserved.
        self.assertIn("oracle_tns_exposed", kinds)
        self.assertIn("oracle_version_leak", kinds)
        # New kinds emitted.
        self.assertIn("oracle_listener_status_leak", kinds)
        self.assertIn("oracle_known_vulnerable_version", kinds)
        dump = [f for f in fs if f["kind"] == "oracle_listener_status_leak"][0]
        self.assertEqual(dump["severity"], "high")
        self.assertIn("XE", dump["detail"])
        self.assertIn("prod-db01.corp.local", dump["detail"])
        # One finding per CVE.
        cve_titles = {f["title"] for f in fs
                      if f["kind"] == "oracle_known_vulnerable_version"}
        self.assertTrue(any("CVE-2012-1675" in t for t in cve_titles))
        self.assertTrue(any("CVE-2012-3137" in t for t in cve_titles))


class ListenerStatusHardened(unittest.TestCase):
    """A hardened 12c/19c listener refuses services/status the same way it refuses
    version — no SIDs, no machine, no listener_status_leak finding."""

    def test_no_new_findings_when_no_data_returned(self):
        # Answer every command with an empty REFUSE — is_oracle still True (via
        # packet-type byte) but nothing to leak.
        def handle(conn):
            conn.recv(4096)
            conn.sendall(_tns_packet(4, b"TNS-01189: refused"))
        port = _tcp_serve(handle)
        pr = oracle.probe("127.0.0.1", port)
        self.assertTrue(pr["is_oracle"])
        self.assertEqual(pr["sids"], [])
        self.assertEqual(pr["service_names"], [])
        self.assertEqual(pr["machine"], "")
        self.assertEqual(pr["known_cves"], [])  # no version leaked -> no CVE list
        fs = oracle.findings([_host_one(port)],
                             {("127.0.0.1", port): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("oracle_tns_exposed", kinds)
        self.assertNotIn("oracle_listener_status_leak", kinds)
        self.assertNotIn("oracle_known_vulnerable_version", kinds)
        self.assertNotIn("oracle_rac_internal_endpoint_leak", kinds)


if __name__ == "__main__":
    unittest.main()
