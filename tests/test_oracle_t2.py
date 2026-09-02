"""T2 SAFE proof-of-exploit for Oracle `oracle_tns_exposed`.

After the T1 wire-fingerprint confirms an Oracle listener AND the follow-on
(COMMAND=services)/(COMMAND=status) enumeration returns at least one
SID/SERVICE_NAME, recce sends ONE bounded TNS service-connect naming that SID
(never AUTH). The reply's packet-type byte disambiguates:

  * ACCEPT (type 2)   — listener has a live handler for the SID; SDU/TDU
                        are parsed out of the header as corroborating evidence.
  * REDIRECT (type 5) — SCAN/RAC listener forwards to an internal cluster
                        node; HOST/PORT captured.
  * REFUSE (type 4)   — SID does not resolve on this listener; T1 stays T1.

The probe is single-shot, uses `proxy.scaled()` for the timeout, sends NO
AUTH packet, and never establishes a database session (the connection is
dropped after the ACCEPT/REDIRECT header). Every test drives a real
in-process fake TNS listener over TCP — no mocks — so the wire format, the
probe helper, and the finding-tier gate all run end-to-end.
"""
from __future__ import annotations

import socket
import struct
import threading
import unittest

from recce.core.models import Host, Port
from recce.services.db import oracle


def _tcp_serve(handler):
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


def _tns_packet(ptype: int, payload: bytes, extra_hdr: bytes = b"") -> bytes:
    """Build a TNS packet with `ptype` at offset 4. `extra_hdr` pads the
    header out past the type byte so ACCEPT-style SDU/TDU fields land at
    the offsets the RFC (and recce's parser) expect."""
    pkt = bytearray(b"\x00\x00\x00\x00" + bytes([ptype]) + b"\x00\x00\x00")
    if extra_hdr:
        pkt += extra_hdr
    pkt += payload
    struct.pack_into(">H", pkt, 0, len(pkt))
    return bytes(pkt)


def _accept_packet(sdu: int = 2048, tdu: int = 32767) -> bytes:
    """A minimal TNS ACCEPT (type 2). offsets 8..20 carry the versions +
    SDU/TDU echoed back to the client; recce's T2 probe reads SDU at
    offset 16 and TDU at offset 18."""
    hdr = bytearray(20)
    hdr[0:2] = b"\x00\x00"          # patched
    hdr[2:4] = b"\x00\x00"          # checksum
    hdr[4] = 2                       # ACCEPT
    hdr[5] = 0
    hdr[6:8] = b"\x00\x00"          # header checksum
    hdr[8:10] = b"\x01\x38"         # version accepted
    hdr[10:12] = b"\x00\x00"        # service options
    hdr[12:14] = b"\x00\x00"        # (server) protocol chars
    hdr[14:16] = b"\x00\x00"        # historical
    struct.pack_into(">H", hdr, 16, sdu)
    struct.pack_into(">H", hdr, 18, tdu)
    struct.pack_into(">H", hdr, 0, len(hdr))
    return bytes(hdr)


def _host_one(port: int) -> Host:
    return Host(ip="127.0.0.1",
                ports=[Port(portid=port, service="oracle-tns", state="open")])


class ServiceConnectProbeUnit(unittest.TestCase):
    """`_service_connect_probe` on its own — smallest wire surface."""

    def test_accept_marks_ok_and_parses_sdu_tdu(self):
        def handle(conn):
            conn.recv(4096)
            conn.sendall(_accept_packet(sdu=8192, tdu=32767))
        port = _tcp_serve(handle)
        r = oracle._service_connect_probe("127.0.0.1", port, "ORCL")
        self.assertTrue(r["ok"])
        self.assertEqual(r["reply_type"], "ACCEPT")
        self.assertEqual(r["sid"], "ORCL")
        self.assertEqual(r["sdu"], 8192)
        self.assertEqual(r["tdu"], 32767)
        self.assertIn("ACCEPT", r["detail"])
        self.assertIn("ORCL", r["detail"])

    def test_redirect_captures_internal_host_port(self):
        def handle(conn):
            conn.recv(4096)
            conn.sendall(_tns_packet(
                5, b"(ADDRESS=(PROTOCOL=TCP)(HOST=10.20.30.40)(PORT=1522))"))
        port = _tcp_serve(handle)
        r = oracle._service_connect_probe("127.0.0.1", port, "ORCL")
        self.assertTrue(r["ok"])
        self.assertEqual(r["reply_type"], "REDIRECT")
        self.assertEqual(r["host"], "10.20.30.40")
        self.assertEqual(r["port"], 1522)
        self.assertIn("REDIRECT", r["detail"])

    def test_refuse_leaves_ok_false(self):
        def handle(conn):
            conn.recv(4096)
            conn.sendall(_tns_packet(4, b"(ERR=12514)"))
        port = _tcp_serve(handle)
        r = oracle._service_connect_probe("127.0.0.1", port, "BOGUS")
        self.assertFalse(r["ok"])
        self.assertEqual(r["reply_type"], "REFUSE")
        self.assertEqual(r["sid"], "BOGUS")

    def test_empty_sid_short_circuits(self):
        # Passing "" is a caller bug; probe must NOT open a socket for it.
        r = oracle._service_connect_probe("127.0.0.1", 65534, "", timeout=0.1)
        self.assertFalse(r["ok"])
        self.assertEqual(r["reply_type"], "")

    def test_timeout_returns_error_not_ok(self):
        # Bind a socket that accepts the connection but never replies —
        # bounded timeout keeps the probe from hanging.
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        # Silent handler — never writes, forces recv() to time out.
        def loop():
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                # Keep the connection open; do NOT write.
                import time
                time.sleep(2)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        threading.Thread(target=loop, daemon=True).start()
        r = oracle._service_connect_probe("127.0.0.1", port, "ORCL", timeout=0.3)
        self.assertFalse(r["ok"])
        # reply_type stays empty on no-reply
        self.assertEqual(r["reply_type"], "")

    def test_probe_never_sends_auth_bytes(self):
        # Capture what the probe actually put on the wire — must be a
        # DESCRIPTION+CONNECT_DATA+SERVICE_NAME payload, NEVER an AUTH_*
        # negotiation packet. Guards the "no writes / no state change /
        # no auth attempt" invariant.
        captured: list[bytes] = []

        def handle(conn):
            data = conn.recv(4096)
            captured.append(data)
            conn.sendall(_tns_packet(4, b""))
        port = _tcp_serve(handle)
        oracle._service_connect_probe("127.0.0.1", port, "ORCL")
        self.assertTrue(captured)
        wire = captured[0]
        self.assertIn(b"SERVICE_NAME=ORCL", wire)
        self.assertIn(b"CID=", wire)
        # None of these AUTH-flavored tokens must appear in a T2 probe.
        for forbidden in (b"AUTH_SESSKEY", b"AUTH_PASSWORD", b"AUTH_TERMINAL",
                          b"AUTH_VFR_DATA", b"AUTH_RTT", b"O5LOGON"):
            self.assertNotIn(forbidden, wire.upper()
                             if forbidden.isupper() else wire)


class TnsExposedT2Promotion(unittest.TestCase):
    """End-to-end: enumeration hands off a SID, service-connect ACCEPT
    promotes `oracle_tns_exposed` to depth_tier='t2' with the SDU/TDU
    evidence woven into the finding detail."""

    def _stub_vulnerable(self):
        """Legacy listener: version REFUSE (leaks version), enumerate
        SIDs on (COMMAND=services), then answer the T2 service-connect
        for that SID with a real ACCEPT."""
        services_blob = (
            b"(DESCRIPTION=(TMP=)(VSNNUM=186647040)(ERR=0)(ALIAS=LISTENER)"
            b"(SECURITY=OFF)(VERSION=TNSLSNR for Linux: Version 11.2.0.1.0)"
            b"(SERVICE=(SERVICE_NAME=orcl.corp.local)"
            b"(INSTANCE=(INSTANCE_NAME=orcl)(NUM=1)"
            b"(MACHINE=prod-db01.corp.local))))"
        )

        def handle(conn):
            data = conn.recv(4096)
            if b"COMMAND=services" in data:
                conn.sendall(_tns_packet(6, services_blob))
            elif b"COMMAND=status" in data:
                conn.sendall(_tns_packet(6, b"(DESCRIPTION=(SECURITY=OFF))"))
            elif b"SERVICE_NAME=" in data and b"COMMAND=" not in data:
                # T2 service-connect probe: ACCEPT.
                conn.sendall(_accept_packet(sdu=4096, tdu=32767))
            else:
                conn.sendall(_tns_packet(
                    4, b" TNSLSNR for Linux: Version 11.2.0.1.0 - Production"))
        return _tcp_serve(handle)

    def _stub_patched(self):
        """Hardened listener: enumerates one SID (say via a limited
        services dump) but REFUSES the T2 service-connect — recce must
        keep the finding at T1, not falsely promote."""
        services_blob = (
            b"(DESCRIPTION=(SERVICE=(SERVICE_NAME=locked.svc)))"
        )

        def handle(conn):
            data = conn.recv(4096)
            if b"COMMAND=services" in data:
                conn.sendall(_tns_packet(6, services_blob))
            elif b"COMMAND=status" in data:
                conn.sendall(_tns_packet(4, b"TNS-01189"))
            elif b"SERVICE_NAME=" in data and b"COMMAND=" not in data:
                # Patched: refuse the service-connect (ORA-12514 style).
                conn.sendall(_tns_packet(4, b"(ERR=12514)"))
            else:
                conn.sendall(_tns_packet(4, b"TNS-01189"))
        return _tcp_serve(handle)

    def test_probe_populates_sid_verified_on_accept(self):
        port = self._stub_vulnerable()
        pr = oracle.probe("127.0.0.1", port)
        self.assertTrue(pr["is_oracle"])
        sv = pr.get("sid_verified") or {}
        self.assertTrue(sv.get("ok"), f"sid_verified missing / not ok: {sv!r}")
        self.assertEqual(sv["reply_type"], "ACCEPT")
        # First enumerated candidate is the SERVICE_NAME.
        self.assertEqual(sv["sid"], "orcl.corp.local")
        self.assertEqual(sv["sdu"], 4096)
        self.assertEqual(sv["tdu"], 32767)

    def test_findings_promote_tns_exposed_to_t2_on_accept(self):
        port = self._stub_vulnerable()
        pr = oracle.probe("127.0.0.1", port)
        fs = oracle.findings([_host_one(port)],
                             {("127.0.0.1", port): pr})
        tns = [f for f in fs if f["kind"] == "oracle_tns_exposed"][0]
        self.assertEqual(tns["depth_tier"], "t2",
                         f"tns_exposed still T1: {tns['detail']!r}")
        # Evidence text must appear in the detail so the tester sees WHAT
        # the T2 probe confirmed — not just that it was promoted.
        self.assertIn("service-connect", tns["detail"].lower())
        self.assertIn("ACCEPT", tns["detail"])
        self.assertIn("orcl.corp.local", tns["detail"])

    def test_findings_stay_t1_when_service_connect_refused(self):
        port = self._stub_patched()
        pr = oracle.probe("127.0.0.1", port)
        # Enumeration still populated one candidate.
        self.assertIn("locked.svc", pr["service_names"])
        sv = pr.get("sid_verified") or {}
        self.assertFalse(sv.get("ok"))
        self.assertEqual(sv["reply_type"], "REFUSE")
        fs = oracle.findings([_host_one(port)],
                             {("127.0.0.1", port): pr})
        tns = [f for f in fs if f["kind"] == "oracle_tns_exposed"][0]
        self.assertEqual(tns["depth_tier"], "t1")
        # Detail must NOT claim service-connect proof when there is none.
        self.assertNotIn("service-connect", tns["detail"].lower())

    def test_findings_stay_t1_when_no_sid_enumerated(self):
        # Hardened listener that refuses services/status entirely — nothing
        # to hand the T2 probe. `sid_verified` remains {}; finding is T1.
        def handle(conn):
            conn.recv(4096)
            conn.sendall(_tns_packet(4, b"TNS-01189: refused"))
        port = _tcp_serve(handle)
        pr = oracle.probe("127.0.0.1", port)
        self.assertEqual(pr["sids"], [])
        self.assertEqual(pr["service_names"], [])
        self.assertEqual(pr["sid_verified"], {})
        fs = oracle.findings([_host_one(port)],
                             {("127.0.0.1", port): pr})
        tns = [f for f in fs if f["kind"] == "oracle_tns_exposed"][0]
        self.assertEqual(tns["depth_tier"], "t1")

    def test_findings_promote_to_t2_on_redirect(self):
        """REDIRECT (SCAN/RAC) is proof of a live handler just as much as
        ACCEPT — the listener wouldn't forward to a cluster node if the SID
        weren't real. The T2 gate accepts both."""
        services_blob = (
            b"(DESCRIPTION=(SERVICE=(SERVICE_NAME=rac.svc)))"
        )

        def handle(conn):
            data = conn.recv(4096)
            if b"COMMAND=services" in data:
                conn.sendall(_tns_packet(6, services_blob))
            elif b"COMMAND=status" in data:
                conn.sendall(_tns_packet(4, b""))
            elif b"SERVICE_NAME=" in data and b"COMMAND=" not in data:
                conn.sendall(_tns_packet(
                    5,
                    b"(ADDRESS=(PROTOCOL=TCP)(HOST=rac-node-3.internal)(PORT=1521))"))
            else:
                conn.sendall(_tns_packet(4, b""))
        port = _tcp_serve(handle)
        pr = oracle.probe("127.0.0.1", port)
        sv = pr.get("sid_verified") or {}
        self.assertTrue(sv.get("ok"))
        self.assertEqual(sv["reply_type"], "REDIRECT")
        self.assertEqual(sv["host"], "rac-node-3.internal")
        fs = oracle.findings([_host_one(port)],
                             {("127.0.0.1", port): pr})
        tns = [f for f in fs if f["kind"] == "oracle_tns_exposed"][0]
        self.assertEqual(tns["depth_tier"], "t2")
        self.assertIn("REDIRECT", tns["detail"])


if __name__ == "__main__":
    unittest.main()
