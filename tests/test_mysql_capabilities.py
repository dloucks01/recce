"""New MySQL capability additions covered by the audit's top-priority gaps:

  * caching_sha2_password + AuthSwitchRequest (MySQL 8.0 default path) — the
    empty-password probe must NOT stop at 0xFE any more.
  * mysql.func UDF enumeration and the instant-RCE finding for lib_mysqludf_sys.
  * Version → CVE correlation on the already-parsed server_version string.

Wire-shape fixtures follow MySQL Internals §"Protocol::AuthSwitchRequest" and
§"caching_sha2_password Information".
"""
from __future__ import annotations

import hashlib
import socketserver
import struct
import threading

from recce.core.models import Host, Port
from recce.services.db import mysql


# ---- helpers to build wire packets identical to what the server sends -------

def _pkt(payload: bytes, seq: int) -> bytes:
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def _lenstr(s) -> bytes:
    b = str(s).encode()
    return bytes([len(b)]) + b


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def _serve(handler_fn):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            handler_fn(self.request)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[0], srv.server_address[1], srv


# ============================================================================
# 1. caching_sha2_password scramble — RFC-derived known vector
# ============================================================================

def test_sha256_scramble_matches_reference_algorithm():
    """SHA256(pw) XOR SHA256(SHA256(SHA256(pw)) || salt) — recompute the
    reference algorithm and confirm bit-for-bit equality with the module's
    implementation on a chosen (password, salt)."""
    password = "Hunter2x"
    salt = bytes(range(20))
    p1 = hashlib.sha256(password.encode()).digest()
    p2 = hashlib.sha256(p1).digest()
    p3 = hashlib.sha256(p2 + salt).digest()
    expected = bytes(a ^ b for a, b in zip(p1, p3))
    assert mysql._sha256_scramble(password, salt) == expected
    # Empty password -> empty scramble (server compares against stored empty hash).
    assert mysql._sha256_scramble("", salt) == b""


def test_auth_switch_response_dispatches_by_plugin_name():
    salt = bytes(range(20))
    # native re-scramble
    assert mysql._auth_switch_response(
        "mysql_native_password", "pw", salt) == mysql._native_scramble("pw", salt)
    # caching_sha2 re-scramble
    assert mysql._auth_switch_response(
        "caching_sha2_password", "pw", salt) == mysql._sha256_scramble("pw", salt)
    # cleartext (PAM/LDAP) — NUL-terminated
    assert mysql._auth_switch_response(
        "mysql_clear_password", "pw", salt) == b"pw\x00"
    # ed25519 / sha256_password full-auth are unsupported — signal None so the
    # caller abandons the negotiation cleanly rather than sending garbage.
    assert mysql._auth_switch_response(
        "client_ed25519", "pw", salt) is None
    assert mysql._auth_switch_response("sha256_password", "pw", salt) is None


# ============================================================================
# 2. AuthSwitchRequest end-to-end — a caching_sha2 MySQL 8.0 that expects
#    the empty-password probe to follow the 0xFE branch (and the 0x01 0x03
#    fast_auth_success MoreData). Previously recce recorded
#    "auth negotiation required"; now it must land on 'unauth'.
# ============================================================================

def _caching_sha2_empty_server():
    """MySQL 8.0-style server: declares caching_sha2_password in the greeting,
    AuthSwitchRequests it after the client's mysql_native_password hello, then
    returns fast_auth_success + OK for an empty auth response."""
    salt = bytes((i % 250) + 1 for i in range(20))

    def greeting():
        # Handshake v10 with default auth plugin caching_sha2_password.
        auth1, auth2 = salt[:8], salt[8:20] + b"\x00"
        return (bytes([10]) + b"8.0.36\x00" + struct.pack("<I", 7) + auth1 + b"\x00"
                + struct.pack("<H", 0x0200) + b"\x21" + struct.pack("<H", 2)
                + struct.pack("<H", 0x0008) + bytes([21]) + b"\x00" * 10 + auth2
                + b"caching_sha2_password\x00")

    def handle(conn):
        conn.sendall(_pkt(greeting(), 0))
        resp = _recv_exact(conn, 4)
        if len(resp) < 4:
            return
        ln = struct.unpack("<I", resp[:3] + b"\x00")[0]
        body = _recv_exact(conn, ln)
        # Client's HandshakeResponse says mysql_native_password w/ empty auth.
        assert b"mysql_native_password\x00" in body
        # -> AuthSwitchRequest: 0xFE + plugin\0 + salt\0
        conn.sendall(_pkt(b"\xFE" + b"caching_sha2_password\x00" + salt + b"\x00", 2))
        # Client's AuthSwitchResponse (empty scramble for empty password).
        rhdr = _recv_exact(conn, 4)
        if len(rhdr) < 4:
            return
        rlen = struct.unpack("<I", rhdr[:3] + b"\x00")[0]
        scramble = _recv_exact(conn, rlen)
        assert scramble == b""                          # empty password -> empty
        # MoreData: fast_auth_success -> OK
        conn.sendall(_pkt(b"\x01\x03", 4))
        conn.sendall(_pkt(b"\x00\x00\x00\x02\x00\x00\x00", 5))
        # keep the socket around briefly so the client can close cleanly
        try:
            conn.recv(64)
        except OSError:
            pass
    return handle


def test_caching_sha2_empty_password_probe_now_succeeds():
    ip, port, srv = _serve(_caching_sha2_empty_server())
    try:
        pr = mysql.probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert pr["reachable"]
    assert pr["unauth"], f"expected empty-password unauth, got err={pr.get('error')!r}"
    assert pr["user"] == "root"
    assert pr["version"] == "8.0.36"


def _caching_sha2_full_auth_server():
    """Server that responds with perform_full_authentication (0x04) after the
    AuthSwitchResponse — recce cannot complete RSA-OAEP, must bail cleanly
    (probe returns not-ok, no crash)."""
    salt = bytes((i % 250) + 1 for i in range(20))

    def greeting():
        auth1, auth2 = salt[:8], salt[8:20] + b"\x00"
        return (bytes([10]) + b"8.0.36\x00" + struct.pack("<I", 7) + auth1 + b"\x00"
                + struct.pack("<H", 0x0200) + b"\x21" + struct.pack("<H", 2)
                + struct.pack("<H", 0x0008) + bytes([21]) + b"\x00" * 10 + auth2
                + b"caching_sha2_password\x00")

    def handle(conn):
        conn.sendall(_pkt(greeting(), 0))
        hdr = _recv_exact(conn, 4)
        if len(hdr) < 4:
            return
        ln = struct.unpack("<I", hdr[:3] + b"\x00")[0]
        _recv_exact(conn, ln)
        conn.sendall(_pkt(b"\xFE" + b"caching_sha2_password\x00" + salt + b"\x00", 2))
        rhdr = _recv_exact(conn, 4)
        if len(rhdr) < 4:
            return
        rlen = struct.unpack("<I", rhdr[:3] + b"\x00")[0]
        _recv_exact(conn, rlen)
        # perform_full_authentication — needs the server's RSA public key.
        conn.sendall(_pkt(b"\x01\x04", 4))
        try:
            conn.recv(64)
        except OSError:
            pass
    return handle


def test_caching_sha2_full_auth_bails_without_crashing():
    ip, port, srv = _serve(_caching_sha2_full_auth_server())
    try:
        pr = mysql.probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    # No RCE path via full-auth over cleartext — probe records
    # 'auth negotiation required' and moves on.
    assert pr["reachable"]
    assert not pr["unauth"]
    assert pr["auth_required"]


# ============================================================================
# 3. mysql.func UDF enumeration + finding
# ============================================================================

def _mysql_host():
    return Host(ip="10.0.0.7",
                ports=[Port(portid=3306, state="open", service="mysql")])


def test_udf_rce_names_trip_critical_finding():
    """Presence of sys_exec / sys_eval in mysql.func = instant RCE. The
    finding must be critical, kind='mysql_udf_loaded', and cite the
    library file name so the operator can grep plugin_dir for it."""
    pr = {("10.0.0.7", 3306): {"reachable": True, "unauth": True, "user": "root",
          "loot": {"loaded_udfs": [
              {"name": "sys_exec", "dl": "lib_mysqludf_sys.so"},
              {"name": "sys_eval", "dl": "lib_mysqludf_sys.so"},
              {"name": "harmless", "dl": "lib_ok.so"}]}}}
    fs = mysql.findings([_mysql_host()], pr)
    udf = [f for f in fs if f["kind"] == "mysql_udf_loaded"]
    assert len(udf) == 1
    f = udf[0]
    assert f["severity"] == "critical"
    assert "sys_exec" in f["detail"] and "lib_mysqludf_sys.so" in f["detail"]


def test_udf_dl_pattern_alone_trips_when_names_are_renamed():
    """Even if the operator renamed the UDF, the backing library
    lib_mysqludf_sys.so is the giveaway — that path substring must also fire."""
    pr = {("10.0.0.7", 3306): {"reachable": True, "unauth": True, "user": "root",
          "loot": {"loaded_udfs": [
              {"name": "runme", "dl": "/usr/lib/mysql/plugin/lib_mysqludf_sys.so"}]}}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    assert "mysql_udf_loaded" in kinds


def test_benign_udfs_get_low_inventory_finding_not_critical():
    """A UDF whose name/library isn't a known RCE primitive still shows up as
    a low-severity inventory line — reviewer can audit the library — but must
    not be labelled critical."""
    pr = {("10.0.0.7", 3306): {"reachable": True, "unauth": True, "user": "root",
          "loot": {"loaded_udfs": [
              {"name": "gis_area", "dl": "libgis.so"}]}}}
    fs = mysql.findings([_mysql_host()], pr)
    kinds = {f["kind"] for f in fs}
    assert "mysql_udf_loaded" not in kinds
    inv = [f for f in fs if f["kind"] == "mysql_udf_inventory"]
    assert len(inv) == 1 and inv[0]["severity"] == "low"


def test_no_udfs_emits_nothing():
    pr = {("10.0.0.7", 3306): {"reachable": True, "unauth": True, "user": "root",
          "loot": {"loaded_udfs": []}}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    assert "mysql_udf_loaded" not in kinds
    assert "mysql_udf_inventory" not in kinds


# ============================================================================
# 4. Version → CVE correlation on the parsed server_version banner
# ============================================================================

def test_parse_version_handles_mysql_and_mariadb_banners():
    assert mysql._parse_mysql_version("8.0.36") == ("mysql", (8, 0, 36))
    assert mysql._parse_mysql_version("5.7.34-log") == ("mysql", (5, 7, 34))
    # MariaDB's compatibility masquerade: '5.5.5-<real>-MariaDB-…'
    assert mysql._parse_mysql_version(
        "5.5.5-10.6.7-MariaDB-1:10.6.7+maria~focal") == ("mariadb", (10, 6, 7))
    assert mysql._parse_mysql_version("") is None
    assert mysql._parse_mysql_version("not-a-version") is None


def test_cve_2012_2122_fires_on_vulnerable_5x_and_not_on_patched():
    # 5.5.22 is at the ceiling — vulnerable.
    pr = {("10.0.0.7", 3306): {"reachable": True, "version": "5.5.22"}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    assert "mysql_cve_cve_2012_2122" in kinds
    # 5.5.23 patched.
    pr = {("10.0.0.7", 3306): {"reachable": True, "version": "5.5.23"}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    assert "mysql_cve_cve_2012_2122" not in kinds
    # 8.0 has never been vulnerable to 2012-2122.
    pr = {("10.0.0.7", 3306): {"reachable": True, "version": "8.0.36"}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    assert "mysql_cve_cve_2012_2122" not in kinds


def test_cve_2021_2154_fires_on_8_0_22_and_not_8_0_23():
    pr = {("10.0.0.7", 3306): {"reachable": True, "version": "8.0.22"}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    assert "mysql_cve_cve_2021_2154" in kinds
    pr = {("10.0.0.7", 3306): {"reachable": True, "version": "8.0.23"}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    assert "mysql_cve_cve_2021_2154" not in kinds


def test_cve_correlation_only_within_the_same_major_minor_train():
    """A 5.6.5 ceiling for CVE-2012-2122 must NOT apply to a 5.7.14 server
    even though the (major, minor, patch) tuple is numerically higher —
    only same-train comparisons are meaningful for a minor-release CVE fix.
    Meanwhile CVE-2016-6662 on 5.7 <5.7.15 must fire on 5.7.14."""
    pr = {("10.0.0.7", 3306): {"reachable": True, "version": "5.7.14"}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    # 2012-2122 5.6 ceiling doesn't leak into 5.7.
    assert "mysql_cve_cve_2012_2122" not in kinds
    # But 5.7 <5.7.15 CVE-2016-6662 DOES fire.
    assert "mysql_cve_cve_2016_6662" in kinds


def test_mariadb_flavor_gate_prevents_false_positive_on_mysql():
    """The MariaDB entry for 2012-2122 must not fire on a same-tuple MySQL
    banner (flavor gate). 10.6.7 MariaDB is modern and clean."""
    pr = {("10.0.0.7", 3306): {"reachable": True,
                                "version": "5.5.5-10.6.7-MariaDB-1"}}
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    assert "mysql_cve_cve_2012_2122" not in kinds


def test_unparseable_version_silently_skips_cve():
    pr = {("10.0.0.7", 3306): {"reachable": True, "version": "who-knows"}}
    # No CVE finding, no exception — version-parse failure is a skip, not a raise.
    kinds = {f["kind"] for f in mysql.findings([_mysql_host()], pr)}
    for k in kinds:
        assert not k.startswith("mysql_cve_"), (
            f"unparseable version leaked into a CVE finding: {k}")
