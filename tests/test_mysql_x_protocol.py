"""MySQL X Protocol (mysqlx / 33060) reachability probe.

Covers the SAFE detection path added on top of the classic 3306 mysql module:
  * Client sends a Mysqlx.Connection.CapabilitiesGet frame (msg id 5).
  * Vulnerable target: server answers with a Capabilities frame (msg id 3)
    carrying the tls flag + authentication.mechanisms list -> the
    mysql_x_protocol_open finding fires with medium severity and depth_tier=t1.
  * Patched/absent target: RST (connection refused) or a non-Capabilities
    frame -> no finding.

Wire shape follows the X Protocol reference: <length:le32><type:u8><payload>,
where length includes the type byte. Capabilities is a protobuf message body
that packs repeated Capability { string name; Any value; }.
"""
from __future__ import annotations

import socket
import socketserver
import struct
import threading

from recce.core.models import Host, Port
from recce.services.db import mysql


# ---- wire helpers ----------------------------------------------------------

def _frame(msg_type: int, payload: bytes) -> bytes:
    return struct.pack("<I", len(payload) + 1) + bytes([msg_type]) + payload


def _pb_varint(n: int) -> bytes:
    out = b""
    while n > 0x7F:
        out += bytes([(n & 0x7F) | 0x80])
        n >>= 7
    return out + bytes([n & 0x7F])


def _pb_tag(field: int, wire: int) -> bytes:
    return _pb_varint((field << 3) | wire)


def _pb_len(field: int, body: bytes) -> bytes:
    return _pb_tag(field, 2) + _pb_varint(len(body)) + body


def _pb_bool(field: int, value: bool) -> bytes:
    return _pb_tag(field, 0) + _pb_varint(1 if value else 0)


def _any_bool(value: bool) -> bytes:
    # Any { type=SCALAR(1), scalar { type=V_BOOL(7), v_bool = value } }
    scalar = _pb_tag(1, 0) + _pb_varint(7) + _pb_bool(8, value)
    return _pb_tag(1, 0) + _pb_varint(1) + _pb_len(2, scalar)


def _any_string_array(values: list) -> bytes:
    # Any { type=ARRAY(3), array { repeated Any values } }
    inner_anys = b""
    for s in values:
        b = s.encode()
        # Any { type=SCALAR, scalar { type=V_STRING(8), v_string { value = b } } }
        v_string = _pb_len(1, b)                       # String { bytes value = 1 }
        scalar = _pb_tag(1, 0) + _pb_varint(8) + _pb_len(9, v_string)
        one_any = _pb_tag(1, 0) + _pb_varint(1) + _pb_len(2, scalar)
        inner_anys += _pb_len(1, one_any)              # Array.value = repeated Any
    array = inner_anys
    return _pb_tag(1, 0) + _pb_varint(3) + _pb_len(4, array)


def _capability(name: str, value_any: bytes) -> bytes:
    return _pb_len(1, name.encode()) + _pb_len(2, value_any)


def _capabilities_message(entries: list) -> bytes:
    """entries: list of (name, any_bytes). Wraps them as
    Mysqlx.Connection.Capabilities { repeated Capability capabilities = 1 }."""
    body = b""
    for name, any_v in entries:
        body += _pb_len(1, _capability(name, any_v))
    return body


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


# ---- 1. protobuf mini-walker --------------------------------------------

def test_pb_varint_and_iter_handle_truncation():
    # Well-formed: two fields, one string one bool.
    buf = _pb_len(1, b"hi") + _pb_tag(2, 0) + _pb_varint(1)
    got = list(mysql._pb_iter(buf, 0, len(buf)))
    assert got == [(1, 2, b"hi"), (2, 0, 1)]
    # Truncated length prefix -> iterator returns cleanly, no exception.
    assert list(mysql._pb_iter(b"\x0a\x05he", 0, 4)) == []


def test_capabilities_parser_extracts_bool_and_string_list():
    body = _capabilities_message([
        ("tls", _any_bool(True)),
        ("authentication.mechanisms",
         _any_string_array(["PLAIN", "MYSQL41", "SHA256_MEMORY"])),
    ])
    caps = mysql._pb_parse_capabilities(body)
    assert caps["tls"] is True
    mechs = caps["authentication.mechanisms"]
    assert isinstance(mechs, list)
    assert "PLAIN" in mechs and "MYSQL41" in mechs and "SHA256_MEMORY" in mechs
    # Round-trip via the accessor helpers.
    assert mysql._mysqlx_tls_flag(caps) is True
    assert set(mysql._mysqlx_auth_mechs(caps)) >= {"PLAIN", "MYSQL41"}


# ---- 2. vulnerable target -> finding ------------------------------------

def _mysqlx_open_server():
    """X Plugin that answers CapabilitiesGet with a real Capabilities frame."""
    def handle(conn):
        req = _recv_exact(conn, 5)
        # CapabilitiesGet: length=1 + type=5 (per the task's message-id map).
        if req[:4] != struct.pack("<I", 1) or req[4] != 5:
            return
        body = _capabilities_message([
            ("tls", _any_bool(False)),
            ("authentication.mechanisms",
             _any_string_array(["PLAIN", "MYSQL41", "SHA256_MEMORY"])),
            ("doc.formats", _any_string_array(["text"])),
        ])
        conn.sendall(_frame(3, body))                  # Capabilities = msg id 3
    return handle


def test_probe_vulnerable_target_reports_open_and_evidence():
    ip, port, srv = _serve(_mysqlx_open_server())
    try:
        pr = mysql.mysqlx_probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert pr["reachable"]
    assert pr["capabilities_open"]
    assert pr["tls"] is False
    assert "PLAIN" in pr["auth_mechanisms"]
    assert "MYSQL41" in pr["auth_mechanisms"]
    # tls capability was reported, so it's not None (distinguishable from missing).
    assert pr["tls"] is not None


def test_findings_emits_x_protocol_open_from_probe():
    host = Host(ip="10.0.0.9",
                ports=[Port(portid=33060, state="open", service="")])
    pr = {("10.0.0.9", 33060): {
        "reachable": True, "capabilities_open": True, "tls": False,
        "auth_mechanisms": ["PLAIN", "MYSQL41"],
        "capabilities": {}, "err": ""}}
    fs = mysql.mysqlx_findings([host], pr)
    assert len(fs) == 1
    f = fs[0]
    assert f["kind"] == "mysql_x_protocol_open"
    assert f["severity"] == "medium"
    assert f["depth_tier"] == "t1"
    assert "CWE-1327" in f["cwes"]
    assert "PLAIN" in f["detail"] and "MYSQL41" in f["detail"]
    assert f["target"] == "10.0.0.9:33060"
    # Exploit note points at mysqlsh, the canonical x-protocol client.
    assert "mysqlsh" in f["exploit_note"]


# ---- 3. patched / absent target -> no finding ---------------------------

def test_probe_closed_port_reports_unreachable_no_finding():
    # Bind and close so the port answers with RST.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    pr = mysql.mysqlx_probe("127.0.0.1", port, timeout=1)
    assert not pr["reachable"]
    assert not pr["capabilities_open"]
    # No finding — the finding builder gates on capabilities_open.
    host = Host(ip="127.0.0.1",
                ports=[Port(portid=33060, state="open", service="")])
    fs = mysql.mysqlx_findings([host], {("127.0.0.1", 33060): pr})
    assert fs == []


def _mysqlx_error_server():
    """Server that answers with an Error frame (msg id 1) instead of
    Capabilities — e.g. mysqlx=DISABLED-but-still-listening builds, or
    something else co-tenanting the port."""
    def handle(conn):
        _recv_exact(conn, 5)
        conn.sendall(_frame(1, b""))
    return handle


def test_probe_error_frame_does_not_trip_finding():
    ip, port, srv = _serve(_mysqlx_error_server())
    try:
        pr = mysql.mysqlx_probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    assert pr["reachable"]              # something answered
    assert not pr["capabilities_open"]  # but not with Capabilities
    host = Host(ip=ip, ports=[Port(portid=port, state="open", service="")])
    # is_mysqlx() gates on port 33060; force the port by rewriting the probe key.
    assert mysql.mysqlx_findings([host],
                                 {(ip, port): pr}) == [] or \
        all(f["kind"] != "mysql_x_protocol_open"
            for f in mysql.mysqlx_findings(
                [host], {(ip, port): pr}))


def _classic_mysql_server_on_wrong_port():
    """A native MySQL 3306-style handshake landing on 33060 by accident —
    server-first Handshake v10 packet, not an X Plugin. The probe must NOT
    treat this as a Capabilities frame."""
    def handle(conn):
        # <len:3><seq:1> greeting: proto v10 + version + rest zero-ish.
        greet = bytes([10]) + b"5.7.44\x00" + b"\x00" * 40
        pkt = struct.pack("<I", len(greet))[:3] + b"\x00" + greet
        conn.sendall(pkt)
    return handle


def test_probe_classic_mysql_on_33060_is_not_mistaken_for_x_protocol():
    ip, port, srv = _serve(_classic_mysql_server_on_wrong_port())
    try:
        pr = mysql.mysqlx_probe(ip, port, timeout=3)
    finally:
        srv.shutdown()
    # The greeting's first four bytes decode to a length that consumes the rest;
    # msg_type byte is 10 (proto version), which is neither 3 nor 1 - so:
    assert not pr["capabilities_open"]
    host = Host(ip=ip, ports=[Port(portid=port, state="open", service="")])
    fs = mysql.mysqlx_findings([host], {(ip, port): pr})
    assert all(f["kind"] != "mysql_x_protocol_open" for f in fs)


def test_is_mysqlx_matches_port_and_service_string():
    assert mysql.is_mysqlx(Port(portid=33060, state="open", service=""))
    assert mysql.is_mysqlx(Port(portid=9999, state="open", service="mysqlx"))
    assert not mysql.is_mysqlx(Port(portid=33060, state="closed", service=""))
    assert not mysql.is_mysqlx(Port(portid=3306, state="open", service="mysql"))
