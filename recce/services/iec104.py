"""IEC 60870-5-104 SCADA probe.

IEC-104 is the TCP transport (2404/tcp) for the IEC 60870-5 telecontrol
protocol used across electric transmission/distribution SCADA. The base
protocol has NO authentication and NO encryption (IEC 62351-3 defines
an optional TLS wrap most fielded gear does not run), so any client that
can reach 2404/tcp can enter data-transfer state (STARTDT) and enumerate
the station's entire process image via General Interrogation.

Coverage here (read-only by default):
  * APCI detection (0x68 START + length octet <= 253) — cheap positive
    protocol ID that beats a bare TCP-open guess.
  * U-format TESTFR act -> TESTFR con liveness (no data-transfer state).
  * U-format STARTDT act -> STARTDT con — the unauthenticated data-
    transfer entry point that gates every downstream ASDU.
  * I-format C_IC_NA_1 (TypeID 100) General Interrogation with COT=6,
    QOI=20 — station-wide process-image dump (M_SP_/M_DP_/M_ME_).
  * Common ASDU Address (CAA) enumeration across a short default list.
  * Optional targeted C_RD_NA_1 (TypeID 102) read for a specific IOA.
  * Vendor fingerprint from private-range TypeIDs (128..255) in replies.
  * IEC 62351-3 TLS-wrap check on the same port.
  * Session-singleton check (second STARTDT while first is live).

Safety (mirrors modbus.py's read-only stance):
  * The module NEVER emits C_SC_NA_1 (45) / C_DC_NA_1 (46) / C_RC_NA_1
    (47) / C_CS_NA_1 (103) / C_RP_NA_1 (105) unless the caller passes
    write=True — an --iec104-write flag class of danger. Even then the
    single/double commands require an explicit target IOA and are never
    swept.

Airgap-safe: stdlib socket + struct + ssl only. All I/O bounded by
proxy.scaled().
"""
from __future__ import annotations

import socket
import ssl
import struct
import time

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 2404
_TIMEOUT = 4.0
_INTERROGATION_BUDGET = 10.0

START = 0x68
MAX_APDU_LEN = 253

# U-format control-field function bits (ctl1). Section 5.3, Table 5.
U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT = 0x13
U_STOPDT_CON = 0x23
U_TESTFR_ACT = 0x43
U_TESTFR_CON = 0x83

# ASDU TypeIDs relevant to the probe (IEC 60870-5-101 §7.2.3).
TI_M_SP_NA_1 = 1
TI_M_DP_NA_1 = 3
TI_M_ME_NA_1 = 9
TI_M_ME_NB_1 = 11
TI_M_ME_NC_1 = 13
TI_C_SC_NA_1 = 45
TI_C_DC_NA_1 = 46
TI_C_RC_NA_1 = 47
TI_C_IC_NA_1 = 100
TI_C_RD_NA_1 = 102
TI_C_CS_NA_1 = 103
TI_C_TS_NA_1 = 104
TI_C_RP_NA_1 = 105

# Cause-of-Transmission values used in this probe (§7.2.3, Table 5).
COT_ACT = 6
COT_ACTCON = 7
COT_ACTTERM = 10
COT_INROGEN = 20
COT_UNKNOWN_TYPEID = 44
COT_UNKNOWN_COT = 45
COT_UNKNOWN_CA = 46
COT_UNKNOWN_IOA = 47

# QOI (Qualifier of Interrogation) — 20 == station interrogation.
QOI_STATION = 20

# Default CAA sweep — a broad sweep would trip OT SIEMs, keep it small.
_DEFAULT_CAA_LIST = (1, 2, 3, 65535)

# Control-type TypeIDs we describe as exposed but do NOT send unless write=True.
_CONTROL_TYPES = {
    TI_C_SC_NA_1: "Single Command",
    TI_C_DC_NA_1: "Double Command",
    TI_C_RC_NA_1: "Regulating Step",
    TI_C_CS_NA_1: "Clock Synchronisation",
    TI_C_RP_NA_1: "Reset Process",
}


def is_iec104(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 2404
            or "iec-104" in svc or "iec104" in svc
            or "iec 60870" in svc or "iec-104" in prod or "iec104" in prod)


# ---------------------------------------------------------------------------
# Frame builders — APCI is a fixed 6 bytes (START + length + 4 control).
# ---------------------------------------------------------------------------
def _u_frame(func_bits: int) -> bytes:
    """U-format APDU. Section 5.3, Table 5. Length octet == 4 (the four
    control octets that follow it)."""
    return bytes([START, 0x04, func_bits, 0x00, 0x00, 0x00])


def _s_frame(nr: int) -> bytes:
    """S-format APDU (supervisory ACK). ctl1 low two bits == 01."""
    ctl3 = (nr & 0x7F) << 1
    ctl4 = (nr >> 7) & 0xFF
    return bytes([START, 0x04, 0x01, 0x00, ctl3, ctl4])


def _i_frame(ns: int, nr: int, asdu: bytes) -> bytes:
    """I-format APDU carrying an ASDU. ctl1 bit 0 == 0.
    ctl1/2 encode N(S), ctl3/4 encode N(R)."""
    ns_bytes = struct.pack("<H", (ns & 0x7FFF) << 1)
    nr_bytes = struct.pack("<H", (nr & 0x7FFF) << 1)
    length = 4 + len(asdu)
    if length > MAX_APDU_LEN:
        raise ValueError("APDU exceeds 253-byte cap")
    return bytes([START, length]) + ns_bytes + nr_bytes + asdu


def _build_asdu(type_id: int, vsq: int, cot: int, orig: int, caa: int,
                payload: bytes) -> bytes:
    """ASDU body with the 2-octet CAA convention IEC-104 uses."""
    return (bytes([type_id, vsq, cot & 0x3F, orig & 0xFF])
            + struct.pack("<H", caa & 0xFFFF)
            + payload)


def _build_general_interrogation(caa: int, ns: int = 0, nr: int = 0,
                                 orig: int = 0) -> bytes:
    payload = bytes([0, 0, 0, QOI_STATION])            # IOA=0 + QOI=20
    asdu = _build_asdu(TI_C_IC_NA_1, 0x01, COT_ACT, orig, caa, payload)
    return _i_frame(ns, nr, asdu)


def _build_read_command(caa: int, ioa: int, ns: int = 0, nr: int = 0,
                        orig: int = 0) -> bytes:
    ioa_bytes = bytes([ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF])
    asdu = _build_asdu(TI_C_RD_NA_1, 0x01, 5, orig, caa, ioa_bytes)  # COT=5 request
    return _i_frame(ns, nr, asdu)


def _cp56time2a(t: float | None = None) -> bytes:
    """CP56Time2a: 7-octet timestamp used by C_CS_NA_1."""
    if t is None:
        t = time.time()
    tm = time.gmtime(t)
    ms = int((t - int(t)) * 1000) + tm.tm_sec * 1000
    out = bytearray(7)
    out[0] = ms & 0xFF
    out[1] = (ms >> 8) & 0xFF
    out[2] = tm.tm_min & 0x3F
    out[3] = tm.tm_hour & 0x1F
    out[4] = ((tm.tm_wday + 1) << 5) | (tm.tm_mday & 0x1F)
    out[5] = tm.tm_mon & 0x0F
    out[6] = (tm.tm_year - 2000) & 0x7F
    return bytes(out)


def _build_clock_sync(caa: int, ns: int = 0, nr: int = 0,
                      orig: int = 0) -> bytes:
    payload = bytes([0, 0, 0]) + _cp56time2a()         # IOA=0 + CP56Time2a
    asdu = _build_asdu(TI_C_CS_NA_1, 0x01, COT_ACT, orig, caa, payload)
    return _i_frame(ns, nr, asdu)


def _build_single_command(caa: int, ioa: int, on: bool, ns: int = 0,
                          nr: int = 0, orig: int = 0) -> bytes:
    """C_SC_NA_1 (TypeID 45). SCO qualifier bit 0 = state, bits 2..7 = QU."""
    ioa_bytes = bytes([ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF])
    sco = 0x01 if on else 0x00
    asdu = _build_asdu(TI_C_SC_NA_1, 0x01, COT_ACT, orig, caa,
                       ioa_bytes + bytes([sco]))
    return _i_frame(ns, nr, asdu)


def _build_reset_process(caa: int, ns: int = 0, nr: int = 0,
                         orig: int = 0) -> bytes:
    """C_RP_NA_1 (TypeID 105). QRP=1 == general reset of process."""
    payload = bytes([0, 0, 0, 0x01])
    asdu = _build_asdu(TI_C_RP_NA_1, 0x01, COT_ACT, orig, caa, payload)
    return _i_frame(ns, nr, asdu)


# ---------------------------------------------------------------------------
# Frame parsers
# ---------------------------------------------------------------------------
def _parse_apci(buf: bytes) -> dict | None:
    """Peek the first APCI in `buf`. Returns
      {kind: 'U'|'S'|'I', length, ctl, ns, nr, apdu (total bytes incl START),
       asdu (bytes payload, may be empty)}
    or None on any malformed prefix."""
    if len(buf) < 6 or buf[0] != START:
        return None
    length = buf[1]
    if length < 4 or length > MAX_APDU_LEN:
        return None
    total = 2 + length
    if len(buf) < total:
        return None
    ctl1, ctl2, ctl3, ctl4 = buf[2], buf[3], buf[4], buf[5]
    if ctl1 & 0x01 == 0:
        kind = "I"
        ns = ((ctl2 << 8) | ctl1) >> 1
        nr = ((ctl4 << 8) | ctl3) >> 1
    elif ctl1 & 0x03 == 0x01:
        kind = "S"
        ns = 0
        nr = ((ctl4 << 8) | ctl3) >> 1
    else:
        kind = "U"
        ns = 0
        nr = 0
    return {"kind": kind, "length": length, "ctl": (ctl1, ctl2, ctl3, ctl4),
            "ns": ns, "nr": nr, "apdu_total": total,
            "asdu": bytes(buf[6:total])}


def _iter_frames(buf: bytes):
    off = 0
    while off < len(buf):
        rest = buf[off:]
        f = _parse_apci(rest)
        if not f:
            # Advance one byte on garbage to resync.
            off += 1
            continue
        yield f
        off += f["apdu_total"]


def _parse_asdu_header(asdu: bytes) -> dict | None:
    """Minimum ASDU header the 2-octet-CAA/2-octet-COT profile requires."""
    if len(asdu) < 6:
        return None
    type_id = asdu[0]
    vsq = asdu[1]
    cot = asdu[2] & 0x3F
    negative = bool(asdu[2] & 0x40)
    test = bool(asdu[2] & 0x80)
    orig = asdu[3]
    caa = struct.unpack("<H", asdu[4:6])[0]
    n_objs = vsq & 0x7F
    seq = bool(vsq & 0x80)
    return {"type_id": type_id, "vsq": vsq, "n_objs": n_objs, "seq": seq,
            "cot": cot, "negative": negative, "test": test,
            "orig": orig, "caa": caa, "objects": asdu[6:]}


def _first_ioa_value(asdu_header: dict) -> tuple[int, str] | None:
    """Best-effort: return (ioa, short-repr) for the first information object
    in an ASDU. Supports the common measurement TypeIDs; unknown TypeIDs
    yield (ioa, '<n bytes>')."""
    obj = asdu_header["objects"]
    if len(obj) < 3:
        return None
    ioa = obj[0] | (obj[1] << 8) | (obj[2] << 16)
    rest = obj[3:]
    ti = asdu_header["type_id"]
    if ti == TI_M_SP_NA_1 and rest:
        return ioa, f"SIQ=0x{rest[0]:02x}"
    if ti == TI_M_DP_NA_1 and rest:
        return ioa, f"DIQ=0x{rest[0]:02x}"
    if ti == TI_M_ME_NA_1 and len(rest) >= 3:
        val = struct.unpack("<h", rest[:2])[0]
        return ioa, f"NVA={val} QDS=0x{rest[2]:02x}"
    if ti == TI_M_ME_NB_1 and len(rest) >= 3:
        val = struct.unpack("<h", rest[:2])[0]
        return ioa, f"SVA={val} QDS=0x{rest[2]:02x}"
    if ti == TI_M_ME_NC_1 and len(rest) >= 5:
        val = struct.unpack("<f", rest[:4])[0]
        return ioa, f"R32={val:.4g} QDS=0x{rest[4]:02x}"
    return ioa, f"<{len(rest)} bytes>"


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------
def _recv_frames(sock, deadline: float, want_at_least: int = 1,
                 idle_timeout: float | None = None) -> list[dict]:
    """Read from `sock` until at least `want_at_least` full APCIs are parsed
    or the wall-clock deadline is reached. Once at least one frame has
    landed, `idle_timeout` (when given) caps the wait for the next chunk —
    so a large collection window does not stall on a station that answered
    but then goes quiet."""
    buf = b""
    frames: list[dict] = []
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if frames and idle_timeout is not None:
            remaining = min(remaining, idle_timeout)
        try:
            sock.settimeout(max(0.05, remaining))
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        # Try to peel as many complete APCIs off the front as possible.
        while buf:
            f = _parse_apci(buf)
            if not f:
                # Not enough bytes yet or garbage — keep listening.
                break
            frames.append(f)
            buf = buf[f["apdu_total"]:]
        if len(frames) >= want_at_least:
            break
    return frames


def _connect(ip: str, port: int, timeout: float,
             wrap_tls: bool = False):
    """TCP connect + optional TLS wrap. Returns the socket or raises OSError."""
    s = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    if wrap_tls:
        ctx = ssl._create_unverified_context()
        return ctx.wrap_socket(s, server_hostname=ip)
    return s


# ---------------------------------------------------------------------------
# Probe orchestration
# ---------------------------------------------------------------------------
def _probe_tls(ip: str, port: int, timeout: float) -> dict:
    """Attempt a TLS handshake — negative outcome is the finding (no IEC
    62351-3 wrap). Return {tls_handshake, cipher, error}."""
    out = {"tls_handshake": False, "cipher": "", "error": ""}
    try:
        raw = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError as e:
        out["error"] = f"connect: {e}"
        return out
    try:
        ctx = ssl._create_unverified_context()
        with ctx.wrap_socket(raw, server_hostname=ip) as ss:
            out["tls_handshake"] = True
            c = ss.cipher()
            if c:
                out["cipher"] = f"{c[0]}"
    except (ssl.SSLError, OSError, ValueError) as e:
        out["error"] = f"tls: {type(e).__name__}"
    finally:
        try:
            raw.close()
        except OSError:
            pass
    return out


def _probe_apci_and_startdt(ip: str, port: int, timeout: float,
                            caa_list: tuple[int, ...],
                            write: bool = False,
                            wrap_tls: bool = False,
                            interrogation_budget: float = _INTERROGATION_BUDGET
                            ) -> dict:
    """One connection: APCI detect + TESTFR + STARTDT + General
    Interrogation + CAA enum + optional writes. Returns the shared probe
    dict (see probe() for the schema)."""
    out: dict = {
        "reachable": False, "apci_valid": False,
        "testfr_ok": False, "startdt_ok": False,
        "interrogation": [], "caa_alive": [], "caa_unknown": [],
        "private_type_ids": [], "vendor_hint": "",
        "clock_sync_accepted": None, "reset_process_accepted": None,
        "single_command_accepted": None,
        "control_types_reachable": [], "wrote": False,
        # T2 SAFE evidence — raw bytes of the first ASDU actually returned
        # after STARTDT + General Interrogation. Captured for concrete
        # server-side proof beyond an APCI-only handshake. Set only when a
        # real I-frame reply landed; never on U/S-only conversations.
        "first_asdu_hex": "", "first_asdu_summary": "",
    }
    try:
        sock = _connect(ip, port, timeout, wrap_tls=wrap_tls)
    except OSError:
        return out
    try:
        deadline = time.monotonic() + proxy.scaled(timeout)
        # 1) TESTFR act — liveness without touching data-transfer state.
        sock.sendall(_u_frame(U_TESTFR_ACT))
        frames = _recv_frames(sock, deadline)
        for f in frames:
            out["reachable"] = True
            out["apci_valid"] = True
            if f["kind"] == "U" and f["ctl"][0] == U_TESTFR_CON:
                out["testfr_ok"] = True
        if not out["apci_valid"]:
            # Some stacks silently drop U-frames before STARTDT — try STARTDT.
            pass

        # 2) STARTDT act — unauthenticated data-transfer entry.
        deadline = time.monotonic() + proxy.scaled(timeout)
        sock.sendall(_u_frame(U_STARTDT_ACT))
        frames = _recv_frames(sock, deadline)
        for f in frames:
            out["reachable"] = True
            out["apci_valid"] = True
            if f["kind"] == "U" and f["ctl"][0] == U_STARTDT_CON:
                out["startdt_ok"] = True
        if not out["startdt_ok"]:
            return out

        # 3) General Interrogation across the CAA shortlist. First alive CAA
        # is the primary; subsequent live CAAs are enumerated.
        ns = 0
        nr = 0
        primary_caa: int | None = None
        for caa in caa_list:
            try:
                sock.sendall(_build_general_interrogation(caa, ns=ns, nr=nr))
            except OSError:
                break
            ns += 1
            end = time.monotonic() + min(
                proxy.scaled(interrogation_budget), proxy.scaled(timeout) * 3)
            batch = _recv_frames(sock, end, want_at_least=1024,
                                 idle_timeout=proxy.scaled(timeout) / 2)
            got_reply = False
            for f in batch:
                if f["kind"] != "I":
                    continue
                nr = (f["ns"] + 1) & 0x7FFF
                hdr = _parse_asdu_header(f["asdu"])
                if not hdr:
                    continue
                got_reply = True
                # T2 SAFE proof: freeze the FIRST real I-frame ASDU response.
                # Even a negative COT (unknown CAA / unknown TypeID) counts —
                # it proves the responder ran the ASDU state machine, not just
                # the APCI parser. Never overwritten by later frames.
                if not out["first_asdu_hex"]:
                    ti = hdr["type_id"]
                    cot = hdr["cot"]
                    caa_r = hdr["caa"]
                    obj = _first_ioa_value(hdr)
                    if obj is not None:
                        summary = (f"TypeID={ti} COT={cot} CAA={caa_r} "
                                   f"IOA={obj[0]} {obj[1]}")
                    else:
                        summary = f"TypeID={ti} COT={cot} CAA={caa_r}"
                    # Reassemble the exact wire APDU (2-byte APCI header +
                    # 4 control octets + ASDU) — length capped by the 255-
                    # byte APDU cap so the finding payload stays bounded.
                    raw = (bytes([START, f["length"]]) + bytes(f["ctl"])
                           + f["asdu"])
                    out["first_asdu_hex"] = raw.hex()
                    out["first_asdu_summary"] = summary
                if hdr["cot"] == COT_UNKNOWN_CA:
                    if caa not in out["caa_unknown"]:
                        out["caa_unknown"].append(caa)
                    continue
                if caa not in out["caa_alive"]:
                    out["caa_alive"].append(caa)
                if primary_caa is None:
                    primary_caa = caa
                if hdr["type_id"] >= 128 and hdr["type_id"] not in out["private_type_ids"]:
                    out["private_type_ids"].append(hdr["type_id"])
                if hdr["type_id"] in (TI_M_SP_NA_1, TI_M_DP_NA_1,
                                      TI_M_ME_NA_1, TI_M_ME_NB_1,
                                      TI_M_ME_NC_1):
                    obj = _first_ioa_value(hdr)
                    if obj and len(out["interrogation"]) < 32:
                        out["interrogation"].append({
                            "caa": caa,
                            "type_id": hdr["type_id"],
                            "cot": hdr["cot"],
                            "ioa": obj[0],
                            "value": obj[1],
                        })
                # Acknowledge periodically to keep the peer sending.
                if len(out["interrogation"]) and len(out["interrogation"]) % 8 == 0:
                    try:
                        sock.sendall(_s_frame(nr))
                    except OSError:
                        break
            if not got_reply:
                continue
            if len(out["interrogation"]) >= 32:
                break

        # 4) Control-type surface. In non-write mode we DESCRIBE only.
        # Any acknowledged STARTDT already proves control types are
        # reachable — the finding text names the specific TypeIDs.
        out["control_types_reachable"] = sorted(_CONTROL_TYPES.keys())

        # 5) Optional writes, gated behind the caller's flag.
        if write and primary_caa is not None:
            try:
                sock.sendall(_build_clock_sync(primary_caa, ns=ns, nr=nr))
                ns += 1
                end = time.monotonic() + proxy.scaled(timeout)
                frames = _recv_frames(sock, end)
                out["clock_sync_accepted"] = any(
                    (f["kind"] == "I" and (h := _parse_asdu_header(f["asdu"]))
                     and h["type_id"] == TI_C_CS_NA_1 and h["cot"] == COT_ACTCON
                     and not h["negative"])
                    for f in frames)
                out["wrote"] = True
            except OSError:
                pass
            try:
                sock.sendall(_build_reset_process(primary_caa, ns=ns, nr=nr))
                ns += 1
                end = time.monotonic() + proxy.scaled(timeout)
                frames = _recv_frames(sock, end)
                out["reset_process_accepted"] = any(
                    (f["kind"] == "I" and (h := _parse_asdu_header(f["asdu"]))
                     and h["type_id"] == TI_C_RP_NA_1 and h["cot"] == COT_ACTCON
                     and not h["negative"])
                    for f in frames)
                out["wrote"] = True
            except OSError:
                pass

        # Vendor hint: two well-known private-range TypeIDs seen in the wild.
        if out["private_type_ids"]:
            out["vendor_hint"] = _vendor_hint(out["private_type_ids"])
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _vendor_hint(private_type_ids: list[int]) -> str:
    """Rough mapping of private-range TypeIDs to vendor families. Empty when
    the fingerprint doesn't match any known cluster — the raw list itself
    is still a stable identifier the operator can carry forward."""
    s = set(private_type_ids)
    if s & {135, 136, 137}:
        return "Siemens SICAM (135-137 seen)"
    if s & {150, 151}:
        return "ABB RTU (150-151 seen)"
    if s & {160, 161, 162}:
        return "GE D20/D400 (160-162 seen)"
    return ""


def _probe_targeted_read(ip: str, port: int, timeout: float, caa: int,
                         ioa: int, wrap_tls: bool = False) -> dict:
    """Second connection: STARTDT + one C_RD_NA_1 for a specific IOA."""
    out = {"reachable": False, "read_ok": False, "value": ""}
    try:
        sock = _connect(ip, port, timeout, wrap_tls=wrap_tls)
    except OSError:
        return out
    try:
        deadline = time.monotonic() + proxy.scaled(timeout)
        sock.sendall(_u_frame(U_STARTDT_ACT))
        _recv_frames(sock, deadline)
        sock.sendall(_build_read_command(caa, ioa))
        end = time.monotonic() + proxy.scaled(timeout)
        frames = _recv_frames(sock, end, want_at_least=1)
        for f in frames:
            if f["kind"] != "I":
                continue
            hdr = _parse_asdu_header(f["asdu"])
            if not hdr or hdr["caa"] != caa:
                continue
            if hdr["negative"] or hdr["cot"] == COT_UNKNOWN_IOA:
                continue
            out["reachable"] = True
            obj = _first_ioa_value(hdr)
            if obj and obj[0] == ioa:
                out["read_ok"] = True
                out["value"] = obj[1]
                break
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return out


def _probe_session_singleton(ip: str, port: int, timeout: float) -> dict:
    """Open two TCP + STARTDT sessions back-to-back. Report which of the
    'refuses second' vs 'displaces first' behaviours we observed."""
    out = {"second_accepted": None, "first_torn_down": None}
    try:
        s1 = _connect(ip, port, timeout)
    except OSError:
        return out
    try:
        d1 = time.monotonic() + proxy.scaled(timeout)
        s1.sendall(_u_frame(U_STARTDT_ACT))
        _recv_frames(s1, d1)
        try:
            s2 = _connect(ip, port, timeout)
        except OSError:
            out["second_accepted"] = False
            return out
        try:
            d2 = time.monotonic() + proxy.scaled(timeout)
            s2.sendall(_u_frame(U_STARTDT_ACT))
            frames2 = _recv_frames(s2, d2)
            out["second_accepted"] = any(
                f["kind"] == "U" and f["ctl"][0] == U_STARTDT_CON
                for f in frames2)
            # Ping the first session — if it's been torn down the TESTFR
            # send/recv will fail or return nothing.
            try:
                s1.sendall(_u_frame(U_TESTFR_ACT))
                d3 = time.monotonic() + proxy.scaled(timeout)
                frames1 = _recv_frames(s1, d3)
                out["first_torn_down"] = not any(
                    f["kind"] == "U" and f["ctl"][0] == U_TESTFR_CON
                    for f in frames1)
            except OSError:
                out["first_torn_down"] = True
        finally:
            try:
                s2.close()
            except OSError:
                pass
    finally:
        try:
            s1.close()
        except OSError:
            pass
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          caa_list: tuple[int, ...] = _DEFAULT_CAA_LIST,
          write: bool = False, singleton_check: bool = False,
          targeted_ioa: tuple[int, int] | None = None) -> dict:
    """Run the read-only IEC-104 probe against ip:port.

    Returns the union of _probe_apci_and_startdt plus optional TLS,
    session-singleton, and targeted-read fields:
      {reachable, apci_valid, testfr_ok, startdt_ok, interrogation[],
       caa_alive[], caa_unknown[], private_type_ids[], vendor_hint,
       control_types_reachable[], clock_sync_accepted, reset_process_accepted,
       single_command_accepted, wrote,
       tls_handshake, tls_cipher,
       session_second_accepted, session_first_torn_down,
       targeted_read_ok, targeted_read_value}
    """
    result = _probe_apci_and_startdt(ip, port, timeout, caa_list, write=write)
    tls = _probe_tls(ip, port, timeout)
    result["tls_handshake"] = tls["tls_handshake"]
    result["tls_cipher"] = tls["cipher"]
    if singleton_check and result.get("startdt_ok"):
        sing = _probe_session_singleton(ip, port, timeout)
        result["session_second_accepted"] = sing["second_accepted"]
        result["session_first_torn_down"] = sing["first_torn_down"]
    else:
        result["session_second_accepted"] = None
        result["session_first_torn_down"] = None
    if targeted_ioa and result.get("startdt_ok"):
        caa, ioa = targeted_ioa
        tr = _probe_targeted_read(ip, port, timeout, caa, ioa)
        result["targeted_read_ok"] = tr["read_ok"]
        result["targeted_read_value"] = tr["value"]
    else:
        result["targeted_read_ok"] = False
        result["targeted_read_value"] = ""
    return result


# ---------------------------------------------------------------------------
# Targets / findings
# ---------------------------------------------------------------------------
def iec104_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_iec104(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "iec104ctl", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_iec104(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            # Reachability / APCI detect.
            liveness_bits = []
            if pr.get("testfr_ok"): liveness_bits.append("TESTFR con")
            if pr.get("startdt_ok"): liveness_bits.append("STARTDT con")
            live_txt = f" ({', '.join(liveness_bits)})" if liveness_bits else ""
            reachable_detail = (
                f"IEC 60870-5-104 responder answered a valid APCI on {tgt}"
                f"{live_txt}. The base protocol has NO authentication and NO "
                f"encryption — any client that can reach 2404/tcp can enter "
                f"data-transfer state and enumerate the station's process "
                f"image. On a corporate/DMZ segment this alone is a "
                f"segmentation gap.")
            # T2 SAFE proof: when the probe captured a real ASDU reply after
            # STARTDT + General Interrogation (single controlled read, no
            # writes, bounded by proxy.scaled), promote reachability from T1
            # (APCI-only handshake) to T2 (station actually spoke the ASDU
            # state machine). Even a negative COT reply proves the responder
            # is not just an APCI echo — it's a real IEC-104 stack.
            reachable_tier = "t1"
            asdu_hex = pr.get("first_asdu_hex") or ""
            asdu_sum = pr.get("first_asdu_summary") or ""
            if asdu_hex and asdu_sum:
                reachable_tier = "t2"
                reachable_detail += (
                    f"\n\nT2 proof — first ASDU response captured after "
                    f"STARTDT + C_IC_NA_1 General Interrogation (single "
                    f"controlled read, no writes):\n"
                    f"    parsed: {asdu_sum}\n"
                    f"    wire:   {asdu_hex}\n"
                    f"A real I-frame ASDU reply confirms the responder ran "
                    f"the IEC 60870-5 application-layer state machine — not "
                    f"just an APCI echo — so the station is genuinely "
                    f"speaking IEC-104 without authentication.")
            out.append(_finding(
                "high",
                "IEC-104 SCADA device on the scanned network", tgt,
                reachable_detail,
                f"nmap -sT -p {p.portid} --script iec-identify {h.ip}",
                "Place SCADA gear on an isolated segment. Where 2404/tcp must "
                "be reachable, front the gateway with an IEC-104-aware "
                "firewall that restricts source addresses and, where the "
                "device supports it, enforce IEC 62351-3 TLS with client "
                "certificates on every session.",
                ["CWE-284", "CWE-923"], kind="iec104_reachable",
                exploit_note=(
                    "printf '\\x68\\x04\\x43\\x00\\x00\\x00' | nc <ip> 2404 | "
                    "xxd (TESTFR act); nmap --script iec-identify -p 2404 <ip>."),
                depth_tier=reachable_tier))

            # STARTDT accepted with no credentials.
            if pr.get("startdt_ok"):
                out.append(_finding(
                    "critical",
                    "IEC-104 accepts STARTDT with no authentication", tgt,
                    "The RTU returned a STARTDT con (U-format ctl1=0x0B) to "
                    "an unauthenticated STARTDT act. Data-transfer state is "
                    "the gate for every downstream ASDU — general "
                    "interrogation, single/double command, clock sync, "
                    "reset process — so an accepted STARTDT is the concrete "
                    "proof that the entire IEC-104 surface is reachable "
                    "without a credential.",
                    f"# raw prove: printf '\\x68\\x04\\x07\\x00\\x00\\x00' | "
                    f"nc {h.ip} {p.portid} | xxd",
                    "Restrict 2404/tcp to the authorised master's source "
                    "address(es) at the segment boundary. Where the RTU "
                    "supports IEC 62351-3, enforce TLS with mutual "
                    "certificate authentication and disable plain 2404 "
                    "entirely.",
                    ["CWE-306", "CWE-319"], kind="iec104_startdt_accepted",
                    exploit_note=(
                        "TEST-CELL ONLY: iec104ctl <ip>:2404 single-command "
                        "--caa 1 --ioa <known_test_ioa> --on. NEVER on live "
                        "substations."),
                    depth_tier="t2"))

            # General Interrogation process-image dump.
            hits = pr.get("interrogation") or []
            if hits:
                sample = "; ".join(
                    f"CAA={r['caa']} TI={r['type_id']} IOA={r['ioa']} {r['value']}"
                    for r in hits[:5])
                out.append(_finding(
                    "critical",
                    "IEC-104 General Interrogation returned the full process image",
                    tgt,
                    f"C_IC_NA_1 (TypeID 100) with COT=6 / QOI=20 returned "
                    f"{len(hits)} information object(s) — analog measurements "
                    f"and single/double points that mirror the station's live "
                    f"process state. First few: {sample}. Read-only, but the "
                    f"same session can issue C_SC_NA_1 (Single Command) to "
                    f"the same IOAs — actuation is one packet away.",
                    f"# read-only prove: iec104ctl {h.ip}:{p.portid} interrogation "
                    f"--caa {pr['caa_alive'][0] if pr.get('caa_alive') else 1}",
                    "Enforce IEC 62351-3 TLS with client-certificate "
                    "authentication on the SCADA transport, or front the RTU "
                    "with a source-IP-restricted proxy. General interrogation "
                    "from an unauthorised source is a segmentation failure.",
                    ["CWE-306", "CWE-200"], kind="iec104_process_image_readable",
                    exploit_note=(
                        "iec104ctl <ip>:2404 interrogation --caa <caa> --for 60 "
                        "(log all telemetry for 60s); identify high-value IOAs "
                        "(breakers/isolators) by IOA range convention (per site)."),
                    depth_tier="t2"))

            # CAA enumeration.
            alive = pr.get("caa_alive") or []
            if len(alive) > 1 or (alive and 65535 in alive):
                out.append(_finding(
                    "medium",
                    "IEC-104 additional Common ASDU Addresses reachable behind the gateway",
                    tgt,
                    f"Interrogation with CAA={alive} answered with valid "
                    f"ASDUs (COT != 46 'unknown common address'). Multiple "
                    f"live CAAs on one gateway typically means the physical "
                    f"device fronts several substations — each is a distinct "
                    f"target for follow-up.",
                    f"# iec104ctl {h.ip}:{p.portid} interrogation --caa <n> for each",
                    "Confirm the CAA list matches the intended substation "
                    "population; retire stale CAAs and log every "
                    "interrogation at the gateway.",
                    ["CWE-200"], kind="iec104_station_addresses",
                    exploit_note=(
                        "For each caa in caa_alive: iec104ctl <ip>:2404 "
                        "interrogation --caa <caa> --limit 1000 — reveals "
                        "each substation's full point list."),
                    depth_tier="t1"))

            # Control-type surface (paired with STARTDT accepted).
            if pr.get("startdt_ok") and pr.get("control_types_reachable"):
                names = ", ".join(
                    f"TypeID {ti} {_CONTROL_TYPES[ti]}"
                    for ti in pr["control_types_reachable"])
                out.append(_finding(
                    "critical",
                    "IEC-104 control write types reachable — unauthenticated actuation of physical equipment",
                    tgt,
                    f"With data-transfer state open, the RTU accepts control "
                    f"ASDUs on the same session: {names}. Recce did NOT send "
                    f"them (a stray Single Command trips real breakers) but "
                    f"the surface is confirmed by the successful STARTDT — "
                    f"any of these from a compromised master directly "
                    f"operates primary equipment (breakers, isolators, "
                    f"regulators) or reinitialises the outstation.",
                    f"# READ-ONLY inventory only: iec104ctl {h.ip}:{p.portid} "
                    f"interrogation --caa {alive[0] if alive else 1}",
                    "IEC 62351-3 TLS + mutual certificate auth on the SCADA "
                    "transport is the primary control. Where the fielded RTU "
                    "cannot terminate TLS, enforce a hardware-based source "
                    "allowlist at the substation boundary and log every "
                    "control ASDU at the gateway.",
                    ["CWE-306", "CWE-284", "CWE-807"],
                    kind="iec104_control_writable",
                    exploit_note=(
                        "TEST-CELL ONLY: iec104ctl <ip>:2404 single-command "
                        "--caa 1 --ioa <ioa> --on; observe the corresponding "
                        "M_SP change in the next interrogation. Never on "
                        "production."),
                    depth_tier="t1"))

            # Actual clock write (only when write=True was passed).
            if pr.get("clock_sync_accepted"):
                out.append(_finding(
                    "critical",
                    "IEC-104 clock synchronisation (C_CS_NA_1) writable — SOE forensic integrity at risk",
                    tgt,
                    "C_CS_NA_1 (TypeID 103) with a CP56Time2a payload was "
                    "acknowledged by the RTU (COT=7 activation confirm, "
                    "P/N=0). An unauthenticated write to the outstation's "
                    "real-time clock desynchronises SOE (sequence-of-events) "
                    "logs and breaks post-incident forensics for every "
                    "downstream event.",
                    f"# gated: iec104ctl {h.ip}:{p.portid} clock-sync --caa "
                    f"{alive[0] if alive else 1}",
                    "Enforce IEC 62351-3; where not feasible, hard-restrict "
                    "the master's source at the boundary and require an "
                    "external, trusted time source (PTP with authenticated "
                    "grandmaster) rather than the SCADA transport.",
                    ["CWE-306", "CWE-345"], kind="iec104_clock_writable",
                    exploit_note=(
                        "TEST-CELL ONLY: iec104ctl <ip>:2404 clock-sync --caa "
                        "<caa> --time '1970-01-01T00:00:00Z' (or drifted); "
                        "verify the RTU's SOE timestamps now diverge from grid "
                        "time."),
                    depth_tier="t3"))

            if pr.get("reset_process_accepted"):
                out.append(_finding(
                    "critical",
                    "IEC-104 Reset Process (C_RP_NA_1) reachable — unauthenticated remote RTU reboot",
                    tgt,
                    "C_RP_NA_1 (TypeID 105) with QRP=1 was acknowledged by "
                    "the RTU. Any master session can force the outstation "
                    "application to reinitialise — a remote reboot with no "
                    "credential requirement.",
                    f"# gated: iec104ctl {h.ip}:{p.portid} reset --caa "
                    f"{alive[0] if alive else 1}",
                    "Restrict 2404/tcp to the master's source at the segment "
                    "boundary and enforce IEC 62351-3 with mutual auth.",
                    ["CWE-306", "CWE-1327"], kind="iec104_reset_writable",
                    exploit_note=(
                        "TEST-CELL ONLY: iec104ctl <ip>:2404 reset --caa <caa>; "
                        "verify all points drop for the boot cycle. NEVER on "
                        "production."),
                    depth_tier="t3"))

            # TLS wrap check — negative outcome is the finding.
            if not pr.get("tls_handshake"):
                out.append(_finding(
                    "medium",
                    "IEC-104 transported in cleartext (no IEC 62351-3 TLS)", tgt,
                    "A TLS ClientHello to 2404/tcp did not complete a "
                    "handshake — the SCADA transport runs cleartext. Every "
                    "IEC-104 frame (interrogation replies, control commands, "
                    "clock sync) is readable and modifiable by anyone on the "
                    "path.",
                    f"openssl s_client -connect {h.ip}:{p.portid} -quiet",
                    "Enable IEC 62351-3 on the RTU/gateway and require TLS "
                    "on 2404/tcp. Provision per-master client certificates; "
                    "disable plaintext IEC-104 after the transition.",
                    ["CWE-319", "CWE-311"], kind="iec104_no_tls",
                    exploit_note=(
                        "tcpdump -w /tmp/104.pcap 'host <ip> and port 2404'; "
                        "capture a legit master session to prove "
                        "interrogation/control content is readable on the "
                        "wire."),
                    depth_tier="t1"))
            else:
                out.append(_finding(
                    "info",
                    "IEC-104 endpoint accepted TLS (IEC 62351-3 candidate)", tgt,
                    f"TLS handshake completed on {tgt} "
                    f"({pr.get('tls_cipher') or 'unknown cipher'}). "
                    f"Confirm the peer requires a client certificate; if it "
                    f"accepts an anonymous client, the transport is TLS-in-"
                    f"name-only.",
                    f"openssl s_client -connect {h.ip}:{p.portid} -showcerts",
                    "Verify mutual authentication is enforced (IEC 62351-3 "
                    "§5).", [], kind="iec104_tls_present",
                    exploit_note=(
                        "openssl s_client -connect <ip>:2404 -showcerts (no "
                        "client cert); if it completes, the peer accepts any "
                        "client — IEC 62351-3 §5 mutual auth is not "
                        "enforced."),
                    depth_tier="t0"))

            # Vendor fingerprint from private TypeIDs.
            if pr.get("private_type_ids"):
                out.append(_finding(
                    "info",
                    "IEC-104 vendor / RTU model identified", tgt,
                    f"Private-range TypeIDs seen in interrogation replies: "
                    f"{pr['private_type_ids']}"
                    + (f" -> {pr['vendor_hint']}" if pr.get("vendor_hint")
                       else "")
                    + ". This fingerprint feeds vendor-specific CVE lookup "
                    "(Siemens SICAM, ABB RTU5xx, GE D20/D400, SEL) and "
                    "default-credential shortlists for the HMI that fronts "
                    "the device.",
                    f"# iec104ctl {h.ip}:{p.portid} fingerprint",
                    "Informational — pairs with the reachability finding.",
                    [], kind="iec104_vendor_identified",
                    exploit_note=(
                        "Correlate against Siemens/ABB/GE/SEL/Schneider "
                        "IEC-104 advisories; check the RTU's web UI on "
                        "80/443 for default creds (SICAM: admin/100, "
                        "RTU5xx: admin/admin)."),
                    depth_tier="t0"))

            # Targeted read (medium-severity capability).
            if pr.get("targeted_read_ok"):
                out.append(_finding(
                    "medium",
                    "IEC-104 targeted per-IOA read succeeded without authentication",
                    tgt,
                    f"C_RD_NA_1 (TypeID 102) for a specific IOA returned "
                    f"{pr.get('targeted_read_value')} — per-object reads are "
                    f"unauthenticated. Combined with the interrogation "
                    f"IOA-list this is a repeatable, low-noise read primitive "
                    f"a tester can point at any known point.",
                    f"# iec104ctl {h.ip}:{p.portid} read --ioa <n>",
                    "Restrict source of 2404/tcp; enforce IEC 62351-3.",
                    ["CWE-306"], kind="iec104_ioa_read_ok",
                    exploit_note=(
                        "iec104ctl <ip>:2404 read --caa <caa> --ioa <n>; "
                        "loop over the IOA-list from interrogation for "
                        "continuous per-object monitoring."),
                    depth_tier="t2"))

            # Session-singleton.
            if pr.get("session_second_accepted") is True and \
                    pr.get("session_first_torn_down") is True:
                out.append(_finding(
                    "medium",
                    "IEC-104 session singleton: legitimate master can be forcibly displaced",
                    tgt,
                    "A second TCP + STARTDT while the first session was "
                    "still live TORE DOWN the first — an attacker who "
                    "reaches 2404/tcp can displace the legitimate SCADA "
                    "master. Any control ASDU issued from the attacker's "
                    "session is then delivered on the master's connection "
                    "slot, and the master reconnects into a spoofable state.",
                    f"# lab-only prove: two concurrent iec104ctl {h.ip}:{p.portid}",
                    "Where the RTU's single-controlling-station design is "
                    "required (IEC 60870-5-104 Annex A), enforce network-"
                    "layer source restriction so no unauthorised host can "
                    "open the displacing second session.",
                    ["CWE-287"], kind="iec104_session_hijack",
                    exploit_note=(
                        "LAB ONLY: open two concurrent iec104ctl sessions; "
                        "while the second is live, issue interrogation/"
                        "control from it while the operator's HMI sees "
                        "connection drop then reconnect. Never on "
                        "production."),
                    depth_tier="t2"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "APCI detect / TESTFR liveness",
         "cmd": f"printf '\\x68\\x04\\x43\\x00\\x00\\x00' | nc {ip} {port} | xxd"},
        {"step": "STARTDT (enter data-transfer state)",
         "cmd": f"printf '\\x68\\x04\\x07\\x00\\x00\\x00' | nc {ip} {port} | xxd"},
        {"step": "General Interrogation (nmap NSE)",
         "cmd": f"nmap -sT -p {port} --script iec-identify {ip}"},
        {"step": "Passive TLS handshake check",
         "cmd": f"openssl s_client -connect {ip}:{port} -quiet"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "iec104", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            write: bool = False, caa_list: tuple[int, ...] = _DEFAULT_CAA_LIST,
            singleton_check: bool = False,
            targeted_ioa: tuple[int, int] | None = None) -> dict:
    """Analyze IEC-104 targets. `write=True` (from --iec104-write) unlocks
    the C_CS_NA_1 / C_RP_NA_1 probes — off by default because a stray Single
    Command on live grid equipment trips real breakers."""
    from . import svcprobe
    targets = iec104_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], write=write,
                                caa_list=caa_list,
                                singleton_check=singleton_check,
                                targeted_ioa=targeted_ioa),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["startdt_ok"] = pr.get("startdt_ok", False)
                t["caa_alive"] = pr.get("caa_alive", [])
                t["vendor_hint"] = pr.get("vendor_hint", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "wrote": write,
                      "stopped": state.get("stopped")}}
