"""DNP3 (IEEE 1815) — SCADA/OT master-outstation probe.

DNP3 is the North American SCADA protocol for electric/water utilities. The
base protocol has no authentication (Secure Authentication SAv2/SAv5 is an
optional bolt-on rarely enabled), so any reachable outstation exposes physical
process data and control primitives (Operate / Direct Operate / Cold Restart /
Warm Restart) to anyone on the link. A DNP3 device on a corporate/DMZ segment
is by itself a segmentation gap.

Coverage here:
  * Data-Link REQUEST_LINK_STATUS (FC9) + 0x0564 sync + CRC-16-DNP verification
    (positive protocol ID that distinguishes DNP3 from arbitrary services).
  * Application FC1 Read of Class 0 static data (g60v1) — proves the peer is a
    real outstation and confirms plain Read is accepted without SA (§7).
  * Application FC1 Read of Group 0 device attributes (g0v240/242/243/250/252)
    for vendor / product / firmware / site name / serial → feeds CVE mapper.
  * Outstation source-address disclosure (2-byte LE from every reply).
  * IIN (Internal Indications) parsing: device restart, trouble, need time,
    local control, config-corrupt.
  * Broadcast-read behaviour check against 0xFFFD (application confirm form).
  * Brief passive unsolicited-response listen after link identification.
  * FC23 Delay Measurement as a second-source liveness check.
  * UDP variant (§7.2) on 20000/udp.

Safety (mirrors modbus.py's read-only stance):
  * NEVER emits FC3/4/5/6/13/14/15/16/17/18/20/21/22/31 — those change plant
    state and can trip protection relays. Read-only means FC1 Read, FC23
    Delay Measurement, and Data-Link FC9 Request-Link-Status only.

Airgap-safe: stdlib socket + struct only. All I/O bounded by proxy.scaled().
"""
from __future__ import annotations

import socket
import struct
import time

from ..core import proxy
from ..core.models import Host, Port

_DEFAULT_PORT = 20000
_TIMEOUT = 4.0

# Data-Link function codes (primary frames, from master).
_DL_FC_UNCONFIRMED_UD = 0x04
_DL_FC_REQ_LINK_STATUS = 0x09

# Data-Link control-byte bits.
_DL_DIR_MASTER = 0x80
_DL_PRM_PRIMARY = 0x40

# Broadcast destination addresses (§10.2.3).
_BCAST_NEEDS_APP_CONF = 0xFFFD
_BCAST_NEEDS_DL_CONF = 0xFFFE
_BCAST_NO_CONF = 0xFFFF

# Application function codes we send (read-only).
_APP_FC_READ = 0x01
_APP_FC_DELAY_MEAS = 0x17
_APP_FC_RESPONSE = 0x81
_APP_FC_UNSOLICITED = 0x82

# Application-control bits.
_APP_FIR = 0x80
_APP_FIN = 0x40
_APP_CON = 0x20
_APP_UNS = 0x10

# Transport-control bits.
_TP_FIN = 0x80
_TP_FIR = 0x40

# Object groups.
_G_DEVICE_ATTR = 0
_G_CLASS_DATA = 60
_G_AUTH = 120

# Group 0 device-attribute variations we harvest (§11.2).
_G0_ATTR_NAMES = {
    240: "software_version",
    242: "vendor",
    243: "location",
    250: "device_name",
    252: "serial",
}

# Dangerous function codes an unauthenticated outstation exposes (§5.3 Tbl 5-1).
# We NEVER send these — recce only names them in findings as the control surface.
_DANGEROUS_FCS = {
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate No Ack",
    13: "Cold Restart",
    14: "Warm Restart",
    15: "Initialize Data",
    16: "Initialize Application",
    17: "Start Application",
    18: "Stop Application",
    20: "Enable Unsolicited",
    21: "Disable Unsolicited",
    22: "Assign Class",
    31: "Save Configuration",
}


def is_dnp3(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in range(20000, 20010)
            or "dnp3" in svc or "dnp3" in prod)


# ---------------------------------------------------------------------------
# CRC-16-DNP (§8.2.6): polynomial 0x3D65, reflected form 0xA6BC, init 0x0000,
# reflect input and output, XOR-out 0xFFFF, transmitted low byte first.
# ---------------------------------------------------------------------------
def _crc_dnp(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (crc ^ 0xFFFF) & 0xFFFF


def _with_block_crcs(user_data: bytes) -> bytes:
    """Append CRC-16-DNP after every 16 bytes of user data (§8.2.5)."""
    out = b""
    for i in range(0, len(user_data), 16):
        block = user_data[i:i + 16]
        out += block + struct.pack("<H", _crc_dnp(block))
    return out


# ---------------------------------------------------------------------------
# Frame builders (read-only paths only)
# ---------------------------------------------------------------------------
def _build_dl_frame(fc: int, dst: int, src: int, user_data: bytes = b"",
                    dir_master: bool = True, prm_primary: bool = True) -> bytes:
    ctrl = 0
    if dir_master:
        ctrl |= _DL_DIR_MASTER
    if prm_primary:
        ctrl |= _DL_PRM_PRIMARY
    ctrl |= (fc & 0x0F)
    length = 5 + len(user_data)                 # CTRL + DST(2) + SRC(2) + user
    header = struct.pack("<BBBBHH", 0x05, 0x64, length, ctrl, dst, src)
    header_crc = struct.pack("<H", _crc_dnp(header))
    return header + header_crc + _with_block_crcs(user_data)


def _build_request_link_status(dst: int, src: int) -> bytes:
    return _build_dl_frame(_DL_FC_REQ_LINK_STATUS, dst, src)


def _build_read_request(dst: int, src: int, app_seq: int, tp_seq: int,
                        object_headers: bytes) -> bytes:
    app_ctrl = _APP_FIR | _APP_FIN | (app_seq & 0x0F)
    app = bytes([app_ctrl, _APP_FC_READ]) + object_headers
    tp = bytes([_TP_FIN | _TP_FIR | (tp_seq & 0x3F)])
    return _build_dl_frame(_DL_FC_UNCONFIRMED_UD, dst, src, tp + app)


def _oh_g60v1_all() -> bytes:
    """Object header: g60v1 qualifier 0x06 (no range, all points)."""
    return bytes([_G_CLASS_DATA, 1, 0x06])


def _oh_g0_range(variation: int) -> bytes:
    """g0 vX, qualifier 0x00 (1-octet start/stop indexes), index 0..0."""
    return bytes([_G_DEVICE_ATTR, variation, 0x00, 0x00, 0x00])


def _build_g60v1_read(dst: int = 1, src: int = 1, app_seq: int = 0,
                      tp_seq: int = 0) -> bytes:
    return _build_read_request(dst, src, app_seq, tp_seq, _oh_g60v1_all())


def _build_g0_read(variation: int, dst: int = 1, src: int = 1,
                   app_seq: int = 0, tp_seq: int = 0) -> bytes:
    return _build_read_request(dst, src, app_seq, tp_seq, _oh_g0_range(variation))


def _build_delay_measurement(dst: int = 1, src: int = 1, app_seq: int = 0,
                             tp_seq: int = 0) -> bytes:
    app_ctrl = _APP_FIR | _APP_FIN | (app_seq & 0x0F)
    app = bytes([app_ctrl, _APP_FC_DELAY_MEAS])
    tp = bytes([_TP_FIN | _TP_FIR | (tp_seq & 0x3F)])
    return _build_dl_frame(_DL_FC_UNCONFIRMED_UD, dst, src, tp + app)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def _parse_dl_header(data: bytes) -> dict | None:
    if len(data) < 10 or data[0] != 0x05 or data[1] != 0x64:
        return None
    length = data[2]
    if length < 5:
        return None
    header = data[:8]
    got = struct.unpack("<H", data[8:10])[0]
    if got != _crc_dnp(header):
        return None
    ctrl = data[3]
    dst = struct.unpack("<H", data[4:6])[0]
    src = struct.unpack("<H", data[6:8])[0]
    return {"length": length, "ctrl": ctrl, "dst": dst, "src": src,
            "fc": ctrl & 0x0F, "dir_master": bool(ctrl & 0x80),
            "prm_primary": bool(ctrl & 0x40),
            "dfc": bool(ctrl & 0x10),
            "user_data_len": length - 5}


def _extract_user_data(data: bytes, dl: dict) -> bytes | None:
    ud_len = dl["user_data_len"]
    if ud_len == 0:
        return b""
    out = b""
    off = 10
    remaining = ud_len
    while remaining > 0:
        take = min(16, remaining)
        block = data[off:off + take]
        if len(block) < take:
            return None
        crc_bytes = data[off + take:off + take + 2]
        if len(crc_bytes) < 2:
            return None
        got = struct.unpack("<H", crc_bytes)[0]
        if got != _crc_dnp(block):
            return None
        out += block
        off += take + 2
        remaining -= take
    return out


def _parse_iin(iin1: int, iin2: int) -> list[str]:
    flags = []
    if iin1 & 0x80: flags.append("device_restart")
    if iin1 & 0x40: flags.append("device_trouble")
    if iin1 & 0x20: flags.append("local_control")
    if iin1 & 0x10: flags.append("need_time")
    if iin1 & 0x08: flags.append("class3_events")
    if iin1 & 0x04: flags.append("class2_events")
    if iin1 & 0x02: flags.append("class1_events")
    if iin1 & 0x01: flags.append("broadcast_msg_received")
    if iin2 & 0x20: flags.append("config_corrupt")
    if iin2 & 0x10: flags.append("already_executing")
    if iin2 & 0x08: flags.append("event_buffer_overflow")
    if iin2 & 0x04: flags.append("parameter_error")
    if iin2 & 0x02: flags.append("object_unknown")
    if iin2 & 0x01: flags.append("no_func_code_support")
    return flags


def _parse_response(data: bytes) -> dict | None:
    dl = _parse_dl_header(data)
    if not dl:
        return None
    ud = _extract_user_data(data, dl)
    if ud is None:
        return None
    out: dict = {"dst": dl["dst"], "src": dl["src"], "dl_fc": dl["fc"],
                 "dfc": dl["dfc"], "dir_master": dl["dir_master"],
                 "tp": ud[0] if ud else None,
                 "app_ctrl": None, "app_fc": None, "objects_raw": b"",
                 "uns": False}
    if dl["fc"] != _DL_FC_UNCONFIRMED_UD or len(ud) < 3:
        # Data-Link-only reply (e.g. link-status secondary FC 11) — no app layer.
        return out
    app_ctrl = ud[1]
    app_fc = ud[2]
    out["app_ctrl"] = app_ctrl
    out["app_fc"] = app_fc
    out["uns"] = bool(app_ctrl & _APP_UNS)
    out["fir"] = bool(app_ctrl & _APP_FIR)
    out["fin"] = bool(app_ctrl & _APP_FIN)
    if app_fc in (_APP_FC_RESPONSE, _APP_FC_UNSOLICITED):
        if len(ud) < 5:
            return None
        out["iin1"] = ud[3]
        out["iin2"] = ud[4]
        out["iin_flags"] = _parse_iin(ud[3], ud[4])
        out["objects_raw"] = ud[5:]
    else:
        out["objects_raw"] = ud[3:]
    return out


def _extract_g0_attribute(objects_raw: bytes) -> str:
    """Parse a Group 0 device-attribute response body. On a response to our
    qualifier-0x00 range request the layout is:
      g(1) v(1) q(1) start(1) stop(1) [ data_type(1) len(1) bytes ]
    Falls back to the first printable ASCII run when the type/length header is
    absent or malformed — some vendors return the raw string directly."""
    if len(objects_raw) < 3:
        return ""
    if objects_raw[0] != _G_DEVICE_ATTR:
        return ""
    q = objects_raw[2]
    off = 3
    if q == 0x00:
        off += 2                                # 1-byte start + 1-byte stop
    elif q == 0x01:
        off += 4                                # 2-byte start + 2-byte stop
    elif q == 0x17 or q == 0x28:
        off += 1                                # count-prefixed
    if off >= len(objects_raw):
        return ""
    payload = objects_raw[off:]
    if len(payload) >= 2:
        dtype = payload[0]
        dlen = payload[1]
        # DNP3 g0 visible-string attribute: type 0x01, then length, then bytes.
        if dtype == 0x01 and 2 + dlen <= len(payload):
            return payload[2:2 + dlen].decode("utf-8", "replace")[:80]
    # Fallback: longest printable run.
    run = bytearray()
    for b in payload:
        if 0x20 <= b < 0x7F:
            run.append(b)
        elif run:
            break
    return run.decode("ascii", "replace")[:80]


def _count_object_groups(objects_raw: bytes) -> dict:
    """Best-effort walk. Returns {'first_groups': [g,...]} — as far as we can
    advance. Detailed decode of every static-object payload is out of scope;
    we only need enough to prove real objects came back."""
    out: dict = {"first_groups": [], "count": 0}
    off = 0
    n = len(objects_raw)
    while off + 3 <= n and out["count"] < 8:
        g = objects_raw[off]
        v = objects_raw[off + 1]
        q = objects_raw[off + 2]
        out["first_groups"].append({"group": g, "variation": v, "qualifier": q})
        out["count"] += 1
        off += 3
        # Skip range field — payload sizes vary per object and we deliberately
        # stop here rather than mis-advance and mislabel groups.
        qh = (q >> 4) & 0x0F
        qc = q & 0x0F
        if qc == 0:                             # index — 1B start + 1B stop
            off += 2
        elif qc == 1:                           # 2B start + 2B stop
            off += 4
        elif qc == 2:                           # 4B start + 4B stop
            off += 8
        elif qc in (7, 8, 9):                   # count only
            off += (1 << (qc - 7)) if qc < 9 else 4
        else:
            break                               # unknown/limited — bail
        _ = qh                                  # unused (data-type of index)
        break                                   # one header is enough for our check
    return out


# ---------------------------------------------------------------------------
# Wire I/O
# ---------------------------------------------------------------------------
def _tcp_send_recv(ip: str, port: int, pkt: bytes,
                   timeout: float, listen_extra: float = 0.0) -> bytes:
    """TCP send + collect. Reads until EOF, timeout, or ~8 KiB. `listen_extra`
    leaves the socket open for an extra window so an outstation that emits
    unsolicited data after the primary reply can be captured."""
    buf = b""
    try:
        with socket.create_connection((ip, port), timeout=proxy.scaled(timeout)) as s:
            s.settimeout(proxy.scaled(timeout))
            s.sendall(pkt)
            try:
                while len(buf) < 8192:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    # Enough to decode one full response — bail unless the caller
                    # asked us to keep listening.
                    if len(buf) >= 32 and not listen_extra:
                        break
            except socket.timeout:
                pass
            if listen_extra > 0:
                s.settimeout(proxy.scaled(listen_extra))
                try:
                    while len(buf) < 8192:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                except (socket.timeout, OSError):
                    pass
    except OSError:
        pass
    return buf


def _udp_send_recv(ip: str, port: int, pkt: bytes, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(proxy.scaled(timeout))
    try:
        sock.sendto(pkt, (ip, port))
        try:
            data, _ = sock.recvfrom(4096)
            return data
        except socket.timeout:
            return b""
    except OSError:
        return b""
    finally:
        sock.close()


def _find_frame(buf: bytes) -> bytes:
    """Return the first well-formed 0x0564 frame in `buf` (header + user data),
    or b'' if none. Some outstations concatenate multiple frames per TCP recv."""
    for i in range(max(0, len(buf) - 9)):
        if buf[i] == 0x05 and buf[i + 1] == 0x64:
            dl = _parse_dl_header(buf[i:])
            if not dl:
                continue
            ud_len = dl["user_data_len"]
            n_blocks = (ud_len + 15) // 16 if ud_len else 0
            total = 10 + ud_len + 2 * n_blocks
            if i + total <= len(buf):
                return buf[i:i + total]
    return b""


# ---------------------------------------------------------------------------
# Probe orchestration
# ---------------------------------------------------------------------------
_MASTER_ADDR = 1
_OUTSTATION_CANDIDATES = (1, 2, 3, 4, 10, 100, 1024)


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          protocol: str = "tcp") -> dict:
    """Run the read-only DNP3 probe against ip:port. Returns:
      {reachable, link_status, outstation_addr, master_addr_accepted,
       iin1, iin2, iin_flags, class0_readable, class0_groups,
       vendor, product, firmware, device_name, location, serial,
       broadcast_reachable, unsolicited_seen, delay_ms, protocol}
    """
    out: dict = {
        "reachable": False, "link_status": False,
        "outstation_addr": None, "master_addr_accepted": None,
        "iin1": None, "iin2": None, "iin_flags": [],
        "class0_readable": False, "class0_groups": [],
        "vendor": "", "product": "", "firmware": "",
        "device_name": "", "location": "", "serial": "",
        "broadcast_reachable": False, "unsolicited_seen": False,
        "delay_ms": None, "protocol": protocol,
    }
    io = _udp_send_recv if protocol == "udp" else _tcp_send_recv

    # 1) REQUEST_LINK_STATUS across a small sweep of common outstation
    # addresses. First reply wins and pins outstation_addr for everything
    # that follows.
    outstation = None
    for dst in _OUTSTATION_CANDIDATES:
        pkt = _build_request_link_status(dst, _MASTER_ADDR)
        try:
            data = io(ip, port, pkt, timeout)
        except OSError:
            continue
        if not data:
            continue
        frame = _find_frame(data)
        if not frame:
            continue
        resp = _parse_response(frame)
        if not resp:
            continue
        out["reachable"] = True
        out["link_status"] = True
        outstation = resp["src"]
        out["outstation_addr"] = outstation
        out["master_addr_accepted"] = resp["dst"]
        break

    # 2) FC1 Read of g60v1 (Class 0 static data). Runs even when link-status
    # was silent — some outstations only answer application traffic.
    seq = 0
    for dst in ([outstation] if outstation is not None else _OUTSTATION_CANDIDATES):
        pkt = _build_g60v1_read(dst=dst, src=_MASTER_ADDR, app_seq=seq, tp_seq=seq)
        try:
            data = io(ip, port, pkt, timeout,
                      listen_extra=1.0) if protocol == "tcp" \
                else io(ip, port, pkt, timeout)
        except OSError:
            continue
        if not data:
            continue
        frame = _find_frame(data)
        if not frame:
            continue
        resp = _parse_response(frame)
        if not resp or resp.get("app_fc") not in (_APP_FC_RESPONSE, _APP_FC_UNSOLICITED):
            continue
        out["reachable"] = True
        if outstation is None:
            outstation = resp["src"]
            out["outstation_addr"] = outstation
            out["master_addr_accepted"] = resp["dst"]
        out["iin1"] = resp["iin1"]
        out["iin2"] = resp["iin2"]
        out["iin_flags"] = resp["iin_flags"]
        out["class0_readable"] = bool(resp["objects_raw"])
        out["class0_groups"] = _count_object_groups(resp["objects_raw"])["first_groups"]
        # Look inside the rest of the collected buffer for an unsolicited frame.
        rest = data[data.find(frame) + len(frame):]
        while rest:
            nxt = _find_frame(rest)
            if not nxt:
                break
            nresp = _parse_response(nxt)
            if nresp and nresp.get("app_fc") == _APP_FC_UNSOLICITED:
                out["unsolicited_seen"] = True
                break
            rest = rest[rest.find(nxt) + len(nxt):]
        break

    if not out["reachable"] or outstation is None:
        return out

    # 3) Group 0 device-attribute reads. One request per variation — some
    # outstations reply IIN2.1 (object unknown) for individual g0 variations
    # while still exposing others, so we walk them independently.
    attr_map = {"software_version": "firmware", "vendor": "vendor",
                "location": "location", "device_name": "device_name",
                "serial": "serial"}
    for var, name in _G0_ATTR_NAMES.items():
        pkt = _build_g0_read(var, dst=outstation, src=_MASTER_ADDR,
                             app_seq=(var & 0x0F), tp_seq=(var & 0x3F))
        try:
            data = io(ip, port, pkt, timeout)
        except OSError:
            continue
        if not data:
            continue
        frame = _find_frame(data)
        if not frame:
            continue
        resp = _parse_response(frame)
        if not resp or resp.get("app_fc") != _APP_FC_RESPONSE:
            continue
        # Skip when the outstation reports the object is unknown for this
        # variation — no attribute to extract.
        if resp["iin2"] & 0x02:
            continue
        val = _extract_g0_attribute(resp["objects_raw"])
        if val:
            key = attr_map[name]
            out[key] = val
    # A "vendor product" concatenation is convenient for the CVE mapper.
    if out["vendor"] and not out["product"] and out["device_name"]:
        out["product"] = out["device_name"]

    # 4) FC23 Delay Measurement — informational round-trip check.
    t0 = time.monotonic()
    pkt = _build_delay_measurement(dst=outstation, src=_MASTER_ADDR,
                                   app_seq=1, tp_seq=1)
    try:
        data = io(ip, port, pkt, timeout)
    except OSError:
        data = b""
    if data:
        frame = _find_frame(data)
        if frame and _parse_response(frame):
            out["delay_ms"] = int((time.monotonic() - t0) * 1000)

    # 5) Broadcast-read (0xFFFD, requires app-layer confirmation).
    pkt = _build_g60v1_read(dst=_BCAST_NEEDS_APP_CONF, src=_MASTER_ADDR,
                            app_seq=2, tp_seq=2)
    try:
        data = io(ip, port, pkt, timeout)
    except OSError:
        data = b""
    if data:
        frame = _find_frame(data)
        if frame:
            resp = _parse_response(frame)
            if resp and resp.get("app_fc") in (_APP_FC_RESPONSE, _APP_FC_UNSOLICITED):
                out["broadcast_reachable"] = True
    return out


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------
def dnp3_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_dnp3(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "protocol": p.protocol or "tcp",
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "dnp3ctl", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_dnp3(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            proto = pr.get("protocol", "tcp")
            tgt = f"{h.ip}:{p.portid}"
            addr = pr.get("outstation_addr")
            master = pr.get("master_addr_accepted")

            # Reachability finding — always emit when the outstation answered.
            addr_txt = f" src={addr}" if addr is not None else ""
            master_txt = f" master-accepted={master}" if master is not None else ""
            out.append(_finding(
                "high",
                "DNP3 SCADA outstation reachable on the scanned network", tgt,
                f"DNP3 outstation replied to {'REQUEST_LINK_STATUS / ' if pr.get('link_status') else ''}"
                f"FC1 Read Class 0 (g60v1).{addr_txt}{master_txt} A DNP3 device on a "
                f"corporate/DMZ segment is a segmentation gap — the base protocol "
                f"has NO authentication, so anyone who reaches this port can read "
                f"process telemetry and, unless IEEE 1815 §7 Secure Authentication "
                f"is enforced, issue control primitives (Select/Operate/Direct "
                f"Operate/Cold-Warm Restart).",
                f"nmap -sT -p {p.portid} --script dnp3-info {h.ip}",
                "Place OT devices on an isolated network segment. Where reachability "
                "is required, front the outstation with a DNP3-aware firewall that "
                "restricts function codes by source and enforces IEEE 1815 §7 SAv5 "
                "on every session.",
                ["CWE-306", "CWE-284", "CWE-923"], kind="dnp3_reachable"))

            # Missing Secure Authentication — the critical finding.
            if pr.get("class0_readable"):
                out.append(_finding(
                    "critical",
                    "DNP3 outstation accepts Read without Secure Authentication (IEEE 1815 §7)",
                    tgt,
                    f"The outstation answered a plain FC1 Read (g60v1) without an "
                    f"Authentication Request (Group 120) preceding it — Secure "
                    f"Authentication SAv2/SAv5 is not enforced. Every DNP3 function "
                    f"available to this port is therefore reachable without a key, "
                    f"including the state-changing primitives "
                    f"({', '.join(f'FC{c} {n}' for c, n in list(_DANGEROUS_FCS.items())[:6])}, "
                    f"...). Recce did not send any of them — the reachable Read is "
                    f"the whole finding.",
                    f"# read-only prove: dnp3ctl {h.ip}:{p.portid} read g60v1 --dst {addr or 1}",
                    "Enable IEEE 1815 §7 Secure Authentication (SAv5 preferred). "
                    "Provision per-user update keys, disable pre-shared keys after "
                    "first commissioning, and restrict the outstation's link layer "
                    "to the SCADA master's address(es).",
                    ["CWE-306", "CWE-287", "CWE-345"], kind="dnp3_no_secure_auth"))

            # Control-surface context finding (paired with the SA finding).
            if pr.get("class0_readable"):
                fc_list = ", ".join(f"FC{c} {n}"
                                    for c, n in _DANGEROUS_FCS.items())
                out.append(_finding(
                    "high",
                    "DNP3 control-function surface exposed alongside missing SA", tgt,
                    f"An unauthenticated outstation exposes the full DNP3 function-code "
                    f"table to the link — recce did NOT invoke any of them (they change "
                    f"plant state and can trip protection relays) but the surface is "
                    f"there: {fc_list}. Any of these from a compromised master is "
                    f"direct control of the outstation.",
                    f"# READ-ONLY inventory: dnp3ctl {h.ip}:{p.portid} read g60v1",
                    "Enforce IEEE 1815 §7 SAv5, restrict source addresses at the link "
                    "layer, and audit outstation configuration to disable any control "
                    "function not required by the SCADA master.",
                    ["CWE-284", "CWE-306"], kind="dnp3_control_surface"))

            # Device identification.
            ident_bits = [(k, pr.get(k)) for k in
                          ("vendor", "product", "firmware", "device_name",
                           "location", "serial") if pr.get(k)]
            if ident_bits:
                bits = "  ".join(f"{k}={v!r}" for k, v in ident_bits)
                out.append(_finding(
                    "info",
                    "DNP3 device identification extracted (vendor/product/firmware)",
                    tgt,
                    f"Group 0 device-attribute read returned: {bits}. This fingerprint "
                    f"feeds vendor-specific CVE mapping (SEL, GE Multilin, Schweitzer, "
                    f"Siemens SICAM, Schneider SCADAPack) and cross-references the "
                    f"outstation identity across engineering-workstation project files.",
                    f"# dnp3ctl {h.ip}:{p.portid} read g0 --var 242",
                    "Informational — pairs with the reachability finding.",
                    [], kind="dnp3_device_id"))

            # Outstation address disclosure — always info when we learned it.
            if addr is not None:
                out.append(_finding(
                    "info",
                    "DNP3 outstation source address disclosed", tgt,
                    f"Outstation address {addr} (0x{addr:04x}) answered on {tgt}"
                    f"{f' with master address {master}' if master is not None else ''}. "
                    f"The address is needed for every subsequent DNP3 frame and is "
                    f"often a per-substation identifier; recording it enables "
                    f"cross-scan correlation and lateral targeting from any master "
                    f"that trusts it.",
                    f"# dnp3ctl {h.ip}:{p.portid} link-status --dst {addr}",
                    "Informational.",
                    [], kind="dnp3_addressing"))

            # IIN flags — surface the interesting ones as one finding.
            flags = pr.get("iin_flags") or []
            interesting = {"device_restart", "device_trouble", "config_corrupt",
                           "local_control", "need_time", "event_buffer_overflow"}
            hit = [f for f in flags if f in interesting]
            if hit:
                sev = "medium" if any(
                    f in ("device_restart", "device_trouble", "config_corrupt")
                    for f in hit) else "low"
                out.append(_finding(
                    sev,
                    "DNP3 IIN flags indicate device restart / trouble / config state",
                    tgt,
                    f"Internal Indications: {', '.join(hit)} "
                    f"(IIN1=0x{pr.get('iin1', 0):02x} IIN2=0x{pr.get('iin2', 0):02x}). "
                    f"Device Restart means uptime reset since the last CLEAR — an "
                    f"attacker who saw the bit before you did may already have "
                    f"issued FC13/14 (Cold/Warm Restart). Config Corrupt indicates "
                    f"the outstation cannot trust its own configuration.",
                    f"# clear via master only: dnp3ctl {h.ip}:{p.portid} clear-iin",
                    "Investigate uptime with the site engineer; if unexpected, "
                    "audit control-message logs for FC13/14/15 and rotate SA keys.",
                    ["CWE-778"], kind="dnp3_iin_state"))

            # Broadcast responsiveness.
            if pr.get("broadcast_reachable"):
                out.append(_finding(
                    "medium",
                    "DNP3 outstation responds to broadcast address 0xFFFD", tgt,
                    "The outstation replied to a broadcast Read (destination "
                    "0xFFFD, application-confirm form). A well-designed outstation "
                    "should ignore broadcast reads; answering permits sweep-style "
                    "enumeration without any prior knowledge of the assigned "
                    "link-layer address.",
                    f"# dnp3ctl {h.ip}:{p.portid} read g60v1 --dst 0xFFFD",
                    "Configure the outstation to ignore broadcast reads. IEEE 1815 "
                    "§10.2.3 permits this — broadcast is only required for time "
                    "synchronisation in most deployments.",
                    ["CWE-200"], kind="dnp3_broadcast_reachable"))

            # Unsolicited leak.
            if pr.get("unsolicited_seen"):
                out.append(_finding(
                    "medium",
                    "DNP3 unsolicited responses observed on connect (misconfigured target)",
                    tgt,
                    "The outstation emitted an unsolicited-response frame (App Control "
                    "UNS bit set) to recce's TCP connect. A device configured to send "
                    "unsolicited events to a wrong or absent master will spray event "
                    "data — analog changes, binary state transitions, counter values — "
                    "to whoever answers on the master port.",
                    f"# passive: tcpdump -i any -w dnp3.pcap 'port {p.portid} and host {h.ip}'",
                    "Configure the correct master destination for unsolicited "
                    "responses, or disable them entirely on outstations that do not "
                    "need to push events.",
                    ["CWE-200"], kind="dnp3_unsolicited_leak"))

            # UDP variant.
            if proto == "udp":
                out.append(_finding(
                    "medium",
                    "DNP3 over UDP reachable (§7.2)", tgt,
                    f"The outstation answered a DNP3 frame on UDP/{p.portid}. UDP-mapped "
                    f"DNP3 is sometimes used on wireless SCADA links but is often "
                    f"overlooked in firewall rules — connectionless transport means no "
                    f"TCP-state tracking to authorise the source.",
                    f"nmap -sU -p {p.portid} --script dnp3-info {h.ip}",
                    "Where DNP3/UDP is not required, block 20000/udp at the segment "
                    "boundary. Where it is, front it with a stateful DNP3-aware "
                    "gateway that enforces SA per source.",
                    ["CWE-306", "CWE-284"], kind="dnp3_udp_reachable"))

            # Delay measurement — informational.
            if pr.get("delay_ms") is not None:
                out.append(_finding(
                    "info", "DNP3 delay-measurement round-trip captured", tgt,
                    f"FC23 Delay Measurement returned in {pr.get('delay_ms')} ms. "
                    f"Second-source liveness signal; useful when Class 0 is empty on "
                    f"a spare or newly-commissioned device.",
                    f"# dnp3ctl {h.ip}:{p.portid} delay-measurement --dst {addr or 1}",
                    "Informational.",
                    [], kind="dnp3_delay_measured"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Fingerprint DNP3 (nmap NSE)",
         "cmd": f"nmap -sT -p {port} --script dnp3-info {ip}"},
        {"step": "Fingerprint DNP3 over UDP",
         "cmd": f"nmap -sU -p {port} --script dnp3-info {ip}"},
        {"step": "Read Class 0 static data (opendnp3)",
         "cmd": f"dnp3ctl {ip}:{port} read g60v1 --dst 1"},
        {"step": "Read Group 0 vendor attribute",
         "cmd": f"dnp3ctl {ip}:{port} read g0 --var 242 --dst 1"},
        {"step": "Passive capture (identify unsolicited events)",
         "cmd": f"tcpdump -i any -s0 -w dnp3.pcap 'port {port} and host {ip}'"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "dnp3", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = dnp3_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], protocol=t.get("protocol", "tcp")),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["outstation_addr"] = pr.get("outstation_addr")
                t["vendor"] = pr.get("vendor", "")
                t["product"] = pr.get("product", "")
                t["firmware"] = pr.get("firmware", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
