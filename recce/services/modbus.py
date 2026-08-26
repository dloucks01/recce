"""Modbus/TCP probe — OT/ICS discovery.

Modbus is the lingua franca of industrial control networks. When it shows
up on a general IT scan (as it sometimes does — misconfigured segmentation,
converged networks, forgotten test rigs), the finding is significant: an
OT device on a corporate segment is a compliance issue and often a direct
route to physical process control.

Probe reads Function 0x03 (Read Holding Registers) at address 0 for 1
register. On a real Modbus device this returns a 2-byte value, letting us
distinguish from arbitrary services on port 502. Also reads the vendor/
product string via Function 0x2B (Read Device Identification) when
supported.

Findings:
  * modbus_reachable (HIGH) — Modbus/TCP device on the scanned network.
    The severity is a stance: a Modbus device should almost never be
    reachable from a corporate/DMZ segment.
  * modbus_device_id (info) — vendor + product string extracted; adds
    context to the reachable finding.

Airgap-safe: stdlib socket + struct only. Single request/response, ~4s
timeout. Never writes to the device — read-only Function 0x03.
"""
from __future__ import annotations

import socket
import struct

from ..models import Host, Port


_DEFAULT_PORT = 502
_TIMEOUT = 4.0


def is_modbus(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (502, 8502)
            or "modbus" in svc or "modbus" in prod)


def _build_read_holding_registers(unit_id: int = 1, addr: int = 0,
                                  count: int = 1, tid: int = 1) -> bytes:
    """Modbus/TCP ADU wrapping a Read Holding Registers (function 0x03) PDU.
      MBAP header: tid(2), protocol(2)=0, length(2), unit_id(1)
      PDU: function(1)=3, start_addr(2), quantity(2)
    Length field = number of bytes in the PDU + unit_id."""
    pdu = struct.pack(">BHH", 0x03, addr, count)
    length = len(pdu) + 1                     # + unit_id byte
    return struct.pack(">HHHB", tid, 0, length, unit_id) + pdu


def _build_read_device_id(unit_id: int = 1, tid: int = 2) -> bytes:
    """Function 0x2B / 0x0E (Read Device Identification), Basic ID (0x01).
    Not universally implemented — devices that don't support it return an
    exception PDU, which we just ignore."""
    # PDU: function 0x2B, MEI type 0x0E, ReadDevID code 0x01 (basic),
    # object id 0x00 (VendorName)
    pdu = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)
    length = len(pdu) + 1
    return struct.pack(">HHHB", tid, 0, length, unit_id) + pdu


def _parse_read_registers_response(data: bytes) -> list[int] | None:
    """Parse the Read Holding Registers response. Returns list of register
    values, or None on any parse failure / exception response."""
    if len(data) < 9:
        return None
    tid, proto, length, unit_id = struct.unpack(">HHHB", data[:7])
    if proto != 0:                           # Modbus/TCP: protocol must be 0
        return None
    fn = data[7]
    if fn & 0x80:                            # exception response (function | 0x80)
        return None
    if fn != 0x03:
        return None
    byte_count = data[8]
    if byte_count % 2 or byte_count > (len(data) - 9):
        return None
    regs = []
    for i in range(byte_count // 2):
        regs.append(struct.unpack(">H", data[9 + i * 2:11 + i * 2])[0])
    return regs


def _parse_device_id_response(data: bytes) -> dict:
    """Parse the Read Device ID response into {vendor, product, revision}.
    Returns empty strings on any parse failure — Modbus devices vary widely
    in what they report here."""
    out = {"vendor": "", "product": "", "revision": ""}
    if len(data) < 15:
        return out
    fn = data[7]
    if fn & 0x80 or fn != 0x2B:
        return out
    # Skip past MEI type (1) + read-dev-id code (1) + conformity (1) +
    # more-follows (1) + next-object-id (1) + number-of-objects (1) at data[8:14]
    n_objects = data[13]
    i = 14
    labels = {0: "vendor", 1: "product", 2: "revision"}
    for _ in range(n_objects):
        if i + 2 > len(data): break
        obj_id = data[i]; obj_len = data[i + 1]; i += 2
        if i + obj_len > len(data): break
        val = data[i:i + obj_len].decode("utf-8", "replace")
        i += obj_len
        key = labels.get(obj_id)
        if key:
            out[key] = val[:80]
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Return {reachable, registers, vendor, product, revision}. Reachable=True
    means we got a valid Modbus response — not just a TCP connect."""
    out = {"reachable": False, "registers": [], "vendor": "", "product": "",
           "revision": ""}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            # Try a couple of common unit IDs — 1 is standard, some devices
            # respond only to 0 (broadcast/default) or 255. `winning_unit`
            # captures the id that answered so the device-ID probe below uses
            # the same address.
            winning_unit = None
            for uid in (1, 0, 255):
                s.sendall(_build_read_holding_registers(unit_id=uid))
                data = s.recv(4096)
                regs = _parse_read_registers_response(data)
                if regs is not None:
                    out["reachable"] = True
                    out["registers"] = regs
                    winning_unit = uid
                    break
            if not out["reachable"]:
                return out
            # Now attempt device identification (may return exception, that's fine).
            s.sendall(_build_read_device_id(unit_id=winning_unit))
            data = s.recv(4096)
            devid = _parse_device_id_response(data)
            out.update(devid)
    except OSError:
        pass
    return out


def modbus_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_modbus(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "modpoll", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_modbus(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            vendor_txt = ""
            if pr.get("vendor") or pr.get("product"):
                vendor_txt = f" · {pr.get('vendor','?')} {pr.get('product','')}".strip()
            regs = pr.get("registers") or []
            out.append(_finding(
                "high",
                "Modbus/TCP device on the scanned network", tgt,
                f"Modbus/TCP responded to Function 0x03 (Read Holding Registers) "
                f"at address 0: value={regs[0] if regs else '?'}{vendor_txt}. "
                f"A Modbus device on a corporate/DMZ segment is a segmentation "
                f"gap — Modbus has NO authentication in the base protocol, so "
                f"anyone who reaches this port can read and (with Function 0x06/0x10) "
                f"WRITE to registers and coils, directly affecting the physical process.",
                f"modpoll -m tcp -a 1 -r 1 -c 10 {h.ip}   # read 10 registers, unit 1",
                "Place OT devices on an isolated network. If the device MUST be "
                "reachable, front it with a Modbus-aware firewall/gateway that "
                "restricts read/write privileges by source IP. Never allow write "
                "functions (0x05, 0x06, 0x0F, 0x10) from untrusted networks.",
                ["CWE-306", "CWE-923", "CWE-284"], kind="modbus_reachable"))
            if pr.get("vendor") or pr.get("product"):
                out.append(_finding(
                    "info", "Modbus device identification extracted", tgt,
                    f"vendor={pr.get('vendor','?')!r}  product={pr.get('product','?')!r}  "
                    f"revision={pr.get('revision','?')!r}. This fingerprint helps "
                    f"cross-reference vendor-specific CVEs and default credentials "
                    f"for HMI/PLC firmware.",
                    f"modpoll -m tcp -a 1 {h.ip}",
                    "Informational — pairs with the modbus_reachable finding above.",
                    [], kind="modbus_device_id"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Read holding registers (function 0x03)",
         "cmd": f"modpoll -m tcp -a 1 -r 1 -c 10 -p {port} {ip}"},
        {"step": "Read device identification (function 0x2B)",
         "cmd": f"mbtget -i {ip} -p {port} -u 1 -d 1"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "modbus", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from .. import svcprobe
    targets = modbus_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["vendor"] = pr.get("vendor", "")
                t["product"] = pr.get("product", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
