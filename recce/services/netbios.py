"""NetBIOS Name Service (137/udp): workgroup / hostname / MAC disclosure.

NBNS Node Status (opcode 0x0021, "*" query) returns:
  * the machine's registered NetBIOS names (hostname + suffix bytes that flag
    services: 0x00 workstation, 0x20 file server, 0x1C domain controller,
    0x1B domain master browser) — that identifies workgroup/domain membership,
    role, and the actual hostname of a host that only showed you an IP,
  * the interface MAC address, which is otherwise only visible from the same L2.

Pre-SMB, but still routine on legacy Windows and Samba estates. The MAC is the
useful pivot: it lets a tester correlate an IP to a device seen elsewhere and
is a free hardware/vendor fingerprint (OUI).

One UDP datagram, stdlib only. Wire format: RFC 1002 (NetBIOS over TCP/UDP).
"""
from __future__ import annotations

import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 137
_TIMEOUT = 2.5

# NetBIOS suffix bytes worth naming. Not exhaustive; the ones a tester actually
# uses to identify role and target.
_SUFFIX: dict[int, str] = {
    0x00: "workstation",
    0x03: "messenger",
    0x1B: "domain master browser",
    0x1C: "domain controller",
    0x1D: "master browser",
    0x1E: "browser election",
    0x20: "file server",
}


def is_netbios(port: Port) -> bool:
    svc = (port.service or "").lower()
    return (port.portid == 137
            or "netbios" in svc or "nbns" in svc or "nbt" in svc)


def _encoded_wildcard() -> bytes:
    """NetBIOS second-level name encoding for the wildcard '*' padded to 16
    bytes with 0x00 and encoded as first-level (2 chars per byte, 0x41-based)."""
    raw = b"*" + b"\x00" * 15
    out = bytearray()
    for b in raw:
        out.append(0x41 + (b >> 4))
        out.append(0x41 + (b & 0x0F))
    return bytes([len(out)]) + bytes(out) + b"\x00"


def _nbstat_query() -> bytes:
    """Standard node-status query: txid 0x1000, flags 0, QDCOUNT=1, name=*, NBSTAT/IN."""
    header = struct.pack("!HHHHHH", 0x1000, 0x0000, 1, 0, 0, 0)
    return header + _encoded_wildcard() + struct.pack("!HH", 0x0021, 0x0001)


def _parse_nbstat(data: bytes) -> dict:
    """Parse the response. The answer section carries a name list and, tacked
    on the end, the 6-byte MAC. Field offsets fixed by the spec; do not depend
    on the name being echoed back byte-for-byte because Windows sometimes
    truncates."""
    if len(data) < 12:
        return {}
    ancount = struct.unpack_from("!H", data, 6)[0]
    if ancount == 0:
        return {}
    # Skip the echoed question: 1-byte length + label + 0x00 + qtype + qclass.
    i = 12
    lb = data[i]
    i += 1 + lb + 1 + 4
    # Answer: NAME (same encoded form), TYPE, CLASS, TTL, RDLENGTH, RDATA.
    lb2 = data[i]
    i += 1 + lb2 + 1
    if i + 10 > len(data):
        return {}
    _t, _c, _ttl, rdlen = struct.unpack_from("!HHIH", data, i)
    i += 10
    if i + rdlen > len(data):
        return {}
    rdata = data[i:i + rdlen]
    if not rdata:
        return {}
    num = rdata[0]
    names = []
    off = 1
    for _ in range(num):
        if off + 18 > len(rdata):
            break
        raw = rdata[off:off + 15].rstrip(b" \x00")
        suffix = rdata[off + 15]
        flags = struct.unpack_from("!H", rdata, off + 16)[0]
        try:
            name = raw.decode("ascii", "replace")
        except UnicodeDecodeError:
            name = raw.decode("latin-1", "replace")
        names.append({"name": name, "suffix": suffix,
                      "role": _SUFFIX.get(suffix, ""),
                      "group": bool(flags & 0x8000)})
        off += 18
    mac = ""
    if off + 6 <= len(rdata):
        mac = ":".join(f"{b:02x}" for b in rdata[off:off + 6])
    return {"names": names, "mac": mac}


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    out: dict = {"reachable": False}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(_nbstat_query(), (ip, port))
        data, _ = s.recvfrom(1024)
    except (OSError, socket.timeout):
        return out
    finally:
        s.close()
    parsed = _parse_nbstat(data)
    if not parsed:
        return out
    out["reachable"] = True
    out.update(parsed)
    # Derive the primary hostname and workgroup/domain from the suffixes.
    for n in parsed["names"]:
        if n["suffix"] == 0x00 and not n["group"] and not out.get("hostname"):
            out["hostname"] = n["name"]
        if n["suffix"] == 0x00 and n["group"]:
            out["workgroup"] = n["name"]
        if n["suffix"] == 0x1C:
            out["domain"] = n["name"]
            out["is_dc"] = True
    return out


def netbios_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_netbios(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_netbios(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            names = pr.get("names") or []
            desc = ", ".join(
                f"{n['name']}<{n['suffix']:02X}>" + (f" [{n['role']}]" if n['role'] else "")
                for n in names[:8])
            hint = ""
            if pr.get("is_dc"):
                hint = f" Host is a domain controller for {pr.get('domain', '?')}."
            elif pr.get("hostname") and pr.get("workgroup"):
                hint = (f" Hostname {pr['hostname']} in "
                        f"{'domain' if pr.get('domain') else 'workgroup'} "
                        f"{pr.get('domain') or pr.get('workgroup')}.")
            out.append(_finding(
                "low", "NetBIOS Name Service discloses hostname / workgroup / MAC",
                tgt,
                f"NBNS answered a node-status query with {len(names)} name(s) and "
                f"MAC {pr.get('mac', 'unknown')}: {desc}." + hint +
                " NBNS reveals the machine's real hostname, its workgroup or "
                "domain membership, its role (DC / file server / master browser), "
                "and its interface MAC — all pre-authentication, all from one UDP "
                "packet. The MAC also correlates a host across networks and "
                "identifies the hardware vendor by OUI.",
                "nbtscan",
                f"nbtscan -v {h.ip}   # or: nmap -sU --script nbstat -p137 {h.ip}",
                "Disable NetBIOS over TCP/IP on interfaces not required by legacy "
                "clients; block 137/udp at the perimeter.",
                ["CWE-200"], kind="netbios_disclosure"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "nbtscan",
         "command": f"nbtscan -v {ip}",
         "why": "name list + suffix -> role + MAC in one query"},
        {"phase": "enumerate", "tool": "nmap",
         "command": f"nmap -sU --script nbstat -p137 {ip}",
         "why": "same, via nmap's parsed output; batches across a range"},
        {"phase": "correlate", "tool": "manuf",
         "command": "manuf <MAC>   # look up the OUI vendor",
         "why": "MAC vendor lookup is often a device-type give-away (VMware / iDRAC / iLO)"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "netbios", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = netbios_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["hostname"] = pr.get("hostname", "")
                t["is_dc"] = pr.get("is_dc", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
