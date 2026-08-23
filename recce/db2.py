"""Deep IBM Db2 (DRDA) enumeration (stdlib only).

Db2 LUW listens on 50000 (SSL 50001; 523 is the DB2 discovery service) and speaks
DRDA over the DDM (Distributed Data Management) wire format. recce builds a DRDA
EXCSAT (Exchange Server Attributes) request directly - no ibm_db / db2 client - to
CONFIRM a Db2 endpoint and read its identity, pre-auth and read-only:

  * **EXCSAT -> EXCSATRD** - the server replies with its class name (SRVCLSNM, e.g.
                            "QDB2/LINUXX8664"), external name and release level
                            (SRVRLSLV, e.g. "SQL11055" = 11.5.5) - the fingerprint.
  * **DSS magic (0xD0)**   - a valid DRDA reply positively identifies Db2/DRDA even if
                            the identity fields are withheld.

An exposed Db2 endpoint discloses the server version/platform and is subject to
database-name enumeration and credential brute-forcing (nmap drda-brute, Metasploit
db2_auth). recce only exchanges server attributes; it never authenticates. Authorized
testing only.
"""
from __future__ import annotations

import re
import socket
import struct

from .models import Host, Port
from .svccommon import finding_builder, make_proof_html_wrapper, make_findings_to_vulns_wrapper

_PORTS = (50000, 50001, 60000, 523, 25000)
_DEFAULT_PORT = 50000
_TIMEOUT = 6.0
_MAX_REPLY = 64 * 1024

# DDM codepoints.
_CP_EXCSAT = 0x1041
_CP_EXCSATRD = 0x1443
_CP_EXTNAM = 0x115E
_CP_MGRLVLLS = 0x1404
_CP_SRVCLSNM = 0x1147
_CP_SRVNAM = 0x116D
_CP_SRVRLSLV = 0x115A

_PRINTABLE_RE = re.compile(r"[^\x20-\x7e]")


def is_db2(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    blob = f"{port.service} {port.product}".lower()
    return "db2" in blob or "drda" in blob


def db2_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_db2(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- DRDA / DDM wire format (stdlib) --------------------------------------------

def _ddm_object(codepoint: int, data: bytes) -> bytes:
    # [length:2][codepoint:2][data]
    return struct.pack(">HH", len(data) + 4, codepoint) + data


def _excsat() -> bytes:
    """Build a DRDA EXCSAT request (server-attribute exchange). EXTNAM identifies the
    client; MGRLVLLS advertises a minimal set of manager levels so the server replies
    with EXCSATRD."""
    extnam = _ddm_object(_CP_EXTNAM, b"recce")
    # MGRLVLLS: (manager-codepoint:2, level:2) pairs the server understands.
    mgrs = b""
    for cp, lvl in ((0x1403, 7),   # AGENT
                    (0x1444, 7),   # SQLAM
                    (0x240F, 7),   # RDB
                    (0x1440, 7),   # SECMGR
                    (0x1474, 5)):  # CMNTCPIP
        mgrs += struct.pack(">HH", cp, lvl)
    mgrlvlls = _ddm_object(_CP_MGRLVLLS, mgrs)
    body = extnam + mgrlvlls
    excsat = _ddm_object(_CP_EXCSAT, body)
    # DSS header: [length:2][magic=0xD0][format=0x01][correlation id:2]
    dss = struct.pack(">HBBH", len(excsat) + 6, 0xD0, 0x01, 1) + excsat
    return dss


def _recv(sock: socket.socket) -> bytes:
    buf = b""
    while len(buf) < _MAX_REPLY:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        if len(chunk) < 4096:
            break
    return buf


def _decode_ddm_string(raw: bytes) -> str:
    """DDM string fields may be ASCII or EBCDIC (cp500). Return whichever decodes to a
    mostly-printable string."""
    ascii_s = raw.decode("ascii", "replace")
    if not _PRINTABLE_RE.search(ascii_s.replace("�", "")) and "�" not in ascii_s:
        return ascii_s.strip()
    try:
        ebcdic = raw.decode("cp500")
        if len(_PRINTABLE_RE.sub("", ebcdic)) >= len(_PRINTABLE_RE.sub("", ascii_s)):
            return ebcdic.strip()
    except (UnicodeDecodeError, LookupError):
        pass
    return ascii_s.strip()


# DDM container codepoints whose data holds further DDM objects (recurse into these).
_CONTAINERS = {_CP_EXCSAT, _CP_EXCSATRD, _CP_MGRLVLLS, 0x1444, 0x2401}


def _collect_objs(buf: bytes, depth: int, out: dict) -> None:
    i = 0
    n = len(buf)
    while i + 4 <= n:
        try:
            (length, cp) = struct.unpack_from(">HH", buf, i)
        except struct.error:
            break
        if length < 4 or i + length > n:
            break
        data = buf[i + 4:i + length]
        out.setdefault(cp, data)
        if depth < 8 and cp in _CONTAINERS and len(data) >= 4:
            _collect_objs(data, depth + 1, out)
        i += length


def _collect(reply: bytes) -> dict:
    """Walk a DRDA reply (one or more DSS segments) and return {codepoint: raw_data} for
    every DDM object, descending into container objects like EXCSATRD."""
    out: dict[int, bytes] = {}
    i = 0
    n = len(reply)
    # DSS-framed reply: [len:2][0xD0][format:1][corrid:2][ddm objects...], possibly repeated.
    if n >= 6 and reply[2] == 0xD0:
        while i + 6 <= n:
            (dss_len,) = struct.unpack_from(">H", reply, i)
            if dss_len < 6 or i + dss_len > n:
                _collect_objs(reply[i + 6:], 0, out)
                break
            _collect_objs(reply[i + 6:i + dss_len], 0, out)
            i += dss_len
    else:
        _collect_objs(reply, 0, out)
    return out


def _find_codepoint(objs: dict, codepoint: int) -> str:
    raw = objs.get(codepoint)
    return _decode_ddm_string(raw) if raw else ""


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Send EXCSAT and parse the EXCSATRD reply. Returns {reachable, is_db2, srvclsnm,
    srvname, version, platform, error}."""
    res: dict = {"reachable": False, "is_db2": False, "srvclsnm": "", "srvname": "",
                 "version": "", "platform": "", "error": ""}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            res["reachable"] = True
            sock.sendall(_excsat())
            reply = _recv(sock)
            if not reply or len(reply) < 6:
                res["error"] = "no DRDA response"
                return res
            objs = _collect(reply)
            # A DRDA DSS reply carries the 0xD0 magic at offset 2.
            if reply[2] == 0xD0 or _CP_EXCSATRD in objs or _CP_SRVCLSNM in objs:
                res["is_db2"] = True
            res["srvclsnm"] = _find_codepoint(objs, _CP_SRVCLSNM)
            res["srvname"] = _find_codepoint(objs, _CP_SRVNAM)
            rlslv = _find_codepoint(objs, _CP_SRVRLSLV)
            if res["srvclsnm"] or rlslv:
                res["is_db2"] = True
            res["platform"] = res["srvclsnm"]
            # SRVRLSLV like "SQL11055" = SQL + vv(2) + rr(2) + mod(1) -> 11.5.5.
            m = re.search(r"SQL(\d{2})(\d{2})(\d)", rlslv)
            if m:
                res["version"] = f"{int(m.group(1))}.{int(m.group(2))}.{int(m.group(3))}"
            elif rlslv:
                res["version"] = rlslv.strip()
            if not res["is_db2"]:
                res["error"] = "not a DRDA/Db2 endpoint"
    except (OSError, socket.timeout, struct.error) as e:
        res["error"] = res["error"] or str(e)
    return res


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "db2_exposed": (
        "An IBM Db2 (DRDA) endpoint is exposed on the network and answered a server-"
        "attribute exchange with no credential, disclosing its class name, platform and "
        "release level. Version/platform disclosure lets an attacker target the exact "
        "patch level; the endpoint is also subject to database-name enumeration and "
        "credential brute-forcing (nmap drda-brute, Metasploit db2_auth), and Db2 has "
        "historically shipped default instance accounts (db2inst1, db2admin). Require "
        "strong authentication, keep Db2 patched, and firewall 50000/523."),
}

TESTING_NARRATIVE = [
    ("1. EXCSAT exchange (stdlib DRDA)",
     "recce builds a DRDA EXCSAT (exchange-server-attributes) request in the DDM wire "
     "format and sends it directly - no ibm_db / Db2 client."),
    ("2. Db2 identification",
     "A DRDA DSS reply (0xD0 magic) positively confirms Db2/DRDA; recce parses the "
     "EXCSATRD for the server class name and release level."),
    ("3. Version fingerprint",
     "It decodes SRVCLSNM (e.g. QDB2/LINUXX8664) and SRVRLSLV (e.g. SQL11055 -> 11.5.5), "
     "handling both ASCII and EBCDIC DDM string encodings."),
    ("4. Runbook",
     "The follow-on commands (nmap db2-das-info/drda-brute, Metasploit db2_version/"
     "db2_auth, default-instance-account spray) are staged per endpoint."),
]

_finding = finding_builder("db2", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_db2(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr or not pr.get("is_db2"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            cls = pr.get("srvclsnm", "")
            ident = []
            if cls:
                ident.append(cls)
            if ver:
                ident.append(f"release {ver}")
            ident_txt = (" (" + ", ".join(ident) + ")") if ident else ""
            out.append(_finding(
                "medium", "IBM Db2 (DRDA) endpoint exposed", tgt,
                "recce confirmed a Db2/DRDA endpoint via an EXCSAT exchange" + ident_txt
                + ". Discloses version/platform; subject to database-name enumeration, "
                  "credential brute-forcing, and default instance accounts.",
                "nmap",
                f"nmap -p{p.portid} --script db2-das-info,drda-brute {h.ip} ; "
                f"# msf: use auxiliary/scanner/db2/db2_auth (db2inst1, db2admin defaults)",
                "Require strong authentication, keep Db2 patched, firewall 50000/523.",
                ["CWE-306", "CWE-200"], kind="db2_exposed"))
    return out


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", f"nmap -p{port} --script db2-das-info,drda-info {ip}",
         "Fingerprint the Db2 server (version, platform, instance)."),
        ("enumerate", "nmap / msf",
         f"nmap -p{port} --script drda-brute {ip} ; "
         f"msfconsole -q -x 'use auxiliary/scanner/db2/db2_version; set RHOSTS {ip}; run'",
         "Enumerate database names and confirm the version."),
        ("access", "msf / db2",
         "msf: use auxiliary/scanner/db2/db2_auth (spray db2inst1, db2admin, dasusr1) ; "
         "db2 connect to <DB> user <u> using <p>",
         "Brute-force / spray default instance accounts against a database name."),
        ("escalate", "post-auth",
         "# post-auth Db2 gives SQL, and (with the right privileges) OS command exec via\n"
         "# external routines / db2 procedures - only within scope.",
         "Turn authenticated Db2 access into OS command execution."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


proof_html = make_proof_html_wrapper("db2 => ")
findings_to_vulns = make_findings_to_vulns_wrapper("db2", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full Db2 (DRDA) analysis. Returns {targets, findings, runbooks, probes, stats}."""
    from . import svcprobe
    targets = db2_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["is_db2"] = pr.get("is_db2", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
