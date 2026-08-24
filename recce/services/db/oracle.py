"""Deep Oracle Database TNS-listener enumeration (stdlib only).

Oracle's TNS listener answers on 1521 (also 1522/1526/1748). recce speaks the TNS
wire format directly (no oracledb/cx_Oracle, no sqlplus) to CONFIRM an exposed
listener and, best-effort, leak its version - all pre-auth, read-only:

  * **TNS CONNECT + (COMMAND=version)** - a status/version request. A pre-11g or
    mis-configured listener answers with its banner (TNSLSNR version, DB version);
    a hardened 11g+ listener refuses with TNS-01189 - which STILL confirms Oracle
    and often leaks the version in the error text.
  * **response type** - the TNS header packet-type byte (ACCEPT/REFUSE/RESEND/DATA)
    positively identifies an Oracle listener even when the version is withheld.

An exposed TNS listener is a foothold surface: SID enumeration/brute (odat, nmap
oracle-sid-brute), the TNS Poison MITM registration attack (CVE-2012-1675), and the
perennial default accounts (scott/tiger, system/manager, dbsnmp). recce only sends a
status request; it never authenticates or brute-forces. Authorized testing only.
"""
from __future__ import annotations

import re
import socket
import struct

from ...models import Host, Port
from ...svccommon import finding_builder, make_proof_html_wrapper, make_findings_to_vulns_wrapper

_PORTS = (1521, 1522, 1526, 1748, 1754)
_DEFAULT_PORT = 1521
_TIMEOUT = 6.0
_MAX_REPLY = 64 * 1024

# TNS packet types (header byte at offset 4).
_TNS_TYPES = {1: "CONNECT", 2: "ACCEPT", 4: "REFUSE", 5: "REDIRECT", 6: "DATA",
              11: "RESEND", 12: "MARKER"}
_VER_RE = re.compile(rb"Version\s+(\d+\.\d+\.\d+\.\d+(?:\.\d+)?)", re.I)
_TNSLSNR_RE = re.compile(rb"TNSLSNR for [^\r\n]+", re.I)


def is_oracle(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    blob = f"{port.service} {port.product}".lower()
    return "oracle" in blob or "oracle-tns" in blob or "tnslsnr" in blob


def oracle_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_oracle(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- TNS wire format (stdlib) ---------------------------------------------------

def _tns_connect(connect_data: bytes) -> bytes:
    """Build a TNS CONNECT packet carrying `connect_data` (the (CONNECT_DATA=...) blob).
    The 58-byte header is the canonical tnscmd/nmap layout; the two length fields and
    the data-length field are patched to match `connect_data`."""
    hdr = bytearray(
        b"\x00\x00"          # 0  packet length            (patched below)
        b"\x00\x00"          # 2  packet checksum
        b"\x01"              # 4  type = CONNECT
        b"\x00"              # 5  reserved
        b"\x00\x00"          # 6  header checksum
        b"\x01\x39"          # 8  version (313)
        b"\x01\x2c"          # 10 version compatible (300)
        b"\x00\x00"          # 12 global service options
        b"\x08\x00"          # 14 SDU (2048)
        b"\x7f\xff"          # 16 TDU (32767)
        b"\x4f\x98"          # 18 protocol characteristics
        b"\x00\x00"          # 20 line turnaround
        b"\x00\x01"          # 22 value of 1 (byte order)
        b"\x00\x00"          # 24 connect data length      (patched below)
        b"\x00\x3a"          # 26 connect data offset (58)
        b"\x00\x00\x00\x00"  # 28 max receivable connect data
        b"\x01"              # 32 connect flags 0
        b"\x00"              # 33 connect flags 1
        b"\x00\x00\x00\x00"  # 34 trace cross facility item 1
        b"\x00\x00\x00\x00"  # 38 trace cross facility item 2
        b"\x00\x00\x00\x00"  # 42 trace unique connection id (hi)
        b"\x00\x00\x00\x00"  # 46 trace unique connection id (lo)
        b"\x00\x00\x00\x00"  # 50 (padding to 58-byte header)
        b"\x00\x00\x00\x00"  # 54
    )
    packet = hdr + connect_data
    struct.pack_into(">H", packet, 0, len(packet))          # packet length
    struct.pack_into(">H", packet, 24, len(connect_data))   # connect data length
    return bytes(packet)


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


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Send a TNS status/version request and identify the listener. Returns
    {reachable, is_oracle, tns_type, version, banner, version_leaked, error}."""
    res: dict = {"reachable": False, "is_oracle": False, "tns_type": "", "version": "",
                 "banner": "", "version_leaked": False, "error": ""}
    payload = b"(CONNECT_DATA=(COMMAND=version))"
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            res["reachable"] = True
            sock.sendall(_tns_connect(payload))
            reply = _recv(sock)
            if not reply or len(reply) < 5:
                res["error"] = "no TNS response"
                return res
            ptype = reply[4]
            if ptype in _TNS_TYPES:
                res["is_oracle"] = True
                res["tns_type"] = _TNS_TYPES[ptype]
            elif b"TNS" in reply or b"ORACLE" in reply.upper():
                res["is_oracle"] = True
            # Best-effort version / banner extraction from any DATA/REFUSE payload.
            m = _VER_RE.search(reply)
            if m:
                res["version"] = m.group(1).decode("ascii", "replace")
                res["version_leaked"] = True
            lsnr = _TNSLSNR_RE.search(reply)
            if lsnr:
                res["banner"] = lsnr.group(0).decode("ascii", "replace")[:200]
                res["is_oracle"] = True
            if not res["is_oracle"]:
                res["error"] = "not a TNS listener"
    except (OSError, socket.timeout, struct.error) as e:
        res["error"] = res["error"] or str(e)
    return res


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "oracle_tns_exposed": (
        "An Oracle TNS listener is exposed on the network. Even without credentials it "
        "is a rich foothold surface: SID enumeration/brute-force (odat, nmap "
        "oracle-sid-brute) recovers the database service names; the TNS Poison attack "
        "(CVE-2012-1675) registers a rogue instance and man-in-the-middles client "
        "sessions on unpatched listeners; and Oracle databases are notorious for "
        "default accounts (scott/tiger, system/manager, dbsnmp/dbsnmp, sys/change_on_"
        "install). Set a listener password / valid-node-checking, apply the "
        "CVE-2012-1675 mitigation, remove default accounts, and firewall 1521."),
    "oracle_version_leak": (
        "The TNS listener disclosed its version to an unauthenticated status request. "
        "Version disclosure lets an attacker target the exact patch level (and, on "
        "pre-11g, the listener accepts remote administration commands). Restrict "
        "listener administration to local OS auth and firewall the port."),
}

TESTING_NARRATIVE = [
    ("1. TNS status request (stdlib)",
     "recce builds a TNS CONNECT packet carrying (CONNECT_DATA=(COMMAND=version)) and "
     "sends it directly - no sqlplus / oracledb."),
    ("2. Listener identification",
     "It reads the response and inspects the TNS packet-type byte (ACCEPT/REFUSE/"
     "RESEND/DATA) to positively confirm an Oracle listener, even when the version is "
     "withheld."),
    ("3. Version leak (best-effort)",
     "A pre-11g or mis-configured listener returns its TNSLSNR / DB version banner, "
     "which recce extracts. A hardened listener refuses (TNS-01189) - still a confirmed "
     "Oracle listener and a foothold surface."),
    ("4. Runbook",
     "The follow-on commands (odat sidguesser/passwordguesser, nmap oracle-sid-brute, "
     "tnscmd status, the CVE-2012-1675 poison check, default-cred spray) are staged."),
]

_finding = finding_builder("oracle", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_oracle(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr or not pr.get("is_oracle"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            banner = pr.get("banner", "")
            detail = ("recce confirmed an Oracle TNS listener"
                      + (f" ({pr.get('tns_type')} response)" if pr.get("tns_type") else "")
                      + (f"; version {ver}" if ver else "")
                      + (f"; banner: {banner}" if banner else "")
                      + ". Exposed listeners allow SID enumeration/brute, TNS Poison "
                        "(CVE-2012-1675), and default-credential access.")
            out.append(_finding(
                "high", "Oracle TNS listener exposed", tgt, detail,
                "odat",
                f"odat sidguesser -s {h.ip} -p {p.portid} ; "
                f"nmap -p{p.portid} --script oracle-sid-brute,oracle-tns-version {h.ip} ; "
                f"# then odat passwordguesser with the default-account list",
                "Set a listener password / valid-node-checking (TCP.VALIDNODE_CHECKING), "
                "apply the CVE-2012-1675 fix, remove default accounts, firewall 1521.",
                ["CWE-306", "CWE-1188"], kind="oracle_tns_exposed"))
            if pr.get("version_leaked"):
                out.append(_finding(
                    "medium", "Oracle TNS listener version disclosure", tgt,
                    f"The listener disclosed version {ver} to an unauthenticated status "
                    "request" + (f" ({banner})" if banner else "")
                    + " - lets an attacker target the exact patch level.",
                    "tnscmd", f"tnscmd10g version -h {h.ip} -p {p.portid}",
                    "Restrict listener admin to local OS auth; set ADMIN_RESTRICTIONS_"
                    "<listener>=ON; firewall the port.",
                    ["CWE-200"], kind="oracle_version_leak"))
    return out


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE",
         f"nmap -p{port} --script oracle-tns-version,oracle-sid-brute {ip}",
         "Fingerprint the listener version and brute-force the SID/service names."),
        ("enumerate", "odat",
         f"odat sidguesser -s {ip} -p {port} ; odat tnscmd -s {ip} -p {port} --status",
         "Recover SIDs and query listener status (no credential)."),
        ("access", "odat / sqlplus",
         f"odat passwordguesser -s {ip} -p {port} -d <SID> --accounts-file default.txt ; "
         f"sqlplus scott/tiger@{ip}:{port}/<SID>",
         "Spray default accounts (scott/tiger, system/manager, dbsnmp) against a SID."),
        ("escalate", "TNS Poison / odat",
         "# CVE-2012-1675: register a rogue instance to MITM sessions on an unpatched\n"
         "# listener. Post-auth: odat utlfile/externaltable/dbmsscheduler -> OS command exec.",
         "Turn listener/DB access into MITM or OS command execution (in scope only)."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


proof_html = make_proof_html_wrapper("SQL> ")
findings_to_vulns = make_findings_to_vulns_wrapper("oracle", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full Oracle TNS analysis. Returns {targets, findings, runbooks, probes, stats}."""
    from ... import svcprobe
    targets = oracle_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["is_oracle"] = pr.get("is_oracle", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
