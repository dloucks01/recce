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

from ...core.models import Host, Port
from ..svccommon import finding_builder, make_proof_html_wrapper, make_findings_to_vulns_wrapper

_PORTS = (1521, 1522, 1526, 1748, 1754)
_DEFAULT_PORT = 1521
_TIMEOUT = 6.0
_MAX_REPLY = 64 * 1024

# TNS packet types (header byte at offset 4).
_TNS_TYPES = {1: "CONNECT", 2: "ACCEPT", 4: "REFUSE", 5: "REDIRECT", 6: "DATA",
              11: "RESEND", 12: "MARKER"}
_VER_RE = re.compile(rb"Version\s+(\d+\.\d+\.\d+\.\d+(?:\.\d+)?)", re.I)
_TNSLSNR_RE = re.compile(rb"TNSLSNR for [^\r\n]+", re.I)

# Extractors for the (COMMAND=services)/(COMMAND=status) DATA payload — a legacy
# listener returns a text `(DESCRIPTION=...(SERVICE=(SERVICE_NAME=..)(INSTANCE=..))..)`
# blob whose keys are stable across 9i/10g/11g/12c/19c.
_SID_RE = re.compile(rb"SID(?:_NAME)?\s*=\s*([A-Za-z0-9_$.\-]+)")
_SVC_NAME_RE = re.compile(rb"SERVICE_NAME\s*=\s*([A-Za-z0-9_$.\-]+)")
_INSTANCE_RE = re.compile(rb"INSTANCE_NAME\s*=\s*([A-Za-z0-9_$.\-]+)")
_MACHINE_RE = re.compile(rb"MACHINE\s*=\s*([A-Za-z0-9_\-.]+)")
_HOST_HDR_RE = re.compile(rb"on host\s+([A-Za-z0-9_\-.]+)", re.I)
# REDIRECT (packet type 5) payload — SCAN/RAC listener directs the client to an
# internal cluster node; the HOST/PORT are plain text inside an (ADDRESS=..) tuple.
_REDIRECT_HOST_RE = re.compile(rb"HOST\s*=\s*([A-Za-z0-9_\-.]+)", re.I)
_REDIRECT_PORT_RE = re.compile(rb"PORT\s*=\s*(\d+)", re.I)


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


# --- offline version -> CVE mapping ---------------------------------------------

def _version_tuple(version: str) -> tuple:
    """Turn a dotted Oracle version like '11.2.0.3.0' into a 4-tuple (major, minor,
    patch, security) for range comparison. Extra components are dropped; short
    versions are right-padded with zeros. Returns () when nothing parseable."""
    if not version:
        return ()
    parts = re.findall(r"\d+", version)[:4]
    if not parts:
        return ()
    ints = [int(x) for x in parts]
    while len(ints) < 4:
        ints.append(0)
    return tuple(ints[:4])


# (predicate(vt) -> bool, finding-dict). Ranges from Oracle CPU advisories; the
# same version can hit more than one entry (e.g. 11.2.0.1 -> both 2012 CVEs).
_CVE_MAP: tuple = (
    (lambda v: bool(v) and v < (11, 2, 0, 4),
     {"id": "CVE-2012-1675", "severity": "high",
      "title": "TNS Poison (remote instance registration)",
      "description": "Listener accepts unsolicited remote instance registration from any "
                     "IP; a rogue instance can MITM subsequent client sessions. "
                     "Mitigation: ADMIN_RESTRICTIONS_<listener>=ON and valid-node "
                     "checking (Oracle Alert CVE-2012-1675).",
      "exploit_note": "For CVE-2012-1675: msf auxiliary/admin/oracle/tnspoison_checker "
                      "RHOST=<ip>; for CVE-2012-3137: native o5logon-grab per "
                      "oracle_listener_status_leak.",
      "depth_tier": "t0"}),
    (lambda v: bool(v) and v <= (11, 2, 0, 3),
     {"id": "CVE-2012-3137", "severity": "high",
      "title": "o5logon pre-auth hash disclosure",
      "description": "The AUTH exchange for a known SID returns AUTH_SESSKEY + "
                     "AUTH_VFR_DATA to any client that names a user, yielding a "
                     "SHA-1/AES-192 hash that JtR ('oracle11') and hashcat (mode 3100) "
                     "crack offline.",
      "exploit_note": "For CVE-2012-1675: msf auxiliary/admin/oracle/tnspoison_checker "
                      "RHOST=<ip>; for CVE-2012-3137: native o5logon-grab per "
                      "oracle_listener_status_leak.",
      "depth_tier": "t0"}),
)


def _known_cves(version: str) -> list[dict]:
    """Offline lookup: return the CVE entries whose vulnerable-range predicate matches
    `version`. Empty list when the version is unknown or post-patch."""
    v = _version_tuple(version)
    return [entry for pred, entry in _CVE_MAP if pred(v)]


# --- listener status / REDIRECT parsing -----------------------------------------

def _tns_probe(ip: str, port: int, timeout: float, payload: bytes) -> bytes:
    """Send one TNS CONNECT carrying `payload` and return the raw reply bytes (or
    b'' on any socket / framing error). Used for the follow-on services/status
    probes; each Oracle listener CONNECT is stateless so a fresh socket is fine."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_tns_connect(payload))
            return _recv(sock)
    except (OSError, socket.timeout, struct.error):
        return b""


def _parse_listener_dump(reply: bytes) -> dict:
    """Extract SIDs / SERVICE_NAMEs / INSTANCE_NAMEs / machine hostname from a
    (COMMAND=services|status) DATA payload. All keys empty when nothing matches -
    a hardened listener that refused the request leaves this a no-op."""
    if not reply:
        return {"sids": [], "service_names": [], "instances": [], "machine": ""}
    sids = sorted({m.group(1).decode("ascii", "replace")
                   for m in _SID_RE.finditer(reply)})
    services = sorted({m.group(1).decode("ascii", "replace")
                       for m in _SVC_NAME_RE.finditer(reply)})
    instances = sorted({m.group(1).decode("ascii", "replace")
                        for m in _INSTANCE_RE.finditer(reply)})
    machine = ""
    m = _MACHINE_RE.search(reply) or _HOST_HDR_RE.search(reply)
    if m:
        machine = m.group(1).decode("ascii", "replace")
    return {"sids": sids, "service_names": services, "instances": instances,
            "machine": machine}


def _parse_redirect(reply: bytes) -> dict:
    """A REDIRECT (packet type 5) reply carries an (ADDRESS=(HOST=..)(PORT=..)) with
    the internal cluster node the SCAN listener wants the client to talk to - often
    an RFC1918 address not otherwise reachable. Returns {} for non-REDIRECT or
    when no HOST= is present."""
    if not reply or len(reply) < 5 or reply[4] != 5:
        return {}
    h = _REDIRECT_HOST_RE.search(reply)
    if not h:
        return {}
    p = _REDIRECT_PORT_RE.search(reply)
    return {"host": h.group(1).decode("ascii", "replace"),
            "port": int(p.group(1)) if p else 0}


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
    {reachable, is_oracle, tns_type, version, banner, version_leaked, error,
    sids, service_names, instances, machine, known_cves, redirect}.

    After the initial (COMMAND=version) confirms the listener, best-effort
    (COMMAND=services) + (COMMAND=status) probes are sent on fresh connections;
    a legacy / unhardened listener returns a DATA blob carrying SIDs /
    SERVICE_NAMEs / INSTANCE_NAMEs and the machine hostname (Oracle Note 260986.1).
    Version -> CVE mapping is an offline lookup off `_CVE_MAP`."""
    res: dict = {"reachable": False, "is_oracle": False, "tns_type": "", "version": "",
                 "banner": "", "version_leaked": False, "error": "",
                 "sids": [], "service_names": [], "instances": [], "machine": "",
                 "known_cves": [], "redirect": {}}
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
            # SCAN/RAC listeners frequently answer the version probe with a REDIRECT
            # to the internal cluster node — parse it before the connection closes.
            redir = _parse_redirect(reply)
            if redir:
                res["redirect"] = redir
            # Machine hostname sometimes leaks in the primary banner too (e.g.
            # "TNSLSNR for Linux: Version 11.2.0.4.0 ... on host prod-db01.corp.local").
            primary = _parse_listener_dump(reply)
            if primary["machine"]:
                res["machine"] = primary["machine"]
    except (OSError, socket.timeout, struct.error) as e:
        res["error"] = res["error"] or str(e)
        return res

    # Follow-on probes: only if we're sure this is Oracle. Each opens its own
    # short socket (listener CONNECT is stateless); failures are non-fatal.
    if res["is_oracle"]:
        for cmd in (b"(CONNECT_DATA=(COMMAND=services))",
                    b"(CONNECT_DATA=(COMMAND=status))"):
            dump = _tns_probe(ip, port, timeout, cmd)
            if not dump:
                continue
            parsed = _parse_listener_dump(dump)
            for key in ("sids", "service_names", "instances"):
                res[key] = sorted(set(res[key]) | set(parsed[key]))
            if not res["machine"] and parsed["machine"]:
                res["machine"] = parsed["machine"]
            if not res["redirect"]:
                redir = _parse_redirect(dump)
                if redir:
                    res["redirect"] = redir
        # Offline version -> CVE lookup; empty when version is unknown / post-patch.
        res["known_cves"] = _known_cves(res.get("version", ""))
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
    "oracle_listener_status_leak": (
        "The listener answered a (COMMAND=services)/(COMMAND=status) request without "
        "authentication, dumping SIDs / SERVICE_NAMEs / instance names and (often) the "
        "machine hostname. Each SID is a foothold candidate: post-auth default-cred "
        "spray (sys/change_on_install, system/manager, dbsnmp/dbsnmp, scott/tiger), "
        "the o5logon pre-auth hash grab (CVE-2012-3137) against known SIDs, and "
        "credential-material feeds for downstream attacks. Enable "
        "LOCAL_OS_AUTHENTICATION_<listener>=ON and restrict admin to the local UNIX "
        "socket / named-pipe."),
    "oracle_known_vulnerable_version": (
        "The banner version falls in a range with a published Oracle CVE. This is a "
        "candidate flag (the exact CPU patch level isn't in the banner) - confirm "
        "with the listed advisory / CPU. High-value chains include TNS Poison "
        "(CVE-2012-1675: MITM future clients) and the o5logon pre-auth hash grab "
        "(CVE-2012-3137: offline crackable hashes)."),
    "oracle_rac_internal_endpoint_leak": (
        "A SCAN / RAC listener answered with a REDIRECT to an internal cluster node "
        "(often RFC1918) - a fresh host for lateral movement and a data point for "
        "network-topology reconstruction. Front-end the SCAN listener with a firewall "
        "or NAT that does not leak internal cluster addresses."),
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
                ["CWE-306", "CWE-1188"], kind="oracle_tns_exposed",
                exploit_note=(
                    f"odat all -s {h.ip} -p {p.portid}; odat sidguesser -s {h.ip} "
                    f"-p {p.portid}; odat passwordguesser -s {h.ip} -p {p.portid} "
                    "-d <SID> --accounts-file default.txt; sqlplus "
                    f"scott/tiger@{h.ip}:{p.portid}/<SID>."),
                depth_tier="t1"))
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
            # NEW: version -> CVE mapping (offline; each entry a separate finding).
            for cve in pr.get("known_cves") or []:
                out.append(_finding(
                    cve.get("severity", "high"),
                    f"Oracle {cve['id']} candidate: {cve.get('title', '')}".rstrip(": "),
                    tgt,
                    f"Reported version {ver or '(unknown)'} is in the vulnerable range "
                    f"for {cve['id']}. {cve.get('description', '')}",
                    "odat",
                    f"# {cve['id']}: consult Oracle CPU / security-alert advisory for "
                    f"{cve['id']} and apply the fix.",
                    "Apply the corresponding Oracle CPU / security-alert patch and "
                    "harden the listener (ADMIN_RESTRICTIONS_<listener>=ON, "
                    "valid-node checking, remove default accounts).",
                    ["CWE-1035"], kind="oracle_known_vulnerable_version",
                    exploit_note=cve.get("exploit_note", ""),
                    depth_tier=cve.get("depth_tier", "")))
            # NEW: listener status / services dump (SIDs, service names, machine).
            sids = pr.get("sids") or []
            svc_names = pr.get("service_names") or []
            instances = pr.get("instances") or []
            machine = pr.get("machine") or ""
            if sids or svc_names or instances or machine:
                names = sorted(set(sids) | set(svc_names) | set(instances))
                detail = ("The listener returned service/status data to an "
                          "unauthenticated request."
                          + (f" SIDs / services: {', '.join(names[:12])}."
                             if names else "")
                          + (f" Machine: {machine}." if machine else "")
                          + " Each SID is a candidate for post-auth logon (default "
                            "credentials, o5logon pre-auth hash grab, etc.).")
                out.append(_finding(
                    "high", "Oracle listener status / services leak", tgt, detail,
                    "tnscmd10g",
                    f"tnscmd10g services -h {h.ip} -p {p.portid} ; "
                    f"tnscmd10g status -h {h.ip} -p {p.portid}",
                    "Enable LOCAL_OS_AUTHENTICATION_<listener>=ON, set "
                    "ADMIN_RESTRICTIONS_<listener>=ON, and restrict listener admin "
                    "to the local UNIX socket / named-pipe.",
                    ["CWE-200"], kind="oracle_listener_status_leak",
                    exploit_note=(
                        f"For each SID, python3 pre-auth-oracle-hash-grab.py -s {h.ip} "
                        f"-p {p.portid} -d <SID> -u SYS -o hashes.txt; then hashcat "
                        "-m 3100 hashes.txt rockyou.txt (JtR: oracle11 format)."),
                    depth_tier="t1"))
            # NEW: SCAN/RAC REDIRECT payload exposes an internal cluster endpoint.
            redir = pr.get("redirect") or {}
            if redir.get("host"):
                rt = redir["host"] + (f":{redir['port']}" if redir.get("port") else "")
                out.append(_finding(
                    "medium", "Oracle SCAN/RAC redirect leaks internal endpoint",
                    tgt,
                    f"The listener redirected the client to internal node '{rt}', "
                    "revealing a cluster member - often an RFC1918 address not "
                    "otherwise reachable from outside the perimeter.",
                    "tnscmd10g",
                    f"tnscmd10g services -h {h.ip} -p {p.portid}",
                    "Front-end the SCAN listener with a firewall / NAT that does not "
                    "leak internal cluster addresses; use REMOTE_LISTENER only inside "
                    "the trusted cluster network.",
                    ["CWE-200"], kind="oracle_rac_internal_endpoint_leak"))
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
    from .. import svcprobe
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
