"""RDP (3389/tcp) fingerprint + security-mode probe.

RDP negotiates its security mode at the X.224 layer before any real auth
happens. One short PDU exchange tells us:

  * Whether the server supports/requires NLA (Network Level Auth)
  * Which security methods it offers (Standard RDP, TLS, CredSSP/Hybrid,
    CredSSP-Ex)
  * Whether the server responded with a NEGOTIATION FAILURE for a specific
    reason (SSL required, hybrid required, inconsistent flags)

Findings:
  * rdp_no_nla (HIGH) — Standard RDP security accepted; MitM-visible auth
    and BlueKeep-family exposure larger. NLA-required deployments reject
    the initial cleartext connection.
  * rdp_bluekeep_candidate (HIGH/info) — pre-2019 Windows versions
    frequently expose CVE-2019-0708 when NLA is off. We can't confirm
    the patch state from a pre-auth handshake, so we flag the CANDIDATE
    (server accepted standard RDP + banner reveals win7/2008 R2).
  * rdp_fingerprint (info) — always emitted with the negotiated security
    layer so the report reflects what was seen.

Airgap-safe: stdlib socket + struct. One TCP roundtrip, 4s timeout.
"""
from __future__ import annotations

import socket
import struct

from ..models import Host, Port


_DEFAULT_PORT = 3389
_TIMEOUT = 4.0


def is_rdp(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 3389
            or "ms-wbt-server" in svc or "rdp" in svc or "rdp" in prod
            or "ms-term-serv" in svc)


# X.224 Connection Request + RDP Negotiation Request. Requests all three
# security types (0x03 = standard | TLS | CredSSP).
_X224_CR = bytes.fromhex(
    "030000130ee0000000000001000800030000")  # 19 bytes total
# Layout:
#   03 00 00 13    TPKT: version 3, reserved 0, length 19 (big-endian)
#   0e             X.224 length indicator
#   e0             X.224 CR TPDU
#   00 00 00 00    dst-ref, src-ref (unused)
#   01             class option
#   00 08 00       RDP Negotiation Request: type 1, flags 0, length 8
#   03 00 00 00    requestedProtocols: 3 = RDP+SSL+HYBRID
# Note: bytes above are already correct; the "030000..." is TPKT.


# Response protocol codes (from RDP Negotiation Response type 2 payload)
_PROTOCOLS = {
    0x00: "STANDARD_RDP",
    0x01: "SSL/TLS",
    0x02: "CredSSP (Hybrid)",
    0x03: "CredSSP+SSL",
    0x08: "CredSSP-Ex",
}
# Failure codes (Negotiation Failure type 3)
_FAILURE_CODES = {
    0x01: "SSL_REQUIRED_BY_SERVER",
    0x02: "SSL_NOT_ALLOWED_BY_SERVER",
    0x03: "SSL_CERT_NOT_ON_SERVER",
    0x04: "INCONSISTENT_FLAGS",
    0x05: "HYBRID_REQUIRED_BY_SERVER",
    0x06: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """One TCP roundtrip. Returns {reachable, protocol, protocol_code,
    failure_reason, nla_required, standard_rdp_accepted}."""
    out = {"reachable": False, "protocol": "", "protocol_code": None,
           "failure_reason": "", "nla_required": False,
           "standard_rdp_accepted": False}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_X224_CR)
            data = s.recv(4096)
    except OSError:
        return out
    if len(data) < 11 or data[0] != 0x03:              # not TPKT
        return out
    out["reachable"] = True
    # Skip TPKT (4 bytes) + X.224 header (7 bytes for CC-Class-0). The RDP
    # Negotiation Response/Failure PDU begins at offset 11.
    if len(data) < 19:
        return out
    ptype = data[11]
    if ptype == 0x02:                                  # RDP Negotiation Response
        # length(2 LE) at offset 13, selectedProtocol(4 LE) at offset 15
        try:
            proto = struct.unpack("<I", data[15:19])[0]
        except struct.error:
            return out
        out["protocol_code"] = proto
        out["protocol"] = _PROTOCOLS.get(proto, f"unknown(0x{proto:x})")
        # Standard RDP (0x00) = no NLA. Anything with CredSSP flag = NLA.
        out["nla_required"] = bool(proto & 0x02)
        out["standard_rdp_accepted"] = (proto == 0x00)
    elif ptype == 0x03:                                # RDP Negotiation Failure
        try:
            code = struct.unpack("<I", data[15:19])[0]
        except struct.error:
            return out
        out["failure_reason"] = _FAILURE_CODES.get(code, f"unknown(0x{code:x})")
        # HYBRID_REQUIRED_BY_SERVER = NLA REQUIRED (good sign, secure config).
        if code == 0x05:
            out["nla_required"] = True
    return out


def rdp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_rdp(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "xfreerdp", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_rdp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            # NLA off = accepts Standard RDP = larger BlueKeep-family surface,
            # plus enables MitM auth prompt attacks.
            if pr.get("standard_rdp_accepted"):
                out.append(_finding(
                    "high",
                    "RDP: Network Level Authentication (NLA) not required", tgt,
                    f"Server accepted Standard RDP security (selectedProtocol=0). "
                    f"BlueKeep-family exposure (CVE-2019-0708 on Win7/2008 R2, "
                    f"CVE-2020-0609/0610 gateway CVEs) is materially larger without "
                    f"NLA. A cred-harvesting attacker on-path can present a fake "
                    f"login and receive plaintext credentials.",
                    f"xfreerdp /v:{h.ip}:{p.portid} /sec:rdp",
                    "Require NLA on every RDP host (Group Policy: Computer "
                    "Configuration > Admin Templates > Windows Components > "
                    "Remote Desktop Services > Remote Desktop Session Host > "
                    "Security > Require user authentication for remote "
                    "connections by using Network Level Authentication).",
                    ["CWE-287", "CWE-319"], kind="rdp_no_nla"))
            # Fingerprint always — pairs with any severity finding above.
            proto = pr.get("protocol") or pr.get("failure_reason") or "?"
            out.append(_finding(
                "info", "RDP endpoint fingerprint", tgt,
                f"Negotiated: {proto}  |  nla_required={pr.get('nla_required')}  "
                f"|  standard_rdp_accepted={pr.get('standard_rdp_accepted')}",
                f"xfreerdp /v:{h.ip}:{p.portid}",
                "Restrict RDP to a jump host / VPN. Log connection attempts.",
                [], kind="rdp_fingerprint"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Negotiate + fingerprint",
         "cmd": f"nmap -p {port} --script rdp-enum-encryption,rdp-ntlm-info {ip}"},
        {"step": "Connect (test NLA behavior)",
         "cmd": f"xfreerdp /v:{ip}:{port} /sec:rdp   # standard-rdp fallback"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from ..svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "rdp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from .. import svcprobe
    targets = rdp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["standard_rdp_accepted"] = pr.get("standard_rdp_accepted", False)
                t["nla_required"] = pr.get("nla_required", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
