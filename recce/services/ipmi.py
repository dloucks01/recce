"""IPMI (623/udp) authentication-capability probe.

IPMI is the management protocol for baseboard management controllers (iDRAC,
iLO, IPMI-over-BMC on rack servers). Two long-standing exposures:

  * **Cipher suite 0** (CVE-2013-4786) — when the BMC allows cipher 0 in
    its authentication capabilities, ANY user with a valid username +
    ANY password authenticates as admin. Reported in the Get Channel
    Authentication Capabilities response when the "OEM proprietary"
    or "None" auth type is offered alongside admin-privilege access.
  * **Anonymous / null-user logon** — the BMC advertises that user
    slot 0 (empty username) is enabled. Combined with a default admin
    password (ADMIN/admin), this is instant control of the host BIOS,
    KVM, and power cycle.

Also flags MD2/MD5 as weak auth algorithms, since anyone reading the
capabilities bitmask should know they're accepted.

Probe: one UDP packet — RMCP header + IPMI 1.5 session header +
Get Channel Auth Capabilities (0x06/0x38) request for channel 0x0E
(current channel), admin privilege level (0x04).

Airgap-safe: stdlib socket + struct. Single send + recv, ~2s timeout.
"""
from __future__ import annotations

import socket

from ..core.models import Host, Port


_DEFAULT_PORT = 623
_TIMEOUT = 3.0


def is_ipmi(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 623
            or "ipmi" in svc or "asf-rmcp" in svc or "ipmi" in prod)


# The Get Channel Auth Capabilities request, hex-annotated:
#   RMCP header
#     06         version 6 (RMCP)
#     00         reserved
#     ff         sequence (0xff = no ACK needed)
#     07         class 7 (IPMI)
#   IPMI 1.5 Session header
#     00         auth type 0 (none - we're just probing)
#     00 00 00 00   session seq
#     00 00 00 00   session id
#     09         message length (9 bytes of IPMI msg follow)
#   IPMI message
#     20         rsAddr (BMC = 0x20)
#     18         netFn 0x06 (APP) << 2 | lun 0
#     c8         checksum 1
#     81         rqAddr (remote console)
#     00         rqSeq << 2 | lun 0
#     38         cmd (Get Channel Auth Cap)
#     8e         channel 0x0e (current) with bit 7 set to request IPMI 2.0 data
#     04         privilege level (admin)
#     b5         checksum 2
_GCAC_REQUEST = bytes.fromhex("0600ff07"                # RMCP
                              "00" "00000000" "00000000" "09"  # session hdr
                              "20" "18" "c8"            # rsAddr/netFn/csum
                              "81" "00" "38" "8e" "04" "b5")   # ipmi msg + csum


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Send one Get Channel Auth Capabilities request; parse response for
    auth-type bitmap + support flags. Returns {reachable, ipmi_version,
    auth_types, null_user, anonymous_login, cipher_zero, ipmi_20}."""
    out = {"reachable": False, "ipmi_version": "", "auth_types": [],
           "null_user": False, "anonymous_login": False,
           "cipher_zero": False, "ipmi_20": False}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(_GCAC_REQUEST, (ip, port))
            data, _addr = sock.recvfrom(1024)
        finally:
            sock.close()
    except OSError:
        return out
    if len(data) < 22:
        return out
    # Verify this is a valid RMCP/IPMI response.
    if data[0] != 0x06 or data[3] != 0x07:
        return out
    out["reachable"] = True
    # After the RMCP header (4 bytes) + session header (10 bytes) + message
    # length (1 byte), the IPMI response payload begins. Its layout is:
    #   rqAddr(1) netFn|lun(1) csum(1) rsAddr(1) rsSeq|lun(1) cmd(1)
    #   compCode(1) channel(1) authTypes(1) authStatus(1) extCaps(1) oem(3)
    # We only need authTypes and authStatus.
    # Auth type = 0 in the response, so no MAC bytes are present:
    #   RMCP(4) + auth_type(1) + seq(4) + session_id(4) + msg_len(1) = 14
    payload_start = 14
    # Payload minimum: 6 header bytes + compCode + channel + authTypes +
    # authStatus + extCaps = 11. Bounds-check.
    if len(data) < payload_start + 11:
        return out
    comp_code = data[payload_start + 6]
    if comp_code != 0:                              # non-zero = error
        return out
    auth_types = data[payload_start + 8]
    auth_status = data[payload_start + 9]
    ext_caps = data[payload_start + 10]
    # Auth type bitmap (bits 0..5):
    #   bit 0: none    bit 1: MD2       bit 2: MD5
    #   bit 3: reserved bit 4: straight (password) bit 5: OEM
    labels = {0x01: "none", 0x02: "MD2", 0x04: "MD5",
              0x10: "password", 0x20: "OEM"}
    accepted = []
    for mask, label in labels.items():
        if auth_types & mask:
            accepted.append(label)
    out["auth_types"] = accepted
    # Auth Status byte (bits 0..5):
    #   bit 0: anonymous logon    bit 1: null user
    #   bit 2: non-null user      bit 3: user-level auth disabled
    #   bit 4: per-msg auth disabled  bit 5: KG set
    out["anonymous_login"] = bool(auth_status & 0x01)
    out["null_user"] = bool(auth_status & 0x02)
    # Extended capabilities:
    #   bit 0: IPMI 2.0 supported     bit 1: IPMI 1.5 supported
    out["ipmi_20"] = bool(ext_caps & 0x01)
    # Cipher suite 0 (CVE-2013-4786) shows up in the IPMI 2.0 auth type
    # bitmap as auth-alg 0 in the RAKP negotiation. The GCAC response doesn't
    # carry the cipher-suite list directly — that's a separate command
    # (Get Channel Cipher Suites, 0x54). But the "none" auth type here plus
    # IPMI 2.0 = strong indicator that cipher 0 is at least offered as an
    # option; we mark it accordingly with a caveat in the finding.
    out["cipher_zero"] = "none" in accepted and out["ipmi_20"]
    if out["ipmi_20"]:
        out["ipmi_version"] = "2.0"
    else:
        out["ipmi_version"] = "1.5"
    return out


def ipmi_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_ipmi(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "ipmitool", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_ipmi(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            # Cipher suite 0 (CVE-2013-4786): critical — ANY password works.
            if pr.get("cipher_zero"):
                out.append(_finding(
                    "critical",
                    "IPMI cipher suite 0 supported (CVE-2013-4786)", tgt,
                    f"BMC advertises 'none' auth in IPMI {pr.get('ipmi_version','2.0')} "
                    f"capabilities. If cipher suite 0 is actually enabled (Get Channel "
                    f"Cipher Suites confirms), ANY valid username with ANY password "
                    f"authenticates as admin. Verify with: ipmitool -I lanplus -C 0 "
                    f"-H {h.ip} -U root -P '' chassis power status",
                    f"ipmitool -I lanplus -C 0 -H {h.ip} -U <user> -P anything user list",
                    "Disable cipher suite 0 on the BMC (vendor-specific — Dell iDRAC: "
                    "Racadm config -g cfgIpmiLan -o cfgIpmiLanEnable 0 or set only "
                    "cipher suites 3+; HPE iLO: ipmi cipher-suite disable). If BMC "
                    "management is not needed remotely, restrict to a dedicated OOB "
                    "management network.",
                    ["CWE-287", "CWE-306"], kind="ipmi_cipher_zero"))
            # Anonymous / null-user logon.
            if pr.get("anonymous_login") or pr.get("null_user"):
                which = []
                if pr.get("anonymous_login"): which.append("anonymous")
                if pr.get("null_user"): which.append("null user")
                out.append(_finding(
                    "high",
                    "IPMI null-user / anonymous logon enabled", tgt,
                    f"BMC accepts {' and '.join(which)} authentication. Combined with a "
                    f"default admin password (ADMIN/admin/'') on user slot 1, this is "
                    f"direct control of the host — BIOS, KVM, power cycle, virtual "
                    f"media (which lets an attacker mount a bootable ISO and re-image).",
                    f"ipmitool -I lanplus -H {h.ip} -U '' -P '' user list",
                    "Disable anonymous / null-user logon. Set strong unique passwords "
                    "on every enabled BMC user slot; disable unused slots.",
                    ["CWE-287", "CWE-521"], kind="ipmi_anonymous"))
            # Weak auth algorithms.
            weak = [t for t in ("MD2", "MD5") if t in (pr.get("auth_types") or [])]
            if weak:
                out.append(_finding(
                    "medium",
                    f"IPMI weak auth algorithm(s) advertised: {', '.join(weak)}", tgt,
                    f"BMC offers {', '.join(weak)} in Get Channel Auth Capabilities. "
                    "MD2/MD5-HMAC in IPMI is deprecated; a captured RAKP2 handshake is "
                    "offline-crackable in the tester's own toolkit (hashcat -m 7300).",
                    f"ipmitool -H {h.ip} -I lan -U root -a channel authcap 14 4",
                    "Disable MD2 and MD5 auth types on the BMC; require the strongest "
                    "supported cipher (typically RAKP-HMAC-SHA256).",
                    ["CWE-327", "CWE-916"], kind="ipmi_weak_auth"))
            # Always emit an info-level fingerprint so IPMI presence is in the report.
            out.append(_finding(
                "info", "IPMI endpoint reachable", tgt,
                f"IPMI {pr.get('ipmi_version','?')} auth capabilities enumerated: "
                f"types={pr.get('auth_types')} null_user={pr.get('null_user')} "
                f"anonymous={pr.get('anonymous_login')}",
                f"ipmitool -H {h.ip} -I lan channel info",
                "Restrict IPMI to a dedicated management network.",
                [], kind="ipmi_fingerprint"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Enumerate auth capabilities",
         "cmd": f"ipmitool -H {ip} -I lan channel authcap 14 4"},
        {"step": "Cipher-zero admin test (CVE-2013-4786)",
         "cmd": f"ipmitool -I lanplus -C 0 -H {ip} -U root -P '' user list"},
        {"step": "List cipher suites the BMC supports",
         "cmd": f"ipmitool -H {ip} -I lan channel getciphers ipmi 14"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "ipmi", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = ipmi_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["cipher_zero"] = pr.get("cipher_zero", False)
                t["anonymous"] = pr.get("anonymous_login", False) or pr.get("null_user", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
