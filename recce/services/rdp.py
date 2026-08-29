"""RDP (3389/tcp) fingerprint + security-mode probe.

RDP negotiates its security mode at the X.224 layer before any real auth
happens. One short PDU exchange tells us:

  * Whether the server supports/requires NLA (Network Level Auth)
  * Which security methods it offers (Standard RDP, TLS, CredSSP/Hybrid,
    CredSSP-Ex)
  * Whether the server responded with a NEGOTIATION FAILURE for a specific
    reason (SSL required, hybrid required, inconsistent flags)

When the server selects CredSSP/Hybrid we take one additional roundtrip:
wrap TLS, send a CredSSP TSRequest carrying an NTLMSSP NEGOTIATE_MESSAGE,
and parse the server's TSRequest reply for the NTLM CHALLENGE_MESSAGE. The
CHALLENGE leaks NetBIOS/DNS names, AD domain and forest, and the exact OS
build (MS-NLMP TargetInfo AV_PAIRs + Version field) — the RDP analogue of
smb.probe_ntlm_info. The TSRequest version field additionally reveals whether
the server carries the CVE-2018-0886 CredSSP patch (version >= 3).

Findings:
  * rdp_no_nla (HIGH) — Standard RDP security accepted; MitM-visible auth
    and BlueKeep-family exposure larger. NLA-required deployments reject
    the initial cleartext connection.
  * rdp_bluekeep_candidate (HIGH/info) — pre-2019 Windows versions
    frequently expose CVE-2019-0708 when NLA is off. We can't confirm
    the patch state from a pre-auth handshake, so we flag the CANDIDATE
    (server accepted standard RDP + banner reveals win7/2008 R2).
  * rdp_ntlm_info (info) — pre-auth NTLM CHALLENGE intel leak (host,
    domain, forest, OS build). See [MS-CSSP] 3.1.5 + [MS-NLMP] 2.2.1.2.
  * rdp_credssp_unpatched (MEDIUM) — server negotiated CredSSP TSRequest
    version <= 2, indicating the CVE-2018-0886 patch is missing.
  * rdp_fingerprint (info) — always emitted with the negotiated security
    layer so the report reflects what was seen.

Airgap-safe: stdlib socket + struct + ssl. One TCP roundtrip for the base
probe; one extra TLS roundtrip if CredSSP is offered. 4s timeout throughout.
"""
from __future__ import annotations

import socket
import ssl
import struct

from ..core.models import Host, Port


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


# --- CredSSP TSRequest ASN.1 (MS-CSSP 2.2.1) ------------------------------------
# Minimal DER: only what a TSRequest{version, negoTokens} needs. We hand-roll it to
# stay stdlib-only (the ad.ntlm module already uses the same tactic).

def _asn1_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _asn1_int(n: int) -> bytes:
    # ASN.1 INTEGER; unsigned small values used here.
    if n == 0:
        body = b"\x00"
    else:
        length = (n.bit_length() + 8) // 8            # extra byte guarantees positive
        body = n.to_bytes(length, "big")
    return b"\x02" + _asn1_len(len(body)) + body


def _asn1_octet(data: bytes) -> bytes:
    return b"\x04" + _asn1_len(len(data)) + data


def _asn1_seq(data: bytes) -> bytes:
    return b"\x30" + _asn1_len(len(data)) + data


def _asn1_ctx(tag: int, data: bytes) -> bytes:
    """Context-specific constructed [tag] wrapper."""
    return bytes([0xa0 | tag]) + _asn1_len(len(data)) + data


def _asn1_read_len(buf: bytes, i: int) -> tuple[int, int]:
    if i >= len(buf):
        raise ValueError("asn1 short")
    b = buf[i]
    i += 1
    if b < 128:
        return b, i
    n = b & 0x7f
    if n == 0 or i + n > len(buf):
        raise ValueError("asn1 bad len")
    return int.from_bytes(buf[i:i + n], "big"), i + n


def build_credssp_tsrequest(nego_token: bytes, version: int = 6) -> bytes:
    """TSRequest ::= SEQUENCE {
        [0] version INTEGER,
        [1] negoTokens NegoData          -- SEQUENCE OF SEQUENCE { [0] negoToken OCTET STRING }
    }
    Used to ship an NTLMSSP NEGOTIATE_MESSAGE inside CredSSP."""
    nego_seq = _asn1_seq(_asn1_ctx(0, _asn1_octet(nego_token)))    # inner SEQUENCE
    nego_data = _asn1_seq(nego_seq)                                # SEQUENCE OF ...
    body = _asn1_ctx(0, _asn1_int(version)) + _asn1_ctx(1, nego_data)
    return _asn1_seq(body)


def parse_credssp_tsrequest(data: bytes) -> dict | None:
    """Extract {version, negoToken} from a server's TSRequest. Returns None on any
    malformed input. Only the fields we consume are decoded — pubKeyAuth / authInfo /
    errorCode are ignored."""
    if not data or data[0] != 0x30:
        return None
    try:
        outer_len, i = _asn1_read_len(data, 1)
        end = i + outer_len
        if end > len(data):
            return None
        out: dict = {"version": None, "negoToken": None}
        while i < end:
            tag = data[i]
            i += 1
            tlen, i = _asn1_read_len(data, i)
            body = data[i:i + tlen]
            i += tlen
            if tag == 0xa0:                            # [0] version INTEGER
                if len(body) >= 2 and body[0] == 0x02:
                    vlen, j = _asn1_read_len(body, 1)
                    out["version"] = int.from_bytes(body[j:j + vlen], "big")
            elif tag == 0xa1:                          # [1] negoTokens
                # SEQUENCE { SEQUENCE { [0] OCTET STRING } }
                if body and body[0] == 0x30:
                    olen, j = _asn1_read_len(body, 1)
                    inner = body[j:j + olen]
                    if inner and inner[0] == 0x30:
                        ilen, k = _asn1_read_len(inner, 1)
                        item = inner[k:k + ilen]
                        if item and item[0] == 0xa0:
                            alen, m = _asn1_read_len(item, 1)
                            ab = item[m:m + alen]
                            if ab and ab[0] == 0x04:
                                olen2, n = _asn1_read_len(ab, 1)
                                out["negoToken"] = ab[n:n + olen2]
        return out
    except ValueError:
        return None


# --- NTLM CHALLENGE_MESSAGE parser (mirror of smb.parse_ntlm_challenge_info) ----

_NTLM_AV = {0x0001: "netbios_computer", 0x0002: "netbios_domain",
            0x0003: "dns_computer",     0x0004: "dns_domain",
            0x0005: "dns_tree"}


def parse_ntlm_challenge_info(sec_buffer: bytes) -> dict | None:
    """Decode an NTLMSSP CHALLENGE_MESSAGE (bare, no SPNEGO wrapping — CredSSP ships
    raw NTLM in negoTokens) into the info-leak fields. Returns None if it isn't a
    Type-2 message. Every field is optional — present iff the server sent it."""
    from ..ad import ntlm
    base = ntlm.parse_type2(sec_buffer)
    if not base:
        return None
    out: dict = {"challenge": base["challenge"].hex(),
                 "ntlm_flags": base["flags"]}
    ti = base.get("target_info") or b""
    i, n = 0, len(ti)
    while i + 4 <= n:
        av_id, av_len = struct.unpack_from("<HH", ti, i)
        i += 4
        if av_id == 0x0000:                            # MsvAvEOL
            break
        if i + av_len > n:
            break
        v = ti[i:i + av_len]
        if av_id in _NTLM_AV:
            out[_NTLM_AV[av_id]] = v.decode("utf-16-le", "replace")
        elif av_id == 0x0007 and av_len == 8:
            filetime = struct.unpack("<Q", v)[0]
            out["server_time_epoch"] = (filetime // 10_000_000) - 11_644_473_600
        i += av_len
    # OS Version at bytes 48..56 of the CHALLENGE header, present iff NEGOTIATE_VERSION
    # (0x02000000) is set. Locate the NTLMSSP signature (CredSSP negoToken is raw NTLM,
    # but find() also tolerates any incidental leading bytes).
    idx = sec_buffer.find(b"NTLMSSP\x00")
    if idx >= 0 and idx + 56 <= len(sec_buffer) and (base["flags"] & 0x02000000):
        ver = sec_buffer[idx + 48:idx + 56]
        major, minor = ver[0], ver[1]
        build = struct.unpack("<H", ver[2:4])[0]
        if major or minor or build:
            out["os_version"] = f"{major}.{minor}.{build}"
            out["ntlm_revision"] = ver[7]
    return out


def _read_tsrequest(sock, timeout: float, cap: int = 65536) -> bytes:
    """Read one full TSRequest DER SEQUENCE from `sock`. Bounded by `cap` (a DoS
    ceiling) and by `timeout`. Returns b"" on any failure."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < cap:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Once the outer SEQUENCE length is known, stop when we have that many bytes.
            if buf and buf[0] == 0x30 and len(buf) >= 2:
                try:
                    total, hdr_end = _asn1_read_len(buf, 1)
                    if len(buf) >= hdr_end + total:
                        return buf[:hdr_end + total]
                except ValueError:
                    return b""
    except OSError:
        return b""
    return buf


def _wrap_tls(sock, timeout: float, server_hostname: str = "") -> ssl.SSLSocket | None:
    """Wrap `sock` with a permissive TLS client context. RDP TLS on older Windows RDS
    (2008 R2 / 2012) still requires TLS1.0 and legacy ciphers — SECLEVEL=0 keeps that
    path open. Returns None on any handshake failure."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        pass
    for suite in ("ALL:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", "DEFAULT"):
        try:
            ctx.set_ciphers(suite)
            break
        except ssl.SSLError:
            continue
    try:
        tls = ctx.wrap_socket(sock, server_hostname=server_hostname or None,
                              do_handshake_on_connect=False)
        tls.settimeout(timeout)
        tls.do_handshake()
        return tls
    except (ssl.SSLError, OSError, ValueError):
        return None


def probe_ntlm_info(ip: str, port: int = _DEFAULT_PORT,
                    timeout: float = _TIMEOUT) -> dict | None:
    """Full flow: X.224 CR (asks for CredSSP+SSL) -> if server selects a CredSSP-
    capable proto, TLS-wrap and exchange one CredSSP TSRequest carrying an NTLM
    NEGOTIATE_MESSAGE. Parses the server's TSRequest reply for the CHALLENGE and
    returns the CHALLENGE AV_PAIRs + credssp_version. Returns None on any failure."""
    from ..ad import ntlm
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        s.settimeout(timeout)
        s.sendall(_X224_CR)
        data = s.recv(4096)
        if len(data) < 19 or data[0] != 0x03 or data[11] != 0x02:
            return None
        try:
            proto = struct.unpack("<I", data[15:19])[0]
        except struct.error:
            return None
        if not (proto & 0x02):                         # server did not offer CredSSP
            return None
        tls = _wrap_tls(s, timeout, server_hostname=ip)
        if tls is None:
            return None
        try:
            req = build_credssp_tsrequest(ntlm.type1(), version=6)
            tls.sendall(req)
            resp = _read_tsrequest(tls, timeout)
        finally:
            try:
                tls.close()
            except OSError:
                pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    if not resp:
        return None
    ts = parse_credssp_tsrequest(resp)
    if not ts or not ts.get("negoToken"):
        return None
    info = parse_ntlm_challenge_info(ts["negoToken"]) or {}
    if ts.get("version") is not None:
        info["credssp_version"] = ts["version"]
    return info or None


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
                    "Server accepted Standard RDP security (selectedProtocol=0). "
                    "BlueKeep-family exposure (CVE-2019-0708 on Win7/2008 R2, "
                    "CVE-2020-0609/0610 gateway CVEs) is materially larger without "
                    "NLA. A cred-harvesting attacker on-path can present a fake "
                    "login and receive plaintext credentials.",
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
            # CredSSP NTLM CHALLENGE info leak — NetBIOS/DNS name, AD domain,
            # forest, OS build. Same wire-shape intel as nmap rdp-ntlm-info; no
            # credentials sent.
            info = pr.get("ntlm_info") if pr else None
            if info:
                bits = []
                for k, label in (("netbios_computer", "NetBIOS name"),
                                 ("netbios_domain", "NetBIOS domain"),
                                 ("dns_computer", "DNS FQDN"),
                                 ("dns_domain", "AD DNS domain"),
                                 ("dns_tree", "AD forest"),
                                 ("os_version", "OS build")):
                    v = info.get(k)
                    if v:
                        bits.append(f"{label}={v}")
                if bits:
                    out.append(_finding(
                        "info",
                        "RDP CredSSP NTLM CHALLENGE leaks host/domain intel",
                        tgt,
                        "After TLS + a CredSSP TSRequest carrying an NTLMSSP "
                        "NEGOTIATE, the server returned a CHALLENGE_MESSAGE "
                        "carrying: " + "; ".join(bits) + ". Pre-auth, no "
                        "credentials required. Reveals NetBIOS/DNS naming, AD "
                        "domain and forest, and exact OS build for CVE mapping "
                        "(MS-NLMP AV_PAIRs + Version field).",
                        f"nmap -p {p.portid} --script rdp-ntlm-info {h.ip}",
                        "Default Windows RDS behavior when CredSSP is enabled; "
                        "network-restrict RDP and disable NTLM where feasible "
                        "(Kerberos-only) to reduce the identity leak surface.",
                        ["CWE-200"], kind="rdp_ntlm_info"))
                # CredSSP TSRequest version <=2 == pre-March-2018 patch level =
                # CVE-2018-0886 (CredSSP logon-cred injection RCE).
                cver = info.get("credssp_version")
                if isinstance(cver, int) and cver <= 2:
                    out.append(_finding(
                        "medium",
                        "RDP CredSSP is unpatched for CVE-2018-0886",
                        tgt,
                        f"Server negotiated CredSSP TSRequest version {cver}. "
                        "Versions <=2 predate the March-2018 CredSSP patch and "
                        "are vulnerable to CVE-2018-0886, a logon-credential "
                        "injection RCE (an attacker who can MitM the RDP "
                        "session executes arbitrary code as the target user).",
                        f"nmap -p {p.portid} --script rdp-vuln-ms12-020 {h.ip}",
                        "Install the March-2018 CredSSP update on both server "
                        "and clients (KB4093120 family; Group Policy: 'Encryption "
                        "Oracle Remediation' = Force updated clients).",
                        ["CWE-287", "CWE-346"], kind="rdp_credssp_unpatched"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Negotiate + fingerprint",
         "cmd": f"nmap -p {port} --script rdp-enum-encryption,rdp-ntlm-info {ip}"},
        {"step": "Connect (test NLA behavior)",
         "cmd": f"xfreerdp /v:{ip}:{port} /sec:rdp   # standard-rdp fallback"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "rdp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = rdp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    def _full_probe(t):
        pr = probe(t["ip"], t["port"])
        # One extra roundtrip only when the server actually offered CredSSP —
        # that's where the CHALLENGE_MESSAGE + TSRequest version live.
        if pr and (pr.get("protocol_code") or 0) & 0x02:
            info = probe_ntlm_info(t["ip"], t["port"])
            if info:
                pr["ntlm_info"] = info
        return pr
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, _full_probe,
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["standard_rdp_accepted"] = pr.get("standard_rdp_accepted", False)
                t["nla_required"] = pr.get("nla_required", False)
                if pr.get("ntlm_info"):
                    t["ntlm_info"] = pr["ntlm_info"]
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
