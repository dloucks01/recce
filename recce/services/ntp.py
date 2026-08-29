"""NTP (123/udp) enumeration: monlist amplification, mode-6 disclosure, clock skew.

Three separate exposures live on this port, and they need three different
packets — an NTP daemon can answer time perfectly while still leaking its whole
client list:

  * **monlist / mode 7 (CVE-2013-5211)** — the legacy private-mode interface
    returns the last ~600 clients that talked to the server. Two problems at
    once: it is a >100x DDoS amplifier (small request, many large responses),
    and on an internal engagement the response is a free map of which hosts
    talk to this server, including ones you have not discovered yet.
  * **mode 6 control (ntpq `readvar`)** — returns `version=`, `processor=`,
    `system=`, and the peer list as ASCII. That is OS + kernel + daemon version
    disclosure without touching a single TCP port, and the peer list exposes
    upstream/internal time topology.
  * **clock skew** — read separately, because it is the one that matters for
    the rest of the engagement rather than for the report. Kerberos rejects
    tickets outside a 5-minute window by default (MS-KILE), so a DC whose clock
    has drifted breaks kerberoasting, AS-REP roasting and pass-the-ticket in a
    way that looks like "the attack failed" rather than "the clock is wrong".

Probes are one UDP datagram each, stdlib socket + struct, airgap-safe. Nothing
here is intrusive: monlist and readvar are read-only queries, and recce sends
exactly one of each rather than the flood an amplification test would imply.

Wire formats: RFC 5905 (NTP v4) for the time packet, RFC 1305 App. B for the
mode-6 control header, and the ntpd mode-7 private request layout
(impl=XNTPD/3, request=REQ_MON_GETLIST_1/42).
"""
from __future__ import annotations

import re
import socket
import struct
import time

from ..core.models import Host, Port


_DEFAULT_PORT = 123
_TIMEOUT = 3.0

# Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
_NTP_EPOCH_DELTA = 2208988800

# Kerberos default maximum clock skew (MS-KILE / RFC 4120). Past this, ticket
# requests fail — which is why recce reports skew as an engagement blocker.
_KERBEROS_SKEW_LIMIT = 300.0


def is_ntp(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 123
            or svc in ("ntp", "sntp") or "ntp" in svc or "ntpd" in prod)


# --- wire ---------------------------------------------------------------------

def _client_packet() -> bytes:
    """RFC 5905 client packet: LI=0, VN=4, Mode=3 (client), rest zero."""
    return bytes([0x23]) + b"\x00" * 47


def _mode6_readvar(assoc: int = 0) -> bytes:
    """RFC 1305 App. B control header, opcode 2 (READVAR).

    byte0 = LI(2) VN(3) Mode(3); VN=2 because that is what ntpq speaks for
    compatibility, Mode=6 = control. byte1 = R|E|M|opcode. assoc 0 = the
    server's own system variables.
    """
    return struct.pack("!BBHHHHH",
                       (2 << 3) | 6,   # 0x16
                       2,              # opcode READVAR, R/E/M clear
                       1,              # sequence
                       0,              # status
                       assoc,          # association id
                       0,              # offset
                       0)              # count


def _mode7_request(request_code: int) -> bytes:
    """ntpd mode-7 private request. impl=3 (XNTPD); padded to 48 bytes.

    byte0 = R(1) M(1) VN(3) Mode(3) -> 0x17 (VN=2, Mode=7).
    """
    return bytes([0x17, 0x00, 0x03, request_code]) + b"\x00" * 44


_REQ_MON_GETLIST_1 = 42          # monlist
_REQ_PEER_LIST = 0               # peer enumeration

# `version="ntpd 4.2.6p5@..."` / processor / system, as returned by readvar.
_VAR_RE = re.compile(r'(\w+)=("(?:[^"]*)"|[^,\r\n]*)')

# Severity ordering for picking the worst CVE that matched a version gate.
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _parse_ntpd_version(v: str) -> tuple[int, int, int, int] | None:
    """Parse '4.2.8p11' / '4.2.6' into (major, minor, patch, p_level).

    The `p` (patchset) counter is authoritative for CVE gating — 4.2.8 and
    4.2.8p3 are distinct security postures. Missing patchset counts as p0.
    """
    m = re.match(r"(\d+)\.(\d+)\.(\d+)(?:p(\d+))?", v or "")
    if not m:
        return None
    a, b, c, d = m.groups()
    return int(a), int(b), int(c), int(d) if d else 0


# ntpd version -> known unauth CVEs, keyed by "first-fixed-in" (exclusive
# upper bound). Every entry here is a public CVE with a documented ntpd
# patchset fix — no invented flags, no unverified IDs.
_NTPD_CVES: list[tuple[tuple[int, int, int, int], list[tuple[str, str, str]]]] = [
    ((4, 2, 8, 0), [
        ("CVE-2014-9295", "critical",
         "crypto_recv / ctl_putdata / configure stack buffer overflows "
         "(unauth RCE-class when autokey is enabled)"),
        ("CVE-2014-9293", "high",
         "ntp-keygen weak default trusted key / predictable authkey_seed"),
        ("CVE-2014-9294", "high",
         "ntp-keygen predictable MD5 symmetric keys"),
    ]),
    ((4, 2, 8, 4), [
        ("CVE-2015-7871", "high",
         "crypto-NAK auth bypass ('NAK to the Future') — spoofed peer "
         "accepted as symmetric-key authenticated"),
    ]),
    ((4, 2, 8, 9), [
        ("CVE-2016-7431", "medium",
         "zero-origin timestamp bypass — off-path time-shift"),
        ("CVE-2016-7434", "medium",
         "mrulist NULL-pointer dereference (unauth DoS)"),
    ]),
    ((4, 2, 8, 11), [
        ("CVE-2018-7182", "medium",
         "ctl_getitem out-of-bounds read on the mode-6 control path"),
    ]),
    ((4, 2, 8, 14), [
        ("CVE-2020-11868", "high",
         "off-path attacker can disrupt time sync via a single forged "
         "mode-6 packet (BCP-38-bypassing amplification+spoof)"),
        ("CVE-2020-13817", "medium",
         "predictable origin timestamp — off-path desync"),
    ]),
]


def _ntpd_cve_gate(version: str) -> list[tuple[str, str, str]]:
    """Return known CVEs the parsed ntpd version is vulnerable to.

    Only fires on a version we can actually parse — an unparseable banner
    yields nothing rather than a speculative CVE claim.
    """
    parsed = _parse_ntpd_version(version)
    if parsed is None:
        return []
    hits: list[tuple[str, str, str]] = []
    for fixed_in, cves in _NTPD_CVES:
        if parsed < fixed_in:
            hits.extend(cves)
    return hits


def _mode7_items(pkt: bytes) -> tuple[int, int, bytes]:
    """Decode a mode-7 response header: (numitems, itemsize, body).

    mode-7 header: R|M|VN|Mode, Auth|Seq, Impl, ReqCode, Err|numitems(12b),
    MBZ|itemsize(12b). Numitems and itemsize live in the low 12 bits of the
    respective 2-byte fields (top 4 = error / mbz).
    """
    if len(pkt) < 8 or (pkt[0] & 0x07) != 7:
        return 0, 0, b""
    numitems = ((pkt[4] << 8) | pkt[5]) & 0x0fff
    itemsize = ((pkt[6] << 8) | pkt[7]) & 0x0fff
    return numitems, itemsize, pkt[8:]


def _dedupe(ips: list[str]) -> list[str]:
    """Preserve first-seen order — the caller may care about disclosure order."""
    seen: set[str] = set()
    out: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def _parse_mon_entries(packets: list[bytes]) -> list[str]:
    """Extract client IPv4 addresses from mode-7 REQ_MON_GETLIST_1 responses.

    info_monitor_1 layout (ntpd request.h): firsttime(4), lasttime(4),
    restr(4), count(4), addr(4)@16, daddr(4)@20, flags(4), port(2), mode(1),
    version(1), v6_flag(4)@32, unused1(4), addr6(16), daddr6(16). We use
    itemsize from the response header rather than assuming a version so a
    v4-only build (itemsize<40) or a v6-capable build both decode.

    A non-zero v6_flag means the v4 addr slot is unpopulated — skip that
    entry rather than emitting a spurious 0.0.0.0 or a byte-swap of the v6
    prefix.
    """
    out: list[str] = []
    for pkt in packets:
        numitems, itemsize, body = _mode7_items(pkt)
        if itemsize < 20 or numitems == 0:
            continue
        for i in range(numitems):
            off = i * itemsize
            rec = body[off:off + itemsize]
            if len(rec) < 20:
                break
            if itemsize >= 36 and rec[32:36] != b"\x00\x00\x00\x00":
                # v6 record — skip; no v4 address to feed the wire.
                continue
            addr = rec[16:20]
            if addr == b"\x00\x00\x00\x00":
                continue
            out.append(".".join(str(b) for b in addr))
    return _dedupe(out)


def _parse_peer_entries(packets: list[bytes]) -> list[str]:
    """Extract peer IPv4 addresses from mode-7 REQ_PEER_LIST responses.

    info_peer_list layout: addr(4)@0, port(2), hmode(1), flags(1), v6_flag(4)
    @8, unused1(4), addr6(16). Same v4/v6 dispatch as _parse_mon_entries.
    """
    out: list[str] = []
    for pkt in packets:
        numitems, itemsize, body = _mode7_items(pkt)
        if itemsize < 4 or numitems == 0:
            continue
        for i in range(numitems):
            off = i * itemsize
            rec = body[off:off + itemsize]
            if len(rec) < 4:
                break
            if itemsize >= 12 and rec[8:12] != b"\x00\x00\x00\x00":
                continue
            addr = rec[0:4]
            if addr == b"\x00\x00\x00\x00":
                continue
            out.append(".".join(str(b) for b in addr))
    return _dedupe(out)


def _parse_readvar(payload: bytes) -> dict:
    """Pull the ASCII k=v pairs out of a mode-6 response payload."""
    try:
        text = payload.decode("ascii", "replace")
    except Exception:                       # noqa: BLE001 - malformed is just "no vars"
        return {}
    out = {}
    for k, v in _VAR_RE.findall(text):
        out[k.lower()] = v.strip().strip('"')
    return out


def _ntpd_version(vars_: dict) -> str:
    """`version` reads like `ntpd 4.2.6p5@1.2349-o Fri...` — keep the useful head."""
    raw = vars_.get("version", "")
    m = re.search(r"ntpd?\s+([0-9][\w.\-p]*)", raw, re.I)
    return m.group(1) if m else raw.split("@")[0].strip()


def _udp_exchange(ip: str, port: int, payload: bytes, timeout: float,
                  reads: int = 1) -> list[bytes]:
    """Send one datagram, collect up to `reads` responses.

    monlist answers with MANY packets — that is the amplification — so the
    caller asks for several and we measure what actually came back rather than
    assuming a single reply.
    """
    out: list[bytes] = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(payload, (ip, port))
        for _ in range(reads):
            try:
                data, _addr = s.recvfrom(8192)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            out.append(data)
    finally:
        s.close()
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """One pass: time + skew, mode-6 readvar, monlist, peer list."""
    out: dict = {"reachable": False}

    # 1) Plain time query — also the reachability test and the skew measurement.
    t0 = time.time()
    replies = _udp_exchange(ip, port, _client_packet(), timeout)
    if replies and len(replies[0]) >= 48:
        t1 = time.time()
        pkt = replies[0]
        out["reachable"] = True
        out["mode"] = pkt[0] & 0x07
        out["version"] = (pkt[0] >> 3) & 0x07
        out["stratum"] = pkt[1]
        secs, frac = struct.unpack("!II", pkt[40:48])
        if secs:
            server = (secs - _NTP_EPOCH_DELTA) + (frac / 2**32)
            # Compare against the midpoint of our own send/receive to keep the
            # round trip from being counted as drift.
            out["server_time"] = server
            out["skew"] = server - ((t0 + t1) / 2)
        ref = pkt[12:16]
        if pkt[1] == 1:                      # stratum 1: refid is an ASCII clock id
            out["refid"] = ref.rstrip(b"\x00").decode("ascii", "replace")
        elif any(ref):
            out["refid"] = ".".join(str(b) for b in ref)

    # 2) Mode 6 control (ntpq readvar) — version / OS / peers.
    m6 = _udp_exchange(ip, port, _mode6_readvar(), timeout)
    if m6:
        pkt = m6[0]
        if len(pkt) > 12 and (pkt[0] & 0x07) == 6:
            out["mode6"] = True
            vars_ = _parse_readvar(pkt[12:])
            if vars_:
                out["vars"] = vars_
                out["ntpd_version"] = _ntpd_version(vars_)
                for k in ("processor", "system", "leap", "stratum"):
                    if vars_.get(k):
                        out.setdefault("sysinfo", {})[k] = vars_[k]

    # 3) monlist (CVE-2013-5211). Ask for several packets: the response volume
    #    IS the finding, so measure it rather than inferring it.
    req = _mode7_request(_REQ_MON_GETLIST_1)
    mon = _udp_exchange(ip, port, req, timeout, reads=6)
    # A refusing server answers with a mode-7 error packet; a vulnerable one
    # returns payload-bearing packets. Require real bytes, not just a reply.
    payload = sum(len(p) for p in mon)
    if mon and payload > len(req):
        out["monlist"] = True
        out["monlist_packets"] = len(mon)
        out["monlist_bytes"] = payload
        out["amplification"] = round(payload / len(req), 1)
        clients = _parse_mon_entries(mon)
        if clients:
            # The whole point of monlist on an internal engagement — a free
            # inventory of hosts talking to this server, including ones the
            # port sweep hasn't reached yet.
            out["mon_clients"] = clients
    elif mon:
        out["mode7"] = True                  # answers mode 7, but not monlist

    # 4) Peer list — internal time topology.
    peers = _udp_exchange(ip, port, _mode7_request(_REQ_PEER_LIST), timeout, reads=3)
    if peers and sum(len(p) for p in peers) > 48:
        out["peer_list"] = True
        out["mode7"] = True
        peer_ips = _parse_peer_entries(peers)
        if peer_ips:
            # Upstream time source on a corporate LAN is almost always the DC
            # or an internal appliance — same wire value as mon_clients.
            out["peers"] = peer_ips
    return out


def ntp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_ntp(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "ntpq", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_ntp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            if pr.get("monlist"):
                amp = pr.get("amplification") or 0
                clients = pr.get("mon_clients") or []
                # Name a handful of clients directly in the detail so the
                # tester sees the wire value on the report page instead of
                # having to open the probes JSON. Cap at 8 to keep the
                # finding text readable on very talkative servers.
                sample = ""
                if clients:
                    head = ", ".join(clients[:8])
                    extra = f" (+{len(clients) - 8} more)" if len(clients) > 8 else ""
                    sample = f" Distinct client IPs disclosed: {len(clients)} — {head}{extra}."
                out.append(_finding(
                    "high",
                    "NTP monlist enabled (CVE-2013-5211) — amplification + client disclosure",
                    tgt,
                    f"The server answered a mode-7 REQ_MON_GETLIST_1 with "
                    f"{pr.get('monlist_packets', 0)} packet(s) / "
                    f"{pr.get('monlist_bytes', 0)} bytes to a 48-byte request "
                    f"(~{amp}x amplification). monlist returns the last ~600 clients "
                    f"that contacted this server: on an internal that is a free list "
                    f"of hosts talking to it, including any recce has not discovered. "
                    f"Externally it is a reflective DDoS amplifier."
                    f"{sample}",
                    "ntpdc -n -c monlist <ip>   # or: nmap -sU -p123 --script ntp-monlist <ip>",
                    "Upgrade to ntpd 4.2.7p26+, or set `disable monitor` in ntp.conf. "
                    "Restrict mode 6/7 with `restrict default noquery`.",
                    ["CWE-200", "CWE-406"], kind="ntp_monlist"))

            if pr.get("mode6"):
                v = pr.get("ntpd_version") or "unknown"
                sysinfo = pr.get("sysinfo") or {}
                extra = ", ".join(f"{k}={sysinfo[k]}" for k in sorted(sysinfo)) or "no system vars"
                out.append(_finding(
                    "medium",
                    "NTP mode-6 control queries allowed (version / OS disclosure)", tgt,
                    f"An unauthenticated ntpq readvar returned the server's system "
                    f"variables: ntpd {v} ({extra}). This discloses the daemon version "
                    f"and frequently the OS, kernel and hardware — host fingerprinting "
                    f"with no TCP contact. Mode 6 is also the interface behind the "
                    f"ntpd remote-config and amplification issues.",
                    "ntpq -c readvar <ip>   # also: ntpq -p <ip>",
                    "`restrict default noquery` (and `nomodify`) in ntp.conf; expose mode 6 "
                    "only to management hosts. Chrony: `cmdallow` off by default.",
                    ["CWE-200"], kind="ntp_mode6"))

            # Version cross-check — piggybacks on the readvar-derived
            # ntpd_version. Aggregated into ONE finding per host so a legacy
            # daemon doesn't drown the report in eight repeated entries; the
            # detail line names every CVE and the finding severity is the
            # worst one that matched.
            ver = pr.get("ntpd_version")
            if ver:
                hits = _ntpd_cve_gate(ver)
                if hits:
                    worst = max(hits, key=lambda c: _SEV_ORDER.get(c[1], 0))
                    ids = [h[0] for h in hits]
                    lines = "; ".join(f"{cve} ({sev}) — {desc}"
                                      for cve, sev, desc in hits)
                    out.append(_finding(
                        worst[1],
                        f"ntpd {ver} matches {len(hits)} known unauth CVE(s)",
                        tgt,
                        f"ntpd version {ver} (from mode-6 readvar) falls within the "
                        f"vulnerable range for {len(hits)} public CVE(s): {lines}. "
                        f"Version match is not proof of exploitability on its own "
                        f"(vendor backports are common — check the distribution "
                        f"changelog), but every hit here is an unauthenticated "
                        f"primitive against ntpd's own request paths.",
                        "ntpq -c readvar <ip>   # then confirm the vendor patchset",
                        "Upgrade to the current ntpd 4.2.8 patchset (or migrate to "
                        "chrony / ntpsec). If a distro backport is in place, cite "
                        "the vendor CVE bulletin to close this finding.",
                        ["CWE-1104", "CWE-1395"], kind="ntp_version_cve"))
                    # CVE ids are named in the detail; keep them on the dict
                    # so downstream consumers that DO index `ids` (like the
                    # vuln-DB matchers) can pick them up.
                    out[-1]["ids"] = ids

            if pr.get("peer_list") and not pr.get("monlist"):
                out.append(_finding(
                    "low",
                    "NTP peer list readable (internal time topology)", tgt,
                    "A mode-7 REQ_PEER_LIST returned this server's peers, exposing "
                    "upstream/peer time sources. On an internal that names further "
                    "infrastructure — often a DC or an appliance not otherwise visible.",
                    "ntpq -p <ip>",
                    "`restrict default noquery` in ntp.conf; disable mode 7 (`disable monitor`).",
                    ["CWE-200"], kind="ntp_peers"))

            # Clock skew — reported for the engagement, not just the report.
            skew = pr.get("skew")
            if skew is not None and abs(skew) >= _KERBEROS_SKEW_LIMIT:
                out.append(_finding(
                    "medium",
                    "Host clock skew exceeds the Kerberos tolerance", tgt,
                    f"This server's clock is {skew:+.0f}s from the testing host "
                    f"(Kerberos rejects beyond {_KERBEROS_SKEW_LIMIT:.0f}s, MS-KILE). "
                    f"If this is a DC or a Kerberos-authenticating service, ticket "
                    f"requests will fail regardless of credentials — kerberoasting and "
                    f"AS-REP roasting will look broken when the clock is the cause. "
                    f"Sync the testing host to this server before Kerberos work.",
                    "sudo ntpdate -u <ip>   # or: faketime / sudo chronyd -q 'server <ip> iburst'",
                    "Correct time sync on the host. For the tester: match the DC's clock "
                    "before Kerberos operations.",
                    ["CWE-361"], kind="ntp_skew"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "nmap",
         "command": f"nmap -sU -p{port} --script ntp-info,ntp-monlist {ip}",
         "why": "version, system vars and monlist in one pass"},
        {"phase": "enumerate", "tool": "ntpq",
         "command": f"ntpq -c readvar {ip}",
         "why": "daemon version + OS/processor disclosure via mode 6"},
        {"phase": "enumerate", "tool": "ntpq",
         "command": f"ntpq -p {ip}",
         "why": "peer list — upstream and internal time sources"},
        {"phase": "exploit", "tool": "ntpdc",
         "command": f"ntpdc -n -c monlist {ip}",
         "why": "CVE-2013-5211: last ~600 clients — free host discovery internally"},
        {"phase": "support", "tool": "ntpdate",
         "command": f"sudo ntpdate -u {ip}",
         "why": "match the target's clock before Kerberos work (5-min skew limit)"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "ntp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = ntp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["monlist"] = pr.get("monlist", False)
                t["mode6"] = pr.get("mode6", False)
                t["ntpd_version"] = pr.get("ntpd_version", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
