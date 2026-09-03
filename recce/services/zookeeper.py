"""Apache Zookeeper 4-letter-word (4LW) probe.

Zookeeper exposes a small set of ASCII commands over TCP that answer with
plain-text status. On a properly locked-down deployment only a handful are
whitelisted; on default/quick-start deployments every 4LW responds — including
the ones that dump the cluster's configuration, session list, and ACL state.

Findings emitted:

* **zk_stat_reachable** (info) — 4LW works at all. Fingerprint only.
* **zk_dump** (high) — `dump` / `srvr` / `conf` etc. leak session lists,
  cluster config, and env vars. Real data disclosure.
* **zk_default_whitelist** (medium) — many dangerous commands whitelisted
  (implies zoo.cfg defaults, no `4lw.commands.whitelist=` tuning).

T2 SAFE proof for `zk_dump`: after the 4LW sweep flags data-leaking commands,
we open a real ZooKeeper client-protocol session (jute-framed TCP), receive
the ConnectResponse (server-assigned sessionId), and issue a single
getChildren("/") request. A non-empty child list (e.g. ["zookeeper"]) proves
that the anonymous data plane is actually usable — not just the 4LW admin
plane. One shot, no writes, no watches, non-destructive.

Airgap-safe: stdlib socket only, no external dependencies. Bounded runtime
(one connection per 4LW * ~14 commands * short timeout = ~14s max).
"""
from __future__ import annotations

import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 2181
_TIMEOUT = 3.0

# Curated 4LW set:
#   safe/info  — just fingerprinting, low harm
#   dumping    — genuine data disclosure (session list, env, conf)
#   admin-ish  — reveal ACL state / can be used to take snapshots
_SAFE_4LW = ["ruok", "stat", "isro", "mntr", "gtmk"]
_DUMPING_4LW = ["srvr", "dump", "conf", "cons", "wchs", "envi"]
_ADMIN_4LW = ["wchc", "wchp"]


def is_zookeeper(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (2181, 2182, 2183)
            or "zookeeper" in svc or "zookeeper" in prod)


def _send_4lw(ip: str, port: int, cmd: str, timeout: float = _TIMEOUT) -> str:
    """Open TCP, send 4-letter ASCII command + '\\n', read up to 65 KiB,
    close. Returns response text or '' on any transport-level failure."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall((cmd + "\n").encode("ascii"))
            chunks = []
            total = 0
            while total < 65536:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk); total += len(chunk)
            return b"".join(chunks).decode("utf-8", "replace")
    except OSError:
        return ""


# -- ZK client wire helpers (jute framing) -----------------------------------
#
# Every ZK client packet is length-prefixed with a big-endian int32. The
# handshake body is a ConnectRequest struct; subsequent requests carry a
# RequestHeader (xid, type) followed by an op-specific body. See ZK's
# ZooKeeperServer / ClientCnxnSocket sources for the canonical layout.

_ZK_OP_GET_CHILDREN = 8  # OpCode.getChildren


def _pack_connect_request() -> bytes:
    """Build a fresh-session ConnectRequest with a 16-byte zero password."""
    body = (
        struct.pack(">i", 0)              # protocolVersion
        + struct.pack(">q", 0)            # lastZxidSeen
        + struct.pack(">i", 30000)        # timeOut ms (server negotiates down)
        + struct.pack(">q", 0)            # sessionId (0 => new session)
        + struct.pack(">i", 16) + b"\x00" * 16   # passwd (16 zero bytes)
        + b"\x00"                          # readOnly=false (post-3.4 optional)
    )
    return struct.pack(">i", len(body)) + body


def _pack_get_children_request(xid: int, path: str) -> bytes:
    """Build a getChildren(path, watch=false) request."""
    pb = path.encode("utf-8")
    body = (
        struct.pack(">i", xid)
        + struct.pack(">i", _ZK_OP_GET_CHILDREN)
        + struct.pack(">i", len(pb)) + pb
        + b"\x00"                          # watch=false
    )
    return struct.pack(">i", len(body)) + body


def _recv_framed(sock: socket.socket, cap: int = 65536) -> bytes:
    """Read one length-prefixed ZK frame. Returns body only (no length hdr)."""
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return b""
        hdr += chunk
    (length,) = struct.unpack(">i", hdr)
    if length <= 0 or length > cap:
        return b""
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(min(4096, length - len(buf)))
        if not chunk:
            return b""
        buf += chunk
    return buf


def _parse_connect_response(buf: bytes) -> dict | None:
    """Parse ConnectResponse: proto(4) timeout(4) sessionId(8) passwd(4+n) [ro(1)]."""
    if len(buf) < 20:
        return None
    proto = struct.unpack(">i", buf[0:4])[0]
    negotiated = struct.unpack(">i", buf[4:8])[0]
    session_id = struct.unpack(">q", buf[8:16])[0]
    pwd_len = struct.unpack(">i", buf[16:20])[0]
    if pwd_len < 0 or pwd_len > 256 or 20 + pwd_len > len(buf):
        return None
    return {"proto": proto, "negotiated_timeout": negotiated,
            "session_id": session_id, "pwd_len": pwd_len}


def _parse_get_children_response(buf: bytes) -> tuple[int, list[str] | None]:
    """Parse ReplyHeader (xid, zxid, err) + optional vector<string>."""
    if len(buf) < 16:
        return (-1, None)
    # xid at buf[0:4] and zxid at buf[4:12] not needed for T2 evidence
    err = struct.unpack(">i", buf[12:16])[0]
    if err != 0:
        return (err, None)
    off = 16
    if len(buf) < off + 4:
        return (err, None)
    count = struct.unpack(">i", buf[off:off + 4])[0]
    off += 4
    if count < 0 or count > 1024:
        return (err, None)
    children: list[str] = []
    for _ in range(count):
        if len(buf) < off + 4:
            return (err, None)
        slen = struct.unpack(">i", buf[off:off + 4])[0]
        off += 4
        if slen < 0 or off + slen > len(buf):
            return (err, None)
        children.append(buf[off:off + slen].decode("utf-8", "replace"))
        off += slen
    return (err, children)


def zk_client_session_probe(ip: str, port: int,
                            timeout: float = _TIMEOUT) -> dict:
    """SAFE T2 proof: open a real ZK client session, read children of "/".

    Returns {session_ok, session_id, negotiated_timeout, children, err}.
    One TCP connection, one ConnectRequest, one getChildren, then close.
    No writes, no watches, no destructive ops.
    """
    result: dict = {"session_ok": False, "session_id": 0,
                    "negotiated_timeout": 0, "children": None,
                    "err": None}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(_pack_connect_request())
            cr_buf = _recv_framed(s)
            cr = _parse_connect_response(cr_buf)
            # session_id == 0 means the server declined to establish a session
            # (e.g. protocol mismatch, IP-ACL denial). No proof.
            if not cr or cr.get("session_id", 0) == 0:
                return result
            result["session_ok"] = True
            result["session_id"] = cr["session_id"]
            result["negotiated_timeout"] = cr["negotiated_timeout"]
            s.sendall(_pack_get_children_request(1, "/"))
            gc_buf = _recv_framed(s)
            err, children = _parse_get_children_response(gc_buf)
            result["err"] = err
            if children is not None:
                result["children"] = children
    except (OSError, struct.error):
        pass
    return result


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Sweep every category of 4LW and record what worked. Returns
    {reachable, version, exposed_commands: {cmd: response_prefix},
     leaks_data, leaks_admin, client_session: {...}}."""
    out: dict = {"reachable": False, "version": "", "exposed_commands": {},
                 "leaks_data": False, "leaks_admin": False,
                 "client_session": None}
    # `ruok` is the canonical existence check: it replies "imok" and closes.
    r = _send_4lw(ip, port, "ruok", timeout)
    if r.strip() != "imok":
        return out
    out["reachable"] = True
    # `srvr` returns the version banner on its first line.
    srvr = _send_4lw(ip, port, "srvr", timeout)
    if srvr:
        first = srvr.splitlines()[0].strip() if srvr.splitlines() else ""
        out["version"] = first[:120]
    # Now walk the categories. Each successful non-empty response is recorded
    # with a short prefix so findings can quote what actually leaked.
    for cmd in _SAFE_4LW + _DUMPING_4LW + _ADMIN_4LW:
        r = _send_4lw(ip, port, cmd, timeout)
        if r and r.strip():
            out["exposed_commands"][cmd] = r[:200]
            if cmd in _DUMPING_4LW:
                out["leaks_data"] = True
            if cmd in _ADMIN_4LW:
                out["leaks_admin"] = True
    # T2 promotion: if the 4LW plane already leaked data, try one client-
    # protocol session to prove the anonymous data-plane is actually open.
    if out["leaks_data"]:
        sess = zk_client_session_probe(ip, port, timeout=timeout)
        if sess.get("session_ok"):
            out["client_session"] = sess
    return out


def zk_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_zookeeper(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


# Canonical alias so /api/scan/context's `<cmd>_targets` lookup finds
# it without the fragile "any *_targets in the module" fallback.
zookeeper_targets = zk_targets


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "nc", "command": cmd, "remediation": rem, "cwes": cwes,
            "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_zookeeper(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            exposed = pr.get("exposed_commands") or {}

            # Reachable ZK with unrestricted 4LW is itself worth surfacing —
            # a well-configured deploy answers only `ruok`, `stat`, `isro`.
            # Anything more implies zoo.cfg defaults.
            if pr.get("leaks_data"):
                dumping = sorted(c for c in exposed if c in _DUMPING_4LW)
                detail = (
                    f"Data-dumping 4LW commands accepted without authentication: "
                    f"{', '.join(dumping)}. These reveal client sessions "
                    f"({exposed.get('cons','')[:80]!r}...), configuration "
                    f"({exposed.get('conf','')[:80]!r}...), and environment. "
                    f"An attacker on the network reads it all with `nc`.")
                tier = "t1"
                sess = pr.get("client_session") or {}
                if sess.get("session_ok") and sess.get("children") is not None:
                    tier = "t2"
                    kids = sess.get("children") or []
                    sid = sess.get("session_id", 0) & 0xFFFFFFFFFFFFFFFF
                    shown = ", ".join(repr(k) for k in kids[:8]) or "(none)"
                    more = f" (+{len(kids) - 8} more)" if len(kids) > 8 else ""
                    detail += (
                        f" T2 PROOF: opened an anonymous ZK client session "
                        f"(sessionId=0x{sid:016x}, negotiated_timeout="
                        f"{sess.get('negotiated_timeout', 0)}ms) and issued "
                        f"getChildren('/'), which returned "
                        f"[{shown}]{more} — the data plane is unauthenticated, "
                        f"not just the 4LW admin plane.")
                elif sess.get("session_ok"):
                    tier = "t2"
                    sid = sess.get("session_id", 0) & 0xFFFFFFFFFFFFFFFF
                    detail += (
                        f" T2 PROOF: opened an anonymous ZK client session "
                        f"(sessionId=0x{sid:016x}) — the server accepted a "
                        f"new session without SASL, though the subsequent "
                        f"getChildren('/') did not decode cleanly.")
                out.append(_finding(
                    "high", "Zookeeper 4LW leaks cluster state / config", tgt,
                    detail,
                    f"echo dump | nc {h.ip} {p.portid}",
                    "Restrict 4LW to safe commands: `4lw.commands.whitelist=srvr,ruok` "
                    "in zoo.cfg. Bind Zookeeper to a private interface; require SASL "
                    "authentication for clients.",
                    ["CWE-200", "CWE-306"], kind="zk_dump",
                    exploit_note=(
                        f"echo dump | nc {h.ip} {p.portid}  ; "
                        f"echo conf | nc {h.ip} {p.portid}  ; then: "
                        "python3 -c 'from kazoo.client import KazooClient; "
                        f"z=KazooClient(hosts=\"{h.ip}:{p.portid}\"); "
                        "z.start(); print(z.get_children(\"/\"))'"),
                    depth_tier=tier))

            if pr.get("leaks_admin"):
                admin_cmds = sorted(c for c in exposed if c in _ADMIN_4LW)
                out.append(_finding(
                    "medium", "Zookeeper watch-inspection 4LW accepted", tgt,
                    f"Admin-adjacent 4LW commands accepted: {', '.join(admin_cmds)}. "
                    f"These reveal which paths are being watched by which sessions — "
                    f"handy for targeting an application built on top of Zookeeper.",
                    f"echo wchs | nc {h.ip} {p.portid}",
                    "Whitelist only what monitoring needs. Never leave wchc/wchp "
                    "reachable from an untrusted network.",
                    ["CWE-200"], kind="zk_admin_4lw",
                    exploit_note=(
                        f"echo wchs | nc {h.ip} {p.portid}  ; echo wchc | "
                        f"nc {h.ip} {p.portid}  # session-to-path map"),
                    depth_tier="t1"))

            # Info-level fingerprint always emitted so the report reflects
            # what recce could actually see.
            safe = sorted(c for c in exposed if c in _SAFE_4LW)
            out.append(_finding(
                "info", "Zookeeper 4LW commands enumerated", tgt,
                f"version={pr.get('version','?')} · safe cmds accepted: "
                f"{', '.join(safe) or 'none'} · total 4LW accepted: {len(exposed)}",
                f"echo srvr | nc {h.ip} {p.portid}",
                "Informational — pairs with any dump/admin finding above.",
                [], kind="zk_fingerprint",
                exploit_note=(f"echo srvr | nc {h.ip} {p.portid}"),
                depth_tier="t0"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Sanity check (should reply 'imok')",
         "cmd": f"echo ruok | nc {ip} {port}"},
        {"step": "Version + basic stats",
         "cmd": f"echo srvr | nc {ip} {port}"},
        {"step": "Dump full cluster state (if enabled)",
         "cmd": f"echo dump | nc {ip} {port}"},
        {"step": "Dump configuration (if enabled)",
         "cmd": f"echo conf | nc {ip} {port}"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "zookeeper", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = zk_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
