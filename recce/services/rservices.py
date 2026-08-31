"""Legacy r-services (512 rexec / 513 rlogin / 514 rsh): trust auth by IP.

The Berkeley r-* protocols authenticate by source IP + a .rhosts / hosts.equiv
file on the server. A host that accepts them from arbitrary sources is a
credential-less shell — and any traffic on them is cleartext, so a passive
listener on the segment captures every login. Rare in 2025, but still turns up
on legacy Solaris/AIX estates and hardware appliances.

Recce cannot safely PROVE trust without attempting a login as some fake user;
what it can do unauthenticated is confirm the daemons are present, which alone
is worth reporting because a 2025 network that runs rlogin/rsh/rexec is
categorically insecure.

Zero packets sent — bare TCP connect is enough to identify the port is open,
and svcdetect + the enum sweep already do that. This module records the
finding + the runbook.
"""
from __future__ import annotations

from ..core.models import Host, Port


_R_PORTS = {512: "rexec", 513: "rlogin", 514: "rsh"}
_DEFAULT_PORT = 514


def is_rservice(port: Port) -> bool:
    svc = (port.service or "").lower()
    return (port.portid in _R_PORTS
            or svc in ("exec", "login", "shell", "rexec", "rlogin", "rsh"))


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = 3.0) -> dict:
    """No packet-level probe — a plain TCP connect is enough, and the enum
    layer already knows it's open. Recording it here so findings() emits the
    protocol-specific advice."""
    import socket
    out = {"reachable": False, "port": port,
           "service": _R_PORTS.get(port, "r-service")}
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        out["reachable"] = True
        s.close()
    except OSError:
        pass
    return out


def rservices_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_rservice(p):
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
            if not is_rservice(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            svc = pr.get("service", "r-service")
            out.append(_finding(
                "high",
                f"Legacy {svc} exposed (cleartext, IP-trust auth)", tgt,
                f"{svc} on {tgt}. The Berkeley r-* protocols authenticate on "
                f"source IP + a .rhosts / hosts.equiv entry, so a permissive "
                f"trust file is an unauthenticated shell. Even where trust is "
                f"restricted, every login and every command travels in "
                f"cleartext — a passive listener on this segment captures "
                f"credentials as they arrive. There is no reason a 2025 "
                f"network should still expose these.",
                "rsh / rlogin / rexec",
                f"rlogin -l root {h.ip}   # rsh -l root {h.ip} id   "
                f"# rexec on {h.ip} 512 with a captured cred",
                f"Disable {svc} (xinetd / inetd / systemd unit); require SSH "
                "with key auth. The tools should not be in $PATH on modern "
                "systems.",
                ["CWE-319", "CWE-287"], kind=f"r_{svc}",
                exploit_note=(
                    f"rsh -l root {h.ip} id ; rlogin -l root {h.ip} ; echo id | "
                    f"rexec -l root -p '' {h.ip} ; also try daemon, bin, sync, "
                    "adm, halt, uucp as trust names; capture -A 'port 512-514' "
                    "for cleartext-cred proof."),
                depth_tier="t1"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    svc = _R_PORTS.get(port, "r-service")
    steps = [
        {"phase": "test", "tool": "rlogin/rsh",
         "command": (f"rlogin -l root {ip}" if port == 513
                     else f"rsh -l root {ip} id" if port == 514
                     else f"echo test | rexec {ip} 512 root PASSWORD id"),
         "why": "attempt an unauthenticated login using common trust names"},
        {"phase": "capture", "tool": "tcpdump",
         "command": f"tcpdump -i any -A 'host {ip} and port {port}'",
         "why": f"{svc} traffic is cleartext — a login on the segment leaks the creds"},
        {"phase": "loot", "tool": "search",
         "command": "# on the target after login: find / -name .rhosts -o -name hosts.equiv 2>/dev/null",
         "why": "trust files name other machines that trust THIS host — pivot chain"},
    ]
    return steps


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "rservices", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = rservices_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["service"] = pr.get("service", "")
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
