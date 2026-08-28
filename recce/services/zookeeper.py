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

Airgap-safe: stdlib socket only, no external dependencies. Bounded runtime
(one connection per 4LW * ~14 commands * short timeout = ~14s max).
"""
from __future__ import annotations

import socket

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


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Sweep every category of 4LW and record what worked. Returns
    {reachable, version, exposed_commands: {cmd: response_prefix}}."""
    out: dict = {"reachable": False, "version": "", "exposed_commands": {},
                 "leaks_data": False, "leaks_admin": False}
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
    return out


def zk_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_zookeeper(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "nc", "command": cmd, "remediation": rem, "cwes": cwes, "kind": kind}


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
                out.append(_finding(
                    "high", "Zookeeper 4LW leaks cluster state / config", tgt,
                    f"Data-dumping 4LW commands accepted without authentication: "
                    f"{', '.join(dumping)}. These reveal client sessions "
                    f"({exposed.get('cons','')[:80]!r}...), configuration "
                    f"({exposed.get('conf','')[:80]!r}...), and environment. "
                    f"An attacker on the network reads it all with `nc`.",
                    f"echo dump | nc {h.ip} {p.portid}",
                    "Restrict 4LW to safe commands: `4lw.commands.whitelist=srvr,ruok` "
                    "in zoo.cfg. Bind Zookeeper to a private interface; require SASL "
                    "authentication for clients.",
                    ["CWE-200", "CWE-306"], kind="zk_dump"))

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
                    ["CWE-200"], kind="zk_admin_4lw"))

            # Info-level fingerprint always emitted so the report reflects
            # what recce could actually see.
            safe = sorted(c for c in exposed if c in _SAFE_4LW)
            out.append(_finding(
                "info", "Zookeeper 4LW commands enumerated", tgt,
                f"version={pr.get('version','?')} · safe cmds accepted: "
                f"{', '.join(safe) or 'none'} · total 4LW accepted: {len(exposed)}",
                f"echo srvr | nc {h.ip} {p.portid}",
                "Informational — pairs with any dump/admin finding above.",
                [], kind="zk_fingerprint"))
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
