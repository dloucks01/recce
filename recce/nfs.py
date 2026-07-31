"""Deep NFS / mountd enumeration (stdlib only).

Speaks ONC RPC (Sun RPC, RFC 1057) + the portmapper and mountd protocols directly
with struct/XDR on a raw socket - no rpcinfo/showmount binary. Airgapped, stdlib
only, read-only.

  * **portmapper DUMP (TCP 111):** the RPC program directory - which services
    (nfs / mountd / nlockmgr / ...) are registered and on which ports. Enumerable with
    no credential.
  * **MOUNTPROC_EXPORT (mountd):** the equivalent of `showmount -e` - every exported
    directory and the host list it is shared to. An export shared to `*` / everyone
    (or with no host restriction) is mountable by any host on the network: read (and
    frequently, via a matching UID or no_root_squash, write) every file under it.

recce only issues the read-only EXPORT/DUMP calls - it never mounts a filesystem or
touches a file. Positive findings fold into the severity totals, the Vulnerabilities
sheet, the write-ups, a dedicated **NFS** tab, and the prove engine. Safety: SECURITY.md.
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port

_PORTS = (2049, 111)
_DEFAULT_PORT = 2049
_TIMEOUT = 6.0

_PMAP_PROG, _PMAP_VERS = 100000, 2
_MOUNT_PROG = 100005
_NFS_PROG = 100003
_IPPROTO_TCP = 6
_MAX_LIST = 4096                     # cap linked-list walks (hostile server guard)
_MAX_RECORD = 8 * 1024 * 1024        # cap total RPC record size (memory guard)
_MAX_FRAGMENTS = 64                  # cap record-marking fragments (loop guard)


def is_nfs(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    blob = f"{port.service} {port.product}".lower()
    return any(k in blob for k in ("nfs", "rpcbind", "portmap", "mountd"))


# --- ONC RPC over TCP (record marking) ------------------------------------------

def _pack_call(xid: int, prog: int, vers: int, proc: int, args: bytes = b"") -> bytes:
    """An RPC CALL message body (AUTH_NULL cred + verf), without record marking."""
    return struct.pack(
        ">IIIIIIIIII",
        xid, 0,            # mtype = CALL
        2,                 # rpcvers
        prog, vers, proc,
        0, 0,              # cred: AUTH_NULL, length 0
        0, 0,              # verf: AUTH_NULL, length 0
    ) + args


def _rpc(sock: socket.socket, xid: int, prog: int, vers: int, proc: int,
         args: bytes, timeout: float) -> bytes | None:
    """Send one RPC call over TCP (with record marking) and return the result bytes
    (everything after a SUCCESS accept), or None on any RPC/transport error."""
    body = _pack_call(xid, prog, vers, proc, args)
    # Record marking: last-fragment bit (0x80000000) | length.
    sock.settimeout(timeout)
    try:
        sock.sendall(struct.pack(">I", 0x80000000 | len(body)) + body)
    except OSError:
        return None
    reply = _recv_record(sock, timeout)
    if reply is None:
        return None
    return _parse_reply(reply, xid)


def _recv_record(sock: socket.socket, timeout: float) -> bytes | None:
    """Read a complete RPC record (one or more record-marking fragments). Bounded on
    both the total accumulated size and the fragment count so a hostile peer can't
    exhaust memory or loop forever by never setting the last-fragment bit."""
    sock.settimeout(timeout)
    out = b""
    for _ in range(_MAX_FRAGMENTS):
        hdr = _recvn(sock, 4, timeout)
        if hdr is None or len(hdr) < 4:
            return None
        marker = struct.unpack(">I", hdr)[0]
        last = bool(marker & 0x80000000)
        length = marker & 0x7FFFFFFF
        if length > _MAX_RECORD or len(out) + length > _MAX_RECORD:
            return None
        frag = _recvn(sock, length, timeout)
        if frag is None or len(frag) < length:
            return None
        out += frag
        if last:
            return out
    return None                                        # too many fragments -> give up


def _recvn(sock: socket.socket, n: int, timeout: float) -> bytes | None:
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(min(65536, n - len(buf)))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _parse_reply(data: bytes, want_xid: int):
    """Validate an RPC REPLY header and return the result payload, or None."""
    try:
        xid, mtype, reply_stat = struct.unpack_from(">III", data, 0)
    except struct.error:
        return None
    if xid != want_xid or mtype != 1 or reply_stat != 0:   # REPLY + MSG_ACCEPTED
        return None
    i = 12
    # verifier: flavor(4) + length(4) + body(length, padded)
    try:
        _flavor, vlen = struct.unpack_from(">II", data, i)
    except struct.error:
        return None
    i += 8 + _xdr_pad(vlen)
    try:
        accept_stat = struct.unpack_from(">I", data, i)[0]
    except struct.error:
        return None
    i += 4
    if accept_stat != 0:                                   # SUCCESS
        return None
    return data[i:]


# --- XDR readers (bounds-checked) ------------------------------------------------

def _xdr_pad(n: int) -> int:
    return (n + 3) & ~3


class _Cur:
    """A tiny bounds-checked XDR cursor over a byte buffer."""
    __slots__ = ("b", "i")

    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def u32(self) -> int:
        if self.i + 4 > len(self.b):
            raise ValueError("XDR: short uint32")
        v = struct.unpack_from(">I", self.b, self.i)[0]
        self.i += 4
        return v

    def opaque(self) -> bytes:
        n = self.u32()
        if n > len(self.b) - self.i:
            raise ValueError("XDR: opaque length out of range")
        v = self.b[self.i:self.i + n]
        self.i += _xdr_pad(n)
        return v

    def string(self) -> str:
        return self.opaque().decode("utf-8", "replace")


# --- portmapper + mountd ---------------------------------------------------------

def portmap_dump(ip: str, timeout: float = _TIMEOUT, pmport: int = 111) -> list[dict]:
    """PMAPPROC_DUMP: the registered RPC programs. Returns [{prog,vers,prot,port}]."""
    try:
        sock = socket.create_connection((ip, pmport), timeout=timeout)
    except OSError:
        return []
    try:
        res = _rpc(sock, 0x1001, _PMAP_PROG, _PMAP_VERS, 4, b"", timeout)
        if res is None:
            return []
        cur = _Cur(res)
        out = []
        try:
            while len(out) < _MAX_LIST:
                if cur.u32() == 0:                         # value-follows == FALSE
                    break
                prog, vers, prot, port = cur.u32(), cur.u32(), cur.u32(), cur.u32()
                out.append({"prog": prog, "vers": vers, "prot": prot, "port": port})
        except (ValueError, struct.error):
            pass                                           # keep what parsed cleanly
        return out
    except (ValueError, struct.error):
        return []
    finally:
        try:
            sock.close()
        except OSError:
            pass


def getport(ip: str, prog: int, vers: int, prot: int = _IPPROTO_TCP,
            timeout: float = _TIMEOUT, pmport: int = 111) -> int:
    """PMAPPROC_GETPORT for (prog, vers, prot). Returns the port, or 0."""
    try:
        sock = socket.create_connection((ip, pmport), timeout=timeout)
    except OSError:
        return 0
    try:
        args = struct.pack(">IIII", prog, vers, prot, 0)
        res = _rpc(sock, 0x1002, _PMAP_PROG, _PMAP_VERS, 3, args, timeout)
        if res is None or len(res) < 4:
            return 0
        return struct.unpack_from(">I", res, 0)[0]
    finally:
        try:
            sock.close()
        except OSError:
            pass


def mount_export(ip: str, port: int, vers: int = 3,
                 timeout: float = _TIMEOUT) -> list[dict]:
    """MOUNTPROC_EXPORT (proc 5): the export list. Returns
    [{dir, groups:[hostspec, ...]}] - groups empty means shared to everyone."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return []
    try:
        res = _rpc(sock, 0x1003, _MOUNT_PROG, vers, 5, b"", timeout)
        if res is None:
            return []
        cur = _Cur(res)
        exports = []
        try:
            while len(exports) < _MAX_LIST:
                if cur.u32() == 0:                         # no more exports
                    break
                dirp = cur.string()
                groups = []
                while len(groups) < _MAX_LIST:
                    if cur.u32() == 0:                     # no more groups
                        break
                    groups.append(cur.string())
                exports.append({"dir": dirp, "groups": groups})
        except (ValueError, struct.error):
            pass                                           # keep exports parsed so far
        return exports
    except (ValueError, struct.error):
        return []
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe(ip: str, timeout: float = _TIMEOUT, pmport: int = 111) -> dict:
    """Read-only NFS/mountd fingerprint via portmapper + mountd EXPORT. Returns
    {reachable, programs, nfs, mountd_port, exports, error}. `pmport` is the
    portmapper port (111 in the wild; overridable for testing)."""
    out: dict = {"reachable": False, "programs": [], "exports": []}
    progs = portmap_dump(ip, timeout, pmport)
    if progs:
        out["reachable"] = True
        out["programs"] = progs
        out["nfs"] = any(p["prog"] == _NFS_PROG for p in progs)
        # mountd's registered TCP port (prefer a v3 registration).
        mport = 0
        for p in progs:
            if p["prog"] == _MOUNT_PROG and p["prot"] == _IPPROTO_TCP and p["port"]:
                mport = p["port"]
                if p["vers"] == 3:
                    break
        if not mport:
            mport = getport(ip, _MOUNT_PROG, 3, _IPPROTO_TCP, timeout, pmport) or \
                getport(ip, _MOUNT_PROG, 1, _IPPROTO_TCP, timeout, pmport)
        out["mountd_port"] = mport
        if mport:
            exp = mount_export(ip, mport, 3, timeout) or \
                mount_export(ip, mport, 1, timeout)
            out["exports"] = exp
    return out


def nfs_targets(hosts: list[Host]) -> list[dict]:
    """One target per host that exposes NFS/portmapper (deduped - the RPC work is
    per-host, driven off portmapper 111)."""
    seen, out = set(), []
    for h in hosts:
        if h.ip in seen:
            continue
        ports = {p.portid for p in h.open_ports}
        if any(is_nfs(p) for p in h.open_ports):
            seen.add(h.ip)
            port = 111 if 111 in ports else _DEFAULT_PORT
            out.append({"ip": h.ip, "hostname": h.hostname, "port": port})
    return out


# --- narratives + findings ------------------------------------------------------

_EVERYONE = ("*", "(everyone)", "everyone", "0.0.0.0/0", "::/0")


def _is_world(groups: list[str]) -> bool:
    """True if an export is shared to any host (no restriction / a bare wildcard).
    A scoped wildcard like '*.corp.example.com' is a domain restriction, NOT
    everyone, so it is not treated as world-mountable."""
    if not groups:
        return True
    return any(g.strip().lower() in _EVERYONE for g in groups)


_NARRATIVE = {
    "nfs_world": (
        "The NFS export is shared to every host on the network (no client "
        "restriction / a wildcard). Any machine can mount it and read every file; if "
        "the server maps UIDs permissively or exports with no_root_squash, a mounted "
        "attacker also writes as any user or root - a direct path to file tampering, "
        "credential theft (SSH keys, /etc/shadow on a root-squash-off export) and code "
        "execution via a planted SUID binary or cron/authorized_keys. Restrict every "
        "export to specific hosts/subnets, enable root_squash, and export read-only "
        "where possible."),
    "nfs_export": (
        "The NFS server lists its exports (showmount -e) to anyone with no credential. "
        "Even restricted exports leak the server's directory layout and the client "
        "ACLs, mapping out what to target next. Firewall the portmapper (111) and "
        "mountd, and restrict who may query the export list."),
    "nfs_rpc": (
        "The portmapper (rpcbind, 111) answers a DUMP with the full list of registered "
        "RPC services and ports to anyone. It is reconnaissance-friendly and has a "
        "history of reflection/amplification abuse - firewall it to trusted hosts."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. RPC directory (stdlib ONC RPC)",
     "recce speaks Sun RPC directly - no rpcinfo/showmount. It calls the portmapper "
     "DUMP on 111 to read which RPC services (nfs / mountd / ...) are registered."),
    ("2. Export list (showmount -e)",
     "It resolves mountd's port and calls MOUNTPROC_EXPORT to read every exported "
     "directory and the host list it is shared to - read-only, no mount."),
    ("3. Exposure classification",
     "An export shared to * / everyone (or with no host restriction) is mountable by "
     "any host (critical/high - read, and often write via no_root_squash). A "
     "restricted-but-enumerable export list is a lower-severity information leak."),
    ("4. Runbook",
     "The exact follow-on commands (showmount -e, mount -o vers=3, the no_root_squash "
     "SUID/UID-switch escalation) are staged per host."),
]


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "nfs", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        pr = probes.get(h.ip) or {}
        if not pr:
            continue
        tgt = f"{h.ip}:2049"
        exports = pr.get("exports") or []
        world = [e for e in exports if _is_world(e.get("groups") or [])]
        if world:
            dirs = ", ".join(e["dir"] for e in world[:12])
            out.append(_finding(
                "high", "NFS export shared to any host (world-mountable)", tgt,
                f"{len(world)} export(s) are shared with no host restriction / a "
                f"wildcard: {dirs}. Any machine on the network can mount and read "
                "them (and write, if root-squash is off).",
                "showmount / mount",
                f"showmount -e {h.ip} ; mkdir /mnt/x ; mount -o vers=3 {h.ip}:"
                f"{world[0]['dir']} /mnt/x   # then read/plant files (within ROE)",
                "Restrict every export to specific hosts/subnets, enable root_squash, "
                "and export read-only where possible.",
                ["CWE-284", "CWE-732"], kind="nfs_world"))
        if exports:
            dirs = ", ".join(e["dir"] for e in exports[:12])
            out.append(_finding(
                "medium", "NFS exports enumerable without authentication", tgt,
                f"mountd listed {len(exports)} export(s) with no credential: {dirs}."
                " The export list leaks the server's layout + client ACLs.",
                "showmount",
                f"showmount -e {h.ip}",
                "Firewall the portmapper (111) + mountd and restrict who may query "
                "the export list.",
                ["CWE-200"], kind="nfs_export"))
        elif pr.get("programs"):
            svcs = ", ".join(sorted({str(p["prog"]) for p in pr["programs"]})[:12])
            out.append(_finding(
                "low", "RPC services enumerable via portmapper (rpcbind)", tgt,
                f"rpcbind (111) listed {len(pr['programs'])} registered RPC "
                f"program/version entr(ies) with no credential (programs: {svcs}).",
                "rpcinfo",
                f"rpcinfo -p {h.ip}",
                "Firewall rpcbind (111) to trusted hosts.",
                ["CWE-200"], kind="nfs_rpc"))
    return out


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str) -> list[dict]:
    steps = [
        ("recon", "rpcinfo", f"rpcinfo -p {ip}",
         "List registered RPC services + ports."),
        ("enumerate", "showmount", f"showmount -e {ip}",
         "List every NFS export and its client ACL (confirms exposure)."),
        ("loot", "mount", f"mkdir /mnt/nfs ; mount -o vers=3 {ip}:<export> /mnt/nfs ; "
         "ls -la /mnt/nfs",
         "Mount an open export and read its files."),
        ("escalate", "no_root_squash", "on a no_root_squash export: copy a SUID-root "
         "shell in, or drop an SSH key / cron as the mapped UID -> code execution "
         "(only within scope).",
         "Turn a writable export into code execution."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "nfs", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full NFS analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = nfs_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(targets, lambda t: probe(t["ip"]),
                                         budget=budget, progress=progress, state=state):
            if pr and pr.get("reachable"):
                probes[t["ip"]] = pr
                t["exports"] = len(pr.get("exports") or [])
                t["world"] = sum(1 for e in pr.get("exports") or []
                                 if _is_world(e.get("groups") or []))
                t["programs"] = len(pr.get("programs") or [])
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": probes,
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
