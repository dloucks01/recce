"""Deep memcached enumeration - PRE-AUTH, airgapped (stdlib only).

memcached speaks a simple line-based text protocol on TCP 11211 and, by default,
requires NO authentication: anyone who can reach the port can read every cached
item and the server statistics. recce speaks that protocol directly (no
python-memcached) to CONFIRM the exposure and sample what is readable:

  * **version**         - the exact server build (feeds the version->CVE engine).
  * **stats**           - item counts, bytes cached, connections, uptime, arch.
  * **stats items**     - which slabs hold data (proves items are present).
  * **stats cachedump** - a READ-ONLY sample of live keys (proves data exposure
                          without dumping values).

An open memcached that answers `stats` with no credential is a confirmed
unauthenticated data-exposure finding (and a massive UDP reflection/amplification
vector on the same port). recce never SETs, deletes or flushes - it only reads.
Authorized testing only.
"""
from __future__ import annotations

import socket

from .models import Host, Port
from .svccommon import finding_builder

_PORTS = (11211, 11210, 11215)
_DEFAULT_PORT = 11211
_TIMEOUT = 5.0
_MAX_REPLY = 256 * 1024            # stats are a few KB; cap so a hostile peer can't
                                  # make us buffer unbounded.
_CACHEDUMP_SLABS = 4              # sample at most this many slabs ...
_CACHEDUMP_KEYS = 20              # ... and this many keys per slab (proof, not a dump).


def is_memcached(port: Port) -> bool:
    if port.portid in _PORTS:
        return True
    return "memcach" in f"{port.service} {port.product}".lower()


def memcached_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_memcached(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- text protocol (stdlib) -----------------------------------------------------

def _read_until(sock: socket.socket, terminators: tuple[bytes, ...]) -> bytes:
    """Read lines until one of `terminators` (e.g. b'END\r\n', b'ERROR\r\n') appears or
    the peer closes / we hit the reply cap. Never raises on a hostile peer."""
    buf = b""
    while len(buf) < _MAX_REPLY:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        # A single-line status reply (VERSION.., ERROR, CLIENT_ERROR, SERVER_ERROR)
        # ends at the first CRLF; multi-line replies end with an END line.
        if any(t in buf for t in terminators):
            break
        if buf.endswith(b"\r\n") and buf.count(b"\r\n") == 1 and not buf.startswith(b"STAT"):
            break
    return buf


def _command(sock: socket.socket, line: str, terminators: tuple[bytes, ...]) -> bytes:
    sock.sendall(line.encode("ascii", "replace") + b"\r\n")
    return _read_until(sock, terminators)


def _parse_stats(raw: bytes) -> dict:
    """STAT <name> <value>\r\n lines -> {name: value}."""
    out: dict[str, str] = {}
    for line in raw.split(b"\r\n"):
        if line.startswith(b"STAT "):
            parts = line[5:].split(b" ", 1)
            if len(parts) == 2:
                out[parts[0].decode("ascii", "replace")] = parts[1].decode("ascii", "replace")
    return out


def _parse_slabs(raw: bytes) -> list[int]:
    """`stats items` -> STAT items:<slab>:number <n> ... return slab ids that hold items."""
    slabs: dict[int, int] = {}
    for line in raw.split(b"\r\n"):
        if line.startswith(b"STAT items:"):
            try:
                _, rest = line.split(b"items:", 1)
                slab_s, kv = rest.split(b":", 1)
                key, val = kv.split(b" ", 1)
                if key == b"number":
                    slabs[int(slab_s)] = int(val)
            except (ValueError, IndexError):
                continue
    return [s for s, n in sorted(slabs.items()) if n > 0]


def _parse_cachedump_keys(raw: bytes) -> list[str]:
    """`stats cachedump <slab> <n>` -> ITEM <key> [<b>; <ts>]  ... return the key names."""
    keys = []
    for line in raw.split(b"\r\n"):
        if line.startswith(b"ITEM "):
            rest = line[5:]
            name = rest.split(b" ", 1)[0]
            keys.append(name.decode("ascii", "replace"))
    return keys


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Read version + stats and (if exposed) sample live keys, all without a credential.
    Returns {reachable, unauth, version, stats, items, keys_sampled, sample_keys, arch,
    error}."""
    res: dict = {"reachable": False, "unauth": False, "version": "", "stats": {},
                 "items": 0, "keys_sampled": 0, "sample_keys": [], "arch": "",
                 "error": ""}
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            res["reachable"] = True
            ver = _command(sock, "version", (b"\r\n", b"ERROR"))
            if ver.startswith(b"VERSION "):
                res["version"] = ver[8:].strip().decode("ascii", "replace")
            elif b"ERROR" in ver or not ver:
                # Not memcached, or SASL-gated (binary protocol) - the text `version`
                # errors. Either way we can't confirm unauth text access.
                res["error"] = "no VERSION reply (non-memcached or SASL-gated)"
                # still try stats below in case only `version` was blocked
            stats_raw = _command(sock, "stats", (b"END\r\n", b"ERROR"))
            stats = _parse_stats(stats_raw)
            if stats:
                res["unauth"] = True
                res["stats"] = {k: stats.get(k, "") for k in (
                    "version", "curr_items", "total_items", "bytes", "limit_maxbytes",
                    "curr_connections", "uptime", "cmd_get", "cmd_set", "pointer_size")
                    if k in stats}
                res["version"] = res["version"] or stats.get("version", "")
                ptr = stats.get("pointer_size", "")
                res["arch"] = f"{ptr}-bit" if ptr else ""
                try:
                    res["items"] = int(stats.get("curr_items", 0))
                except ValueError:
                    res["items"] = 0
                # Prove data exposure: sample a few live keys (read-only), never values.
                if res["items"] > 0:
                    items_raw = _command(sock, "stats items", (b"END\r\n", b"ERROR"))
                    for slab in _parse_slabs(items_raw)[:_CACHEDUMP_SLABS]:
                        dump = _command(sock, f"stats cachedump {slab} {_CACHEDUMP_KEYS}",
                                        (b"END\r\n", b"ERROR"))
                        res["sample_keys"].extend(_parse_cachedump_keys(dump))
                    res["sample_keys"] = res["sample_keys"][:_CACHEDUMP_KEYS]
                    res["keys_sampled"] = len(res["sample_keys"])
    except (OSError, socket.timeout) as e:
        res["error"] = res["error"] or str(e)
    return res


# --- narratives + findings ------------------------------------------------------

_NARRATIVE = {
    "memcached_unauth": (
        "The memcached instance answers the text protocol with NO authentication - "
        "recce read the server `stats` (and sampled live keys) without a credential. "
        "That is full read access to everything cached here: session tokens, rendered "
        "pages, API responses, DB query results and any secret the application caches. "
        "recce only READ - but an attacker with the same access can also SET/DELETE/"
        "FLUSH to poison caches (auth-bypass, XSS, cache-poisoning of downstream apps). "
        "The same open UDP 11211 is one of the largest DDoS reflection/amplification "
        "vectors on the internet. Bind memcached to localhost, enable SASL (-S), "
        "disable UDP (-U 0), and firewall 11211."),
    "memcached_version": (
        "The memcached build is old. Pre-1.4.32 releases have integer-overflow RCE bugs "
        "in the binary/SASL protocol (CVE-2016-8704/8705/8706); confirm the version and "
        "upgrade."),
}

TESTING_NARRATIVE = [
    ("1. Version (stdlib text protocol)",
     "recce speaks the memcached text protocol directly (no client library). It sends "
     "`version` and reads the VERSION reply to fingerprint the exact build."),
    ("2. Unauthenticated access test",
     "It sends `stats`. If the server statistics come back, the instance is exposed "
     "unauthenticated (a SASL-enforced server errors instead) - a confirmed finding."),
    ("3. Data-exposure proof (read-only)",
     "On an exposed instance it runs `stats items` then `stats cachedump <slab> <n>` to "
     "list a sample of LIVE key names - proving real cached data is readable. It never "
     "reads values and never writes."),
    ("4. Runbook",
     "The follow-on commands (nmap memcached-info, the ncat stats/cachedump chain, the "
     "amplification note) are staged per endpoint."),
]

_finding = finding_builder("memcached", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_memcached(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version", "")
            if pr.get("unauth"):
                items = pr.get("items", 0)
                sample = pr.get("sample_keys") or []
                extra = ""
                if items:
                    extra = f"; {items} item(s) cached"
                    if sample:
                        extra += " (sample keys: " + ", ".join(sample[:8]) + ")"
                out.append(_finding(
                    "high", "memcached exposed without authentication", tgt,
                    "recce read server `stats` with no credential"
                    + (f" (version {ver})" if ver else "")
                    + extra
                    + ". Full unauthenticated read access to every cached item, cache "
                      "poisoning via SET/DELETE, and a UDP reflection/amplification vector.",
                    "ncat",
                    f"printf 'stats\\r\\nstats items\\r\\n' | ncat {h.ip} {p.portid}   "
                    f"# then: stats cachedump <slab> <n> ; get <key>",
                    "Bind to localhost, enable SASL (-S), disable UDP (-U 0), firewall 11211.",
                    ["CWE-306", "CWE-284"], kind="memcached_unauth"))
            if ver and _old_version(ver):
                out.append(_finding(
                    "medium", "memcached end-of-life / legacy build", tgt,
                    f"memcached {ver} predates 1.4.32 and carries binary/SASL-protocol "
                    "integer-overflow RCE bugs (CVE-2016-8704/8705/8706).",
                    "ncat", f"printf 'version\\r\\n' | ncat {h.ip} {p.portid}",
                    "Upgrade memcached to a supported release (>= 1.6).",
                    ["CWE-1104", "CWE-190"], kind="memcached_version"))
    return out


def _old_version(ver: str) -> bool:
    from . import vulndb
    try:
        return vulndb._cmp(ver, "1.4.32") < 0
    except Exception:      # noqa: BLE001 - a weird banner must never crash the scan
        return False


# --- runbook + proof + analyze --------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", f"nmap -p{port} --script memcached-info {ip}",
         "Server info + stats (confirms unauth if it answers)."),
        ("enumerate", "ncat",
         f"printf 'stats\\r\\nstats items\\r\\nstats slabs\\r\\n' | ncat {ip} {port}",
         "Read server stats and which slabs hold cached data - no credential."),
        ("loot", "ncat",
         f"printf 'stats cachedump 1 100\\r\\n' | ncat {ip} {port}   "
         f"# then: get <key>",
         "List live key names, then read cached values (sessions, tokens, secrets)."),
        ("amplify", "note",
         f"# UDP {port} is a DDoS reflection vector (bandwidth amp ~= 10,000-51,000x)",
         "Exposed UDP memcached is abused for reflection/amplification DDoS."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "memcached", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full memcached analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = memcached_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["unauth"] = pr.get("unauth", False)
                t["version"] = pr.get("version", "") or t.get("version", "")
                t["items"] = pr.get("items", 0)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
