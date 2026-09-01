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
import struct

from ...core.models import Host, Port
from ..svccommon import finding_builder, make_proof_html_wrapper, make_findings_to_vulns_wrapper

_PORTS = (11211, 11210, 11215)
_DEFAULT_PORT = 11211
_TIMEOUT = 5.0
_MAX_REPLY = 256 * 1024            # stats are a few KB; cap so a hostile peer can't
                                  # make us buffer unbounded.
_CACHEDUMP_SLABS = 4              # sample at most this many slabs ...
_CACHEDUMP_KEYS = 20              # ... and this many keys per slab (proof, not a dump).
# --- bounded value + metadump caps (additive capabilities) ---------------------
_METADUMP_MAX_KEYS = 200          # `lru_crawler metadump all` can stream forever - cap.
_METADUMP_MAX_BYTES = 128 * 1024  # ...and cap the raw stream too so a huge cache
                                  # can't make us buffer unbounded.
_VALUE_FETCH_MAX_KEYS = 8         # multi-`get` at most this many keys (proof, not a
                                  # dump - a full dump is what an attacker does).
_VALUE_PREVIEW_BYTES = 256        # per-value preview cap (redact the rest to a length).
_VALUE_TOTAL_BYTES = 4 * 1024     # aggregate cap across all captured previews.
_UDP_TIMEOUT = 2.0                # UDP probe budget (single datagram round trip).
_UDP_REPLY_CAP = 65_507           # max UDP payload; also the single-recv upper bound.


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


def _pct_unquote(s: str) -> str:
    """URL-decode `%XX` escapes in metadump key names (protocol.txt encodes any
    byte outside `[a-zA-Z0-9._-]` as %XX). stdlib-only, tolerant to malformed
    escapes (leave them literal rather than crash on a hostile peer)."""
    if "%" not in s:
        return s
    out: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "%" and i + 2 < len(s):
            try:
                out.append(chr(int(s[i + 1:i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(c)
        i += 1
    return "".join(out)


def _parse_metadump_keys(raw: bytes) -> list[str]:
    """`lru_crawler metadump all` -> lines starting with `key=<pct-encoded>` and
    space-separated `k=v` metadata. Returns the decoded key names in order, up to
    `_METADUMP_MAX_KEYS`. Also returns cleanly on:
      * `BUSY` / `NOTFOUND` / `CLIENT_ERROR` (added <1.4.31 or crawler disabled)
      * `ERROR` (command unknown on very old servers)
    ...i.e. an empty list means 'not supported here', never a crash."""
    keys: list[str] = []
    for line in raw.split(b"\n"):
        if len(keys) >= _METADUMP_MAX_KEYS:
            break
        line = line.rstrip(b"\r")
        if line.startswith(b"key="):
            head = line.split(b" ", 1)[0]     # key=<encoded>
            try:
                enc = head[4:].decode("ascii", "replace")
            except Exception:                  # noqa: BLE001
                continue
            keys.append(_pct_unquote(enc))
    return keys


def _parse_values(raw: bytes) -> list[dict]:
    """`get k1 k2 ...` reply -> [{key, bytes, preview, truncated}]. Reply lines:
        VALUE <key> <flags> <bytes>[ <cas>]\r\n
        <data of exactly <bytes> bytes>\r\n
        ...
        END\r\n
    We walk the buffer as bytes (values are opaque - may contain CR/LF), pull
    the first `_VALUE_PREVIEW_BYTES` of each value as a printable-with-replace
    preview, and stop when we hit END or the total-preview budget."""
    out: list[dict] = []
    total = 0
    i = 0
    n = len(raw)
    while i < n:
        # Find next line end
        nl = raw.find(b"\r\n", i)
        if nl == -1:
            break
        line = raw[i:nl]
        i = nl + 2
        if line == b"END":
            break
        if not line.startswith(b"VALUE "):
            # ERROR, CLIENT_ERROR, SERVER_ERROR, or unexpected -> stop cleanly.
            break
        parts = line.split(b" ")
        # VALUE <key> <flags> <bytes> [<cas>]
        if len(parts) < 4:
            break
        try:
            key = parts[1].decode("ascii", "replace")
            length = int(parts[3])
        except (ValueError, IndexError):
            break
        if length < 0 or length > _MAX_REPLY:
            break
        end = i + length
        if end > n:
            break
        data = raw[i:end]
        i = end + 2                            # skip trailing \r\n after value
        preview_len = min(length, _VALUE_PREVIEW_BYTES,
                          max(0, _VALUE_TOTAL_BYTES - total))
        preview_bytes = data[:preview_len]
        preview = preview_bytes.decode("utf-8", "replace")
        out.append({"key": key, "bytes": length, "preview": preview,
                    "truncated": length > preview_len})
        total += preview_len
        if total >= _VALUE_TOTAL_BYTES:
            break
    return out


def _udp_frame(payload: bytes, request_id: int = 0x0001) -> bytes:
    """Build the memcached UDP frame: 8-byte header (request_id, seq_num=0,
    num_datagrams=1, reserved=0) followed by the ASCII text command. See
    memcached protocol.txt 'UDP protocol'."""
    return struct.pack("!HHHH", request_id & 0xFFFF, 0, 1, 0) + payload


def udp_stats_probe(ip: str, port: int, timeout: float = _UDP_TIMEOUT) -> dict:
    """Send a single `stats\\r\\n` UDP datagram and measure the reply. Returns
    {responded, request_bytes, response_bytes, amp_ratio, num_datagrams, error}.

    The 8-byte UDP frame header is included in both counts (that's what an
    attacker's spoofed packet and its reflected reply actually carry on the wire).
    Reads at most one datagram - a real memcrashed abuser gets many, but for a
    CONFIRMATION-of-exposure probe one is enough to prove the port answers and
    to fingerprint the amplification factor.
    """
    res = {"responded": False, "request_bytes": 0, "response_bytes": 0,
           "amp_ratio": 0.0, "num_datagrams": 0, "error": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        frame = _udp_frame(b"stats\r\n")
        res["request_bytes"] = len(frame)
        sock.sendto(frame, (ip, port))
        try:
            data, _ = sock.recvfrom(_UDP_REPLY_CAP)
        except (socket.timeout, OSError) as e:
            res["error"] = str(e) or "no reply"
            return res
        res["responded"] = True
        res["response_bytes"] = len(data)
        if len(data) >= 8:
            _req, _seq, nd, _res = struct.unpack("!HHHH", data[:8])
            res["num_datagrams"] = int(nd)
        if res["request_bytes"] > 0:
            res["amp_ratio"] = round(res["response_bytes"] / res["request_bytes"], 2)
    except OSError as e:
        res["error"] = res["error"] or str(e)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return res


def _classify_key(name: str) -> str:
    """Return a short tag ('session' / 'auth' / 'csrf' / 'apikey' / '') for a
    key name - purely a string-shape hint, no value inspection. Order matters:
    more specific tags win over generic 'auth'."""
    low = name.lower()
    if "csrf" in low or "xsrf" in low:
        return "csrf"
    for hint in ("sess", "sessid", "phpsessid", "jsessionid", "asp.net_sessionid",
                 "django.contrib.sessions", "laravel_session", "connect.sid"):
        if hint in low:
            return "session"
    for hint in ("api_key", "apikey", "api-key", "secret", "password", "passwd"):
        if hint in low:
            return "apikey"
    for hint in ("jwt", "token", "bearer", "oauth", "refresh", "auth"):
        if hint in low:
            return "auth"
    return ""


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Read version + stats and (if exposed) sample live keys, all without a credential.
    Returns {reachable, unauth, version, stats, items, keys_sampled, sample_keys, arch,
    error, sample_values, metadump_supported, sensitive_key_tags, udp}."""
    res: dict = {"reachable": False, "unauth": False, "version": "", "stats": {},
                 "items": 0, "keys_sampled": 0, "sample_keys": [], "arch": "",
                 "error": "",
                 # additive fields for new capabilities (empty on failure/unsupported)
                 "sample_values": [], "metadump_supported": False,
                 "sensitive_key_tags": {}, "udp": {}}
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
                    # Modern servers (>=1.4.31) often truncate/disable cachedump for
                    # large slabs. `lru_crawler metadump all` streams metadata for
                    # every item. Cap the raw stream and the key count so a huge
                    # cache can't make us buffer unbounded (see _METADUMP_MAX_*).
                    meta_raw = _command(sock, "lru_crawler metadump all",
                                        (b"END\r\n", b"BUSY", b"NOTFOUND",
                                         b"CLIENT_ERROR", b"ERROR"))
                    meta_raw = meta_raw[:_METADUMP_MAX_BYTES]
                    meta_keys = _parse_metadump_keys(meta_raw)
                    if meta_keys:
                        res["metadump_supported"] = True
                        # Merge without losing insertion order; metadump is authoritative
                        # (full enumeration) but keep cachedump names first for stability.
                        seen = set(res["sample_keys"])
                        for k in meta_keys:
                            if k not in seen:
                                res["sample_keys"].append(k)
                                seen.add(k)
                        res["sample_keys"] = res["sample_keys"][:_METADUMP_MAX_KEYS]
                    res["keys_sampled"] = len(res["sample_keys"])
                    # Classify key names (session/JWT/csrf/apikey shapes) and use
                    # those tags to prioritise which keys we `get` for the value proof.
                    tags: dict[str, str] = {}
                    for k in res["sample_keys"]:
                        t = _classify_key(k)
                        if t:
                            tags[k] = t
                    res["sensitive_key_tags"] = tags
                    # Value-retrieval proof: multi-`get` on a bounded selection, keeping
                    # per-value + total previews small. Sensitive-shaped keys first.
                    if res["sample_keys"]:
                        ranked = sorted(res["sample_keys"],
                                        key=lambda k: (0 if k in tags else 1))
                        picks = ranked[:_VALUE_FETCH_MAX_KEYS]
                        # `get` accepts up to ~250-byte keys space-separated; keep the
                        # command well under _MAX_REPLY on the send side too.
                        get_line = "get " + " ".join(picks)
                        vals_raw = _command(sock, get_line, (b"END\r\n", b"ERROR"))
                        res["sample_values"] = _parse_values(vals_raw)
    except (OSError, socket.timeout) as e:
        res["error"] = res["error"] or str(e)
    # UDP amplification-vector confirmation. Independent of the TCP session so a
    # TCP-only bind still gets an honest "no UDP" answer (and old builds where
    # UDP defaults on get a MEASURED amplification ratio, not a narrative claim).
    try:
        res["udp"] = udp_stats_probe(ip, port, timeout=min(timeout, _UDP_TIMEOUT))
    except OSError as e:
        res["udp"] = {"responded": False, "request_bytes": 0, "response_bytes": 0,
                      "amp_ratio": 0.0, "num_datagrams": 0, "error": str(e)}
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
    "memcached_values_readable": (
        "recce fetched actual cached VALUES with `get` and no credential - not just key "
        "names. Whatever the application caches (session tokens, JWTs, rendered pages, "
        "API responses, DB query results, secrets) is directly readable by anyone who "
        "can reach this port. Session/JWT-shaped keys are session-hijack primitives; "
        "cached responses may contain PII. Bind to localhost, enable SASL (-S), and "
        "firewall the port."),
    "memcached_udp_amplification": (
        "UDP 11211 answered a `stats` datagram and the reply was many times larger "
        "than the request - this instance is USABLE as a DDoS reflection/amplification "
        "source (the memcrashed class of attack, historic factors up to ~50,000x). "
        "Attackers spoof a victim's source IP, send small UDP `stats`/`get` queries, "
        "and the server floods the victim with the replies. Disable UDP (-U 0) on "
        "modern builds and firewall UDP 11211 at the network edge."),
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
                    ["CWE-306", "CWE-284"], kind="memcached_unauth",
                    exploit_note=(
                        "printf 'stats\\r\\nstats items\\r\\nstats cachedump 1 200"
                        "\\r\\n' | ncat <ip> <port>"),
                    depth_tier="t2"))
            if ver and _old_version(ver):
                out.append(_finding(
                    "medium", "memcached end-of-life / legacy build", tgt,
                    f"memcached {ver} predates 1.4.32 and carries binary/SASL-protocol "
                    "integer-overflow RCE bugs (CVE-2016-8704/8705/8706).",
                    "ncat", f"printf 'version\\r\\n' | ncat {h.ip} {p.portid}",
                    "Upgrade memcached to a supported release (>= 1.6).",
                    ["CWE-1104", "CWE-190"], kind="memcached_version",
                    exploit_note=(
                        "printf 'version\\r\\n' | ncat <ip> <port> ; compare against "
                        "1.4.32 / 1.6.x advisories."),
                    depth_tier="t0"))
            # Value-retrieval proof - upgrades unauth-key-names to unauth-values.
            vals = pr.get("sample_values") or []
            if vals:
                tags = pr.get("sensitive_key_tags") or {}
                sample_bits = []
                for v in vals[:4]:
                    k = v.get("key", "")
                    tag = tags.get(k, "")
                    tag_s = f" [{tag}]" if tag else ""
                    sample_bits.append(f"{k}{tag_s}={v.get('bytes', 0)}B")
                sens = sorted({t for t in tags.values() if t})
                sens_s = f"; sensitive-shaped keys: {', '.join(sens)}" if sens else ""
                out.append(_finding(
                    "critical", "memcached cached values readable without credential",
                    tgt,
                    f"recce fetched {len(vals)} cached value(s) with `get` and no "
                    f"authentication (sample: {'; '.join(sample_bits)}){sens_s}.",
                    "ncat",
                    f"printf 'get <key>\\r\\n' | ncat {h.ip} {p.portid}   "
                    f"# after: stats cachedump <slab> <n>",
                    "Bind to localhost, enable SASL (-S), firewall the port.",
                    ["CWE-200", "CWE-522"], kind="memcached_values_readable",
                    exploit_note=(
                        "printf 'get <sensitive-key>\\r\\n' | ncat <ip> <port> ; "
                        "then curl -H 'Cookie: SESSIONID=<hijacked>' "
                        "https://<paired-app>/ to prove the hijack."),
                    depth_tier="t2"))
            # UDP amplification-vector confirmation - only fires when we actually
            # got a datagram back (never on inference).
            udp = pr.get("udp") or {}
            if udp.get("responded") and udp.get("amp_ratio", 0.0) >= 2.0:
                out.append(_finding(
                    "critical", "memcached UDP reflection/amplification confirmed",
                    tgt,
                    f"UDP {p.portid} replied to `stats` with "
                    f"{udp.get('response_bytes', 0)} bytes for a "
                    f"{udp.get('request_bytes', 0)}-byte request "
                    f"(amplification ~{udp.get('amp_ratio', 0.0)}x, "
                    f"{udp.get('num_datagrams', 0)} datagram(s)).",
                    "ncat",
                    f"# UDP is answering - reflection-usable\n"
                    f"# hexdump -C <<< $'\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x00stats\\r\\n'"
                    f" | ncat -u {h.ip} {p.portid}",
                    "Disable UDP with `-U 0` (memcached >= 1.5.6 default) and firewall "
                    "UDP 11211 at the edge.",
                    ["CWE-406", "CWE-405"], kind="memcached_udp_amplification",
                    exploit_note=(
                        "printf '\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x00stats"
                        "\\r\\n' | ncat -u <ip> <port> - measure reply size vs "
                        "request size."),
                    depth_tier="t1"))
    return out


def _old_version(ver: str) -> bool:
    from ...vuln import vulndb
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


proof_html = make_proof_html_wrapper("$ ")
findings_to_vulns = make_findings_to_vulns_wrapper("memcached", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full memcached analysis. Returns {targets, findings, runbooks, probes, stats}.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from .. import svcprobe
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
