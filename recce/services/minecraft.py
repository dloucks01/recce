"""Minecraft Java Edition Server List Ping (SLP) probe (25565/tcp).

Minecraft's SLP is an unauthenticated protocol every vanilla/Paper/Spigot/Forge
server answers: two client-first frames (Handshake + Status Request) → one
JSON blob describing version, MOTD, player sample, favicon, and (Forge) mod
inventory. On corp-owned dev/game boxes the MOTD and player sample routinely
carry internal hostnames and employee identities — an enumeration payoff
regardless of whether the server itself is exploitable.

Two exploit surfaces sit on top of the raw enumeration:

  * **Log4Shell (CVE-2021-44228)** — every Java Edition build from 1.7
    through 1.18.0 inclusive shipped a vulnerable log4j 2.x that logged
    chat/JNDI substitutions. Mojang backported an emergency mitigation in
    1.18.1 and out-of-band patches for older lines; the version string
    alone is enough to classify. recce does NOT send a JNDI probe — that
    would BE the exploit — it flags off the captured version.name.
  * **RCON on 25575/tcp** — Source-RCON companion port, off by default in
    server.properties but enabled on plenty of admin-friendly builds. An
    empty-password Login (type 3) that gets an AUTH_RESPONSE with the
    original request-id is instant `/op` / `/execute` on the server.

Wire format (wiki.vg "Server List Ping"): all lengths + packet-ids are
VarInt (7-bit LE, MSB=continuation). Framed outer packet = VarInt length
prefix + body. Handshake state 1 → Status Request 0x00 → Status Response
0x00 with a single length-prefixed JSON String field.

Stdlib only (socket, struct, json, hashlib, base64, re). Bounded 2-6s
timeouts through proxy.scaled(_TIMEOUT).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 25565
_RCON_DEFAULT_PORT = 25575
_TIMEOUT = 4.0
_RCON_TIMEOUT = 3.0

# Cap the JSON status body at 128 KiB. A 64x64 favicon PNG base64-encoded is
# ~15 KiB; 128 KiB accommodates verbose modpack advertisements without letting
# a hostile server drain the read.
_STATUS_MAX = 128 * 1024

# Legacy formatting: § followed by [0-9a-fk-or].
_MC_FORMAT_RE = re.compile("§[0-9a-fk-orA-FK-OR]")

# FQDN-ish token — at least two DNS labels, no scheme, no port, no /path.
_FQDN_TOKEN_RE = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,})\b"
)

# Vanilla / Paper / Spigot / Forge / Purpur / etc. — capture the Java Edition
# version (X.Y[.Z]) from a version.name that may prefix a distro tag.
_MC_VERSION_RE = re.compile(
    r"\b(1\.(?:[2-9]|1[0-9]|20)(?:\.\d{1,2})?)\b"
)


def is_minecraft(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == _DEFAULT_PORT
            or "minecraft" in svc or "minecraft" in prod)


# --- VarInt / packet framing ------------------------------------------------

def _write_varint(value: int) -> bytes:
    """Minecraft VarInt: 7 bits per byte, MSB=continuation, two's-complement
    for negative values (protocol_version=-1 is a common client hint)."""
    n = value & 0xFFFFFFFF
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _read_varint(buf: bytes, offset: int) -> tuple[int, int]:
    """Return (value, new_offset). Raises IndexError on truncation."""
    n = 0
    shift = 0
    i = offset
    while True:
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 35:
            raise ValueError("VarInt too long")
    if n & 0x80000000:                                # sign-extend to int32
        n -= 0x100000000
    return n, i


def _read_varint_stream(sock: socket.socket) -> int:
    """Pull a VarInt off the wire one byte at a time (the length prefix — we
    don't know how many bytes it occupies until the MSB clears)."""
    n = 0
    shift = 0
    for _ in range(5):
        chunk = sock.recv(1)
        if not chunk:
            raise OSError("EOF reading VarInt")
        b = chunk[0]
        n |= (b & 0x7F) << shift
        if not (b & 0x80):
            if n & 0x80000000:
                n -= 0x100000000
            return n
        shift += 7
    raise ValueError("VarInt too long")


def _framed(payload: bytes) -> bytes:
    """VarInt length prefix + payload — the outer frame every SLP packet uses."""
    return _write_varint(len(payload)) + payload


def _handshake(host: str, port: int, protocol_version: int = -1) -> bytes:
    """Handshake packet (id 0x00) into next_state=1 (status)."""
    addr = host.encode("utf-8")[:255]
    body = (_write_varint(0x00)
            + _write_varint(protocol_version)
            + _write_varint(len(addr)) + addr
            + struct.pack(">H", port)
            + _write_varint(1))
    return _framed(body)


def _status_request() -> bytes:
    """Status Request packet (id 0x00, empty body)."""
    return _framed(_write_varint(0x00))


def _recvn(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise OSError("short read")
        buf += chunk
    return buf


# --- Status Response parsing ------------------------------------------------

def _walk_description(node) -> str:
    """Flatten a chat-component tree (or a bare string) into plain text.

    Servers post-1.7 send `description` as an object with `text` and nested
    `extra`; older ones send a raw string. `translate` keys are surfaced as
    `{key}` since we don't ship Mojang's lang files."""
    if node is None:
        return ""
    if isinstance(node, str):
        return _MC_FORMAT_RE.sub("", node)
    if isinstance(node, list):
        return "".join(_walk_description(x) for x in node)
    if not isinstance(node, dict):
        return ""
    parts: list[str] = []
    text = node.get("text")
    if isinstance(text, str):
        parts.append(_MC_FORMAT_RE.sub("", text))
    tr = node.get("translate")
    if isinstance(tr, str) and not text:
        parts.append("{" + tr + "}")
    extra = node.get("extra")
    if isinstance(extra, list):
        for x in extra:
            parts.append(_walk_description(x))
    return "".join(parts)


def _extract_favicon(favicon_uri: str) -> tuple[str, int, tuple[int, int] | None]:
    """('sha256hex', bytes_len, (w, h)|None) from a `data:image/png;base64,...`
    URI. Returns ('', 0, None) on anything malformed — favicons are optional."""
    if not isinstance(favicon_uri, str):
        return "", 0, None
    prefix = "data:image/png;base64,"
    if not favicon_uri.startswith(prefix):
        return "", 0, None
    try:
        raw = base64.b64decode(favicon_uri[len(prefix):], validate=False)
    except (ValueError, TypeError):
        return "", 0, None
    if len(raw) < 24 or not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return hashlib.sha256(raw).hexdigest(), len(raw), None
    try:
        w, h = struct.unpack(">II", raw[16:24])
    except struct.error:
        w, h = 0, 0
    return hashlib.sha256(raw).hexdigest(), len(raw), (w, h)


def _extract_mods(status: dict) -> list[dict]:
    """Forge (1.13+ `forgeData.mods`) or FML1 (1.7-1.12 `modinfo.modList`)
    mod list, normalised to [{id, version}]."""
    mods: list[dict] = []
    fd = status.get("forgeData")
    if isinstance(fd, dict):
        for m in (fd.get("mods") or []):
            if isinstance(m, dict):
                mid = m.get("modId") or m.get("modid") or ""
                mver = m.get("modmarker") or m.get("version") or ""
                if mid:
                    mods.append({"id": str(mid), "version": str(mver)})
    mi = status.get("modinfo")
    if isinstance(mi, dict):
        for m in (mi.get("modList") or []):
            if isinstance(m, dict):
                mid = m.get("modid") or m.get("modId") or ""
                mver = m.get("version") or ""
                if mid:
                    mods.append({"id": str(mid), "version": str(mver)})
    return mods


def _parse_status_json(status: dict) -> dict:
    """Normalise the SLP Status Response JSON into the flat dict probe() returns."""
    out: dict = {}
    ver = status.get("version") or {}
    if isinstance(ver, dict):
        out["version_name"] = str(ver.get("name") or "")
        try:
            out["protocol_number"] = int(ver.get("protocol") or 0)
        except (TypeError, ValueError):
            out["protocol_number"] = 0
    else:
        out["version_name"] = ""
        out["protocol_number"] = 0

    players = status.get("players") or {}
    if isinstance(players, dict):
        try:
            out["players_online"] = int(players.get("online") or 0)
        except (TypeError, ValueError):
            out["players_online"] = 0
        try:
            out["players_max"] = int(players.get("max") or 0)
        except (TypeError, ValueError):
            out["players_max"] = 0
        sample = players.get("sample") or []
        out["players_sample"] = [
            {"name": str(p.get("name", "")), "id": str(p.get("id", ""))}
            for p in sample
            if isinstance(p, dict) and p.get("name")
        ]
    else:
        out["players_online"] = 0
        out["players_max"] = 0
        out["players_sample"] = []

    desc = status.get("description")
    out["motd_json"] = desc if isinstance(desc, (dict, list)) else None
    out["motd_text"] = _walk_description(desc)

    fav = status.get("favicon")
    sha, blen, dims = _extract_favicon(fav) if isinstance(fav, str) else ("", 0, None)
    out["favicon_sha256"] = sha
    out["favicon_bytes"] = blen
    out["favicon_dims"] = dims

    out["forge_mods"] = _extract_mods(status)

    for key, out_key in (("enforcesSecureChat", "enforces_secure_chat"),
                         ("preventsChatReports", "prevents_chat_reports"),
                         ("previewsChat", "previews_chat")):
        if key in status:
            out[out_key] = bool(status.get(key))
    return out


# --- Log4Shell classification ----------------------------------------------

def _parse_java_edition_version(version_name: str) -> str:
    """Return the Java Edition version (e.g. '1.16.5') embedded in version.name,
    or '' if none is recognisable. Handles 'Paper 1.16.5', 'Spigot 1.7.10',
    'Forge 1.12.2-14.23.5.2860', '1.19.4', 'BungeeCord 1.8.x-1.20.x' (proxies
    span a range — return '' rather than pick one)."""
    if not isinstance(version_name, str):
        return ""
    # A range like 1.8.x-1.20.x is a proxy hint, not a single-server version.
    if version_name.count("-") and "x" in version_name.lower():
        return ""
    m = _MC_VERSION_RE.search(version_name)
    return m.group(1) if m else ""


def _version_tuple(v: str) -> tuple[int, int, int]:
    parts = v.split(".")
    a = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    b = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    c = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return a, b, c


def _is_log4shell_vulnerable(version_name: str) -> tuple[bool, str]:
    """Java Edition 1.7 through 1.18.0 inclusive shipped a vulnerable log4j.
    Mojang's fixed line starts at 1.18.1. Returns (vulnerable, parsed_version)."""
    ver = _parse_java_edition_version(version_name)
    if not ver:
        return False, ""
    t = _version_tuple(ver)
    if t < (1, 7, 0):
        return False, ver                              # pre-log4j era
    if t < (1, 18, 1):
        return True, ver
    return False, ver


def _proxy_kind(version_name: str) -> str:
    """'bungeecord' / 'velocity' / '' — proxies front backend fleets that a
    scanner otherwise never sees."""
    if not isinstance(version_name, str):
        return ""
    low = version_name.lower()
    if low.startswith("bungeecord") or low.startswith("waterfall"):
        return "bungeecord"
    if low.startswith("velocity"):
        return "velocity"
    return ""


# --- Probe ------------------------------------------------------------------

def slp_probe(ip: str, port: int = _DEFAULT_PORT,
              timeout: float = _TIMEOUT) -> dict:
    """One SLP round trip. Returns {reachable, ...parsed fields..., raw_json_len,
    error}. Fields absent on unreachable/malformed responses."""
    out: dict = {"reachable": False}
    to = proxy.scaled(timeout)
    try:
        with socket.create_connection((ip, port), timeout=to) as sock:
            sock.settimeout(to)
            sock.sendall(_handshake(ip, port))
            sock.sendall(_status_request())
            frame_len = _read_varint_stream(sock)
            if frame_len <= 0 or frame_len > _STATUS_MAX:
                out["error"] = f"frame length out of range ({frame_len})"
                return out
            body = _recvn(sock, frame_len)
    except (OSError, ValueError) as e:
        out["error"] = str(e) or e.__class__.__name__
        return out

    try:
        pkt_id, o = _read_varint(body, 0)
        if pkt_id != 0x00:
            out["error"] = f"unexpected packet id {pkt_id:#x}"
            return out
        json_len, o = _read_varint(body, o)
    except (IndexError, ValueError) as e:
        out["error"] = f"malformed status frame: {e}"
        return out
    if json_len < 0 or o + json_len > len(body):
        out["error"] = "status JSON length mismatch"
        return out
    raw = body[o:o + json_len]
    try:
        status = json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        out["error"] = f"status JSON parse: {e}"
        return out
    if not isinstance(status, dict):
        out["error"] = "status payload not a JSON object"
        return out

    out["reachable"] = True
    out["raw_json_len"] = len(raw)
    out.update(_parse_status_json(status))
    return out


# --- RCON companion (25575/tcp) --------------------------------------------

_RCON_AUTH = 3


def _rcon_packet(request_id: int, ptype: int, payload: bytes) -> bytes:
    body = struct.pack("<ii", request_id, ptype) + payload + b"\x00\x00"
    return struct.pack("<i", len(body)) + body


def _read_rcon_packet(sock: socket.socket) -> tuple[int, int, bytes] | None:
    try:
        header = _recvn(sock, 4)
        (size,) = struct.unpack("<i", header)
        if size < 10 or size > 4096:
            return None
        rest = _recvn(sock, size)
    except (OSError, struct.error):
        return None
    if len(rest) < 10:
        return None
    rid, ptype = struct.unpack("<ii", rest[:8])
    payload = rest[8:-2]
    return rid, ptype, payload


def rcon_probe(ip: str, port: int = _RCON_DEFAULT_PORT,
               timeout: float = _RCON_TIMEOUT) -> dict:
    """Send one Source-RCON Login with an empty password and read the reply.
    Never sends any command payload. Returns:
      {reachable, speaks_rcon, empty_password_accepted, error}
    """
    out = {"reachable": False, "speaks_rcon": False,
           "empty_password_accepted": False, "error": ""}
    to = proxy.scaled(timeout)
    request_id = 0x5EC0FFEE
    try:
        with socket.create_connection((ip, port), timeout=to) as sock:
            sock.settimeout(to)
            sock.sendall(_rcon_packet(request_id, _RCON_AUTH, b""))
            reply = _read_rcon_packet(sock)
    except OSError as e:
        out["error"] = str(e) or e.__class__.__name__
        return out
    out["reachable"] = True
    if reply is None:
        out["error"] = "no framed RCON reply"
        return out
    rid, ptype, _payload = reply
    out["speaks_rcon"] = True
    # AUTH_RESPONSE with rid == our request-id means auth ACCEPTED.
    # rid == -1 (0xFFFFFFFF int32) means REJECTED. Some servers echo a
    # SERVERDATA_RESPONSE_VALUE first — if either frame carries rid==our-id
    # it's accepted.
    if rid == request_id:
        out["empty_password_accepted"] = True
    return out


# --- Targets / probe entrypoint / findings ---------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          check_rcon: bool = True, rcon_port: int = _RCON_DEFAULT_PORT) -> dict:
    """SLP probe + version-derived Log4Shell classification + optional RCON."""
    out = slp_probe(ip, port, timeout=timeout)
    if not out.get("reachable"):
        return out
    vulnerable, ver = _is_log4shell_vulnerable(out.get("version_name", ""))
    out["java_edition_version"] = ver
    out["log4shell_vulnerable"] = vulnerable
    out["proxy_kind"] = _proxy_kind(out.get("version_name", ""))
    if check_rcon:
        rc = rcon_probe(ip, rcon_port, timeout=min(timeout, _RCON_TIMEOUT))
        if rc.get("reachable"):
            out["rcon"] = rc
    return out


def minecraft_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_minecraft(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "mcstatus", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_minecraft(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver_name = pr.get("version_name") or "?"
            proto = pr.get("protocol_number") or 0

            if pr.get("log4shell_vulnerable"):
                jver = pr.get("java_edition_version") or "?"
                out.append(_finding(
                    "high",
                    "Minecraft server in Log4Shell-vulnerable version range "
                    "(CVE-2021-44228)", tgt,
                    f"SLP version.name = '{ver_name}' (Java Edition {jver}). "
                    f"Every 1.7 through 1.18.0 build shipped a log4j 2.x that "
                    f"logged JNDI substitutions from chat/console. Mojang's "
                    f"fixed line starts at 1.18.1 with backports for older "
                    f"lines. Version-only classification: recce did NOT send "
                    f"a JNDI payload — that would BE the exploit.",
                    f"# Check the operator's console for the applied backport;\n"
                    f"# on unpatched boxes CVE-2021-44228 is trivially reachable.\n"
                    f"nmap -sV -p {p.portid} {h.ip}",
                    "Apply Mojang's log4j mitigation for this line (JVM flag "
                    "-Dlog4j2.formatMsgNoLookups=true on 2.10-2.14; the "
                    "log4j2_112-2.xml patch for 1.7-1.11.2; the client-side "
                    "log4j2_17-111.xml for 1.12-1.16.5), or upgrade to 1.18.1+.",
                    ["CWE-502", "CWE-20"], kind="minecraft_log4shell"))

            sample = pr.get("players_sample") or []
            if sample:
                names = ", ".join(pl["name"] for pl in sample[:10] if pl.get("name"))
                out.append(_finding(
                    "medium",
                    "Minecraft SLP discloses player roster (usernames + UUIDs) "
                    "unauthenticated", tgt,
                    f"Server List Ping returned {len(sample)} player sample "
                    f"entry(ies): {names}. On a corp-owned server these are "
                    f"employee Mojang accounts — usernames frequently mirror "
                    f"corp usernames and the UUID is a stable identity pivot.",
                    f"# read the sample directly:\n"
                    f"mcstatus {h.ip}:{p.portid} status",
                    "Mojang exposes no server-side toggle to suppress the "
                    "sample list; plugins like SamplePermission on Paper can "
                    "hide it. Restrict SLP to trusted networks.",
                    ["CWE-200"], kind="minecraft_player_roster"))

            motd = (pr.get("motd_text") or "").strip()
            fqdns = sorted({m.group(1).lower() for m in _FQDN_TOKEN_RE.finditer(motd)})
            if fqdns:
                out.append(_finding(
                    "medium",
                    "Minecraft MOTD discloses internal hostnames / branding",
                    tgt,
                    f"MOTD text '{motd[:200]}' contains FQDN-shaped token(s): "
                    f"{', '.join(fqdns[:8])}. These frequently name internal "
                    f"admin panels, backing services or department resources "
                    f"an outside scanner would not otherwise see.",
                    f"mcstatus {h.ip}:{p.portid} status",
                    "Remove environment / hostname references from the server "
                    "MOTD; put contact/help URLs on a public-only domain.",
                    ["CWE-200"], kind="minecraft_motd_hostnames"))

            rc = pr.get("rcon") or {}
            if rc.get("reachable") and rc.get("speaks_rcon"):
                if rc.get("empty_password_accepted"):
                    out.append(_finding(
                        "high",
                        "Minecraft RCON accepts empty password",
                        f"{h.ip}:{rc.get('port', _RCON_DEFAULT_PORT)}",
                        "Source-RCON Login (type 3) with an empty password "
                        "returned AUTH_RESPONSE echoing our request-id — "
                        "the server accepted the login. RCON grants "
                        "arbitrary /op, /stop and /execute; this is full "
                        "server takeover, and worlds routinely contain "
                        "private notes and player IPs.",
                        f"# minecraft-rcon-cli or mcrcon, empty password:\n"
                        f"mcrcon -H {h.ip} -p '' -P {_RCON_DEFAULT_PORT} list",
                        "Set a strong `rcon.password` in server.properties, "
                        "or disable RCON (`enable-rcon=false`) and restrict "
                        "25575/tcp to management-only networks.",
                        ["CWE-521", "CWE-798"], kind="minecraft_rcon_open"))
                else:
                    out.append(_finding(
                        "medium",
                        "Minecraft RCON exposed on 25575/tcp",
                        f"{h.ip}:{_RCON_DEFAULT_PORT}",
                        "Source-RCON framing answered on the default port "
                        "companion to 25565/tcp Minecraft. RCON is off by "
                        "default in server.properties; a reachable RCON port "
                        "is a stronger take-over target than the game port "
                        "itself since a single accepted password yields "
                        "arbitrary /op /execute.",
                        f"nmap -sV -p {_RCON_DEFAULT_PORT} {h.ip}",
                        "Restrict RCON to management-only networks; require "
                        "a strong `rcon.password` in server.properties.",
                        ["CWE-521"], kind="minecraft_rcon_exposed"))

            pk = pr.get("proxy_kind") or ""
            if pk:
                out.append(_finding(
                    "info",
                    "BungeeCord/Velocity proxy detected — enumerate backend "
                    "Minecraft fleet from this host", tgt,
                    f"version.name = '{ver_name}' identifies a {pk} proxy. "
                    f"The BACKEND servers behind it are usually reachable "
                    f"only from THIS host and rarely appear in an external "
                    f"scan. Enumerate the proxy's config (config.yml / "
                    f"velocity.toml) for the backend list.",
                    f"# from the proxy host:\n"
                    f"cat /opt/{pk}/config.yml 2>/dev/null || "
                    f"cat /opt/{pk}/velocity.toml 2>/dev/null",
                    "Firewall the backend segment so the proxy is the only "
                    "reachable path; require ip-forwarding auth (proxy secret).",
                    [], kind="minecraft_proxy"))

            mods = pr.get("forge_mods") or []
            if mods:
                mid_list = ", ".join(
                    f"{m['id']}{'/' + m['version'] if m['version'] else ''}"
                    for m in mods[:6])
                more = f" (+{len(mods) - 6} more)" if len(mods) > 6 else ""
                out.append(_finding(
                    "info",
                    "Modded Minecraft server (Forge/Fabric) — mod inventory "
                    "captured", tgt,
                    f"{len(mods)} mod(s) advertised in forgeData/modinfo: "
                    f"{mid_list}{more}. Feeds the product-inventory / CVE "
                    f"mapper — many mods have their own CVE histories.",
                    f"mcstatus {h.ip}:{p.portid} json",
                    "n/a (informational).",
                    [], kind="minecraft_mods"))

            fav_sha = pr.get("favicon_sha256") or ""
            dims = pr.get("favicon_dims")
            dim_txt = f"{dims[0]}x{dims[1]}" if dims else "unknown-size"
            out.append(_finding(
                "info",
                "Minecraft server identified (version, protocol, MOTD, players)",
                tgt,
                f"Java Edition SLP: version.name='{ver_name}' "
                f"protocol={proto} players={pr.get('players_online', 0)}/"
                f"{pr.get('players_max', 0)} "
                f"favicon={dim_txt}{' sha256='+fav_sha[:16] if fav_sha else ''} "
                f"motd='{motd[:120]}'",
                f"mcstatus {h.ip}:{p.portid} status",
                "Restrict SLP to trusted networks if the server is not "
                "intended to be publicly listed.",
                [], kind="minecraft_fingerprint"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "mcstatus",
         "command": f"mcstatus {ip}:{port} status",
         "why": "one-shot SLP — version, MOTD, player sample, favicon"},
        {"phase": "enumerate", "tool": "mcstatus",
         "command": f"mcstatus {ip}:{port} json",
         "why": "full raw JSON (forgeData mods, chat-report flags)"},
        {"phase": "enumerate", "tool": "nmap",
         "command": f"nmap -sV -p {port},{_RCON_DEFAULT_PORT} "
                    f"--script minecraft-info {ip}",
         "why": "cross-check the SLP result and detect the RCON companion"},
        {"phase": "exploit", "tool": "review",
         "command": "# CVE-2021-44228 Log4Shell: version 1.7-1.18.0 range.\n"
                    "# recce flags off version.name; DO NOT send a JNDI "
                    "payload on production.",
         "why": "the log4j RCE surfaces via chat/console log substitution"},
        {"phase": "exploit", "tool": "mcrcon",
         "command": f"mcrcon -H {ip} -p '' -P {_RCON_DEFAULT_PORT} list",
         "why": "check for empty/default RCON password — only with ROE"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "minecraft", _DEFAULT_PORT)


# --- Cross-service fanout --------------------------------------------------

def _has_rcon_port(host: Host, port_id: int) -> bool:
    return any(p.portid == port_id and p.is_open for p in host.ports)


def _fanout(hosts: list[Host], probes: dict) -> dict:
    """Wire probe results into the cross-service picture.

    - MOTD FQDN-shaped tokens append to Host.hostnames (like nbd_ndmp).
    - version_name / java_edition_version populate Port.product/Port.version
      so the existing CVE mapper sees Log4Shell without a bespoke rule.
    - Player usernames and mod ids and favicon sha256 are returned as
      inventory buckets the caller (analyze) attaches to its result dict.
    """
    added_names: list[tuple[str, str]] = []
    identities: list[dict] = []
    mod_inventory: list[dict] = []
    branding: dict[str, list[str]] = {}
    for h in hosts:
        for p in h.open_ports:
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue

            motd = pr.get("motd_text") or ""
            for m in _FQDN_TOKEN_RE.finditer(motd):
                name = m.group(1)
                if name.lower() not in {x.lower() for x in h.hostnames}:
                    h.hostnames.append(name)
                    added_names.append((h.ip, name))

            ver_name = pr.get("version_name") or ""
            jver = pr.get("java_edition_version") or ""
            if ver_name and not p.product:
                p.product = "Minecraft " + (
                    "BungeeCord" if pr.get("proxy_kind") == "bungeecord"
                    else "Velocity" if pr.get("proxy_kind") == "velocity"
                    else ver_name.split()[0] if " " in ver_name
                    else "Java Edition")
            if jver and not p.version:
                p.version = jver
            if not p.service:
                p.service = "minecraft"

            for pl in pr.get("players_sample") or []:
                identities.append({"ip": h.ip, "port": p.portid,
                                   "username": pl.get("name", ""),
                                   "uuid": pl.get("id", ""),
                                   "source": "minecraft-slp"})

            for mod in pr.get("forge_mods") or []:
                mod_inventory.append({"ip": h.ip, "port": p.portid,
                                      "id": mod.get("id", ""),
                                      "version": mod.get("version", "")})

            sha = pr.get("favicon_sha256") or ""
            if sha:
                branding.setdefault(sha, []).append(h.ip)

    return {"hostnames_added": added_names,
            "identities": identities,
            "mod_inventory": mod_inventory,
            "favicon_groups": {sha: sorted(set(ips))
                               for sha, ips in branding.items()
                               if len(set(ips)) > 1}}


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = minecraft_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version_name"] = pr.get("version_name", "")
                t["log4shell"] = bool(pr.get("log4shell_vulnerable"))
                t["players_online"] = pr.get("players_online", 0)
    fanout = _fanout(hosts, probes)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "fanout": fanout,
            "stats": {"targets": len(targets), "findings": len(fs),
                      "hostnames_added": len(fanout["hostnames_added"]),
                      "identities": len(fanout["identities"]),
                      "mods": len(fanout["mod_inventory"]),
                      "stopped": state.get("stopped")}}
